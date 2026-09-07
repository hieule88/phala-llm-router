"""Route-level tests for POST /v1/payment-intents/{memo}/checkout.

These exist because the bug they pin was ROUTE-level: an earlier
revision mutated the intent's provider before validating the request,
so an unauthenticated `provider=manual` call flipped a victim's
on-chain intent off the matching table and answered 400 — row already
changed. Every scenario here asserts BOTH the HTTP status and that the
intent's rail did not move (via the watcher matching table).

Uses a real FastAPI TestClient with the app's own lifespan; the DB is a
fresh temp file per class, and module config (tokens, provider config)
is patched on the modules rather than via env, since env was consumed
at import time.

Run from `auth-service/`:
    python -m unittest tests.test_checkout_route -v
"""

import hashlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# This file sorts alphabetically before test_consume_gate, which relies
# on being the first importer of app.main with these env vars set (they
# are read at import time). Mirror its values so import order stays
# irrelevant; our own class patches module attributes on top anyway.
os.environ.setdefault("ADMIN_TOKEN", "A" * 40)
os.environ.setdefault("PROXY_REFUND_TOKEN", "P" * 40)
os.environ.setdefault("AUTH_DB_PATH", ":memory:")

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app import onchain_client, stripe_client  # noqa: E402
from app.db import init_db as real_init_db  # noqa: E402

ADMIN = "a" * 32
WATCHER = "w" * 32
GATEWAY = "mtst1gatewayreceivingaccount000000000"
FAUCET = "mtst1azftenneus72ugqqsj9rk7cveqk0eraz"

KEY_HASH_OWNER = hashlib.sha256(b"lev_owner").hexdigest()
KEY_HASH_OTHER = hashlib.sha256(b"lev_other").hexdigest()


class CheckoutRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(cls._tmp.name, "auth.db")

        async def fake_init():
            return await real_init_db(db_path)

        cls._patches = [
            patch.object(main, "init_db", fake_init),
            patch.object(main, "ADMIN_TOKEN", ADMIN),
            patch.object(main, "ONCHAIN_WATCHER_TOKEN", WATCHER),
            patch.object(main, "TOPUP_PROVIDER_OVERRIDE", ""),
            # onchain rail fully configured...
            patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", GATEWAY),
            patch.object(onchain_client, "ONCHAIN_FAUCET_ID", FAUCET),
            # ...stripe deliberately NOT (the 503-before-mutation case)
            patch.object(stripe_client, "STRIPE_SECRET_KEY", ""),
            patch.object(stripe_client, "STRIPE_SUCCESS_URL", ""),
        ]
        for p in cls._patches:
            p.start()
        cls.client = TestClient(main.app)
        cls.client.__enter__()   # runs lifespan → opens the temp DB

        # Two identities, seeded over the admin API so everything runs
        # in the TestClient's own event loop.
        for value in (KEY_HASH_OWNER, KEY_HASH_OTHER):
            r = cls.client.post(
                "/v1/identities",
                headers={"authorization": f"Bearer {ADMIN}"},
                json={"credential_type": "api_key", "credential_value": value},
            )
            assert r.status_code == 201, r.text

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        for p in cls._patches:
            p.stop()
        cls._tmp.cleanup()

    # ── helpers ────────────────────────────────────────────────────────

    def _create_intent(self, provider, credential=KEY_HASH_OWNER, credits=300):
        r = self.client.post("/v1/payment-intents", json={
            "credential_type": "api_key", "credential_value": credential,
            "credits": credits, "provider": provider,
        })
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _checkout(self, memo, provider, credential=None):
        body = {"provider": provider}
        if credential is not None:
            body["credential_type"] = "api_key"
            body["credential_value"] = credential
        return self.client.post(f"/v1/payment-intents/{memo}/checkout", json=body)

    def _matching_memos(self):
        r = self.client.get("/v1/onchain/pending-intents",
                            headers={"authorization": f"Bearer {WATCHER}"})
        self.assertEqual(r.status_code, 200, r.text)
        return [i["memo"] for i in r.json()["intents"]]

    # ── the pinned regression: no mutation before validation ─────────

    def test_unauthenticated_manual_switch_is_400_and_row_unmoved(self):
        intent = self._create_intent("onchain", credits=101)
        r = self._checkout(intent["memo"], "manual")
        self.assertEqual(r.status_code, 400)
        self.assertIn(intent["memo"], self._matching_memos(),
                      "row must still be on the on-chain rail")

    def test_unauthenticated_switch_is_401_and_row_unmoved(self):
        intent = self._create_intent("onchain", credits=102)
        r = self._checkout(intent["memo"], "stripe")
        self.assertEqual(r.status_code, 401)
        self.assertIn(intent["memo"], self._matching_memos())

    def test_wrong_owner_switch_is_403_and_row_unmoved(self):
        intent = self._create_intent("onchain", credits=103)
        r = self._checkout(intent["memo"], "stripe", credential=KEY_HASH_OTHER)
        self.assertEqual(r.status_code, 403)
        self.assertIn(intent["memo"], self._matching_memos())

    def test_switch_to_unconfigured_rail_is_503_and_row_unmoved(self):
        # Even the OWNER must not be able to move an intent onto a dead
        # rail — that strands it exactly like a stranger's switch would.
        intent = self._create_intent("onchain", credits=104)
        r = self._checkout(intent["memo"], "stripe", credential=KEY_HASH_OWNER)
        self.assertEqual(r.status_code, 503)
        self.assertIn(intent["memo"], self._matching_memos())

    # ── the flows that must keep working ──────────────────────────────

    def test_same_provider_retry_needs_no_auth(self):
        intent = self._create_intent("onchain", credits=105)
        r = self._checkout(intent["memo"], "onchain")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["memo"], intent["memo"])
        self.assertIn("onchain", body)
        self.assertEqual(body["onchain"]["note_kind"], "p2id")

    def test_owner_can_switch_stripe_intent_onto_the_onchain_rail(self):
        # Stripe checkout creation fails softly at create time (rail
        # unconfigured) but the row exists — the owner moves it onchain.
        intent = self._create_intent("stripe", credits=106)
        self.assertNotIn(intent["memo"], self._matching_memos())
        r = self._checkout(intent["memo"], "onchain", credential=KEY_HASH_OWNER)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("onchain", r.json())
        self.assertIn(intent["memo"], self._matching_memos())


if __name__ == "__main__":
    unittest.main()
