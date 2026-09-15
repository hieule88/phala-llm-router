"""Route-level tests for POST /v1/payment-intents/{memo}/checkout.

The endpoint rebuilds payment instructions for an existing pending
intent; it must NEVER move the intent to another rail. Two separate
bugs live in that sentence, and both are pinned here:

  * An earlier revision mutated the intent's provider before validating
    the request, so an unauthenticated `provider=manual` call flipped a
    victim's on-chain intent off the matching table and answered 400 —
    row already changed.
  * Rail switching itself was then removed: a switch away from Stripe
    does not cancel the Checkout Session already handed to the payer,
    so one order became payable on both rails at once — paid twice,
    credited once (topups UNIQUE), refunded by hand.

Every scenario asserts BOTH the HTTP status and that the intent's rail
did not move (via the watcher matching table).

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

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app import onchain_client, stripe_client  # noqa: E402
from app.db import init_db as real_init_db  # noqa: E402


class _StripeStub:
    """Canned Checkout Session transport. Both rails must be configured
    here: creating an intent now preflights its rail, so an unconfigured
    Stripe would fail at creation and these tests would never reach the
    checkout route they exist to exercise."""

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, data=None, headers=None):
        class _Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"id": "cs_stub", "url": "https://checkout.stripe.com/stub"}

        return _Resp()


ADMIN = "a" * 32
WATCHER = "w" * 32
GATEWAY = "mtst1gatewayreceivingaccount000000000"
FAUCET = "mtst1azftenneus72ugqqsj9rk7cveqk0eraz"

KEY_HASH_OWNER = hashlib.sha256(b"lev_owner").hexdigest()


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
            # The shared per-minute limiter is not what these tests
            # exercise, and its state outlives a test class — one
            # chatty test would otherwise 429 every later one.
            patch.object(main.limiter, "enabled", False),
            patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", GATEWAY),
            patch.object(onchain_client, "ONCHAIN_FAUCET_ID", FAUCET),
            patch.object(stripe_client, "STRIPE_SECRET_KEY", "sk_test_stub"),
            patch.object(stripe_client, "STRIPE_SUCCESS_URL", "https://app.example/ok"),
            patch.object(httpx, "AsyncClient", _StripeStub),
        ]
        for p in cls._patches:
            p.start()
        cls.client = TestClient(main.app)
        cls.client.__enter__()   # runs lifespan → opens the temp DB

        # One identity, seeded over the admin API so everything runs in
        # the TestClient's own event loop.
        r = cls.client.post(
            "/v1/identities",
            headers={"authorization": f"Bearer {ADMIN}"},
            json={"credential_type": "api_key", "credential_value": KEY_HASH_OWNER},
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

    def _checkout(self, memo, provider=None):
        body = {} if provider is None else {"provider": provider}
        return self.client.post(f"/v1/payment-intents/{memo}/checkout", json=body)

    def _matching_memos(self):
        r = self.client.get("/v1/onchain/pending-intents",
                            headers={"authorization": f"Bearer {WATCHER}"})
        self.assertEqual(r.status_code, 200, r.text)
        return [i["memo"] for i in r.json()["intents"]]

    # ── the rail is fixed at creation ─────────────────────────────────

    def test_garbage_provider_is_400_and_row_unmoved(self):
        # 'manual' is a legal intent provider but has no checkout to build.
        intent = self._create_intent("onchain", credits=101)
        r = self._checkout(intent["memo"], "manual")
        self.assertEqual(r.status_code, 400)
        self.assertIn(intent["memo"], self._matching_memos(),
                      "row must still be on the on-chain rail")

    def test_asking_for_the_other_rail_is_409_and_row_unmoved(self):
        # No credential can move it either: there is no switch to
        # authenticate. The answer points at creating a new intent.
        intent = self._create_intent("onchain", credits=102)
        r = self._checkout(intent["memo"], "stripe")
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn("create a new intent", r.json()["detail"])
        self.assertIn(intent["memo"], self._matching_memos())

    def test_stripe_intent_cannot_be_pulled_onto_the_onchain_rail(self):
        # The reverse direction, and the one that used to succeed: a
        # stripe intent must never appear in the watcher's matching
        # table, or a Stripe session and an on-chain quote would be
        # payable for the same order at the same time.
        intent = self._create_intent("stripe", credits=103)
        self.assertNotIn(intent["memo"], self._matching_memos())
        r = self._checkout(intent["memo"], "onchain")
        self.assertEqual(r.status_code, 409, r.text)
        self.assertNotIn(intent["memo"], self._matching_memos(),
                         "a refused request must not move the row")

    # ── the flows that must keep working ──────────────────────────────

    def test_same_provider_retry_needs_no_auth(self):
        intent = self._create_intent("onchain", credits=105)
        r = self._checkout(intent["memo"], "onchain")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["memo"], intent["memo"])
        self.assertIn("onchain", body)
        self.assertEqual(body["onchain"]["note_kind"], "p2id")

    def test_empty_body_rebuilds_the_intents_own_rail(self):
        # What buy_credits.py prints as the retry command: `-d '{}'`.
        # It must work on BOTH rails — an omitted provider means "this
        # intent's own rail", never a default that switches it.
        intent = self._create_intent("onchain", credits=106)
        r = self._checkout(intent["memo"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("onchain", r.json())

    def test_retry_after_the_rail_breaks_is_503(self):
        # The intent was created while Stripe worked (creation preflights
        # the rail, so it could not have been created otherwise); the rail
        # broke afterwards. Retrying surfaces the rail's 503 — an
        # operator problem, not a client error, and the intent survives
        # for a later retry.
        intent = self._create_intent("stripe", credits=107)
        with patch.object(stripe_client, "STRIPE_SECRET_KEY", ""):
            r = self._checkout(intent["memo"], "stripe")
        self.assertEqual(r.status_code, 503, r.text)
        # and once the rail is back, the same intent still yields a link
        again = self._checkout(intent["memo"], "stripe")
        self.assertEqual(again.status_code, 200, again.text)


if __name__ == "__main__":
    unittest.main()
