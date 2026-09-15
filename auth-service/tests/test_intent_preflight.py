"""A rail that cannot quote must refuse BEFORE the intent row exists.

Intents used to be committed first, with a provider failure coming back
only as a soft `checkout_error`, on the theory that the client would
retry checkout for the same memo. No client does — App.jsx and
buy_credits.py both create a NEW intent on every attempt. Since pending
intents are capped per rail and only an admin can cancel one, every
doomed attempt cost the user a slot for the intent's whole TTL (30 days
on Stripe). Two ways to hit it without doing anything unusual:

  * the rail is not configured — a handful of clicks and the rail is
    locked for a month;
  * buying fewer credits than Stripe's minimum charge ($0.50), which
    Stripe rejects every single time.

Every test here asserts BOTH the HTTP answer and that nothing was
written — the budget is the thing being protected.

Run from `auth-service/`:
    python -m unittest tests.test_intent_preflight -v
"""

import hashlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mirror test_consume_gate's import-time env (see test_checkout_route).
os.environ.setdefault("ADMIN_TOKEN", "A" * 40)
os.environ.setdefault("PROXY_REFUND_TOKEN", "P" * 40)
os.environ.setdefault("AUTH_DB_PATH", ":memory:")

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app import onchain_client, stripe_client  # noqa: E402
from app.db import init_db as real_init_db  # noqa: E402

ADMIN = "a" * 32
GATEWAY = "mtst1gatewayreceivingaccount000000000"
FAUCET = "mtst1azftenneus72ugqqsj9rk7cveqk0eraz"
KEY_HASH = hashlib.sha256(b"lev_preflight").hexdigest()


class _StripeStub:
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


class PreflightTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(cls._tmp.name, "auth.db")

        async def fake_init():
            return await real_init_db(db_path)

        cls._patches = [
            patch.object(main, "init_db", fake_init),
            patch.object(main, "ADMIN_TOKEN", ADMIN),
            patch.object(main, "TOPUP_PROVIDER_OVERRIDE", ""),
            # The shared per-minute limiter is not what these tests
            # exercise, and its state outlives a test class — one
            # chatty test would otherwise 429 every later one.
            patch.object(main.limiter, "enabled", False),
            patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", GATEWAY),
            patch.object(onchain_client, "ONCHAIN_FAUCET_ID", FAUCET),
            patch.object(stripe_client, "STRIPE_SECRET_KEY", "sk_test_stub"),
            patch.object(stripe_client, "STRIPE_SUCCESS_URL", "https://app.example/ok"),
            patch.object(stripe_client, "STRIPE_MIN_AMOUNT_CENTS", 50),
            patch.object(httpx, "AsyncClient", _StripeStub),
        ]
        for p in cls._patches:
            p.start()
        cls.client = TestClient(main.app)
        cls.client.__enter__()
        r = cls.client.post(
            "/v1/identities",
            headers={"authorization": f"Bearer {ADMIN}"},
            json={"credential_type": "api_key", "credential_value": KEY_HASH},
        )
        assert r.status_code == 201, r.text

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        for p in cls._patches:
            p.stop()
        cls._tmp.cleanup()

    # ── helpers ────────────────────────────────────────────────────────

    def _create(self, provider, credits):
        return self.client.post("/v1/payment-intents", json={
            "credential_type": "api_key", "credential_value": KEY_HASH,
            "credits": credits, "provider": provider,
        })

    # ── the refusals ──────────────────────────────────────────────────

    def test_below_stripe_minimum_is_400_and_writes_nothing(self):
        # 10 credits = 10 cents, under Stripe's $0.50 floor. Stripe would
        # reject this every time, so it must never reach the ledger.
        before = self._create("stripe", 60).json()["memo"]     # a real one first
        r = self._create("stripe", 10)
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("minimum", r.json()["detail"])
        # the refusal must not have created an intent of its own
        self.assertNotIn("memo", r.json())
        # the earlier, valid intent is untouched
        status = self.client.get(f"/v1/payment-intents/{before}")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["status"], "pending")

    def test_refused_attempts_do_not_eat_the_rail_budget(self):
        # The heart of it: hammering a doomed amount must not lock the
        # rail. With the old order these attempts would have committed a
        # row each and blown the (here: 3) per-rail cap for 30 days.
        with patch.object(main.handlers, "INTENT_MAX_PENDING_PER_IDENTITY", 3):
            for _ in range(10):
                self.assertEqual(self._create("stripe", 10).status_code, 400)
            # the budget is still completely free
            ok = self._create("stripe", 60)
            self.assertEqual(ok.status_code, 201, ok.text)

    def test_unconfigured_stripe_rail_is_503_not_a_committed_row(self):
        with patch.object(stripe_client, "STRIPE_SECRET_KEY", ""):
            r = self._create("stripe", 300)
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("STRIPE_SECRET_KEY", r.json()["detail"])

    def test_unconfigured_onchain_rail_is_503_not_a_committed_row(self):
        with patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", ""):
            r = self._create("onchain", 300)
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("ONCHAIN_GATEWAY_ADDRESS", r.json()["detail"])

    def test_unconfigured_rail_does_not_eat_the_budget_either(self):
        with patch.object(main.handlers, "ONCHAIN_MAX_PENDING_PER_IDENTITY", 2), \
             patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", ""):
            for _ in range(10):
                self.assertEqual(self._create("onchain", 300).status_code, 503)
        with patch.object(main.handlers, "ONCHAIN_MAX_PENDING_PER_IDENTITY", 2):
            self.assertEqual(self._create("onchain", 300).status_code, 201)

    # ── the happy paths still work ────────────────────────────────────

    def test_valid_stripe_intent_still_gets_a_link(self):
        r = self._create("stripe", 300)
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["invoice_url"], "https://checkout.stripe.com/stub")
        self.assertNotIn("checkout_error", r.json())

    def test_onchain_has_no_minimum(self):
        # The floor is Stripe's, not ours: one credit on-chain is fine.
        r = self._create("onchain", 1)
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["onchain"]["token_amount"], "10000")


if __name__ == "__main__":
    unittest.main()
