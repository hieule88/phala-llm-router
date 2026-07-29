"""Tests for the Stripe webhook path.

Signature verification is exercised via `stripe.Webhook.construct_event`
(the same call the production endpoint makes) — we generate the HMAC
locally, feed it in, and confirm both the happy path and every failure
mode (missing header, bad signature, unknown identity, zero amount,
idempotent replay).

Run from `phala-TEE/auth-service/`:
    python -m unittest tests.test_stripe_webhook -v
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


WEBHOOK_SECRET = "whsec_test_" + "a" * 32


def _sign(payload: bytes, secret: str, ts: int) -> str:
    """Build a Stripe-Signature header the way Stripe does. Format:
    `t=<ts>,v1=<hex_hmac_sha256("<ts>.<payload>", secret)>`.
    """
    signed_payload = f"{ts}.".encode() + payload
    mac = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def _event(event_type: str, session_overrides: dict | None = None) -> bytes:
    session = {
        "id": "cs_test_abc",
        "object": "checkout.session",
        "amount_total": 1000,   # 1000 cents = $10 = 1000 credits at default rate
        "currency": "usd",
        "metadata": {"identity_id": "42"},
        "payment_status": "paid",
    }
    if session_overrides:
        session.update(session_overrides)
    return json.dumps({
        "id": "evt_test_1",
        "object": "event",
        "type": event_type,
        "data": {"object": session},
    }).encode()


class SetupMixin:
    """Set env before importing the module so its module-level constants
    pick up the test secret."""

    @classmethod
    def setUpClass(cls):
        os.environ["STRIPE_WEBHOOK_SECRET"] = WEBHOOK_SECRET
        os.environ["STRIPE_CENTS_PER_CREDIT"] = "1"
        # Force fresh import of the module so it re-reads env.
        import importlib
        from app import stripe_webhook  # noqa: F401
        importlib.reload(stripe_webhook)
        cls.stripe_webhook = stripe_webhook


class SignatureVerifyTest(SetupMixin, unittest.TestCase):
    def test_missing_signature_header_400s(self):
        payload = _event("checkout.session.completed")
        with self.assertRaises(self.stripe_webhook.WebhookError) as cm:
            self.stripe_webhook.verify_and_parse(payload, None)
        self.assertEqual(cm.exception.status_code, 400)

    def test_bad_signature_401s(self):
        payload = _event("checkout.session.completed")
        bad = f"t={int(time.time())},v1=deadbeef"
        with self.assertRaises(self.stripe_webhook.WebhookError) as cm:
            self.stripe_webhook.verify_and_parse(payload, bad)
        self.assertEqual(cm.exception.status_code, 401)

    def test_valid_signature_parses(self):
        payload = _event("checkout.session.completed")
        sig = _sign(payload, WEBHOOK_SECRET, int(time.time()))
        event = self.stripe_webhook.verify_and_parse(payload, sig)
        self.assertEqual(event["type"], "checkout.session.completed")


class DispatchTest(SetupMixin, unittest.TestCase):
    def _run_with_event(self, session_overrides: dict | None = None,
                        event_type: str = "checkout.session.completed"):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                # Pre-provision the identity referenced by the fixture.
                await handlers.create_identity(conn, "api_key", "hash_x")
                # First identity id is 1 by AUTOINCREMENT; adjust the
                # fixture so it lines up with our seeded id.
                payload = _event(event_type, session_overrides)
                sig = _sign(payload, WEBHOOK_SECRET, int(time.time()))
                event = self.stripe_webhook.verify_and_parse(payload, sig)
                return await self.stripe_webhook.dispatch(conn, event)
            finally:
                await conn.close()

        return run(go())

    def test_checkout_credits_correct_amount(self):
        # 1000 cents @ 1 cent/credit = 1000 credits, on identity_id 1.
        result = self._run_with_event({"metadata": {"identity_id": "1"}})
        self.assertTrue(result["handled"])
        self.assertTrue(result["result"]["success"])
        self.assertEqual(result["result"]["balance"], 1000)

    def test_replay_deduplicates(self):
        # Same event id + session id → second dispatch is a no-op.
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                payload = _event("checkout.session.completed",
                                 {"metadata": {"identity_id": "1"}})
                sig = _sign(payload, WEBHOOK_SECRET, int(time.time()))
                event = self.stripe_webhook.verify_and_parse(payload, sig)
                r1 = await self.stripe_webhook.dispatch(conn, event)
                r2 = await self.stripe_webhook.dispatch(conn, event)
                return r1, r2
            finally:
                await conn.close()

        r1, r2 = run(go())
        self.assertEqual(r1["result"]["balance"], 1000)
        self.assertEqual(r2["result"]["balance"], 1000)
        self.assertTrue(r2["result"].get("deduplicated"))

    def test_missing_identity_metadata_400s(self):
        with self.assertRaises(self.stripe_webhook.WebhookError) as cm:
            self._run_with_event({"metadata": {}})
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("identity_id", cm.exception.detail)

    def test_non_integer_identity_400s(self):
        with self.assertRaises(self.stripe_webhook.WebhookError) as cm:
            self._run_with_event({"metadata": {"identity_id": "not-a-number"}})
        self.assertEqual(cm.exception.status_code, 400)

    def test_zero_amount_400s(self):
        with self.assertRaises(self.stripe_webhook.WebhookError) as cm:
            self._run_with_event(
                {"metadata": {"identity_id": "1"}, "amount_total": 0},
            )
        self.assertEqual(cm.exception.status_code, 400)

    def test_unknown_event_type_is_acknowledged_not_processed(self):
        result = self._run_with_event(event_type="charge.refunded")
        self.assertFalse(result["handled"])
        self.assertEqual(result["type"], "charge.refunded")


class PricingTest(SetupMixin, unittest.TestCase):
    def test_cents_per_credit_scales_correctly(self):
        # Override the module constant to 10 (1 credit = 10 cents = $0.10).
        # 1000 cents → 100 credits.
        os.environ["STRIPE_CENTS_PER_CREDIT"] = "10"
        import importlib
        from app import stripe_webhook as sw
        importlib.reload(sw)
        self.assertEqual(sw._cents_to_credits(1000), 100)
        # 5 cents at 10 cents/credit rounds down to 0 — refuse the topup.
        with self.assertRaises(sw.WebhookError):
            sw._cents_to_credits(5)
        # Reset to default so other tests don't inherit this.
        os.environ["STRIPE_CENTS_PER_CREDIT"] = "1"
        importlib.reload(sw)


if __name__ == "__main__":
    unittest.main()
