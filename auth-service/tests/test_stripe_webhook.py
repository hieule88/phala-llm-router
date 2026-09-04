"""Tests for the Stripe webhook (receive-side).

Signature verification exercises the exact scheme Stripe uses:
HMAC-SHA256 over "<t>.<raw body>" carried in the Stripe-Signature header.

Run from `auth-service/`:
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


WHSEC = "whsec_test_" + "c" * 32


def _sign(body: bytes, ts: int | None = None) -> str:
    ts = ts if ts is not None else int(time.time())
    mac = hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def _event(
    etype: str = "checkout.session.completed",
    memo: str = "intent-abc",
    payment_status: str = "paid",
    amount_total: int = 300,
    currency: str = "usd",
    session_id: str = "cs_test_123",
) -> dict:
    return {
        "id": "evt_1",
        "type": etype,
        "data": {"object": {
            "id": session_id,
            "object": "checkout.session",
            "client_reference_id": memo,
            "payment_status": payment_status,
            "amount_total": amount_total,
            "currency": currency,
            "metadata": {"memo": memo},
        }},
    }


class SetupMixin:
    @classmethod
    def setUpClass(cls):
        os.environ["STRIPE_WEBHOOK_SECRET"] = WHSEC
        import importlib
        from app import stripe_webhook  # noqa: F401
        importlib.reload(stripe_webhook)
        cls.mod = stripe_webhook


class SignatureVerifyTest(SetupMixin, unittest.TestCase):
    def test_valid_signature_parses(self):
        body = json.dumps(_event()).encode()
        event = self.mod.verify_and_parse(body, _sign(body))
        self.assertEqual(event["type"], "checkout.session.completed")

    def test_missing_header_400s(self):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(b"{}", None)
        self.assertEqual(cm.exception.status_code, 400)

    def test_bad_signature_401s(self):
        body = json.dumps(_event()).encode()
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(body, f"t={int(time.time())},v1=" + "0" * 64)
        self.assertEqual(cm.exception.status_code, 401)

    def test_tampered_body_401s(self):
        body = json.dumps(_event()).encode()
        sig = _sign(body)
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(body.replace(b"paid", b"free"), sig)
        self.assertEqual(cm.exception.status_code, 401)

    def test_stale_timestamp_401s(self):
        body = json.dumps(_event()).encode()
        old_sig = _sign(body, ts=int(time.time()) - 3600)   # signed an hour ago
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(body, old_sig)
        self.assertEqual(cm.exception.status_code, 401)

    def test_second_v1_candidate_is_accepted(self):
        # Stripe sends multiple v1 entries during secret rotation.
        body = json.dumps(_event()).encode()
        ts = int(time.time())
        good = hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        header = f"t={ts},v1={'0' * 64},v1={good}"
        event = self.mod.verify_and_parse(body, header)
        self.assertEqual(event["type"], "checkout.session.completed")


class DispatchTest(SetupMixin, unittest.TestCase):
    def _with_intent(self, scenario):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="stripe")
                return await scenario(conn, intent["memo"])
            finally:
                await conn.close()

        return run(go())

    async def _balance(self, conn):
        cur = await conn.execute("SELECT balance FROM balances WHERE identity_id = 1")
        return (await cur.fetchone())[0]

    def test_paid_session_credits_the_intent(self):
        async def scenario(conn, memo):
            out = await self.mod.dispatch(conn, _event(memo=memo, amount_total=300))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["handled"])
        self.assertTrue(out["result"]["success"], out)
        self.assertEqual(balance, 300)

    def test_replay_deduplicates(self):
        async def scenario(conn, memo):
            e = _event(memo=memo, amount_total=300)
            r1 = await self.mod.dispatch(conn, e)
            r2 = await self.mod.dispatch(conn, e)
            return r1, r2, await self._balance(conn)

        r1, r2, balance = self._with_intent(scenario)
        self.assertTrue(r1["result"]["success"])
        self.assertTrue(r2["result"].get("deduplicated"))
        self.assertEqual(balance, 300)   # credited exactly once

    def test_underpaid_session_is_refused(self):
        async def scenario(conn, memo):
            out = await self.mod.dispatch(conn, _event(memo=memo, amount_total=100))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertFalse(out["result"]["success"])
        self.assertIn("underpaid", out["result"]["error"])
        self.assertEqual(balance, 0)

    def test_unpaid_session_is_acknowledged_not_credited(self):
        async def scenario(conn, memo):
            out = await self.mod.dispatch(
                conn, _event(memo=memo, payment_status="unpaid"))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertFalse(out["handled"])
        self.assertEqual(balance, 0)

    def test_unrelated_event_is_acknowledged(self):
        async def scenario(conn, memo):
            return await self.mod.dispatch(conn, _event(etype="invoice.created", memo=memo))

        out = self._with_intent(scenario)
        self.assertFalse(out["handled"])

    def test_non_usd_400s(self):
        async def scenario(conn, memo):
            return await self.mod.dispatch(conn, _event(memo=memo, currency="eur"))

        with self.assertRaises(self.mod.WebhookError) as cm:
            self._with_intent(scenario)
        self.assertEqual(cm.exception.status_code, 400)

    def test_paid_expired_intent_still_credits(self):
        # H3 guarantee: a lazily-flipped 'expired' row
        # must still be payable when Stripe confirms money arrived.
        from app import handlers

        async def scenario(conn, memo):
            await conn.execute(
                "UPDATE payment_intents SET expires_at = "
                "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?", (memo,))
            await conn.commit()
            await handlers.mark_paid_by_memo(conn, memo)   # ops probe flips to 'expired'
            out = await self.mod.dispatch(conn, _event(memo=memo, amount_total=300))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["result"]["success"], out)
        self.assertEqual(balance, 300)


if __name__ == "__main__":
    unittest.main()
