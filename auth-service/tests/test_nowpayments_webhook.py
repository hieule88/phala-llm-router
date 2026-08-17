"""Tests for the NOWPayments IPN webhook.

Signature verification is exercised by generating the exact HMAC-SHA512
NOWPayments would send (canonical JSON, sorted keys) and feeding it in.

Run from `phala-TEE/auth-service/`:
    python -m unittest tests.test_nowpayments_webhook -v
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


IPN_SECRET = "test_ipn_secret_" + "b" * 32


def _sign_bytes(body: bytes) -> str:
    """Sign the EXACT bytes, the way NOWPayments does (HMAC over the raw body)."""
    return hmac.new(IPN_SECRET.encode(), body, hashlib.sha512).hexdigest()


def _sign(payload: dict) -> tuple[bytes, str]:
    # The wire body can be any encoding NOWPayments chooses; the handler HMACs
    # whatever raw bytes arrive, so the test signs the exact bytes it will send.
    body = json.dumps(payload, separators=(",", ":")).encode()
    return body, _sign_bytes(body)


def _payload(
    payment_status: str = "finished",
    order_id: str = "identity:1",
    price_amount: float = 10.0,
    price_currency: str = "usd",
    payment_id: int = 5245185943,
) -> dict:
    return {
        "payment_id": payment_id,
        "payment_status": payment_status,
        "pay_address": "0x1234567890abcdef",
        "price_amount": price_amount,
        "price_currency": price_currency,
        "pay_amount": 0.005,
        "pay_currency": "eth",
        "order_id": order_id,
        "order_description": "1000 credits for identity 1",
        "purchase_id": "purch_1",
        "created_at": "2026-07-08T09:00:00Z",
        "updated_at": "2026-07-08T09:15:00Z",
        "outcome_amount": 0.005,
        "outcome_currency": "eth",
    }


class SetupMixin:
    @classmethod
    def setUpClass(cls):
        os.environ["NOWPAYMENTS_IPN_SECRET"] = IPN_SECRET
        os.environ["NOWPAYMENTS_CENTS_PER_CREDIT"] = "1"
        import importlib
        from app import nowpayments_webhook  # noqa: F401
        importlib.reload(nowpayments_webhook)
        cls.mod = nowpayments_webhook


class SignatureVerifyTest(SetupMixin, unittest.TestCase):
    def test_missing_signature_header_400s(self):
        body, _ = _sign(_payload())
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(body, None)
        self.assertEqual(cm.exception.status_code, 400)

    def test_bad_signature_401s(self):
        body, _ = _sign(_payload())
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(body, "deadbeef" * 16)
        self.assertEqual(cm.exception.status_code, 401)

    def test_valid_signature_parses(self):
        body, sig = _sign(_payload())
        payload = self.mod.verify_and_parse(body, sig)
        self.assertEqual(payload["payment_status"], "finished")

    def test_verifies_raw_body_verbatim_unsorted_with_slashes(self):
        # Regression: NOWPayments signs the RAW body it sends — unsorted keys,
        # whitespace, and unescaped slashes included. Re-serializing/sorting
        # (the old bug) would change the bytes and 401 a valid event.
        raw = b'{"payment_status": "finished", "order_id": "intent-abc/def", "pay_url": "https://x.io/p"}'
        payload = self.mod.verify_and_parse(raw, _sign_bytes(raw))
        self.assertEqual(payload["order_id"], "intent-abc/def")

    def test_valid_signature_with_wrong_body_bytes_fails(self):
        # If we tamper with the body after signing, verification must
        # fail — the signature is bound to the exact bytes.
        body, sig = _sign(_payload())
        tampered = body.replace(b'"finished"', b'"failed"')
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(tampered, sig)
        self.assertEqual(cm.exception.status_code, 401)

    def test_invalid_json_400s(self):
        sig = hmac.new(IPN_SECRET.encode(), b"not json", hashlib.sha512).hexdigest()
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.verify_and_parse(b"not json", sig)
        self.assertEqual(cm.exception.status_code, 400)


class DispatchTest(SetupMixin, unittest.TestCase):
    def _run(self, payload_overrides: dict | None = None):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                payload = _payload(**(payload_overrides or {}))
                return await self.mod.dispatch(conn, payload)
            finally:
                await conn.close()

        return run(go())

    def test_finished_credits_correct_amount(self):
        result = self._run({"order_id": "identity:1", "price_amount": 10.0})
        self.assertTrue(result["handled"])
        self.assertTrue(result["result"]["success"])
        self.assertEqual(result["result"]["balance"], 1000)  # $10 * 100 = 1000 credits

    def test_replay_deduplicates(self):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                payload = _payload(order_id="identity:1", payment_id=12345)
                r1 = await self.mod.dispatch(conn, payload)
                r2 = await self.mod.dispatch(conn, payload)
                return r1, r2
            finally:
                await conn.close()

        r1, r2 = run(go())
        self.assertEqual(r1["result"]["balance"], 1000)
        self.assertEqual(r2["result"]["balance"], 1000)
        self.assertTrue(r2["result"].get("deduplicated"))

    def test_waiting_status_is_acknowledged_not_credited(self):
        result = self._run({"payment_status": "waiting"})
        self.assertFalse(result["handled"])
        self.assertEqual(result["payment_status"], "waiting")

    def test_failed_status_is_acknowledged_not_credited(self):
        result = self._run({"payment_status": "failed"})
        self.assertFalse(result["handled"])
        self.assertEqual(result["payment_status"], "failed")

    def test_partially_paid_is_not_credited(self):
        # partially_paid means the user underpaid — refuse to credit.
        # If ops want to credit partial, do it manually via /v1/topup.
        result = self._run({"payment_status": "partially_paid"})
        self.assertFalse(result["handled"])

    def test_missing_order_id_400s(self):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self._run({"order_id": ""})
        self.assertEqual(cm.exception.status_code, 400)

    def test_malformed_order_id_400s(self):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self._run({"order_id": "user:1"})   # wrong prefix
        self.assertEqual(cm.exception.status_code, 400)

    def test_non_integer_identity_400s(self):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self._run({"order_id": "identity:not-a-number"})
        self.assertEqual(cm.exception.status_code, 400)

    def test_non_usd_currency_400s(self):
        # Store settings pin USD; anything else is a misconfiguration.
        with self.assertRaises(self.mod.WebhookError) as cm:
            self._run({"price_currency": "eur"})
        self.assertEqual(cm.exception.status_code, 400)

    def test_zero_amount_400s(self):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self._run({"price_amount": 0})
        self.assertEqual(cm.exception.status_code, 400)


class ExpiredIntentTrapTest(SetupMixin, unittest.TestCase):
    """H3 regression: an intent lazily flipped to 'expired' (by an ops probe
    or monitoring script) must still be payable when the provider's
    `finished` IPN arrives — the flip-then-IPN ordering used to swallow the
    payment forever while ACKing 200."""

    def _go(self):
        from app.db import init_db
        from app import handlers

        async def scenario():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="nowpayments")
                memo = intent["memo"]
                # Force the TTL into the past, then poke it WITHOUT
                # allow_expired — the lazy sweep flips the row to 'expired'.
                await conn.execute(
                    "UPDATE payment_intents SET expires_at = "
                    "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?", (memo,))
                await conn.commit()
                probe = await handlers.mark_paid_by_memo(conn, memo)
                # The late IPN lands after the flip.
                ipn = await self.mod.dispatch(conn, _payload(
                    order_id=memo, price_amount=3.0, payment_id=777))
                cur = await conn.execute(
                    "SELECT status FROM payment_intents WHERE memo = ?", (memo,))
                status = (await cur.fetchone())[0]
                cur = await conn.execute(
                    "SELECT balance FROM balances WHERE identity_id = 1")
                balance = (await cur.fetchone())[0]
                return probe, ipn, status, balance
            finally:
                await conn.close()

        return run(scenario())

    def test_late_ipn_still_credits_a_flipped_expired_intent(self):
        probe, ipn, status, balance = self._go()
        self.assertFalse(probe["success"])                 # the probe still refuses
        self.assertIn("expired", probe["error"])
        self.assertTrue(ipn["result"]["success"], ipn)     # the IPN pays anyway
        self.assertEqual(status, "paid")
        self.assertEqual(balance, 300)                     # intent's ORIGINAL credits

    def test_replayed_late_ipn_deduplicates(self):
        from app.db import init_db
        from app import handlers

        async def scenario():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="nowpayments")
                memo = intent["memo"]
                await conn.execute(
                    "UPDATE payment_intents SET expires_at = "
                    "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?", (memo,))
                await conn.commit()
                await handlers.mark_paid_by_memo(conn, memo)     # flip
                p = _payload(order_id=memo, price_amount=3.0, payment_id=778)
                r1 = await self.mod.dispatch(conn, p)
                r2 = await self.mod.dispatch(conn, p)
                cur = await conn.execute(
                    "SELECT balance FROM balances WHERE identity_id = 1")
                return r1, r2, (await cur.fetchone())[0]
            finally:
                await conn.close()

        r1, r2, balance = run(scenario())
        self.assertTrue(r1["result"]["success"])
        self.assertTrue(r2["result"].get("deduplicated"))
        self.assertEqual(balance, 300)                     # credited exactly once

    def test_cancelled_intent_is_still_refused(self):
        # 'cancelled' is an explicit operator verdict, not a TTL accident —
        # allow_expired must not override it. The 500-ack + ERROR log make
        # the arriving money visible instead of silently credited.
        from app.db import init_db
        from app import handlers

        async def scenario():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="nowpayments")
                memo = intent["memo"]
                await handlers.cancel_intent_by_memo(conn, memo)
                return await self.mod.dispatch(conn, _payload(
                    order_id=memo, price_amount=3.0, payment_id=779))
            finally:
                await conn.close()

        ipn = run(scenario())
        self.assertFalse(ipn["result"]["success"])
        self.assertIn("cancelled", ipn["result"]["error"])


class PricingTest(SetupMixin, unittest.TestCase):
    def test_price_rounds_correctly(self):
        # $10.00 → 1000 cents → 1000 credits at 1 cent/credit.
        self.assertEqual(self.mod._usd_to_credits(10.00, "usd"), 1000)
        # $10.99 → 1099 cents → 1099 credits.
        self.assertEqual(self.mod._usd_to_credits(10.99, "usd"), 1099)
        # $0.006 → 0.6 cents → rounds to 1 cent → 1 credit.
        self.assertEqual(self.mod._usd_to_credits(0.006, "usd"), 1)
        # $0.005 lands exactly on the boundary — Python's banker's rounding
        # sends it to the nearest even (0) → refuse. Documented behaviour;
        # users can't reasonably pay in sub-cent increments anyway.
        with self.assertRaises(self.mod.WebhookError):
            self.mod._usd_to_credits(0.005, "usd")
        # $0.001 → 0.1 cents → rounds to 0 → refuse.
        with self.assertRaises(self.mod.WebhookError):
            self.mod._usd_to_credits(0.001, "usd")


if __name__ == "__main__":
    unittest.main()
