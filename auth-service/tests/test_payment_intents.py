"""Tests for the provider-agnostic payment_intents layer.

Run from `phala-TEE/auth-service/`:
    python -m unittest tests.test_payment_intents -v
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import handlers  # noqa: E402
from app.db import init_db  # noqa: E402


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class CreateIntentTest(unittest.TestCase):
    def test_create_returns_unique_memo(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                r1 = await handlers.create_intent(conn, ident, credits=100)
                r2 = await handlers.create_intent(conn, ident, credits=100)
                self.assertTrue(r1["success"])
                self.assertTrue(r2["success"])
                self.assertNotEqual(r1["memo"], r2["memo"])
                self.assertTrue(r1["memo"].startswith("intent-"))
            finally:
                await conn.close()
        run(go())

    def test_rejects_zero_credits(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                r = await handlers.create_intent(conn, ident, credits=0)
                self.assertFalse(r["success"])
            finally:
                await conn.close()
        run(go())

    def test_rejects_unknown_identity(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.create_intent(conn, 999, credits=10)
                self.assertFalse(r["success"])
                self.assertIn("not found", r["error"])
            finally:
                await conn.close()
        run(go())


class MarkPaidTest(unittest.TestCase):
    def test_full_flow_credits_balance(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(
                    conn, ident, credits=100,
                )
                self.assertEqual((await handlers.get_balance(conn, ident))["balance"], 0)

                result = await handlers.mark_paid_by_memo(
                    conn, intent["memo"], provider_ref="bank_tx_123",
                )
                self.assertTrue(result["success"])
                self.assertEqual(result["status"], "paid")
                self.assertEqual(result["balance"], 100)
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 100,
                )
            finally:
                await conn.close()
        run(go())

    def test_replay_is_idempotent(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(
                    conn, ident, credits=100,
                )
                r1 = await handlers.mark_paid_by_memo(conn, intent["memo"])
                r2 = await handlers.mark_paid_by_memo(conn, intent["memo"])
                self.assertTrue(r1["success"])
                self.assertTrue(r2["success"])
                self.assertTrue(r2.get("deduplicated"))
                # Balance stays at 100 (not 200) after replay.
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 100,
                )
            finally:
                await conn.close()
        run(go())

    def test_unknown_memo_returns_not_found(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.mark_paid_by_memo(conn, "intent-does-not-exist")
                self.assertFalse(r["success"])
                self.assertIn("not found", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_underpayment_refused(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(conn, ident, credits=100)
                # Intent expects amount_cents = 100 (server-derived from
                # credits × CENTS_PER_CREDIT). Caller supplies 50 → refuse.
                r = await handlers.mark_paid_by_memo(
                    conn, intent["memo"], actual_amount_cents=50,
                )
                self.assertFalse(r["success"])
                self.assertIn("underpaid", r["error"])
                # Balance untouched.
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 0,
                )
                # Intent still pending.
                intent2 = await handlers.get_intent_by_memo(conn, intent["memo"])
                self.assertEqual(intent2["status"], "pending")
            finally:
                await conn.close()
        run(go())

    def test_exact_payment_accepted(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(conn, ident, credits=100)
                r = await handlers.mark_paid_by_memo(
                    conn, intent["memo"],
                    actual_amount_cents=intent["amount_cents"],
                )
                self.assertTrue(r["success"])
            finally:
                await conn.close()
        run(go())

    def test_overpayment_accepted(self):
        # User paid more than expected — credit exactly what the intent
        # promised. Extra amount is the operator's problem.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(conn, ident, credits=100)
                r = await handlers.mark_paid_by_memo(
                    conn, intent["memo"],
                    actual_amount_cents=intent["amount_cents"] * 10,
                )
                self.assertTrue(r["success"])
                # Still 100 credits.
                self.assertEqual(r["balance"], 100)
            finally:
                await conn.close()
        run(go())


class CancelIntentTest(unittest.TestCase):
    def test_cancel_pending_intent(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(
                    conn, ident, credits=100,
                )
                r = await handlers.cancel_intent_by_memo(conn, intent["memo"])
                self.assertTrue(r["success"])
                self.assertEqual(r["status"], "cancelled")
                # Refuse to cancel again.
                r2 = await handlers.cancel_intent_by_memo(conn, intent["memo"])
                self.assertFalse(r2["success"])
            finally:
                await conn.close()
        run(go())

    def test_cannot_mark_paid_after_cancel(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(
                    conn, ident, credits=100,
                )
                await handlers.cancel_intent_by_memo(conn, intent["memo"])
                r = await handlers.mark_paid_by_memo(conn, intent["memo"])
                self.assertFalse(r["success"])
                self.assertIn("cancelled", r["error"])
            finally:
                await conn.close()
        run(go())


class GetIntentTest(unittest.TestCase):
    def test_unknown_memo_returns_none(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.get_intent_by_memo(conn, "intent-nope")
                self.assertIsNone(r)
            finally:
                await conn.close()
        run(go())

    def test_returns_full_state_after_mark_paid(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                intent = await handlers.create_intent(
                    conn, ident, credits=100, provider="manual",
                )
                await handlers.mark_paid_by_memo(
                    conn, intent["memo"], provider_ref="bank_tx_999",
                )
                state = await handlers.get_intent_by_memo(conn, intent["memo"])
                self.assertEqual(state["status"], "paid")
                self.assertEqual(state["provider_ref"], "bank_tx_999")
                self.assertIsNotNone(state["paid_at"])
            finally:
                await conn.close()
        run(go())


if __name__ == "__main__":
    unittest.main()
