"""Tests for token-based billing: variable-amount consume (hold),
/v1/settle, refund-by-amount, and the one-shot credit→millicredit rescale.

Run from `auth-service/`:
    python -m unittest tests.test_settle -v

Each test gets its own in-memory SQLite DB so they cannot interfere; the
rescale tests use a temp file DB because they need to close and re-open it.
"""

import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import handlers  # noqa: E402
from app.db import init_db, LEDGER_UNIT  # noqa: E402

MC = handlers.MC_PER_CREDIT  # 1000


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _funded_identity(conn, key="k", credits=10):
    ident = await handlers.create_identity(conn, "api_key", key)
    await handlers.topup(conn, ident, credits * MC, source=f"test-{key}")
    return ident


class ConsumeAmountTest(unittest.TestCase):
    """consume(amount=N) holds exactly N mc and requires full coverage."""

    def test_default_amount_is_legacy_flat_rate(self):
        # Backward compatibility: the deployed Edge / TEE prover send no
        # `amount` and must debit exactly the old 1 credit (= 1000 mc).
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=5)
                r = await handlers.consume(conn, "api_key", "k")
                self.assertTrue(r["success"])
                self.assertEqual(r["amount"], 1 * MC)
                self.assertEqual(r["balance"], 4 * MC)
                self.assertEqual(r["unit"], "millicredit")
            finally:
                await conn.close()
        run(go())

    def test_explicit_amount_debits_that_amount(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=10)
                r = await handlers.consume(conn, "api_key", "k", amount=721)
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 10 * MC - 721)
            finally:
                await conn.close()
        run(go())

    def test_hold_must_be_fully_covered(self):
        # balance 500 mc, hold 721 mc → denied, with actionable numbers.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 500, source="t")
                r = await handlers.consume(conn, "api_key", "k", amount=721)
                self.assertFalse(r["success"])
                self.assertIn("insufficient", r["error"])
                self.assertEqual(r["required_mc"], 721)
                self.assertEqual(r["balance_mc"], 500)
                # Balance untouched by the failed hold.
                bal = await handlers.get_balance(conn, ident)
                self.assertEqual(bal["balance"], 500)
            finally:
                await conn.close()
        run(go())

    def test_exact_balance_is_spendable(self):
        # `balance >= amount` must let the last mc be spent (no off-by-one).
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 721, source="t")
                r = await handlers.consume(conn, "api_key", "k", amount=721)
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 0)
            finally:
                await conn.close()
        run(go())

    def test_amount_cap_enforced(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=1000)
                r = await handlers.consume(
                    conn, "api_key", "k", amount=handlers.CONSUME_MAX_MC + 1,
                )
                self.assertFalse(r["success"])
                self.assertIn("amount", r["error"])
                r0 = await handlers.consume(conn, "api_key", "k", amount=0)
                self.assertFalse(r0["success"])
                rn = await handlers.consume(conn, "api_key", "k", amount=-5)
                self.assertFalse(rn["success"])
            finally:
                await conn.close()
        run(go())

    def test_usage_log_records_held_amount(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                await handlers.consume(conn, "api_key", "k",
                                       amount=250, request_id="req-9")
                cur = await conn.execute(
                    "SELECT operation, delta, balance_after FROM usage_log "
                    "WHERE identity_id=? AND operation='prove'", (ident,),
                )
                op, delta, after = await cur.fetchone()
                self.assertEqual(delta, -250)
                self.assertEqual(after, 10 * MC - 250)
            finally:
                await conn.close()
        run(go())


class SettleTest(unittest.TestCase):
    """settle() converts a hold into the final charge exactly once."""

    def test_settle_down_returns_difference(self):
        # Hold 1000, actual 128 → 872 back.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                s = await handlers.settle(conn, "api_key", "k",
                                          c["debit_token"], final_mc=128,
                                          note="in=1012 out=486")
                self.assertTrue(s["success"])
                self.assertEqual(s["held_mc"], 1000)
                self.assertEqual(s["final_mc"], 128)
                self.assertEqual(s["delta_mc"], 872)
                self.assertEqual(s["balance"], 10 * MC - 128)
            finally:
                await conn.close()
        run(go())

    def test_settle_up_charges_extra(self):
        # Hold 1000, actual 3600 (estimate ran low) → extra 2600 debited.
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                s = await handlers.settle(conn, "api_key", "k",
                                          c["debit_token"], final_mc=3600)
                self.assertTrue(s["success"])
                self.assertEqual(s["delta_mc"], -2600)
                self.assertEqual(s["balance"], 10 * MC - 3600)
            finally:
                await conn.close()
        run(go())

    def test_settle_up_may_go_negative_then_consume_blocks(self):
        # Low estimate on a nearly-empty balance: settle records the true
        # cost (negative balance), and the next hold is refused until topup.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 1000, source="t")
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                s = await handlers.settle(conn, "api_key", "k",
                                          c["debit_token"], final_mc=3600)
                self.assertTrue(s["success"])
                self.assertEqual(s["balance"], -2600)
                nxt = await handlers.consume(conn, "api_key", "k", amount=1)
                self.assertFalse(nxt["success"])
                self.assertIn("insufficient", nxt["error"])
                # Topping up past zero unblocks.
                await handlers.topup(conn, ident, 3000, source="t2")
                ok = await handlers.consume(conn, "api_key", "k", amount=100)
                self.assertTrue(ok["success"])
                self.assertEqual(ok["balance"], -2600 + 3000 - 100)
            finally:
                await conn.close()
        run(go())

    def test_settle_replay_same_amount_is_idempotent(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                await handlers.settle(conn, "api_key", "k",
                                      c["debit_token"], final_mc=128)
                s2 = await handlers.settle(conn, "api_key", "k",
                                           c["debit_token"], final_mc=128)
                self.assertTrue(s2["success"])
                self.assertTrue(s2.get("deduplicated"))
                # Balance unchanged by the replay.
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"],
                    10 * MC - 128,
                )
            finally:
                await conn.close()
        run(go())

    def test_settle_replay_different_amount_rejected(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                await handlers.settle(conn, "api_key", "k",
                                      c["debit_token"], final_mc=128)
                s2 = await handlers.settle(conn, "api_key", "k",
                                           c["debit_token"], final_mc=999)
                self.assertFalse(s2["success"])
                self.assertIn("different amount", s2["error"])
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"],
                    10 * MC - 128,
                )
            finally:
                await conn.close()
        run(go())

    def test_settle_after_refund_rejected(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                await handlers.refund(conn, "api_key", "k",
                                      debit_token=c["debit_token"])
                s = await handlers.settle(conn, "api_key", "k",
                                          c["debit_token"], final_mc=128)
                self.assertFalse(s["success"])
                self.assertIn("refunded", s["error"])
                # Full hold stays returned.
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 10 * MC,
                )
            finally:
                await conn.close()
        run(go())

    def test_refund_after_settle_rejected(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                await handlers.settle(conn, "api_key", "k",
                                      c["debit_token"], final_mc=128)
                r = await handlers.refund(conn, "api_key", "k",
                                          debit_token=c["debit_token"])
                self.assertFalse(r["success"])
                self.assertIn("settled", r["error"])
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"],
                    10 * MC - 128,
                )
            finally:
                await conn.close()
        run(go())

    def test_settle_unknown_token_rejected(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=10)
                s = await handlers.settle(conn, "api_key", "k",
                                          "never_issued", final_mc=1)
                self.assertFalse(s["success"])
                self.assertIn("no matching debit", s["error"])
            finally:
                await conn.close()
        run(go())

    def test_another_identity_token_cannot_settle_mine(self):
        # Token scoping matches refund: B presenting A's token must miss.
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, key="ka", credits=10)
                b = await _funded_identity(conn, key="kb", credits=10)
                ca = await handlers.consume(conn, "api_key", "ka",
                                            idempotency_key="x", amount=1000)
                s = await handlers.settle(conn, "api_key", "kb",
                                          ca["debit_token"], final_mc=1)
                self.assertFalse(s["success"])
                self.assertEqual(
                    (await handlers.get_balance(conn, b))["balance"], 10 * MC,
                )
            finally:
                await conn.close()
        run(go())

    def test_deduplicated_consume_cannot_settle(self):
        # A replay got no token → it can't settle (or re-price) the
        # original cycle's work. Mirrors the refund capability rule.
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=10)
                first = await handlers.consume(conn, "api_key", "k",
                                               idempotency_key="same",
                                               amount=1000)
                replay = await handlers.consume(conn, "api_key", "k",
                                                idempotency_key="same",
                                                amount=1000)
                self.assertTrue(replay.get("deduplicated"))
                self.assertIsNone(replay.get("debit_token"))
                # The ORIGINAL token still settles fine.
                s = await handlers.settle(conn, "api_key", "k",
                                          first["debit_token"], final_mc=128)
                self.assertTrue(s["success"])
            finally:
                await conn.close()
        run(go())

    def test_settle_validates_final_mc_bounds(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                bad = await handlers.settle(conn, "api_key", "k",
                                            c["debit_token"], final_mc=0)
                self.assertFalse(bad["success"])
                huge = await handlers.settle(
                    conn, "api_key", "k", c["debit_token"],
                    final_mc=handlers.SETTLE_MAX_MC + 1,
                )
                self.assertFalse(huge["success"])
            finally:
                await conn.close()
        run(go())

    def test_new_cycle_after_refund_gets_fresh_settle_state(self):
        # consume→refund→consume (same idempotency key reactivates the row)
        # → settle of cycle 2 must work and price cycle 2's hold, and the
        # reactivation must have cleared cycle 1's settle columns.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c1 = await handlers.consume(conn, "api_key", "k",
                                            idempotency_key="i", amount=1000)
                await handlers.refund(conn, "api_key", "k",
                                      debit_token=c1["debit_token"])
                c2 = await handlers.consume(conn, "api_key", "k",
                                            idempotency_key="i", amount=700)
                s = await handlers.settle(conn, "api_key", "k",
                                          c2["debit_token"], final_mc=100)
                self.assertTrue(s["success"])
                self.assertEqual(s["held_mc"], 700)
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"],
                    10 * MC - 100,
                )
            finally:
                await conn.close()
        run(go())

    def test_settle_writes_usage_log_with_note(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=1000)
                await handlers.settle(conn, "api_key", "k",
                                      c["debit_token"], final_mc=128,
                                      request_id="req-7",
                                      note="in=1012 out=486 receipt=rcpt_9")
                cur = await conn.execute(
                    "SELECT delta, balance_after, request_id, note "
                    "FROM usage_log WHERE identity_id=? AND operation='settle'",
                    (ident,),
                )
                delta, after, req_id, note = await cur.fetchone()
                self.assertEqual(delta, 872)
                self.assertEqual(after, 10 * MC - 128)
                self.assertEqual(req_id, "req-7")
                self.assertIn("held=1000", note)
                self.assertIn("final=128", note)
                self.assertIn("receipt=rcpt_9", note)
            finally:
                await conn.close()
        run(go())


class RefundAmountTest(unittest.TestCase):
    """refund() must reverse the held amount, not a hardcoded 1."""

    def test_refund_reverses_variable_hold(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await _funded_identity(conn, credits=10)
                c = await handlers.consume(conn, "api_key", "k",
                                           idempotency_key="i", amount=4321)
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"],
                    10 * MC - 4321,
                )
                r = await handlers.refund(conn, "api_key", "k",
                                          debit_token=c["debit_token"])
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 10 * MC)
            finally:
                await conn.close()
        run(go())


class UnitRescaleTest(unittest.TestCase):
    """The one-shot credit→millicredit rescale on a legacy DB."""

    @staticmethod
    async def _make_legacy_db(path):
        """Build a DB with credit-unit data, then strip the ledger_unit
        marker so it looks exactly like a pre-migration deploy."""
        conn = await init_db(path)
        ident = await handlers.create_identity(conn, "api_key", "legacy")
        # Simulate legacy activity in CREDIT units.
        await handlers.topup(conn, ident, 10, source="legacy-topup")
        c = await handlers.consume(conn, "api_key", "legacy",
                                   idempotency_key="old", amount=1)
        intent = await handlers.create_intent(conn, ident, credits=100)
        # Undo the mc conversions this build already applied, leaving pure
        # credit-unit rows, then remove the guard row.
        await conn.execute("UPDATE payment_intents SET credits = credits / 1000")
        await conn.execute("UPDATE consume_dedup SET amount_mc = NULL")
        await conn.execute("DELETE FROM schema_meta WHERE key='ledger_unit'")
        await conn.commit()
        await conn.close()
        return ident, c["debit_token"], intent["memo"]

    def test_rescale_multiplies_everything_once(self):
        async def go():
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "auth.db")
                ident, token, memo = await self._make_legacy_db(path)

                # Re-open: rescale fires exactly once.
                conn = await init_db(path)
                try:
                    bal = await handlers.get_balance(conn, ident)
                    self.assertEqual(bal["balance"], 9 * MC)  # (10-1) credits

                    cur = await conn.execute(
                        "SELECT SUM(delta) FROM usage_log WHERE identity_id=?",
                        (ident,),
                    )
                    total = (await cur.fetchone())[0]
                    # Ledger reconciles: sum of deltas == live balance.
                    self.assertEqual(total, bal["balance"])

                    cur = await conn.execute(
                        "SELECT amount_mc, balance_after FROM consume_dedup "
                        "WHERE identity_id=?", (ident,),
                    )
                    amount_mc, bal_after = await cur.fetchone()
                    self.assertEqual(amount_mc, 1 * MC)      # backfilled
                    self.assertEqual(bal_after, 9 * MC)

                    cur = await conn.execute(
                        "SELECT amount FROM topups WHERE identity_id=?", (ident,),
                    )
                    self.assertEqual((await cur.fetchone())[0], 10 * MC)

                    intent = await handlers.get_intent_by_memo(conn, memo)
                    self.assertEqual(intent["credits_mc"], 100 * MC)
                    self.assertEqual(intent["credits"], 100)   # display unchanged
                    self.assertEqual(intent["amount_cents"], 100)  # money untouched
                finally:
                    await conn.close()
        run(go())

    def test_rescale_is_one_shot(self):
        async def go():
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "auth.db")
                ident, _, _ = await self._make_legacy_db(path)
                conn = await init_db(path)
                await conn.close()
                # Third open: values must NOT multiply again.
                conn = await init_db(path)
                try:
                    bal = await handlers.get_balance(conn, ident)
                    self.assertEqual(bal["balance"], 9 * MC)
                    cur = await conn.execute(
                        "SELECT value FROM schema_meta WHERE key='ledger_unit'",
                    )
                    self.assertEqual((await cur.fetchone())[0], LEDGER_UNIT)
                finally:
                    await conn.close()
        run(go())

    def test_legacy_refund_reverses_backfilled_credit(self):
        # A debit held BEFORE the migration must refund exactly the old
        # 1 credit (=1000 mc) after it.
        async def go():
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "auth.db")
                ident, token, _ = await self._make_legacy_db(path)
                conn = await init_db(path)
                try:
                    r = await handlers.refund(conn, "api_key", "legacy",
                                              debit_token=token)
                    self.assertTrue(r["success"])
                    self.assertEqual(r["balance"], 10 * MC)
                finally:
                    await conn.close()
        run(go())

    def test_unknown_ledger_unit_refuses_to_start(self):
        async def go():
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "auth.db")
                conn = await init_db(path)
                await conn.execute(
                    "UPDATE schema_meta SET value='femtocredit' "
                    "WHERE key='ledger_unit'",
                )
                await conn.commit()
                await conn.close()
                with self.assertRaises(RuntimeError):
                    await init_db(path)
        run(go())

    def test_fresh_db_starts_in_millicredit_with_no_rescale(self):
        # A brand-new DB gets the marker immediately; nothing to multiply.
        async def go():
            conn = await init_db(":memory:")
            try:
                cur = await conn.execute(
                    "SELECT value FROM schema_meta WHERE key='ledger_unit'",
                )
                self.assertEqual((await cur.fetchone())[0], LEDGER_UNIT)
            finally:
                await conn.close()
        run(go())


if __name__ == "__main__":
    unittest.main()
