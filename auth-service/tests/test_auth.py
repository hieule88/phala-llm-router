"""Tests for the auth service.

Run from `phala-TEE/auth-service/`:
    python -m unittest tests.test_auth -v

Each test gets its own in-memory SQLite DB so they cannot interfere.
"""

import asyncio
import os
import sys
import unittest

# Allow `python -m unittest tests.test_auth` from the auth-service dir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import handlers  # noqa: E402
from app.db import init_db  # noqa: E402
from app.tier_limit import TierRateLimiter  # noqa: E402
from app.tiers import TIERS, get_tier  # noqa: E402


def run(coro):
    """Run a coroutine on a fresh event loop and clean up.

    Using a fresh loop per test (rather than asyncio.run, which can
    deprecation-warn on nested use) keeps tests hermetic.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ─── F3 — handlers ────────────────────────────────────────────────────────


class CreateAndLookupTest(unittest.TestCase):
    def test_create_returns_identity_id(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_abc")
                self.assertIsInstance(ident, int)
                self.assertGreater(ident, 0)

                # Idempotency: same credential → same id
                ident2 = await handlers.create_identity(conn, "api_key", "hash_abc")
                self.assertEqual(ident, ident2)
            finally:
                await conn.close()
        run(go())

    def test_lookup_returns_identity_for_known_credential(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_xyz")
                found = await handlers.lookup_identity(conn, "api_key", "hash_xyz")
                self.assertEqual(found, ident)
            finally:
                await conn.close()
        run(go())

    def test_lookup_returns_none_for_unknown(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                found = await handlers.lookup_identity(conn, "api_key", "nope")
                self.assertIsNone(found)
            finally:
                await conn.close()
        run(go())


class ValidateTest(unittest.TestCase):
    def test_unknown_credential_returns_invalid(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.validate(conn, "api_key", "nope")
                self.assertFalse(r["valid"])
                self.assertIn("not found", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_zero_balance_returns_invalid(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                # Default balance is 0
                r = await handlers.validate(conn, "api_key", "hash_a")
                self.assertFalse(r["valid"])
                self.assertIn("insufficient", r["error"])
                # A front still learns WHO the key is, so it can serve
                # receipts for already-paid requests.
                self.assertEqual(r["identity_id"], ident)
            finally:
                await conn.close()
        run(go())

    def test_positive_balance_returns_valid(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_a")
                await handlers.topup(conn, ident, 100, source="test")
                r = await handlers.validate(conn, "api_key", "hash_a")
                self.assertTrue(r["valid"])
                self.assertEqual(r["balance"], 100)
                self.assertEqual(r["tier"], "free")
                self.assertEqual(r["identity_id"], ident)
            finally:
                await conn.close()
        run(go())


class ConsumeDedupTtlTest(unittest.TestCase):
    """The idempotency replay is a retry-protection, not a season ticket:
    it must expire after CONSUME_DEDUP_TTL_SECONDS."""

    def test_replay_within_ttl_is_free(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 5, source="test")
                r1 = await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                r2 = await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                self.assertEqual(r1["balance"], 4)
                self.assertTrue(r2.get("deduplicated"))
                self.assertEqual(r2["balance"], 4)      # no second debit
            finally:
                await conn.close()
        run(go())

    def test_replay_after_ttl_debits_again(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 5, source="test")
                await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                # Age the dedup row past the replay window.
                await conn.execute(
                    "UPDATE consume_dedup SET created_at = datetime('now', ?)",
                    (f"-{handlers.CONSUME_DEDUP_TTL_SECONDS + 60} seconds",),
                )
                await conn.commit()
                r2 = await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                self.assertTrue(r2["success"])
                self.assertFalse(r2.get("deduplicated"))
                self.assertEqual(r2["balance"], 3)      # debited again
                # And the refreshed row replays free again within the new window.
                r3 = await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                self.assertTrue(r3.get("deduplicated"))
                self.assertEqual(r3["balance"], 3)
            finally:
                await conn.close()
        run(go())


class ConsumeTest(unittest.TestCase):
    def test_consume_decrements_by_one(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 5, source="test")
                r = await handlers.consume(conn, "api_key", "k")
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 4)
            finally:
                await conn.close()
        run(go())

    def test_consume_until_empty(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 3, source="test")
                for expected in (2, 1, 0):
                    r = await handlers.consume(conn, "api_key", "k")
                    self.assertTrue(r["success"])
                    self.assertEqual(r["balance"], expected)
                # 4th consume rejected
                r = await handlers.consume(conn, "api_key", "k")
                self.assertFalse(r["success"])
                self.assertIn("insufficient", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_consume_unknown_credential(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.consume(conn, "api_key", "nope")
                self.assertFalse(r["success"])
            finally:
                await conn.close()
        run(go())

    def test_consume_writes_usage_log(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                await handlers.consume(conn, "api_key", "k", request_id="req-001")

                cur = await conn.execute(
                    "SELECT operation, delta, request_id, balance_after "
                    "FROM usage_log WHERE identity_id=? ORDER BY id",
                    (ident,),
                )
                rows = await cur.fetchall()
                # 1 topup + 1 prove
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0][0], "topup")
                self.assertEqual(rows[0][1], 10)
                self.assertEqual(rows[1][0], "prove")
                self.assertEqual(rows[1][1], -1)
                self.assertEqual(rows[1][2], "req-001")
                self.assertEqual(rows[1][3], 9)
            finally:
                await conn.close()
        run(go())


class TopupTest(unittest.TestCase):
    def test_topup_positive_amount(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                r = await handlers.topup(conn, ident, 500, source="nowpayments:x")
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 500)
            finally:
                await conn.close()
        run(go())

    def test_topup_rejects_zero_or_negative(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                r0 = await handlers.topup(conn, ident, 0, source="x")
                self.assertFalse(r0["success"])
                rn = await handlers.topup(conn, ident, -5, source="x")
                self.assertFalse(rn["success"])
            finally:
                await conn.close()
        run(go())

    def test_topup_unknown_identity(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.topup(conn, 999, 10, source="x")
                self.assertFalse(r["success"])
            finally:
                await conn.close()
        run(go())


class RefundTest(unittest.TestCase):
    """A refund reverses the specific consume that minted its debit_token
    and lets the SAME request be retried without double-billing."""

    def test_refund_reverses_a_consume(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                c = await handlers.consume(conn, "api_key", "k", idempotency_key="idem_x")
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 9,
                )
                r = await handlers.refund(conn, "api_key", "k",
                                          debit_token=c["debit_token"],
                                          reason="upstream crash")
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 10)
            finally:
                await conn.close()
        run(go())

    def test_refund_is_idempotent(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                c = await handlers.consume(conn, "api_key", "k", idempotency_key="ix")
                await handlers.refund(conn, "api_key", "k", debit_token=c["debit_token"])
                r2 = await handlers.refund(conn, "api_key", "k", debit_token=c["debit_token"])
                self.assertTrue(r2["success"])
                self.assertTrue(r2.get("deduplicated"))
                # Still 10, not 11.
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 10,
                )
            finally:
                await conn.close()
        run(go())

    def test_refund_of_unknown_key_returns_error(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "k")
                r = await handlers.refund(conn, "api_key", "k",
                                          debit_token="never_issued")
                self.assertFalse(r["success"])
                self.assertIn("no matching debit", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_after_refund_same_key_can_debit_again(self):
        # The whole point: a client retrying the same prove after a
        # refund can debit again (the credit is available again).
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                c = await handlers.consume(conn, "api_key", "k", idempotency_key="i")
                await handlers.refund(conn, "api_key", "k", debit_token=c["debit_token"])
                r = await handlers.consume(conn, "api_key", "k", idempotency_key="i")
                self.assertTrue(r["success"])
                self.assertFalse(r.get("deduplicated"))
                self.assertEqual(r["balance"], 9)
            finally:
                await conn.close()
        run(go())

    def test_refund_cycle_2_refunds_the_second_debit(self):
        # Regression for A-HIGH-1: after consume→refund→consume→refund,
        # the second refund must actually credit back (not silently dedup
        # against the first cycle's refund marker).
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                # Cycle 1: consume then refund.
                c1 = await handlers.consume(conn, "api_key", "k", idempotency_key="k1")
                r1 = await handlers.refund(conn, "api_key", "k", debit_token=c1["debit_token"])
                self.assertTrue(r1["success"])
                self.assertFalse(r1.get("deduplicated"))
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 10,
                )
                # Cycle 2: same key, consume+refund again. Must credit back.
                c2 = await handlers.consume(conn, "api_key", "k", idempotency_key="k1")
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 9,
                )
                r2 = await handlers.refund(conn, "api_key", "k", debit_token=c2["debit_token"])
                self.assertTrue(r2["success"])
                self.assertFalse(r2.get("deduplicated"),
                                 "second cycle's refund was silently deduped")
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 10,
                )
            finally:
                await conn.close()
        run(go())


class RefundCapabilityTest(unittest.TestCase):
    """Regression for the credit-minting hole: a consume that was
    deduplicated spent nothing, so it must not be able to reverse the debit
    an earlier request made. Only the request that actually paid gets a
    debit_token, and a token dies once spent or superseded."""

    def test_deduplicated_consume_gets_no_token_and_cannot_mint(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 5, source="test")
                first = await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                self.assertEqual(first["balance"], 4)
                self.assertTrue(first.get("debit_token"))

                replay = await handlers.consume(conn, "api_key", "k", idempotency_key="same")
                self.assertTrue(replay.get("deduplicated"))
                # The replay debited nothing, so it holds no reversal capability.
                self.assertIsNone(replay.get("debit_token"))

                # With no token there is nothing to refund with; and the
                # idempotency key alone must not work as one.
                bad = await handlers.refund(conn, "api_key", "k", debit_token="same")
                self.assertFalse(bad["success"])
                self.assertEqual((await handlers.get_balance(conn, ident))["balance"], 4)
            finally:
                await conn.close()
        run(go())

    def test_spent_token_cannot_refund_twice_across_cycles(self):
        # Refund with cycle 1's token, debit again, then replay the OLD token:
        # it must not credit a second time (consume rotates the token).
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 5, source="test")
                c1 = await handlers.consume(conn, "api_key", "k", idempotency_key="i")
                await handlers.refund(conn, "api_key", "k", debit_token=c1["debit_token"])
                self.assertEqual((await handlers.get_balance(conn, ident))["balance"], 5)

                c2 = await handlers.consume(conn, "api_key", "k", idempotency_key="i")
                self.assertNotEqual(c1["debit_token"], c2["debit_token"])
                self.assertEqual((await handlers.get_balance(conn, ident))["balance"], 4)

                stale = await handlers.refund(conn, "api_key", "k",
                                              debit_token=c1["debit_token"])
                self.assertFalse(stale["success"])
                self.assertEqual((await handlers.get_balance(conn, ident))["balance"], 4)
            finally:
                await conn.close()
        run(go())

    def test_another_identity_token_cannot_refund_mine(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                a = await handlers.create_identity(conn, "api_key", "ka")
                b = await handlers.create_identity(conn, "api_key", "kb")
                # Distinct sources: `source` is UNIQUE (topup idempotency).
                await handlers.topup(conn, a, 5, source="test-a")
                await handlers.topup(conn, b, 5, source="test-b")
                ca = await handlers.consume(conn, "api_key", "ka", idempotency_key="x")
                # B presents A's token: scoped per identity, so it must miss.
                r = await handlers.refund(conn, "api_key", "kb",
                                          debit_token=ca["debit_token"])
                self.assertFalse(r["success"])
                self.assertEqual((await handlers.get_balance(conn, b))["balance"], 5)
            finally:
                await conn.close()
        run(go())


class ConsumeIdempotencyTest(unittest.TestCase):
    """Same idempotency_key on the same identity must debit exactly once,
    even under retries. Guards against network-drop double-debit."""

    def test_replay_returns_cached_balance_no_second_debit(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                r1 = await handlers.consume(conn, "api_key", "k",
                                            idempotency_key="idem_abc")
                r2 = await handlers.consume(conn, "api_key", "k",
                                            idempotency_key="idem_abc")
                self.assertTrue(r1["success"])
                self.assertTrue(r2["success"])
                self.assertEqual(r1["balance"], 9)
                self.assertEqual(r2["balance"], 9)
                self.assertTrue(r2.get("deduplicated"))
                # Real balance in the DB is 9 (single debit).
                self.assertEqual(
                    (await handlers.get_balance(conn, ident))["balance"], 9,
                )
            finally:
                await conn.close()
        run(go())

    def test_different_keys_debit_independently(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                await handlers.consume(conn, "api_key", "k", idempotency_key="a")
                r = await handlers.consume(conn, "api_key", "k", idempotency_key="b")
                self.assertTrue(r["success"])
                self.assertEqual(r["balance"], 8)
            finally:
                await conn.close()
        run(go())

    def test_missing_key_still_debits(self):
        # Backward compatibility: legacy client without idempotency_key
        # continues to work — dedup is opt-in per request.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="test")
                r1 = await handlers.consume(conn, "api_key", "k")
                r2 = await handlers.consume(conn, "api_key", "k")
                self.assertEqual(r1["balance"], 9)
                self.assertEqual(r2["balance"], 8)
            finally:
                await conn.close()
        run(go())

    def test_replay_across_identities_does_not_collide(self):
        # Same idempotency_key on DIFFERENT identities must NOT collide —
        # each identity has its own dedup namespace.
        async def go():
            conn = await init_db(":memory:")
            try:
                a = await handlers.create_identity(conn, "api_key", "ka")
                b = await handlers.create_identity(conn, "api_key", "kb")
                await handlers.topup(conn, a, 10, source="ta")
                await handlers.topup(conn, b, 10, source="tb")
                ra = await handlers.consume(conn, "api_key", "ka",
                                            idempotency_key="shared")
                rb = await handlers.consume(conn, "api_key", "kb",
                                            idempotency_key="shared")
                self.assertEqual(ra["balance"], 9)
                self.assertEqual(rb["balance"], 9)
                self.assertFalse(ra.get("deduplicated"))
                self.assertFalse(rb.get("deduplicated"))
            finally:
                await conn.close()
        run(go())

    def test_replay_after_balance_change_still_returns_cached(self):
        # Even if later topups change the balance, replaying the same
        # idempotency_key must return the balance AT DEBIT TIME —
        # anything else defeats the purpose of the dedup.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 10, source="t1")
                r1 = await handlers.consume(conn, "api_key", "k",
                                            idempotency_key="key")
                # Later topup — new balance is 15.
                await handlers.topup(conn, ident, 6, source="t2")
                r2 = await handlers.consume(conn, "api_key", "k",
                                            idempotency_key="key")
                self.assertEqual(r2["balance"], r1["balance"])  # 9 not 15
                self.assertTrue(r2["deduplicated"])
            finally:
                await conn.close()
        run(go())


class AtomicConsumeRaceTest(unittest.TestCase):
    """A balance of 1 consumed by N concurrent callers must yield exactly
    one success and N-1 rejections.

    Without the `balance > 0` predicate inside the UPDATE, this race could
    over-debit and leave balance negative. SQLite's serialised writer plus
    the predicate combine to make this safe.
    """

    def test_concurrent_consume_with_balance_one(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, 1, source="test")

                # Fire 10 concurrent consumes
                results = await asyncio.gather(*[
                    handlers.consume(conn, "api_key", "k")
                    for _ in range(10)
                ])
                successes = [r for r in results if r["success"]]
                failures = [r for r in results if not r["success"]]
                self.assertEqual(len(successes), 1,
                    f"exactly one success expected, got {len(successes)}")
                self.assertEqual(len(failures), 9)

                # Final balance is 0
                bal = await handlers.get_balance(conn, ident)
                self.assertEqual(bal["balance"], 0)
            finally:
                await conn.close()
        run(go())

    def test_concurrent_consume_with_balance_n(self):
        """N concurrent consumes against a balance of N → all succeed,
        final balance 0. Validates we don't *under*-debit either.
        """
        async def go():
            conn = await init_db(":memory:")
            N = 20
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                await handlers.topup(conn, ident, N, source="test")
                results = await asyncio.gather(*[
                    handlers.consume(conn, "api_key", "k") for _ in range(N)
                ])
                self.assertTrue(all(r["success"] for r in results))
                bal = await handlers.get_balance(conn, ident)
                self.assertEqual(bal["balance"], 0)
            finally:
                await conn.close()
        run(go())


class CredentialTypeAllowlistTest(unittest.TestCase):
    """Regression: public identifiers (miden_wallet) MUST
    NOT authenticate a consume/validate. Otherwise anyone who knows the
    victim's public wallet address can drain their balance."""

    def test_validate_rejects_non_api_key_type(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "miden_wallet", "0xabc")
                await handlers.topup(conn, ident, 10, "test")
                r = await handlers.validate(conn, "miden_wallet", "0xabc")
                self.assertFalse(r["valid"])
                self.assertIn("credential not found", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_consume_rejects_non_api_key_type(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "miden_wallet", "wallet_x")
                await handlers.topup(conn, ident, 10, "test")
                r = await handlers.consume(conn, "miden_wallet", "wallet_x")
                self.assertFalse(r["success"])
                self.assertIn("credential not found", r["error"])
                # Balance untouched.
                bal = await handlers.get_balance(conn, ident)
                self.assertEqual(bal["balance"], 10)
            finally:
                await conn.close()
        run(go())


class TopupIdempotencyTest(unittest.TestCase):
    """Regression: payment webhooks retry aggressively. Two calls with the
    same source must credit exactly once."""

    def test_same_source_twice_only_credits_once(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "h")
                r1 = await handlers.topup(conn, ident, 100, "nowpayments:ABC")
                r2 = await handlers.topup(conn, ident, 100, "nowpayments:ABC")
                self.assertTrue(r1["success"])
                self.assertEqual(r1["balance"], 100)
                self.assertTrue(r2["success"])
                self.assertTrue(r2.get("deduplicated"))
                self.assertEqual(r2["balance"], 100)  # NOT 200
            finally:
                await conn.close()
        run(go())

    def test_different_source_credits_twice(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "h")
                await handlers.topup(conn, ident, 100, "src-a")
                r = await handlers.topup(conn, ident, 100, "src-b")
                self.assertEqual(r["balance"], 200)
            finally:
                await conn.close()
        run(go())


class CredentialRotationTest(unittest.TestCase):
    def test_add_credential_to_existing_identity(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_old")
                r = await handlers.add_credential(conn, ident, "api_key", "hash_new")
                self.assertTrue(r["success"])
                self.assertEqual(r["identity_id"], ident)
                # Both credentials resolve to the same identity.
                self.assertEqual(
                    await handlers.lookup_identity(conn, "api_key", "hash_old"), ident,
                )
                self.assertEqual(
                    await handlers.lookup_identity(conn, "api_key", "hash_new"), ident,
                )
            finally:
                await conn.close()
        run(go())

    def test_add_credential_rejects_unknown_identity(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                r = await handlers.add_credential(conn, 999, "api_key", "h")
                self.assertFalse(r["success"])
                self.assertIn("not found", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_add_credential_rejects_duplicate(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "h1")
                r = await handlers.add_credential(conn, ident, "api_key", "h1")
                self.assertFalse(r["success"])
                self.assertIn("already exists", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_revoke_credential_stops_lookup(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "hash_old")
                await handlers.add_credential(conn, ident, "api_key", "hash_new")

                # Revoke the old — lookup returns None; new still works.
                r = await handlers.revoke_credential(conn, "api_key", "hash_old")
                self.assertTrue(r["success"])
                self.assertIsNone(
                    await handlers.lookup_identity(conn, "api_key", "hash_old"),
                )
                self.assertEqual(
                    await handlers.lookup_identity(conn, "api_key", "hash_new"), ident,
                )
            finally:
                await conn.close()
        run(go())

    def test_revoke_twice_is_noop(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "h")
                await handlers.revoke_credential(conn, "api_key", "h")
                r = await handlers.revoke_credential(conn, "api_key", "h")
                self.assertFalse(r["success"])
                self.assertIn("not found or already revoked", r["error"])
            finally:
                await conn.close()
        run(go())

    def test_revoke_preserves_balance(self):
        # Revoking a credential must not touch the identity's balance —
        # rotation is a per-credential op, not a wallet wipe.
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "h1")
                await handlers.topup(conn, ident, 50, "test")
                await handlers.add_credential(conn, ident, "api_key", "h2")
                await handlers.revoke_credential(conn, "api_key", "h1")
                bal = await handlers.get_balance(conn, ident)
                self.assertEqual(bal["balance"], 50)
            finally:
                await conn.close()
        run(go())


class TierTest(unittest.TestCase):
    def test_set_tier_updates(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                ident = await handlers.create_identity(conn, "api_key", "k")
                r = await handlers.set_tier(conn, ident, "starter")
                self.assertTrue(r["success"])
                bal = await handlers.get_balance(conn, ident)
                self.assertEqual(bal["tier"], "starter")
            finally:
                await conn.close()
        run(go())

    def test_get_tier_unknown_falls_back_to_free(self):
        # Defensive: a misconfigured tier name returns the free tier,
        # NOT raises, so the rate limiter can never accidentally accept
        # an unbounded user.
        t = get_tier("nonexistent-tier-name")
        self.assertEqual(t.name, "free")


# ─── F5 — TierRateLimiter ─────────────────────────────────────────────────


class TierRateLimiterTest(unittest.TestCase):

    def test_free_tier_one_rps(self):
        async def go():
            limiter = TierRateLimiter(window_sec=1.0)
            # 1st request at t=0 allowed; 2nd at t=0.5 (still in window) rejected
            self.assertTrue(await limiter.check(1, "free", now=0.0))
            self.assertFalse(await limiter.check(1, "free", now=0.5))
            # After window slides past, allowed again
            self.assertTrue(await limiter.check(1, "free", now=1.1))
        run(go())

    def test_starter_tier_ten_rps(self):
        async def go():
            limiter = TierRateLimiter(window_sec=1.0)
            # 10 requests in same 1s window all allowed
            for i in range(10):
                ok = await limiter.check(2, "starter", now=0.1 * i)
                self.assertTrue(ok, f"request {i} should be allowed")
            # 11th rejected
            self.assertFalse(await limiter.check(2, "starter", now=0.95))
        run(go())

    def test_pro_tier_fifty_rps(self):
        async def go():
            limiter = TierRateLimiter(window_sec=1.0)
            for i in range(50):
                self.assertTrue(await limiter.check(3, "pro", now=0.01 * i))
            self.assertFalse(await limiter.check(3, "pro", now=0.5))
        run(go())

    def test_separate_identities_independent(self):
        async def go():
            limiter = TierRateLimiter(window_sec=1.0)
            # Two free-tier identities — one exhausts, the other still has slot
            self.assertTrue(await limiter.check(1, "free", now=0.0))
            self.assertFalse(await limiter.check(1, "free", now=0.5))
            # identity 2 unaffected
            self.assertTrue(await limiter.check(2, "free", now=0.5))
        run(go())

    def test_tier_change_takes_effect_immediately(self):
        """Upgrading tier mid-stream — the limit applied at each call is the
        tier the caller passes, so a starter upgrade is honored on the very
        next request.
        """
        async def go():
            limiter = TierRateLimiter(window_sec=1.0)
            # Free user exhausts their 1 rps
            self.assertTrue(await limiter.check(7, "free", now=0.0))
            self.assertFalse(await limiter.check(7, "free", now=0.5))
            # Upgrade — same identity_id, new tier param
            self.assertTrue(await limiter.check(7, "starter", now=0.5))
        run(go())

    def test_invalid_params_raise(self):
        with self.assertRaises(ValueError):
            TierRateLimiter(window_sec=0)
        with self.assertRaises(ValueError):
            TierRateLimiter(window_sec=1.0, max_keys=0)

    def test_max_keys_cap_enforced(self):
        async def go():
            limiter = TierRateLimiter(window_sec=3600, max_keys=5)
            limiter._sweep_every = 10_000   # disable opportunistic sweep
            for i in range(8):
                await limiter.check(i, "pro", now=float(i))
            self.assertEqual(len(limiter._buckets), 5,
                f"expected dict bounded at 5, got {len(limiter._buckets)}")
        run(go())


class NowpaymentsClientTest(unittest.TestCase):
    """Send-side (invoice creation) tests. Uses a mocked httpx.AsyncClient
    so no outbound calls happen — we exercise the shape of the request we
    would send, plus the response handling for the various failure modes
    NOWPayments can return.
    """

    def test_missing_api_key_raises_503(self):
        # Reload module state with an empty key to simulate an operator
        # who hasn't finished the send-side setup yet.
        async def go():
            from unittest.mock import patch
            from app import nowpayments_client
            with patch.object(nowpayments_client, "NOWPAYMENTS_API_KEY", ""):
                with self.assertRaises(nowpayments_client.NowpaymentsError) as ctx:
                    await nowpayments_client.create_invoice(
                        memo="intent-abc", amount_cents=100,
                    )
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertIn("NOWPAYMENTS_API_KEY", ctx.exception.detail)
        run(go())

    def test_negative_amount_raises_400(self):
        async def go():
            from unittest.mock import patch
            from app import nowpayments_client
            with patch.object(nowpayments_client, "NOWPAYMENTS_API_KEY", "fakekey"):
                with self.assertRaises(nowpayments_client.NowpaymentsError) as ctx:
                    await nowpayments_client.create_invoice(
                        memo="intent-abc", amount_cents=0,
                    )
                self.assertEqual(ctx.exception.status_code, 400)
        run(go())

    def test_happy_path_returns_url(self):
        async def go():
            from unittest.mock import AsyncMock, MagicMock, patch
            from app import nowpayments_client
            fake_response = MagicMock()
            fake_response.status_code = 200
            fake_response.json = MagicMock(return_value={
                "id": "5555555555",
                "invoice_url": "https://nowpayments.io/payment/?iid=5555",
                "expiration_estimate_date": "2026-08-01T00:00:00Z",
            })
            fake_client = AsyncMock()
            fake_client.__aenter__.return_value = fake_client
            fake_client.post = AsyncMock(return_value=fake_response)
            with patch.object(nowpayments_client, "NOWPAYMENTS_API_KEY", "fakekey"), \
                 patch.object(nowpayments_client.httpx, "AsyncClient",
                              return_value=fake_client):
                result = await nowpayments_client.create_invoice(
                    memo="intent-abc", amount_cents=100,
                )
                self.assertEqual(result["invoice_url"],
                                 "https://nowpayments.io/payment/?iid=5555")
                self.assertEqual(result["invoice_id"], "5555555555")
                # Verify request body: order_id must equal our memo so
                # NOWPayments echoes it back in the IPN webhook.
                call = fake_client.post.call_args
                body = call.kwargs["json"]
                self.assertEqual(body["order_id"], "intent-abc")
                self.assertEqual(body["price_amount"], 1.0)  # 100 cents
                self.assertEqual(body["price_currency"], "usd")
                # x-api-key header must be present.
                self.assertEqual(call.kwargs["headers"]["x-api-key"], "fakekey")
        run(go())

    def test_upstream_5xx_surfaces_as_bad_gateway(self):
        async def go():
            from unittest.mock import AsyncMock, MagicMock, patch
            from app import nowpayments_client
            fake_response = MagicMock()
            fake_response.status_code = 502
            fake_response.text = "bad gateway"
            fake_client = AsyncMock()
            fake_client.__aenter__.return_value = fake_client
            fake_client.post = AsyncMock(return_value=fake_response)
            with patch.object(nowpayments_client, "NOWPAYMENTS_API_KEY", "fakekey"), \
                 patch.object(nowpayments_client.httpx, "AsyncClient",
                              return_value=fake_client):
                with self.assertRaises(nowpayments_client.NowpaymentsError) as ctx:
                    await nowpayments_client.create_invoice(
                        memo="intent-abc", amount_cents=100,
                    )
                self.assertEqual(ctx.exception.status_code, 502)
                self.assertIn("502", ctx.exception.detail)
        run(go())


if __name__ == "__main__":
    unittest.main()
