"""One order, paid twice — detection, evidence, and the ops flow it must
NOT cry wolf on.

An intent that is already 'paid' short-circuits in mark_paid_by_memo, and
three very different events land on that branch:

  * the same payment delivered twice (Stripe retries deliveries and fires
    two crediting event types per session; the watcher re-sends reports it
    got no answer for) — routine, must stay quiet;
  * a hand-settled intent later reported by its provider (admin mark-paid
    leaves provider_ref NULL) — the everyday ops flow for a parked note,
    must not alert;
  * a SECOND real payment — money held and owed back, must be loud AND
    leave a row that outlives the container's logs.

Run from `auth-service/`:
    python -m unittest tests.test_duplicate_payment -v
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class MarkPaidReplayTest(unittest.TestCase):
    """The discriminator lives in mark_paid_by_memo, so every rail and
    admin settlement inherit it."""

    def _db(self, scenario):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(conn, 1, 300, "stripe")
                return await scenario(conn, handlers, intent["memo"])
            finally:
                await conn.close()

        return run(go())

    async def _dup_rows(self, conn):
        cur = await conn.execute(
            "SELECT note, delta FROM usage_log WHERE operation = 'duplicate_payment'")
        return await cur.fetchall()

    async def _balance(self, conn):
        cur = await conn.execute("SELECT balance FROM balances WHERE identity_id = 1")
        return (await cur.fetchone())[0]

    def test_same_ref_replay_is_quiet(self):
        async def scenario(conn, h, memo):
            await h.mark_paid_by_memo(conn, memo, provider_ref="stripe:cs_1")
            again = await h.mark_paid_by_memo(conn, memo, provider_ref="stripe:cs_1")
            return again, await self._dup_rows(conn), await self._balance(conn)

        again, rows, balance = self._db(scenario)
        self.assertTrue(again["deduplicated"])
        self.assertNotIn("duplicate_payment", again)
        self.assertNotIn("backfilled_provider_ref", again)
        self.assertEqual(rows, [], "a redelivery must not look like a second payment")
        self.assertEqual(balance, 300, "credited exactly once")

    def test_no_ref_replay_is_quiet(self):
        # Admin calling mark-paid twice by hand, without a reference.
        async def scenario(conn, h, memo):
            await h.mark_paid_by_memo(conn, memo)
            again = await h.mark_paid_by_memo(conn, memo)
            return again, await self._dup_rows(conn)

        again, rows = self._db(scenario)
        self.assertTrue(again["deduplicated"])
        self.assertNotIn("duplicate_payment", again)
        self.assertEqual(rows, [])

    def test_second_real_payment_is_flagged_and_recorded(self):
        async def scenario(conn, h, memo):
            await h.mark_paid_by_memo(conn, memo, provider_ref="stripe:cs_first")
            second = await h.mark_paid_by_memo(conn, memo, provider_ref="stripe:cs_second")
            intent = await h.get_intent_by_memo(conn, memo)
            return second, await self._dup_rows(conn), await self._balance(conn), intent

        second, rows, balance, intent = self._db(scenario)
        self.assertEqual(second["duplicate_payment"], {
            "credited_ref": "stripe:cs_first",
            "duplicate_ref": "stripe:cs_second",
        })
        self.assertEqual(balance, 300, "the second payment must NOT credit again")
        # the durable trace: queryable long after any log buffer is gone
        self.assertEqual(len(rows), 1)
        note, delta = rows[0]
        self.assertEqual(delta, 0)
        self.assertIn("stripe:cs_first", note)
        self.assertIn("stripe:cs_second", note)
        self.assertIn(f"intent={intent['memo']}", note)
        # provider_ref keeps pointing at the payment that actually credited
        self.assertEqual(intent["provider_ref"], "stripe:cs_first")

    def test_hand_settled_then_reported_backfills_without_alerting(self):
        # The most common ops flow: a parked/mismatched payment is
        # finalised by hand (provider_ref NULL), then the provider reports
        # the very same money. Alerting here would burn the alert's
        # credibility on its most frequent trigger.
        async def scenario(conn, h, memo):
            await h.mark_paid_by_memo(conn, memo)          # admin, no ref
            reported = await h.mark_paid_by_memo(
                conn, memo, provider_ref="stripe:cs_real")
            return reported, await self._dup_rows(conn), await h.get_intent_by_memo(conn, memo)

        reported, rows, intent = self._db(scenario)
        self.assertTrue(reported["backfilled_provider_ref"])
        self.assertNotIn("duplicate_payment", reported)
        self.assertEqual(rows, [], "a backfill is not a duplicate payment")
        self.assertEqual(intent["provider_ref"], "stripe:cs_real",
                         "the reference is filled in, not left unknown")

    def test_backfilled_ref_then_a_real_duplicate_still_alerts(self):
        # Backfilling must not blind the detector afterwards.
        async def scenario(conn, h, memo):
            await h.mark_paid_by_memo(conn, memo)
            await h.mark_paid_by_memo(conn, memo, provider_ref="stripe:cs_real")
            third = await h.mark_paid_by_memo(conn, memo, provider_ref="stripe:cs_other")
            return third, await self._dup_rows(conn)

        third, rows = self._db(scenario)
        self.assertEqual(third["duplicate_payment"]["credited_ref"], "stripe:cs_real")
        self.assertEqual(len(rows), 1)


class TwoNotesOneMemoTest(unittest.TestCase):
    """The on-chain path that is NOT a race: the watcher reads the
    matching table once per tick, so two notes carrying the same memo both
    match while the intent is still pending and both get reported. Each
    note id is new, so the webhook's note-reuse pre-check cannot see it —
    only the ORDER is already paid."""

    @classmethod
    def setUpClass(cls):
        from app import onchain_client, onchain_webhook
        cls.client = onchain_client
        cls.mod = onchain_webhook
        cls._patches = [
            patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", "mtst1gateway"),
            patch.object(onchain_client, "ONCHAIN_FAUCET_ID", "mtst1faucet"),
            patch.object(onchain_client, "ONCHAIN_TOKEN_DECIMALS", 6),
            patch.object(onchain_client, "ONCHAIN_CENTS_PER_TOKEN", 100),
        ]
        for p in cls._patches:
            p.start()

    @classmethod
    def tearDownClass(cls):
        for p in cls._patches:
            p.stop()

    def test_second_note_for_one_memo_is_flagged_not_swallowed(self):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(conn, 1, 300, "onchain")
                units = self.client.token_amount_for_cents(300)
                report = {
                    "memo": intent["memo"], "faucet_id": "mtst1faucet",
                    "amount_base_units": units, "note_kind": "p2id",
                }
                first = await self.mod.dispatch(
                    conn, {**report, "note_id": "0xnote_one"})
                second = await self.mod.dispatch(
                    conn, {**report, "note_id": "0xnote_two"})
                cur = await conn.execute(
                    "SELECT note FROM usage_log WHERE operation = 'duplicate_payment'")
                rows = await cur.fetchall()
                cur = await conn.execute(
                    "SELECT balance FROM balances WHERE identity_id = 1")
                return first, second, rows, (await cur.fetchone())[0]
            finally:
                await conn.close()

        first, second, rows, balance = run(go())
        self.assertTrue(first["result"]["success"])
        # the second note is accepted (2xx, so the watcher stops retrying)
        # but it is NOT silently absorbed
        self.assertTrue(second["result"]["deduplicated"])
        self.assertEqual(second["result"]["duplicate_payment"], {
            "credited_ref": "miden:0xnote_one",
            "duplicate_ref": "miden:0xnote_two",
        })
        self.assertEqual(balance, 300)
        self.assertEqual(len(rows), 1)
        self.assertIn("miden:0xnote_two", rows[0][0])


class StripeIdempotencyKeyTest(unittest.TestCase):
    """Checkout retries must collapse onto ONE Session instead of minting
    a parallel payable link — and a config change must not turn every open
    intent's checkout into an idempotency error."""

    def _capture_key(self, **overrides):
        """Run create_checkout_session against a stubbed transport and
        return the Idempotency-Key it sent."""
        import httpx
        from app import stripe_client

        sent = {}

        class _Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"id": "cs_test", "url": "https://checkout.stripe.com/x"}

        class _Client:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, data=None, headers=None):
                sent["headers"] = headers
                sent["data"] = data
                return _Resp()

        conf = {
            "STRIPE_SECRET_KEY": "sk_test_x",
            "STRIPE_SUCCESS_URL": "https://app.example/ok",
            "STRIPE_CANCEL_URL": "",
            **overrides,
        }
        patches = [patch.object(stripe_client, k, v) for k, v in conf.items()]
        patches.append(patch.object(httpx, "AsyncClient", _Client))
        for p in patches:
            p.start()
        try:
            run(stripe_client.create_checkout_session(
                memo="intent-abc", amount_cents=300))
        finally:
            for p in patches:
                p.stop()
        return sent["headers"]["Idempotency-Key"]

    def test_identical_requests_reuse_one_key(self):
        self.assertEqual(self._capture_key(), self._capture_key())

    def test_key_names_the_memo(self):
        self.assertTrue(self._capture_key().startswith("checkout:intent-abc:"))

    def test_changing_success_url_changes_the_key(self):
        # Stripe errors when one key is replayed with different
        # parameters, and success_url comes from the environment at call
        # time. Keyed on the memo alone, changing STRIPE_SUCCESS_URL and
        # redeploying would break checkout for every open intent.
        other = self._capture_key(STRIPE_SUCCESS_URL="https://app.example/thanks")
        self.assertNotEqual(self._capture_key(), other)

    def test_key_is_within_stripes_length_limit(self):
        self.assertLessEqual(len(self._capture_key()), 255)


if __name__ == "__main__":
    unittest.main()
