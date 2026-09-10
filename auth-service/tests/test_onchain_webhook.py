"""Tests for the on-chain (Miden) payment rail — receive-side.

Covers the watcher payload validation, the dispatch path (accepted-faucet
check, base-units → cents conversion, mark_paid_by_memo integration), the
pending-intents matching table, and the watcher bearer gate.

Run from `auth-service/`:
    python -m unittest tests.test_onchain_webhook -v
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


FAUCET = "mtst1azftenneus72ugqqsj9rk7cveqk0eraz"
GATEWAY = "mtst1gatewayreceivingaccount000000000"

# With the defaults (6 decimals, 100 cents per token, 1 cent per credit):
# a 300-credit intent costs 300 cents = 3 USDT = 3_000_000 base units.
EXACT_UNITS = 3_000_000


def _report(memo="intent-abc", note_id="0xnote1", faucet_id=FAUCET,
            amount_base_units=EXACT_UNITS, note_kind="p2id") -> dict:
    return {"memo": memo, "note_id": note_id, "faucet_id": faucet_id,
            "amount_base_units": amount_base_units, "note_kind": note_kind}


class SetupMixin:
    @classmethod
    def setUpClass(cls):
        from app import onchain_client, onchain_webhook
        cls.client = onchain_client
        cls.mod = onchain_webhook
        # Pin the rail config at the module level (mirrors env config);
        # decimals/rate keep their defaults (6, 100).
        cls._patches = [
            patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", GATEWAY),
            patch.object(onchain_client, "ONCHAIN_FAUCET_ID", FAUCET),
            patch.object(onchain_client, "ONCHAIN_TOKEN_DECIMALS", 6),
            patch.object(onchain_client, "ONCHAIN_CENTS_PER_TOKEN", 100),
        ]
        for p in cls._patches:
            p.start()

    @classmethod
    def tearDownClass(cls):
        for p in cls._patches:
            p.stop()


class ParsePayloadTest(SetupMixin, unittest.TestCase):
    def _rejects(self, **overrides):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.parse_payload({**_report(), **overrides})
        self.assertEqual(cm.exception.status_code, 400)

    def test_valid_payload_parses(self):
        p = self.mod.parse_payload(_report())
        self.assertEqual(p["amount_base_units"], EXACT_UNITS)

    def test_amount_as_decimal_string_is_accepted(self):
        # Base-unit amounts can exceed 2^53-1, so watchers may send them
        # as strings the way onchain_client returns token_amount.
        p = self.mod.parse_payload(_report(amount_base_units=str(EXACT_UNITS)))
        self.assertEqual(p["amount_base_units"], EXACT_UNITS)

    def test_non_object_payload_400s(self):
        with self.assertRaises(self.mod.WebhookError) as cm:
            self.mod.parse_payload(["not", "a", "dict"])
        self.assertEqual(cm.exception.status_code, 400)

    def test_missing_or_empty_fields_400(self):
        self._rejects(memo="")
        self._rejects(note_id="")
        self._rejects(faucet_id="")

    def test_bad_amounts_400(self):
        self._rejects(amount_base_units=0)
        self._rejects(amount_base_units=-5)
        self._rejects(amount_base_units=True)   # bool is an int subclass
        self._rejects(amount_base_units="3.14")
        self._rejects(amount_base_units=None)

    def test_non_p2id_notes_are_refused(self):
        # P2IDE is reclaimable until consumed — committed is not settled.
        self._rejects(note_kind="p2ide")
        self._rejects(note_kind="")
        self._rejects(note_kind=None)
        with self.assertRaises(self.mod.WebhookError) as cm:
            payload = _report()
            del payload["note_kind"]
            self.mod.parse_payload(payload)
        self.assertEqual(cm.exception.status_code, 400)


class QuoteAmountTest(SetupMixin, unittest.TestCase):
    """Amounts are PLAIN prices now: attribution rides on the memo the
    payer embeds in the note's NoteAttachment, not on the amount. Two
    same-price intents share the same token_amount by design."""

    def test_same_price_intents_share_the_same_amount(self):
        a = self.client.token_amount_for_cents(300)
        b = self.client.token_amount_for_cents(300)
        self.assertEqual(a, b)
        self.assertEqual(a, 300 * 10_000)   # 3.00 USDT at 6 decimals

    def test_amount_converts_back_to_the_exact_cents(self):
        # The underpay guard, display price and accounting must all see
        # the same value the payer was quoted.
        for cents in (1, 300, 12_345):
            units = self.client.token_amount_for_cents(cents)
            self.assertEqual(self.client.cents_for_token_amount(units), cents)

    def test_quote_and_matching_table_agree(self):
        # The payer's quote (create_payment_request) and the watcher's
        # expected amount (token_amount_for_cents) must be the same number.
        async def go():
            with patch.object(self.client, "ONCHAIN_GATEWAY_ADDRESS", GATEWAY):
                r = await self.client.create_payment_request(
                    memo="intent-abc", amount_cents=300)
            return r["onchain"]["token_amount"]

        quoted = run(go())
        self.assertEqual(quoted, str(self.client.token_amount_for_cents(300)))


class DispatchTest(SetupMixin, unittest.TestCase):
    def _with_intent(self, scenario, credits=300):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=credits, provider="onchain")
                return await scenario(conn, intent["memo"])
            finally:
                await conn.close()

        return run(go())

    async def _balance(self, conn):
        cur = await conn.execute("SELECT balance FROM balances WHERE identity_id = 1")
        return (await cur.fetchone())[0]

    def _units(self, memo, cents=300):
        """What the payer was quoted for this intent: the exact price in
        base units (memo kept in the signature only so call sites read
        naturally — it no longer affects the amount)."""
        return self.client.token_amount_for_cents(cents)

    def test_exact_payment_credits_the_intent(self):
        async def scenario(conn, memo):
            out = await self.mod.dispatch(
                conn, _report(memo=memo, amount_base_units=self._units(memo)))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["handled"])
        self.assertTrue(out["result"]["success"], out)
        self.assertEqual(balance, 300)

    def test_provider_ref_records_the_note_id(self):
        from app import handlers

        async def scenario(conn, memo):
            await self.mod.dispatch(conn, _report(
                memo=memo, note_id="0xdeadbeef",
                amount_base_units=self._units(memo)))
            return await handlers.get_intent_by_memo(conn, memo)

        intent = self._with_intent(scenario)
        self.assertEqual(intent["provider_ref"], "miden:0xdeadbeef")
        self.assertEqual(intent["status"], "paid")

    def test_replay_deduplicates(self):
        async def scenario(conn, memo):
            r = _report(memo=memo, amount_base_units=self._units(memo))
            r1 = await self.mod.dispatch(conn, r)
            r2 = await self.mod.dispatch(conn, r)
            return r1, r2, await self._balance(conn)

        r1, r2, balance = self._with_intent(scenario)
        self.assertTrue(r1["result"]["success"])
        self.assertTrue(r2["result"].get("deduplicated"))
        self.assertEqual(balance, 300)   # credited exactly once

    def test_wrong_faucet_is_refused_and_not_credited(self):
        # Real assets of the WRONG token must never buy credits.
        async def scenario(conn, memo):
            try:
                await self.mod.dispatch(
                    conn, _report(memo=memo, faucet_id="mtst1someothertoken000"))
            except self.mod.WebhookError as e:
                return e, await self._balance(conn)

        err, balance = self._with_intent(scenario)
        self.assertEqual(err.status_code, 400)
        self.assertEqual(balance, 0)

    def test_underpayment_is_refused(self):
        # One base unit short of the quoted price. Permanent → 409, not
        # a retried 500.
        async def scenario(conn, memo):
            try:
                await self.mod.dispatch(
                    conn, _report(memo=memo, amount_base_units=self._units(memo) - 1))
                err = None
            except self.mod.WebhookError as e:
                err = e
            return err, await self._balance(conn)

        err, balance = self._with_intent(scenario)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 409)
        self.assertIn("underpaid", err.detail)
        self.assertEqual(balance, 0)

    def test_overpaid_note_is_not_auto_credited(self):
        # >= would let a wrong-order-of-magnitude payment credit
        # silently, so a too-large note is an ops case, never an
        # auto-credit.
        async def scenario(conn, memo):
            try:
                await self.mod.dispatch(
                    conn, _report(memo=memo,
                                  amount_base_units=self._units(memo) + 12_345))
                err = None
            except self.mod.WebhookError as e:
                err = e
            return err, await self._balance(conn)

        err, balance = self._with_intent(scenario)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 409)
        self.assertIn("mismatch", err.detail)
        self.assertEqual(balance, 0)

    # NOTE: the old "same-price theft" scenario (report a victim's note
    # against a thief's same-price memo) is no longer distinguishable by
    # amount — same-price intents share the amount by design. The memo
    # now comes off the note's own attachment, which the payer fixed at
    # send time and nobody can rewrite; the server-side backstop against
    # a lying watcher is one-note-one-intent (test below) plus the
    # watcher's own restricted bearer.

    def test_one_note_cannot_credit_two_intents(self):
        # A compromised watcher replaying one real note across the
        # pending table: the second claim must be refused permanently.
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_1")
                await handlers.create_identity(conn, "api_key", "hash_2")
                a = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="onchain")
                b = await handlers.create_intent(
                    conn, identity_id=2, credits=300, provider="onchain")
                r1 = await self.mod.dispatch(conn, _report(
                    memo=a["memo"], note_id="0xnote_reused",
                    amount_base_units=self._units(a["memo"])))
                try:
                    await self.mod.dispatch(conn, _report(
                        memo=b["memo"], note_id="0xnote_reused",
                        amount_base_units=self._units(b["memo"])))
                    err = None
                except self.mod.WebhookError as e:
                    err = e
                cur = await conn.execute(
                    "SELECT balance FROM balances WHERE identity_id = 2")
                b2 = (await cur.fetchone())[0]
                return r1, err, b2
            finally:
                await conn.close()

        r1, err, second_balance = run(go())
        self.assertTrue(r1["result"]["success"])
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 409)
        self.assertEqual(second_balance, 0)

    def test_same_note_same_memo_replay_still_dedups(self):
        # The reuse guard must not break the ordinary retry: identical
        # (note, memo) goes through to mark_paid's dedup path.
        async def scenario(conn, memo):
            r = _report(memo=memo, note_id="0xsame",
                        amount_base_units=self._units(memo))
            await self.mod.dispatch(conn, r)
            out = await self.mod.dispatch(conn, r)
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["result"].get("deduplicated"))
        self.assertEqual(balance, 300)

    def test_non_onchain_intent_is_refused(self):
        # Watcher bearer + a leaked Stripe memo must not credit anything.
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="stripe")
                try:
                    await self.mod.dispatch(conn, _report(memo=intent["memo"]))
                    err = None
                except self.mod.WebhookError as e:
                    err = e
                cur = await conn.execute(
                    "SELECT balance FROM balances WHERE identity_id = 1")
                return err, (await cur.fetchone())[0]
            finally:
                await conn.close()

        err, balance = run(go())
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 400)
        self.assertEqual(balance, 0)

    def test_db_index_is_the_backstop_for_note_reuse(self):
        # Belt under the pre-check: writing the same miden ref twice must
        # fail at the schema level, while non-miden refs stay repeatable.
        import sqlite3 as _sqlite3
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                for _ in range(4):
                    await handlers.create_intent(
                        conn, identity_id=1, credits=10, provider="onchain")
                await conn.execute(
                    "UPDATE payment_intents SET provider_ref = 'miden:0xdup' WHERE id = 1")
                try:
                    await conn.execute(
                        "UPDATE payment_intents SET provider_ref = 'miden:0xdup' WHERE id = 2")
                    dup_err = None
                except _sqlite3.IntegrityError as e:
                    dup_err = str(e)
                # non-miden refs are deliberately unconstrained
                await conn.execute(
                    "UPDATE payment_intents SET provider_ref = 'stripe:cs_1' WHERE id = 3")
                await conn.execute(
                    "UPDATE payment_intents SET provider_ref = 'stripe:cs_1' WHERE id = 4")
                return dup_err
            finally:
                await conn.close()

        dup_err = run(go())
        self.assertIsNotNone(dup_err)
        self.assertIn("payment_intents.provider_ref", dup_err)

    def test_unknown_memo_is_404(self):
        # Permanent (watcher bug or attack, not a stranded payment) →
        # 404 so the watcher dead-letters instead of retrying forever.
        async def scenario(conn, memo):
            try:
                await self.mod.dispatch(conn, _report(memo="intent-nonexistent"))
                return None
            except self.mod.WebhookError as e:
                return e

        err = self._with_intent(scenario)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 404)

    def test_cancelled_intent_is_409(self):
        # Money on-chain against a cancelled intent: logged loudly (ops
        # will see MONEY RECEIVED BUT NOT CREDITED) but permanent → 409.
        from app import handlers

        async def scenario(conn, memo):
            await handlers.cancel_intent_by_memo(conn, memo)
            try:
                await self.mod.dispatch(
                    conn, _report(memo=memo, amount_base_units=self._units(memo)))
                err = None
            except self.mod.WebhookError as e:
                err = e
            return err, await self._balance(conn)

        err, balance = self._with_intent(scenario)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 409)
        self.assertIn("cancelled", err.detail)
        self.assertEqual(balance, 0)

    def test_paid_expired_intent_still_credits(self):
        # Same H3 guarantee as the other rails: an on-chain confirmation
        # landing after the TTL must be honoured — the tokens are ours.
        from app import handlers

        async def scenario(conn, memo):
            await conn.execute(
                "UPDATE payment_intents SET expires_at = "
                "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?", (memo,))
            await conn.commit()
            await handlers.mark_paid_by_memo(conn, memo)   # ops probe flips to 'expired'
            out = await self.mod.dispatch(
                conn, _report(memo=memo, amount_base_units=self._units(memo)))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["result"]["success"], out)
        self.assertEqual(balance, 300)


class PendingIntentsTest(SetupMixin, unittest.TestCase):
    def test_lists_only_pending_onchain_with_sender_accounts(self):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                # identity 1: onchain intent + a bound miden_account label
                await handlers.create_identity(conn, "api_key", "hash_1")
                await conn.execute(
                    "INSERT INTO credentials (identity_id, credential_type, credential_value) "
                    "VALUES (1, 'miden_account', 'mtst1payeraccount000')")
                await conn.commit()
                kept = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="onchain")
                # a stripe intent must not appear
                await handlers.create_intent(
                    conn, identity_id=1, credits=100, provider="stripe")
                # a PAID onchain intent must not appear
                paid = await handlers.create_intent(
                    conn, identity_id=1, credits=200, provider="onchain")
                await handlers.mark_paid_by_memo(conn, paid["memo"])
                # identity 2: onchain intent with NO bound address — still
                # listed (matching rides on the note attachment), with empty sender_accounts
                await handlers.create_identity(conn, "api_key", "hash_2")
                bare = await handlers.create_intent(
                    conn, identity_id=2, credits=50, provider="onchain")
                out = await handlers.list_pending_onchain_intents(conn)
                return kept, bare, out
            finally:
                await conn.close()

        kept, bare, out = run(go())
        self.assertEqual([i["memo"] for i in out], [kept["memo"], bare["memo"]])
        self.assertEqual(out[0]["sender_accounts"], ["mtst1payeraccount000"])
        self.assertEqual(out[0]["amount_cents"], 300)
        self.assertEqual(out[1]["sender_accounts"], [])

    def test_expired_pending_intent_stays_listed(self):
        # The webhook honours late payments (allow_expired), so the watcher
        # must still be able to match them.
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_1")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="onchain")
                await conn.execute(
                    "UPDATE payment_intents SET expires_at = "
                    "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?",
                    (intent["memo"],))
                await conn.commit()
                return intent, await handlers.list_pending_onchain_intents(conn)
            finally:
                await conn.close()

        intent, out = run(go())
        self.assertEqual([i["memo"] for i in out], [intent["memo"]])

    def test_lazily_flipped_expired_row_stays_matchable(self):
        # An admin probe flips a stale row to status='expired'
        # (handlers lazy sweep); the webhook still credits it via
        # allow_expired, so the matching table must keep showing it —
        # otherwise the payment lands with nobody to match it.
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_1")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="onchain")
                await conn.execute(
                    "UPDATE payment_intents SET expires_at = "
                    "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?",
                    (intent["memo"],))
                await conn.commit()
                await handlers.mark_paid_by_memo(conn, intent["memo"])  # flips to 'expired'
                return intent, await handlers.list_pending_onchain_intents(conn)
            finally:
                await conn.close()

        intent, out = run(go())
        self.assertEqual([i["memo"] for i in out], [intent["memo"]])

    def test_ancient_intent_leaves_the_matching_table(self):
        # Past the grace window the intent leaves the table; a late
        # payment becomes an ops case instead of an eternal listing.
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_1")
                intent = await handlers.create_intent(
                    conn, identity_id=1, credits=300, provider="onchain")
                await conn.execute(
                    "UPDATE payment_intents SET expires_at = "
                    "datetime(CURRENT_TIMESTAMP, '-30 days') WHERE memo = ?",
                    (intent["memo"],))
                await conn.commit()
                return await handlers.list_pending_onchain_intents(conn)
            finally:
                await conn.close()

        self.assertEqual(run(go()), [])


class IntentSlotDisciplineTest(SetupMixin, unittest.TestCase):
    """create_intent's on-chain rules: per-identity cap, short TTL."""

    def _db(self, scenario):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                return await scenario(conn, handlers)
            finally:
                await conn.close()

        return run(go())

    def test_pending_cap_per_identity(self):
        from app import handlers

        async def scenario(conn, h):
            with patch.object(handlers, "ONCHAIN_MAX_PENDING_PER_IDENTITY", 2):
                r1 = await h.create_intent(conn, 1, 100, "onchain")
                r2 = await h.create_intent(conn, 1, 200, "onchain")
                r3 = await h.create_intent(conn, 1, 300, "onchain")
                # other rails are not subject to the cap
                r4 = await h.create_intent(conn, 1, 300, "stripe")
            return r1, r2, r3, r4

        r1, r2, r3, r4 = self._db(scenario)
        self.assertTrue(r1["success"] and r2["success"])
        self.assertFalse(r3["success"])
        self.assertIn("too many", r3["error"])
        self.assertTrue(r4["success"])

    def test_same_price_intents_coexist(self):
        # No dust, no slot exclusivity: several live same-price quotes
        # are fine — the note attachment disambiguates, not the amount.
        async def scenario(conn, h):
            a = await h.create_intent(conn, 1, 300, "onchain")
            b = await h.create_intent(conn, 1, 300, "onchain")
            return a, b

        a, b = self._db(scenario)
        self.assertTrue(a["success"] and b["success"])
        self.assertNotEqual(a["memo"], b["memo"])

    def test_cap_ignores_expired_intents(self):
        # A user who abandoned quotes must not stay locked out for the
        # whole match-grace window: only LIVE pending rows count.
        from app import handlers

        async def scenario(conn, h):
            with patch.object(handlers, "ONCHAIN_MAX_PENDING_PER_IDENTITY", 2):
                a = await h.create_intent(conn, 1, 100, "onchain")
                await h.create_intent(conn, 1, 200, "onchain")
                blocked = await h.create_intent(conn, 1, 300, "onchain")
                # one quote times out (still matchable within grace, but
                # no longer counted against the cap)
                await conn.execute(
                    "UPDATE payment_intents SET expires_at = "
                    "datetime(CURRENT_TIMESTAMP, '-1 hour') WHERE memo = ?",
                    (a["memo"],))
                await conn.commit()
                unblocked = await h.create_intent(conn, 1, 300, "onchain")
            return blocked, unblocked

        blocked, unblocked = self._db(scenario)
        self.assertFalse(blocked["success"])
        self.assertTrue(unblocked["success"], unblocked)

    def test_global_pending_cap_applies_to_every_provider(self):
        # The stockpile cap: without it one api_key could pre-mint ~10^4
        # capless Stripe intents as raw material for rail-switch games.
        from app import handlers

        async def scenario(conn, h):
            with patch.object(handlers, "INTENT_MAX_PENDING_PER_IDENTITY", 3):
                for _ in range(3):
                    r = await h.create_intent(conn, 1, 300, "stripe")
                    self.assertTrue(r["success"])
                stripe_blocked = await h.create_intent(conn, 1, 300, "stripe")
                onchain_blocked = await h.create_intent(conn, 1, 300, "onchain")
            return stripe_blocked, onchain_blocked

        stripe_blocked, onchain_blocked = self._db(scenario)
        self.assertFalse(stripe_blocked["success"])
        self.assertIn("too many unpaid intents", stripe_blocked["error"])
        self.assertFalse(onchain_blocked["success"])

    def test_onchain_ttl_is_short(self):
        async def scenario(conn, h):
            await h.create_intent(conn, 1, 300, "onchain")
            await h.create_intent(conn, 1, 300, "stripe")
            cur = await conn.execute(
                "SELECT provider, "
                "(julianday(expires_at) - julianday(CURRENT_TIMESTAMP)) * 86400 "
                "FROM payment_intents")
            return dict(await cur.fetchall())

        ttls = self._db(scenario)
        self.assertLess(ttls["onchain"], 2 * 86400)      # ~24h
        self.assertGreater(ttls["stripe"], 20 * 86400)   # ~30d


class SetIntentProviderTest(SetupMixin, unittest.TestCase):
    def _db(self, scenario):
        from app.db import init_db
        from app import handlers

        async def go():
            conn = await init_db(":memory:")
            try:
                await handlers.create_identity(conn, "api_key", "hash_x")
                return await scenario(conn, handlers)
            finally:
                await conn.close()

        return run(go())

    def test_switch_to_onchain_updates_row_and_matching_table(self):
        async def scenario(conn, h):
            intent = await h.create_intent(conn, 1, 300, "stripe")
            out = await h.set_intent_provider(conn, intent["memo"], "onchain")
            listed = await h.list_pending_onchain_intents(conn)
            cur = await conn.execute(
                "SELECT provider, "
                "(julianday(expires_at) - julianday(CURRENT_TIMESTAMP)) * 86400 "
                "FROM payment_intents WHERE memo = ?", (intent["memo"],))
            row = await cur.fetchone()
            return intent, out, listed, row

        intent, out, listed, (provider, ttl) = self._db(scenario)
        self.assertTrue(out["success"] and out["changed"])
        self.assertEqual(provider, "onchain")
        self.assertEqual([i["memo"] for i in listed], [intent["memo"]])
        # the slot is not held for a hosted-checkout-sized lifetime
        self.assertLess(ttl, 2 * 86400)

    def test_switch_resets_the_time_anchor(self):
        # The pre-mint bypass: stockpile a cheap Stripe intent, backdate
        # it, switch onto the on-chain rail, and claim a note that was
        # parked before the switch. matchable_since must be the SWITCH
        # time, never the row's created_at.
        async def scenario(conn, h):
            intent = await h.create_intent(conn, 1, 300, "stripe")
            await conn.execute(
                "UPDATE payment_intents SET created_at = "
                "datetime(CURRENT_TIMESTAMP, '-2 days') WHERE memo = ?",
                (intent["memo"],))
            await conn.commit()
            out = await h.set_intent_provider(conn, intent["memo"], "onchain")
            listed = await h.list_pending_onchain_intents(conn)
            cur = await conn.execute(
                "SELECT (julianday(CURRENT_TIMESTAMP) - julianday(onchain_since)) * 86400, "
                "       (julianday(CURRENT_TIMESTAMP) - julianday(created_at)) * 86400 "
                "FROM payment_intents WHERE memo = ?", (intent["memo"],))
            anchor_age, created_age = await cur.fetchone()
            return out, listed, anchor_age, created_age

        out, listed, anchor_age, created_age = self._db(scenario)
        self.assertTrue(out["success"])
        self.assertLess(anchor_age, 60, "anchor must be the switch time")
        self.assertGreater(created_age, 86400, "created_at stays historical")
        # and the matching table serves the fresh anchor, not created_at
        self.assertEqual(listed[0]["matchable_since"] == listed[0]["created_at"], False)

    def test_created_as_onchain_gets_an_anchor(self):
        async def scenario(conn, h):
            await h.create_intent(conn, 1, 300, "onchain")
            listed = await h.list_pending_onchain_intents(conn)
            cur = await conn.execute(
                "SELECT onchain_since IS NOT NULL FROM payment_intents")
            return listed, (await cur.fetchone())[0]

        listed, has_anchor = self._db(scenario)
        self.assertTrue(has_anchor)
        self.assertTrue(listed[0]["matchable_since"])

    def test_switch_away_from_onchain_leaves_matching_table(self):
        async def scenario(conn, h):
            intent = await h.create_intent(conn, 1, 300, "onchain")
            out = await h.set_intent_provider(conn, intent["memo"], "stripe")
            return out, await h.list_pending_onchain_intents(conn)

        out, listed = self._db(scenario)
        self.assertTrue(out["success"])
        self.assertEqual(listed, [])

    def test_non_pending_intent_cannot_switch(self):
        async def scenario(conn, h):
            intent = await h.create_intent(conn, 1, 300, "stripe")
            await h.mark_paid_by_memo(conn, intent["memo"])
            return await h.set_intent_provider(conn, intent["memo"], "onchain")

        out = self._db(scenario)
        self.assertFalse(out["success"])
        self.assertIn("paid", out["error"])

    def test_switch_to_onchain_beside_a_same_price_quote(self):
        # No dust slots anymore: switching next to a live same-price
        # on-chain quote is fine — the note attachment disambiguates.
        async def scenario(conn, h):
            await h.create_intent(conn, 1, 300, "onchain")
            other = await h.create_intent(conn, 1, 300, "stripe")
            return await h.set_intent_provider(conn, other["memo"], "onchain")

        out = self._db(scenario)
        self.assertTrue(out["success"], out)
        self.assertTrue(out["changed"])


class WatcherTokenGateTest(unittest.TestCase):
    """The dependency logic itself — no TestClient needed."""

    @classmethod
    def setUpClass(cls):
        from app import main
        cls.main = main

    def _call(self, authorization):
        self.main.require_watcher_token(authorization=authorization)

    def test_unset_token_fails_closed_503(self):
        from fastapi import HTTPException
        with patch.object(self.main, "ONCHAIN_WATCHER_TOKEN", ""):
            with self.assertRaises(HTTPException) as cm:
                self._call("Bearer anything")
        self.assertEqual(cm.exception.status_code, 503)

    def test_missing_and_wrong_bearer_401(self):
        from fastapi import HTTPException
        with patch.object(self.main, "ONCHAIN_WATCHER_TOKEN", "w" * 32):
            with self.assertRaises(HTTPException) as cm:
                self._call(None)
            self.assertEqual(cm.exception.status_code, 401)
            with self.assertRaises(HTTPException) as cm:
                self._call("Bearer " + "x" * 32)
            self.assertEqual(cm.exception.status_code, 401)

    def test_watcher_token_passes(self):
        with patch.object(self.main, "ONCHAIN_WATCHER_TOKEN", "w" * 32):
            self._call("Bearer " + "w" * 32)   # no raise

    def test_admin_token_also_passes(self):
        # Ops replaying a missed note by hand use ADMIN_TOKEN.
        with patch.object(self.main, "ONCHAIN_WATCHER_TOKEN", "w" * 32), \
             patch.object(self.main, "ADMIN_TOKEN", "a" * 32):
            self._call("Bearer " + "a" * 32)   # no raise


if __name__ == "__main__":
    unittest.main()
