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


def _report(memo="intent-abc", note_id="0xnote1",
            faucet_id=FAUCET, amount_base_units=EXACT_UNITS) -> dict:
    return {"memo": memo, "note_id": note_id,
            "faucet_id": faucet_id, "amount_base_units": amount_base_units}


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

    def test_exact_payment_credits_the_intent(self):
        async def scenario(conn, memo):
            out = await self.mod.dispatch(conn, _report(memo=memo))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["handled"])
        self.assertTrue(out["result"]["success"], out)
        self.assertEqual(balance, 300)

    def test_provider_ref_records_the_note_id(self):
        from app import handlers

        async def scenario(conn, memo):
            await self.mod.dispatch(conn, _report(memo=memo, note_id="0xdeadbeef"))
            return await handlers.get_intent_by_memo(conn, memo)

        intent = self._with_intent(scenario)
        self.assertEqual(intent["provider_ref"], "miden:0xdeadbeef")
        self.assertEqual(intent["status"], "paid")

    def test_replay_deduplicates(self):
        async def scenario(conn, memo):
            r1 = await self.mod.dispatch(conn, _report(memo=memo))
            r2 = await self.mod.dispatch(conn, _report(memo=memo))
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
        # One base unit short: floor conversion gives 299 cents < 300.
        async def scenario(conn, memo):
            out = await self.mod.dispatch(
                conn, _report(memo=memo, amount_base_units=EXACT_UNITS - 1))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertFalse(out["result"]["success"])
        self.assertIn("underpaid", out["result"]["error"])
        self.assertEqual(balance, 0)

    def test_overpayment_still_credits_the_intent_amount(self):
        async def scenario(conn, memo):
            out = await self.mod.dispatch(
                conn, _report(memo=memo, amount_base_units=EXACT_UNITS + 12_345))
            return out, await self._balance(conn)

        out, balance = self._with_intent(scenario)
        self.assertTrue(out["result"]["success"], out)
        self.assertEqual(balance, 300)   # credits come from the intent, not the payment

    def test_unknown_memo_reports_failure(self):
        async def scenario(conn, memo):
            return await self.mod.dispatch(conn, _report(memo="intent-nonexistent"))

        out = self._with_intent(scenario)
        self.assertTrue(out["handled"])
        self.assertFalse(out["result"]["success"])
        self.assertIn("not found", out["result"]["error"])

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
            out = await self.mod.dispatch(conn, _report(memo=memo))
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
                # listed (amount-only matching), with empty sender_accounts
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
