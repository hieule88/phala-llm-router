"""Tests for wallet → identity resolution (handlers.wallet_bind).

Run from `auth-service/`:
    python -m unittest tests.test_wallet_bind -v

This is the seam where a Miden wallet becomes a billable identity. The
invariants that matter: it is idempotent (the Edge calls it on every bind), a
public wallet value can never authenticate a spend, and a bind can never graft
a wallet onto an identity that is not its own.
"""

import asyncio
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("ADMIN_TOKEN", "A" * 40)
os.environ.setdefault("PROXY_REFUND_TOKEN", "P" * 40)
os.environ.setdefault("AUTH_DB_PATH", ":memory:")

from app import handlers  # noqa: E402
from app.db import init_db  # noqa: E402

WALLET_A = "ab" * 64
WALLET_B = "cd" * 64


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def key_hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class WalletBindTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.conn = await init_db(":memory:")

    async def asyncTearDown(self):
        await self.conn.close()

    async def test_first_bind_creates_identity_balance_and_credentials(self):
        res = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"), account_id="mtst1qa")
        self.assertTrue(res["success"])
        self.assertTrue(res["created"])
        self.assertEqual(res["balance"], 0)
        self.assertEqual(res["unit"], "millicredit")

        identity = res["identity_id"]
        self.assertEqual(
            await handlers.lookup_identity(self.conn, "miden_wallet", WALLET_A), identity,
        )
        self.assertEqual(
            await handlers.lookup_identity(self.conn, "miden_account", "mtst1qa"), identity,
        )
        self.assertEqual(
            await handlers.lookup_identity(self.conn, "api_key", key_hash("a")), identity,
        )

    async def test_rebinding_the_same_wallet_is_idempotent(self):
        first = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"), account_id="mtst1qa")
        second = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"), account_id="mtst1qa")
        self.assertEqual(first["identity_id"], second["identity_id"])
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])

        cur = await self.conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE identity_id=?", (first["identity_id"],),
        )
        self.assertEqual((await cur.fetchone())[0], 3)

    async def test_balance_survives_a_rebind(self):
        res = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"))
        await handlers.topup(self.conn, res["identity_id"], 5000, source="test")
        again = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"))
        self.assertEqual(again["balance"], 5000)

    async def test_a_rotated_spending_key_attaches_to_the_same_identity(self):
        # Rotating EDGE_WALLET_KEY_SECRET changes the derived hash; the wallet
        # must keep its identity and its balance.
        first = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("old"))
        await handlers.topup(self.conn, first["identity_id"], 3000, source="t")
        rotated = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("new"))
        self.assertEqual(rotated["identity_id"], first["identity_id"])
        self.assertEqual(rotated["balance"], 3000)
        for label in ("old", "new"):
            self.assertEqual(
                await handlers.lookup_identity(self.conn, "api_key", key_hash(label)),
                first["identity_id"],
            )

    async def test_wallet_value_cannot_authenticate_a_spend(self):
        # The whole reason miden_wallet stays out of AUTHENTICATOR_CREDENTIAL_TYPES:
        # it is a public value, and a public value that can spend is a public balance.
        res = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"), account_id="mtst1qa")
        await handlers.topup(self.conn, res["identity_id"], 10000, source="t")

        for cred_type, value in (("miden_wallet", WALLET_A), ("miden_account", "mtst1qa")):
            validated = await handlers.validate(self.conn, cred_type, value)
            self.assertFalse(validated["valid"])
            consumed = await handlers.consume(self.conn, cred_type, value)
            self.assertFalse(consumed["success"])

        # The derived api-key hash, which only the Edge can compute, does work.
        self.assertTrue((await handlers.validate(self.conn, "api_key", key_hash("a")))["valid"])

    async def test_refuses_to_steal_another_identitys_api_key(self):
        await handlers.wallet_bind(self.conn, WALLET_A, key_hash("shared"))
        res = await handlers.wallet_bind(self.conn, WALLET_B, key_hash("shared"))
        self.assertFalse(res["success"])
        self.assertIn("another identity", res["error"])

    async def test_conflicting_account_id_skips_the_label_but_binds(self):
        # account_id is an unverified claim: a conflict must not fail the
        # bind, or anyone could DoS a wallet by claiming its address first.
        first = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"), account_id="mtst1qa")
        self.assertTrue(first["account_id_attached"])

        res = await handlers.wallet_bind(self.conn, WALLET_B, key_hash("b"), account_id="mtst1qa")
        self.assertTrue(res["success"])
        self.assertFalse(res["account_id_attached"])
        self.assertIn("not attached", res["warning"])
        # The label stays with the first claimant; the second identity exists
        # and can spend regardless.
        self.assertEqual(
            await handlers.lookup_identity(self.conn, "miden_account", "mtst1qa"),
            first["identity_id"],
        )
        self.assertNotEqual(res["identity_id"], first["identity_id"])

    async def test_squatting_an_address_cannot_block_the_victims_bind(self):
        # The attack the soft-fail exists for: a squatter (valid signature,
        # own wallet) claims the victim's address before the victim binds.
        squatter = await handlers.wallet_bind(
            self.conn, WALLET_B, key_hash("squatter"), account_id="mtst1qvictim",
        )
        self.assertTrue(squatter["account_id_attached"])

        victim = await handlers.wallet_bind(
            self.conn, WALLET_A, key_hash("victim"), account_id="mtst1qvictim",
        )
        self.assertTrue(victim["success"])
        self.assertFalse(victim["account_id_attached"])
        self.assertIn("warning", victim)
        # Re-binding stays idempotent and keeps reporting the conflict.
        again = await handlers.wallet_bind(
            self.conn, WALLET_A, key_hash("victim"), account_id="mtst1qvictim",
        )
        self.assertTrue(again["success"])
        self.assertFalse(again["account_id_attached"])

    async def test_two_wallets_get_two_identities(self):
        a = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"))
        b = await handlers.wallet_bind(self.conn, WALLET_B, key_hash("b"))
        self.assertNotEqual(a["identity_id"], b["identity_id"])

    async def test_account_id_is_optional(self):
        res = await handlers.wallet_bind(self.conn, WALLET_A, key_hash("a"))
        self.assertTrue(res["success"])
        self.assertIsNone(await handlers.lookup_identity(self.conn, "miden_account", ""))


if __name__ == "__main__":
    unittest.main()
