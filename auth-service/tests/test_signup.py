"""Tests for self-service signup (POST /v1/signup).

Run from `auth-service/`:
    python -m unittest tests.test_signup -v

Signup is the one public endpoint that mints a credential, so the tests here
care about three things: the key is unguessable, only its hash is persisted,
and a caller cannot talk the endpoint into giving them anything better than a
zero-balance free-tier identity.
"""

import asyncio
import hashlib
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tokens must exist before importing main (read at import time).
os.environ.setdefault("ADMIN_TOKEN", "A" * 40)
os.environ.setdefault("PROXY_REFUND_TOKEN", "P" * 40)
os.environ.setdefault("AUTH_DB_PATH", ":memory:")

from app import handlers  # noqa: E402
from app.db import init_db  # noqa: E402


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class KeyMintingTest(unittest.TestCase):
    def test_prefix_and_entropy(self):
        key = handlers.new_api_key()
        self.assertTrue(key.startswith("lev_"))
        # token_urlsafe(32) is 256 bits base64url-encoded (~43 chars).
        self.assertGreaterEqual(len(key) - len("lev_"), 40)

    def test_keys_are_unique(self):
        keys = {handlers.new_api_key() for _ in range(500)}
        self.assertEqual(len(keys), 500)

    def test_hash_matches_the_edge_implementation(self):
        # The Edge hashes the bearer and looks the result up here. If these two
        # ever diverge every issued key 401s, so pin the algorithm explicitly
        # rather than trusting both sides to keep saying "sha256".
        raw = "lev_example"
        self.assertEqual(handlers.hash_api_key(raw),
                         hashlib.sha256(raw.encode("utf-8")).hexdigest())


class SignupHandlerTest(unittest.TestCase):
    def test_stores_only_the_hash_never_the_raw_key(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                res = await handlers.signup(conn)
                raw = res["api_key"]

                cur = await conn.execute("SELECT credential_type, credential_value FROM credentials")
                rows = await cur.fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], "api_key")
                self.assertEqual(rows[0][1], handlers.hash_api_key(raw))
                self.assertNotEqual(rows[0][1], raw)

                # Belt and braces: the raw key must not appear anywhere in the DB.
                for table in ("credentials", "identities", "balances"):
                    cur = await conn.execute(f"SELECT * FROM {table}")
                    dumped = str(await cur.fetchall())
                    self.assertNotIn(raw, dumped)
            finally:
                await conn.close()
        run(go())

    def test_new_identity_is_free_tier_with_zero_balance(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                res = await handlers.signup(conn)
                bal = await handlers.get_balance(conn, res["identity_id"])
                self.assertEqual(bal["balance"], 0)
                self.assertEqual(bal["tier"], "free")
            finally:
                await conn.close()
        run(go())

    def test_issued_key_authenticates_and_spends_after_funding(self):
        # End-to-end proof that a self-issued key is a first-class credential:
        # it resolves, and once funded it debits like any operator-provisioned one.
        async def go():
            conn = await init_db(":memory:")
            try:
                res = await handlers.signup(conn)
                key_hash = handlers.hash_api_key(res["api_key"])

                found = await handlers.lookup_identity(conn, "api_key", key_hash)
                self.assertEqual(found, res["identity_id"])

                # Unfunded: refused.
                spent = await handlers.consume(conn, "api_key", key_hash)
                self.assertFalse(spent["success"])
                self.assertIn("balance", spent["error"])

                await handlers.topup(conn, res["identity_id"], 2, source="test")
                spent = await handlers.consume(conn, "api_key", key_hash)
                self.assertTrue(spent["success"])
                self.assertEqual(spent["balance"], 1)
            finally:
                await conn.close()
        run(go())

    def test_each_signup_is_a_distinct_identity(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                a = await handlers.signup(conn)
                b = await handlers.signup(conn)
                self.assertNotEqual(a["identity_id"], b["identity_id"])
                self.assertNotEqual(a["api_key"], b["api_key"])
            finally:
                await conn.close()
        run(go())


class RotateKeyHandlerTest(unittest.TestCase):
    def test_rotation_keeps_identity_and_balance(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                await handlers.topup(conn, first["identity_id"], 250, source="paid")

                rotated = await handlers.rotate_api_key(conn, first["api_key"])
                self.assertTrue(rotated["success"])
                self.assertEqual(rotated["identity_id"], first["identity_id"])
                self.assertEqual(rotated["balance"], 250)
                self.assertNotEqual(rotated["api_key"], first["api_key"])

                # New key spends the money the old key paid for.
                spent = await handlers.consume(
                    conn, "api_key", handlers.hash_api_key(rotated["api_key"]))
                self.assertTrue(spent["success"])
                self.assertEqual(spent["balance"], 249)
            finally:
                await conn.close()
        run(go())

    def test_old_key_stops_working_once_its_grace_is_over(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                await handlers.topup(conn, first["identity_id"], 10, source="paid")
                with patch.object(handlers, "ROTATE_GRACE_SECONDS", 0):
                    await handlers.rotate_api_key(conn, first["api_key"])

                old_hash = handlers.hash_api_key(first["api_key"])
                self.assertIsNone(await handlers.lookup_identity(conn, "api_key", old_hash))
                spent = await handlers.consume(conn, "api_key", old_hash)
                self.assertFalse(spent["success"])
            finally:
                await conn.close()
        run(go())

    def test_rejects_unknown_keys_and_keys_past_their_grace(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                self.assertFalse(
                    (await handlers.rotate_api_key(conn, "lev_not_a_real_key"))["success"])

                with patch.object(handlers, "ROTATE_GRACE_SECONDS", 0):
                    await handlers.rotate_api_key(conn, first["api_key"])
                again = await handlers.rotate_api_key(conn, first["api_key"])
                self.assertFalse(again["success"])
            finally:
                await conn.close()
        run(go())

    def test_hash_alone_cannot_rotate(self):
        # The hash is semi-public (the Edge sends it every request, /v1/validate
        # takes it unauthenticated). If it could rotate, anyone who saw it could
        # seize the account — strictly worse than the proxy-gated debit path.
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                leaked_hash = handlers.hash_api_key(first["api_key"])
                res = await handlers.rotate_api_key(conn, leaked_hash)
                self.assertFalse(res["success"])
                self.assertEqual(
                    await handlers.lookup_identity(conn, "api_key", leaked_hash),
                    first["identity_id"])
            finally:
                await conn.close()
        run(go())

    def test_chained_rotations(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                cur = await handlers.signup(conn)
                identity = cur["identity_id"]
                for _ in range(5):
                    cur = await handlers.rotate_api_key(conn, cur["api_key"])
                    self.assertTrue(cur["success"])
                self.assertEqual(cur["identity_id"], identity)
                self.assertEqual(
                    await handlers.lookup_identity(
                        conn, "api_key", handlers.hash_api_key(cur["api_key"])),
                    identity)
            finally:
                await conn.close()
        run(go())


class RotationGraceTest(unittest.TestCase):
    def test_old_key_still_works_during_the_grace_window(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                await handlers.topup(conn, first["identity_id"], 500, source="paid")
                res = await handlers.rotate_api_key(conn, first["api_key"])
                self.assertIsNotNone(res["old_key_valid_until"])

                old_hash = handlers.hash_api_key(first["api_key"])
                self.assertEqual(
                    await handlers.lookup_identity(conn, "api_key", old_hash),
                    first["identity_id"], "lost response would have stranded the account")
                spent = await handlers.consume(conn, "api_key", old_hash)
                self.assertTrue(spent["success"])
            finally:
                await conn.close()
        run(go())

    def test_a_lost_response_is_recoverable_by_retrying(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                await handlers.topup(conn, first["identity_id"], 500, source="paid")
                lost = await handlers.rotate_api_key(conn, first["api_key"])

                retry = await handlers.rotate_api_key(conn, first["api_key"])
                self.assertTrue(retry["success"])
                self.assertEqual(retry["balance"], 500)

                # The key from the lost response is an orphan nobody holds; it
                # must not stay in the authenticating set.
                self.assertIsNone(await handlers.lookup_identity(
                    conn, "api_key", handlers.hash_api_key(lost["api_key"])))
                self.assertEqual(await handlers.lookup_identity(
                    conn, "api_key", handlers.hash_api_key(retry["api_key"])),
                    first["identity_id"])
            finally:
                await conn.close()
        run(go())

    def test_at_most_two_keys_ever_authenticate(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                for _ in range(6):                      # repeated "lost" rotations
                    await handlers.rotate_api_key(conn, first["api_key"])
                cur = await conn.execute(
                    "SELECT COUNT(*) FROM credentials WHERE identity_id = ? "
                    "AND revoked_at IS NULL "
                    "AND (grace_until IS NULL OR grace_until > CURRENT_TIMESTAMP)",
                    (first["identity_id"],))
                self.assertEqual((await cur.fetchone())[0], 2)
            finally:
                await conn.close()
        run(go())

    def test_grace_expiry_kills_the_old_key(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                with patch.object(handlers, "ROTATE_GRACE_SECONDS", 0):  # expires at once
                    await handlers.rotate_api_key(conn, first["api_key"])
                self.assertIsNone(await handlers.lookup_identity(
                    conn, "api_key", handlers.hash_api_key(first["api_key"])))
            finally:
                await conn.close()
        run(go())

    def test_revoke_now_kills_the_old_key_immediately(self):
        # The leaked-key case: instant death is the whole point, and the caller
        # accepts that a lost response then costs them the account.
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                res = await handlers.rotate_api_key(conn, first["api_key"], revoke_now=True)
                self.assertIsNone(res["old_key_valid_until"])
                self.assertIsNone(await handlers.lookup_identity(
                    conn, "api_key", handlers.hash_api_key(first["api_key"])))
                self.assertEqual(await handlers.lookup_identity(
                    conn, "api_key", handlers.hash_api_key(res["api_key"])),
                    first["identity_id"])
            finally:
                await conn.close()
        run(go())

    def test_expired_grace_key_cannot_rotate_either(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                first = await handlers.signup(conn)
                with patch.object(handlers, "ROTATE_GRACE_SECONDS", 0):
                    await handlers.rotate_api_key(conn, first["api_key"])
                self.assertFalse(
                    (await handlers.rotate_api_key(conn, first["api_key"]))["success"])
            finally:
                await conn.close()
        run(go())


class AuditTrailTest(unittest.TestCase):
    def test_signup_and_rotation_leave_a_trail(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                res = await handlers.signup(conn, ip_fingerprint="deadbeef")
                await handlers.rotate_api_key(conn, res["api_key"], ip_fingerprint="deadbeef")

                cur = await conn.execute(
                    "SELECT operation, note FROM usage_log WHERE identity_id = ? "
                    "ORDER BY id", (res["identity_id"],))
                rows = await cur.fetchall()
                self.assertEqual([r[0] for r in rows], ["signup", "key_rotate"])
                self.assertEqual(rows[0][1], "ip=deadbeef")
            finally:
                await conn.close()
        run(go())

    def test_no_fingerprint_recorded_by_default(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                res = await handlers.signup(conn)
                cur = await conn.execute(
                    "SELECT note FROM usage_log WHERE identity_id = ?", (res["identity_id"],))
                self.assertIsNone((await cur.fetchone())[0])
            finally:
                await conn.close()
        run(go())

    def test_audit_row_never_holds_the_key(self):
        async def go():
            conn = await init_db(":memory:")
            try:
                res = await handlers.signup(conn, ip_fingerprint="abc123")
                cur = await conn.execute("SELECT * FROM usage_log")
                self.assertNotIn(res["api_key"], str(await cur.fetchall()))
            finally:
                await conn.close()
        run(go())


class SignupRouteTest(unittest.TestCase):
    """HTTP-level behaviour: public, unprivileged, and not tier-selectable."""

    def setUp(self):
        from unittest.mock import patch
        from fastapi.testclient import TestClient
        from app import main as m
        from app.db import init_db as real_init_db

        # db.DEFAULT_DB_PATH is bound at import time, so under `unittest
        # discover` an earlier module can fix it to the production path before
        # this file's env default is applied. Pin the lifespan's DB explicitly.
        patcher = patch.object(m, "init_db", lambda *a, **k: real_init_db(":memory:"))
        patcher.start()
        self.addCleanup(patcher.stop)

        self.m = m
        m.limiter.reset()
        self.client = TestClient(m.app)

    def _deps(self, path):
        for r in self.m.app.routes:
            if getattr(r, "path", None) == path and "POST" in getattr(r, "methods", set()):
                return [d.call.__name__ for d in r.dependant.dependencies]
        return None

    def test_is_public(self):
        self.assertNotIn("require_admin", self._deps("/v1/signup"))
        self.assertNotIn("require_proxy_token", self._deps("/v1/signup"))

    def test_returns_a_usable_key_once(self):
        with self.client as c:
            r = c.post("/v1/signup")
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertTrue(body["api_key"].startswith("lev_"))
        self.assertEqual(body["tier"], "free")
        self.assertEqual(body["balance"], 0)
        self.assertIsInstance(body["identity_id"], int)

    def test_caller_cannot_select_a_tier(self):
        # A public endpoint that honoured `initial_tier` would let anyone grant
        # themselves the top tier's rate limit for free.
        # One session throughout: an in-memory DB lives and dies with the
        # app lifespan, so a second `with` block would start from an empty one.
        with self.client as c:
            r = c.post("/v1/signup", json={"initial_tier": "pro", "credits": 10_000})
            self.assertEqual(r.status_code, 201)
            body = r.json()
            self.assertEqual(body["tier"], "free")
            self.assertEqual(body["balance"], 0)

            state = c.post("/v1/validate", json={
                "credential_type": "api_key",
                "credential_value": self.m.handlers.hash_api_key(body["api_key"]),
            }).json()
        # Known credential, but zero balance: nothing to spend, and certainly
        # not on a tier the caller asked for.
        self.assertFalse(state["valid"])
        self.assertEqual(state["error"], "insufficient balance")
        self.assertEqual(state["identity_id"], body["identity_id"])

    def test_response_tells_the_caller_which_value_goes_where(self):
        # Regression: the first version said "fund it via POST
        # /v1/payment-intents" while that endpoint wants the HASH. Following
        # the instruction literally returned 401 invalid credential, which
        # reads as "my new key is broken".
        with self.client as c:
            body = c.post("/v1/signup").json()
            self.assertIn("api_key_hash", body)
            self.assertEqual(body["api_key_hash"],
                             self.m.handlers.hash_api_key(body["api_key"]))

            r = c.post("/v1/payment-intents", json={
                "credential_type": "api_key",
                "credential_value": body["api_key_hash"], "credits": 10})
        self.assertEqual(r.status_code, 201, "the documented value must actually work")

    def test_secret_bearing_responses_are_not_cacheable(self):
        with self.client as c:
            signed_up = c.post("/v1/signup")
            rotated = c.post("/v1/keys/rotate",
                             json={"api_key": signed_up.json()["api_key"]})
        for r in (signed_up, rotated):
            self.assertEqual(r.headers.get("cache-control"), "no-store")

    def test_rotate_route_is_public_and_swaps_the_key(self):
        with self.client as c:
            self.assertNotIn("require_admin", self._deps("/v1/keys/rotate"))
            first = c.post("/v1/signup").json()
            r = c.post("/v1/keys/rotate", json={"api_key": first["api_key"]})
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertNotEqual(body["api_key"], first["api_key"])
            self.assertEqual(body["identity_id"], first["identity_id"])

            # Both resolve during the grace window — that overlap is what
            # makes a lost rotation response recoverable.
            old = c.post("/v1/validate", json={
                "credential_type": "api_key",
                "credential_value": first["api_key_hash"]}).json()
            new = c.post("/v1/validate", json={
                "credential_type": "api_key",
                "credential_value": body["api_key_hash"]}).json()
            self.assertIsNotNone(body["old_key_valid_until"])

            # ...and revoke_now closes it for the leaked-key case.
            second = c.post("/v1/keys/rotate", json={"api_key": body["api_key"],
                                                     "revoke_now": True}).json()
            killed = c.post("/v1/validate", json={
                "credential_type": "api_key",
                "credential_value": body["api_key_hash"]}).json()
        self.assertEqual(old.get("identity_id"), first["identity_id"])
        self.assertEqual(new.get("identity_id"), first["identity_id"])
        self.assertIsNone(second["old_key_valid_until"])
        self.assertEqual(killed["error"], "credential not found")

    def test_rotate_rejects_the_hash_with_an_opaque_401(self):
        with self.client as c:
            first = c.post("/v1/signup").json()
            r = c.post("/v1/keys/rotate", json={"api_key": first["api_key_hash"]})
            bogus = c.post("/v1/keys/rotate", json={"api_key": "lev_nope"})
        self.assertEqual(r.status_code, 401)
        # Identical response for "wrong value" and "not a key at all" — no oracle.
        self.assertEqual(r.status_code, bogus.status_code)
        self.assertEqual(r.json(), bogus.json())

    def test_rate_limited_per_ip(self):
        # Derived from the module constant so raising the limit in config does
        # not quietly turn this into a test of nothing.
        allowed = int(self.m.RATE_LIMIT_SIGNUP.split("/")[0])
        with self.client as c:
            codes = [c.post("/v1/signup").status_code for _ in range(allowed + 2)]
        self.assertEqual(codes.count(201), allowed)
        self.assertEqual(codes.count(429), 2)


if __name__ == "__main__":
    unittest.main()
