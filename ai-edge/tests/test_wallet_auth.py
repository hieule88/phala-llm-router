"""Tests for wallet-bound authentication (../wallet_auth.py).

Run from `ai-edge/`:
    python -m unittest tests.test_wallet_auth -v

Falcon verification is stubbed — it is the wallet-verifier's job and has its
own Rust tests with real signatures. What is exercised here is everything the
Edge itself decides: statement validity, nonce burning, replay, spend caps,
and the Ed25519 request signature that authorizes each call.
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import wallet_auth  # noqa: E402
from wallet_auth import (  # noqa: E402
    WalletAuthConfig,
    WalletAuthenticator,
    WalletAuthError,
    WalletStore,
)

SERVICE = "https://ai.leviathan.test"
WALLET_PK = "ab" * 64


def run(coro):
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class StubVerifier:
    """Stands in for the wallet-verifier. Records what it was asked."""

    def __init__(self, valid=True):
        self.valid = valid
        self.calls = []

    async def verify(self, public_key_hex, word_bytes, signature_b64):
        self.calls.append((public_key_hex, word_bytes, signature_b64))
        if not self.valid:
            raise WalletAuthError("wallet_invalid_signature", "nope")


def make_auth(now=None, verifier=None, **overrides):
    cfg_kwargs = dict(
        enabled=True,
        verifier_url="http://verifier.test",
        service_origin=SERVICE,
        key_secret="wallet-secret",
        state_db=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name,
        session_max_ttl_sec=86400,
        max_spend_mc=1000000,
        verifier_timeout_sec=5.0,
    )
    cfg_kwargs.update(overrides)
    cfg = WalletAuthConfig(**cfg_kwargs)
    clock = now or (lambda: 1765000000)
    return WalletAuthenticator(cfg, WalletStore(cfg.state_db), verifier or StubVerifier(), clock=clock)


def make_statement(auth, session_pub_hex, nonce, **overrides):
    now = auth.now()
    stmt = {
        "purpose": wallet_auth.BIND_PURPOSE,
        "service": SERVICE,
        "nonce": nonce,
        "issued_at": now,
        "expires_at": now + 3600,
        "wallet_pub_key": WALLET_PK,
        "account_id": "mtst1qexample",
        "session_pub_key": session_pub_hex,
        "e2ee_pub_key": "cd" * 32,
        "scope": ["inference", "receipts", "models"],
        "max_spend_mc": 100000,
    }
    stmt.update(overrides)
    return stmt


def bind(auth, session_key=None, **overrides):
    """Full happy-path bind; returns (session, private key)."""
    sk = session_key or Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw().hex()
    nonce = auth.challenge(WALLET_PK)["nonce"]
    stmt = make_statement(auth, pub, nonce, **overrides)
    normalized = run(auth.verify_bind(stmt, base64.b64encode(b"sig").decode()))
    session = auth.store.create_session(42, normalized, normalized["scope"], auth.now())
    return session, sk


def sign_request(sk, session_id, method, path, body, ts, nonce):
    payload = wallet_auth.request_signing_bytes(session_id, method, path, body, ts, nonce)
    return base64.b64encode(sk.sign(payload)).decode()


def headers(sk, session_id, method, path, body, ts, nonce="ab" * 16):
    return {
        "x-wallet-timestamp": str(ts),
        "x-wallet-nonce": nonce,
        "x-wallet-signature": sign_request(sk, session_id, method, path, body, ts, nonce),
    }


class CanonicalizationTest(unittest.TestCase):
    def test_jcs_sorts_keys_and_drops_whitespace(self):
        self.assertEqual(wallet_auth.jcs({"b": 1, "a": [2, {"d": 3, "c": 4}]}),
                         b'{"a":[2,{"c":4,"d":3}],"b":1}')

    def test_jcs_rejects_floats(self):
        with self.assertRaises(WalletAuthError):
            wallet_auth.jcs({"a": 1.5})

    def test_word_limbs_are_reduced_field_elements(self):
        limbs = wallet_auth.statement_word({"a": 1})
        self.assertEqual(len(limbs), 4)
        for limb in limbs:
            self.assertLess(limb, wallet_auth.GOLDILOCKS_P)

    def test_word_bytes_are_little_endian_limbs(self):
        stmt = {"a": 1}
        limbs = wallet_auth.statement_word(stmt)
        raw = wallet_auth.statement_word_bytes(stmt)
        self.assertEqual(len(raw), 32)
        self.assertEqual(int.from_bytes(raw[0:8], "little"), limbs[0])

    def test_word_matches_the_documented_construction(self):
        # Pins §3.1 so a refactor cannot quietly change what the wallet must
        # hash — a mismatch here is an outage, not a test failure.
        stmt = {"purpose": "leviathan.wallet.bind.v1", "n": 7}
        digest = hashlib.sha512(wallet_auth.jcs(stmt)).digest()
        expected = [
            int.from_bytes(digest[8 * i:8 * i + 8], "little") % wallet_auth.GOLDILOCKS_P
            for i in range(4)
        ]
        self.assertEqual(wallet_auth.statement_word(stmt), expected)


class CrossLanguageVectorTest(unittest.TestCase):
    """Pinned bytes shared with the TypeScript client.

    The wallet builds these bytes and the Edge rebuilds them independently; if
    the two ever disagree, every signature stops verifying. The identical
    vector lives in clients/wallet-aci/test/wallet-aci.test.ts, so drift on
    either side fails a test instead of an outage. Non-ASCII content is in the
    fixture on purpose — it is where two JSON encoders are most likely to part
    ways.
    """

    STATEMENT = {
        "purpose": "leviathan.wallet.bind.v1",
        "service": "https://ai.leviathan.test",
        "nonce": "aa" * 32,
        "issued_at": 1765000000,
        "expires_at": 1765043200,
        "wallet_pub_key": "ab" * 64,
        "account_id": "mtst1qexample — ünïcode",
        "session_pub_key": "cd" * 32,
        "e2ee_pub_key": "ef" * 32,
        "scope": ["inference", "receipts", "models"],
        "max_spend_mc": 100000,
    }
    BODY = '{"model":"m","messages":[{"role":"user","content":"xin chào"}]}'.encode()

    def test_statement_word(self):
        self.assertEqual(
            wallet_auth.statement_word_bytes(self.STATEMENT).hex(),
            "08460a83f2c3c8d2a229191a1fb9353ab477f31ec7de4b0d791d340a36d02d92",
        )

    def test_request_signing_bytes(self):
        self.assertEqual(
            wallet_auth.request_signing_bytes(
                "lev_s_abc", "POST", "/v1/chat/completions", self.BODY, 1765000123, "ab" * 8,
            ).decode(),
            '{"body_sha256":"1af010da68c70ae832966da81b4bf2f185724b0f296565677f0c25e834b4a89c",'
            '"method":"POST","nonce":"abababababababab","path":"/v1/chat/completions",'
            '"purpose":"leviathan.wallet.request.v1","session":"lev_s_abc","ts":1765000123}',
        )

    def test_statement_jcs_is_unescaped_utf8(self):
        # ensure_ascii would produce \\u escapes here and silently diverge from
        # the browser's JSON.stringify.
        self.assertIn("mtst1qexample — ünïcode", wallet_auth.jcs(self.STATEMENT).decode())


class ChallengeTest(unittest.TestCase):
    def test_nonce_is_single_use(self):
        auth = make_auth()
        nonce = auth.challenge(WALLET_PK)["nonce"]
        self.assertEqual(len(nonce), 64)
        auth.store.consume_challenge(nonce, WALLET_PK, auth.now())
        with self.assertRaises(WalletAuthError):
            auth.store.consume_challenge(nonce, WALLET_PK, auth.now())

    def test_nonce_is_bound_to_the_wallet_that_asked(self):
        auth = make_auth()
        nonce = auth.challenge(WALLET_PK)["nonce"]
        with self.assertRaises(WalletAuthError):
            auth.store.consume_challenge(nonce, "ff" * 64, auth.now())

    def test_expired_nonce_is_refused(self):
        t = [1765000000]
        auth = make_auth(now=lambda: t[0])
        nonce = auth.challenge(WALLET_PK)["nonce"]
        t[0] += wallet_auth.CHALLENGE_TTL_SEC + 1
        with self.assertRaises(WalletAuthError):
            auth.store.consume_challenge(nonce, WALLET_PK, auth.now())


class StatementValidationTest(unittest.TestCase):
    def setUp(self):
        self.auth = make_auth()
        self.pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

    def _stmt(self, **overrides):
        return make_statement(self.auth, self.pub, "aa" * 32, **overrides)

    def test_accepts_a_well_formed_statement(self):
        self.assertEqual(self.auth.validate_statement(self._stmt())["service"], SERVICE)

    def test_rejects_extra_or_missing_fields(self):
        stmt = self._stmt()
        stmt["extra"] = 1
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(stmt)
        del stmt["extra"]
        del stmt["scope"]
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(stmt)

    def test_rejects_another_services_statement(self):
        # Without this a statement signed for a different Leviathan deployment
        # would authorize spending here.
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(service="https://evil.test"))

    def test_rejects_wrong_purpose(self):
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(purpose="something.else"))

    def test_rejects_stale_or_overlong_sessions(self):
        now = self.auth.now()
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(issued_at=now - 10000))
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(expires_at=now - 1))
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(expires_at=now + 86401))

    def test_rejects_spend_cap_above_policy(self):
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(max_spend_mc=1000001))
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(max_spend_mc=0))

    def test_rejects_unknown_scope(self):
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(scope=["inference", "withdraw"]))

    def test_requires_canonical_hex(self):
        # Uppercase or 0x-prefixed hex would make the stored key differ from
        # the bytes the wallet hashed, so the signature would cover something
        # other than what we act on.
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(wallet_pub_key=WALLET_PK.upper()))
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(session_pub_key="0x" + self.pub))

    def test_rejects_wrong_length_session_key(self):
        with self.assertRaises(WalletAuthError):
            self.auth.validate_statement(self._stmt(session_pub_key="ab" * 31))


class BindTest(unittest.TestCase):
    def test_bind_verifies_the_word_over_the_statement(self):
        verifier = StubVerifier()
        auth = make_auth(verifier=verifier)
        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw().hex()
        nonce = auth.challenge(WALLET_PK)["nonce"]
        stmt = make_statement(auth, pub, nonce)

        run(auth.verify_bind(stmt, base64.b64encode(b"sig").decode()))

        pk_hex, word, _ = verifier.calls[0]
        self.assertEqual(pk_hex, WALLET_PK)
        self.assertEqual(word, wallet_auth.statement_word_bytes(stmt))

    def test_key_order_does_not_change_the_signed_word(self):
        # The wallet and the Edge canonicalize independently; a client that
        # ships its JSON in a different key order must verify identically.
        verifier = StubVerifier()
        auth = make_auth(verifier=verifier)
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

        n1 = auth.challenge(WALLET_PK)["nonce"]
        stmt = make_statement(auth, pub, n1)
        run(auth.verify_bind(stmt, base64.b64encode(b"s").decode()))

        n2 = auth.challenge(WALLET_PK)["nonce"]
        shuffled = dict(reversed(list(make_statement(auth, pub, n2).items())))
        run(auth.verify_bind(shuffled, base64.b64encode(b"s").decode()))

        w1 = json.loads(wallet_auth.jcs(dict(stmt, nonce="X")))
        w2 = json.loads(wallet_auth.jcs(dict(shuffled, nonce="X")))
        self.assertEqual(w1, w2)
        self.assertEqual(
            wallet_auth.statement_word_bytes(dict(stmt, nonce="X")),
            wallet_auth.statement_word_bytes(dict(shuffled, nonce="X")),
        )

    def test_failed_verification_still_burns_the_nonce(self):
        # Otherwise a challenge stays live for unlimited retries.
        auth = make_auth(verifier=StubVerifier(valid=False))
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        nonce = auth.challenge(WALLET_PK)["nonce"]
        stmt = make_statement(auth, pub, nonce)
        sig = base64.b64encode(b"sig").decode()

        with self.assertRaises(WalletAuthError):
            run(auth.verify_bind(stmt, sig))
        with self.assertRaises(WalletAuthError) as ctx:
            run(auth.verify_bind(stmt, sig))
        self.assertEqual(ctx.exception.code, "wallet_invalid_nonce")

    def test_rejects_replay_of_someone_elses_statement(self):
        auth = make_auth()
        _, _sk = bind(auth)
        # The same statement cannot be replayed: its nonce is gone.
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        stmt = make_statement(auth, pub, "00" * 32)
        with self.assertRaises(WalletAuthError) as ctx:
            run(auth.verify_bind(stmt, base64.b64encode(b"sig").decode()))
        self.assertEqual(ctx.exception.code, "wallet_invalid_nonce")

    def test_rejects_a_session_key_already_bound_to_another_wallet(self):
        auth = make_auth()
        session, sk = bind(auth)
        other_wallet = "cc" * 64
        nonce = auth.challenge(other_wallet)["nonce"]
        stmt = make_statement(
            auth, session.session_pub_key, nonce, wallet_pub_key=other_wallet,
        )
        with self.assertRaises(WalletAuthError) as ctx:
            run(auth.verify_bind(stmt, base64.b64encode(b"sig").decode()))
        self.assertEqual(ctx.exception.code, "wallet_session_key_reused")

    def test_rejects_non_base64_signature(self):
        auth = make_auth()
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        nonce = auth.challenge(WALLET_PK)["nonce"]
        with self.assertRaises(WalletAuthError):
            run(auth.verify_bind(make_statement(auth, pub, nonce), "not base64!!"))


class SpendCredentialTest(unittest.TestCase):
    def test_hash_is_deterministic_and_secret_dependent(self):
        a = make_auth()
        b = make_auth(key_secret="different")
        self.assertEqual(a.spend_credential_hash(WALLET_PK), a.spend_credential_hash(WALLET_PK))
        self.assertNotEqual(a.spend_credential_hash(WALLET_PK), b.spend_credential_hash(WALLET_PK))
        self.assertNotEqual(a.spend_credential_hash(WALLET_PK), a.spend_credential_hash("ff" * 64))
        self.assertEqual(len(a.spend_credential_hash(WALLET_PK)), 64)

    def test_hash_matches_the_documented_derivation(self):
        auth = make_auth()
        import hmac as _hmac

        mac = _hmac.new(b"wallet-secret", WALLET_PK.encode(), hashlib.sha256).hexdigest()
        expected = hashlib.sha256(f"lev_w_{mac}".encode()).hexdigest()
        self.assertEqual(auth.spend_credential_hash(WALLET_PK), expected)


class RequestAuthTest(unittest.TestCase):
    def setUp(self):
        self.auth = make_auth()
        self.session, self.sk = bind(self.auth)
        self.body = b'{"model":"x"}'

    def _auth(self, **overrides):
        kwargs = dict(
            session_id=self.session.session_id,
            method="POST",
            path="/v1/chat/completions",
            body=self.body,
            headers=headers(self.sk, self.session.session_id, "POST",
                            "/v1/chat/completions", self.body, self.auth.now()),
            required_scope="inference",
        )
        kwargs.update(overrides)
        return self.auth.authenticate_request(**kwargs)

    def test_valid_signature_authenticates(self):
        self.assertEqual(self._auth().session_id, self.session.session_id)

    def test_session_id_alone_is_not_enough(self):
        # The whole point: leaking the session id must not grant access.
        with self.assertRaises(WalletAuthError) as ctx:
            self._auth(headers={})
        self.assertEqual(ctx.exception.code, "wallet_missing_signature")

    def test_signature_is_bound_to_the_body(self):
        with self.assertRaises(WalletAuthError) as ctx:
            self._auth(body=b'{"model":"evil"}')
        self.assertEqual(ctx.exception.code, "wallet_invalid_signature")

    def test_signature_is_bound_to_the_path(self):
        with self.assertRaises(WalletAuthError):
            self._auth(path="/v1/embeddings")

    def test_signature_is_bound_to_the_method(self):
        with self.assertRaises(WalletAuthError):
            self._auth(method="GET")

    def test_signature_from_another_key_is_rejected(self):
        other = Ed25519PrivateKey.generate()
        with self.assertRaises(WalletAuthError):
            self._auth(headers=headers(other, self.session.session_id, "POST",
                                       "/v1/chat/completions", self.body, self.auth.now()))

    def test_replayed_nonce_is_rejected(self):
        hdrs = headers(self.sk, self.session.session_id, "POST",
                       "/v1/chat/completions", self.body, self.auth.now())
        self._auth(headers=hdrs)
        with self.assertRaises(WalletAuthError) as ctx:
            self._auth(headers=hdrs)
        self.assertEqual(ctx.exception.code, "wallet_replay")

    def test_stale_timestamp_is_rejected(self):
        old = self.auth.now() - wallet_auth.REQUEST_CLOCK_SKEW_SEC - 1
        with self.assertRaises(WalletAuthError) as ctx:
            self._auth(headers=headers(self.sk, self.session.session_id, "POST",
                                       "/v1/chat/completions", self.body, old))
        self.assertEqual(ctx.exception.code, "wallet_stale_request")

    def test_bad_signature_does_not_burn_the_nonce(self):
        # A failed verification must not let an unauthenticated caller poison
        # the replay cache with nonces the real client is about to use.
        nonce = "cd" * 16
        bad = headers(Ed25519PrivateKey.generate(), self.session.session_id, "POST",
                      "/v1/chat/completions", self.body, self.auth.now(), nonce=nonce)
        with self.assertRaises(WalletAuthError):
            self._auth(headers=bad)
        good = headers(self.sk, self.session.session_id, "POST",
                       "/v1/chat/completions", self.body, self.auth.now(), nonce=nonce)
        self.assertEqual(self._auth(headers=good).session_id, self.session.session_id)

    def test_scope_is_enforced(self):
        auth = make_auth()
        session, sk = bind(auth, scope=["receipts"])
        with self.assertRaises(WalletAuthError) as ctx:
            auth.authenticate_request(
                session.session_id, "POST", "/v1/chat/completions", b"{}",
                headers(sk, session.session_id, "POST", "/v1/chat/completions", b"{}", auth.now()),
                "inference",
            )
        self.assertEqual(ctx.exception.code, "wallet_scope")
        self.assertEqual(ctx.exception.status, 403)

    def test_unknown_and_revoked_sessions_are_rejected(self):
        with self.assertRaises(WalletAuthError) as ctx:
            self._auth(session_id="lev_s_deadbeef")
        self.assertEqual(ctx.exception.code, "wallet_unknown_session")

        self.auth.store.revoke_session(self.session.session_id, self.auth.now())
        with self.assertRaises(WalletAuthError) as ctx:
            self._auth()
        self.assertEqual(ctx.exception.code, "wallet_session_revoked")

    def test_expired_session_is_rejected(self):
        t = [1765000000]
        auth = make_auth(now=lambda: t[0])
        session, sk = bind(auth)
        t[0] = session.expires_at + 1
        with self.assertRaises(WalletAuthError) as ctx:
            auth.authenticate_request(
                session.session_id, "POST", "/v1/chat/completions", b"{}",
                headers(sk, session.session_id, "POST", "/v1/chat/completions", b"{}", auth.now()),
                "inference",
            )
        self.assertEqual(ctx.exception.code, "wallet_session_expired")


class SpendCapTest(unittest.TestCase):
    def test_cap_is_enforced_and_releasable(self):
        auth = make_auth()
        session, _ = bind(auth, max_spend_mc=2000)
        auth.store.charge(session.session_id, 1000, auth.now())
        auth.store.charge(session.session_id, 1000, auth.now())
        with self.assertRaises(WalletAuthError) as ctx:
            auth.store.charge(session.session_id, 1000, auth.now())
        self.assertEqual(ctx.exception.code, "wallet_spend_cap")
        self.assertEqual(ctx.exception.status, 402)

        auth.store.uncharge(session.session_id, 1000)
        auth.store.charge(session.session_id, 1000, auth.now())

    def test_uncharge_cannot_mint_budget(self):
        auth = make_auth()
        session, _ = bind(auth, max_spend_mc=1000)
        for _ in range(3):
            auth.store.uncharge(session.session_id, 1000)
        auth.store.charge(session.session_id, 1000, auth.now())
        with self.assertRaises(WalletAuthError):
            auth.store.charge(session.session_id, 1000, auth.now())

    def test_revoked_session_cannot_be_charged(self):
        auth = make_auth()
        session, _ = bind(auth)
        auth.store.revoke_session(session.session_id, auth.now())
        with self.assertRaises(WalletAuthError):
            auth.store.charge(session.session_id, 1000, auth.now())

    def test_revoke_all_kills_every_session_of_the_wallet(self):
        auth = make_auth()
        s1, _ = bind(auth)
        s2, _ = bind(auth)
        self.assertEqual(auth.store.revoke_all_for_wallet(WALLET_PK, auth.now()), 2)
        for s in (s1, s2):
            with self.assertRaises(WalletAuthError):
                auth.store.get_session(s.session_id, auth.now())


class ConfigTest(unittest.TestCase):
    def test_disabled_config_needs_nothing(self):
        self.assertFalse(WalletAuthConfig.from_env({}).enabled)

    def test_enabled_config_fails_closed_on_missing_secrets(self):
        with self.assertRaises(RuntimeError):
            WalletAuthConfig.from_env({"WALLET_AUTH_ENABLED": "true"})
        with self.assertRaises(RuntimeError):
            WalletAuthConfig.from_env({
                "WALLET_AUTH_ENABLED": "true",
                "WALLET_VERIFIER_URL": "http://v",
                "WALLET_SERVICE_ORIGIN": SERVICE,
            })

    def test_enabled_config_accepts_a_full_environment(self):
        cfg = WalletAuthConfig.from_env({
            "WALLET_AUTH_ENABLED": "true",
            "WALLET_VERIFIER_URL": "http://v/",
            "WALLET_SERVICE_ORIGIN": SERVICE + "/",
            "EDGE_WALLET_KEY_SECRET": "s",
        })
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.verifier_url, "http://v")
        self.assertEqual(cfg.service_origin, SERVICE)


class VerifierClientTest(unittest.TestCase):
    def test_unreachable_verifier_fails_closed_as_503(self):
        import httpx

        cfg = WalletAuthConfig.from_env({
            "WALLET_AUTH_ENABLED": "true",
            "WALLET_VERIFIER_URL": "http://v",
            "WALLET_SERVICE_ORIGIN": SERVICE,
            "EDGE_WALLET_KEY_SECRET": "s",
        })

        def boom(request):
            raise httpx.ConnectError("down", request=request)

        v = wallet_auth.FalconVerifier(cfg, httpx.AsyncClient(transport=httpx.MockTransport(boom)))
        with self.assertRaises(WalletAuthError) as ctx:
            run(v.verify(WALLET_PK, b"\x00" * 32, "c2ln"))
        self.assertEqual(ctx.exception.code, "wallet_verifier_down")
        self.assertEqual(ctx.exception.status, 503)

    def test_invalid_verdict_is_a_rejection(self):
        import httpx

        cfg = WalletAuthConfig.from_env({
            "WALLET_AUTH_ENABLED": "true",
            "WALLET_VERIFIER_URL": "http://v",
            "WALLET_SERVICE_ORIGIN": SERVICE,
            "EDGE_WALLET_KEY_SECRET": "s",
        })
        v = wallet_auth.FalconVerifier(
            cfg,
            httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={"valid": False}))),
        )
        with self.assertRaises(WalletAuthError) as ctx:
            run(v.verify(WALLET_PK, b"\x00" * 32, "c2ln"))
        self.assertEqual(ctx.exception.code, "wallet_invalid_signature")


if __name__ == "__main__":
    unittest.main()
