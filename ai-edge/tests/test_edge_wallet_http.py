"""End-to-end HTTP tests for the wallet-bound path through the Edge.

Run from `ai-edge/`:
    python -m unittest tests.test_edge_wallet_http -v

Everything outside the Edge is stubbed — the Falcon verifier, the auth-service
ledger, and the TEE gateway — so what this exercises is the wiring: that a
bind produces a session, that a signed request reaches the gateway carrying the
right tenant bearer, and that an unsigned one does not reach it at all.
"""

import base64
import importlib
import os
import sys
import tempfile
import unittest

import httpx
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import wallet_auth  # noqa: E402

SERVICE = "https://ai.leviathan.test"
WALLET_PK = "ab" * 64


def _load_app_with_wallet_enabled():
    """Re-import app.py with the wallet env set.

    app.py reads its config at import time (fail-closed startup), so the only
    way to flip WALLET_AUTH_ENABLED for a test is to reload the module.
    """
    os.environ.update(
        AUTH_SERVICE_URL="https://auth.test",
        AUTH_SERVICE_PROXY_TOKEN="ptok",
        AUTH_SERVICE_VERIFY_TLS="false",
        GATEWAY_URL="https://gw.test",
        GATEWAY_API_TOKEN="gtok",
        EDGE_TENANT_SECRET="tsecret",
        WALLET_AUTH_ENABLED="true",
        WALLET_VERIFIER_URL="http://verifier.test",
        WALLET_SERVICE_ORIGIN=SERVICE,
        EDGE_WALLET_KEY_SECRET="wallet-secret",
        WALLET_STATE_DB=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name,
    )
    if "app" in sys.modules:
        return importlib.reload(sys.modules["app"])
    import app  # noqa: PLC0415
    return app


class AcceptingVerifier:
    async def verify(self, public_key_hex, word_bytes, signature_b64):
        return None

    async def aclose(self):
        return None


class WalletHttpTest(unittest.TestCase):
    def setUp(self):
        self.edge = _load_app_with_wallet_enabled()
        self.gateway_requests = []
        self.ledger_calls = []
        self.client = TestClient(self.edge.app)
        self.client.__enter__()

        state = self.edge.app.state
        state.wallet.verifier = AcceptingVerifier()
        state.auth._c = httpx.AsyncClient(transport=httpx.MockTransport(self._ledger))
        state.gw = httpx.AsyncClient(transport=httpx.MockTransport(self._gateway))

    def tearDown(self):
        self.client.__exit__(None, None, None)

    # -- stubs --

    def _ledger(self, request: httpx.Request) -> httpx.Response:
        import json

        path = request.url.path
        body = json.loads(request.content or b"{}")
        self.ledger_calls.append((path, body))
        if path == "/v1/wallet/bind":
            return httpx.Response(200, json={
                "success": True, "identity_id": 7, "created": True,
                "balance": 50000, "unit": "millicredit", "tier": "free",
            })
        if path == "/v1/consume":
            return httpx.Response(200, json={
                "success": True, "identity_id": 7, "balance": 49000,
                "debit_token": "dt", "unit": "millicredit",
            })
        if path == "/v1/validate":
            return httpx.Response(200, json={"valid": True, "identity_id": 7, "balance": 49000})
        return httpx.Response(200, json={"success": True})

    def _gateway(self, request: httpx.Request) -> httpx.Response:
        self.gateway_requests.append(request)
        return httpx.Response(200, json={"id": "chatcmpl-1", "choices": []},
                              headers={"x-receipt-id": "rcpt_1"})

    # -- helpers --

    def _bind(self, **overrides):
        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw().hex()
        nonce = self.client.post(
            "/v1/wallet/challenge", json={"wallet_pub_key": WALLET_PK},
        ).json()["nonce"]
        now = int(self.edge.app.state.wallet.now())
        statement = {
            "purpose": wallet_auth.BIND_PURPOSE,
            "service": SERVICE,
            "nonce": nonce,
            "issued_at": now,
            "expires_at": now + 3600,
            "wallet_pub_key": WALLET_PK,
            "account_id": "mtst1qexample",
            "session_pub_key": pub,
            "e2ee_pub_key": "cd" * 32,
            "scope": ["inference", "receipts", "models"],
            "max_spend_mc": 100000,
        }
        statement.update(overrides)
        res = self.client.post("/v1/wallet/bind", json={
            "statement": statement, "signature": base64.b64encode(b"sig").decode(),
        })
        return res, sk

    def _signed_headers(self, sk, session_id, method, path, body, nonce="ab" * 16, ts=None):
        ts = ts if ts is not None else int(self.edge.app.state.wallet.now())
        payload = wallet_auth.request_signing_bytes(session_id, method, path, body, ts, nonce)
        return {
            "authorization": f"Wallet {session_id}",
            "x-wallet-timestamp": str(ts),
            "x-wallet-nonce": nonce,
            "x-wallet-signature": base64.b64encode(sk.sign(payload)).decode(),
            "content-type": "application/json",
        }

    # -- tests --

    def test_health_reports_the_wallet_surface(self):
        self.assertTrue(self.client.get("/health").json()["wallet_auth"])

    def test_bind_returns_a_session_and_registers_the_derived_credential(self):
        res, _ = self._bind()
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertTrue(body["session_id"].startswith("lev_s_"))
        self.assertEqual(body["identity_id"], 7)
        self.assertEqual(body["balance_mc"], 50000)

        path, payload = next(c for c in self.ledger_calls if c[0] == "/v1/wallet/bind")
        self.assertEqual(payload["wallet_pub_key"], WALLET_PK)
        self.assertEqual(payload["account_id"], "mtst1qexample")
        # The ledger must never see anything but the hash of the derived key.
        self.assertEqual(
            payload["api_key_hash"],
            self.edge.app.state.wallet.spend_credential_hash(WALLET_PK),
        )

    def test_signed_chat_completion_reaches_the_gateway_as_the_right_tenant(self):
        res, sk = self._bind()
        session_id = res.json()["session_id"]
        body = b'{"model":"m","messages":[]}'

        out = self.client.post(
            "/v1/chat/completions",
            headers=self._signed_headers(sk, session_id, "POST", "/v1/chat/completions", body),
            content=body,
        )
        self.assertEqual(out.status_code, 200, out.text)
        self.assertEqual(out.headers.get("x-receipt-id"), "rcpt_1")

        fwd = self.gateway_requests[-1]
        self.assertEqual(fwd.headers["x-gateway-token"], "gtok")
        self.assertEqual(fwd.headers["authorization"], f"Bearer {self.edge._tenant_bearer(7)}")
        self.assertEqual(fwd.content, body)

        # The ledger was debited against the wallet's derived credential.
        consume = next(c for c in self.ledger_calls if c[0] == "/v1/consume")[1]
        self.assertEqual(
            consume["credential_value"],
            self.edge.app.state.wallet.spend_credential_hash(WALLET_PK),
        )

    def test_session_id_without_a_signature_is_refused(self):
        res, _ = self._bind()
        out = self.client.post(
            "/v1/chat/completions",
            headers={"authorization": f"Wallet {res.json()['session_id']}"},
            content=b"{}",
        )
        self.assertEqual(out.status_code, 401)
        self.assertEqual(out.json()["error"]["type"], "wallet_missing_signature")
        self.assertEqual(self.gateway_requests, [])

    def test_tampering_with_the_body_after_signing_is_refused(self):
        res, sk = self._bind()
        session_id = res.json()["session_id"]
        signed = b'{"model":"m","messages":[]}'
        hdrs = self._signed_headers(sk, session_id, "POST", "/v1/chat/completions", signed)

        out = self.client.post("/v1/chat/completions", headers=hdrs, content=b'{"model":"evil"}')
        self.assertEqual(out.status_code, 401)
        self.assertEqual(out.json()["error"]["type"], "wallet_invalid_signature")
        self.assertEqual(self.gateway_requests, [])

    def test_replayed_request_is_refused_and_not_forwarded(self):
        res, sk = self._bind()
        session_id = res.json()["session_id"]
        body = b'{"model":"m"}'
        hdrs = self._signed_headers(sk, session_id, "POST", "/v1/chat/completions", body)

        self.assertEqual(self.client.post("/v1/chat/completions", headers=hdrs, content=body).status_code, 200)
        again = self.client.post("/v1/chat/completions", headers=hdrs, content=body)
        self.assertEqual(again.status_code, 401)
        self.assertEqual(again.json()["error"]["type"], "wallet_replay")
        self.assertEqual(len(self.gateway_requests), 1)

    def test_spend_cap_stops_the_session_before_the_ledger_is_touched(self):
        res, sk = self._bind(max_spend_mc=1000)
        session_id = res.json()["session_id"]
        body = b'{"model":"m"}'

        first = self.client.post(
            "/v1/chat/completions",
            headers=self._signed_headers(sk, session_id, "POST", "/v1/chat/completions", body,
                                         nonce="11" * 16),
            content=body)
        self.assertEqual(first.status_code, 200)

        consumes_before = len([c for c in self.ledger_calls if c[0] == "/v1/consume"])
        second = self.client.post(
            "/v1/chat/completions",
            headers=self._signed_headers(sk, session_id, "POST", "/v1/chat/completions", body,
                                         nonce="22" * 16),
            content=body)
        self.assertEqual(second.status_code, 402)
        self.assertEqual(second.json()["error"]["type"], "wallet_spend_cap")
        self.assertEqual(
            len([c for c in self.ledger_calls if c[0] == "/v1/consume"]), consumes_before,
        )

    def test_revoke_ends_the_session(self):
        res, sk = self._bind()
        session_id = res.json()["session_id"]

        out = self.client.post(
            "/v1/wallet/session/revoke",
            headers=self._signed_headers(sk, session_id, "POST", "/v1/wallet/session/revoke", b""),
        )
        self.assertEqual(out.status_code, 200)
        self.assertTrue(out.json()["revoked"])

        after = self.client.post(
            "/v1/chat/completions",
            headers=self._signed_headers(sk, session_id, "POST", "/v1/chat/completions", b"{}",
                                         nonce="33" * 16),
            content=b"{}")
        self.assertEqual(after.json()["error"]["type"], "wallet_session_revoked")

    def test_api_key_path_still_works_alongside(self):
        body = b'{"model":"m"}'
        out = self.client.post(
            "/v1/chat/completions",
            headers={"authorization": "Bearer lev_plainkey"},
            content=body)
        self.assertEqual(out.status_code, 200, out.text)
        consume = next(c for c in reversed(self.ledger_calls) if c[0] == "/v1/consume")[1]
        self.assertEqual(consume["credential_value"], self.edge.AuthClient.hash_key("lev_plainkey"))

    def test_bind_is_refused_when_the_statement_names_another_service(self):
        res, _ = self._bind(service="https://evil.test")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()["error"]["type"], "wallet_invalid_statement")


if __name__ == "__main__":
    unittest.main()
