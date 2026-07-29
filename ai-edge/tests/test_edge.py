"""Tests for the Leviathan AI Edge auth/metering gate.

Run from `ai-edge/`:
    python -m unittest tests.test_edge -v

We drive AuthClient's httpx with a MockTransport (no real auth-service), and
check every status maps to exactly one decision so the user-facing HTTP code
is deterministic.
"""

import asyncio
import hashlib
import os
import sys
import unittest

import httpx

# Config must exist BEFORE importing app (fail-closed startup checks run at import).
os.environ.setdefault("AUTH_SERVICE_URL", "https://auth.test")
os.environ.setdefault("AUTH_SERVICE_PROXY_TOKEN", "ptok")
os.environ.setdefault("AUTH_SERVICE_VERIFY_TLS", "false")
os.environ.setdefault("GATEWAY_URL", "https://gw.test")
os.environ.setdefault("GATEWAY_API_TOKEN", "gtok")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as edge  # noqa: E402


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _auth_with(handler):
    ac = edge.AuthClient()
    ac._c = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return ac


class HashKeyTest(unittest.TestCase):
    def test_sha256_hex(self):
        h = edge.AuthClient.hash_key("lev_abc")
        self.assertEqual(h, hashlib.sha256(b"lev_abc").hexdigest())
        self.assertEqual(len(h), 64)


class ConsumeMappingTest(unittest.TestCase):
    def test_allow_and_sends_proxy_token_and_hash(self):
        seen = {}

        def handler(req: httpx.Request) -> httpx.Response:
            seen["auth"] = req.headers.get("authorization")
            import json
            seen["cred"] = json.loads(req.content)["credential_value"]
            return httpx.Response(200, json={"success": True, "balance": 9})

        ac = _auth_with(handler)
        r = run(ac.consume("lev_abc", "edge:x"))
        self.assertEqual(r.status, edge.ALLOW)
        self.assertEqual(r.balance, 9)
        self.assertEqual(seen["auth"], "Bearer ptok")                       # proxy-gated
        self.assertEqual(seen["cred"], hashlib.sha256(b"lev_abc").hexdigest())  # hash, not raw

    def test_no_balance(self):
        ac = _auth_with(lambda r: httpx.Response(200, json={"success": False, "error": "insufficient balance"}))
        self.assertEqual(run(ac.consume("k", "i")).status, edge.DENY_NO_BALANCE)

    def test_invalid_key_401(self):
        ac = _auth_with(lambda r: httpx.Response(401, json={"detail": "invalid proxy token"}))
        self.assertEqual(run(ac.consume("k", "i")).status, edge.DENY_UNAUTH)

    def test_rate_limited_429(self):
        ac = _auth_with(lambda r: httpx.Response(429, json={"detail": "rate"}))
        self.assertEqual(run(ac.consume("k", "i")).status, edge.DENY_RATE)

    def test_5xx_is_auth_down(self):
        ac = _auth_with(lambda r: httpx.Response(503, json={"error": "down"}))
        self.assertEqual(run(ac.consume("k", "i")).status, edge.DENY_DOWN)

    def test_unreachable_is_auth_down(self):
        def boom(req):
            raise httpx.ConnectError("refused", request=req)
        ac = _auth_with(boom)
        self.assertEqual(run(ac.consume("k", "i")).status, edge.DENY_DOWN)


class ValidateMappingTest(unittest.TestCase):
    def test_valid(self):
        ac = _auth_with(lambda r: httpx.Response(200, json={"valid": True, "balance": 5}))
        self.assertEqual(run(ac.validate("k")).status, edge.ALLOW)

    def test_known_but_empty_is_no_balance(self):
        ac = _auth_with(lambda r: httpx.Response(200, json={"valid": False, "error": "insufficient balance"}))
        self.assertEqual(run(ac.validate("k")).status, edge.DENY_NO_BALANCE)

    def test_unknown_is_unauth(self):
        ac = _auth_with(lambda r: httpx.Response(200, json={"valid": False, "error": "credential not found"}))
        self.assertEqual(run(ac.validate("k")).status, edge.DENY_UNAUTH)


class HelpersTest(unittest.TestCase):
    def test_deny_status_codes(self):
        codes = {s: edge._deny_response(edge.AuthResult(s)).status_code
                 for s in (edge.DENY_UNAUTH, edge.DENY_NO_BALANCE, edge.DENY_RATE, edge.DENY_DOWN)}
        self.assertEqual(codes[edge.DENY_UNAUTH], 401)
        self.assertEqual(codes[edge.DENY_NO_BALANCE], 402)
        self.assertEqual(codes[edge.DENY_RATE], 429)
        self.assertEqual(codes[edge.DENY_DOWN], 503)

    def test_fwd_request_headers_strip_and_inject(self):
        class R:
            headers = {"authorization": "Bearer lev_user", "content-type": "application/json", "host": "x"}
        h = edge._fwd_request_headers(R())
        self.assertEqual(h["authorization"], "Bearer gtok")   # internal token, user bearer stripped
        self.assertNotIn("host", h)
        self.assertEqual(h["content-type"], "application/json")


class EndToEndProxyTest(unittest.TestCase):
    """Drive the real FastAPI routes over ASGI with mocked auth-service +
    gateway, so the full path (auth gate -> forward -> deny/refund) is tested."""

    def _run_chat(self, consume="allow", gateway=(200, b'{"ok":true}')):
        state = {"refunds": 0, "gw_calls": 0}

        def auth_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/consume":
                if consume == "allow":
                    return httpx.Response(200, json={"success": True, "balance": 9})
                return httpx.Response(200, json={"success": False, "error": "insufficient balance"})
            if req.url.path == "/v1/refund":
                state["refunds"] += 1
                return httpx.Response(200, json={"success": True})
            return httpx.Response(404)

        def gw_handler(req: httpx.Request) -> httpx.Response:
            state["gw_calls"] += 1
            code, body = gateway
            return httpx.Response(code, content=body, headers={"content-type": "application/json"})

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))

        async def go():
            transport = httpx.ASGITransport(app=edge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.post(
                    "/v1/chat/completions",
                    headers={"authorization": "Bearer lev_user"},
                    json={"model": "gpt-oss-120b", "messages": [{"role": "user", "content": "hi"}]},
                )

        resp = run(go())
        return resp, state

    def test_allow_forwards_and_returns_gateway_body(self):
        resp, state = self._run_chat(consume="allow", gateway=(200, b'{"ok":true}'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'{"ok":true}')
        self.assertEqual(state["gw_calls"], 1)
        self.assertEqual(state["refunds"], 0)

    def test_no_balance_returns_402_and_does_not_call_gateway(self):
        resp, state = self._run_chat(consume="no_balance")
        self.assertEqual(resp.status_code, 402)
        self.assertEqual(state["gw_calls"], 0)      # never touched the gateway
        self.assertEqual(state["refunds"], 0)

    def test_missing_key_returns_401(self):
        edge.app.state.auth = edge.AuthClient()
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

        async def go():
            transport = httpx.ASGITransport(app=edge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.post("/v1/chat/completions", json={"model": "m", "messages": []})

        self.assertEqual(run(go()).status_code, 401)

    def test_gateway_error_refunds_credit(self):
        resp, state = self._run_chat(consume="allow", gateway=(404, b'{"error":"not_found"}'))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(state["gw_calls"], 1)
        self.assertEqual(state["refunds"], 1)       # debited then refunded


if __name__ == "__main__":
    unittest.main()
