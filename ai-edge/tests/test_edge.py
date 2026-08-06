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
os.environ.setdefault("EDGE_TENANT_SECRET", "tsecret")

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
            return httpx.Response(200, json={"success": True, "balance": 9, "identity_id": 7,
                                             "debit_token": "tok-1"})

        ac = _auth_with(handler)
        r = run(ac.consume("lev_abc", "edge:x"))
        self.assertEqual(r.status, edge.ALLOW)
        self.assertEqual(r.balance, 9)
        self.assertEqual(r.identity_id, 7)
        self.assertEqual(r.debit_token, "tok-1")
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
        ac = _auth_with(lambda r: httpx.Response(200, json={"valid": True, "balance": 5, "identity_id": 3}))
        res = run(ac.validate("k"))
        self.assertEqual(res.status, edge.ALLOW)
        self.assertEqual(res.identity_id, 3)

    def test_known_but_empty_is_no_balance_and_keeps_identity(self):
        ac = _auth_with(lambda r: httpx.Response(
            200, json={"valid": False, "error": "insufficient balance", "identity_id": 3}))
        res = run(ac.validate("k"))
        self.assertEqual(res.status, edge.DENY_NO_BALANCE)
        self.assertEqual(res.identity_id, 3)

    def test_unknown_is_unauth(self):
        ac = _auth_with(lambda r: httpx.Response(200, json={"valid": False, "error": "credential not found"}))
        self.assertEqual(run(ac.validate("k")).status, edge.DENY_UNAUTH)

    def test_sends_proxy_token_so_auth_buckets_per_credential(self):
        # validate is a public endpoint, but auth-service uses the proxy token to
        # recognise OUR calls and rate-limit them per credential. Without it every
        # tenant shares the Edge's single per-IP bucket, and one user polling
        # /v1/models 429s -> 503s everyone else's model list and receipt reads.
        seen = {}

        def handler(req: httpx.Request) -> httpx.Response:
            seen["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json={"valid": True, "balance": 5, "identity_id": 3})

        run(_auth_with(handler).validate("k"))
        self.assertEqual(seen["auth"], f"Bearer {edge.AUTH_SERVICE_PROXY_TOKEN}")


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
            headers = {"authorization": "Bearer lev_user", "content-type": "application/json",
                       "host": "x", "x-gateway-token": "smuggled", "x-user-tier": "vip"}
        h = edge._fwd_request_headers(R(), identity_id=7)
        # Service token rides x-gateway-token; authorization carries the
        # per-user tenant bearer (never the raw user key, never the api token).
        self.assertEqual(h["x-gateway-token"], "gtok")
        self.assertEqual(h["authorization"], f"Bearer {edge._tenant_bearer(7)}")
        self.assertNotIn("lev_user", str(h))
        self.assertNotIn("host", h)
        self.assertNotIn("x-user-tier", h)                    # client can't smuggle tier
        self.assertEqual(h["content-type"], "application/json")

    def test_fwd_request_headers_allowlist_drops_response_changing_headers(self):
        # The idempotency key covers path+body only, so any client header that
        # can change the gateway's answer would let a replay of an already-paid
        # body produce a different outcome. Only the allowlist gets through.
        class R:
            headers = {"content-type": "application/json", "accept": "*/*",
                       "x-upstream-verification": "bogus", "x-e2ee-version": "99",
                       "x-signing-algo": "ed25519", "x-anything-else": "1"}
        h = edge._fwd_request_headers(R(), identity_id=7)
        for smuggled in ("x-upstream-verification", "x-e2ee-version",
                         "x-signing-algo", "x-anything-else"):
            self.assertNotIn(smuggled, h)
        self.assertEqual(h["content-type"], "application/json")
        self.assertEqual(h["accept"], "*/*")

    def test_tenant_bearer_is_hmac_per_identity(self):
        import hmac as hmac_mod
        expected = hmac_mod.new(b"tsecret", b"7", hashlib.sha256).hexdigest()
        self.assertEqual(edge._tenant_bearer(7), f"lev_t_{expected}")
        self.assertNotEqual(edge._tenant_bearer(7), edge._tenant_bearer(8))


class EndToEndProxyTest(unittest.TestCase):
    """Drive the real FastAPI routes over ASGI with mocked auth-service +
    gateway, so the full path (auth gate -> forward -> deny/refund) is tested."""

    def _run_chat(self, consume="allow", gateway=(200, b'{"ok":true}'), identity_id=7,
                  debit_token="tok-1"):
        state = {"refunds": 0, "gw_calls": 0, "gw_headers": None, "refund_bodies": []}

        def auth_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/consume":
                if consume == "allow":
                    payload = {"success": True, "balance": 9}
                    if identity_id is not None:
                        payload["identity_id"] = identity_id
                    if debit_token is not None:
                        payload["debit_token"] = debit_token
                    return httpx.Response(200, json=payload)
                return httpx.Response(200, json={"success": False, "error": "insufficient balance"})
            if req.url.path == "/v1/refund":
                import json as _json
                state["refunds"] += 1
                state["refund_bodies"].append(_json.loads(req.content))
                return httpx.Response(200, json={"success": True})
            return httpx.Response(404)

        def gw_handler(req: httpx.Request) -> httpx.Response:
            state["gw_calls"] += 1
            state["gw_headers"] = dict(req.headers)
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
        # The gateway saw the service token + THIS user's tenant bearer.
        self.assertEqual(state["gw_headers"]["x-gateway-token"], "gtok")
        self.assertEqual(state["gw_headers"]["authorization"], f"Bearer {edge._tenant_bearer(7)}")

    def test_consume_without_identity_fails_closed_and_refunds(self):
        resp, state = self._run_chat(consume="allow", identity_id=None)
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(state["gw_calls"], 0)      # never reached the gateway
        self.assertEqual(state["refunds"], 1)       # debit was reversed

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
        # The refund names the debit it reverses, not the idempotency key.
        self.assertEqual(state["refund_bodies"][0]["debit_token"], "tok-1")
        self.assertNotIn("idempotency_key", state["refund_bodies"][0])

    def test_idempotency_is_opt_in_not_derived_from_body(self):
        # Two submissions of the same body must be two distinct debits;
        # otherwise the second is a free replay inside the dedup window.
        # Only an explicit client Idempotency-Key makes them one.
        seen = []

        def auth_handler(req: httpx.Request) -> httpx.Response:
            import json as _json
            if req.url.path == "/v1/consume":
                seen.append(_json.loads(req.content)["idempotency_key"])
                return httpx.Response(200, json={"success": True, "balance": 9,
                                                 "identity_id": 7, "debit_token": "t"})
            return httpx.Response(404)

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b'{"ok":true}',
                                     headers={"content-type": "application/json"})))

        async def post(headers):
            transport = httpx.ASGITransport(app=edge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.post("/v1/chat/completions", headers=headers,
                                    json={"model": "m", "messages": []})

        auth = {"authorization": "Bearer lev_user"}
        run(post(auth)); run(post(auth))
        self.assertNotEqual(seen[0], seen[1], "same body reused one idempotency key")

        run(post({**auth, "idempotency-key": "retry-1"}))
        run(post({**auth, "idempotency-key": "retry-1"}))
        self.assertEqual(seen[2], seen[3], "explicit Idempotency-Key did not dedup")

    def test_same_idempotency_key_different_body_is_a_new_debit(self):
        # Regression for the billing bypass: reusing one Idempotency-Key with a
        # DIFFERENT prompt used to reuse the ledger key, so auth-service
        # deduplicated (no debit) while the Edge still forwarded the new prompt
        # to the gateway — unlimited free inference for one credit.
        seen = []

        def auth_handler(req: httpx.Request) -> httpx.Response:
            import json as _json
            if req.url.path == "/v1/consume":
                seen.append(_json.loads(req.content)["idempotency_key"])
                return httpx.Response(200, json={"success": True, "balance": 9,
                                                 "identity_id": 7, "debit_token": "t"})
            return httpx.Response(404)

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b'{"ok":true}',
                                     headers={"content-type": "application/json"})))

        async def post(body):
            transport = httpx.ASGITransport(app=edge.app)
            headers = {"authorization": "Bearer lev_user", "idempotency-key": "EXPLOIT-C1"}
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.post("/v1/chat/completions", headers=headers, json=body)

        run(post({"model": "m", "messages": [{"role": "user", "content": "APPLE"}]}))
        run(post({"model": "m", "messages": [{"role": "user", "content": "BANANA"}]}))
        self.assertNotEqual(seen[0], seen[1],
                            "same key + different prompt reused one ledger key (free inference)")

        # ...while a genuine retry (same key, same bytes) still dedups.
        run(post({"model": "m", "messages": [{"role": "user", "content": "APPLE"}]}))
        self.assertEqual(seen[0], seen[2], "genuine retry no longer deduplicates")

    def test_deduplicated_consume_never_refunds(self):
        # Regression for the credit-minting hole: a replayed request debits
        # nothing (auth-service returns no debit_token), so even when the
        # gateway rejects it the Edge must NOT ask for a refund — doing so
        # would reverse an earlier request's debit and mint a credit.
        resp, state = self._run_chat(consume="allow", debit_token=None,
                                     gateway=(400, b'{"error":"invalid_request_error"}'))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(state["gw_calls"], 1)
        self.assertEqual(state["refunds"], 0)


class ReceiptRouteTest(unittest.TestCase):
    """The receipt passthrough must authenticate the user and present the
    SAME tenant bearer used at chat time, or the gateway 401/403s."""

    def _get_receipt(self, validate_json, with_key=True):
        state = {"gw_headers": None}

        def auth_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/validate":
                return httpx.Response(200, json=validate_json)
            return httpx.Response(404)

        def gw_handler(req: httpx.Request) -> httpx.Response:
            state["gw_headers"] = dict(req.headers)
            return httpx.Response(200, json={"receipt_id": "r-1"},
                                  headers={"content-type": "application/json"})

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))

        async def go():
            transport = httpx.ASGITransport(app=edge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                headers = {"authorization": "Bearer lev_user"} if with_key else {}
                return await c.get("/v1/aci/receipts/r-1", headers=headers)

        return run(go()), state

    def test_no_key_is_401(self):
        resp, state = self._get_receipt({"valid": True, "identity_id": 7}, with_key=False)
        self.assertEqual(resp.status_code, 401)
        self.assertIsNone(state["gw_headers"])      # gateway never called

    def test_valid_key_forwards_tenant_bearer(self):
        resp, state = self._get_receipt({"valid": True, "balance": 5, "identity_id": 7})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(state["gw_headers"]["authorization"], f"Bearer {edge._tenant_bearer(7)}")

    def test_empty_balance_can_still_read_own_receipts(self):
        resp, state = self._get_receipt(
            {"valid": False, "error": "insufficient balance", "identity_id": 7})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(state["gw_headers"]["authorization"], f"Bearer {edge._tenant_bearer(7)}")

    def test_unknown_key_is_401_and_gateway_untouched(self):
        resp, state = self._get_receipt({"valid": False, "error": "credential not found"})
        self.assertEqual(resp.status_code, 401)
        self.assertIsNone(state["gw_headers"])


if __name__ == "__main__":
    unittest.main()
