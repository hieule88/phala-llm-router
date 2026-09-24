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
import re
import sys
import unittest
import unittest.mock

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
        # Like asyncio.run(): finalize async generators a request left
        # half-consumed (e.g. a body the Edge stopped reading at its cap)
        # instead of leaving their aclose() as a destroyed pending task.
        loop.run_until_complete(loop.shutdown_asyncgens())
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

    def test_fwd_request_headers_allowlist_drops_unbound_headers(self):
        # Anything that can steer the gateway but is NOT bound into the
        # idempotency key stays out: otherwise a replay of an already-paid body
        # could produce a different outcome than the debited request.
        class R:
            headers = {"content-type": "application/json", "accept": "*/*",
                       "x-upstream-verification": "bogus", "x-anything-else": "1"}
        h = edge._fwd_request_headers(R(), identity_id=7)
        for smuggled in ("x-upstream-verification", "x-anything-else"):
            self.assertNotIn(smuggled, h)
        self.assertEqual(h["content-type"], "application/json")
        self.assertEqual(h["accept"], "*/*")

    def test_fwd_request_headers_pass_e2ee_through(self):
        # E2EE is the whole point of the bound set: the client encrypts to the
        # gateway's attested keyset, so these MUST arrive or the enclave never
        # learns the request was meant to be private and answers in plaintext.
        class R:
            headers = {"content-type": "application/json",
                       "x-e2ee-version": "2", "x-e2ee-nonce": "ab" * 16,
                       "x-e2ee-timestamp": "1700000000",
                       "x-client-pub-key": "aa" * 32, "x-model-pub-key": "bb" * 32}
        h = edge._fwd_request_headers(R(), identity_id=7)
        for name in ("x-e2ee-version", "x-e2ee-nonce", "x-e2ee-timestamp",
                     "x-client-pub-key", "x-model-pub-key"):
            self.assertEqual(h[name], R.headers[name], f"{name} did not reach the gateway")

    def test_bound_set_mirrors_the_gateways_e2ee_headers(self):
        # Read the names out of the GATEWAY'S OWN source rather than restating
        # them here. A hand-copied list makes this test agree with itself: it
        # passes forever while someone adds a seventh header to util.rs, and
        # the drift it exists to catch is exactly the drift it cannot see.
        #
        # Drift is silent and harmful in both directions: a name the gateway
        # acts on but we drop is a privacy control that fails shut (E2EE
        # ignored, request forwarded in plaintext); a name we forward but do
        # not bind is a billing hole.
        util_rs = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "src", "http", "app", "util.rs")
        if not os.path.isfile(util_rs):
            self.skipTest(f"gateway source not present at {util_rs} "
                          "(ai-edge deployed standalone); nothing to compare against")
        with open(util_rs, encoding="utf-8") as fh:
            source = fh.read()
        body = re.search(r"fn has_e2ee_headers\(.*?\n\}", source, re.S)
        self.assertIsNotNone(body, "could not find has_e2ee_headers in util.rs")
        gateway_names = set(re.findall(r'"(x-[a-z0-9-]+)"', body.group(0)))
        self.assertTrue(gateway_names, "parsed no header names out of has_e2ee_headers")
        self.assertEqual(
            set(edge._BOUND_REQ_HEADERS), gateway_names,
            "the Edge's bound-header set has drifted from the gateway's "
            "has_e2ee_headers; forward AND bind every name the gateway acts on")

    def test_bound_header_digest_is_stable_when_no_headers_are_sent(self):
        # A plain request must keep exactly the ledger key it had before the
        # binding existed, or every existing client's retries stop deduplicating.
        class R:
            headers = {}
        self.assertEqual(edge._bound_header_digest(R()), edge._bound_header_digest(R()))

    def test_cors_exposes_every_forwarded_header_a_client_acts_on(self):
        # Forwarding a header is not enough for a cross-origin page: the
        # browser hides it unless it is in Access-Control-Expose-Headers.
        # The SDK refuses a reply without x-e2ee-applied, so a Railway/Vite
        # frontend saw every encrypted chat fail while same-origin proxies
        # (which never consult this list) worked — the 2026-09-23 bug.
        exposed = {h.lower() for h in edge._CORS_EXPOSE_HEADERS}
        for must in ("x-receipt-id", "x-e2ee-applied", "x-e2ee-version", "x-e2ee-algo"):
            self.assertIn(must, exposed)
        # and everything the forwarder lets through by name is exposed too
        for h in edge._FWD_RESP_HEADERS:
            if h != "content-type":
                self.assertIn(h, exposed)

    def test_fwd_response_headers_expose_the_e2ee_verdict(self):
        # The gateway stamps x-e2ee-applied true/false on every completion.
        # Swallowing it leaves a client unable to distinguish "encrypted to the
        # enclave" from "the Edge read it" — both are a 200.
        resp = httpx.Response(200, headers={
            "content-type": "application/json", "x-receipt-id": "r-1",
            "x-e2ee-applied": "true", "x-e2ee-version": "2", "x-e2ee-algo": "x25519",
            "set-cookie": "nope", "server": "hide-me"})
        h = {k.lower(): v for k, v in edge._fwd_response_headers(resp).items()}
        self.assertEqual(h["x-e2ee-applied"], "true")
        self.assertEqual(h["x-e2ee-version"], "2")
        self.assertEqual(h["x-e2ee-algo"], "x25519")
        self.assertEqual(h["x-receipt-id"], "r-1")
        self.assertNotIn("set-cookie", h)
        self.assertNotIn("server", h)

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

    def test_e2ee_headers_are_bound_into_the_ledger_key(self):
        # E2EE headers reach the gateway, so they must also reach the ledger's
        # notion of "the same request". Same key + same bytes but E2EE toggled
        # is different work for the gateway; if the two shared a ledger key the
        # second would be deduplicated (no debit) and still forwarded — the
        # exact billing bypass the body-binding already closed for prompts.
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

        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        e2ee = {"x-e2ee-version": "2", "x-e2ee-nonce": "ab" * 16,
                "x-e2ee-timestamp": "1700000000",
                "x-client-pub-key": "aa" * 32, "x-model-pub-key": "bb" * 32}

        async def post(extra):
            transport = httpx.ASGITransport(app=edge.app)
            headers = {"authorization": "Bearer lev_user",
                       "idempotency-key": "retry-1", **extra}
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.post("/v1/chat/completions", headers=headers, json=body)

        run(post({}))                                  # plaintext
        run(post(e2ee))                                # same bytes, now encrypted
        self.assertNotEqual(seen[0], seen[1],
                            "toggling E2EE reused one ledger key (free inference)")

        run(post(e2ee))                                # a genuine retry of the E2EE one
        self.assertEqual(seen[1], seen[2], "identical E2EE retry no longer deduplicates")

        run(post({**e2ee, "x-e2ee-nonce": "cd" * 16}))  # fresh nonce = fresh request
        self.assertNotEqual(seen[2], seen[3], "a changed E2EE nonce reused one ledger key")

    def test_e2ee_verdict_survives_the_whole_round_trip(self):
        # End-to-end: the client must be able to READ the gateway's verdict
        # after the Edge has streamed the body back. A client that cannot see
        # x-e2ee-applied has no way to distinguish a prompt encrypted to the
        # enclave from one this Edge read in cleartext — both arrive as 200.
        def auth_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/consume":
                return httpx.Response(200, json={"success": True, "balance": 9,
                                                 "identity_id": 7, "debit_token": "t"})
            return httpx.Response(404)

        def gw_handler(req: httpx.Request) -> httpx.Response:
            # Echo the gateway's real response-header shape (backend.rs).
            return httpx.Response(200, content=b'{"ok":true}', headers={
                "content-type": "application/json", "x-receipt-id": "rcpt-1",
                "x-e2ee-applied": "true", "x-e2ee-version": "2",
                "x-e2ee-algo": "x25519-xsalsa20-poly1305"})

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))

        async def go():
            transport = httpx.ASGITransport(app=edge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.post("/v1/chat/completions",
                                    headers={"authorization": "Bearer lev_user"},
                                    json={"model": "m", "messages": []})

        resp = run(go())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("x-e2ee-applied"), "true")
        self.assertEqual(resp.headers.get("x-e2ee-version"), "2")
        self.assertEqual(resp.headers.get("x-receipt-id"), "rcpt-1")

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


class ModelsInputModalitiesTest(unittest.TestCase):
    """/v1/models decorates each model with `input_modalities` from the
    operator map, so frontends enable image attachment per model without
    hardcoding names. It decorates only: errors and odd bodies pass through."""

    MAP = {"glm-5.3-flash": ["text", "image"], "qwen3.6-35b-a3b": ["text"]}
    GW_LIST = (b'{"object":"list","data":[{"id":"glm-5.3-flash","object":"model","owned_by":"phala"},'
               b'{"id":"qwen3.6-35b-a3b","object":"model","owned_by":"phala"},'
               b'{"id":"brand-new","object":"model","owned_by":"phala"}]}')

    def test_annotate_adds_modalities_and_defaults_unknown_to_text(self):
        import json as _json
        with unittest.mock.patch.object(edge, "MODEL_INPUT_MODALITIES", self.MAP):
            out = _json.loads(edge._annotate_models(self.GW_LIST))
        by_id = {m["id"]: m for m in out["data"]}
        self.assertEqual(by_id["glm-5.3-flash"]["input_modalities"], ["text", "image"])
        self.assertEqual(by_id["qwen3.6-35b-a3b"]["input_modalities"], ["text"])
        self.assertEqual(by_id["brand-new"]["input_modalities"], ["text"])   # conservative default
        self.assertEqual(by_id["glm-5.3-flash"]["owned_by"], "phala")           # nothing else touched

    def test_annotate_passes_non_list_bodies_through_untouched(self):
        for body in (b'{"error":{"message":"nope"}}', b"not json", b"[]", b'{"data":"x"}'):
            self.assertEqual(edge._annotate_models(body), body)

    def test_annotate_respects_a_gateway_that_already_knows(self):
        import json as _json
        body = b'{"object":"list","data":[{"id":"glm-5.3-flash","input_modalities":["text","image","audio"]}]}'
        out = _json.loads(edge._annotate_models(body))
        self.assertEqual(out["data"][0]["input_modalities"], ["text", "image", "audio"])

    def test_parse_modalities_accepts_lists_and_csv_and_rejects_garbage(self):
        self.assertEqual(edge._parse_modalities(""), {})
        self.assertEqual(edge._parse_modalities('{"a":["text","image"],"b":"text, image"}'),
                         {"a": ["text", "image"], "b": ["text", "image"]})
        for bad in ("[1,2]", '{"a":[]}', '{"a":[1]}', "{nope"):
            with self.assertRaises(RuntimeError):
                edge._parse_modalities(bad)

    def test_models_route_returns_decorated_list_for_an_api_key(self):
        def auth_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/validate":
                return httpx.Response(200, json={"valid": True, "identity_id": 7, "balance": 49})
            return httpx.Response(404)

        def gw_handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=self.GW_LIST,
                                  headers={"content-type": "application/json",
                                           "content-length": str(len(self.GW_LIST))})

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))

        async def go():
            transport = httpx.ASGITransport(app=edge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://edge") as c:
                return await c.get("/v1/models", headers={"authorization": "Bearer lev_user"})

        with unittest.mock.patch.object(edge, "MODEL_INPUT_MODALITIES", self.MAP):
            resp = run(go())
        self.assertEqual(resp.status_code, 200, resp.text)
        by_id = {m["id"]: m for m in resp.json()["data"]}
        self.assertEqual(by_id["glm-5.3-flash"]["input_modalities"], ["text", "image"])
        self.assertEqual(by_id["brand-new"]["input_modalities"], ["text"])
        # a stale upstream content-length must not be forwarded with a longer body
        self.assertEqual(len(resp.content), int(resp.headers["content-length"]))


if __name__ == "__main__":
    unittest.main()


class BodyCapTest(unittest.TestCase):
    """The Edge refuses an oversized body BEFORE auth, spend-cap booking and
    debit — by Content-Length without reading a byte, or while streaming a
    body that declares no length — so an anonymous client cannot balloon the
    Edge's memory and a too-large legitimate request costs no debit/refund
    round trip. Caps are patched small so the tests stay cheap."""

    def _post(self, content, headers=None, cap=1024):
        state = {"consumes": 0, "gw_calls": 0}

        def auth_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/consume":
                state["consumes"] += 1
                return httpx.Response(200, json={"success": True, "balance": 9, "identity_id": 7,
                                                 "debit_token": "tok-1"})
            return httpx.Response(200, json={"success": True})

        def gw_handler(req: httpx.Request) -> httpx.Response:
            state["gw_calls"] += 1
            return httpx.Response(200, content=b'{"ok":true}', headers={"content-type": "application/json"})

        ac = edge.AuthClient()
        ac._c = httpx.AsyncClient(transport=httpx.MockTransport(auth_handler))
        edge.app.state.auth = ac
        edge.app.state.gw = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))

        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=edge.app), base_url="http://edge") as c:
                return await c.post("/v1/chat/completions",
                                    headers={"authorization": "Bearer lev_user",
                                             "content-type": "application/json", **(headers or {})},
                                    content=content)

        with unittest.mock.patch.object(edge, "EDGE_MAX_BODY_BYTES", cap):
            resp = run(go())
        return resp, state

    def test_declared_length_over_cap_is_413_before_auth_or_debit(self):
        resp, state = self._post(b"x" * 2000)          # httpx sets Content-Length: 2000
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json()["error"]["type"], "request_too_large")
        self.assertEqual(state["consumes"], 0, "no debit for a body the gateway would refuse")
        self.assertEqual(state["gw_calls"], 0)

    def test_streamed_body_without_length_is_cut_at_cap(self):
        async def chunks():
            for _ in range(20):
                yield b"y" * 100                      # 2000 bytes, Transfer-Encoding: chunked
        resp, state = self._post(chunks())   # left half-consumed by design; run() finalizes it
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json()["error"]["type"], "request_too_large")
        self.assertEqual(state["consumes"], 0)

    def test_body_under_cap_goes_through_unchanged(self):
        body = b'{"model":"m","messages":[{"role":"user","content":"' + b"z" * 800 + b'"}]}'
        resp, state = self._post(body)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(state["consumes"], 1)
        self.assertEqual(state["gw_calls"], 1)

    def test_read_body_helper_caps_wallet_endpoints_too(self):
        """_read_body is what every wallet handler and _json_body use, with the
        small wallet cap; drive it with a raw ASGI receive."""
        from starlette.requests import Request

        def make_request(headers, payload_chunks):
            it = iter(payload_chunks)

            async def receive():
                try:
                    return {"type": "http.request", "body": next(it), "more_body": True}
                except StopIteration:
                    return {"type": "http.request", "body": b"", "more_body": False}
            scope = {"type": "http", "method": "POST", "path": "/v1/wallet/challenge",
                     "headers": [(k.encode(), v.encode()) for k, v in headers.items()], "query_string": b""}
            return Request(scope, receive)

        cap = edge.EDGE_MAX_WALLET_BODY_BYTES
        self.assertEqual(cap, 64 * 1024)
        # declared over the cap: refused without reading
        req = make_request({"content-length": str(cap + 1)}, [b"never read"])
        with self.assertRaises(edge.WalletAuthError) as ctx:
            run(edge._read_body(req, cap))
        self.assertEqual(ctx.exception.status, 413)
        # no length, streamed past the cap: refused mid-stream
        req = make_request({}, [b"a" * 1024] * 70)
        with self.assertRaises(edge.WalletAuthError) as ctx:
            run(edge._read_body(req, cap))
        self.assertEqual(ctx.exception.status, 413)
        # under the cap: the exact bytes come back (the signature covers them)
        req = make_request({}, [b"hel", b"lo"])
        self.assertEqual(run(edge._read_body(req, cap)), b"hello")
        # a garbage Content-Length is a 400, not a crash
        req = make_request({"content-length": "lots"}, [b""])
        with self.assertRaises(edge.WalletAuthError) as ctx:
            run(edge._read_body(req, cap))
        self.assertEqual(ctx.exception.status, 400)
