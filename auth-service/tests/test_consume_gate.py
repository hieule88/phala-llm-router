"""Tests for the /v1/consume + /v1/refund proxy-token gate.

Regression for the public-consume balance-drain bug: the api_key hash is
semi-public (users share it over chat), so the DEBIT path must be gated by a
bearer token only the TEE proxy holds. /v1/validate (read-only) stays public.

Run from `phala-TEE/auth-service/`:
    python -m unittest tests.test_consume_gate -v
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tokens must be set BEFORE importing the app module (read at import time).
os.environ["ADMIN_TOKEN"] = "A" * 40
os.environ["PROXY_REFUND_TOKEN"] = "P" * 40
os.environ.setdefault("AUTH_DB_PATH", ":memory:")

from fastapi import HTTPException  # noqa: E402

from app import main as m  # noqa: E402


class RequireProxyTokenTest(unittest.TestCase):
    """The guard fails closed: only the exact proxy or admin token opens it."""

    def _status(self, header):
        try:
            m.require_proxy_token(header)
            return "OK"
        except HTTPException as e:
            return e.status_code

    def test_missing_header_401(self):
        self.assertEqual(self._status(None), 401)

    def test_wrong_token_401(self):
        self.assertEqual(self._status("Bearer nope"), 401)

    def test_non_bearer_scheme_401(self):
        self.assertEqual(self._status("Basic " + "P" * 40), 401)

    def test_proxy_token_ok(self):
        self.assertEqual(self._status("Bearer " + "P" * 40), "OK")

    def test_admin_token_ok(self):
        self.assertEqual(self._status("Bearer " + "A" * 40), "OK")

    def test_no_tokens_configured_503(self):
        # Fail-closed: neither token set → the gate refuses, never opens.
        with patch.object(m, "PROXY_REFUND_TOKEN", ""), \
             patch.object(m, "ADMIN_TOKEN", ""):
            self.assertEqual(self._status("Bearer " + "P" * 40), 503)


class EndpointWiringTest(unittest.TestCase):
    """The gate must be wired onto the debit endpoints and NOT onto the
    public read-only validate (which the docs' curl UX + the compose
    healthcheck both depend on staying open)."""

    def _deps(self, path):
        for r in m.app.routes:
            if getattr(r, "path", None) == path and "POST" in getattr(r, "methods", set()):
                return [d.call.__name__ for d in r.dependant.dependencies]
        return None

    def test_consume_is_gated(self):
        self.assertIn("require_proxy_token", self._deps("/v1/consume"))

    def test_refund_is_gated(self):
        self.assertIn("require_proxy_token", self._deps("/v1/refund"))

    def test_validate_is_public(self):
        self.assertNotIn("require_proxy_token", self._deps("/v1/validate"))


class ValidateRateBucketTest(unittest.IsolatedAsyncioTestCase):
    """The Edge fronts every tenant from ONE container IP, so /v1/validate must
    not bucket its calls per-IP: exhausting that shared bucket 503s /v1/models
    and receipt reads for all co-tenants (the verification path) while chat,
    which is not per-IP limited, keeps working."""

    @staticmethod
    def _request(headers, body, peer="172.18.0.9"):
        import json as _json
        from starlette.requests import Request

        raw = _json.dumps(body).encode()
        scope = {
            "type": "http", "method": "POST", "path": "/v1/validate",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": (peer, 51234), "query_string": b"", "scheme": "http",
            "server": ("auth", 8000), "root_path": "", "app": m.app,
        }

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        return Request(scope, receive)

    async def _key(self, headers, body, peer="172.18.0.9"):
        req = self._request(headers, body, peer)
        await m.tag_validate_rate_subject(req)
        return m._validate_rate_key(req)

    async def test_proxy_calls_bucket_per_credential(self):
        proxy = {"authorization": "Bearer " + "P" * 40}
        a = await self._key(proxy, {"credential_type": "api_key", "credential_value": "hash-a"})
        b = await self._key(proxy, {"credential_type": "api_key", "credential_value": "hash-b"})
        self.assertNotEqual(a, b, "two tenants shared one bucket behind the Edge")
        self.assertTrue(a.startswith("cred:"))
        # Same tenant keeps ONE bucket, so the per-user ceiling still applies.
        again = await self._key(proxy, {"credential_type": "api_key", "credential_value": "hash-a"})
        self.assertEqual(a, again)

    async def test_untrusted_caller_cannot_choose_its_bucket(self):
        # No/!valid proxy token → per-IP, even when the body names a credential:
        # otherwise a public caller rotates credential_value for a fresh bucket
        # per request and the limit stops existing.
        body = {"credential_type": "api_key", "credential_value": "hash-a"}
        anon = await self._key({}, body, peer="203.0.113.7")
        forged = await self._key({"authorization": "Bearer nope"}, body, peer="203.0.113.7")
        rotated = await self._key({}, {"credential_type": "api_key", "credential_value": "hash-z"},
                                  peer="203.0.113.7")
        self.assertEqual(anon, "203.0.113.7")
        self.assertEqual(forged, "203.0.113.7")
        self.assertEqual(anon, rotated)

    async def test_malformed_body_falls_back_to_per_ip(self):
        req = self._request({"authorization": "Bearer " + "P" * 40}, {}, peer="203.0.113.8")

        async def receive():
            return {"type": "http.request", "body": b"not json", "more_body": False}

        req = __import__("starlette.requests", fromlist=["Request"]).Request(req.scope, receive)
        await m.tag_validate_rate_subject(req)
        self.assertEqual(m._validate_rate_key(req), "203.0.113.8")


if __name__ == "__main__":
    unittest.main()
