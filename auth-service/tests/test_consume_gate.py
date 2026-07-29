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


if __name__ == "__main__":
    unittest.main()
