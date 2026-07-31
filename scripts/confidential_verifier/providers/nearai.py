import os
import requests
import secrets
from typing import List, Dict, Any, Optional
from .base import ServiceProvider
from ..types import AttestationReport


def _near_auth_headers() -> Dict[str, str]:
    """cloud-api.near.ai now requires auth on the attestation endpoint.
    The upstream vendored provider predates that; read the key from env so the
    bridge can fetch the report. Set TEE_AI_API_KEY (or NEARAI_API_KEY)."""
    key = (os.getenv("TEE_AI_API_KEY") or os.getenv("NEARAI_API_KEY") or "").strip()
    return {"Authorization": f"Bearer {key}"} if key else {}


class NearaiProvider(ServiceProvider):
    def __init__(self, include_tls_fingerprint: bool = False):
        self.api_base = "https://cloud-api.near.ai/v1"
        self.include_tls_fingerprint = include_tls_fingerprint

    def fetch_report(
        self,
        model_id: str,
        include_tls_fingerprint: Optional[bool] = None,
    ) -> AttestationReport:
        """
        Fetch attestation report from NearAI.

        Args:
            model_id: The model identifier
            include_tls_fingerprint: If True, request attestation with TLS cert binding.
                When enabled, report_data format changes to:
                    SHA256(signing_address || tls_cert_fingerprint) || nonce
                Default format (False):
                    signing_address (padded) || nonce
        """
        nonce = secrets.token_hex(32)
        params = {"model": model_id, "signing_algo": "ecdsa", "nonce": nonce}

        # Use instance default if not specified
        use_tls_fingerprint = (
            include_tls_fingerprint
            if include_tls_fingerprint is not None
            else self.include_tls_fingerprint
        )

        if use_tls_fingerprint:
            params["include_tls_fingerprint"] = "true"

        url = f"{self.api_base}/attestation/report"
        print(f"[Near] Fetching report for {model_id} with nonce {nonce[:8]}...")
        if use_tls_fingerprint:
            print(f"[Near] TLS fingerprint binding enabled")

        response = requests.get(url, params=params, headers=_near_auth_headers())
        response.raise_for_status()
        data = response.json()

        attestations = data.get("model_attestations", [])
        if not attestations or not isinstance(attestations, list):
            raise Exception("Near report missing model_attestations")

        first = attestations[0]
        nvidia_payload = first.get("nvidia_payload")
        if isinstance(nvidia_payload, str):
            try:
                import json

                nvidia_payload = json.loads(nvidia_payload)
            except:
                pass

        # Store TLS fingerprint mode in raw data for verifier
        data["include_tls_fingerprint"] = use_tls_fingerprint

        return AttestationReport(
            provider="nearai",
            model_id=model_id,
            intel_quote=first["intel_quote"],
            request_nonce=nonce,
            nvidia_payload=nvidia_payload,
            raw=data,
        )

    def list_models(self) -> List[str]:
        url = f"{self.api_base}/model/list"
        print(f"[Near] Fetching models from {url}")
        response = requests.get(url, headers=_near_auth_headers())
        response.raise_for_status()
        data = response.json()

        models = data if isinstance(data, list) else data.get("models", [])
        return [m if isinstance(m, str) else m.get("modelId") for m in models]
