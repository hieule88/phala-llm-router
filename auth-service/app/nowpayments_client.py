"""NOWPayments send-side client: create invoices for payment intents.

Companion to `nowpayments_webhook.py` (receive-side). Given an existing
`payment_intents` row, we POST to NOWPayments' invoice API to obtain a
hosted-checkout URL. The user opens the URL, chooses a cryptocurrency,
pays, and NOWPayments fires the IPN webhook which the receive-side
adapter converts into a balance credit.

Kept in a separate module from the webhook so:
  * The webhook path has no dependency on NOWPAYMENTS_API_KEY (env keeps
    the concerns separate — you can accept payments without ever calling
    NOWPayments' outbound API).
  * Test isolation: mocking the outbound httpx call in tests doesn't
    touch the webhook signature verification path.

NOWPayments invoices API:
  https://documenter.getpostman.com/view/7907941/2s93JusNJt#f6d6bc35-7b70-4f24-8de1-25b83c8c8b3e
"""

from __future__ import annotations

import os
from typing import Optional

import httpx


NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")

# Base URL: prod is api.nowpayments.io. Sandbox is api-sandbox.nowpayments.io
# and requires a separate sandbox API key. We default to prod but let the
# operator flip to sandbox for staging via env.
NOWPAYMENTS_API_BASE = os.getenv(
    "NOWPAYMENTS_API_BASE", "https://api.nowpayments.io/v1",
).rstrip("/")

# Explicit IPN callback URL passed in every invoice create request. When
# set, NOWPayments POSTs status transitions here — overriding whatever
# is in the merchant's dashboard IPN settings. Making it explicit prevents
# the class of "dashboard says one URL, this deployment says another"
# misconfigurations that silently lose paid events.
NOWPAYMENTS_IPN_CALLBACK_URL = os.getenv("NOWPAYMENTS_IPN_CALLBACK_URL", "")

# Where NOWPayments redirects the user's browser after they pay (or cancel).
# The prover doesn't have a customer-facing site, so we default to a
# blank/hash page — the intent status is polled by the client anyway.
NOWPAYMENTS_SUCCESS_URL = os.getenv("NOWPAYMENTS_SUCCESS_URL", "")
NOWPAYMENTS_CANCEL_URL = os.getenv("NOWPAYMENTS_CANCEL_URL", "")

# Outbound timeout. NOWPayments' invoice endpoint typically responds in
# under a second; anything above 10s means the network is bad and we'd
# rather fail fast than pin the request thread.
NOWPAYMENTS_HTTP_TIMEOUT = float(os.getenv("NOWPAYMENTS_HTTP_TIMEOUT", "10.0"))


class NowpaymentsError(Exception):
    """Raised when the outbound call to NOWPayments failed for any
    reason (missing key, network, non-2xx response, malformed body).
    Callers surface as 502 Bad Gateway — this service is up, the
    upstream provider isn't.
    """

    def __init__(self, detail: str, status_code: int = 502):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _require_api_key() -> str:
    if not NOWPAYMENTS_API_KEY:
        # Operator hasn't configured NOWPayments send-side yet. Distinct
        # from receive-side (nowpayments_webhook), so the check is here.
        raise NowpaymentsError(
            "NOWPAYMENTS_API_KEY not configured on server",
            status_code=503,
        )
    return NOWPAYMENTS_API_KEY


async def create_invoice(
    *,
    memo: str,
    amount_cents: int,
    description: str = "Miden TEE prove credits",
) -> dict:
    """Create a NOWPayments invoice bound to `memo` (which becomes the
    `order_id` NOWPayments returns on the IPN webhook).

    Returns a dict with at least:
      { "invoice_url": <hosted checkout URL>,
        "invoice_id":  <NOWPayments invoice id, opaque>,
        "expiration_estimate_date": <ISO string or None> }

    Raises NowpaymentsError on any failure — the caller (create-intent
    HTTP endpoint) surfaces that as 502/503 without touching the
    payment_intents row (the row is already committed at intent-create
    time, so a failed invoice creation just means "no URL yet — retry").
    """
    api_key = _require_api_key()
    amount_usd = amount_cents / 100.0
    if amount_usd <= 0:
        raise NowpaymentsError(
            f"invoice amount must be positive (got {amount_cents} cents)",
            status_code=400,
        )

    body: dict = {
        "price_amount": amount_usd,
        "price_currency": "usd",
        "order_id": memo,
        "order_description": description,
        # is_fee_paid_by_user=false → the operator eats the network fee.
        # Set true to pass the fee to the buyer (they see a higher total).
        "is_fee_paid_by_user": False,
    }
    if NOWPAYMENTS_IPN_CALLBACK_URL:
        body["ipn_callback_url"] = NOWPAYMENTS_IPN_CALLBACK_URL
    if NOWPAYMENTS_SUCCESS_URL:
        body["success_url"] = NOWPAYMENTS_SUCCESS_URL
    if NOWPAYMENTS_CANCEL_URL:
        body["cancel_url"] = NOWPAYMENTS_CANCEL_URL

    try:
        async with httpx.AsyncClient(timeout=NOWPAYMENTS_HTTP_TIMEOUT) as client:
            r = await client.post(
                f"{NOWPAYMENTS_API_BASE}/invoice",
                json=body,
                headers={"x-api-key": api_key},
            )
    except httpx.RequestError as e:
        raise NowpaymentsError(f"NOWPayments unreachable: {e}") from None

    if not (200 <= r.status_code < 300):
        # Include upstream body in the error so ops can debug — but
        # trim in case NOWPayments returns something absurd.
        raise NowpaymentsError(
            f"NOWPayments returned {r.status_code}: {r.text[:500]}",
        )

    try:
        data = r.json()
    except ValueError as e:
        raise NowpaymentsError(f"NOWPayments non-JSON response: {e}") from None

    invoice_url = data.get("invoice_url")
    invoice_id: Optional[str] = data.get("id")
    if not isinstance(invoice_url, str) or not invoice_url:
        raise NowpaymentsError(
            f"NOWPayments response missing invoice_url: {data!r}",
        )
    return {
        "invoice_url": invoice_url,
        "invoice_id": invoice_id,
        "expiration_estimate_date": data.get("expiration_estimate_date"),
    }
