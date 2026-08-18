"""Stripe send-side client: create hosted Checkout Sessions for payment
intents.

Companion to `stripe_webhook.py` (receive-side), mirroring the
nowpayments_client / nowpayments_webhook split and the same caller
contract: given an existing `payment_intents` row, obtain a hosted
checkout URL. The user pays on Stripe's page; Stripe fires the
`checkout.session.completed` webhook which the receive-side adapter
converts into a balance credit via mark_paid_by_memo.

Uses Stripe's REST API directly over httpx (form-encoded, Bearer auth) —
no `stripe` pip dependency, consistent with the NOWPayments client.

Test mode: use an `sk_test_...` key; payments are made with Stripe's
test cards (4242 4242 4242 4242, any future date, any CVC). No real
money moves.

Stripe Checkout Sessions API:
  https://docs.stripe.com/api/checkout/sessions/create
"""

from __future__ import annotations

import os
from typing import Optional

import httpx


STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_API_BASE = os.getenv("STRIPE_API_BASE", "https://api.stripe.com/v1").rstrip("/")

# Where Stripe redirects the buyer's browser after paying / cancelling.
# success_url is REQUIRED by Stripe for hosted checkout — point it at the
# frontend (e.g. https://<your-app>/?paid=1). The balance is credited by
# the webhook, never by the redirect, so this is purely cosmetic.
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", "")

STRIPE_HTTP_TIMEOUT = float(os.getenv("STRIPE_HTTP_TIMEOUT", "10.0"))


class StripeError(Exception):
    """Raised when the outbound call to Stripe failed for any reason
    (missing config, network, non-2xx, malformed body). Callers surface
    it exactly like NowpaymentsError: 502/503 without touching the
    committed payment_intents row."""

    def __init__(self, detail: str, status_code: int = 502):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _require_config() -> str:
    if not STRIPE_SECRET_KEY:
        raise StripeError("STRIPE_SECRET_KEY not configured on server", status_code=503)
    if not STRIPE_SUCCESS_URL:
        # Stripe rejects hosted sessions without a success_url; fail here
        # with a message that names the missing knob instead of relaying
        # Stripe's generic 400.
        raise StripeError("STRIPE_SUCCESS_URL not configured on server", status_code=503)
    return STRIPE_SECRET_KEY


async def create_checkout_session(
    *,
    memo: str,
    amount_cents: int,
    description: str = "Leviathan AI credits",
) -> dict:
    """Create a Stripe Checkout Session bound to `memo`.

    `memo` rides in `client_reference_id` (and metadata) and comes back on
    the webhook event — the same correlation role as NOWPayments'
    `order_id`. Returns the same shape as nowpayments_client.create_invoice:
      { "invoice_url": <hosted checkout URL>,
        "invoice_id":  <session id, cs_...>,
        "expiration_estimate_date": <unix ts or None> }
    """
    api_key = _require_config()
    if amount_cents <= 0:
        raise StripeError(
            f"checkout amount must be positive (got {amount_cents} cents)",
            status_code=400,
        )

    form = {
        "mode": "payment",
        "client_reference_id": memo,
        "metadata[memo]": memo,
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": str(amount_cents),
        "line_items[0][price_data][product_data][name]": description,
        "success_url": STRIPE_SUCCESS_URL,
    }
    if STRIPE_CANCEL_URL:
        form["cancel_url"] = STRIPE_CANCEL_URL

    try:
        async with httpx.AsyncClient(timeout=STRIPE_HTTP_TIMEOUT) as client:
            r = await client.post(
                f"{STRIPE_API_BASE}/checkout/sessions",
                data=form,
                headers={"Authorization": f"Bearer {api_key}"},
            )
    except httpx.RequestError as e:
        raise StripeError(f"Stripe unreachable: {e}") from None

    if not (200 <= r.status_code < 300):
        raise StripeError(f"Stripe returned {r.status_code}: {r.text[:500]}")

    try:
        data = r.json()
    except ValueError as e:
        raise StripeError(f"Stripe non-JSON response: {e}") from None

    url = data.get("url")
    session_id: Optional[str] = data.get("id")
    if not isinstance(url, str) or not url:
        raise StripeError(f"Stripe response missing checkout url: {str(data)[:300]}")
    return {
        "invoice_url": url,
        "invoice_id": session_id,
        "expiration_estimate_date": data.get("expires_at"),
    }
