"""Stripe send-side client: create hosted Checkout Sessions for payment
intents.

Companion to `stripe_webhook.py` (receive-side), with a simple caller
contract: given an existing `payment_intents` row, obtain a hosted
checkout URL. The user pays on Stripe's page; Stripe fires the
`checkout.session.completed` webhook which the receive-side adapter
converts into a balance credit via mark_paid_by_memo.

Uses Stripe's REST API directly over httpx (form-encoded, Bearer auth) —
no `stripe` pip dependency.

Test mode: use an `sk_test_...` key; payments are made with Stripe's
test cards (4242 4242 4242 4242, any future date, any CVC). No real
money moves.

Stripe Checkout Sessions API:
  https://docs.stripe.com/api/checkout/sessions/create
"""

from __future__ import annotations

import hashlib
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

# Stripe refuses charges below a per-currency floor "to ensure the Stripe
# fee is not greater than your payment amount". Sessions here are created
# in USD, whose floor is $0.50 — but the floor that actually applies is
# the one for the account's SETTLEMENT currency (GBP 0.30, HUF 175, …),
# so operators settling elsewhere must raise this.
#
# Checked before the intent row is written: without it, buying fewer
# credits than half a dollar's worth produced a committed intent plus a
# Stripe rejection, and pending intents are capped and cannot be
# cancelled by the user — every attempt burned a slot for 30 days.
STRIPE_MIN_AMOUNT_CENTS = int(os.getenv("STRIPE_MIN_AMOUNT_CENTS", "50"))


class StripeError(Exception):
    """Raised when the outbound call to Stripe failed for any reason
    (missing config, network, non-2xx, malformed body). Callers surface
    it as 502/503 without touching the committed payment_intents row."""

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


def preflight(amount_cents: int) -> None:
    """Everything that can be refused WITHOUT calling Stripe.

    Callers run this BEFORE committing the intent row. The row used to be
    written first and a provider failure only came back as a soft
    `checkout_error`, on the theory that the client would retry checkout
    for the same memo — no client does, they all just create another
    intent. Since pending intents are capped per rail and only the admin
    can cancel one, every doomed attempt cost the user a slot for the
    intent's whole TTL. Anything knowable up front therefore has to fail
    before anything is written.

    Raises StripeError (503 for missing config, 400 for an amount Stripe
    would reject anyway).
    """
    _require_config()
    if amount_cents <= 0:
        raise StripeError(
            f"checkout amount must be positive (got {amount_cents} cents)",
            status_code=400,
        )
    if amount_cents < STRIPE_MIN_AMOUNT_CENTS:
        raise StripeError(
            f"amount {amount_cents} cents is below Stripe's minimum charge "
            f"({STRIPE_MIN_AMOUNT_CENTS} cents) — buy more credits, or pay "
            f"on the on-chain rail, which has no minimum",
            status_code=400,
        )


async def create_checkout_session(
    *,
    memo: str,
    amount_cents: int,
    description: str = "Leviathan AI credits",
) -> dict:
    """Create a Stripe Checkout Session bound to `memo`.

    `memo` rides in `client_reference_id` (and metadata) and comes back on
    the webhook event — the correlation key that binds the payment to the
    intent. Returns:
      { "invoice_url": <hosted checkout URL>,
        "invoice_id":  <session id, cs_...>,
        "expiration_estimate_date": <unix ts or None> }
    """
    preflight(amount_cents)
    api_key = STRIPE_SECRET_KEY

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

    # Retrying checkout for one memo must hand back the SAME Session, not
    # mint a parallel one: two live sessions for a single order is how an
    # order gets paid twice (the ledger then credits it once and the payer
    # is owed a refund).
    #
    # The key carries a digest of the exact request rather than the memo
    # alone, because Stripe "compares incoming parameters to those of the
    # original request and errors if they're not the same" — and
    # success_url/cancel_url are read from the environment at call time.
    # Keyed on the memo alone, changing STRIPE_SUCCESS_URL and redeploying
    # would turn every open intent's checkout into an error instead of a
    # link. Keyed on the parameters, a config change simply starts a new
    # key, which is the intended behaviour.
    #
    # This NARROWS the window, it does not close it: Stripe prunes keys
    # after 24h and then treats a reuse as a fresh request, so an intent
    # living 30 days can still accumulate sessions. The ledger's
    # duplicate-payment detection is the actual safety net.
    request_digest = hashlib.sha256(
        "\n".join(f"{k}={v}" for k, v in sorted(form.items())).encode()
    ).hexdigest()[:32]

    try:
        async with httpx.AsyncClient(timeout=STRIPE_HTTP_TIMEOUT) as client:
            r = await client.post(
                f"{STRIPE_API_BASE}/checkout/sessions",
                data=form,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    # memo is an opaque server-generated token, never
                    # personal data — safe to put in the key, and it makes
                    # the key greppable in the Stripe dashboard.
                    "Idempotency-Key": f"checkout:{memo}:{request_digest}",
                },
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
