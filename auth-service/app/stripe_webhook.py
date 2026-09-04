"""Stripe webhook handling (receive-side).

Stripe authenticates deliveries with the `Stripe-Signature` header:

    Stripe-Signature: t=<unix ts>,v1=<hex hmac>[,v1=<hex hmac>...]

where each v1 is HMAC-SHA256 over the ASCII string "<t>.<raw body>" keyed
with the endpoint's signing secret (whsec_...). The signature covers the
EXACT bytes on the wire — never re-serialize before verifying.

We act on `checkout.session.completed` (and
`checkout.session.async_payment_succeeded` for delayed methods) with
payment_status == "paid": the session's client_reference_id is our intent
memo, amount_total is in USD cents, and crediting goes through the same
mark_paid_by_memo path as every other channel — so replay dedup, the
underpaid guard, and the expired-intent escape hatch all apply unchanged.

Stripe signature scheme:
  https://docs.stripe.com/webhooks/signature
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

import aiosqlite

from . import handlers

logger = logging.getLogger("auth.stripe")

STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# Reject events whose signed timestamp is older/newer than this (replay
# window). Stripe's own SDK default is 300s.
STRIPE_SIG_TOLERANCE_SEC = int(os.getenv("STRIPE_SIG_TOLERANCE_SEC", "300"))

# Event types that mean "money is in hand, credit the user".
CREDIT_EVENT_TYPES = frozenset({
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
})


class WebhookError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _require_secret() -> str:
    if not STRIPE_WEBHOOK_SECRET:
        # A 404 (not 5xx) so a misconfigured deployment doesn't look
        # retryable to Stripe.
        raise WebhookError(404, "stripe webhook not configured")
    return STRIPE_WEBHOOK_SECRET


def verify_and_parse(raw_body: bytes, signature_header: str | None, now: float | None = None) -> dict:
    """Verify the Stripe-Signature header over the RAW request bytes and
    return the parsed event. Raises WebhookError on any failure."""
    secret = _require_secret()
    if not signature_header:
        raise WebhookError(400, "missing Stripe-Signature header")

    timestamp: str | None = None
    candidates: list[str] = []
    for part in signature_header.split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            timestamp = v
        elif k == "v1":
            candidates.append(v)
    if timestamp is None or not candidates:
        raise WebhookError(400, "malformed Stripe-Signature header")
    try:
        ts = int(timestamp)
    except ValueError:
        raise WebhookError(400, "malformed Stripe-Signature timestamp") from None

    current = now if now is not None else time.time()
    if abs(current - ts) > STRIPE_SIG_TOLERANCE_SEC:
        raise WebhookError(401, "Stripe-Signature timestamp outside tolerance")

    signed_payload = f"{ts}.".encode() + raw_body
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, c) for c in candidates):
        raise WebhookError(401, "invalid Stripe signature")

    try:
        return json.loads(raw_body)
    except ValueError:
        raise WebhookError(400, "invalid JSON body") from None


async def dispatch(conn: aiosqlite.Connection, event: dict) -> dict:
    """Route a verified Stripe event. Only paid checkout sessions credit;
    everything else is acknowledged with handled: False."""
    etype = event.get("type")
    obj = (event.get("data") or {}).get("object") or {}

    if etype not in CREDIT_EVENT_TYPES or obj.get("payment_status") != "paid":
        logger.info("stripe event %s ack'd, no credit (session=%s payment_status=%s)",
                    etype, obj.get("id"), obj.get("payment_status"))
        return {"handled": False, "event_type": etype}

    session_id = obj.get("id")
    memo = obj.get("client_reference_id") or (obj.get("metadata") or {}).get("memo")
    if not memo:
        raise WebhookError(400, "paid session carries no client_reference_id/memo")

    currency = str(obj.get("currency") or "")
    if currency.lower() != "usd":
        raise WebhookError(400, f"unsupported currency {currency!r}; sessions are created in USD")
    amount_total = obj.get("amount_total")
    if not isinstance(amount_total, int) or amount_total <= 0:
        raise WebhookError(400, f"non-positive amount_total: {amount_total!r}")

    result = await handlers.mark_paid_by_memo(
        conn,
        memo,
        provider_ref=f"stripe:{session_id}",
        actual_amount_cents=amount_total,
        # Escape hatch: a payment confirmed by the provider must be
        # honoured even if the intent's TTL lapsed (or the row was
        # already lazily flipped to 'expired').
        allow_expired=True,
    )
    if result.get("success"):
        logger.info("stripe payment credited (session=%s memo=%s dedup=%s)",
                    session_id, memo, bool(result.get("deduplicated")))
    else:
        logger.error(
            "MONEY RECEIVED BUT NOT CREDITED: stripe session=%s memo=%s "
            "amount_cents=%s error=%r — investigate and finalise via "
            "POST /v1/payment-intents/%s/mark-paid",
            session_id, memo, amount_total, result.get("error"), memo)
    return {"handled": True, "event_type": etype, "result": result}
