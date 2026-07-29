"""Stripe webhook handling.

Kept separate from `main.py` so the HTTP wiring stays thin and the
event-dispatch logic is unit-testable without spinning up FastAPI.

Trust model: the incoming request is authenticated by Stripe's HMAC
signature (`Stripe-Signature` header) verified against a shared
`STRIPE_WEBHOOK_SECRET`. That's the only auth on this endpoint — no
Bearer token — because the caller is Stripe's infrastructure, not
an admin. Rate-limit is set high because Stripe retries aggressively
on failure and we absolutely do not want to drop a paid event.
"""

import os
from typing import Optional

import aiosqlite
import stripe

from . import handlers


STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# How many Stripe cents equal one prove credit. Default: $0.01 (1 cent)
# per credit → $1.00 = 100 credits. Overridable per deployment via env.
# Kept as an integer to avoid float-arithmetic surprises when we do
# amount // STRIPE_CENTS_PER_CREDIT below.
STRIPE_CENTS_PER_CREDIT = int(os.getenv("STRIPE_CENTS_PER_CREDIT", "1"))

if STRIPE_CENTS_PER_CREDIT <= 0:
    raise RuntimeError(
        f"STRIPE_CENTS_PER_CREDIT must be > 0 (got {STRIPE_CENTS_PER_CREDIT})",
    )


class WebhookError(Exception):
    """Raised on any webhook-processing failure the caller should turn
    into an HTTP error. `status_code` mirrors the FastAPI response we
    want the framework to emit."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _require_secret() -> str:
    if not STRIPE_WEBHOOK_SECRET:
        # 404 rather than 503 so Stripe doesn't retry — and doesn't
        # auto-disable the endpoint after ~3 days of continuous 5xx
        # while we're mid-configuration. A misconfigured secret must
        # NEVER be treated as authorised.
        raise WebhookError(404, "Stripe webhook not configured")
    return STRIPE_WEBHOOK_SECRET


def verify_and_parse(raw_body: bytes, signature_header: Optional[str]) -> stripe.Event:
    """Verify the HMAC signature and return the parsed event.

    Raises WebhookError with the HTTP status FastAPI should surface.
    """
    secret = _require_secret()
    if not signature_header:
        raise WebhookError(400, "missing Stripe-Signature header")
    try:
        return stripe.Webhook.construct_event(
            payload=raw_body,
            sig_header=signature_header,
            secret=secret,
        )
    except stripe.SignatureVerificationError as e:
        # 401 rather than 400 so Stripe's dashboard flags this as an
        # auth problem rather than a "we sent bad data" problem.
        raise WebhookError(401, f"invalid Stripe signature: {e}") from None
    except ValueError as e:
        raise WebhookError(400, f"invalid payload: {e}") from None


def _extract_identity_id(session: dict) -> int:
    """Pull identity_id from a Checkout Session's metadata. Callers set
    this when they create the Payment Link or Session — we refuse to
    process a payment we can't attribute.
    """
    metadata = session.get("metadata") or {}
    raw = metadata.get("identity_id")
    if raw is None:
        raise WebhookError(
            400,
            "checkout session is missing metadata.identity_id — refusing "
            "to credit an unattributed payment",
        )
    try:
        identity_id = int(raw)
    except (TypeError, ValueError):
        raise WebhookError(400, f"metadata.identity_id is not an integer: {raw!r}") from None
    if identity_id <= 0:
        raise WebhookError(400, f"metadata.identity_id must be positive: {identity_id}")
    return identity_id


def _cents_to_credits(amount_cents: int) -> int:
    """Round DOWN. Users lose the remainder — that's the trade-off for
    keeping this integer-only. Alternative would be storing fractional
    credits, which complicates the atomic decrement path for zero
    benefit at MVP scale.
    """
    if amount_cents <= 0:
        raise WebhookError(400, f"non-positive amount_total: {amount_cents}")
    credits = amount_cents // STRIPE_CENTS_PER_CREDIT
    if credits <= 0:
        raise WebhookError(
            400,
            f"amount_total {amount_cents} cents rounds down to 0 credits at "
            f"{STRIPE_CENTS_PER_CREDIT} cents/credit",
        )
    return credits


async def _handle_checkout_completed(
    conn: aiosqlite.Connection, event: stripe.Event,
) -> dict:
    """Credit the balance from a completed Checkout Session.

    IMPORTANT: `checkout.session.completed` fires the instant the
    Session enters `status=complete`, even for async payment methods
    (ACH, SEPA, boleto) where the funds have NOT arrived yet. Those
    events carry `payment_status="unpaid"` and settle later via
    `checkout.session.async_payment_succeeded`. Crediting here without
    the status check enables ACH-then-reverse fraud — the user gets
    credits immediately and reverses the debit within 60 days.

    Idempotent on the session id — the handlers.topup layer enforces
    UNIQUE(source), so a Stripe retry with the same event will get
    deduplicated at the DB level and return the existing balance.
    """
    session = event["data"]["object"]

    payment_status = session.get("payment_status")
    # `no_payment_required` covers 0-total Sessions (rare but valid).
    if payment_status not in ("paid", "no_payment_required"):
        return {
            "handled": False,
            "type": event["type"],
            "reason": f"payment_status={payment_status}",
        }

    if session.get("metadata", {}).get("intent_memo"):
        # Preferred flow — dispatched by dispatch() when the operator
        # created the Session with metadata.intent_memo. Kept here as
        # a defensive fallback in case a retry lands directly.
        return await _handle_via_intent(conn, event)

    identity_id = _extract_identity_id(session)

    amount_cents = session.get("amount_total")
    if amount_cents is None:
        raise WebhookError(400, "checkout session has no amount_total")
    credits = _cents_to_credits(int(amount_cents))

    session_id = session.get("id")
    if not session_id:
        raise WebhookError(400, "checkout session has no id")
    source = f"stripe_session:{session_id}"

    return await handlers.topup(conn, identity_id, credits, source)


async def _handle_via_intent(
    conn: aiosqlite.Connection, event: stripe.Event,
) -> dict:
    """Finalise a payment_intents row when the Session carries
    metadata.intent_memo. Preferred over `topup(source=stripe_session:X)`
    because it unifies the source-key namespace with other providers
    and prevents double-credit if the same payment also gets manually
    marked paid by ops."""
    session = event["data"]["object"]
    payment_status = session.get("payment_status")
    if payment_status not in ("paid", "no_payment_required"):
        return {
            "handled": False,
            "type": event["type"],
            "reason": f"payment_status={payment_status}",
        }
    memo = session.get("metadata", {}).get("intent_memo")
    if not memo:
        raise WebhookError(400, "metadata.intent_memo missing for intent flow")
    session_id = session.get("id")
    amount_cents = session.get("amount_total")
    result = await handlers.mark_paid_by_memo(
        conn,
        memo,
        provider_ref=f"stripe:{session_id}",
        actual_amount_cents=int(amount_cents) if amount_cents is not None else None,
        # Stripe can fire this event long after the checkout was
        # created (delayed async payments, chargeback-then-reversal).
        # Money is real — honour it even if the intent TTL elapsed.
        allow_expired=True,
    )
    return {"handled": True, "type": event["type"], "result": result}


# Event types we act on. Anything else is acknowledged with a 200 (so
# Stripe stops retrying) but not processed. That includes refunds for
# now — mishandling a refund would either double-refund the user or
# leave them stuck; explicit ops workflow is safer than a naive auto.
EVENT_HANDLERS = {
    "checkout.session.completed": _handle_checkout_completed,
    # Async payment methods (ACH/SEPA/boleto) settle here after the
    # initial `completed` event returns `payment_status=unpaid`.
    "checkout.session.async_payment_succeeded": _handle_checkout_completed,
}


async def dispatch(conn: aiosqlite.Connection, event: stripe.Event) -> dict:
    """Route a verified event to its handler. Unknown types are 200-OK'd
    with a `handled: False` marker so Stripe stops retrying."""
    handler = EVENT_HANDLERS.get(event["type"])
    if handler is None:
        return {"handled": False, "type": event["type"]}
    result = await handler(conn, event)
    return {"handled": True, "type": event["type"], "result": result}
