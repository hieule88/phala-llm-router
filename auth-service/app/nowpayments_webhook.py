"""NOWPayments IPN (webhook) handling.

NOWPayments authenticates callbacks by signing a canonical JSON body
with HMAC-SHA512 using the store's IPN secret. Signature check is the
only auth — no Bearer token — because the caller is NOWPayments' infra.

NOWPayments IPN reference:
  https://documenter.getpostman.com/view/7907941/2s93JusNJt#intro-ipn

Payment state machine (we act only on `finished`):
  waiting → confirming → confirmed → sending → finished
                                                  ↓
                                             partially_paid / failed / refunded / expired

`order_id` is a caller-supplied opaque string we set when creating the
payment. We require the form `identity:<int>` so a compromised or
misrouted event can't credit an arbitrary account.
"""

import hashlib
import hmac
import json
import logging
import os
from typing import Optional

import aiosqlite

from . import handlers

# Money-path logging. A `finished` IPN that fails to credit is real revenue
# with no ledger entry — it must leave a trace even when the HTTP layer ACKs.
logger = logging.getLogger("auth.nowpayments")

NOWPAYMENTS_IPN_SECRET = os.getenv("NOWPAYMENTS_IPN_SECRET", "")

# Reject bodies bigger than this before HMAC-verifying (which parses
# JSON). Prevents an unauthenticated caller from forcing the process
# to parse a 100 MB deeply-nested payload — real IPNs are under 4 KB.
MAX_IPN_BODY_BYTES = int(os.getenv("MAX_IPN_BODY_BYTES", str(64 * 1024)))

# How many USD cents equal one prove credit. Default: 1 cent = 1 credit
# → $1.00 = 100 credits. `price_amount` in the IPN is in the store's
# fiat currency (we require USD in the NOWPayments store settings).
NOWPAYMENTS_CENTS_PER_CREDIT = int(os.getenv("NOWPAYMENTS_CENTS_PER_CREDIT", "1"))

if NOWPAYMENTS_CENTS_PER_CREDIT <= 0:
    raise RuntimeError(
        f"NOWPAYMENTS_CENTS_PER_CREDIT must be > 0 "
        f"(got {NOWPAYMENTS_CENTS_PER_CREDIT})",
    )


class WebhookError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _require_secret() -> str:
    if not NOWPAYMENTS_IPN_SECRET:
        # 404 rather than 5xx: NOWPayments treats 5xx as retryable and
        # will eventually flag/disable a persistently-failing endpoint,
        # losing events that expire mid-retry. A missing secret is
        # "not deployed", not "temporary outage".
        raise WebhookError(404, "NOWPayments webhook not configured")
    return NOWPAYMENTS_IPN_SECRET


def verify_and_parse(raw_body: bytes, signature_header: Optional[str]) -> dict:
    """Verify HMAC-SHA512 signature and return the parsed IPN payload.

    NOWPayments signs the HMAC over the **exact raw request body** it sends —
    NOT a re-serialized/sorted form. Re-encoding (sort keys, whitespace, slash
    or unicode escaping) produces different bytes and the HMAC never matches;
    verified empirically against real sandbox IPNs. So we HMAC `raw_body` as-is
    and only parse it into a dict afterwards, for the caller.

    Raises WebhookError with the HTTP status FastAPI should surface.
    """
    secret = _require_secret()
    if not signature_header:
        raise WebhookError(400, "missing x-nowpayments-sig header")
    if len(raw_body) > MAX_IPN_BODY_BYTES:
        raise WebhookError(413, "IPN body too large")

    expected = hmac.new(secret.encode(), raw_body, hashlib.sha512).hexdigest()
    # Constant-time compare so an attacker can't derive the secret via
    # per-byte response-time differences.
    if not hmac.compare_digest(expected, signature_header.strip()):
        raise WebhookError(401, "invalid NOWPayments signature")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as e:
        raise WebhookError(400, f"invalid JSON payload: {e}") from None
    if not isinstance(payload, dict):
        raise WebhookError(400, "IPN payload must be a JSON object")

    return payload


def _extract_identity_id(payload: dict) -> int:
    """Pull identity_id from `order_id`. Expected format: 'identity:<int>'
    (colon-separated). Refuse anything else — an unattributable payment
    is an ops problem, not something we silently credit somewhere."""
    order_id = payload.get("order_id")
    if not isinstance(order_id, str) or not order_id:
        raise WebhookError(
            400,
            "IPN missing order_id — refusing to credit an unattributed payment",
        )
    prefix = "identity:"
    if not order_id.startswith(prefix):
        raise WebhookError(
            400,
            f"order_id must be prefixed with '{prefix}' (got {order_id!r})",
        )
    raw = order_id[len(prefix):]
    try:
        identity_id = int(raw)
    except (TypeError, ValueError):
        raise WebhookError(400, f"order_id identity is not an integer: {raw!r}") from None
    if identity_id <= 0:
        raise WebhookError(400, f"order_id identity must be positive: {identity_id}")
    return identity_id


def _usd_to_credits(price_amount: float, currency: str) -> int:
    """Convert `price_amount` in the store's fiat currency to credits.

    Requires USD — the store settings pin the fiat currency and this
    layer refuses any other value, so a mis-configuration surfaces as
    a loud denial rather than a wrong credit amount.
    """
    if currency.lower() != "usd":
        raise WebhookError(
            400,
            f"unsupported price_currency {currency!r}; set the NOWPayments store to USD",
        )
    if price_amount is None or float(price_amount) <= 0:
        raise WebhookError(400, f"non-positive price_amount: {price_amount!r}")
    # USD has 2 decimal places — round to cents deterministically.
    cents = round(float(price_amount) * 100)
    credits = cents // NOWPAYMENTS_CENTS_PER_CREDIT
    if credits <= 0:
        raise WebhookError(
            400,
            f"price_amount ${price_amount} rounds down to 0 credits at "
            f"{NOWPAYMENTS_CENTS_PER_CREDIT} cents/credit",
        )
    return credits


# Statuses that mean "money has arrived, credit the user". Others are
# either transient (waiting/confirming) or terminal-but-negative
# (failed/refunded/expired) — we ack 200 to stop retries and log,
# but don't touch the balance.
TERMINAL_SUCCESS_STATUSES = frozenset({"finished"})


async def dispatch(conn: aiosqlite.Connection, payload: dict) -> dict:
    """Route a verified IPN payload to the appropriate handler.

    Only `payment_status == "finished"` credits the balance. Everything
    else is acknowledged with `handled: False` so NOWPayments doesn't
    retry indefinitely.

    Two flows depending on order_id:
    - "intent-<hex>" (preferred) → mark the payment_intents row paid.
      Unifies the source-key namespace with every other channel and
      prevents double-credit when ops also manually marks paid.
    - "identity:<int>" (legacy) → direct topup by identity. Kept for
      NOWPayments Payment Buttons that predate the intent flow.
    """
    status = payload.get("payment_status")
    if status not in TERMINAL_SUCCESS_STATUSES:
        logger.info("IPN %s ack'd, no credit (payment_id=%s order_id=%s)",
                    status, payload.get("payment_id"), payload.get("order_id"))
        return {"handled": False, "payment_status": status}

    order_id = payload.get("order_id")
    payment_id = payload.get("payment_id")
    if payment_id is None:
        raise WebhookError(400, "IPN missing payment_id")

    price_amount = payload.get("price_amount")
    price_currency = payload.get("price_currency", "")

    if isinstance(order_id, str) and order_id.startswith("intent-"):
        # Convert USD to cents for the underpayment check inside
        # mark_paid_by_memo — the intent's expected_cents was set when
        # the user created the intent, and this actual value is what
        # NOWPayments confirms was received.
        if price_currency.lower() != "usd":
            raise WebhookError(
                400,
                f"unsupported price_currency {price_currency!r}; store must be USD",
            )
        if price_amount is None or float(price_amount) <= 0:
            raise WebhookError(400, f"non-positive price_amount: {price_amount!r}")
        actual_cents = round(float(price_amount) * 100)
        result = await handlers.mark_paid_by_memo(
            conn,
            order_id,
            provider_ref=f"nowpayments:{payment_id}",
            actual_amount_cents=actual_cents,
            # A slow bank/crypto confirm may land after the intent's
            # TTL. NOWPayments' 'finished' signal is money-in-hand;
            # dropping it on expiry would lose real revenue. This also
            # pays intents already lazily flipped to 'expired'.
            allow_expired=True,
        )
        if result.get("success"):
            logger.info("IPN finished credited (payment_id=%s memo=%s dedup=%s)",
                        payment_id, order_id, bool(result.get("deduplicated")))
        else:
            logger.error(
                "MONEY RECEIVED BUT NOT CREDITED: payment_id=%s memo=%s "
                "amount=%s %s error=%r — investigate and finalise via "
                "POST /v1/payment-intents/%s/mark-paid",
                payment_id, order_id, price_amount, price_currency,
                result.get("error"), order_id)
        return {"handled": True, "payment_status": status, "result": result}

    # Legacy identity:<id> path — direct topup by identity, source keyed
    # off the NOWPayments payment_id. Kept for backward compat with
    # existing NOWPayments Payment Buttons that don't set an intent memo.
    identity_id = _extract_identity_id(payload)
    credits = _usd_to_credits(price_amount, price_currency)
    source = f"nowpayments:{payment_id}"
    result = await handlers.topup(conn, identity_id, credits, source)
    if result.get("success"):
        logger.info("IPN finished credited (payment_id=%s identity=%s credits=%s)",
                    payment_id, identity_id, credits)
    else:
        logger.error(
            "MONEY RECEIVED BUT NOT CREDITED: payment_id=%s identity=%s "
            "credits=%s error=%r — finalise manually via POST /v1/topup",
            payment_id, identity_id, credits, result.get("error"))
    return {"handled": True, "payment_status": status, "result": result}
