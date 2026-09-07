"""On-chain (Miden) payment reporting — receive-side.

Companion to `onchain_client.py` (send-side). Unlike Stripe there is no
third-party processor signing deliveries: the caller is OUR OWN
note-watcher, which observed a P2ID note committed on-chain to the
gateway's receiving account and matched it to a pending intent. The HTTP
layer authenticates it with a dedicated bearer (ONCHAIN_WATCHER_TOKEN in
main.py) — deliberately distinct from ADMIN_TOKEN and PROXY_REFUND_TOKEN
so a compromised watcher can only report payments (bounded by the
underpay guard and the intents it can name), never mint credit, create
identities, or debit balances.

Trust model: the watcher's claim is re-checked server-side wherever the
server has independent knowledge — the faucet must be the one accepted
rail-wide (a note of the wrong token must never credit), the reported
amount must EQUAL the intent's dusted amount (token_amount_for_intent:
price + per-memo sub-cent dust, the value the payer was quoted), and
crediting goes through the same mark_paid_by_memo path as every other
rail, so replay dedup (topups.source UNIQUE), the underpaid guard, and
the expired-intent escape hatch all apply unchanged. The dust check is
what makes amounts intent-specific: a note that paid intent A cannot be
re-attributed to a same-price intent B, because B demands different
base units. What the server cannot re-check — that note_id really
exists on-chain with those assets — is exactly the watcher's job, which
is why the endpoint is not public.
"""

from __future__ import annotations

import logging

import aiosqlite

from . import handlers, onchain_client

logger = logging.getLogger("auth-service.onchain")


class WebhookError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def parse_payload(payload: dict) -> dict:
    """Validate the watcher's report shape. 400 on anything malformed —
    the caller is our own service, so a bad payload is a watcher bug and
    must be loud, never silently coerced."""
    if not isinstance(payload, dict):
        raise WebhookError(400, "payload must be a JSON object")

    memo = payload.get("memo")
    if not isinstance(memo, str) or not memo:
        raise WebhookError(400, "memo must be a non-empty string")

    note_id = payload.get("note_id")
    if not isinstance(note_id, str) or not note_id:
        raise WebhookError(400, "note_id must be a non-empty string")

    faucet_id = payload.get("faucet_id")
    if not isinstance(faucet_id, str) or not faucet_id:
        raise WebhookError(400, "faucet_id must be a non-empty string")

    # bool is an int subclass; a watcher sending `true` here is broken.
    amount = payload.get("amount_base_units")
    if isinstance(amount, str) and amount.isdigit():
        # Base-unit amounts can exceed 2^53-1, so a careful watcher sends
        # them as decimal strings (the same reason onchain_client returns
        # token_amount as a string).
        amount = int(amount)
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise WebhookError(400, "amount_base_units must be a positive integer")

    return {"memo": memo, "note_id": note_id,
            "faucet_id": faucet_id, "amount_base_units": amount}


async def dispatch(conn: aiosqlite.Connection, payload: dict) -> dict:
    """Credit the intent a committed note pays for.

    Returns {"handled": bool, "result": ...} mirroring the Stripe
    dispatcher's contract, so the route layer applies the same fail-loud
    rule: handled-but-not-credited is answered 500 (the watcher retries
    and ops get an ERROR log) instead of the payment vanishing behind a
    silent 200.
    """
    p = parse_payload(payload)

    # Wrong token: not handled at all. Real assets may have arrived, but
    # they are not the asset this rail sells credits for — sweeping or
    # refunding a stray token is an ops decision, not an auto-credit.
    if p["faucet_id"] != onchain_client.ONCHAIN_FAUCET_ID:
        raise WebhookError(
            400,
            f"faucet {p['faucet_id']!r} is not the accepted faucet",
        )

    try:
        actual_cents = onchain_client.cents_for_token_amount(p["amount_base_units"])
    except onchain_client.OnchainError as e:
        raise WebhookError(e.status_code, e.detail) from None

    # Dusted-amount guard, enforced HERE and not merely advised to the
    # watcher: the payer was quoted price + memo_dust, and the note must
    # match that figure EXACTLY. Less is an underpayment; more is NOT
    # accepted as overpay, because a >= rule reopens the misattribution
    # hole (mint intents until one's dust undercuts the observed note,
    # then claim it as "overpaid"). An honest off-by-anything note is
    # unmatchable by the watcher's exact-amount rule too — it lands in
    # ops territory (admin mark-paid after eyeballing), never auto-credit.
    intent = await handlers.get_intent_by_memo(conn, p["memo"])
    if intent is not None:
        expected_units = onchain_client.token_amount_for_intent(
            p["memo"], intent["amount_cents"])
        if p["amount_base_units"] != expected_units:
            direction = ("underpaid" if p["amount_base_units"] < expected_units
                         else "amount mismatch")
            result = {
                "success": False,
                "error": (f"{direction}: intent expects exactly {expected_units} "
                          f"base units (price + memo dust), got {p['amount_base_units']}"),
            }
            logger.error(
                "MONEY RECEIVED BUT NOT CREDITED (onchain): note=%s memo=%s "
                "units=%d expected_units=%d — amount does not match this "
                "intent's dusted quote; verify the note was matched to the "
                "right memo before any manual mark-paid",
                p["note_id"], p["memo"], p["amount_base_units"], expected_units,
            )
            return {"handled": True, "result": result}
    # intent None falls through: mark_paid_by_memo reports 'intent not
    # found' through the standard fail-loud path.

    result = await handlers.mark_paid_by_memo(
        conn,
        p["memo"],
        provider_ref=f"miden:{p['note_id']}",
        actual_amount_cents=actual_cents,
        # Same escape hatch as every webhook adapter: an on-chain
        # confirmation that lands after the intent's TTL must be honoured
        # at the intent's ORIGINAL price — the tokens are already ours.
        allow_expired=True,
    )
    if result.get("success"):
        logger.info(
            "onchain payment credited (note=%s memo=%s cents=%d dedup=%s)",
            p["note_id"], p["memo"], actual_cents, bool(result.get("deduplicated")),
        )
    else:
        # The tokens are on-chain in our account either way — this must
        # never disappear into a silent log line.
        logger.error(
            "MONEY RECEIVED BUT NOT CREDITED (onchain): note=%s memo=%s "
            "cents=%d error=%r — inspect the intent, then finalise via "
            "POST /v1/payment-intents/%s/mark-paid (ADMIN)",
            p["note_id"], p["memo"], actual_cents, result.get("error"), p["memo"],
        )
    return {"handled": True, "result": result}
