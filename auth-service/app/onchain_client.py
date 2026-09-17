"""On-chain (Miden/Leviathan) send-side client: build payment instructions
for payment intents.

Companion to the note-watcher (receive-side, separate service), mirroring
the stripe_client / stripe_webhook split and the same caller contract:
given an existing
`payment_intents` row, produce what the payer needs to pay it. Unlike the
hosted-checkout rails there is no third-party API to call — "checkout" is
pure data: the gateway's receiving address, the accepted faucet (token) id,
the exact token amount, and the intent memo the payer must attach to the
P2ID note (NoteAttachment) so the watcher can bind the note to the intent.

The balance is credited by the note-watcher observing the committed note
on-chain and calling mark_paid_by_memo — never by anything in this module.

Key custody: this service holds NO wallet key material. Receiving requires
only the public bech32 address; the seed/private key is needed only to
sweep (consume) notes into the vault, which is the watcher/sweeper's
concern, deliberately outside the ledger's trust boundary.

Amount convention: `payment_intents` prices in USD cents. The token is
assumed USD-pegged (USDT); conversion to base units is
    base_units = ceil(amount_cents * 10**DECIMALS / CENTS_PER_TOKEN)
rounded UP so decimal truncation can never make an honest payer land one
base unit under the webhook's underpay guard. The receive side converts
back with cents_for_token_amount(), which rounds DOWN for the symmetric
reason: the ledger must never credit a cent that wasn't fully paid.
"""

from __future__ import annotations

import os

import httpx


# The gateway's receiving account, as a public bech32 address
# (mm1... mainnet, mtst1... testnet). Public information — the seed that
# controls this account must never appear in this service's config.
ONCHAIN_GATEWAY_ADDRESS = os.getenv("ONCHAIN_GATEWAY_ADDRESS", "")

# The fungible faucet whose asset we accept; the faucet's account id IS the
# token id. Testnet USDT faucet: mtst1azftenneus72ugqqsj9rk7cveqk0eraz
ONCHAIN_FAUCET_ID = os.getenv("ONCHAIN_FAUCET_ID", "")

ONCHAIN_TOKEN_SYMBOL = os.getenv("ONCHAIN_TOKEN_SYMBOL", "USDT")

# Base-unit exponent of the faucet's asset. This is defined by the faucet's
# on-chain metadata, not by us — verify it against the faucet (the wallet UI
# shows amounts already scaled) before going live: a wrong value here
# mis-prices every intent by powers of ten.
ONCHAIN_TOKEN_DECIMALS = int(os.getenv("ONCHAIN_TOKEN_DECIMALS", "6"))

# USD cents per 1 whole token. 100 = the token is a dollar-pegged stable.
# Fixed-rate by design: accepting only a stablecoin keeps an oracle out of
# the billing path.
ONCHAIN_CENTS_PER_TOKEN = int(os.getenv("ONCHAIN_CENTS_PER_TOKEN", "100"))

# Informational only (shown to payers / used by frontends to pick the right
# wallet network). Never trusted by the receive side — the watcher talks to
# one node and sees one chain.
ONCHAIN_NETWORK = os.getenv("ONCHAIN_NETWORK", "testnet")

# Bech32 HRPs of the Miden networks; a light sanity check so a truncated or
# foreign-chain address fails at config time instead of minting unpayable
# intents.
_KNOWN_ADDRESS_PREFIXES = ("mm1", "mtst1", "mdev1", "mlcl1", "mcst1")

# The note-builder: an internal HTTP service (ai-edge/note-watcher,
# `node src/builder-server.mjs`) that turns (sender, gateway, faucet,
# amount, memo) into the serialized wallet payload the payer's wallet
# signs. Same SDK build and same memo codec as the watcher that later
# reads the note. Empty URL = server-built payloads are OFF: intents are
# still created, clients must build their own note (legacy path).
ONCHAIN_BUILDER_URL = os.getenv("ONCHAIN_BUILDER_URL", "").rstrip("/")
ONCHAIN_BUILDER_TOKEN = os.getenv("ONCHAIN_BUILDER_TOKEN", "")
ONCHAIN_BUILDER_TIMEOUT_SEC = float(os.getenv("ONCHAIN_BUILDER_TIMEOUT_SEC", "10"))


class OnchainError(Exception):
    """Raised when payment instructions cannot be produced (missing or
    inconsistent config, bad amount). Callers surface it exactly like
    StripeError: HTTP error without touching the committed
    payment_intents row."""

    def __init__(self, detail: str, status_code: int = 502):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _require_config() -> None:
    if not ONCHAIN_GATEWAY_ADDRESS:
        raise OnchainError("ONCHAIN_GATEWAY_ADDRESS not configured on server", status_code=503)
    if not ONCHAIN_GATEWAY_ADDRESS.startswith(_KNOWN_ADDRESS_PREFIXES):
        raise OnchainError(
            "ONCHAIN_GATEWAY_ADDRESS is not a Miden bech32 address", status_code=503,
        )
    if not ONCHAIN_FAUCET_ID:
        raise OnchainError("ONCHAIN_FAUCET_ID not configured on server", status_code=503)
    if not ONCHAIN_FAUCET_ID.startswith(_KNOWN_ADDRESS_PREFIXES):
        raise OnchainError(
            "ONCHAIN_FAUCET_ID is not a Miden bech32 account id", status_code=503,
        )
    if ONCHAIN_CENTS_PER_TOKEN <= 0:
        raise OnchainError("ONCHAIN_CENTS_PER_TOKEN must be positive", status_code=503)
    if not (0 <= ONCHAIN_TOKEN_DECIMALS <= 18):
        raise OnchainError("ONCHAIN_TOKEN_DECIMALS out of range", status_code=503)


def token_amount_for_cents(amount_cents: int) -> int:
    """USD cents -> token base units, rounded UP (payer-side)."""
    if amount_cents <= 0:
        raise OnchainError(
            f"payment amount must be positive (got {amount_cents} cents)",
            status_code=400,
        )
    numerator = amount_cents * (10 ** ONCHAIN_TOKEN_DECIMALS)
    return -(-numerator // ONCHAIN_CENTS_PER_TOKEN)  # ceil division


def cents_for_token_amount(base_units: int) -> int:
    """Token base units -> USD cents, rounded DOWN (receive-side).

    The note-watcher uses this to turn an observed note's asset amount into
    the `actual_amount_cents` it reports to mark_paid_by_memo, which then
    applies the standard underpay guard against the intent's amount_cents.
    """
    if base_units < 0:
        raise OnchainError(f"token amount must be non-negative (got {base_units})",
                           status_code=400)
    return (base_units * ONCHAIN_CENTS_PER_TOKEN) // (10 ** ONCHAIN_TOKEN_DECIMALS)


def preflight(amount_cents: int) -> None:
    """Everything that can be refused WITHOUT building instructions.

    Symmetric with stripe_client.preflight: callers run this BEFORE the
    intent row is committed, so a rail that cannot quote does not cost
    the user one of their capped, self-uncancellable pending slots.
    The on-chain rail has no minimum — any positive amount is payable.
    """
    _require_config()
    token_amount_for_cents(amount_cents)   # raises on a non-positive amount


def validate_sender_address(sender_address: str) -> str:
    """The payer's Miden account the payload is built FOR.

    A note names its sender and the wallet signs only for its own
    account, so a payload built for address A is unusable from B — the
    address must be right BEFORE we spend a build on it. Only the shape
    and the network can be checked here (the wallet proves ownership by
    signing); a wrong-but-well-formed address costs nothing: the wallet
    refuses to sign it, and any payload can only ever pay the gateway.
    """
    if (not isinstance(sender_address, str)
            or not (20 <= len(sender_address) <= 120)
            or not sender_address.startswith(_KNOWN_ADDRESS_PREFIXES)
            or not all(ch in "abcdefghijklmnopqrstuvwxyz0123456789" for ch in sender_address)):
        raise OnchainError("sender_address must be a Miden bech32 address", status_code=400)
    gateway_prefix = next((p for p in _KNOWN_ADDRESS_PREFIXES
                           if ONCHAIN_GATEWAY_ADDRESS.startswith(p)), None)
    if gateway_prefix and not sender_address.startswith(gateway_prefix):
        raise OnchainError(
            f"sender_address is on a different network than the gateway "
            f"({ONCHAIN_NETWORK})", status_code=400)
    return sender_address


def builder_enabled() -> bool:
    return bool(ONCHAIN_BUILDER_URL)


async def _builder_request(method: str, path: str, json: dict | None = None) -> httpx.Response:
    """One HTTP call to the note-builder. Kept as a single seam so tests
    replace it without touching httpx (the Stripe tests already patch
    httpx.AsyncClient globally, and the two must not collide)."""
    headers = {}
    if ONCHAIN_BUILDER_TOKEN:
        headers["authorization"] = f"Bearer {ONCHAIN_BUILDER_TOKEN}"
    async with httpx.AsyncClient(timeout=ONCHAIN_BUILDER_TIMEOUT_SEC) as client:
        return await client.request(method, f"{ONCHAIN_BUILDER_URL}{path}",
                                    json=json, headers=headers)


async def preflight_builder() -> None:
    """Refuse BEFORE the intent row exists when the builder cannot serve.

    Symmetric with preflight(): a payer who asked for a server-built
    payload gets nothing useful from an intent whose payload cannot be
    built, and that intent would still hold one of their capped pending
    slots for the whole TTL. /health is 503 until the builder's WASM is
    loaded, so "up but not ready" is refused too.
    """
    if not builder_enabled():
        raise OnchainError(
            "server-built wallet payloads are not enabled on this server "
            "(ONCHAIN_BUILDER_URL unset) — build the note client-side", status_code=503)
    try:
        r = await _builder_request("GET", "/health")
    except httpx.HTTPError as e:
        raise OnchainError(f"note-builder unreachable: {e}", status_code=503) from None
    if r.status_code != 200:
        raise OnchainError(
            f"note-builder not ready (HTTP {r.status_code})", status_code=503)


async def build_custom_tx(*, memo: str, amount_cents: int, sender_address: str) -> dict:
    """Ask the note-builder for the wallet payload of one intent.

    Returns {address, recipientAddress, transactionRequest, note_id} —
    `transactionRequest` is the base64 the wallet's
    requestTransaction({type:'Custom'}) deserializes; `note_id` is the
    note the payer will publish, known here BEFORE payment.
    """
    _require_config()
    if not builder_enabled():
        raise OnchainError("ONCHAIN_BUILDER_URL not configured on server", status_code=503)
    body = {
        "sender_address": validate_sender_address(sender_address),
        "pay_to_address": ONCHAIN_GATEWAY_ADDRESS,
        "faucet_id": ONCHAIN_FAUCET_ID,
        "token_amount": str(token_amount_for_cents(amount_cents)),
        "memo": memo,
    }
    try:
        r = await _builder_request("POST", "/build", json=body)
    except httpx.HTTPError as e:
        raise OnchainError(f"note-builder unreachable: {e}", status_code=502) from None
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code != 200:
        detail = data.get("error") if isinstance(data, dict) else None
        # The builder's 4xx are OUR bugs or bad input (validation
        # mirrors ours), never the payer's fault: report as 502.
        raise OnchainError(
            f"note-builder refused (HTTP {r.status_code}): {detail or r.text[:200]}",
            status_code=502)
    for key in ("address", "recipientAddress", "transactionRequest", "note_id"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise OnchainError(f"note-builder returned no {key}", status_code=502)
    if data["address"] != body["sender_address"] or data["recipientAddress"] != ONCHAIN_GATEWAY_ADDRESS:
        raise OnchainError("note-builder returned a payload for other parties", status_code=502)
    return {k: data[k] for k in ("address", "recipientAddress", "transactionRequest", "note_id")}


async def create_payment_request(
    *,
    memo: str,
    amount_cents: int,
    description: str = "Leviathan AI credits",
    custom_tx: dict | None = None,
) -> dict:
    """Build the payment instructions for an intent bound to `memo`.

    `token_amount` is the intent's exact price in base units. The payer
    MUST attach `memo` to the note as a NoteAttachment (scheme
    0x4C565431 "LVT1"; codec in ai-edge/note-watcher/src/core.mjs) —
    that memo is the ONLY thing that binds a committed note to an
    intent (same-price intents have identical amounts). A payment
    without the attachment cannot be auto-credited: it parks in the
    watcher as an ops case. The amount must still be EXACT — the
    webhook refuses any deviation.

    Returns the same top-level shape as the other rails so callers can
    treat all providers uniformly:
      { "invoice_url": <miden:<address> URI — QR-compatible with the wallet>,
        "invoice_id":  None (no third-party session exists),
        "expiration_estimate_date": None (the intent's own expires_at rules),
        "onchain": { pay_to_address, faucet_id, token_amount (str, base
                     units), token_decimals, token_symbol, memo, network,
                     description } }

    `token_amount` is a string: it can exceed 2^53-1 and must survive
    JSON round-trips through JavaScript clients undamaged.

    async for contract symmetry with the other rails only — there is no
    network call here.
    """
    _require_config()
    base_units = token_amount_for_cents(amount_cents)

    return {
        # The wallet's QR format is address-only (`miden:<address>`); amount
        # and memo have no URI params yet, so clients must present them from
        # the `onchain` block alongside the QR.
        "invoice_url": f"miden:{ONCHAIN_GATEWAY_ADDRESS}",
        "invoice_id": None,
        "expiration_estimate_date": None,
        "onchain": {
            "pay_to_address": ONCHAIN_GATEWAY_ADDRESS,
            "faucet_id": ONCHAIN_FAUCET_ID,
            # Pure P2ID only: a P2IDE (reclaimable) note is not settled
            # money at commit time and the watcher will not credit it.
            "note_kind": "p2id",
            # A private note is unobservable by the watcher — the money
            # would arrive and never be credited. Frontends must pass
            # noteType 'public' explicitly, never rely on wallet defaults.
            "note_visibility": "public",
            "token_amount": str(base_units),
            "token_decimals": ONCHAIN_TOKEN_DECIMALS,
            "token_symbol": ONCHAIN_TOKEN_SYMBOL,
            "memo": memo,
            "network": ONCHAIN_NETWORK,
            "description": description,
            # Server-built wallet payload (build_custom_tx), when the
            # payer supplied a sender_address: hand it straight to
            # wallet.requestTransaction({type:'Custom', payload}) — no
            # client-side SDK needed. Absent = client builds its own.
            **({"custom_tx": custom_tx} if custom_tx else {}),
        },
    }
