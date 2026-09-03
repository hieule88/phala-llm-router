"""On-chain (Miden/Leviathan) send-side client: build payment instructions
for payment intents.

Companion to the note-watcher (receive-side, separate service), mirroring
the stripe_client / stripe_webhook and nowpayments_client /
nowpayments_webhook splits and the same caller contract: given an existing
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


class OnchainError(Exception):
    """Raised when payment instructions cannot be produced (missing or
    inconsistent config, bad amount). Callers surface it exactly like
    StripeError / NowpaymentsError: HTTP error without touching the
    committed payment_intents row."""

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


async def create_payment_request(
    *,
    memo: str,
    amount_cents: int,
    description: str = "Leviathan AI credits",
) -> dict:
    """Build the payment instructions for an intent bound to `memo`.

    `memo` must ride in the P2ID note's attachment (NoteAttachment) — the
    same correlation role as Stripe's `client_reference_id` — and comes
    back to the ledger when the watcher matches the committed note.

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
            "token_amount": str(base_units),
            "token_decimals": ONCHAIN_TOKEN_DECIMALS,
            "token_symbol": ONCHAIN_TOKEN_SYMBOL,
            "memo": memo,
            "network": ONCHAIN_NETWORK,
            "description": description,
        },
    }
