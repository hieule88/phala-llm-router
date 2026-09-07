"""Business logic — independent of HTTP framing.

Kept separate from `main.py` so tests can exercise the database semantics
without spinning up FastAPI. Each function returns a plain dict (or None)
that the HTTP layer wraps into a response.

Concurrency model: every write path that mutates a balance holds an
explicit transaction. SQLite serialises writes at the connection level,
so the atomic decrement here cannot race against a concurrent topup or
another consume on the same identity.
"""

import hashlib
import os
import secrets
from typing import Optional

import aiosqlite

from . import onchain_client
from .db import transaction
from .tiers import get_tier


# Number of random bytes in an intent memo. 8 bytes = 16 hex chars = 64
# bits of entropy — enough that an attacker cannot guess a pending
# intent belonging to someone else. Not a secret, but not enumerable.
INTENT_MEMO_ENTROPY_BYTES = 8

# Entropy in the one-shot refund capability minted per debit. 16 bytes =
# 128 bits: a caller cannot guess another request's token, so only the
# request that actually spent a credit can reverse it.
REFUND_TOKEN_ENTROPY_BYTES = 16

# Server-side price per credit in USD cents. The intent's amount_cents
# is derived from credits × this constant — never taken from the user.
# Prevents a caller from creating an intent for 1_000_000 credits at 1¢.
# Override via env at deploy time; changes only affect intents created
# AFTER the redeploy (existing pending intents keep their original amount).
CENTS_PER_CREDIT = int(os.getenv("CENTS_PER_CREDIT", "1"))

if CENTS_PER_CREDIT <= 0:
    raise RuntimeError(
        f"CENTS_PER_CREDIT must be > 0 (got {CENTS_PER_CREDIT})",
    )

# Providers that create_intent is allowed to record. Anything else is a
# routing-info lie or a log-injection attempt and is refused up front.
ALLOWED_PROVIDERS = frozenset({"manual", "stripe", "onchain"})

# Default lifetime of a pending intent. Long enough to comfortably span
# a cross-border bank transfer or a slow on-chain confirmation (30 days).
# The expiry guards against a stale-price attack (user creates intent,
# operator raises rates, user pays at old price a year later), so it
# needs to be shorter than any plausible operator rate-change cadence.
# Overridable via env for tests / dev.
INTENT_TTL_SECONDS = int(os.getenv("INTENT_TTL_SECONDS", str(30 * 24 * 3600)))

# On-chain intents get their own, much shorter TTL. Their dusted amount
# IS the matching key, and the sub-cent dust space is only ~10^4 slots
# per price point — a 30-day lifetime would let an attacker (or mere
# accretion) occupy slots long enough to exhaust the space and make
# honest payments ambiguous. 24h comfortably covers wallet payment +
# chain confirmation.
ONCHAIN_INTENT_TTL_SECONDS = int(os.getenv("ONCHAIN_INTENT_TTL_SECONDS", str(24 * 3600)))

# Cap on simultaneously matchable on-chain intents per identity. Slots
# are a shared, finite resource (see above); without a cap one identity
# can blanket a price point's whole dust space. Nobody legitimately
# needs many concurrent unpaid top-ups.
ONCHAIN_MAX_PENDING_PER_IDENTITY = int(os.getenv("ONCHAIN_MAX_PENDING_PER_IDENTITY", "8"))

# Cap on live pending intents per identity across ALL providers. The
# on-chain cap alone left a farm door open: Stripe intents had no cap
# and a 30-day TTL, so one api_key could stockpile ~10^4 of them at a
# price point and later switch a dust-matching one onto the on-chain
# rail. The switch now resets the time anchor (onchain_since), which
# kills that attack outright — this cap just makes stockpiles expensive
# everywhere. Generous: no honest client needs dozens of open invoices.
INTENT_MAX_PENDING_PER_IDENTITY = int(os.getenv("INTENT_MAX_PENDING_PER_IDENTITY", "16"))

# How long past expires_at an on-chain intent stays in the watcher's
# matching table (and keeps occupying its dust slot). The webhook
# honours late payments via allow_expired, so vanishing at the TTL edge
# would strand a payment that was in flight; staying matchable forever
# would leak slots — and every extra hour of grace is extra time an
# attacker can grind fresh intents against a parked note's amount. 48h
# comfortably covers a slow confirmation without handing out a week.
ONCHAIN_MATCH_GRACE_SECONDS = int(os.getenv("ONCHAIN_MATCH_GRACE_SECONDS", str(48 * 3600)))

for _name, _val in (("ONCHAIN_INTENT_TTL_SECONDS", ONCHAIN_INTENT_TTL_SECONDS),
                    ("ONCHAIN_MAX_PENDING_PER_IDENTITY", ONCHAIN_MAX_PENDING_PER_IDENTITY),
                    ("INTENT_MAX_PENDING_PER_IDENTITY", INTENT_MAX_PENDING_PER_IDENTITY),
                    ("ONCHAIN_MATCH_GRACE_SECONDS", ONCHAIN_MATCH_GRACE_SECONDS)):
    if _val <= 0:
        raise RuntimeError(f"{_name} must be > 0 (got {_val})")

# Attempts at drawing a memo whose dust doesn't collide with a live
# same-price intent before giving up. With 10^4 slots, 64 draws fail
# only when the price point is already ~90%+ occupied — at which point
# failing closed IS the defence (see create_intent).
ONCHAIN_MEMO_DRAW_ATTEMPTS = 64

# SQL fragment selecting on-chain intents that are still MATCHABLE by
# the note-watcher: pending, or lazily flipped to 'expired' but still
# inside the grace window (the webhook credits those via allow_expired).
# Takes one bound parameter: the negative grace modifier string.
_ONCHAIN_MATCHABLE_SQL = (
    "provider = 'onchain' AND status IN ('pending', 'expired') "
    "AND expires_at > datetime(CURRENT_TIMESTAMP, ?)"
)


def _grace_modifier() -> str:
    return f"-{ONCHAIN_MATCH_GRACE_SECONDS} seconds"


# How long an idempotency replay stays free. Covers genuine network-drop
# retries (seconds to a couple of minutes), but a byte-identical request
# re-sent after the window is a NEW debit — otherwise resending the same
# prompt forever costs one credit total while every replay still buys a
# fresh (non-deterministic) completion.
CONSUME_DEDUP_TTL_SECONDS = int(os.getenv("CONSUME_DEDUP_TTL_SECONDS", "600"))

if CONSUME_DEDUP_TTL_SECONDS <= 0:
    raise RuntimeError(
        f"CONSUME_DEDUP_TTL_SECONDS must be > 0 (got {CONSUME_DEDUP_TTL_SECONDS})",
    )


# Only credential types in this set can be used to authenticate a spend
# (validate / consume). Public-identifier types like miden_wallet or
# miden_wallet may exist on an identity for routing topups but must
# NEVER let an unauthenticated attacker drain the balance by presenting a
# publicly-known value.
AUTHENTICATOR_CREDENTIAL_TYPES = frozenset({"api_key"})

API_KEY_PREFIX = "lev_"
API_KEY_ENTROPY_BYTES = 32

# How long a rotated-away api_key keeps working
ROTATE_GRACE_SECONDS = int(os.getenv("ROTATE_GRACE_SECONDS", "900"))

if ROTATE_GRACE_SECONDS < 0:
    raise RuntimeError(
        f"ROTATE_GRACE_SECONDS must be >= 0 (got {ROTATE_GRACE_SECONDS})",
    )


def new_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_ENTROPY_BYTES)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def signup(
    conn: aiosqlite.Connection,
    ip_fingerprint: Optional[str] = None,
) -> dict:
    raw_key = new_api_key()
    key_hash = hash_api_key(raw_key)
    identity_id = await create_identity(
        conn, "api_key", key_hash, initial_tier="free",
    )
    async with transaction(conn):
        await conn.execute(
            "INSERT INTO usage_log (identity_id, operation, delta, balance_after, note) "
            "VALUES (?, 'signup', 0, 0, ?)",
            (identity_id, f"ip={ip_fingerprint}" if ip_fingerprint else None),
        )
    return {
        "identity_id": identity_id,
        "api_key": raw_key,
        "api_key_hash": key_hash,
    }


async def rotate_api_key(
    conn: aiosqlite.Connection,
    current_raw_key: str,
    ip_fingerprint: Optional[str] = None,
    revoke_now: bool = False,
) -> dict:
    current_hash = hash_api_key(current_raw_key)
    new_raw_key = new_api_key()
    new_hash = hash_api_key(new_raw_key)

    async with transaction(conn):
        cur = await conn.execute(
            "SELECT id, identity_id FROM credentials "
            "WHERE credential_type = 'api_key' AND credential_value = ? "
            "  AND revoked_at IS NULL "
            "  AND (grace_until IS NULL OR grace_until > CURRENT_TIMESTAMP)",
            (current_hash,),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "invalid credential"}
        current_id, identity_id = row

        cur = await conn.execute(
            "INSERT INTO credentials (identity_id, credential_type, credential_value) "
            "VALUES (?, 'api_key', ?) RETURNING id",
            (identity_id, new_hash),
        )
        new_id = (await cur.fetchone())[0]

        if revoke_now:
            await conn.execute(
                "UPDATE credentials SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?",
                (current_id,),
            )
            old_key_valid_until = None
        else:
            grace = max(0, ROTATE_GRACE_SECONDS)
            await conn.execute(
                "UPDATE credentials "
                "SET grace_until = datetime('now', ?) WHERE id = ?",
                (f"{grace:+d} seconds", current_id),
            )
            cur = await conn.execute(
                "SELECT grace_until FROM credentials WHERE id = ?", (current_id,),
            )
            old_key_valid_until = (await cur.fetchone())[0]

        # Sweep everything else still authenticating on this identity.
        await conn.execute(
            "UPDATE credentials SET revoked_at = CURRENT_TIMESTAMP "
            "WHERE identity_id = ? AND credential_type = 'api_key' "
            "  AND revoked_at IS NULL AND id NOT IN (?, ?)",
            (identity_id, current_id, new_id),
        )

        cur = await conn.execute(
            "SELECT balance FROM balances WHERE identity_id = ?", (identity_id,),
        )
        bal_row = await cur.fetchone()
        balance = bal_row[0] if bal_row else 0
        await conn.execute(
            "INSERT INTO usage_log (identity_id, operation, delta, balance_after, note) "
            "VALUES (?, 'key_rotate', 0, ?, ?)",
            (identity_id, balance,
             ";".join(filter(None, [
                 f"ip={ip_fingerprint}" if ip_fingerprint else None,
                 "revoke_now" if revoke_now else f"grace={ROTATE_GRACE_SECONDS}s",
             ])) or None),
        )

    return {
        "success": True,
        "identity_id": identity_id,
        "api_key": new_raw_key,
        "api_key_hash": new_hash,
        "balance": balance,
        "old_key_valid_until": old_key_valid_until,
    }


async def create_identity(
    conn: aiosqlite.Connection,
    credential_type: str,
    credential_value: str,
    initial_tier: str = "free",
) -> int:
    """Create a fresh identity + first credential + zero balance.

    Returns the new identity_id. Idempotent on (credential_type,
    credential_value): if the credential already exists, returns the
    existing identity instead of creating a duplicate.
    """
    async with transaction(conn):
        cur = await conn.execute(
            "SELECT identity_id FROM credentials WHERE credential_type=? AND credential_value=?",
            (credential_type, credential_value),
        )
        row = await cur.fetchone()
        if row:
            return row[0]

        cur = await conn.execute("INSERT INTO identities DEFAULT VALUES")
        identity_id = cur.lastrowid
        assert identity_id is not None

        await conn.execute(
            "INSERT INTO credentials (identity_id, credential_type, credential_value) "
            "VALUES (?, ?, ?)",
            (identity_id, credential_type, credential_value),
        )
        tier = get_tier(initial_tier).name
        await conn.execute(
            "INSERT INTO balances (identity_id, balance, tier) VALUES (?, 0, ?)",
            (identity_id, tier),
        )
        return identity_id


async def add_credential(
    conn: aiosqlite.Connection,
    identity_id: int,
    credential_type: str,
    credential_value: str,
) -> dict:
    """Attach a new credential (e.g. a rotated api_key hash) to an existing
    identity. Fails if the identity doesn't exist or the credential is a
    duplicate.
    """
    async with transaction(conn):
        cur = await conn.execute(
            "SELECT id FROM identities WHERE id=?", (identity_id,),
        )
        if not await cur.fetchone():
            return {"success": False, "error": "identity not found"}

        cur = await conn.execute(
            "SELECT id FROM credentials "
            "WHERE credential_type=? AND credential_value=? AND revoked_at IS NULL",
            (credential_type, credential_value),
        )
        if await cur.fetchone():
            return {"success": False, "error": "credential already exists"}

        cur = await conn.execute(
            "INSERT INTO credentials (identity_id, credential_type, credential_value) "
            "VALUES (?, ?, ?) RETURNING id",
            (identity_id, credential_type, credential_value),
        )
        row = await cur.fetchone()
        return {"success": True, "credential_id": row[0], "identity_id": identity_id}


async def wallet_bind(
    conn: aiosqlite.Connection,
    wallet_pub_key: str,
    api_key_hash: str,
    account_id: Optional[str] = None,
    initial_tier: str = "free",
) -> dict:
    """Resolve a Miden wallet to its ledger identity, creating it on first use.

    Called by the AI Edge (proxy token) after it has cryptographically verified
    that the holder of `wallet_pub_key` signed a bind statement — see
    docs/wallet-bound-aci.md. This service does not and cannot verify Falcon
    signatures; it trusts the Edge to have done so, exactly as it trusts the
    Edge's `consume` calls today.

    Three effects, all idempotent, all in one transaction:
      1. get-or-create the identity holding ('miden_wallet', wallet_pub_key),
      2. attach ('miden_account', account_id) as a public label — never an
         authenticator (it is a public address, and a public value that can
         spend is a public balance),
      3. attach ('api_key', api_key_hash) to THAT identity. This is how the
         wallet spends through the ordinary consume/settle/refund path with no
         changes to it; the Edge derives the raw key from the wallet public key
         and never stores it.

    The api-key attachment refuses to move an existing hash between identities:
    without that check a bind could graft a wallet onto someone else's balance.
    """
    async with transaction(conn):
        cur = await conn.execute(
            "SELECT identity_id FROM credentials "
            "WHERE credential_type='miden_wallet' AND credential_value=? AND revoked_at IS NULL",
            (wallet_pub_key,),
        )
        row = await cur.fetchone()
        created = row is None
        if row:
            identity_id = row[0]
        else:
            cur = await conn.execute("INSERT INTO identities DEFAULT VALUES")
            identity_id = cur.lastrowid
            assert identity_id is not None
            await conn.execute(
                "INSERT INTO credentials (identity_id, credential_type, credential_value) "
                "VALUES (?, 'miden_wallet', ?)",
                (identity_id, wallet_pub_key),
            )
            await conn.execute(
                "INSERT INTO balances (identity_id, balance, tier) VALUES (?, 0, ?)",
                (identity_id, get_tier(initial_tier).name),
            )

        account_id_attached = False
        account_id_conflict = False
        if account_id:
            cur = await conn.execute(
                "SELECT identity_id FROM credentials "
                "WHERE credential_type='miden_account' AND credential_value=? "
                "  AND revoked_at IS NULL",
                (account_id,),
            )
            owner = await cur.fetchone()
            if owner and owner[0] != identity_id:
                account_id_conflict = True
            else:
                if not owner:
                    await conn.execute(
                        "INSERT INTO credentials (identity_id, credential_type, credential_value) "
                        "VALUES (?, 'miden_account', ?)",
                        (identity_id, account_id),
                    )
                account_id_attached = True

        cur = await conn.execute(
            "SELECT identity_id FROM credentials "
            "WHERE credential_type='api_key' AND credential_value=? AND revoked_at IS NULL",
            (api_key_hash,),
        )
        owner = await cur.fetchone()
        if owner and owner[0] != identity_id:
            return {"success": False, "error": "api_key_hash belongs to another identity"}
        if not owner:
            await conn.execute(
                "INSERT INTO credentials (identity_id, credential_type, credential_value) "
                "VALUES (?, 'api_key', ?)",
                (identity_id, api_key_hash),
            )

        cur = await conn.execute(
            "SELECT balance, tier FROM balances WHERE identity_id=?", (identity_id,),
        )
        bal = await cur.fetchone()

    result = {
        "success": True,
        "identity_id": identity_id,
        "created": created,
        "balance": bal[0] if bal else 0,
        "unit": "credit",
        "tier": bal[1] if bal else get_tier(initial_tier).name,
        "account_id_attached": account_id_attached,
    }
    if account_id_conflict:
        result["warning"] = (
            "account_id is already claimed by another identity; "
            "the label was not attached and topups will not route by it"
        )
    return result


async def revoke_credential(
    conn: aiosqlite.Connection,
    credential_type: str,
    credential_value: str,
) -> dict:
    """Mark a credential revoked so it no longer matches in lookups.
    Balance and other credentials on the same identity are untouched.
    """
    async with transaction(conn):
        cur = await conn.execute(
            "UPDATE credentials "
            "SET revoked_at = CURRENT_TIMESTAMP "
            "WHERE credential_type = ? AND credential_value = ? AND revoked_at IS NULL "
            "RETURNING id, identity_id",
            (credential_type, credential_value),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "credential not found or already revoked"}
        return {"success": True, "credential_id": row[0], "identity_id": row[1]}


async def lookup_identity(
    conn: aiosqlite.Connection,
    credential_type: str,
    credential_value: str,
) -> Optional[int]:
    """Return identity_id for a (type, value) credential, or None if not found,
    revoked, or superseded by a rotation whose grace window has run out.

    The grace clause is evaluated on read rather than swept by a job, so an
    expired key stops working the moment it expires with no write on this path.
    """
    cur = await conn.execute(
        "SELECT identity_id FROM credentials "
        "WHERE credential_type=? AND credential_value=? AND revoked_at IS NULL "
        "  AND (grace_until IS NULL OR grace_until > CURRENT_TIMESTAMP)",
        (credential_type, credential_value),
    )
    row = await cur.fetchone()
    return row[0] if row else None


async def get_balance(
    conn: aiosqlite.Connection,
    identity_id: int,
) -> Optional[dict]:
    """Return {balance, tier} for an identity, or None if no balance row."""
    cur = await conn.execute(
        "SELECT balance, tier FROM balances WHERE identity_id=?",
        (identity_id,),
    )
    row = await cur.fetchone()
    if not row:
        return None
    return {"balance": row[0], "tier": row[1]}


async def validate(
    conn: aiosqlite.Connection,
    credential_type: str,
    credential_value: str,
) -> dict:
    """Read-only check: does this credential have balance > 0?

    Returns:
        {valid: True, identity_id, balance, tier}  on success
        {valid: False, error: <reason>}             on failure

    Does NOT decrement — callers should follow up with `consume()` for the
    actual debit. The TEE proxy caches positive validate() results briefly
    to skip a DB round-trip on the hot path.
    """
    if credential_type not in AUTHENTICATOR_CREDENTIAL_TYPES:
        return {"valid": False, "error": "credential not found"}
    identity_id = await lookup_identity(conn, credential_type, credential_value)
    if identity_id is None:
        return {"valid": False, "error": "credential not found"}
    bal = await get_balance(conn, identity_id)
    if bal is None or bal["balance"] <= 0:
        # identity_id is included so a front can still resolve WHO this key
        # is (e.g. to serve receipts for already-paid requests) even though
        # new inference is denied.
        return {"valid": False, "error": "insufficient balance", "identity_id": identity_id}
    return {
        "valid": True,
        "identity_id": identity_id,
        "balance": bal["balance"],
        "tier": bal["tier"],
    }


async def consume(
    conn: aiosqlite.Connection,
    credential_type: str,
    credential_value: str,
    request_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> dict:
    """Atomically decrement balance by 1.

    Returns:
        {success: True, identity_id, balance}  on success (balance is the
                                                value AFTER the decrement)
        {success: True, ..., deduplicated: True} on idempotent replay
        {success: False, error: <reason>}      otherwise

    Atomicity: the UPDATE with `balance > 0` filter ensures that two
    concurrent consume calls on the same identity with balance=1 cannot
    both succeed — exactly one wins, the other sees zero rows updated.

    Idempotency: when the caller passes `idempotency_key` (typically a
    deterministic hash of the prove request the client is retrying),
    the same key on the same identity returns the previously-computed
    balance without debiting again. Guards against network-drop
    retries producing double-debit that no server-side lock can catch.
    The replay is honoured only within CONSUME_DEDUP_TTL_SECONDS of the
    original debit — after that the same key debits again (an identical
    request replayed much later is new work, not a retry).
    """
    if credential_type not in AUTHENTICATOR_CREDENTIAL_TYPES:
        return {"success": False, "error": "credential not found"}
    async with transaction(conn):
        identity_id = await lookup_identity(conn, credential_type, credential_value)
        if identity_id is None:
            return {"success": False, "error": "credential not found"}

        # Existing dedup row for this (identity, key) can be in one of three
        # states:
        #   active + fresh   → this is a retry → return cached balance, no debit
        #   active + stale   → past the replay TTL: same bytes, but new work
        #                      → fresh debit that reuses the row (UPDATE)
        #   refunded         → previous cycle was refunded → fresh debit that
        #                      reuses the row (UPDATE) instead of INSERTing a
        #                      duplicate that UNIQUE would reject
        existing_dedup: Optional[tuple[int, int, Optional[str]]] = None
        if idempotency_key:
            cur = await conn.execute(
                "SELECT id, balance_after, refunded_at, "
                "       created_at > datetime('now', ?) "
                "FROM consume_dedup "
                "WHERE identity_id = ? AND idempotency_key = ?",
                (f"-{CONSUME_DEDUP_TTL_SECONDS} seconds", identity_id, idempotency_key),
            )
            row = await cur.fetchone()
            if row:
                existing_dedup = (row[0], row[1], row[2])
                if row[2] is None and row[3]:
                    return {
                        "success": True,
                        "identity_id": identity_id,
                        "balance": row[1],
                        "deduplicated": True,
                    }

        cur = await conn.execute(
            "UPDATE balances "
            "SET balance = balance - 1, updated_at = CURRENT_TIMESTAMP "
            "WHERE identity_id = ? AND balance > 0 "
            "RETURNING balance",
            (identity_id,),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "insufficient balance"}
        new_balance = row[0]

        # One-shot capability for reversing THIS debit. Only the caller that
        # actually spent the credit receives it, so a later replay (which
        # debits nothing) cannot reverse this debit and mint a credit.
        debit_token = secrets.token_hex(REFUND_TOKEN_ENTROPY_BYTES)

        if idempotency_key:
            if existing_dedup is not None:
                # Refunded or TTL-stale row from a prior cycle — reactivate
                # it in-place. created_at is refreshed so the audit trail
                # (and the next replay window) starts at THIS debit, and the
                # token is rotated so the previous cycle's token is dead.
                await conn.execute(
                    "UPDATE consume_dedup "
                    "SET balance_after = ?, refunded_at = NULL, "
                    "    created_at = CURRENT_TIMESTAMP, debit_token = ? "
                    "WHERE id = ?",
                    (new_balance, debit_token, existing_dedup[0]),
                )
            else:
                # Fresh key — UNIQUE(identity_id, idempotency_key) guarantees
                # at most one winner across concurrent debits with the same
                # key. A racing INSERT gets an IntegrityError we deliberately
                # don't catch — the outer transaction rolls back and the
                # caller retries, then the second attempt finds the row in
                # the SELECT above.
                await conn.execute(
                    "INSERT INTO consume_dedup "
                    "  (identity_id, idempotency_key, balance_after, debit_token) "
                    "VALUES (?, ?, ?, ?)",
                    (identity_id, idempotency_key, new_balance, debit_token),
                )

        await conn.execute(
            "INSERT INTO usage_log "
            "  (identity_id, operation, request_id, delta, balance_after, note) "
            "VALUES (?, 'prove', ?, -1, ?, ?)",
            (identity_id, request_id, new_balance,
             f"idem={idempotency_key}" if idempotency_key else None),
        )
        result = {"success": True, "identity_id": identity_id, "balance": new_balance}
        if idempotency_key:
            # Only a real debit hands back the reversal capability.
            result["debit_token"] = debit_token
        return result


async def topup(
    conn: aiosqlite.Connection,
    identity_id: int,
    amount: int,
    source: str,
) -> dict:
    """Credit an identity's balance, idempotent on `source`.

    `source` is a caller-supplied tag (e.g. "stripe:SESSION_ID",
    "miden_p2id_<note_id>", "lightning_invoice_Y") and is stored with a
    UNIQUE constraint in the `topups` table. A second call with the same
    tag returns the existing balance without applying the credit again —
    essential so payment-webhook retries don't double-credit the user.
    """
    if amount <= 0:
        return {"success": False, "error": "amount must be positive"}

    async with transaction(conn):
        # Cheap existence check before the topups INSERT so an unknown
        # identity_id surfaces a clean "identity not found" instead of a
        # raw FOREIGN KEY IntegrityError from the topups table.
        cur = await conn.execute(
            "SELECT 1 FROM identities WHERE id = ?", (identity_id,),
        )
        if not await cur.fetchone():
            return {"success": False, "error": "identity not found"}

        # INSERT OR IGNORE fails silently on a duplicate source. rowcount
        # of 0 means we already saw this tag — return balance untouched.
        cur = await conn.execute(
            "INSERT OR IGNORE INTO topups (identity_id, amount, source) "
            "VALUES (?, ?, ?)",
            (identity_id, amount, source),
        )
        if cur.rowcount == 0:
            bal = await get_balance(conn, identity_id)
            if bal is None:
                # topups row exists but balances doesn't → orphan; caller
                # asked to top up an identity that was deleted. Uncommon;
                # surface as not-found rather than silently succeed.
                return {"success": False, "error": "identity not found"}
            return {
                "success": True,
                "identity_id": identity_id,
                "balance": bal["balance"],
                "deduplicated": True,
            }

        cur = await conn.execute(
            "UPDATE balances SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE identity_id = ? RETURNING balance",
            (amount, identity_id),
        )
        row = await cur.fetchone()
        if not row:
            # No balances row → identity doesn't exist. The INSERT into
            # topups above will have violated the FK unless FKs are off;
            # even if it slipped through, refuse to record a fake credit.
            return {"success": False, "error": "identity not found"}
        new_balance = row[0]

        await conn.execute(
            "INSERT INTO usage_log "
            "  (identity_id, operation, delta, balance_after, note) "
            "VALUES (?, 'topup', ?, ?, ?)",
            (identity_id, amount, new_balance, f"source={source}"),
        )
        return {"success": True, "identity_id": identity_id, "balance": new_balance}


async def set_tier(
    conn: aiosqlite.Connection,
    identity_id: int,
    tier_name: str,
) -> dict:
    """Change an identity's tier (e.g. when their subscription
    upgrades). Does not change current balance.

    Wrapped in a transaction so this write serialises with every other
    balance mutation on the shared connection — without the lock, an
    UPDATE issued while another coroutine is mid-BEGIN could land in the
    wrong transaction scope and silently roll back on the outer failure.
    """
    tier = get_tier(tier_name)
    async with transaction(conn):
        cur = await conn.execute(
            "UPDATE balances SET tier = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE identity_id = ? RETURNING tier",
            (tier.name, identity_id),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "identity not found"}
        return {"success": True, "identity_id": identity_id, "tier": row[0]}


async def refund(
    conn: aiosqlite.Connection,
    credential_type: str,
    credential_value: str,
    debit_token: str,
    reason: str = "",
) -> dict:
    """Reverse the specific consume that minted `debit_token`.

    The proxy calls this when it debited a credit but then failed to
    return the result to the client (upstream error, container SIGKILL
    mid-response, TLS write failure). Without a refund path the user
    silently loses the credit.

    Authorised by the one-shot `debit_token` that `consume` returns ONLY
    when it actually debited — never on an idempotent replay. Keying the
    reversal on the idempotency_key instead would let a caller whose
    consume was deduplicated (and therefore paid nothing) reverse the
    debit an earlier request made, minting a credit out of nothing and
    turning one paid request into unlimited free work.

    Idempotent: refunding an already-refunded debit is a no-op.
    """
    if credential_type not in AUTHENTICATOR_CREDENTIAL_TYPES:
        return {"success": False, "error": "credential not found"}
    if not debit_token:
        return {"success": False, "error": "debit_token required"}

    async with transaction(conn):
        identity_id = await lookup_identity(conn, credential_type, credential_value)
        if identity_id is None:
            return {"success": False, "error": "credential not found"}

        # The token identifies one debit of one identity. A token from a
        # previous consume→refund cycle no longer matches (consume rotates
        # it), so a stale token cannot reverse the current debit either.
        cur = await conn.execute(
            "SELECT id, refunded_at, idempotency_key FROM consume_dedup "
            "WHERE identity_id = ? AND debit_token = ?",
            (identity_id, debit_token),
        )
        dedup = await cur.fetchone()
        if not dedup:
            return {"success": False, "error": "no matching debit to refund"}
        dedup_id, already_refunded_at, idempotency_key = dedup

        if already_refunded_at is not None:
            # Idempotent replay: this specific debit's refund already ran.
            # A separate consume after the refund would have rotated the
            # token, so seeing this token still attached means no fresh
            # debit intervened.
            bal = await get_balance(conn, identity_id)
            return {
                "success": True,
                "identity_id": identity_id,
                "balance": bal["balance"] if bal else 0,
                "deduplicated": True,
            }

        # First refund of this dedup row. Mark it, credit the balance.
        # The refunded_at flag both:
        #   (a) survives to answer a refund-retry with `deduplicated: true`
        #   (b) lets a legitimate consume-retry reactivate the row via
        #       UPDATE instead of hitting UNIQUE on a fresh INSERT
        await conn.execute(
            "UPDATE consume_dedup SET refunded_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (dedup_id,),
        )

        cur = await conn.execute(
            "UPDATE balances SET balance = balance + 1, updated_at = CURRENT_TIMESTAMP "
            "WHERE identity_id = ? RETURNING balance",
            (identity_id,),
        )
        row = await cur.fetchone()
        new_balance = row[0] if row else 0

        await conn.execute(
            "INSERT INTO usage_log "
            "  (identity_id, operation, delta, balance_after, note) "
            "VALUES (?, 'refund', +1, ?, ?)",
            (identity_id, new_balance, f"idem={idempotency_key} reason={reason}"),
        )
        return {
            "success": True,
            "identity_id": identity_id,
            "balance": new_balance,
        }


# ─── Payment intents (provider-agnostic) ───────────────────────────────


def _new_memo() -> str:
    """Random public-safe reference the user includes in their payment.
    Not a secret — an attacker who guesses one can query the intent's
    status but cannot mark it paid without ADMIN_TOKEN or a valid
    provider-webhook signature.
    """
    return "intent-" + secrets.token_hex(INTENT_MEMO_ENTROPY_BYTES)


async def create_intent(
    conn: aiosqlite.Connection,
    identity_id: int,
    credits: int,
    provider: str = "manual",
) -> dict:
    """Create a pending payment intent. Server derives amount_cents
    from `credits × CENTS_PER_CREDIT` — the client never picks the
    price. Otherwise a user could ask for 1M credits at 1¢.

    Returns a random opaque `memo` the user must include as a
    reference/tag when they pay. Deduplication at mark_paid time
    piggybacks on `topups.source` UNIQUE (memo == source).

    On-chain intents get extra slot discipline, because their dusted
    amount is the payment's matching key and the sub-cent dust space is
    finite (~10^4 per price point): the memo is re-drawn until its dust
    collides with NO still-matchable same-price on-chain intent (so
    every live quote is unique by construction, not just by 1/10^4
    luck), each identity holds at most ONCHAIN_MAX_PENDING_PER_IDENTITY
    matchable intents (a shared-resource cap — one account must not
    blanket a price point), and the TTL is the short on-chain one. When
    the space at a price point is genuinely saturated we fail CLOSED
    with an error instead of minting an ambiguous quote.
    """
    if credits <= 0:
        return {"success": False, "error": "credits must be positive"}
    if provider not in ALLOWED_PROVIDERS:
        return {"success": False, "error": f"unknown provider {provider!r}"}

    amount_cents = credits * CENTS_PER_CREDIT

    async with transaction(conn):
        cur = await conn.execute(
            "SELECT 1 FROM identities WHERE id = ?", (identity_id,),
        )
        if not await cur.fetchone():
            return {"success": False, "error": "identity not found"}

        # Global stockpile cap — every provider. See the constant's note.
        cur = await conn.execute(
            "SELECT COUNT(*) FROM payment_intents "
            "WHERE identity_id = ? AND status = 'pending' "
            "  AND expires_at > CURRENT_TIMESTAMP",
            (identity_id,),
        )
        if (await cur.fetchone())[0] >= INTENT_MAX_PENDING_PER_IDENTITY:
            return {
                "success": False,
                "error": ("too many unpaid intents "
                          f"(max {INTENT_MAX_PENDING_PER_IDENTITY}); "
                          "pay or let some expire first"),
            }

        if provider == "onchain":
            grace = _grace_modifier()
            # The cap counts only LIVE pending intents (expired ones in
            # the grace window still hold their dust slot but must not
            # lock a real user out of the rail for grace+TTL — with the
            # 24h TTL an abandoned batch frees the cap within a day).
            cur = await conn.execute(
                "SELECT COUNT(*) FROM payment_intents "
                "WHERE identity_id = ? AND provider = 'onchain' "
                "  AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP",
                (identity_id,),
            )
            if (await cur.fetchone())[0] >= ONCHAIN_MAX_PENDING_PER_IDENTITY:
                return {
                    "success": False,
                    "error": ("too many unpaid on-chain intents "
                              f"(max {ONCHAIN_MAX_PENDING_PER_IDENTITY}); "
                              "pay or let one expire first"),
                }
            cur = await conn.execute(
                "SELECT memo FROM payment_intents "
                f"WHERE amount_cents = ? AND {_ONCHAIN_MATCHABLE_SQL}",
                (amount_cents, grace),
            )
            taken = {onchain_client.memo_dust(row[0])
                     for row in await cur.fetchall()}
            memo = None
            for _ in range(ONCHAIN_MEMO_DRAW_ATTEMPTS):
                candidate = _new_memo()
                if onchain_client.memo_dust(candidate) not in taken:
                    memo = candidate
                    break
            if memo is None:
                return {
                    "success": False,
                    "error": ("no unique payment amount available at this "
                              "price right now; retry shortly"),
                }
            ttl_seconds = ONCHAIN_INTENT_TTL_SECONDS
        else:
            memo = _new_memo()
            ttl_seconds = INTENT_TTL_SECONDS

        # Pre-format the datetime modifier as a plain string so SQLite
        # sees a literal like '+86400 seconds' — the concatenation form
        # `'+' || ? || ' seconds'` is fragile across driver versions.
        expires_modifier = f"+{ttl_seconds} seconds"
        cur = await conn.execute(
            "INSERT INTO payment_intents "
            "  (identity_id, credits, amount_cents, memo, provider, status, expires_at, "
            "   onchain_since) "
            "VALUES (?, ?, ?, ?, ?, 'pending', "
            "        datetime(CURRENT_TIMESTAMP, ?), "
            # The watcher's time-order anchor: when the intent ENTERED the
            # on-chain rail. NULL for other rails; a later rail switch
            # sets it to the switch time, never inheriting created_at.
            "        CASE WHEN ? = 'onchain' THEN CURRENT_TIMESTAMP END) "
            "RETURNING id, expires_at",
            (identity_id, credits, amount_cents, memo, provider, expires_modifier,
             provider),
        )
        row = await cur.fetchone()
        return {
            "success": True,
            "intent_id": row[0],
            "identity_id": identity_id,
            "credits": credits,
            "amount_cents": amount_cents,
            "memo": memo,
            "provider": provider,
            "status": "pending",
            "expires_at": row[1],
        }


async def get_intent_by_memo(
    conn: aiosqlite.Connection, memo: str,
) -> Optional[dict]:
    """Look up an intent by its opaque memo. Returns None if not found."""
    cur = await conn.execute(
        "SELECT id, identity_id, credits, amount_cents, memo, provider, "
        "       provider_ref, status, created_at, paid_at, expires_at "
        "FROM payment_intents WHERE memo = ?",
        (memo,),
    )
    row = await cur.fetchone()
    if not row:
        return None
    return {
        "intent_id": row[0],
        "identity_id": row[1],
        "credits": row[2],
        "amount_cents": row[3],
        "memo": row[4],
        "provider": row[5],
        "provider_ref": row[6],
        "status": row[7],
        "created_at": row[8],
        "paid_at": row[9],
        "expires_at": row[10],
    }


async def mark_paid_by_memo(
    conn: aiosqlite.Connection,
    memo: str,
    provider_ref: Optional[str] = None,
    actual_amount_cents: Optional[int] = None,
    allow_expired: bool = False,
) -> dict:
    """Finalize a payment intent: verify → credit balance → mark paid.

    Atomic across the whole transition: an intent that lands here more
    than once (webhook retry, dupe admin call) short-circuits to the
    already-paid response without a second topup. The topups UNIQUE
    constraint on (source == memo) is the second line of defence.

    `actual_amount_cents` is optional: when a caller (a webhook that
    knows the exact paid amount) provides it, we reject under-payments.
    Manual admin calls can leave it None to trust the intent's amount.

    `allow_expired` — webhook adapters set this True. A slow bank
    transfer or on-chain confirmation can land after the intent's TTL
    has elapsed; if the provider says money arrived, honour the payment
    at the intent's ORIGINAL price rather than dropping it silently.
    Admin/manual finalisation leaves it False to keep the price-freshness
    guard intact for their path.
    """
    async with transaction(conn):
        cur = await conn.execute(
            "SELECT id, identity_id, credits, amount_cents, status, "
            "       expires_at, "
            "       (expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP) "
            "FROM payment_intents WHERE memo = ?",
            (memo,),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "intent not found"}
        intent_id, identity_id, credits, expected_cents, status, _exp, is_expired = row

        # Lazy expiry sweep: flip the row to 'expired' the first time
        # anyone tries to mark it paid after the deadline. Webhook path
        # skips the reject and honours the original price so a delayed
        # transfer isn't silently lost.
        if status == "pending" and is_expired and not allow_expired:
            await conn.execute(
                "UPDATE payment_intents SET status = 'expired' WHERE id = ?",
                (intent_id,),
            )
            return {"success": False, "error": "intent has expired"}

        if status == "paid":
            # Idempotent replay — already credited. Do not touch balance.
            return {
                "success": True,
                "intent_id": intent_id,
                "identity_id": identity_id,
                "status": "paid",
                "deduplicated": True,
            }
        if status != "pending" and not (status == "expired" and allow_expired):
            return {
                "success": False,
                "error": f"intent is {status}, cannot mark paid",
            }
        if actual_amount_cents is not None and actual_amount_cents < expected_cents:
            return {
                "success": False,
                "error": f"underpaid: expected {expected_cents} cents, got {actual_amount_cents}",
            }

        # Credit balance. topups UNIQUE(source=memo) makes this idempotent
        # even if the transaction retries at the SQL layer.
        cur = await conn.execute(
            "INSERT OR IGNORE INTO topups (identity_id, amount, source) "
            "VALUES (?, ?, ?)",
            (identity_id, credits, memo),
        )
        credited_now = cur.rowcount > 0
        if credited_now:
            await conn.execute(
                "UPDATE balances "
                "SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE identity_id = ?",
                (credits, identity_id),
            )
            await conn.execute(
                "INSERT INTO usage_log "
                "  (identity_id, operation, delta, balance_after, note) "
                "VALUES (?, 'topup', ?, "
                "        (SELECT balance FROM balances WHERE identity_id = ?), "
                "        ?)",
                (identity_id, credits, identity_id, f"intent={memo}"),
            )

        await conn.execute(
            "UPDATE payment_intents "
            "SET status = 'paid', paid_at = CURRENT_TIMESTAMP, provider_ref = ? "
            "WHERE id = ?",
            (provider_ref, intent_id),
        )

        # Fetch new balance for the response so the caller doesn't have
        # to round-trip a second query.
        cur = await conn.execute(
            "SELECT balance FROM balances WHERE identity_id = ?", (identity_id,),
        )
        bal_row = await cur.fetchone()
        return {
            "success": True,
            "intent_id": intent_id,
            "identity_id": identity_id,
            "credits": credits,
            "balance": bal_row[0] if bal_row else 0,
            "status": "paid",
        }


async def cancel_intent_by_memo(
    conn: aiosqlite.Connection, memo: str,
) -> dict:
    """Cancel a pending intent. Refuses if already paid."""
    async with transaction(conn):
        cur = await conn.execute(
            "UPDATE payment_intents "
            "SET status = 'cancelled' "
            "WHERE memo = ? AND status = 'pending' "
            "RETURNING id, identity_id",
            (memo,),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "intent not found or not pending"}
        return {"success": True, "intent_id": row[0], "identity_id": row[1], "status": "cancelled"}


async def set_intent_provider(
    conn: aiosqlite.Connection, memo: str, provider: str,
) -> dict:
    """Move a still-pending intent to another payment rail.

    Exists so the retry-friendly checkout endpoint can switch rails
    WITHOUT leaving the row's provider stale: an intent recorded as
    'stripe' but paid on-chain would be invisible to the note-watcher's
    matching table (filtered by provider), so the money would arrive
    with nobody to credit it — and no MONEY RECEIVED log, since the
    webhook refuses foreign-rail memos.

    Switching TO 'onchain' applies the same slot discipline as creating
    an on-chain intent — the memo is already fixed, so if its dust
    collides with a live same-price on-chain quote the switch is refused
    (create a fresh intent instead) — and shortens expires_at to the
    on-chain TTL so the slot is not held for a hosted-checkout-sized
    lifetime.
    """
    if provider not in ALLOWED_PROVIDERS:
        return {"success": False, "error": f"unknown provider {provider!r}"}
    async with transaction(conn):
        cur = await conn.execute(
            "SELECT id, identity_id, amount_cents, provider, status "
            "FROM payment_intents WHERE memo = ?",
            (memo,),
        )
        row = await cur.fetchone()
        if not row:
            return {"success": False, "error": "intent not found"}
        intent_id, identity_id, amount_cents, old_provider, status_ = row
        if status_ != "pending":
            return {"success": False,
                    "error": f"intent is {status_}, cannot switch provider"}
        if provider == old_provider:
            return {"success": True, "intent_id": intent_id,
                    "provider": provider, "changed": False}

        if provider == "onchain":
            grace = _grace_modifier()
            # Same cap rule as create_intent: live pending only.
            cur = await conn.execute(
                "SELECT COUNT(*) FROM payment_intents "
                "WHERE identity_id = ? AND provider = 'onchain' "
                "  AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP",
                (identity_id,),
            )
            if (await cur.fetchone())[0] >= ONCHAIN_MAX_PENDING_PER_IDENTITY:
                return {
                    "success": False,
                    "error": ("too many unpaid on-chain intents "
                              f"(max {ONCHAIN_MAX_PENDING_PER_IDENTITY}); "
                              "pay or let one expire first"),
                }
            cur = await conn.execute(
                "SELECT memo FROM payment_intents "
                f"WHERE amount_cents = ? AND memo != ? AND {_ONCHAIN_MATCHABLE_SQL}",
                (amount_cents, memo, grace),
            )
            taken = {onchain_client.memo_dust(row[0])
                     for row in await cur.fetchall()}
            if onchain_client.memo_dust(memo) in taken:
                return {
                    "success": False,
                    "error": ("this intent's payment amount collides with a "
                              "live on-chain quote — create a new intent "
                              "with provider 'onchain' instead"),
                }
            await conn.execute(
                # onchain_since = NOW, never the row's created_at: the
                # watcher refuses to match notes seen before this stamp,
                # so a stockpiled old intent switched onto the rail can
                # never claim a note that was already parked.
                "UPDATE payment_intents SET provider = 'onchain', "
                "expires_at = datetime(CURRENT_TIMESTAMP, ?), "
                "onchain_since = CURRENT_TIMESTAMP WHERE id = ?",
                (f"+{ONCHAIN_INTENT_TTL_SECONDS} seconds", intent_id),
            )
        else:
            # Leaving expires_at alone on the way OUT of onchain keeps
            # the price-staleness guard: switching rails must not extend
            # an intent's life.
            await conn.execute(
                "UPDATE payment_intents SET provider = ? WHERE id = ?",
                (provider, intent_id),
            )
        return {"success": True, "intent_id": intent_id,
                "provider": provider, "changed": True}


async def list_pending_onchain_intents(
    conn: aiosqlite.Connection,
) -> list:
    """Matchable 'onchain' intents plus each identity's bound Miden
    account addresses — the note-watcher's matching table.

    The plain-send payment path carries no memo on the note, so the
    matching KEY is the intent's exact dusted token amount (computed by
    the route via onchain_client.token_amount_for_intent — unique among
    live same-price quotes by construction at create_intent time, and
    enforced by the webhook). `sender_accounts` holds the identity's
    `miden_account` credential labels for tie-breaking ONLY: they are
    attached at wallet-bind as unverified, user-claimed values — anyone
    can bind a wallet while claiming someone else's address — so they
    must never decide which intent a payment credits.

    Matchable = pending OR lazily flipped to 'expired', within the
    grace window past expires_at: the webhook credits late payments via
    allow_expired, so rows must not vanish from the table at the TTL
    edge (an admin probe flipping a row to 'expired' must not strand an
    in-flight payment either) — but they also must not occupy their
    dust slot forever, so past the grace window a late payment becomes
    an ops case. expires_at is returned so the watcher can prioritise
    fresh intents.
    """
    cur = await conn.execute(
        "SELECT id, identity_id, memo, credits, amount_cents, created_at, expires_at, "
        # The watcher's time-order anchor: when the intent ENTERED the
        # on-chain rail. COALESCE covers rows predating the column —
        # those were created as onchain, so created_at IS their entry.
        "       COALESCE(onchain_since, created_at) AS matchable_since "
        "FROM payment_intents "
        f"WHERE {_ONCHAIN_MATCHABLE_SQL} "
        "ORDER BY id",
        (_grace_modifier(),),
    )
    rows = await cur.fetchall()
    intents = [
        {
            "intent_id": r[0],
            "identity_id": r[1],
            "memo": r[2],
            "credits": r[3],
            "amount_cents": r[4],
            "created_at": r[5],
            "expires_at": r[6],
            "matchable_since": r[7],
            "sender_accounts": [],
        }
        for r in rows
    ]
    if not intents:
        return []

    identity_ids = sorted({i["identity_id"] for i in intents})
    marks = ",".join("?" for _ in identity_ids)
    cur = await conn.execute(
        "SELECT identity_id, credential_value FROM credentials "
        "WHERE credential_type = 'miden_account' AND revoked_at IS NULL "
        f"AND identity_id IN ({marks})",
        identity_ids,
    )
    accounts: dict = {}
    for identity_id, value in await cur.fetchall():
        accounts.setdefault(identity_id, []).append(value)
    for intent in intents:
        intent["sender_accounts"] = accounts.get(intent["identity_id"], [])
    return intents
