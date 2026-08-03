"""Business logic — independent of HTTP framing.

Kept separate from `main.py` so tests can exercise the database semantics
without spinning up FastAPI. Each function returns a plain dict (or None)
that the HTTP layer wraps into a response.

Concurrency model: every write path that mutates a balance holds an
explicit transaction. SQLite serialises writes at the connection level,
so the atomic decrement here cannot race against a concurrent topup or
another consume on the same identity.
"""

import os
import secrets
from typing import Optional

import aiosqlite

from .db import transaction
from .tiers import get_tier


# Number of random bytes in an intent memo. 8 bytes = 16 hex chars = 64
# bits of entropy — enough that an attacker cannot guess a pending
# intent belonging to someone else. Not a secret, but not enumerable.
INTENT_MEMO_ENTROPY_BYTES = 8

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
ALLOWED_PROVIDERS = frozenset({"manual", "nowpayments", "onchain"})

# Default lifetime of a pending intent. Long enough to comfortably span
# a cross-border bank transfer or a slow on-chain confirmation (30 days).
# The expiry guards against a stale-price attack (user creates intent,
# operator raises rates, user pays at old price a year later), so it
# needs to be shorter than any plausible operator rate-change cadence.
# Overridable via env for tests / dev.
INTENT_TTL_SECONDS = int(os.getenv("INTENT_TTL_SECONDS", str(30 * 24 * 3600)))


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
    """Return identity_id for a (type, value) credential, or None if not found
    or revoked.
    """
    cur = await conn.execute(
        "SELECT identity_id FROM credentials "
        "WHERE credential_type=? AND credential_value=? AND revoked_at IS NULL",
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

        if idempotency_key:
            if existing_dedup is not None:
                # Refunded or TTL-stale row from a prior cycle — reactivate
                # it in-place. created_at is refreshed so the audit trail
                # (and the next replay window) starts at THIS debit.
                await conn.execute(
                    "UPDATE consume_dedup "
                    "SET balance_after = ?, refunded_at = NULL, "
                    "    created_at = CURRENT_TIMESTAMP "
                    "WHERE id = ?",
                    (new_balance, existing_dedup[0]),
                )
            else:
                # Fresh key — UNIQUE(identity_id, idempotency_key) guarantees
                # at most one winner across concurrent debits with the same
                # key. A racing INSERT gets an IntegrityError we deliberately
                # don't catch — the outer transaction rolls back and the
                # caller retries, then the second attempt finds the row in
                # the SELECT above.
                await conn.execute(
                    "INSERT INTO consume_dedup (identity_id, idempotency_key, balance_after) "
                    "VALUES (?, ?, ?)",
                    (identity_id, idempotency_key, new_balance),
                )

        await conn.execute(
            "INSERT INTO usage_log "
            "  (identity_id, operation, request_id, delta, balance_after, note) "
            "VALUES (?, 'prove', ?, -1, ?, ?)",
            (identity_id, request_id, new_balance,
             f"idem={idempotency_key}" if idempotency_key else None),
        )
        return {"success": True, "identity_id": identity_id, "balance": new_balance}


async def topup(
    conn: aiosqlite.Connection,
    identity_id: int,
    amount: int,
    source: str,
) -> dict:
    """Credit an identity's balance, idempotent on `source`.

    `source` is a caller-supplied tag (e.g. "nowpayments:PAYMENT_ID",
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
    idempotency_key: str,
    reason: str = "",
) -> dict:
    """Reverse a consume that has already been recorded for the given
    (identity, idempotency_key).

    The TEE proxy calls this when it debited a credit but then failed
    to return the proof to the client (upstream error, container SIGKILL
    mid-response, TLS write failure). Without a refund path the user
    silently loses the credit.

    Idempotent on the same key: a second refund for a debit that has
    already been refunded is a no-op.
    """
    if credential_type not in AUTHENTICATOR_CREDENTIAL_TYPES:
        return {"success": False, "error": "credential not found"}
    if not idempotency_key:
        return {"success": False, "error": "idempotency_key required"}

    async with transaction(conn):
        identity_id = await lookup_identity(conn, credential_type, credential_value)
        if identity_id is None:
            return {"success": False, "error": "credential not found"}

        # Find the dedup row this key refers to. Whether it's live
        # (refunded_at IS NULL) or already-refunded (refunded_at set)
        # affects the branch below, but a missing row is unambiguous:
        # nothing to reverse.
        cur = await conn.execute(
            "SELECT id, refunded_at FROM consume_dedup "
            "WHERE identity_id = ? AND idempotency_key = ?",
            (identity_id, idempotency_key),
        )
        dedup = await cur.fetchone()
        if not dedup:
            return {"success": False, "error": "no matching debit to refund"}
        dedup_id, already_refunded_at = dedup

        if already_refunded_at is not None:
            # Idempotent replay: this specific debit's refund already ran.
            # A separate consume(key) after the refund would have UPDATEd
            # refunded_at back to NULL (see consume path), so seeing a
            # non-NULL here means no fresh debit intervened.
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

        memo = _new_memo()
        # Pre-format the datetime modifier as a plain string so SQLite
        # sees a literal like '+86400 seconds' — the concatenation form
        # `'+' || ? || ' seconds'` is fragile across driver versions.
        expires_modifier = f"+{INTENT_TTL_SECONDS} seconds"
        cur = await conn.execute(
            "INSERT INTO payment_intents "
            "  (identity_id, credits, amount_cents, memo, provider, status, expires_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', "
            "        datetime(CURRENT_TIMESTAMP, ?)) "
            "RETURNING id, expires_at",
            (identity_id, credits, amount_cents, memo, provider, expires_modifier),
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
        if status != "pending":
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
