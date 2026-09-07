"""SQLite-backed storage for the auth service.

We use aiosqlite directly (no ORM) — the schema is small and the queries are
short, so an ORM would be more weight than it's worth. The same SQL is
mostly portable to Postgres later; the only places that need adapting are
the `INTEGER PRIMARY KEY AUTOINCREMENT` columns (Postgres uses `SERIAL`).

Connection model: a single shared `aiosqlite.Connection` for the process,
opened at startup. SQLite supports a single writer transaction at a time,
so the `transaction()` context manager guards itself with an asyncio.Lock
attached to the connection — concurrent callers serialise cleanly rather
than racing into "cannot start a transaction within a transaction".
"""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import aiosqlite

DEFAULT_DB_PATH = os.getenv("AUTH_DB_PATH", "/var/lib/miden-tee-auth/auth.db")

# SQLite retries SQLITE_BUSY errors internally for up to this many
# milliseconds before surfacing them. Long enough to absorb WAL
# checkpoint stalls and short enough that a genuinely wedged writer
# fails deterministically inside a request's normal timeout budget.
BUSY_TIMEOUT_MS = 5000

# The schema. Kept here as a single string so a fresh deploy is one statement.
# Postgres port notes:
#   - INTEGER PRIMARY KEY AUTOINCREMENT  → SERIAL PRIMARY KEY
#   - TIMESTAMP DEFAULT CURRENT_TIMESTAMP → TIMESTAMPTZ DEFAULT NOW()
SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id      INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_type  TEXT NOT NULL,       -- 'api_key' | 'miden_wallet' | ...
    credential_value TEXT NOT NULL,       -- hash for secrets (api_key), raw for public IDs (wallet)
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at       TIMESTAMP
);

-- Looking up a credential is the hottest path (every prove call). Index it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_lookup
    ON credentials(credential_type, credential_value);

CREATE INDEX IF NOT EXISTS idx_credentials_identity
    ON credentials(identity_id);

-- Partial unique constraint: two credentials with the same (type, value)
-- can coexist only if the older one is revoked. Lets an operator rotate
-- an api_key hash back to a previously-revoked value without hitting a
-- spurious UNIQUE conflict.
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_active
    ON credentials(credential_type, credential_value)
    WHERE revoked_at IS NULL;

-- Topups are recorded with a caller-supplied `source` tag (e.g. a Stripe
-- session id). Making it UNIQUE means a webhook retry with the same tag
-- is a no-op — no double-credit.
CREATE TABLE IF NOT EXISTS topups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id   INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    amount        INTEGER NOT NULL,
    source        TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_topups_identity
    ON topups(identity_id, created_at DESC);

-- Payment intents: provider-agnostic representation of "user wants to
-- buy N credits". The user pays via any channel (bank transfer, Stripe,
-- on-chain) and references the intent by its
-- `memo` string. When ops or a webhook confirms the payment landed,
-- the intent transitions pending → paid and the balance is credited.
-- The memo doubles as the topup `source` so idempotency is trivial.
CREATE TABLE IF NOT EXISTS payment_intents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id   INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credits       INTEGER NOT NULL,               -- how many prove credits to mint on completion
    amount_cents  INTEGER NOT NULL,               -- expected USD-cents equivalent (for verification)
    memo          TEXT NOT NULL UNIQUE,           -- opaque public reference; used as topup source
    provider      TEXT NOT NULL DEFAULT 'manual', -- 'manual' | 'stripe' | 'onchain'
    provider_ref  TEXT,                            -- external reference filled at mark-paid time
    status        TEXT NOT NULL DEFAULT 'pending',-- 'pending' | 'paid' | 'expired' | 'cancelled'
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    paid_at       TIMESTAMP,
    -- Absolute expiry set at creation time. mark_paid refuses intents
    -- past this deadline so a user can't sit on a pending intent for a
    -- year and pay at the stale price after the operator raised rates.
    expires_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_payment_intents_identity
    ON payment_intents(identity_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_intents_status
    ON payment_intents(status);

-- One on-chain note credits AT MOST one intent. The note-watcher path
-- records provider_ref = 'miden:<note_id>' at mark-paid time; without
-- this constraint a compromised or buggy watcher could replay a single
-- real note (or an invented one) against every pending intent and
-- credit them all. Partial: other rails' refs (e.g. 'stripe:...') are
-- deliberately unconstrained — Stripe dedup lives in the memo/session
-- binding, and admin refs may legitimately repeat.
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_intents_miden_note
    ON payment_intents(provider_ref) WHERE provider_ref LIKE 'miden:%';

CREATE TABLE IF NOT EXISTS balances (
    identity_id   INTEGER PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
    balance       INTEGER NOT NULL DEFAULT 0,         -- prove credits remaining
    tier          TEXT NOT NULL DEFAULT 'free',       -- 'free' | 'starter' | 'pro'
    period_start  DATE,                                -- for monthly-reset tiers
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS usage_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id   INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operation     TEXT NOT NULL,                       -- 'prove' | 'topup' | 'refund'
    request_id    TEXT,                                 -- correlate with TEE proxy logs
    delta         INTEGER NOT NULL,                    -- +1000 for topup, -1 for prove
    balance_after INTEGER NOT NULL,
    note          TEXT
);

CREATE INDEX IF NOT EXISTS idx_usage_log_identity
    ON usage_log(identity_id, timestamp DESC);

-- Consume-request deduplication. Client sends a stable idempotency key
-- (deterministic hash of the prove request) as gRPC metadata; TEE proxy
-- forwards it here. If we've already debited for the same
-- (identity, idempotency_key) pair, return the cached balance rather
-- than debiting again. Protects against network-retry double-debits
-- (dropped response, client retry, second consume) that no amount of
-- server-side transaction locking can prevent.
CREATE TABLE IF NOT EXISTS consume_dedup (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id     INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    balance_after   INTEGER NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    refunded_at     TIMESTAMP,   -- non-NULL means /v1/refund reversed this debit
    -- One-shot capability for reversing THIS debit. Minted fresh on every
    -- real debit, returned only to the caller that caused it, and cleared
    -- once spent. A replayed consume debits nothing and therefore gets no
    -- token, so it cannot reverse a debit some earlier request made.
    debit_token     TEXT,
    UNIQUE(identity_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_consume_dedup_identity
    ON consume_dedup(identity_id, created_at DESC);
"""


async def init_db(path: str = DEFAULT_DB_PATH) -> aiosqlite.Connection:
    """Open the DB and run schema migrations. Idempotent.

    `path = ":memory:"` is used by tests for isolation.

    Startup safety: if the DB file didn't exist before this call, we still
    want to catch the foot-gun where a typo in `AUTH_DB_PATH` (e.g.
    `/data/auth.dbb`) silently creates a fresh empty DB next to the real
    one — every existing identity would look like "not found" while
    `/health` stays green, a silent full outage.

    But requiring a manual `ALLOW_EMPTY_DB=true` on every first deploy is
    error-prone (it was the #1 first-boot support issue). So we auto-detect:
    a genuinely fresh deploy has an EMPTY (or not-yet-created) data
    directory → create the DB with no flag. We only refuse when the
    directory already holds OTHER files, which is exactly the typo case.
    `ALLOW_EMPTY_DB=true` still forces creation for any edge case.
    """
    file_existed = path == ":memory:" or os.path.exists(path)
    if not file_existed:
        parent = os.path.dirname(path) or "."
        # Fresh = dir doesn't exist yet, or exists but is empty.
        dir_is_fresh = (not os.path.isdir(parent)) or (len(os.listdir(parent)) == 0)
        forced = os.getenv("ALLOW_EMPTY_DB", "").lower() == "true"
        if not dir_is_fresh and not forced:
            raise RuntimeError(
                f"AUTH_DB_PATH={path} does not exist but its directory "
                f"{parent} already contains other files — refusing to create "
                "a fresh empty DB (likely an AUTH_DB_PATH typo; the real DB is "
                "probably a nearby filename). Set ALLOW_EMPTY_DB=true to override.",
            )

    if path != ":memory:":
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    # `isolation_level=None` disables sqlite3's auto-BEGIN before DML
    # statements. We use explicit BEGIN/COMMIT inside `transaction()`, so
    # leaving it on the default would produce "cannot start a transaction
    # within a transaction" errors.
    conn = await aiosqlite.connect(path, isolation_level=None)
    # Attach a serialisation lock so concurrent callers can't try to BEGIN
    # while another BEGIN/COMMIT block is in flight on the same connection.
    conn._tx_lock = asyncio.Lock()  # type: ignore[attr-defined]
    # WAL mode allows concurrent readers while a write is in flight.
    # Skip on in-memory DBs (not supported).
    if path != ":memory:":
        await conn.execute("PRAGMA journal_mode = WAL")
        # busy_timeout tells SQLite to retry SQLITE_BUSY errors rather than
        # surfacing them to the caller as 500s. Essential if the DB is ever
        # opened by more than one process (a future multi-worker uvicorn
        # deploy or an ops shell running side-by-side).
        await conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        # NORMAL synchronous mode is safe with WAL and materially faster
        # than the default FULL — a crash may lose the last committed
        # transaction but never corrupts the file.
        await conn.execute("PRAGMA synchronous = NORMAL")
    await conn.execute("PRAGMA foreign_keys = ON")
    await conn.executescript(SCHEMA)
    await _run_light_migrations(conn)
    return conn


async def _run_light_migrations(conn: aiosqlite.Connection) -> None:
    """Idempotent forward-only schema patches for columns added AFTER
    the initial CREATE. `CREATE TABLE IF NOT EXISTS` doesn't alter an
    existing table, so any column we add post-launch has to go here
    with a try/except OperationalError on the duplicate-column case.
    """
    migrations = [
        "ALTER TABLE payment_intents ADD COLUMN expires_at TIMESTAMP",
        # `refunded_at` marks a debit that was reversed by /v1/refund.
        # Kept as a column (not a separate delete + topup marker) so
        # cycle 2 of consume→refund can reuse the SAME row via UPDATE
        # without violating UNIQUE(identity_id, idempotency_key), and
        # so idempotent refund replays still find the row and return
        # a `deduplicated: true` response instead of "not found".
        "ALTER TABLE consume_dedup ADD COLUMN refunded_at TIMESTAMP",
        # One-shot refund capability minted per real debit; see the CREATE
        # above. Rows predating this column have NULL and are therefore no
        # longer refundable — deliberate: those debits are long settled.
        "ALTER TABLE consume_dedup ADD COLUMN debit_token TEXT",
        # Deadline after which a SUPERSEDED api_key stops authenticating.
        # Set on the old key by a rotation instead of revoking it outright:
        # revoking at commit means a rotation whose response never reaches the
        # client (dropped connection, proxy timeout) leaves the caller holding
        # a dead key while the live one exists only in a response nobody read —
        # the account, and any credit on it, is then unreachable forever.
        # A short overlap makes that failure retryable with the old key.
        # NULL means "not superseded"; rows predating this column are NULL and
        # so behave exactly as before.
        "ALTER TABLE credentials ADD COLUMN grace_until TIMESTAMP",
    ]
    for stmt in migrations:
        try:
            await conn.execute(stmt)
        except aiosqlite.OperationalError as e:
            # "duplicate column name" is the expected replay result;
            # anything else is a real problem worth surfacing.
            if "duplicate column name" not in str(e).lower():
                raise


@asynccontextmanager
async def transaction(conn: aiosqlite.Connection) -> AsyncIterator[aiosqlite.Connection]:
    """Run a block inside an explicit BEGIN/COMMIT; ROLLBACK on exception.

    The asyncio lock attached to `conn` ensures we don't try to nest
    transactions when multiple coroutines call into `handlers` at once —
    SQLite only supports a single writer transaction per connection. The
    short-lived lock turns concurrent writes into FIFO serial writes,
    which is the correct semantics for our consume-with-balance-check.
    """
    lock: asyncio.Lock = conn._tx_lock  # type: ignore[attr-defined]
    await lock.acquire()
    try:
        # BEGIN IMMEDIATE acquires the write lock at transaction start.
        # With DEFERRED (the default) two writers can each read, then one
        # upgrades to WRITER and the other hits SQLITE_BUSY mid-block —
        # noise our busy_timeout above can't retry through. IMMEDIATE
        # surfaces contention deterministically at BEGIN, where the
        # timeout retries kick in.
        await conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise
    finally:
        lock.release()
