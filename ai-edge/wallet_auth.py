"""Wallet-bound authentication for the Leviathan AI Edge.

The user's Leviathan wallet IS the AI account. Instead of a bearer api key, the
Edge accepts:

  * a **bind statement** signed by the wallet's Falcon-512 account key, which
    delegates to a short-lived Ed25519 session key (and publishes the wallet's
    X25519 key for ACI E2EE), and
  * a **per-request Ed25519 signature** from that session key over the exact
    method, path and body bytes.

See ../docs/wallet-bound-aci.md for the protocol. Everything here is pure
logic + SQLite; the FastAPI wiring lives in app.py, and Falcon verification is
delegated to the stateless `wallet-verifier` service (no Python implementation
of Leviathan's Falcon exists).

Design notes worth keeping in mind while editing:

  * The session id is a HANDLE, not a credential. Possessing it proves nothing;
    every call must carry a fresh signature. That is what makes leaking it in a
    log or a proxy harmless.
  * The ledger never learns about wallets. The Edge derives an api-key hash
    from the wallet public key and spends through the existing credential
    machinery, so `consume`/`settle`/`refund` semantics are untouched.
  * Every check fails closed, and the challenge nonce is consumed on the FIRST
    bind attempt that references it — a failed attempt must not leave a live
    nonce for the next try.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ─── Protocol constants ──────────────────────────────────────────────────────

BIND_PURPOSE = "leviathan.wallet.bind.v1"
REQUEST_PURPOSE = "leviathan.wallet.request.v1"

# Goldilocks prime: Leviathan field elements live in [0, p).
GOLDILOCKS_P = (1 << 64) - (1 << 32) + 1

SESSION_PREFIX = "lev_s_"
SPEND_CREDENTIAL_PREFIX = "lev_w_"

CHALLENGE_TTL_SEC = 300
# How far a bind statement's `issued_at` may sit from our clock.
BIND_CLOCK_SKEW_SEC = 300
# How far a per-request `ts` may sit from our clock. Tighter than the bind
# window: a request signature is produced and used immediately.
REQUEST_CLOCK_SKEW_SEC = 120

BIND_FIELDS = frozenset({
    "purpose", "service", "nonce", "issued_at", "expires_at",
    "wallet_pub_key", "account_id", "session_pub_key", "e2ee_pub_key",
    "scope", "max_spend",
})
REQUEST_FIELDS = ("purpose", "session", "method", "path", "body_sha256", "ts", "nonce")

KNOWN_SCOPES = frozenset({"inference", "receipts", "models"})


class WalletAuthError(Exception):
    """Fail-closed rejection. `code` is the machine-readable `type` we surface."""

    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


# ─── Config ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class WalletAuthConfig:
    enabled: bool
    verifier_url: str
    service_origin: str
    key_secret: str
    state_db: str
    session_max_ttl_sec: int
    # Hard ceiling (in CREDITS — 1 credit = 1 request) a bind statement may
    # authorize per session. The ledger itself is denominated in credits.
    max_spend: int
    verifier_timeout_sec: float

    @staticmethod
    def from_env(env: Optional[dict] = None) -> "WalletAuthConfig":
        e = env if env is not None else os.environ
        enabled = str(e.get("WALLET_AUTH_ENABLED", "false")).lower() == "true"
        cfg = WalletAuthConfig(
            enabled=enabled,
            verifier_url=str(e.get("WALLET_VERIFIER_URL", "")).rstrip("/"),
            service_origin=str(e.get("WALLET_SERVICE_ORIGIN", "")).rstrip("/"),
            key_secret=str(e.get("EDGE_WALLET_KEY_SECRET", "")),
            state_db=str(e.get("WALLET_STATE_DB", "/edge/wallet-state.db")),
            session_max_ttl_sec=int(e.get("WALLET_SESSION_MAX_TTL_SEC", "86400")),
            max_spend=int(e.get("WALLET_MAX_SPEND", "1000")),
            verifier_timeout_sec=float(e.get("WALLET_VERIFIER_TIMEOUT_SEC", "10.0")),
        )
        if not enabled:
            return cfg
        # Fail-closed at import: a half-configured wallet path would either
        # accept unverified binds or hand out sessions nothing can spend.
        for name, val in (
            ("WALLET_VERIFIER_URL", cfg.verifier_url),
            ("WALLET_SERVICE_ORIGIN", cfg.service_origin),
            ("EDGE_WALLET_KEY_SECRET", cfg.key_secret),
        ):
            if not val:
                raise RuntimeError(f"{name} must be set when WALLET_AUTH_ENABLED=true")
        if cfg.session_max_ttl_sec <= 0:
            raise RuntimeError("WALLET_SESSION_MAX_TTL_SEC must be > 0")
        if cfg.max_spend <= 0:
            raise RuntimeError("WALLET_MAX_SPEND must be > 0")
        return cfg


# ─── Canonicalization (RFC 8785 subset, per aci.md §3) ───────────────────────


def _reject_non_integers(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise WalletAuthError("wallet_invalid_statement", "non-integer numbers are not allowed")
    if isinstance(value, dict):
        for v in value.values():
            _reject_non_integers(v)
    elif isinstance(value, list):
        for v in value:
            _reject_non_integers(v)


def jcs(obj: Any) -> bytes:
    """JCS canonical bytes. ACI objects contain only integer numbers, so the
    ECMAScript number formatting rules never come up — reject floats instead of
    implementing them (aci.md §3)."""
    _reject_non_integers(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def statement_word(statement: dict) -> list[int]:
    """Map a statement onto the four Goldilocks felts the wallet signs.

    SHA-512 over the canonical bytes, split into four little-endian u64 limbs,
    each reduced mod p. The reduction is required, not cosmetic: an unreduced
    limb is not a field element and `Word` deserialization rejects it.
    """
    h = hashlib.sha512(jcs(statement)).digest()
    return [int.from_bytes(h[8 * i:8 * i + 8], "little") % GOLDILOCKS_P for i in range(4)]


def statement_word_bytes(statement: dict) -> bytes:
    return b"".join(f.to_bytes(8, "little") for f in statement_word(statement))


def request_signing_bytes(
    session_id: str, method: str, path: str, body: bytes, ts: int, nonce: str
) -> bytes:
    return jcs({
        "purpose": REQUEST_PURPOSE,
        "session": session_id,
        "method": method.upper(),
        "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "ts": ts,
        "nonce": nonce,
    })


# ─── Small validators ────────────────────────────────────────────────────────


def _hex_key(value: Any, name: str, expected_bytes: Optional[int] = None) -> str:
    """Require *canonical* hex: lowercase, no `0x`, even length.

    Accepting variants and normalizing them would split the statement in two —
    the bytes the wallet hashed and the bytes we store — and the signature only
    ever covers the former. Demanding one spelling keeps the signed object and
    the stored object identical, so there is no gap to reason about.
    """
    if not isinstance(value, str) or not value:
        raise WalletAuthError("wallet_invalid_statement", f"{name} must be a hex string")
    if value != value.lower() or value.startswith("0x"):
        raise WalletAuthError(
            "wallet_invalid_statement", f"{name} must be lowercase hex without a 0x prefix",
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise WalletAuthError("wallet_invalid_statement", f"{name} is not valid hex") from None
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise WalletAuthError(
            "wallet_invalid_statement", f"{name} must be {expected_bytes} bytes",
        )
    return value


def _int_field(statement: dict, name: str) -> int:
    v = statement.get(name)
    if isinstance(v, bool) or not isinstance(v, int):
        raise WalletAuthError("wallet_invalid_statement", f"{name} must be an integer")
    return v


# ─── Falcon verification (delegated) ─────────────────────────────────────────


class FalconVerifier:
    """Client for the stateless `wallet-verifier` service.

    Verification is a hard dependency of a bind: if the verifier is
    unreachable we reject rather than fall back, because the only fallback
    available would be "trust the claim".
    """

    def __init__(self, cfg: WalletAuthConfig, client: Optional[httpx.AsyncClient] = None) -> None:
        self._cfg = cfg
        self._c = client or httpx.AsyncClient(timeout=cfg.verifier_timeout_sec)

    async def aclose(self) -> None:
        await self._c.aclose()

    async def verify(self, public_key_hex: str, word_bytes: bytes, signature_b64: str) -> None:
        payload = {
            "public_key": public_key_hex,
            "message_word": word_bytes.hex(),
            "signature": signature_b64,
        }
        try:
            r = await self._c.post(f"{self._cfg.verifier_url}/verify", json=payload)
        except httpx.RequestError as exc:
            raise WalletAuthError(
                "wallet_verifier_down", f"signature verifier unreachable: {exc}", status=503,
            ) from None
        if r.status_code == 400:
            raise WalletAuthError("wallet_invalid_signature", "malformed signature or public key")
        if not (200 <= r.status_code < 300):
            raise WalletAuthError(
                "wallet_verifier_down", f"verifier returned {r.status_code}", status=503,
            )
        if r.json().get("valid") is not True:
            raise WalletAuthError("wallet_invalid_signature", "wallet signature did not verify")


# ─── State store ─────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wallet_challenges (
    nonce          TEXT PRIMARY KEY,
    wallet_pub_key TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    consumed_at    INTEGER
);

CREATE TABLE IF NOT EXISTS wallet_sessions (
    session_id      TEXT PRIMARY KEY,
    identity_id     INTEGER NOT NULL,
    wallet_pub_key  TEXT NOT NULL,
    account_id      TEXT,
    session_pub_key TEXT NOT NULL,
    e2ee_pub_key    TEXT NOT NULL,
    scope           TEXT NOT NULL,
    max_spend       INTEGER NOT NULL,
    spent           INTEGER NOT NULL DEFAULT 0,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    revoked_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_wallet_sessions_pubkey
    ON wallet_sessions(session_pub_key);
CREATE INDEX IF NOT EXISTS idx_wallet_sessions_wallet
    ON wallet_sessions(wallet_pub_key);

-- Replay cache for per-request nonces. Rows older than the acceptance window
-- are dead weight and are swept on write.
CREATE TABLE IF NOT EXISTS wallet_request_nonces (
    session_id TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (session_id, nonce)
);
"""


@dataclass
class WalletSession:
    session_id: str
    identity_id: int
    wallet_pub_key: str
    account_id: Optional[str]
    session_pub_key: str
    e2ee_pub_key: str
    scope: tuple[str, ...]
    max_spend: int   # credits this session may spend (1 credit = 1 request)
    spent: int       # credits already booked against max_spend
    issued_at: int
    expires_at: int


class WalletStore:
    """SQLite-backed challenge/session state.

    Synchronous on purpose: these are microsecond-scale local queries and the
    Edge's real latency is the upstream inference. Callers on the async path
    wrap them in `asyncio.to_thread` where it matters.
    """

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        # Migrate pre-credit DBs (columns were named *_mc when the accounting
        # was labeled millicredits; values were per-request either way).
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(wallet_sessions)")}
        if "max_spend_mc" in cols:
            with self._conn:
                self._conn.execute(
                    "ALTER TABLE wallet_sessions RENAME COLUMN max_spend_mc TO max_spend")
                self._conn.execute(
                    "ALTER TABLE wallet_sessions RENAME COLUMN spent_mc TO spent")

    def close(self) -> None:
        self._conn.close()

    # -- challenges --

    def issue_challenge(self, wallet_pub_key: str, now: int) -> dict:
        nonce = secrets.token_hex(32)
        expires_at = now + CHALLENGE_TTL_SEC
        with self._conn:
            self._conn.execute(
                "DELETE FROM wallet_challenges WHERE expires_at < ?", (now - CHALLENGE_TTL_SEC,),
            )
            self._conn.execute(
                "INSERT INTO wallet_challenges (nonce, wallet_pub_key, expires_at) VALUES (?,?,?)",
                (nonce, wallet_pub_key, expires_at),
            )
        return {"nonce": nonce, "expires_at": expires_at}

    def consume_challenge(self, nonce: str, wallet_pub_key: str, now: int) -> None:
        """Burn the nonce. Raises if it is unknown, expired, already used, or
        was issued to a different wallet.

        The burn happens even when the bind later fails: a nonce that survives
        a failed attempt is a nonce an attacker can keep grinding against.
        """
        with self._conn:
            cur = self._conn.execute(
                "UPDATE wallet_challenges SET consumed_at = ? "
                "WHERE nonce = ? AND wallet_pub_key = ? AND consumed_at IS NULL "
                "  AND expires_at >= ? RETURNING nonce",
                (now, nonce, wallet_pub_key, now),
            )
            if cur.fetchone() is None:
                raise WalletAuthError("wallet_invalid_nonce", "challenge is unknown, used or expired")

    # -- sessions --

    def session_key_conflicts(self, session_pub_key: str, wallet_pub_key: str, now: int) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM wallet_sessions "
            "WHERE session_pub_key = ? AND wallet_pub_key <> ? "
            "  AND revoked_at IS NULL AND expires_at > ? LIMIT 1",
            (session_pub_key, wallet_pub_key, now),
        )
        return cur.fetchone() is not None

    def create_session(
        self,
        identity_id: int,
        statement: dict,
        scope: Iterable[str],
        now: int,
    ) -> WalletSession:
        session_id = SESSION_PREFIX + secrets.token_hex(16)
        scope_t = tuple(scope)
        session = WalletSession(
            session_id=session_id,
            identity_id=identity_id,
            wallet_pub_key=statement["wallet_pub_key"],
            account_id=statement.get("account_id"),
            session_pub_key=statement["session_pub_key"],
            e2ee_pub_key=statement["e2ee_pub_key"],
            scope=scope_t,
            max_spend=statement["max_spend"],
            spent=0,
            issued_at=statement["issued_at"],
            expires_at=statement["expires_at"],
        )
        with self._conn:
            self._conn.execute(
                "INSERT INTO wallet_sessions (session_id, identity_id, wallet_pub_key, account_id,"
                " session_pub_key, e2ee_pub_key, scope, max_spend, issued_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    session.session_id, identity_id, session.wallet_pub_key, session.account_id,
                    session.session_pub_key, session.e2ee_pub_key, " ".join(scope_t),
                    session.max_spend, session.issued_at, session.expires_at,
                ),
            )
        return session

    def get_session(self, session_id: str, now: int) -> WalletSession:
        cur = self._conn.execute(
            "SELECT session_id, identity_id, wallet_pub_key, account_id, session_pub_key,"
            "       e2ee_pub_key, scope, max_spend, spent, issued_at, expires_at,"
            "       revoked_at "
            "FROM wallet_sessions WHERE session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise WalletAuthError("wallet_unknown_session", "unknown session — bind again")
        if row[11] is not None:
            raise WalletAuthError("wallet_session_revoked", "session was revoked — bind again")
        if row[10] <= now:
            raise WalletAuthError("wallet_session_expired", "session expired — bind again")
        return WalletSession(
            session_id=row[0], identity_id=row[1], wallet_pub_key=row[2], account_id=row[3],
            session_pub_key=row[4], e2ee_pub_key=row[5], scope=tuple(row[6].split()) if row[6] else (),
            max_spend=row[7], spent=row[8], issued_at=row[9], expires_at=row[10],
        )

    def revoke_session(self, session_id: str, now: int) -> bool:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE wallet_sessions SET revoked_at = ? "
                "WHERE session_id = ? AND revoked_at IS NULL RETURNING session_id",
                (now, session_id),
            )
            return cur.fetchone() is not None

    def revoke_all_for_wallet(self, wallet_pub_key: str, now: int) -> int:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE wallet_sessions SET revoked_at = ? "
                "WHERE wallet_pub_key = ? AND revoked_at IS NULL RETURNING session_id",
                (now, wallet_pub_key),
            )
            return len(cur.fetchall())

    def note_request_nonce(self, session_id: str, nonce: str, now: int) -> None:
        with self._conn:
            self._conn.execute(
                "DELETE FROM wallet_request_nonces WHERE seen_at < ?",
                (now - REQUEST_CLOCK_SKEW_SEC * 2,),
            )
            try:
                self._conn.execute(
                    "INSERT INTO wallet_request_nonces (session_id, nonce, seen_at) VALUES (?,?,?)",
                    (session_id, nonce, now),
                )
            except sqlite3.IntegrityError:
                raise WalletAuthError("wallet_replay", "request nonce already used") from None

    def charge(self, session_id: str, amount: int, now: int) -> None:
        """Book `amount` credits against the session's signed spend cap.

        The UPDATE carries the cap in its WHERE clause, so two concurrent
        requests cannot both slip past the last credit.
        """
        with self._conn:
            cur = self._conn.execute(
                "UPDATE wallet_sessions SET spent = spent + ? "
                "WHERE session_id = ? AND revoked_at IS NULL AND expires_at > ? "
                "  AND spent + ? <= max_spend RETURNING spent",
                (amount, session_id, now, amount),
            )
            if cur.fetchone() is None:
                raise WalletAuthError(
                    "wallet_spend_cap",
                    "session spend cap reached — re-authorize in the wallet",
                    status=402,
                )

    def uncharge(self, session_id: str, amount: int) -> None:
        """Give back a booking whose request never happened (gateway refused).

        Mirrors the ledger refund; clamped at zero so a double-uncharge cannot
        mint session budget.
        """
        with self._conn:
            self._conn.execute(
                "UPDATE wallet_sessions SET spent = MAX(spent - ?, 0) WHERE session_id = ?",
                (amount, session_id),
            )


# ─── The authenticator ───────────────────────────────────────────────────────


@dataclass
class BindResult:
    session: WalletSession
    created_identity: bool
    balance: Optional[int]  # credits


class WalletAuthenticator:
    """Stateless-ish façade over the store + verifier used by app.py."""

    def __init__(
        self,
        cfg: WalletAuthConfig,
        store: WalletStore,
        verifier: FalconVerifier,
        clock=time.time,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.verifier = verifier
        self._clock = clock

    def now(self) -> int:
        return int(self._clock())

    # -- ledger credential --

    def spend_credential_hash(self, wallet_pub_key: str) -> str:
        """SHA256 of the wallet's derived spending api key.

        The raw key exists only inside this expression: the ledger stores and
        compares hashes, so there is nothing secret to persist here beyond
        EDGE_WALLET_KEY_SECRET itself.
        """
        mac = hmac.new(
            self.cfg.key_secret.encode("utf-8"), wallet_pub_key.encode("utf-8"), hashlib.sha256,
        ).hexdigest()
        raw = f"{SPEND_CREDENTIAL_PREFIX}{mac}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # -- challenge --

    def challenge(self, wallet_pub_key: Any) -> dict:
        pk = _hex_key(wallet_pub_key, "wallet_pub_key")
        out = self.store.issue_challenge(pk, self.now())
        return {"nonce": out["nonce"], "expires_at": out["expires_at"], "service": self.cfg.service_origin}

    # -- bind --

    def validate_statement(self, statement: Any) -> dict:
        """Shape, freshness and policy checks — everything that does not need
        the signature. Returns the normalized statement."""
        if not isinstance(statement, dict):
            raise WalletAuthError("wallet_invalid_statement", "statement must be an object")
        extra = set(statement) - BIND_FIELDS
        missing = BIND_FIELDS - set(statement)
        if extra or missing:
            raise WalletAuthError(
                "wallet_invalid_statement",
                f"statement fields mismatch (unexpected={sorted(extra)}, missing={sorted(missing)})",
            )
        if statement["purpose"] != BIND_PURPOSE:
            raise WalletAuthError("wallet_invalid_statement", "wrong purpose")
        if statement["service"] != self.cfg.service_origin:
            raise WalletAuthError("wallet_invalid_statement", "statement is for a different service")

        nonce = statement["nonce"]
        if not isinstance(nonce, str) or len(nonce) != 64:
            raise WalletAuthError("wallet_invalid_statement", "nonce must be 64 hex chars")

        issued_at = _int_field(statement, "issued_at")
        expires_at = _int_field(statement, "expires_at")
        max_spend = _int_field(statement, "max_spend")
        now = self.now()
        if abs(now - issued_at) > BIND_CLOCK_SKEW_SEC:
            raise WalletAuthError("wallet_stale_statement", "issued_at is too far from server time")
        if expires_at <= now:
            raise WalletAuthError("wallet_stale_statement", "statement already expired")
        if expires_at - issued_at > self.cfg.session_max_ttl_sec:
            raise WalletAuthError(
                "wallet_invalid_statement",
                f"session lifetime exceeds {self.cfg.session_max_ttl_sec}s",
            )
        if not (0 < max_spend <= self.cfg.max_spend):
            raise WalletAuthError(
                "wallet_invalid_statement",
                f"max_spend must be in 1..{self.cfg.max_spend}",
            )

        scope = statement["scope"]
        if (not isinstance(scope, list) or not scope
                or not all(isinstance(s, str) for s in scope)):
            raise WalletAuthError("wallet_invalid_statement", "scope must be a non-empty string list")
        unknown = set(scope) - KNOWN_SCOPES
        if unknown:
            raise WalletAuthError("wallet_invalid_statement", f"unknown scopes {sorted(unknown)}")

        account_id = statement["account_id"]
        if account_id is not None and not isinstance(account_id, str):
            raise WalletAuthError("wallet_invalid_statement", "account_id must be a string or null")

        # Canonical hex is enforced, not normalized, so the object we validate
        # is byte-for-byte the object the wallet signed.
        _hex_key(statement["wallet_pub_key"], "wallet_pub_key")
        _hex_key(statement["session_pub_key"], "session_pub_key", 32)
        _hex_key(statement["e2ee_pub_key"], "e2ee_pub_key", 32)
        return dict(statement)

    async def verify_bind(self, statement: Any, signature_b64: Any) -> dict:
        """Full bind verification up to (not including) ledger resolution.

        Returns the normalized statement. The caller resolves the identity and
        calls `create_session`.
        """
        if not isinstance(signature_b64, str) or not signature_b64:
            raise WalletAuthError("wallet_invalid_signature", "signature must be a base64 string")
        try:
            base64.b64decode(signature_b64, validate=True)
        except Exception:
            raise WalletAuthError("wallet_invalid_signature", "signature is not valid base64") from None

        normalized = self.validate_statement(statement)
        now = self.now()

        # Burn the nonce BEFORE the expensive verification: a nonce that
        # survives a failed attempt is one an attacker can keep grinding.
        self.store.consume_challenge(normalized["nonce"], normalized["wallet_pub_key"], now)

        if self.store.session_key_conflicts(
            normalized["session_pub_key"], normalized["wallet_pub_key"], now,
        ):
            raise WalletAuthError(
                "wallet_session_key_reused", "session_pub_key is already bound to another wallet",
            )

        # The Word is computed from the statement WE parsed, canonicalized by
        # our own encoder — never from the client's byte framing. Two clients
        # sending the same object with different whitespace or key order must
        # verify identically, and a client cannot smuggle bytes past us.
        await self.verifier.verify(
            normalized["wallet_pub_key"], statement_word_bytes(normalized), signature_b64,
        )
        return normalized

    # -- per-request --

    def authenticate_request(
        self,
        session_id: str,
        method: str,
        path: str,
        body: bytes,
        headers: dict,
        required_scope: Optional[str],
    ) -> WalletSession:
        now = self.now()
        session = self.store.get_session(session_id, now)

        # `required_scope=None` means "any valid session" — used by actions that
        # are not a delegated spend/read (e.g. topping up one's own balance).
        if required_scope is not None and required_scope not in session.scope:
            raise WalletAuthError(
                "wallet_scope", f"session was not authorized for '{required_scope}'", status=403,
            )

        ts_raw = headers.get("x-wallet-timestamp")
        nonce = headers.get("x-wallet-nonce")
        sig_b64 = headers.get("x-wallet-signature")
        if not ts_raw or not nonce or not sig_b64:
            raise WalletAuthError(
                "wallet_missing_signature",
                "x-wallet-timestamp, x-wallet-nonce and x-wallet-signature are required",
            )
        try:
            ts = int(ts_raw)
        except ValueError:
            raise WalletAuthError("wallet_invalid_signature", "x-wallet-timestamp must be an integer") from None
        if abs(now - ts) > REQUEST_CLOCK_SKEW_SEC:
            raise WalletAuthError("wallet_stale_request", "request timestamp outside the accepted window")
        if len(nonce) != 32 or not _is_hex(nonce):
            raise WalletAuthError("wallet_invalid_signature", "x-wallet-nonce must be 32 hex chars")

        try:
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception:
            raise WalletAuthError("wallet_invalid_signature", "signature is not valid base64") from None

        payload = request_signing_bytes(session_id, method, path, body, ts, nonce)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(session.session_pub_key)).verify(sig, payload)
        except InvalidSignature:
            raise WalletAuthError("wallet_invalid_signature", "request signature did not verify") from None

        # Only after the signature holds — otherwise an unauthenticated caller
        # could fill the replay table with nonces of its choosing.
        self.store.note_request_nonce(session_id, nonce, now)
        return session


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False
