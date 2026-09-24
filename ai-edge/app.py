"""Leviathan AI Edge — multi-tenant front for the single-tenant AI gateway.

End users hold ONE Leviathan API key (`lev_...`). This Edge:
  1. hashes the key and meters/debits credits via the Leviathan auth-service
     (the same ledger the TEE prover uses: api_key -> identity -> credit),
  2. forwards the OpenAI-compatible request to the gateway with TWO headers:
       x-gateway-token: <internal service token>   (passes the gateway's api gate)
       authorization:   Bearer <per-user tenant bearer>
     The tenant bearer is HMAC-SHA256(EDGE_TENANT_SECRET, identity_id), so the
     gateway records each receipt as owned by THAT user
     (`ReceiptOwner::from_bearer`) — per-user receipt isolation is enforced by
     the gateway's own crypto-ownership, not by Edge bookkeeping — while the
     user's raw key and the provider keys never reach the gateway logs.
  3. streams the response back; refunds the credit if the gateway rejects it.

This hides Phala + the GPU-TEE provider keys behind Leviathan — users never
register with Phala or the providers; they only hold a Leviathan key.

Authentication comes in two flavours, side by side:

  Authorization: Bearer lev_...     the api key described above
  Authorization: Wallet lev_s_...   a Leviathan wallet session (wallet_auth.py)

In the wallet flavour the user's Miden wallet IS the account: no api key
exists, the ledger identity hangs off the wallet's public key, and every call
carries a fresh Ed25519 signature from a session key the wallet's Falcon
account key delegated to. See ../docs/wallet-bound-aci.md.

Endpoints (OpenAI-compatible):
  POST /v1/chat/completions | /v1/completions | /v1/embeddings  -> metered (1 credit)
  GET  /v1/models                                               -> requires a valid key, no debit
  GET  /v1/aci/receipts/{id}   -> requires a valid key; only the receipt's owner gets it
  GET  /v1/attestation/report  -> public passthrough (verifiability)
  GET  /health

Wallet endpoints (only when WALLET_AUTH_ENABLED=true):
  POST /v1/wallet/challenge            -> single-use nonce
  POST /v1/wallet/bind                 -> Falcon-verified session
  POST /v1/wallet/session/revoke       -> end this session (sent on wallet lock)
  POST /v1/wallet/sessions/revoke-all  -> end every session of this wallet
  POST /v1/wallet/payment-intents      -> self-serve top-up (Stripe/on-chain) for the wallet
  GET  /v1/wallet/balance              -> current balance (signed read, no re-bind)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

import wallet_auth
from wallet_auth import WalletAuthError, WalletSession

# ─── Config ──────────────────────────────────────────────────────────────────

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "").rstrip("/")
# Bearer that authenticates the Edge to the auth-service's /v1/consume + /v1/refund
# (MUST equal PROXY_REFUND_TOKEN on the auth-service — same gate the TEE proxy uses).
AUTH_SERVICE_PROXY_TOKEN = os.getenv("AUTH_SERVICE_PROXY_TOKEN", "")
AUTH_SERVICE_TIMEOUT_SEC = float(os.getenv("AUTH_SERVICE_TIMEOUT_SEC", "5.0"))


def _resolve_verify(raw: str) -> "bool | str":
    low = raw.lower()
    if low == "false":
        return False
    if low == "true":
        return True
    if not os.path.isfile(raw):
        raise RuntimeError(f"AUTH_SERVICE_VERIFY_TLS={raw!r} is not a file")
    return raw


AUTH_SERVICE_VERIFY_TLS = _resolve_verify(os.getenv("AUTH_SERVICE_VERIFY_TLS", "true"))

# The gateway this Edge fronts, and its internal service token (sent on
# x-gateway-token so `authorization` stays free for the tenant bearer).
GATEWAY_URL = os.getenv("GATEWAY_URL", "").rstrip("/")
GATEWAY_API_TOKEN = os.getenv("GATEWAY_API_TOKEN", "")

# Request-body caps. The gateway refuses bodies over 32 MiB
# (MAX_REQUEST_BODY_BYTES); the Edge refuses the same BEFORE reading them into
# memory, authenticating, or debiting: a Content-Length over the cap is
# rejected without reading a byte, and a body without one is read up to the
# cap and not further. Keep EDGE_MAX_BODY_BYTES equal to the gateway's cap —
# lower rejects requests the gateway would take, higher debits a credit for a
# guaranteed 413 (refunded, but a round trip for nothing). Wallet control
# endpoints carry a few KB of JSON (a Falcon signature is ~1.3 KB); they get a
# cap that no honest client reaches and no anonymous client can abuse.
EDGE_MAX_BODY_BYTES = int(os.getenv("EDGE_MAX_BODY_BYTES", str(32 * 1024 * 1024)))
EDGE_MAX_WALLET_BODY_BYTES = int(os.getenv("EDGE_MAX_WALLET_BODY_BYTES", str(64 * 1024)))

# Which public models accept which input modalities, e.g.
#   {"glm-5.3-flash": ["text", "image"], "qwen3.6-35b-a3b": ["text"]}
# Merged into /v1/models as `input_modalities` so a frontend can enable
# image attachment per model without hardcoding names. The truth lives in
# the upstream catalog (NEAR's /v1/models, per upstream id), which the
# gateway does not expose per public alias — so the operator keeps this
# map alongside the model map (ai-edge/sync_tee_models.py prints the
# matching line). Unknown model → ["text"], the conservative default.


def _parse_modalities(raw: str) -> "dict[str, list[str]]":
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise RuntimeError(f"EDGE_MODEL_INPUT_MODALITIES is not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise RuntimeError("EDGE_MODEL_INPUT_MODALITIES must be a JSON object {model: [modalities]}")
    out: dict[str, list[str]] = {}
    for model_id, mods in data.items():
        if isinstance(mods, str):
            mods = [m.strip() for m in mods.split(",") if m.strip()]
        if (not isinstance(mods, list) or not mods
                or not all(isinstance(m, str) and m for m in mods)):
            raise RuntimeError(
                f"EDGE_MODEL_INPUT_MODALITIES[{model_id!r}] must be a non-empty list of strings")
        out[str(model_id)] = mods
    return out


MODEL_INPUT_MODALITIES = _parse_modalities(os.getenv("EDGE_MODEL_INPUT_MODALITIES", ""))
DEFAULT_INPUT_MODALITIES = ["text"]


def _annotate_models(content: bytes) -> bytes:
    """Add `input_modalities` to every entry of an OpenAI-style model list.

    Anything that is not a well-formed list response (an error body, a
    non-JSON payload) is returned byte-for-byte: this decorates, it never
    decides. Entries already carrying `input_modalities` (a future gateway
    that knows) are left alone.
    """
    try:
        payload = json.loads(content)
    except ValueError:
        return content
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return content
    for entry in data:
        if isinstance(entry, dict) and "input_modalities" not in entry:
            entry["input_modalities"] = list(
                MODEL_INPUT_MODALITIES.get(str(entry.get("id")), DEFAULT_INPUT_MODALITIES))
    return json.dumps(payload).encode("utf-8")
GATEWAY_TIMEOUT_SEC = float(os.getenv("GATEWAY_TIMEOUT_SEC", "600.0"))

# Secret behind the per-user tenant bearers. Receipts at the gateway are owned
# by SHA256(tenant bearer); anyone who can derive a user's bearer can read
# that user's receipts, so this must stay as private as the api tokens.
# Rotating it orphans receipts issued under the old bearers (they stay owned
# by the old digest) — rotate only with that in mind.
EDGE_TENANT_SECRET = os.getenv("EDGE_TENANT_SECRET", "")

# Wallet-bound auth (../docs/wallet-bound-aci.md). Reads its own env; when
# disabled the whole wallet surface is absent and only api keys work, exactly
# as before this feature existed.
WALLET_CFG = wallet_auth.WalletAuthConfig.from_env()

# What one metered request books against a session's signed spend cap, in
# CREDITS. Matches the ledger exactly: auth-service /v1/consume debits a flat
# 1 credit per request, so the cap the user signed is denominated in the same
# unit they see billed ($3 -> 300 credits -> 300 chats).
WALLET_REQUEST_COST = int(os.getenv("WALLET_REQUEST_COST", "1"))

# Fail-closed: refuse to start misconfigured so we never bill/serve wrong.
for _name, _val in (
    ("AUTH_SERVICE_URL", AUTH_SERVICE_URL),
    ("AUTH_SERVICE_PROXY_TOKEN", AUTH_SERVICE_PROXY_TOKEN),
    ("GATEWAY_URL", GATEWAY_URL),
    ("GATEWAY_API_TOKEN", GATEWAY_API_TOKEN),
    ("EDGE_TENANT_SECRET", EDGE_TENANT_SECRET),
):
    if not _val:
        raise RuntimeError(f"{_name} must be set")
# The api-key hash + ALLOW/DENY travel on this channel → require https unless the
# operator explicitly opts into http for a co-located/private-network deploy
# (Edge and auth-service on the same host or an internal Docker network).
AUTH_SERVICE_ALLOW_HTTP = os.getenv("AUTH_SERVICE_ALLOW_HTTP", "false").lower() == "true"
if not AUTH_SERVICE_URL.startswith("https://") and not AUTH_SERVICE_ALLOW_HTTP:
    raise RuntimeError(
        "AUTH_SERVICE_URL must be https:// (the api-key hash travels on it); "
        "set AUTH_SERVICE_ALLOW_HTTP=true only for a co-located/private-network deploy",
    )

# Allowlist, not a denylist: only these client headers reach the gateway.
# Rationale — the idempotency key is derived from path+body, so any header
# that can change the gateway's response would let a replay of an
# already-charged body produce a DIFFERENT outcome than the debited request.
# Auth/tenancy headers (authorization, x-gateway-token, x-user-tier) are
# Edge-controlled and are set explicitly in _fwd_request_headers; hop-by-hop
# headers must not be proxied at all.
_FWD_REQ_HEADERS = {"content-type", "accept", "accept-encoding", "user-agent"}

_BOUND_REQ_HEADERS = frozenset({
    "x-signing-algo", "x-client-pub-key", "x-model-pub-key",
    "x-e2ee-version", "x-e2ee-nonce", "x-e2ee-timestamp",
})

_FWD_RESP_HEADERS = {"content-type", "x-receipt-id"}
_FWD_RESP_PREFIXES = ("x-e2ee-",)


# ─── Auth-service client (credit ledger) ─────────────────────────────────────

ALLOW, DENY_UNAUTH, DENY_NO_BALANCE, DENY_RATE, DENY_DOWN = (
    "allow", "unauth", "no_balance", "rate_limited", "auth_down",
)


@dataclass
class AuthResult:
    status: str
    balance: Optional[int] = None
    error: Optional[str] = None
    # Stable ledger identity behind the api key — the tenant. Set on ALLOW,
    # and on DENY_NO_BALANCE from validate() (known key, empty balance), so
    # receipt reads keep working after the user runs out of credit.
    identity_id: Optional[int] = None
    # One-shot capability to reverse THIS debit, returned by the ledger only
    # when a credit was actually spent. Absent on an idempotent replay —
    # which is exactly why a replay can never trigger a refund.
    debit_token: Optional[str] = None
    # Wallet-bind only: whether the (unverified) miden_account label was
    # attached, and the ledger's warning when it was skipped on a claim
    # conflict. The bind itself succeeds either way.
    account_id_attached: Optional[bool] = None
    warning: Optional[str] = None


class AuthClient:
    """Calls the Leviathan auth-service. `consume` debits atomically (never
    cached); mirrors the TEE proxy's gate so the Edge reuses the same ledger."""

    def __init__(self) -> None:
        self._c = httpx.AsyncClient(timeout=AUTH_SERVICE_TIMEOUT_SEC, verify=AUTH_SERVICE_VERIFY_TLS)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    # The `*_hashed` variants take the credential hash directly. Wallet
    # sessions have no raw api key to hash — the Edge derives their hash from
    # the wallet public key — so the ledger calls are expressed in terms of the
    # hash, and the raw-key entry points below are thin wrappers.

    async def consume(self, raw_key: str, idempotency_key: str) -> AuthResult:
        return await self.consume_hashed(self.hash_key(raw_key), idempotency_key)

    async def refund(self, raw_key: str, debit_token: Optional[str], reason: str) -> None:
        await self.refund_hashed(self.hash_key(raw_key), debit_token, reason)

    async def validate(self, raw_key: str) -> AuthResult:
        return await self.validate_hashed(self.hash_key(raw_key))

    async def consume_hashed(self, key_hash: str, idempotency_key: str) -> AuthResult:
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/consume",
                json={
                    "credential_type": "api_key",
                    "credential_value": key_hash,
                    "idempotency_key": idempotency_key,
                },
                headers={"Authorization": f"Bearer {AUTH_SERVICE_PROXY_TOKEN}"},
            )
        except httpx.RequestError as e:
            return AuthResult(DENY_DOWN, error=f"auth unreachable: {e}")
        if r.status_code == 401:
            return AuthResult(DENY_UNAUTH, error="invalid api key")
        if r.status_code == 429:
            return AuthResult(DENY_RATE, error="rate limit exceeded")
        if not (200 <= r.status_code < 300):
            return AuthResult(DENY_DOWN, error=f"auth returned {r.status_code}")
        data = r.json()
        if data.get("success") is True:
            return AuthResult(ALLOW, balance=data.get("balance"),
                              identity_id=data.get("identity_id"),
                              debit_token=data.get("debit_token"))
        err = str(data.get("error", "")).lower()
        if "balance" in err or "insufficient" in err:
            return AuthResult(DENY_NO_BALANCE, error=data.get("error"))
        return AuthResult(DENY_UNAUTH, error=data.get("error"))

    async def refund_hashed(self, key_hash: str, debit_token: Optional[str], reason: str) -> None:
        # Best-effort reversal when the gateway rejected the request post-debit.
        # `debit_token` is None when this request's consume was an idempotent
        # replay: it spent nothing, so there is nothing of ITS to reverse —
        # refunding here would mint a credit against an earlier request's debit
        # and turn one paid request into unlimited free inference.
        if not debit_token:
            return
        try:
            await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/refund",
                json={
                    "credential_type": "api_key",
                    "credential_value": key_hash,
                    "debit_token": debit_token,
                    "reason": reason,
                },
                headers={"Authorization": f"Bearer {AUTH_SERVICE_PROXY_TOKEN}"},
            )
        except httpx.RequestError:
            pass  # refund miss is logged upstream; don't mask the original error

    async def validate_hashed(self, key_hash: str) -> AuthResult:
        # Read-only: is this a known credential (with balance)? Used by /v1/models.
        # The proxy token is not required here (validate is public) — it tells
        # auth-service these calls come from the Edge, which relays every tenant
        # from one IP, so it buckets them per credential instead of collapsing
        # the whole deployment into one per-IP rate limit.
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/validate",
                json={"credential_type": "api_key", "credential_value": key_hash},
                headers={"Authorization": f"Bearer {AUTH_SERVICE_PROXY_TOKEN}"},
            )
        except httpx.RequestError as e:
            return AuthResult(DENY_DOWN, error=f"auth unreachable: {e}")
        if not (200 <= r.status_code < 300):
            return AuthResult(DENY_DOWN, error=f"auth returned {r.status_code}")
        data = r.json()
        if data.get("valid") is True:
            return AuthResult(ALLOW, balance=data.get("balance"),
                              identity_id=data.get("identity_id"))
        err = str(data.get("error", "")).lower()
        if "balance" in err or "insufficient" in err:
            # Known key, just empty — allow listing models / reading receipts.
            return AuthResult(DENY_NO_BALANCE, error=data.get("error"),
                              identity_id=data.get("identity_id"))
        return AuthResult(DENY_UNAUTH, error=data.get("error"))

    async def wallet_bind(self, wallet_pub_key: str, api_key_hash: str,
                          account_id: Optional[str]) -> AuthResult:
        """Resolve a verified wallet to its ledger identity (get-or-create).

        Only ever called after the Falcon signature verified: this is the step
        that turns a proven wallet into something the credit ledger can bill.
        """
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/wallet/bind",
                json={
                    "wallet_pub_key": wallet_pub_key,
                    "api_key_hash": api_key_hash,
                    "account_id": account_id,
                },
                headers={"Authorization": f"Bearer {AUTH_SERVICE_PROXY_TOKEN}"},
            )
        except httpx.RequestError as e:
            return AuthResult(DENY_DOWN, error=f"auth unreachable: {e}")
        if r.status_code == 409:
            # The wallet's derived spending credential collides with another
            # identity. (An account_id label conflict is NOT a 409 — the
            # ledger skips the label and the bind succeeds with a warning.)
            # Not retryable, and not the caller's to fix silently.
            return AuthResult(DENY_UNAUTH, error=str(r.json().get("detail", "wallet bind conflict")))
        if not (200 <= r.status_code < 300):
            return AuthResult(DENY_DOWN, error=f"auth returned {r.status_code}")
        data = r.json()
        return AuthResult(ALLOW, balance=data.get("balance"), identity_id=data.get("identity_id"),
                          account_id_attached=data.get("account_id_attached"),
                          warning=data.get("warning"))

    async def create_payment_intent_hashed(
        self, key_hash: str, credits: int, provider: str = "stripe",
        sender_address: Optional[str] = None,
    ) -> "tuple[Optional[dict], Optional[AuthResult]]":
        """Create a payment intent for the identity behind `key_hash`.

        Wallet users have no raw api key, so the Edge presents their derived
        credential hash to the SAME user-facing intent endpoint api-key users
        hit. auth-service resolves it to the wallet's identity and returns
        the provider's payment instructions (Stripe checkout URL, or the
        `onchain` block); the matching receive side credits it on payment.
        Returns (intent, None) on success or (None, AuthResult) on failure.
        """
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/payment-intents",
                json={
                    "credential_type": "api_key", "credential_value": key_hash,
                    "credits": credits, "provider": provider,
                    # The payer's Miden account: lets auth-service build
                    # the wallet payload server-side (onchain.custom_tx).
                    # Passed through verbatim; validated by the ledger.
                    **({"sender_address": sender_address} if sender_address else {}),
                },
            )
        except httpx.RequestError as e:
            return None, AuthResult(DENY_DOWN, error=f"auth unreachable: {e}")
        if not (200 <= r.status_code < 300):
            try:
                detail = r.json().get("detail")
            except Exception:
                detail = None
            status = DENY_UNAUTH if r.status_code in (400, 401) else DENY_DOWN
            return None, AuthResult(status, error=str(detail or f"auth returned {r.status_code}"))
        return r.json(), None

    async def checkout_payment_intent_hashed(
        self, key_hash: str, memo: str, sender_address: Optional[str] = None,
    ) -> "tuple[int, dict]":
        """Reopen an existing intent's payment instructions for the wallet
        behind `key_hash`, vouching for it with its derived credential.

        The ledger's /checkout is public for READS, but (re)preparing the
        on-chain wallet payload for a named account is a write that needs
        the order owner's credential — which a browser never holds. The
        Edge supplies it here, exactly as it does for intent creation.

        Returns (status, json) VERBATIM rather than an AuthResult: the
        ledger's 403 (not the owner) / 404 / 409 (no longer payable) carry
        meaning the SDK acts on, and collapsing them would lose it.
        """
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/payment-intents/{memo}/checkout",
                json={
                    "credential_type": "api_key", "credential_value": key_hash,
                    **({"sender_address": sender_address} if sender_address else {}),
                },
            )
        except httpx.RequestError as e:
            return 503, {"detail": f"auth unreachable: {e}"}
        try:
            data = r.json()
        except ValueError:
            data = {"detail": r.text[:200]}
        return r.status_code, data if isinstance(data, dict) else {"detail": str(data)[:200]}


# ─── App ─────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.auth = AuthClient()
    app.state.gw = httpx.AsyncClient(timeout=GATEWAY_TIMEOUT_SEC)
    app.state.wallet = None
    if WALLET_CFG.enabled:
        app.state.wallet = wallet_auth.WalletAuthenticator(
            WALLET_CFG,
            wallet_auth.WalletStore(WALLET_CFG.state_db),
            wallet_auth.FalconVerifier(WALLET_CFG),
        )
    try:
        yield
    finally:
        await app.state.auth._c.aclose()
        await app.state.gw.aclose()
        if app.state.wallet is not None:
            await app.state.wallet.verifier.aclose()
            app.state.wallet.store.close()


app = FastAPI(title="Leviathan AI Edge", lifespan=lifespan)

# Cross-origin browser access, OFF by default. The wallet dApp page is served
# on the Edge's own origin (Caddy /wallet/*) precisely so it needs no CORS;
# set this only for a frontend hosted elsewhere (e.g. the Railway chat app)
# that must call the Edge directly from the browser. Exact origins,
# comma-separated — never "*": with "*" any web page could drive a visitor's
# wallet session cross-site. Auth still rests on per-request signatures; CORS
# here only gates which pages a browser will let talk to us at all.
EDGE_CORS_ORIGINS = [o.strip() for o in os.getenv("EDGE_CORS_ORIGINS", "").split(",") if o.strip()]

# Response headers a CROSS-ORIGIN page may read. Everything the Edge forwards
# from the gateway that a client acts on must be here, or a browser app on
# another origin sees the request succeed and the header vanish:
#   x-receipt-id      — verifiability
#   x-e2ee-applied    — the gateway's confirmation that it decrypted the
#                       request; an E2EE client REFUSES the reply without it
#                       (the SDK throws e2ee_not_applied). A same-origin proxy
#                       never notices this list; a Railway/Vite page does.
#   x-e2ee-version / x-e2ee-algo — which scheme the reply is encrypted under
_CORS_EXPOSE_HEADERS = ["x-receipt-id", "x-e2ee-applied", "x-e2ee-version", "x-e2ee-algo"]

if EDGE_CORS_ORIGINS:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=EDGE_CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "authorization", "content-type", "idempotency-key",
            "x-wallet-timestamp", "x-wallet-nonce", "x-wallet-signature",
            "x-signing-algo", "x-client-pub-key", "x-model-pub-key",
            "x-e2ee-version", "x-e2ee-nonce", "x-e2ee-timestamp",
        ],
        expose_headers=_CORS_EXPOSE_HEADERS,
    )


def _bearer(request: Request) -> Optional[str]:
    return _authorization(request, "bearer")


def _authorization(request: Request, scheme: str) -> Optional[str]:
    h = request.headers.get("authorization", "")
    prefix, _, rest = h.partition(" ")
    if prefix.lower() != scheme.lower() or not rest.strip():
        return None
    return rest.strip()


@dataclass
class Principal:
    """Whoever is making this request, reduced to what the ledger needs.

    Both auth flavours converge here: the ledger only ever sees a credential
    hash, so nothing downstream needs to know whether a wallet or an api key
    produced it. `session` is set only for wallet principals, and only so the
    spend cap the user signed can be booked and released.
    """

    credential_hash: str
    session: Optional[WalletSession] = None

    @property
    def is_wallet(self) -> bool:
        return self.session is not None


def _wallet_error(exc: WalletAuthError) -> Response:
    return JSONResponse(
        status_code=exc.status,
        content={"error": {"message": exc.message, "type": exc.code}},
    )


async def _resolve_principal(
    request: Request, path: str, body: bytes, required_scope: str,
) -> Principal:
    """Authenticate the caller, api key or wallet session.

    Raises WalletAuthError for every failure — including the api-key ones — so
    a caller has exactly one error path to handle and cannot forget one.
    """
    session_id = _authorization(request, "wallet")
    if session_id:
        wallet: Optional[wallet_auth.WalletAuthenticator] = request.app.state.wallet
        if wallet is None:
            raise WalletAuthError("wallet_disabled", "wallet authentication is not enabled", status=501)
        session = wallet.authenticate_request(
            session_id, request.method, path, body, request.headers, required_scope,
        )
        return Principal(
            credential_hash=wallet.spend_credential_hash(session.wallet_pub_key),
            session=session,
        )

    raw_key = _bearer(request)
    if not raw_key:
        raise WalletAuthError("unauth", "api key or wallet session required")
    return Principal(credential_hash=AuthClient.hash_key(raw_key))


def _deny_response(res: AuthResult) -> Response:
    code, err = {
        DENY_UNAUTH: (401, "invalid api key"),
        DENY_NO_BALANCE: (402, "insufficient credits — top up to continue"),
        DENY_RATE: (429, "rate limit exceeded — slow down"),
        DENY_DOWN: (503, "billing service unavailable, retry later"),
    }[res.status]
    return JSONResponse(status_code=code, content={"error": {"message": res.error or err, "type": res.status}})


def _tenant_bearer(identity_id: int) -> str:
    """Deterministic, unguessable per-user bearer the gateway sees.

    The gateway records receipt ownership as SHA256(bearer); deriving the
    bearer as HMAC(secret, identity_id) gives every ledger identity its own
    owner without the gateway ever learning the user's raw key.
    """
    mac = hmac.new(EDGE_TENANT_SECRET.encode("utf-8"),
                   str(identity_id).encode("utf-8"), hashlib.sha256)
    return f"lev_t_{mac.hexdigest()}"


def _bound_header_digest(request: Request) -> bytes:
    """Digest over the response-affecting headers this Edge forwards.

    Mixed into the idempotency key so two requests differing only in these
    headers get two ledger keys. Without it the ledger would deduplicate a pair
    the gateway treats as different work — the same body sent once with E2EE
    and once without — and the second would run unpaid inside the dedup window.

    Absent headers hash as empty, so a request that sends none keeps exactly
    the key it would have had before: the binding is invisible until used.
    """
    h = hashlib.sha256()
    for name in sorted(_BOUND_REQ_HEADERS):
        h.update(name.encode())
        h.update(b"\0")
        h.update((request.headers.get(name) or "").encode())
        h.update(b"\0")
    return h.digest()


def _fwd_request_headers(request: Request, identity_id: int) -> dict:
    hdrs = {k: v for k, v in request.headers.items() if k.lower() in _FWD_REQ_HEADERS}
    # Read these through .get() — the same accessor `_bound_header_digest`
    # uses — so a client sending a header twice cannot have the digest cover
    # one value while a different one reaches the gateway, which would collide
    # two materially different requests onto a single ledger key.
    for name in _BOUND_REQ_HEADERS:
        value = request.headers.get(name)
        if value is not None:
            hdrs[name] = value
    hdrs["x-gateway-token"] = GATEWAY_API_TOKEN            # passes the gateway's api gate
    hdrs["authorization"] = f"Bearer {_tenant_bearer(identity_id)}"  # owns the receipt
    return hdrs


def _fwd_response_headers(resp: httpx.Response) -> dict:
    keep = {}
    for k, v in resp.headers.items():
        # content-type, the receipt id (verifiability), and the gateway's
        # x-e2ee-* verdict on whether the prompt was really encrypted to it.
        low = k.lower()
        if low in _FWD_RESP_HEADERS or low.startswith(_FWD_RESP_PREFIXES):
            keep[k] = v
    return keep


@app.get("/health")
async def health():
    return {"status": "ok", "wallet_auth": WALLET_CFG.enabled}


# ─── Wallet-bound auth (../docs/wallet-bound-aci.md) ─────────────────────────


def _wallet_or_501(request: Request) -> "wallet_auth.WalletAuthenticator":
    wallet = request.app.state.wallet
    if wallet is None:
        raise WalletAuthError("wallet_disabled", "wallet authentication is not enabled", status=501)
    return wallet


async def _read_body(request: Request, limit: int) -> bytes:
    """Read the request body, never holding more than `limit` bytes.

    A wallet signature covers the exact bytes, so nothing can be authenticated
    before the body is read — but the body can be refused before it is read:
    a declared Content-Length over the cap is a 413 with zero bytes consumed,
    and an undeclared (chunked) or lying length is read only up to the cap.
    Raises WalletAuthError(status=413) — `_wallet_error` renders it for API-key
    and wallet callers alike.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            n = int(declared)
        except ValueError:
            n = -1
        if n < 0:
            raise WalletAuthError("wallet_invalid_request", "invalid Content-Length", status=400)
        if n > limit:
            raise WalletAuthError(
                "request_too_large", f"request body exceeds {limit} bytes", status=413)
    chunks: list[bytes] = []
    total = 0
    stream = request.stream()
    try:
        async for chunk in stream:
            total += len(chunk)
            if total > limit:
                raise WalletAuthError(
                    "request_too_large", f"request body exceeds {limit} bytes", status=413)
            chunks.append(chunk)
    finally:
        await stream.aclose()   # bailing out mid-body must not leave the generator dangling
    return b"".join(chunks)


async def _json_body(request: Request) -> dict:
    try:
        payload = json.loads(await _read_body(request, EDGE_MAX_WALLET_BODY_BYTES) or b"{}")
    except ValueError:
        raise WalletAuthError("wallet_invalid_request", "body must be JSON") from None
    if not isinstance(payload, dict):
        raise WalletAuthError("wallet_invalid_request", "body must be a JSON object")
    return payload


@app.post("/v1/wallet/challenge")
async def wallet_challenge(request: Request):
    """Hand out a single-use nonce for a bind statement.

    Public: a nonce is worthless without the wallet's signature, and requiring
    a credential here would be circular — this is how a user with no
    credential gets one.
    """
    try:
        wallet = _wallet_or_501(request)
        payload = await _json_body(request)
        return wallet.challenge(payload.get("wallet_pub_key"))
    except WalletAuthError as exc:
        return _wallet_error(exc)


@app.post("/v1/wallet/bind")
async def wallet_bind(request: Request):
    """Verify a Falcon-signed bind statement and open a session."""
    try:
        wallet = _wallet_or_501(request)
        payload = await _json_body(request)
        statement = await wallet.verify_bind(payload.get("statement"), payload.get("signature"))
    except WalletAuthError as exc:
        return _wallet_error(exc)

    # Verified. Now (and only now) resolve the wallet to a billable identity.
    res = await request.app.state.auth.wallet_bind(
        statement["wallet_pub_key"],
        wallet.spend_credential_hash(statement["wallet_pub_key"]),
        statement.get("account_id"),
    )
    if res.status != ALLOW or res.identity_id is None:
        return _deny_response(res if res.status != ALLOW else AuthResult(
            DENY_DOWN, error="billing service returned no identity, retry later"))

    session = wallet.store.create_session(
        res.identity_id, statement, statement["scope"], wallet.now(),
    )
    out = {
        "session_id": session.session_id,
        "identity_id": session.identity_id,
        "expires_at": session.expires_at,
        "scope": list(session.scope),
        "max_spend": session.max_spend,
        "balance": res.balance,
    }
    if res.account_id_attached is not None:
        out["account_id_attached"] = res.account_id_attached
    if res.warning:
        out["warning"] = res.warning
    return out


@app.post("/v1/wallet/session/revoke")
async def wallet_session_revoke(request: Request):
    """End this session. The extension calls it when the wallet locks — and
    drops its keys either way, so a failure here costs the user nothing."""
    try:
        body = await _read_body(request, EDGE_MAX_WALLET_BODY_BYTES)
        principal = await _resolve_principal(
            request, "/v1/wallet/session/revoke", body, "inference",
        )
    except WalletAuthError as exc:
        return _wallet_error(exc)
    if principal.session is None:
        return _wallet_error(WalletAuthError(
            "wallet_required", "only a wallet session can be revoked", status=400))
    wallet = request.app.state.wallet
    return {"revoked": wallet.store.revoke_session(principal.session.session_id, wallet.now())}


@app.post("/v1/wallet/sessions/revoke-all")
async def wallet_sessions_revoke_all(request: Request):
    """Kill every session of this wallet — the lost-device button. Reachable
    from any device holding the mnemonic, since binding is all it takes."""
    try:
        body = await _read_body(request, EDGE_MAX_WALLET_BODY_BYTES)
        principal = await _resolve_principal(
            request, "/v1/wallet/sessions/revoke-all", body, "inference",
        )
    except WalletAuthError as exc:
        return _wallet_error(exc)
    if principal.session is None:
        return _wallet_error(WalletAuthError(
            "wallet_required", "only a wallet session can revoke sessions", status=400))
    wallet = request.app.state.wallet
    return {"revoked": wallet.store.revoke_all_for_wallet(
        principal.session.wallet_pub_key, wallet.now())}


@app.post("/v1/wallet/payment-intents")
async def wallet_payment_intent(request: Request):
    """Self-serve top-up for a wallet — the same intent path api-key users have.

    A wallet has no raw api key to authenticate the payment endpoint with, so
    the Edge authenticates the wallet session (Ed25519), derives the wallet's
    credential hash, and creates the intent on its behalf. Provider 'stripe'
    returns a hosted checkout `invoice_url`; 'onchain' returns the wallet
    payment instructions in `onchain`. Either receive side credits this
    wallet's identity — no wallet-specific billing code.
    """
    try:
        body = await _read_body(request, EDGE_MAX_WALLET_BODY_BYTES)
        # No spend/read scope required: funding your own balance only helps you.
        principal = await _resolve_principal(request, "/v1/wallet/payment-intents", body, None)
    except WalletAuthError as exc:
        return _wallet_error(exc)
    if principal.session is None:
        return _wallet_error(WalletAuthError(
            "wallet_required", "only a wallet session can create a wallet top-up", status=400))

    try:
        payload = json.loads(body or b"{}")
    except ValueError:
        return _wallet_error(WalletAuthError("wallet_invalid_request", "body must be JSON", status=400))
    if not isinstance(payload, dict):
        return _wallet_error(WalletAuthError("wallet_invalid_request", "body must be a JSON object", status=400))
    credits = payload.get("credits")
    if isinstance(credits, bool) or not isinstance(credits, int) or credits <= 0:
        return _wallet_error(WalletAuthError(
            "wallet_invalid_request", "credits must be a positive integer", status=400))
    provider = payload.get("provider", "stripe")
    if not isinstance(provider, str):
        return _wallet_error(WalletAuthError("wallet_invalid_request", "provider must be a string", status=400))
    # Optional: the payer's Miden account, so the ledger can build the
    # wallet payload server-side. Only its type is checked here — the
    # ledger owns the address rules and answers 400 for a bad one.
    sender_address = payload.get("sender_address")
    if sender_address is not None and (not isinstance(sender_address, str) or not sender_address):
        return _wallet_error(WalletAuthError(
            "wallet_invalid_request", "sender_address must be a non-empty string", status=400))

    intent, err = await request.app.state.auth.create_payment_intent_hashed(
        principal.credential_hash, credits, provider, sender_address=sender_address)
    if err is not None:
        return _deny_response(err)
    return intent


_MEMO_SHAPE = re.compile(r"[A-Za-z0-9._-]{1,128}")

# Ledger status → error type the SDK understands (toError reads .error.type).
_CHECKOUT_ERROR_TYPES = {
    400: "wallet_invalid_request",
    401: "unauth",
    403: "topup_not_owner",
    404: "topup_not_pending",
    409: "topup_not_pending",
    502: "auth_down",
    503: "auth_down",
}


@app.post("/v1/wallet/payment-intents/{memo}/checkout")
async def wallet_payment_intent_checkout(request: Request, memo: str):
    """Reopen an unpaid top-up's payment instructions for the wallet that
    owns it — the authenticated counterpart of the ledger's public
    /v1/payment-intents/{memo}/checkout.

    Reading instructions is public and stays so. But (re)PREPARING the
    on-chain wallet payload for a named account is a write the ledger
    only performs for the order owner: memos travel in the note
    attachment and are public on-chain, so an open write would let
    anyone drive the builder and overwrite the note id kept for
    reconciliation. The Edge proves ownership the same way it does at
    intent creation — the wallet session's derived credential hash.

    Status codes from the ledger pass through unchanged (403/404/409 mean
    things to the client); the body is reshaped to the Edge's error form.
    """
    path = f"/v1/wallet/payment-intents/{memo}/checkout"
    try:
        body = await _read_body(request, EDGE_MAX_WALLET_BODY_BYTES)
        principal = await _resolve_principal(request, path, body, None)
    except WalletAuthError as exc:
        return _wallet_error(exc)
    if principal.session is None:
        return _wallet_error(WalletAuthError(
            "wallet_required", "only a wallet session can reopen a wallet top-up", status=400))
    if not _MEMO_SHAPE.fullmatch(memo):
        return _wallet_error(WalletAuthError("wallet_invalid_request", "invalid memo", status=400))

    try:
        payload = json.loads(body or b"{}")
    except ValueError:
        return _wallet_error(WalletAuthError("wallet_invalid_request", "body must be JSON", status=400))
    if not isinstance(payload, dict):
        return _wallet_error(WalletAuthError("wallet_invalid_request", "body must be a JSON object", status=400))
    sender_address = payload.get("sender_address")
    if sender_address is not None and (not isinstance(sender_address, str) or not sender_address):
        return _wallet_error(WalletAuthError(
            "wallet_invalid_request", "sender_address must be a non-empty string", status=400))

    status_code, data = await request.app.state.auth.checkout_payment_intent_hashed(
        principal.credential_hash, memo, sender_address)
    if 200 <= status_code < 300:
        return data
    detail = data.get("detail")
    return JSONResponse(
        status_code=status_code,
        content={"error": {
            "type": _CHECKOUT_ERROR_TYPES.get(status_code, f"http_{status_code}"),
            "message": str(detail or f"ledger returned {status_code}"),
        }},
    )


@app.get("/v1/wallet/balance")
async def wallet_balance(request: Request):
    """Current credit balance for the authenticated wallet.

    A signed READ — one Ed25519-signed GET, no Falcon and no re-bind — so a page
    can refresh the balance after a top-up without reconnecting the wallet.
    """
    try:
        principal = await _resolve_principal(request, "/v1/wallet/balance", b"", None)
    except WalletAuthError as exc:
        return _wallet_error(exc)
    res = await request.app.state.auth.validate_hashed(principal.credential_hash)
    if res.status in (DENY_UNAUTH, DENY_DOWN):   # ALLOW and DENY_NO_BALANCE both carry a balance
        return _deny_response(res)
    return {"balance": res.balance, "identity_id": res.identity_id}


async def _metered_proxy(request: Request, path: str) -> Response:
    # Body first: a wallet signature covers the exact bytes, so it cannot be
    # checked before they are read. Capped: an oversized body is a 413 here,
    # before any auth call, spend-cap booking or ledger debit — the gateway
    # would refuse it anyway, so nothing is booked only to be refunded.
    try:
        body = await _read_body(request, EDGE_MAX_BODY_BYTES)
        principal = await _resolve_principal(request, path, body, "inference")
    except WalletAuthError as exc:
        return _wallet_error(exc)

    # Idempotency is OPT-IN (the client's own `Idempotency-Key`) AND bound to
    # the body. Both halves are load-bearing:
    #   opt-in     — deriving the key from content alone would make every
    #                re-send of the same prompt a free replay.
    #   body-bound — a key covering only the path is a billing bypass: the
    #                ledger debits once for `Idempotency-Key: k`, and every
    #                later request carrying k is deduplicated (no debit) yet
    #                still forwarded, so an arbitrary NEW prompt runs free
    #                until the dedup window expires.
    # The same argument covers the headers we forward that steer the gateway
    # (_BOUND_REQ_HEADERS), which is why the digest includes them: identical
    # bytes asking for E2EE and asking for plaintext are different work.
    # A retry the client means as a retry re-sends the same bytes AND the same
    # steering headers; anything else is new, billable work with its own ledger
    # key. (auth-service scopes the key per identity, so two users sending
    # identical bodies never collide.)
    client_idem = request.headers.get("idempotency-key", "").strip()
    idem = ("edge:" + hashlib.sha256(
        path.encode() + b"\0" + client_idem.encode()
        + b"\0" + hashlib.sha256(body).digest()
        + b"\0" + _bound_header_digest(request)).hexdigest()
        if client_idem else "edge:once:" + secrets.token_hex(16))

    # Book the request against the spend cap the wallet signed BEFORE debiting
    # the ledger: the cap is the user's own authorization, and a request that
    # exceeds it must not cost them anything.
    if principal.session is not None:
        try:
            request.app.state.wallet.store.charge(
                principal.session.session_id, WALLET_REQUEST_COST,
                request.app.state.wallet.now(),
            )
        except WalletAuthError as exc:
            return _wallet_error(exc)

    released = False
    debited = False                       # a real ledger debit happened
    debit_token: Optional[str] = None

    async def _release(reason: str) -> None:
        """Undo everything this request booked. The ledger refund and the
        session cap are separate books; a failure must reverse both."""
        nonlocal released
        if released:
            return
        released = True
        if debited:
            await request.app.state.auth.refund_hashed(
                principal.credential_hash, debit_token, reason)
        if principal.session is not None:
            request.app.state.wallet.store.uncharge(
                principal.session.session_id, WALLET_REQUEST_COST,
            )

    try:
        res = await request.app.state.auth.consume_hashed(principal.credential_hash, idem)
        if res.status != ALLOW:
            # No debit happened; _release only returns the session hold.
            await _release(f"consume_denied:{res.status}")
            return _deny_response(res)
        debited, debit_token = True, res.debit_token
        if res.identity_id is None:
            # Ledger allowed the debit but did not say WHO — without an identity
            # we cannot assign receipt ownership. Fail closed and give it back.
            await _release("auth_missing_identity")
            return JSONResponse(status_code=503, content={"error": {
                "message": "billing service returned no identity, retry later", "type": DENY_DOWN}})

        # Forward to the gateway: service token + this user's tenant bearer, streaming.
        gw: httpx.AsyncClient = request.app.state.gw
        req = gw.build_request("POST", f"{GATEWAY_URL}{path}",
                               headers=_fwd_request_headers(request, res.identity_id), content=body)
        try:
            resp = await gw.send(req, stream=True)
        except httpx.RequestError as e:
            await _release(f"gateway_unreachable:{e}")
            return JSONResponse(status_code=502, content={"error": {"message": "gateway unreachable", "type": "gateway"}})

        try:
            if resp.status_code >= 400:
                # Gateway rejected (e.g. upstream 404/429). Refund and surface the error.
                err_body = await resp.aread()
                await resp.aclose()
                await _release(f"gateway_status:{resp.status_code}")
                return Response(content=err_body, status_code=resp.status_code, headers=_fwd_response_headers(resp))
        except BaseException:
            # aread/aclose died (gateway sent headers then stalled or dropped
            # the socket). Close our half; the outer envelope releases.
            await resp.aclose()
            raise

        async def _stream():
            # aiter_bytes (not aiter_raw): yields decoded chunks and we deliberately
            # do NOT forward content-encoding, so the client gets a coherent body.
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            finally:
                await resp.aclose()

        return StreamingResponse(_stream(), status_code=resp.status_code, headers=_fwd_response_headers(resp))
    except BaseException as e:
        # The unanticipated exits: CancelledError (client hung up mid-flight),
        # JSON decode of a malformed ledger reply, anything else. Shield the
        # release so a second cancellation cannot kill the refund mid-flight,
        # then let the original exception continue.
        await asyncio.shield(_release(f"unexpected:{type(e).__name__}"))
        raise


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    return await _metered_proxy(request, "/v1/chat/completions")


@app.post("/v1/completions")
async def completions(request: Request):
    return await _metered_proxy(request, "/v1/completions")


@app.post("/v1/embeddings")
async def embeddings(request: Request):
    return await _metered_proxy(request, "/v1/embeddings")


@app.get("/v1/models")
async def models(request: Request):
    try:
        principal = await _resolve_principal(request, "/v1/models", b"", "models")
    except WalletAuthError as exc:
        return _wallet_error(exc)
    res = await request.app.state.auth.validate_hashed(principal.credential_hash)
    if res.status in (DENY_UNAUTH, DENY_DOWN):   # allow DENY_NO_BALANCE (known key, empty)
        return _deny_response(res)
    gw: httpx.AsyncClient = request.app.state.gw
    try:
        r = await gw.get(f"{GATEWAY_URL}/v1/models", headers={"authorization": f"Bearer {GATEWAY_API_TOKEN}"})
    except httpx.RequestError:
        return JSONResponse(status_code=502, content={"error": {"message": "gateway unreachable", "type": "gateway"}})
    # Decorate a successful list with per-model `input_modalities` (see
    # MODEL_INPUT_MODALITIES); errors and odd bodies pass through untouched.
    content = _annotate_models(r.content) if r.status_code == 200 else r.content
    headers = _fwd_response_headers(r)
    headers.pop("content-length", None)   # body may have grown
    return Response(content=content, status_code=r.status_code, headers=headers)


@app.api_route("/v1/attestation/report", methods=["GET"])
async def attestation_report(request: Request):
    # Public passthrough so any user can still verify the workload — no debit.
    gw: httpx.AsyncClient = request.app.state.gw
    url = f"{GATEWAY_URL}/v1/attestation/report"
    if request.url.query:
        url += f"?{request.url.query}"
    r = await gw.get(url)
    return Response(content=r.content, status_code=r.status_code, headers=_fwd_response_headers(r))


@app.get("/v1/aci/receipts/{receipt_id}")
async def receipt(request: Request, receipt_id: str):
    # Receipts at the gateway are owned by the tenant bearer used at chat
    # time, so we must present the SAME derived bearer here. A known key with
    # an empty balance may still read receipts for requests it already paid
    # for (validate is read-only, no debit).
    try:
        principal = await _resolve_principal(
            request, f"/v1/aci/receipts/{receipt_id}", b"", "receipts",
        )
    except WalletAuthError as exc:
        return _wallet_error(exc)
    res = await request.app.state.auth.validate_hashed(principal.credential_hash)
    if res.status not in (ALLOW, DENY_NO_BALANCE):
        return _deny_response(res)
    if res.identity_id is None:
        return JSONResponse(status_code=503, content={"error": {
            "message": "billing service returned no identity, retry later", "type": DENY_DOWN}})
    gw: httpx.AsyncClient = request.app.state.gw
    r = await gw.get(
        f"{GATEWAY_URL}/v1/aci/receipts/{receipt_id}",
        headers={"authorization": f"Bearer {_tenant_bearer(res.identity_id)}"},
    )
    return Response(content=r.content, status_code=r.status_code, headers=_fwd_response_headers(r))
