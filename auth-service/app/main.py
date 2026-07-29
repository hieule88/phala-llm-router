"""FastAPI app exposing the auth service over HTTP.

Thin HTTP layer over `handlers.py` — keep validation here and let the
business logic stay in handlers so tests can exercise it without a server.

Endpoints under `/v1`:
  POST /v1/identities                     → create identity + first credential (ADMIN)
  POST /v1/credentials                    → add another credential to an identity (ADMIN)
  POST /v1/credentials/revoke             → revoke a credential (ADMIN)
  POST /v1/validate                       → check credential has balance (no debit)
  POST /v1/consume                        → atomic debit of 1 credit (proxy token)
  POST /v1/refund                         → reverse a prior consume (TEE proxy on crash)
  POST /v1/topup                          → credit a balance (ADMIN, payment layer)
  POST /v1/tier                           → change an identity's tier (ADMIN)
  POST /v1/payment-intents                → create intent (auth: api_key)
  GET  /v1/payment-intents/{memo}         → check intent status (public, opaque memo)
  POST /v1/payment-intents/{memo}/mark-paid → finalize intent (ADMIN or webhook)
  POST /v1/payment-intents/{memo}/cancel  → cancel pending intent (ADMIN)
  POST /v1/webhooks/stripe                → Stripe payment events (HMAC-authenticated)
  POST /v1/webhooks/nowpayments           → NOWPayments IPN (HMAC-SHA512-authenticated)
  GET  /health                            → liveness probe (no DB hit)

Auth model:
  - Admin endpoints require `Authorization: Bearer <ADMIN_TOKEN>`. Compared
    with `hmac.compare_digest` so timing side channels can't extract it.
  - `validate` (read-only, no debit) stays unauthenticated: the api_key
    hash IS the credential, and the worst a leaked hash allows here is
    reading a balance.
  - `consume` DEBITS, so it is gated by the proxy token (require_proxy_token:
    PROXY_REFUND_TOKEN or ADMIN_TOKEN). The api_key hash is semi-public
    (users share it over chat/email), so an open consume would let anyone
    who learned a victim's hash drain their balance — only the TEE proxy,
    which holds the token, may debit.
  - The Stripe webhook is authenticated by Stripe's HMAC signature — no
    Bearer token is expected because the caller is Stripe's infra.
"""

import hmac
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from . import handlers, nowpayments_client, nowpayments_webhook, stripe_webhook
from .db import init_db
from .tier_limit import TierRateLimiter


# Per-identity rate limiter shared across consume/validate. Complements
# the IP-based slowapi limit: a busy TEE proxy fronting many users looks
# like ONE source IP to us, so a purely IP-based limit lets one loud
# user starve every co-tenant behind that same TEE.
tier_limiter = TierRateLimiter()


ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# Shared secret between the TEE proxy and this service that gates BOTH
# /v1/consume (the per-prove debit) and /v1/refund (crash-recovery
# reversal). Only the TEE proxy holds it. Consume must be gated because the
# api_key hash is semi-public (users share it over chat/email); without the
# token anyone who learned a victim's hash could POST /v1/consume and drain
# the balance. Refund must be gated so a client can't drain-and-refund
# forever. Different from ADMIN_TOKEN so a compromised TEE image can't also
# topup / create identities.
PROXY_REFUND_TOKEN = os.getenv("PROXY_REFUND_TOKEN", "")

# Refuse to start with a token that's trivially brute-forceable. This many
# hex chars is what `openssl rand -hex 16` produces (128 bits of entropy);
# raising the floor prevents an operator from accidentally shipping
# ADMIN_TOKEN="admin" and having the rate limit be the only defence.
MIN_ADMIN_TOKEN_LEN = 32

if ADMIN_TOKEN and len(ADMIN_TOKEN) < MIN_ADMIN_TOKEN_LEN:
    raise RuntimeError(
        f"ADMIN_TOKEN is set but shorter than {MIN_ADMIN_TOKEN_LEN} chars; "
        "use `openssl rand -hex 32` for a secure value",
    )
if PROXY_REFUND_TOKEN and len(PROXY_REFUND_TOKEN) < MIN_ADMIN_TOKEN_LEN:
    raise RuntimeError(
        f"PROXY_REFUND_TOKEN is set but shorter than {MIN_ADMIN_TOKEN_LEN} chars; "
        "use `openssl rand -hex 32` for a secure value",
    )

# Per-IP rate limits. Overridable via env for load tests. Consume/validate
# get the higher tier because a single TEE proxy handles many end-users
# from one source IP.
RATE_LIMIT_CONSUME = os.getenv("RATE_LIMIT_CONSUME", "60/minute")
RATE_LIMIT_VALIDATE = os.getenv("RATE_LIMIT_VALIDATE", "120/minute")
RATE_LIMIT_ADMIN = os.getenv("RATE_LIMIT_ADMIN", "30/minute")
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "20/minute")
# Payment processor retries are aggressive; a rate-limit-driven drop of
# a paid event is a revenue bug. Keep these ceilings well above any
# plausible retry burst. Shared across Stripe / NOWPayments / any future
# processor that hits its own endpoint.
RATE_LIMIT_STRIPE_WEBHOOK = os.getenv("RATE_LIMIT_STRIPE_WEBHOOK", "600/minute")
RATE_LIMIT_NOWPAYMENTS_WEBHOOK = os.getenv("RATE_LIMIT_NOWPAYMENTS_WEBHOOK", "600/minute")

# Hard cap on webhook body size, applied at Content-Length inspection time
# so an attacker announcing a huge payload never triggers a full-body read.
# Real Stripe/NOWPayments events fit in a few kilobytes; 64KB gives comfortable
# headroom for future event shapes.
WEBHOOK_MAX_BODY_BYTES = int(os.getenv("WEBHOOK_MAX_BODY_BYTES", str(64 * 1024)))


async def _read_bounded_body(request: Request, max_bytes: int) -> bytes:
    """Body reader that refuses payloads over the configured cap.

    Checks Content-Length first (cheap 413 on obviously-huge requests)
    then streams the body and 413s again as soon as accumulated size
    crosses the threshold. Streaming ensures a client that omits or
    lies about Content-Length still can't force us to buffer arbitrary
    bytes into RAM.
    """
    cl_raw = request.headers.get("content-length")
    if cl_raw is not None:
        try:
            if int(cl_raw) > max_bytes:
                raise HTTPException(status_code=413, detail="request body too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid content-length")
    total = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    return b"".join(chunks)

# We trust ONLY the X-Real-IP header set explicitly by Caddy (see the
# `header_up X-Real-IP {remote_host}` directive in Caddyfile). We do NOT
# split X-Forwarded-For: Caddy appends to XFF rather than overwriting it,
# so a client-supplied "X-Forwarded-For: 1.2.3.4" reaches us as
# "1.2.3.4, <real>". Reading either the first or last entry lets the
# attacker rotate keys and defeat per-IP rate limits.
def _client_key(request: Request) -> str:
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return get_remote_address(request)


limiter = Limiter(key_func=_client_key, default_limits=[RATE_LIMIT_DEFAULT])


def require_admin(authorization: str | None = Header(default=None)):
    """Bearer-token guard for admin endpoints. Boots MUST set ADMIN_TOKEN
    to a non-empty value or every admin call is refused (fail-closed on
    misconfiguration)."""
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ADMIN_TOKEN not configured on server",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="invalid admin token")


def require_proxy_token(authorization: str | None = Header(default=None)):
    """Gate on the TEE-proxy-only endpoints (/v1/consume and /v1/refund) —
    accepts EITHER PROXY_REFUND_TOKEN (the TEE proxy's own secret) OR
    ADMIN_TOKEN (ops manual action). Refuses if neither token is configured,
    so an unset env can't leave these endpoints accidentally open.

    Consume is gated because the api_key hash is semi-public; refund because
    a client who could self-refund would drain-and-retry for free proofs.
    Both are legitimately only ever called by the TEE proxy."""
    if not PROXY_REFUND_TOKEN and not ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="proxy token not configured on server",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
    if PROXY_REFUND_TOKEN and hmac.compare_digest(token, PROXY_REFUND_TOKEN):
        return
    if ADMIN_TOKEN and hmac.compare_digest(token, ADMIN_TOKEN):
        return
    raise HTTPException(status_code=401, detail="invalid proxy token")


# ─── Pydantic request models ──────────────────────────────────────────────


class CreateIdentityRequest(BaseModel):
    credential_type: str = Field(..., examples=["api_key", "miden_wallet"])
    credential_value: str = Field(...,
        description="For secret credentials (api_key) this should be the hash, "
                    "not the raw value. For public identifiers (miden_wallet, "
                    "stripe_customer_id) the raw value is fine.")
    initial_tier: str = Field("free", examples=["free", "starter", "pro"])


class AddCredentialRequest(BaseModel):
    identity_id: int
    credential_type: str
    credential_value: str


class RevokeCredentialRequest(BaseModel):
    credential_type: str
    credential_value: str


class ValidateRequest(BaseModel):
    credential_type: str
    credential_value: str


class ConsumeRequest(BaseModel):
    credential_type: str
    credential_value: str
    request_id: str | None = Field(None,
        description="Optional correlation ID (TEE proxy's request_id).")
    idempotency_key: str | None = Field(None,
        description="Deterministic client-side hash of the prove request. "
                    "Same key on the same identity returns cached balance "
                    "without debiting a second time.")


class RefundRequest(BaseModel):
    credential_type: str
    credential_value: str
    idempotency_key: str = Field(..., min_length=1,
        description="The same key the failed consume was recorded under.")
    reason: str = Field("", description="Free-form audit note.")


class TopupRequest(BaseModel):
    identity_id: int
    amount: int = Field(..., gt=0)
    source: str = Field(..., description="Provenance tag, e.g. 'stripe_session_X'.")


class SetTierRequest(BaseModel):
    identity_id: int
    tier: str


class CreatePaymentIntentRequest(BaseModel):
    credential_type: str
    credential_value: str
    credits: int = Field(..., gt=0)
    provider: str = Field("manual",
        description="'manual', 'stripe', 'nowpayments', or 'onchain'. "
                    "amount_cents is derived server-side from credits × CENTS_PER_CREDIT.")


class MarkIntentPaidRequest(BaseModel):
    provider_ref: Optional[str] = Field(None,
        description="External reference for audit (bank tx id, Stripe session, etc.).")
    actual_amount_cents: Optional[int] = Field(None, gt=0,
        description="If provided, must be >= intent's expected amount_cents.")


# ─── Lifespan: open DB once at startup, close on shutdown ─────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = await init_db()
    app.state.db = conn
    try:
        yield
    finally:
        await conn.close()


app = FastAPI(title="Miden TEE auth-service", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ─── Endpoints ────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    """Liveness + shallow readiness probe.

    Reads a single COUNT so a monitor can detect an AUTH_DB_PATH-typo
    outage where the container boots against a fresh empty DB. Alert
    on `db_identity_count` dropping to 0 (or by >50%) between polls.
    Still cheap enough to hit every 30s — one indexed SELECT.
    """
    try:
        cur = await app.state.db.execute("SELECT COUNT(*) FROM identities")
        row = await cur.fetchone()
        identity_count = row[0] if row else 0
    except Exception as e:
        return {"status": "degraded", "db_error": str(e)}
    return {
        "status": "ok",
        "db_identity_count": identity_count,
    }


@app.post("/v1/identities", status_code=201, dependencies=[Depends(require_admin)])
@limiter.limit(RATE_LIMIT_ADMIN)
async def create_identity(request: Request, req: CreateIdentityRequest):
    identity_id = await handlers.create_identity(
        app.state.db, req.credential_type, req.credential_value, req.initial_tier,
    )
    return {"identity_id": identity_id}


@app.post("/v1/credentials", status_code=201, dependencies=[Depends(require_admin)])
@limiter.limit(RATE_LIMIT_ADMIN)
async def add_credential(request: Request, req: AddCredentialRequest):
    result = await handlers.add_credential(
        app.state.db, req.identity_id, req.credential_type, req.credential_value,
    )
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "add credential failed"))
    return result


@app.post("/v1/credentials/revoke", dependencies=[Depends(require_admin)])
@limiter.limit(RATE_LIMIT_ADMIN)
async def revoke_credential(request: Request, req: RevokeCredentialRequest):
    result = await handlers.revoke_credential(
        app.state.db, req.credential_type, req.credential_value,
    )
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "revoke failed"))
    return result


@app.post("/v1/validate")
@limiter.limit(RATE_LIMIT_VALIDATE)
async def validate(request: Request, req: ValidateRequest):
    result = await handlers.validate(
        app.state.db, req.credential_type, req.credential_value,
    )
    # Always return 200 — the body says valid: true/false. This matches how
    # the TEE proxy distinguishes "credential not found" from "auth service
    # is down" (the former is a 200 with valid=false, the latter is 5xx).
    return result


@app.post("/v1/consume", dependencies=[Depends(require_proxy_token)])
@limiter.limit(RATE_LIMIT_CONSUME)
async def consume(request: Request, req: ConsumeRequest):
    # Per-identity rate limit — applies to genuinely new debits only.
    # Idempotent replays skip the limit because they're not new work
    # (a network hiccup causing a retry shouldn't burn a legit user's
    # quota). Resolving identity is cheap; the check happens BEFORE
    # the DB write path so a rate-storm can't monopolise writes.
    if req.credential_type in handlers.AUTHENTICATOR_CREDENTIAL_TYPES:
        identity_id = await handlers.lookup_identity(
            app.state.db, req.credential_type, req.credential_value,
        )
        if identity_id is not None:
            already_debited = False
            if req.idempotency_key:
                cur = await app.state.db.execute(
                    "SELECT 1 FROM consume_dedup "
                    "WHERE identity_id = ? AND idempotency_key = ?",
                    (identity_id, req.idempotency_key),
                )
                already_debited = await cur.fetchone() is not None

            if not already_debited:
                bal = await handlers.get_balance(app.state.db, identity_id)
                tier = bal["tier"] if bal else "free"
                allowed = await tier_limiter.check(identity_id, tier)
                if not allowed:
                    raise HTTPException(
                        status_code=429,
                        detail=f"rate limit exceeded for identity (tier={tier})",
                    )
    return await handlers.consume(
        app.state.db, req.credential_type, req.credential_value,
        request_id=req.request_id, idempotency_key=req.idempotency_key,
    )


@app.post("/v1/refund", dependencies=[Depends(require_proxy_token)])
@limiter.limit(RATE_LIMIT_CONSUME)
async def refund(request: Request, req: RefundRequest):
    """Reverse a prior consume identified by (credential, idempotency_key).

    Gated by PROXY_REFUND_TOKEN (TEE proxy's crash-recovery path) or
    ADMIN_TOKEN (manual ops reversal) — NOT by knowledge of the api_key
    hash, because a paying user knows their own hash + can compute the
    deterministic idempotency_key from their own tx inputs and would then
    refund-and-retry to unlimited free proofs.
    """
    result = await handlers.refund(
        app.state.db, req.credential_type, req.credential_value,
        req.idempotency_key, req.reason,
    )
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "refund failed"))
    return result


@app.post("/v1/topup", dependencies=[Depends(require_admin)])
@limiter.limit(RATE_LIMIT_ADMIN)
async def topup(request: Request, req: TopupRequest):
    result = await handlers.topup(
        app.state.db, req.identity_id, req.amount, req.source,
    )
    if not result.get("success"):
        # 404 for unknown identity (more useful to caller than 200+success=false)
        raise HTTPException(status_code=404, detail=result.get("error", "topup failed"))
    return result


@app.post("/v1/tier", dependencies=[Depends(require_admin)])
@limiter.limit(RATE_LIMIT_ADMIN)
async def set_tier(request: Request, req: SetTierRequest):
    result = await handlers.set_tier(app.state.db, req.identity_id, req.tier)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "tier change failed"))
    return result


@app.post("/v1/payment-intents", status_code=201)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def create_payment_intent(request: Request, req: CreatePaymentIntentRequest):
    """User-facing: create a payment intent for a specific credit amount.

    Authenticated by the caller's api_key hash — public identifiers
    like miden_wallet / stripe_customer_id are refused here because
    they'd let anyone who learns Alice's public address create intents
    bound to Alice's identity. The returned `memo` is the reference
    the user must include when they actually pay.

    When `provider == "nowpayments"`, we also call NOWPayments'
    invoice API and return a hosted-checkout `invoice_url` alongside
    the memo. NOWPayments failure does NOT roll back the intent — the
    intent row is committed either way, and the caller can retry the
    checkout-URL step via /v1/payment-intents/{memo}/checkout.
    """
    if req.credential_type not in handlers.AUTHENTICATOR_CREDENTIAL_TYPES:
        raise HTTPException(status_code=401, detail="invalid credential")
    identity_id = await handlers.lookup_identity(
        app.state.db, req.credential_type, req.credential_value,
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid credential")
    result = await handlers.create_intent(
        app.state.db, identity_id, req.credits, req.provider,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "create intent failed"))

    if req.provider == "nowpayments":
        try:
            invoice = await nowpayments_client.create_invoice(
                memo=result["memo"],
                amount_cents=result["amount_cents"],
            )
            result["invoice_url"] = invoice["invoice_url"]
            result["invoice_id"] = invoice["invoice_id"]
        except nowpayments_client.NowpaymentsError as e:
            # Intent is committed; downstream provider failed. Report
            # via a soft warning field so the client can decide to retry
            # checkout without recreating the intent.
            result["checkout_error"] = e.detail
    return result


class CheckoutRequest(BaseModel):
    provider: str = Field("nowpayments",
        description="Currently only 'nowpayments' is supported for on-demand checkout.")


@app.post("/v1/payment-intents/{memo}/checkout")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def create_checkout_for_intent(request: Request, memo: str, req: CheckoutRequest):
    """Retry-friendly checkout-URL creation for an existing pending intent.

    Called by a client that either got a checkout_error at intent-create
    time, or wants to switch payment providers on a still-pending intent.
    Does NOT authenticate on api_key — anyone with the memo can request
    a checkout URL for it. That is safe: paying the URL always credits
    the intent's original identity, which was fixed at intent-create.
    """
    intent = await handlers.get_intent_by_memo(app.state.db, memo)
    if intent is None:
        raise HTTPException(status_code=404, detail="intent not found")
    if intent["status"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"intent is {intent['status']}, cannot create checkout",
        )
    if req.provider != "nowpayments":
        raise HTTPException(status_code=400, detail=f"unsupported provider: {req.provider!r}")
    try:
        invoice = await nowpayments_client.create_invoice(
            memo=intent["memo"],
            amount_cents=intent["amount_cents"],
        )
    except nowpayments_client.NowpaymentsError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from None
    return {
        "memo": intent["memo"],
        "invoice_url": invoice["invoice_url"],
        "invoice_id": invoice["invoice_id"],
        "amount_cents": intent["amount_cents"],
        "credits": intent["credits"],
    }


@app.get("/v1/payment-intents/{memo}")
@limiter.limit(RATE_LIMIT_VALIDATE)
async def get_payment_intent(request: Request, memo: str):
    """Publicly readable — the memo is opaque BUT it travels in payment
    channels that leak it (bank memo fields, on-chain calldata, Stripe
    metadata). We return only the fields the caller needs to poll the
    payment status — identity_id, provider_ref, and other internal
    fields are only exposed via authenticated endpoints (not yet built).
    """
    intent = await handlers.get_intent_by_memo(app.state.db, memo)
    if intent is None:
        raise HTTPException(status_code=404, detail="intent not found")
    return {
        "memo": intent["memo"],
        "status": intent["status"],
        "credits": intent["credits"],
        "amount_cents": intent["amount_cents"],
        "expires_at": intent.get("expires_at"),
    }


@app.post(
    "/v1/payment-intents/{memo}/mark-paid",
    dependencies=[Depends(require_admin)],
)
@limiter.limit(RATE_LIMIT_ADMIN)
async def mark_payment_intent_paid(
    request: Request, memo: str, req: MarkIntentPaidRequest,
):
    """Admin-gated finalisation. Provider webhooks that also want to
    finalise an intent should call `handlers.mark_paid_by_memo` after
    verifying their own signature, rather than hitting this endpoint
    with ADMIN_TOKEN."""
    result = await handlers.mark_paid_by_memo(
        app.state.db, memo, req.provider_ref, req.actual_amount_cents,
    )
    if not result.get("success"):
        status_code = 404 if "not found" in result.get("error", "") else 400
        raise HTTPException(status_code=status_code, detail=result.get("error", "mark-paid failed"))
    return result


@app.post(
    "/v1/payment-intents/{memo}/cancel",
    dependencies=[Depends(require_admin)],
)
@limiter.limit(RATE_LIMIT_ADMIN)
async def cancel_payment_intent(request: Request, memo: str):
    result = await handlers.cancel_intent_by_memo(app.state.db, memo)
    if not result.get("success"):
        status_code = 404 if "not found" in result.get("error", "") else 400
        raise HTTPException(status_code=status_code, detail=result.get("error", "cancel failed"))
    return result


@app.post("/v1/webhooks/stripe")
@limiter.limit(RATE_LIMIT_STRIPE_WEBHOOK)
async def stripe_webhook_endpoint(request: Request):
    """Stripe webhook receiver.

    Authenticated by the Stripe-Signature header (HMAC over the raw body)
    rather than by ADMIN_TOKEN — the caller is Stripe's infrastructure.
    We ACK with 200 on any event we chose not to act on so Stripe stops
    retrying; only signature failures / malformed events / handler errors
    return 4xx/5xx.
    """
    raw_body = await _read_bounded_body(request, WEBHOOK_MAX_BODY_BYTES)
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe_webhook.verify_and_parse(raw_body, sig)
        return await stripe_webhook.dispatch(app.state.db, event)
    except stripe_webhook.WebhookError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from None


@app.post("/v1/webhooks/nowpayments")
@limiter.limit(RATE_LIMIT_NOWPAYMENTS_WEBHOOK)
async def nowpayments_webhook_endpoint(request: Request):
    """NOWPayments IPN receiver.

    Authenticated by the x-nowpayments-sig header (HMAC-SHA512 over the
    canonical JSON body). Only `payment_status == "finished"` credits
    the balance; every other status is ACK'd so retries stop.
    """
    raw_body = await _read_bounded_body(request, WEBHOOK_MAX_BODY_BYTES)
    sig = request.headers.get("x-nowpayments-sig")
    try:
        payload = nowpayments_webhook.verify_and_parse(raw_body, sig)
        return await nowpayments_webhook.dispatch(app.state.db, payload)
    except nowpayments_webhook.WebhookError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from None
