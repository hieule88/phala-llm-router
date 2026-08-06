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

Endpoints (OpenAI-compatible):
  POST /v1/chat/completions | /v1/completions | /v1/embeddings  -> metered (1 credit)
  GET  /v1/models                                               -> requires a valid key, no debit
  GET  /v1/aci/receipts/{id}   -> requires a valid key; only the receipt's owner gets it
  GET  /v1/attestation/report  -> public passthrough (verifiability)
  GET  /health
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

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
GATEWAY_TIMEOUT_SEC = float(os.getenv("GATEWAY_TIMEOUT_SEC", "600.0"))

# Secret behind the per-user tenant bearers. Receipts at the gateway are owned
# by SHA256(tenant bearer); anyone who can derive a user's bearer can read
# that user's receipts, so this must stay as private as the api tokens.
# Rotating it orphans receipts issued under the old bearers (they stay owned
# by the old digest) — rotate only with that in mind.
EDGE_TENANT_SECRET = os.getenv("EDGE_TENANT_SECRET", "")

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


class AuthClient:
    """Calls the Leviathan auth-service. `consume` debits atomically (never
    cached); mirrors the TEE proxy's gate so the Edge reuses the same ledger."""

    def __init__(self) -> None:
        self._c = httpx.AsyncClient(timeout=AUTH_SERVICE_TIMEOUT_SEC, verify=AUTH_SERVICE_VERIFY_TLS)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    async def consume(self, raw_key: str, idempotency_key: str) -> AuthResult:
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/consume",
                json={
                    "credential_type": "api_key",
                    "credential_value": self.hash_key(raw_key),
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

    async def refund(self, raw_key: str, debit_token: Optional[str], reason: str) -> None:
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
                    "credential_value": self.hash_key(raw_key),
                    "debit_token": debit_token,
                    "reason": reason,
                },
                headers={"Authorization": f"Bearer {AUTH_SERVICE_PROXY_TOKEN}"},
            )
        except httpx.RequestError:
            pass  # refund miss is logged upstream; don't mask the original error

    async def validate(self, raw_key: str) -> AuthResult:
        # Read-only: is this a known credential (with balance)? Used by /v1/models.
        # The proxy token is not required here (validate is public) — it tells
        # auth-service these calls come from the Edge, which relays every tenant
        # from one IP, so it buckets them per credential instead of collapsing
        # the whole deployment into one per-IP rate limit.
        try:
            r = await self._c.post(
                f"{AUTH_SERVICE_URL}/v1/validate",
                json={"credential_type": "api_key", "credential_value": self.hash_key(raw_key)},
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


# ─── App ─────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.auth = AuthClient()
    app.state.gw = httpx.AsyncClient(timeout=GATEWAY_TIMEOUT_SEC)
    try:
        yield
    finally:
        await app.state.auth._c.aclose()
        await app.state.gw.aclose()


app = FastAPI(title="Leviathan AI Edge", lifespan=lifespan)


def _bearer(request: Request) -> Optional[str]:
    h = request.headers.get("authorization", "")
    for pfx in ("Bearer ", "bearer "):
        if h.startswith(pfx):
            return h[len(pfx):].strip()
    return None


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
    return {"status": "ok"}


async def _metered_proxy(request: Request, path: str) -> Response:
    raw_key = _bearer(request)
    if not raw_key:
        return JSONResponse(status_code=401, content={"error": {"message": "api key required", "type": "unauth"}})

    body = await request.body()
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

    res = await request.app.state.auth.consume(raw_key, idem)
    if res.status != ALLOW:
        return _deny_response(res)
    if res.identity_id is None:
        # Ledger allowed the debit but did not say WHO — without an identity
        # we cannot assign receipt ownership. Fail closed and give it back.
        await request.app.state.auth.refund(raw_key, res.debit_token, "auth_missing_identity")
        return JSONResponse(status_code=503, content={"error": {
            "message": "billing service returned no identity, retry later", "type": DENY_DOWN}})

    # Forward to the gateway: service token + this user's tenant bearer, streaming.
    gw: httpx.AsyncClient = request.app.state.gw
    req = gw.build_request("POST", f"{GATEWAY_URL}{path}",
                           headers=_fwd_request_headers(request, res.identity_id), content=body)
    try:
        resp = await gw.send(req, stream=True)
    except httpx.RequestError as e:
        await request.app.state.auth.refund(raw_key, res.debit_token, f"gateway_unreachable:{e}")
        return JSONResponse(status_code=502, content={"error": {"message": "gateway unreachable", "type": "gateway"}})

    if resp.status_code >= 400:
        # Gateway rejected (e.g. upstream 404/429). Refund and surface the error.
        err_body = await resp.aread()
        await resp.aclose()
        await request.app.state.auth.refund(raw_key, res.debit_token, f"gateway_status:{resp.status_code}")
        return Response(content=err_body, status_code=resp.status_code, headers=_fwd_response_headers(resp))

    async def _stream():
        # aiter_bytes (not aiter_raw): yields decoded chunks and we deliberately
        # do NOT forward content-encoding, so the client gets a coherent body.
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()

    return StreamingResponse(_stream(), status_code=resp.status_code, headers=_fwd_response_headers(resp))


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
    raw_key = _bearer(request)
    if not raw_key:
        return JSONResponse(status_code=401, content={"error": {"message": "api key required", "type": "unauth"}})
    res = await request.app.state.auth.validate(raw_key)
    if res.status in (DENY_UNAUTH, DENY_DOWN):   # allow DENY_NO_BALANCE (known key, empty)
        return _deny_response(res)
    gw: httpx.AsyncClient = request.app.state.gw
    try:
        r = await gw.get(f"{GATEWAY_URL}/v1/models", headers={"authorization": f"Bearer {GATEWAY_API_TOKEN}"})
    except httpx.RequestError:
        return JSONResponse(status_code=502, content={"error": {"message": "gateway unreachable", "type": "gateway"}})
    return Response(content=r.content, status_code=r.status_code, headers=_fwd_response_headers(r))


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
    raw_key = _bearer(request)
    if not raw_key:
        return JSONResponse(status_code=401, content={"error": {"message": "api key required", "type": "unauth"}})
    res = await request.app.state.auth.validate(raw_key)
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
