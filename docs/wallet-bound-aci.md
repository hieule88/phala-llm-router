# Wallet-Bound ACI — the Leviathan wallet *is* the account

> **Version:** `lev.wallet/1`
> **Status:** implemented in this repo (`ai-edge/wallet_auth.py`, `wallet-verifier/`)
> plus the Leviathan wallet extension (`src/lib/aci/`).
> **Conformance language:** MUST / SHOULD / MAY per RFC 2119.

Today a user of the Leviathan AI Edge holds an API key (`lev_...`): a bearer
secret, separate from their wallet, stored in some other place, lost when that
place is lost. This document replaces it. After this change the **Miden account
in the Leviathan wallet is the AI account**: credits, receipts and E2EE
material all hang off the wallet's key material, access is gated by the wallet
lock, and every call to the TEE is authorized by a signature the wallet
produced.

Nothing about the ACI protocol itself changes. The TEE gateway keeps seeing the
`x-gateway-token` + per-tenant bearer split it sees today
(`ai-edge/app.py`); wallet identity is resolved at the Edge and mapped onto the
same ledger identity the api-key path uses.

## 1. Why two keys, not one

The wallet's account authentication key is **Falcon-512** (post-quantum,
lattice). It signs, and that is all it does: there is no Diffie–Hellman on a
Falcon key, so it cannot be used for ACI E2EE (§7 of [aci.md](../spec/aci.md)),
and a per-request Falcon signature is ~666 bytes and needs a vault unlock and a
user confirmation each time. Using it on the hot path would make every prompt a
wallet popup.

So the design is a two-tier hierarchy — the standard "root key delegates to a
session key" shape, with both tiers derived from the *same mnemonic*:

```
BIP-39 mnemonic  (Leviathan vault; encrypted at rest, released only when unlocked)
│
└─ m/44'/0'/{0|1}'/{i}'  → Falcon-512 account key            ROOT AUTHORITY
                             │   signs the bind statement, once per session
                             │
                             └─ HKDF(info="leviathan.aci.v1|<account key>")
                                  → aci_seed
                                     ├─ HKDF(info="leviathan.aci.v1/sig")
                                     │     → Ed25519   session signing key
                                     └─ HKDF(info="leviathan.aci.v1/e2ee")
                                           → X25519    ACI E2EE key
```

Consequences that matter:

- **No separate secret to back up.** The mnemonic recovers the wallet *and* the
  AI account. There is no `lev_...` key for the user to lose or paste.
- **Lock = revoke.** The derived keys live only in the unlocked vault's memory.
  Locking the wallet destroys them; without the Ed25519 key no request can be
  signed, so the API stops answering. This is the "mở/khóa" the user asked for,
  enforced by cryptography rather than by UI state.
- **The E2EE key is a wallet key.** `X-Client-Pub-Key` on every inference is the
  wallet-derived X25519 key, so the *receipt* — which commits to the request
  bytes and headers inside the TEE — binds the inference to the wallet. That is
  the encrypted link between the TEE API and the wallet.
- **Ed25519 verifies everywhere.** Web Crypto in the extension, `cryptography`
  in the Edge, `ed25519-dalek` in the gateway. Falcon verification is needed
  exactly once per session, in one Rust service.

The session keys hang off the **account key's own secret**, not off a second HD
branch. That choice does one extra thing a parallel branch would not: an
account imported into the wallet without a mnemonic still has an AI identity,
because the only input is material the wallet already holds for that account.
HKDF is one-way and domain-separated by the account key, so the seed reveals
nothing about the Falcon secret, and two accounts of one wallet get unrelated
AI identities.

A consequence worth stating plainly: rotating an account's auth key rotates its
AI identity too. The ledger keyed that identity on `wallet_pub_key`, so a
rotated account binds as a *new* identity with a zero balance. Wallets that
support key rotation must migrate the ledger identity deliberately (attach the
new `miden_wallet` credential to the existing identity through auth-service)
rather than assume it follows.

## 2. Roles

| Component | Responsibility |
| --- | --- |
| Wallet extension | Holds the mnemonic. Derives the session keys. Signs the bind statement (Falcon, with user confirmation) and every request (Ed25519, silent). |
| **Edge** (`ai-edge/`) | Issues challenges, verifies bind statements and per-request signatures, maps a wallet to a ledger identity, meters, forwards. |
| **wallet-verifier** (`wallet-verifier/`) | Verifies one thing: an RPO/Poseidon2 Falcon-512 signature over a `Word`. Stateless, no secrets, no network egress. |
| **auth-service** | Owns the credit ledger. Gains one proxy-token-gated endpoint that gets-or-creates the identity behind a wallet public key. |
| TEE gateway | Unchanged. |

The wallet-verifier is a separate process only because Falcon-512 has no Python
implementation; keeping it stateless and secretless means it can be deployed
inside the same TEE as the gateway, which makes "who may spend my credits" a
question answered by attested code.

## 3. Canonicalization

Every signed payload is **JCS** (RFC 8785) over the object described, exactly as
in [aci.md §3](../spec/aci.md). Digests are lowercase hex. Every payload carries
an explicit `purpose` string for domain separation.

### 3.1 Hashing a statement into a Miden `Word`

Falcon in Miden signs a `Word` — four Goldilocks field elements
(p = 2^64 − 2^32 + 1), not arbitrary bytes. The statement is mapped into one
deterministically:

```text
h      = SHA-512( JCS(statement) )              # 64 bytes
f[i]   = u64_le( h[8i .. 8i+8] )  mod p         # i = 0..3
word   = [ f[0], f[1], f[2], f[3] ]
bytes  = concat( u64_le(f[i]) )                 # 32 bytes, always canonical
```

The reduction mod p is not cosmetic: an unreduced limb is not a valid field
element and `Word` deserialization rejects it. Both sides MUST reduce, and both
sides MUST compute the digest over the *same* JCS bytes — the Edge never
re-serializes the client's JSON with its own encoder, it canonicalizes the
parsed object and compares.

## 4. Binding a wallet (once per session)

### 4.1 Challenge

```http
POST /v1/wallet/challenge
{ "wallet_pub_key": "<falcon public key, lowercase hex>" }
```
```json
{ "nonce": "<64 hex chars>", "service": "https://ai.leviathan.example",
  "expires_at": 1765000300 }
```

The nonce is 32 random bytes, single-use, TTL 300 s, and is bound to the
`wallet_pub_key` that asked for it. A nonce is consumed on the first bind
attempt that references it, successful or not.

### 4.2 Bind statement

```json
{
  "purpose":         "leviathan.wallet.bind.v1",
  "service":         "https://ai.leviathan.example",
  "nonce":           "<hex from the challenge>",
  "issued_at":       1765000000,
  "expires_at":      1765086400,
  "wallet_pub_key":  "<falcon public key hex>",
  "account_id":      "mtst1q…",
  "session_pub_key": "<ed25519 public key hex>",
  "e2ee_pub_key":    "<x25519 public key hex>",
  "scope":           ["inference", "receipts"],
  "max_spend_mc":    100000
}
```

`wallet_pub_key` may be either spelling of the account key: the full
serialized Falcon `PublicKey` (897 bytes) or its 32-byte `Word` commitment —
the form a Miden keystore keys its entries by, and therefore the form the
extension has on hand. The verifier accepts both and binds the signature to
whichever was claimed. Whatever spelling a wallet first binds with becomes its
ledger identity, so a wallet MUST NOT alternate between them.

`account_id` is the bech32 Miden address. It is an **unverified claim**: the
proven identity is `wallet_pub_key`, because that is what the signature attests
to — the signature proves nothing about the address, which any wallet can put
in its statement. The Edge records it inside the signature's coverage (so a
relay cannot swap it), but it is a label only. Nothing may credit a balance
routed by this label until ownership of the address is proven (§5).

`scope` and `max_spend_mc` make a signature a **bounded grant**, not a blank
cheque: the session may spend at most `max_spend_mc` millicredits and may only
touch the listed capabilities. `expires_at` MUST be at most 24 h after
`issued_at`.

### 4.3 Bind

```http
POST /v1/wallet/bind
{ "statement": { … }, "signature": "<base64 Miden Signature serialization>" }
```

The Edge checks, in order, failing closed on the first failure:

1. `purpose`, `service`, and the field set are exactly as specified.
2. `issued_at` is within ±300 s of now; `expires_at` is in the future and
   ≤ `issued_at + 86400`; `max_spend_mc` is within the configured ceiling.
3. The nonce is live, unconsumed, and was issued to this `wallet_pub_key`.
4. `session_pub_key` and `e2ee_pub_key` are well-formed 32-byte hex, and
   `session_pub_key` is not already bound to a *different* wallet.
5. The Falcon signature verifies over the §3.1 `Word` under `wallet_pub_key`
   — via wallet-verifier, which **also checks that the public key embedded in
   the signature equals the claimed one**. (A Miden `Signature` carries its own
   `h`; verifying against that instead of the claimed key would accept any
   attacker-generated key pair.)
6. auth-service resolves the wallet to an identity (§5).

On success the Edge stores a session and answers:

```json
{ "session_id": "lev_s_<32 hex>", "identity_id": 12,
  "expires_at": 1765086400, "scope": ["inference","receipts"],
  "max_spend_mc": 100000, "balance_mc": 42000,
  "account_id_attached": true }
```

`session_id` is an opaque handle, **not a bearer credential** — see §6.
`account_id_attached` reports whether the (unverified) address label stuck;
when another identity claimed it first the bind still succeeds with
`account_id_attached: false` and a `warning` (§5).

## 5. Wallet → ledger identity

The Edge calls auth-service with its proxy token:

```http
POST /v1/wallet/bind
{ "wallet_pub_key": "<hex>", "account_id": "mtst1q…",
  "api_key_hash": "<sha256 hex>" }
→ { "identity_id": 12, "created": false, "balance": 42000, "tier": "free" }
```

which is idempotent and does three things: get-or-create the identity holding
credential `("miden_wallet", wallet_pub_key)`; attach `("miden_account",
account_id)` if given (a non-authenticator label); and attach
`("api_key", api_key_hash)` to *that* identity.

The `miden_account` label is first-come-first-served and **unverified**. When
another identity already claims the address, the label is skipped — the bind
still succeeds, and the response carries `account_id_attached: false` plus a
`warning`. Failing the bind instead would let anyone deny a wallet service by
claiming its (public) address first with a validly signed statement of their
own. The flip side of first-come-first-served is that a squatter can hold the
label; that is acceptable **only because the label routes nothing**: any future
feature that credits topups by `miden_account` MUST first prove the address
belongs to the wallet — by checking the on-chain account state (public
accounts), or by having the wallet supply the seed/commitment material from
which the address derives so the verifier can recompute it. Until then, topups
route by payment-intent memo or identity id only.

The api-key hash is how the Edge spends against the existing ledger without any
change to `consume` / `settle` / `refund`. The raw key is never stored and never
leaves the process — it is recomputed on demand:

```text
raw = "lev_w_" || HMAC-SHA256( EDGE_WALLET_KEY_SECRET, wallet_pub_key )
api_key_hash = SHA256(raw)
```

Rotating `EDGE_WALLET_KEY_SECRET` mints a new spending credential for every
wallet; the old one keeps working until revoked, and balances are unaffected
because they live on the identity, not the credential.

The endpoint refuses to attach an `api_key_hash` that already belongs to a
*different* identity, so a bind can never graft a wallet onto someone else's
balance.

`miden_wallet` and `miden_account` stay **outside**
`AUTHENTICATOR_CREDENTIAL_TYPES`: they are public values, and a public value
must never be able to spend. Only the derived api-key hash authenticates, and
only the Edge can compute it.

## 6. Authorizing each call

The session id alone grants nothing. Every request carries a fresh Ed25519
signature from the session key:

```http
POST /v1/chat/completions
Authorization:       Wallet lev_s_9f3c…
X-Wallet-Timestamp:  1765000123
X-Wallet-Nonce:      <32 hex chars>
X-Wallet-Signature:  <base64 ed25519 signature>
```

signed over the JCS of:

```json
{ "purpose":     "leviathan.wallet.request.v1",
  "session":     "lev_s_9f3c…",
  "method":      "POST",
  "path":        "/v1/chat/completions",
  "body_sha256": "<hex of the exact request body bytes>",
  "ts":          1765000123,
  "nonce":       "<hex>" }
```

Rules:

- `|now − ts| > 120 s` → rejected (`wallet_stale_request`).
- A repeated `(session_id, nonce)` inside that window → rejected
  (`wallet_replay`). The replay cache spans the acceptance window.
- `body_sha256` is over the bytes the Edge actually read, so neither a proxy nor
  a compromised page can alter the prompt after the wallet signed it.
- `path` is the Edge path, so a signature for `/v1/models` cannot be replayed
  onto `/v1/chat/completions`.

This is what makes theft of a `session_id` useless: it is a lookup handle whose
use requires a private key that never leaves the unlocked vault. It is also
what ties spending to the user's intent — the wallet decides, per call, whether
to produce a signature.

`POST /v1/wallet/session/revoke` (same signature envelope, empty body) ends a
session immediately; the extension sends it on wallet lock, and drops the keys
regardless of whether the call succeeded.

## 7. E2EE, unchanged but now wallet-bound

The extension runs the existing verifier (`clients/verifier-ts`):
`verifyReportBinding` on `GET /v1/attestation/report`, then `openE2eeChannel`
with its **derived X25519 key** as the client key. Everything downstream is
stock ACI: `X-Client-Pub-Key` is the wallet key, `X-Model-Pub-Key` is an
attested service key, request fields are encrypted under the §7.3 AAD.

The receipt therefore commits — inside the TEE, under an attested signing key —
to a request whose client key is the wallet's. Given the bind statement, that
chain reads end to end:

```
mnemonic → Falcon account key → (bind, signed) → session + E2EE keys
        → X-Client-Pub-Key → request bytes hashed in the TEE → signed receipt
```

An auditor holding the bind statement and the receipt can verify that a
specific Miden account, and no one else, was the counterparty of a specific
inference — without the Edge being trusted for that claim.

## 8. Threat model

| Adversary | Outcome |
| --- | --- |
| Steals `session_id` (logs, proxy, XSS on a dapp page) | Nothing. Cannot sign. |
| Malicious dapp page | Can ask the wallet to sign; the wallet shows origin + scope + spend cap and requires confirmation. Cannot read the session key — it lives in the service worker, never in the page. |
| Compromised Edge | Full compromise of wallet auth: it verifies signatures and holds `EDGE_WALLET_KEY_SECRET`, so it can bind arbitrary wallets and spend their balances. Mitigation path: move §4.3 verification and the key derivation into the TEE gateway, so the Edge only relays. Prompts stay confidential regardless — they are E2EE'd to the attested key, which the Edge does not hold. |
| Compromised wallet-verifier | Can approve forged binds. Deploy it inside the TEE, or have the Edge additionally require that the challenge nonce it issued is the one signed (it does). |
| Replay of a whole signed request | Blocked by ts + nonce cache; billing dedup (`Idempotency-Key`) is unchanged and independent. |
| Claims someone else's `account_id` in a validly signed bind (address squatting) | Cannot block the victim's bind (a claim conflict skips the label, never fails the bind) and cannot spend or receive anything by it: the label authenticates nothing and routes no topups. What it buys the squatter is holding an unverified label — which stops mattering the moment address ownership proof lands (§5). |
| Quantum adversary | The *root* authority is Falcon-512 (PQ). The session tier is Ed25519, so a future quantum adversary who records traffic could forge session signatures — but only within a session's ≤24 h lifetime and only up to `max_spend_mc`. Prompt confidentiality against harvest-now-decrypt-later is the gateway's ML-KEM story, not this layer's. |
| Lost device | Sessions expire in ≤24 h. `POST /v1/wallet/sessions/revoke-all` after a re-bind from any device with the mnemonic kills the rest. |

## 9. Configuration

| Variable | Component | Meaning |
| --- | --- | --- |
| `WALLET_AUTH_ENABLED` | Edge | Turns the wallet path on. Off → only api keys, exactly as today. |
| `WALLET_VERIFIER_URL` | Edge | wallet-verifier base URL. Required when enabled. |
| `EDGE_WALLET_KEY_SECRET` | Edge | HMAC secret behind the derived spending credential. As sensitive as `EDGE_TENANT_SECRET`. |
| `WALLET_SERVICE_ORIGIN` | Edge | The `service` value bind statements must carry. Must be the public origin users see. |
| `WALLET_STATE_DB` | Edge | SQLite file for challenges + sessions. |
| `WALLET_SESSION_MAX_TTL_SEC` | Edge | Ceiling on `expires_at − issued_at` (default 86400). |
| `WALLET_MAX_SPEND_MC` | Edge | Ceiling on a session's `max_spend_mc`. |

The api-key path is untouched: `Authorization: Bearer lev_…` keeps working
alongside `Authorization: Wallet lev_s_…`, so this ships without a migration.

### 9.1 Deploying the verifier

`wallet-verifier` is a standalone crate (not part of the gateway's Cargo
package), stateless and secretless, listening on `WALLET_VERIFIER_BIND`:

```yaml
  wallet-verifier:
    build: ./wallet-verifier
    environment:
      WALLET_VERIFIER_BIND: 0.0.0.0:8091
    # No volumes, no secrets, no egress — it only answers /verify and /health.

  ai-edge:
    environment:
      WALLET_AUTH_ENABLED: "true"
      WALLET_VERIFIER_URL: http://wallet-verifier:8091
      WALLET_SERVICE_ORIGIN: https://ai.leviathan.example
      EDGE_WALLET_KEY_SECRET: ${EDGE_WALLET_KEY_SECRET}
      WALLET_STATE_DB: /edge/state/wallet-state.db
```

`WALLET_STATE_DB` must live on a volume: losing it invalidates every live
session (users re-bind, nothing is lost but a click) — but losing it *while
sessions are live* also drops their spend accounting, so treat it as state, not
cache.

Leaving `WALLET_AUTH_ENABLED` unset keeps the wallet surface absent entirely:
the endpoints return 501 and the Edge behaves exactly as it did before.

## 10. Compatibility note (Falcon serialization)

The wallet signs with `@miden-sdk/miden-sdk` (WASM); the verifier deserializes
with the `miden-crypto` crate. These MUST be the same generation of the Miden
codebase — the crate has renamed the module (`rpo_falcon512` →
`falcon512_poseidon2`) and the signature encoding is not stable across that
boundary. `wallet-verifier` pins its version explicitly and ships a
`tests/vectors/` directory; before deploying, capture one real
`(public_key, word, signature)` triple from the wallet build in use and add it
there. A verifier that cannot parse the wallet's signatures fails closed, which
is safe but total — treat the vector test as a release gate.
