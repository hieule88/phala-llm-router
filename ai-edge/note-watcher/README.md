# note-watcher

The receive-side eyes of the on-chain payment rail: scans the Miden
chain for **pure P2ID notes paying the gateway's receiving account**,
matches them to pending intents by the **intent memo carried in the
note's own NoteAttachment**, and reports each payment to auth-service's
`POST /v1/webhooks/onchain`.
Crediting itself happens in auth-service; this process holds **no key
material** and can at worst *report* — every report is re-checked
server-side (accepted faucet, exact price amount, one-note-one-intent,
onchain-provider-only).

## What qualifies as a payment

1. Note is **committed** on-chain (from `SyncNotes`), at least
   `FINALITY_DEPTH` blocks below the tip.
2. Script root is **pure P2ID** — P2IDE is reclaimable until consumed,
   so it is logged and ignored, never credited.
3. The note's **real target** (P2ID storage `[suffix, prefix]`) is the
   gateway account. The sync tag is only a ~16-bit filter and can be
   ground into collision; without this check an attacker could "pay"
   the quoted amount to an account of their own and have it credited.
4. It carries a positive amount of the **accepted faucet**.

**Memo-only matching.** The paying dApp submits a wallet *Custom*
transaction (see `test_frontend/src/onchain-attach.js`) that embeds
the intent memo in the note's `NoteAttachment` (scheme `0x4C565431`
"LVT1"; codec in `src/core.mjs` — length-prefixed UTF-8, 7 bytes per
felt). That memo is the ONLY matching key: amounts are plain prices
and **collide across same-price intents by design**, so a note without
a decodable memo can never be auto-credited — it raises an
`unattached` ALERT immediately (with a shortlist of same-amount
intents for ops) and parks until an operator finalises it via admin
mark-paid. A note that names a live intent still must pay the **exact**
`token_amount`; a named-but-wrong-amount note is refused outright
(`attachment mismatch` ALERT, parked, never auto-credited). A memo
naming no live intent yet is re-matched every tick — it may have raced
the intent listing, and since memos are server-drawn randomness nobody
can mint an intent later that claims a parked note. `sender_accounts`
are unverified labels: logs and diagnostics only.

## Retry contract (mirrors the server's docs)

- **2xx** → done (a `deduplicated` result is still done).
- **4xx about the note** (404/409/400) → permanent: appended to
  `dead-letter.jsonl`, `ALERT` logged, never retried.
- **4xx about the caller/transport** (401/403/408/429) → transient:
  a rotated token or a rate limit says nothing about the note, so the
  report stays pending instead of dead-lettering every payment at once.
- **5xx / network** → transient: retried every tick from persisted state.

Qualified memo-carrying notes whose intent is **not in the table yet**
are parked and re-matched against a fresh table every tick (the note
may race the intent listing); after `UNMATCHED_TTL_SECONDS` they
dead-letter with an ALERT (money on-chain with no intent = ops case).
Settled bookkeeping (reported / dead-lettered ids) is pruned after
`PRUNE_TTL_SECONDS` so the state file stays bounded.

Grep the logs for `ALERT ` — those lines are the ones to page on.

## Env

| var | default | meaning |
|---|---|---|
| `AUTH_URL` | — | auth-service base URL |
| `ONCHAIN_WATCHER_TOKEN` | — | bearer for the two watcher endpoints |
| `NODE_RPC_URL` | — | Miden node RPC (gRPC-web) |
| `POLL_INTERVAL_SEC` | 10 | tick period |
| `FINALITY_DEPTH` | 0 | blocks below tip before acting |
| `SCAN_LOOKBACK_BLOCKS` | 100 | first-run scan start = tip − this |
| `UNMATCHED_TTL_SECONDS` | 172800 | park time before ops dead-letter |
| `PRUNE_TTL_SECONDS` | 2592000 | settled-bookkeeping retention |
| `HTTP_TIMEOUT_MS` | 30000 | per-call bound on auth-service fetches |
| `RPC_TIMEOUT_MS` | 60000 | per-call bound on Miden node RPC |
| `WATCHDOG_STALL_SECONDS` | 600 | no tick progress → exit(1) (restart) |
| `HEALTHCHECK_MAX_AGE_SEC` | 180 | heartbeat age the healthcheck accepts |
| `STATE_FILE` | /state/watcher-state.json | cursor + bookkeeping |
| `DEAD_LETTER_FILE` | /state/dead-letter.jsonl | permanent refusals |
| `HEARTBEAT_FILE` | /state/heartbeat | progress marker for the healthcheck |

Missing required env does **not** crash-loop the container: the process
logs and idles until configured (`restart: always`-friendly), still
heartbeating so the healthcheck reads healthy-but-idle.

## Hang protection (the pull-loop failure mode)

Stripe pushes events and retries for 3 days; the chain does neither —
if this loop silently stops pulling, crediting stops with the process
still "alive" and `restart: always` never fires. Three layers close
that:

1. **Per-call timeouts** — every fetch (AbortSignal + race) and every
   WASM RPC await is time-bounded, so a hung call fails the tick fast
   and loudly instead of parking it.
2. **In-process stall watchdog** — JS cannot cancel a wedged WASM
   client, so if no tick PROGRESS (heartbeat via `beat()`: table fetch,
   drained reports, scanned pages) happens for `WATCHDOG_STALL_SECONDS`,
   the process ALERTs and exits(1); docker restarts it with a fresh
   WASM client. Failed-but-moving ticks count as progress — the
   watchdog is for silence, not for outages the retry already handles.
3. **Docker healthcheck** — `scripts/healthcheck.mjs` compares the
   heartbeat file's age against `HEALTHCHECK_MAX_AGE_SEC`, so ops see
   `unhealthy` in `docker ps` before the watchdog recycles the process.

All of this is crash-safe by construction: state is saved per page and
the server dedups replays, so being killed mid-tick loses nothing.

Gateway address, faucet id and decimals are **not** configured here —
they come from `GET /v1/onchain/pending-intents`, the same source of
truth that priced the intents.

## SDK dependency

`@miden-sdk/miden-sdk` at dist-tag `node` (the `0.15.0-node.<sha>`
builds) from the private Gitea registry — see `.npmrc`. For a
reproducible image, pin the exact sha-stamped version in package.json
instead of the moving tag. If the registry requires auth for reads,
build with `--build-arg GITEA_NPM_TOKEN=...`.

## Tests

`npm test` — pure-logic and tick-level tests with faked chain/ledger;
the WASM SDK is only loaded by the real entrypoint, never by tests.

`npm run smoke` — LIVE smoke test of the WASM boundary (chain.mjs)
against a real node: RPC connectivity, bech32 decoding, one real
syncNotes/getNotesById page, script-root classification, and the
attachment/memo of every note found. Run it on testnet before enabling
the rail (env: `NODE_RPC_URL`, `ONCHAIN_GATEWAY_ADDRESS`,
`ONCHAIN_FAUCET_ID`).

`npm run smoke:attachment` — OFFLINE smoke of the memo round trip on
the real WASM build (no chain, no wallet, no money): our codec →
`NoteAttachment` → `Note.createP2IDNote` → `TransactionRequest`
serialize/deserialize (the wallet's Custom-payload contract) →
`metadata().attachment()` → memo decoded back. Run it after every SDK
version bump — it already caught two real API breaks
(`withOwnOutputNotes` wants `NoteArray`, and wasm arrays MOVE their
element handles). Env: `ONCHAIN_FAUCET_ID` (a real faucet id;
`FungibleAsset` rejects non-faucet accounts).

Node-runtime note: the SDK dist is browser-shaped at module top level
(worker globals + a `fetch(file://)` WASM load). `src/wasm-preload.mjs`
shims both and MUST stay the first import of chain.mjs — without it the
watcher dies at startup under node (verified against
`0.15.0-node.5e72c326`).

## Not in scope

Sweeping (consuming notes into the gateway vault) needs the account
key and deliberately lives elsewhere. Prefer making the receiving
account a **network account** so the node's ntx-builder consumes
tagged notes automatically.
