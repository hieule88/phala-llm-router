/**
 * Leviathan note-watcher — the receive-side eyes of the 'onchain' rail.
 *
 * Loop: pull the matching table from auth-service, scan the chain for
 * committed notes tagged at the gateway account, qualify them (pure
 * P2ID, real target = gateway, accepted faucet), match them by the
 * intent memo carried in the note's own NoteAttachment, and report
 * each payment to POST /v1/webhooks/onchain. The memo is the ONLY
 * matching key: amounts are plain prices that collide across
 * same-price intents, so a note without a decodable memo can never
 * auto-credit — it alerts immediately and parks as an ops case.
 *
 * Retry contract (server-documented): 2xx done (deduplicated included);
 * 4xx PERMANENT → dead-letter file + alert, never retried; 5xx/network
 * transient → the report stays in state.pending and is retried every
 * tick. The server is idempotent (topups.source UNIQUE + one-note-one-
 * intent index), so replays after a crash are safe by construction.
 *
 * Unmatched memo-carrying notes are NOT dropped: the note may have
 * raced the intent listing (user paid quickly), so they are re-matched
 * against a fresh table every tick until UNMATCHED_TTL_SECONDS, then
 * dead-lettered for ops.
 */

import {
  buildReport, classifyReport, decodeMemoAttachment, disqualify,
  matchNote, sameAmountMemos,
} from './core.mjs';
import { appendDeadLetter, loadState, saveState } from './state.mjs';
import { makeLedger } from './ledger.mjs';

export function configFromEnv(env = process.env) {
  const need = (name) => {
    const v = env[name];
    if (!v) throw new Error(`${name} is required`);
    return v;
  };
  return {
    authUrl: need('AUTH_URL'),
    watcherToken: need('ONCHAIN_WATCHER_TOKEN'),
    rpcUrl: need('NODE_RPC_URL'),
    pollIntervalSec: Number(env.POLL_INTERVAL_SEC ?? 10),
    // Blocks below the tip a note must be before we act on it. Miden
    // blocks carry validity proofs, so 0 is defensible; the knob exists
    // for operators who want depth anyway.
    finalityDepth: Number(env.FINALITY_DEPTH ?? 0),
    // First-run lookback: how far behind the tip the very first scan
    // starts. Scanning from genesis is pointless — no intents predate
    // the watcher going live.
    scanLookback: Number(env.SCAN_LOOKBACK_BLOCKS ?? 100),
    // 48h, aligned with the server's ONCHAIN_MATCH_GRACE default: past
    // it a parked note stops being re-matched and dead-letters for ops.
    // Safe to keep generous — a parked note's memo is fixed on-chain,
    // so nobody can mint an intent that claims it later.
    unmatchedTtlSec: Number(env.UNMATCHED_TTL_SECONDS ?? 48 * 3600),
    // How long settled bookkeeping (reported / dead-lettered ids) is
    // kept. The cursor is monotonic, so entries older than any possible
    // rescan exist only to keep the state file small-ish.
    pruneTtlSec: Number(env.PRUNE_TTL_SECONDS ?? 30 * 24 * 3600),
    // Per-call time bounds. HTTP (auth-service) is on the same docker
    // network — 30s is already generous; RPC crosses the internet to
    // the Miden node and pays WASM parse costs — 60s.
    httpTimeoutMs: Number(env.HTTP_TIMEOUT_MS ?? 30_000),
    rpcTimeoutMs: Number(env.RPC_TIMEOUT_MS ?? 60_000),
    // The stall watchdog: no tick PROGRESS (not merely "process alive")
    // for this long → ALERT + exit(1), so `restart: always` actually
    // rescues us. This is the backstop for what per-call timeouts can't
    // cancel — a wedged WASM RPC client stays wedged until the process
    // is replaced. Must comfortably exceed one worst-case tick.
    watchdogStallSec: Number(env.WATCHDOG_STALL_SECONDS ?? 600),
    stateFile: env.STATE_FILE ?? '/state/watcher-state.json',
    deadLetterFile: env.DEAD_LETTER_FILE ?? '/state/dead-letter.jsonl',
    // Touched on every unit of progress; the docker healthcheck reads
    // its age. Ops visibility only — the watchdog does the restarting.
    heartbeatFile: env.HEARTBEAT_FILE ?? '/state/heartbeat',
  };
}

/** Drop settled bookkeeping past the prune TTL. Entries may be legacy
 *  plain strings (no timestamp) — stamp them now instead of guessing. */
export function pruneState(state, now, pruneTtlMs) {
  for (const key of ['reported', 'deadLettered']) {
    for (const [noteId, entry] of Object.entries(state[key])) {
      if (typeof entry !== 'object' || entry === null || !entry.at) {
        state[key][noteId] = { value: entry, at: now };
        continue;
      }
      if (now - entry.at > pruneTtlMs) delete state[key][noteId];
    }
  }
}

/** Drain state.pending: push every stored report at the ledger and
 *  settle each per the retry contract. */
async function drainPending({ state, ledger, log, deadLetterFile }) {
  for (const [noteId, entry] of Object.entries(state.pending)) {
    let outcome;
    let detail = null;
    try {
      const res = await ledger.report(entry.payload);
      outcome = classifyReport(res.status);
      detail = res.body?.detail ?? null;
      if (outcome === 'done') {
        const dedup = res.body?.result?.deduplicated ? ' (deduplicated)' : '';
        log.info(`credited note=${noteId} memo=${entry.payload.memo}${dedup}`);
      }
    } catch (err) {
      outcome = 'retry';
      detail = String(err);
    }
    if (outcome === 'done') {
      state.reported[noteId] = { memo: entry.payload.memo, at: Date.now() };
      delete state.pending[noteId];
    } else if (outcome === 'dead_letter') {
      log.alert(`DEAD-LETTER note=${noteId} memo=${entry.payload.memo}: ${detail}`);
      state.deadLettered[noteId] = { reason: detail ?? 'refused', at: Date.now() };
      delete state.pending[noteId];
      await appendDeadLetter(deadLetterFile, {
        at: new Date().toISOString(), noteId, ...entry, detail,
      });
    } else {
      log.warn(`report retry later note=${noteId}: ${detail}`);
    }
  }
}

/** Decide the fate of one qualified note against the current table. */
function disposition({ note, intents, state, log, faucetId, now }) {
  const verdict = matchNote(note, intents);
  if (verdict.kind === 'match') {
    log.info(`note ${note.noteId} matched via on-note attachment memo`);
    state.pending[note.noteId] = {
      payload: buildReport(note, verdict.memo, faucetId),
      firstSeenAt: state.unmatched[note.noteId]?.firstSeenAt ?? now,
    };
    delete state.unmatched[note.noteId];
    return;
  }

  const park = () => {
    state.unmatched[note.noteId] ??= {
      amount: note.amount, sender: note.sender, firstSeenAt: note.seenAt ?? now,
      memoHint: note.memoHint ?? null,
    };
    return state.unmatched[note.noteId];
  };

  if (verdict.kind === 'attachment_mismatch') {
    // The note NAMES an intent on-chain but pays the wrong amount.
    // Never credited (exact amount stays a hard requirement) — park it
    // and hand ops the named memo, once.
    if (!state.unmatched[note.noteId]?.mismatchAlerted) {
      log.alert(`attachment mismatch: note=${note.noteId} names memo ${verdict.memo} `
        + `but paid ${note.amount}, expected ${verdict.expected} — never auto-credited; `
        + `verify the note, then finalise via admin mark-paid`);
    }
    park().mismatchAlerted = true;
    return;
  }

  if (verdict.kind === 'unattached') {
    // No decodable memo on the note: with plain-price amounts this can
    // NEVER auto-credit (same-price intents are indistinguishable), so
    // it is an ops case from the first sighting — alert now, not at
    // the 48h dead-letter, and shortlist same-amount intents as a
    // starting point. Alerted once per note; re-matching cannot help.
    if (!state.unmatched[note.noteId]?.unattachedAlerted) {
      const hints = sameAmountMemos(note, intents);
      const hint = hints.length > 0
        ? `same-amount intents: ${hints.join(', ')}`
        : 'no same-amount intent live';
      log.alert(`unattached payment: note=${note.noteId} paid ${note.amount} `
        + `with no readable memo attachment — cannot auto-credit; ${hint}; `
        + `verify the note, then finalise via admin mark-paid`);
    }
    park().unattachedAlerted = true;
    return;
  }

  // unmatched: memo present but names no live intent yet — keep for
  // re-matching (the note may have raced the intent listing).
  // firstSeenAt keeps the note's own time anchor (block time when
  // available), so the TTL reasons about chain time; memoHint is
  // stored so later ticks re-match by memo.
  park();
}

/** One full tick. Exported for tests; the main loop just repeats it.
 *  `beat` is called on every unit of PROGRESS (table fetched, report
 *  drained, page scanned) — the stall watchdog and the heartbeat file
 *  hang off it, so a long-but-moving tick never trips the watchdog
 *  while a genuinely stuck one does. */
export async function runTick({ cfg, state, chain, ledger, log,
                                now = Date.now(), beat = () => {} }) {
  const table = await ledger.fetchPendingIntents();
  beat();
  const gateway = table.pay_to_address;
  const faucet = table.faucet_id;
  if (!gateway || !faucet) {
    // Rail config comes from the same source of truth that priced the
    // intents; empty means auth-service is not configured yet. Ticking
    // against guessed values could match the wrong notes — refuse.
    log.warn('rail config empty (pay_to_address/faucet_id) — skipping tick');
    return state;
  }

  // Matching needs only (memo, exact token_amount) — the memo comes off
  // the note's own attachment, so no time anchors and no sender labels
  // enter the decision.
  const intents = (table.intents ?? []).map(i => ({
    memo: i.memo,
    token_amount: i.token_amount,
  }));

  // 0. Trim settled bookkeeping so the state file stays bounded.
  pruneState(state, now, cfg.pruneTtlSec * 1000);

  // 1. Retry reports that didn't land last tick.
  await drainPending({ state, ledger, log, deadLetterFile: cfg.deadLetterFile });
  beat();

  // 2. Re-match parked notes against the fresh table (they may have
  //    raced intent creation), and expire the ones past the TTL.
  for (const [noteId, u] of Object.entries(state.unmatched)) {
    if (now - u.firstSeenAt > cfg.unmatchedTtlSec * 1000) {
      log.alert(`UNMATCHED note ${noteId} (amount=${u.amount}) expired after `
        + `${cfg.unmatchedTtlSec}s — money on-chain with no matching intent; ops case`);
      state.deadLettered[noteId] = 'unmatched past TTL';
      delete state.unmatched[noteId];
      await appendDeadLetter(cfg.deadLetterFile, {
        at: new Date(now).toISOString(), noteId, unmatched: u,
      });
      continue;
    }
    disposition({
      // seenAt stays the FIRST observation: an intent minted after the
      // note was parked can never claim it, no matter how many ticks pass.
      note: { noteId, amount: u.amount, sender: u.sender, seenAt: u.firstSeenAt,
              memoHint: u.memoHint ?? null },
      intents, state, log, faucetId: faucet, now,
    });
  }

  // 3. Scan new blocks up to tip - finalityDepth, page by page. The
  //    cursor advances to blockTo()+1 (the node's own pagination mark),
  //    never straight to the tip — the node may truncate a window.
  const tip = await chain.tip();
  const cap = tip - cfg.finalityDepth;
  if (state.cursor === null) {
    state.cursor = Math.max(0, cap - cfg.scanLookback);
  }
  while (state.cursor <= cap) {
    const { notes, blockTo } = await chain.scan(state.cursor, cap, gateway, faucet);
    for (const note of notes) {
      if (state.pending[note.noteId] || state.reported[note.noteId]
          || state.deadLettered[note.noteId] || state.unmatched[note.noteId]) {
        continue; // already tracked — rescans are expected and harmless
      }
      const reason = disqualify(note);
      if (reason) {
        if (note.kind === 'p2ide' && note.targetOk) {
          // Someone paid us with a reclaimable note: not creditable
          // (sender can pull it back until consumed) but worth eyes.
          log.warn(`P2IDE note to gateway ignored (reclaimable): ${note.noteId}`);
        }
        continue;
      }
      // Anchor the note in CHAIN time when the block header provides
      // it: wall-clock stamping would loosen the time-order filter by
      // exactly the watcher's downtime (or a long tick's duration).
      // The attachment (if any) is decoded ONCE here — chain.mjs hands
      // over raw felts, core.mjs owns the codec; a malformed or foreign
      // attachment yields null and the note matches by amount only.
      disposition({
        note: { ...note, seenAt: note.blockTimeMs ?? Date.now(),
                memoHint: decodeMemoAttachment(note.attachment) },
        intents, state, log, faucetId: faucet, now,
      });
    }
    const next = blockTo + 1;
    if (next <= state.cursor) break; // defensive: node made no progress
    state.cursor = next;
    await saveState(cfg.stateFile, state); // page-granular crash safety
    beat();
  }

  // 4. Push what the scan just matched.
  await drainPending({ state, ledger, log, deadLetterFile: cfg.deadLetterFile });
  beat();

  await saveState(cfg.stateFile, state);
  return state;
}

export function makeLog() {
  const ts = () => new Date().toISOString();
  return {
    info: (m) => console.log(`${ts()} INFO  ${m}`),
    warn: (m) => console.warn(`${ts()} WARN  ${m}`),
    // "alert" lines are the ones ops must page on — keep the marker stable.
    alert: (m) => console.error(`${ts()} ALERT ${m}`),
  };
}

async function main() {
  const log = makeLog();
  const { promises: fsp } = await import('node:fs');
  const path = await import('node:path');

  const writeHeartbeat = async (file) => {
    try {
      await fsp.mkdir(path.dirname(file), { recursive: true });
      await fsp.writeFile(file, String(Date.now()));
    } catch (err) {
      log.warn(`cannot write heartbeat ${file}: ${err}`);
    }
  };

  let cfg;
  try {
    cfg = configFromEnv();
  } catch (err) {
    // The service ships in the compose file with the token unset until
    // the rail goes live. Exiting would make `restart: always` a crash
    // loop, so idle with a clear log line instead — still heartbeating,
    // so the healthcheck reads "healthy but idle", not "wedged".
    log.warn(`not configured (${err.message}) — idling; set the env and restart`);
    const file = process.env.HEARTBEAT_FILE ?? '/state/heartbeat';
    for (;;) {
      await writeHeartbeat(file);
      await new Promise(r => setTimeout(r, 30_000));
    }
  }

  const { makeChain } = await import('./chain.mjs'); // WASM only in prod path
  const chain = makeChain({ rpcUrl: cfg.rpcUrl, timeoutMs: cfg.rpcTimeoutMs });
  const ledger = makeLedger({
    authUrl: cfg.authUrl, token: cfg.watcherToken, timeoutMs: cfg.httpTimeoutMs,
  });
  let state = await loadState(cfg.stateFile);
  log.info(`note-watcher up: auth=${cfg.authUrl} rpc=${cfg.rpcUrl} `
    + `cursor=${state.cursor} poll=${cfg.pollIntervalSec}s `
    + `timeouts http=${cfg.httpTimeoutMs}ms rpc=${cfg.rpcTimeoutMs}ms `
    + `watchdog=${cfg.watchdogStallSec}s`);

  // Progress tracking. Per-call timeouts make ticks fail fast in the
  // normal case; the watchdog is the backstop for what JS cannot cancel
  // (a wedged WASM client keeps its promise pending forever). "Alive"
  // is not the bar — PROGRESS is: beat() fires per table fetch, per
  // drained report batch and per scanned page.
  let lastProgress = Date.now();
  const beat = () => {
    lastProgress = Date.now();
    void writeHeartbeat(cfg.heartbeatFile);
  };
  beat();

  const watchdog = setInterval(() => {
    const stalledMs = Date.now() - lastProgress;
    if (stalledMs > cfg.watchdogStallSec * 1000) {
      log.alert(`WATCHDOG: no tick progress for ${Math.round(stalledMs / 1000)}s `
        + `(> ${cfg.watchdogStallSec}s) — exiting so docker restarts us with a `
        + `fresh process; state is page-safe, the server dedups replays`);
      process.exit(1);
    }
  }, 15_000);
  watchdog.unref?.();

  for (;;) {
    try {
      state = await runTick({ cfg, state, chain, ledger, log, beat });
    } catch (err) {
      // A failed tick (auth-service down, node RPC down, a call timing
      // out) is transient: state was saved page-by-page, next tick
      // resumes where we were. It still COUNTS as progress — the loop
      // is demonstrably running; the watchdog is for silence, not for
      // outages the retry already handles.
      log.warn(`tick failed, will retry: ${err}`);
      beat();
    }
    await new Promise(r => setTimeout(r, cfg.pollIntervalSec * 1000));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(`FATAL ${err}`);
    process.exit(1);
  });
}
