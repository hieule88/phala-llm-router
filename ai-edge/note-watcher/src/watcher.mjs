/**
 * Leviathan note-watcher — the receive-side eyes of the 'onchain' rail.
 *
 * Loop: pull the matching table from auth-service, scan the chain for
 * committed notes tagged at the gateway account, qualify them (pure
 * P2ID, real target = gateway, accepted faucet), match by EXACT dusted
 * amount, and report each payment to POST /v1/webhooks/onchain.
 *
 * Retry contract (server-documented): 2xx done (deduplicated included);
 * 4xx PERMANENT → dead-letter file + alert, never retried; 5xx/network
 * transient → the report stays in state.pending and is retried every
 * tick. The server is idempotent (topups.source UNIQUE + one-note-one-
 * intent index), so replays after a crash are safe by construction.
 *
 * Unmatched qualified notes are NOT dropped: the note may have raced
 * the intent listing (user paid quickly), so they are re-matched
 * against a fresh table every tick until UNMATCHED_TTL_SECONDS, then
 * dead-lettered for ops. Ambiguous matches (server slot discipline
 * should make them impossible) alert immediately and follow the same
 * retry path — a colliding intent expiring can resolve them.
 */

import { buildReport, classifyReport, disqualify, matchNote, parseCreatedAt } from './core.mjs';
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
    // it a parked note is an ops case. Every extra hour a note sits
    // parked is grinding time for someone minting same-price intents
    // against its (publicly visible) amount — the time-order filter is
    // the real defence, this bounds the exposure window on top.
    unmatchedTtlSec: Number(env.UNMATCHED_TTL_SECONDS ?? 48 * 3600),
    // How long settled bookkeeping (reported / dead-lettered ids) is
    // kept. The cursor is monotonic, so entries older than any possible
    // rescan exist only to keep the state file small-ish.
    pruneTtlSec: Number(env.PRUNE_TTL_SECONDS ?? 30 * 24 * 3600),
    stateFile: env.STATE_FILE ?? '/state/watcher-state.json',
    deadLetterFile: env.DEAD_LETTER_FILE ?? '/state/dead-letter.jsonl',
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
    if (verdict.tieBroken) {
      log.alert(`amount collision resolved by sender hint — should be impossible, `
        + `check server slot discipline (note=${note.noteId})`);
    }
    state.pending[note.noteId] = {
      payload: buildReport(note, verdict.memo, faucetId),
      firstSeenAt: state.unmatched[note.noteId]?.firstSeenAt ?? now,
    };
    delete state.unmatched[note.noteId];
    return;
  }
  if (verdict.kind === 'ambiguous') {
    log.alert(`ambiguous amount ${note.amount} across memos ${verdict.memos.join(',')} `
      + `— server slot discipline violated? (note=${note.noteId})`);
  }
  // unmatched (or still-ambiguous): keep for re-matching — the intent
  // may not have been in the table yet when the note was scanned.
  // firstSeenAt keeps the note's own time anchor (block time when
  // available), so later ticks and the TTL reason about chain time.
  state.unmatched[note.noteId] ??= {
    amount: note.amount, sender: note.sender, firstSeenAt: note.seenAt ?? now,
  };
}

/** One full tick. Exported for tests; the main loop just repeats it. */
export async function runTick({ cfg, state, chain, ledger, log, now = Date.now() }) {
  const table = await ledger.fetchPendingIntents();
  const gateway = table.pay_to_address;
  const faucet = table.faucet_id;
  if (!gateway || !faucet) {
    // Rail config comes from the same source of truth that priced the
    // intents; empty means auth-service is not configured yet. Ticking
    // against guessed values could match the wrong notes — refuse.
    log.warn('rail config empty (pay_to_address/faucet_id) — skipping tick');
    return state;
  }

  // Pre-decode sender labels and parse the time anchor once per tick:
  // hex-vs-hex and ms-vs-ms from here on. The anchor is the server's
  // matchable_since — when the intent ENTERED the on-chain rail — not
  // created_at: a rail-switched intent must not inherit its row's age
  // (pre-minted Stripe intents would sail past the time-order filter).
  // created_at is only a fallback for servers predating the field. An
  // unparseable anchor is kept as null — matchNote excludes it (fail
  // closed) — and logged.
  const intents = (table.intents ?? []).map(i => {
    const createdAtMs = parseCreatedAt(i.matchable_since ?? i.created_at);
    if (createdAtMs === null) {
      log.warn(`intent ${i.memo}: unparseable time anchor `
        + `${JSON.stringify(i.matchable_since ?? i.created_at)} `
        + `— excluded from matching (fail closed)`);
    }
    return {
      memo: i.memo,
      token_amount: i.token_amount,
      createdAtMs,
      sender_account_ids: (i.sender_accounts ?? [])
        .map(b => chain.bech32ToHex(b))
        .filter(Boolean),
    };
  });

  // 0. Trim settled bookkeeping so the state file stays bounded.
  pruneState(state, now, cfg.pruneTtlSec * 1000);

  // 1. Retry reports that didn't land last tick.
  await drainPending({ state, ledger, log, deadLetterFile: cfg.deadLetterFile });

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
      note: { noteId, amount: u.amount, sender: u.sender, seenAt: u.firstSeenAt },
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
      disposition({
        note: { ...note, seenAt: note.blockTimeMs ?? Date.now() },
        intents, state, log, faucetId: faucet, now,
      });
    }
    const next = blockTo + 1;
    if (next <= state.cursor) break; // defensive: node made no progress
    state.cursor = next;
    await saveState(cfg.stateFile, state); // page-granular crash safety
  }

  // 4. Push what the scan just matched.
  await drainPending({ state, ledger, log, deadLetterFile: cfg.deadLetterFile });

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
  let cfg;
  try {
    cfg = configFromEnv();
  } catch (err) {
    // The service ships in the compose file with the token unset until
    // the rail goes live. Exiting would make `restart: always` a crash
    // loop, so idle with a clear log line instead.
    log.warn(`not configured (${err.message}) — idling; set the env and restart`);
    await new Promise(() => {});
    return;
  }
  const { makeChain } = await import('./chain.mjs'); // WASM only in prod path
  const chain = makeChain({ rpcUrl: cfg.rpcUrl });
  const ledger = makeLedger({ authUrl: cfg.authUrl, token: cfg.watcherToken });
  let state = await loadState(cfg.stateFile);
  log.info(`note-watcher up: auth=${cfg.authUrl} rpc=${cfg.rpcUrl} `
    + `cursor=${state.cursor} poll=${cfg.pollIntervalSec}s`);

  for (;;) {
    try {
      state = await runTick({ cfg, state, chain, ledger, log });
    } catch (err) {
      // A failed tick (auth-service down, node RPC down) is transient:
      // state was saved page-by-page, next tick resumes where we were.
      log.warn(`tick failed, will retry: ${err}`);
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
