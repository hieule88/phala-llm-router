import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync } from 'node:fs';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { runTick } from '../src/watcher.mjs';
import { loadState } from '../src/state.mjs';

// ── fakes ────────────────────────────────────────────────────────────────

const GATEWAY = 'mtst1gateway';
const FAUCET = 'mtst1faucet';

function makeCfg() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'watcher-test-'));
  return {
    stateFile: path.join(dir, 'state.json'),
    deadLetterFile: path.join(dir, 'dead.jsonl'),
    finalityDepth: 0,
    scanLookback: 100,
    unmatchedTtlSec: 3600,
    pruneTtlSec: 30 * 24 * 3600,
  };
}

function makeLogCapture() {
  const lines = { info: [], warn: [], alert: [] };
  return {
    lines,
    info: (m) => lines.info.push(m),
    warn: (m) => lines.warn.push(m),
    alert: (m) => lines.alert.push(m),
  };
}

/** Chain fake: one page containing `notes`, blockTo == requested `to`. */
function makeChain(notes, { tip = 50 } = {}) {
  const calls = [];
  return {
    calls,
    bech32ToHex: (b) => `hex(${b})`,
    tip: async () => tip,
    scan: async (from, to) => {
      calls.push({ from, to });
      return { notes, blockTo: to };
    },
  };
}

function makeLedger({ intents = [], reportStatus = 200, reportBody = null } = {}) {
  const reports = [];
  return {
    reports,
    fetchPendingIntents: async () => ({
      pay_to_address: GATEWAY, faucet_id: FAUCET,
      token_decimals: 6, network: 'testnet', intents,
    }),
    report: async (payload) => {
      reports.push(payload);
      return { status: reportStatus, body: reportBody };
    },
  };
}

const note = (over = {}) => ({
  noteId: '0xn1', kind: 'p2id', targetOk: true,
  amount: '3001234', sender: null, ...over,
});

// created_at long in the past (server SQLite format) so time ordering
// never interferes with tests that aren't about it.
const tableIntent = (over = {}) => ({
  memo: 'intent-a', token_amount: '3001234', sender_accounts: [],
  created_at: '2020-01-01 00:00:00', ...over,
});

function fresh() {
  return { cursor: null, pending: {}, reported: {}, deadLettered: {}, unmatched: {} };
}

// ── tests ────────────────────────────────────────────────────────────────

test('happy path: scan → match → report → reported; cursor advances', async () => {
  const cfg = makeCfg();
  const chain = makeChain([note()]);
  const ledger = makeLedger({ intents: [tableIntent()] });
  const log = makeLogCapture();

  const state = await runTick({ cfg, state: fresh(), chain, ledger, log });

  assert.equal(ledger.reports.length, 1);
  assert.deepEqual(ledger.reports[0], {
    memo: 'intent-a', note_id: '0xn1', faucet_id: FAUCET,
    amount_base_units: '3001234', note_kind: 'p2id',
  });
  assert.equal(state.reported['0xn1'].memo, 'intent-a');
  assert.deepEqual(state.pending, {});
  // first run starts at tip - lookback, ends past the cap
  assert.equal(chain.calls[0].from, 50 - 100 < 0 ? 0 : 50 - 100);
  assert.equal(state.cursor, 51);
  // state survived on disk
  const onDisk = await loadState(cfg.stateFile);
  assert.equal(onDisk.reported['0xn1'].memo, 'intent-a');
});

test('finality depth caps the scan window', async () => {
  const cfg = { ...makeCfg(), finalityDepth: 10 };
  const chain = makeChain([], { tip: 50 });
  const state = await runTick({
    cfg, state: fresh(), chain, ledger: makeLedger(), log: makeLogCapture(),
  });
  assert.equal(chain.calls[0].to, 40);
  assert.equal(state.cursor, 41);
});

test('5xx keeps the report pending and retries next tick', async () => {
  const cfg = makeCfg();
  const chain = makeChain([note()]);
  const log = makeLogCapture();
  const ledger = makeLedger({ intents: [tableIntent()], reportStatus: 503 });

  let state = await runTick({ cfg, state: fresh(), chain, ledger, log });
  assert.ok(state.pending['0xn1'], 'stays pending after 503');
  assert.deepEqual(state.reported, {});

  // next tick the ledger recovered — the SAME payload is retried
  const ledger2 = makeLedger({ intents: [tableIntent()], reportStatus: 200 });
  state = await runTick({ cfg, state, chain: makeChain([]), ledger: ledger2, log });
  assert.equal(ledger2.reports.length, 1);
  assert.equal(state.reported['0xn1'].memo, 'intent-a');
});

test('401 (rotated token) is retried, never dead-lettered', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const ledger = makeLedger({ intents: [tableIntent()], reportStatus: 401 });
  const state = await runTick({
    cfg, state: fresh(), chain: makeChain([note()]), ledger, log,
  });
  assert.ok(state.pending['0xn1'], 'stays pending after 401');
  assert.deepEqual(state.deadLettered, {});
});

test('4xx dead-letters with an alert and never retries', async () => {
  const cfg = makeCfg();
  const chain = makeChain([note()]);
  const log = makeLogCapture();
  const ledger = makeLedger({
    intents: [tableIntent()], reportStatus: 409,
    reportBody: { detail: 'note already credited another intent' },
  });

  let state = await runTick({ cfg, state: fresh(), chain, ledger, log });
  assert.ok(state.deadLettered['0xn1']);
  assert.ok(log.lines.alert.some(l => l.includes('DEAD-LETTER')));
  const dl = await fs.readFile(cfg.deadLetterFile, 'utf8');
  assert.ok(dl.includes('0xn1'));

  // subsequent tick does not re-report
  const ledger2 = makeLedger({ intents: [tableIntent()] });
  state = await runTick({ cfg, state, chain: makeChain([]), ledger: ledger2, log });
  assert.equal(ledger2.reports.length, 0);
});

test('note racing the intent listing is parked, then matched next tick', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();

  // tick 1: the note is on-chain but the table is still empty
  const ledger1 = makeLedger({ intents: [] });
  let state = await runTick({
    cfg, state: fresh(), chain: makeChain([note()]), ledger: ledger1, log,
  });
  assert.ok(state.unmatched['0xn1']);
  assert.equal(ledger1.reports.length, 0);

  // tick 2: the intent shows up — created BEFORE the note was seen, so
  // the parked note is matched and reported
  const ledger2 = makeLedger({ intents: [tableIntent()] });
  state = await runTick({ cfg, state, chain: makeChain([]), ledger: ledger2, log });
  assert.equal(ledger2.reports.length, 1);
  assert.equal(state.reported['0xn1'].memo, 'intent-a');
  assert.deepEqual(state.unmatched, {});
});

test('grind defence: an intent minted after the note was parked never claims it', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();

  // tick 1: note lands, no intent → parked
  let state = await runTick({
    cfg, state: fresh(), chain: makeChain([note()]),
    ledger: makeLedger({ intents: [] }), log,
  });
  assert.ok(state.unmatched['0xn1']);

  // tick 2: a same-amount intent appears, but created AFTER the note
  // was first seen (the griefer minting until the dust collides)
  const future = new Date(Date.now() + 3600_000)
    .toISOString().slice(0, 19).replace('T', ' ');
  const ledger2 = makeLedger({
    intents: [tableIntent({ memo: 'intent-grind', created_at: future })],
  });
  state = await runTick({ cfg, state, chain: makeChain([]), ledger: ledger2, log });
  assert.equal(ledger2.reports.length, 0);
  assert.ok(state.unmatched['0xn1'], 'still parked — the late intent is ineligible');
});

test('matchable_since outranks created_at (rail-switch attack)', async () => {
  // A stockpiled Stripe intent switched onto the on-chain rail keeps an
  // old created_at, but the server stamps matchable_since at switch
  // time — and THAT is the anchor the filter must use.
  const cfg = makeCfg();
  const log = makeLogCapture();
  const switchedNow = new Date(Date.now() + 3600_000)
    .toISOString().slice(0, 19).replace('T', ' ');
  const ledger = makeLedger({
    intents: [tableIntent({
      memo: 'intent-switched',
      created_at: '2020-01-01 00:00:00',      // looks ancient…
      matchable_since: switchedNow,           // …but entered the rail late
    })],
  });
  const state = await runTick({
    cfg, state: fresh(), chain: makeChain([note()]), ledger, log,
  });
  assert.equal(ledger.reports.length, 0);
  assert.ok(state.unmatched['0xn1'], 'the switched intent must not claim the note');
});

test('notes are anchored in block time, not watcher wall-clock', async () => {
  // Downtime scenario: the watcher restarts and scans a note whose
  // block committed an hour ago. An intent minted 30 minutes ago (after
  // the block, before the restart) must NOT be able to claim it — with
  // wall-clock seenAt it would.
  const cfg = makeCfg();
  const log = makeLogCapture();
  const blockTimeMs = Date.now() - 3600_000;
  const mintedAfterBlock = new Date(Date.now() - 1800_000)
    .toISOString().slice(0, 19).replace('T', ' ');
  const ledger = makeLedger({
    intents: [tableIntent({ memo: 'intent-late', created_at: mintedAfterBlock })],
  });
  const state = await runTick({
    cfg, state: fresh(), chain: makeChain([note({ blockTimeMs })]), ledger, log,
  });
  assert.equal(ledger.reports.length, 0);
  assert.ok(state.unmatched['0xn1'], 'parked — the intent postdates the block');
  // and the park keeps the CHAIN time anchor for later ticks
  assert.equal(state.unmatched['0xn1'].firstSeenAt, blockTimeMs);
});

test('settled bookkeeping is pruned after the prune TTL', async () => {
  const cfg = { ...makeCfg(), pruneTtlSec: 60 };
  const log = makeLogCapture();
  const state0 = fresh();
  state0.cursor = 51;
  state0.reported['0xold'] = { memo: 'intent-x', at: Date.now() - 120_000 };
  state0.reported['0xnew'] = { memo: 'intent-y', at: Date.now() };
  state0.deadLettered['0xdead'] = { reason: 'r', at: Date.now() - 120_000 };
  state0.reported['0xlegacy'] = 'intent-legacy'; // pre-timestamp shape

  const state = await runTick({
    cfg, state: state0, chain: makeChain([]), ledger: makeLedger(), log,
  });
  assert.equal(state.reported['0xold'], undefined);
  assert.ok(state.reported['0xnew']);
  assert.equal(state.deadLettered['0xdead'], undefined);
  // legacy entries get stamped, not dropped
  assert.ok(state.reported['0xlegacy'].at);
});

test('unmatched note past TTL is dead-lettered with an alert', async () => {
  const cfg = { ...makeCfg(), unmatchedTtlSec: 60 };
  const log = makeLogCapture();
  const state0 = fresh();
  state0.cursor = 51;
  state0.unmatched['0xold'] = {
    amount: '77', sender: null, firstSeenAt: Date.now() - 120_000,
  };

  const state = await runTick({
    cfg, state: state0, chain: makeChain([]), ledger: makeLedger(), log,
  });
  assert.ok(state.deadLettered['0xold']);
  assert.deepEqual(state.unmatched, {});
  assert.ok(log.lines.alert.some(l => l.includes('UNMATCHED')));
});

test('ambiguous amounts alert and are never guessed', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const two = [
    tableIntent({ memo: 'intent-a' }),
    tableIntent({ memo: 'intent-b' }),
  ];
  const state = await runTick({
    cfg, state: fresh(), chain: makeChain([note()]),
    ledger: makeLedger({ intents: two }), log,
  });
  assert.ok(state.unmatched['0xn1'], 'parked, not reported');
  assert.ok(log.lines.alert.some(l => l.includes('ambiguous')));
});

test('p2ide, wrong-target and wrong-faucet notes are ignored', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const chain = makeChain([
    note({ noteId: '0xa', kind: 'p2ide' }),
    note({ noteId: '0xb', targetOk: false }),
    note({ noteId: '0xc', amount: '0' }),   // no accepted-faucet asset
  ]);
  const ledger = makeLedger({ intents: [tableIntent()] });
  const state = await runTick({ cfg, state: fresh(), chain, ledger, log });
  assert.equal(ledger.reports.length, 0);
  assert.deepEqual(state.pending, {});
  assert.deepEqual(state.unmatched, {});
  assert.ok(log.lines.warn.some(l => l.includes('P2IDE')));
});

test('empty rail config skips the tick', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const chain = makeChain([note()]);
  const ledger = {
    fetchPendingIntents: async () => ({ pay_to_address: '', faucet_id: '', intents: [] }),
    report: async () => { throw new Error('must not be called'); },
  };
  const state = await runTick({ cfg, state: fresh(), chain, ledger, log });
  assert.equal(chain.calls.length, 0);
  assert.equal(state.cursor, null);
  assert.ok(log.lines.warn.some(l => l.includes('rail config')));
});

test('deduplicated server answer counts as done', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const ledger = makeLedger({
    intents: [tableIntent()], reportStatus: 200,
    reportBody: { handled: true, result: { success: true, deduplicated: true } },
  });
  const state = await runTick({
    cfg, state: fresh(), chain: makeChain([note()]), ledger, log,
  });
  assert.equal(state.reported['0xn1'].memo, 'intent-a');
  assert.ok(log.lines.info.some(l => l.includes('deduplicated')));
});
