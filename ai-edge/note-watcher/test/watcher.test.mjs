import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync } from 'node:fs';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { runTick } from '../src/watcher.mjs';
import { encodeMemoAttachment } from '../src/core.mjs';
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
      token_decimals: 6, cents_per_token: 100, network: 'testnet', intents,
    }),
    report: async (payload) => {
      reports.push(payload);
      return { status: reportStatus, body: reportBody };
    },
  };
}

// The default note carries intent-a's memo in its attachment — the dApp
// Custom-transaction path, which is the only auto-creditable one.
const note = (over = {}) => ({
  noteId: '0xn1', kind: 'p2id', targetOk: true,
  amount: '3000000', sender: null,
  attachment: encodeMemoAttachment('intent-a'), ...over,
});

const tableIntent = (over = {}) => ({
  memo: 'intent-a', token_amount: '3000000', sender_accounts: [], ...over,
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
    amount_base_units: '3000000', note_kind: 'p2id',
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

  // tick 2: the intent shows up — the parked note's stored memoHint
  // matches it and the report goes out
  const ledger2 = makeLedger({ intents: [tableIntent()] });
  state = await runTick({ cfg, state, chain: makeChain([]), ledger: ledger2, log });
  assert.equal(ledger2.reports.length, 1);
  assert.equal(state.reported['0xn1'].memo, 'intent-a');
  assert.deepEqual(state.unmatched, {});
});

test('parked notes keep the block-time anchor for the TTL', async () => {
  // Downtime scenario: the watcher restarts and scans a note whose
  // block committed an hour ago. The unmatched TTL must count from
  // CHAIN time, not from when the watcher happened to see it.
  const cfg = makeCfg();
  const log = makeLogCapture();
  const blockTimeMs = Date.now() - 3600_000;
  const ledger = makeLedger({ intents: [] }); // nothing to match yet
  const state = await runTick({
    cfg, state: fresh(), chain: makeChain([note({ blockTimeMs })]), ledger, log,
  });
  assert.ok(state.unmatched['0xn1']);
  assert.equal(state.unmatched['0xn1'].firstSeenAt, blockTimeMs);
});

test('unattached note alerts once with same-amount shortlist, never credits', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  // a manual payment: right price, but no memo on the note
  const ledger = makeLedger({ intents: [tableIntent()] });
  const manual = note({ attachment: null });

  let state = await runTick({ cfg, state: fresh(), chain: makeChain([manual]), ledger, log });
  assert.equal(ledger.reports.length, 0, 'never auto-credited');
  assert.ok(state.unmatched['0xn1'], 'parked as an ops case');
  const alerts = log.lines.alert.filter(l => l.includes('unattached'));
  assert.equal(alerts.length, 1);
  assert.ok(alerts[0].includes('intent-a'),
    'alert shortlists the same-amount intents for ops');

  // next tick must NOT alert again (re-matching cannot help this note)
  state = await runTick({ cfg, state, chain: makeChain([]), ledger, log });
  assert.equal(log.lines.alert.filter(l => l.includes('unattached')).length, 1);
});

test('named intent with the wrong amount alerts once and never credits', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const ledger = makeLedger({ intents: [tableIntent()] });
  const wrong = note({ amount: '2990000' }); // names intent-a, pays short

  let state = await runTick({ cfg, state: fresh(), chain: makeChain([wrong]), ledger, log });
  assert.equal(ledger.reports.length, 0, 'never auto-credited');
  assert.ok(state.unmatched['0xn1']);
  const alerts = log.lines.alert.filter(l => l.includes('attachment mismatch'));
  assert.equal(alerts.length, 1);
  assert.ok(alerts[0].includes('intent-a') && alerts[0].includes('3000000'));

  state = await runTick({ cfg, state, chain: makeChain([]), ledger, log });
  assert.equal(log.lines.alert.filter(l => l.includes('attachment mismatch')).length, 1);
});

test('beat() fires on every unit of tick progress', async () => {
  // The stall watchdog and the heartbeat file hang off beat(): a tick
  // that is long but moving must keep beating (table fetch, drains,
  // each scanned page).
  const cfg = makeCfg();
  let beats = 0;
  await runTick({
    cfg, state: fresh(), chain: makeChain([note()]),
    ledger: makeLedger({ intents: [tableIntent()] }), log: makeLogCapture(),
    beat: () => { beats += 1; },
  });
  assert.ok(beats >= 4, `expected >=4 beats (table, drain, page, drain), got ${beats}`);
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

test('same-price intents: the memo on the note picks the winner', async () => {
  const cfg = makeCfg();
  const log = makeLogCapture();
  const two = [
    tableIntent({ memo: 'intent-a' }),
    tableIntent({ memo: 'intent-b' }),
  ];
  const state = await runTick({
    cfg, state: fresh(),
    chain: makeChain([note({ attachment: encodeMemoAttachment('intent-b') })]),
    ledger: makeLedger({ intents: two }), log,
  });
  assert.equal(state.reported['0xn1'].memo, 'intent-b');
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
