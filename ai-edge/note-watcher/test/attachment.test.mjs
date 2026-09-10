import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  TOPUP_ATTACHMENT_SCHEME, decodeMemoAttachment, encodeMemoAttachment,
  matchNote,
} from '../src/core.mjs';
import { runTick } from '../src/watcher.mjs';

// ── codec ────────────────────────────────────────────────────────────────

test('encode/decode round-trips a server-shaped memo', () => {
  const memo = 'intent-0123456789abcdef';
  const att = encodeMemoAttachment(memo);
  assert.equal(att.scheme, TOPUP_ATTACHMENT_SCHEME);
  // 23 bytes → length prefix + ceil(23/7)=4 chunks
  assert.equal(att.felts.length, 5);
  assert.equal(att.felts[0], '23');
  assert.equal(decodeMemoAttachment(att), memo);
});

test('round-trip survives boundary lengths and leading-zero-ish bytes', () => {
  for (const memo of ['x', 'abcdefg', 'abcdefgh', 'A'.repeat(64), 'intent-!' + '~'.repeat(20)]) {
    assert.equal(decodeMemoAttachment(encodeMemoAttachment(memo)), memo, memo);
  }
});

test('encode refuses empty and oversized memos', () => {
  assert.throws(() => encodeMemoAttachment(''));
  assert.throws(() => encodeMemoAttachment('A'.repeat(65)));
});

test('decode fails closed to null on anything unexpected', () => {
  const good = encodeMemoAttachment('intent-0123456789abcdef');
  assert.equal(decodeMemoAttachment(null), null);
  assert.equal(decodeMemoAttachment({}), null);
  // foreign scheme — not ours to interpret
  assert.equal(decodeMemoAttachment({ ...good, scheme: 7 }), null);
  // no payload felts
  assert.equal(decodeMemoAttachment({ scheme: TOPUP_ATTACHMENT_SCHEME, felts: ['5'] }), null);
  // felt count disagrees with the declared length
  assert.equal(decodeMemoAttachment({ ...good, felts: [...good.felts, '0'] }), null);
  assert.equal(decodeMemoAttachment({ ...good, felts: good.felts.slice(0, -1) }), null);
  // declared length out of range
  assert.equal(decodeMemoAttachment({ scheme: TOPUP_ATTACHMENT_SCHEME, felts: ['0', '65'] }), null);
  assert.equal(decodeMemoAttachment({ scheme: TOPUP_ATTACHMENT_SCHEME, felts: ['65', ...Array(10).fill('65')] }), null);
  // non-numeric felt
  assert.equal(decodeMemoAttachment({ ...good, felts: ['23', 'zzz', ...good.felts.slice(2)] }), null);
  // chunk value ≥ 2^56
  assert.equal(decodeMemoAttachment({
    ...good, felts: [good.felts[0], (1n << 56n).toString(), ...good.felts.slice(2)],
  }), null);
  // last chunk wider than its declared byte count (23 % 7 = 2 bytes max)
  assert.equal(decodeMemoAttachment({
    ...good, felts: [...good.felts.slice(0, -1), (1n << 17n).toString()],
  }), null);
  // non-printable / space bytes decode but are refused
  assert.equal(decodeMemoAttachment(encodeMemoAttachment('a b')), null);
  assert.equal(decodeMemoAttachment(encodeMemoAttachment('a\x01b')), null);
});

// ── matching ─────────────────────────────────────────────────────────────

const intents = () => ([
  { memo: 'intent-a', token_amount: '3001234', sender_account_ids: [], createdAtMs: 1000 },
  { memo: 'intent-b', token_amount: '3005678', sender_account_ids: [], createdAtMs: 1000 },
]);

test('attachment memo matches its intent at the exact amount', () => {
  const v = matchNote(
    { noteId: '0xn', amount: '3001234', sender: null, seenAt: 5000, memoHint: 'intent-a' },
    intents());
  assert.deepEqual(v, { kind: 'match', memo: 'intent-a', tieBroken: false, viaAttachment: true });
});

test('attachment match skips the time-order filter (memo is unforgeable in advance)', () => {
  const late = [{ memo: 'intent-a', token_amount: '3001234', sender_account_ids: [],
                  createdAtMs: 10_000_000 }];
  const v = matchNote(
    { noteId: '0xn', amount: '3001234', sender: null, seenAt: 5000, memoHint: 'intent-a' },
    late);
  assert.equal(v.kind, 'match');
  assert.equal(v.viaAttachment, true);
});

test('named intent + wrong amount is refused even when another intent matches exactly', () => {
  // note pays intent-b's exact amount but NAMES intent-a: crediting b
  // would be exactly the misattribution the attachment exists to kill.
  const v = matchNote(
    { noteId: '0xn', amount: '3005678', sender: null, seenAt: 5000, memoHint: 'intent-a' },
    intents());
  assert.deepEqual(v, { kind: 'attachment_mismatch', memo: 'intent-a', expected: '3001234' });
});

test('memoHint naming no live intent falls through to amount matching', () => {
  const v = matchNote(
    { noteId: '0xn', amount: '3001234', sender: null, seenAt: 5000, memoHint: 'intent-zzz' },
    intents());
  assert.deepEqual(v, { kind: 'match', memo: 'intent-a', tieBroken: false });
});

test('no memoHint keeps the plain amount path byte-identical', () => {
  const v = matchNote(
    { noteId: '0xn', amount: '3001234', sender: null, seenAt: 5000 },
    intents());
  assert.deepEqual(v, { kind: 'match', memo: 'intent-a', tieBroken: false });
});

// ── end-to-end tick ──────────────────────────────────────────────────────

function makeCfg() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'watcher-att-test-'));
  return {
    stateFile: path.join(dir, 'state.json'),
    deadLetterFile: path.join(dir, 'dead.jsonl'),
    finalityDepth: 0, scanLookback: 100,
    unmatchedTtlSec: 3600, pruneTtlSec: 30 * 24 * 3600,
  };
}

const makeLog = () => {
  const lines = { info: [], warn: [], alert: [] };
  return { lines, info: m => lines.info.push(m), warn: m => lines.warn.push(m),
           alert: m => lines.alert.push(m) };
};

function harness({ notes, intents: tableIntents, reportStatus = 200 }) {
  const reports = [];
  return {
    cfg: makeCfg(),
    state: { cursor: null, pending: {}, reported: {}, deadLettered: {}, unmatched: {} },
    chain: {
      bech32ToHex: b => `hex(${b})`,
      tip: async () => 50,
      scan: async (from, to) => ({ notes, blockTo: to }),
    },
    ledger: {
      reports,
      fetchPendingIntents: async () => ({
        pay_to_address: 'mtst1gateway', faucet_id: 'mtst1faucet',
        token_decimals: 6, cents_per_token: 100, intents: tableIntents,
      }),
      report: async p => { reports.push(p); return { status: reportStatus, body: null }; },
    },
    log: makeLog(),
  };
}

test('runTick credits a note carrying a valid memo attachment', async () => {
  const h = harness({
    notes: [{
      noteId: '0xatt', kind: 'p2id', targetOk: true, amount: '3001234',
      sender: null, blockTimeMs: 5000,
      attachment: encodeMemoAttachment('intent-a'),
    }],
    // intent enters the table AFTER the note's block time: the amount
    // path would exclude it (time order) — the attachment must not.
    intents: [{ memo: 'intent-a', token_amount: '3001234', sender_accounts: [],
                created_at: '2030-01-01 00:00:00' }],
  });
  const state = await runTick(h);
  assert.equal(h.ledger.reports.length, 1);
  assert.equal(h.ledger.reports[0].memo, 'intent-a');
  assert.equal(h.ledger.reports[0].note_id, '0xatt');
  assert.equal(state.reported['0xatt'].memo, 'intent-a');
  assert.ok(h.log.lines.info.some(m => m.includes('attachment')));
});

test('runTick parks + alerts once on attachment/amount mismatch, keeps hint for re-match', async () => {
  const h = harness({
    notes: [{
      noteId: '0xbad', kind: 'p2id', targetOk: true, amount: '9999999',
      sender: null, blockTimeMs: Date.now(),
      attachment: encodeMemoAttachment('intent-a'),
    }],
    intents: [{ memo: 'intent-a', token_amount: '3001234', sender_accounts: [],
                created_at: '2020-01-01 00:00:00' }],
  });
  let state = await runTick(h);
  assert.equal(h.ledger.reports.length, 0);
  assert.equal(state.unmatched['0xbad'].memoHint, 'intent-a');
  assert.equal(state.unmatched['0xbad'].mismatchAlerted, true);
  const alerts1 = h.log.lines.alert.filter(m => m.includes('attachment mismatch')).length;
  assert.equal(alerts1, 1);
  // second tick: still parked, no duplicate alert
  state = await runTick({ ...h, state });
  assert.ok(state.unmatched['0xbad']);
  const alerts2 = h.log.lines.alert.filter(m => m.includes('attachment mismatch')).length;
  assert.equal(alerts2, 1);
});

test('runTick: malformed attachment demotes the note to plain amount matching', async () => {
  const h = harness({
    notes: [{
      noteId: '0xmal', kind: 'p2id', targetOk: true, amount: '3001234',
      sender: null, blockTimeMs: Date.now(),
      attachment: { scheme: 12345, felts: ['1', '2', '3'] }, // foreign scheme
    }],
    intents: [{ memo: 'intent-a', token_amount: '3001234', sender_accounts: [],
                created_at: '2020-01-01 00:00:00' }],
  });
  const state = await runTick(h);
  assert.equal(h.ledger.reports.length, 1);
  assert.equal(h.ledger.reports[0].memo, 'intent-a');
  assert.equal(state.reported['0xmal'].memo, 'intent-a');
});
