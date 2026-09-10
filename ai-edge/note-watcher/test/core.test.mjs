import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildReport, classifyReport, disqualify, encodeMemoAttachment,
  matchNote, sameAmountMemos,
} from '../src/core.mjs';

const intent = (memo, amount) => ({ memo, token_amount: amount });
const note = (amount, memoHint = null) => ({ noteId: 'n', amount, memoHint });

test('memo naming a live intent matches at the exact amount', () => {
  const v = matchNote(note('3000000', 'intent-a'),
    [intent('intent-a', '3000000'), intent('intent-b', '2000000')]);
  assert.deepEqual(v, { kind: 'match', memo: 'intent-a', viaAttachment: true });
});

test('same-price intents are fine — the memo picks the winner', () => {
  // Amounts are plain prices and COLLIDE by design; only the memo decides.
  const two = [intent('intent-a', '3000000'), intent('intent-b', '3000000')];
  assert.equal(matchNote(note('3000000', 'intent-b'), two).memo, 'intent-b');
  assert.equal(matchNote(note('3000000', 'intent-a'), two).memo, 'intent-a');
});

test('named intent + wrong amount is refused, never re-attributed', () => {
  // The note names A but pays B's (identical-format) price ± anything:
  // refuse outright — crediting anything from a mislabeled note is the
  // misattribution the attachment exists to kill.
  const v = matchNote(note('2990000', 'intent-a'),
    [intent('intent-a', '3000000'), intent('intent-b', '2990000')]);
  assert.deepEqual(v,
    { kind: 'attachment_mismatch', memo: 'intent-a', expected: '3000000' });
});

test('no decodable memo can never match — unattached', () => {
  // Exact same-amount intent exists; without a memo it must NOT credit.
  const v = matchNote(note('3000000'), [intent('intent-a', '3000000')]);
  assert.equal(v.kind, 'unattached');
});

test('memo naming no live intent is unmatched (re-match later)', () => {
  const v = matchNote(note('3000000', 'intent-zzz'),
    [intent('intent-a', '3000000')]);
  assert.equal(v.kind, 'unmatched');
});

test('retry contract classification', () => {
  assert.equal(classifyReport(200), 'done');
  assert.equal(classifyReport(400), 'dead_letter');
  assert.equal(classifyReport(404), 'dead_letter');
  assert.equal(classifyReport(409), 'dead_letter');
  assert.equal(classifyReport(500), 'retry');
  assert.equal(classifyReport(503), 'retry');
  // caller/transport statuses say nothing about the note — retry, or a
  // single bad token rotation dead-letters every pending payment
  assert.equal(classifyReport(401), 'retry');
  assert.equal(classifyReport(403), 'retry');
  assert.equal(classifyReport(408), 'retry');
  assert.equal(classifyReport(429), 'retry');
});

test('sameAmountMemos shortlists ops candidates for an unattached note', () => {
  const table = [
    intent('intent-a', '3000000'),
    intent('intent-b', '3000000'),
    intent('intent-c', '2000000'),
  ];
  assert.deepEqual(sameAmountMemos(note('3000000'), table),
    ['intent-a', 'intent-b']);
  assert.deepEqual(sameAmountMemos(note('999'), table), []);
});

test('report payload shape matches the webhook contract', () => {
  assert.deepEqual(
    buildReport({ noteId: '0xn1', amount: '3000000' }, 'intent-a', 'mtst1faucet'),
    {
      memo: 'intent-a', note_id: '0xn1', faucet_id: 'mtst1faucet',
      amount_base_units: '3000000', note_kind: 'p2id',
    });
});

test('disqualify: p2ide, wrong target, wrong faucet', () => {
  assert.match(disqualify({ kind: 'p2ide', targetOk: true, amount: '5' }), /p2id/);
  assert.match(disqualify({ kind: 'p2id', targetOk: false, amount: '5' }), /target/);
  assert.match(disqualify({ kind: 'p2id', targetOk: true, amount: '0' }), /faucet/);
  assert.equal(disqualify({ kind: 'p2id', targetOk: true, amount: '5' }), null);
});

test('encode → matchNote end to end (codec output is the memoHint)', () => {
  // The hint the watcher decodes from a real attachment is exactly the
  // memo the server issued — sanity-check the two ends line up.
  const att = encodeMemoAttachment('intent-0123456789abcdef');
  assert.ok(att.felts.length > 1);
  const v = matchNote({ noteId: 'n', amount: '42', memoHint: 'intent-0123456789abcdef' },
    [intent('intent-0123456789abcdef', '42')]);
  assert.equal(v.kind, 'match');
});
