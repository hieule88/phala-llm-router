import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  CREATED_AT_SKEW_MS, buildReport, classifyReport, disqualify, matchNote,
  parseCreatedAt,
} from '../src/core.mjs';

// createdAtMs defaults to 0 (epoch) — before any test note's seenAt.
const intent = (memo, amount, senders = [], createdAtMs = 0) =>
  ({ memo, token_amount: amount, sender_account_ids: senders, createdAtMs });

const NOW = 1_700_000_000_000;
const note = (amount, sender = null, seenAt = NOW) =>
  ({ noteId: 'n', amount, sender, seenAt });

test('exact amount with one candidate matches', () => {
  const v = matchNote(note('3001234'),
    [intent('intent-a', '3001234'), intent('intent-b', '2005678')]);
  assert.deepEqual(v, { kind: 'match', memo: 'intent-a', tieBroken: false });
});

test('no candidate is unmatched', () => {
  const v = matchNote(note('999'), [intent('intent-a', '3001234')]);
  assert.equal(v.kind, 'unmatched');
});

test('an intent created after the note was seen can never claim it', () => {
  // The grind defence: park a note, mint same-price intents until the
  // dust collides — time ordering makes the minted intent ineligible.
  const late = intent('intent-grind', '3001234', [], NOW + CREATED_AT_SKEW_MS + 1);
  assert.equal(matchNote(note('3001234'), [late]).kind, 'unmatched');

  // within clock skew still matches (honest same-moment creation)
  const nearby = intent('intent-a', '3001234', [], NOW + CREATED_AT_SKEW_MS - 1);
  assert.equal(matchNote(note('3001234'), [nearby]).kind, 'match');
});

test('unparseable created_at is excluded, fail closed', () => {
  const broken = intent('intent-a', '3001234', [], null);
  assert.equal(matchNote(note('3001234'), [broken]).kind, 'unmatched');
});

test('collision resolved only when sender singles out exactly one', () => {
  const two = [
    intent('intent-a', '3001234', ['0xaaa']),
    intent('intent-b', '3001234', ['0xbbb']),
  ];
  const bySender = matchNote(note('3001234', '0xbbb'), two);
  assert.deepEqual(bySender, { kind: 'match', memo: 'intent-b', tieBroken: true });

  // sender matches neither → ambiguous, never a guess
  const unknown = matchNote(note('3001234', '0xccc'), two);
  assert.equal(unknown.kind, 'ambiguous');
  assert.deepEqual(unknown.memos, ['intent-a', 'intent-b']);

  // sender matches BOTH (squatted label) → still ambiguous
  const both = [
    intent('intent-a', '3001234', ['0xeee']),
    intent('intent-b', '3001234', ['0xeee']),
  ];
  assert.equal(matchNote(note('3001234', '0xeee'), both).kind, 'ambiguous');
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

test('parseCreatedAt handles the SQLite UTC format and garbage', () => {
  assert.equal(parseCreatedAt('2026-09-07 10:00:00'),
    Date.parse('2026-09-07T10:00:00Z'));
  assert.equal(parseCreatedAt('not a date'), null);
  assert.equal(parseCreatedAt(''), null);
  assert.equal(parseCreatedAt(undefined), null);
});

test('report payload shape matches the webhook contract', () => {
  assert.deepEqual(
    buildReport({ noteId: '0xn1', amount: '3001234' }, 'intent-a', 'mtst1faucet'),
    {
      memo: 'intent-a', note_id: '0xn1', faucet_id: 'mtst1faucet',
      amount_base_units: '3001234', note_kind: 'p2id',
    });
});

test('disqualify: p2ide, wrong target, wrong faucet', () => {
  assert.match(disqualify({ kind: 'p2ide', targetOk: true, amount: '5' }), /p2id/);
  assert.match(disqualify({ kind: 'p2id', targetOk: false, amount: '5' }), /target/);
  assert.match(disqualify({ kind: 'p2id', targetOk: true, amount: '0' }), /faucet/);
  assert.equal(disqualify({ kind: 'p2id', targetOk: true, amount: '5' }), null);
});
