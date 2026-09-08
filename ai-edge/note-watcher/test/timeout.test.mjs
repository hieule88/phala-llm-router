import assert from 'node:assert/strict';
import { test } from 'node:test';

import { withTimeout } from '../src/util.mjs';
import { makeLedger } from '../src/ledger.mjs';

const NEVER = () => new Promise(() => {});

test('withTimeout passes results and errors through', async () => {
  assert.equal(await withTimeout(Promise.resolve(42), 1000, 'x'), 42);
  await assert.rejects(
    withTimeout(Promise.reject(new Error('boom')), 1000, 'x'), /boom/);
});

test('withTimeout rejects a hung promise with a named error', async () => {
  await assert.rejects(
    withTimeout(NEVER(), 20, 'syncNotes'),
    /syncNotes timed out after 20ms/);
});

test('a hung fetch cannot park fetchPendingIntents', async () => {
  // The pull-loop failure mode Stripe never has: nothing pushes, nothing
  // retries for us — a silent hang here would stop crediting forever
  // with the process still "alive". The ledger must fail fast even when
  // fetchImpl ignores AbortSignal entirely (as this fake does).
  const ledger = makeLedger({
    authUrl: 'http://auth', token: 't', fetchImpl: NEVER, timeoutMs: 20,
  });
  await assert.rejects(ledger.fetchPendingIntents(), /timed out/);
});

test('a hung report surfaces as a throw (retry path), not a hang', async () => {
  const ledger = makeLedger({
    authUrl: 'http://auth', token: 't', fetchImpl: NEVER, timeoutMs: 20,
  });
  await assert.rejects(ledger.report({ memo: 'm' }), /timed out/);
});
