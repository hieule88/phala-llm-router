import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

import { BuildError, validateBuildRequest, buildTopupPayload, loadWasm } from '../src/builder.mjs';
import { createBuilderServer, makeSerialQueue } from '../src/builder-server.mjs';
import { TOPUP_ATTACHMENT_SCHEME, decodeMemoAttachment } from '../src/core.mjs';

const GOOD = {
  sender_address: 'mtst1ard3m9w34puygyqe5thme4u5dqhsr3np',
  pay_to_address: 'mtst1ard3m9w34puygyqe5thme4u5dqhsr3np',
  faucet_id: 'mtst1azftenneus72ugqqsj9rk7cveqk0eraz',
  token_amount: '3000000',
  memo: 'intent-0101ff56084525b7',
};

// ── validation (pure, no WASM) ───────────────────────────────────────────

test('validateBuildRequest accepts a server-shaped request', () => {
  const v = validateBuildRequest(GOOD);
  assert.equal(v.senderAddress, GOOD.sender_address);
  assert.equal(v.tokenAmount, 3000000n);
  assert.equal(v.memo, GOOD.memo);
});

test('validateBuildRequest accepts the wallet\'s interface-suffixed address form', () => {
  const suffixed = GOOD.sender_address + '_qr7qqq9wr6w';
  const v = validateBuildRequest({ ...GOOD, sender_address: suffixed });
  assert.equal(v.senderAddress, suffixed);   // verbatim — the SDK compares this echo
  // ...but not two suffixes, an empty suffix, or uppercase
  for (const bad of [suffixed + '_x', GOOD.sender_address + '_', GOOD.sender_address + '_QR']) {
    assert.throws(() => validateBuildRequest({ ...GOOD, sender_address: bad }), /sender_address/);
  }
});

test('validateBuildRequest refuses each malformed field with a specific reason', () => {
  const cases = [
    [{ ...GOOD, sender_address: 'not-an-address' }, /sender_address/],
    [{ ...GOOD, pay_to_address: '' }, /pay_to_address/],
    [{ ...GOOD, faucet_id: 'MTST1UPPER' }, /faucet_id/],
    // mainnet payer, testnet gateway — the wallet would only fail later
    [{ ...GOOD, sender_address: 'mm1' + 'q'.repeat(36) }, /different networks/],
    [{ ...GOOD, token_amount: 3000000 }, /token_amount/],   // number, not string
    [{ ...GOOD, token_amount: '0' }, /token_amount/],
    [{ ...GOOD, token_amount: '-5' }, /token_amount/],
    [{ ...GOOD, memo: '' }, /memo/],
    [{ ...GOOD, memo: 'A'.repeat(65) }, /memo/],
    [null, /JSON object/],
  ];
  for (const [body, re] of cases) {
    assert.throws(() => validateBuildRequest(body), (e) => e instanceof BuildError
      && e.status === 400 && re.test(e.message), JSON.stringify(body));
  }
});

// ── the serial queue ─────────────────────────────────────────────────────

test('serial queue runs jobs one at a time and survives a failing job', async () => {
  const serial = makeSerialQueue();
  let active = 0, maxActive = 0;
  const job = (fail) => async () => {
    active++; maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
    if (fail) throw new Error('boom');
    return 'ok';
  };
  const results = await Promise.allSettled([serial(job(false)), serial(job(true)), serial(job(false))]);
  assert.equal(maxActive, 1);
  assert.deepEqual(results.map((r) => r.status), ['fulfilled', 'rejected', 'fulfilled']);
});

// ── the HTTP contract (fake build, no WASM) ──────────────────────────────

async function withServer(deps, fn) {
  const server = createBuilderServer({ log: { info() {}, warn() {}, error() {} }, ...deps });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { await new Promise((r) => server.close(r)); }
}

const fakeBuild = async (v) => ({
  address: v.senderAddress, recipientAddress: v.payToAddress,
  transactionRequest: 'QUJD', note_id: '0x' + '11'.repeat(32),
});
const ready = () => ({ ok: true, wasm: 'ready' });

test('POST /build returns the payload for a valid request', async () => {
  await withServer({ build: fakeBuild, health: ready }, async (base) => {
    const res = await fetch(`${base}/build`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(GOOD),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.address, GOOD.sender_address);
    assert.equal(body.recipientAddress, GOOD.pay_to_address);
    assert.equal(body.transactionRequest, 'QUJD');
    assert.match(body.note_id, /^0x[0-9a-f]{64}$/);
  });
});

test('POST /build rejects garbage with 400 and never calls build', async () => {
  let calls = 0;
  await withServer({ build: async () => { calls++; }, health: ready }, async (base) => {
    for (const body of ['{not json', JSON.stringify({ ...GOOD, memo: '' })]) {
      const res = await fetch(`${base}/build`, { method: 'POST', body });
      assert.equal(res.status, 400);
      assert.ok((await res.json()).error);
    }
  });
  assert.equal(calls, 0);
});

test('bearer is enforced only when configured', async () => {
  await withServer({ build: fakeBuild, health: ready, token: 'secret-token' }, async (base) => {
    const post = (headers) => fetch(`${base}/build`, {
      method: 'POST', headers, body: JSON.stringify(GOOD),
    });
    assert.equal((await post({})).status, 401);
    assert.equal((await post({ authorization: 'Bearer wrong' })).status, 401);
    assert.equal((await post({ authorization: 'Bearer secret-token' })).status, 200);
  });
});

test('/health mirrors the SDK state: 503 while loading, 200 when ready', async () => {
  let state = 'loading';
  const health = () => ({ ok: state === 'ready', wasm: state });
  await withServer({ build: fakeBuild, health }, async (base) => {
    assert.equal((await fetch(`${base}/health`)).status, 503);
    state = 'ready';
    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.equal((await fetch(`${base}/nope`)).status, 404);
  });
});

test('a build that throws is a 500 with the reason, not a hung request', async () => {
  await withServer({ build: async () => { throw new Error('wasm exploded'); }, health: ready },
    async (base) => {
      const res = await fetch(`${base}/build`, { method: 'POST', body: JSON.stringify(GOOD) });
      assert.equal(res.status, 500);
      assert.match((await res.json()).error, /wasm exploded/);
    });
});

// ── the real thing: build with the SDK, read the memo back like the watcher ──
// Skipped when the SDK is not installed locally (CI without the private
// registry); the Docker image always has it.

let sdkPresent = true;
try { createRequire(import.meta.url).resolve('@miden-sdk/miden-sdk'); } catch { sdkPresent = false; }

test('real WASM: payload deserializes and carries memo, amount, faucet, sender; note_id matches',
  { skip: !sdkPresent && 'SDK not installed' }, async () => {
    const wasm = await loadWasm();
    const v = validateBuildRequest(GOOD);
    const payload = buildTopupPayload(wasm, v);

    const back = wasm.TransactionRequest.deserialize(
      new Uint8Array(Buffer.from(payload.transactionRequest, 'base64')));
    const own = back.expectedOutputOwnNotes();
    assert.equal(own.length, 1);
    const note = own[0];
    // The note id the server recorded is the note the payer will publish.
    assert.equal(note.id().toString(), payload.note_id);

    const att = note.metadata().attachment();
    assert.equal(att.attachmentKind(), 2);
    assert.equal(att.attachmentScheme().asU32(), TOPUP_ATTACHMENT_SCHEME);
    const arr = att.asArray();
    const felts = [];
    for (let i = 0; i < arr.length(); i++) felts.push(arr.get(i).asInt().toString());
    assert.equal(decodeMemoAttachment({ scheme: TOPUP_ATTACHMENT_SCHEME, felts }), GOOD.memo);

    const assets = note.assets().fungibleAssets();
    assert.equal(assets.length, 1);
    assert.equal(assets[0].amount(), 3000000n);
    assert.equal(assets[0].faucetId().toBech32(wasm.NetworkId.testnet()).startsWith(GOOD.faucet_id), true);
    assert.equal(note.metadata().noteType(), wasm.NoteType.Public);
  });

test('real WASM: the wallet\'s suffixed address form builds and names the same sender',
  { skip: !sdkPresent && 'SDK not installed' }, async () => {
    const wasm = await loadWasm();
    const bare = validateBuildRequest(GOOD);
    const suffixed = validateBuildRequest({
      ...GOOD, sender_address: GOOD.sender_address + '_qr7qqq9wr6w' });
    const a = buildTopupPayload(wasm, bare);
    const b = buildTopupPayload(wasm, suffixed);
    const senderOf = (p) => wasm.TransactionRequest.deserialize(
      new Uint8Array(Buffer.from(p.transactionRequest, 'base64')))
      .expectedOutputOwnNotes()[0].metadata().sender().toString();
    assert.equal(senderOf(a), senderOf(b), 'both spellings must resolve to one account id');
    assert.equal(b.address, GOOD.sender_address + '_qr7qqq9wr6w');   // echoed verbatim
  });

test('real WASM: two builds of one memo are two different notes (random serial)',
  { skip: !sdkPresent && 'SDK not installed' }, async () => {
    const wasm = await loadWasm();
    const v = validateBuildRequest(GOOD);
    const a = buildTopupPayload(wasm, v);
    const b = buildTopupPayload(wasm, v);
    // This is WHY auth-service stores the payload instead of rebuilding
    // on every retry: a rebuilt payload is a second payable note.
    assert.notEqual(a.note_id, b.note_id);
  });
