/**
 * Attachment-path smoke: proves, against the REAL WASM SDK build, the
 * one chain the unit tests cannot cover — that the memo survives the
 * full dApp → wallet → watcher round trip:
 *
 *   1. encodeMemoAttachment (our codec) → NoteAttachment.newArray
 *      (scheme LVT1) is accepted by the protocol;
 *   2. Note.createP2IDNote embeds it — the exact call
 *      test_frontend/src/onchain-attach.js makes;
 *   3. TransactionRequestBuilder → serialize → base64 → deserialize
 *      — the exact payload contract of the wallet's
 *      requestTransaction({type:'Custom'}) (builder.ts does
 *      TransactionRequest.deserialize on our bytes);
 *   4. note.metadata().attachment() reads the memo back — the exact
 *      calls chain.mjs makes — and decodeMemoAttachment returns the
 *      original memo.
 *
 * Needs no chain, no wallet, no money: run it after every SDK version
 * bump. Exits 0 on success, 1 with a stage name on failure.
 *
 *   npm run smoke:attachment
 *
 * Node note: the SDK's WASM loader fetches its .wasm via a file:// URL,
 * which Node's fetch may refuse — so the bytes are pre-loaded and
 * handed to the module through the loader's __wbgInitArg escape hatch
 * (the same one the wallet's rayon workers use).
 */

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

import { TOPUP_ATTACHMENT_SCHEME, decodeMemoAttachment, encodeMemoAttachment }
  from '../src/core.mjs';

const stage = (name) => console.log(`── ${name}`);
const fail = (name, err) => {
  console.error(`FAIL at ${name}: ${err?.stack ?? err}`);
  process.exit(1);
};

// ── load the WASM under node ─────────────────────────────────────────
// Browser-global shims + wasm-bytes preload live in ../src/wasm-preload.mjs
// (the same module chain.mjs loads first in the real watcher).
let wasm;
try {
  stage('load SDK WASM (node)');
  await import('../src/wasm-preload.mjs');
  const sdk = await import('@miden-sdk/miden-sdk');
  wasm = await sdk.getWasmOrThrow();
  const require = createRequire(import.meta.url);
  const pkgMain = require.resolve('@miden-sdk/miden-sdk');
  console.log(`   SDK version: ${JSON.parse(readFileSync(
    path.join(path.dirname(pkgMain), '..', 'package.json'), 'utf8')).version}`);
} catch (e) { fail('load SDK WASM', e); }

const memo = process.env.SMOKE_MEMO ?? 'intent-0123456789abcdef';

// ── 1. our codec → a protocol-level NoteAttachment ───────────────────
let attachment;
try {
  stage(`build NoteAttachment (scheme LVT1, memo=${memo})`);
  const { scheme, felts } = encodeMemoAttachment(memo);
  attachment = wasm.NoteAttachment.newArray(
    new wasm.NoteAttachmentScheme(scheme),
    new wasm.FeltArray(felts.map((v) => new wasm.Felt(BigInt(v)))),
  );
} catch (e) { fail('build NoteAttachment', e); }

// ── 2. the note the dApp builds ──────────────────────────────────────
let note;
try {
  stage('Note.createP2IDNote with the attachment');
  const sender = wasm.TestUtils.createMockAccountId();
  const target = wasm.TestUtils.createMockAccountId();
  const faucetEnv = process.env.ONCHAIN_FAUCET_ID;
  const faucet = faucetEnv
    ? wasm.AccountId.fromBech32(faucetEnv)
    : wasm.TestUtils.createMockAccountId();
  note = wasm.Note.createP2IDNote(
    sender, target,
    new wasm.NoteAssets([new wasm.FungibleAsset(faucet, 3_000_000n)]),
    wasm.NoteType.Public,
    attachment,
  );
} catch (e) { fail('createP2IDNote', e); }

// ── 3. what the watcher reads back (checked BEFORE the note handle is
//       consumed: wasm arrays MOVE their elements, like NoteTag does) ─
const readMemoBack = (label, n) => {
  const att = n.metadata().attachment();
  const kind = att.attachmentKind();
  if (kind !== 2) throw new Error(`${label}: attachment kind ${kind}, expected 2 (Array)`);
  const scheme = att.attachmentScheme().asU32();
  if (scheme !== TOPUP_ATTACHMENT_SCHEME) {
    throw new Error(`${label}: scheme 0x${scheme.toString(16)}, expected LVT1`);
  }
  const arr = att.asArray();
  const felts = [];
  for (let i = 0; i < arr.length(); i++) felts.push(arr.get(i).asInt().toString());
  const decoded = decodeMemoAttachment({ scheme, felts });
  if (decoded !== memo) {
    throw new Error(`${label}: decoded ${JSON.stringify(decoded)}, expected ${JSON.stringify(memo)}`);
  }
  console.log(`   ${label}: memo read back OK (${felts.length} felts)`);
};
try {
  stage('metadata().attachment() on the built note');
  readMemoBack('built note', note);
} catch (e) { fail('read attachment (built note)', e); }

// ── 4. the wallet payload round trip ─────────────────────────────────
let roundTripped;
try {
  stage('TransactionRequest serialize → base64 → deserialize');
  // NOTE: this build's withOwnOutputNotes takes NoteArray (per its own
  // .d.ts), NOT OutputNoteArray as the SDK's high-level send(returnNote)
  // recipe suggests — that recipe targets a newer crate. Verified here.
  const request = new wasm.TransactionRequestBuilder()
    .withOwnOutputNotes(new wasm.NoteArray([note]))
    .build();
  const b64 = Buffer.from(request.serialize()).toString('base64');
  console.log(`   payload size: ${b64.length} base64 chars`);
  const back = wasm.TransactionRequest.deserialize(
    new Uint8Array(Buffer.from(b64, 'base64')));
  const own = back.expectedOutputOwnNotes();
  if (own.length !== 1) throw new Error(`expected 1 own output note, got ${own.length}`);
  roundTripped = own[0];
} catch (e) { fail('TransactionRequest round trip', e); }

// ── 5. the same read on the note that came OUT of the payload ────────
try {
  stage('metadata().attachment() on the deserialized note');
  readMemoBack('deserialized note', roundTripped);
} catch (e) { fail('read attachment (deserialized note)', e); }

console.log('OK: memo survives dApp → wallet payload → watcher read, on the real SDK build.');
