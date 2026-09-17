/**
 * Server-side top-up payload builder.
 *
 * Produces the exact object a dApp hands to the Leviathan wallet's
 * `requestTransaction({type: 'Custom'})`: a serialized one-output-note
 * TransactionRequest whose public P2ID note pays the gateway the intent's
 * EXACT price and carries the intent memo as a NoteAttachment.
 *
 * Why this lives on the server and not in every frontend:
 *   - the payload contains no secret — sender address (public), gateway
 *     address, faucet, amount, memo. Signing + proving stay in the wallet;
 *   - the memo codec (encodeMemoAttachment) is the SAME module the
 *     watcher decodes with (core.mjs) — one codec, no lockstep drift;
 *   - the SDK build must match the wallet's; that pin becomes an operator
 *     concern (this image) instead of every client's `npm install`.
 *
 * Mirrors test_frontend/src/onchain-attach.js (the original client-side
 * builder), including its two hard-won details: the attachment is built
 * at the WASM level (the high-level createP2IDNote({attachment}) option
 * is silently dropped by this SDK build), and NoteArray MOVES the note
 * handle, so everything read off the note happens BEFORE that line.
 *
 * Node note: the SDK is browser-shaped; ./wasm-preload.mjs must be
 * imported first (see chain.mjs / scripts/smoke-attachment.mjs).
 */

import { encodeMemoAttachment } from './core.mjs';

// Bech32 HRPs of the Miden networks — same light sanity check the
// auth-service applies to its own config (onchain_client.py).
const KNOWN_PREFIXES = ['mm1', 'mtst1', 'mdev1', 'mlcl1', 'mcst1'];

export class BuildError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'BuildError';
    this.status = status;
  }
}

// Both spellings the SDK parses: the bare account id (`mtst1…`) and the
// wallet's Address form with an interface suffix (`mtst1…_qr7qqq9wr6w`,
// what the Leviathan wallet hands dApps as `address`).
function isBech32(addr) {
  return typeof addr === 'string' && addr.length >= 20 && addr.length <= 120
    && /^[a-z0-9]+(?:_[a-z0-9]+)?$/.test(addr) && KNOWN_PREFIXES.some((p) => addr.startsWith(p));
}

function prefixOf(addr) {
  return KNOWN_PREFIXES.find((p) => addr.startsWith(p));
}

/**
 * Validate and normalise a build request. Pure — no WASM — so the HTTP
 * layer can reject garbage before touching the SDK, and tests can pin the
 * contract without the 17 MB module.
 *
 * @returns {{senderAddress, payToAddress, faucetId, tokenAmount: bigint, memo}}
 * @throws {BuildError} 400 with a specific reason
 */
export function validateBuildRequest(body) {
  if (!body || typeof body !== 'object') throw new BuildError('body must be a JSON object');
  const { sender_address, pay_to_address, faucet_id, token_amount, memo } = body;
  for (const [k, v] of Object.entries({ sender_address, pay_to_address, faucet_id })) {
    if (!isBech32(v)) throw new BuildError(`${k} must be a Miden bech32 address`);
  }
  // Sender and gateway must live on the same network: a testnet payer
  // cannot pay a mainnet gateway, and the wallet would only reject it
  // later with a far less useful message.
  if (prefixOf(sender_address) !== prefixOf(pay_to_address)) {
    throw new BuildError('sender_address and pay_to_address are on different networks');
  }
  if (typeof token_amount !== 'string' || !/^[1-9][0-9]{0,38}$/.test(token_amount)) {
    throw new BuildError('token_amount must be a positive integer encoded as a decimal string');
  }
  if (typeof memo !== 'string') throw new BuildError('memo must be a string');
  const memoBytes = Buffer.byteLength(memo, 'utf8');
  if (memoBytes < 1 || memoBytes > 64) throw new BuildError('memo must encode to 1..64 bytes');
  return {
    senderAddress: sender_address,
    payToAddress: pay_to_address,
    faucetId: faucet_id,
    tokenAmount: BigInt(token_amount),
    memo,
  };
}

/**
 * Load the SDK's WASM once (browser shims + bytes preload for Node).
 * Kept lazy so importing this module is free for the HTTP/validation
 * layer and for tests that never build.
 */
let wasmPromise = null;
export function loadWasm() {
  wasmPromise ??= (async () => {
    await import('./wasm-preload.mjs');
    const sdk = await import('@miden-sdk/miden-sdk');
    return sdk.getWasmOrThrow();
  })();
  return wasmPromise;
}

/**
 * Build the wallet payload for one intent.
 *
 * @param {object} wasm   the initialised SDK module (loadWasm())
 * @param {ReturnType<typeof validateBuildRequest>} req
 * @returns {{address: string, recipientAddress: string, transactionRequest: string, note_id: string}}
 *   `transactionRequest` is base64 of TransactionRequest.serialize();
 *   `note_id` is the note the payer will publish — the server learns it
 *   here, BEFORE payment, which the client-side builder could never tell it.
 */
export function buildTopupPayload(wasm, req) {
  const sender = wasm.AccountId.fromBech32(req.senderAddress);
  const target = wasm.AccountId.fromBech32(req.payToAddress);
  const faucet = wasm.AccountId.fromBech32(req.faucetId);

  const { scheme, felts } = encodeMemoAttachment(req.memo);
  const attachment = wasm.NoteAttachment.newArray(
    new wasm.NoteAttachmentScheme(scheme),
    new wasm.FeltArray(felts.map((v) => new wasm.Felt(BigInt(v)))),
  );
  // Public on purpose: the watcher can only observe public notes.
  const note = wasm.Note.createP2IDNote(
    sender, target,
    new wasm.NoteAssets([new wasm.FungibleAsset(faucet, req.tokenAmount)]),
    wasm.NoteType.Public,
    attachment,
  );
  // Read BEFORE the handle is moved into NoteArray below.
  const noteId = note.id().toString();

  const request = new wasm.TransactionRequestBuilder()
    .withOwnOutputNotes(new wasm.NoteArray([note]))
    .build();

  return {
    // `address` is the executor the wallet validates the payload on;
    // `recipientAddress` only feeds the wallet's confirmation-popup label.
    address: req.senderAddress,
    recipientAddress: req.payToAddress,
    transactionRequest: Buffer.from(request.serialize()).toString('base64'),
    note_id: noteId,
  };
}
