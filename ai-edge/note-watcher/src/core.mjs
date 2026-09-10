/**
 * Pure decision logic — no SDK, no network, no filesystem, no clock.
 * Everything here is exercised by unit tests without loading the WASM
 * SDK; watcher.mjs wires these decisions to the real chain and ledger.
 *
 * Matching contract (mirrors auth-service):
 *  - The KEY is the intent memo the payer embedded in the note's own
 *    NoteAttachment. Amounts are plain prices and COLLIDE across
 *    same-price intents by design, so a note without a decodable
 *    attachment memo can never be auto-credited — it parks as an ops
 *    case. The exact amount is still required on a memo match: a named
 *    intent paid the wrong amount is refused outright.
 *  - sender_accounts are UNVERIFIED user-claimed labels (squattable at
 *    wallet-bind) — logs and diagnostics only, never an input to
 *    matching.
 */

/**
 * NoteAttachment scheme for "this note pays a Leviathan top-up intent"
 * ("LVT1"). Paying dApps attach the intent memo to the note under this
 * scheme via a wallet Custom transaction (reference encoder below; the
 * client-side copy lives in test_frontend/src/onchain-attach.js — keep
 * them in lockstep). The memo is the ONLY matching key; the exact
 * price amount is a second server-enforced check.
 */
export const TOPUP_ATTACHMENT_SCHEME = 0x4c565431;

/** Max memo byte length the codec accepts. Server memos are ~23 bytes
 *  ("intent-" + 16 hex); the cap just bounds hostile input. */
const MEMO_MAX_BYTES = 64;

/**
 * memo string → attachment {scheme, felts: string[]} (decimal strings —
 * felts stay strings end to end, same rule as amounts).
 * Layout: felt[0] = byte length n (1..=64); felt[i] = big-endian integer
 * of memo bytes [7(i-1), min(7i, n)). 7 bytes/felt keeps every value
 * < 2^56, far below the field modulus; the length prefix makes the
 * chunking reversible (leading-zero bytes survive).
 */
export function encodeMemoAttachment(memo) {
  const bytes = new TextEncoder().encode(memo);
  if (bytes.length < 1 || bytes.length > MEMO_MAX_BYTES) {
    throw new Error(`memo must encode to 1..${MEMO_MAX_BYTES} bytes, got ${bytes.length}`);
  }
  const felts = [String(bytes.length)];
  for (let off = 0; off < bytes.length; off += 7) {
    let v = 0n;
    for (const b of bytes.subarray(off, off + 7)) v = (v << 8n) | BigInt(b);
    felts.push(v.toString());
  }
  return { scheme: TOPUP_ATTACHMENT_SCHEME, felts };
}

/**
 * attachment {scheme, felts} → memo string, or null. Null (never throw)
 * on ANYTHING unexpected — wrong scheme, bad lengths, oversized chunks,
 * non-printable bytes: the attachment is attacker-controlled on-chain
 * data, and a malformed one simply demotes the note to plain
 * amount-matching (fail closed into the stricter path).
 */
export function decodeMemoAttachment(attachment) {
  if (!attachment || attachment.scheme !== TOPUP_ATTACHMENT_SCHEME) return null;
  const felts = attachment.felts;
  if (!Array.isArray(felts) || felts.length < 2) return null;
  let len;
  try { len = Number(BigInt(felts[0])); } catch { return null; }
  if (!Number.isInteger(len) || len < 1 || len > MEMO_MAX_BYTES) return null;
  const chunks = Math.ceil(len / 7);
  if (felts.length !== 1 + chunks) return null;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < chunks; i++) {
    let v;
    try { v = BigInt(felts[1 + i]); } catch { return null; }
    if (v < 0n || v >= (1n << 56n)) return null;
    const n = Math.min(7, len - i * 7);
    for (let j = n - 1; j >= 0; j--) { bytes[i * 7 + j] = Number(v & 0xffn); v >>= 8n; }
    if (v !== 0n) return null; // value wider than the chunk's declared bytes
  }
  let memo;
  try { memo = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return null; }
  return /^[\x21-\x7e]+$/.test(memo) ? memo : null; // printable ASCII, no spaces
}

/**
 * Decide what a candidate note pays for.
 * @param {{noteId: string, amount: string, memoHint?: string|null}} note
 *   `memoHint` is the memo decoded from the note's own attachment
 *   (decodeMemoAttachment), or null when absent/malformed.
 * @param {Array<{memo: string, token_amount: string}>} intents
 *   The matching table.
 * @returns {{kind: 'match', memo: string, viaAttachment: true}
 *          |{kind: 'attachment_mismatch', memo: string, expected: string}
 *          |{kind: 'unattached'}
 *          |{kind: 'unmatched'}}
 *
 * The attachment memo is the ONLY matching key. Amounts are plain
 * prices and collide across same-price intents by design, so a note
 * without a decodable memo ('unattached') can NEVER auto-credit — it
 * is an ops case from the moment it is seen. A memo naming a live
 * intent matches iff the amount is the intent's exact price; a
 * named-but-wrong-amount note is refused outright
 * ('attachment_mismatch', never credited). A memo naming NO live
 * intent is 'unmatched' — kept for re-matching, because the note may
 * have raced the intent listing (the memo is server-drawn randomness:
 * if it never turns up in the table, nobody can mint an intent that
 * claims it later, so re-matching is safe by construction).
 */
export function matchNote(note, intents) {
  if (!note.memoHint) return { kind: 'unattached' };
  const named = intents.find(i => i.memo === note.memoHint);
  if (!named) return { kind: 'unmatched' };
  if (named.token_amount === note.amount) {
    return { kind: 'match', memo: named.memo, viaAttachment: true };
  }
  return { kind: 'attachment_mismatch', memo: named.memo, expected: named.token_amount };
}

/**
 * Map a webhook HTTP status onto the retry contract the server
 * documents: 4xx is PERMANENT (dead-letter + alert, the condition will
 * not change), everything else transient (retry with the next tick).
 * 200 with result.deduplicated is still 'done' — the ledger already
 * holds this payment.
 *
 * Exception inside 4xx: statuses that describe the CALLER or the
 * TRANSPORT, not the note — 401/403 (token rotated out from under us),
 * 408 (timeout), 429 (rate limit). Dead-lettering those would turn one
 * bad token rotation into a hand-replay of every pending payment.
 */
const RETRYABLE_4XX = new Set([401, 403, 408, 429]);

export function classifyReport(status) {
  if (status >= 200 && status < 300) return 'done';
  if (RETRYABLE_4XX.has(status)) return 'retry';
  if (status >= 400 && status < 500) return 'dead_letter';
  return 'retry';
}

/**
 * Ops hint for an UNATTACHED note (no decodable memo — a manual
 * payment, or a wallet path that cannot attach): live intents whose
 * exact price equals the note's amount. Never an input to crediting —
 * matching is memo-only — but the alert that parks the note can name
 * the plausible candidates so ops start from a shortlist instead of
 * the whole table.
 *
 * @param {{amount: string}} note
 * @param {Array<{memo, token_amount}>} intents
 * @returns {string[]} memos of same-amount intents
 */
export function sameAmountMemos(note, intents) {
  return intents
    .filter(i => i.token_amount === note.amount)
    .map(i => i.memo);
}

/** The webhook payload for a matched note. Amount stays a decimal
 *  string end to end — base units can exceed 2^53-1. */
export function buildReport(note, memo, faucetId) {
  return {
    memo,
    note_id: note.noteId,
    faucet_id: faucetId,
    amount_base_units: note.amount,
    note_kind: 'p2id',
  };
}

/**
 * Screen a scanned note down to "candidate payment or not". Everything
 * here is a hard requirement:
 *  - pure P2ID script (P2IDE is reclaimable — committed is not settled);
 *  - the note's REAL target is the gateway account. The sync tag is a
 *    ~16-bit filter, and an attacker can grind an account whose tag
 *    collides with the gateway's, then "pay" the quoted amount to
 *    themselves — without this check the watcher would report money
 *    that never reached us;
 *  - it carries a positive amount of the accepted faucet.
 * Returns a reason string for the log, or null when it qualifies.
 */
export function disqualify(note) {
  if (note.kind !== 'p2id') return `note script is ${note.kind}, not pure p2id`;
  if (!note.targetOk) return 'note does not target the gateway account';
  if (!note.amount || note.amount === '0') return 'no accepted-faucet asset';
  return null;
}
