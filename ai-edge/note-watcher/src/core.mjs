/**
 * Pure decision logic — no SDK, no network, no filesystem, no clock.
 * Everything here is exercised by unit tests without loading the WASM
 * SDK; watcher.mjs wires these decisions to the real chain and ledger.
 *
 * Matching contract (mirrors auth-service):
 *  - The KEY is the exact dusted token amount. The server guarantees it
 *    is unique among live same-price on-chain intents (create_intent
 *    redraws memos), and the webhook enforces exact equality — so an
 *    exact-amount match is authoritative.
 *  - sender_accounts are UNVERIFIED user-claimed labels (squattable at
 *    wallet-bind). They may tie-break an ambiguity that should never
 *    happen, and they appear in logs — they must never override an
 *    amount decision.
 */

/**
 * Clock-skew allowance between auth-service's created_at stamps and the
 * watcher's own clock when enforcing note/intent time ordering.
 */
export const CREATED_AT_SKEW_MS = 120_000;

/**
 * Decide what a candidate note pays for.
 * @param {{noteId: string, amount: string, sender: string|null,
 *          seenAt: number}} note
 *   `sender` is the hex account id from note metadata (or null);
 *   `seenAt` is when the watcher first observed the note (ms epoch).
 * @param {Array<{memo: string, token_amount: string,
 *                sender_account_ids: string[],
 *                createdAtMs: number|null}>} intents
 *   The matching table, with sender_accounts pre-decoded to hex ids and
 *   created_at pre-parsed to ms epoch (null when unparseable).
 * @returns {{kind: 'match', memo: string, tieBroken: boolean}
 *          |{kind: 'unmatched'}
 *          |{kind: 'ambiguous', memos: string[]}}
 *
 * Time ordering is a hard filter: a payment cannot be FOR an intent
 * that did not exist yet when the note was first seen. Without it, a
 * note parked as unmatched (paid after grace, mistyped amount) invites
 * grinding — mint same-price intents until one's dust equals the parked
 * note's visible amount, then collect the credit. An intent whose
 * created_at fails to parse is excluded (fail closed): a wrongly
 * excluded honest payment parks and alerts loudly, a wrongly included
 * one hands an attacker money.
 */
export function matchNote(note, intents) {
  const candidates = intents.filter(i =>
    i.token_amount === note.amount
    && i.createdAtMs !== null && i.createdAtMs !== undefined
    && i.createdAtMs <= note.seenAt + CREATED_AT_SKEW_MS);
  if (candidates.length === 1) {
    return { kind: 'match', memo: candidates[0].memo, tieBroken: false };
  }
  if (candidates.length === 0) return { kind: 'unmatched' };

  // Server-side slot discipline makes this unreachable unless something
  // is wrong (config drift, server bug). Try the sender hint, but only
  // accept it when it singles out EXACTLY one candidate — a squatted
  // label plus a colliding amount must not pick a winner.
  if (note.sender) {
    const bySender = candidates.filter(
      i => (i.sender_account_ids ?? []).includes(note.sender));
    if (bySender.length === 1) {
      return { kind: 'match', memo: bySender[0].memo, tieBroken: true };
    }
  }
  return { kind: 'ambiguous', memos: candidates.map(i => i.memo) };
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

/** auth-service stamps created_at as SQLite UTC 'YYYY-MM-DD HH:MM:SS';
 *  returns ms epoch, or null when the value doesn't parse (fail closed
 *  in matchNote). */
export function parseCreatedAt(value) {
  if (typeof value !== 'string' || !value) return null;
  const ms = Date.parse(value.replace(' ', 'T') + 'Z');
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Near-miss detector for unmatched notes: intents within one cent of
 * the note's amount but NOT exactly equal. The dust is the only
 * binding on the plain-send path, and it lives entirely in the
 * sub-cent digits — so "right price, wrong dust" is the signature of a
 * hand-typed amount (someone sent 3.00 for a 3.004217 quote). Those
 * notes can NEVER auto-credit (exact match is the security boundary),
 * but they deserve a specific, actionable ALERT naming the likely
 * intent instead of a generic "no matching intent" 48 hours later:
 * ops can eyeball the note and finalise via admin mark-paid (the
 * whole-cent price is intact, so the ledger's cents guard passes).
 *
 * Candidates respect the same time-order rule as real matches — a
 * minted-after-the-note intent must not even be SUGGESTED to ops.
 *
 * @param {{amount: string, seenAt: number}} note
 * @param {Array<{memo, token_amount, createdAtMs}>} intents
 * @param {number} subCentUnits  base units in one cent
 *                               (10^decimals / cents_per_token)
 * @returns {Array<{memo: string, expected: string}>}
 */
export function findNearMisses(note, intents, subCentUnits) {
  if (!Number.isFinite(subCentUnits) || subCentUnits <= 1) return [];
  const got = BigInt(note.amount);
  const window = BigInt(subCentUnits);
  return intents
    .filter(i =>
      i.token_amount !== note.amount
      && i.createdAtMs !== null && i.createdAtMs !== undefined
      && i.createdAtMs <= note.seenAt + CREATED_AT_SKEW_MS)
    .filter(i => {
      const want = BigInt(i.token_amount);
      const diff = want > got ? want - got : got - want;
      return diff < window;
    })
    .map(i => ({ memo: i.memo, expected: i.token_amount }));
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
