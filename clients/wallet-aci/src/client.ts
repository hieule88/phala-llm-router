/**
 * The wallet-side half of wallet-bound ACI.
 *
 * `openAciSession` performs the one Falcon signature that delegates to a
 * session key; `signedFetch` produces the Ed25519 signature that authorizes
 * each individual API call. Nothing here touches a vault — the Falcon
 * signature arrives through a callback — so the same module works in the
 * extension's service worker, in its popup, and in a dApp bridge.
 *
 * Protocol: ../../../docs/wallet-bound-aci.md
 */

import { BIND_PURPOSE, bytesToB64, randomHex, requestSigningBytes, statementWordBytes } from './canonical.js';
import type { BindStatement, Json } from './canonical.js';
import type { AciKeys } from './keys.js';

/** What the confirmation popup asks the user to approve. */
export interface AciAuthorization {
  /** Capabilities this session may use. */
  scope: string[];
  /** Millicredits this session may spend before the user must re-authorize. */
  maxSpendMc: number;
  /** Session lifetime in seconds. The Edge caps this at 24h. */
  ttlSec: number;
}

export const DEFAULT_AUTHORIZATION: AciAuthorization = {
  scope: ['inference', 'receipts', 'models'],
  maxSpendMc: 100_000,
  ttlSec: 12 * 60 * 60
};

export interface AciSession {
  serviceOrigin: string;
  sessionId: string;
  identityId: number;
  expiresAt: number;
  scope: string[];
  maxSpendMc: number;
  balanceMc: number | null;
  /**
   * The statement the user actually approved. Worth keeping: it is the audit
   * trail that ties this session — and every receipt it produces — back to the
   * Miden account.
   */
  statement: BindStatement;
}

/**
 * Signs a 32-byte Miden `Word` with the account's Falcon key, returning the
 * base64 Miden `Signature` serialization. Implemented by the wallet, which
 * prompts the user and requires an unlocked vault.
 *
 * In the Leviathan extension this is `vault.signData(pubKey, b64(word), 'word')`.
 */
export type FalconWordSigner = (wordBytes: Uint8Array) => Promise<string>;

export class AciError extends Error {
  constructor(readonly code: string, message: string, readonly status?: number) {
    super(message);
    this.name = 'AciError';
  }
}

async function readError(res: Response): Promise<AciError> {
  let code = `http_${res.status}`;
  let message = res.statusText || 'request failed';
  try {
    const body = await res.json();
    if (body?.error?.type) code = body.error.type;
    if (body?.error?.message) message = body.error.message;
  } catch {
    // A non-JSON error body is still an error; keep the status-derived text.
  }
  return new AciError(code, message, res.status);
}

/**
 * Bind this wallet to the AI service and open a session.
 *
 * The user sees one confirmation, for a statement that spells out the service,
 * the lifetime and the spend cap — so what they approve is a bounded grant,
 * not an open-ended one.
 */
export async function openAciSession(params: {
  serviceOrigin: string;
  /** Falcon public key or its Word commitment, lowercase hex. */
  walletPubKey: string;
  /** Bech32 Miden address. A label, carried inside the signature. */
  accountId: string | null;
  keys: AciKeys;
  signWord: FalconWordSigner;
  authorization?: Partial<AciAuthorization>;
  fetchImpl?: typeof fetch;
}): Promise<AciSession> {
  const doFetch = params.fetchImpl ?? fetch;
  const origin = params.serviceOrigin.replace(/\/+$/, '');
  const auth = { ...DEFAULT_AUTHORIZATION, ...params.authorization };

  const challengeRes = await doFetch(`${origin}/v1/wallet/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ wallet_pub_key: params.walletPubKey })
  });
  if (!challengeRes.ok) throw await readError(challengeRes);
  const challenge = await challengeRes.json();

  // `issued_at` is derived from the challenge's own expiry, i.e. from the
  // Edge's clock rather than this device's. A skewed local clock would
  // otherwise produce statements rejected as stale, with nothing in the error
  // to explain why.
  const issuedAt = Number(challenge.expires_at) - 300;
  const statement: BindStatement = {
    purpose: BIND_PURPOSE,
    service: origin,
    nonce: challenge.nonce,
    issued_at: issuedAt,
    expires_at: issuedAt + auth.ttlSec,
    wallet_pub_key: params.walletPubKey.toLowerCase(),
    account_id: params.accountId,
    session_pub_key: params.keys.signPublicKeyHex,
    e2ee_pub_key: params.keys.e2eePublicKeyHex,
    scope: auth.scope,
    max_spend_mc: auth.maxSpendMc
  };

  const signature = await params.signWord(await statementWordBytes(statement as unknown as Json));

  const bindRes = await doFetch(`${origin}/v1/wallet/bind`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ statement, signature })
  });
  if (!bindRes.ok) throw await readError(bindRes);
  const bound = await bindRes.json();

  return {
    serviceOrigin: origin,
    sessionId: bound.session_id,
    identityId: bound.identity_id,
    expiresAt: bound.expires_at,
    scope: bound.scope,
    maxSpendMc: bound.max_spend_mc,
    balanceMc: bound.balance_mc ?? null,
    statement
  };
}

/**
 * Call the AI service as this wallet.
 *
 * The signature covers the method, the path and the exact body bytes, so the
 * session id on its own authorizes nothing: lifting it from a log or a proxy
 * gains an attacker no access, and no intermediary can alter the prompt after
 * the wallet signed it.
 */
export async function signedFetch(
  session: AciSession,
  keys: AciKeys,
  init: { path: string; method?: string; body?: string; headers?: Record<string, string> },
  fetchImpl: typeof fetch = fetch
): Promise<Response> {
  const method = (init.method ?? 'POST').toUpperCase();
  const bodyBytes = new TextEncoder().encode(init.body ?? '');
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomHex(16);

  const signature = await crypto.subtle.sign(
    'Ed25519',
    keys.signPrivateKey,
    (await requestSigningBytes(session.sessionId, method, init.path, bodyBytes, ts, nonce)) as BufferSource
  );

  const request: RequestInit = {
    method,
    headers: {
      ...(init.headers ?? {}),
      authorization: `Wallet ${session.sessionId}`,
      'x-wallet-timestamp': String(ts),
      'x-wallet-nonce': nonce,
      'x-wallet-signature': bytesToB64(new Uint8Array(signature))
    }
  };
  // Assigned rather than spread: `exactOptionalPropertyTypes` distinguishes an
  // absent body from an explicitly undefined one, and GET must send neither.
  if (init.body !== undefined) request.body = init.body;

  return fetchImpl(`${session.serviceOrigin}${init.path}`, request);
}

/**
 * End a session server-side. Called when the wallet locks.
 *
 * Best-effort by design: the caller drops the derived keys either way, and
 * without them no further request can be signed — so a failed revoke costs the
 * user nothing.
 */
export async function closeAciSession(
  session: AciSession,
  keys: AciKeys,
  fetchImpl: typeof fetch = fetch
): Promise<boolean> {
  try {
    const res = await signedFetch(
      session,
      keys,
      { path: '/v1/wallet/session/revoke', method: 'POST', body: '' },
      fetchImpl
    );
    return res.ok;
  } catch {
    return false;
  }
}

/** Kill every session of this wallet — the lost-device button. */
export async function revokeAllAciSessions(
  session: AciSession,
  keys: AciKeys,
  fetchImpl: typeof fetch = fetch
): Promise<number> {
  const res = await signedFetch(
    session,
    keys,
    { path: '/v1/wallet/sessions/revoke-all', method: 'POST', body: '' },
    fetchImpl
  );
  if (!res.ok) throw await readError(res);
  return (await res.json()).revoked ?? 0;
}
