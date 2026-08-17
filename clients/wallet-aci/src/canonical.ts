/**
 * Canonicalization for wallet-bound ACI.
 *
 * Every payload the wallet signs is hashed over its JCS (RFC 8785) form, and
 * the Edge canonicalizes the object it parsed with its own encoder before
 * checking the signature. That is deliberate: neither side depends on the
 * other's byte framing, so key order, whitespace or a re-serializing proxy
 * cannot break a signature — or slip one past.
 *
 * Protocol: ../../../docs/wallet-bound-aci.md
 */

export const BIND_PURPOSE = 'leviathan.wallet.bind.v1';
export const REQUEST_PURPOSE = 'leviathan.wallet.request.v1';

/** Goldilocks prime — Miden field elements live in [0, p). */
export const GOLDILOCKS_P = (1n << 64n) - (1n << 32n) + 1n;

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

/** The bind statement, exactly as the Edge expects it — no extra fields. */
export interface BindStatement {
  purpose: typeof BIND_PURPOSE;
  service: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  /** Falcon public key, or its Word commitment — lowercase hex, no `0x`. */
  wallet_pub_key: string;
  account_id: string | null;
  /** Ed25519 session key, lowercase hex. */
  session_pub_key: string;
  /** X25519 key used for ACI E2EE, lowercase hex. */
  e2ee_pub_key: string;
  scope: string[];
  max_spend: number;
}

/**
 * JCS canonical bytes.
 *
 * ACI objects carry only integer numbers, so the ECMAScript number-formatting
 * rules of RFC 8785 never come up — non-integers are rejected instead of
 * formatted, which is the same subset the Edge implements.
 */
export function jcs(value: Json): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

function canonicalize(value: Json): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error('aci: only integer numbers may be canonicalized');
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  // RFC 8785 orders members by their UTF-16 code units, which is exactly what
  // the default string comparison does.
  return `{${Object.keys(value)
    .sort()
    .map(k => `${JSON.stringify(k)}:${canonicalize(value[k]!)}`)
    .join(',')}}`;
}

/**
 * Map a statement onto the four field elements the Falcon key signs.
 *
 * Falcon in Miden signs a `Word`, not arbitrary bytes: SHA-512 over the
 * canonical form, split into four little-endian u64 limbs, each reduced mod p.
 * The reduction is load-bearing — an unreduced limb is not a field element and
 * `Word` deserialization rejects it.
 */
export async function statementWordBytes(statement: Json): Promise<Uint8Array> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', jcs(statement) as BufferSource));
  const out = new Uint8Array(32);
  const view = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) {
    let limb = 0n;
    for (let b = 7; b >= 0; b--) {
      limb = (limb << 8n) | BigInt(digest[i * 8 + b]!);
    }
    view.setBigUint64(i * 8, limb % GOLDILOCKS_P, true);
  }
  return out;
}

/** The bytes the session key signs for one API call. */
export async function requestSigningBytes(
  sessionId: string,
  method: string,
  path: string,
  body: Uint8Array,
  ts: number,
  nonce: string
): Promise<Uint8Array> {
  const bodyDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', body as BufferSource));
  return jcs({
    purpose: REQUEST_PURPOSE,
    session: sessionId,
    method: method.toUpperCase(),
    path,
    body_sha256: bytesToHex(bodyDigest),
    ts,
    nonce
  });
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('aci: odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function randomHex(byteLength: number): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}
