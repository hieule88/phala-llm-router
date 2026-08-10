/**
 * The session keys that make a Leviathan wallet an AI account.
 *
 *   mnemonic ─ m/44'/0'/t'/i' ─▶ Falcon account key   (root authority)
 *                                  └─ HKDF ─▶ aci_seed
 *                                       ├─ HKDF ─▶ Ed25519  (signs API calls)
 *                                       └─ HKDF ─▶ X25519   (ACI E2EE)
 *
 * Deriving from the account's own secret key rather than from a second HD
 * branch buys three things:
 *
 *   - there is no extra secret to back up — the mnemonic that restores the
 *     wallet restores the AI account too, and an account imported without a
 *     mnemonic still has an AI identity;
 *   - the keys exist only while the vault is unlocked, so locking the wallet
 *     revokes API access by making signatures impossible; and
 *   - HKDF is one-way, so a leaked session key says nothing about the account
 *     key that authorized it.
 *
 * Ed25519 signs each API call; X25519 is the client key for ACI E2EE, so the
 * TEE's receipt binds the inference to the wallet. Both come from the Web
 * Crypto API — no third-party cryptography, same as ../../verifier-ts.
 */

import { bytesToHex } from './canonical.js';

/** Domain separation for the two keys derived from one ACI seed. */
const SIGN_INFO = 'leviathan.aci.v1/sig';
const E2EE_INFO = 'leviathan.aci.v1/e2ee';

/**
 * PKCS#8 wrappers for a bare 32-byte seed. Web Crypto will not import a raw
 * private key for these curves, but the PKCS#8 encoding of a seed-only key is
 * a fixed prefix plus the seed, so this is exact, not a workaround.
 */
const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
]);

export interface AciKeys {
  /** Signs every API call. Its public half is what the bind statement delegates to. */
  signPrivateKey: CryptoKey;
  signPublicKeyHex: string;
  /** ACI E2EE client key (`X-Client-Pub-Key`). */
  e2eePrivateKey: CryptoKey;
  e2eePublicKeyHex: string;
}

/**
 * Derive the ACI seed from the account's Falcon secret key material.
 *
 * `accountKey` (the account's public key, or its commitment) goes into the
 * info string so two accounts of one wallet get unrelated AI identities, and
 * so the same secret can never be stretched into the same seed under another
 * name.
 */
export async function deriveAciSeed(accountSecretKey: Uint8Array, accountKey: string): Promise<Uint8Array> {
  return hkdf(accountSecretKey, `leviathan.aci.v1|${accountKey}`);
}

export async function deriveAciKeys(aciSeed: Uint8Array): Promise<AciKeys> {
  if (aciSeed.length !== 32) {
    throw new Error('aci: seed must be 32 bytes');
  }
  const [signSeed, e2eeSeed] = await Promise.all([hkdf(aciSeed, SIGN_INFO), hkdf(aciSeed, E2EE_INFO)]);
  const [sign, e2ee] = await Promise.all([
    importSeed(signSeed, 'Ed25519', ['sign']),
    importSeed(e2eeSeed, 'X25519', ['deriveBits'])
  ]);

  return {
    signPrivateKey: sign.privateKey,
    signPublicKeyHex: sign.publicKeyHex,
    e2eePrivateKey: e2ee.privateKey,
    e2eePublicKeyHex: e2ee.publicKeyHex
  };
}

async function hkdf(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) as BufferSource },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function importSeed(
  seed: Uint8Array,
  algorithm: 'Ed25519' | 'X25519',
  usages: KeyUsage[]
): Promise<{ privateKey: CryptoKey; publicKeyHex: string }> {
  const prefix = algorithm === 'Ed25519' ? PKCS8_ED25519_PREFIX : PKCS8_X25519_PREFIX;
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);

  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, algorithm, true, usages);
  // The public half is not derivable through Web Crypto's API, but the JWK
  // export of an OKP private key carries it in `x` — which is why the key is
  // imported as extractable.
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  if (!jwk.x) {
    throw new Error(`aci: ${algorithm} export carried no public key`);
  }
  return { privateKey, publicKeyHex: bytesToHex(base64UrlToBytes(jwk.x)) };
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
