/**
 * Capture a real (public_key, word, signature) triple from the wallet's own
 * SDK build — the release gate of docs/wallet-bound-aci.md §10.
 *
 * The wallet signs with `@miden-sdk/miden-sdk` (WASM); wallet-verifier parses
 * with the `miden-crypto` crate. The Falcon signature encoding is NOT stable
 * across Miden generations, so a verifier that was never tested against a
 * signature from the exact wallet build may fail closed on every bind. This
 * script produces that test input.
 *
 * It mirrors the extension's key path EXACTLY (leviathan/wallet
 * src/lib/miden/back/vault.ts — read, never modified):
 *
 *   1. new wallet: BIP-39 mnemonic                        (createWallet)
 *   2. seed      : Bip39.mnemonicToSeedSync(mnemonic)     (deriveClientSeed)
 *   3. child     : derivePath("m/44'/0'/0'/0'", seed)     (getMainDerivationPath,
 *                                                          OnChain type, account 0)
 *   4. key       : AuthSecretKey.rpoFalconWithRNG(child)
 *   5. sign      : sk.sign(Word.deserialize(bytes32))     (signData kind 'word')
 *   6. output    : base64(signature.serialize())
 *
 * Run:  npm install && npm run capture
 * Then: cd ../.. && cargo test   (the vector gate reads tests/vectors/*.json)
 *
 * The wallet it creates is a THROWAWAY: the mnemonic is printed so you can
 * optionally import it into the extension and cross-check that the extension
 * build signs identically — never fund it, never use it for anything real.
 */

import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { derivePath } from '@demox-labs/aleo-hd-key';
import * as Bip39 from 'bip39';

const require = createRequire(import.meta.url);

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(HERE, '..', 'vectors');
const SDK_VERSION = require('@miden-sdk/miden-sdk/package.json').version;

// The build the extension actually ships (leviathan/wallet package.json). The
// public npm 0.15.0 is the same upstream generation and normally serializes
// identically, but the RELEASE gate wants a vector from this exact build:
//   GITEA_NPM_TOKEN=<token> npm run install:wallet-build && npm run capture
const EXPECTED_WALLET_BUILD = '0.15.0-node.5e72c326';

// ─── Load the SDK (node build; may export directly or behind an init) ───────

async function loadSdk() {
  const mod = await import('@miden-sdk/miden-sdk');
  const sdk = mod.AuthSecretKey ? mod : mod.default;
  if (!sdk?.AuthSecretKey || !sdk?.Word) {
    throw new Error(
      `@miden-sdk/miden-sdk@${SDK_VERSION} does not export AuthSecretKey/Word ` +
      `(got: ${Object.keys(mod).join(', ')})`
    );
  }
  return sdk;
}

/**
 * The package's napi-compat wrapper converts Buffer args to plain arrays, but
 * some native methods (`Word.deserialize`) are declared with a Buffer type and
 * reject arrays. Load the RAW napi module (same classes, same prototypes — a
 * raw Word is accepted by a wrapped AuthSecretKey) for those calls. An
 * absolute-path import bypasses the package's `exports` map.
 */
async function loadRawSdk() {
  const pkgDir = dirname(require.resolve('@miden-sdk/miden-sdk/package.json'));
  const loader = await import(pathToFileURL(join(pkgDir, 'js', 'node', 'loader.js')).href);
  return loader.loadNativeModule();
}

// ─── §3.1 statement → Word mapping (mirror of clients/wallet-aci canonical.ts) ─

const GOLDILOCKS_P = (1n << 64n) - (1n << 32n) + 1n;

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('only integers');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
}

function statementWordBytes(statement) {
  const digest = createHash('sha512').update(Buffer.from(jcs(statement), 'utf8')).digest();
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    const limb = digest.readBigUInt64LE(i * 8) % GOLDILOCKS_P;
    out.writeBigUInt64LE(limb, i * 8);
  }
  return out;
}

function wordFromLimbs(limbs) {
  const out = Buffer.alloc(32);
  limbs.forEach((l, i) => out.writeBigUInt64LE(BigInt(l), i * 8));
  return out;
}

// ─── Public-key extraction (API names differ across SDK generations) ─────────

function tryCall(obj, names) {
  for (const name of names) {
    if (typeof obj?.[name] === 'function') {
      try {
        const v = obj[name]();
        if (v !== undefined && v !== null) return { name, value: v };
      } catch { /* next candidate */ }
    }
  }
  return null;
}

function toHex(v) {
  if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
  const ser = tryCall(v, ['serialize', 'toBytes', 'to_bytes']);
  if (ser && ser.value instanceof Uint8Array) return Buffer.from(ser.value).toString('hex');
  return null;
}

function extractPublicKeys(sk) {
  const keys = {};
  const pk = tryCall(sk, ['publicKey', 'getPublicKey', 'public_key', 'pubKey']);
  if (pk) {
    const full = toHex(pk.value);
    if (full) keys.full_hex = full;
    const commit = tryCall(pk.value, ['toCommitment', 'commitment', 'toWord', 'intoWord', 'digest']);
    if (commit) {
      const c = toHex(commit.value);
      if (c) keys.commitment_hex = c;
    }
  }
  return keys;
}

// ─── Main ────────────────────────────────────────────────────────────────────

const sdk = await loadSdk();
const raw = await loadRawSdk();
const { AuthSecretKey } = sdk;
const Word = raw.Word ?? sdk.Word;

// 1-3. A brand-new Leviathan wallet, exactly as the extension creates one:
//      fresh mnemonic, OnChain type (index 0), HD account 0.
const mnemonic = Bip39.generateMnemonic();
const seed = Bip39.mnemonicToSeedSync(mnemonic);
const DERIVATION_PATH = "m/44'/0'/0'/0'";
const { seed: childSeed } = derivePath(DERIVATION_PATH, seed.toString('hex'));

// 4. The account's Falcon-512 auth key.
const sk = AuthSecretKey.rpoFalconWithRNG(new Uint8Array(childSeed));

const publicKeys = extractPublicKeys(sk);
if (!publicKeys.full_hex && !publicKeys.commitment_hex) {
  console.error(
    'Could not extract a public key from AuthSecretKey.\n' +
    `Available methods: ${Object.getOwnPropertyNames(Object.getPrototypeOf(sk)).join(', ')}\n` +
    'Adjust extractPublicKeys() for this SDK build.'
  );
  process.exit(1);
}

// 5. Sign two words, the way vault.signData(kind='word') does.
//    - a fixed word (stable, easy to eyeball in the Rust test)
//    - a §3.1-mapped word over a realistic bind statement (covers the real path)
const sampleStatement = {
  purpose: 'leviathan.wallet.bind.v1',
  service: 'https://ai.leviathan.example',
  nonce: randomBytes(32).toString('hex'),
  issued_at: 1765000000,
  expires_at: 1765043200,
  wallet_pub_key: publicKeys.commitment_hex ?? publicKeys.full_hex,
  account_id: null,
  session_pub_key: randomBytes(32).toString('hex'),
  e2ee_pub_key: randomBytes(32).toString('hex'),
  scope: ['inference', 'receipts'],
  max_spend: 100,
};

const cases = [
  { name: 'fixed-word', wordBytes: wordFromLimbs([1, 2, 3, 4]) },
  { name: 'bind-statement', wordBytes: statementWordBytes(sampleStatement), statement: sampleStatement },
];

const vectors = cases.map(({ name, wordBytes, statement }) => {
  const word = Word.deserialize(wordBytes);            // vault.ts:588
  const signature = sk.sign(word);                     // vault.ts:589
  const signatureB64 = Buffer.from(signature.serialize()).toString('base64'); // vault.ts:597-598
  const v = {
    name,
    message_word_hex: Buffer.from(wordBytes).toString('hex'),
    signature_b64: signatureB64,
  };
  if (statement) v.statement = statement;
  return v;
});

// 6. Write the vector file the Rust gate test consumes.
const isWalletBuild = SDK_VERSION === EXPECTED_WALLET_BUILD;
const out = {
  sdk: `@miden-sdk/miden-sdk@${SDK_VERSION}`,
  source: isWalletBuild ? 'wallet-exact-build' : 'public-npm-fallback',
  derivation_path: DERIVATION_PATH,
  note: 'Throwaway wallet created by capture.mjs; never funded, never reused.',
  public_keys: publicKeys,
  vectors,
};

mkdirSync(VECTORS_DIR, { recursive: true });
const outPath = join(VECTORS_DIR, `wallet-${SDK_VERSION}.json`);
writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n');

console.log(`vector written: ${outPath}`);
console.log(`public key forms: ${Object.keys(publicKeys).join(', ')}`);
if (!isWalletBuild) {
  console.log('');
  console.log(`WARNING: captured with public npm ${SDK_VERSION}, not the wallet's exact`);
  console.log(`build ${EXPECTED_WALLET_BUILD}. Good enough to develop against; before a`);
  console.log('RELEASE, re-capture with the wallet build:');
  console.log('  GITEA_NPM_TOKEN=<token> npm run install:wallet-build && npm run capture');
}
console.log('');
console.log('THROWAWAY test wallet (never fund it). To cross-check against the');
console.log('real extension build, import this mnemonic there and sign the same word:');
console.log(`  ${mnemonic}`);
console.log('');
console.log('Now run the gate:  cd ../.. && cargo test');
