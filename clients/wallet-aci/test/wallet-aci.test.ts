/**
 * Tests for the wallet side of wallet-bound ACI.
 *
 *   npm test        (from clients/wallet-aci/)
 *
 * The Falcon signer is stubbed — that key lives in the wallet vault and its
 * verification has its own Rust tests. What matters here is that this client
 * produces exactly the bytes the Edge recomputes: the same JCS, the same
 * `Word`, the same request payload. Where a value is pinned, the Python side
 * (ai-edge/wallet_auth.py) pins the identical construction.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import {
  BIND_PURPOSE,
  bytesToHex,
  closeAciSession,
  deriveAciKeys,
  deriveAciSeed,
  GOLDILOCKS_P,
  jcs,
  openAciSession,
  requestSigningBytes,
  signedFetch,
  statementWordBytes,
  type AciKeys,
  type AciSession,
  type BindStatement,
  type Json
} from '../src/index.js';

const SERVICE = 'https://ai.leviathan.test';
const WALLET_PK = 'ab'.repeat(64);

function statement(overrides: Partial<BindStatement> = {}): BindStatement {
  return {
    purpose: BIND_PURPOSE,
    service: SERVICE,
    nonce: 'aa'.repeat(32),
    issued_at: 1765000000,
    expires_at: 1765043200,
    wallet_pub_key: WALLET_PK,
    account_id: 'mtst1qexample',
    session_pub_key: 'cd'.repeat(32),
    e2ee_pub_key: 'ef'.repeat(32),
    scope: ['inference', 'receipts', 'models'],
    max_spend: 100,
    ...overrides
  };
}

async function keys(seedByte = 7): Promise<AciKeys> {
  return deriveAciKeys(new Uint8Array(32).fill(seedByte));
}

// ─── Canonicalization ────────────────────────────────────────────────────────

test('jcs sorts keys and drops whitespace', () => {
  assert.equal(
    new TextDecoder().decode(jcs({ b: 1, a: [2, { d: 3, c: 4 }] } as Json)),
    '{"a":[2,{"c":4,"d":3}],"b":1}'
  );
});

test('jcs rejects non-integer numbers', () => {
  assert.throws(() => jcs({ a: 1.5 } as Json), /integer/);
});

test('key order does not change the signed word', async () => {
  const a = statement();
  const shuffled = Object.fromEntries(Object.entries(a).reverse()) as unknown as BindStatement;
  assert.deepEqual(
    await statementWordBytes(a as unknown as Json),
    await statementWordBytes(shuffled as unknown as Json)
  );
});

test('statement word is four reduced little-endian limbs of SHA-512', async () => {
  // The construction the Edge recomputes (docs/wallet-bound-aci.md §3.1). A
  // mismatch here is an outage, not a test failure.
  const stmt = statement();
  const digest = createHash('sha512').update(jcs(stmt as unknown as Json)).digest();
  const word = await statementWordBytes(stmt as unknown as Json);

  assert.equal(word.length, 32);
  const view = new DataView(word.buffer, word.byteOffset, word.byteLength);
  for (let i = 0; i < 4; i++) {
    const expected = digest.readBigUInt64LE(i * 8) % GOLDILOCKS_P;
    assert.equal(view.getBigUint64(i * 8, true), expected);
    assert.ok(view.getBigUint64(i * 8, true) < GOLDILOCKS_P);
  }
});

test('request signing bytes commit to method, path and body', async () => {
  const body = new TextEncoder().encode('{"model":"m"}');
  const payload = new TextDecoder().decode(
    await requestSigningBytes('lev_s_1', 'post', '/v1/chat/completions', body, 1765000000, 'ab'.repeat(8))
  );
  const parsed = JSON.parse(payload);

  assert.equal(parsed.purpose, 'leviathan.wallet.request.v1');
  assert.equal(parsed.method, 'POST'); // upper-cased, as the Edge expects
  assert.equal(parsed.path, '/v1/chat/completions');
  assert.equal(parsed.body_sha256, createHash('sha256').update(body).digest('hex'));

  const other = await requestSigningBytes(
    'lev_s_1',
    'POST',
    '/v1/chat/completions',
    new TextEncoder().encode('{"model":"evil"}'),
    1765000000,
    'ab'.repeat(8)
  );
  const same = await requestSigningBytes('lev_s_1', 'POST', '/v1/chat/completions', body, 1765000000, 'ab'.repeat(8));
  assert.notDeepEqual(same, other);
});

test('cross-language vector: the Edge rebuilds exactly these bytes', async () => {
  // The identical vector is pinned in ai-edge/tests/test_wallet_auth.py. The
  // wallet builds these bytes and the Edge rebuilds them independently; if the
  // two ever disagree, every signature stops verifying, so drift must fail a
  // test rather than production. Non-ASCII content is in the fixture on
  // purpose — it is where two JSON encoders are most likely to part ways.
  const stmt = statement({ account_id: 'mtst1qexample — ünïcode' });
  assert.equal(
    bytesToHex(await statementWordBytes(stmt as unknown as Json)),
    'a3a82deb545db9841fe99d852845ec718b9b41132a863591dd6b0f863f59c1f3'
  );

  const body = new TextEncoder().encode('{"model":"m","messages":[{"role":"user","content":"xin chào"}]}');
  assert.equal(
    new TextDecoder().decode(
      await requestSigningBytes('lev_s_abc', 'POST', '/v1/chat/completions', body, 1765000123, 'ab'.repeat(8))
    ),
    '{"body_sha256":"1af010da68c70ae832966da81b4bf2f185724b0f296565677f0c25e834b4a89c",' +
      '"method":"POST","nonce":"abababababababab","path":"/v1/chat/completions",' +
      '"purpose":"leviathan.wallet.request.v1","session":"lev_s_abc","ts":1765000123}'
  );
});

// ─── Key derivation ──────────────────────────────────────────────────────────

test('the same account secret always yields the same AI identity', async () => {
  const secret = new Uint8Array(48).fill(3);
  const first = await deriveAciKeys(await deriveAciSeed(secret, WALLET_PK));
  const second = await deriveAciKeys(await deriveAciSeed(secret, WALLET_PK));
  assert.equal(first.signPublicKeyHex, second.signPublicKeyHex);
  assert.equal(first.e2eePublicKeyHex, second.e2eePublicKeyHex);
  assert.equal(first.signPublicKeyHex.length, 64);
  assert.equal(first.e2eePublicKeyHex.length, 64);
});

test('different accounts of one wallet get unrelated AI identities', async () => {
  const secret = new Uint8Array(48).fill(3);
  const a = await deriveAciKeys(await deriveAciSeed(secret, WALLET_PK));
  const b = await deriveAciKeys(await deriveAciSeed(secret, 'ff'.repeat(64)));
  assert.notEqual(a.signPublicKeyHex, b.signPublicKeyHex);
});

test('the signing and E2EE keys are independent', async () => {
  const k = await keys();
  assert.notEqual(k.signPublicKeyHex, k.e2eePublicKeyHex);
});

test('a wrong-sized seed is refused', async () => {
  await assert.rejects(() => deriveAciKeys(new Uint8Array(31)), /32 bytes/);
});

test('the derived Ed25519 key really signs', async () => {
  const k = await keys();
  const message = new TextEncoder().encode('hello');
  const signature = await crypto.subtle.sign('Ed25519', k.signPrivateKey, message);
  const publicKey = await crypto.subtle.importKey(
    'raw',
    Uint8Array.from(Buffer.from(k.signPublicKeyHex, 'hex')) as BufferSource,
    'Ed25519',
    false,
    ['verify']
  );
  assert.ok(await crypto.subtle.verify('Ed25519', publicKey, signature, message as BufferSource));
});

test('the derived X25519 key really does ECDH', async () => {
  // This is the key that goes into X-Client-Pub-Key, so it has to be a usable
  // ACI E2EE key, not just 32 bytes that look like one.
  const k = await keys();
  const peer = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const peerPublic = (peer as CryptoKeyPair).publicKey;

  const ours = await crypto.subtle.deriveBits({ name: 'X25519', public: peerPublic }, k.e2eePrivateKey, 256);

  const ourPublic = await crypto.subtle.importKey(
    'raw',
    Uint8Array.from(Buffer.from(k.e2eePublicKeyHex, 'hex')) as BufferSource,
    'X25519',
    false,
    []
  );
  const theirs = await crypto.subtle.deriveBits(
    { name: 'X25519', public: ourPublic },
    (peer as CryptoKeyPair).privateKey,
    256
  );
  assert.equal(bytesToHex(new Uint8Array(ours)), bytesToHex(new Uint8Array(theirs)));
});

// ─── Protocol flow ───────────────────────────────────────────────────────────

function stubFetch(handlers: Record<string, (req: { url: string; init: RequestInit }) => Response>) {
  const seen: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string | URL, init: RequestInit = {}) => {
    const call = { url: String(url), init };
    seen.push(call);
    const path = new URL(call.url).pathname;
    const handler = handlers[path];
    if (!handler) throw new Error(`unexpected call to ${path}`);
    return handler(call);
  }) as unknown as typeof fetch;
  return { impl, seen };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('openAciSession signs the statement it sends', async () => {
  const k = await keys();
  const signedWords: Uint8Array[] = [];
  const { impl, seen } = stubFetch({
    '/v1/wallet/challenge': () => json({ nonce: 'bb'.repeat(32), expires_at: 1765000300, service: SERVICE }),
    '/v1/wallet/bind': () =>
      json({
        session_id: 'lev_s_abc',
        identity_id: 7,
        expires_at: 1765043200,
        scope: ['inference', 'receipts', 'models'],
        max_spend: 100,
        balance: 50
      })
  });

  const session = await openAciSession({
    serviceOrigin: SERVICE + '/',
    walletPubKey: WALLET_PK,
    accountId: 'mtst1qexample',
    keys: k,
    signWord: async word => {
      signedWords.push(word);
      return Buffer.from('sig').toString('base64');
    },
    fetchImpl: impl
  });

  assert.equal(session.sessionId, 'lev_s_abc');
  assert.equal(session.identityId, 7);
  assert.equal(session.serviceOrigin, SERVICE); // trailing slash trimmed

  const sent = JSON.parse(String(seen[1]!.init.body)).statement as BindStatement;
  assert.equal(sent.session_pub_key, k.signPublicKeyHex);
  assert.equal(sent.e2ee_pub_key, k.e2eePublicKeyHex);
  assert.equal(sent.nonce, 'bb'.repeat(32));
  assert.equal(sent.service, SERVICE);
  // Signed the statement that was actually transmitted — not a variant of it.
  assert.deepEqual(signedWords[0], await statementWordBytes(sent as unknown as Json));
  // issued_at follows the Edge's clock, not this machine's.
  assert.equal(sent.issued_at, 1765000000);
});

test('openAciSession surfaces the Edge error code', async () => {
  const { impl } = stubFetch({
    '/v1/wallet/challenge': () => json({ nonce: 'bb'.repeat(32), expires_at: 1765000300 }),
    '/v1/wallet/bind': () => json({ error: { type: 'wallet_invalid_signature', message: 'nope' } }, 401)
  });

  const k = await keys();
  await assert.rejects(
    () =>
      openAciSession({
        serviceOrigin: SERVICE,
        walletPubKey: WALLET_PK,
        accountId: null,
        keys: k,
        signWord: async () => Buffer.from('sig').toString('base64'),
        fetchImpl: impl
      }),
    (err: Error & { code?: string }) => err.code === 'wallet_invalid_signature'
  );
});

function fakeSession(): AciSession {
  return {
    serviceOrigin: SERVICE,
    sessionId: 'lev_s_abc',
    identityId: 7,
    expiresAt: 1765043200,
    scope: ['inference'],
    maxSpend: 100,
    balance: 50,
    statement: statement()
  };
}

test('signedFetch attaches a verifiable signature over the exact body', async () => {
  const k = await keys();
  const { impl, seen } = stubFetch({ '/v1/chat/completions': () => json({ id: 'chatcmpl-1' }) });
  const body = '{"model":"m","messages":[]}';

  await signedFetch(fakeSession(), k, { path: '/v1/chat/completions', body }, impl);

  const headers = seen[0]!.init.headers as Record<string, string>;
  assert.equal(headers['authorization'], 'Wallet lev_s_abc');
  assert.match(headers['x-wallet-nonce']!, /^[0-9a-f]{32}$/);

  const publicKey = await crypto.subtle.importKey(
    'raw',
    Uint8Array.from(Buffer.from(k.signPublicKeyHex, 'hex')) as BufferSource,
    'Ed25519',
    false,
    ['verify']
  );
  const payload = await requestSigningBytes(
    'lev_s_abc',
    'POST',
    '/v1/chat/completions',
    new TextEncoder().encode(body),
    Number(headers['x-wallet-timestamp']),
    headers['x-wallet-nonce']!
  );
  assert.ok(
    await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      Uint8Array.from(Buffer.from(headers['x-wallet-signature']!, 'base64')) as BufferSource,
      payload as BufferSource
    )
  );

  // ...and the same signature does NOT cover a different body.
  const tampered = await requestSigningBytes(
    'lev_s_abc',
    'POST',
    '/v1/chat/completions',
    new TextEncoder().encode('{"model":"evil"}'),
    Number(headers['x-wallet-timestamp']),
    headers['x-wallet-nonce']!
  );
  assert.equal(
    await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      Uint8Array.from(Buffer.from(headers['x-wallet-signature']!, 'base64')) as BufferSource,
      tampered as BufferSource
    ),
    false
  );
});

test('each request gets a fresh nonce', async () => {
  const k = await keys();
  const { impl, seen } = stubFetch({ '/v1/models': () => json({ data: [] }) });
  await signedFetch(fakeSession(), k, { path: '/v1/models', method: 'GET' }, impl);
  await signedFetch(fakeSession(), k, { path: '/v1/models', method: 'GET' }, impl);
  const [a, b] = seen.map(c => (c.init.headers as Record<string, string>)['x-wallet-nonce']);
  assert.notEqual(a, b);
});

test('closeAciSession swallows a failed revoke', async () => {
  const k = await keys();
  const failing = (async () => {
    throw new Error('offline');
  }) as unknown as typeof fetch;
  assert.equal(await closeAciSession(fakeSession(), k, failing), false);
});
