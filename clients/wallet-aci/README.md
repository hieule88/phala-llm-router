# @leviathan/wallet-aci

The wallet side of [wallet-bound ACI](../../docs/wallet-bound-aci.md): the code
that turns a Leviathan Miden wallet into the account for the TEE inference API,
so there is no separate API key, the wallet lock gates access, and every call is
authorized by a signature.

Zero dependencies — Web Crypto (Ed25519, X25519, HKDF, SHA-256/512) plus a
built-in JCS canonicalizer, the same constraint as [`../verifier-ts`](../verifier-ts).
Runs in a browser, an MV3 service worker, and Node 22+.

```bash
npm install && npm test     # 17 tests, including the cross-language vector
```

## What it does

| Function | Role |
| --- | --- |
| `deriveAciSeed(accountSecretKey, accountKey)` | HKDF the AI seed out of the Miden account's own Falcon secret. |
| `deriveAciKeys(seed)` | Ed25519 (signs API calls) + X25519 (ACI E2EE client key). |
| `openAciSession({...})` | Challenge → build bind statement → **one** Falcon signature → session. |
| `signedFetch(session, keys, {path, body})` | One Ed25519 signature per call, over method + path + exact body bytes. |
| `closeAciSession` / `revokeAllAciSessions` | Lock the wallet / lost-device button. |

The session id is a **handle, not a credential**: leaking it grants nothing,
because using it requires a key that never leaves the unlocked vault.

## Wiring it into the Leviathan wallet extension

This package is deliberately vault-agnostic — the one Falcon signature arrives
through a callback — so the extension needs three small additions.

**1. The vault derives the seed and signs the bind statement.** In
`src/lib/miden/back/vault.ts`, alongside `signData`:

```ts
import { deriveAciSeed } from '@leviathan/wallet-aci';

/**
 * Seed for this account's AI session keys. Only reachable through an unlocked
 * vault — which is what makes locking the wallet revoke API access.
 */
async deriveAciSeed(publicKey: string): Promise<Uint8Array> {
  const secretKeyHex = await fetchAndDecryptOneWithLegacyFallBack<string>(
    accAuthSecretKeyStrgKey(publicKey),
    this.vaultKey
  );
  return deriveAciSeed(new Uint8Array(Buffer.from(secretKeyHex, 'hex')), publicKey);
}

/** The one Falcon signature in the AI flow: it delegates to a session key. */
async signAciWord(publicKey: string, wordBytes: Uint8Array): Promise<string> {
  if (wordBytes.length !== 32) throw new PublicError('ACI word must be 32 bytes');
  return this.signData(publicKey, u8ToB64(wordBytes), 'word');
}
```

`signData` already routes `'word'` through `Word.deserialize` → `secretKey.sign`,
and the statement word is built as four reduced Goldilocks limbs precisely so
that deserialization always succeeds (protocol §3.1).

**2. The service worker owns the session, and drops it on lock.** Keys and
session live in service-worker memory only — never in `chrome.storage`, or the
lock would stop meaning anything:

```ts
let current: { session: AciSession; keys: AciKeys } | null = null;

export async function connectAi(origin: string) {
  return withUnlocked(async ({ vault }) => {
    const publicKey = await Vault.getCurrentAccountPublicKey();
    const keys = await deriveAciKeys(await vault.deriveAciSeed(publicKey));
    const session = await openAciSession({
      serviceOrigin: origin,
      walletPubKey: publicKey,
      accountId: await getCurrentAccountAddress(),
      keys,
      signWord: word => vault.signAciWord(publicKey, word)   // user confirmation
    });
    current = { session, keys };
    return session;
  });
}

export async function lockAi() {
  if (!current) return;
  await closeAciSession(current.session, current.keys);   // best effort
  current = null;                                          // the part that matters
}
```

Call `lockAi()` from the same place the vault is locked. Even if the network
call fails, dropping `current` makes every later request unsignable.

**3. Expose it to dApps.** Add an `aci` namespace to `LeviathanWindowObject`
(`src/lib/adapter/midenWindowObject.ts`) that forwards to the background over
intercom. The page never receives the session key — it asks the worker to sign,
exactly as it already does for transactions.

Also add the Edge origin to `host_permissions` in `public/manifest.json`.

## Confirmation UI

The bind statement is what the user approves, so show its terms rather than a
generic prompt — the service origin, `max_spend` (in credits — 1 credit =
1 request), the expiry, and the scopes. `openAciSession` takes them as
`authorization: { scope, maxSpend, ttlSec }`; the Edge enforces every one and
caps the lifetime at 24h.

## E2EE

`keys.e2eePrivateKey` is a normal X25519 key, so it plugs straight into
`../verifier-ts`'s `openE2eeChannel` as the client key. Use it: then
`X-Client-Pub-Key` is a wallet key, and the TEE's signed receipt binds the
inference to the Miden account rather than to an anonymous browser session.
