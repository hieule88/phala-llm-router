# capture-vector — the §10 release gate's input

Creates a **throwaway Leviathan wallet** with the same `@miden-sdk/miden-sdk`
the extension ships, signs test words with its Falcon-512 account key, and
writes `(public_key, word, signature)` vectors into `../vectors/`. The Rust
test `real_wallet_vector_gate` (and therefore the Docker image build) refuses
to pass without them: a `miden-crypto` pin that cannot parse the wallet's
signature encoding fails closed on every bind, and this gate makes that state
unshippable instead of discoverable in production.

The wallet-creation path mirrors the extension exactly
(`leviathan/wallet src/lib/miden/back/vault.ts`, read-only):
BIP-39 mnemonic → `derivePath("m/44'/0'/0'/0'")` →
`AuthSecretKey.rpoFalconWithRNG(childSeed)` → `sk.sign(Word)` →
`base64(signature.serialize())`.

## Usage

```bash
npm install          # public npm @miden-sdk/miden-sdk 0.15.0 (dev fallback)
npm run capture      # writes ../vectors/wallet-<version>.json
cd ../.. && cargo test
```

For a **release**, capture with the wallet's exact private build instead:

```bash
GITEA_NPM_TOKEN=<token> npm run install:wallet-build
npm run capture      # vector file records source: wallet-exact-build
```

The script prints the throwaway mnemonic so you can import it into the
extension and cross-check that the real extension build signs identically.
Never fund that wallet.

## What the first capture already taught us

`@miden-sdk` 0.15.0 serializes public keys and signatures behind a one-byte
auth-scheme tag (`0x02` = Falcon-512/Poseidon2); the bytes after the tag are
exactly what `miden-crypto` 0.29 expects. The verifier accepts both the bare
and the tagged form (`read_bare_or_tagged` in `src/main.rs`) because
`vault.signData` returns the tagged form verbatim.
