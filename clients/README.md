# ACI client libraries

- [`verifier-ts`](verifier-ts) — `@dstack/aci-verifier`, a zero-dependency,
  Web-Crypto ACI client: verify attestation reports and receipts, and open an
  **E2EE channel** to a *verified* workload (`openE2eeChannel`) to encrypt
  request fields and decrypt replies (X25519 suite, §7).

- [`wallet-aci`](wallet-aci) — `@leviathan/wallet-aci`, the wallet side of
  [wallet-bound ACI](../docs/wallet-bound-aci.md): a Leviathan Miden wallet as
  the account, with no API key. Derives the session and E2EE keys from the
  wallet, binds them with one Falcon signature, and signs every API call. Its
  X25519 key feeds `verifier-ts`'s `openE2eeChannel`, so receipts bind the
  inference to the Miden account.

The secp256k1 suite and non-browser (Rust) clients are separate extensions.
