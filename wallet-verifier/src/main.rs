//! Leviathan wallet-verifier — one job: decide whether a Falcon-512 signature
//! from a Miden wallet is valid over a given `Word`.
//!
//! It exists because Miden's Falcon variant has no Python implementation and
//! the Edge is Python. It holds no secrets, keeps no state, and makes no
//! outbound connections, which is what lets it be deployed inside the same TEE
//! as the gateway: then "who may spend my credits" is a question answered by
//! attested code rather than by the Edge.
//!
//! Protocol: docs/wallet-bound-aci.md.

use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use miden_crypto::{
    dsa::falcon512_poseidon2::{PublicKey, Signature},
    utils::{Deserializable, Serializable},
    Word,
};
use serde::{Deserialize, Serialize};

/// Goldilocks modulus. A limb at or above this is not a field element.
const FIELD_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

#[derive(Deserialize)]
struct VerifyRequest {
    /// The wallet's account key, lowercase hex, in either of the two forms a
    /// Miden wallet may hold it: the full serialized Falcon `PublicKey`
    /// (897 bytes), or its 32-byte `Word` commitment — which is what a
    /// keystore keyed by public-key digest actually stores. Both name the same
    /// key; the commitment form just makes the verifier do the hashing.
    public_key: String,
    /// The 32-byte message word: four little-endian u64 limbs, each < p.
    message_word: String,
    /// Miden `Signature` serialization, base64.
    signature: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// A rejection the *caller* caused (malformed input). Distinguished from
/// `valid: false` on purpose: "I cannot parse this" and "this signature is a
/// forgery" are different facts, and collapsing them hides deployment
/// mismatches (§10 of the protocol doc) behind what looks like an attack.
#[derive(Debug)]
struct BadRequest(String);

impl IntoResponse for BadRequest {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: self.0 })).into_response()
    }
}

fn parse_word(hex_str: &str) -> Result<Word, BadRequest> {
    let bytes = hex::decode(hex_str).map_err(|_| BadRequest("message_word is not hex".into()))?;
    if bytes.len() != 32 {
        return Err(BadRequest("message_word must be 32 bytes".into()));
    }
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        let v = u64::from_le_bytes(buf);
        if v >= FIELD_MODULUS {
            return Err(BadRequest(format!("message_word limb {i} is not a field element")));
        }
        *limb = v;
    }
    Word::try_from(limbs).map_err(|e| BadRequest(format!("message_word is not a valid Word: {e}")))
}

/// The wallet's `@miden-sdk` serializes public keys and signatures behind a
/// one-byte auth-scheme discriminant; 2 is Falcon-512/Poseidon2 — the only
/// scheme this verifier speaks. `vault.signData` returns the tagged form
/// verbatim, so production traffic carries it. Bare `miden-crypto` encodings
/// (no tag) are accepted too; any other scheme tag is refused rather than
/// guessed at.
const SDK_SCHEME_TAG_FALCON512_POSEIDON2: u8 = 2;

/// Parse `bytes` as `T`, first as-is, then — if that fails and the first byte
/// is the Falcon/Poseidon2 scheme tag — with the tag stripped. At most one of
/// the two parses can succeed (both encodings are self-describing), so this
/// introduces no ambiguity about what was signed.
fn read_bare_or_tagged<T: Deserializable>(bytes: &[u8], what: &str) -> Result<T, BadRequest> {
    match T::read_from_bytes(bytes) {
        Ok(v) => Ok(v),
        Err(direct_err) => match bytes.split_first() {
            Some((&SDK_SCHEME_TAG_FALCON512_POSEIDON2, rest)) => T::read_from_bytes(rest)
                .map_err(|e| BadRequest(format!("{what} does not deserialize (tagged): {e}"))),
            _ => Err(BadRequest(format!("{what} does not deserialize: {direct_err}"))),
        },
    }
}

/// Which of the accepted spellings of the account key we were given.
enum ClaimedKey {
    Full(PublicKey),
    Commitment(Word),
}

fn parse_claimed_key(hex_str: &str) -> Result<ClaimedKey, BadRequest> {
    let bytes = hex::decode(hex_str).map_err(|_| BadRequest("public_key is not hex".into()))?;
    if bytes.len() == 32 {
        return Ok(ClaimedKey::Commitment(parse_word(hex_str)?));
    }
    read_bare_or_tagged::<PublicKey>(&bytes, "public_key").map(ClaimedKey::Full)
}

async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<VerifyResponse>, BadRequest> {
    let word = parse_word(&req.message_word)?;
    let claimed = parse_claimed_key(&req.public_key)?;

    let sig_bytes = B64
        .decode(req.signature.as_bytes())
        .map_err(|_| BadRequest("signature is not base64".into()))?;
    let signature: Signature = read_bare_or_tagged(&sig_bytes, "signature")?;

    // A Miden `Signature` carries its own copy of the public key, and
    // `Signature::verify` would happily check against THAT one. Verifying
    // without binding it to the CLAIMED key accepts any signature made with
    // any key the attacker generated: the maths would hold, and the claim
    // "this is wallet X" would not.
    let signer = signature.public_key();
    let binds_to_claim = match &claimed {
        // Compare serialized forms so this does not depend on `PublicKey: PartialEq`.
        ClaimedKey::Full(pk) => Serializable::to_bytes(&signer) == Serializable::to_bytes(&pk),
        ClaimedKey::Commitment(word) => signer.to_commitment() == *word,
    };

    if !binds_to_claim {
        return Ok(Json(VerifyResponse { valid: false }));
    }

    Ok(Json(VerifyResponse { valid: signer.verify(word, &signature) }))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "scheme": "falcon512_poseidon2" }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr = std::env::var("WALLET_VERIFIER_BIND").unwrap_or_else(|_| "127.0.0.1:8091".into());
    let app = Router::new().route("/health", get(health)).route("/verify", post(verify));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "wallet-verifier listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_limbs_are_little_endian_and_range_checked() {
        let mut bytes = vec![0u8; 32];
        bytes[0] = 5;
        let word = parse_word(&hex::encode(&bytes)).unwrap();
        let limbs: [u64; 4] = word.into();
        assert_eq!(limbs, [5, 0, 0, 0]);

        // p itself is out of range; p-1 is the largest element.
        let mut at_modulus = vec![0u8; 32];
        at_modulus[..8].copy_from_slice(&FIELD_MODULUS.to_le_bytes());
        assert!(parse_word(&hex::encode(&at_modulus)).is_err());

        let mut max = vec![0u8; 32];
        max[..8].copy_from_slice(&(FIELD_MODULUS - 1).to_le_bytes());
        assert!(parse_word(&hex::encode(&max)).is_ok());
    }

    #[test]
    fn short_word_is_rejected() {
        assert!(parse_word(&hex::encode([0u8; 31])).is_err());
        assert!(parse_word("zz").is_err());
    }

    fn word_hex(limbs: [u64; 4]) -> String {
        hex::encode(limbs.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<u8>>())
    }

    #[tokio::test]
    async fn accepts_a_real_signature_and_rejects_a_swapped_message() {
        let sk = miden_crypto::dsa::falcon512_poseidon2::SecretKey::new();
        let pk = sk.public_key();
        let word = Word::try_from([1u64, 2, 3, 4]).unwrap();
        let sig = sk.sign(word);

        let req = VerifyRequest {
            public_key: hex::encode(Serializable::to_bytes(&&pk)),
            message_word: word_hex([1, 2, 3, 4]),
            signature: B64.encode(sig.to_bytes()),
        };
        assert!(verify(Json(req)).await.unwrap().0.valid);

        let wrong = VerifyRequest {
            public_key: hex::encode(Serializable::to_bytes(&&pk)),
            message_word: word_hex([1, 2, 3, 5]),
            signature: B64.encode(sig.to_bytes()),
        };
        assert!(!verify(Json(wrong)).await.unwrap().0.valid);
    }

    #[tokio::test]
    async fn accepts_the_commitment_spelling_of_the_same_key() {
        // A Miden keystore identifies a key by its Word commitment, so this is
        // the form the wallet extension actually has on hand.
        let sk = miden_crypto::dsa::falcon512_poseidon2::SecretKey::new();
        let word = Word::try_from([9u64, 8, 7, 6]).unwrap();
        let sig = sk.sign(word);
        let commitment: [u64; 4] = sk.public_key().to_commitment().into();

        let req = VerifyRequest {
            public_key: word_hex(commitment),
            message_word: word_hex([9, 8, 7, 6]),
            signature: B64.encode(sig.to_bytes()),
        };
        assert!(verify(Json(req)).await.unwrap().0.valid);

        let other: [u64; 4] =
            miden_crypto::dsa::falcon512_poseidon2::SecretKey::new().public_key().to_commitment().into();
        let mismatched = VerifyRequest {
            public_key: word_hex(other),
            message_word: word_hex([9, 8, 7, 6]),
            signature: B64.encode(sig.to_bytes()),
        };
        assert!(!verify(Json(mismatched)).await.unwrap().0.valid);
    }

    /// The §10 release gate: signatures captured from the REAL wallet SDK
    /// build must parse and verify here. A `miden-crypto` pin that cannot
    /// read the wallet's serialization fails closed on every bind — safe but
    /// total — so this test failing (or having no vectors to run) must block
    /// a release, not be shrugged off.
    ///
    /// Vectors are produced by `tests/capture-vector/capture.mjs`, which
    /// creates a throwaway Leviathan wallet with the same `@miden-sdk`
    /// version the extension ships and signs with its Falcon account key.
    #[tokio::test]
    async fn real_wallet_vector_gate() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !entries.is_empty(),
            "no vector files in {} — run tests/capture-vector/capture.mjs with the \
             wallet's @miden-sdk build first (docs/wallet-bound-aci.md §10); a verifier \
             never tested against the wallet's real signature encoding must not ship",
            dir.display(),
        );

        for path in entries {
            let text = std::fs::read_to_string(&path).unwrap();
            let file: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{}: not JSON: {e}", path.display()));
            let sdk = file["sdk"].as_str().unwrap_or("<unknown sdk>");

            // Every vector must verify under every public-key spelling the
            // wallet may present (full serialization and/or Word commitment).
            let mut key_forms: Vec<(&str, &str)> = Vec::new();
            if let Some(k) = file["public_keys"]["full_hex"].as_str() {
                key_forms.push(("full", k));
            }
            if let Some(k) = file["public_keys"]["commitment_hex"].as_str() {
                key_forms.push(("commitment", k));
            }
            assert!(!key_forms.is_empty(), "{}: no public_keys", path.display());

            for vector in file["vectors"].as_array().expect("vectors array") {
                let name = vector["name"].as_str().unwrap_or("<unnamed>");
                let word_hex = vector["message_word_hex"].as_str().expect("message_word_hex");
                let sig_b64 = vector["signature_b64"].as_str().expect("signature_b64");

                for (form, key_hex) in &key_forms {
                    let res = verify(Json(VerifyRequest {
                        public_key: key_hex.to_string(),
                        message_word: word_hex.to_string(),
                        signature: sig_b64.to_string(),
                    }))
                    .await;
                    match res {
                        Ok(Json(VerifyResponse { valid: true })) => {}
                        Ok(Json(VerifyResponse { valid: false })) => panic!(
                            "{sdk} vector '{name}' ({form} key): signature parsed but did NOT \
                             verify — key binding or Word mapping mismatch with this wallet build",
                        ),
                        Err(bad) => panic!(
                            "{sdk} vector '{name}' ({form} key): verifier cannot parse the \
                             wallet's encoding ({}) — the miden-crypto pin does not match the \
                             wallet's @miden-sdk generation (docs §10)",
                            bad.0,
                        ),
                    }
                }

                // Guard against a vacuous pass: the same signature over a
                // different word must NOT verify.
                let mut tampered = hex::decode(word_hex).unwrap();
                tampered[0] ^= 0x01;
                if let Ok(Json(VerifyResponse { valid })) = verify(Json(VerifyRequest {
                    public_key: key_forms[0].1.to_string(),
                    message_word: hex::encode(&tampered),
                    signature: sig_b64.to_string(),
                }))
                .await
                {
                    assert!(!valid, "{sdk} vector '{name}': tampered word still verified");
                }
            }
        }
    }

    #[tokio::test]
    async fn rejects_a_signature_made_with_another_key() {
        // The forgery this guards against: a valid signature under an
        // attacker's own key, presented as the victim's. `Signature::verify`
        // alone would pass it, because the signature carries the key it was
        // made with.
        let victim = miden_crypto::dsa::falcon512_poseidon2::SecretKey::new().public_key();
        let attacker = miden_crypto::dsa::falcon512_poseidon2::SecretKey::new();
        let word = Word::try_from([7u64, 7, 7, 7]).unwrap();
        let sig = attacker.sign(word);

        let req = VerifyRequest {
            public_key: hex::encode(Serializable::to_bytes(&&victim)),
            message_word: word_hex([7, 7, 7, 7]),
            signature: B64.encode(sig.to_bytes()),
        };
        assert!(!verify(Json(req)).await.unwrap().0.valid);
    }
}
