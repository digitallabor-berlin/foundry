//! JWE compact-serialization encryption over josekit.
//!
//! This is the encrypt counterpart to the verifier's decrypt path
//! (`foundry-verifier`'s `verify_vp_response`, which uses
//! `josekit::jwe::ECDH_ES.decrypter_from_jwk` +
//! `josekit::jwt::decode_with_decrypter`). Both directions go through the same
//! JOSE library, so compact-serialization compatibility is structural.
//!
//! Used by the wallet to encrypt an OpenID4VP authorization response
//! (`{"vp_token": ...}`) to the verifier's ephemeral public JWK, and by tests
//! on both sides to construct such responses.

use crate::error::CryptoError;
use base64::Engine as _;
use josekit::jwe::JweHeader;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jwk::{Jwk, KeyPair as _};
use josekit::jwt::JwtPayload;
use serde_json::Value;

/// The only JWE key-management algorithm this codebase issues or accepts.
const SUPPORTED_ALG: &str = "ECDH-ES";

/// A long-lived issuer key used to **decrypt** Credential Requests.
///
/// OpenID4VCI L1373 requires every JWK published in
/// `credential_request_encryption.jwks` to carry a unique `kid`, and L1188
/// requires the encrypting client to echo it. The `kid` here is *derived* — the
/// RFC 7638 thumbprint of the public JWK — so it is unique by construction,
/// stable across restarts and replicas, and cannot drift from its key.
///
/// The private JWK stays **bare** (no `kid`/`use`/`alg`), mirroring the
/// asymmetry `foundry-verifier` already relies on: an annotated public JWK goes
/// to the client, a bare private JWK feeds `ECDH_ES.decrypter_from_jwk`.
pub struct DecryptionKey {
    kid: String,
    public_jwk: Value,
    private_jwk: Value,
}

impl std::fmt::Debug for DecryptionKey {
    /// Hand-written: a derive would print `private_jwk`, and private key
    /// material must never reach a log (root `AGENTS.md` §4.5).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl DecryptionKey {
    /// Load from an in-memory PKCS#8 PEM. Curve auto-detected, as in
    /// `FileSigner::from_pem`.
    pub fn from_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let key_pair =
            EcKeyPair::from_pem(pem, None).map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        let public_jwk = serde_json::to_value(key_pair.to_jwk_public_key())
            .map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        let private_jwk = serde_json::to_value(key_pair.to_jwk_private_key())
            .map_err(|e| CryptoError::KeyLoad(e.to_string()))?;
        // `obs::thumbprint` degrades to a placeholder on malformed input, which
        // is the wrong contract for a value that goes on the wire as an
        // identifier. Use the fail-closed form and propagate.
        let digest = crate::obs::thumbprint_bytes(&public_jwk).map_err(CryptoError::KeyLoad)?;
        let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Ok(Self {
            kid,
            public_jwk,
            private_jwk,
        })
    }

    pub fn from_pem_file(path: &str) -> Result<Self, CryptoError> {
        let pem = std::fs::read(path).map_err(|source| CryptoError::KeyRead {
            path: path.to_string(),
            source,
        })?;
        Self::from_pem(&pem)
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public JWK as published in `credential_request_encryption.jwks`.
    ///
    /// L1188 makes `alg` mandatory on the encryption key, L1373 makes `kid`
    /// mandatory, and `use: "enc"` lets a wallet select by purpose. Same
    /// annotation pattern as `foundry-verifier`'s `annotate_encryption_jwk`.
    pub fn published_jwk(&self) -> Value {
        let mut jwk = self.public_jwk.clone();
        if let Some(obj) = jwk.as_object_mut() {
            obj.insert("kid".to_string(), Value::String(self.kid.clone()));
            obj.insert("use".to_string(), Value::String("enc".to_string()));
            obj.insert("alg".to_string(), Value::String(SUPPORTED_ALG.to_string()));
        }
        jwk
    }
}

/// The clear-text protected header of a compact-serialization JWE.
///
/// Parsed directly from segment 0 rather than via a josekit selector callback so
/// the `alg`/`enc`/`kid` checks below can return typed `CryptoError`s naming the
/// offending value instead of an opaque JOSE error.
fn protected_header(jwe: &str) -> Result<Value, CryptoError> {
    let segments: Vec<&str> = jwe.split('.').collect();
    if segments.len() != 5 {
        return Err(CryptoError::Jwe(format!(
            "a compact JWE must have five segments, got {}",
            segments.len()
        )));
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|e| CryptoError::Jwe(format!("protected header is not base64url: {e}")))?;
    serde_json::from_slice(&raw)
        .map_err(|e| CryptoError::Jwe(format!("protected header is not JSON: {e}")))
}

/// Decrypt a compact-serialization JWE Credential Request to its JWT claims set.
///
/// OpenID4VCI L1186 requires the message contents to be a JWT, so the returned
/// value is the claims set — which *is* the Credential Request object.
///
/// Three header checks run **before** any key agreement, each a conformance
/// clause:
///
/// * L1188 / VCI-0100 — the JWE `alg` MUST equal the `alg` of the chosen JWK,
///   and every published JWK carries `ECDH-ES`.
/// * L1188 / VCI-0101 — the JWE MUST echo the selected key's `kid`. Every
///   published key has one, so an absent `kid` is a rejection rather than a fall
///   back to trial decryption; trial decryption would reduce `kid` to decoration
///   and mask a client bug.
/// * VCI-0135 — `enc` must be one of the advertised values.
pub fn decrypt_compact(
    jwe: &str,
    keys: &[DecryptionKey],
    allowed_enc: &[String],
) -> Result<Value, CryptoError> {
    if keys.is_empty() {
        return Err(CryptoError::Jwe(
            "no request-decryption keys are configured".to_string(),
        ));
    }

    let header = protected_header(jwe)?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CryptoError::Jwe("JWE header has no string `alg`".to_string()))?;
    if alg != SUPPORTED_ALG {
        return Err(CryptoError::Jwe(format!(
            "unsupported key-management algorithm '{alg}' (only {SUPPORTED_ALG} is supported)"
        )));
    }

    let enc = header
        .get("enc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CryptoError::Jwe("JWE header has no string `enc`".to_string()))?;
    if !allowed_enc.iter().any(|a| a == enc) {
        return Err(CryptoError::Jwe(format!(
            "unsupported content-encryption algorithm '{enc}'"
        )));
    }

    let kid = header.get("kid").and_then(|v| v.as_str()).ok_or_else(|| {
        CryptoError::Jwe(
            "JWE header has no `kid`; every published encryption key carries one \
             (OpenID4VCI L1188)"
                .to_string(),
        )
    })?;
    let key = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| CryptoError::Jwe(format!("no decryption key matches `kid` '{kid}'")))?;

    let jwk_bytes = serde_json::to_vec(&key.private_jwk)
        .map_err(|e| CryptoError::Jwe(format!("decryption jwk is not serialisable: {e}")))?;
    let jwk =
        Jwk::from_bytes(&jwk_bytes).map_err(|e| CryptoError::Jwe(format!("invalid jwk: {e}")))?;
    let decrypter = josekit::jwe::ECDH_ES
        .decrypter_from_jwk(&jwk)
        .map_err(|e| CryptoError::Jwe(format!("cannot build decrypter: {e}")))?;

    let (payload, _header) = josekit::jwt::decode_with_decrypter(jwe, &decrypter)
        .map_err(|e| CryptoError::Jwe(e.to_string()))?;

    serde_json::to_value(payload.claims_set())
        .map_err(|e| CryptoError::Jwe(format!("decrypted claims are not JSON: {e}")))
}

/// Encrypt `payload` to `recipient_public_jwk` as a compact-serialization JWE.
///
/// Emits **no** `kid` header. This is the OpenID4VP path (a wallet encrypting an
/// authorization response to the verifier's ephemeral key) and its wire shape
/// must not change; see [`encrypt_compact_with_kid`] for the Credential Response
/// path, where OpenID4VCI L1188 requires the recipient's `kid` to be echoed.
pub fn encrypt_compact(
    payload: &Value,
    recipient_public_jwk: &Value,
    alg: &str,
    enc: &str,
) -> Result<String, CryptoError> {
    encrypt_compact_with_kid(payload, recipient_public_jwk, alg, enc, None)
}

/// As [`encrypt_compact`], but writes `kid` into the protected header when one
/// is supplied.
///
/// OpenID4VCI L1188: *"If the selected public key contains a `kid` parameter,
/// the JWE MUST include the same value in the `kid` JWE Header Parameter."* On
/// the Credential Response path the selected key is the wallet's
/// `credential_response_encryption.jwk` (VCI-0101).
pub fn encrypt_compact_with_kid(
    payload: &Value,
    recipient_public_jwk: &Value,
    alg: &str,
    enc: &str,
    kid: Option<&str>,
) -> Result<String, CryptoError> {
    if alg != SUPPORTED_ALG {
        return Err(CryptoError::Jwe(format!(
            "unsupported key-management algorithm '{alg}' (only {SUPPORTED_ALG} is supported)"
        )));
    }

    let claims = payload
        .as_object()
        .ok_or_else(|| CryptoError::Jwe("payload must be a JSON object".to_string()))?
        .clone();
    let jwt_payload = JwtPayload::from_map(claims)
        .map_err(|e| CryptoError::Jwe(format!("invalid payload claims: {e}")))?;

    let jwk_bytes = serde_json::to_vec(recipient_public_jwk)
        .map_err(|e| CryptoError::Jwe(format!("recipient jwk is not serialisable: {e}")))?;
    let jwk = Jwk::from_bytes(&jwk_bytes)
        .map_err(|e| CryptoError::Jwe(format!("invalid recipient jwk: {e}")))?;
    let encrypter = josekit::jwe::ECDH_ES
        .encrypter_from_jwk(&jwk)
        .map_err(|e| CryptoError::Jwe(format!("cannot encrypt to recipient jwk: {e}")))?;

    let mut header = JweHeader::new();
    header.set_algorithm(alg);
    header.set_content_encryption(enc);
    if let Some(kid) = kid {
        header.set_key_id(kid);
    }

    josekit::jwt::encode_with_encrypter(&jwt_payload, &header, &encrypter)
        .map_err(|e| CryptoError::Jwe(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::EcCurve;
    use josekit::jwk::Jwk;
    use serde_json::json;

    /// Mirrors the verifier's real key handling: the *public* JWK handed to the
    /// wallet is annotated with `kid`/`use`/`alg` so a wallet can select it,
    /// while the *private* JWK kept by the verifier stays bare so its decrypter
    /// carries no key id. See `foundry-verifier`'s `annotate_encryption_jwk`.
    fn annotated_public_and_bare_private() -> (Value, Value) {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public = serde_json::to_value(keypair.to_jwk_public_key()).unwrap();
        let obj = public.as_object_mut().unwrap();
        obj.insert("kid".to_string(), json!("2f8a1c74-test-kid"));
        obj.insert("use".to_string(), json!("enc"));
        obj.insert("alg".to_string(), json!("ECDH-ES"));
        let private = serde_json::to_value(keypair.to_jwk_private_key()).unwrap();
        (public, private)
    }

    /// Decrypt exactly the way `foundry-verifier` does in production.
    fn decrypt_as_verifier_does(jwe: &str, bare_private_jwk: &Value) -> Value {
        let jwk_str = serde_json::to_string(bare_private_jwk).unwrap();
        let jwk = Jwk::from_bytes(jwk_str.as_bytes()).unwrap();
        let decrypter = josekit::jwe::ECDH_ES.decrypter_from_jwk(&jwk).unwrap();
        let (jwt_payload, _header) = josekit::jwt::decode_with_decrypter(jwe, &decrypter).unwrap();
        serde_json::to_value(jwt_payload.claims_set()).unwrap()
    }

    /// The asymmetry that matters: encrypt against an annotated public JWK
    /// (which carries a `kid`), decrypt with a bare private JWK (which does
    /// not). If the encrypter propagated `kid` into the header in a way the
    /// bare decrypter rejected, this is where it would surface.
    #[test]
    fn round_trips_annotated_public_to_bare_private() {
        let (public, private) = annotated_public_and_bare_private();
        let payload = json!({ "vp_token": "eyJhbGciOiJFUzI1NiJ9.body.sig~disclosure~" });

        let jwe = encrypt_compact(&payload, &public, "ECDH-ES", "A128GCM").unwrap();

        assert_eq!(
            jwe.split('.').count(),
            5,
            "expected JWE compact serialization"
        );
        assert_eq!(decrypt_as_verifier_does(&jwe, &private), payload);
    }

    #[test]
    fn round_trips_nested_json_payload() {
        let (public, private) = annotated_public_and_bare_private();
        let payload = json!({
            "vp_token": { "credentials": [{ "id": "c1", "claims": { "given_name": "Ada" } }] },
            "state": "abc123"
        });

        let jwe = encrypt_compact(&payload, &public, "ECDH-ES", "A128GCM").unwrap();

        assert_eq!(decrypt_as_verifier_does(&jwe, &private), payload);
    }

    #[test]
    fn round_trips_with_a_bare_public_jwk_too() {
        // The annotations are a wallet-selection aid, not an encryption input.
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let public = serde_json::to_value(keypair.to_jwk_public_key()).unwrap();
        let private = serde_json::to_value(keypair.to_jwk_private_key()).unwrap();
        let payload = json!({ "vp_token": "token" });

        let jwe = encrypt_compact(&payload, &public, "ECDH-ES", "A128GCM").unwrap();

        assert_eq!(decrypt_as_verifier_does(&jwe, &private), payload);
    }

    #[test]
    fn rejects_unsupported_alg() {
        let (public, _private) = annotated_public_and_bare_private();
        let err = encrypt_compact(&json!({ "a": 1 }), &public, "RSA-OAEP", "A128GCM").unwrap_err();
        assert!(matches!(err, CryptoError::Jwe(_)), "got {err:?}");
        assert!(err.to_string().contains("RSA-OAEP"), "got {err}");
    }

    #[test]
    fn rejects_unsupported_enc() {
        let (public, _private) = annotated_public_and_bare_private();
        let err = encrypt_compact(&json!({ "a": 1 }), &public, "ECDH-ES", "A999GCM").unwrap_err();
        assert!(matches!(err, CryptoError::Jwe(_)), "got {err:?}");
    }

    #[test]
    fn rejects_malformed_recipient_jwk() {
        let err = encrypt_compact(
            &json!({ "a": 1 }),
            &json!({ "kty": "EC" }),
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::Jwe(_)), "got {err:?}");
    }

    #[test]
    fn rejects_non_object_payload() {
        let (public, _private) = annotated_public_and_bare_private();
        let err =
            encrypt_compact(&json!("just a string"), &public, "ECDH-ES", "A128GCM").unwrap_err();
        assert!(matches!(err, CryptoError::Jwe(_)), "got {err:?}");
    }

    fn test_decryption_key() -> DecryptionKey {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        DecryptionKey::from_pem(&kp.to_pem_private_key()).unwrap()
    }

    fn both_gcm() -> Vec<String> {
        vec!["A128GCM".to_string(), "A256GCM".to_string()]
    }

    #[test]
    fn kid_is_the_rfc7638_thumbprint_of_the_public_jwk() {
        let key = test_decryption_key();
        let published = key.published_jwk();
        assert_eq!(key.kid(), crate::obs::thumbprint(&published));
        assert_eq!(published["kid"], json!(key.kid()));
        assert_eq!(published["use"], json!("enc"));
        assert_eq!(published["alg"], json!("ECDH-ES"));
    }

    #[test]
    fn round_trips_an_encrypted_credential_request() {
        let key = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "credential_configuration_id": "pid" }),
            &key.published_jwk(),
            "ECDH-ES",
            "A128GCM",
            Some(key.kid()),
        )
        .unwrap();
        let out = decrypt_compact(&jwe, std::slice::from_ref(&key), &both_gcm()).unwrap();
        assert_eq!(out["credential_configuration_id"], json!("pid"));
    }

    #[test]
    fn selects_the_right_key_from_several() {
        let k1 = test_decryption_key();
        let k2 = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &k2.published_jwk(),
            "ECDH-ES",
            "A256GCM",
            Some(k2.kid()),
        )
        .unwrap();
        let keys = vec![k1, k2];
        assert_eq!(
            decrypt_compact(&jwe, &keys, &both_gcm()).unwrap()["a"],
            json!(1)
        );
    }

    #[test]
    fn rejects_a_missing_kid() {
        let key = test_decryption_key();
        // `published_jwk()` always carries a `kid`, and josekit's own
        // `serialize_compact` copies a recipient JWK's `kid` into the header
        // whenever the caller did not set one explicitly (confirmed in
        // josekit 0.10.3's `jwe_context.rs`). Strip it here so this test
        // exercises the genuine "no kid at all" case rather than accidentally
        // relying on that auto-copy to synthesize one.
        let mut jwk = key.published_jwk();
        jwk.as_object_mut().unwrap().remove("kid");
        let jwe = encrypt_compact(&json!({ "a": 1 }), &jwk, "ECDH-ES", "A128GCM").unwrap();
        let err = decrypt_compact(&jwe, std::slice::from_ref(&key), &both_gcm()).unwrap_err();
        assert!(err.to_string().contains("kid"), "got: {err}");
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let k1 = test_decryption_key();
        let k2 = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &k2.published_jwk(),
            "ECDH-ES",
            "A128GCM",
            Some(k2.kid()),
        )
        .unwrap();
        let err = decrypt_compact(&jwe, std::slice::from_ref(&k1), &both_gcm()).unwrap_err();
        assert!(err.to_string().contains("kid"), "got: {err}");
    }

    #[test]
    fn rejects_an_unsupported_enc() {
        let key = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &key.published_jwk(),
            "ECDH-ES",
            "A256GCM",
            Some(key.kid()),
        )
        .unwrap();
        let only_128 = vec!["A128GCM".to_string()];
        let err = decrypt_compact(&jwe, std::slice::from_ref(&key), &only_128).unwrap_err();
        assert!(err.to_string().contains("A256GCM"), "got: {err}");
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = test_decryption_key();
        let jwe = encrypt_compact_with_kid(
            &json!({ "a": 1 }),
            &key.published_jwk(),
            "ECDH-ES",
            "A128GCM",
            Some(key.kid()),
        )
        .unwrap();
        let mut parts: Vec<String> = jwe.split('.').map(|s| s.to_string()).collect();
        parts[3].push('A');
        let broken = parts.join(".");
        assert!(decrypt_compact(&broken, std::slice::from_ref(&key), &both_gcm()).is_err());
    }

    #[test]
    fn rejects_a_non_compact_input() {
        let key = test_decryption_key();
        let err =
            decrypt_compact("not.a.jwe", std::slice::from_ref(&key), &both_gcm()).unwrap_err();
        assert!(err.to_string().contains("five segments"), "got: {err}");
    }

    #[test]
    fn rejects_when_no_keys_are_configured() {
        let err = decrypt_compact("a.b.c.d.e", &[], &both_gcm()).unwrap_err();
        assert!(
            err.to_string().contains("no request-decryption keys"),
            "got: {err}"
        );
    }

    /// Regression guard: `encrypt_compact`'s delegation to
    /// `encrypt_compact_with_kid(.., None)` must not itself inject a `kid`.
    ///
    /// Uses a **bare** recipient JWK deliberately, not
    /// `annotated_public_and_bare_private()`: josekit's `serialize_compact`
    /// auto-copies a recipient JWK's own `kid` into the header whenever the
    /// caller didn't set one explicitly, so a JWK that already carries a `kid`
    /// (as that helper's does, and as `DecryptionKey::published_jwk()`'s
    /// always does) would pass this assertion for the wrong reason. A bare JWK
    /// isolates what this guard is actually about: the four-argument form adds
    /// nothing on top of whatever the recipient key already implies.
    #[test]
    fn encrypt_compact_still_writes_no_kid() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let public = serde_json::to_value(keypair.to_jwk_public_key()).unwrap();
        let jwe =
            encrypt_compact(&json!({ "vp_token": "x" }), &public, "ECDH-ES", "A128GCM").unwrap();
        let header = protected_header(&jwe).unwrap();
        assert!(header.get("kid").is_none(), "header was {header}");
    }
}
