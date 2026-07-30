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
use josekit::jwe::JweHeader;
use josekit::jwk::Jwk;
use josekit::jwt::JwtPayload;
use serde_json::Value;

/// The only JWE key-management algorithm this codebase issues or accepts.
const SUPPORTED_ALG: &str = "ECDH-ES";

/// Encrypt `payload` to `recipient_public_jwk` as a compact-serialization JWE.
///
/// `alg` selects the key-management algorithm and `enc` the content-encryption
/// algorithm; both are written to the JWE protected header. Only `ECDH-ES` is
/// supported for `alg` — anything else is rejected rather than silently
/// producing a header that misdescribes the ciphertext.
///
/// The payload is encoded as a JWT claims set, matching what
/// `josekit::jwt::decode_with_decrypter` expects on the receiving side.
pub fn encrypt_compact(
    payload: &Value,
    recipient_public_jwk: &Value,
    alg: &str,
    enc: &str,
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

    josekit::jwt::encode_with_encrypter(&jwt_payload, &header, &encrypter)
        .map_err(|e| CryptoError::Jwe(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};
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
}
