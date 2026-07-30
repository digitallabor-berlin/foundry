//! Wallet and key attestation verifier traits and default implementations.

use crate::error::IssuanceError;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use foundry_core::config::Mode;
use foundry_core::trust::{validate_chain, x5c_entry_to_pem, TrustStore};
use josekit::jwk::Jwk;
use josekit::jws::ES256;

pub trait WalletAttestationVerifier: Send + Sync {
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
    ) -> Result<(), IssuanceError>;
}

pub trait KeyAttestationVerifier: Send + Sync {
    fn verify_key_attestation(
        &self,
        mode: Mode,
        attestation_data: Option<&str>,
    ) -> Result<(), IssuanceError>;
}

/// The `attested_keys` a verified key attestation vouches for.
#[derive(Debug, Clone)]
pub struct KeyAttestationClaims {
    pub attested_keys: Vec<Jwk>,
}

/// Verify a key-attestation JWT (OpenID4VCI Appendix D.1) against `trust_store`
/// (the issuer's configured Wallet-Provider CAs), binding it to the current
/// `c_nonce` per Appendix F.1's `key_attestation` header rule.
pub fn verify_key_attestation_jwt(
    key_attestation_jwt: &str,
    trust_store: &TrustStore,
    expected_c_nonce: &str,
    now_unix: i64,
) -> Result<KeyAttestationClaims, IssuanceError> {
    let parts: Vec<&str> = key_attestation_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidProof(
            "key_attestation: invalid JWS format, expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL.decode(parts[0]).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid base64url header: {e}"))
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid header JSON: {e}"))
    })?;

    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidProof("key_attestation: missing typ header".into()))?;
    if typ != "key-attestation+jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "key_attestation: invalid typ header: {typ}, expected key-attestation+jwt"
        )));
    }

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidProof("key_attestation: missing alg header".into()))?;
    if alg == "none" || alg.starts_with("HS") {
        return Err(IssuanceError::InvalidProof(format!(
            "key_attestation: alg '{alg}' is not permitted (must not be none or symmetric)"
        )));
    }

    let x5c = header
        .get("x5c")
        .and_then(|v| v.as_array())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("key_attestation: header has no x5c chain".into())
        })?;
    let leaf_b64 = x5c[0].as_str().ok_or_else(|| {
        IssuanceError::InvalidProof("key_attestation: x5c[0] is not a string".into())
    })?;
    let leaf_pem = x5c_entry_to_pem(leaf_b64)?;
    let intermediates: Vec<Vec<u8>> = x5c[1..]
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| x5c_entry_to_pem(s).ok())
        .collect();

    let leaf_cert = foundry_core::trust::parse_cert_pem(&leaf_pem)?;
    use x509_cert::der::Encode;
    let spki_der = leaf_cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| {
            IssuanceError::InvalidProof(format!(
                "key_attestation: failed to re-encode leaf public key: {e}"
            ))
        })?;
    let mut spki_pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    let spki_b64 = B64STD.encode(&spki_der);
    for chunk in spki_b64.as_bytes().chunks(64) {
        spki_pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        spki_pem.push('\n');
    }
    spki_pem.push_str("-----END PUBLIC KEY-----\n");

    let verifier = ES256.verifier_from_pem(spki_pem.as_bytes()).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "key_attestation: unable to build verifier from leaf cert: {e}"
        ))
    })?;
    josekit::jwt::decode_with_verifier(key_attestation_jwt, &verifier).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "key_attestation: signature verification failed: {e}"
        ))
    })?;

    validate_chain(&leaf_pem, &intermediates, trust_store, now_unix as u64)?;

    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid base64url payload: {e}"))
    })?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        IssuanceError::InvalidProof(format!("key_attestation: invalid payload JSON: {e}"))
    })?;

    let exp = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| IssuanceError::InvalidProof("key_attestation: missing exp claim".into()))?;
    if now_unix > exp {
        return Err(IssuanceError::InvalidProof(
            "key_attestation: has expired".into(),
        ));
    }

    let nonce = payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("key_attestation: missing nonce claim".into())
        })?;
    if nonce != expected_c_nonce {
        return Err(IssuanceError::InvalidProof(format!(
            "key_attestation: nonce mismatch: got {nonce}, expected {expected_c_nonce}"
        )));
    }

    let attested_keys_json = payload
        .get("attested_keys")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidProof(
                "key_attestation: missing or empty attested_keys claim".into(),
            )
        })?;

    let mut attested_keys = Vec::with_capacity(attested_keys_json.len());
    for jwk_val in attested_keys_json {
        let jwk: Jwk = serde_json::from_value(jwk_val.clone()).map_err(|e| {
            IssuanceError::InvalidProof(format!("key_attestation: invalid attested key JWK: {e}"))
        })?;
        attested_keys.push(jwk);
    }

    Ok(KeyAttestationClaims { attested_keys })
}

#[derive(Debug, Clone, Default)]
pub struct DefaultAttestationVerifier;

impl WalletAttestationVerifier for DefaultAttestationVerifier {
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
    ) -> Result<(), IssuanceError> {
        match mode {
            Mode::Required => {
                if attestation_header.is_none() {
                    return Err(IssuanceError::InvalidRequest(
                        "wallet attestation is required".into(),
                    ));
                }
                Ok(())
            }
            Mode::Optional | Mode::Disabled => Ok(()),
        }
    }
}

impl KeyAttestationVerifier for DefaultAttestationVerifier {
    fn verify_key_attestation(
        &self,
        mode: Mode,
        attestation_data: Option<&str>,
    ) -> Result<(), IssuanceError> {
        match mode {
            Mode::Required => {
                if attestation_data.is_none() {
                    return Err(IssuanceError::InvalidRequest(
                        "key attestation is required".into(),
                    ));
                }
                Ok(())
            }
            Mode::Optional | Mode::Disabled => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_mode_required_checks_presence() {
        let verifier = DefaultAttestationVerifier;
        assert!(verifier
            .verify_wallet_attestation(Mode::Required, None)
            .is_err());
        assert!(verifier
            .verify_wallet_attestation(Mode::Required, Some("header"))
            .is_ok());
        assert!(verifier
            .verify_wallet_attestation(Mode::Optional, None)
            .is_ok());
        assert!(verifier
            .verify_wallet_attestation(Mode::Disabled, None)
            .is_ok());
    }

    use super::verify_key_attestation_jwt;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::KeyPair as _;

    /// Builds a signed key-attestation JWT whose leaf cert chains to `ca`.
    /// Returns (jwt, ca_cert_pem) so the caller can build a matching TrustStore.
    fn signed_key_attestation(
        nonce: &str,
        exp: i64,
        attested_keys: Vec<serde_json::Value>,
    ) -> (String, String) {
        let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "wallet-provider.example.com",
            &["wallet-provider.example.com".to_string()],
            365,
        )
        .unwrap();
        let leaf_der = {
            let cert = foundry_core::trust::parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
            use x509_cert::der::Encode;
            cert.to_der().unwrap()
        };
        let x5c = vec![base64::engine::general_purpose::STANDARD.encode(&leaf_der)];

        let header = serde_json::json!({
            "typ": "key-attestation+jwt",
            "alg": "ES256",
            "x5c": x5c,
        });
        let payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "iat": 1_700_000_000,
            "exp": exp,
            "nonce": nonce,
            "attested_keys": attested_keys,
        });
        let header_b64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = B64URL.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig = signer.sign(signing_input.as_bytes()).unwrap();
        let sig_b64 = B64URL.encode(sig);

        (format!("{signing_input}.{sig_b64}"), ca.cert_pem)
    }

    fn sample_jwk() -> serde_json::Value {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut jwk = kp.to_jwk_public_key();
        jwk.set_algorithm("ES256");
        serde_json::to_value(&jwk).unwrap()
    }

    /// Real wall-clock time, matching the validity windows `pki::new_ca`/
    /// `pki::issue_leaf` stamp onto generated certs (they use `now_utc()`,
    /// not an injectable clock), so chain validation isn't spuriously
    /// rejected as "not yet valid"/expired against a stale fixed timestamp.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn verifies_valid_key_attestation_and_returns_attested_keys() {
        let now = now_secs();
        let (jwt, ca_pem) =
            signed_key_attestation("nonce-abc", now + 100_000, vec![sample_jwk(), sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let claims = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", now).unwrap();
        assert_eq!(claims.attested_keys.len(), 2);
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", now + 100_000, vec![sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "wrong-nonce", now).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_expired_attestation() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", now - 100, vec![sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", now).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_untrusted_chain() {
        let now = now_secs();
        let (jwt, _ca_pem) = signed_key_attestation("nonce-abc", now + 100_000, vec![sample_jwk()]);
        let other_ca = new_ca("Some Other Root CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[other_ca.cert_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", now).unwrap_err();
        assert!(
            matches!(err, IssuanceError::Trust(_)) || matches!(err, IssuanceError::InvalidProof(_))
        );
    }

    #[test]
    fn rejects_empty_attested_keys() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", now + 100_000, vec![]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, "nonce-abc", now).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }
}
