//! Real X.509 trust validation for both directions: the issuer's
//! credential-signing JWT and the verifier's signed request object. Both are
//! compact JWS values carrying an `x5c` header (leaf-first chain); this
//! module verifies the JWS signature against the leaf's public key, then
//! validates the leaf..intermediates chain against the configured trust
//! anchors via `foundry_core::trust::validate_chain`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::trust::{validate_chain, x5c_entry_to_pem, TrustStore};
use josekit::jws::{JwsVerifier, ES256};
use josekit::jwt;

pub struct TrustOutcome {
    pub valid: bool,
    pub detail: String,
}

impl TrustOutcome {
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            valid: false,
            detail: detail.into(),
        }
    }

    fn ok(detail: impl Into<String>) -> Self {
        Self {
            valid: true,
            detail: detail.into(),
        }
    }
}

/// Verify `jws_compact`'s signature and X.509 chain. `now_unix` is injectable
/// for deterministic tests; production callers pass the real current time.
pub fn validate_jws_x5c_chain(
    jws_compact: &str,
    store: &TrustStore,
    now_unix: u64,
) -> TrustOutcome {
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() < 2 {
        return TrustOutcome::fail("not a compact JWS (fewer than 2 dot-separated segments)");
    }
    let header_bytes = match B64URL.decode(parts[0]) {
        Ok(b) => b,
        Err(e) => return TrustOutcome::fail(format!("invalid JWS header base64: {e}")),
    };
    let header: serde_json::Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(e) => return TrustOutcome::fail(format!("invalid JWS header JSON: {e}")),
    };
    let x5c = match header.get("x5c").and_then(|v| v.as_array()) {
        Some(chain) if !chain.is_empty() => chain,
        _ => return TrustOutcome::fail("JWS header has no x5c chain"),
    };
    let leaf_b64 = match x5c[0].as_str() {
        Some(s) => s,
        None => return TrustOutcome::fail("x5c[0] is not a string"),
    };
    let leaf_pem = match x5c_entry_to_pem(leaf_b64) {
        Ok(p) => p,
        Err(e) => return TrustOutcome::fail(format!("x5c[0] is not valid DER: {e}")),
    };

    // Verify the JWS signature itself using the leaf certificate's public key.
    let leaf_cert = match foundry_core::trust::parse_cert_pem(&leaf_pem) {
        Ok(c) => c,
        Err(e) => return TrustOutcome::fail(format!("failed to parse leaf cert: {e}")),
    };
    let verifier: Box<dyn JwsVerifier> = match build_verifier(&leaf_cert) {
        Ok(v) => v,
        Err(e) => return TrustOutcome::fail(e),
    };
    if let Err(e) = jwt::decode_with_verifier(jws_compact, verifier.as_ref()) {
        return TrustOutcome::fail(format!("JWS signature verification failed: {e}"));
    }

    let intermediates: Vec<Vec<u8>> = x5c[1..]
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| x5c_entry_to_pem(s).ok())
        .collect();

    match validate_chain(&leaf_pem, &intermediates, store, now_unix) {
        Ok(()) => TrustOutcome::ok("chain validated against configured trust anchors"),
        Err(e) => TrustOutcome::fail(format!("chain validation failed: {e}")),
    }
}

fn build_verifier(
    leaf_cert: &foundry_core::trust::Certificate,
) -> Result<Box<dyn JwsVerifier>, String> {
    use x509_cert::der::Encode;
    // josekit's `verifier_from_pem` only accepts a "PUBLIC KEY" (SubjectPublicKeyInfo)
    // PEM, not a "CERTIFICATE" PEM, so extract the SPKI from the leaf cert.
    let spki = leaf_cert.tbs_certificate().subject_public_key_info();
    let der = spki
        .to_der()
        .map_err(|e| format!("failed to re-encode leaf cert public key: {e}"))?;
    let pem = pem_from_der(&der);
    ES256
        .verifier_from_pem(pem.as_bytes())
        .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        .map_err(|e| format!("failed to build verifier from leaf cert: {e}"))
}

fn pem_from_der(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::build_x5c;
    use josekit::jws::JwsHeader;
    use josekit::jwt::JwtPayload;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_test_jws(cert_pem: &str, key_pem: &str) -> String {
        let x5c = build_x5c(&[cert_pem.as_bytes().to_vec()]).unwrap();
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        header
            .set_claim("x5c", Some(serde_json::to_value(&x5c).unwrap()))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("hello", Some(serde_json::json!("world")))
            .unwrap();
        let signer = ES256.signer_from_pem(key_pem.as_bytes()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    #[test]
    fn valid_chain_against_matching_root_passes() {
        let root = new_ca("Test Root", 365).unwrap();
        let leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let jws = sign_test_jws(&leaf.cert_pem, &leaf.key_pem);
        assert!(!jws.is_empty(), "test JWS must be constructed");

        let store = TrustStore::from_pems(&[root.cert_pem.into_bytes()]).unwrap();
        let outcome = validate_jws_x5c_chain(&jws, &store, now());
        assert!(
            outcome.valid,
            "expected valid chain, got: {}",
            outcome.detail
        );
    }

    #[test]
    fn chain_against_unrelated_root_fails() {
        let root = new_ca("Test Root", 365).unwrap();
        let leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let jws = sign_test_jws(&leaf.cert_pem, &leaf.key_pem);

        let other_root = new_ca("Other Root", 365).unwrap();
        let store = TrustStore::from_pems(&[other_root.cert_pem.into_bytes()]).unwrap();
        let outcome = validate_jws_x5c_chain(&jws, &store, now());
        assert!(!outcome.valid);
    }

    #[test]
    fn missing_x5c_header_fails_closed() {
        // A valid base64url-encoded `{}` header (no `x5c` claim), followed by
        // arbitrary payload/signature segments so the split still yields >= 2 parts.
        let store = TrustStore::from_pems(&[]).unwrap();
        let outcome = validate_jws_x5c_chain("e30.b.c", &store, now());
        assert!(!outcome.valid);
        assert!(
            outcome.detail.contains("x5c"),
            "detail was: {}",
            outcome.detail
        );
    }

    #[test]
    fn tampered_signature_fails_even_with_a_trusted_chain() {
        // Simulates a forged/MITM'd JWS: the x5c header presents a genuine,
        // trust-anchor-rooted leaf certificate, but the JWS body was actually
        // signed with a *different* private key (e.g. an attacker's own key),
        // not the one whose public key the presented certificate contains.
        // The chain-validation step alone would incorrectly pass this, since
        // it only checks the cert chain, not who actually produced the
        // signature bytes -- this is exactly what the earlier
        // `jwt::decode_with_verifier` signature check must catch.
        let root = new_ca("Test Root", 365).unwrap();
        let presented_leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        let attacker_leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "attacker",
            &["attacker".to_string()],
            365,
        )
        .unwrap();

        // Sign with the attacker's key, but present the (unrelated, trusted)
        // `presented_leaf` certificate in x5c -- a signature/cert mismatch.
        let jws = sign_test_jws(&presented_leaf.cert_pem, &attacker_leaf.key_pem);

        let store = TrustStore::from_pems(&[root.cert_pem.into_bytes()]).unwrap();
        let outcome = validate_jws_x5c_chain(&jws, &store, now());
        assert!(
            !outcome.valid,
            "a JWS signed with a key that doesn't match the presented x5c \
             certificate must fail, even though the certificate itself \
             chains to a trusted anchor"
        );
        assert!(
            outcome.detail.contains("signature"),
            "detail should mention signature verification, was: {}",
            outcome.detail
        );
    }
}
