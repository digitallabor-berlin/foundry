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
        trust_store: &TrustStore,
        now_unix: i64,
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
    /// The attestation's `nonce` claim, returned so the caller can bind it to
    /// the outer proof's own `nonce`.
    pub nonce: String,
}

/// The claims a verified Wallet Attestation JWT (OpenID4VCI Appendix E) vouches
/// for, carried forward so the Client Attestation PoP JWT (ABCA draft -07) can
/// be checked against them: `sub` is the PoP's expected `iss`, `cnf_jwk` is the
/// key the PoP's signature must verify against (GAP-VCI-14).
#[derive(Debug, Clone)]
pub struct ValidatedAttestation {
    pub sub: String,
    pub cnf_jwk: Jwk,
}

/// Verify a Wallet Attestation JWT (OpenID4VCI Appendix E "Wallet Attestation",
/// L2564) against `trust_store` (the issuer's configured Wallet-Provider CAs).
///
/// HAIP OpenID4VCI / Wallet Attestation (L225) narrows OpenID4VCI's own
/// Appendix E to additionally require the certificate validating the
/// signature be carried in the JWT's `x5c` JOSE header. OpenID4VCI (L2555)
/// separately requires the Authorization Server verify the attestation is
/// signed by an issuer it trusts for this purpose — that is what
/// `validate_chain` against `trust_store` establishes here.
///
/// This validates the attestation JWT only, not the Client Attestation PoP
/// JWT `draft-ietf-oauth-attestation-based-client-auth` also requires
/// (OpenID4VCI Appendix E, L2600) — that PoP check is
/// `validate_client_attestation_pop_jwt`, a separate function, against the
/// `sub`/`cnf_jwk` this function returns.
/// `skip_all` is mandatory: the argument is the attestation JWT itself.
#[tracing::instrument(skip_all)]
fn validate_wallet_attestation_jwt(
    attestation_jwt: &str,
    trust_store: &TrustStore,
    now_unix: i64,
) -> Result<ValidatedAttestation, IssuanceError> {
    let parts: Vec<&str> = attestation_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidClient(
            "wallet attestation: invalid JWS format, expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL.decode(parts[0]).map_err(|e| {
        IssuanceError::InvalidClient(format!("wallet attestation: invalid base64url header: {e}"))
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        IssuanceError::InvalidClient(format!("wallet attestation: invalid header JSON: {e}"))
    })?;

    let typ = header.get("typ").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient("wallet attestation: missing typ header".into())
    })?;
    if typ != "oauth-client-attestation+jwt" {
        return Err(IssuanceError::InvalidClient(format!(
            "wallet attestation: invalid typ header: {typ}, expected oauth-client-attestation+jwt"
        )));
    }

    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient("wallet attestation: missing alg header".into())
    })?;
    if alg == "none" || alg.starts_with("HS") {
        return Err(IssuanceError::InvalidClient(format!(
            "wallet attestation: alg '{alg}' is not permitted (must not be none or symmetric)"
        )));
    }

    // HAIP OpenID4VCI / Wallet Attestation (L225): the public key certificate
    // validating the signature MUST be included in the x5c JOSE header.
    let x5c = header
        .get("x5c")
        .and_then(|v| v.as_array())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidClient("wallet attestation: header has no x5c chain".into())
        })?;
    let leaf_b64 = x5c[0].as_str().ok_or_else(|| {
        IssuanceError::InvalidClient("wallet attestation: x5c[0] is not a string".into())
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
            IssuanceError::InvalidClient(format!(
                "wallet attestation: failed to re-encode leaf public key: {e}"
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
        IssuanceError::InvalidClient(format!(
            "wallet attestation: unable to build verifier from leaf cert: {e}"
        ))
    })?;
    josekit::jwt::decode_with_verifier(attestation_jwt, &verifier).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "wallet attestation: signature verification failed: {e}"
        ))
    })?;

    // OpenID4VCI (L2555): the Authorization Server MUST verify the
    // attestation is signed by an issuer it trusts for this purpose.
    validate_chain(&leaf_pem, &intermediates, trust_store, now_unix as u64)?;

    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "wallet attestation: invalid base64url payload: {e}"
        ))
    })?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        IssuanceError::InvalidClient(format!("wallet attestation: invalid payload JSON: {e}"))
    })?;

    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient("wallet attestation: missing exp claim".into())
    })?;
    if now_unix > exp {
        return Err(IssuanceError::InvalidClient(
            "wallet attestation: has expired".into(),
        ));
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if now_unix < nbf {
            return Err(IssuanceError::InvalidClient(
                "wallet attestation: not yet valid (nbf in the future)".into(),
            ));
        }
    }

    // OpenID4VCI Appendix E: cnf.jwk and sub are REQUIRED. Parsed (not just
    // presence-checked) so a malformed cnf.jwk cannot silently pass. Returned
    // to the caller: sub is the Client Attestation PoP JWT's expected `iss`,
    // cnf_jwk is the key its signature must verify against (GAP-VCI-14).
    let cnf_jwk_value = payload
        .get("cnf")
        .and_then(|v| v.get("jwk"))
        .ok_or_else(|| {
            IssuanceError::InvalidClient("wallet attestation: missing cnf.jwk claim".into())
        })?;
    let cnf_jwk: Jwk = serde_json::from_value(cnf_jwk_value.clone()).map_err(|e| {
        IssuanceError::InvalidClient(format!("wallet attestation: invalid cnf.jwk: {e}"))
    })?;
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidClient("wallet attestation: missing or empty sub claim".into())
        })?;

    Ok(ValidatedAttestation {
        sub: sub.to_string(),
        cnf_jwk,
    })
}

/// Verify a key-attestation JWT (OpenID4VCI Appendix D.1) against `trust_store`
/// (the issuer's configured Wallet-Provider CAs), checking that its `nonce` is
/// an authentic, unexpired issuer-minted challenge per Appendix F.1's
/// `key_attestation` header rule.
///
/// The nonce is validated against `nonce_secret` rather than compared to
/// per-transaction state, because the Nonce Endpoint is unauthenticated and so
/// nonces are never bound to a transaction (see [`crate::nonce`]).
/// `skip_all` is mandatory: the arguments are the attestation JWT and the
/// process MAC secret.
#[tracing::instrument(skip_all)]
pub fn verify_key_attestation_jwt(
    key_attestation_jwt: &str,
    trust_store: &TrustStore,
    nonce_secret: &crate::nonce::NonceSecret,
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
    crate::nonce::verify_nonce(nonce_secret, nonce, now_unix)
        .map_err(|e| IssuanceError::InvalidProof(format!("key_attestation: {e}")))?;
    let nonce = nonce.to_string();

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

    Ok(KeyAttestationClaims {
        attested_keys,
        nonce,
    })
}

#[derive(Debug, Clone, Default)]
pub struct DefaultAttestationVerifier;

impl WalletAttestationVerifier for DefaultAttestationVerifier {
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
        trust_store: &TrustStore,
        now_unix: i64,
    ) -> Result<(), IssuanceError> {
        // `validate_wallet_attestation_jwt` now returns `ValidatedAttestation`
        // (Task 5), but this trait's own signature does not change until
        // Task 8 rewires it to return `Option<PopClaims>`; discard it here.
        match mode {
            // Disabled skips validation entirely, even if a header happens
            // to be present.
            Mode::Disabled => Ok(()),
            Mode::Required => {
                let jwt = attestation_header.ok_or_else(|| {
                    IssuanceError::InvalidClient("wallet attestation is required".into())
                })?;
                validate_wallet_attestation_jwt(jwt, trust_store, now_unix).map(|_| ())
            }
            // Optional tolerates absence, but a *present* attestation must
            // still be a validly signed, trust-anchored JWT — presence and
            // validity are distinct checks (GAP-HAIP-04).
            Mode::Optional => match attestation_header {
                Some(jwt) => {
                    validate_wallet_attestation_jwt(jwt, trust_store, now_unix).map(|_| ())
                }
                None => Ok(()),
            },
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

    /// Builds a Wallet (Client) Attestation JWT (OpenID4VCI Appendix E) with
    /// full control over header/payload shape, chained to a fresh CA, to
    /// exercise the structural requirements `signed_wallet_attestation`'s
    /// happy path does not vary. Returns (jwt, ca_cert_pem).
    #[allow(clippy::too_many_arguments)]
    fn wallet_attestation_jwt_custom(
        alg: &str,
        typ: &str,
        include_x5c: bool,
        exp: Option<i64>,
        nbf: Option<i64>,
        cnf_jwk: Option<serde_json::Value>,
        include_sub: bool,
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

        let mut header = serde_json::Map::new();
        header.insert("typ".to_string(), serde_json::json!(typ));
        header.insert("alg".to_string(), serde_json::json!(alg));
        if include_x5c {
            header.insert(
                "x5c".to_string(),
                serde_json::Value::Array(x5c.into_iter().map(serde_json::Value::String).collect()),
            );
        }

        let mut payload = serde_json::Map::new();
        payload.insert(
            "iss".to_string(),
            serde_json::json!("https://wallet-provider.example.com"),
        );
        if include_sub {
            payload.insert(
                "sub".to_string(),
                serde_json::json!("https://wallet.example.org"),
            );
        }
        if let Some(v) = exp {
            payload.insert("exp".to_string(), serde_json::json!(v));
        }
        if let Some(v) = nbf {
            payload.insert("nbf".to_string(), serde_json::json!(v));
        }
        if let Some(cnf_jwk) = cnf_jwk {
            payload.insert("cnf".to_string(), serde_json::json!({ "jwk": cnf_jwk }));
        }

        let header_b64 =
            B64URL.encode(serde_json::to_vec(&serde_json::Value::Object(header)).unwrap());
        let payload_b64 =
            B64URL.encode(serde_json::to_vec(&serde_json::Value::Object(payload)).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig_b64 = B64URL.encode(signer.sign(signing_input.as_bytes()).unwrap());

        (format!("{signing_input}.{sig_b64}"), ca.cert_pem)
    }

    /// A validly signed, fully-formed Wallet Attestation JWT chained to a
    /// fresh CA, plus that CA's PEM so the caller can build a matching
    /// `TrustStore`. The happy path all the negative `wallet_attestation_jwt_custom`
    /// cases vary from.
    fn signed_wallet_attestation(exp: i64) -> (String, String) {
        wallet_attestation_jwt_custom(
            "ES256",
            "oauth-client-attestation+jwt",
            true,
            Some(exp),
            None,
            Some(sample_jwk()),
            true,
        )
    }

    #[test]
    fn accepts_a_validly_signed_trust_anchored_wallet_attestation() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_wallet_attestation(now + 100_000);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .expect("a validly signed, trust-anchored attestation must be accepted");
    }

    /// GAP-VCI-14: `sub` and `cnf_jwk` are the two claims the Client
    /// Attestation PoP JWT is verified against (Task 6) -- this proves they
    /// actually come back from a valid attestation, not just that validation
    /// passes.
    #[test]
    fn returns_the_attestations_sub_and_a_usable_cnf_jwk() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_wallet_attestation(now + 100_000);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let validated = validate_wallet_attestation_jwt(&jwt, &store, now)
            .expect("a validly signed, trust-anchored attestation must be accepted");
        assert_eq!(validated.sub, "https://wallet.example.org");
        // Must be usable as a real ES256 verification key, not merely "some
        // JSON value" -- proves it was parsed as a Jwk, not just presence-checked.
        ES256
            .verifier_from_jwk(&validated.cnf_jwk)
            .expect("cnf_jwk must be usable as an ES256 verification key");
    }

    /// The `cnf.jwk` claim can be well-formed JSON and still be unusable as an
    /// ES256 verification key (wrong curve). This must be rejected, not
    /// silently accepted as "parses as *a* JWK".
    #[test]
    fn rejects_a_cnf_jwk_that_is_not_an_ec_p256_key() {
        let now = now_secs();
        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "ES256",
            "oauth-client-attestation+jwt",
            true,
            Some(now + 100_000),
            None,
            Some(wrong_curve_jwk()),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        // The wrong-curve JWK still parses structurally, so acceptance would
        // be silent here; the failure must surface downstream when the PoP
        // check (Task 6) tries to build a verifier from it. Confirmed here
        // via ES256::verifier_from_jwk directly, since attestation.rs
        // currently has no caller that does this check itself.
        let validated = validate_wallet_attestation_jwt(&jwt, &store, now)
            .expect("the attestation JWT itself is validly signed and trust-anchored");
        assert!(
            ES256.verifier_from_jwk(&validated.cnf_jwk).is_err(),
            "a P-384 EC key must not be usable as an ES256 verification key"
        );
    }

    /// GAP-HAIP-04: this is the bypass the gap describes. Before the fix, an
    /// arbitrary non-JWT string passed `Mode::Required` because the checker
    /// only tested presence.
    #[test]
    fn rejects_an_arbitrary_non_jwt_string() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some("not-a-jwt-at-all"), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_attestation_signed_by_an_untrusted_anchor() {
        let now = now_secs();
        let (jwt, _ca_pem) = signed_wallet_attestation(now + 100_000);
        let other_ca = new_ca("Some Other Root CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[other_ca.cert_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::Trust(_)));
    }

    #[test]
    fn rejects_alg_none() {
        let now = now_secs();
        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "none",
            "oauth-client-attestation+jwt",
            true,
            Some(now + 100_000),
            None,
            Some(sample_jwk()),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_symmetric_alg() {
        let now = now_secs();
        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "HS256",
            "oauth-client-attestation+jwt",
            true,
            Some(now + 100_000),
            None,
            Some(sample_jwk()),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_missing_x5c() {
        let now = now_secs();
        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "ES256",
            "oauth-client-attestation+jwt",
            false,
            Some(now + 100_000),
            None,
            Some(sample_jwk()),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_wrong_typ() {
        let now = now_secs();
        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "ES256",
            "jwt",
            true,
            Some(now + 100_000),
            None,
            Some(sample_jwk()),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_expired_wallet_attestation() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_wallet_attestation(now - 100);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, Some(&jwt), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn optional_mode_validates_a_present_attestation_but_tolerates_absence() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_wallet_attestation(now + 100_000);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Optional, Some(&jwt), &store, now)
            .expect("Optional mode must still validate a present attestation");
        DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Optional, None, &store, now)
            .expect("Optional mode must tolerate absence");

        // And a present-but-invalid attestation must still be rejected under
        // Optional -- presence-vs-validity is the distinction GAP-HAIP-04
        // found collapsed; Optional only governs whether absence is
        // tolerated, not whether a present header must be valid.
        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Optional, Some("not-a-jwt-at-all"), &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn disabled_mode_skips_validation_entirely() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Disabled, None, &store, now)
            .expect("Disabled must tolerate absence");
        DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Disabled, Some("not-a-jwt-at-all"), &store, now)
            .expect("Disabled must skip validation even when a header is present");
    }

    #[test]
    fn required_mode_still_rejects_absence() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, None, &store, now)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
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

    /// Structurally valid EC JWK, but the wrong curve for ES256 -- `kty` is
    /// still "EC" so it clears the coarse `kty` check, but `crv` is "P-384"
    /// so `ES256.verifier_from_jwk` must still reject it.
    fn wrong_curve_jwk() -> serde_json::Value {
        let kp = EcKeyPair::generate(EcCurve::P384).unwrap();
        let jwk = kp.to_jwk_public_key();
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

    fn test_secret() -> crate::nonce::NonceSecret {
        crate::nonce::NonceSecret::from_bytes([42u8; 32])
    }

    /// A real MAC-authenticated nonce, exactly as `POST /nonce` mints them.
    fn minted_nonce(secret: &crate::nonce::NonceSecret, now: i64) -> String {
        crate::nonce::issue_nonce(secret, now).unwrap().c_nonce
    }

    #[test]
    fn verifies_valid_key_attestation_and_returns_attested_keys() {
        let now = now_secs();
        let secret = test_secret();
        let nonce = minted_nonce(&secret, now);
        let (jwt, ca_pem) =
            signed_key_attestation(&nonce, now + 100_000, vec![sample_jwk(), sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let claims = verify_key_attestation_jwt(&jwt, &store, &secret, now).unwrap();
        assert_eq!(claims.attested_keys.len(), 2);
        // Returned so the caller can bind it to the outer proof's nonce.
        assert_eq!(claims.nonce, nonce);
    }

    #[test]
    fn rejects_nonce_not_minted_by_this_issuer() {
        let now = now_secs();
        // A nonce this issuer never minted carries no valid MAC.
        let (jwt, ca_pem) = signed_key_attestation("nonce-abc", now + 100_000, vec![sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, &test_secret(), now).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_expired_attestation() {
        let now = now_secs();
        let secret = test_secret();
        let nonce = minted_nonce(&secret, now);
        let (jwt, ca_pem) = signed_key_attestation(&nonce, now - 100, vec![sample_jwk()]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, &secret, now).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_untrusted_chain() {
        let now = now_secs();
        let secret = test_secret();
        let nonce = minted_nonce(&secret, now);
        let (jwt, _ca_pem) = signed_key_attestation(&nonce, now + 100_000, vec![sample_jwk()]);
        let other_ca = new_ca("Some Other Root CA", 3650).unwrap();
        let store = TrustStore::from_pems(&[other_ca.cert_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, &secret, now).unwrap_err();
        assert!(
            matches!(err, IssuanceError::Trust(_)) || matches!(err, IssuanceError::InvalidProof(_))
        );
    }

    #[test]
    fn rejects_empty_attested_keys() {
        let now = now_secs();
        let secret = test_secret();
        let nonce = minted_nonce(&secret, now);
        let (jwt, ca_pem) = signed_key_attestation(&nonce, now + 100_000, vec![]);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = verify_key_attestation_jwt(&jwt, &store, &secret, now).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }
}
