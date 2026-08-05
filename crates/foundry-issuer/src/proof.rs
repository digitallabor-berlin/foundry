//! Holder proof of possession JWT verification for OpenID4VCI.

use crate::error::IssuanceError;
use crate::nonce::{verify_nonce, NonceSecret};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::Mode;
use foundry_core::trust::TrustStore;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256};
use serde::{Deserialize, Serialize};

/// Wire shape of the OpenID4VCI `proofs` request member.
///
/// OpenID4VCI Credential Request (L852): "The `proofs` parameter contains
/// exactly one parameter named as the proof type" -- enforced by
/// [`ProofsRequest::resolve`], not by the type, because "exactly one of two
/// optional members" is not expressible in a serde-derived struct.
///
/// Two proof types are accepted:
///
/// * `jwt` -- OpenID4VCI's own (L2610), the only path
///   `eudi-lib-jvm-openid4vci-kt`'s `ProofsSpecification.JwtProofs` emits.
/// * `android_keystore_attestation` -- Google Wallet's, an array of X.509
///   certificate chains (see `crate::keystore_proof`). A proof-type name beyond
///   the registry, which Credential Issuer Metadata (L1395) explicitly permits.
///
/// `di_vp` and the top-level `attestation` proof type remain unaccepted;
/// `deny_unknown_fields` makes that an explicit rejection rather than a silently
/// ignored member.
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Vec<String>>,
    /// One entry per attested key; each entry is a certificate chain, leaf
    /// first, each certificate base64-STANDARD DER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android_keystore_attestation: Option<Vec<Vec<String>>>,
}

/// The single proof type a `proofs` member resolved to.
#[derive(Debug)]
pub enum ResolvedProofs<'a> {
    Jwt(&'a [String]),
    AndroidKeystoreAttestation(&'a [Vec<String>]),
}

impl ProofsRequest {
    /// A `jwt`-only `proofs` member. Keeps call sites that predate the second
    /// proof type readable.
    pub fn from_jwts(jwts: Vec<String>) -> Self {
        Self {
            jwt: Some(jwts),
            android_keystore_attestation: None,
        }
    }

    /// Resolve to exactly one non-empty proof type, per L852.
    ///
    /// An empty array is treated as absence, preserving the pre-existing
    /// "missing proof in credential request" message for that case.
    pub fn resolve(&self) -> Result<ResolvedProofs<'_>, IssuanceError> {
        let jwt = self.jwt.as_deref().filter(|j| !j.is_empty());
        let android = self
            .android_keystore_attestation
            .as_deref()
            .filter(|a| !a.is_empty());
        match (jwt, android) {
            (Some(j), None) => Ok(ResolvedProofs::Jwt(j)),
            (None, Some(a)) => Ok(ResolvedProofs::AndroidKeystoreAttestation(a)),
            (Some(_), Some(_)) => Err(IssuanceError::InvalidProof(
                "proofs must contain exactly one proof type, found both jwt and \
                 android_keystore_attestation"
                    .into(),
            )),
            (None, None) => Err(IssuanceError::InvalidProof(
                "missing proof in credential request".into(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedProof {
    pub holder_jwk: Jwk,
}

/// Verifies a single holder proof-of-possession JWT: JWS signature (against
/// a key identified via `jwk`, or `kid` + `key_attestation`), `typ`, `aud`,
/// and the `nonce` claim.
///
/// The `nonce` is not compared against per-transaction state. The Nonce
/// Endpoint is unauthenticated (OpenID4VCI Section 7.1), so a nonce is never
/// bound to a transaction; it is instead validated as an authentic, unexpired,
/// issuer-minted challenge via `nonce_secret` — see [`crate::nonce`].
///
/// `key_attestation_mode` gates which key-source header is acceptable:
/// `Required` rejects a bare `jwk` proof (no attestation), `Disabled`
/// rejects a `kid`+`key_attestation` proof, `Optional` accepts either.
/// `skip_all` is mandatory: `jwt_str` is the holder's proof JWT and
/// `nonce_secret` is the process MAC secret.
#[tracing::instrument(skip_all, fields(key_attestation_mode = ?key_attestation_mode))]
pub fn verify_holder_proof(
    jwt_str: &str,
    expected_issuer: &str,
    nonce_secret: &NonceSecret,
    now_unix: i64,
    key_attestation_mode: Mode,
    key_attestation_trust_store: &TrustStore,
) -> Result<VerifiedProof, IssuanceError> {
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidProof(
            "invalid JWS format: expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid base64url header: {e}")))?;

    let header = JwsHeader::from_bytes(&header_bytes)
        .map_err(|e| IssuanceError::InvalidProof(format!("invalid proof header: {e}")))?;

    let typ = header
        .token_type()
        .ok_or_else(|| IssuanceError::InvalidProof("missing typ header in proof JWT".into()))?;
    if typ != "openid4vci-proof+jwt" {
        return Err(IssuanceError::InvalidProof(format!(
            "invalid proof typ header: {typ}, expected openid4vci-proof+jwt"
        )));
    }

    let jwk_claim = header.claim("jwk");
    let kid_claim = header.claim("kid");
    let x5c_claim = header.claim("x5c");
    let key_attestation_claim = header.claim("key_attestation");

    let present_count = [
        jwk_claim.is_some(),
        kid_claim.is_some(),
        x5c_claim.is_some(),
    ]
    .iter()
    .filter(|p| **p)
    .count();
    if present_count != 1 {
        return Err(IssuanceError::InvalidProof(
            "exactly one of jwk, kid, x5c header claims is required".into(),
        ));
    }

    // Set on the `kid`+`key_attestation` path so the proof payload's own nonce
    // can be required to match the attestation's, preserving Appendix F.1's
    // single-challenge binding now that neither is looked up in storage.
    let mut attested_nonce: Option<String> = None;

    let jwk: Jwk = if let Some(jwk_val) = jwk_claim {
        if key_attestation_mode == Mode::Required {
            return Err(IssuanceError::InvalidProof(
                "key attestation is required for this credential type".into(),
            ));
        }
        serde_json::from_value(jwk_val.clone())
            .map_err(|e| IssuanceError::InvalidProof(format!("invalid jwk in proof header: {e}")))?
    } else if let Some(kid_val) = kid_claim {
        let key_attestation_jwt =
            key_attestation_claim
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    IssuanceError::InvalidProof(
                        "kid header without key_attestation is not supported".into(),
                    )
                })?;

        if key_attestation_mode == Mode::Disabled {
            return Err(IssuanceError::InvalidProof(
                "key attestation is disabled by issuer configuration".into(),
            ));
        }

        let kid_str = kid_val
            .as_str()
            .ok_or_else(|| IssuanceError::InvalidProof("kid header must be a string".into()))?;
        let kid_index: usize = kid_str.parse().map_err(|_| {
            IssuanceError::InvalidProof("kid header must be a valid attested-key index".into())
        })?;

        let claims = crate::attestation::verify_key_attestation_jwt(
            key_attestation_jwt,
            key_attestation_trust_store,
            nonce_secret,
            now_unix,
        )?;

        attested_nonce = Some(claims.nonce.clone());

        claims
            .attested_keys
            .get(kid_index)
            .cloned()
            .ok_or_else(|| {
                IssuanceError::InvalidProof("kid index out of bounds for attested_keys".into())
            })?
    } else {
        return Err(IssuanceError::InvalidProof(
            "x5c header for the jwt proof type is not yet supported".into(),
        ));
    };

    // josekit's `verifier_from_jwk` copies the JWK's own `kid` member into the
    // verifier's `key_id`, which then makes `decode_with_verifier` require a
    // matching `kid` *header* claim on the JWS itself. For an OpenID4VCI proof
    // JWT the key is embedded inline (via `jwk` or resolved from
    // `key_attestation`), so the outer JWS header legitimately has no `kid` —
    // a `kid` on the JWK is just key metadata, not a signature requirement.
    // Strip it before building the verifier so a wallet-supplied JWK `kid`
    // doesn't spuriously fail proof verification.
    let mut verifier_jwk = jwk.clone();
    verifier_jwk.set_parameter("kid", None).map_err(|e| {
        IssuanceError::InvalidProof(format!("unable to normalize jwk for verification: {e}"))
    })?;

    let verifier = ES256.verifier_from_jwk(&verifier_jwk).map_err(|e| {
        IssuanceError::InvalidProof(format!("unable to create verifier from jwk: {e}"))
    })?;

    let (payload, _) = josekit::jwt::decode_with_verifier(jwt_str, &verifier).map_err(|e| {
        IssuanceError::InvalidProof(format!("proof JWS signature verification failed: {e}"))
    })?;

    let aud = payload
        .claim("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("missing or non-string aud claim in proof payload".into())
        })?;
    if aud != expected_issuer {
        return Err(IssuanceError::InvalidProof(format!(
            "proof aud mismatch: got {aud}, expected {expected_issuer}"
        )));
    }

    let nonce = payload
        .claim("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IssuanceError::InvalidProof("missing or non-string nonce claim in proof payload".into())
        })?;
    verify_nonce(nonce_secret, nonce, now_unix)?;

    if let Some(attested) = &attested_nonce {
        if nonce != attested {
            return Err(IssuanceError::InvalidProof(
                "proof nonce does not match the key_attestation nonce".into(),
            ));
        }
    }

    Ok(VerifiedProof { holder_jwk: jwk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::Mode;
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwt::{self, JwtPayload};

    const NOW: i64 = 1_700_000_000;

    fn test_secret() -> NonceSecret {
        NonceSecret::from_bytes([42u8; 32])
    }

    /// A real MAC-authenticated nonce, exactly as `POST /nonce` mints them.
    fn minted_nonce(secret: &NonceSecret, now: i64) -> String {
        crate::nonce::issue_nonce(secret, now).unwrap().c_nonce
    }

    fn signed_proof_jwt(aud: &str, nonce: &str) -> String {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!(aud)))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(nonce)))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    /// Builds a valid key attestation whose sole attested key is `holder_pub_jwk`
    /// (so the caller can sign the outer proof with the matching private key).
    fn valid_key_attestation(
        nonce: &str,
        holder_pub_jwk: &serde_json::Value,
    ) -> (String, TrustStore) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
        use foundry_core::pki::{issue_leaf, new_ca};

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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let header = serde_json::json!({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c});
        let payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "iat": now,
            "exp": now + 100_000,
            "nonce": nonce,
            "attested_keys": [holder_pub_jwk],
        });
        let header_b64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = B64URL.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signer =
            FileSigner::from_pem(leaf.key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let sig_b64 = B64URL.encode(signer.sign(signing_input.as_bytes()).unwrap());
        let jwt = format!("{signing_input}.{sig_b64}");

        let store = TrustStore::from_pems(&[ca.cert_pem.into_bytes()]).unwrap();
        (jwt, store)
    }

    #[test]
    fn verifies_valid_proof_jwt() {
        let secret = test_secret();
        let nonce = minted_nonce(&secret, NOW);
        let jwt_str = signed_proof_jwt("https://issuer.example.com", &nonce);
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let res = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &secret,
            NOW,
            Mode::Optional,
            &empty_store,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }

    #[test]
    fn verifies_valid_proof_jwt_when_embedded_jwk_has_its_own_kid() {
        // Regression test: some wallets (e.g. eudi-lib-jvm-openid4vci-kt-based
        // clients) set a `kid` member on the embedded `jwk` itself (typically a
        // thumbprint), with no `kid` header on the outer JWS. josekit's
        // `verifier_from_jwk` used to propagate that JWK-level `kid` into the
        // verifier's key_id, which then made signature verification fail with
        // "the JWS kid header claim is required" even though the proof is
        // otherwise perfectly valid.
        let secret = test_secret();
        let nonce = minted_nonce(&secret, NOW);

        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");
        public_jwk.set_key_id("some-thumbprint-or-key-id");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(nonce)))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let empty_store = TrustStore::from_pems(&[]).unwrap();
        let res = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &secret,
            NOW,
            Mode::Optional,
            &empty_store,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
        // The original jwk's kid is preserved on the returned holder_jwk even
        // though it was stripped for verification purposes.
        assert_eq!(res.holder_jwk.key_id(), Some("some-thumbprint-or-key-id"));
    }

    #[test]
    fn rejects_nonce_not_minted_by_this_issuer() {
        // The nonce is no longer compared to per-transaction state, so the
        // failure mode is a nonce that carries no valid issuer MAC -- a
        // *present but invalid* c_nonce, which is InvalidNonce (GAP-VCI-04),
        // not InvalidProof.
        let jwt_str = signed_proof_jwt("https://issuer.example.com", "wrong-nonce");
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &test_secret(),
            NOW,
            Mode::Optional,
            &empty_store,
        )
        .unwrap_err();

        assert!(
            matches!(err, IssuanceError::InvalidNonce(_)),
            "got: {err:?}"
        );
    }

    /// OpenID4VCI 1.0 L1049 clause 3: a proof whose `nonce` claim is *missing*
    /// entirely stays `InvalidProof`, distinct from a *present but invalid*
    /// c_nonce (`InvalidNonce`, GAP-VCI-04). This is the boundary that makes
    /// the split meaningful.
    #[test]
    fn rejects_proof_with_missing_nonce_claim_as_invalid_proof_not_invalid_nonce() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public_jwk = keypair.to_jwk_public_key();
        public_jwk.set_algorithm("ES256");

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
            .unwrap();

        // aud set, nonce deliberately omitted.
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let empty_store = TrustStore::from_pems(&[]).unwrap();
        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &test_secret(),
            NOW,
            Mode::Optional,
            &empty_store,
        )
        .unwrap_err();

        assert!(
            matches!(err, IssuanceError::InvalidProof(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_expired_nonce() {
        let secret = test_secret();
        let nonce = minted_nonce(&secret, NOW);
        let jwt_str = signed_proof_jwt("https://issuer.example.com", &nonce);
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &secret,
            NOW + crate::nonce::C_NONCE_TTL_SECS as i64 + 1,
            Mode::Optional,
            &empty_store,
        )
        .unwrap_err();

        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    #[test]
    fn accepts_kid_plus_key_attestation_proof() {
        let secret = test_secret();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = minted_nonce(&secret, now);

        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut holder_pub = keypair.to_jwk_public_key();
        holder_pub.set_algorithm("ES256");
        let holder_pub_json = serde_json::to_value(&holder_pub).unwrap();

        let (attestation_jwt, store) = valid_key_attestation(&nonce, &holder_pub_json);

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("kid", Some(serde_json::json!("0")))
            .unwrap();
        header
            .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(nonce)))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let res = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &secret,
            now,
            Mode::Required,
            &store,
        )
        .unwrap();

        assert_eq!(res.holder_jwk.key_type(), "EC");
    }

    #[test]
    fn rejects_kid_without_key_attestation() {
        // A `kid` header with no accompanying `key_attestation` claim at all.
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("kid", Some(serde_json::json!("0")))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("nonce-123")))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let no_attestation_jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let empty_store = TrustStore::from_pems(&[]).unwrap();
        let err = verify_holder_proof(
            &no_attestation_jwt,
            "https://issuer.example.com",
            &test_secret(),
            NOW,
            Mode::Optional,
            &empty_store,
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_jwk_proof_when_key_attestation_required() {
        let secret = test_secret();
        let nonce = minted_nonce(&secret, NOW);
        let jwt_str = signed_proof_jwt("https://issuer.example.com", &nonce);
        let empty_store = TrustStore::from_pems(&[]).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &secret,
            NOW,
            Mode::Required,
            &empty_store,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn rejects_kid_attestation_proof_when_key_attestation_disabled() {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut holder_pub = keypair.to_jwk_public_key();
        holder_pub.set_algorithm("ES256");
        let holder_pub_json = serde_json::to_value(&holder_pub).unwrap();
        let (attestation_jwt, store) = valid_key_attestation("nonce-123", &holder_pub_json);

        let mut header = JwsHeader::new();
        header.set_token_type("openid4vci-proof+jwt");
        header
            .set_claim("kid", Some(serde_json::json!("0")))
            .unwrap();
        header
            .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!("nonce-123")))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let err = verify_holder_proof(
            &jwt_str,
            "https://issuer.example.com",
            &test_secret(),
            NOW,
            Mode::Disabled,
            &store,
        )
        .unwrap_err();

        assert!(matches!(err, IssuanceError::InvalidProof(_)));
    }

    #[test]
    fn resolves_a_jwt_only_proofs_object() {
        let p = ProofsRequest::from_jwts(vec!["a".into(), "b".into()]);
        match p.resolve().expect("resolves") {
            ResolvedProofs::Jwt(jwts) => assert_eq!(jwts.len(), 2),
            other => panic!("expected Jwt, got {other:?}"),
        }
    }

    #[test]
    fn resolves_an_android_only_proofs_object() {
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({
            "android_keystore_attestation": [["MII"], ["MII"]]
        }))
        .expect("deserializes");
        match p.resolve().expect("resolves") {
            ResolvedProofs::AndroidKeystoreAttestation(chains) => assert_eq!(chains.len(), 2),
            other => panic!("expected AndroidKeystoreAttestation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_two_proof_types_at_once() {
        // OpenID4VCI Credential Request (L852): "The proofs parameter contains
        // exactly one parameter named as the proof type".
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({
            "jwt": ["a"],
            "android_keystore_attestation": [["MII"]]
        }))
        .expect("deserializes");
        let err = p.resolve().expect_err("two proof types must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_an_empty_proofs_object() {
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({})).expect("deserializes");
        let err = p.resolve().expect_err("no proof type must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_an_empty_proof_array() {
        let p = ProofsRequest::from_jwts(Vec::new());
        let err = p
            .resolve()
            .expect_err("an empty jwt array must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
        let p: ProofsRequest = serde_json::from_value(serde_json::json!({
            "android_keystore_attestation": []
        }))
        .expect("deserializes");
        assert!(
            p.resolve().is_err(),
            "an empty chain array must be rejected"
        );
    }

    #[test]
    fn rejects_an_unknown_proof_type_name() {
        // A strictness gain over the previous shape, where serde ignored the
        // unknown key and the request then failed as "missing jwt". L1395 lets
        // an issuer accept proof-type names beyond the registry, but not ones it
        // has never heard of.
        let err = serde_json::from_value::<ProofsRequest>(serde_json::json!({
            "di_vp": ["something"]
        }))
        .expect_err("an unknown proof type must not deserialize");
        assert!(err.to_string().contains("di_vp"), "got {err}");
    }
}
