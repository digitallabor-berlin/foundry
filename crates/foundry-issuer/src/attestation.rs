//! Wallet and key attestation verifier traits and default implementations.

use crate::error::IssuanceError;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use foundry_core::config::Mode;
use foundry_core::storage::Storage;
use foundry_core::trust::{validate_chain, x5c_entry_to_pem, TrustStore};
use josekit::jwk::Jwk;
use josekit::jws::ES256;
use sha2::{Digest, Sha256};

pub trait WalletAttestationVerifier: Send + Sync {
    /// Returns `Ok(Some(claims))` when both a Wallet Attestation and a
    /// matching Client Attestation PoP JWT were present and verified;
    /// `Ok(None)` when `mode` is `Disabled`, or both are absent under
    /// `Optional`. Stays synchronous and takes no `Storage` -- the anti-replay
    /// claim (`claim_pop_jti`) is a separate step so a database is never
    /// required to unit-test the crypto/claim checks here.
    #[allow(clippy::too_many_arguments)]
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
        pop_header: Option<&str>,
        trust_store: &TrustStore,
        expected_aud: &str,
        now_unix: i64,
        max_age_secs: u64,
    ) -> Result<Option<PopClaims>, IssuanceError>;
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

/// The claims recovered from a verified Client Attestation PoP JWT (ABCA
/// draft -07 §5.2), consumed by `claim_pop_jti`'s anti-replay check.
#[derive(Debug, Clone)]
pub struct PopClaims {
    pub iss: String,
    pub jti: String,
    pub iat: i64,
}

/// ABCA draft -07 §12.1: "clock skews between servers and clients may be
/// large" -- the tolerance applied when a PoP's `iat`/`nbf` lands slightly in
/// the future relative to this server's clock. Never used to widen how far
/// into the past an `iat` may be -- that is `max_age_secs`, a distinct policy
/// knob (`AttestationMode.pop_max_age_secs`).
const POP_CLOCK_SKEW_SECS: i64 = 60;

/// Verify a Client Attestation PoP JWT (ABCA draft -07 §5.2) against the
/// Wallet Attestation it accompanies (GAP-VCI-14).
///
/// Every check below cites its ABCA clause; see
/// docs/superlight/specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md
/// for the full table this mirrors. `skip_all` is mandatory: the argument is
/// the PoP JWT itself.
///
#[tracing::instrument(skip_all)]
fn validate_client_attestation_pop_jwt(
    pop_jwt: &str,
    attestation: &ValidatedAttestation,
    expected_aud: &str,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<PopClaims, IssuanceError> {
    // Check 1 (ABCA §5.2 / RFC 7519): exactly three dot-separated parts,
    // base64url-decodable header and payload.
    let parts: Vec<&str> = pop_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: invalid JWS format, expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL.decode(parts[0]).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "client attestation pop: invalid base64url header: {e}"
        ))
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        IssuanceError::InvalidClient(format!("client attestation pop: invalid header JSON: {e}"))
    })?;

    // Check 2 (ABCA §5.2): typ REQUIRED, must be oauth-client-attestation-pop+jwt.
    let typ = header.get("typ").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient("client attestation pop: missing typ header".into())
    })?;
    if typ != "oauth-client-attestation-pop+jwt" {
        return Err(IssuanceError::InvalidClient(format!(
            "client attestation pop: invalid typ header: {typ}, expected oauth-client-attestation-pop+jwt"
        )));
    }

    // Check 3 (ABCA §9.4; HAIP-0088): alg must be ES256. ABCA §9.4 only
    // requires "a registered asymmetric digital signature algorithm ...
    // not none"; HAIP-0088 narrows this to ES256 specifically for the PoP JWT.
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient("client attestation pop: missing alg header".into())
    })?;
    if alg != "ES256" {
        return Err(IssuanceError::InvalidClient(format!(
            "client attestation pop: alg '{alg}' is not permitted, expected ES256"
        )));
    }

    // Check 4 (ABCA §5.2 r3, §6.2.3, §9.7): the signature MUST verify against
    // the public key in the Client Attestation JWT's cnf.jwk claim.
    let verifier = ES256.verifier_from_jwk(&attestation.cnf_jwk).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "client attestation pop: unable to build a verifier from the attestation's cnf.jwk: {e}"
        ))
    })?;
    josekit::jwt::decode_with_verifier(pop_jwt, &verifier).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "client attestation pop: signature verification failed: {e}"
        ))
    })?;

    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "client attestation pop: invalid base64url payload: {e}"
        ))
    })?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        IssuanceError::InvalidClient(format!("client attestation pop: invalid payload JSON: {e}"))
    })?;

    // Check 5 (ABCA §5.2 r4, §9.13): iss REQUIRED, non-empty, MUST equal the
    // attestation's sub claim (both represent the client_id).
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidClient(
                "client attestation pop: missing or empty iss claim".into(),
            )
        })?;
    if iss != attestation.sub {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: iss does not match the attestation's sub claim".into(),
        ));
    }

    // Check 6 (ABCA §5.2, §9.10): aud REQUIRED, string or array form, MUST
    // exactly equal / contain expected_aud (the AS's RFC 8414 issuer
    // identifier URL). Exact match only -- no prefix or case-insensitive
    // comparison escape hatch (Q2(a)).
    let aud_value = payload.get("aud").ok_or_else(|| {
        IssuanceError::InvalidClient("client attestation pop: missing aud claim".into())
    })?;
    let aud_matches = match aud_value {
        serde_json::Value::String(s) => s == expected_aud,
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
        _ => false,
    };
    if !aud_matches {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: aud does not match the authorization server's issuer identifier"
                .into(),
        ));
    }

    // Check 7 (ABCA §5.2): jti REQUIRED, a non-empty string.
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            IssuanceError::InvalidClient(
                "client attestation pop: missing or empty jti claim".into(),
            )
        })?;

    // Check 8 (ABCA §9.9, §10.6, §12.1): iat REQUIRED, an integer; bounds the
    // sliding replay-detection window both from staleness (max_age_secs) and
    // from the future (POP_CLOCK_SKEW_SECS).
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "client attestation pop: missing or non-integer iat claim".into(),
        )
    })?;
    if now_unix - iat > max_age_secs as i64 {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: iat is older than the allowed max age".into(),
        ));
    }
    if iat > now_unix + POP_CLOCK_SKEW_SECS {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: iat is too far in the future".into(),
        ));
    }

    // Check 9 (ABCA §5.2): nbf, if present, MUST NOT be beyond the tolerable
    // clock skew.
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if nbf > now_unix + POP_CLOCK_SKEW_SECS {
            return Err(IssuanceError::InvalidClient(
                "client attestation pop: not yet valid (nbf beyond tolerable clock skew)".into(),
            ));
        }
    }

    // No `exp` check by design: ABCA removed `exp` from the PoP JWT in draft
    // -06. Freshness is entirely the `iat` sliding window above. §5.2 rule 1:
    // "The JWT MAY contain other claims. All claims that are not understood
    // by implementations MUST be ignored" -- an exp claim, even an expired
    // one, is simply unrecognised and ignored.

    Ok(PopClaims {
        iss: iss.to_string(),
        jti: jti.to_string(),
        iat,
    })
}

/// KV storage namespace for Client Attestation PoP `jti` replay claims
/// (GAP-VCI-14).
const POP_JTI_NAMESPACE: &str = "client_attestation_pop_jti";

/// Atomically claims a Client Attestation PoP JWT's `(iss, jti)` pair,
/// rejecting a replay (ABCA draft -07 §10.6, §12.1).
///
/// Keyed on a hash of `(iss, jti)` rather than bare `jti`: a bare-`jti`
/// namespace would let one wallet pre-claim `jti` values and deny service to
/// another. Hashing also keeps the raw, attacker-controlled `iss`/`jti`
/// strings out of the SQL key and out of any log line derived from it.
///
/// No `now_unix` parameter: the TTL derives from `claims.iat`, which
/// `validate_client_attestation_pop_jwt` has already bounded against `now` --
/// passing `now` again here would create a second source of truth for the
/// same fact.
/// `skip_all` is mandatory: `claims` carries the raw `iss` and `jti`.
#[tracing::instrument(skip_all)]
pub(crate) async fn claim_pop_jti(
    storage: &dyn Storage,
    claims: &PopClaims,
    max_age_secs: u64,
) -> Result<(), IssuanceError> {
    let mut hasher = Sha256::new();
    hasher.update(claims.iss.as_bytes());
    hasher.update([0u8]);
    hasher.update(claims.jti.as_bytes());
    let key = B64URL.encode(hasher.finalize());

    let expires_at = claims.iat + max_age_secs as i64 + POP_CLOCK_SKEW_SECS;

    let claimed = storage
        .insert_kv_if_absent(POP_JTI_NAMESPACE, &key, "1", Some(expires_at))
        .await?;
    if !claimed {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: jti has already been used".into(),
        ));
    }
    Ok(())
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
    #[allow(clippy::too_many_arguments)]
    fn verify_wallet_attestation(
        &self,
        mode: Mode,
        attestation_header: Option<&str>,
        pop_header: Option<&str>,
        trust_store: &TrustStore,
        expected_aud: &str,
        now_unix: i64,
        max_age_secs: u64,
    ) -> Result<Option<PopClaims>, IssuanceError> {
        // Disabled skips validation entirely, even if either header happens
        // to be present and structurally invalid.
        if matches!(mode, Mode::Disabled) {
            return Ok(None);
        }

        let attestation_jwt = match attestation_header {
            Some(jwt) => jwt,
            None => {
                if matches!(mode, Mode::Required) {
                    return Err(IssuanceError::InvalidClient(
                        "wallet attestation is required".into(),
                    ));
                }
                // Optional + absent attestation: a PoP without an attestation
                // makes no sense -- there is no cnf.jwk to verify it against.
                if pop_header.is_some() {
                    return Err(IssuanceError::InvalidClient(
                        "client attestation pop present without a wallet attestation".into(),
                    ));
                }
                return Ok(None);
            }
        };

        // A *present* attestation must still be a validly signed,
        // trust-anchored JWT -- presence and validity are distinct checks
        // (GAP-HAIP-04), under both Required and Optional.
        let attestation = validate_wallet_attestation_jwt(attestation_jwt, trust_store, now_unix)?;

        // ABCA §6.2 rule 2: exactly one Client Attestation PoP JWT MUST
        // accompany a present Wallet Attestation, under both Required and
        // Optional (GAP-VCI-14).
        let pop_jwt = pop_header.ok_or_else(|| {
            IssuanceError::InvalidClient(
                "client attestation pop is required when a wallet attestation is present".into(),
            )
        })?;

        let claims = validate_client_attestation_pop_jwt(
            pop_jwt,
            &attestation,
            expected_aud,
            now_unix,
            max_age_secs,
        )?;
        Ok(Some(claims))
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
            .verify_wallet_attestation(
                Mode::Required,
                Some("not-a-jwt-at-all"),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
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
            .verify_wallet_attestation(
                Mode::Required,
                Some(&jwt),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
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
            .verify_wallet_attestation(
                Mode::Required,
                Some(&jwt),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
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
            .verify_wallet_attestation(
                Mode::Required,
                Some(&jwt),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
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
            .verify_wallet_attestation(
                Mode::Required,
                Some(&jwt),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
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
            .verify_wallet_attestation(
                Mode::Required,
                Some(&jwt),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_expired_wallet_attestation() {
        let now = now_secs();
        let (jwt, ca_pem) = signed_wallet_attestation(now - 100);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                Some(&jwt),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// A present-but-invalid attestation must still be rejected under
    /// Optional -- presence-vs-validity is the distinction GAP-HAIP-04 found
    /// collapsed; Optional only governs whether *absence* is tolerated, not
    /// whether a present header must be valid.
    #[test]
    fn optional_mode_rejects_a_present_but_invalid_attestation() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Optional,
                Some("not-a-jwt-at-all"),
                None,
                &store,
                POP_TEST_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    // -- verify_wallet_attestation mode matrix (Task 8, GAP-VCI-14) --

    const WALLET_ATTESTATION_SUB: &str = "https://wallet.example.org";
    const MATRIX_AUD: &str = "https://as.example.com/matrix";

    /// A fresh EC P-256 keypair usable both as a Wallet Attestation's
    /// `cnf.jwk` and to sign a matching Client Attestation PoP JWT.
    fn fresh_cnf_keypair() -> (Jwk, impl JwsSigner) {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut public = kp.to_jwk_public_key();
        public.set_algorithm("ES256");
        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        (public, signer)
    }

    /// A fully-formed, validly signed Wallet Attestation (chained to a fresh
    /// CA) plus a Client Attestation PoP JWT that verifies against its
    /// `cnf.jwk` -- the "present, present" happy path the mode matrix
    /// accepts. Returns `(attestation_jwt, pop_jwt, ca_cert_pem)`.
    fn matched_attestation_and_pop(now: i64, aud: &str) -> (String, String, String) {
        let (cnf_jwk, signer) = fresh_cnf_keypair();
        let cnf_jwk_value = serde_json::to_value(&cnf_jwk).unwrap();
        let (attestation_jwt, ca_pem) = wallet_attestation_jwt_custom(
            "ES256",
            "oauth-client-attestation+jwt",
            true,
            Some(now + 100_000),
            None,
            Some(cnf_jwk_value),
            true,
        );
        let hdr = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            WALLET_ATTESTATION_SUB,
            serde_json::json!(aud),
            "jti-matrix-1",
            now,
        );
        let pop_jwt = sign_pop(&hdr, &payload, &signer);
        (attestation_jwt, pop_jwt, ca_pem)
    }

    #[test]
    fn matrix_disabled_any_any_is_ok_none_with_no_validation() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let result = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Disabled,
                Some("not-a-jwt-at-all"),
                Some("also-not-a-jwt"),
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .expect("Disabled must skip all validation, even with structurally invalid inputs");
        assert!(result.is_none());
    }

    #[test]
    fn matrix_required_absent_absent_rejects() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Required, None, None, &store, MATRIX_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn matrix_required_absent_present_rejects() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                None,
                Some("some-pop-jwt"),
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// ABCA §6.2 rule 2.
    #[test]
    fn matrix_required_present_absent_rejects() {
        let now = now_secs();
        let (attestation_jwt, _pop_jwt, ca_pem) = matched_attestation_and_pop(now, MATRIX_AUD);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                Some(&attestation_jwt),
                None,
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn matrix_required_present_present_returns_some_claims() {
        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) = matched_attestation_and_pop(now, MATRIX_AUD);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let result = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                Some(&attestation_jwt),
                Some(&pop_jwt),
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .expect("both attestation and a matching PoP present must be accepted");
        let claims = result.expect("must return Some(claims)");
        assert_eq!(claims.iss, WALLET_ATTESTATION_SUB);
    }

    #[test]
    fn matrix_optional_absent_absent_is_ok_none() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let result = DefaultAttestationVerifier
            .verify_wallet_attestation(Mode::Optional, None, None, &store, MATRIX_AUD, now, 300)
            .expect("Optional with both absent must be Ok(None)");
        assert!(result.is_none());
    }

    /// No `cnf.jwk` exists to verify a PoP against when there is no
    /// attestation.
    #[test]
    fn matrix_optional_absent_present_rejects() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Optional,
                None,
                Some("some-pop-jwt"),
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// ABCA §6.2 rule 2 applies identically under Optional once an
    /// attestation is present.
    #[test]
    fn matrix_optional_present_absent_rejects() {
        let now = now_secs();
        let (attestation_jwt, _pop_jwt, ca_pem) = matched_attestation_and_pop(now, MATRIX_AUD);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Optional,
                Some(&attestation_jwt),
                None,
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn matrix_optional_present_present_returns_some_claims() {
        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem) = matched_attestation_and_pop(now, MATRIX_AUD);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let result = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Optional,
                Some(&attestation_jwt),
                Some(&pop_jwt),
                &store,
                MATRIX_AUD,
                now,
                300,
            )
            .expect("both present and matching under Optional must be accepted");
        assert!(result.is_some());
    }

    use super::verify_key_attestation_jwt;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::KeyPair as _;
    use josekit::jws::{JwsSigner, HS256};

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

    // -- Client Attestation PoP JWT (ABCA draft -07 §5.2, GAP-VCI-14) --

    const POP_TEST_SUB: &str = "https://client.example.com";
    const POP_TEST_AUD: &str = "https://as.example.com";

    /// A fresh EC P-256 keypair: the public half is usable as an
    /// attestation's `cnf.jwk`, the private half signs a matching PoP JWT --
    /// mirrors ABCA §5.2 r3 (the PoP is signed by the same key the
    /// attestation vouches for).
    fn pop_attestation_and_signer() -> (ValidatedAttestation, impl JwsSigner) {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut cnf_jwk = kp.to_jwk_public_key();
        cnf_jwk.set_algorithm("ES256");
        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        (
            ValidatedAttestation {
                sub: POP_TEST_SUB.to_string(),
                cnf_jwk,
            },
            signer,
        )
    }

    /// Signs `header`/`payload` with `signer`, producing a compact JWS.
    fn sign_pop(
        header: &serde_json::Value,
        payload: &serde_json::Value,
        signer: &dyn JwsSigner,
    ) -> String {
        let header_b64 = B64URL.encode(serde_json::to_vec(header).unwrap());
        let payload_b64 = B64URL.encode(serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_b64 = B64URL.encode(signer.sign(signing_input.as_bytes()).unwrap());
        format!("{signing_input}.{sig_b64}")
    }

    fn pop_header(alg: &str, typ: &str) -> serde_json::Value {
        serde_json::json!({ "typ": typ, "alg": alg })
    }

    /// A fully-formed, valid PoP payload. Individual tests clone and mutate
    /// this via `serde_json::Map` operations for negative cases.
    fn pop_payload(iss: &str, aud: serde_json::Value, jti: &str, iat: i64) -> serde_json::Value {
        serde_json::json!({ "iss": iss, "aud": aud, "jti": jti, "iat": iat })
    }

    #[test]
    fn accepts_a_valid_pop_jwt_and_returns_its_claims() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let claims =
            validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
                .expect("a valid PoP must be accepted");
        assert_eq!(claims.iss, POP_TEST_SUB);
        assert_eq!(claims.jti, "jti-1");
        assert_eq!(claims.iat, now);
    }

    #[test]
    fn rejects_pop_that_is_not_three_dot_separated_parts() {
        let (attestation, _signer) = pop_attestation_and_signer();
        let now = now_secs();
        let err =
            validate_client_attestation_pop_jwt("only.two", &attestation, POP_TEST_AUD, now, 300)
                .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_invalid_base64url_header() {
        let (attestation, _signer) = pop_attestation_and_signer();
        let now = now_secs();
        let err = validate_client_attestation_pop_jwt(
            "not-valid-base64!!.YWJj.c2ln",
            &attestation,
            POP_TEST_AUD,
            now,
            300,
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_invalid_base64url_payload() {
        let (attestation, _signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header_b64 = B64URL.encode(
            serde_json::to_vec(&pop_header("ES256", "oauth-client-attestation-pop+jwt")).unwrap(),
        );
        let err = validate_client_attestation_pop_jwt(
            &format!("{header_b64}.not-valid-base64!!.c2ln"),
            &attestation,
            POP_TEST_AUD,
            now,
            300,
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_missing_typ_header() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = serde_json::json!({ "alg": "ES256" });
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_wrong_typ_header() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_alg_none() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("none", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// A genuinely HS256-signed JWT, not merely a header claiming HS256 --
    /// proves the rejection isn't an accident of every fixture happening to
    /// be ES256.
    #[test]
    fn rejects_pop_with_hs256_alg_even_when_genuinely_hs256_signed() {
        let (attestation, _signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("HS256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let hmac_signer = HS256
            .signer_from_bytes(b"a-shared-secret-of-no-relation-at-all-32b")
            .unwrap();
        let jwt = sign_pop(&header, &payload, &hmac_signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_signed_by_a_different_key_than_the_attestations_cnf_jwk() {
        let (attestation, _signer) = pop_attestation_and_signer();
        let (_other_attestation, other_signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &other_signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_missing_iss() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = serde_json::json!({ "aud": POP_TEST_AUD, "jti": "jti-1", "iat": now });
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_iss_not_matching_attestation_sub() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            "https://someone-else.example.com",
            serde_json::json!(POP_TEST_AUD),
            "jti-1",
            now,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_missing_aud() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = serde_json::json!({ "iss": POP_TEST_SUB, "jti": "jti-1", "iat": now });
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_wrong_aud_string() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!("https://not-the-as.example.com"),
            "jti-1",
            now,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn accepts_pop_with_aud_array_containing_expected_aud() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(["https://other-as.example.com", POP_TEST_AUD]),
            "jti-1",
            now,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .expect("an aud array containing expected_aud must be accepted");
    }

    #[test]
    fn rejects_pop_with_aud_array_not_containing_expected_aud() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!([
                "https://other-as.example.com",
                "https://yet-another.example.com"
            ]),
            "jti-1",
            now,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Guards the "exact match only" constraint (Q2(a)): neither a prefix nor
    /// a case-insensitive match of `expected_aud` may be accepted.
    #[test]
    fn rejects_pop_with_aud_matching_only_as_prefix_or_case_insensitively() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");

        let prefix_payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(format!("{POP_TEST_AUD}/extra-path-segment")),
            "jti-1",
            now,
        );
        let prefix_jwt = sign_pop(&header, &prefix_payload, &signer);
        let err =
            validate_client_attestation_pop_jwt(&prefix_jwt, &attestation, POP_TEST_AUD, now, 300)
                .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));

        let upper_payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD.to_uppercase()),
            "jti-2",
            now,
        );
        let upper_jwt = sign_pop(&header, &upper_payload, &signer);
        let err =
            validate_client_attestation_pop_jwt(&upper_jwt, &attestation, POP_TEST_AUD, now, 300)
                .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_missing_jti() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = serde_json::json!({ "iss": POP_TEST_SUB, "aud": POP_TEST_AUD, "iat": now });
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_empty_jti() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_non_string_jti() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = serde_json::json!({
            "iss": POP_TEST_SUB, "aud": POP_TEST_AUD, "jti": 12345, "iat": now
        });
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_missing_iat() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload =
            serde_json::json!({ "iss": POP_TEST_SUB, "aud": POP_TEST_AUD, "jti": "jti-1" });
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_non_integer_iat() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = serde_json::json!({
            "iss": POP_TEST_SUB, "aud": POP_TEST_AUD, "jti": "jti-1", "iat": "not-a-number"
        });
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_iat_older_than_max_age() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD),
            "jti-1",
            now - 301,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_pop_with_iat_too_far_in_the_future() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD),
            "jti-1",
            now + 61,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn accepts_pop_with_iat_slightly_in_the_future_within_skew() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD),
            "jti-1",
            now + 30,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .expect("an iat slightly in the future, within skew, must be accepted");
    }

    #[test]
    fn rejects_pop_with_nbf_beyond_skew() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["nbf"] = serde_json::json!(now + 61);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// ABCA §5.2 rule 1: "The JWT MAY contain other claims. All claims that
    /// are not understood by implementations MUST be ignored."
    #[test]
    fn accepts_pop_with_an_unrecognised_extra_claim() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["some_future_extension_claim"] = serde_json::json!("unrecognised-value");
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .expect("an unrecognised extra claim must be ignored, not rejected");
    }

    /// ABCA removed `exp` from the PoP JWT in draft -06; this pins the
    /// deliberate omission so a future reader does not "fix" it by adding an
    /// exp check. An exp claim, even an already-past one, must be accepted --
    /// it is simply an unrecognised claim under §5.2 rule 1.
    #[test]
    fn accepts_pop_with_an_already_expired_exp_claim() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["exp"] = serde_json::json!(now - 1_000_000);
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(&jwt, &attestation, POP_TEST_AUD, now, 300)
            .expect("an exp claim, even an already-past one, must be ignored, not rejected");
    }

    // -- claim_pop_jti: atomic replay detection (GAP-VCI-14) --

    async fn test_storage() -> foundry_core::storage::SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        // Keep the tempdir alive for the storage's lifetime -- dropping it
        // would delete the SQLite file out from under the pool.
        std::mem::forget(dir);
        foundry_core::storage::SqliteStorage::connect(db.to_str().unwrap())
            .await
            .unwrap()
    }

    fn pop_claims(iss: &str, jti: &str, iat: i64) -> PopClaims {
        PopClaims {
            iss: iss.to_string(),
            jti: jti.to_string(),
            iat,
        }
    }

    #[tokio::test]
    async fn claim_pop_jti_first_claim_succeeds() {
        let storage = test_storage().await;
        let claims = pop_claims("https://client.example.com", "jti-1", 1_700_000_000);

        claim_pop_jti(&storage, &claims, 300)
            .await
            .expect("the first claim for a (iss, jti) pair must succeed");
    }

    #[tokio::test]
    async fn claim_pop_jti_rejects_an_immediate_replay() {
        let storage = test_storage().await;
        let claims = pop_claims("https://client.example.com", "jti-1", 1_700_000_000);
        claim_pop_jti(&storage, &claims, 300).await.unwrap();

        let err = claim_pop_jti(&storage, &claims, 300).await.unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[tokio::test]
    async fn claim_pop_jti_a_different_jti_under_the_same_iss_succeeds() {
        let storage = test_storage().await;
        let claims_a = pop_claims("https://client.example.com", "jti-1", 1_700_000_000);
        let claims_b = pop_claims("https://client.example.com", "jti-2", 1_700_000_000);
        claim_pop_jti(&storage, &claims_a, 300).await.unwrap();

        claim_pop_jti(&storage, &claims_b, 300)
            .await
            .expect("a different jti under the same iss must succeed");
    }

    /// Proves `(iss, jti)` keying rather than bare `jti`: a bare-`jti`
    /// namespace would let one wallet pre-claim `jti` values and deny
    /// service to another.
    #[tokio::test]
    async fn claim_pop_jti_the_same_jti_under_a_different_iss_succeeds() {
        let storage = test_storage().await;
        let claims_a = pop_claims("https://wallet-a.example.com", "jti-shared", 1_700_000_000);
        let claims_b = pop_claims("https://wallet-b.example.com", "jti-shared", 1_700_000_000);
        claim_pop_jti(&storage, &claims_a, 300).await.unwrap();

        claim_pop_jti(&storage, &claims_b, 300)
            .await
            .expect("the same jti under a different iss must succeed");
    }

    #[tokio::test]
    async fn claim_pop_jti_expires_at_iat_plus_max_age_plus_skew() {
        let storage = test_storage().await;
        let claims = pop_claims("https://client.example.com", "jti-1", 1_000);
        claim_pop_jti(&storage, &claims, 300).await.unwrap();

        // expected expires_at = iat(1000) + max_age(300) + skew(60) = 1360.
        let removed_before = storage.purge_expired(1359).await.unwrap();
        assert_eq!(
            removed_before, 0,
            "must not have expired yet at iat + max_age + skew - 1"
        );

        let removed_at = storage.purge_expired(1360).await.unwrap();
        assert_eq!(
            removed_at, 1,
            "must expire at exactly iat + max_age + skew, not now + max_age + skew"
        );
    }

    /// The anti-log-leak property: the raw `jti` must never be usable
    /// verbatim as the storage key.
    #[tokio::test]
    async fn claim_pop_jti_does_not_store_the_raw_jti_as_the_key() {
        let storage = test_storage().await;
        let claims = pop_claims(
            "https://client.example.com",
            "a-very-identifiable-jti-value",
            1_700_000_000,
        );
        claim_pop_jti(&storage, &claims, 300).await.unwrap();

        assert_eq!(
            storage
                .get_kv(POP_JTI_NAMESPACE, &claims.jti)
                .await
                .unwrap(),
            None,
            "the raw jti string must never be used as the storage key"
        );
    }
}
