//! Wallet and key attestation verifier traits and default implementations.

use crate::error::IssuanceError;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use foundry_core::config::Mode;
use foundry_core::storage::Storage;
use foundry_core::trust::{TrustStore, validate_chain, x5c_entry_to_pem};
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
        challenge_mode: Mode,
        nonce_secret: &crate::challenge::NonceSecret,
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
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64())
        && now_unix < nbf
    {
        return Err(IssuanceError::InvalidClient(
            "wallet attestation: not yet valid (nbf in the future)".into(),
        ));
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

    // ABCA draft -07 §9 rule 6: "The key contained in the cnf claim of the
    // Client Attestation JWT is not a private key."
    //
    // `cnf.jwk` names the key the *client* proves possession of, so it must be
    // a public key. A private key here means the Attester leaked the client
    // instance's signing key into a JWT that travels in a plaintext HTTP header
    // — at which point anyone who observes one attestation can mint PoPs for
    // that client indefinitely, and the PoP stops being a proof of anything.
    // Rejecting is cheap and catches a broken Attester before it becomes a
    // credential-theft vector.
    //
    // Checked across every key type's private parameters (RFC 7518 §6.2.2 for
    // EC, §6.3.2 for RSA, §6.4.1 for oct; RFC 8037 §2 for OKP) rather than only
    // EC's `d`, so a non-EC `cnf` cannot smuggle one past on a technicality
    // even though the ES256 verifier built below would reject its `kty`.
    const PRIVATE_JWK_PARAMS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(param) = PRIVATE_JWK_PARAMS
        .iter()
        .find(|p| cnf_jwk.parameter(p).is_some())
    {
        // Names the offending parameter but never its value — that value is,
        // by construction, private key material (AGENTS.md §4.5).
        return Err(IssuanceError::InvalidClient(format!(
            "wallet attestation: cnf.jwk MUST be a public key, but carries the private parameter `{param}`"
        )));
    }
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
    /// The Client Attestation JWT's `cnf.jwk` — the key this PoP's signature
    /// was verified against (ABCA draft -07 §5.2 rule 3, GAP-VCI-14).
    ///
    /// Carried out to the caller because the Google Wallet profile's
    /// `encrypted_pre-authorized_code` inner JWS is signed by this same key
    /// ("The JWS must be signed by the cnf.jwk found in the
    /// OAuth-Client-Attestation JWT used for wallet attestation"), and there is
    /// no other route to it. Exposing it asserts nothing new — the signature
    /// check above already proved this key authenticates this client.
    pub cnf_jwk: Jwk,
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
/// docs/superpowers/specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md
/// for the full table this mirrors. `skip_all` is mandatory: the argument is
/// the PoP JWT itself.
///
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
fn validate_client_attestation_pop_jwt(
    pop_jwt: &str,
    attestation: &ValidatedAttestation,
    expected_aud: &str,
    now_unix: i64,
    max_age_secs: u64,
    challenge_mode: Mode,
    nonce_secret: &crate::challenge::NonceSecret,
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

    // Check 3 (ABCA §9 rule 4; HAIP-0088): alg must be ES256. ABCA §9 rule 4
    // only requires "a registered asymmetric digital signature algorithm ...
    // not none"; HAIP-0088 narrows this to ES256 specifically for the PoP JWT.
    //
    // Note on citation form: ABCA §9 and §6.2 are each a single flat numbered
    // list of rules, not subsectioned prose -- so "§9 rule 4" is the rule at
    // list position 4 under the "9. Verification and Processing" heading. There
    // is no §9.4 heading to look up (contrast §10, which genuinely does have
    // §10.1..§10.6 subsections).
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient("client attestation pop: missing alg header".into())
    })?;
    if alg != "ES256" {
        return Err(IssuanceError::InvalidClient(format!(
            "client attestation pop: alg '{alg}' is not permitted, expected ES256"
        )));
    }

    // Check 4 (ABCA §5.2 r3, §6.2 rule 3, §9 rule 7): the signature MUST verify
    // against the public key in the Client Attestation JWT's cnf.jwk claim.
    // §9 rule 6's "cnf is not a private key" precondition is enforced upstream
    // in validate_wallet_attestation_jwt, where the cnf.jwk is first parsed.
    //
    // Via `es256_verifier_from_inline_jwk` because the key is inline: a `kid`
    // on the cnf.jwk must not become a demand for a `kid` on the PoP's own
    // header, which ABCA never asks for. See `crate::jose`.
    let verifier =
        crate::jose::es256_verifier_from_inline_jwk(&attestation.cnf_jwk).map_err(|e| {
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

    // Check 5 (ABCA §5.2 r4, §9 rule 13): iss REQUIRED, non-empty, MUST equal
    // the attestation's sub claim (both represent the client_id).
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

    // Check 6 (ABCA §5.2, §9 rule 10): aud REQUIRED, string or array form, MUST
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

    // Check 8 (ABCA §9 rule 9, §10.6, §12.1): iat REQUIRED, an integer; bounds the
    // sliding replay-detection window both from staleness (max_age_secs) and
    // from the future (POP_CLOCK_SKEW_SECS).
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "client attestation pop: missing or non-integer iat claim".into(),
        )
    })?;
    // All comparisons below use saturating arithmetic. `iat` arrives via
    // `as_i64` straight off the wire, so any i64 -- including the boundaries --
    // is representable, and bare `+`/`-` would either panic (dev profile's
    // `overflow-checks = true`, breaking AGENTS.md §4.1 in a request path) or
    // silently wrap (release profile), in which case *both* freshness bounds
    // stop firing and the ABCA §9 rule 9 / §10.6 window is bypassed rather
    // than merely mis-tuned.
    //
    // In practice josekit's own JWT verification currently rejects a negative
    // `iat` during check 4 above, so `i64::MIN` never reaches here today. That
    // is an incidental property of a third-party library's claim validation,
    // not a guarantee this function is entitled to assume -- so the bound is
    // enforced locally too.
    //
    // `max_age_secs` is a `u64` from config, and `as i64` would be lossy:
    // `u64::MAX as i64` is `-1`, which would make *every* PoP "older than the
    // allowed max age". Clamped to `i64::MAX` instead, so an absurd config
    // value degrades to "effectively no upper bound" rather than to "reject
    // everything" -- the direction that fails loudly at configuration time
    // rather than silently at request time.
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if now_unix.saturating_sub(iat) > max_age {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: iat is older than the allowed max age".into(),
        ));
    }
    if iat > now_unix.saturating_add(POP_CLOCK_SKEW_SECS) {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: iat is too far in the future".into(),
        ));
    }

    // Check 9 (ABCA §5.2): nbf, if present, MUST NOT be beyond the tolerable
    // clock skew. Saturating for the same reason as `iat` above.
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64())
        && nbf > now_unix.saturating_add(POP_CLOCK_SKEW_SECS)
    {
        return Err(IssuanceError::InvalidClient(
            "client attestation pop: not yet valid (nbf beyond tolerable clock skew)".into(),
        ));
    }

    // No `exp` check by design: ABCA removed `exp` from the PoP JWT in draft
    // -06. Freshness is entirely the `iat` sliding window above. §5.2 rule 1:
    // "The JWT MAY contain other claims. All claims that are not understood
    // by implementations MUST be ignored" -- an exp claim, even an expired
    // one, is simply unrecognised and ignored.

    // Check 10 (ABCA §9 rule 8, §5.2, §8): the `challenge` claim.
    //
    // §5.2 makes the claim OPTIONAL at the *format* level. What makes it
    // mandatory is §8: "If the Authorization Server offers a challenge
    // endpoint, the Client MUST retrieve a challenge and MUST use this
    // challenge in the OAuth-Attestation-PoP." `challenge_mode` is exactly that
    // condition -- see the design doc §4.1.
    //
    // §9 rule 9 ("creation time ... as determined by either the iat claim or a
    // server managed timestamp via the challenge claim") is satisfied on both
    // paths at once: Check 8's iat window still applies, and a verified
    // challenge additionally carries a server-minted expiry.
    match (challenge_mode, payload.get("challenge")) {
        // No challenge endpoint is offered, so §9 rule 8's precondition ("If
        // the server provided a challenge value to the client") is false. Per
        // §5.2 rule 1, a claim we did not ask for "MUST be ignored".
        (Mode::Disabled, _) => {}

        // Advertised but not yet mandatory: a wallet mid-migration is accepted.
        (Mode::Optional, None) => {}

        // §6.2: "use_attestation_challenge MUST be used when the Client
        // Attestation PoP JWT is not using an expected server-provided
        // challenge."
        (Mode::Required, None) => {
            tracing::warn!("client attestation pop carried no challenge claim");
            return Err(IssuanceError::UseAttestationChallenge(
                "client attestation pop: a server-provided challenge claim is required".into(),
            ));
        }

        (Mode::Optional | Mode::Required, Some(value)) => {
            // §5.2: the claim "MUST specify a String value", so a non-string is
            // a rejection, not an ignore.
            let challenge = value.as_str().ok_or_else(|| {
                IssuanceError::UseAttestationChallenge(
                    "client attestation pop: challenge claim is not a string".into(),
                )
            })?;
            crate::challenge::verify(
                nonce_secret,
                crate::challenge::Domain::AttestationChallenge,
                challenge,
                now_unix,
            )
            .map_err(|_| {
                // Never echoes the presented value: a challenge is a freshness
                // secret (root `AGENTS.md` §4.5). The distinct failure reasons
                // are collapsed deliberately too -- telling a client which one
                // applied would be an oracle.
                tracing::warn!("client attestation pop carried an unusable challenge");
                IssuanceError::UseAttestationChallenge(
                    "client attestation pop: challenge is malformed, expired, or was not issued by this issuer"
                        .into(),
                )
            })?;
        }
    }

    Ok(PopClaims {
        iss: iss.to_string(),
        jti: jti.to_string(),
        iat,
        cnf_jwk: attestation.cnf_jwk.clone(),
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

    // Saturating, and via `try_from` rather than `as`, for the same two reasons
    // documented at the `iat` bounds check in
    // `validate_client_attestation_pop_jwt`: `claims.iat` originates off the
    // wire, and `max_age_secs as i64` would be a lossy cast of a `u64` config
    // value (`u64::MAX as i64 == -1`). A bare `+` here overflows on a boundary
    // `iat` -- confirmed by `claim_pop_jti_does_not_overflow_on_boundary_iat`,
    // which panicked on this exact line before this change.
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    let expires_at = claims
        .iat
        .saturating_add(max_age)
        .saturating_add(POP_CLOCK_SKEW_SECS);

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
    // GAP-VCI-04 Decision 3: propagate InvalidNonce as-is (keeping the
    // key_attestation: prefix) rather than collapsing it back to InvalidProof --
    // the Key Attestation JWT's nonce is a c_nonce like any other, and a wallet's
    // recovery (fetch a fresh nonce and retry) is identical regardless of which
    // nested JWT carried the invalid value.
    crate::nonce::verify_nonce(nonce_secret, nonce, now_unix).map_err(|e| match e {
        IssuanceError::InvalidNonce(msg) => {
            IssuanceError::InvalidNonce(format!("key_attestation: {msg}"))
        }
        other => other,
    })?;
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
        challenge_mode: Mode,
        nonce_secret: &crate::challenge::NonceSecret,
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
            challenge_mode,
            nonce_secret,
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

    /// ABCA draft -07 §9 rule 6: "The key contained in the cnf claim of the
    /// Client Attestation JWT is not a private key."
    ///
    /// A private key in `cnf` means the Attester leaked the client instance's
    /// signing key into a JWT that travels in a plaintext HTTP header, so
    /// anyone who observes one attestation can mint PoPs for that client
    /// forever. Crucially, this is NOT caught by the signature check further
    /// down: `ES256.verifier_from_jwk` is perfectly happy to build a verifier
    /// from a private JWK (it just reads `x`/`y` and ignores `d`), and the
    /// resulting PoP verification would *succeed*. So without this explicit
    /// check the condition is silently accepted -- which is what makes it worth
    /// a dedicated test rather than relying on a downstream failure.
    #[test]
    fn rejects_a_cnf_jwk_that_carries_a_private_key() {
        let now = now_secs();
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let private_jwk = serde_json::to_value(kp.to_jwk_private_key()).unwrap();

        // Guard the premise: the planted JWK really does carry `d`, so the
        // test would be vacuous if a future refactor changed the helper.
        assert!(
            private_jwk.get("d").is_some(),
            "fixture must actually be a private JWK for this test to mean anything"
        );

        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "ES256",
            "oauth-client-attestation+jwt",
            true,
            Some(now + 100_000),
            None,
            Some(private_jwk.clone()),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let err = validate_wallet_attestation_jwt(&jwt, &store, now)
            .expect_err("a private key in cnf.jwk must be rejected (ABCA §9 rule 6)");
        assert!(
            matches!(err, IssuanceError::InvalidClient(_)),
            "expected InvalidClient, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("public key") && msg.contains('d'),
            "error should name the offending private parameter: {msg}"
        );

        // AGENTS.md §4.5: the error names the parameter but must never carry
        // its value -- that value is private key material.
        let d_value = private_jwk
            .get("d")
            .and_then(|v| v.as_str())
            .expect("fixture has a string d");
        assert!(
            !msg.contains(d_value),
            "the private key scalar must never appear in an error message"
        );
    }

    /// Counterpart to the above, proving the check is not simply "reject any
    /// JWK with more than the bare minimum members": a legitimate public JWK
    /// that happens to carry optional public metadata is still accepted.
    #[test]
    fn accepts_a_cnf_jwk_that_is_a_public_key_with_optional_members() {
        let now = now_secs();
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut jwk = kp.to_jwk_public_key();
        jwk.set_algorithm("ES256");
        jwk.set_key_id("wallet-instance-key-1");
        let public_jwk = serde_json::to_value(&jwk).unwrap();
        assert!(
            public_jwk.get("d").is_none(),
            "a public JWK must not carry d"
        );

        let (jwt, ca_pem) = wallet_attestation_jwt_custom(
            "ES256",
            "oauth-client-attestation+jwt",
            true,
            Some(now + 100_000),
            None,
            Some(public_jwk),
            true,
        );
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        validate_wallet_attestation_jwt(&jwt, &store, now)
            .expect("a public cnf.jwk with kid/alg must be accepted");
    }

    /// The `cnf.jwk` claim can be well-formed JSON and still be unusable as an
    /// ES256 verification key (wrong curve). `validate_wallet_attestation_jwt`
    /// deliberately does *not* reject it here -- it only parses `cnf.jwk`
    /// structurally; the curve mismatch surfaces at check 4 of
    /// `validate_client_attestation_pop_jwt`, where the verifier is built. This
    /// test pins that division of labour so the failure is known to be caught
    /// *somewhere* rather than assumed.
    #[test]
    fn a_wrong_curve_cnf_jwk_is_rejected_when_the_pop_verifier_is_built() {
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

        // The wrong-curve JWK still parses structurally, so the attestation
        // itself validates -- acceptance here is correct, not a bug.
        let validated = validate_wallet_attestation_jwt(&jwt, &store, now)
            .expect("the attestation JWT itself is validly signed and trust-anchored");
        assert!(
            ES256.verifier_from_jwk(&validated.cnf_jwk).is_err(),
            "a P-384 EC key must not be usable as an ES256 verification key"
        );

        // ...and the real production path rejects it: check 4 of
        // validate_client_attestation_pop_jwt fails to build the verifier. This
        // is the assertion that makes the division of labour above safe; without
        // it, "caught downstream" would be an untested claim.
        let err = validate_client_attestation_pop_jwt(
            "a.b.c",
            &validated,
            "https://issuer.example.com",
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .expect_err("a P-384 cnf.jwk cannot verify an ES256 PoP");
        assert!(
            matches!(err, IssuanceError::InvalidClient(_)),
            "expected InvalidClient, got {err:?}"
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
        let (attestation_jwt, pop_jwt, ca_pem, _cnf_jwk) =
            matched_attestation_and_pop_with_jwk(now, aud);
        (attestation_jwt, pop_jwt, ca_pem)
    }

    /// As [`matched_attestation_and_pop`], additionally returning the
    /// attestation's `cnf.jwk` so a caller can assert the verifier carried
    /// exactly that key out rather than a re-derived or empty one.
    fn matched_attestation_and_pop_with_jwk(now: i64, aud: &str) -> (String, String, String, Jwk) {
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
        (attestation_jwt, pop_jwt, ca_pem, cnf_jwk)
    }

    /// The key that verified the PoP must reach the caller: the Google Wallet
    /// profile's `encrypted_pre-authorized_code` inner JWS is signed by this
    /// same key, and there is no other route to it.
    #[test]
    fn verified_pop_claims_carry_the_attestation_cnf_jwk() {
        let now = now_secs();
        let (attestation_jwt, pop_jwt, ca_pem, expected_cnf_jwk) =
            matched_attestation_and_pop_with_jwk(now, MATRIX_AUD);
        let store = TrustStore::from_pems(&[ca_pem.into_bytes()]).unwrap();

        let claims = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                Some(&attestation_jwt),
                Some(&pop_jwt),
                &store,
                MATRIX_AUD,
                now,
                300,
                Mode::Disabled,
                &test_secret(),
            )
            .expect("a matched attestation and pop must verify")
            .expect("Required mode with both headers present must yield claims");

        assert_eq!(claims.cnf_jwk.key_type(), "EC");
        assert_eq!(
            claims.cnf_jwk.parameter("x"),
            expected_cnf_jwk.parameter("x"),
            "cnf_jwk must be the attestation's key, not a re-derived or empty one"
        );
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
                Mode::Disabled,
                &test_secret(),
            )
            .expect("Disabled must skip all validation, even with structurally invalid inputs");
        assert!(result.is_none());
    }

    #[test]
    fn matrix_required_absent_absent_rejects() {
        let now = now_secs();
        let store = TrustStore::from_pems(&[]).unwrap();

        let err = DefaultAttestationVerifier
            .verify_wallet_attestation(
                Mode::Required,
                None,
                None,
                &store,
                MATRIX_AUD,
                now,
                300,
                Mode::Disabled,
                &test_secret(),
            )
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
            .verify_wallet_attestation(
                Mode::Optional,
                None,
                None,
                &store,
                MATRIX_AUD,
                now,
                300,
                Mode::Disabled,
                &test_secret(),
            )
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
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
                Mode::Disabled,
                &test_secret(),
            )
            .expect("both present and matching under Optional must be accepted");
        assert!(result.is_some());
    }

    use super::verify_key_attestation_jwt;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::TrustStore;
    use josekit::jwk::KeyPair as _;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::{HS256, JwsSigner};

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
        // GAP-VCI-04 Decision 3: propagated as InvalidNonce, not collapsed back
        // to InvalidProof, with the key_attestation: prefix preserved.
        match &err {
            IssuanceError::InvalidNonce(msg) => {
                assert!(
                    msg.starts_with("key_attestation:"),
                    "expected the key_attestation: prefix to survive, got: {msg}"
                );
            }
            other => panic!("expected InvalidNonce, got: {other:?}"),
        }
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

    // -- ABCA §8 challenge claim (check 9) --

    fn challenge_secret() -> crate::challenge::NonceSecret {
        crate::challenge::NonceSecret::from_bytes([3u8; 32])
    }

    /// A challenge minted the way `POST /challenge` mints one.
    fn fresh_challenge(now: i64) -> String {
        crate::challenge::mint(
            &challenge_secret(),
            crate::challenge::Domain::AttestationChallenge,
            300,
            now,
        )
        .expect("mint challenge")
    }

    #[test]
    fn disabled_challenge_mode_accepts_a_pop_without_a_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .expect("Disabled mode with no challenge claim must be accepted");
    }

    /// ABCA §5.2 rule 1: a claim we never asked for "MUST be ignored".
    #[test]
    fn disabled_challenge_mode_ignores_a_garbage_challenge_claim() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!("not-a-real-challenge");
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .expect("Disabled mode must ignore any challenge claim, garbage or not");
    }

    #[test]
    fn optional_challenge_mode_accepts_a_pop_without_a_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Optional,
            &challenge_secret(),
        )
        .expect("Optional mode must accept an absent challenge claim");
    }

    #[test]
    fn optional_challenge_mode_verifies_a_present_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!(fresh_challenge(now));
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Optional,
            &challenge_secret(),
        )
        .expect("Optional mode must accept a valid, present challenge");
    }

    #[test]
    fn optional_challenge_mode_rejects_a_bad_present_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!("garbage");
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Optional,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
    }

    #[test]
    fn required_challenge_mode_rejects_a_pop_without_a_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
        assert_eq!(err.kind(), "use_attestation_challenge");
    }

    #[test]
    fn required_challenge_mode_accepts_a_fresh_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!(fresh_challenge(now));
        let jwt = sign_pop(&header, &payload, &signer);

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .expect("Required mode must accept a fresh, valid challenge");
    }

    /// Isolates the *challenge's own* expiry from Check 8's `iat` staleness
    /// window: the challenge is minted well in the past (long expired by
    /// `now`), but `iat` is fresh at `now`, so Check 8 passes and this test
    /// actually exercises Check 10's expiry path rather than tripping Check 8
    /// first.
    #[test]
    fn an_expired_challenge_is_rejected() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let stale_challenge = crate::challenge::mint(
            &challenge_secret(),
            crate::challenge::Domain::AttestationChallenge,
            300,
            now - 1_000,
        )
        .expect("mint stale challenge");
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!(stale_challenge);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
    }

    #[test]
    fn a_challenge_from_another_issuer_is_rejected() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let other_secret = crate::challenge::NonceSecret::from_bytes([4u8; 32]);
        let other_challenge = crate::challenge::mint(
            &other_secret,
            crate::challenge::Domain::AttestationChallenge,
            300,
            now,
        )
        .unwrap();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!(other_challenge);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
    }

    /// The domain-separation guard at this layer: a `c_nonce` is a structurally
    /// valid MAC under the very same process secret, and must still be refused
    /// here. Without `challenge.rs`'s domain label this test would fail.
    #[test]
    fn a_c_nonce_is_not_accepted_as_an_attestation_challenge() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let c_nonce = crate::challenge::mint(
            &challenge_secret(),
            crate::challenge::Domain::CNonce,
            300,
            now,
        )
        .expect("mint c_nonce");
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!(c_nonce);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
    }

    /// ABCA §5.2: the claim "MUST specify a String value".
    #[test]
    fn a_non_string_challenge_claim_is_rejected() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        payload["challenge"] = serde_json::json!(12345);
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::UseAttestationChallenge(_)));
    }

    /// Check 8 (`iat`) must run before Check 9: a stale PoP is reported as
    /// stale, not as a challenge problem.
    #[test]
    fn a_stale_iat_is_reported_as_stale_not_as_a_challenge_problem() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let mut payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD),
            "jti-1",
            now - 10_000,
        );
        payload["challenge"] = serde_json::json!(fresh_challenge(now));
        let jwt = sign_pop(&header, &payload, &signer);

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Required,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(
            !matches!(err, IssuanceError::UseAttestationChallenge(_)),
            "a stale iat must be reported as stale (Check 8), not as a challenge problem: {err:?}"
        );
    }

    #[test]
    fn accepts_a_valid_pop_jwt_and_returns_its_claims() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(POP_TEST_SUB, serde_json::json!(POP_TEST_AUD), "jti-1", now);
        let jwt = sign_pop(&header, &payload, &signer);

        let claims = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .expect("a valid PoP must be accepted");
        assert_eq!(claims.iss, POP_TEST_SUB);
        assert_eq!(claims.jti, "jti-1");
        assert_eq!(claims.iat, now);
    }

    #[test]
    fn accepts_a_pop_whose_attestation_cnf_jwk_carries_its_own_kid() {
        // Regression (same defect class as `dpop.rs` and `proof.rs`): a Client
        // Attestation's `cnf.jwk` is an RFC 7517 JWK, so it may carry a `kid`
        // labelling the wallet instance key. ABCA §5.2 r3 / §9 rule 7 require
        // only that the PoP verify against that key -- nothing requires the
        // PoP's own JWS header to repeat the label. josekit's
        // `verifier_from_jwk` copies the cnf.jwk's `kid` into the verifier,
        // which then rejected such a PoP with "The JWS kid header claim is
        // required".
        let (mut attestation, signer) = pop_attestation_and_signer();
        attestation.cnf_jwk.set_key_id("wallet-instance-key-1");

        let now = now_secs();
        // `pop_header` builds the header by hand and never emits a kid.
        let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
        let payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD),
            "jti-kid",
            now,
        );
        let jwt = sign_pop(&header, &payload, &signer);

        let claims = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .expect("a kid on the attestation's cnf.jwk must not require a kid on the PoP header");
        assert_eq!(claims.jti, "jti-kid");
    }

    #[test]
    fn rejects_pop_that_is_not_three_dot_separated_parts() {
        let (attestation, _signer) = pop_attestation_and_signer();
        let now = now_secs();
        let err = validate_client_attestation_pop_jwt(
            "only.two",
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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
            Mode::Disabled,
            &challenge_secret(),
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
            Mode::Disabled,
            &challenge_secret(),
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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
        let err = validate_client_attestation_pop_jwt(
            &prefix_jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));

        let upper_payload = pop_payload(
            POP_TEST_SUB,
            serde_json::json!(POP_TEST_AUD.to_uppercase()),
            "jti-2",
            now,
        );
        let upper_jwt = sign_pop(&header, &upper_payload, &signer);
        let err = validate_client_attestation_pop_jwt(
            &upper_jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
        .unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// `iat` is read with `as_i64` straight off the wire, so every i64 --
    /// including both boundaries -- is representable in the payload. Both must
    /// be rejected, and rejected *without arithmetic overflow*.
    ///
    /// Honest accounting of what each case actually exercises, established by
    /// instrumenting this test rather than by reasoning about it:
    ///
    /// - **`i64::MAX`** genuinely reaches check 8 and is rejected there by the
    ///   "too far in the future" branch. This is the case that exercises our
    ///   own arithmetic.
    /// - **`i64::MIN`** never reaches check 8: josekit's JWT verification inside
    ///   check 4 rejects it first ("the JWT iat payload claim must be a 64bit
    ///   positive integer"). So the `now_unix - iat` overflow a bare `-` would
    ///   suffer here is, today, unreachable through this function.
    ///
    /// The arithmetic is saturating anyway, and the `i64::MIN` case is still
    /// pinned, because that guard is an *incidental* property of a third-party
    /// library's claim validation -- not part of josekit's documented contract,
    /// and not something a security bound should rest on. If josekit ever
    /// relaxes it, a bare `-` would panic in a request path (AGENTS.md §4.1)
    /// under the dev profile's `overflow-checks = true`, or silently wrap under
    /// release's `overflow-checks = false` -- and on wrap *both* freshness
    /// bounds stop firing, bypassing the ABCA §9 rule 9 / §10.6 window rather
    /// than merely mis-tuning it. This test is the tripwire for that regression.
    ///
    /// Note this is wallet-controlled, not anonymous, input: check 4's signature
    /// verification runs first, so a caller needs the attested private key to
    /// get here at all. That bounds the blast radius; it does not excuse it.
    #[test]
    fn rejects_pop_with_iat_at_the_i64_boundaries_without_overflowing() {
        let (attestation, signer) = pop_attestation_and_signer();
        let now = now_secs();

        for (label, iat) in [("i64::MIN", i64::MIN), ("i64::MAX", i64::MAX)] {
            let header = pop_header("ES256", "oauth-client-attestation-pop+jwt");
            let payload = pop_payload(
                POP_TEST_SUB,
                serde_json::json!(POP_TEST_AUD),
                "jti-i64-boundary",
                iat,
            );
            let jwt = sign_pop(&header, &payload, &signer);

            let err = validate_client_attestation_pop_jwt(
                &jwt,
                &attestation,
                POP_TEST_AUD,
                now,
                300,
                Mode::Disabled,
                &challenge_secret(),
            )
            .expect_err("a boundary iat must be rejected, not accepted or panicked on");
            assert!(
                matches!(err, IssuanceError::InvalidClient(_)),
                "iat = {label}: expected InvalidClient, got {err:?}"
            );
        }
    }

    /// Companion to the above for `claim_pop_jti`'s own `iat + max_age + skew`:
    /// even a `PopClaims` carrying a boundary `iat` (however it was obtained)
    /// must not overflow when the replay TTL is computed.
    #[tokio::test]
    async fn claim_pop_jti_does_not_overflow_on_boundary_iat() {
        for iat in [i64::MIN, i64::MAX] {
            let storage = test_storage().await;
            let claims = pop_claims("https://wallet.example.com", "jti-boundary", iat);
            // Must return a Result, not panic. Either verdict is acceptable;
            // the point is that the TTL arithmetic is saturating.
            let _ = claim_pop_jti(&storage, &claims, u64::MAX).await;
        }
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

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        let err = validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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

        validate_client_attestation_pop_jwt(
            &jwt,
            &attestation,
            POP_TEST_AUD,
            now,
            300,
            Mode::Disabled,
            &challenge_secret(),
        )
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
            // `claim_pop_jti` keys on (iss, jti) only and never reads this, so
            // any well-formed P-256 public JWK serves.
            cnf_jwk: EcKeyPair::generate(EcCurve::P256)
                .unwrap()
                .to_jwk_public_key(),
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
