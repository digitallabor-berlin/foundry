//! Google Wallet's `encrypted_pre-authorized_code` Token Request extension:
//! the pre-authorized code delivered as a JWS nested inside a JWE.
//!
//! **Vendor profile, not a specification** (root `AGENTS.md` §4.4). Its only
//! source is the Google Wallet VCI 1.0 Profile, §"token request field signing
//! & encryption", whose stated motivation is that the wallet *server* relaying
//! the Token Request must be unable to read or forge the code. No
//! standards-track document defines this parameter. Design:
//! `docs/superpowers/specs/2026-08-17-encrypted-pre-authorized-code-design.md`.
//!
//! Two independent keys meet here, and conflating them is the mistake this
//! module exists to prevent:
//!
//! * the **outer JWE** is opened with the issuer's own
//!   `credential_request_encryption` private keys — the same keys that already
//!   decrypt a Credential Request, per the profile's explicit instruction;
//! * the **inner JWS** is verified against the *client's* `cnf.jwk`, carried
//!   out of the verified Client Attestation JWT on `PopClaims`.
//!
//! Nothing here may be logged: root `AGENTS.md` §4.5 covers the envelope, the
//! decrypted JWS, the extracted code and the `jti`.

use crate::error::IssuanceError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry_core::crypto::jwe::{DecryptionKey, decrypt_compact_to_bytes};
use foundry_core::storage::Storage;
use josekit::jwk::Jwk;
use sha2::{Digest, Sha256};

/// The clock-skew tolerance for the inner JWS's `iat`. The same value and the
/// same reasoning as `attestation.rs`'s `POP_CLOCK_SKEW_SECS` (ABCA §12.1:
/// "clock skews between servers and clients may be large"). Never used to
/// widen how far into the *past* an `iat` may be — that is `max_age_secs`.
const ENVELOPE_CLOCK_SKEW_SECS: i64 = 60;

/// KV storage namespace for `encrypted_pre-authorized_code` `jti` replay
/// claims.
///
/// Deliberately **not** shared with `attestation.rs`'s
/// `client_attestation_pop_jti`: a shared namespace would let a PoP `jti` and
/// an envelope `jti` of the same value collide, so one artifact could deny
/// service to the other.
pub(crate) const ENVELOPE_JTI_NAMESPACE: &str = "encrypted_pre_auth_code_jti";

/// The claims recovered from a verified `encrypted_pre-authorized_code`
/// envelope.
#[derive(Debug, Clone)]
pub struct EncryptedCodeClaims {
    pub iss: String,
    pub jti: String,
    pub iat: i64,
    pub pre_authorized_code: String,
}

/// Decrypt the outer JWE and verify the inner JWS, returning its payload.
///
/// Implements steps 3-6 of the profile's validation algorithm. Claim
/// validation is [`validate_claims`]; this function proves only that the bytes
/// came from the attested client and were addressed to this issuer.
///
/// `skip_all` is mandatory and total: `envelope` is the JWE, `decryption_keys`
/// are private keys, and the return value carries the pre-authorized code.
#[tracing::instrument(skip_all)]
pub fn open_envelope(
    envelope: &str,
    decryption_keys: &[DecryptionKey],
    allowed_enc: &[String],
    cnf_jwk: &Jwk,
) -> Result<serde_json::Value, IssuanceError> {
    // Checks 1-4. The three header checks (alg == ECDH-ES, enc advertised, kid
    // present and known) live in `decrypt_compact_to_bytes` and carry their
    // OpenID4VCI citations there: L1188, VCI-0100/0101, VCI-0135.
    //
    // `InvalidRequest`, not `InvalidClient`: nothing has been authenticated
    // yet, so a failure here is a malformed parameter value (RFC 6749 §5.2).
    // The message names only the structural defect -- `CryptoError`'s Display
    // never echoes ciphertext or key material.
    let plaintext =
        decrypt_compact_to_bytes(envelope, decryption_keys, allowed_enc).map_err(|e| {
            IssuanceError::InvalidRequest(format!(
                "encrypted_pre-authorized_code decryption failed: {e}"
            ))
        })?;

    let jws = std::str::from_utf8(&plaintext).map_err(|_| {
        IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code: the decrypted payload is not UTF-8".into(),
        )
    })?;

    // Check 5: the payload must be a compact JWS. A bare JSON object here
    // would mean an unsigned code, which defeats the extension's purpose --
    // so this is a rejection, never a fallback.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidRequest(
            "encrypted_pre-authorized_code: the decrypted payload is not a compact JWS \
             (expected 3 dot-separated parts)"
                .into(),
        ));
    }

    // Check 6 (HAIP-0088, narrowing the profile): ES256 only -- the same policy
    // `dpop.rs` and `attestation.rs` already apply to every other client-signed
    // artifact in this crate.
    //
    // From here on failures are `InvalidClient`: past decryption the artifact
    // is signed by the client instance key and asserts client identity, so a
    // failure is a failed client-authentication mechanism.
    let header_bytes = B64URL.decode(parts[0]).map_err(|_| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS header is not valid base64url".into(),
        )
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS header is not JSON".into(),
        )
    })?;
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS header has no string alg".into(),
        )
    })?;
    if alg != "ES256" {
        return Err(IssuanceError::InvalidClient(format!(
            "encrypted_pre-authorized_code: inner JWS alg '{alg}' is not permitted, \
             expected ES256"
        )));
    }

    // Check 7: the signature MUST verify against the Client Attestation's
    // cnf.jwk -- "The JWS must be signed by the cnf.jwk found in the
    // OAuth-Client-Attestation JWT used for wallet attestation."
    //
    // Via `es256_verifier_from_inline_jwk` because the key is inline: a `kid`
    // on the cnf.jwk must not become a demand for a `kid` on the inner JWS
    // header, which the profile does not emit. See `crate::jose`.
    let verifier = crate::jose::es256_verifier_from_inline_jwk(cnf_jwk).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "encrypted_pre-authorized_code: cannot build a verifier from the attestation's \
             cnf.jwk: {e}"
        ))
    })?;
    let (payload, _header) = josekit::jwt::decode_with_verifier(jws, &verifier).map_err(|_| {
        // Deliberately does not distinguish "bad signature" from "malformed
        // payload": telling a client which applied would be an oracle.
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: inner JWS signature did not verify against the \
             wallet attestation's cnf.jwk"
                .into(),
        )
    })?;

    serde_json::to_value(payload.claims_set()).map_err(|e| {
        IssuanceError::InvalidClient(format!(
            "encrypted_pre-authorized_code: inner JWS claims are not JSON: {e}"
        ))
    })
}

/// Validate the inner JWS payload (checks 8-13 and 15).
///
/// `attestation_iss` is `PopClaims.iss` — the `sub` of the Client Attestation
/// that authenticated this request, which `validate_client_attestation_pop_jwt`
/// already proved equal to the PoP's `iss`.
///
/// `expected_aud` is the **Token Endpoint URL**, not the Authorization Server's
/// issuer identifier. The profile's worked example is explicit
/// (`"aud": "https://authorization-server.example.com/token" // Token endpoint`)
/// and this deliberately differs from the Client Attestation PoP's `aud`, which
/// ABCA §9 rule 10 binds to the issuer identifier.
///
/// `skip_all` is mandatory: `payload` carries the pre-authorized code.
#[tracing::instrument(skip_all)]
pub fn validate_claims(
    payload: &serde_json::Value,
    attestation_iss: &str,
    expected_aud: &str,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<EncryptedCodeClaims, IssuanceError> {
    let str_claim = |name: &str| -> Result<String, IssuanceError> {
        payload
            .get(name)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                IssuanceError::InvalidClient(format!(
                    "encrypted_pre-authorized_code: missing or empty {name} claim"
                ))
            })
    };

    // Check 8: iss == sub. Both are the client_id.
    let iss = str_claim("iss")?;
    let sub = str_claim("sub")?;
    if iss != sub {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iss and sub disagree; both must be the client_id"
                .into(),
        ));
    }

    // Check 9: the envelope must name the client the attestation authenticated.
    // Without this, any wallet holding any valid client attestation could
    // submit an envelope claiming to be a different client -- the check that
    // makes the signature mean something. Profile, inline in its example:
    // "The client ID, must match the 'sub' in the attestation".
    if iss != attestation_iss {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iss does not match the wallet attestation's sub".into(),
        ));
    }

    // Check 10: aud is the Token Endpoint URL. Exact match, no normalization --
    // a prefix or case-insensitive match would weaken the binding, the same
    // posture `attestation.rs` takes for the PoP's aud.
    let aud = payload.get("aud").ok_or_else(|| {
        IssuanceError::InvalidClient("encrypted_pre-authorized_code: missing aud claim".into())
    })?;
    let aud_matches = match aud {
        serde_json::Value::String(s) => s == expected_aud,
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
        _ => false,
    };
    if !aud_matches {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: aud does not match this Token Endpoint".into(),
        ));
    }

    // Check 11.
    let jti = str_claim("jti")?;

    // Check 12: iat within the issuer's own window. Saturating arithmetic and
    // `try_from` for the same two reasons documented in `attestation.rs`:
    // `iat` originates off the wire, and `max_age_secs as i64` would be a lossy
    // cast of a u64 config value (`u64::MAX as i64 == -1`).
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: missing or non-integer iat claim".into(),
        )
    })?;
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if iat.saturating_add(max_age) < now_unix {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iat is too far in the past".into(),
        ));
    }
    if iat.saturating_sub(ENVELOPE_CLOCK_SKEW_SECS) > now_unix {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: iat is in the future beyond the tolerable skew".into(),
        ));
    }

    // Check 13. `exp` bounds the client's own intent; check 12 bounds the
    // issuer's. Both apply -- a client may set an arbitrarily distant `exp`.
    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: missing or non-integer exp claim".into(),
        )
    })?;
    if now_unix > exp {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: has expired".into(),
        ));
    }

    // Check 15.
    let pre_authorized_code = str_claim("pre-authorized_code")?;

    Ok(EncryptedCodeClaims {
        iss,
        jti,
        iat,
        pre_authorized_code,
    })
}

/// Check 14: claim this envelope's `jti` exactly once (atomic).
///
/// Mirrors `attestation.rs`'s `claim_pop_jti` deliberately — same `(iss, jti)`
/// keying so one client cannot pre-claim another's values, same hashed key so
/// the raw `jti` never appears in storage, same `iat`-relative `expires_at` so
/// the row expires with the artifact rather than with the request — but over
/// its own namespace and its own claims type.
///
/// `skip_all` is mandatory: `claims` carries the pre-authorized code.
#[tracing::instrument(skip_all)]
pub(crate) async fn claim_envelope_jti(
    storage: &dyn Storage,
    claims: &EncryptedCodeClaims,
    max_age_secs: u64,
) -> Result<(), IssuanceError> {
    let mut hasher = Sha256::new();
    hasher.update(claims.iss.as_bytes());
    hasher.update([0u8]);
    hasher.update(claims.jti.as_bytes());
    let key = B64URL.encode(hasher.finalize());

    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    let expires_at = claims
        .iat
        .saturating_add(max_age)
        .saturating_add(ENVELOPE_CLOCK_SKEW_SECS);

    let claimed = storage
        .insert_kv_if_absent(ENVELOPE_JTI_NAMESPACE, &key, "1", Some(expires_at))
        .await?;
    if !claimed {
        return Err(IssuanceError::InvalidClient(
            "encrypted_pre-authorized_code: jti has already been used".into(),
        ));
    }
    Ok(())
}

/// The module's single entry point: envelope in, pre-authorized code out.
///
/// Runs the profile's steps 3-7 plus the claim validation its numbered
/// algorithm omits, then claims the `jti`. The caller receives a plain
/// `String` and never learns encryption was involved.
///
/// `skip_all` is mandatory and total.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub async fn resolve_encrypted_pre_authorized_code(
    storage: &dyn Storage,
    envelope: &str,
    decryption_keys: &[DecryptionKey],
    allowed_enc: &[String],
    cnf_jwk: &Jwk,
    attestation_iss: &str,
    token_endpoint: &str,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<String, IssuanceError> {
    let payload = open_envelope(envelope, decryption_keys, allowed_enc, cnf_jwk)?;
    let claims = validate_claims(
        &payload,
        attestation_iss,
        token_endpoint,
        now_unix,
        max_age_secs,
    )?;
    claim_envelope_jti(storage, &claims, max_age_secs).await?;

    // No field carries a secret: this records only that the step succeeded.
    tracing::info!("encrypted_pre-authorized_code accepted");
    Ok(claims.pre_authorized_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwe::JweHeader;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::{ES256, JwsSigner};

    fn recipient_key() -> DecryptionKey {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        DecryptionKey::from_pem(&kp.to_pem_private_key()).unwrap()
    }

    fn both_gcm() -> Vec<String> {
        vec!["A128GCM".to_string(), "A256GCM".to_string()]
    }

    pub(super) fn sample_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "GoogleWallet",
            "sub": "GoogleWallet",
            "aud": "https://issuer.example.com/token",
            "jti": "envelope-jti-1",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300,
            "pre-authorized_code": "code-123",
        })
    }

    /// Build a real envelope: ES256-sign `claims` with `signer_kp`, then
    /// ECDH-ES-encrypt the resulting compact JWS to `recipient`.
    ///
    /// The compact JWS is assembled by hand rather than via
    /// `josekit::jwt::encode_with_signer`, which overwrites the header's `alg`
    /// with the *signer's* algorithm name. That would make `alg_override`
    /// silently ineffective and the ES256-policy test vacuous -- it would be
    /// asserting against a header that still said `ES256`.
    fn build_envelope(
        claims: &serde_json::Value,
        signer_kp: &EcKeyPair,
        recipient: &DecryptionKey,
        enc: &str,
        alg_override: Option<&str>,
    ) -> String {
        let header = serde_json::json!({
            "alg": alg_override.unwrap_or("ES256"),
            "typ": "JWT",
        });
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(serde_json::to_vec(&header).unwrap()),
            B64URL.encode(serde_json::to_vec(claims).unwrap()),
        );
        let signer = ES256
            .signer_from_jwk(&signer_kp.to_jwk_private_key())
            .unwrap();
        let signature = signer.sign(signing_input.as_bytes()).unwrap();
        let jws = format!("{signing_input}.{}", B64URL.encode(signature));

        wrap_in_jwe(jws.as_bytes(), recipient, enc)
    }

    fn wrap_in_jwe(plaintext: &[u8], recipient: &DecryptionKey, enc: &str) -> String {
        let pub_jwk =
            Jwk::from_bytes(serde_json::to_vec(&recipient.published_jwk()).unwrap()).unwrap();
        let encrypter = josekit::jwe::ECDH_ES.encrypter_from_jwk(&pub_jwk).unwrap();

        let mut header = JweHeader::new();
        header.set_algorithm("ECDH-ES");
        header.set_content_encryption(enc);
        header.set_key_id(recipient.kid());

        josekit::jwe::serialize_compact(plaintext, &header, &encrypter).unwrap()
    }

    /// THE POSITIVE CONTROL. Without it every negative test below could pass
    /// against a function that rejects everything.
    #[test]
    fn a_valid_envelope_opens_to_its_claims() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &signer_kp, &recipient, "A128GCM", None);

        let payload = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect("a correctly signed and encrypted envelope must open");

        assert_eq!(payload["pre-authorized_code"], "code-123");
        assert_eq!(payload["iss"], "GoogleWallet");
    }

    /// Regression (same defect class as `dpop.rs`, `proof.rs`, `attestation.rs`):
    /// the `cnf.jwk` carried out of the Client Attestation may label itself
    /// with a `kid`. The inner JWS is verified against that key directly, so
    /// nothing requires the JWS header to repeat the label -- and Google's
    /// profile does not put one there. josekit's `verifier_from_jwk` copies
    /// the JWK's `kid` into the verifier, which then rejected the envelope
    /// with "The JWS kid header claim is required".
    #[test]
    fn opens_an_envelope_whose_cnf_jwk_carries_its_own_kid() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        // `build_envelope` assembles the inner JWS header by hand: `alg` and
        // `typ` only, never a kid.
        let envelope = build_envelope(&sample_claims(), &signer_kp, &recipient, "A128GCM", None);

        let mut cnf_jwk = signer_kp.to_jwk_public_key();
        cnf_jwk.set_key_id("wallet-instance-key-1");

        let payload = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &cnf_jwk,
        )
        .expect("a kid on the cnf.jwk must not require a kid on the inner JWS header");

        assert_eq!(payload["pre-authorized_code"], "code-123");
    }

    /// Check 2 (VCI-0135): `enc` must be advertised.
    #[test]
    fn rejects_an_enc_the_issuer_does_not_advertise() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &signer_kp, &recipient, "A256GCM", None);

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &["A128GCM".to_string()],
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("an unadvertised enc must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 3 (L1188 / VCI-0101): the `kid` must match a configured key.
    #[test]
    fn rejects_an_envelope_encrypted_to_an_unknown_key() {
        let ours = recipient_key();
        let theirs = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &signer_kp, &theirs, "A128GCM", None);

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&ours),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("an envelope for another issuer's key must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 4: undecryptable ciphertext.
    #[test]
    fn rejects_a_structurally_broken_envelope() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();

        let err = open_envelope(
            "not.a.valid.jwe.at-all",
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("a malformed envelope must be rejected");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 5: the plaintext must be a compact JWS. A bare JSON object would
    /// mean an UNSIGNED code, which defeats the extension's whole purpose.
    #[test]
    fn rejects_a_plaintext_that_is_not_a_compact_jws() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = wrap_in_jwe(br#"{"pre-authorized_code":"naked"}"#, &recipient, "A128GCM");

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("a bare JSON plaintext must be rejected: the code must be SIGNED");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// Check 6 (HAIP-0088): ES256 only. Signed with a genuine ES256 key but
    /// declaring another alg, so the rejection is the alg policy and not a
    /// signature failure.
    #[test]
    fn rejects_an_inner_jws_that_does_not_declare_es256() {
        let recipient = recipient_key();
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(
            &sample_claims(),
            &signer_kp,
            &recipient,
            "A128GCM",
            Some("ES384"),
        );

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &signer_kp.to_jwk_public_key(),
        )
        .expect_err("only ES256 is permitted (HAIP-0088)");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 7 -- THE FORGERY TEST. A well-formed envelope signed by a key the
    /// attestation never vouched for.
    #[test]
    fn rejects_an_inner_jws_signed_by_a_key_the_attestation_did_not_vouch_for() {
        let recipient = recipient_key();
        let attested_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let attacker_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let envelope = build_envelope(&sample_claims(), &attacker_kp, &recipient, "A128GCM", None);

        let err = open_envelope(
            &envelope,
            std::slice::from_ref(&recipient),
            &both_gcm(),
            &attested_kp.to_jwk_public_key(),
        )
        .expect_err("a signature from an unattested key must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    // ---- claim validation (checks 8-13, 15) ----

    const NOW: i64 = 1_700_000_000;
    const AUD: &str = "https://issuer.example.com/token";

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

    /// Positive control for the claims half.
    #[test]
    fn valid_claims_yield_the_pre_authorized_code() {
        let claims = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW, 300)
            .expect("a well-formed claim set must validate");

        assert_eq!(claims.pre_authorized_code, "code-123");
        assert_eq!(claims.iss, "GoogleWallet");
        assert_eq!(claims.jti, "envelope-jti-1");
        assert_eq!(claims.iat, NOW);
    }

    /// Check 8: iss must equal sub.
    #[test]
    fn rejects_claims_whose_iss_and_sub_disagree() {
        let mut c = sample_claims();
        c["sub"] = serde_json::json!("SomeoneElse");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 9 -- THE IMPERSONATION TEST. A perfectly signed envelope whose
    /// `iss` names a different client than the attestation that authenticated
    /// this request must be rejected. Without this check, any wallet holding
    /// any valid client attestation could redeem another client's code.
    #[test]
    fn rejects_claims_naming_a_different_client_than_the_attestation() {
        let err = validate_claims(&sample_claims(), "SomeOtherWallet", AUD, NOW, 300)
            .expect_err("the envelope's iss must match the attestation's sub");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 10: aud is the TOKEN ENDPOINT URL, deliberately not the issuer
    /// identifier the Client Attestation PoP uses (ABCA §9 rule 10). Two
    /// artifacts, two audiences; conflating them breaks the profile as written.
    #[test]
    fn rejects_claims_addressed_to_another_audience() {
        let err = validate_claims(
            &sample_claims(),
            "GoogleWallet",
            "https://issuer.example.com",
            NOW,
            300,
        )
        .expect_err("the issuer identifier is not the token endpoint URL");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 11.
    #[test]
    fn rejects_claims_without_a_jti() {
        let mut c = sample_claims();
        c.as_object_mut().unwrap().remove("jti");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 12: iat outside the issuer's own sliding window. `exp` alone is
    /// not enough -- a client can set an arbitrarily distant one -- so the
    /// issuer keeps its own bound, exactly as `pop_max_age_secs` does.
    #[test]
    fn rejects_claims_whose_iat_is_older_than_max_age() {
        let err = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW + 301, 300)
            .expect_err("an iat beyond max_age_secs must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn accepts_claims_whose_iat_is_slightly_in_the_future_within_skew() {
        validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW - 30, 300)
            .expect("clock skew of 30s must be tolerated");
    }

    #[test]
    fn rejects_claims_whose_iat_is_far_in_the_future() {
        let err = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW - 600, 300)
            .expect_err("an iat far beyond the skew allowance must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 13. `exp` is 1_700_000_300, so a large max_age isolates the
    /// rejection to `exp` rather than to check 12.
    #[test]
    fn rejects_expired_claims() {
        validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW + 299, 3600)
            .expect("one second before exp must still be accepted");

        let err = validate_claims(&sample_claims(), "GoogleWallet", AUD, NOW + 301, 3600)
            .expect_err("a claim set past its exp must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Check 15.
    #[test]
    fn rejects_claims_without_a_pre_authorized_code() {
        let mut c = sample_claims();
        c.as_object_mut().unwrap().remove("pre-authorized_code");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    #[test]
    fn rejects_claims_whose_pre_authorized_code_is_empty() {
        let mut c = sample_claims();
        c["pre-authorized_code"] = serde_json::json!("");
        let err = validate_claims(&c, "GoogleWallet", AUD, NOW, 300).unwrap_err();
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    // ---- check 14: replay ----

    fn envelope_claims(iss: &str, jti: &str) -> EncryptedCodeClaims {
        EncryptedCodeClaims {
            iss: iss.to_string(),
            jti: jti.to_string(),
            iat: NOW,
            pre_authorized_code: "code-123".to_string(),
        }
    }

    #[tokio::test]
    async fn the_first_claim_of_an_envelope_jti_succeeds() {
        let storage = test_storage().await;
        claim_envelope_jti(&storage, &envelope_claims("GoogleWallet", "jti-1"), 300)
            .await
            .expect("the first use of a jti must succeed");
    }

    #[tokio::test]
    async fn a_replayed_envelope_jti_is_rejected() {
        let storage = test_storage().await;
        let claims = envelope_claims("GoogleWallet", "jti-1");
        claim_envelope_jti(&storage, &claims, 300).await.unwrap();

        let err = claim_envelope_jti(&storage, &claims, 300)
            .await
            .expect_err("a replayed envelope must be rejected");
        assert!(matches!(err, IssuanceError::InvalidClient(_)));
    }

    /// Namespace separation: a Client Attestation PoP `jti` and an envelope
    /// `jti` sharing a value must not collide. A shared namespace would let one
    /// artifact deny service to the other.
    #[tokio::test]
    async fn an_envelope_jti_does_not_collide_with_a_pop_jti_of_the_same_value() {
        let storage = test_storage().await;
        let shared = "jti-shared";

        crate::attestation::claim_pop_jti(
            &storage,
            &crate::attestation::PopClaims {
                iss: "GoogleWallet".to_string(),
                jti: shared.to_string(),
                iat: NOW,
                cnf_jwk: EcKeyPair::generate(EcCurve::P256)
                    .unwrap()
                    .to_jwk_public_key(),
            },
            300,
        )
        .await
        .unwrap();

        claim_envelope_jti(&storage, &envelope_claims("GoogleWallet", shared), 300)
            .await
            .expect("the two artifacts must use separate jti namespaces");
    }

    /// The raw jti must never be usable verbatim as a storage key -- the same
    /// anti-leak property `claim_pop_jti` is tested for.
    #[tokio::test]
    async fn the_raw_envelope_jti_is_not_the_storage_key() {
        use foundry_core::storage::Storage as _;
        let storage = test_storage().await;
        let claims = envelope_claims("GoogleWallet", "a-very-identifiable-jti");
        claim_envelope_jti(&storage, &claims, 300).await.unwrap();

        assert_eq!(
            storage
                .get_kv(ENVELOPE_JTI_NAMESPACE, &claims.jti)
                .await
                .unwrap(),
            None
        );
    }

    /// Same saturating-arithmetic guard `claim_pop_jti` carries: a boundary
    /// `iat` must return a `Result`, not overflow.
    #[tokio::test]
    async fn claim_envelope_jti_does_not_overflow_on_boundary_iat() {
        for iat in [i64::MIN, i64::MAX] {
            let storage = test_storage().await;
            let mut claims = envelope_claims("GoogleWallet", "jti-boundary");
            claims.iat = iat;
            let _ = claim_envelope_jti(&storage, &claims, u64::MAX).await;
        }
    }
}
