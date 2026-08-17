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
use josekit::jwk::Jwk;
use josekit::jws::ES256;

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
    let verifier = ES256.verifier_from_jwk(cnf_jwk).map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwe::JweHeader;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::JwsSigner;

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
}
