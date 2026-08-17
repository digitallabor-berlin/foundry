//! Shared JOSE helper for verifying a JWS against a key the message itself
//! carries — an *inline* key.
//!
//! # Why this exists
//!
//! Several OpenID4VCI/ABCA/DPoP messages are signed by a key that travels with
//! the message rather than being looked up out of band:
//!
//! | Caller | Where the key comes from |
//! | --- | --- |
//! | [`crate::proof`] | the proof JWT's own `jwk` header, or a key resolved from `key_attestation` |
//! | [`crate::dpop`] | the DPoP proof's `jwk` header (RFC 9449 §4.2) |
//! | [`crate::attestation`] | the Client Attestation's `cnf.jwk` (ABCA §5.2 r3) |
//! | [`crate::encrypted_pre_auth`] | that same `cnf.jwk`, for the inner JWS |
//!
//! In every one of those cases the key is unambiguous before verification
//! starts, so no specification requires the JWS header to carry a `kid`.
//!
//! josekit disagrees. `EcdsaJwsAlgorithm::verifier_from_jwk` copies the JWK's
//! own `kid` member into the verifier's `key_id`
//! (`josekit-0.10.3/src/jws/alg/ecdsa.rs:246`), and `decode_with_verifier`
//! then requires the JWS header to carry a matching `kid`
//! (`josekit-0.10.3/src/jws/jws_context.rs:439-445`):
//!
//! ```text
//! match verifier.key_id() {
//!     Some(expected) => match header.key_id() {
//!         Some(actual) if expected == actual => {}
//!         Some(actual) => bail!("The JWS kid header claim is mismatched: {}", actual),
//!         None => bail!("The JWS kid header claim is required."),
//!     },
//!     None => {}
//! }
//! ```
//!
//! A `kid` is an optional member of *any* JWK (RFC 7517 §4.5), so a wallet may
//! perfectly legitimately label the key it embedded. Google Wallet does. The
//! result was that a conformant DPoP proof was rejected with
//! `"Invalid JWS format: The JWS kid header claim is required"` — a `kid` no
//! specification asked for.
//!
//! # Why dropping the `kid` is safe
//!
//! The verifier is built from *the exact key the message supplied*, and the
//! signature is checked against that key. A `kid` is a label for selecting
//! among several candidate keys; when there is exactly one candidate and it
//! arrived inline, the label decides nothing. Dropping it therefore weakens no
//! check — it removes a comparison whose only possible outcomes were "agrees
//! with the key we already committed to" or "spurious rejection". The
//! signature check itself is untouched.
//!
//! This does **not** apply to keys selected *by* `kid` from a set (a JWKS, or
//! the issuer's own configured recipients). Those look the key up by its label
//! first, so the label is load-bearing and must not be discarded. This helper
//! is deliberately named for the inline case and must not be used for them.
//!
//! # History
//!
//! Found and fixed once for [`crate::proof`] alone, then rediscovered in
//! production against Google Wallet's `/token` DPoP proof. Centralised here so
//! the next inline-key call site inherits the fix instead of the bug. Each of
//! the four callers carries its own regression test.

use josekit::jwk::Jwk;
use josekit::jws::alg::ecdsa::EcdsaJwsVerifier;
use josekit::jws::ES256;
use josekit::JoseError;

/// Build an ES256 verifier for a public key that arrived **inline** with the
/// message it verifies, ignoring any `kid` the JWK carries.
///
/// Use for a key embedded in the message (a `jwk` header, a `cnf.jwk`). Do not
/// use for a key selected out of a set by its `kid` — see the module docs.
pub(crate) fn es256_verifier_from_inline_jwk(jwk: &Jwk) -> Result<EcdsaJwsVerifier, JoseError> {
    let mut verifier = ES256.verifier_from_jwk(jwk)?;
    // The whole point of this module: see the docs above.
    verifier.remove_key_id();
    Ok(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::{JwsHeader, JwsVerifier};
    use josekit::jwt::{self, JwtPayload};

    /// Sign a JWT with `kp`, embedding `kp`'s public JWK — carrying `jwk_kid`
    /// when given — in the `jwk` header. The private JWK never carries a kid,
    /// so josekit's `serialize_compact` (which copies a signer's kid onto the
    /// header) cannot put one on the outer header.
    fn signed_jwt_with_embedded_jwk(kp: &EcKeyPair, jwk_kid: Option<&str>) -> String {
        let mut public_jwk = kp.to_jwk_public_key();
        if let Some(kid) = jwk_kid {
            public_jwk.set_key_id(kid);
        }

        let mut header = JwsHeader::new();
        header.set_jwk(public_jwk);

        let mut payload = JwtPayload::new();
        payload.set_claim("sub", Some("alice".into())).unwrap();

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    fn header_of(jwt: &str) -> serde_json::Value {
        let raw = B64URL
            .decode(jwt.split('.').next().expect("compact JWS has a header"))
            .expect("header is base64url");
        serde_json::from_slice(&raw).expect("header is JSON")
    }

    #[test]
    fn drops_a_kid_the_jwk_carried() {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut jwk = kp.to_jwk_public_key();
        jwk.set_key_id("some-label");

        let verifier = es256_verifier_from_inline_jwk(&jwk).unwrap();
        assert_eq!(verifier.key_id(), None);

        // The caller's JWK is untouched -- callers such as `proof.rs` hand the
        // holder JWK onward, kid and all.
        assert_eq!(jwk.key_id(), Some("some-label"));
    }

    /// THE REGRESSION. Without the helper this JWS is rejected with
    /// "The JWS kid header claim is required".
    #[test]
    fn verifies_a_jws_whose_embedded_jwk_has_a_kid_but_whose_header_has_none() {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let jwt = signed_jwt_with_embedded_jwk(&kp, Some("some-label"));

        // Guard the setup: a kid on the outer header would make this vacuous.
        let header = header_of(&jwt);
        assert!(header.get("kid").is_none());
        assert_eq!(header["jwk"]["kid"], "some-label");

        let verifier = es256_verifier_from_inline_jwk(&kp.to_jwk_public_key()).unwrap();
        josekit::jwt::decode_with_verifier(&jwt, &verifier)
            .expect("an inline key must verify without a header kid");
    }

    /// THE POSITIVE CONTROL for the negative below: the same construction with
    /// a valid signature is accepted, so the rejection below is attributable
    /// to the signature and not to the shape of the test.
    #[test]
    fn verifies_a_jws_signed_by_the_inline_key() {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let jwt = signed_jwt_with_embedded_jwk(&kp, None);

        let verifier = es256_verifier_from_inline_jwk(&kp.to_jwk_public_key()).unwrap();
        josekit::jwt::decode_with_verifier(&jwt, &verifier).expect("a valid signature verifies");
    }

    /// Dropping the `kid` must not drop the signature check: a JWS signed by a
    /// different key is still rejected, matching kid or not.
    #[test]
    fn still_rejects_a_signature_from_another_key() {
        let signer_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let other_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let jwt = signed_jwt_with_embedded_jwk(&signer_kp, Some("some-label"));

        let mut other_jwk = other_kp.to_jwk_public_key();
        other_jwk.set_key_id("some-label");

        let verifier = es256_verifier_from_inline_jwk(&other_jwk).unwrap();
        assert!(
            josekit::jwt::decode_with_verifier(&jwt, &verifier).is_err(),
            "a signature from a key we did not commit to must still be rejected"
        );
    }
}
