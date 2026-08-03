//! RFC 9449 (DPoP) proof JWT validation — Demonstrating Proof of Possession.
//!
//! Implements §4.2 (proof JWT syntax) and §4.3 (checking proofs) for both the
//! Token Endpoint and the Credential Endpoint, plus §11.1 replay defence.
//!
//! **Two of §4.3's twelve checks are deliberately not here:**
//!
//! - **Check 1** ("not more than one DPoP HTTP request header field") needs the
//!   header map, which this module never sees — it takes a single `&str`. It is
//!   enforced in `crates/foundry/src/server.rs` via `exactly_one_header`.
//! - **Check 10** (`nonce` matches a server-supplied nonce) is vacuous: foundry
//!   does not implement §8/§9 server-provided nonces, so it never supplies one.
//!   §11.3 ("MUST NOT accept any DPoP proofs without the nonce claim when a
//!   DPoP nonce has been provided") is therefore satisfied by construction.
//!   See the design doc §2.2 for why, and §6.2 for the residual §11.2 exposure.

use crate::error::IssuanceError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::obs::thumbprint_bytes;
use foundry_core::storage::Storage;
use josekit::jwk::Jwk;
use josekit::jws::ES256;
use sha2::{Digest, Sha256};

/// RFC 9449 §11.1: "To accommodate for clock offsets, the server MAY accept
/// DPoP proofs that carry an iat time in the reasonably near future."
///
/// Distinct from `max_age_secs`, which bounds how far into the *past* an `iat`
/// may sit. Mirrors `attestation.rs`'s `POP_CLOCK_SKEW_SECS`.
const DPOP_CLOCK_SKEW_SECS: i64 = 60;

/// A DPoP proof that has passed every §4.3 check this module is responsible
/// for. Carries only what a caller still needs; every other claim was checked
/// here and has no consumer above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// RFC 7638 JWK SHA-256 thumbprint of the proof's `jwk` header, base64url
    /// — the §6.1 `jkt` value the access token is bound to.
    pub jkt: String,
    /// The proof's `jti`, for the caller to hand to `claim_dpop_jti`.
    /// Never logged (root `AGENTS.md` §4.5).
    pub jti: String,
    /// The **normalised** `htu`. Returned rather than recomputed by the caller
    /// so the §11.1 replay key and this function's comparison can never
    /// disagree about what URI a proof was scoped to.
    pub htu: String,
}

/// RFC 7638 JWK thumbprint, base64url — the §6.1 `jkt` / §10 `dpop_jkt` value.
///
/// Uses `thumbprint_bytes` (the fail-closed form) rather than `obs::thumbprint`
/// deliberately: the infallible form degrades a malformed JWK to a placeholder
/// string, which would then compare unequal to every real `jkt` and turn a
/// parse error into a confusing binding mismatch.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, IssuanceError> {
    let digest = thumbprint_bytes(jwk).map_err(|e| {
        // `e` names only the structural defect (which member, which kty) and
        // never echoes key material — see obs::thumbprint_bytes's contract.
        IssuanceError::InvalidDpopProof(format!("jwk header is not a valid JWK: {e}"))
    })?;
    Ok(B64URL.encode(digest))
}

/// RFC 9449 §4.3 check 9: compare `htu` "ignoring any query and fragment
/// parts", after the RFC 3986 §6.2.2/§6.2.3 normalisation §4.3 recommends
/// ("servers SHOULD employ syntax-based normalization and scheme-based
/// normalization before comparing the htu claim").
///
/// Applies exactly three transformations: strip query and fragment, lowercase
/// scheme and authority, and drop an explicitly-written default port.
///
/// Deliberately does **no** path normalisation: collapsing `..` segments is a
/// security-relevant rewrite of a value used for an equality check, and neither
/// side of that comparison should contain them in the first place.
fn normalize_htu(raw: &str) -> String {
    let no_fragment = raw.split('#').next().unwrap_or("");
    let no_query = no_fragment.split('?').next().unwrap_or("");

    let Some((scheme, rest)) = no_query.split_once("://") else {
        // Not an absolute URI. Returned as-is so the comparison simply fails
        // rather than this function inventing a shape for it.
        return no_query.to_string();
    };
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let authority = authority.to_ascii_lowercase();

    // RFC 3986 §6.2.3: an explicitly-written default port is equivalent to
    // omitting it.
    let default_port = match scheme.as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    let authority = match default_port {
        Some(p) => authority.strip_suffix(p).unwrap_or(&authority).to_string(),
        None => authority,
    };

    format!("{scheme}://{authority}{path}")
}

/// Validate a DPoP proof JWT per RFC 9449 §4.3.
///
/// `htm` and `htu` MUST be the real method and target URI of the request being
/// authenticated. They are parameters rather than being derived here because
/// only the HTTP layer knows them — and `htu` must come from configuration,
/// never from a client-controlled `Host` header, or an attacker could replay a
/// proof minted for a different origin.
///
/// `expected_ath` is `Some` only at a protected resource (§7): `None` at the
/// Token Endpoint, where no access token is being presented and check 12 does
/// not apply.
///
/// `skip_all` is mandatory: `proof_jwt` is the wallet's proof and
/// `expected_ath` is derived from an access token (root `AGENTS.md` §4.5).
#[tracing::instrument(skip_all, fields(htm = %htm))]
pub fn verify_dpop_proof(
    proof_jwt: &str,
    htm: &str,
    htu: &str,
    expected_ath: Option<&str>,
    now_unix: i64,
    max_age_secs: u64,
) -> Result<VerifiedDpopProof, IssuanceError> {
    // Check 2: "a single and well-formed JWT".
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuanceError::InvalidDpopProof(
            "invalid JWS format, expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = B64URL
        .decode(parts[0])
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid base64url header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid header JSON: {e}")))?;

    // Check 4: "The typ JOSE Header Parameter has the value dpop+jwt."
    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing typ header".into()))?;
    if typ != "dpop+jwt" {
        return Err(IssuanceError::InvalidDpopProof(format!(
            "invalid typ header '{typ}', expected dpop+jwt"
        )));
    }

    // Check 5: alg is a registered asymmetric algorithm, "is not none, is
    // supported by the application, and is acceptable per local policy". Local
    // policy here is ES256 only (HAIP crypto suites), which also discharges
    // "not none" and "not symmetric" by construction.
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing alg header".into()))?;
    if alg != "ES256" {
        return Err(IssuanceError::InvalidDpopProof(format!(
            "alg '{alg}' is not permitted, expected ES256"
        )));
    }

    // §4.2: the jwk header is REQUIRED and "represents the public key chosen
    // by the client".
    let jwk_value = header
        .get("jwk")
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing jwk header".into()))?;

    // Check 7: "The jwk JOSE Header Parameter does not contain a private key."
    //
    // Checked across every key type's private parameters (RFC 7518 §6.2.2 EC,
    // §6.3.2 RSA, §6.4.1 oct; RFC 8037 §2 OKP) rather than only EC's `d`, so a
    // non-EC jwk cannot smuggle one past on a technicality even though the
    // ES256 verifier below would reject its kty. Same list and reasoning as
    // `attestation.rs`'s cnf.jwk guard.
    const PRIVATE_JWK_PARAMS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(param) = PRIVATE_JWK_PARAMS
        .iter()
        .find(|p| jwk_value.get(**p).is_some())
    {
        // Names the offending parameter but never its value — that value is,
        // by construction, private key material (root `AGENTS.md` §4.5).
        return Err(IssuanceError::InvalidDpopProof(format!(
            "jwk header MUST be a public key, but carries the private parameter `{param}`"
        )));
    }

    // Check 6: "The JWT signature verifies with the public key contained in
    // the jwk JOSE Header Parameter."
    let jwk: Jwk = serde_json::from_value(jwk_value.clone())
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid jwk header: {e}")))?;
    let verifier = ES256.verifier_from_jwk(&jwk).map_err(|e| {
        IssuanceError::InvalidDpopProof(format!(
            "unable to build a verifier from the jwk header: {e}"
        ))
    })?;
    josekit::jwt::decode_with_verifier(proof_jwt, &verifier).map_err(|e| {
        IssuanceError::InvalidDpopProof(format!("signature verification failed: {e}"))
    })?;

    let payload_bytes = B64URL
        .decode(parts[1])
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid base64url payload: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| IssuanceError::InvalidDpopProof(format!("invalid payload JSON: {e}")))?;

    // Check 3 (for jti) + §4.2: jti is REQUIRED, "unique identifier for the
    // DPoP proof JWT".
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing or empty jti claim".into()))?;

    // Check 8: "The htm claim matches the HTTP method of the current request."
    // Case-sensitive: RFC 9110 method names are uppercase tokens.
    let claim_htm = payload
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing htm claim".into()))?;
    if claim_htm != htm {
        return Err(IssuanceError::InvalidDpopProof(
            "htm claim does not match the request method".into(),
        ));
    }

    // Check 9: "The htu claim matches the HTTP URI value for the HTTP request
    // in which the JWT was received, ignoring any query and fragment parts."
    let claim_htu = payload
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::InvalidDpopProof("missing htu claim".into()))?;
    let normalized_claim_htu = normalize_htu(claim_htu);
    if normalized_claim_htu != normalize_htu(htu) {
        // Never echoes either URI: the expected one is configuration and the
        // claimed one is attacker-controlled.
        return Err(IssuanceError::InvalidDpopProof(
            "htu claim does not match the request URI".into(),
        ));
    }

    // Check 11: "The creation time of the JWT, as determined by either the iat
    // claim or a server managed timestamp via the nonce claim, is within an
    // acceptable window."
    //
    // Saturating throughout, and via try_from rather than `as`: `iat` arrives
    // off the wire, and `max_age_secs as i64` would be a lossy cast of a u64
    // config value (`u64::MAX as i64 == -1`, which would reject every proof).
    // A bare +/- would panic under the dev profile's overflow-checks (breaking
    // root AGENTS.md §4.1 in a request path) or silently wrap in release, in
    // which case *both* freshness bounds stop firing and the §11.1 window is
    // bypassed rather than merely mis-tuned.
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        IssuanceError::InvalidDpopProof("missing or non-integer iat claim".into())
    })?;
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if now_unix.saturating_sub(iat) > max_age {
        return Err(IssuanceError::InvalidDpopProof(
            "iat is older than the allowed max age".into(),
        ));
    }
    if iat > now_unix.saturating_add(DPOP_CLOCK_SKEW_SECS) {
        return Err(IssuanceError::InvalidDpopProof(
            "iat is too far in the future".into(),
        ));
    }

    // Check 12, first half: "ensure that the value of the ath claim equals the
    // hash of that access token". The second half — "confirm that the public
    // key to which the access token is bound matches the public key from the
    // DPoP proof" — is the caller's, since this module knows nothing about
    // transactions.
    if let Some(expected) = expected_ath {
        let claim_ath = payload
            .get("ath")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IssuanceError::InvalidDpopProof("missing ath claim".into()))?;
        // Never echoes either value: both are derived from the access token.
        if claim_ath != expected {
            return Err(IssuanceError::InvalidDpopProof(
                "ath claim does not match the presented access token".into(),
            ));
        }
    }

    Ok(VerifiedDpopProof {
        jkt: jwk_thumbprint(jwk_value)?,
        jti: jti.to_string(),
        htu: normalized_claim_htu,
    })
}

/// RFC 9449 §7: `base64url(SHA-256(ASCII(access_token)))` — the `ath` claim
/// value a proof presented alongside `access_token` must carry.
pub fn access_token_hash(access_token: &str) -> String {
    B64URL.encode(Sha256::digest(access_token.as_bytes()))
}

/// KV namespace for RFC 9449 §11.1 DPoP proof `jti` replay claims.
// TODO(Task 7/9): remove this allow once /token and /credential call
// claim_dpop_jti -- this constant and the function below are exercised only
// by this module's own tests until those call sites land.
#[allow(dead_code)]
pub(crate) const DPOP_JTI_NAMESPACE: &str = "dpop_jti";

/// RFC 9449 §11.1: claim a proof's `jti` for its acceptance window, rejecting
/// a replay.
///
/// The key is `base64url(SHA-256(jkt ‖ 0x00 ‖ htu ‖ 0x00 ‖ jti))`. Three
/// deliberate properties:
///
/// - **Scoped per target URI**, because §11.1 scopes single-use "in the context
///   of the target URI" — a proof for `/token` and one for `/credential` are
///   distinct claims. The `htu` used is the *normalised* one from
///   `VerifiedDpopProof`, which is why this function takes the whole struct
///   rather than loose strings: a caller cannot key the store on a URI other
///   than the one `verify_dpop_proof` actually compared.
/// - **Scoped per `jkt`**, so one wallet cannot pre-claim `jti` values and deny
///   service to another. Same reasoning as `attestation.rs`'s `claim_pop_jti`.
/// - **Hashed**, because §11.1 says to "store only a hash thereof" to bound
///   memory against exhaustion attacks, and because it keeps the raw,
///   attacker-controlled `jti` out of the SQL key and out of anything derived
///   from it.
///
/// Uses `insert_kv_if_absent`, not get-then-put: the atomicity is the entire
/// mechanism. A get-then-put has a TOCTOU window in which two concurrent
/// replays both observe "absent" and both succeed.
///
/// `skip_all` is mandatory: `proof` carries the raw `jti` (root `AGENTS.md`
/// §4.5).
#[tracing::instrument(skip_all)]
#[allow(dead_code)]
pub(crate) async fn claim_dpop_jti(
    storage: &dyn Storage,
    proof: &VerifiedDpopProof,
    max_age_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    let mut hasher = Sha256::new();
    hasher.update(proof.jkt.as_bytes());
    hasher.update([0u8]);
    hasher.update(proof.htu.as_bytes());
    hasher.update([0u8]);
    hasher.update(proof.jti.as_bytes());
    let key = B64URL.encode(hasher.finalize());

    // Saturating and via try_from for the same reasons as the `iat` bounds
    // check above: `max_age_secs as i64` would be lossy for a u64 config value.
    // The row need only outlive the window in which the proof itself would
    // still be accepted, so the TTL mirrors that window plus the skew
    // tolerance.
    let max_age = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    let expires_at = now_unix
        .saturating_add(max_age)
        .saturating_add(DPOP_CLOCK_SKEW_SECS);

    let claimed = storage
        .insert_kv_if_absent(DPOP_JTI_NAMESPACE, &key, "1", Some(expires_at))
        .await?;
    if !claimed {
        return Err(IssuanceError::InvalidDpopProof(
            "jti has already been used".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::JwsHeader;
    use josekit::jwt::{self, JwtPayload};

    const HTU: &str = "https://issuer.example.com/token";
    const NOW: i64 = 1_700_000_000;
    const MAX_AGE: u64 = 300;

    fn keypair() -> EcKeyPair {
        EcKeyPair::generate(EcCurve::P256).unwrap()
    }

    /// The RFC 9449 §4.2 Figure 2 key, whose §6.1 Figure 9 `jkt` is published
    /// in the RFC itself — the known-answer vector this module asserts against.
    fn rfc9449_figure2_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
        })
    }

    /// Mint a DPoP proof. Every negative test below is this call with exactly
    /// one argument mutated.
    #[allow(clippy::too_many_arguments)]
    fn dpop_proof(
        kp: &EcKeyPair,
        typ: &str,
        htm: Option<&str>,
        htu: Option<&str>,
        iat: Option<i64>,
        jti: Option<&str>,
        ath: Option<&str>,
    ) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type(typ);
        let jwk = kp.to_jwk_public_key();
        header.set_jwk(jwk);

        let mut payload = JwtPayload::new();
        if let Some(v) = htm {
            payload.set_claim("htm", Some(v.into())).unwrap();
        }
        if let Some(v) = htu {
            payload.set_claim("htu", Some(v.into())).unwrap();
        }
        if let Some(v) = iat {
            payload.set_claim("iat", Some(v.into())).unwrap();
        }
        if let Some(v) = jti {
            payload.set_claim("jti", Some(v.into())).unwrap();
        }
        if let Some(v) = ath {
            payload.set_claim("ath", Some(v.into())).unwrap();
        }

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    /// A fully valid proof for the happy path.
    fn valid(kp: &EcKeyPair) -> String {
        dpop_proof(
            kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW),
            Some("jti-1"),
            None,
        )
    }

    #[test]
    fn thumbprint_matches_the_rfc9449_figure_9_known_answer() {
        // RFC 9449 §6.1 Figure 9 publishes this jkt for the Figure 2 key.
        // Asserting against the RFC's own vector, not against our output.
        let jkt = jwk_thumbprint(&rfc9449_figure2_jwk()).unwrap();
        assert_eq!(jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    }

    #[test]
    fn a_valid_proof_is_accepted_and_yields_a_thumbprint() {
        let kp = keypair();
        let v = verify_dpop_proof(&valid(&kp), "POST", HTU, None, NOW, MAX_AGE).unwrap();
        assert_eq!(v.jti, "jti-1");
        assert_eq!(v.htu, HTU);
        assert!(!v.jkt.is_empty());
    }

    #[test]
    fn rejects_a_non_jwt_string() {
        // Check 2.
        let e = verify_dpop_proof("not-a-jwt", "POST", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[test]
    fn rejects_a_two_part_jws() {
        // Check 2.
        assert!(verify_dpop_proof("aaa.bbb", "POST", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_wrong_typ() {
        // Check 4. `jwt` instead of `dpop+jwt` is the realistic mistake, and
        // §11.5 (signed JWT swapping) is why typ is checked at all.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW),
            Some("j"),
            None,
        );
        let e = verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert!(e.to_string().contains("dpop+jwt"), "got: {e}");
    }

    #[test]
    fn rejects_missing_jti() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW),
            None,
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("jti"));
    }

    #[test]
    fn rejects_missing_htm() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(&kp, "dpop+jwt", None, Some(HTU), Some(NOW), Some("j"), None);
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("htm"));
    }

    #[test]
    fn rejects_missing_htu() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            None,
            Some(NOW),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("htu"));
    }

    #[test]
    fn rejects_missing_iat() {
        // Check 3.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            None,
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("iat"));
    }

    #[test]
    fn rejects_a_signature_by_another_key() {
        // Check 6: the jwk header advertises one key, the signature is by
        // another. This is the check that makes the proof a proof.
        let signer_kp = keypair();
        let other_kp = keypair();
        let p = valid(&signer_kp);
        // Swap the jwk header for a different key, keeping the signature.
        let parts: Vec<&str> = p.split('.').collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        let other_jwk = other_kp.to_jwk_public_key();
        header["jwk"] = serde_json::to_value(&other_jwk).unwrap();
        let forged = format!(
            "{}.{}.{}",
            B64URL.encode(serde_json::to_vec(&header).unwrap()),
            parts[1],
            parts[2]
        );
        assert!(verify_dpop_proof(&forged, "POST", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_a_tampered_payload() {
        // Check 6.
        let kp = keypair();
        let p = valid(&kp);
        let parts: Vec<&str> = p.split('.').collect();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        payload["htm"] = serde_json::json!("GET");
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            B64URL.encode(serde_json::to_vec(&payload).unwrap()),
            parts[2]
        );
        assert!(verify_dpop_proof(&forged, "GET", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_a_jwk_carrying_a_private_key() {
        // Check 7. A private key in the header means the wallet leaked its
        // signing key into a plaintext HTTP header, at which point the proof
        // proves nothing.
        let kp = keypair();
        let p = valid(&kp);
        let parts: Vec<&str> = p.split('.').collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        header["jwk"]["d"] = serde_json::json!("c3VwZXItc2VjcmV0LXNjYWxhcg");
        let leaked = format!(
            "{}.{}.{}",
            B64URL.encode(serde_json::to_vec(&header).unwrap()),
            parts[1],
            parts[2]
        );
        let e = verify_dpop_proof(&leaked, "POST", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert!(e.to_string().contains('d'), "must name the parameter: {e}");
        assert!(
            !e.to_string().contains("c3VwZXItc2VjcmV0"),
            "the private scalar must never appear in an error message: {e}"
        );
    }

    #[test]
    fn rejects_htm_mismatch() {
        // Check 8.
        let kp = keypair();
        let e = verify_dpop_proof(&valid(&kp), "GET", HTU, None, NOW, MAX_AGE).unwrap_err();
        assert!(e.to_string().contains("htm"), "got: {e}");
    }

    #[test]
    fn rejects_htu_mismatch() {
        // Check 9. A proof minted for /token replayed at /credential is
        // exactly what this prevents.
        let kp = keypair();
        let e = verify_dpop_proof(
            &valid(&kp),
            "POST",
            "https://issuer.example.com/credential",
            None,
            NOW,
            MAX_AGE,
        )
        .unwrap_err();
        assert!(e.to_string().contains("htu"), "got: {e}");
    }

    #[test]
    fn accepts_htu_differing_only_by_query_or_fragment() {
        // Check 9: "ignoring any query and fragment parts".
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some("https://issuer.example.com/token?x=1#frag"),
            Some(NOW),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn accepts_htu_differing_only_by_case_or_default_port() {
        // Check 9 + RFC 3986 §6.2.2/§6.2.3 normalisation.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some("HTTPS://Issuer.Example.COM:443/token"),
            Some(NOW),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn htu_normalisation_does_not_collapse_dot_segments() {
        // Deliberate: path normalisation is a security-relevant rewrite of a
        // value used for an equality check. A traversal-shaped htu must fail,
        // not be silently rewritten into a match.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some("https://issuer.example.com/admin/../token"),
            Some(NOW),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn rejects_iat_older_than_the_window() {
        // Check 11 / §11.1.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW - 301),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("older"));
    }

    #[test]
    fn rejects_iat_too_far_in_the_future() {
        // Check 11 / §11.2: an attacker pre-generating proofs.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW + 61),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE)
            .unwrap_err()
            .to_string()
            .contains("future"));
    }

    #[test]
    fn accepts_iat_slightly_in_the_future_within_clock_skew() {
        // §11.1: "servers MAY accept DPoP proofs that carry an iat time in the
        // reasonably near future."
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW + 30),
            Some("j"),
            None,
        );
        assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn does_not_overflow_on_a_boundary_iat() {
        // Root AGENTS.md §4.1: overflow-checks = true in the dev profile turns
        // a bare +/- on a wire-sourced i64 into a panic in a request path.
        //
        // Built via raw payload substitution rather than `dpop_proof`/`set_claim`:
        // josekit's own JWT builder validates iat as a non-negative integer and
        // rejects i64::MIN before a JWT can even be produced. verify_dpop_proof
        // parses claims itself (it does not go through josekit's claim
        // validation), so it must be exercised directly against a boundary
        // value a hand-crafted proof could actually carry on the wire.
        let kp = keypair();
        for iat in [i64::MIN, i64::MAX] {
            let base = valid(&kp);
            let parts: Vec<&str> = base.split('.').collect();
            let mut payload: serde_json::Value =
                serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
            payload["iat"] = serde_json::json!(iat);
            let p = format!(
                "{}.{}.{}",
                parts[0],
                B64URL.encode(serde_json::to_vec(&payload).unwrap()),
                parts[2]
            );
            // Must return an error, never panic. The signature no longer
            // verifies (the payload changed), which is fine: any error path is
            // acceptable here, the panic is what this test guards against.
            assert!(verify_dpop_proof(&p, "POST", HTU, None, NOW, u64::MAX).is_err());
        }
    }

    #[test]
    fn rejects_missing_ath_when_an_access_token_is_presented() {
        // Check 12 / §7: "The DPoP proof MUST include the ath claim."
        let kp = keypair();
        let e = verify_dpop_proof(
            &valid(&kp),
            "POST",
            HTU,
            Some("expected-hash"),
            NOW,
            MAX_AGE,
        )
        .unwrap_err();
        assert!(e.to_string().contains("ath"), "got: {e}");
    }

    #[test]
    fn rejects_ath_mismatch() {
        // Check 12 / §11.5: prevents a proof for token AT1 being replayed
        // with token AT2.
        let kp = keypair();
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW),
            Some("j"),
            Some(&access_token_hash("at_one")),
        );
        assert!(verify_dpop_proof(
            &p,
            "POST",
            HTU,
            Some(&access_token_hash("at_two")),
            NOW,
            MAX_AGE
        )
        .is_err());
    }

    #[test]
    fn accepts_a_matching_ath() {
        let kp = keypair();
        let token = "at_deadbeef";
        let p = dpop_proof(
            &kp,
            "dpop+jwt",
            Some("POST"),
            Some(HTU),
            Some(NOW),
            Some("j"),
            Some(&access_token_hash(token)),
        );
        assert!(verify_dpop_proof(
            &p,
            "POST",
            HTU,
            Some(&access_token_hash(token)),
            NOW,
            MAX_AGE
        )
        .is_ok());
    }

    #[test]
    fn ath_is_the_base64url_sha256_of_the_token() {
        // §7 / §4.2: "the result of a base64url encoding the SHA-256 hash of
        // the ASCII encoding of the associated access token's value."
        // Known answer for the RFC 9449 §7.1 Figure 13 token.
        assert_eq!(
            access_token_hash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        );
    }

    async fn test_storage() -> foundry_core::storage::SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        std::mem::forget(dir);
        foundry_core::storage::SqliteStorage::connect(db.to_str().unwrap())
            .await
            .unwrap()
    }

    fn proof_for(jkt: &str, htu: &str, jti: &str) -> VerifiedDpopProof {
        VerifiedDpopProof {
            jkt: jkt.to_string(),
            htu: htu.to_string(),
            jti: jti.to_string(),
        }
    }

    #[tokio::test]
    async fn a_first_sighting_is_claimed_and_a_replay_is_rejected() {
        // §11.1: "servers can store the jti value of each DPoP proof for the
        // time window in which the respective DPoP proof JWT would be
        // accepted to prevent multiple uses of the same DPoP proof."
        let storage = test_storage().await;
        let p = proof_for("jkt-a", HTU, "jti-1");

        claim_dpop_jti(&storage, &p, MAX_AGE, NOW).await.unwrap();
        let e = claim_dpop_jti(&storage, &p, MAX_AGE, NOW)
            .await
            .expect_err("a replayed jti must be rejected");
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn the_same_jti_at_a_different_htu_is_accepted() {
        // §11.1 scopes single-use "in the context of the target URI", so the
        // same jti at /token and at /credential are distinct claims.
        let storage = test_storage().await;
        claim_dpop_jti(&storage, &proof_for("jkt-a", HTU, "jti-1"), MAX_AGE, NOW)
            .await
            .unwrap();
        claim_dpop_jti(
            &storage,
            &proof_for("jkt-a", "https://issuer.example.com/credential", "jti-1"),
            MAX_AGE,
            NOW,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn two_wallets_may_use_the_same_jti() {
        // Keyed per jkt so one wallet cannot pre-claim jti values and deny
        // service to another -- the same reasoning as claim_pop_jti.
        let storage = test_storage().await;
        claim_dpop_jti(&storage, &proof_for("jkt-a", HTU, "shared"), MAX_AGE, NOW)
            .await
            .unwrap();
        claim_dpop_jti(&storage, &proof_for("jkt-b", HTU, "shared"), MAX_AGE, NOW)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_raw_jti_never_appears_in_the_storage_key() {
        // §11.1: "a server that is tracking jti values should reject DPoP
        // proof JWTs with unnecessarily large jti values or store only a hash
        // thereof." Also keeps attacker-controlled bytes out of the SQL key.
        let storage = test_storage().await;
        let p = proof_for("jkt-a", HTU, "recognisable-raw-jti");
        claim_dpop_jti(&storage, &p, MAX_AGE, NOW).await.unwrap();
        assert!(
            storage
                .get_kv(DPOP_JTI_NAMESPACE, "recognisable-raw-jti")
                .await
                .unwrap()
                .is_none(),
            "the raw jti must not be the storage key"
        );
    }

    #[tokio::test]
    async fn claiming_does_not_overflow_on_an_absurd_max_age() {
        // u64::MAX as i64 would be -1; try_from + saturating keeps the TTL sane.
        let storage = test_storage().await;
        claim_dpop_jti(&storage, &proof_for("jkt-a", HTU, "j"), u64::MAX, NOW)
            .await
            .unwrap();
    }
}
