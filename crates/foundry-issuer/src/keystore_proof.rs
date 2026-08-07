//! Google Wallet's `android_keystore_attestation` proof type: arrays of X.509
//! certificate chains carrying Android Keystore attestations.
//!
//! Vendor profile: `docs/specs/google-wallet-openid4vci-profile.md` and
//! <https://developer.android.com/identity/digital-credentials/credential-issuer/keystore-attestation>.
//! Design: `docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md`.
//!
//! This is **not** OpenID4VCI Appendix D key attestation: there is no JWT, no
//! claim set, and no signature by the attested key. Do not route it through
//! `attestation.rs`'s `verify_key_attestation_jwt`.
//!
//! Two properties the `jwt` proof type has and this one structurally cannot
//! (both recorded as conformance gap rows):
//!
//! * **No audience binding.** The format carries no Credential Issuer
//!   Identifier, so OpenID4VCI L862's mechanism is unmet. The property it exists
//!   for still holds: the `c_nonce` is MAC'd with this issuer's secret, so
//!   another issuer's nonce does not verify here.
//! * **No proof of possession** of the attested key -- the same posture as
//!   OpenID4VCI's own `attestation` proof type (L2612). The hardware statement
//!   substitutes.
//!
//! Certificate validity contributes no freshness: real Android leaves are valid
//! 1970-2106. The `attestationChallenge` binding is the only replay defence,
//! which is why it is checked unconditionally and never made optional.

use crate::error::IssuanceError;
use crate::nonce::{NonceSecret, verify_nonce};
use crate::proof::VerifiedProof;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry_core::config::{AndroidKeystoreConfig, Mode};
use foundry_core::trust::android_attestation::find_attestation_cert;
use foundry_core::trust::{
    TrustStore, cert_ec_public_coords, parse_cert_pem, validate_chain, x5c_entry_to_pem,
};
use josekit::jwk::Jwk;

/// Verify every chain in a `proofs.android_keystore_attestation` array.
///
/// Returns one `VerifiedProof` per chain, in request order, so the caller binds
/// the Nth issued credential to the Nth attested key exactly as it does for the
/// `jwt` proof array.
///
/// `skip_all` is mandatory: `chains` carries certificates and `nonce_secret` is
/// the process MAC secret.
#[tracing::instrument(skip_all, fields(chain_count = chains.len()))]
pub fn verify_android_keystore_proofs(
    chains: &[Vec<String>],
    cfg: &AndroidKeystoreConfig,
    trust_store: &TrustStore,
    nonce_secret: &NonceSecret,
    now_unix: i64,
) -> Result<Vec<VerifiedProof>, IssuanceError> {
    if cfg.mode == Mode::Disabled {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation is an unsupported proof type for this issuer".into(),
        ));
    }
    if chains.is_empty() {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation must contain at least one certificate chain".into(),
        ));
    }
    chains
        .iter()
        .map(|chain| verify_one_chain(chain, cfg, trust_store, nonce_secret, now_unix))
        .collect()
}

#[tracing::instrument(skip_all)]
fn verify_one_chain(
    chain: &[String],
    cfg: &AndroidKeystoreConfig,
    trust_store: &TrustStore,
    nonce_secret: &NonceSecret,
    now_unix: i64,
) -> Result<VerifiedProof, IssuanceError> {
    if chain.is_empty() {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation: certificate chain is empty".into(),
        ));
    }

    // Google transmits "Base64-NoWrap padded DER", which is exactly the `x5c`
    // entry encoding of RFC 7515 §4.1.6, so the existing converter applies.
    let pems: Vec<Vec<u8>> = chain
        .iter()
        .map(|entry| {
            x5c_entry_to_pem(entry).map_err(|e| {
                IssuanceError::InvalidProof(format!(
                    "android_keystore_attestation: certificate is not base64 DER: {e}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let now_u64 = u64::try_from(now_unix)
        .map_err(|_| IssuanceError::Internal("current time is before the unix epoch".into()))?;

    // Every failure here is a client fault. `IssuanceError::Trust` would fall
    // through `wallet_error_response`'s catch-all arm to HTTP 500, turning "your
    // chain reaches no anchor I trust" into an apparent server outage -- so the
    // TrustError is wrapped, never propagated with `?`.
    //
    // Google's format includes its own root as the last element.
    // `validate_chain` discards self-signed presented certificates, so the
    // transmitted root grants nothing and trust must reach a configured anchor.
    validate_chain(&pems[0], &pems[1..], trust_store, now_u64).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: certificate chain validation failed: {e}"
        ))
    })?;

    let certs = pems
        .iter()
        .map(|pem| {
            parse_cert_pem(pem).map_err(|e| {
                IssuanceError::InvalidProof(format!(
                    "android_keystore_attestation: certificate does not parse: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (attesting_idx, key_description) = find_attestation_cert(&certs)
        .map_err(|e| IssuanceError::InvalidProof(format!("android_keystore_attestation: {e}")))?;

    // The attestationChallenge holds the UTF-8 bytes of the c_nonce string as
    // transmitted, not raw nonce bytes -- established from the real Android
    // chain in `crates/foundry-core/tests/fixtures/android-attestation/`.
    let challenge = std::str::from_utf8(&key_description.attestation_challenge).map_err(|_| {
        IssuanceError::InvalidProof(
            "android_keystore_attestation: attestationChallenge is not valid UTF-8".into(),
        )
    })?;

    // Never log `challenge`: it is a c_nonce (root AGENTS.md §4.5). The prefix
    // mirrors `attestation.rs`'s `key_attestation:` so an operator can tell
    // which nonce-consuming path rejected the request.
    verify_nonce(nonce_secret, challenge, now_unix).map_err(|e| match e {
        IssuanceError::InvalidNonce(msg) => {
            IssuanceError::InvalidNonce(format!("android_keystore_attestation: {msg}"))
        }
        other => other,
    })?;

    // Both levels, not just the one Google's metadata names:
    // attestationSecurityLevel is where the key lives, keyMintSecurityLevel is
    // the implementation making the statement. A policy satisfied by only one of
    // them is not the policy the operator configured.
    let minimum = cfg.key_mint_security_level;
    if key_description.attestation_security_level < minimum
        || key_description.key_mint_security_level < minimum
    {
        return Err(IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: security level below the configured minimum {}",
            minimum.as_str()
        )));
    }

    let attesting_cert = certs.get(attesting_idx).ok_or_else(|| {
        IssuanceError::Internal("attestation certificate index out of range".into())
    })?;
    let (x, y) = cert_ec_public_coords(attesting_cert).map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: attested key is not an EC public key: {e}"
        ))
    })?;
    // The attested key becomes the credential's holder key, and every credential
    // format foundry issues binds P-256. Google's metadata schema requires
    // `proof_signing_alg_values_supported`, which is read as constraining this
    // key even though nothing here is signed by it.
    if x.len() != 32 || y.len() != 32 {
        return Err(IssuanceError::InvalidProof(
            "android_keystore_attestation: attested key is not on P-256".into(),
        ));
    }
    let holder_jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64URL.encode(&x),
        "y": B64URL.encode(&y),
    }))
    .map_err(|e| {
        IssuanceError::InvalidProof(format!(
            "android_keystore_attestation: attested key is not a usable JWK: {e}"
        ))
    })?;

    // Fields are opt-in, and `attestationChallenge` and `uniqueId` are never
    // among them (root AGENTS.md §4.5).
    let jwk_json = serde_json::to_value(&holder_jwk)
        .map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    tracing::debug!(
        attestation_version = key_description.attestation_version,
        attestation_security_level = key_description.attestation_security_level.as_str(),
        key_mint_security_level = key_description.key_mint_security_level.as_str(),
        attested_key = %foundry_core::obs::thumbprint(&jwk_json),
        "android_keystore_attestation proof accepted"
    );

    Ok(VerifiedProof { holder_jwk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::Mode;
    use foundry_core::trust::android_attestation::SecurityLevel;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    // --- synthetic Android-shaped chains ---------------------------------
    //
    // The real Google fixture can never pass a happy-path test: its
    // attestationChallenge is Google's c_nonce, which cannot verify against
    // foundry's per-process MAC secret, and a static fixture cannot carry an
    // unexpired nonce. Chains are therefore minted at run time.
    //
    // The DER builder is deliberately duplicated from
    // `crates/foundry-core/tests/android_attestation.rs`; the design doc's
    // Testing section records why a public encoder in foundry-core was rejected.

    fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn integer(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
            bytes.remove(0);
        }
        tlv(&[0x02], &bytes)
    }

    fn enumerated(v: u8) -> Vec<u8> {
        tlv(&[0x0a], &[v])
    }

    fn octet_string(bytes: &[u8]) -> Vec<u8> {
        tlv(&[0x04], bytes)
    }

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }

    /// `KeyDescription` DER (attestation version 3) with the given levels and
    /// challenge, and empty authorization lists.
    fn key_description(attestation_level: u8, key_mint_level: u8, challenge: &[u8]) -> Vec<u8> {
        sequence(&[
            integer(3),
            enumerated(attestation_level),
            integer(41),
            enumerated(key_mint_level),
            octet_string(challenge),
            octet_string(&[]),
            sequence(&[]),
            sequence(&[]),
        ])
    }

    struct SyntheticChain {
        /// Base64-STANDARD DER, leaf first -- the wire form of one chain.
        chain: Vec<String>,
        /// The root's PEM, for the `TrustStore`.
        root_pem: String,
        /// The leaf's public JWK as JSON, for asserting the derived holder key.
        leaf_public_jwk: serde_json::Value,
    }

    /// A root CA plus a leaf carrying `key_description_der` in the Android
    /// attestation extension. `leaf_alg` selects the leaf's key algorithm so the
    /// non-P-256 rejection path is testable.
    fn synthetic_chain(
        key_description_der: &[u8],
        leaf_alg: &'static rcgen::SignatureAlgorithm,
    ) -> SyntheticChain {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut root_dn = DistinguishedName::new();
        root_dn.push(DnType::CommonName, "Synthetic Android Attestation Root");
        root_params.distinguished_name = root_dn;
        let root = root_params.self_signed(&root_key).expect("root cert");
        let root_pem = root.pem();

        let issuer = Issuer::from_ca_cert_pem(&root_pem, root_key).expect("issuer");

        let leaf_key = KeyPair::generate_for(leaf_alg).expect("leaf key");
        let mut leaf_params = CertificateParams::default();
        let mut leaf_dn = DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, "Android Keystore Key");
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                key_description_der.to_vec(),
            ));
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");

        let leaf_pem = leaf.pem();
        let leaf_cert = parse_cert_pem(leaf_pem.as_bytes()).expect("leaf parses");
        let leaf_public_jwk = match cert_ec_public_coords(&leaf_cert) {
            Ok((x, y)) => serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": B64URL.encode(x),
                "y": B64URL.encode(y),
            }),
            // Only the non-P-256 rejection test produces a leaf this fails on,
            // and it never reads this field.
            Err(_) => serde_json::Value::Null,
        };

        let chain = foundry_core::trust::build_x5c(&[
            leaf_pem.clone().into_bytes(),
            root_pem.clone().into_bytes(),
        ])
        .expect("base64 DER chain");

        SyntheticChain {
            chain,
            root_pem,
            leaf_public_jwk,
        }
    }

    fn store_for(root_pem: &str) -> TrustStore {
        TrustStore::from_pems(&[root_pem.as_bytes().to_vec()]).expect("trust store")
    }

    fn cfg(mode: Mode, level: SecurityLevel) -> AndroidKeystoreConfig {
        AndroidKeystoreConfig {
            mode,
            key_mint_security_level: level,
        }
    }

    fn secret() -> NonceSecret {
        NonceSecret::from_bytes([42u8; 32])
    }

    fn now() -> i64 {
        1_800_000_000
    }

    /// A live, unexpired, MAC-authenticated `c_nonce`, exactly as `POST /nonce`
    /// mints one.
    fn fresh_nonce(secret: &NonceSecret) -> String {
        crate::nonce::issue_nonce(secret, now())
            .expect("mint nonce")
            .c_nonce
    }

    // --- tests ----------------------------------------------------------

    #[test]
    fn accepts_a_valid_chain_and_binds_the_attested_key() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );

        let proofs = verify_android_keystore_proofs(
            std::slice::from_ref(&sc.chain),
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect("a genuine chain must be accepted");

        assert_eq!(proofs.len(), 1);
        let derived = serde_json::to_value(&proofs[0].holder_jwk).expect("jwk serializes");
        assert_eq!(derived["kty"], sc.leaf_public_jwk["kty"]);
        assert_eq!(derived["crv"], sc.leaf_public_jwk["crv"]);
        assert_eq!(derived["x"], sc.leaf_public_jwk["x"]);
        assert_eq!(derived["y"], sc.leaf_public_jwk["y"]);
    }

    #[test]
    fn issues_one_proof_per_chain_in_request_order() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let first = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let proofs = verify_android_keystore_proofs(
            &[first.chain.clone(), first.chain.clone()],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&first.root_pem),
            &secret,
            now(),
        )
        .expect("both chains accepted");
        assert_eq!(proofs.len(), 2);
        let a = serde_json::to_value(&proofs[0].holder_jwk).expect("jwk");
        let b = serde_json::to_value(&proofs[1].holder_jwk).expect("jwk");
        assert_eq!(a["x"], first.leaf_public_jwk["x"]);
        assert_eq!(a["x"], b["x"], "the same chain twice yields the same key");
    }

    #[test]
    fn rejects_a_challenge_that_is_not_an_issuer_minted_nonce() {
        let secret = secret();
        let sc = synthetic_chain(
            &key_description(1, 1, b"not-a-real-c-nonce"),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a forged challenge must be rejected");
        assert!(
            matches!(err, IssuanceError::InvalidNonce(ref m)
                if m.contains("android_keystore_attestation")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_an_expired_nonce() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            // Far beyond any plausible c_nonce lifetime.
            now() + 86_400,
        )
        .expect_err("an expired challenge must be rejected");
        assert!(matches!(err, IssuanceError::InvalidNonce(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_non_utf8_challenge() {
        let secret = secret();
        let sc = synthetic_chain(
            &key_description(1, 1, &[0xff, 0xfe, 0xfd]),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a non-UTF-8 challenge must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_security_level_below_the_configured_minimum() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        // Software-backed key against the default TrustedEnvironment policy.
        let sc = synthetic_chain(
            &key_description(0, 0, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a software-backed key must be rejected under the default policy");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn strongbox_policy_rejects_a_trusted_environment_key() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::StrongBox),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("TEE must not satisfy a StrongBox minimum");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn each_security_level_is_checked_independently() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        // attestationSecurityLevel satisfies the policy, keyMintSecurityLevel
        // does not. A verifier checking only the metadata-named field would
        // wrongly accept this.
        let sc = synthetic_chain(
            &key_description(1, 0, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("both levels must meet the minimum");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn an_unanchored_chain_is_invalid_proof_not_trust() {
        // The regression test for a 500-instead-of-400 response: an untrusted
        // holder chain is a client fault, but `IssuanceError::Trust` falls
        // through `wallet_error_response`'s catch-all arm to HTTP 500.
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let unrelated = foundry_core::pki::new_ca("Unrelated Root", 3650).expect("CA");
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&unrelated.cert_pem),
            &secret,
            now(),
        )
        .expect_err("a chain reaching no configured anchor must be rejected");
        assert!(
            matches!(err, IssuanceError::InvalidProof(_)),
            "must be InvalidProof (HTTP 400), got {err:?}"
        );
    }

    #[test]
    fn rejects_a_non_p256_attested_key() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("a P-384 attested key must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_chain_with_no_attestation_extension() {
        let secret = secret();
        let ca = foundry_core::pki::new_ca("Plain Root", 3650).expect("CA");
        let leaf = foundry_core::pki::issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "plain.test.local",
            &["plain.test.local".to_string()],
            365,
        )
        .expect("leaf");
        let chain = foundry_core::trust::build_x5c(&[
            leaf.cert_pem.clone().into_bytes(),
            ca.cert_pem.clone().into_bytes(),
        ])
        .expect("chain");
        let err = verify_android_keystore_proofs(
            &[chain],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&ca.cert_pem),
            &secret,
            now(),
        )
        .expect_err("a chain with no attestation extension must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }

    #[test]
    fn rejects_everything_when_the_mode_is_disabled() {
        let secret = secret();
        let nonce = fresh_nonce(&secret);
        let sc = synthetic_chain(
            &key_description(1, 1, nonce.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let err = verify_android_keystore_proofs(
            &[sc.chain],
            &cfg(Mode::Disabled, SecurityLevel::TrustedEnvironment),
            &store_for(&sc.root_pem),
            &secret,
            now(),
        )
        .expect_err("the default configuration must reject this proof type");
        assert!(
            matches!(err, IssuanceError::InvalidProof(ref m)
                if m.contains("unsupported proof type")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_an_empty_chain_list_and_an_empty_chain() {
        let secret = secret();
        let ca = foundry_core::pki::new_ca("R", 3650).expect("CA");
        let store = store_for(&ca.cert_pem);
        let c = cfg(Mode::Optional, SecurityLevel::TrustedEnvironment);
        assert!(
            verify_android_keystore_proofs(&[], &c, &store, &secret, now()).is_err(),
            "an empty chain list must be rejected"
        );
        assert!(
            verify_android_keystore_proofs(&[vec![]], &c, &store, &secret, now()).is_err(),
            "an empty chain must be rejected"
        );
    }

    #[test]
    fn rejects_a_chain_entry_that_is_not_base64_der() {
        let secret = secret();
        let ca = foundry_core::pki::new_ca("R", 3650).expect("CA");
        let err = verify_android_keystore_proofs(
            &[vec!["not base64!".to_string()]],
            &cfg(Mode::Optional, SecurityLevel::TrustedEnvironment),
            &store_for(&ca.cert_pem),
            &secret,
            now(),
        )
        .expect_err("garbage must be rejected");
        assert!(matches!(err, IssuanceError::InvalidProof(_)), "got {err:?}");
    }
}
