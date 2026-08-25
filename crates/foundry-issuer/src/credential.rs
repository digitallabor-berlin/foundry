//! OpenID4VCI credential endpoint business logic.

use crate::dpop::{DpopPresentation, claim_dpop_jti, verify_dpop_proof};
use crate::error::IssuanceError;
use crate::nonce::NonceSecret;
use crate::proof::{ProofsRequest, ResolvedProofs, verify_holder_proof};
use crate::transaction::{
    IssuanceState, load_transaction_by_access_token, save_transaction_with_indices,
};
use base64::Engine as _;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as B64STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry_core::config::Config;
use foundry_core::crypto::FileSigner;
use foundry_core::storage::Storage;
use foundry_mdoc::builder::{MdocClaims, build_mdoc};
use foundry_sd_jwt_vc::builder::{IssuerClaims, build_sd_jwt_vc};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use std::collections::BTreeMap;

/// OpenID4VCI §Credential Request (L853–856): the wallet's parameters for
/// encrypting the Credential Response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponseEncryptionParams {
    /// L854: a single public key as a JWK. L1188 additionally requires an `alg`
    /// member on it.
    #[schema(value_type = Object)]
    pub jwk: serde_json::Value,
    /// L855: the JWE `enc` algorithm.
    pub enc: String,
    /// L856: compression before encryption. foundry advertises no
    /// `zip_values_supported`, so a present value is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CredentialRequest {
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    pub proofs: Option<ProofsRequest>,
    /// L853. Absent means the Credential Response is not encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryptionParams>,
}

/// OpenID4VCI encryption policy for the Credential Endpoint.
///
/// Lives in the engine rather than in the HTTP extractor so no call site can
/// reach issuance while skipping it.
///
/// * L1192 — an unencrypted request is rejected when encryption was required.
/// * L960 — a request carrying `credential_response_encryption` MUST itself be
///   encrypted, "to prevent it being substituted by an attacker".
/// * L969 — the issuer MUST encrypt when asked. If the mechanism is not
///   configured the request is refused rather than answered in plaintext.
///   Deliberate deviation (root `AGENTS.md` §4.4): the specification does not
///   contemplate this case, and silently downgrading would deliver the
///   credential unencrypted to a wallet that asked for encryption.
/// * L1188 / L855 / L856 — the wallet's JWK must carry `alg`, `enc` must be
///   advertised, and `zip` must be absent.
pub fn check_encryption_policy(
    cfg: &Config,
    req: &CredentialRequest,
    request_was_encrypted: bool,
) -> Result<(), IssuanceError> {
    if let Some(re) = &cfg.issuer.request_encryption
        && re.encryption_required
        && !request_was_encrypted
    {
        return Err(IssuanceError::InvalidCredentialRequest(
            "this Credential Endpoint requires the Credential Request to be encrypted \
                 (OpenID4VCI L1192)"
                .to_string(),
        ));
    }

    let Some(params) = &req.credential_response_encryption else {
        return Ok(());
    };

    if !request_was_encrypted {
        return Err(IssuanceError::InvalidCredentialRequest(
            "credential_response_encryption requires the Credential Request itself to be \
             encrypted (OpenID4VCI L960)"
                .to_string(),
        ));
    }

    let Some(rs) = &cfg.issuer.response_encryption else {
        return Err(IssuanceError::InvalidCredentialRequest(
            "Credential Response encryption is not supported by this deployment".to_string(),
        ));
    };

    if params.jwk.get("alg").and_then(|v| v.as_str()).is_none() {
        return Err(IssuanceError::InvalidCredentialRequest(
            "credential_response_encryption.jwk must carry an `alg` member (OpenID4VCI L1188)"
                .to_string(),
        ));
    }

    if !rs.enc_values_supported.contains(&params.enc) {
        return Err(IssuanceError::InvalidCredentialRequest(format!(
            "credential_response_encryption.enc '{}' is not supported",
            params.enc
        )));
    }

    if let Some(zip) = &params.zip {
        return Err(IssuanceError::InvalidCredentialRequest(format!(
            "credential_response_encryption.zip '{zip}' is not supported; this Credential \
             Endpoint advertises no zip_values_supported (OpenID4VCI L856)"
        )));
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IssuedCredential {
    pub credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponse {
    pub credentials: Vec<IssuedCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
    /// EMVCo DPC display metadata, echoed from the `IssuanceTransaction`.
    ///
    /// **OpenID4VCI 1.0 defines no `display` member on a Credential Response.**
    /// Same divergence, same justification and same confinement as
    /// `CredentialOffer::display`; see that field's comment.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub display: Option<Vec<serde_json::Value>>,
}

/// `skip_all` is mandatory: the arguments include the bearer `access_token`, the
/// holder proofs and the whole `Config`.
#[tracing::instrument(
    skip_all,
    fields(
        credential_configuration_id = ?req.credential_configuration_id,
        format = ?req.format,
        request_encrypted = request_was_encrypted,
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn handle_credential_request(
    config: &Config,
    storage: &dyn Storage,
    access_token: &str,
    req: &CredentialRequest,
    nonce_secret: &NonceSecret,
    dpop: &DpopPresentation<'_>,
    now_unix: i64,
    request_was_encrypted: bool,
) -> Result<CredentialResponse, IssuanceError> {
    check_encryption_policy(config, req, request_was_encrypted)?;
    tracing::info!("credential request received");
    let mut tx = load_transaction_by_access_token(storage, access_token)
        .await?
        .ok_or_else(|| {
            // Never log the token itself, only that presenting it failed.
            tracing::warn!("access_token did not resolve to a live transaction");
            IssuanceError::InvalidGrant("invalid or expired access_token".into())
        })?;

    if tx.state != IssuanceState::Offered {
        return Err(IssuanceError::InvalidGrant(
            "credential offer has already been claimed".into(),
        ));
    }

    // RFC 9449 §6/§7: enforce the access token's key binding before doing any
    // issuance work. `tx.dpop_jkt` is how this resource server "reliably
    // identif[ies] whether an access token is DPoP-bound" (§6) — the AS and the
    // resource server are this same process sharing one `Storage`, which is the
    // "agreement by the authorization server and the protected resource" §6
    // permits as an alternative to a JWT `cnf.jkt` or introspection.
    match (&tx.dpop_jkt, dpop.scheme_is_dpop) {
        // Unbound token, Bearer scheme: the pre-DPoP path, unchanged.
        (None, false) => {}

        // §7.2: "such a protected resource MUST reject a DPoP-bound access
        // token received as a bearer token." Without this, an attacker holding
        // a stolen bound token simply downgrades to Bearer.
        (Some(_), false) => {
            return Err(IssuanceError::InvalidDpopProof(
                "this access token is DPoP-bound and MUST be presented with the DPoP scheme".into(),
            ));
        }

        // Deliberate deviation, stricter than RFC 9449, which leaves this case
        // undefined: accepting it would let a wallet conclude it has
        // sender-constraining when the token has no bound key at all — the
        // false assurance §5's "the client MUST discard the response" language
        // exists to prevent. Fail-closed.
        (None, true) => {
            return Err(IssuanceError::InvalidDpopProof(
                "this access token is not DPoP-bound and MUST be presented with the Bearer scheme"
                    .into(),
            ));
        }

        (Some(bound_jkt), true) => {
            // §7: "Requests to DPoP-protected resources MUST include both a
            // DPoP proof as per Section 4 and the access token."
            let proof_jwt = dpop.proof_jwt.ok_or_else(|| {
                IssuanceError::InvalidDpopProof(
                    "a DPoP proof is required when presenting a DPoP-bound access token".into(),
                )
            })?;
            // §7: "The DPoP proof MUST include the ath claim with a valid hash
            // of the associated access token." Absent `ath` here would be a
            // caller bug, not a client one — the HTTP layer always computes it.
            let expected_ath = dpop.ath.ok_or_else(|| {
                IssuanceError::Internal("dpop presentation is missing the computed ath".into())
            })?;

            let nonce_policy = crate::dpop::DpopNoncePolicy {
                mode: config.issuer.dpop.nonce_mode.clone(),
                secret: nonce_secret,
            };
            let verified = verify_dpop_proof(
                proof_jwt,
                dpop.htm,
                dpop.htu,
                Some(expected_ath),
                now_unix,
                config.issuer.dpop.max_age_secs,
                Some(&nonce_policy),
            )
            .inspect_err(|e| {
                tracing::warn!(error.kind = e.kind(), "dpop proof rejected at /credential");
            })?;

            // §4.3 check 12, second half / §7.1: "confirm that the public key
            // to which the access token is bound matches the public key from
            // the DPoP proof." This is the check that makes a stolen access
            // token useless without the private key.
            if &verified.jkt != bound_jkt {
                return Err(IssuanceError::InvalidDpopProof(
                    "the DPoP proof key does not match the key this access token is bound to"
                        .into(),
                ));
            }

            // §11.1 single-use, scoped to this endpoint's htu.
            claim_dpop_jti(
                storage,
                &verified,
                config.issuer.dpop.max_age_secs,
                now_unix,
            )
            .await?;
            // A thumbprint, so loggable per root AGENTS.md §4.5.
            tracing::info!(jkt = %verified.jkt, "dpop-bound access token accepted");
        }
    }

    // OpenID4VCI 1.0 Credential Request (L851): credential_configuration_id is
    // REQUIRED here -- this issuer never returns credential_identifiers via
    // authorization_details, so the exemption never applies -- and MUST
    // identify the Credential Type the Access Token was issued for. Checked
    // before proof verification so a misaddressed request fails on this cheap
    // check rather than after signature work -- GAP-VCI-02.
    match &req.credential_configuration_id {
        None => {
            return Err(IssuanceError::InvalidCredentialRequest(
                "credential_configuration_id is required".into(),
            ));
        }
        Some(id) if *id == tx.credential_type_id => {}
        Some(id) if config.credential_types.iter().any(|ct| ct.id == *id) => {
            return Err(IssuanceError::InvalidCredentialRequest(format!(
                "credential_configuration_id '{id}' does not identify the Credential Type \
                 this access_token was issued for"
            )));
        }
        Some(id) => {
            return Err(IssuanceError::UnknownCredentialConfiguration(id.clone()));
        }
    }

    let proofs = req
        .proofs
        .as_ref()
        .ok_or_else(|| IssuanceError::InvalidProof("missing proof in credential request".into()))?;

    let key_attestation_trust_store = foundry_core::trust::TrustStore::from_config(
        &config.issuer.key_attestation.trusted_anchors,
    )?;

    let verified_proofs = match proofs.resolve()? {
        ResolvedProofs::Jwt(proof_jwts) => {
            // `android.mode: required` makes this issuer accept only Google
            // Wallet's proof type. The parent `key_attestation.mode` continues
            // to govern the jwt path's own key-source rules.
            if config.issuer.key_attestation.android.mode == foundry_core::config::Mode::Required {
                return Err(IssuanceError::InvalidProof(
                    "the jwt proof type is not accepted: this issuer requires \
                     android_keystore_attestation"
                        .into(),
                ));
            }
            proof_jwts
                .iter()
                .map(|jwt_str| {
                    verify_holder_proof(
                        jwt_str,
                        &config.issuer.credential_issuer,
                        nonce_secret,
                        now_unix,
                        config.issuer.key_attestation.mode.clone(),
                        &key_attestation_trust_store,
                    )
                })
                .collect::<Result<Vec<_>, IssuanceError>>()?
        }
        ResolvedProofs::AndroidKeystoreAttestation(chains) => {
            crate::keystore_proof::verify_android_keystore_proofs(
                chains,
                &config.issuer.key_attestation.android,
                &key_attestation_trust_store,
                nonce_secret,
                now_unix,
            )?
        }
    };

    let cred_type = config
        .credential_types
        .iter()
        .find(|ct| ct.id == tx.credential_type_id)
        .ok_or_else(|| IssuanceError::UnknownCredentialType(tx.credential_type_id.clone()))?;

    // Resolved through `Config::credential_signing_key` rather than inline, so
    // that `build_issuer_metadata` advertises the algorithm of the key this
    // actually signs with. OpenID4VCI 1.0 L2223 requires the advertised
    // `credential_signing_alg_values_supported` value for `mso_mdoc` to match
    // the `alg` in the `IssuerAuth` COSE header produced below, so the two
    // sites cannot be allowed to resolve the key independently.
    let (_, issuer_key) = config
        .credential_signing_key()
        .ok_or_else(|| IssuanceError::InvalidRequest("no signing key configured".into()))?;

    let signer = FileSigner::from_pem_file(&issuer_key.private_key, issuer_key.alg.parse()?)?;
    let x5c = if let Some(ref path) = issuer_key.x5c {
        let pem_bytes = std::fs::read(path)
            .map_err(|e| IssuanceError::InvalidRequest(format!("failed to read x5c file: {e}")))?;
        Some(foundry_core::trust::build_x5c(&[pem_bytes])?)
    } else {
        None
    };

    let mut credentials = Vec::with_capacity(verified_proofs.len());
    for verified_proof in &verified_proofs {
        let holder_jwk_json = serde_json::to_value(&verified_proof.holder_jwk)
            .map_err(|e| IssuanceError::Serialization(e.to_string()))?;

        let credential_str = match cred_type.format.as_str() {
            "dc+sd-jwt" => {
                let vct = cred_type
                    .vct
                    .clone()
                    .unwrap_or_else(|| tx.credential_type_id.clone());

                let mut always_disclosed = Map::new();
                let mut selectively_disclosable = Map::new();

                for claim_def in &cred_type.claims {
                    if let Some(top_key) = claim_def.path.first()
                        && let Some(val) = tx.claims.get(top_key)
                    {
                        if claim_def.selectively_disclosable {
                            selectively_disclosable.insert(top_key.clone(), val.clone());
                        } else {
                            always_disclosed.insert(top_key.clone(), val.clone());
                        }
                    }
                }

                let (status_list_index, status_list_uri) = if config.issuer.status_list.enabled {
                    (
                        tx.status_list_index,
                        config
                            .issuer
                            .status_list
                            .public_base_url
                            .as_ref()
                            .map(|url| format!("{}/1", url.trim_end_matches('/'))),
                    )
                } else {
                    (None, None)
                };

                let sd_claims = IssuerClaims {
                    iss: config.issuer.credential_issuer.clone(),
                    // Omitted deliberately: a per-transaction `sub` is a static
                    // correlation identifier that no verifier needs and that
                    // leaks an internal transaction id into every presentation.
                    // See docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md §1.2(a).
                    sub: None,
                    iat: now_unix,
                    // Lifetime is per credential type; see
                    // CredentialType::resolved_validity_seconds.
                    exp: now_unix + cred_type.resolved_validity_seconds() as i64,
                    vct,
                    cnf_jwk: holder_jwk_json,
                    status_list_index,
                    status_list_uri,
                    always_disclosed,
                    selectively_disclosable,
                };

                build_sd_jwt_vc(sd_claims, &signer, x5c.clone()).map_err(|e| {
                    IssuanceError::InvalidRequest(format!("sd-jwt vc build failed: {e}"))
                })?
            }
            "mso_mdoc" => {
                // OpenID4VCI Format Profile / mdoc (L2235): `doctype` is
                // REQUIRED and identifies the Credential type per ISO 18013-5.
                // `doctype` is the SOLE source — there is deliberately no
                // fallback to `vct` or to the credential type id. Preferring
                // `vct` produced an SD-JWT-VC-style URL where an ISO 18013-5
                // reverse-DNS identifier belongs, which was GAP-VCI-12;
                // `Config::validate()` now rejects `vct` on an `mso_mdoc` type
                // outright, so a fallback chain here could only ever return
                // `doctype` while documenting a precedence rule that no longer
                // exists.
                //
                // Validation makes the `None` branch unreachable for a loaded
                // config. It stays a typed error rather than an unwrap because
                // this is a request path (root AGENTS.md §4.1).
                let doc_type = cred_type.doctype.clone().ok_or_else(|| {
                    IssuanceError::InvalidRequest(format!(
                        "credential type '{}' has format mso_mdoc but no doctype",
                        tx.credential_type_id
                    ))
                })?;

                // The namespace is NOT always the docType. ISO mDL carries its
                // elements in `org.iso.18013.5.1` under docType
                // `org.iso.18013.5.1.mDL`; EUDI attestations do use the docType
                // verbatim — EU Age Verification Annex A §4.1.2, "All attributes
                // belong to namespace `eu.europa.ec.av.1`". See
                // `foundry_core::config::mdoc`.
                let namespace = foundry_core::config::mdoc::namespace_for_doctype(&doc_type);

                // Elements come from the credential type's CONFIGURED claim
                // list, with the offer supplying only values — the same rule the
                // SD-JWT VC arm above follows. Iterating `tx.claims` instead
                // would let an offer introduce an element the configured type
                // never declared, defeating the profile checks
                // `Config::validate()` performs against the closed attribute set
                // of a doctype like `eu.europa.ec.av.1`.
                let mut elem_map = BTreeMap::new();
                for claim_def in &cred_type.claims {
                    if let Some(top_key) = claim_def.path.first()
                        && let Some(val) = tx.claims.get(top_key)
                    {
                        elem_map.insert(top_key.clone(), val.clone());
                    }
                }

                let mut ns_map = BTreeMap::new();
                ns_map.insert(namespace.to_string(), elem_map);

                let mdoc_claims = MdocClaims {
                    doc_type,
                    namespaces: ns_map,
                    device_key_jwk: holder_jwk_json,
                    signed_at: now_unix,
                    // Same per-credential-type lifetime as the SD-JWT VC branch
                    // above: a config knob that applied to only one of the two
                    // formats would be a defect, not a feature.
                    valid_until: now_unix + cred_type.resolved_validity_seconds() as i64,
                };

                let cbor_bytes = build_mdoc(mdoc_claims, &signer, x5c.clone()).map_err(|e| {
                    IssuanceError::InvalidRequest(format!("mdoc build failed: {e}"))
                })?;

                // OpenID4VCI 1.0 Credential Response (L976): Credential Formats
                // expressed as binary data MUST be base64url-encoded, not standard
                // base64 — a decoder expecting the URL-safe alphabet rejects '+',
                // '/' and '=' padding.
                B64URL.encode(cbor_bytes)
            }
            other => {
                return Err(IssuanceError::InvalidRequest(format!(
                    "unsupported credential format: {other}"
                )));
            }
        };

        credentials.push(IssuedCredential {
            credential: credential_str,
        });
    }

    tx.state = IssuanceState::Issued;
    save_transaction_with_indices(storage, &tx, 600, now_unix).await?;

    Ok(CredentialResponse {
        credentials,
        notification_id: None,
        // Echoed verbatim from the transaction, where create_offer pinned and
        // already validated it. Not re-validated here: a defect in an operator's
        // input belongs to the admin boundary that accepted it, not to the
        // wallet's /credential call.
        display: tx.credential_response_display.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        IssuanceTransaction, load_transaction, save_transaction_with_indices,
    };
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, DpopConfig, IssuerConfig, KeyEntry,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
        WalletFacingConfig,
    };
    use foundry_core::crypto::SignatureAlgorithm;
    use foundry_core::storage::SqliteStorage;
    use josekit::jwk::KeyPair as _;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jws::{ES256, JwsHeader};
    use josekit::jwt::{self, JwtPayload};
    use std::collections::BTreeMap as StdBTreeMap;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("c.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn test_config(key_path: &str) -> Config {
        let mut keys = StdBTreeMap::new();
        keys.insert(
            "issuer_key".to_string(),
            KeyEntry {
                private_key: key_path.to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );

        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "./foundry.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys,
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: Some("issuer_key".to_string()),
                    list_size: None,
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
                request_encryption: None,
                response_encryption: None,
                encrypted_pre_authorized_code: Default::default(),
                access_token_ttl_secs: 600,
                offer_by_reference: false,
                paso_metadata: Default::default(),
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![ClaimDef {
                    path: vec!["given_name".to_string()],
                    required: None,
                    selectively_disclosable: true,
                    display: vec![],
                }],
                validity_seconds: None,
                transaction_data_types: None,
            }],
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
                dc_api_accept_legacy_web_origin_audience: false,
            },
            logging: LoggingConfig::default(),
        }
    }

    fn test_secret() -> NonceSecret {
        NonceSecret::from_bytes([42u8; 32])
    }

    /// A real MAC-authenticated nonce, exactly as `POST /nonce` mints them.
    fn minted_nonce(secret: &NonceSecret, now: i64) -> String {
        crate::nonce::issue_nonce(secret, now).unwrap().c_nonce
    }

    fn generate_proof(c_nonce: &str, issuer: &str) -> (String, EcKeyPair) {
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
            .set_claim("aud", Some(serde_json::json!(issuer)))
            .unwrap();
        payload
            .set_claim("nonce", Some(serde_json::json!(c_nonce)))
            .unwrap();

        let private_jwk = keypair.to_jwk_private_key();
        let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        (jwt_str, keypair)
    }

    #[tokio::test]
    async fn issues_sd_jwt_vc_credential_successfully() {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let config = test_config(key_path.to_str().unwrap());
        let storage = test_storage().await;

        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));

        let tx = IssuanceTransaction {
            transaction_id: "tx-cred-1".to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: None,
            status_list_index: None,
            access_token: Some("at_secret_123".to_string()),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            credential_response_display: None,
        };
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let secret = test_secret();
        let nonce = minted_nonce(&secret, 1_700_000_000);
        let (proof_jwt, _) = generate_proof(&nonce, "https://issuer.example.com");

        let req = CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest::from_jwts(vec![proof_jwt])),
            credential_response_encryption: None,
        };

        let res = handle_credential_request(
            &config,
            &storage,
            "at_secret_123",
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_010,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.credentials.len(), 1);
        assert!(!res.credentials[0].credential.is_empty());

        let updated_tx = load_transaction(&storage, "tx-cred-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_tx.state, IssuanceState::Issued);
    }

    #[tokio::test]
    async fn required_android_mode_rejects_a_jwt_proof() {
        // Same setup as `issues_sd_jwt_vc_credential_successfully` above, with
        // `android.mode` made mandatory: a jwt proof must then be rejected
        // before any credential is issued, naming the required proof type.
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.issuer.key_attestation.android.mode = Mode::Required;
        let storage = test_storage().await;

        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));

        let tx = IssuanceTransaction {
            transaction_id: "tx-cred-android-required".to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: Some("code-android-required".to_string()),
            tx_code: None,
            status_list_index: None,
            access_token: Some("at_secret_android_required".to_string()),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            credential_response_display: None,
        };
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let secret = test_secret();
        let nonce = minted_nonce(&secret, 1_700_000_000);
        let (proof_jwt, _) = generate_proof(&nonce, "https://issuer.example.com");

        let req = CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest::from_jwts(vec![proof_jwt])),
            credential_response_encryption: None,
        };

        let err = handle_credential_request(
            &config,
            &storage,
            "at_secret_android_required",
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_010,
            false,
        )
        .await
        .expect_err("a jwt proof must be rejected when android.mode is Required");

        assert!(
            matches!(err, IssuanceError::InvalidProof(ref m)
                if m.contains("requires android_keystore_attestation")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn issues_credential_with_kid_key_attestation_proof() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use foundry_core::pki::{issue_leaf, new_ca};
        use foundry_core::trust::parse_cert_pem;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        // Wallet Provider CA that will be configured as a trusted anchor.
        let ca = new_ca("Test Wallet Provider Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "wallet-provider.example.com",
            &["wallet-provider.example.com".to_string()],
            365,
        )
        .unwrap();
        let ca_path = key_dir.path().join("wallet-provider-ca.pem");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.issuer.key_attestation.mode = Mode::Required;
        config.issuer.key_attestation.trusted_anchors = vec![foundry_core::config::TrustAnchor {
            name: "wallet-provider-ca".to_string(),
            certs: ca_path.to_str().unwrap().to_string(),
        }];

        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));

        let tx = IssuanceTransaction {
            transaction_id: "tx-cred-2".to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: Some("code-456".to_string()),
            tx_code: None,
            status_list_index: None,
            access_token: Some("at_secret_456".to_string()),
            state: IssuanceState::Offered,
            created_at: now,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            credential_response_display: None,
        };
        save_transaction_with_indices(&storage, &tx, 600, now)
            .await
            .unwrap();

        let secret = test_secret();
        let nonce = minted_nonce(&secret, now);

        // Build a key attestation whose sole attested key matches the outer proof's signer.
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut holder_pub = keypair.to_jwk_public_key();
        holder_pub.set_algorithm("ES256");

        let leaf_der = {
            let cert = parse_cert_pem(leaf.cert_pem.as_bytes()).unwrap();
            use x509_cert::der::Encode;
            cert.to_der().unwrap()
        };
        let x5c = vec![B64STD.encode(&leaf_der)];
        let attestation_header =
            serde_json::json!({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c});
        let attestation_payload = serde_json::json!({
            "iss": "https://wallet-provider.example.com",
            "iat": now,
            "exp": now + 100_000,
            "nonce": nonce,
            "attested_keys": [serde_json::to_value(&holder_pub).unwrap()],
        });
        let h_b64 = B64URL.encode(serde_json::to_vec(&attestation_header).unwrap());
        let p_b64 = B64URL.encode(serde_json::to_vec(&attestation_payload).unwrap());
        let signing_input = format!("{h_b64}.{p_b64}");
        let leaf_signer = foundry_core::crypto::FileSigner::from_pem(
            leaf.key_pem.as_bytes(),
            SignatureAlgorithm::Es256,
        )
        .unwrap();
        let sig_b64 = B64URL.encode(
            foundry_core::crypto::Signer::sign(&leaf_signer, signing_input.as_bytes()).unwrap(),
        );
        let attestation_jwt = format!("{signing_input}.{sig_b64}");

        let mut proof_header = JwsHeader::new();
        proof_header.set_token_type("openid4vci-proof+jwt");
        proof_header
            .set_claim("kid", Some(serde_json::json!("0")))
            .unwrap();
        proof_header
            .set_claim("key_attestation", Some(serde_json::json!(attestation_jwt)))
            .unwrap();
        let mut proof_payload = JwtPayload::new();
        proof_payload
            .set_claim("aud", Some(serde_json::json!("https://issuer.example.com")))
            .unwrap();
        proof_payload
            .set_claim("nonce", Some(serde_json::json!(nonce)))
            .unwrap();
        let private_jwk = keypair.to_jwk_private_key();
        let proof_signer = ES256.signer_from_jwk(&private_jwk).unwrap();
        let proof_jwt =
            jwt::encode_with_signer(&proof_payload, &proof_header, &proof_signer).unwrap();

        let req = CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest::from_jwts(vec![proof_jwt])),
            credential_response_encryption: None,
        };

        let res = handle_credential_request(
            &config,
            &storage,
            "at_secret_456",
            &req,
            &secret,
            &bearer_presentation(),
            now + 10,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.credentials.len(), 1);
    }

    // --- RFC 9449 §6/§7/§7.1/§7.2 -- the design's §5.3 decision table ---

    const CRED_HTU: &str = "https://issuer.example.com/credential";

    /// A fresh signing key plus a `Config` pointed at it -- the setup every
    /// test in this module needs, consolidated so the DPoP tests below don't
    /// duplicate it a third time.
    fn setup_config() -> (Config, tempfile::TempDir) {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();
        let config = test_config(key_path.to_str().unwrap());
        (config, key_dir)
    }

    fn sample_offered_tx(
        id: &str,
        access_token: &str,
        dpop_jkt: Option<String>,
    ) -> IssuanceTransaction {
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        IssuanceTransaction {
            transaction_id: id.to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: None,
            tx_code: None,
            status_list_index: None,
            access_token: Some(access_token.to_string()),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt,
            credential_response_display: None,
        }
    }

    /// Seed a caller-chosen access token, so the test can compute a matching
    /// `ath`/proof against it before the transaction even exists.
    async fn seed_offered_tx_with_exact_token(
        storage: &SqliteStorage,
        id: &str,
        token: &str,
        dpop_jkt: Option<String>,
    ) {
        let tx = sample_offered_tx(id, token, dpop_jkt);
        save_transaction_with_indices(storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();
    }

    /// Seed a generated access token and return it.
    async fn seed_offered_tx_with_token(
        storage: &SqliteStorage,
        id: &str,
        dpop_jkt: Option<String>,
    ) -> String {
        let token = format!("at_{id}");
        seed_offered_tx_with_exact_token(storage, id, &token, dpop_jkt).await;
        token
    }

    /// A full, valid `CredentialRequest` -- fresh nonce, fresh holder proof --
    /// so the DPoP "accepted" test rows exercise the whole endpoint, not just
    /// the binding check.
    fn sample_request(config: &Config, secret: &NonceSecret, now: i64) -> CredentialRequest {
        let nonce = minted_nonce(secret, now);
        let (proof_jwt, _keypair) = generate_proof(&nonce, &config.issuer.credential_issuer);
        CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest::from_jwts(vec![proof_jwt])),
            credential_response_encryption: None,
        }
    }

    fn bearer_presentation<'a>() -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: false,
            proof_jwt: None,
            htm: "POST",
            htu: CRED_HTU,
            ath: None,
        }
    }

    /// A `DPoP`-scheme presentation carrying `proof` and the `ath` for `token`.
    fn dpop_presentation<'a>(proof: Option<&'a str>, ath: &'a str) -> DpopPresentation<'a> {
        DpopPresentation {
            scheme_is_dpop: true,
            proof_jwt: proof,
            htm: "POST",
            htu: CRED_HTU,
            ath: Some(ath),
        }
    }

    /// A DPoP proof for `POST /credential` bound to `access_token`.
    /// Returns `(proof_jwt, jkt)`.
    fn credential_proof(access_token: &str, jti: &str, now: i64) -> (String, String) {
        let kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let public = kp.to_jwk_public_key();

        let mut header = JwsHeader::new();
        header.set_token_type("dpop+jwt");
        header.set_jwk(public);

        let ath = crate::dpop::access_token_hash(access_token);
        let mut payload = JwtPayload::new();
        payload.set_claim("htm", Some("POST".into())).unwrap();
        payload.set_claim("htu", Some(CRED_HTU.into())).unwrap();
        payload.set_claim("iat", Some(now.into())).unwrap();
        payload.set_claim("jti", Some(jti.into())).unwrap();
        payload.set_claim("ath", Some(ath.clone().into())).unwrap();

        let signer = ES256.signer_from_jwk(&kp.to_jwk_private_key()).unwrap();
        let proof = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let jkt =
            crate::dpop::verify_dpop_proof(&proof, "POST", CRED_HTU, Some(&ath), now, 300, None)
                .unwrap()
                .jkt;
        (proof, jkt)
    }

    #[tokio::test]
    async fn an_unbound_token_with_the_bearer_scheme_is_accepted() {
        // Row 1: today's path. This is the regression that proves DPoP is
        // additive and does not break existing wallets.
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token = seed_offered_tx_with_token(&storage, "tx-cred-bearer", None).await;
        let secret = test_secret();
        let req = sample_request(&config, &secret, 1_700_000_000);

        let res = handle_credential_request(
            &config,
            &storage,
            &token,
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_000,
            false,
        )
        .await;
        assert!(
            res.is_ok(),
            "an unbound token must still work with Bearer: {res:?}"
        );
    }

    #[tokio::test]
    async fn a_bound_token_presented_as_bearer_is_rejected() {
        // Row 2 / §7.2: "such a protected resource MUST reject a DPoP-bound
        // access token received as a bearer token." Without this, an attacker
        // holding a stolen bound token downgrades to Bearer and the binding
        // buys nothing.
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token =
            seed_offered_tx_with_token(&storage, "tx-cred-downgrade", Some("some-jkt".to_string()))
                .await;
        let secret = test_secret();
        let req = sample_request(&config, &secret, 1_700_000_000);

        let e = handle_credential_request(
            &config,
            &storage,
            &token,
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_000,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_bound_token_with_a_matching_proof_is_accepted() {
        // Row 3 / §7.1 + §4.3 check 12.
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token = "at_cred_dpop_ok";
        let (proof, jkt) = credential_proof(token, "j-cred-ok", 1_700_000_000);
        seed_offered_tx_with_exact_token(&storage, "tx-cred-ok", token, Some(jkt)).await;

        let secret = test_secret();
        let req = sample_request(&config, &secret, 1_700_000_000);
        let ath = crate::dpop::access_token_hash(token);
        let res = handle_credential_request(
            &config,
            &storage,
            token,
            &req,
            &secret,
            &dpop_presentation(Some(&proof), &ath),
            1_700_000_000,
            false,
        )
        .await;
        assert!(res.is_ok(), "a matching proof must be accepted: {res:?}");
    }

    #[tokio::test]
    async fn a_bound_token_with_another_keys_proof_is_rejected() {
        // Row 3 negative / §7.1: "check that the public key of the DPoP proof
        // matches the public key to which the access token is bound". This is
        // the check that makes a stolen token useless.
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token = "at_cred_dpop_wrongkey";
        let (proof, _wrong_jkt) = credential_proof(token, "j-cred-wrong", 1_700_000_000);
        seed_offered_tx_with_exact_token(
            &storage,
            "tx-cred-wrongkey",
            token,
            Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string()),
        )
        .await;

        let secret = test_secret();
        let req = sample_request(&config, &secret, 1_700_000_000);
        let ath = crate::dpop::access_token_hash(token);
        let e = handle_credential_request(
            &config,
            &storage,
            token,
            &req,
            &secret,
            &dpop_presentation(Some(&proof), &ath),
            1_700_000_000,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_bound_token_with_no_proof_at_all_is_rejected() {
        // Row 4 / §7: "Requests to DPoP-protected resources MUST include both
        // a DPoP proof as per Section 4 and the access token."
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token =
            seed_offered_tx_with_token(&storage, "tx-cred-noproof", Some("some-jkt".to_string()))
                .await;

        let secret = test_secret();
        let req = sample_request(&config, &secret, 1_700_000_000);
        let ath = crate::dpop::access_token_hash(&token);
        let e = handle_credential_request(
            &config,
            &storage,
            &token,
            &req,
            &secret,
            &dpop_presentation(None, &ath),
            1_700_000_000,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn an_unbound_token_with_the_dpop_scheme_is_rejected() {
        // Row 5 — a DELIBERATE DEVIATION, stricter than RFC 9449, which leaves
        // this case undefined. Accepting it would let a wallet conclude it has
        // sender-constraining when the token has no bound key at all: the same
        // false assurance §5's "the client MUST discard the response" language
        // exists to prevent. Fail-closed.
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token = "at_cred_unbound_dpop";
        let (proof, _) = credential_proof(token, "j-cred-unbound", 1_700_000_000);
        seed_offered_tx_with_exact_token(&storage, "tx-cred-unbound", token, None).await;

        let secret = test_secret();
        let req = sample_request(&config, &secret, 1_700_000_000);
        let ath = crate::dpop::access_token_hash(token);
        let e = handle_credential_request(
            &config,
            &storage,
            token,
            &req,
            &secret,
            &dpop_presentation(Some(&proof), &ath),
            1_700_000_000,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn a_credential_proof_replayed_at_the_credential_endpoint_is_rejected() {
        // §11.1 again, this time at the protected resource. Note the offer is
        // single-use anyway, so this asserts the *proof* is rejected on its own
        // terms rather than incidentally by the state check -- hence a fresh
        // transaction bound to the same key for the second attempt.
        let (config, _key_dir) = setup_config();
        let storage = test_storage().await;
        let token = "at_cred_replay";
        let (proof, jkt) = credential_proof(token, "j-cred-replay", 1_700_000_000);
        let ath = crate::dpop::access_token_hash(token);

        seed_offered_tx_with_exact_token(&storage, "tx-cred-replay-1", token, Some(jkt.clone()))
            .await;
        let secret = test_secret();
        let req1 = sample_request(&config, &secret, 1_700_000_000);
        handle_credential_request(
            &config,
            &storage,
            token,
            &req1,
            &secret,
            &dpop_presentation(Some(&proof), &ath),
            1_700_000_000,
            false,
        )
        .await
        .unwrap();

        // A different transaction, same token value and same bound key, so the
        // only thing that can reject the second call is the jti claim.
        seed_offered_tx_with_exact_token(&storage, "tx-cred-replay-2", token, Some(jkt)).await;
        let req2 = sample_request(&config, &secret, 1_700_000_000);
        let e = handle_credential_request(
            &config,
            &storage,
            token,
            &req2,
            &secret,
            &dpop_presentation(Some(&proof), &ath),
            1_700_000_000,
            false,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("jti"), "got: {e}");
    }

    // --- OpenID4VCI Credential Request/Response encryption policy ---

    fn wallet_enc_jwk() -> serde_json::Value {
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        let signer = foundry_core::crypto::FileSigner::from_pem(
            km.private_pem.as_bytes(),
            SignatureAlgorithm::Es256,
        )
        .unwrap();
        let mut jwk = foundry_core::crypto::Signer::public_jwk(&signer).unwrap();
        if let Some(o) = jwk.as_object_mut() {
            o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
        }
        jwk
    }

    fn req_with_response_encryption(
        jwk: serde_json::Value,
        enc: &str,
        zip: Option<&str>,
    ) -> CredentialRequest {
        CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: None,
            proofs: None,
            credential_response_encryption: Some(CredentialResponseEncryptionParams {
                jwk,
                enc: enc.to_string(),
                zip: zip.map(|z| z.to_string()),
            }),
        }
    }

    fn plain_req() -> CredentialRequest {
        CredentialRequest {
            credential_configuration_id: Some("pid".to_string()),
            format: None,
            proofs: None,
            credential_response_encryption: None,
        }
    }

    /// A config with an issuer signing key on disk, optionally with both
    /// encryption blocks enabled. The `TempDir` is returned so the caller keeps
    /// the key file alive for the duration of the test.
    fn cfg_with_encryption(enabled: bool, required: bool) -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();
        let mut cfg = test_config(key_path.to_str().unwrap());
        if enabled {
            cfg.issuer.request_encryption = Some(foundry_core::config::RequestEncryptionConfig {
                keys: vec!["enc".to_string()],
                enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
                encryption_required: required,
            });
            cfg.issuer.response_encryption = Some(foundry_core::config::ResponseEncryptionConfig {
                enc_values_supported: vec!["A128GCM".to_string(), "A256GCM".to_string()],
                encryption_required: required,
            });
        }
        (cfg, dir)
    }

    #[test]
    fn plaintext_request_is_accepted_when_encryption_is_off() {
        let (cfg, _dir) = cfg_with_encryption(false, false);
        assert!(check_encryption_policy(&cfg, &plain_req(), false).is_ok());
    }

    #[test]
    fn plaintext_request_is_rejected_when_request_encryption_is_required() {
        let (cfg, _dir) = cfg_with_encryption(true, true);
        let err = check_encryption_policy(&cfg, &plain_req(), false).unwrap_err();
        assert!(
            matches!(err, IssuanceError::InvalidCredentialRequest(_)),
            "got: {err}"
        );
        assert!(err.to_string().contains("encrypted"), "got: {err}");
    }

    #[test]
    fn response_encryption_over_a_plaintext_request_is_rejected() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A128GCM", None);
        let err = check_encryption_policy(&cfg, &req, false).unwrap_err();
        assert!(err.to_string().contains("L960"), "got: {err}");
    }

    #[test]
    fn response_encryption_is_rejected_when_the_feature_is_off() {
        let (cfg, _dir) = cfg_with_encryption(false, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A128GCM", None);
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("not supported"), "got: {err}");
    }

    #[test]
    fn response_encryption_requires_an_alg_on_the_wallet_jwk() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let mut jwk = wallet_enc_jwk();
        if let Some(o) = jwk.as_object_mut() {
            o.remove("alg");
        }
        let req = req_with_response_encryption(jwk, "A128GCM", None);
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("alg"), "got: {err}");
    }

    #[test]
    fn response_encryption_rejects_an_unadvertised_enc() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A192GCM", None);
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("A192GCM"), "got: {err}");
    }

    #[test]
    fn response_encryption_rejects_zip() {
        let (cfg, _dir) = cfg_with_encryption(true, false);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A128GCM", Some("DEF"));
        let err = check_encryption_policy(&cfg, &req, true).unwrap_err();
        assert!(err.to_string().contains("zip"), "got: {err}");
    }

    #[test]
    fn a_well_formed_encrypted_pair_is_accepted() {
        let (cfg, _dir) = cfg_with_encryption(true, true);
        let req = req_with_response_encryption(wallet_enc_jwk(), "A256GCM", None);
        assert!(check_encryption_policy(&cfg, &req, true).is_ok());
    }

    /// Run one full `handle_credential_request` and return the issued SD-JWT VC
    /// compact presentation, so lifetime and claim-shape tests share one setup.
    async fn issue_for_test_with_claims(
        config: &Config,
        credential_type_id: &str,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> String {
        let res = issue_response_for_test(config, credential_type_id, claims, None).await;
        assert_eq!(res.credentials.len(), 1);
        res.credentials[0].credential.clone()
    }

    /// The full-response variant of [`issue_for_test_with_claims`], which
    /// discards everything but the credential string.
    ///
    /// `credential_response_display` is seeded onto the transaction exactly as
    /// `create_offer` would, so a test can assert what `/credential` does with
    /// it without reaching for a second harness.
    async fn issue_response_for_test(
        config: &Config,
        credential_type_id: &str,
        claims: serde_json::Map<String, serde_json::Value>,
        credential_response_display: Option<Vec<serde_json::Value>>,
    ) -> CredentialResponse {
        let storage = test_storage().await;

        let tx = IssuanceTransaction {
            transaction_id: "tx-cred-1".to_string(),
            credential_type_id: credential_type_id.to_string(),
            claims,
            pre_authorized_code: Some("code-123".to_string()),
            tx_code: None,
            status_list_index: None,
            access_token: Some("at_secret_123".to_string()),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
            redirect_uri: None,
            issuer_state: None,
            authorization_code: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            credential_response_display,
        };
        save_transaction_with_indices(&storage, &tx, 600, 1_700_000_000)
            .await
            .unwrap();

        let secret = test_secret();
        let nonce = minted_nonce(&secret, 1_700_000_000);
        let (proof_jwt, _) = generate_proof(&nonce, "https://issuer.example.com");

        let req = CredentialRequest {
            credential_configuration_id: Some(credential_type_id.to_string()),
            format: Some("dc+sd-jwt".to_string()),
            proofs: Some(ProofsRequest::from_jwts(vec![proof_jwt])),
            credential_response_encryption: None,
        };

        handle_credential_request(
            config,
            &storage,
            "at_secret_123",
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_010,
            false,
        )
        .await
        .unwrap()
    }

    /// The issuer JWT payload of an SD-JWT VC issuer presentation.
    fn payload_of(presentation: &str) -> serde_json::Map<String, serde_json::Value> {
        let jwt = presentation.split('~').next().unwrap();
        let b64 = jwt.split('.').nth(1).unwrap();
        let bytes = B64URL.decode(b64).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Disclosed claim name -> value, decoded from the `~`-separated disclosures.
    fn disclosures_of(presentation: &str) -> std::collections::BTreeMap<String, serde_json::Value> {
        presentation
            .split('~')
            .skip(1)
            .filter(|s| !s.is_empty())
            .map(|d| {
                let raw = B64URL.decode(d).unwrap();
                let arr: Vec<serde_json::Value> = serde_json::from_slice(&raw).unwrap();
                (arr[1].as_str().unwrap().to_string(), arr[2].clone())
            })
            .collect()
    }

    /// A DPC-shaped credential type, as shipped in the quickstart config:
    /// `credential_id` and `network` mandatory *and* selectively disclosable,
    /// `card_id` optional.
    fn dpc_config(key_path: &str) -> Config {
        let mut config = test_config(key_path);
        config.credential_types[0].id = "com.emvco.dpc.card".to_string();
        config.credential_types[0].vct = Some("com.emvco.dpc.card".to_string());
        config.credential_types[0].validity_seconds = Some(43_200);
        config.credential_types[0].claims = vec![
            ClaimDef {
                path: vec!["credential_id".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["network".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["card_id".to_string()],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            },
        ];
        config
    }

    fn issuer_key_for_test() -> (tempfile::TempDir, String) {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();
        let s = key_path.to_str().unwrap().to_string();
        (key_dir, s)
    }

    /// The co-badged case: `network` carries an array. Required claims must land
    /// in the disclosures rather than inline in the payload, and an unsupplied
    /// optional claim must be absent entirely.
    #[tokio::test]
    async fn dpc_shaped_type_issues_with_claims_in_disclosures() {
        let (_key_dir, key_path) = issuer_key_for_test();
        let config = dpc_config(&key_path);

        let mut claims = serde_json::Map::new();
        claims.insert(
            "credential_id".to_string(),
            serde_json::json!("urn:uuid:9f2b7a2e-3b74-4a0d-9b1a-0e6a91f5d2c8"),
        );
        claims.insert(
            "network".to_string(),
            serde_json::json!(["example_network", "example_network_2"]),
        );
        // card_id deliberately not supplied.

        let credential = issue_for_test_with_claims(&config, "com.emvco.dpc.card", claims).await;
        let payload = payload_of(&credential);

        assert_eq!(payload["vct"], "com.emvco.dpc.card");
        assert!(!payload.contains_key("sub"), "sub must be omitted");
        assert!(
            !payload.contains_key("credential_id"),
            "a selectively-disclosable claim must not be inline in the payload"
        );
        assert!(!payload.contains_key("network"));
        assert!(payload.contains_key("_sd"), "expected _sd digests");

        let named = disclosures_of(&credential);
        assert_eq!(
            named["credential_id"],
            serde_json::json!("urn:uuid:9f2b7a2e-3b74-4a0d-9b1a-0e6a91f5d2c8")
        );
        assert_eq!(
            named["network"],
            serde_json::json!(["example_network", "example_network_2"]),
            "an array-valued network must survive as an array"
        );
        assert!(
            !named.contains_key("card_id"),
            "an unsupplied optional claim must not be disclosed"
        );
    }

    /// The single-network case: `network` as a plain string, which the DPC schema
    /// allows alongside the array form.
    #[tokio::test]
    async fn dpc_shaped_type_accepts_a_single_string_network() {
        let (_key_dir, key_path) = issuer_key_for_test();
        let config = dpc_config(&key_path);

        let mut claims = serde_json::Map::new();
        claims.insert(
            "credential_id".to_string(),
            serde_json::json!("urn:uuid:abc"),
        );
        claims.insert("network".to_string(), serde_json::json!("example_network"));

        let credential = issue_for_test_with_claims(&config, "com.emvco.dpc.card", claims).await;
        let named = disclosures_of(&credential);

        assert_eq!(
            named["network"],
            serde_json::json!("example_network"),
            "a string-valued network must survive as a string, not be wrapped"
        );
    }

    /// `exp` must follow the credential type's configured lifetime rather than
    /// a hardcoded year.
    #[tokio::test]
    async fn credential_exp_follows_the_configured_validity() {
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("issuer.pem");
        let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut config = test_config(key_path.to_str().unwrap());
        config.credential_types[0].validity_seconds = Some(43_200);

        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        let credential = issue_for_test_with_claims(&config, "pid", claims).await;
        let payload = payload_of(&credential);

        let iat = payload["iat"].as_i64().expect("iat");
        let exp = payload["exp"].as_i64().expect("exp");
        assert_eq!(
            exp - iat,
            43_200,
            "exp must be iat + validity_seconds, got iat={iat} exp={exp}"
        );
        assert!(
            !payload.contains_key("sub"),
            "sub must not be present (it is omitted by default)"
        );
    }

    fn dpc_display() -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "locale": "en-US",
            "card": {
                "last_four": "4444",
                "card_art": [
                    { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
                ]
            }
        })]
    }

    fn dpc_test_claims() -> serde_json::Map<String, serde_json::Value> {
        let mut claims = serde_json::Map::new();
        claims.insert("credential_id".to_string(), serde_json::json!("cred-1"));
        claims.insert("network".to_string(), serde_json::json!("example_network"));
        claims
    }

    /// The response half of design §3.6: whatever was pinned on the transaction
    /// at offer time appears on the Credential Response, unchanged.
    ///
    /// Validation is deliberately NOT repeated at `/credential`. The object was
    /// validated at the admin boundary and has been inert in storage since;
    /// re-validating would turn an operator's input defect into a wallet-facing
    /// `/credential` failure.
    #[tokio::test]
    async fn the_credential_response_echoes_the_transactions_display_metadata() {
        let (_key_dir, key_path) = issuer_key_for_test();
        let config = dpc_config(&key_path);

        let res = issue_response_for_test(
            &config,
            "com.emvco.dpc.card",
            dpc_test_claims(),
            Some(dpc_display()),
        )
        .await;

        let display = res
            .display
            .as_ref()
            .expect("the credential response must echo the transaction's display metadata");
        assert_eq!(display[0]["card"]["last_four"], "4444");
        assert_eq!(display[0]["card"]["card_art"][0]["theme"], "DEFAULT");
        assert!(
            res.credentials[0].credential.contains('~'),
            "the credential itself must still be issued"
        );
    }

    /// The no-regression counterpart: a transaction with no display metadata
    /// produces a response with no `display` key at all.
    #[tokio::test]
    async fn a_credential_response_omits_display_when_the_transaction_has_none() {
        let (_key_dir, key_path) = issuer_key_for_test();
        let config = dpc_config(&key_path);

        let res =
            issue_response_for_test(&config, "com.emvco.dpc.card", dpc_test_claims(), None).await;

        assert!(res.display.is_none());
        let value = serde_json::to_value(&res).unwrap();
        assert!(
            !value.as_object().unwrap().contains_key("display"),
            "got: {value}"
        );
    }

    /// The no-regression assertion for the Credential Response: with no display
    /// metadata the key must be absent entirely, not present as `null`.
    /// Asserted on the serialised keys for the same reason as the offer's
    /// counterpart in `offer.rs`.
    #[test]
    fn a_credential_response_without_display_serialises_without_a_display_key() {
        let response = CredentialResponse {
            credentials: vec![IssuedCredential {
                credential: "eyJ...".to_string(),
            }],
            notification_id: None,
            display: None,
        };
        let value = serde_json::to_value(&response).unwrap();
        assert!(
            !value.as_object().unwrap().contains_key("display"),
            "got: {value}"
        );
    }

    /// An `eu.europa.ec.av.1` credential type declaring ONLY `age_over_18` —
    /// the minimum EU Age Verification Annex A §4.1.2 admits. Deliberately
    /// narrower than the shipped config's two attributes, so a test can offer a
    /// value for an element the type never declared.
    fn av_config(key_path: &str) -> Config {
        let mut config = test_config(key_path);
        config.credential_types[0].id = "eu.europa.ec.av.1".to_string();
        config.credential_types[0].format = "mso_mdoc".to_string();
        // No vct: an mdoc is identified by doctype (OpenID4VCI L2235), and
        // Config::validate() rejects vct on an mso_mdoc type.
        config.credential_types[0].vct = None;
        config.credential_types[0].doctype = Some("eu.europa.ec.av.1".to_string());
        config.credential_types[0].claims = vec![ClaimDef {
            path: vec!["age_over_18".to_string()],
            required: Some(true),
            selectively_disclosable: false,
            display: vec![],
        }];
        config
    }

    /// Element identifiers present in an issued mdoc credential, sorted.
    ///
    /// Decodes rather than trusting: base64url → CBOR `IssuerSigned` →
    /// `nameSpaces[ns]` → each `#6.24(bstr .cbor IssuerSignedItem)` →
    /// `elementIdentifier`.
    fn issued_elements(credential_b64: &str, namespace: &str) -> Vec<String> {
        let bytes = B64URL.decode(credential_b64).expect("base64url");
        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).expect("CBOR");
        let map = decoded.as_map().expect("IssuerSigned map");
        let namespaces = map
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(s) if s == "nameSpaces" => Some(v),
                _ => None,
            })
            .expect("nameSpaces")
            .as_map()
            .expect("nameSpaces is a map");
        let items = namespaces
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(s) if s == namespace => Some(v),
                _ => None,
            })
            .unwrap_or_else(|| panic!("namespace {namespace} is present"))
            .as_array()
            .expect("a namespace holds an array of IssuerSignedItemBytes");

        let mut out = Vec::new();
        for item in items {
            let inner = match item {
                ciborium::Value::Tag(24, b) => match b.as_ref() {
                    ciborium::Value::Bytes(bytes) => bytes.clone(),
                    other => panic!("tag 24 must wrap a byte string, got {other:?}"),
                },
                other => panic!("elements travel tag-24 embedded, got {other:?}"),
            };
            let item: ciborium::Value =
                ciborium::from_reader(inner.as_slice()).expect("IssuerSignedItem CBOR");
            out.push(
                item.as_map()
                    .expect("IssuerSignedItem map")
                    .iter()
                    .find_map(|(k, v)| match k {
                        ciborium::Value::Text(s) if s == "elementIdentifier" => v.as_text(),
                        _ => None,
                    })
                    .expect("elementIdentifier")
                    .to_string(),
            );
        }
        out.sort();
        out
    }

    /// An offer may not introduce an mdoc data element the credential type did
    /// not declare.
    ///
    /// `Config::validate()` checks a credential type's claim list against the
    /// governing profile — for `eu.europa.ec.av.1`, Annex A §4.1.2's closed
    /// attribute set. That check is worthless if the Credential Endpoint then
    /// emits whatever the offer happened to carry, so the element **set** comes
    /// from configuration and the offer supplies only **values**. The SD-JWT VC
    /// arm has always worked this way; the two arms disagreeing was the defect.
    #[tokio::test]
    async fn an_offer_supplied_element_absent_from_config_is_not_issued() {
        let (_key_dir, key_path) = issuer_key_for_test();
        let config = av_config(&key_path);

        let mut claims = serde_json::Map::new();
        claims.insert("age_over_18".to_string(), serde_json::json!(true));
        // Never declared by the credential type above. An offer carrying it must
        // not be able to smuggle it into the credential.
        claims.insert(
            "issuing_country".to_string(),
            serde_json::json!("Deutschland"),
        );

        let credential = issue_for_test_with_claims(&config, "eu.europa.ec.av.1", claims).await;

        assert_eq!(
            issued_elements(&credential, "eu.europa.ec.av.1"),
            vec!["age_over_18".to_string()],
            "an element the credential type never declared must not be issued"
        );
    }
}
