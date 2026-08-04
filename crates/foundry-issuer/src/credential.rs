//! OpenID4VCI credential endpoint business logic.

use crate::dpop::{claim_dpop_jti, verify_dpop_proof, DpopPresentation};
use crate::error::IssuanceError;
use crate::nonce::NonceSecret;
use crate::proof::{verify_holder_proof, ProofsRequest};
use crate::transaction::{
    load_transaction_by_access_token, save_transaction_with_indices, IssuanceState,
};
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as B64STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::Config;
use foundry_core::crypto::FileSigner;
use foundry_core::storage::Storage;
use foundry_mdoc::builder::{build_mdoc, MdocClaims};
use foundry_sd_jwt_vc::builder::{build_sd_jwt_vc, IssuerClaims};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CredentialRequest {
    pub credential_configuration_id: Option<String>,
    pub format: Option<String>,
    pub proofs: Option<ProofsRequest>,
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
}

/// `skip_all` is mandatory: the arguments include the bearer `access_token`, the
/// holder proofs and the whole `Config`.
#[tracing::instrument(
    skip_all,
    fields(
        credential_configuration_id = ?req.credential_configuration_id,
        format = ?req.format,
    )
)]
pub async fn handle_credential_request(
    config: &Config,
    storage: &dyn Storage,
    access_token: &str,
    req: &CredentialRequest,
    nonce_secret: &NonceSecret,
    dpop: &DpopPresentation<'_>,
    now_unix: i64,
) -> Result<CredentialResponse, IssuanceError> {
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

    let proof_jwts = req
        .proofs
        .as_ref()
        .map(|p| p.jwt.as_slice())
        .filter(|jwts| !jwts.is_empty())
        .ok_or_else(|| IssuanceError::InvalidProof("missing proof in credential request".into()))?;

    let key_attestation_trust_store = foundry_core::trust::TrustStore::from_config(
        &config.issuer.key_attestation.trusted_anchors,
    )?;

    let verified_proofs = proof_jwts
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
        .collect::<Result<Vec<_>, IssuanceError>>()?;

    let cred_type = config
        .credential_types
        .iter()
        .find(|ct| ct.id == tx.credential_type_id)
        .ok_or_else(|| IssuanceError::UnknownCredentialType(tx.credential_type_id.clone()))?;

    let status_signing_key_name = config
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .or_else(|| config.keys.keys().next().map(|s| s.as_str()))
        .ok_or_else(|| IssuanceError::InvalidRequest("no signing key configured".into()))?;

    let issuer_key = config
        .keys
        .get(status_signing_key_name)
        .ok_or_else(|| IssuanceError::InvalidRequest("configured signing key not found".into()))?;

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
                    if let Some(top_key) = claim_def.path.first() {
                        if let Some(val) = tx.claims.get(top_key) {
                            if claim_def.selectively_disclosable {
                                selectively_disclosable.insert(top_key.clone(), val.clone());
                            } else {
                                always_disclosed.insert(top_key.clone(), val.clone());
                            }
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
                    sub: format!("sub_{}", tx.transaction_id),
                    iat: now_unix,
                    exp: now_unix + 86400 * 365,
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
                let doc_type = cred_type
                    .vct
                    .clone()
                    .or_else(|| cred_type.doctype.clone())
                    .unwrap_or_else(|| tx.credential_type_id.clone());

                let mut ns_map = BTreeMap::new();
                let mut elem_map = BTreeMap::new();
                for (k, v) in &tx.claims {
                    elem_map.insert(k.clone(), v.clone());
                }
                ns_map.insert(doc_type.clone(), elem_map);

                let mdoc_claims = MdocClaims {
                    doc_type,
                    namespaces: ns_map,
                    device_key_jwk: holder_jwk_json,
                    signed_at: now_unix,
                    valid_until: now_unix + 86400 * 365,
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
                )))
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        load_transaction, save_transaction_with_indices, IssuanceTransaction,
    };
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, DpopConfig, IssuerConfig, KeyEntry,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
        WalletFacingConfig,
    };
    use foundry_core::crypto::SignatureAlgorithm;
    use foundry_core::storage::SqliteStorage;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::KeyPair as _;
    use josekit::jws::{JwsHeader, ES256};
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
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
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
                    selectively_disclosable: true,
                    display: vec![],
                }],
            }],
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
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
            proofs: Some(ProofsRequest {
                jwt: vec![proof_jwt],
            }),
        };

        let res = handle_credential_request(
            &config,
            &storage,
            "at_secret_123",
            &req,
            &secret,
            &bearer_presentation(),
            1_700_000_010,
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
            proofs: Some(ProofsRequest {
                jwt: vec![proof_jwt],
            }),
        };

        let res = handle_credential_request(
            &config,
            &storage,
            "at_secret_456",
            &req,
            &secret,
            &bearer_presentation(),
            now + 10,
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
            proofs: Some(ProofsRequest {
                jwt: vec![proof_jwt],
            }),
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
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("jti"), "got: {e}");
    }
}
