//! OpenID4VCI credential endpoint business logic.

use crate::error::IssuanceError;
use crate::nonce::NonceSecret;
use crate::proof::{verify_holder_proof, ProofsRequest};
use crate::transaction::{
    load_transaction_by_access_token, save_transaction_with_indices, IssuanceState,
};
use base64::engine::general_purpose::STANDARD as B64STD;
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

                B64STD.encode(cbor_bytes)
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
        AdminConfig, AttestationMode, ClaimDef, CredentialType, IssuerConfig, KeyEntry,
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
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: Some("issuer_key".to_string()),
                    list_size: None,
                    public_base_url: None,
                },
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![ClaimDef {
                    path: vec!["given_name".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                }],
            }],
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
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

        let res =
            handle_credential_request(&config, &storage, "at_secret_456", &req, &secret, now + 10)
                .await
                .unwrap();

        assert_eq!(res.credentials.len(), 1);
    }
}
