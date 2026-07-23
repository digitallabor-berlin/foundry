use crate::error::VerificationError;
use crate::transaction::{save_verification_transaction, VerificationState, VerificationTransaction};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::config::Config;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
use foundry_core::storage::Storage;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateVerificationRequest {
    pub dcql_query: Option<serde_json::Value>,
    pub named_query_ref: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    pub transaction_data: Option<Vec<serde_json::Value>>,
}

fn default_transport() -> String {
    "request_uri".to_string()
}

pub(crate) fn dns_host_only(base_url: &str) -> String {
    let host = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    host.split(':').next().unwrap_or(host).to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateVerificationResponse {
    pub verification_id: String,
    pub request_uri: Option<String>,
    pub openid4vp_uri: Option<String>,
    pub dc_api_request: Option<serde_json::Value>,
}

pub async fn create_verification_request(
    config: &Config,
    storage: &dyn Storage,
    req: CreateVerificationRequest,
    now_unix: i64,
) -> Result<CreateVerificationResponse, VerificationError> {
    let dcql = if let Some(q) = req.dcql_query {
        q
    } else if let Some(ref named) = req.named_query_ref {
        let entry = config
            .verifier
            .named_queries
            .iter()
            .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(named.as_str()))
            .ok_or_else(|| VerificationError::Dcql(format!("unknown named_query_ref '{named}'")))?;

        let dcql_val = entry
            .get("dcql")
            .or_else(|| entry.get("dcql_query"))
            .cloned()
            .unwrap_or_else(|| entry.clone());
        dcql_val
    } else {
        return Err(VerificationError::Dcql(
            "either dcql_query or named_query_ref is required".to_string(),
        ));
    };

    let id = format!("v_{}", Uuid::new_v4().simple());
    let nonce = format!("vn_{}", Uuid::new_v4().simple());

    let keypair = EcKeyPair::generate(EcCurve::P256)
        .map_err(|e| VerificationError::Crypto(e.to_string()))?;

    let public_jwk = keypair.to_jwk_public_key();
    let private_jwk = keypair.to_jwk_private_key();

    let ephem_public_json = serde_json::to_value(&public_jwk)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;
    let ephem_private_json = serde_json::to_value(&private_jwk)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;

    let transport_str = if req.transport.is_empty() {
        "request_uri".to_string()
    } else {
        req.transport.clone()
    };

    let response_mode = match transport_str.as_str() {
        "dc_api" => "dc_api.jwt".to_string(),
        _ => "direct_post.jwt".to_string(),
    };

    let tx = VerificationTransaction {
        id: id.clone(),
        state: VerificationState::Pending,
        nonce: nonce.clone(),
        dcql_query: dcql.clone(),
        transport: transport_str.clone(),
        response_mode: response_mode.clone(),
        ephem_private_jwk: ephem_private_json,
        ephem_public_jwk: ephem_public_json.clone(),
        transaction_data: req.transaction_data.clone(),
        result: None,
        created_at: now_unix,
    };

    save_verification_transaction(storage, &tx, config.storage.transaction_ttl_secs, now_unix)
        .await?;

    let base_url = config.server.wallet_facing.public_base_url.trim_end_matches('/');

    if transport_str == "dc_api" {
        let dc_api_obj = serde_json::json!({
            "response_mode": "dc_api.jwt",
            "dcql_query": dcql,
            "nonce": nonce,
            "client_metadata": {
                "jwks": { "keys": [ephem_public_json] }
            }
        });

        Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: None,
            openid4vp_uri: None,
            dc_api_request: Some(dc_api_obj),
        })
    } else {
        let request_uri = format!("{base_url}/vp/request/{id}");
        let host = dns_host_only(base_url);
        let client_id = format!("x509_san_dns:{host}");
        let client_id_enc = utf8_percent_encode(&client_id, NON_ALPHANUMERIC).to_string();
        let request_uri_enc = utf8_percent_encode(&request_uri, NON_ALPHANUMERIC).to_string();
        let openid4vp_uri =
            format!("openid4vp://?client_id={client_id_enc}&request_uri={request_uri_enc}");

        Ok(CreateVerificationResponse {
            verification_id: id,
            request_uri: Some(request_uri),
            openid4vp_uri: Some(openid4vp_uri),
            dc_api_request: None,
        })
    }
}

pub fn build_signed_request_object(
    config: &Config,
    tx: &VerificationTransaction,
) -> Result<String, VerificationError> {
    let key_entry = config
        .keys
        .get(&config.verifier.signing_key)
        .ok_or_else(|| {
            VerificationError::Crypto(format!(
                "verifier signing key '{}' not found in config.keys",
                config.verifier.signing_key
            ))
        })?;

    let alg: SignatureAlgorithm = key_entry.alg.parse()?;
    let signer = FileSigner::from_pem_file(&key_entry.private_key, alg)?;

    let x5c = if let Some(ref path) = key_entry.x5c {
        let pem_bytes = std::fs::read(path)
            .map_err(|e| VerificationError::Crypto(format!("failed to read x5c file '{path}': {e}")))?;
        Some(foundry_core::trust::build_x5c(&[pem_bytes])?)
    } else {
        None
    };

    let base_url = config.server.wallet_facing.public_base_url.trim_end_matches('/');
    let host = dns_host_only(base_url);
    let client_id = format!("x509_san_dns:{host}");
    let response_uri = format!("{base_url}/vp/response/{}", tx.id);

    let mut payload_map = serde_json::Map::new();
    payload_map.insert("client_id".to_string(), serde_json::json!(client_id));
    payload_map.insert("response_uri".to_string(), serde_json::json!(response_uri));
    payload_map.insert("response_mode".to_string(), serde_json::json!("direct_post.jwt"));
    payload_map.insert("nonce".to_string(), serde_json::json!(tx.nonce));
    payload_map.insert("state".to_string(), serde_json::json!(tx.id));
    payload_map.insert("dcql_query".to_string(), tx.dcql_query.clone());
    payload_map.insert(
        "client_metadata".to_string(),
        serde_json::json!({
            "jwks": { "keys": [tx.ephem_public_jwk.clone()] }
        }),
    );
    if let Some(ref td) = tx.transaction_data {
        payload_map.insert("transaction_data".to_string(), serde_json::json!(td));
    }
    let payload_val = serde_json::Value::Object(payload_map);

    let mut header_map = serde_json::Map::new();
    header_map.insert("typ".to_string(), serde_json::json!("oauth-authz-req+jwt"));
    header_map.insert("alg".to_string(), serde_json::json!(alg.as_str()));
    if let Some(chain) = x5c {
        header_map.insert("x5c".to_string(), serde_json::json!(chain));
    }
    let header_val = serde_json::Value::Object(header_map);

    let header_bytes = serde_json::to_vec(&header_val)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;
    let payload_bytes = serde_json::to_vec(&payload_val)
        .map_err(|e| VerificationError::Serialization(e.to_string()))?;

    let header_b64 = B64URL.encode(&header_bytes);
    let payload_b64 = B64URL.encode(&payload_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig_bytes = signer.sign(signing_input.as_bytes())?;
    let sig_b64 = B64URL.encode(&sig_bytes);

    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::load_verification_transaction;
    use foundry_core::config::*;
    use foundry_core::pki::generate_ec_key;
    use foundry_core::storage::SqliteStorage;
    use josekit::jws::ES256;
    use std::collections::BTreeMap;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("verifier_test.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn sample_config(key_path: &str) -> Config {
        let mut keys = BTreeMap::new();
        keys.insert(
            "verifier_signing".to_string(),
            KeyEntry {
                private_key: key_path.to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );

        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://verifier.example.com".to_string(),
                    bind: "127.0.0.1:8080".to_string(),
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:8081".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                },
            },
            storage: StorageConfig {
                path: ":memory:".to_string(),
                transaction_ttl_secs: 600,
            },
            keys,
            trust_anchors: vec![],
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: Default::default(),
                key_attestation: Default::default(),
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: None,
                    public_base_url: None,
                },
            },
            credential_types: vec![],
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec!["sha-256".to_string()],
                named_queries: vec![serde_json::json!({
                    "id": "over18",
                    "dcql": {
                        "credentials": [{
                            "id": "c1",
                            "format": "mso_mdoc",
                            "meta": { "doctype": "org.iso.18013.5.1.mDL" }
                        }]
                    }
                })],
                webhook: None,
            },
        }
    }

    #[tokio::test]
    async fn test_create_verification_request_dcql() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert!(res.verification_id.starts_with("v_"));
        let req_uri = res.request_uri.as_ref().unwrap();
        assert!(req_uri.contains("/vp/request/"));
        let vp_uri = res.openid4vp_uri.as_ref().unwrap();
        assert!(vp_uri.starts_with("openid4vp://?client_id="));
        assert!(res.dc_api_request.is_none());

        // Verify transaction saved in storage
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tx.id, res.verification_id);
        assert_eq!(tx.state, VerificationState::Pending);
        assert_eq!(tx.transport, "request_uri");
        assert_eq!(tx.response_mode, "direct_post.jwt");
    }

    #[tokio::test]
    async fn test_create_verification_request_named_query() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: None,
            named_query_ref: Some("over18".to_string()),
            transport: "request_uri".to_string(),
            transaction_data: Some(vec![serde_json::json!({"type": "payment"})]),
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tx.dcql_query["credentials"][0]["meta"]["doctype"],
            "org.iso.18013.5.1.mDL"
        );
        assert_eq!(tx.transaction_data.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_create_verification_request_unknown_named_query_fails() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: None,
            named_query_ref: Some("nonexistent".to_string()),
            transport: "request_uri".to_string(),
            transaction_data: None,
        };

        let err = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap_err();

        assert!(matches!(err, VerificationError::Dcql(_)));
    }

    #[tokio::test]
    async fn test_create_verification_request_dc_api() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({"credentials": []})),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        assert!(res.request_uri.is_none());
        assert!(res.openid4vp_uri.is_none());
        let dc_req = res.dc_api_request.unwrap();
        assert_eq!(dc_req["response_mode"], "dc_api.jwt");
        assert!(dc_req["nonce"].is_string());
        assert!(dc_req["client_metadata"]["jwks"]["keys"].is_array());
    }

    #[tokio::test]
    async fn test_build_signed_request_object_and_verify_jws() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");

        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: Some(vec![serde_json::json!({"amount": 50})]),
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws_str = build_signed_request_object(&config, &tx).unwrap();

        // Check JWS structure: 3 dot-separated parts
        let parts: Vec<&str> = jws_str.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_bytes = B64URL.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "oauth-authz-req+jwt");
        assert_eq!(header["alg"], "ES256");

        let payload_bytes = B64URL.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["client_id"], "x509_san_dns:verifier.example.com");
        assert_eq!(
            payload["response_uri"],
            format!("https://verifier.example.com/vp/response/{}", tx.id)
        );
        assert_eq!(payload["response_mode"], "direct_post.jwt");
        assert_eq!(payload["nonce"], tx.nonce);
        assert_eq!(payload["state"], tx.id);
        assert_eq!(payload["transaction_data"][0]["amount"], 50);

        // Verify JWS signature using verifier key
        let keypair = EcKeyPair::from_pem(km.private_pem.as_bytes(), None).unwrap();
        let verifier = ES256.verifier_from_jwk(&keypair.to_jwk_public_key()).unwrap();

        let (verified_payload, verified_header) =
            josekit::jwt::decode_with_verifier(&jws_str, &verifier).unwrap();
        assert_eq!(
            verified_header.token_type(),
            Some("oauth-authz-req+jwt")
        );
        assert_eq!(
            verified_payload.claim("state").and_then(|v| v.as_str()),
            Some(tx.id.as_str())
        );
    }
}
