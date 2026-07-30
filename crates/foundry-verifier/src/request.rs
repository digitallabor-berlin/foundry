use crate::error::VerificationError;
use crate::transaction::{
    save_verification_transaction, VerificationState, VerificationTransaction,
};
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

/// The only `response_type` defined for an OpenID4VP presentation request
/// (OpenID4VP v1.0 §5, where the parameter is REQUIRED).
///
/// Wallets enforce this strictly and early: the EUDI reference iOS wallet aborts
/// request resolution unless `response_type` is both present and parseable into
/// its `ResponseType` enum, which happens *before* the DCQL query is inspected —
/// so omitting it surfaces as a misleading DCQL error rather than a missing
/// parameter. It must be emitted on every transport.
const RESPONSE_TYPE_VP_TOKEN: &str = "vp_token";

/// Response-encryption parameters advertised to wallets, sourced from
/// `verifier.response_encryption`. Defaults match OpenID4VP v1.0 §8.3.
fn response_encryption_params(config: &Config) -> (String, String) {
    let configured = config.verifier.response_encryption.as_ref();
    let alg = configured
        .and_then(|v| v.get("alg"))
        .and_then(|v| v.as_str())
        .unwrap_or("ECDH-ES")
        .to_string();
    let enc = configured
        .and_then(|v| v.get("enc"))
        .and_then(|v| v.as_str())
        .unwrap_or("A128GCM")
        .to_string();
    (alg, enc)
}

/// Presentation formats this verifier can actually verify, in the OpenID4VP
/// v1.0 `vp_formats_supported` shape. REQUIRED in client metadata unless the
/// wallet obtains it by another mechanism (§5.1).
///
/// The algorithm values are load-bearing, not decorative: wallets intersect this
/// set against their own supported formats by *exact equality*, so an
/// under-specified entry such as `"mso_mdoc": {}` causes that format to be
/// dropped entirely rather than read as "any algorithm".
///
/// Keep in sync with what `foundry-sd-jwt-vc` and `foundry-mdoc` actually
/// verify: ES256, which is COSE algorithm -7.
fn vp_formats_supported() -> serde_json::Value {
    serde_json::json!({
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256"],
            "kb-jwt_alg_values": ["ES256"]
        },
        "mso_mdoc": {
            "issuerauth_alg_values": [-7],
            "deviceauth_alg_values": [-7]
        }
    })
}

/// Annotate an ephemeral EC public JWK so a wallet can *select* it as the
/// response-encryption key.
///
/// OpenID4VP wallets filter candidate encryption keys on `kid` and `alg` being
/// present and non-empty, and locate the reader key via `use == "enc"`. josekit
/// emits none of these for a generated keypair, so a bare public JWK is silently
/// discarded and the wallet reports that the verifier advertised no encryption
/// keys at all.
///
/// Only the *public* JWK is annotated. The stored private JWK deliberately stays
/// bare so josekit's decrypter carries no key id, and therefore does not require
/// the wallet to echo `kid` back in the JWE header.
fn annotate_encryption_jwk(mut jwk: serde_json::Value, alg: &str) -> serde_json::Value {
    if let Some(obj) = jwk.as_object_mut() {
        obj.insert(
            "kid".to_string(),
            serde_json::json!(Uuid::new_v4().to_string()),
        );
        obj.insert("use".to_string(), serde_json::json!("enc"));
        obj.insert("alg".to_string(), serde_json::json!(alg));
    }
    jwk
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

/// Encode `transaction_data` entries for the wire.
///
/// OpenID4VP v1.0 §8.4 defines each entry as a **base64url-encoded (unpadded)
/// JSON object**, not a bare JSON object. foundry's admin API accepts objects
/// because that is the ergonomic shape for a relying party; the encoding happens
/// here, once, and the encoded strings are what get stored and emitted so that
/// what a wallet hashes into `transaction_data_hashes` is byte-identical to what
/// was advertised.
///
/// The validation is load-bearing, not politeness. A wallet that cannot parse an
/// entry aborts the entire presentation rather than skipping it — the EUDI iOS
/// wallet unwraps every parsed entry with `.get()`
/// (`ResolvedRequestData.parseTransactionData`) and additionally requires each
/// `credential_ids` element to name a credential present in the DCQL query
/// (`TransactionData.hasCorrectIds`). Rejecting a malformed entry here converts
/// an opaque device-side failure into a precise 400 for whoever built the
/// request.
fn encode_transaction_data(
    entries: &[serde_json::Value],
    dcql: &serde_json::Value,
) -> Result<Vec<String>, VerificationError> {
    let known_ids: Vec<&str> = dcql
        .get("credentials")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();

    entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let obj = entry.as_object().ok_or_else(|| {
                VerificationError::InvalidRequest(format!(
                    "transaction_data[{i}] must be a JSON object"
                ))
            })?;

            let has_type = obj
                .get("type")
                .and_then(|v| v.as_str())
                .is_some_and(|t| !t.is_empty());
            if !has_type {
                return Err(VerificationError::InvalidRequest(format!(
                    "transaction_data[{i}] requires a non-empty string 'type'"
                )));
            }

            let ids = obj
                .get("credential_ids")
                .and_then(|v| v.as_array())
                .filter(|a| !a.is_empty())
                .ok_or_else(|| {
                    VerificationError::InvalidRequest(format!(
                        "transaction_data[{i}] requires a non-empty 'credential_ids' array"
                    ))
                })?;

            for id in ids {
                let id = id.as_str().ok_or_else(|| {
                    VerificationError::InvalidRequest(format!(
                        "transaction_data[{i}] 'credential_ids' must contain only strings"
                    ))
                })?;
                if !known_ids.contains(&id) {
                    return Err(VerificationError::InvalidRequest(format!(
                        "transaction_data[{i}] references credential id '{id}' which is not \
                         present in the DCQL query"
                    )));
                }
            }

            let bytes = serde_json::to_vec(entry)
                .map_err(|e| VerificationError::Serialization(e.to_string()))?;
            Ok(B64URL.encode(bytes))
        })
        .collect()
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

    let keypair =
        EcKeyPair::generate(EcCurve::P256).map_err(|e| VerificationError::Crypto(e.to_string()))?;

    let public_jwk = keypair.to_jwk_public_key();
    let private_jwk = keypair.to_jwk_private_key();

    let (response_enc_alg, response_enc_method) = response_encryption_params(config);

    let ephem_public_json = annotate_encryption_jwk(
        serde_json::to_value(&public_jwk)
            .map_err(|e| VerificationError::Serialization(e.to_string()))?,
        &response_enc_alg,
    );
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

    // Validate and encode before persisting: a bad entry must fail the request,
    // not reach a wallet that will abort the whole presentation over it.
    let encoded_transaction_data = match req.transaction_data.as_deref() {
        Some(entries) => Some(encode_transaction_data(entries, &dcql)?),
        None => None,
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
        transaction_data: encoded_transaction_data,
        result: None,
        created_at: now_unix,
    };

    save_verification_transaction(storage, &tx, config.storage.transaction_ttl_secs, now_unix)
        .await?;

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');

    if transport_str == "dc_api" {
        let dc_api_obj = serde_json::json!({
            "response_type": RESPONSE_TYPE_VP_TOKEN,
            "response_mode": "dc_api.jwt",
            "dcql_query": dcql,
            "nonce": nonce,
            "client_metadata": {
                "jwks": { "keys": [ephem_public_json] },
                "encrypted_response_enc_values_supported": [response_enc_method],
                "vp_formats_supported": vp_formats_supported()
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
        let pem_bytes = std::fs::read(path).map_err(|e| {
            VerificationError::Crypto(format!("failed to read x5c file '{path}': {e}"))
        })?;
        Some(foundry_core::trust::build_x5c(&[pem_bytes])?)
    } else {
        None
    };

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');
    let host = dns_host_only(base_url);
    let client_id = format!("x509_san_dns:{host}");
    let response_uri = format!("{base_url}/vp/response/{}", tx.id);

    let mut payload_map = serde_json::Map::new();
    payload_map.insert(
        "response_type".to_string(),
        serde_json::json!(RESPONSE_TYPE_VP_TOKEN),
    );
    payload_map.insert("client_id".to_string(), serde_json::json!(client_id));
    payload_map.insert("response_uri".to_string(), serde_json::json!(response_uri));
    payload_map.insert(
        "response_mode".to_string(),
        serde_json::json!("direct_post.jwt"),
    );
    payload_map.insert("nonce".to_string(), serde_json::json!(tx.nonce));
    payload_map.insert("state".to_string(), serde_json::json!(tx.id));
    payload_map.insert("dcql_query".to_string(), tx.dcql_query.clone());
    let (_, response_enc_method) = response_encryption_params(config);
    payload_map.insert(
        "client_metadata".to_string(),
        serde_json::json!({
            "jwks": { "keys": [tx.ephem_public_jwk.clone()] },
            "encrypted_response_enc_values_supported": [response_enc_method],
            "vp_formats_supported": vp_formats_supported()
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
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:8081".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
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
            transaction_data: Some(vec![serde_json::json!({
                "type": "payment",
                "credential_ids": ["c1"]
            })]),
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
            transaction_data: Some(vec![serde_json::json!({
                "type": "payment",
                "credential_ids": ["c1"],
                "amount": 50
            })]),
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
        // Entries are advertised base64url-encoded per OpenID4VP v1.0 §8.4.
        let td_encoded = payload["transaction_data"][0].as_str().unwrap();
        let td: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(td_encoded).unwrap()).unwrap();
        assert_eq!(td["amount"], 50);
        assert_eq!(td["type"], "payment");

        // Verify JWS signature using verifier key
        let keypair = EcKeyPair::from_pem(km.private_pem.as_bytes(), None).unwrap();
        let verifier = ES256
            .verifier_from_jwk(&keypair.to_jwk_public_key())
            .unwrap();

        let (verified_payload, verified_header) =
            josekit::jwt::decode_with_verifier(&jws_str, &verifier).unwrap();
        assert_eq!(verified_header.token_type(), Some("oauth-authz-req+jwt"));
        assert_eq!(
            verified_payload.claim("state").and_then(|v| v.as_str()),
            Some(tx.id.as_str())
        );
    }

    /// The ephemeral response-encryption JWK must carry the metadata a wallet
    /// needs to *select* it: OpenID4VP wallets filter candidate encryption keys
    /// on `kid` and `alg` being present and non-empty, and locate the reader key
    /// via `use == "enc"`. A bare josekit public JWK has none of these and is
    /// silently discarded, leaving the wallet with zero encryption keys.
    #[tokio::test]
    async fn test_dc_api_client_metadata_encryption_jwk_is_wallet_selectable() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let dc_req = res.dc_api_request.unwrap();
        let cm = &dc_req["client_metadata"];
        let key = &cm["jwks"]["keys"][0];

        assert!(
            key["kid"].as_str().is_some_and(|s| !s.is_empty()),
            "encryption JWK must carry a non-empty kid, got: {key}"
        );
        assert_eq!(key["alg"], "ECDH-ES", "encryption JWK must carry alg");
        assert_eq!(key["use"], "enc", "encryption JWK must be marked use=enc");

        assert_eq!(
            cm["encrypted_response_enc_values_supported"],
            serde_json::json!(["A128GCM"]),
            "client_metadata must advertise supported response encryption methods"
        );
    }

    /// Same contract for the `request_uri` transport, whose client metadata is
    /// carried inside the signed request object rather than returned inline.
    #[tokio::test]
    async fn test_signed_request_object_encryption_jwk_is_wallet_selectable() {
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
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();

        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws_str.split('.').collect();
        let payload_bytes = B64URL.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let cm = &payload["client_metadata"];
        let key = &cm["jwks"]["keys"][0];

        assert!(
            key["kid"].as_str().is_some_and(|s| !s.is_empty()),
            "encryption JWK must carry a non-empty kid, got: {key}"
        );
        assert_eq!(key["alg"], "ECDH-ES", "encryption JWK must carry alg");
        assert_eq!(key["use"], "enc", "encryption JWK must be marked use=enc");

        assert_eq!(
            cm["encrypted_response_enc_values_supported"],
            serde_json::json!(["A128GCM"]),
            "client_metadata must advertise supported response encryption methods"
        );

        // The advertised public key must still be the transaction's ephemeral
        // key material, not a freshly generated one.
        assert_eq!(key["x"], tx.ephem_public_jwk["x"]);
        assert_eq!(key["y"], tx.ephem_public_jwk["y"]);
    }

    /// OpenID4VP v1.0 §5.1 makes `vp_formats_supported` REQUIRED unless the
    /// wallet learns it by another mechanism. It must describe what this verifier
    /// can actually verify: SD-JWT VC and mdoc, ES256 / COSE -7.
    ///
    /// The algorithm values are load-bearing, not decorative: wallets intersect
    /// this set against their own by *exact equality*, so advertising e.g.
    /// `"mso_mdoc": {}` would drop mdoc from the intersection entirely.
    #[tokio::test]
    async fn test_client_metadata_advertises_vp_formats_supported() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let expected = serde_json::json!({
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256"],
                "kb-jwt_alg_values": ["ES256"]
            },
            "mso_mdoc": {
                "issuerauth_alg_values": [-7],
                "deviceauth_alg_values": [-7]
            }
        });

        // dc_api transport: client metadata is returned inline.
        let dc_res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "dc_api".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        assert_eq!(
            dc_res.dc_api_request.unwrap()["client_metadata"]["vp_formats_supported"],
            expected,
            "dc_api client_metadata must advertise vp_formats_supported"
        );

        // request_uri transport: client metadata lives in the signed request object.
        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws_str.split('.').collect();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload["client_metadata"]["vp_formats_supported"], expected,
            "signed request object client_metadata must advertise vp_formats_supported"
        );
    }

    /// OpenID4VP v1.0 §5 makes `response_type` a REQUIRED Authorization Request
    /// parameter, and `vp_token` is the only value defined for a presentation
    /// request. Wallets treat it as a hard gate: the EUDI reference iOS wallet
    /// resolves the request object into an `UnvalidatedRequestObject` and then
    /// requires both that `response_type` is present and that it parses into its
    /// `ResponseType` enum, otherwise resolution is abandoned before the DCQL
    /// query is ever looked at.
    #[tokio::test]
    async fn test_authorization_request_advertises_response_type_vp_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();

        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        // dc_api transport: the request object is returned inline.
        let dc_res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "dc_api".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        assert_eq!(
            dc_res.dc_api_request.unwrap()["response_type"],
            serde_json::json!("vp_token"),
            "dc_api request must advertise response_type=vp_token"
        );

        // request_uri transport: the request object is the signed JWS payload.
        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();
        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws_str = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws_str.split('.').collect();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload["response_type"],
            serde_json::json!("vp_token"),
            "signed request object must advertise response_type=vp_token"
        );
    }

    /// `verifier.response_encryption` was previously parsed but never read.
    /// The advertised values must come from it rather than being hardcoded.
    #[tokio::test]
    async fn test_client_metadata_response_encryption_honours_config() {
        let storage = test_storage().await;
        let mut config = sample_config("/tmp/fake_key.pem");
        config.verifier.response_encryption = Some(serde_json::json!({
            "alg": "ECDH-ES",
            "enc": "A256GCM"
        }));

        let req = CreateVerificationRequest {
            dcql_query: Some(serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            })),
            named_query_ref: None,
            transport: "dc_api".to_string(),
            transaction_data: None,
        };

        let res = create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .unwrap();

        let cm = &res.dc_api_request.unwrap()["client_metadata"];
        assert_eq!(
            cm["encrypted_response_enc_values_supported"],
            serde_json::json!(["A256GCM"])
        );
        assert_eq!(cm["jwks"]["keys"][0]["alg"], "ECDH-ES");
    }

    /// OpenID4VP v1.0 §8.4 defines `transaction_data` as an array of
    /// **base64url-encoded JSON strings**, not raw JSON objects.
    ///
    /// Emitting objects is silently destructive rather than loudly wrong: the
    /// EUDI iOS wallet reads the parameter as `[String]`
    /// (`RequestAuthenticator.swift:48`), so an array of objects yields `nil`
    /// and the transaction data is dropped with no error at all.
    #[tokio::test]
    async fn test_transaction_data_is_emitted_as_base64url_strings() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("verifier_key.pem");
        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_file, km.private_pem.as_bytes()).unwrap();
        let config = sample_config(key_file.to_str().unwrap());
        let storage = test_storage().await;

        let entry = serde_json::json!({
            "type": "qes_authorization",
            "credential_ids": ["pid"],
            "transaction_data_hashes_alg": ["sha-256"]
        });

        let res = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![entry.clone()]),
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let tx = load_verification_transaction(&storage, &res.verification_id)
            .await
            .unwrap()
            .unwrap();
        let jws = build_signed_request_object(&config, &tx).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();

        let arr = payload["transaction_data"]
            .as_array()
            .expect("transaction_data must be an array");
        assert_eq!(arr.len(), 1);
        let encoded = arr[0]
            .as_str()
            .unwrap_or_else(|| panic!("entry must be a base64url string, got: {}", arr[0]));

        // Must decode back to exactly the caller-supplied object.
        let decoded: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, entry);
    }

    /// A wallet hard-throws on an entry it cannot parse
    /// (`ResolvedRequestData.parseTransactionData` unwraps with `.get()`), so
    /// foundry must reject a structurally invalid entry at request-creation time
    /// with a clear error instead of shipping one that breaks resolution.
    #[tokio::test]
    async fn test_transaction_data_requires_type_and_credential_ids() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");
        let dcql = serde_json::json!({
            "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
        });

        // Missing `type`.
        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(dcql.clone()),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!({"credential_ids": ["pid"]})]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidRequest(ref m) if m.contains("type")),
            "expected InvalidRequest mentioning 'type', got: {err}"
        );

        // Missing `credential_ids`.
        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(dcql.clone()),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!({"type": "qes_authorization"})]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidRequest(ref m) if m.contains("credential_ids")),
            "expected InvalidRequest mentioning 'credential_ids', got: {err}"
        );

        // Not an object.
        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(dcql),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!("already-encoded?")]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VerificationError::InvalidRequest(_)));
    }

    /// The wallet also checks that every `credential_ids` entry refers to a
    /// credential actually present in the DCQL query
    /// (`TransactionData.hasCorrectIds`). foundry holds both at creation time,
    /// so it can and should catch the mismatch first.
    #[tokio::test]
    async fn test_transaction_data_credential_ids_must_exist_in_dcql() {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");

        let err = create_verification_request(
            &config,
            &storage,
            CreateVerificationRequest {
                dcql_query: Some(serde_json::json!({
                    "credentials": [{"id": "pid", "format": "dc+sd-jwt"}]
                })),
                named_query_ref: None,
                transport: "request_uri".to_string(),
                transaction_data: Some(vec![serde_json::json!({
                    "type": "qes_authorization",
                    "credential_ids": ["not_in_the_query"]
                })]),
            },
            1_700_000_000,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, VerificationError::InvalidRequest(ref m)
                if m.contains("not_in_the_query")),
            "expected InvalidRequest naming the unknown id, got: {err}"
        );
    }
}
