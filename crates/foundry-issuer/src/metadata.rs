//! OpenID4VCI Credential Issuer Metadata and OAuth Authorization Server
//! Metadata, defined directly against the specification rather than derived
//! from a generic protocol library's types.

use foundry_core::config::Config;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfigurationSupported>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialConfigurationSupported {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    pub cryptographic_binding_methods_supported: Vec<String>,
    pub credential_signing_alg_values_supported: Vec<String>,
    pub proof_types_supported: BTreeMap<String, ProofTypeSupported>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub claims: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub key_attestations_required: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

/// Build the Credential Issuer Metadata document, fully derived from
/// `cfg.credential_types` and `cfg.issuer` — nothing hard-coded per credential type.
pub fn build_issuer_metadata(cfg: &Config) -> CredentialIssuerMetadata {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    let mut configs = BTreeMap::new();
    for ct in &cfg.credential_types {
        let cryptographic_binding_methods_supported = if ct.cryptographic_holder_binding {
            vec!["jwk".to_string()]
        } else {
            Vec::new()
        };
        let claims: Vec<serde_json::Value> = ct
            .claims
            .iter()
            .map(|c| {
                serde_json::json!({
                    "path": c.path,
                    "selectively_disclosable": c.selectively_disclosable,
                    "display": c.display,
                })
            })
            .collect();
        configs.insert(
            ct.id.clone(),
            CredentialConfigurationSupported {
                format: ct.format.clone(),
                vct: ct.vct.clone(),
                doctype: ct.doctype.clone(),
                cryptographic_binding_methods_supported,
                credential_signing_alg_values_supported: vec!["ES256".to_string()],
                proof_types_supported: BTreeMap::from([(
                    "jwt".to_string(),
                    ProofTypeSupported {
                        proof_signing_alg_values_supported: vec!["ES256".to_string()],
                        key_attestations_required: if cfg.issuer.key_attestation.mode
                            == foundry_core::config::Mode::Required
                        {
                            Some(serde_json::json!({}))
                        } else {
                            None
                        },
                    },
                )]),
                display: ct.display.clone(),
                claims,
            },
        );
    }
    CredentialIssuerMetadata {
        credential_issuer: base.to_string(),
        authorization_servers: Vec::new(),
        credential_endpoint: format!("{base}/credential"),
        nonce_endpoint: Some(format!("{base}/nonce")),
        display: Vec::new(),
        credential_configurations_supported: configs,
    }
}

/// Build the OAuth Authorization Server Metadata document.
pub fn build_authorization_server_metadata(cfg: &Config) -> AuthorizationServerMetadata {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    AuthorizationServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        nonce_endpoint: Some(format!("{base}/nonce")),
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            "authorization_code".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        pre_authorized_grant_anonymous_access_supported: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, IssuerConfig, LoggingConfig, Mode,
        ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
    };
    use std::collections::BTreeMap as StdBTreeMap;

    fn test_config() -> Config {
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
            keys: StdBTreeMap::new(),
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
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                cryptographic_holder_binding: true,
                display: vec![serde_json::json!({"name": "Person ID", "locale": "en-US"})],
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
                transaction_data_hashes_alg: vec!["sha-256".to_string()],
                named_queries: vec![],
                webhook: None,
            },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn builds_issuer_metadata_from_credential_types() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg);
        assert_eq!(meta.credential_issuer, "https://issuer.example.com");
        assert_eq!(
            meta.credential_endpoint,
            "https://issuer.example.com/credential"
        );
        assert_eq!(
            meta.nonce_endpoint.as_deref(),
            Some("https://issuer.example.com/nonce")
        );
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(pid.format, "dc+sd-jwt");
        assert_eq!(
            pid.vct.as_deref(),
            Some("https://issuer.example.com/vct/pid")
        );
        assert_eq!(
            pid.cryptographic_binding_methods_supported,
            vec!["jwk".to_string()]
        );
        assert!(pid.proof_types_supported.contains_key("jwt"));
    }

    #[test]
    fn key_attestations_required_present_when_mode_required() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.mode = Mode::Required;
        let meta = build_issuer_metadata(&cfg);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        let jwt_proof = pid.proof_types_supported.get("jwt").unwrap();
        assert_eq!(
            jwt_proof.key_attestations_required,
            Some(serde_json::json!({}))
        );
    }

    #[test]
    fn key_attestations_required_absent_when_mode_optional_or_disabled() {
        let mut cfg = test_config();
        cfg.issuer.key_attestation.mode = Mode::Optional;
        let meta = build_issuer_metadata(&cfg);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(
            pid.proof_types_supported
                .get("jwt")
                .unwrap()
                .key_attestations_required,
            None
        );

        cfg.issuer.key_attestation.mode = Mode::Disabled;
        let meta = build_issuer_metadata(&cfg);
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(
            pid.proof_types_supported
                .get("jwt")
                .unwrap()
                .key_attestations_required,
            None
        );
    }

    #[test]
    fn trims_trailing_slash_from_credential_issuer() {
        let mut cfg = test_config();
        cfg.issuer.credential_issuer = "https://issuer.example.com/".to_string();
        let meta = build_issuer_metadata(&cfg);
        assert_eq!(
            meta.credential_endpoint,
            "https://issuer.example.com/credential"
        );
    }

    #[test]
    fn builds_authorization_server_metadata() {
        let cfg = test_config();
        let meta = build_authorization_server_metadata(&cfg);
        assert_eq!(meta.issuer, "https://issuer.example.com");
        assert_eq!(meta.token_endpoint, "https://issuer.example.com/token");
        assert!(meta.pre_authorized_grant_anonymous_access_supported);
        assert_eq!(
            meta.authorization_endpoint,
            "https://issuer.example.com/authorize"
        );
        assert_eq!(meta.response_types_supported, vec!["code".to_string()]);
        assert_eq!(
            meta.code_challenge_methods_supported,
            vec!["S256".to_string()]
        );
        assert_eq!(
            meta.grant_types_supported,
            vec![
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                "authorization_code".to_string(),
            ]
        );
    }
}
