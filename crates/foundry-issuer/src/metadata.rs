//! OpenID4VCI Credential Issuer Metadata and OAuth Authorization Server
//! Metadata, defined directly against the specification rather than derived
//! from a generic protocol library's types.

use foundry_core::config::{Config, Mode};
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
    /// HAIP OpenID4VCI L186: the metadata MUST include a scope for every Credential
    /// Configuration. Neither `Option` nor `skip_serializing_if`: "every" admits no
    /// omission.
    pub scope: String,
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
    /// RFC 9207 §2.3: an authorization server publishing metadata per RFC 8414
    /// MUST indicate its support for the `iss` parameter by setting this to
    /// `true` -- GAP-HAIP-02. Deliberately a plain required field (no
    /// `skip_serializing_if`): §2.3 wants it present and `true`, not merely
    /// inferable from its absence.
    pub authorization_response_iss_parameter_supported: bool,
    /// RFC 9449 §5.1: "A JSON array containing a list of the JWS alg values
    /// (from the [IANA.JOSE.ALGS] registry) supported by the authorization
    /// server for DPoP proof JWTs."
    ///
    /// Omitted entirely when `issuer.dpop.mode` is `Disabled` — the field's
    /// presence *is* the support signal, so advertising it while ignoring every
    /// proof would tell a wallet it can sender-constrain when it cannot.
    /// Contrast `authorization_response_iss_parameter_supported` above, which
    /// RFC 9207 §2.3 wants present-and-true unconditionally.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
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
                scope: ct.resolved_scope().to_string(),
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
        authorization_response_iss_parameter_supported: true,
        dpop_signing_alg_values_supported: if cfg.issuer.dpop.mode == Mode::Disabled {
            Vec::new()
        } else {
            // ES256 only: it is what josekit verification is wired for
            // throughout this crate, and HAIP's crypto-suites section mandates
            // it for every JWS in this profile.
            vec!["ES256".to_string()]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, DpopConfig, IssuerConfig,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, VerifierConfig,
        WalletFacingConfig,
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
                    pop_max_age_secs: 300,
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                },
                status_list: StatusListConfig {
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![serde_json::json!({"name": "Person ID", "locale": "en-US"})],
                claims: vec![ClaimDef {
                    path: vec!["given_name".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                }],
            }],
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec!["sha-256".to_string()],
                named_queries: vec![],
                webhook: None,
                dc_api_expected_origins: Vec::new(),
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
        // RFC 9207 §2.3, GAP-HAIP-02.
        assert!(meta.authorization_response_iss_parameter_supported);
    }

    #[test]
    fn every_credential_configuration_carries_a_scope() {
        // HAIP OpenID4VCI L186: the Credential Issuer metadata MUST include a scope
        // for every Credential Configuration it supports.
        let cfg = test_config();
        let metadata = build_issuer_metadata(&cfg);
        assert!(!metadata.credential_configurations_supported.is_empty());
        for (id, config) in &metadata.credential_configurations_supported {
            let json = serde_json::to_value(config).unwrap();
            let scope = json
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("configuration '{id}' has no scope"));
            assert!(!scope.is_empty(), "configuration '{id}' has an empty scope");
        }
    }

    #[test]
    fn scope_defaults_to_the_credential_type_id_and_can_be_overridden() {
        let mut cfg = test_config();
        cfg.credential_types[0].scope = None;
        let default_id = cfg.credential_types[0].id.clone();
        cfg.credential_types.push(CredentialType {
            id: "override_me".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/other".to_string()),
            doctype: None,
            scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
        });

        let metadata = build_issuer_metadata(&cfg);
        assert_eq!(
            metadata.credential_configurations_supported[&default_id].scope,
            default_id
        );
        assert_eq!(
            metadata.credential_configurations_supported["override_me"].scope,
            "eu.europa.ec.eudi.pid.1"
        );
    }

    /// VCI-0145 (OpenID4VCI Credential Issuer Metadata L1392): "The Authorization
    /// Server MUST be able to uniquely identify the Credential Issuer based on the
    /// scope value." foundry's Authorization Server always serves exactly one
    /// Credential Issuer (`config.issuer.credential_issuer`), so `issuer` in
    /// `AuthorizationServerMetadata` is the same single value no matter which
    /// Credential Type's scope a Wallet used to get there -- there is only ever one
    /// candidate to identify.
    #[test]
    fn authorization_server_metadata_issuer_is_independent_of_credential_type_scope() {
        let mut cfg = test_config();
        cfg.credential_types.push(CredentialType {
            id: "mdl".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/mdl".to_string()),
            doctype: None,
            scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
        });

        let meta = build_authorization_server_metadata(&cfg);
        assert_eq!(meta.issuer, cfg.issuer.credential_issuer);
    }

    #[test]
    fn advertises_dpop_signing_algs_when_dpop_is_enabled() {
        // RFC 9449 §5.1: dpop_signing_alg_values_supported is "A JSON array
        // containing a list of the JWS alg values supported by the authorization
        // server for DPoP proof JWTs". Its presence is the support signal.
        let mut cfg = test_config();
        cfg.issuer.dpop.mode = Mode::Optional;
        let md = build_authorization_server_metadata(&cfg);
        assert_eq!(
            md.dpop_signing_alg_values_supported,
            vec!["ES256".to_string()]
        );
    }

    #[test]
    fn advertises_dpop_signing_algs_under_required_mode_too() {
        let mut cfg = test_config();
        cfg.issuer.dpop.mode = Mode::Required;
        let md = build_authorization_server_metadata(&cfg);
        assert_eq!(
            md.dpop_signing_alg_values_supported,
            vec!["ES256".to_string()]
        );
    }

    #[test]
    fn omits_dpop_signing_algs_when_dpop_is_disabled() {
        // Advertising support while ignoring every proof would be a lie: a wallet
        // reading this field would conclude it can sender-constrain when it cannot.
        let mut cfg = test_config();
        cfg.issuer.dpop.mode = Mode::Disabled;
        let md = build_authorization_server_metadata(&cfg);
        assert!(md.dpop_signing_alg_values_supported.is_empty());

        // skip_serializing_if means an empty vec is absent from the wire, not `[]`.
        let json = serde_json::to_value(&md).unwrap();
        assert!(
            json.get("dpop_signing_alg_values_supported").is_none(),
            "an empty list MUST be omitted, not serialized as []"
        );
    }
}
