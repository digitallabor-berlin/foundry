use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub keys: BTreeMap<String, KeyEntry>,
    #[serde(default)]
    pub trust_anchors: Vec<TrustAnchor>,
    pub issuer: IssuerConfig,
    #[serde(default)]
    pub credential_types: Vec<CredentialType>,
    pub verifier: VerifierConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// How the process logs.
///
/// Every member has a default, and the section itself is `#[serde(default)]` on
/// [`Config`], so a config file written before this section existed still
/// loads and lands on production-safe settings.
///
/// These values are the lowest-precedence tier: `RUST_LOG` and the CLI flags
/// both override them. See the binary's `logging` module for the resolution
/// order.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// An `EnvFilter` directive, e.g. `info` or `info,foundry_verifier=debug`.
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
    /// Unlocks payload-bearing log fields at `debug`/`trace`.
    ///
    /// **Development and test only.** With this on, the log may contain raw
    /// JWEs, `vp_token`s and disclosed claim values.
    #[serde(default)]
    pub sensitive_payloads: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
            sensitive_payloads: false,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Log output shape.
///
/// Deliberately distinct from the `clap::ValueEnum` of the same name in the
/// binary's `cli` module: `foundry-core` must not depend on `clap`. The binary
/// provides the conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub wallet_facing: WalletFacingConfig,
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletFacingConfig {
    pub public_base_url: String,
    pub bind: String,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub bind: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
    #[serde(default = "default_true")]
    pub console_enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub path: String,
    #[serde(default = "default_ttl")]
    pub transaction_ttl_secs: u64,
}

fn default_ttl() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub private_key: String,
    #[serde(default)]
    pub x5c: Option<String>,
    pub alg: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustAnchor {
    pub name: String,
    pub certs: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuerConfig {
    pub credential_issuer: String,
    #[serde(default)]
    pub wallet_attestation: AttestationMode,
    #[serde(default)]
    pub key_attestation: AttestationMode,
    pub status_list: StatusListConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttestationMode {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub trusted_anchors: Vec<TrustAnchor>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Required,
    #[default]
    Optional,
    Disabled,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusListConfig {
    pub enabled: bool,
    #[serde(default)]
    pub signing_key: Option<String>,
    #[serde(default)]
    pub list_size: Option<u64>,
    #[serde(default)]
    pub public_base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialType {
    pub id: String,
    pub format: String,
    #[serde(default)]
    pub vct: Option<String>,
    #[serde(default)]
    pub doctype: Option<String>,
    #[serde(default)]
    pub cryptographic_holder_binding: bool,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
    #[serde(default)]
    pub claims: Vec<ClaimDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaimDef {
    pub path: Vec<String>,
    #[serde(default)]
    pub selectively_disclosable: bool,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every required field and nothing else, so each test can add exactly the
    /// one section it is about.
    const MINIMAL: &str = r#"
server:
  wallet_facing:
    public_base_url: https://example.test
    bind: 127.0.0.1:8080
  admin:
    bind: 127.0.0.1:8081
storage:
  path: ./test.db
issuer:
  credential_issuer: https://example.test
  status_list:
    enabled: false
verifier:
  client_id_scheme: x509_san_dns
  signing_key: verifier-key
"#;

    fn parse(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("config should parse")
    }

    /// The backward-compatibility guarantee: adding `logging:` must not break a
    /// config file written before it existed.
    #[test]
    fn config_without_logging_block_yields_defaults() {
        let cfg = parse(MINIMAL);
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, LogFormat::Human);
        assert!(!cfg.logging.sensitive_payloads);
    }

    #[test]
    fn logging_block_parses_all_fields() {
        let yaml = format!(
            "{MINIMAL}\nlogging:\n  level: \"info,foundry_verifier=debug\"\n  format: json\n  sensitive_payloads: true\n"
        );
        let cfg = parse(&yaml);
        assert_eq!(cfg.logging.level, "info,foundry_verifier=debug");
        assert_eq!(cfg.logging.format, LogFormat::Json);
        assert!(cfg.logging.sensitive_payloads);
    }

    #[test]
    fn logging_block_with_only_level_defaults_the_rest() {
        let yaml = format!("{MINIMAL}\nlogging:\n  level: trace\n");
        let cfg = parse(&yaml);
        assert_eq!(cfg.logging.level, "trace");
        assert_eq!(cfg.logging.format, LogFormat::Human);
        assert!(!cfg.logging.sensitive_payloads);
    }

    #[test]
    fn both_log_formats_parse() {
        for (text, expected) in [("human", LogFormat::Human), ("json", LogFormat::Json)] {
            let yaml = format!("{MINIMAL}\nlogging:\n  format: {text}\n");
            assert_eq!(parse(&yaml).logging.format, expected);
        }
    }

    /// A typo in `format:` must be loud. Silently defaulting to `human` would
    /// hide a misconfiguration that changes how every log line is shaped.
    #[test]
    fn unknown_log_format_is_a_parse_error() {
        let yaml = format!("{MINIMAL}\nlogging:\n  format: yaml\n");
        let parsed: Result<Config, _> = serde_yaml::from_str(&yaml);
        assert!(
            parsed.is_err(),
            "an unknown log format must not be accepted"
        );
    }

    /// Regression guard against the real file, not just synthetic YAML.
    #[test]
    fn repository_config_yaml_still_loads() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.yaml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let cfg: Config = serde_yaml::from_str(&text)
            .unwrap_or_else(|e| panic!("the repository's own config.yaml must load: {e}"));
        // It has no `logging:` block today, so it must land on the defaults.
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, LogFormat::Human);
        assert!(!cfg.logging.sensitive_payloads);
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifierConfig {
    pub client_id_scheme: String,
    pub signing_key: String,
    #[serde(default)]
    pub response_encryption: Option<serde_json::Value>,
    #[serde(default)]
    pub transaction_data_hashes_alg: Vec<String>,
    #[serde(default)]
    pub named_queries: Vec<serde_json::Value>,
    #[serde(default)]
    pub webhook: Option<serde_json::Value>,
    /// Origins (e.g. `https://wallet.example.org`) that this Verifier accepts
    /// as the `origin:`-prefixed KB-JWT/response audience for the DC API
    /// transport (OpenID4VP L2543, IETF SD-JWT VC Presentation Response
    /// L3179). Deployment-specific and unknowable from `public_base_url`
    /// alone -- an Origin is a browsing-context property (RFC 6454), not a
    /// server identifier -- so it must be configured explicitly. When empty,
    /// `do_verify_vp_response` falls back to a single origin derived from
    /// `server.wallet_facing.public_base_url`, which keeps existing
    /// single-origin dev/test deployments working unconfigured.
    #[serde(default)]
    pub dc_api_expected_origins: Vec<String>,
}
