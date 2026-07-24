//! Wallet configuration file (`wallet.yaml`) parsing. See
//! docs/superpowers/specs/2026-07-24-foundry-wallet-cli-design.md section 3.

use crate::error::{WalletError, WalletResult};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct WalletConfig {
    pub data_dir: PathBuf,
    pub endpoints: EndpointsConfig,
    pub trust: TrustConfig,
    #[serde(default)]
    pub issuance_presets: BTreeMap<String, IssuancePreset>,
    #[serde(default)]
    pub verification_presets: BTreeMap<String, VerificationPreset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EndpointsConfig {
    pub admin_base_url: String,
    pub wallet_base_url: String,
    #[serde(default)]
    pub admin_api_key: Option<String>,
    #[serde(default)]
    pub admin_api_key_env: Option<String>,
}

impl EndpointsConfig {
    /// Prefer an inline key; fall back to the named env var; error if neither
    /// is configured or the env var is unset.
    pub fn resolve_admin_api_key(&self) -> WalletResult<String> {
        if let Some(key) = &self.admin_api_key {
            return Ok(key.clone());
        }
        if let Some(env_name) = &self.admin_api_key_env {
            return std::env::var(env_name)
                .map_err(|_| WalletError::Config(format!("env var '{env_name}' is not set")));
        }
        Err(WalletError::Config(
            "endpoints.admin_api_key or endpoints.admin_api_key_env is required".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustConfig {
    pub validation: TrustValidationMode,
    #[serde(default)]
    pub anchors: Vec<TrustAnchorConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustValidationMode {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustAnchorConfig {
    pub certs: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuancePreset {
    pub credential_type_id: String,
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub tx_code_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationPreset {
    pub dcql_query: serde_json::Value,
    #[serde(default = "default_transport")]
    pub transport: String,
}

fn default_transport() -> String {
    "request_uri".to_string()
}

impl WalletConfig {
    pub fn load(path: &Path) -> WalletResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| WalletError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
        let cfg: WalletConfig = serde_yaml::from_str(&text)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
data_dir: ./wallet-data
endpoints:
  admin_base_url: http://127.0.0.1:9000
  wallet_base_url: http://127.0.0.1:8443
  admin_api_key: dev-admin-key
trust:
  validation: enabled
  anchors:
    - certs: ./trust/root-ca.pem
issuance_presets:
  pid:
    credential_type_id: pid
    claims:
      given_name: Alice
      birthdate: "1990-01-01"
    tx_code_required: false
verification_presets:
  dcql1:
    dcql_query:
      credentials:
        - id: c1
          format: dc+sd-jwt
          meta: { vct_values: ["https://issuer.example.com/vct/pid"] }
          claims:
            - path: ["given_name"]
    transport: request_uri
"#;

    #[test]
    fn loads_a_full_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.yaml");
        std::fs::write(&path, SAMPLE_YAML).unwrap();

        let cfg = WalletConfig::load(&path).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from("./wallet-data"));
        assert_eq!(cfg.endpoints.admin_base_url, "http://127.0.0.1:9000");
        assert_eq!(cfg.trust.validation, TrustValidationMode::Enabled);
        assert_eq!(cfg.trust.anchors.len(), 1);
        let preset = cfg.issuance_presets.get("pid").unwrap();
        assert_eq!(preset.credential_type_id, "pid");
        assert_eq!(
            preset.claims.get("given_name"),
            Some(&serde_json::json!("Alice"))
        );
        assert!(cfg.verification_presets.contains_key("dcql1"));
    }

    #[test]
    fn resolve_admin_api_key_prefers_inline_value() {
        let endpoints = EndpointsConfig {
            admin_base_url: "http://x".to_string(),
            wallet_base_url: "http://y".to_string(),
            admin_api_key: Some("inline-key".to_string()),
            admin_api_key_env: None,
        };
        assert_eq!(endpoints.resolve_admin_api_key().unwrap(), "inline-key");
    }

    #[test]
    fn resolve_admin_api_key_errors_when_neither_configured() {
        let endpoints = EndpointsConfig {
            admin_base_url: "http://x".to_string(),
            wallet_base_url: "http://y".to_string(),
            admin_api_key: None,
            admin_api_key_env: None,
        };
        let err = endpoints.resolve_admin_api_key().unwrap_err();
        assert_eq!(err.kind(), "config");
    }

    #[test]
    fn load_errors_on_missing_file() {
        let err = WalletConfig::load(Path::new("/nonexistent/wallet.yaml")).unwrap_err();
        assert_eq!(err.kind(), "storage");
    }
}
