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
}
