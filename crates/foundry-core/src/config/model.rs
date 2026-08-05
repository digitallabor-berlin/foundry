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
    /// RFC 9449 (DPoP) — sender-constrained access tokens. Absent means
    /// `Optional`, which reproduces foundry's pre-DPoP behaviour exactly.
    #[serde(default)]
    pub dpop: DpopConfig,
    /// OpenID4VCI §Credential Request (L848, L871) and §Credential Issuer
    /// Metadata (L1373): encryption of the Credential Request on top of TLS.
    /// Absent means the mechanism is off and `credential_request_encryption` is
    /// omitted from metadata entirely.
    #[serde(default)]
    pub request_encryption: Option<RequestEncryptionConfig>,
    /// OpenID4VCI §Credential Response (L960, L969) and §Credential Issuer
    /// Metadata (L1378): encryption of the Credential Response on top of TLS.
    ///
    /// Distinct from `verifier.response_encryption`, which configures the
    /// unrelated OpenID4VP authorization-response JWE.
    #[serde(default)]
    pub response_encryption: Option<ResponseEncryptionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationMode {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub trusted_anchors: Vec<TrustAnchor>,
    /// Sliding-window duration (ABCA §10.6, §12.1) bounding how old a Client
    /// Attestation PoP JWT's `iat` may be before it is rejected as stale; also
    /// the basis for the `jti` replay-store row's `expires_at`. Consulted
    /// **only** for `issuer.wallet_attestation` -- `AttestationMode` is shared
    /// with `issuer.key_attestation`, which has no PoP mechanism and never
    /// reads this field.
    #[serde(default = "default_pop_max_age_secs")]
    pub pop_max_age_secs: u64,
    /// ABCA draft -07 §8 challenge retrieval.
    ///
    /// - `disabled` (default) — no `/challenge` route, `challenge_endpoint` is
    ///   absent from AS metadata, and a `challenge` claim in a Client
    ///   Attestation PoP is ignored. Reproduces pre-challenge behaviour exactly.
    /// - `optional` — the route is served and advertised, but a PoP without a
    ///   `challenge` claim is still accepted. The migration rung: wallets adopt
    ///   at their own pace.
    /// - `required` — the route is served and advertised, and a PoP with no
    ///   `challenge` claim is rejected with `use_attestation_challenge` (§6.2).
    ///
    /// **`required` only binds a PoP that is actually presented.** This field
    /// strengthens a Client Attestation PoP; it is not an independent
    /// authentication requirement. Under `mode: Optional` a wallet presenting
    /// no attestation is never asked for a PoP, so no `challenge` is ever
    /// checked and `challenge_mode: Required` is effectively optional. Genuinely
    /// mandatory challenges need **both** `mode` and `challenge_mode` set to
    /// `Required`.
    ///
    /// Consulted **only** for `issuer.wallet_attestation` -- `AttestationMode`
    /// is shared with `issuer.key_attestation`, which has no PoP and therefore
    /// no challenge mechanism, and never reads this field. Same restriction as
    /// `pop_max_age_secs` above.
    #[serde(default = "default_disabled")]
    pub challenge_mode: Mode,
    /// Google Wallet's `android_keystore_attestation` proof type. Consulted
    /// **only** for `issuer.key_attestation`.
    #[serde(default)]
    pub android: AndroidKeystoreConfig,
}

fn default_pop_max_age_secs() -> u64 {
    300
}

/// Both ABCA challenge retrieval and DPoP nonces default to **off**.
///
/// Deliberately not `#[serde(default)]`: `Mode::default()` is `Optional`, which
/// would silently enable both mechanisms on every existing deployment.
fn default_disabled() -> Mode {
    Mode::Disabled
}

// Hand-written rather than derived: the derive would give `challenge_mode` the
// `Mode::default()` value (`Optional`), silently enabling ABCA challenge
// retrieval for any code path building this struct with `..Default::default()`.
impl Default for AttestationMode {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            trusted_anchors: Vec::new(),
            pop_max_age_secs: default_pop_max_age_secs(),
            challenge_mode: default_disabled(),
            android: AndroidKeystoreConfig::default(),
        }
    }
}

/// Google Wallet's `android_keystore_attestation` proof type.
///
/// Vendor profile: `docs/specs/google-wallet-openid4vci-profile.md`. Design:
/// `docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md`.
///
/// Consulted **only** for `issuer.key_attestation` -- `AttestationMode` is
/// shared with `issuer.wallet_attestation`, which has no such proof type and
/// never reads this field. Same restriction as `pop_max_age_secs` and
/// `challenge_mode`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AndroidKeystoreConfig {
    /// - `disabled` (default) — an `android_keystore_attestation` member in a
    ///   Credential Request is rejected, and the proof type is absent from
    ///   issuer metadata. Reproduces pre-support behaviour exactly.
    /// - `optional` — accepted alongside the `jwt` proof type.
    /// - `required` — accepted, and a `jwt` proofs member is rejected: a
    ///   Google-Wallet-only deployment.
    ///
    /// Deliberately `default_disabled()` rather than `#[serde(default)]`:
    /// `Mode::default()` is `Optional`, which would silently start accepting a
    /// proof type that carries no proof of possession of the attested key.
    #[serde(default = "default_disabled")]
    pub mode: Mode,
    /// Minimum accepted hardware security level, compared against **both**
    /// `attestationSecurityLevel` and `keyMintSecurityLevel` under
    /// `Software < TrustedEnvironment < StrongBox`.
    ///
    /// Advertised in issuer metadata as `proof_types_supported`
    /// `.android_keystore_attestation.key_attestations_required`
    /// `.key_mint_security_level`.
    #[serde(default = "default_key_mint_security_level")]
    pub key_mint_security_level: crate::trust::android_attestation::SecurityLevel,
}

fn default_key_mint_security_level() -> crate::trust::android_attestation::SecurityLevel {
    crate::trust::android_attestation::SecurityLevel::TrustedEnvironment
}

// Hand-written for the same reason `AttestationMode`'s is: a derived `Default`
// would give `mode` the `Mode::default()` value (`Optional`) and silently enable
// the proof type for any code path using `..Default::default()`.
impl Default for AndroidKeystoreConfig {
    fn default() -> Self {
        Self {
            mode: default_disabled(),
            key_mint_security_level: default_key_mint_security_level(),
        }
    }
}

/// RFC 9449 DPoP policy for the Token and Credential Endpoints.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DpopConfig {
    /// RFC 9449 §5 / §5.2.
    ///
    /// - `Optional` (default) — a valid `DPoP` proof yields a key-bound token
    ///   and `token_type: "DPoP"`; its absence yields `Bearer`, exactly as
    ///   before DPoP existed.
    /// - `Required` — equivalent to §5.2's `dpop_bound_access_tokens: true`:
    ///   a token request with no `DPoP` header is rejected.
    /// - `Disabled` — the header is **ignored** and `Bearer` is always issued.
    ///   Deliberately *not* "reject": §10.1 encourages clients that blindly
    ///   attach `DPoP` to every AS call, and §5 states an AS "MAY elect to
    ///   issue access tokens that are not DPoP bound, which is signaled to the
    ///   client with a value of `Bearer`". Rejecting would hard-fail a wallet
    ///   doing exactly what the RFC recommends.
    #[serde(default)]
    pub mode: Mode,
    /// RFC 9449 §4.3 check 11 / §11.1: how far from `now` a proof's `iat` may
    /// sit, in **either** direction — §11.1 explicitly permits accepting an
    /// `iat` "in the reasonably near future" to absorb clock skew.
    #[serde(default = "default_dpop_max_age_secs")]
    pub max_age_secs: u64,
    /// RFC 9449 §8 (authorization server) and §9 (resource server)
    /// server-provided nonce.
    ///
    /// - `disabled` (default) — no `DPoP-Nonce` header is ever emitted and a
    ///   `nonce` claim is ignored, so §11.3 is satisfied vacuously (the
    ///   pre-nonce behaviour recorded in the 2026-08-03 DPoP design §2.2).
    /// - `optional` — a `DPoP-Nonce` is supplied and a presented `nonce` is
    ///   verified, but a proof without one is still accepted.
    /// - `required` — a proof without a valid `nonce` is rejected with
    ///   `use_dpop_nonce` plus a fresh `DPoP-Nonce` header. This is what closes
    ///   §11.2 (proof pre-generation).
    ///
    /// **`required` only binds a proof that is actually presented.** This field
    /// strengthens a DPoP proof; it is not an independent authentication
    /// requirement. Under `mode: Optional` a wallet sending no `DPoP` header
    /// receives a `Bearer` token and never encounters the nonce requirement, so
    /// `nonce_mode: Required` is effectively optional. Genuinely mandatory
    /// nonces need **both** `mode` and `nonce_mode` set to `Required`.
    #[serde(default = "default_disabled")]
    pub nonce_mode: Mode,
}

fn default_dpop_max_age_secs() -> u64 {
    300
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            max_age_secs: default_dpop_max_age_secs(),
            nonce_mode: default_disabled(),
        }
    }
}

/// The only content-encryption algorithms foundry advertises or accepts.
///
/// HAIP OpenID4VP L260 requires both on the presentation side; mirroring them on
/// the issuance side keeps one algorithm story across the codebase.
pub const SUPPORTED_ENC_VALUES: [&str; 2] = ["A128GCM", "A256GCM"];

fn default_enc_values_supported() -> Vec<String> {
    SUPPORTED_ENC_VALUES.iter().map(|s| s.to_string()).collect()
}

/// OpenID4VCI `credential_request_encryption` (L1373–L1377).
#[derive(Debug, Clone, Deserialize)]
pub struct RequestEncryptionConfig {
    /// Names of `keys:` entries whose private keys decrypt Credential Requests.
    ///
    /// Ordered and non-empty. Listing several at once is how rotation happens
    /// without downtime: all are published and all decrypt.
    ///
    /// The referenced `keys:` entry carries `alg: ES256`, naming the **key
    /// material** (a P-256 EC key) — `validate_key_material` parses every entry's
    /// `alg` as a `SignatureAlgorithm`, so `ECDH-ES` there would fail startup.
    /// The published JWK carries `alg: "ECDH-ES"` instead; see
    /// `DecryptionKey::published_jwk`.
    pub keys: Vec<String>,
    #[serde(default = "default_enc_values_supported")]
    pub enc_values_supported: Vec<String>,
    /// L1377. `false` (the default) lets a wallet choose; `true` rejects an
    /// unencrypted Credential Request (L1192).
    #[serde(default)]
    pub encryption_required: bool,
}

/// OpenID4VCI `credential_response_encryption` (L1378–L1381).
///
/// No `alg_values_supported`: it is always `["ECDH-ES"]`, because
/// `foundry_core::crypto::jwe::encrypt_compact_with_kid` rejects every other
/// key-management algorithm. Making it configurable could only advertise
/// something the code cannot do.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseEncryptionConfig {
    #[serde(default = "default_enc_values_supported")]
    pub enc_values_supported: Vec<String>,
    /// L1381. `true` requires every Credential Response to be encrypted, which
    /// in turn requires the wallet to supply keys in the request.
    #[serde(default)]
    pub encryption_required: bool,
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
    /// The OAuth `scope` value that identifies this Credential Type.
    ///
    /// HAIP OpenID4VCI L186 requires the Credential Issuer metadata to carry a
    /// scope for every Credential Configuration, and L199/L209 require the value to
    /// map to a specific Credential Type. When unset, the credential type's `id` is
    /// used, so an unconfigured deployment is conformant without change; set it
    /// explicitly when an Ecosystem mandates a particular scope string.
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub cryptographic_holder_binding: bool,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
    #[serde(default)]
    pub claims: Vec<ClaimDef>,
}

impl CredentialType {
    /// The scope this Credential Type is published and requested under.
    /// HAIP OpenID4VCI L186/L199/L209 — see the `scope` field.
    pub fn resolved_scope(&self) -> &str {
        self.scope.as_deref().unwrap_or(&self.id)
    }
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

    /// GAP-HAIP-05 fixed the Client Identifier Prefix to `x509_hash` (HAIP
    /// OpenID4VP L256), leaving `verifier.client_id_scheme` with exactly one
    /// legal value -- not configuration -- so the field was deleted from
    /// `VerifierConfig`. No config struct sets `deny_unknown_fields`, so an
    /// existing deployment's `config.yaml` that still lists the now-removed
    /// key must keep loading rather than fail to parse.
    #[test]
    fn a_config_still_listing_the_removed_client_id_scheme_key_loads() {
        let yaml = MINIMAL.replacen(
            "verifier:\n",
            "verifier:\n  client_id_scheme: x509_san_dns\n",
            1,
        );
        let cfg = parse(&yaml);
        assert_eq!(cfg.verifier.signing_key, "verifier-key");
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

    /// Same shape as `MINIMAL` but with a caller-supplied `issuer:` block, so
    /// these tests can vary `wallet_attestation`/`key_attestation` without
    /// duplicating the `issuer:` key `MINIMAL` already declares.
    fn parse_with_issuer(issuer_block: &str) -> Config {
        let yaml = format!(
            "server:\n  wallet_facing:\n    public_base_url: https://example.test\n    bind: 127.0.0.1:8080\n  admin:\n    bind: 127.0.0.1:8081\nstorage:\n  path: ./test.db\n{issuer_block}\nverifier:\n  signing_key: verifier-key\n"
        );
        parse(&yaml)
    }

    /// GAP-VCI-14: a config omitting `pop_max_age_secs` under
    /// `wallet_attestation` must default to the ABCA section-10.6 sliding-
    /// window value the spec fixes at 300s.
    #[test]
    fn wallet_attestation_without_pop_max_age_secs_defaults_to_300() {
        let cfg = parse_with_issuer("issuer:\n  credential_issuer: https://example.test\n  wallet_attestation:\n    mode: required\n  status_list:\n    enabled: false\n");
        assert_eq!(cfg.issuer.wallet_attestation.pop_max_age_secs, 300);
    }

    /// An explicit value must be honoured, not silently overridden by the
    /// default.
    #[test]
    fn wallet_attestation_pop_max_age_secs_explicit_value_is_honoured() {
        let cfg = parse_with_issuer("issuer:\n  credential_issuer: https://example.test\n  wallet_attestation:\n    mode: required\n    pop_max_age_secs: 60\n  status_list:\n    enabled: false\n");
        assert_eq!(cfg.issuer.wallet_attestation.pop_max_age_secs, 60);
    }

    /// `0` is a legal (if operationally severe) value -- it must parse rather
    /// than being silently clamped. Whether to reject 0 at the validation
    /// layer is a separate, deliberately unmade decision (see the plan's
    /// Task 3 note); this test only pins that the deserializer itself is not
    /// the place that decision gets made implicitly.
    #[test]
    fn wallet_attestation_pop_max_age_secs_zero_still_parses() {
        let cfg = parse_with_issuer("issuer:\n  credential_issuer: https://example.test\n  wallet_attestation:\n    mode: required\n    pop_max_age_secs: 0\n  status_list:\n    enabled: false\n");
        assert_eq!(cfg.issuer.wallet_attestation.pop_max_age_secs, 0);
    }

    /// `AttestationMode` is shared by `key_attestation`, which has no PoP
    /// mechanism. Setting the field there must still parse cleanly (the type
    /// is shared) even though nothing in the codebase ever reads it for that
    /// path -- proven here by the absence of any `key_attestation`-scoped
    /// consumer, not by a runtime assertion.
    #[test]
    fn key_attestation_pop_max_age_secs_parses_but_has_no_consumer() {
        let cfg = parse_with_issuer("issuer:\n  credential_issuer: https://example.test\n  key_attestation:\n    mode: required\n    pop_max_age_secs: 60\n  status_list:\n    enabled: false\n");
        assert_eq!(cfg.issuer.key_attestation.pop_max_age_secs, 60);
    }

    #[test]
    fn dpop_defaults_to_optional_mode_and_a_300_second_window() {
        // RFC 9449 §5 permits Bearer when no proof is presented, so the default
        // must be the mode that preserves foundry's pre-DPoP behaviour.
        let cfg: DpopConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.mode, Mode::Optional);
        assert_eq!(cfg.max_age_secs, 300);
    }

    #[test]
    fn issuer_config_without_a_dpop_block_still_deserializes() {
        // Every config file in the wild predates this field.
        let json = serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "status_list": { "enabled": false }
        });
        let issuer: IssuerConfig = serde_json::from_value(json).unwrap();
        assert_eq!(issuer.dpop.mode, Mode::Optional);
        assert_eq!(issuer.dpop.max_age_secs, 300);
    }

    #[test]
    fn dpop_mode_deserializes_from_lowercase() {
        let cfg: DpopConfig =
            serde_json::from_str(r#"{"mode":"required","max_age_secs":60}"#).unwrap();
        assert_eq!(cfg.mode, Mode::Required);
        assert_eq!(cfg.max_age_secs, 60);
    }

    /// Both new toggles default to `Disabled`, not to `Mode::default()`
    /// (`Optional`). A wrong default would silently turn on ABCA challenge
    /// retrieval and DPoP nonces for every existing deployment.
    #[test]
    fn challenge_and_nonce_modes_default_to_disabled() {
        let attestation: AttestationMode = serde_json::from_str("{}").expect("attestation");
        assert_eq!(attestation.challenge_mode, Mode::Disabled);
        // The pre-existing default is unchanged.
        assert_eq!(attestation.mode, Mode::Optional);

        let dpop: DpopConfig = serde_json::from_str("{}").expect("dpop");
        assert_eq!(dpop.nonce_mode, Mode::Disabled);
        assert_eq!(dpop.mode, Mode::Optional);
    }

    /// `Default::default()` must agree with serde's default, or a `..Default::default()`
    /// struct literal anywhere in the codebase would enable the features silently.
    #[test]
    fn the_default_impls_agree_with_serde() {
        assert_eq!(AttestationMode::default().challenge_mode, Mode::Disabled);
        assert_eq!(DpopConfig::default().nonce_mode, Mode::Disabled);
    }

    #[test]
    fn challenge_and_nonce_modes_are_settable() {
        let attestation: AttestationMode =
            serde_json::from_str(r#"{"challenge_mode":"required"}"#).expect("attestation");
        assert_eq!(attestation.challenge_mode, Mode::Required);

        let dpop: DpopConfig = serde_json::from_str(r#"{"nonce_mode":"optional"}"#).expect("dpop");
        assert_eq!(dpop.nonce_mode, Mode::Optional);
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifierConfig {
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
