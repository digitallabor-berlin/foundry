use super::model::Config;
use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};
use crate::error::ConfigError;
use base64::Engine as _;
use std::path::Path;
use std::str::FromStr;

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Every verifier.signing_key must resolve into keys.
        if !self.keys.contains_key(&self.verifier.signing_key) {
            return Err(ConfigError::Validation(format!(
                "verifier.signing_key references unknown key '{}'",
                self.verifier.signing_key
            )));
        }
        // status_list.signing_key, when set, must resolve.
        if let Some(sk) = &self.issuer.status_list.signing_key {
            if !self.keys.contains_key(sk) {
                return Err(ConfigError::Validation(format!(
                    "issuer.status_list.signing_key references unknown key '{sk}'"
                )));
            }
        }
        // Credential types: supported formats + required identifier per format.
        for ct in &self.credential_types {
            match ct.format.as_str() {
                "dc+sd-jwt" => {
                    if ct.vct.is_none() {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (dc+sd-jwt) requires 'vct'",
                            ct.id
                        )));
                    }
                }
                "mso_mdoc" => {
                    if ct.doctype.is_none() {
                        return Err(ConfigError::Validation(format!(
                            "credential_type '{}' (mso_mdoc) requires 'doctype'",
                            ct.id
                        )));
                    }
                }
                other => {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has unsupported format '{other}'",
                        ct.id
                    )));
                }
            }

            // A zero lifetime yields exp == iat, so the credential is expired
            // the instant it is issued. That is a configuration error, not a
            // policy an operator could intend.
            if ct.validity_seconds == Some(0) {
                return Err(ConfigError::Validation(format!(
                    "credential_type '{}' has validity_seconds: 0; a credential whose \
                     exp equals its iat is never valid",
                    ct.id
                )));
            }

            // OpenID4VCI 1.0 Claims Path Pointer (L2366): a claims path pointer
            // is a *non-empty* array. An empty path addresses no claim, so no
            // supplied value can ever satisfy it -- reject at startup rather
            // than per offer. Closes the emptiness half of GAP-VCI-13; the
            // typing half (Vec<String> cannot express null or integer segments)
            // remains open.
            for cd in &ct.claims {
                if cd.path.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has a claim with an empty 'path'; a claims \
                         path pointer must be a non-empty array",
                        ct.id
                    )));
                }
            }
        }

        // HAIP OpenID4VCI L209: the scope value MUST map to a *specific* Credential
        // Type, so two types may not resolve to the same scope.
        let mut seen_scopes: std::collections::BTreeMap<&str, &str> =
            std::collections::BTreeMap::new();
        for ct in &self.credential_types {
            if let Some(explicit) = &ct.scope {
                if explicit.trim().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "credential_type '{}' has an empty 'scope'",
                        ct.id
                    )));
                }
            }
            if let Some(previous) = seen_scopes.insert(ct.resolved_scope(), &ct.id) {
                return Err(ConfigError::Validation(format!(
                    "credential_types '{}' and '{}' both resolve to scope '{}'; each \
                     scope must map to exactly one Credential Type",
                    previous,
                    ct.id,
                    ct.resolved_scope()
                )));
            }
        }

        // OpenID4VCI 1.0 Credential Issuer Metadata (L1368, L1369): `credential_endpoint`
        // and `nonce_endpoint`, both derived unconditionally from `issuer.credential_issuer`
        // (see `build_issuer_metadata`), MUST use the `https` scheme.
        //
        // Deliberate deviation (GAP-VCI-08, AGENTS.md §4.4): loopback hosts are exempt.
        // The repository's own dev config (`config.yaml`) runs `issuer.credential_issuer`
        // over plain `http://localhost:8443`, and enforcing the MUST unconditionally
        // would make that shipped config fail to boot. See `foundry-core/AGENTS.md`
        // Gotchas for the accepted consequence: a loopback deployment's RFC 9207 `iss`
        // value (also required to be `https`, RFC 9207 §2) will not be conformant either.
        if !self.issuer.credential_issuer.starts_with("https://") {
            let host = crate::url::dns_host_only(&self.issuer.credential_issuer);
            if !is_loopback_host(&host) {
                return Err(ConfigError::Validation(format!(
                    "issuer.credential_issuer '{}' must use the https scheme (OpenID4VCI \
                     credential_endpoint/nonce_endpoint MUST use https), unless its host is \
                     a loopback address",
                    self.issuer.credential_issuer
                )));
            }
        }

        // OpenID4VCI 1.0 Credential Issuer Metadata (L1366): `credential_issuer` MUST be
        // identical -- "compared using a simple string comparison with no normalization" --
        // to the identifier used to build the well-known URL, which in this deployment is
        // `server.wallet_facing.public_base_url` (the router `credential_issuer` is actually
        // served under). No trailing-slash or case tolerance.
        if self.issuer.credential_issuer != self.server.wallet_facing.public_base_url {
            return Err(ConfigError::Validation(format!(
                "issuer.credential_issuer '{}' must be byte-identical to \
                 server.wallet_facing.public_base_url '{}' (OpenID4VCI credential_issuer \
                 identity requires a simple string comparison with no normalization -- a \
                 trailing slash or scheme/case difference is a mismatch)",
                self.issuer.credential_issuer, self.server.wallet_facing.public_base_url
            )));
        }

        // RFC 9449 §4.3 check 11: a zero acceptance window makes every proof stale
        // the instant it is minted, so every DPoP request would fail with a blanket
        // invalid_dpop_proof. Caught at startup rather than at request time.
        if self.issuer.dpop.max_age_secs == 0 {
            return Err(ConfigError::Validation(
                "issuer.dpop.max_age_secs must be greater than 0".to_string(),
            ));
        }

        // OpenID4VCI Credential Issuer Metadata (L1373): `jwks` is REQUIRED, so
        // an enabled block with no resolvable keys is unservable metadata.
        if let Some(re) = &self.issuer.request_encryption {
            if re.keys.is_empty() {
                return Err(ConfigError::Validation(
                    "issuer.request_encryption.keys must be non-empty".to_string(),
                ));
            }
            for name in &re.keys {
                if !self.keys.contains_key(name) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references unknown key '{name}'"
                    )));
                }
                // One EC key must not serve both ECDSA signing and ECDH key
                // agreement. The `keys:` map is shared, so this is the only place
                // cross-purpose reuse can be prevented.
                if name == &self.verifier.signing_key {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which is also \
                         verifier.signing_key; an encryption key must not be reused for signing"
                    )));
                }
                if self.issuer.status_list.signing_key.as_deref() == Some(name.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "issuer.request_encryption.keys references '{name}', which is also \
                         issuer.status_list.signing_key; an encryption key must not be reused \
                         for signing"
                    )));
                }
            }
            check_enc_values("issuer.request_encryption", &re.enc_values_supported)?;
        }

        if let Some(rs) = &self.issuer.response_encryption {
            check_enc_values("issuer.response_encryption", &rs.enc_values_supported)?;
            // OpenID4VCI L960: a request carrying `credential_response_encryption`
            // MUST itself be encrypted. Requiring response encryption while
            // supporting no request decryption is unsatisfiable.
            let no_request_keys = match &self.issuer.request_encryption {
                None => true,
                Some(re) => re.keys.is_empty(),
            };
            if rs.encryption_required && no_request_keys {
                return Err(ConfigError::Validation(
                    "issuer.response_encryption.encryption_required is true but \
                     issuer.request_encryption has no keys; OpenID4VCI L960 requires a request \
                     carrying credential_response_encryption to be encrypted, so no conformant \
                     wallet could use this deployment"
                        .to_string(),
                ));
            }
        }

        // Fail closed at load time. With the proof type enabled and no anchors
        // every attestation chain would be rejected at request time -- a silent
        // total outage. Failing here makes it a legible misconfiguration.
        if self.issuer.key_attestation.android.mode != super::model::Mode::Disabled
            && self.issuer.key_attestation.trusted_anchors.is_empty()
        {
            return Err(ConfigError::Validation(
                "issuer.key_attestation.android.mode is enabled but \
                 issuer.key_attestation.trusted_anchors is empty: every \
                 android_keystore_attestation chain would be rejected"
                    .into(),
            ));
        }

        Ok(())
    }
}

/// An `enc` value may be advertised only if it can actually be honoured.
fn check_enc_values(block: &str, values: &[String]) -> Result<(), ConfigError> {
    if values.is_empty() {
        return Err(ConfigError::Validation(format!(
            "{block}.enc_values_supported must be non-empty"
        )));
    }
    for v in values {
        if !crate::config::SUPPORTED_ENC_VALUES.contains(&v.as_str()) {
            return Err(ConfigError::Validation(format!(
                "{block}.enc_values_supported contains unsupported value '{v}' (supported: {})",
                crate::config::SUPPORTED_ENC_VALUES.join(", ")
            )));
        }
    }
    Ok(())
}

/// GAP-VCI-08's documented exemption from the `https` MUST (OpenID4VCI L1368/L1369).
/// Exactly these four forms -- not private IP ranges, not `*.local`.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

impl Config {
    /// Filesystem-aware validation: every key/cert reference must resolve
    /// (relative to `base_dir`), keys must load as signers, x5c leaves must
    /// parse and MUST NOT be self-signed (HAIP §6.1.1), and trust-anchor
    /// certs must parse.
    pub fn validate_key_material(&self, base_dir: &Path) -> Result<(), ConfigError> {
        for (name, entry) in &self.keys {
            let alg = SignatureAlgorithm::from_str(&entry.alg)
                .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;
            let key_path = base_dir.join(&entry.private_key);
            let key_path = key_path.to_string_lossy();
            let signer = FileSigner::from_pem_file(&key_path, alg)
                .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;

            if let Some(x5c) = &entry.x5c {
                let cert_path = base_dir.join(x5c);
                let pem = std::fs::read(&cert_path).map_err(|e| {
                    ConfigError::Validation(format!(
                        "key '{name}' x5c {}: {e}",
                        cert_path.display()
                    ))
                })?;
                let cert = crate::trust::parse_cert_pem(&pem)
                    .map_err(|e| ConfigError::Validation(format!("key '{name}' x5c: {e}")))?;
                if crate::trust::is_self_signed(&cert) {
                    return Err(ConfigError::Validation(format!(
                        "key '{name}' x5c leaf must not be self-signed (HAIP §6.1.1)"
                    )));
                }

                // The private key must match its x5c leaf certificate.
                let jwk = signer
                    .public_jwk()
                    .map_err(|e| ConfigError::Validation(format!("key '{name}': {e}")))?;
                let kx = jwk.get("x").and_then(|v| v.as_str());
                let ky = jwk.get("y").and_then(|v| v.as_str());
                let (kx, ky) = match (kx, ky) {
                    (Some(x), Some(y)) => (
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(x)
                            .map_err(|e| {
                                ConfigError::Validation(format!("key '{name}': bad JWK x: {e}"))
                            })?,
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(y)
                            .map_err(|e| {
                                ConfigError::Validation(format!("key '{name}': bad JWK y: {e}"))
                            })?,
                    ),
                    _ => {
                        return Err(ConfigError::Validation(format!(
                            "key '{name}': public JWK missing EC coordinates"
                        )))
                    }
                };
                let (cx, cy) = crate::trust::cert_ec_public_coords(&cert)
                    .map_err(|e| ConfigError::Validation(format!("key '{name}' x5c: {e}")))?;
                if kx != cx || ky != cy {
                    return Err(ConfigError::Validation(format!(
                        "key '{name}' private key does not match its x5c leaf certificate"
                    )));
                }
            }
        }

        validate_trust_anchor_list(&self.trust_anchors, base_dir, "top-level")?;
        validate_trust_anchor_list(
            &self.issuer.wallet_attestation.trusted_anchors,
            base_dir,
            "issuer.wallet_attestation",
        )?;
        validate_trust_anchor_list(
            &self.issuer.key_attestation.trusted_anchors,
            base_dir,
            "issuer.key_attestation",
        )?;

        Ok(())
    }
}

fn validate_trust_anchor_list(
    anchors: &[super::model::TrustAnchor],
    base_dir: &Path,
    label: &str,
) -> Result<(), ConfigError> {
    for anchor in anchors {
        let path = base_dir.join(&anchor.certs);
        let pem = std::fs::read(&path).map_err(|e| {
            ConfigError::Validation(format!(
                "{label} trust anchor '{}' {}: {e}",
                anchor.name,
                path.display()
            ))
        })?;
        crate::trust::parse_cert_pem(&pem).map_err(|e| {
            ConfigError::Validation(format!("{label} trust anchor '{}': {e}", anchor.name))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::model::{
        AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, DpopConfig, IssuerConfig,
        LoggingConfig, Mode, ServerConfig, StatusListConfig, StorageConfig, TrustAnchor,
        VerifierConfig, WalletFacingConfig,
    };
    use std::collections::BTreeMap;

    fn minimal_config() -> Config {
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
            keys: BTreeMap::new(),
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                    pop_max_age_secs: 300,
                    challenge_mode: Mode::Disabled,
                    android: Default::default(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: None,
                    public_base_url: None,
                },
                dpop: DpopConfig::default(),
                request_encryption: None,
                response_encryption: None,
            },
            credential_types: Vec::new(),
            verifier: VerifierConfig {
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: Vec::new(),
                named_queries: Vec::new(),
                webhook: None,
                dc_api_expected_origins: Vec::new(),
            },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn key_attestation_trusted_anchor_must_resolve_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer
            .key_attestation
            .trusted_anchors
            .push(TrustAnchor {
                name: "wallet-provider-ca".to_string(),
                certs: "does-not-exist.pem".to_string(),
            });

        let err = cfg.validate_key_material(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("wallet-provider-ca"),
            "expected error to name the anchor, got: {msg}"
        );
    }

    #[test]
    fn key_attestation_trusted_anchor_parses_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(&key_path, km.private_pem).unwrap();

        let ca = crate::pki::new_ca("Wallet Provider Root CA", 3650).unwrap();
        let ca_path = dir.path().join("wallet-provider-ca.pem");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();

        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer
            .key_attestation
            .trusted_anchors
            .push(TrustAnchor {
                name: "wallet-provider-ca".to_string(),
                certs: "wallet-provider-ca.pem".to_string(),
            });

        cfg.validate_key_material(dir.path()).unwrap();
    }

    /// A config whose `verifier.signing_key` resolves, so that `Config::validate()`
    /// gets past the pre-existing keyref check and reaches the checks under test here.
    fn config_passing_keyref_check() -> Config {
        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "unused.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        cfg
    }

    #[test]
    fn minimal_config_with_matching_https_urls_passes_validate() {
        // Regression guard: neither new check fires on a well-formed config.
        // minimal_config() already pairs identical https URLs.
        config_passing_keyref_check().validate().unwrap();
    }

    #[test]
    fn non_loopback_http_credential_issuer_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "http://issuer.example.com".to_string();
        cfg.server.wallet_facing.public_base_url = "http://issuer.example.com".to_string();

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("https"),
            "expected an https-scheme error, got: {err}"
        );
    }

    #[test]
    fn loopback_http_credential_issuer_localhost_is_accepted() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "http://localhost:8443".to_string();
        cfg.server.wallet_facing.public_base_url = "http://localhost:8443".to_string();

        cfg.validate().unwrap();
    }

    #[test]
    fn loopback_http_credential_issuer_127_0_0_1_is_accepted() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "http://127.0.0.1:8443".to_string();
        cfg.server.wallet_facing.public_base_url = "http://127.0.0.1:8443".to_string();

        cfg.validate().unwrap();
    }

    #[test]
    fn credential_issuer_diverging_from_public_base_url_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.server.wallet_facing.public_base_url = "https://different-host.example.com".to_string();
        // cfg.issuer.credential_issuer stays at minimal_config()'s
        // "https://issuer.example.com" -- the two values now diverge.

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("public_base_url"),
            "expected an identity-mismatch error, got: {err}"
        );
    }

    #[test]
    fn credential_issuer_differing_only_by_trailing_slash_is_rejected() {
        // OpenID4VCI L1366: "a simple string comparison with no normalization" --
        // a trailing slash is a mismatch, not a benign variant.
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.credential_issuer = "https://issuer.example.com/".to_string();
        // public_base_url stays "https://issuer.example.com" (no trailing slash).

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("public_base_url"),
            "expected an identity-mismatch error, got: {err}"
        );
    }

    #[test]
    fn duplicate_resolved_scopes_are_rejected() {
        // HAIP OpenID4VCI L209: "The scope value MUST map to a specific Credential
        // Type." Two types resolving to one scope makes that unsatisfiable.
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![
            CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
            },
            CredentialType {
                id: "other".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/other".to_string()),
                doctype: None,
                // Collides with the first type's defaulted scope ("pid").
                scope: Some("pid".to_string()),
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
            },
        ];
        let err = cfg.validate().unwrap_err();
        assert!(
            format!("{err}").contains("scope"),
            "the error must name the scope collision: {err}"
        );
    }

    #[test]
    fn distinct_resolved_scopes_are_accepted() {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![
            CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/pid".to_string()),
                doctype: None,
                scope: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
            },
            CredentialType {
                id: "mdl".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.test/vct/mdl".to_string()),
                doctype: None,
                scope: Some("eu.europa.ec.eudi.pid.1".to_string()),
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![],
                validity_seconds: None,
            },
        ];
        cfg.validate().unwrap();
    }

    #[test]
    fn an_explicitly_blank_scope_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.credential_types = vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/pid".to_string()),
            doctype: None,
            scope: Some("   ".to_string()),
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: None,
        }];
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("scope"), "{err}");
    }

    #[test]
    fn resolved_scope_defaults_to_the_id() {
        let ct = CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://example.test/vct/pid".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![],
            validity_seconds: None,
        };
        assert_eq!(ct.resolved_scope(), "pid");
        let with_scope = CredentialType {
            scope: Some("s".to_string()),
            ..ct
        };
        assert_eq!(with_scope.resolved_scope(), "s");
    }

    #[test]
    fn a_zero_dpop_max_age_is_rejected() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.dpop.max_age_secs = 0;
        let err = cfg.validate().expect_err("max_age_secs 0 must be rejected");
        assert!(
            err.to_string().contains("issuer.dpop.max_age_secs"),
            "error must name the offending field, got: {err}"
        );
    }

    #[test]
    fn a_nonzero_dpop_max_age_validates() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.dpop.max_age_secs = 1;
        assert!(cfg.validate().is_ok());
    }

    fn cfg_with_signing_key() -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
        std::fs::write(dir.path().join("key.pem"), km.private_pem).unwrap();
        let mut cfg = minimal_config();
        cfg.keys.insert(
            "verifier_signing".to_string(),
            crate::config::model::KeyEntry {
                private_key: "key.pem".to_string(),
                x5c: None,
                alg: "ES256".to_string(),
            },
        );
        (cfg, dir)
    }

    fn req_enc(keys: Vec<String>) -> crate::config::RequestEncryptionConfig {
        crate::config::RequestEncryptionConfig {
            keys,
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: false,
        }
    }

    #[test]
    fn request_encryption_key_must_resolve() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(vec!["nope".to_string()]));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("nope"),
            "message must name the key, got: {msg}"
        );
    }

    #[test]
    fn request_encryption_keys_must_be_non_empty() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(Vec::new()));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("non-empty"), "got: {msg}");
    }

    #[test]
    fn an_encryption_key_may_not_also_be_a_signing_key() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.request_encryption = Some(req_enc(vec!["verifier_signing".to_string()]));
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("verifier_signing") && msg.contains("signing"),
            "got: {msg}"
        );
    }

    #[test]
    fn required_response_encryption_needs_request_encryption() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.response_encryption = Some(crate::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A128GCM".to_string()],
            encryption_required: true,
        });
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("request_encryption"), "got: {msg}");
    }

    #[test]
    fn advertised_enc_values_must_be_supported() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.issuer.response_encryption = Some(crate::config::ResponseEncryptionConfig {
            enc_values_supported: vec!["A192GCM".to_string()],
            encryption_required: false,
        });
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("A192GCM"), "got: {msg}");
    }

    #[test]
    fn loads_request_decryption_keys_and_derives_distinct_kids() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = minimal_config();
        for name in ["enc_a", "enc_b"] {
            let km = crate::pki::generate_ec_key(crate::crypto::SignatureAlgorithm::Es256).unwrap();
            std::fs::write(dir.path().join(format!("{name}.pem")), km.private_pem).unwrap();
            cfg.keys.insert(
                name.to_string(),
                crate::config::model::KeyEntry {
                    private_key: format!("{name}.pem"),
                    x5c: None,
                    alg: "ES256".to_string(),
                },
            );
        }
        cfg.issuer.request_encryption =
            Some(req_enc(vec!["enc_a".to_string(), "enc_b".to_string()]));
        let keys = cfg.load_request_decryption_keys(dir.path()).unwrap();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].kid(), keys[1].kid());
    }

    #[test]
    fn loads_no_keys_when_the_feature_is_off() {
        let cfg = minimal_config();
        assert!(cfg
            .load_request_decryption_keys(std::path::Path::new("."))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn encryption_blocks_default_to_both_gcm_sizes_and_optional() {
        let yaml = "server:\n  wallet_facing:\n    public_base_url: https://example.test\n    bind: 127.0.0.1:8080\n  admin:\n    bind: 127.0.0.1:8081\nstorage:\n  path: ./t.db\nissuer:\n  credential_issuer: https://example.test\n  status_list:\n    enabled: false\n  request_encryption:\n    keys: [k]\n  response_encryption: {}\nverifier:\n  signing_key: verifier-key\n";
        let cfg: Config = serde_yaml::from_str(yaml).expect("config should parse");
        let re = cfg.issuer.request_encryption.as_ref().unwrap();
        assert_eq!(re.enc_values_supported, vec!["A128GCM", "A256GCM"]);
        assert!(!re.encryption_required);
        let rs = cfg.issuer.response_encryption.as_ref().unwrap();
        assert_eq!(rs.enc_values_supported, vec!["A128GCM", "A256GCM"]);
        assert!(!rs.encryption_required);
    }

    #[test]
    fn android_keystore_attestation_requires_trust_anchors() {
        let mut cfg = config_passing_keyref_check();
        cfg.issuer.key_attestation.android.mode = Mode::Optional;
        cfg.issuer.key_attestation.trusted_anchors = Vec::new();
        let err = cfg
            .validate()
            .expect_err("enabling the proof type with no anchors must fail at load time");
        let msg = err.to_string();
        assert!(
            msg.contains("android") && msg.contains("trusted_anchors"),
            "the message must name both fields, got: {msg}"
        );
    }

    #[test]
    fn android_keystore_attestation_disabled_needs_no_anchors() {
        let cfg = config_passing_keyref_check();
        assert_eq!(
            cfg.issuer.key_attestation.android.mode,
            Mode::Disabled,
            "the default must be Disabled so no deployment changes behaviour on upgrade"
        );
        cfg.validate()
            .expect("the default configuration stays valid");
    }

    #[test]
    fn android_key_mint_security_level_defaults_to_trusted_environment() {
        let cfg = minimal_config();
        assert_eq!(
            cfg.issuer.key_attestation.android.key_mint_security_level,
            crate::trust::android_attestation::SecurityLevel::TrustedEnvironment
        );
    }

    /// A `dc+sd-jwt` credential type with whatever claims the caller supplies.
    /// `minimal_config()` ships no credential types, so validation tests that
    /// need one construct it here rather than indexing an empty vec.
    fn sd_jwt_type(claims: Vec<ClaimDef>, validity_seconds: Option<u64>) -> CredentialType {
        CredentialType {
            id: "dpc".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("com.emvco.dpc.card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims,
            validity_seconds,
        }
    }

    /// A credential whose `exp` equals its `iat` is never usable — that is a
    /// configuration error, not a policy choice.
    #[test]
    fn validity_seconds_may_not_be_zero() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![sd_jwt_type(vec![], Some(0))];
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("validity_seconds"),
            "error must name the offending field, got: {msg}"
        );
    }

    /// A non-zero lifetime must still pass, so the check is narrow.
    #[test]
    fn a_nonzero_validity_seconds_passes() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![sd_jwt_type(vec![], Some(43_200))];
        cfg.validate().expect("a 12-hour lifetime is valid");
    }

    /// An empty claims path pointer addresses nothing, so no supplied value can
    /// ever satisfy it. Catching it at startup beats failing per offer.
    /// Closes the emptiness half of GAP-VCI-13.
    #[test]
    fn claim_path_may_not_be_empty() {
        let (mut cfg, _dir) = cfg_with_signing_key();
        cfg.credential_types = vec![sd_jwt_type(
            vec![ClaimDef {
                path: vec![],
                required: None,
                selectively_disclosable: true,
                display: vec![],
            }],
            None,
        )];
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(
            msg.contains("path"),
            "error must name the offending field, got: {msg}"
        );
    }
}
