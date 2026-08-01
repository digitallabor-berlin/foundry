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
        }
        Ok(())
    }
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
        AdminConfig, AttestationMode, Config, IssuerConfig, LoggingConfig, Mode, ServerConfig,
        StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
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
                },
                key_attestation: AttestationMode {
                    mode: Mode::Optional,
                    trusted_anchors: Vec::new(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: None,
                    public_base_url: None,
                },
            },
            credential_types: Vec::new(),
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
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
}
