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

        for anchor in &self.trust_anchors {
            let path = base_dir.join(&anchor.certs);
            let pem = std::fs::read(&path).map_err(|e| {
                ConfigError::Validation(format!(
                    "trust anchor '{}' {}: {e}",
                    anchor.name,
                    path.display()
                ))
            })?;
            crate::trust::parse_cert_pem(&pem).map_err(|e| {
                ConfigError::Validation(format!("trust anchor '{}': {e}", anchor.name))
            })?;
        }

        Ok(())
    }
}
