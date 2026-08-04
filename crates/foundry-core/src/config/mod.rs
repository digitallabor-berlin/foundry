mod model;
mod validate;

pub use model::*;

use crate::crypto::jwe::DecryptionKey;
use crate::error::ConfigError;
use std::path::Path;

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let is_json = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if is_json {
            serde_json::from_str(&text).map_err(|e| ConfigError::Parse {
                format: "json".into(),
                message: e.to_string(),
            })
        } else {
            serde_yaml::from_str(&text).map_err(|e| ConfigError::Parse {
                format: "yaml".into(),
                message: e.to_string(),
            })
        }
    }

    /// Load the private keys that decrypt Credential Requests.
    ///
    /// Called once at startup — never per request. Returns an empty vector when
    /// `issuer.request_encryption` is absent, which is what makes the feature
    /// default-off.
    pub fn load_request_decryption_keys(
        &self,
        base_dir: &Path,
    ) -> Result<Vec<DecryptionKey>, ConfigError> {
        let Some(re) = &self.issuer.request_encryption else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(re.keys.len());
        for name in &re.keys {
            let entry = self.keys.get(name).ok_or_else(|| {
                ConfigError::Validation(format!(
                    "issuer.request_encryption.keys references unknown key '{name}'"
                ))
            })?;
            let path = base_dir.join(&entry.private_key);
            let key = DecryptionKey::from_pem_file(&path.to_string_lossy()).map_err(|e| {
                ConfigError::Validation(format!("issuer.request_encryption key '{name}': {e}"))
            })?;
            out.push(key);
        }
        Ok(out)
    }
}
