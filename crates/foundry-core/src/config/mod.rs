pub mod mdoc;
mod model;
mod validate;

pub use model::*;
pub use validate::validate_paso_transaction_data_type_metadata;

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

    /// The key that signs issued credentials, as `(name, entry)`.
    ///
    /// Resolution order: `issuer.credential_signing_key`, else
    /// `issuer.status_list.signing_key`, else the first entry in `keys`.
    ///
    /// Only the first step is design. The other two are the behaviour
    /// `handle_credential_request` has always had, back when no field named
    /// the credential signer at all: one configured key signed both Status
    /// List Tokens and credentials, and only the status-list spelling was ever
    /// given a config field. They are retained rather than removed because
    /// dropping them would silently re-key every deployment that has not yet
    /// set `issuer.credential_signing_key`.
    ///
    /// Both fallbacks are hazards, not conveniences. The second couples two
    /// distinct trust roles — credential issuer and status-list authority —
    /// so rotating one key invalidates the other identity with it. The third
    /// is `BTreeMap` order, i.e. **alphabetical**, not the order the operator
    /// wrote: an ECDH-ES Credential-Request decryption key named early in the
    /// alphabet can win, which would sign credentials with a key-agreement key
    /// and emit no `x5c`. `Config::validate` rejects that last case rather
    /// than letting it resolve.
    ///
    /// It exists as a method because two call sites need the *same* answer:
    /// `handle_credential_request` builds the signer from it, and
    /// `build_issuer_metadata` advertises its algorithm in
    /// `credential_signing_alg_values_supported`. Resolved independently, the
    /// two can disagree — and then the issuer advertises one algorithm and
    /// signs with another, which OpenID4VCI 1.0 L2223 makes a conformance
    /// defect for `mso_mdoc` specifically (the advertised COSE value SHOULD
    /// match the `alg` in the `IssuerAuth` header).
    ///
    /// `None` only when `keys` is empty, which `Config::validate_key_material`
    /// rejects at startup for any issuer that can serve a credential.
    pub fn credential_signing_key(&self) -> Option<(&str, &KeyEntry)> {
        let name = self
            .issuer
            .credential_signing_key
            .as_deref()
            .or(self.issuer.status_list.signing_key.as_deref())
            .or_else(|| self.keys.keys().next().map(|s| s.as_str()))?;
        self.keys.get_key_value(name).map(|(k, v)| (k.as_str(), v))
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
