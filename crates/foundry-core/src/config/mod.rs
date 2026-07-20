mod model;
mod validate;

pub use model::*;

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
}