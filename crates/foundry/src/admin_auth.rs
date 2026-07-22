//! Bearer-token authentication for the admin HTTP surface. Resolves the
//! expected key from `AdminConfig.api_key` (literal, takes precedence) or
//! `AdminConfig.api_key_env` (an environment variable name). If neither is
//! configured, auth is a no-op — acceptable for local dev, never for a
//! production deployment (log a warning at startup in that case).

use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use foundry_core::config::AdminConfig;

#[derive(Clone)]
pub struct AdminApiKey(pub Option<String>);

impl AdminApiKey {
    pub fn resolve(cfg: &AdminConfig) -> Self {
        if let Some(k) = &cfg.api_key {
            return Self(Some(k.clone()));
        }
        if let Some(env_name) = &cfg.api_key_env {
            if let Ok(v) = std::env::var(env_name) {
                return Self(Some(v));
            }
        }
        Self(None)
    }
}

pub async fn require_api_key(
    State(expected): State<AdminApiKey>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected_key) = &expected.0 else {
        return Ok(next.run(request).await);
    };
    let provided = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match provided {
        Some(token) if token == expected_key => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(api_key: Option<&str>, api_key_env: Option<&str>) -> AdminConfig {
        AdminConfig {
            bind: "127.0.0.1:9000".to_string(),
            api_key: api_key.map(str::to_string),
            api_key_env: api_key_env.map(str::to_string),
            swagger_ui_enabled: true,
        }
    }

    #[test]
    fn literal_api_key_takes_precedence() {
        std::env::set_var("FOUNDRY_TEST_ADMIN_KEY_PRECEDENCE", "from-env");
        let cfg = cfg_with(
            Some("from-literal"),
            Some("FOUNDRY_TEST_ADMIN_KEY_PRECEDENCE"),
        );
        let resolved = AdminApiKey::resolve(&cfg);
        assert_eq!(resolved.0.as_deref(), Some("from-literal"));
        std::env::remove_var("FOUNDRY_TEST_ADMIN_KEY_PRECEDENCE");
    }

    #[test]
    fn falls_back_to_env_var_when_no_literal_key() {
        std::env::set_var("FOUNDRY_TEST_ADMIN_KEY_FALLBACK", "from-env-only");
        let cfg = cfg_with(None, Some("FOUNDRY_TEST_ADMIN_KEY_FALLBACK"));
        let resolved = AdminApiKey::resolve(&cfg);
        assert_eq!(resolved.0.as_deref(), Some("from-env-only"));
        std::env::remove_var("FOUNDRY_TEST_ADMIN_KEY_FALLBACK");
    }

    #[test]
    fn resolves_to_none_when_neither_is_set() {
        let cfg = cfg_with(None, None);
        let resolved = AdminApiKey::resolve(&cfg);
        assert!(resolved.0.is_none());
    }

    #[test]
    fn resolves_to_none_when_env_var_is_unset_and_no_literal() {
        let cfg = cfg_with(None, Some("FOUNDRY_TEST_ADMIN_KEY_DOES_NOT_EXIST"));
        let resolved = AdminApiKey::resolve(&cfg);
        assert!(resolved.0.is_none());
    }
}
