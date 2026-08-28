//! Outbound delivery of verification events to an operator-configured endpoint
//! (design `docs/superpowers/specs/2026-08-28-verifier-artifact-webhook-design.md`).
//!
//! Delivery is best-effort and at-most-once: the caller spawns it, nothing
//! awaits it, and a failure is a log record rather than a retry. Root
//! AGENTS.md §4.3 classifies HTTP outcomes by what the *protocol* did, and
//! "the audit sink was down" is none of those outcomes.

use crate::transaction::{VerificationResult, VerificationState};
use foundry_core::config::WebhookConfig;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Failures of the delivery path.
///
/// Deliberately **not** a `VerificationError` variant: a webhook failure never
/// reaches the HTTP error mappers in `crates/foundry/src/server.rs`, and adding
/// a variant they do not handle is how an unmapped error silently becomes a
/// 500 (root AGENTS.md §4.3).
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("http client init: {0}")]
    ClientInit(String),
    #[error("serialize event: {0}")]
    Serialization(String),
    #[error("hmac key: {0}")]
    Signing(String),
    #[error("deliver to {url}: {detail}")]
    Delivery { url: String, detail: String },
    #[error("endpoint returned HTTP {0}")]
    Status(u16),
}

impl WebhookError {
    /// Stable token for the `error.kind` log field, which root AGENTS.md §4.5
    /// makes operator-facing API. Renaming one is a breaking change.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ClientInit(_) => "webhook_client_init",
            Self::Serialization(_) => "webhook_serialization",
            Self::Signing(_) => "webhook_signing",
            Self::Delivery { .. } => "webhook_delivery",
            Self::Status(_) => "webhook_status",
        }
    }
}

/// An event delivered to the configured endpoint.
///
/// `#[serde(tag = "event")]` renders the discriminant as the `event` member the
/// receiver switches on. Artifact members use `skip_serializing_if` so that
/// with `include_raw_artifacts` off the key is **absent rather than null** --
/// a receiver can then test key presence instead of distinguishing "not
/// collected" from "collected as null" (design §4.2).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WebhookEvent {
    /// Emitted at the moment request bytes go to the wallet. Fires **per
    /// delivery**, so a wallet that fetches `GET /vp/request/:id` twice
    /// produces two events with different signatures -- ECDSA signing is
    /// randomized, so each really is different bytes (design D5).
    PresentationRequestDelivered {
        tx_id: String,
        transport: String,
        /// The signed transports (`request_uri`, `dc_api_signed`).
        #[serde(skip_serializing_if = "Option::is_none")]
        request_object_jws: Option<String>,
        /// The unsigned `dc_api` transport, which has no signed form.
        #[serde(skip_serializing_if = "Option::is_none")]
        dc_api_request: Option<serde_json::Value>,
    },
    /// Emitted on **both** the `Ok` and `Err` paths of `verify_vp_response` --
    /// a failed verification is the case this feed exists for.
    VerificationCompleted {
        tx_id: String,
        state: VerificationState,
        /// The full verdict, unconditionally (design D10).
        result: VerificationResult,
        #[serde(skip_serializing_if = "Option::is_none")]
        vp_token: Option<serde_json::Value>,
    },
}

impl WebhookEvent {
    /// The value of the `X-Foundry-Event` header, identical to the serialized
    /// `event` member.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::PresentationRequestDelivered { .. } => "presentation_request_delivered",
            Self::VerificationCompleted { .. } => "verification_completed",
        }
    }

    pub fn tx_id(&self) -> &str {
        match self {
            Self::PresentationRequestDelivered { tx_id, .. } => tx_id,
            Self::VerificationCompleted { tx_id, .. } => tx_id,
        }
    }
}

/// The resolved HMAC key, or `None` when unconfigured.
///
/// Resolution mirrors `AdminApiKey` (`crates/foundry/src/admin_auth.rs`): a
/// literal beats an environment variable name, and the lookup is injected so
/// tests exercise the env path without mutating process-global state --
/// `std::env::set_var` is `unsafe` in edition 2024 because the test harness is
/// multi-threaded.
#[derive(Debug, Clone, PartialEq)]
pub struct WebhookSecret(Option<String>);

impl WebhookSecret {
    pub fn resolve(cfg: &WebhookConfig) -> Self {
        Self::resolve_with(cfg, |name| std::env::var(name).ok())
    }

    fn resolve_with(cfg: &WebhookConfig, lookup: impl Fn(&str) -> Option<String>) -> Self {
        if let Some(s) = &cfg.secret {
            return Self(Some(s.clone()));
        }
        if let Some(env_name) = &cfg.secret_env
            && let Some(v) = lookup(env_name)
        {
            return Self(Some(v));
        }
        Self(None)
    }
}

/// `sha256=<hex>` over **exactly** `body`, or `None` when no secret is set.
///
/// The caller must transmit the same `&str` it passed here. This is why the
/// sink serializes once into a `String` and sends it with `.body(..)` rather
/// than `.json(..)`, which would re-serialize.
pub fn sign_body(secret: &WebhookSecret, body: &str) -> Result<Option<String>, WebhookError> {
    let Some(key) = secret.0.as_deref() else {
        return Ok(None);
    };
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| WebhookError::Signing(e.to_string()))?;
    mac.update(body.as_bytes());
    Ok(Some(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::CheckResult;
    use foundry_core::config::WebhookConfig;

    fn cfg(secret: Option<&str>, secret_env: Option<&str>) -> WebhookConfig {
        WebhookConfig {
            url: "https://audit.example.com/hook".to_string(),
            secret: secret.map(str::to_string),
            secret_env: secret_env.map(str::to_string),
            timeout_secs: 5,
            include_raw_artifacts: false,
        }
    }

    #[test]
    fn a_literal_secret_takes_precedence_over_the_env_name() {
        let resolved = WebhookSecret::resolve_with(&cfg(Some("literal"), Some("IGNORED")), |_| {
            Some("from-env".to_string())
        });
        assert_eq!(resolved, WebhookSecret(Some("literal".to_string())));
    }

    #[test]
    fn secret_env_is_read_through_the_injected_lookup() {
        let resolved =
            WebhookSecret::resolve_with(&cfg(None, Some("FOUNDRY_WEBHOOK_SECRET")), |n| {
                (n == "FOUNDRY_WEBHOOK_SECRET").then(|| "from-env".to_string())
            });
        assert_eq!(resolved, WebhookSecret(Some("from-env".to_string())));
    }

    #[test]
    fn no_secret_configured_yields_no_signature() {
        let secret = WebhookSecret::resolve_with(&cfg(None, None), |_| None);
        assert_eq!(sign_body(&secret, "{}").unwrap(), None);
    }

    #[test]
    fn the_signature_covers_the_exact_body_bytes() {
        let secret = WebhookSecret(Some("k".to_string()));
        let signed = sign_body(&secret, r#"{"a":1}"#).unwrap().unwrap();
        assert!(signed.starts_with("sha256="), "got: {signed}");

        // The whole point: one byte different, one signature different.
        let other = sign_body(&secret, r#"{"a":2}"#).unwrap().unwrap();
        assert_ne!(signed, other);
    }

    #[test]
    fn a_request_event_omits_absent_artifacts_rather_than_nulling_them() {
        let event = WebhookEvent::PresentationRequestDelivered {
            tx_id: "v_1".to_string(),
            transport: "request_uri".to_string(),
            request_object_jws: None,
            dc_api_request: None,
        };
        let v: serde_json::Value = serde_json::to_value(&event).unwrap();

        assert_eq!(v["event"], "presentation_request_delivered");
        assert_eq!(v["tx_id"], "v_1");
        // Absent, not null -- a receiver tests key presence (design §4.2).
        assert!(v.get("request_object_jws").is_none());
        assert!(v.get("dc_api_request").is_none());
    }

    #[test]
    fn a_completed_event_always_carries_the_verdict() {
        let event = WebhookEvent::VerificationCompleted {
            tx_id: "v_1".to_string(),
            state: VerificationState::Failed,
            result: VerificationResult {
                verified: false,
                checks: vec![CheckResult {
                    check: "jwe_decryption".to_string(),
                    passed: true,
                    detail: None,
                }],
                credentials: Vec::new(),
            },
            vp_token: None,
        };
        let v: serde_json::Value = serde_json::to_value(&event).unwrap();

        assert_eq!(v["event"], "verification_completed");
        assert_eq!(v["state"], "failed");
        assert_eq!(v["result"]["verified"], false);
        assert!(v.get("vp_token").is_none());
    }

    #[test]
    fn event_type_matches_the_serialized_discriminant() {
        let e = WebhookEvent::PresentationRequestDelivered {
            tx_id: "v_1".to_string(),
            transport: "dc_api".to_string(),
            request_object_jws: None,
            dc_api_request: None,
        };
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event"], e.event_type());
        assert_eq!(e.tx_id(), "v_1");
    }
}
