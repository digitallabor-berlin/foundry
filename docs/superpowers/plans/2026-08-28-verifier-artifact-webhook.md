# Verifier Artifact Webhook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver verification events — the verdict, and optionally the verbatim Request Object and `vp_token` — to an operator-configured HTTP endpoint, storing nothing.

**Architecture:** A `WebhookSink` trait in `foundry-verifier` (mirroring the existing `StatusListResolver`) with an HTTP implementation that HMAC-signs the exact bytes it transmits. All dispatch happens in `crates/foundry/src/server.rs` via a fire-and-forget `tokio::spawn`, so no wallet-facing response can be affected by the endpoint's health. The `vp_token` travels to the event through an out-param and is never a field on a persisted type.

**Tech Stack:** Rust 2024, axum, reqwest (rustls-tls, **no** `json` feature), `hmac` + `sha2` + `hex`, `async-trait`, `thiserror`, `tracing`.

**Spec:** [`docs/superpowers/specs/2026-08-28-verifier-artifact-webhook-design.md`](../specs/2026-08-28-verifier-artifact-webhook-design.md)

## Global Constraints

- **Test runner is `cargo nextest run`, never `cargo test`.** The gate (root AGENTS.md §5.1) is, in order: `cargo fmt`; `cargo nextest run --workspace --no-fail-fast --status-level fail`; `cargo clippy --workspace --all-targets -- -D warnings`. There is one gate and it is the whole workspace — no per-crate tier.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside `#[cfg(test)]` (root AGENTS.md §4.1).
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (root AGENTS.md §4.5).
- **Never logged:** the webhook event body, the webhook secret, the computed signature. Log field names are operator-facing API — `event`, `tx_id`, `http.status`, `latency_ms`, `error.kind`, `error.detail`.
- **Dependency layering is one-directional.** `foundry-core` → `foundry-sd-jwt-vc`/`foundry-mdoc` → `foundry-issuer`/`foundry-verifier` → `foundry`. Never introduce an upward or sideways dependency.
- **`url` is NOT a workspace crate.** Do not add it; the scheme/host check is hand-rolled in Task 1.
- **`foundry-verifier`'s `reqwest` has no `json` feature.** Serialize the body to a `String` once, sign those bytes, send them with `.body(..)`. Never `.json(..)` — it would re-serialize and could transmit bytes other than the ones signed.
- **`openapi.json` is NOT regenerated.** No route, request shape, or response shape changes.
- Spec deviations must be documented inline with a comment naming the spec section (root AGENTS.md §4.4).

---

### Task 1: `WebhookConfig` type and validation

**Files:**

- Modify: `crates/foundry-core/src/config/model.rs:980` (the `webhook` field) and the `VerifierConfig` block
- Modify: `crates/foundry-core/src/config/validate.rs` (inside `Config::validate`)
- Test: `crates/foundry-core/src/config/validate.rs` (inline `#[cfg(test)]`)

**Interfaces:**

- Consumes: nothing.
- Produces: `foundry_core::config::WebhookConfig { url: String, secret: Option<String>, secret_env: Option<String>, timeout_secs: u64, include_raw_artifacts: bool }`, and `VerifierConfig.webhook: Option<WebhookConfig>`. Every later task reads this type.

- [ ] **Step 1: Write the failing tests**

Add to the inline `#[cfg(test)] mod tests` in `crates/foundry-core/src/config/validate.rs`. `minimal_config()` already exists there; it sets `webhook: None`.

```rust
    fn config_with_webhook(url: &str, include_raw_artifacts: bool) -> Config {
        let mut cfg = config_passing_keyref_check();
        cfg.verifier.webhook = Some(crate::config::WebhookConfig {
            url: url.to_string(),
            secret: None,
            secret_env: None,
            timeout_secs: 5,
            include_raw_artifacts,
        });
        cfg
    }

    #[test]
    fn webhook_url_must_be_https_for_a_routable_host() {
        let err = config_with_webhook("http://audit.example.com/hook", false)
            .validate()
            .expect_err("plaintext to a routable host must be rejected");
        assert!(
            err.to_string().contains("verifier.webhook.url"),
            "error must name the offending key, got: {err}"
        );
    }

    #[test]
    fn webhook_url_accepts_https() {
        config_with_webhook("https://audit.example.com/hook", false)
            .validate()
            .expect("https must be accepted");
    }

    #[test]
    fn webhook_url_accepts_plaintext_on_loopback() {
        for url in [
            "http://localhost:9000/hook",
            "http://127.0.0.1:9000/hook",
            "http://[::1]:9000/hook",
        ] {
            config_with_webhook(url, false)
                .validate()
                .unwrap_or_else(|e| panic!("loopback {url} must be accepted, got: {e}"));
        }
    }

    #[test]
    fn webhook_rejects_a_url_with_no_recognised_scheme() {
        let err = config_with_webhook("audit.example.com/hook", false)
            .validate()
            .expect_err("a schemeless url must be rejected");
        assert!(err.to_string().contains("verifier.webhook.url"));
    }
```

Note: `config_passing_keyref_check()` is the existing helper used by the neighbouring tests in this module; reuse it rather than `minimal_config()` if that is what the surrounding tests use — check the file and match.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-core webhook`
Expected: FAIL to **compile** — `WebhookConfig` does not exist. That is the correct first failure.

- [ ] **Step 3: Add the type**

In `crates/foundry-core/src/config/model.rs`, add above `VerifierConfig`:

```rust
/// Delivery target for verification events (design §4.1).
///
/// Its *presence* is the enable flag: absent, no sink is constructed and no
/// code path changes. `include_raw_artifacts` is deliberately a second,
/// nested gate — it is the one that authorises holder PII to leave the
/// process, and conflating it with "webhook on" would make a verdict feed and
/// a PII egress the same decision.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// Destination URL. Must be `https`, unless the host is a loopback
    /// address — enforced by `Config::validate()`.
    pub url: String,
    /// HMAC key, literal. Takes precedence over [`Self::secret_env`], the same
    /// precedence `AdminConfig.api_key` has over `api_key_env`.
    #[serde(default)]
    pub secret: Option<String>,
    /// Name of an environment variable holding the HMAC key.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// Per-delivery HTTP timeout. Bounds the spawned task only; no
    /// wallet-facing request ever waits on it.
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,
    /// Transmit the verbatim Request Object and `vp_token` alongside the
    /// verdict. **Off by default: these carry holder PII in the clear.**
    #[serde(default)]
    pub include_raw_artifacts: bool,
}

fn default_webhook_timeout() -> u64 {
    5
}
```

Then change the existing field on `VerifierConfig` from

```rust
    pub webhook: Option<serde_json::Value>,
```

to

```rust
    pub webhook: Option<WebhookConfig>,
```

The 24 `VerifierConfig` literals across the workspace all write `webhook: None`, which stays valid — do not edit them.

Export it: confirm `WebhookConfig` is reachable as `foundry_core::config::WebhookConfig`. If `config/mod.rs` re-exports `model`'s items by name rather than glob, add `WebhookConfig` to that list.

- [ ] **Step 4: Add the validation**

In `crates/foundry-core/src/config/validate.rs`, add these free functions near the other helpers at the bottom of the file (outside `impl Config`):

```rust
/// Whether `url` may receive holder PII.
///
/// `https` always; `http` only to a loopback host. Hand-rolled rather than
/// using a URL parser because `url` is not a workspace dependency and adding
/// one for a scheme check is not warranted.
fn webhook_url_is_acceptable(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    match webhook_http_host(url) {
        Some(host) => is_loopback_host(host),
        None => false,
    }
}

/// The host of an `http://` URL, with userinfo, port, and path removed.
/// Returns `None` for any other scheme.
fn webhook_http_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // `user:pass@host` -> `host`; a bare `host` is unchanged.
    let authority = authority.rsplit('@').next()?;
    // IPv6 literals are bracketed: `[::1]:9000` -> `::1`.
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next();
    }
    authority.split(':').next()
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host == "::1" {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
}
```

Then inside `Config::validate()`, before the final `Ok(())`:

```rust
        // Design §4.1 — the webhook may carry holder PII, so plaintext to a
        // routable host is a configuration error rather than a warning.
        if let Some(wh) = &self.verifier.webhook {
            if !webhook_url_is_acceptable(&wh.url) {
                return Err(ConfigError::Validation(format!(
                    "verifier.webhook.url must use https, or http to a loopback host; got '{}'",
                    wh.url
                )));
            }
            // Permitted (the receiver may be on a trusted network) but never
            // silent: without a secret the receiver cannot establish that an
            // audit record came from this verifier.
            if wh.include_raw_artifacts && wh.secret.is_none() && wh.secret_env.is_none() {
                tracing::warn!(
                    "verifier.webhook.include_raw_artifacts is enabled with no secret or \
                     secret_env; holder PII will be delivered unsigned"
                );
            }
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-core webhook`
Expected: PASS, 4 tests.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all pass. Quote the summary line.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/config/model.rs crates/foundry-core/src/config/validate.rs
git commit -m "feat(config): type verifier.webhook and validate its URL scheme"
```

---

### Task 2: Event types, secret resolution, and HMAC signing

**Files:**

- Create: `crates/foundry-verifier/src/webhook.rs`
- Modify: `crates/foundry-verifier/src/lib.rs`
- Modify: `crates/foundry-verifier/Cargo.toml`
- Test: `crates/foundry-verifier/src/webhook.rs` (inline `#[cfg(test)]`)

**Interfaces:**

- Consumes: `foundry_core::config::WebhookConfig` (Task 1); `VerificationResult` and `VerificationState` from `crate::transaction`.
- Produces:
  - `WebhookEvent` (enum, `Serialize`) with variants `PresentationRequestDelivered { tx_id, transport, request_object_jws, dc_api_request }` and `VerificationCompleted { tx_id, state, result, vp_token }`
  - `WebhookEvent::event_type(&self) -> &'static str`, `WebhookEvent::tx_id(&self) -> &str`
  - `WebhookSecret::resolve(&WebhookConfig) -> WebhookSecret`
  - `sign_body(&WebhookSecret, &str) -> Result<Option<String>, WebhookError>`
  - `WebhookError` with `kind(&self) -> &'static str`

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry-verifier/src/webhook.rs` containing **only** this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
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
        let resolved = WebhookSecret::resolve_with(&cfg(None, Some("FOUNDRY_WEBHOOK_SECRET")), |n| {
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
        // Absent, not null — a receiver tests key presence (design §4.2).
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
```

Register the module in `crates/foundry-verifier/src/lib.rs` — add `pub mod webhook;` to the module list (alphabetically, after `pub mod transaction;`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-verifier webhook`
Expected: FAIL to compile — `WebhookEvent`, `WebhookSecret`, `sign_body` do not exist.

- [ ] **Step 3: Add the `hmac` dependency**

In `crates/foundry-verifier/Cargo.toml`, in `[dependencies]` beside the existing `sha2`:

```toml
hmac = { workspace = true }
```

`hex` and `thiserror` are already dependencies of this crate; do not re-add them.

- [ ] **Step 4: Write the implementation**

Prepend to `crates/foundry-verifier/src/webhook.rs`, above the test module:

```rust
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
/// with `include_raw_artifacts` off the key is **absent rather than null** —
/// a receiver can then test key presence instead of distinguishing "not
/// collected" from "collected as null" (design §4.2).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WebhookEvent {
    /// Emitted at the moment request bytes go to the wallet. Fires **per
    /// delivery**, so a wallet that fetches `GET /vp/request/:id` twice
    /// produces two events with different signatures — ECDSA signing is
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
    /// Emitted on **both** the `Ok` and `Err` paths of `verify_vp_response` —
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
/// tests exercise the env path without mutating process-global state —
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
```

The test module references `CheckResult`; extend the existing `use crate::transaction::{...}` line to include it, or add `use crate::transaction::CheckResult;` inside `mod tests`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-verifier webhook`
Expected: PASS, 7 tests.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-verifier/src/webhook.rs crates/foundry-verifier/src/lib.rs crates/foundry-verifier/Cargo.toml
git commit -m "feat(verifier): webhook event types, secret resolution, HMAC signing"
```

---

### Task 3: `WebhookSink` trait and `HttpWebhookSink`

**Files:**

- Modify: `crates/foundry-verifier/src/webhook.rs`
- Modify: `crates/foundry-verifier/src/lib.rs` (`pub use`)
- Test: `crates/foundry-verifier/src/webhook.rs` (inline `#[cfg(test)]`)

**Interfaces:**

- Consumes: everything from Task 2.
- Produces:
  - `#[async_trait::async_trait] pub trait WebhookSink: Send + Sync { async fn deliver(&self, event: &WebhookEvent) -> Result<u16, WebhookError>; }` — returns the HTTP status so the caller can log `http.status` on success
  - `HttpWebhookSink::new(&WebhookConfig) -> Result<HttpWebhookSink, WebhookError>`
  - `build_signed_request_parts(&WebhookSecret, &WebhookEvent) -> Result<(String, Option<String>), WebhookError>` — `(body, signature)`, factored out so the exact bytes are testable without a network
- Re-exported from `crates/foundry-verifier/src/lib.rs` as `pub use webhook::{HttpWebhookSink, WebhookError, WebhookEvent, WebhookSink};`

- [ ] **Step 1: Write the failing tests**

Add inside the existing `mod tests` in `crates/foundry-verifier/src/webhook.rs`:

```rust
    #[test]
    fn the_signed_bytes_are_the_bytes_that_will_be_sent() {
        let secret = WebhookSecret(Some("k".to_string()));
        let event = WebhookEvent::PresentationRequestDelivered {
            tx_id: "v_1".to_string(),
            transport: "request_uri".to_string(),
            request_object_jws: Some("eyJ0eXAi.aaa.bbb".to_string()),
            dc_api_request: None,
        };

        let (body, signature) = build_signed_request_parts(&secret, &event).unwrap();

        // The signature must verify against `body` verbatim — this is the
        // invariant that forbids `.json(..)` re-serialization at the call site.
        assert_eq!(signature, sign_body(&secret, &body).unwrap());
        assert!(signature.is_some());

        // And `body` must really be the event.
        let round_tripped: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(round_tripped["tx_id"], "v_1");
        assert_eq!(round_tripped["request_object_jws"], "eyJ0eXAi.aaa.bbb");
    }

    #[test]
    fn an_unsecured_sink_produces_a_body_and_no_signature() {
        let secret = WebhookSecret(None);
        let event = WebhookEvent::PresentationRequestDelivered {
            tx_id: "v_1".to_string(),
            transport: "dc_api".to_string(),
            request_object_jws: None,
            dc_api_request: Some(serde_json::json!({ "response_type": "vp_token" })),
        };

        let (body, signature) = build_signed_request_parts(&secret, &event).unwrap();
        assert!(signature.is_none());
        assert!(body.contains("\"dc_api_request\""));
    }

    #[test]
    fn http_sink_construction_succeeds_for_a_valid_config() {
        HttpWebhookSink::new(&cfg(Some("k"), None)).expect("client must build");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-verifier webhook`
Expected: FAIL to compile — `build_signed_request_parts` and `HttpWebhookSink` do not exist.

- [ ] **Step 3: Write the implementation**

Append to the non-test portion of `crates/foundry-verifier/src/webhook.rs`:

```rust
use std::time::Duration;

/// Where verification events go.
///
/// A trait rather than a concrete call so tests inject a recording fake and
/// the suite needs no mock HTTP server — the same shape as
/// [`crate::status::StatusListResolver`].
#[async_trait::async_trait]
pub trait WebhookSink: Send + Sync {
    /// Deliver one event, returning the HTTP status on success so the caller
    /// can record `http.status`.
    async fn deliver(&self, event: &WebhookEvent) -> Result<u16, WebhookError>;
}

/// The exact `(body, signature)` pair to transmit.
///
/// Factored out of [`HttpWebhookSink::deliver`] so the bytes-and-signature
/// invariant is testable without a network.
pub fn build_signed_request_parts(
    secret: &WebhookSecret,
    event: &WebhookEvent,
) -> Result<(String, Option<String>), WebhookError> {
    let body =
        serde_json::to_string(event).map_err(|e| WebhookError::Serialization(e.to_string()))?;
    let signature = sign_body(secret, &body)?;
    Ok((body, signature))
}

/// Production sink: one `POST` per event.
///
/// The `reqwest::Client` is built once and held, unlike
/// `HttpStatusListResolver::new()` which `crates/foundry/src/server.rs`
/// constructs per request — a `Client` owns a connection pool, and rebuilding
/// it per delivery would defeat keep-alive to a single, fixed endpoint.
pub struct HttpWebhookSink {
    client: reqwest::Client,
    url: String,
    secret: WebhookSecret,
}

impl HttpWebhookSink {
    pub fn new(cfg: &WebhookConfig) -> Result<Self, WebhookError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .build()
            .map_err(|e| WebhookError::ClientInit(e.to_string()))?;
        Ok(Self {
            client,
            url: cfg.url.clone(),
            secret: WebhookSecret::resolve(cfg),
        })
    }
}

#[async_trait::async_trait]
impl WebhookSink for HttpWebhookSink {
    async fn deliver(&self, event: &WebhookEvent) -> Result<u16, WebhookError> {
        let (body, signature) = build_signed_request_parts(&self.secret, event)?;

        let mut req = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("x-foundry-event", event.event_type());
        if let Some(sig) = signature {
            req = req.header("x-foundry-signature", sig);
        }

        // `.body(body)` and never `.json(event)`: the signature above covers
        // these exact bytes, and re-serializing could transmit different ones.
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| WebhookError::Delivery {
                url: self.url.clone(),
                detail: e.to_string(),
            })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(WebhookError::Status(status.as_u16()));
        }
        Ok(status.as_u16())
    }
}
```

Add to `crates/foundry-verifier/src/lib.rs`:

```rust
pub use webhook::{HttpWebhookSink, WebhookError, WebhookEvent, WebhookSink};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-verifier webhook`
Expected: PASS, 10 tests.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-verifier/src/webhook.rs crates/foundry-verifier/src/lib.rs
git commit -m "feat(verifier): WebhookSink trait and HTTP implementation"
```

---

### Task 4: Capture the `vp_token` through an out-param

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` (`verify_vp_response` ~line 219, `do_verify_vp_response` ~line 1281, the `vp_token` extraction ~line 1318)
- Modify: `crates/foundry/src/server.rs:1687` (the sole production call site)
- Test: `crates/foundry-verifier/src/verify.rs` (inline `#[cfg(test)]`)

**Interfaces:**

- Consumes: `foundry_core::config::WebhookConfig` (Task 1).
- Produces: `verify_vp_response(config, tx, encrypted_jwe_str, resolver, captured_vp_token: &mut Option<serde_json::Value>)`. Task 6 reads the populated local.

**Why an out-param and not a field on `VerificationTransaction`:** the transaction is serialized wholesale into storage. Keeping the token off that type means it *cannot* reach storage — a structural guarantee rather than a discipline someone must remember at each save site (design D8).

- [ ] **Step 1: Write the failing test**

The existing test module in `verify.rs` has helpers that build a `Config` and drive a verification. Find an existing **failing-verification** test (several assert `tx.state == VerificationState::Failed`, e.g. around lines 2491–2736) and model this on its setup, reusing its helpers verbatim.

```rust
    /// The case the feed exists for: a verification that FAILED still yields
    /// the token, because it is captured at extraction before any check runs
    /// (design D3/§4.5).
    #[tokio::test]
    async fn vp_token_is_captured_even_when_verification_fails() {
        // Reuse the harness of the neighbouring failure test; it must produce a
        // response that decrypts cleanly and then fails a later check.
        let (config, mut tx, jwe, resolver) = failing_verification_fixture().await;

        let mut config = config;
        config.verifier.webhook = Some(foundry_core::config::WebhookConfig {
            url: "https://audit.example.com/hook".to_string(),
            secret: None,
            secret_env: None,
            timeout_secs: 5,
            include_raw_artifacts: true,
        });

        let mut captured = None;
        let _ = verify_vp_response(&config, &mut tx, &jwe, &resolver, &mut captured).await;

        assert_eq!(tx.state, VerificationState::Failed, "precondition");
        let token = captured.expect("vp_token must survive a failed verification");
        assert!(token.is_object(), "vp_token is an object keyed by query id");
    }

    /// Off by default: no webhook configured means nothing is even cloned.
    #[tokio::test]
    async fn vp_token_is_not_captured_when_no_webhook_is_configured() {
        let (config, mut tx, jwe, resolver) = failing_verification_fixture().await;

        let mut captured = None;
        let _ = verify_vp_response(&config, &mut tx, &jwe, &resolver, &mut captured).await;

        assert!(captured.is_none());
    }
```

`failing_verification_fixture()` is a name for whatever setup the neighbouring failure test already performs — if no such helper exists, inline that test's setup into both tests rather than inventing an abstraction.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry-verifier vp_token_is_captured`
Expected: FAIL to compile — `verify_vp_response` takes four arguments, not five.

- [ ] **Step 3: Thread the out-param**

In `crates/foundry-verifier/src/verify.rs`, change the signature of `verify_vp_response`:

```rust
pub async fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
    /// Receives the decrypted `vp_token` when `verifier.webhook.include_raw_artifacts`
    /// is set — populated at extraction, so it survives every later failure.
    captured_vp_token: &mut Option<serde_json::Value>,
) -> Result<VerificationResult, VerificationError> {
```

Pass it through at the `do_verify_vp_response` call (~line 236):

```rust
    match do_verify_vp_response(config, tx, encrypted_jwe_str, resolver, captured_vp_token).await {
```

Change `do_verify_vp_response`'s signature to match (it keeps `tx: &VerificationTransaction`; only the new parameter is added):

```rust
async fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
    captured_vp_token: &mut Option<serde_json::Value>,
) -> Result<VerifyOutcome, VerificationError> {
```

Immediately after the `vp_token` extraction (~line 1318), before any check:

```rust
    // Captured BEFORE any check runs, so a structural failure later still
    // yields the bytes the receiver needs to diagnose it (design D3/§4.5).
    // Gated so an unconfigured deployment does not even clone the value.
    if config
        .verifier
        .webhook
        .as_ref()
        .is_some_and(|w| w.include_raw_artifacts)
    {
        *captured_vp_token = Some(vp_token.clone());
    }
```

- [ ] **Step 4: Update the production call site**

In `crates/foundry/src/server.rs`, at the `verify_vp_response` call (~line 1687), introduce the local and pass it. Task 6 consumes it; for now it is `let _`-adjacent but must be a real binding:

```rust
    let mut captured_vp_token: Option<serde_json::Value> = None;
    let verify_res = foundry_verifier::verify_vp_response(
        &state.config,
        &mut tx,
        encrypted_jwe_str,
        &resolver,
        &mut captured_vp_token,
    )
    .await;
```

If clippy reports `captured_vp_token` as unused at this point, that is expected until Task 6 — do **not** silence it with an underscore prefix, because Task 6 renames it back. Instead complete Task 6 before running clippy, or accept the warning locally and let Step 6's gate run after Task 6. If you need a green gate at this commit, add a temporary read: `let _ = &captured_vp_token;` and delete it in Task 6.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry-verifier vp_token_is_captured`
Expected: PASS, 2 tests.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs crates/foundry/src/server.rs
git commit -m "feat(verifier): capture vp_token at extraction via out-param"
```

---

### Task 5: Hold the sink in `AppState` and build it in `serve()`

**Files:**

- Modify: `crates/foundry/src/server.rs:27-61` (`AppState` and its builders), and `serve()` (~line 1877)
- Create: the `RecordingSink` test double in `crates/foundry/tests/support/mod.rs`
- Test: `crates/foundry/tests/support/mod.rs` plus one assertion in a new test file `crates/foundry/tests/webhook_delivery.rs`

**Interfaces:**

- Consumes: `foundry_verifier::{HttpWebhookSink, WebhookEvent, WebhookSink}` (Tasks 2–3).
- Produces:
  - `AppState.webhook_sink: Option<Arc<dyn WebhookSink>>`
  - `AppState::with_webhook_sink(self, sink: Arc<dyn WebhookSink>) -> Self`
  - `support::RecordingSink` + `support::recording_sink() -> (Arc<RecordingSink>, UnboundedReceiver<WebhookEvent>)`

**Test-double design — read this before writing it.** Dispatch is `tokio::spawn`ed, so a test that asserts on a `Vec<WebhookEvent>` behind a `Mutex` immediately after the HTTP call is a **race**, and nextest's per-test process isolation will not save it. The fake therefore sends each event on an `mpsc::UnboundedSender` and the test `await`s `recv()` under a timeout. That is deterministic: the assertion blocks until the spawned task has actually delivered.

**Fixture warning — this bites in Tasks 6 and 7.** `support::setup_without_encryption` sets `verifier.signing_key: "verifier_signing"` while its `keys` map contains only `issuer_key`. **No verification flow can run against it** — `verifier_x5c_leaf_pem` will fail. It is fine for *this* task's two smoke tests, which only inspect `AppState` fields, but Tasks 6 and 7 must use a verification-capable fixture copied from `crates/foundry/tests/wallet_verification.rs`'s `setup_test_app`. That copying is deliberate: `support/mod.rs`'s own header records this repository's convention that fixture helpers are **duplicated across test binaries** rather than shared through the crate's public API.

- [ ] **Step 1: Write the test double and the failing test**

Add to `crates/foundry/tests/support/mod.rs`:

```rust
/// A `WebhookSink` that hands every delivered event to the test over a
/// channel.
///
/// A channel rather than a shared `Vec`: dispatch is `tokio::spawn`ed, so a
/// test that inspects a `Vec` right after the HTTP call races the spawned
/// task. Awaiting `recv()` blocks until delivery has actually happened.
pub struct RecordingSink {
    tx: tokio::sync::mpsc::UnboundedSender<foundry_verifier::WebhookEvent>,
}

#[async_trait::async_trait]
impl foundry_verifier::WebhookSink for RecordingSink {
    async fn deliver(
        &self,
        event: &foundry_verifier::WebhookEvent,
    ) -> Result<u16, foundry_verifier::WebhookError> {
        let _ = self.tx.send(event.clone());
        Ok(200)
    }
}

pub fn recording_sink() -> (
    std::sync::Arc<RecordingSink>,
    tokio::sync::mpsc::UnboundedReceiver<foundry_verifier::WebhookEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (std::sync::Arc::new(RecordingSink { tx }), rx)
}

/// Await the next delivered event, failing the test rather than hanging.
pub async fn next_event(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<foundry_verifier::WebhookEvent>,
) -> foundry_verifier::WebhookEvent {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for a webhook event")
        .expect("sink channel closed without delivering an event")
}
```

`async-trait` must be a dev-dependency of the `foundry` crate for this `impl`. Check `crates/foundry/Cargo.toml`; if absent, add `async-trait = { workspace = true }` under `[dev-dependencies]`.

Create `crates/foundry/tests/webhook_delivery.rs` with one test proving injection works:

```rust
mod support;

#[tokio::test]
async fn an_unconfigured_app_state_holds_no_sink() {
    let (state, _dir) = support::setup_without_encryption().await;
    assert!(
        state.webhook_sink.is_none(),
        "no verifier.webhook config must mean no sink"
    );
}

#[tokio::test]
async fn a_sink_can_be_attached_for_tests() {
    let (state, _dir) = support::setup_without_encryption().await;
    let (sink, _rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);
    assert!(state.webhook_sink.is_some());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry --test webhook_delivery`
Expected: FAIL to compile — `AppState` has no `webhook_sink` field and no `with_webhook_sink`.

- [ ] **Step 3: Extend `AppState`**

In `crates/foundry/src/server.rs`, add the field to the struct (after `request_decryption_keys`):

```rust
    /// Destination for verification events, or `None` when
    /// `verifier.webhook` is unconfigured — which makes "webhook off" an
    /// `is_none()` check at each dispatch site rather than a config re-read.
    pub webhook_sink: Option<Arc<dyn foundry_verifier::WebhookSink>>,
```

Set it in `new()`:

```rust
            webhook_sink: None,
```

Add the builder beside `with_request_decryption_keys`, matching its rationale:

```rust
    /// Attach the verification-event sink.
    ///
    /// A builder rather than another `new` parameter, for the same reason
    /// `with_request_decryption_keys` is one: the many existing
    /// `AppState::new` call sites stay unchanged.
    pub fn with_webhook_sink(mut self, sink: Arc<dyn foundry_verifier::WebhookSink>) -> Self {
        self.webhook_sink = Some(sink);
        self
    }
```

- [ ] **Step 4: Construct it in `serve()`**

In `serve()`, where `AppState` is built, construct the sink from config:

```rust
    // Built once: a reqwest::Client owns a connection pool, and this endpoint
    // is fixed for the process lifetime.
    let state = match &cfg.verifier.webhook {
        Some(w) => {
            let sink = foundry_verifier::HttpWebhookSink::new(w)?;
            tracing::info!(
                include_raw_artifacts = w.include_raw_artifacts,
                "verification event webhook enabled"
            );
            state.with_webhook_sink(Arc::new(sink))
        }
        None => state,
    };
```

Place this immediately after the existing `AppState` construction and before the routers are built. The `?` works because `serve()` returns `anyhow::Result` and `WebhookError` implements `std::error::Error` via `thiserror`. Note the log line records the *setting*, never the URL's secret, and the URL itself is operator-authored config — safe, but omitted here as it adds nothing at startup.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry --test webhook_delivery`
Expected: PASS, 2 tests.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/support/mod.rs crates/foundry/tests/webhook_delivery.rs crates/foundry/Cargo.toml
git commit -m "feat(server): hold the verification-event sink in AppState"
```

---

### Task 6: Dispatch `verification_completed`

**Files:**

- Modify: `crates/foundry/src/server.rs` (`submit_vp_response` ~line 1647, plus a new `dispatch_webhook` helper)
- Test: `crates/foundry/tests/webhook_delivery.rs`

**Interfaces:**

- Consumes: `AppState.webhook_sink` (Task 5); `captured_vp_token` (Task 4); `WebhookEvent::VerificationCompleted` (Task 2).
- Produces: `fn dispatch_webhook(state: &AppState, event: WebhookEvent)` — used again by Task 7.

- [ ] **Step 1: Write the failing tests**

First add the verification-capable fixture to `crates/foundry/tests/webhook_delivery.rs`. Do **not** reach for `support::setup_without_encryption` — see Task 5's fixture warning.

```rust
/// Copied from `wallet_verification.rs`'s `setup_test_app`, per this
/// repository's convention that fixture helpers are duplicated across test
/// binaries rather than shared (see `support/mod.rs`'s header). The only
/// change is that `verifier.webhook` is populated before `AppState::new`.
///
/// Returns the same tuple the original does, so the flow bodies of
/// `wallet_verification.rs`'s tests can be reused verbatim.
async fn setup_with_webhook(
    include_raw_artifacts: bool,
) -> (AppState, tempfile::TempDir, String, String) {
    // 1. Copy the body of `wallet_verification.rs::setup_test_app` verbatim.
    // 2. Immediately before its `AppState::new(...)` line, insert:
    //
    //        config.verifier.webhook = Some(foundry_core::config::WebhookConfig {
    //            url: "https://audit.example.test/hook".to_string(),
    //            secret: Some("s3cr3t".to_string()),
    //            secret_env: None,
    //            timeout_secs: 5,
    //            include_raw_artifacts,
    //        });
    //
    //    which requires changing its `let config = Config { .. }` to
    //    `let mut config = Config { .. }`.
    // 3. Return its existing tuple unchanged.
    todo!("copy wallet_verification.rs::setup_test_app, then set config.verifier.webhook")
}
```

The `todo!()` is a scaffold marker for the implementer to replace in this same step — it must not survive to the commit in Step 7. Then the tests, whose flow bodies come from `wallet_verification.rs`:

```rust
/// The point of the feature: a FAILED verification still delivers, and carries
/// the token that explains why.
#[tokio::test]
async fn a_failed_verification_delivers_the_verdict_and_the_vp_token() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_with_webhook(true).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    // Drive a presentation that decrypts cleanly and then fails a check.
    // `wallet_verification.rs` already contains such a flow — lift its request
    // and response construction, then submit to POST /vp/response/:id.
    let _ = run_failing_presentation(state, &issuer_cert_pem, &issuer_key_pem).await;

    let event = support::next_event(&mut rx).await;
    match event {
        foundry_verifier::WebhookEvent::VerificationCompleted {
            state: tx_state,
            result,
            vp_token,
            ..
        } => {
            assert_eq!(tx_state, foundry_verifier::VerificationState::Failed);
            assert!(!result.verified, "the verdict travels with the event");
            assert!(vp_token.is_some(), "artifacts are on for this fixture");
        }
        other => panic!("expected VerificationCompleted, got {other:?}"),
    }
}

/// With artifacts off, the verdict still travels but the PII does not.
#[tokio::test]
async fn the_verdict_is_delivered_without_artifacts_by_default() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_with_webhook(false).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    let _ = run_successful_presentation(state, &issuer_cert_pem, &issuer_key_pem).await;

    match support::next_event(&mut rx).await {
        foundry_verifier::WebhookEvent::VerificationCompleted { result, vp_token, .. } => {
            assert!(result.verified);
            assert!(vp_token.is_none(), "artifacts must be off by default");
        }
        other => panic!("expected VerificationCompleted, got {other:?}"),
    }
}

/// §4.3: a broken sink must not be visible to the wallet.
#[tokio::test]
async fn a_failing_sink_does_not_change_the_wallet_response() {
    // Run the SAME successful flow twice and compare, so the assertion is
    // "identical to no-sink" rather than a hardcoded expectation that could
    // drift with the response shape.
    let (baseline_status, baseline_body) = {
        let (state, _dir, cert, key) = setup_with_webhook(true).await;
        // no sink attached
        run_successful_presentation(state, &cert, &key).await
    };

    let (with_sink_status, with_sink_body) = {
        let (state, _dir, cert, key) = setup_with_webhook(true).await;
        let state = state.with_webhook_sink(std::sync::Arc::new(support::FailingSink));
        run_successful_presentation(state, &cert, &key).await
    };

    assert_eq!(baseline_status, with_sink_status);
    assert_eq!(baseline_body, with_sink_body);
}
```

Extract the shared flow body into one helper in this file so both arms above are literally the same code path:

```rust
/// Drive a full successful presentation and return the wallet's
/// `POST /vp/response/:id` status and body.
///
/// The body is `wallet_verification.rs`'s `full_verification_flow_end_to_end`,
/// stopping at the wallet's response submission rather than going on to the
/// admin GET.
async fn run_successful_presentation(
    state: AppState,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    todo!("lift steps 1-6 of wallet_verification.rs::full_verification_flow_end_to_end")
}

/// The same, for a presentation that decrypts cleanly and then FAILS a check.
///
/// Model on `wallet_verification.rs::dcql_vct_mismatch_is_rejected`
/// (line ~993): a `vct` the query did not ask for is a **policy** verdict, so
/// the wallet still gets HTTP 200 with `verified: false` and the transaction
/// reaches `VerificationState::Failed` — root AGENTS.md §4.3. That is the
/// right shape here, because a structural 400 would abort before the
/// `vp_token` is even extracted and would not exercise D3.
async fn run_failing_presentation(
    state: AppState,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    todo!("lift wallet_verification.rs::dcql_vct_mismatch_is_rejected's flow body")
}
```

Add the erroring double to `support/mod.rs`:

```rust
/// A sink that always fails, for proving §4.3: delivery problems must be
/// invisible to the wallet.
pub struct FailingSink;

#[async_trait::async_trait]
impl foundry_verifier::WebhookSink for FailingSink {
    async fn deliver(
        &self,
        _event: &foundry_verifier::WebhookEvent,
    ) -> Result<u16, foundry_verifier::WebhookError> {
        Err(foundry_verifier::WebhookError::Status(500))
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry --test webhook_delivery`
Expected: FAIL — `next_event` times out, because nothing dispatches yet.

- [ ] **Step 3: Add the dispatch helper**

In `crates/foundry/src/server.rs`, near the other private helpers:

```rust
/// Fire-and-forget delivery of one verification event.
///
/// Deliberately **not** awaited. Root AGENTS.md §4.3 classifies an HTTP
/// outcome by what the protocol did — structural fault 400, policy verdict
/// 200, status-fetch outage 502 — and "the operator's audit sink was down" is
/// none of those. Awaiting would let a slow endpoint add latency to a wallet's
/// request and a dead one change its status code, so delivery is best-effort
/// and at-most-once (design D2).
fn dispatch_webhook(state: &AppState, event: foundry_verifier::WebhookEvent) {
    let Some(sink) = state.webhook_sink.clone() else {
        return;
    };
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let event_type = event.event_type();
        let tx_id = event.tx_id().to_string();
        let latency_ms = || started.elapsed().as_millis() as u64;

        // The event body is never logged: it is the payload this feature
        // exists to move, and carries holder PII (root AGENTS.md §4.5).
        match sink.deliver(&event).await {
            Ok(status) => tracing::debug!(
                event = event_type,
                tx_id = %tx_id,
                http.status = status,
                latency_ms = latency_ms(),
                "webhook delivered"
            ),
            Err(e) => tracing::warn!(
                event = event_type,
                tx_id = %tx_id,
                latency_ms = latency_ms(),
                error.kind = e.kind(),
                error.detail = %foundry_core::obs::truncate(&e.to_string(), DETAIL_MAX),
                "webhook delivery failed"
            ),
        }
    });
}
```

- [ ] **Step 4: Fire the event**

In `submit_vp_response`, after `verify_vp_response` returns and after the existing `save_verification_transaction` block, before mapping `verify_res` into a response. It must fire on **both** arms, so read the verdict off `tx` rather than off the `Ok` value:

```rust
    // Both arms: a failed verification is the case this feed exists for, and
    // `verify_vp_response` populates `tx.result` on its error path too.
    if let Some(result) = tx.result.clone() {
        dispatch_webhook(
            state,
            foundry_verifier::WebhookEvent::VerificationCompleted {
                tx_id: tx.id.clone(),
                state: tx.state,
                result,
                vp_token: captured_vp_token.take(),
            },
        );
    }
```

Delete the temporary `let _ = &captured_vp_token;` from Task 4 if you added it, and make the binding `let mut captured_vp_token`.

Note `tx.state` is `Copy` (`VerificationState` derives it), so no clone is needed.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry --test webhook_delivery`
Expected: PASS.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/webhook_delivery.rs crates/foundry/tests/support/mod.rs
git commit -m "feat(server): deliver verification_completed events"
```

---

### Task 7: Dispatch `presentation_request_delivered`

**Files:**

- Modify: `crates/foundry/src/server.rs` (`create_verification_handler` ~line 1330, `get_request_object_handler` ~line 1617)
- Test: `crates/foundry/tests/webhook_delivery.rs`

**Interfaces:**

- Consumes: `dispatch_webhook` (Task 6); `WebhookEvent::PresentationRequestDelivered` (Task 2).
- Produces: nothing new.

- [ ] **Step 1: Write the failing tests**

```rust
/// D5: the event means "these exact bytes went out now", so two fetches are
/// two events. ECDSA signing is randomized, so they genuinely differ.
#[tokio::test]
async fn each_request_object_fetch_delivers_its_own_event() {
    let (state, _dir, ..) = setup_with_webhook(true).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    let admin = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet = wallet_router(state.clone());

    // POST /admin/verification/requests with transport "request_uri", read the
    // `verification_id` from the response, then GET /vp/request/:id twice.
    // Reuse `wallet_verification.rs`'s request construction for the POST.

    let first = support::next_event(&mut rx).await;
    let second = support::next_event(&mut rx).await;

    let jws_of = |e: &foundry_verifier::WebhookEvent| match e {
        foundry_verifier::WebhookEvent::PresentationRequestDelivered {
            request_object_jws, transport, ..
        } => {
            assert_eq!(transport, "request_uri");
            request_object_jws.clone().expect("signed transport carries the JWS")
        }
        other => panic!("expected PresentationRequestDelivered, got {other:?}"),
    };

    assert_ne!(
        jws_of(&first),
        jws_of(&second),
        "ECDSA is randomized, so each served copy is different bytes"
    );
}

/// The unsigned transport has no JWS, so it carries the JSON object instead.
#[tokio::test]
async fn the_unsigned_dc_api_transport_delivers_its_request_object() {
    let (state, _dir, ..) = setup_with_webhook(true).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    let admin = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    // POST /admin/verification/requests with transport "dc_api" — copy the
    // request body from `wallet_verification.rs`'s DC API test.

    match support::next_event(&mut rx).await {
        foundry_verifier::WebhookEvent::PresentationRequestDelivered {
            transport,
            request_object_jws,
            dc_api_request,
            ..
        } => {
            assert_eq!(transport, "dc_api");
            assert!(request_object_jws.is_none(), "no signed form exists");
            assert!(dc_api_request.is_some());
        }
        other => panic!("expected PresentationRequestDelivered, got {other:?}"),
    }
}

/// O1: the event fires even with artifacts off, as a PII-free record that a
/// request was served.
#[tokio::test]
async fn a_request_event_fires_without_artifacts_when_they_are_disabled() {
    let (state, _dir, ..) = setup_with_webhook(false).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    // POST /admin/verification/requests with transport "dc_api".

    match support::next_event(&mut rx).await {
        foundry_verifier::WebhookEvent::PresentationRequestDelivered {
            request_object_jws, dc_api_request, ..
        } => {
            assert!(request_object_jws.is_none());
            assert!(dc_api_request.is_none(), "artifacts are gated off");
        }
        other => panic!("expected PresentationRequestDelivered, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p foundry --test webhook_delivery`
Expected: FAIL — `next_event` times out.

- [ ] **Step 3: Fire from `create_verification_handler`**

The handler already holds everything needed: `CreateVerificationResponse` carries `verification_id` and `dc_api_request`, and for `dc_api_signed` the JWS is `dc_api_request["request"]`. `create_verification_request`'s signature does **not** change.

Replace the handler body's tail so the response is inspected before being returned:

```rust
    let resp = foundry_verifier::create_verification_request(
        &state.config,
        state.storage.as_ref(),
        req,
        now,
    )
    .await
    .map_err(|e| verifier_admin_error_response(&e))?;

    // The two DC API transports hand their request object to the invoking page
    // right here, so this is the moment it is "delivered". The `request_uri`
    // transport has no object yet — its event fires from
    // `get_request_object_handler` when the wallet fetches it.
    if let Some(dc_api) = &resp.dc_api_request {
        let include = state
            .config
            .verifier
            .webhook
            .as_ref()
            .is_some_and(|w| w.include_raw_artifacts);
        // `dc_api_signed` wraps the JWS in a `request` member (OpenID4VP 1.0
        // L2476); the unsigned form is the object itself.
        let signed_jws = dc_api.get("request").and_then(|v| v.as_str());
        let (request_object_jws, dc_api_request) = match (include, signed_jws) {
            (false, _) => (None, None),
            (true, Some(jws)) => (Some(jws.to_string()), None),
            (true, None) => (None, Some(dc_api.clone())),
        };
        dispatch_webhook(
            &state,
            foundry_verifier::WebhookEvent::PresentationRequestDelivered {
                tx_id: resp.verification_id.clone(),
                transport: if signed_jws.is_some() {
                    "dc_api_signed".to_string()
                } else {
                    "dc_api".to_string()
                },
                request_object_jws,
                dc_api_request,
            },
        );
    }

    Ok(Json(resp))
```

- [ ] **Step 4: Fire from `get_request_object_handler`**

After the JWS is built and before it is returned:

```rust
    // Fires per fetch, not per transaction: ECDSA signing is randomized, so
    // this JWS is genuinely different bytes from any previous one, and the
    // event's contract is "these exact bytes went out now" (design D5).
    // Deduping would require remembering what was sent, i.e. storage.
    let include = state
        .config
        .verifier
        .webhook
        .as_ref()
        .is_some_and(|w| w.include_raw_artifacts);
    dispatch_webhook(
        &state,
        foundry_verifier::WebhookEvent::PresentationRequestDelivered {
            tx_id: tx.id.clone(),
            transport: tx.transport.clone(),
            request_object_jws: include.then(|| jws_str.clone()),
            dc_api_request: None,
        },
    );
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p foundry --test webhook_delivery`
Expected: PASS.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/webhook_delivery.rs
git commit -m "feat(server): deliver presentation_request_delivered events"
```

---

### Task 8: Redaction proof, documentation, and AGENTS.md

**Files:**

- Modify: `crates/foundry/tests/logging_redaction.rs`
- Modify: `crates/foundry/src/commands.rs` (sample config, near the `dc_api_accept_legacy_web_origin_audience` block ~line 469)
- Modify: `docs/manual/reference/configuration.md`, `docs/manual/reference/log-fields.md`, `docs/manual/verification/request-diagnostics.md`
- Modify: `crates/foundry-verifier/AGENTS.md`

**Interfaces:**

- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Write the failing redaction test**

In `crates/foundry/tests/logging_redaction.rs`, following the file's existing capture-and-assert pattern (it has a positive control — keep that discipline):

```rust
/// §4.6: the event body is the payload this feature moves, and it carries
/// holder PII. It must never reach a log record, at any level, with the
/// webhook enabled and artifacts on.
#[tokio::test]
async fn webhook_delivery_never_logs_the_event_body_or_secret() {
    // Use this file's EXISTING log-capture helper — do not introduce a second
    // capture mechanism. Configure `verifier.webhook` with
    // `secret: Some("s3cr3t")` and `include_raw_artifacts: true`, attach
    // `support::FailingSink` so a delivery record is guaranteed to be emitted,
    // and run at trace level with sensitive payloads enabled — the most
    // permissive setting there is, so a pass here means the value is
    // unreachable rather than merely gated.
    let logs = /* this file's capture helper */ String::new();

    // Positive control FIRST: without it, every assertion below passes
    // vacuously on an empty capture.
    assert!(
        logs.contains("webhook delivery failed"),
        "positive control: the delivery record must be present, else the \
         negative assertions below prove nothing"
    );

    assert!(!logs.contains("s3cr3t"), "the webhook secret must never be logged");
    assert!(!logs.contains("sha256="), "the signature must never be logged");
    // `given_name` is the only claim the fixture credential discloses, and its
    // value is "Alice" (`wallet_verification.rs:281`). Seeing it anywhere means
    // the event body reached a log record.
    assert!(
        !logs.contains("Alice"),
        "the event body must never be logged"
    );
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo nextest run -p foundry --test logging_redaction webhook`
Expected: FAIL — the test does not compile or the positive control does not match until the log message text is confirmed.

- [ ] **Step 3: Make it pass**

No production change should be needed — Task 6's `dispatch_webhook` already logs no payload. If the test fails on a real leak, fix `dispatch_webhook`, not the test.

- [ ] **Step 4: Add the sample config**

In `crates/foundry/src/commands.rs`, after the `dc_api_accept_legacy_web_origin_audience` commented block:

```rust
  #
  # Deliver verification events to an operator-owned endpoint. Absent (the
  # default) means no sink is constructed and nothing changes.
  # `include_raw_artifacts` is a SECOND gate, off by default: it authorises the
  # verbatim Request Object and the decrypted vp_token -- holder PII in the
  # clear -- to leave this process. Foundry stores none of it.
  # webhook:
  #   url: https://audit.example.com/vp-callback
  #   secret_env: FOUNDRY_WEBHOOK_SECRET
  #   timeout_secs: 5
  #   include_raw_artifacts: false
```

- [ ] **Step 5: Document it**

`docs/manual/reference/configuration.md` — add the `verifier.webhook` block with every key, its default, and the https/loopback rule.

`docs/manual/reference/log-fields.md` — add `event`, and note that `http.status`, `latency_ms`, `error.kind`, `error.detail` also appear on webhook delivery records.

`docs/manual/verification/request-diagnostics.md` — add the three-channel comparison from design §4.7, stating plainly that webhook delivery is best-effort and at-most-once, and that a failed delivery appears only as a `warn`.

- [ ] **Step 6: Update `crates/foundry-verifier/AGENTS.md`**

- Module map: add a `webhook.rs` row — "`WebhookEvent`, `WebhookSink` + `HttpWebhookSink`, secret resolution and HMAC signing".
- Key public types: add `WebhookSink`, `HttpWebhookSink`, `WebhookEvent`, `WebhookError`.
- Gotchas, three entries:
  - Delivery is fire-and-forget: never `await` it in a handler, because §4.3 has no HTTP status meaning "the audit sink was down".
  - `WebhookError` is deliberately not a `VerificationError` variant — an unmapped variant becomes a silent 500.
  - `build_signed_request_parts` returns the exact bytes to send; never re-serialize with `.json(..)`, or the signature will not cover what was transmitted.
  - `presentation_request_delivered` fires per fetch, not per transaction.

- [ ] **Step 7: Run the full gate plus docs**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
source .venv/bin/activate && mkdocs build --strict
```

Links into `docs/superpowers/` must be absolute `https://github.com/digitallabor-berlin/foundry/blob/main/…` URLs — `crates/foundry/tests/docs_hygiene.rs` enforces this.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry/tests/logging_redaction.rs crates/foundry/src/commands.rs docs/manual crates/foundry-verifier/AGENTS.md
git commit -m "docs: document the verification event webhook"
```

---

## Final Verification

- [ ] Run the whole gate one last time, plus the E2E suite (root AGENTS.md §5.2):

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
source .venv/bin/activate && mkdocs build --strict
```

- [ ] Confirm `openapi.json` and `openapi-wallet.json` are **unchanged** (`git diff --exit-code openapi.json openapi-wallet.json`). If either moved, a route or schema changed and the spec's §8 claim is wrong — stop and reconcile.
- [ ] Write the change record to `docs/superpowers/changes/2026-08-28-verifier-artifact-webhook.md`, noting the three open questions (O1 request events when artifacts are off, O2 DCQL query in the verdict event, O3 payload timestamp) as deliberately deferred.
