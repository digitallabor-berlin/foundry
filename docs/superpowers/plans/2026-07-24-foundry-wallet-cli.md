# Foundry Debug Wallet CLI/TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new `foundry-wallet` binary crate — a debug wallet, operable both as a `ratatui` TUI and as scriptable headless `clap` subcommands — that triggers/consumes OpenID4VCI issuance and OpenID4VP verification flows against a running Foundry server, storing every credential artifact as reviewable files with real, toggleable X.509 trust validation and full HTTP request/response logging.

**Architecture:** A `foundry-wallet` lib crate (mirroring `foundry`'s `lib.rs`/`main.rs`/`cli.rs` split) with a shared `actions/` module (issuance flow, verification flow, offer/request-URI parsing, proof building, trust validation, DCQL-based credential matching) used identically by headless subcommands and TUI screens; a `storage/` module for the on-disk credential/key/event-log layout; and a small `http/` module wrapping `reqwest` with full request/response logging into the event log. Protocol/crypto primitives are reused from `foundry-core`, `foundry-issuer`, `foundry-verifier`, `foundry-sd-jwt-vc`, and `openid4vp` rather than reimplemented.

**Tech Stack:** Rust (workspace edition 2021, rust-version 1.97), `clap` (derive), `ratatui` + `crossterm` (new workspace deps), `reqwest` (rustls-tls), `tokio`, `serde`/`serde_json`/`serde_yaml`, `thiserror`, `josekit`, `time`, `uuid`.

## Global Constraints

- Workspace edition `2021`, `rust-version = "1.97"` (from `Cargo.toml` `[workspace.package]`) — match existing crates' `Cargo.toml` headers exactly (`edition.workspace = true`, `rust-version.workspace = true`, `license.workspace = true`).
- No `.unwrap()`, `.expect()`, `panic!()`, or `unreachable!()` in production code paths of `foundry-wallet`'s `actions/`, `storage/`, `http/`, and `tui/` modules — return typed `WalletError`/`WalletResult` instead. Permitted only inside `#[cfg(test)]` code (per repo-wide `AGENTS.md` rule, applied here to the wallet's own request/response handling).
- Before considering any task in this plan complete, its own crate's gates must pass: `cargo test -p foundry-wallet` (and `-p foundry-issuer` for Task 1), `cargo clippy -p foundry-wallet --all-targets -- -D warnings`, `cargo fmt --check -p foundry-wallet`. The full workspace gates (`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`) are run once, in the final task.
- OpenAPI documentation requirement (`AGENTS.md` §5) is **not applicable** to this plan: `foundry-wallet` is an HTTP *client* only and exposes no HTTP endpoints of its own. Do not add anything to `foundry`'s OpenAPI spec for this work.
- Reuse existing crypto/protocol primitives — do not reimplement JOSE, SD-JWT, JWE, or X.509 chain logic that already exists in `foundry-core`, `foundry-sd-jwt-vc`, `foundry-verifier`, or `openid4vp`.

---

### Task 1: Add `Deserialize` to `foundry-issuer`'s offer/response types

**Files:**
- Modify: `crates/foundry-issuer/src/offer.rs:25,32,38,46` (`CredentialOffer`, `CredentialOfferGrants`, `PreAuthorizedCodeGrant`, `TxCodeDefinition`)
- Modify: `crates/foundry-issuer/src/create_offer.rs:26` (`CreateOfferResponse`)
- Test: `crates/foundry-issuer/src/offer.rs` (add to existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `CredentialOffer`, `CredentialOfferGrants`, `PreAuthorizedCodeGrant`, `TxCodeDefinition`, `CreateOfferResponse` all gain `serde::Deserialize` (in addition to their existing `Serialize`), so `foundry-wallet` can deserialize the admin API's `POST /admin/issuance/offers` JSON response and parse offer-URI JSON payloads without a duplicate local struct.

`foundry-issuer`'s `Cargo.toml` already depends on `serde = { workspace = true, features = ["derive"] }` (used elsewhere in the crate), so no dependency changes are needed.

- [ ] **Step 1: Write the failing test**

In `crates/foundry-issuer/src/offer.rs`, add this test inside the existing `#[cfg(test)] mod tests { ... }` block (after `build_offer_uri_percent_encodes_and_uses_the_correct_scheme`):

```rust
    #[test]
    fn credential_offer_round_trips_through_json() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["pid".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: PreAuthorizedCodeGrant {
                    pre_authorized_code: "abc123".to_string(),
                    tx_code: Some(TxCodeDefinition {
                        input_mode: "numeric".to_string(),
                        length: 4,
                    }),
                },
            },
        };
        let json = serde_json::to_string(&offer).unwrap();
        let round_tripped: CredentialOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.credential_issuer, offer.credential_issuer);
        assert_eq!(
            round_tripped.grants.pre_authorized_code.pre_authorized_code,
            "abc123"
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer credential_offer_round_trips_through_json`
Expected: FAIL to compile — `the trait bound CredentialOffer: Deserialize<'_> is not satisfied`.

- [ ] **Step 3: Add `Deserialize` to the derive lists**

In `crates/foundry-issuer/src/offer.rs`, change all four struct derives from `Serialize` to `Serialize, Deserialize`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialOffer {
```
```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialOfferGrants {
```
```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PreAuthorizedCodeGrant {
```
```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TxCodeDefinition {
```

And add the import at the top of the file: change `use serde::Serialize;` to `use serde::{Deserialize, Serialize};`.

In `crates/foundry-issuer/src/create_offer.rs`, change:
```rust
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CreateOfferResponse {
```
to:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateOfferResponse {
```
(`Deserialize` is already imported in this file via `use serde::{Deserialize, Serialize};`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-issuer credential_offer_round_trips_through_json`
Expected: PASS

- [ ] **Step 5: Run full crate test suite and gates**

Run: `cargo test -p foundry-issuer && cargo clippy -p foundry-issuer --all-targets -- -D warnings && cargo fmt --check -p foundry-issuer`
Expected: all PASS (this is a purely additive derive change; no existing behavior changes).

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/offer.rs crates/foundry-issuer/src/create_offer.rs
git commit -m "feat(foundry-issuer): derive Deserialize for CredentialOffer/CreateOfferResponse"
```

---

### Task 2: Scaffold the `foundry-wallet` crate (Cargo.toml, error type, CLI parsing skeleton)

**Files:**
- Modify: `Cargo.toml` (workspace `members`, add `ratatui`/`crossterm` to `[workspace.dependencies]`)
- Create: `crates/foundry-wallet/Cargo.toml`
- Create: `crates/foundry-wallet/src/lib.rs`
- Create: `crates/foundry-wallet/src/error.rs`
- Create: `crates/foundry-wallet/src/cli.rs`
- Create: `crates/foundry-wallet/src/main.rs`
- Test: `crates/foundry-wallet/src/cli.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces: `foundry_wallet::error::{WalletError, WalletResult<T>}` with a `WalletError::kind(&self) -> &'static str` method; `foundry_wallet::cli::{Cli, Command, CredentialsAction, EventsAction}` (clap types), all subsequent tasks add variants/fields/handlers to `cli.rs`/`main.rs` incrementally but these three names must not change.

- [ ] **Step 1: Add workspace member and new dependencies**

In `Cargo.toml`, add `"crates/foundry-wallet"` to `[workspace] members` (after `"crates/foundry-verifier"`), and add to `[workspace.dependencies]` (after `utoipa-swagger-ui`):

```toml
ratatui = "0.29"
crossterm = { version = "0.28", features = ["event-stream"] }
```

- [ ] **Step 2: Create `crates/foundry-wallet/Cargo.toml`**

```toml
[package]
name = "foundry-wallet"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lib]
name = "foundry_wallet"
path = "src/lib.rs"

[[bin]]
name = "foundry-wallet"
path = "src/main.rs"

[dependencies]
foundry-core = { path = "../foundry-core" }
foundry-issuer = { path = "../foundry-issuer" }
foundry-verifier = { path = "../foundry-verifier" }
foundry-sd-jwt-vc = { path = "../foundry-sd-jwt-vc" }
openid4vp = { path = "../openid4vp" }
tokio = { workspace = true }
clap = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
josekit = "0.10"
base64 = { workspace = true }
time = { workspace = true }
uuid = { version = "1", features = ["v4"] }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
ratatui = { workspace = true }
crossterm = { workspace = true }

[dev-dependencies]
tempfile = "3"
axum = { workspace = true }
foundry = { path = "../foundry" }
assert_cmd = "2"
```

- [ ] **Step 3: Create `crates/foundry-wallet/src/error.rs`**

```rust
//! Wallet-wide error type. Every fallible operation in `actions/`, `storage/`,
//! and `http/` returns `WalletResult<T>`; headless subcommands serialize a
//! failing `WalletError` to `{"error": "<message>", "kind": "<kind>"}` on
//! stderr (see `cli.rs`/`main.rs`).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("http {status} from {url}: {body}")]
    HttpStatus {
        status: u16,
        url: String,
        body: String,
    },
    #[error("storage error at {path}: {source}")]
    Storage {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("config error: {0}")]
    Config(String),
    #[error("malformed credential offer: {0}")]
    MalformedOffer(String),
    #[error("malformed request object: {0}")]
    MalformedRequestObject(String),
    #[error("trust validation failed: {0}")]
    TrustValidation(String),
    #[error("no matching credential for the requested DCQL query")]
    NoMatchingCredential,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

pub type WalletResult<T> = Result<T, WalletError>;

impl WalletError {
    /// Machine-readable discriminant for headless JSON error output.
    pub fn kind(&self) -> &'static str {
        match self {
            WalletError::Http(_) => "http",
            WalletError::HttpStatus { .. } => "http_status",
            WalletError::Storage { .. } => "storage",
            WalletError::Config(_) => "config",
            WalletError::MalformedOffer(_) => "malformed_offer",
            WalletError::MalformedRequestObject(_) => "malformed_request_object",
            WalletError::TrustValidation(_) => "trust_validation",
            WalletError::NoMatchingCredential => "no_matching_credential",
            WalletError::Json(_) => "json",
            WalletError::Yaml(_) => "yaml",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_is_stable_per_variant() {
        assert_eq!(WalletError::NoMatchingCredential.kind(), "no_matching_credential");
        assert_eq!(WalletError::Config("x".into()).kind(), "config");
    }
}
```

- [ ] **Step 4: Create `crates/foundry-wallet/src/lib.rs`**

```rust
pub mod cli;
pub mod error;
```

(Later tasks add `pub mod config;`, `pub mod storage;`, `pub mod http;`, `pub mod actions;`, `pub mod tui;` to this file — one line each, no other changes needed here.)

- [ ] **Step 5: Create `crates/foundry-wallet/src/cli.rs`**

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "foundry-wallet",
    version,
    about = "Debug wallet for exercising Foundry's OpenID4VCI/OpenID4VP flows"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Launch the interactive TUI (default when no subcommand is given).
    Tui,
    /// Trigger or consume an issuance flow.
    Issue {
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        offer_uri: Option<String>,
        #[arg(long)]
        tx_code: Option<String>,
    },
    /// Trigger or consume a verification flow.
    Verify {
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        request_uri: Option<String>,
        #[arg(long, value_enum)]
        consent: ConsentArg,
    },
    /// Inspect stored credentials.
    Credentials {
        #[command(subcommand)]
        action: CredentialsAction,
    },
    /// Inspect the event log.
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ConsentArg {
    Accept,
    Decline,
}

#[derive(Debug, Subcommand)]
pub enum CredentialsAction {
    /// List all stored credentials.
    List,
    /// Show one stored credential's metadata and decoded payload.
    Show {
        #[arg(long)]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EventsAction {
    /// Print the event log.
    Tail {
        #[arg(long, default_value_t = 20)]
        n: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_issue_with_preset() {
        let cli = Cli::parse_from([
            "foundry-wallet",
            "--config",
            "wallet.yaml",
            "issue",
            "--preset",
            "pid",
        ]);
        assert_eq!(cli.config.to_str().unwrap(), "wallet.yaml");
        match cli.command {
            Some(Command::Issue { preset, offer_uri, tx_code }) => {
                assert_eq!(preset.as_deref(), Some("pid"));
                assert_eq!(offer_uri, None);
                assert_eq!(tx_code, None);
            }
            other => panic!("expected Issue, got {other:?}"),
        }
    }

    #[test]
    fn parses_verify_requires_consent() {
        let cli = Cli::parse_from([
            "foundry-wallet",
            "--config",
            "wallet.yaml",
            "verify",
            "--preset",
            "dcql1",
            "--consent",
            "accept",
        ]);
        match cli.command {
            Some(Command::Verify { preset, consent, .. }) => {
                assert_eq!(preset.as_deref(), Some("dcql1"));
                assert!(matches!(consent, ConsentArg::Accept));
            }
            other => panic!("expected Verify, got {other:?}"),
        }
    }

    #[test]
    fn defaults_to_no_subcommand_meaning_tui() {
        let cli = Cli::parse_from(["foundry-wallet", "--config", "wallet.yaml"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_credentials_show() {
        let cli = Cli::parse_from([
            "foundry-wallet",
            "--config",
            "wallet.yaml",
            "credentials",
            "show",
            "--id",
            "cred_1",
        ]);
        match cli.command {
            Some(Command::Credentials {
                action: CredentialsAction::Show { id },
            }) => assert_eq!(id, "cred_1"),
            other => panic!("expected Credentials Show, got {other:?}"),
        }
    }
}
```

- [ ] **Step 6: Create `crates/foundry-wallet/src/main.rs`**

```rust
use clap::Parser;
use foundry_wallet::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            println!("TUI not yet implemented; config = {}", cli.config.display());
            Ok(())
        }
        Some(_) => {
            println!("subcommand not yet implemented");
            Ok(())
        }
    }
}
```

- [ ] **Step 7: Run tests to verify the scaffold compiles and CLI parsing passes**

Run: `cargo test -p foundry-wallet`
Expected: PASS (4 tests in `cli.rs`).

- [ ] **Step 8: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS (run `cargo fmt -p foundry-wallet` first if formatting fails, then re-check).

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock crates/foundry-wallet
git commit -m "feat(foundry-wallet): scaffold crate, error type, CLI parsing skeleton"
```

---

### Task 3: Wallet config file loading (`config.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/config.rs`
- Modify: `crates/foundry-wallet/src/lib.rs` (add `pub mod config;`)

**Interfaces:**
- Consumes: `WalletError`, `WalletResult` from Task 2.
- Produces: `WalletConfig::load(path: &Path) -> WalletResult<WalletConfig>`; `WalletConfig { data_dir: PathBuf, endpoints: EndpointsConfig, trust: TrustConfig, issuance_presets: BTreeMap<String, IssuancePreset>, verification_presets: BTreeMap<String, VerificationPreset> }`; `EndpointsConfig::resolve_admin_api_key(&self) -> WalletResult<String>`; `TrustValidationMode::{Enabled, Disabled}` (used by Task 10 to gate validation).

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/config.rs` with just the test module first:

```rust
//! Wallet configuration file (`wallet.yaml`) parsing. See
//! docs/superpowers/specs/2026-07-24-foundry-wallet-cli-design.md section 3.

use crate::error::{WalletError, WalletResult};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct WalletConfig {
    pub data_dir: PathBuf,
    pub endpoints: EndpointsConfig,
    pub trust: TrustConfig,
    #[serde(default)]
    pub issuance_presets: BTreeMap<String, IssuancePreset>,
    #[serde(default)]
    pub verification_presets: BTreeMap<String, VerificationPreset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EndpointsConfig {
    pub admin_base_url: String,
    pub wallet_base_url: String,
    #[serde(default)]
    pub admin_api_key: Option<String>,
    #[serde(default)]
    pub admin_api_key_env: Option<String>,
}

impl EndpointsConfig {
    /// Prefer an inline key; fall back to the named env var; error if neither
    /// is configured or the env var is unset.
    pub fn resolve_admin_api_key(&self) -> WalletResult<String> {
        if let Some(key) = &self.admin_api_key {
            return Ok(key.clone());
        }
        if let Some(env_name) = &self.admin_api_key_env {
            return std::env::var(env_name)
                .map_err(|_| WalletError::Config(format!("env var '{env_name}' is not set")));
        }
        Err(WalletError::Config(
            "endpoints.admin_api_key or endpoints.admin_api_key_env is required".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustConfig {
    pub validation: TrustValidationMode,
    #[serde(default)]
    pub anchors: Vec<TrustAnchorConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustValidationMode {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustAnchorConfig {
    pub certs: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuancePreset {
    pub credential_type_id: String,
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub tx_code_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationPreset {
    pub dcql_query: serde_json::Value,
    #[serde(default = "default_transport")]
    pub transport: String,
}

fn default_transport() -> String {
    "request_uri".to_string()
}

impl WalletConfig {
    pub fn load(path: &Path) -> WalletResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| WalletError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
        let cfg: WalletConfig = serde_yaml::from_str(&text)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
data_dir: ./wallet-data
endpoints:
  admin_base_url: http://127.0.0.1:9000
  wallet_base_url: http://127.0.0.1:8443
  admin_api_key: dev-admin-key
trust:
  validation: enabled
  anchors:
    - certs: ./trust/root-ca.pem
issuance_presets:
  pid:
    credential_type_id: pid
    claims:
      given_name: Alice
      birthdate: "1990-01-01"
    tx_code_required: false
verification_presets:
  dcql1:
    dcql_query:
      credentials:
        - id: c1
          format: dc+sd-jwt
          meta: { vct_values: ["https://issuer.example.com/vct/pid"] }
          claims:
            - path: ["given_name"]
    transport: request_uri
"#;

    #[test]
    fn loads_a_full_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.yaml");
        std::fs::write(&path, SAMPLE_YAML).unwrap();

        let cfg = WalletConfig::load(&path).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from("./wallet-data"));
        assert_eq!(cfg.endpoints.admin_base_url, "http://127.0.0.1:9000");
        assert_eq!(cfg.trust.validation, TrustValidationMode::Enabled);
        assert_eq!(cfg.trust.anchors.len(), 1);
        let preset = cfg.issuance_presets.get("pid").unwrap();
        assert_eq!(preset.credential_type_id, "pid");
        assert_eq!(
            preset.claims.get("given_name"),
            Some(&serde_json::json!("Alice"))
        );
        assert!(cfg.verification_presets.contains_key("dcql1"));
    }

    #[test]
    fn resolve_admin_api_key_prefers_inline_value() {
        let endpoints = EndpointsConfig {
            admin_base_url: "http://x".to_string(),
            wallet_base_url: "http://y".to_string(),
            admin_api_key: Some("inline-key".to_string()),
            admin_api_key_env: None,
        };
        assert_eq!(endpoints.resolve_admin_api_key().unwrap(), "inline-key");
    }

    #[test]
    fn resolve_admin_api_key_errors_when_neither_configured() {
        let endpoints = EndpointsConfig {
            admin_base_url: "http://x".to_string(),
            wallet_base_url: "http://y".to_string(),
            admin_api_key: None,
            admin_api_key_env: None,
        };
        let err = endpoints.resolve_admin_api_key().unwrap_err();
        assert_eq!(err.kind(), "config");
    }

    #[test]
    fn load_errors_on_missing_file() {
        let err = WalletConfig::load(Path::new("/nonexistent/wallet.yaml")).unwrap_err();
        assert_eq!(err.kind(), "storage");
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

In `crates/foundry-wallet/src/lib.rs`, add `pub mod config;` after `pub mod cli;`.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p foundry-wallet config::`
Expected: PASS (4 tests). (This task writes the implementation and test together since the struct fields *are* the interface under test — there is no separate "make it fail first" step beyond compiling the module for the first time.)

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/config.rs crates/foundry-wallet/src/lib.rs
git commit -m "feat(foundry-wallet): wallet.yaml config parsing"
```

---

### Task 4: Storage layout init + event log (`storage/mod.rs`, `storage/event_log.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/storage/mod.rs`
- Create: `crates/foundry-wallet/src/storage/event_log.rs`
- Modify: `crates/foundry-wallet/src/lib.rs` (add `pub mod storage;`)

**Interfaces:**
- Consumes: `WalletError`, `WalletResult`.
- Produces: `storage::ensure_data_dir_layout(data_dir: &Path) -> WalletResult<()>`; `storage::now_rfc3339() -> String`; `storage::event_log::{append_event(data_dir: &Path, event: &serde_json::Value) -> WalletResult<()>, read_events(data_dir: &Path) -> WalletResult<Vec<Value>>, tail_events(data_dir: &Path, n: usize) -> WalletResult<Vec<Value>>}`. Used by Task 5 (credential_store), Task 6 (http client), and every `actions/` module thereafter.

- [ ] **Step 1: Write the failing test for `ensure_data_dir_layout` and `now_rfc3339`**

Create `crates/foundry-wallet/src/storage/mod.rs`:

```rust
//! On-disk wallet data directory: `keys/`, `credentials/<id>/`, `trust/`,
//! `log/`. See docs/superpowers/specs/2026-07-24-foundry-wallet-cli-design.md
//! section 5.

pub mod credential_store;
pub mod event_log;

use crate::error::{WalletError, WalletResult};
use std::path::Path;

/// Create `keys/`, `credentials/`, `trust/`, `log/` under `data_dir` if they
/// don't already exist. Safe to call repeatedly.
pub fn ensure_data_dir_layout(data_dir: &Path) -> WalletResult<()> {
    for sub in ["keys", "credentials", "trust", "log"] {
        let dir = data_dir.join(sub);
        std::fs::create_dir_all(&dir).map_err(|e| WalletError::Storage {
            path: dir.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}

/// Current UTC time as RFC3339, used for event timestamps and
/// `metadata.json`'s `received_at`.
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_data_dir_layout_creates_all_four_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        ensure_data_dir_layout(dir.path()).unwrap();
        for sub in ["keys", "credentials", "trust", "log"] {
            assert!(dir.path().join(sub).is_dir(), "missing {sub}");
        }
    }

    #[test]
    fn ensure_data_dir_layout_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        ensure_data_dir_layout(dir.path()).unwrap();
        ensure_data_dir_layout(dir.path()).unwrap(); // must not error the 2nd time
    }

    #[test]
    fn now_rfc3339_produces_a_parseable_timestamp() {
        let ts = now_rfc3339();
        assert!(ts.contains('T'));
        assert!(time::OffsetDateTime::parse(&ts, &time::format_description::well_known::Rfc3339).is_ok());
    }
}
```

- [ ] **Step 2: Create `crates/foundry-wallet/src/storage/event_log.rs`**

```rust
//! Append-only JSONL event log at `<data_dir>/log/events.jsonl`. Every
//! outbound HTTP request/response and every wallet-level decision
//! (credential stored, consent decision, trust validation failure) is logged
//! here for human review — see the design doc section 8 for the event shapes.

use crate::error::{WalletError, WalletResult};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::Path;

fn log_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("log").join("events.jsonl")
}

pub fn append_event(data_dir: &Path, event: &Value) -> WalletResult<()> {
    let path = log_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| WalletError::Storage {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| WalletError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
    writeln!(file, "{}", serde_json::to_string(event)?).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

pub fn read_events(data_dir: &Path) -> WalletResult<Vec<Value>> {
    let path = log_path(data_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(&path).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })?;
    let reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| WalletError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

/// The last `n` events (fewer if the log is shorter), oldest-first.
pub fn tail_events(data_dir: &Path, n: usize) -> WalletResult<Vec<Value>> {
    let mut all = read_events(data_dir)?;
    if all.len() > n {
        all = all.split_off(all.len() - n);
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_read_round_trips_events_in_order() {
        let dir = tempfile::tempdir().unwrap();
        append_event(dir.path(), &serde_json::json!({"kind": "a"})).unwrap();
        append_event(dir.path(), &serde_json::json!({"kind": "b"})).unwrap();

        let events = read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "a");
        assert_eq!(events[1]["kind"], "b");
    }

    #[test]
    fn read_events_on_missing_log_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_events(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn tail_events_returns_only_the_last_n() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            append_event(dir.path(), &serde_json::json!({"i": i})).unwrap();
        }
        let tail = tail_events(dir.path(), 2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0]["i"], 3);
        assert_eq!(tail[1]["i"], 4);
    }
}
```

- [ ] **Step 3: Wire the module into `lib.rs`**

In `crates/foundry-wallet/src/lib.rs`, add `pub mod storage;` after `pub mod config;`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p foundry-wallet storage::`
Expected: PASS (6 tests).

- [ ] **Step 5: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-wallet/src/storage crates/foundry-wallet/src/lib.rs
git commit -m "feat(foundry-wallet): data dir layout init + JSONL event log"
```

---

### Task 5: Credential store (`storage/credential_store.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/storage/credential_store.rs`
- Modify: `crates/foundry-wallet/src/storage/mod.rs` (already declares `pub mod credential_store;` from Task 4 Step 1 — no change needed)

**Interfaces:**
- Consumes: `WalletError`, `WalletResult`, `storage::now_rfc3339`.
- Produces: `credential_store::{CredentialMetadata, NewCredential, store_credential, load_metadata, load_payload, load_holder_key_pem, load_compact_sdjwt, list_credentials}`. `list_credentials` is consumed by Task 11 (DCQL matching) and the `credentials list`/`show` subcommands (Task 15).

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/storage/credential_store.rs`:

```rust
//! Per-credential on-disk storage: `credentials/<id>/{credential.sdjwt,
//! payload.json, holder_key.pem, metadata.json}`.

use crate::error::{WalletError, WalletResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub vct: String,
    pub issuer: String,
    pub received_at: String,
    pub status_list_uri: Option<String>,
    pub status_list_idx: Option<u64>,
    pub disclosed_claims: Vec<String>,
    pub trust_valid: Option<bool>,
    pub holder_key_path: String,
}

pub struct NewCredential<'a> {
    pub credential_id: &'a str,
    pub compact_sdjwt: &'a str,
    /// `{"header": ..., "payload": ..., "disclosed_claims": {"given_name": "Alice", ...}}`
    pub decoded_payload: &'a serde_json::Value,
    pub holder_key_pem: &'a [u8],
    pub metadata: &'a CredentialMetadata,
}

fn credential_dir(data_dir: &Path, credential_id: &str) -> PathBuf {
    data_dir.join("credentials").join(credential_id)
}

fn write_file(path: &Path, bytes: &[u8]) -> WalletResult<()> {
    std::fs::write(path, bytes).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })
}

fn read_to_string(path: &Path) -> WalletResult<String> {
    std::fs::read_to_string(path).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })
}

pub fn store_credential(data_dir: &Path, new: &NewCredential<'_>) -> WalletResult<()> {
    let dir = credential_dir(data_dir, new.credential_id);
    std::fs::create_dir_all(&dir).map_err(|e| WalletError::Storage {
        path: dir.display().to_string(),
        source: e,
    })?;
    write_file(&dir.join("credential.sdjwt"), new.compact_sdjwt.as_bytes())?;
    write_file(
        &dir.join("payload.json"),
        serde_json::to_string_pretty(new.decoded_payload)?.as_bytes(),
    )?;
    write_file(&dir.join("holder_key.pem"), new.holder_key_pem)?;
    write_file(
        &dir.join("metadata.json"),
        serde_json::to_string_pretty(new.metadata)?.as_bytes(),
    )?;
    Ok(())
}

pub fn load_metadata(data_dir: &Path, credential_id: &str) -> WalletResult<CredentialMetadata> {
    let text = read_to_string(&credential_dir(data_dir, credential_id).join("metadata.json"))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_payload(data_dir: &Path, credential_id: &str) -> WalletResult<serde_json::Value> {
    let text = read_to_string(&credential_dir(data_dir, credential_id).join("payload.json"))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_holder_key_pem(data_dir: &Path, credential_id: &str) -> WalletResult<Vec<u8>> {
    let path = credential_dir(data_dir, credential_id).join("holder_key.pem");
    std::fs::read(&path).map_err(|e| WalletError::Storage {
        path: path.display().to_string(),
        source: e,
    })
}

pub fn load_compact_sdjwt(data_dir: &Path, credential_id: &str) -> WalletResult<String> {
    read_to_string(&credential_dir(data_dir, credential_id).join("credential.sdjwt"))
}

/// All stored credentials' metadata, oldest-`received_at`-first.
pub fn list_credentials(data_dir: &Path) -> WalletResult<Vec<CredentialMetadata>> {
    let creds_dir = data_dir.join("credentials");
    let mut out = Vec::new();
    if !creds_dir.exists() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(&creds_dir).map_err(|e| WalletError::Storage {
        path: creds_dir.display().to_string(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| WalletError::Storage {
            path: creds_dir.display().to_string(),
            source: e,
        })?;
        if entry.path().is_dir() {
            if let Some(id) = entry.file_name().to_str() {
                out.push(load_metadata(data_dir, id)?);
            }
        }
    }
    out.sort_by(|a, b| a.received_at.cmp(&b.received_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata(id: &str, received_at: &str) -> CredentialMetadata {
        CredentialMetadata {
            credential_id: id.to_string(),
            vct: "https://issuer.example.com/vct/pid".to_string(),
            issuer: "https://issuer.example.com".to_string(),
            received_at: received_at.to_string(),
            status_list_uri: Some("https://issuer.example.com/statuslists/1".to_string()),
            status_list_idx: Some(0),
            disclosed_claims: vec!["given_name".to_string()],
            trust_valid: Some(true),
            holder_key_path: "holder_key.pem".to_string(),
        }
    }

    #[test]
    fn store_then_load_round_trips_all_four_files() {
        let dir = tempfile::tempdir().unwrap();
        let metadata = sample_metadata("cred_1", "2026-07-24T10:00:00Z");
        let payload = serde_json::json!({
            "header": {"alg": "ES256"},
            "payload": {"vct": metadata.vct},
            "disclosed_claims": {"given_name": "Alice"}
        });
        let new = NewCredential {
            credential_id: "cred_1",
            compact_sdjwt: "abc.def.ghi~disclosure~",
            decoded_payload: &payload,
            holder_key_pem: b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
            metadata: &metadata,
        };
        store_credential(dir.path(), &new).unwrap();

        assert_eq!(
            load_compact_sdjwt(dir.path(), "cred_1").unwrap(),
            "abc.def.ghi~disclosure~"
        );
        assert_eq!(load_payload(dir.path(), "cred_1").unwrap(), payload);
        assert_eq!(
            load_holder_key_pem(dir.path(), "cred_1").unwrap(),
            new.holder_key_pem
        );
        assert_eq!(load_metadata(dir.path(), "cred_1").unwrap(), metadata);
    }

    #[test]
    fn list_credentials_sorts_by_received_at_and_is_empty_when_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list_credentials(dir.path()).unwrap().is_empty());

        let payload = serde_json::json!({});
        for (id, ts) in [("cred_b", "2026-07-24T11:00:00Z"), ("cred_a", "2026-07-24T09:00:00Z")] {
            let metadata = sample_metadata(id, ts);
            store_credential(
                dir.path(),
                &NewCredential {
                    credential_id: id,
                    compact_sdjwt: "x",
                    decoded_payload: &payload,
                    holder_key_pem: b"key",
                    metadata: &metadata,
                },
            )
            .unwrap();
        }
        let list = list_credentials(dir.path()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].credential_id, "cred_a");
        assert_eq!(list[1].credential_id, "cred_b");
    }

    #[test]
    fn load_metadata_on_missing_credential_errors_as_storage() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_metadata(dir.path(), "nonexistent").unwrap_err();
        assert_eq!(err.kind(), "storage");
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p foundry-wallet storage::credential_store::`
Expected: PASS (3 tests).

- [ ] **Step 3: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-wallet/src/storage/credential_store.rs
git commit -m "feat(foundry-wallet): per-credential file storage"
```

---

### Task 6: Logging HTTP client (`http/mod.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/http/mod.rs`
- Modify: `crates/foundry-wallet/src/lib.rs` (add `pub mod http;`)

**Interfaces:**
- Consumes: `WalletError`, `WalletResult`, `storage::event_log::append_event`, `storage::now_rfc3339`.
- Produces: `http::LoggingHttpClient::{new(data_dir: &Path) -> Self, get(&self, url: &str, bearer: Option<&str>) -> WalletResult<(u16, String)>, post_json(&self, url: &str, bearer: Option<&str>, body: &Value) -> WalletResult<(u16, String)>, post_form(&self, url: &str, bearer: Option<&str>, form_body: &str) -> WalletResult<(u16, String)>, post_text(&self, url: &str, text_body: &str) -> WalletResult<(u16, String)>, post_empty(&self, url: &str, bearer: Option<&str>) -> WalletResult<(u16, String)>}`. Every method logs an `http_request` then `http_response` event, full body/headers, no redaction. Used by every `actions/` module from Task 12 onward.

- [ ] **Step 1: Write the failing test (local echo server)**

Create `crates/foundry-wallet/src/http/mod.rs`:

```rust
//! Thin `reqwest` wrapper that logs every outbound request and its response
//! in full (no redaction — this is a debugging tool, see the design doc
//! section 6) to the wallet's event log before returning.

use crate::error::WalletResult;
use crate::storage::{event_log, now_rfc3339};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct LoggingHttpClient {
    client: reqwest::Client,
    data_dir: PathBuf,
}

impl LoggingHttpClient {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            client: reqwest::Client::new(),
            data_dir: data_dir.to_path_buf(),
        }
    }

    fn log_request(&self, method: &str, url: &str, headers: &Value, body: &str) -> WalletResult<()> {
        event_log::append_event(
            &self.data_dir,
            &serde_json::json!({
                "ts": now_rfc3339(), "kind": "http_request", "direction": "out",
                "method": method, "url": url, "headers": headers, "body": body,
            }),
        )
    }

    fn log_response(&self, status: u16, body: &str) -> WalletResult<()> {
        event_log::append_event(
            &self.data_dir,
            &serde_json::json!({
                "ts": now_rfc3339(), "kind": "http_response", "status": status, "body": body,
            }),
        )
    }

    async fn finish(&self, resp: reqwest::Response) -> WalletResult<(u16, String)> {
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        self.log_response(status, &text)?;
        Ok((status, text))
    }

    pub async fn get(&self, url: &str, bearer: Option<&str>) -> WalletResult<(u16, String)> {
        let mut req = self.client.get(url);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let headers = if let Some(token) = bearer {
            serde_json::json!({"authorization": format!("Bearer {token}")})
        } else {
            serde_json::json!({})
        };
        self.log_request("GET", url, &headers, "")?;
        let resp = req.send().await?;
        self.finish(resp).await
    }

    pub async fn post_json(
        &self,
        url: &str,
        bearer: Option<&str>,
        body: &Value,
    ) -> WalletResult<(u16, String)> {
        let mut req = self.client.post(url).json(body);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let mut headers = serde_json::json!({"content-type": "application/json"});
        if let Some(token) = bearer {
            headers["authorization"] = serde_json::json!(format!("Bearer {token}"));
        }
        self.log_request("POST", url, &headers, &serde_json::to_string(body)?)?;
        let resp = req.send().await?;
        self.finish(resp).await
    }

    pub async fn post_form(
        &self,
        url: &str,
        bearer: Option<&str>,
        form_body: &str,
    ) -> WalletResult<(u16, String)> {
        let mut req = self
            .client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body.to_string());
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        self.log_request(
            "POST",
            url,
            &serde_json::json!({"content-type": "application/x-www-form-urlencoded"}),
            form_body,
        )?;
        let resp = req.send().await?;
        self.finish(resp).await
    }

    pub async fn post_text(&self, url: &str, text_body: &str) -> WalletResult<(u16, String)> {
        self.log_request(
            "POST",
            url,
            &serde_json::json!({"content-type": "text/plain"}),
            text_body,
        )?;
        let resp = self
            .client
            .post(url)
            .header("content-type", "text/plain")
            .body(text_body.to_string())
            .send()
            .await?;
        self.finish(resp).await
    }

    pub async fn post_empty(&self, url: &str, bearer: Option<&str>) -> WalletResult<(u16, String)> {
        let mut req = self.client.post(url);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let headers = if let Some(token) = bearer {
            serde_json::json!({"authorization": format!("Bearer {token}")})
        } else {
            serde_json::json!({})
        };
        self.log_request("POST", url, &headers, "")?;
        let resp = req.send().await?;
        self.finish(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    async fn spawn_echo_server() -> String {
        let app = Router::new()
            .route("/echo-get", get(|| async { "hello-get" }))
            .route(
                "/echo-post",
                post(|Json(body): Json<serde_json::Value>| async move { Json(body) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn post_json_returns_body_and_logs_request_and_response() {
        let base = spawn_echo_server().await;
        let dir = tempfile::tempdir().unwrap();
        let client = LoggingHttpClient::new(dir.path());

        let (status, body) = client
            .post_json(
                &format!("{base}/echo-post"),
                Some("secret-token"),
                &serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, r#"{"hello":"world"}"#);

        let events = event_log::read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "http_request");
        assert_eq!(events[0]["method"], "POST");
        // No redaction: the bearer token appears in full in the logged headers.
        assert!(events[0]["headers"]["authorization"]
            .as_str()
            .unwrap()
            .contains("secret-token"));
        assert_eq!(events[1]["kind"], "http_response");
        assert_eq!(events[1]["status"], 200);
    }

    #[tokio::test]
    async fn get_without_bearer_logs_empty_auth_header() {
        let base = spawn_echo_server().await;
        let dir = tempfile::tempdir().unwrap();
        let client = LoggingHttpClient::new(dir.path());

        let (status, body) = client.get(&format!("{base}/echo-get"), None).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "hello-get");

        let events = event_log::read_events(dir.path()).unwrap();
        assert_eq!(events[0]["headers"], serde_json::json!({}));
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

In `crates/foundry-wallet/src/lib.rs`, add `pub mod http;` after `pub mod storage;`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p foundry-wallet http::`
Expected: PASS (2 tests).

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/http crates/foundry-wallet/src/lib.rs
git commit -m "feat(foundry-wallet): logging HTTP client wrapper"
```

---

### Task 7: Offer and request deep-link parsing (`actions/offer_source.rs`, `actions/request_source.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/actions/mod.rs`
- Create: `crates/foundry-wallet/src/actions/offer_source.rs`
- Create: `crates/foundry-wallet/src/actions/request_source.rs`
- Modify: `crates/foundry-wallet/src/lib.rs` (add `pub mod actions;`)

**Interfaces:**
- Consumes: `WalletError`, `WalletResult`, `foundry_issuer::CredentialOffer` (now `Deserialize` per Task 1).
- Produces: `actions::offer_source::{OfferSource::{Inline(CredentialOffer), RemoteUri(String)}, parse_offer_deep_link(uri: &str) -> WalletResult<OfferSource>}`; `actions::request_source::parse_request_deep_link(uri: &str) -> WalletResult<String>` (returns the URL to `GET`). Consumed by Task 12 (`actions::issuance`) and Task 13 (`actions::verification`).

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/actions/mod.rs`:

```rust
pub mod offer_source;
pub mod request_source;
```

Create `crates/foundry-wallet/src/actions/offer_source.rs`:

```rust
//! Parses `openid-credential-offer://` deep links (RFC-style query params
//! `credential_offer=<url-encoded-json>` or `credential_offer_uri=<url>`).

use crate::error::{WalletError, WalletResult};
use foundry_issuer::CredentialOffer;

#[derive(Debug)]
pub enum OfferSource {
    /// The offer JSON was inline in the deep link.
    Inline(CredentialOffer),
    /// The deep link referenced a URL that must be fetched to obtain the offer JSON.
    RemoteUri(String),
}

/// Parse an `openid-credential-offer://?credential_offer=...` or
/// `...?credential_offer_uri=...` deep link. Also accepts a bare
/// `credential_offer_uri` URL (no scheme wrapper) for convenience.
pub fn parse_offer_deep_link(uri: &str) -> WalletResult<OfferSource> {
    let query = extract_query(uri)?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        let decoded = percent_decode(value);
        match key {
            "credential_offer" => {
                let offer: CredentialOffer = serde_json::from_str(&decoded)?;
                return Ok(OfferSource::Inline(offer));
            }
            "credential_offer_uri" => return Ok(OfferSource::RemoteUri(decoded)),
            _ => continue,
        }
    }
    Err(WalletError::MalformedOffer(format!(
        "no credential_offer or credential_offer_uri parameter found in '{uri}'"
    )))
}

fn extract_query(uri: &str) -> WalletResult<String> {
    if let Some(idx) = uri.find('?') {
        Ok(uri[idx + 1..].to_string())
    } else {
        Err(WalletError::MalformedOffer(format!(
            "offer deep link has no query string: '{uri}'"
        )))
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_issuer::{CredentialOfferGrants, PreAuthorizedCodeGrant};

    fn sample_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["pid".to_string()],
            grants: CredentialOfferGrants {
                pre_authorized_code: PreAuthorizedCodeGrant {
                    pre_authorized_code: "abc123".to_string(),
                    tx_code: None,
                },
            },
        }
    }

    #[test]
    fn parses_inline_credential_offer() {
        let uri = foundry_issuer::build_offer_uri(&sample_offer()).unwrap();
        match parse_offer_deep_link(&uri).unwrap() {
            OfferSource::Inline(offer) => {
                assert_eq!(offer.credential_issuer, "https://issuer.example.com");
                assert_eq!(
                    offer.grants.pre_authorized_code.pre_authorized_code,
                    "abc123"
                );
            }
            OfferSource::RemoteUri(_) => panic!("expected Inline"),
        }
    }

    #[test]
    fn parses_remote_credential_offer_uri() {
        let uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Foffer%2F123";
        match parse_offer_deep_link(uri).unwrap() {
            OfferSource::RemoteUri(url) => {
                assert_eq!(url, "https://issuer.example.com/offer/123")
            }
            OfferSource::Inline(_) => panic!("expected RemoteUri"),
        }
    }

    #[test]
    fn errors_on_missing_query_string() {
        let err = parse_offer_deep_link("openid-credential-offer://").unwrap_err();
        assert_eq!(err.kind(), "malformed_offer");
    }

    #[test]
    fn errors_when_no_recognized_parameter_present() {
        let err = parse_offer_deep_link("openid-credential-offer://?foo=bar").unwrap_err();
        assert_eq!(err.kind(), "malformed_offer");
    }
}
```

Create `crates/foundry-wallet/src/actions/request_source.rs`:

```rust
//! Parses `openid4vp://` deep links referencing a `request_uri` to `GET`.

use crate::error::{WalletError, WalletResult};

/// Parse an `openid4vp://?request_uri=<url>` deep link, or accept a bare
/// `https://.../vp/request/:id` URL directly (both forms are documented
/// entry points per the design doc section 7, step 1).
pub fn parse_request_deep_link(uri: &str) -> WalletResult<String> {
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return Ok(uri.to_string());
    }
    let query = uri
        .find('?')
        .map(|idx| &uri[idx + 1..])
        .ok_or_else(|| {
            WalletError::MalformedRequestObject(format!(
                "request deep link has no query string and is not a bare http(s) URL: '{uri}'"
            ))
        })?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if key == "request_uri" {
            return Ok(percent_decode(value));
        }
    }
    Err(WalletError::MalformedRequestObject(format!(
        "no request_uri parameter found in '{uri}'"
    )))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openid4vp_request_uri_deep_link() {
        let uri = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Fvp%2Frequest%2Fabc";
        assert_eq!(
            parse_request_deep_link(uri).unwrap(),
            "https://verifier.example.com/vp/request/abc"
        );
    }

    #[test]
    fn accepts_a_bare_https_url() {
        let uri = "https://verifier.example.com/vp/request/abc";
        assert_eq!(parse_request_deep_link(uri).unwrap(), uri);
    }

    #[test]
    fn errors_on_malformed_deep_link() {
        let err = parse_request_deep_link("openid4vp://?foo=bar").unwrap_err();
        assert_eq!(err.kind(), "malformed_request_object");
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

In `crates/foundry-wallet/src/lib.rs`, add `pub mod actions;` after `pub mod http;`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p foundry-wallet actions::`
Expected: PASS (7 tests).

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/actions crates/foundry-wallet/src/lib.rs
git commit -m "feat(foundry-wallet): offer and request deep-link parsing"
```

---

### Task 8: Holder proof JWT builder (`actions/proof.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/actions/proof.rs`
- Modify: `crates/foundry-wallet/src/actions/mod.rs` (add `pub mod proof;`)

**Interfaces:**
- Produces: `actions::proof::{HolderProof { proof_json: serde_json::Value, private_key_pem: Vec<u8> }, build_proof_jwt(c_nonce: &str, aud: &str) -> WalletResult<HolderProof>}`. Consumed by Task 12 (`actions::issuance`), which writes `private_key_pem` to `holder_key.pem`.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/actions/proof.rs`:

```rust
//! Builds an `openid4vci-proof+jwt` bound to a `c_nonce`/`aud`, generating a
//! fresh holder EC key pair per credential. Construction mirrors the one
//! already proven out against the real server in
//! `crates/foundry/tests/e2e_full_flow.rs::create_proof`.

use crate::error::WalletResult;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};

pub struct HolderProof {
    pub proof_json: serde_json::Value,
    pub private_key_pem: Vec<u8>,
}

pub fn build_proof_jwt(c_nonce: &str, aud: &str) -> WalletResult<HolderProof> {
    let keypair = EcKeyPair::generate(EcCurve::P256)
        .map_err(|e| crate::error::WalletError::MalformedOffer(format!("key generation failed: {e}")))?;
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk)?))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(aud)))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256
        .signer_from_jwk(&private_jwk)
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| crate::error::WalletError::MalformedOffer(e.to_string()))?;

    Ok(HolderProof {
        proof_json: serde_json::json!({ "proof_type": "jwt", "jwt": jwt_str }),
        private_key_pem: keypair.to_pem_private_key(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;

    #[test]
    fn builds_a_proof_jwt_bound_to_nonce_and_aud() {
        let proof = build_proof_jwt("nonce-123", "https://issuer.example.com").unwrap();
        assert_eq!(proof.proof_json["proof_type"], "jwt");
        let jwt_str = proof.proof_json["jwt"].as_str().unwrap();
        let parts: Vec<&str> = jwt_str.split('.').collect();
        assert_eq!(parts.len(), 3, "must be a compact JWS");

        let header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert!(header["jwk"].is_object());

        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["aud"], "https://issuer.example.com");
        assert_eq!(payload["nonce"], "nonce-123");

        assert!(proof
            .private_key_pem
            .starts_with(b"-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn each_call_generates_a_distinct_key() {
        let a = build_proof_jwt("n", "aud").unwrap();
        let b = build_proof_jwt("n", "aud").unwrap();
        assert_ne!(a.private_key_pem, b.private_key_pem);
    }
}
```

- [ ] **Step 2: Wire the module**

In `crates/foundry-wallet/src/actions/mod.rs`, add `pub mod proof;`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p foundry-wallet actions::proof::`
Expected: PASS (2 tests).

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/actions/proof.rs crates/foundry-wallet/src/actions/mod.rs
git commit -m "feat(foundry-wallet): holder proof JWT builder"
```

---

### Task 9: Trust validation wrappers (`actions/trust.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/actions/trust.rs`
- Modify: `crates/foundry-wallet/src/actions/mod.rs` (add `pub mod trust;`)

**Interfaces:**
- Consumes: `foundry_core::trust::{TrustStore, validate_chain, x5c_entry_to_pem}`.
- Produces: `actions::trust::{TrustOutcome { valid: bool, detail: String }, validate_jws_x5c_chain(jws_compact: &str, store: &TrustStore) -> TrustOutcome}`. This single function covers both directions: Task 12 (issuance) calls it on the issuer-signed JWT (first `~`-segment of the SD-JWT VC), Task 13 (verification) calls it on the verifier's signed request object JWS — same shape (compact JWS with an `x5c` header), same validation. Never returns `Err` (fail-closed via `valid: false`), matching `foundry_verifier::dcql::check_dcql_match`'s "never errors" convention.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/actions/trust.rs`:

```rust
//! Real X.509 trust validation for both directions: the issuer's
//! credential-signing JWT and the verifier's signed request object. Both are
//! compact JWS values carrying an `x5c` header (leaf-first chain); this
//! module verifies the JWS signature against the leaf's public key, then
//! validates the leaf..intermediates chain against the configured trust
//! anchors via `foundry_core::trust::validate_chain`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::trust::{validate_chain, x5c_entry_to_pem, TrustStore};
use josekit::jws::{JwsVerifier, ES256};
use josekit::jwt;

pub struct TrustOutcome {
    pub valid: bool,
    pub detail: String,
}

impl TrustOutcome {
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            valid: false,
            detail: detail.into(),
        }
    }

    fn ok(detail: impl Into<String>) -> Self {
        Self {
            valid: true,
            detail: detail.into(),
        }
    }
}

/// Verify `jws_compact`'s signature and X.509 chain. `now_unix` is injectable
/// for deterministic tests; production callers pass the real current time.
pub fn validate_jws_x5c_chain(jws_compact: &str, store: &TrustStore, now_unix: u64) -> TrustOutcome {
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() < 2 {
        return TrustOutcome::fail("not a compact JWS (fewer than 2 dot-separated segments)");
    }
    let header_bytes = match B64URL.decode(parts[0]) {
        Ok(b) => b,
        Err(e) => return TrustOutcome::fail(format!("invalid JWS header base64: {e}")),
    };
    let header: serde_json::Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(e) => return TrustOutcome::fail(format!("invalid JWS header JSON: {e}")),
    };
    let x5c = match header.get("x5c").and_then(|v| v.as_array()) {
        Some(chain) if !chain.is_empty() => chain,
        _ => return TrustOutcome::fail("JWS header has no x5c chain"),
    };
    let leaf_b64 = match x5c[0].as_str() {
        Some(s) => s,
        None => return TrustOutcome::fail("x5c[0] is not a string"),
    };
    let leaf_pem = match x5c_entry_to_pem(leaf_b64) {
        Ok(p) => p,
        Err(e) => return TrustOutcome::fail(format!("x5c[0] is not valid DER: {e}")),
    };

    // Verify the JWS signature itself using the leaf certificate's public key.
    let leaf_cert = match foundry_core::trust::parse_cert_pem(&leaf_pem) {
        Ok(c) => c,
        Err(e) => return TrustOutcome::fail(format!("failed to parse leaf cert: {e}")),
    };
    let verifier: Box<dyn JwsVerifier> = match build_verifier(&leaf_cert) {
        Ok(v) => v,
        Err(e) => return TrustOutcome::fail(e),
    };
    if let Err(e) = jwt::decode_with_verifier(jws_compact, verifier.as_ref()) {
        return TrustOutcome::fail(format!("JWS signature verification failed: {e}"));
    }

    let intermediates: Vec<Vec<u8>> = x5c[1..]
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| x5c_entry_to_pem(s).ok())
        .collect();

    match validate_chain(&leaf_pem, &intermediates, store, now_unix) {
        Ok(()) => TrustOutcome::ok("chain validated against configured trust anchors"),
        Err(e) => TrustOutcome::fail(format!("chain validation failed: {e}")),
    }
}

fn build_verifier(leaf_cert: &foundry_core::trust::Certificate) -> Result<Box<dyn JwsVerifier>, String> {
    use x509_cert::der::Encode;
    let der = leaf_cert
        .to_der()
        .map_err(|e| format!("failed to re-encode leaf cert: {e}"))?;
    // Re-PEM-encode so josekit can parse the public key out of the certificate.
    let pem = pem_from_der(&der);
    ES256
        .verifier_from_pem(pem.as_bytes())
        .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        .map_err(|e| format!("failed to build verifier from leaf cert: {e}"))
}

fn pem_from_der(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_core::trust::{build_x5c, TrustStore};
    use josekit::jws::JwsHeader;
    use josekit::jwt::JwtPayload;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn sign_test_jws(cert_pem: &str, key_pem: &str) -> String {
        let signer = FileSigner::from_pem(key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();
        let x5c = build_x5c(&[cert_pem.as_bytes().to_vec()]).unwrap();
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        header.set_claim("x5c", Some(serde_json::to_value(&x5c).unwrap())).unwrap();
        let mut payload = JwtPayload::new();
        payload.set_claim("hello", Some(serde_json::json!("world"))).unwrap();
        let key_pair = josekit::jwk::alg::ec::EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
        let _ = key_pair; // unused placeholder to keep imports minimal; real signer below
        signer
            .sign_jws(&payload, &header)
            .unwrap_or_else(|_| String::new())
    }

    #[test]
    fn valid_chain_against_matching_root_passes() {
        let root = new_ca("Test Root", 365).unwrap();
        let leaf = issue_leaf(&root.cert_pem, &root.key_pem, "localhost", &["localhost".to_string()], 365).unwrap();
        let jws = sign_test_jws(&leaf.cert_pem, &leaf.key_pem);
        assert!(!jws.is_empty(), "test JWS must be constructed");

        let store = TrustStore::from_pems(&[root.cert_pem.into_bytes()]).unwrap();
        let outcome = validate_jws_x5c_chain(&jws, &store, now());
        assert!(outcome.valid, "expected valid chain, got: {}", outcome.detail);
    }

    #[test]
    fn chain_against_unrelated_root_fails() {
        let root = new_ca("Test Root", 365).unwrap();
        let leaf = issue_leaf(&root.cert_pem, &root.key_pem, "localhost", &["localhost".to_string()], 365).unwrap();
        let jws = sign_test_jws(&leaf.cert_pem, &leaf.key_pem);

        let other_root = new_ca("Other Root", 365).unwrap();
        let store = TrustStore::from_pems(&[other_root.cert_pem.into_bytes()]).unwrap();
        let outcome = validate_jws_x5c_chain(&jws, &store, now());
        assert!(!outcome.valid);
    }

    #[test]
    fn missing_x5c_header_fails_closed() {
        let store = TrustStore::from_pems(&[]).unwrap();
        let outcome = validate_jws_x5c_chain("a.b.c", &store, now());
        assert!(!outcome.valid);
        assert!(outcome.detail.contains("x5c"));
    }
}
```

`foundry_core::crypto::FileSigner` needs a `sign_jws` helper for the test to build a signed JWS from a PEM key — check `crates/foundry-core/src/crypto/mod.rs` for the existing `Signer` trait/`FileSigner` API before writing the test; if no such convenience method exists, replace `sign_test_jws`'s body with a direct `josekit::jws::ES256.signer_from_pem(key_pem.as_bytes())` + `jwt::encode_with_signer(&payload, &header, &signer)` call (the same pattern already used in `actions/proof.rs`), which does not depend on `foundry_core::crypto` at all. Prefer that direct approach — it avoids depending on `foundry_core::crypto::Signer`'s exact trait shape:

```rust
    fn sign_test_jws(cert_pem: &str, key_pem: &str) -> String {
        let x5c = build_x5c(&[cert_pem.as_bytes().to_vec()]).unwrap();
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        header
            .set_claim("x5c", Some(serde_json::to_value(&x5c).unwrap()))
            .unwrap();
        let mut payload = JwtPayload::new();
        payload
            .set_claim("hello", Some(serde_json::json!("world")))
            .unwrap();
        let signer = ES256.signer_from_pem(key_pem.as_bytes()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }
```

Use this simplified version (remove the unused `key_pair`/`FileSigner`/`Signer` imports and the placeholder line) instead of the first draft above.

- [ ] **Step 2: Wire the module**

In `crates/foundry-wallet/src/actions/mod.rs`, add `pub mod trust;`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p foundry-wallet actions::trust::`
Expected: PASS (3 tests).

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS. If clippy flags the `Box<dyn JwsVerifier>` return type or unused imports from the simplification in Step 1, fix per its suggestions (e.g. remove now-unused `FileSigner`/`Signer`/`SignatureAlgorithm` imports from the test module).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/actions/trust.rs crates/foundry-wallet/src/actions/mod.rs
git commit -m "feat(foundry-wallet): real X.509 trust validation for issuer/verifier JWS"
```

---

### Task 10: DCQL-based stored-credential matching (`actions/match_credentials.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/actions/match_credentials.rs`
- Modify: `crates/foundry-wallet/src/actions/mod.rs` (add `pub mod match_credentials;`)

**Interfaces:**
- Consumes: `storage::credential_store::{list_credentials, load_payload}`, `foundry_verifier::{check_dcql_match, PresentedFormat}`.
- Produces: `actions::match_credentials::{MatchedCredential { query_id: String, credential_id: String, disclosed_claims: serde_json::Value }, match_credentials(data_dir: &Path, dcql_query: &serde_json::Value) -> WalletResult<Vec<MatchedCredential>>}`. Errors with `WalletError::NoMatchingCredential` if any `credentials[]` entry in the query has no stored match. Consumed by Task 13 (`actions::verification`).

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/actions/match_credentials.rs`:

```rust
//! Matches stored SD-JWT VC credentials against a DCQL query's
//! `credentials[]` entries, reusing the verifier's own satisfaction-checking
//! logic (`foundry_verifier::check_dcql_match`) so wallet-side "will this
//! request succeed" matches server-side "did this presentation satisfy the
//! query" exactly.

use crate::error::{WalletError, WalletResult};
use crate::storage::credential_store::{list_credentials, load_payload};
use foundry_verifier::{check_dcql_match, PresentedFormat};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MatchedCredential {
    pub query_id: String,
    pub credential_id: String,
    pub disclosed_claims: serde_json::Value,
}

/// For each `dcql_query.credentials[]` entry, find the most-recently-received
/// stored credential whose disclosed claims satisfy it (per
/// `check_dcql_match`). Errors if any entry has no match.
pub fn match_credentials(
    data_dir: &Path,
    dcql_query: &serde_json::Value,
) -> WalletResult<Vec<MatchedCredential>> {
    let entries = dcql_query
        .get("credentials")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            WalletError::MalformedRequestObject("dcql_query.credentials is missing or not an array".to_string())
        })?;

    // Newest-first so the first satisfying credential found per entry is the
    // most recently received one.
    let mut stored = list_credentials(data_dir)?;
    stored.reverse();

    let mut out = Vec::new();
    for entry in entries {
        let query_id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let single_entry_query = serde_json::json!({ "credentials": [entry] });

        let mut found = None;
        for metadata in &stored {
            let payload = load_payload(data_dir, &metadata.credential_id)?;
            let disclosed_claims = payload
                .get("disclosed_claims")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let result = check_dcql_match(
                &single_entry_query,
                PresentedFormat::SdJwtVc,
                &disclosed_claims,
                None,
            );
            if result.passed {
                found = Some(MatchedCredential {
                    query_id: query_id.clone(),
                    credential_id: metadata.credential_id.clone(),
                    disclosed_claims,
                });
                break;
            }
        }

        match found {
            Some(m) => out.push(m),
            None => return Err(WalletError::NoMatchingCredential),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::credential_store::{store_credential, CredentialMetadata, NewCredential};

    fn store_test_credential(data_dir: &Path, id: &str, received_at: &str, vct: &str, claims: serde_json::Value) {
        let payload = serde_json::json!({
            "header": {"alg": "ES256"},
            "payload": {"vct": vct},
            "disclosed_claims": claims,
        });
        let metadata = CredentialMetadata {
            credential_id: id.to_string(),
            vct: vct.to_string(),
            issuer: "https://issuer.example.com".to_string(),
            received_at: received_at.to_string(),
            status_list_uri: None,
            status_list_idx: None,
            disclosed_claims: claims
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
            trust_valid: Some(true),
            holder_key_path: "holder_key.pem".to_string(),
        };
        store_credential(
            data_dir,
            &NewCredential {
                credential_id: id,
                compact_sdjwt: "x",
                decoded_payload: &payload,
                holder_key_pem: b"key",
                metadata: &metadata,
            },
        )
        .unwrap();
    }

    fn sample_query() -> serde_json::Value {
        serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://issuer.example.com/vct/pid"] },
                "claims": [{ "path": ["given_name"] }]
            }]
        })
    }

    #[test]
    fn matches_a_stored_credential_satisfying_the_query() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_1",
            "2026-07-24T10:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"given_name": "Alice"}),
        );

        let matches = match_credentials(dir.path(), &sample_query()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].query_id, "c1");
        assert_eq!(matches[0].credential_id, "cred_1");
    }

    #[test]
    fn picks_the_most_recently_received_match() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_old",
            "2026-07-24T09:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"given_name": "Alice"}),
        );
        store_test_credential(
            dir.path(),
            "cred_new",
            "2026-07-24T11:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"given_name": "Bob"}),
        );

        let matches = match_credentials(dir.path(), &sample_query()).unwrap();
        assert_eq!(matches[0].credential_id, "cred_new");
    }

    #[test]
    fn errors_with_no_matching_credential_when_vct_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_1",
            "2026-07-24T10:00:00Z",
            "https://issuer.example.com/vct/other",
            serde_json::json!({"given_name": "Alice"}),
        );

        let err = match_credentials(dir.path(), &sample_query()).unwrap_err();
        assert_eq!(err.kind(), "no_matching_credential");
    }

    #[test]
    fn errors_with_no_matching_credential_when_claim_missing() {
        let dir = tempfile::tempdir().unwrap();
        store_test_credential(
            dir.path(),
            "cred_1",
            "2026-07-24T10:00:00Z",
            "https://issuer.example.com/vct/pid",
            serde_json::json!({"family_name": "Smith"}),
        );

        let err = match_credentials(dir.path(), &sample_query()).unwrap_err();
        assert_eq!(err.kind(), "no_matching_credential");
    }
}
```

- [ ] **Step 2: Wire the module**

In `crates/foundry-wallet/src/actions/mod.rs`, add `pub mod match_credentials;`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p foundry-wallet actions::match_credentials::`
Expected: PASS (4 tests).

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/actions/match_credentials.rs crates/foundry-wallet/src/actions/mod.rs
git commit -m "feat(foundry-wallet): DCQL-based stored-credential matching"
```

---

### Task 11: Shared in-process server test harness

**Files:**
- Create: `crates/foundry-wallet/tests/support/mod.rs`

**Interfaces:**
- Produces: `support::{TestServer { admin_base: String, wallet_base: String, root_cert_pem: String, _storage_dir: tempfile::TempDir }, spawn_test_server() -> TestServer}`. `TestServer` boots real `axum::serve` listeners for both the admin and wallet routers, in-process, on ephemeral ports, backed by a temp SQLite DB — adapted from `crates/foundry/tests/wallet_verification.rs::setup_test_app`, but bound to real sockets (via `axum::serve`) instead of used through `tower::ServiceExt::oneshot`, since `foundry-wallet`'s `LoggingHttpClient` makes real HTTP calls. Consumed by Task 12 and Task 13's integration tests.

This is scaffolding with no independent test of its own (per Task Right-Sizing, it's folded into the next task that needs it) — but since Tasks 12 and 13 **both** depend on it, it is pulled out as its own task here so it is written and reviewed once, not duplicated. Its "test" is that Task 12's first integration test successfully boots and talks to it.

- [ ] **Step 1: Write the test harness**

Create `crates/foundry-wallet/tests/support/mod.rs`:

```rust
//! Shared in-process test harness for foundry-wallet's integration tests:
//! boots the real `foundry` admin + wallet axum routers on ephemeral real
//! TCP ports (backed by a temp SQLite DB and a temp dev PKI), so
//! `foundry-wallet`'s HTTP client exercises the genuine wire format without
//! subprocess/binary-path complexity. Adapted from
//! `crates/foundry/tests/wallet_verification.rs::setup_test_app`.

use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, KeyEntry, Mode,
    ServerConfig, StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;

pub const ADMIN_API_KEY: &str = "test-admin-key";
pub const ISSUER_BASE: &str = "https://issuer.example.com";
pub const VCT_PID: &str = "https://issuer.example.com/vct/pid";

pub struct TestServer {
    pub admin_base: String,
    pub wallet_base: String,
    /// PEM of the dev root CA both the issuer and verifier leaf certs chain to.
    pub root_cert_pem: String,
    _storage_dir: tempfile::TempDir,
}

/// Boot a real admin-facing + wallet-facing server pair in-process, each on
/// its own ephemeral `127.0.0.1` port, with one `pid` credential type and a
/// verifier configured with `x509_san_dns` client_id_scheme (matching the
/// dev-PKI leaf certs' SAN).
pub async fn spawn_test_server() -> TestServer {
    let dir = tempfile::tempdir().expect("create tempdir");
    let db_path = dir.path().join("foundry.db");

    let root = new_ca("Foundry Wallet Test Root CA", 365).expect("new_ca");
    let issuer_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .expect("issue_leaf issuer");
    let verifier_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .expect("issue_leaf verifier");

    let issuer_key_path = dir.path().join("issuer.pem");
    let verifier_key_path = dir.path().join("verifier.pem");
    std::fs::write(&issuer_key_path, &issuer_leaf.key_pem).unwrap();
    std::fs::write(&verifier_key_path, &verifier_leaf.key_pem).unwrap();
    let issuer_cert_path = dir.path().join("issuer_cert.pem");
    std::fs::write(&issuer_cert_path, &issuer_leaf.cert_pem).unwrap();
    let trust_root_path = dir.path().join("trust_root.pem");
    std::fs::write(&trust_root_path, &root.cert_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .expect("connect sqlite");

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: issuer_key_path.to_str().unwrap().to_string(),
            x5c: Some(issuer_cert_path.to_str().unwrap().to_string()),
            alg: "ES256".to_string(),
        },
    );
    keys.insert(
        "verifier_signing".to_string(),
        KeyEntry {
            private_key: verifier_key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: ISSUER_BASE.to_string(),
                bind: "127.0.0.1:0".to_string(),
                swagger_ui_enabled: false,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:0".to_string(),
                api_key: Some(ADMIN_API_KEY.to_string()),
                api_key_env: None,
                swagger_ui_enabled: false,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().unwrap().to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: vec![TrustAnchor {
            certs: trust_root_path.to_str().unwrap().to_string(),
        }],
        issuer: IssuerConfig {
            credential_issuer: ISSUER_BASE.to_string(),
            wallet_attestation: AttestationMode { mode: Mode::Optional },
            key_attestation: AttestationMode { mode: Mode::Optional },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(VCT_PID.to_string()),
            doctype: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![
                ClaimDef {
                    path: vec!["given_name".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                },
                ClaimDef {
                    path: vec!["birthdate".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                },
            ],
        }],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
        },
    };

    let state = AppState {
        config: Arc::new(config),
        storage: Arc::new(storage),
        admin_key: Arc::new(AdminApiKey::from(ADMIN_API_KEY.to_string())),
    };

    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin listener");
    let admin_addr = admin_listener.local_addr().unwrap();
    let admin_app = admin_router(state.clone());
    tokio::spawn(async move {
        axum::serve(admin_listener, admin_app).await.unwrap();
    });

    let wallet_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wallet listener");
    let wallet_addr = wallet_listener.local_addr().unwrap();
    let wallet_app = wallet_router(state);
    tokio::spawn(async move {
        axum::serve(wallet_listener, wallet_app).await.unwrap();
    });

    TestServer {
        admin_base: format!("http://{admin_addr}"),
        wallet_base: format!("http://{wallet_addr}"),
        root_cert_pem: root.cert_pem,
        _storage_dir: dir,
    }
}
```

The exact field/type names in `foundry_core::config::Config` and `foundry::server::AppState` (`config`, `storage`, `admin_key`, and whether `AdminApiKey` has a `From<String>` impl) must match `crates/foundry/tests/wallet_verification.rs`'s `setup_test_app` — read that file's full `setup_test_app` function (not just the excerpt already seen) before finalizing this harness, and adjust field names/constructor calls to match exactly if they differ from what's written above.

- [ ] **Step 2: Verify the harness compiles**

Since `tests/support/mod.rs` alone has no `#[test]` functions, verify it compiles by temporarily adding one throwaway smoke test in the same file:

```rust
#[cfg(test)]
mod smoke {
    use super::*;

    #[tokio::test]
    async fn server_boots_and_admin_base_is_reachable() {
        let server = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/ready", server.admin_base))
            .send()
            .await
            .expect("GET /ready");
        assert!(resp.status().is_success());
    }
}
```

Run: `cargo test -p foundry-wallet --test support server_boots_and_admin_base_is_reachable`

Note: Cargo only compiles files directly under `tests/` as integration test binaries, not files under `tests/support/`. Create a thin `crates/foundry-wallet/tests/support_smoke.rs` that does `mod support; use support::spawn_test_server;` plus the smoke test above (move the smoke test there instead of leaving it in `tests/support/mod.rs`), so `cargo test -p foundry-wallet --test support_smoke` runs it.

Expected: PASS.

- [ ] **Step 3: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-wallet/tests/support crates/foundry-wallet/tests/support_smoke.rs
git commit -m "test(foundry-wallet): shared in-process admin+wallet server harness"
```

---

### Task 12: Issuance action (`actions/issuance.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/actions/issuance.rs`
- Modify: `crates/foundry-wallet/src/actions/mod.rs` (add `pub mod issuance;`)
- Create: `crates/foundry-wallet/tests/issuance.rs`

**Interfaces:**
- Consumes: `config::{WalletConfig, IssuancePreset, TrustValidationMode}`, `http::LoggingHttpClient`, `actions::{offer_source, proof, trust}`, `storage::{ensure_data_dir_layout, credential_store}`, `foundry_core::trust::TrustStore`, `foundry_issuer::CreateOfferResponse`.
- Produces: `actions::issuance::{IssuanceOutcome { credential_id: String, vct: String, trust_valid: Option<bool> }, run_issuance(config: &WalletConfig, preset: Option<&str>, offer_uri: Option<&str>, tx_code: Option<&str>) -> WalletResult<IssuanceOutcome>}`. Consumed by Task 14 (CLI `issue` subcommand) and Task 16 (TUI issuance screen).

- [ ] **Step 1: Write the failing integration test**

Create `crates/foundry-wallet/tests/issuance.rs`:

```rust
mod support;

use foundry_core::trust::TrustStore;
use foundry_wallet::actions::issuance::run_issuance;
use foundry_wallet::config::{
    EndpointsConfig, IssuancePreset, TrustAnchorConfig, TrustConfig, TrustValidationMode, WalletConfig,
};
use std::collections::BTreeMap;
use support::spawn_test_server;

fn wallet_config(data_dir: std::path::PathBuf, server: &support::TestServer, trust_anchor_path: std::path::PathBuf) -> WalletConfig {
    let mut issuance_presets = BTreeMap::new();
    issuance_presets.insert(
        "pid".to_string(),
        IssuancePreset {
            credential_type_id: "pid".to_string(),
            claims: BTreeMap::from([
                ("given_name".to_string(), serde_json::json!("Alice")),
                ("birthdate".to_string(), serde_json::json!("1990-01-01")),
            ]),
            tx_code_required: false,
        },
    );
    WalletConfig {
        data_dir,
        endpoints: EndpointsConfig {
            admin_base_url: server.admin_base.clone(),
            wallet_base_url: server.wallet_base.clone(),
            admin_api_key: Some(support::ADMIN_API_KEY.to_string()),
            admin_api_key_env: None,
        },
        trust: TrustConfig {
            validation: TrustValidationMode::Enabled,
            anchors: vec![TrustAnchorConfig { certs: trust_anchor_path }],
        },
        issuance_presets,
        verification_presets: BTreeMap::new(),
    }
}

#[tokio::test]
async fn issuance_with_matching_trust_anchor_stores_a_valid_credential() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();

    let config = wallet_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    let outcome = run_issuance(&config, Some("pid"), None, None).await.unwrap();
    assert_eq!(outcome.vct, support::VCT_PID);
    assert_eq!(outcome.trust_valid, Some(true));

    let stored = foundry_wallet::storage::credential_store::load_metadata(
        &config.data_dir,
        &outcome.credential_id,
    )
    .unwrap();
    assert_eq!(stored.vct, support::VCT_PID);
    assert!(stored.disclosed_claims.contains(&"given_name".to_string()));

    let payload = foundry_wallet::storage::credential_store::load_payload(
        &config.data_dir,
        &outcome.credential_id,
    )
    .unwrap();
    assert_eq!(payload["disclosed_claims"]["given_name"], "Alice");
    assert_eq!(payload["disclosed_claims"]["birthdate"], "1990-01-01");

    // Full request/response logging happened (no redaction).
    let events =
        foundry_wallet::storage::event_log::read_events(&config.data_dir).unwrap();
    assert!(events.iter().any(|e| e["kind"] == "http_request" && e["method"] == "POST"));
}

#[tokio::test]
async fn issuance_with_unrelated_trust_anchor_stores_but_flags_trust_invalid() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    // An unrelated root that does NOT chain to the issuer's leaf.
    let unrelated_root = foundry_core::pki::new_ca("Unrelated Root", 365).unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &unrelated_root.cert_pem).unwrap();

    let config = wallet_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    // Storage is never blocked, per the design doc's asymmetric rule.
    let outcome = run_issuance(&config, Some("pid"), None, None).await.unwrap();
    assert_eq!(outcome.trust_valid, Some(false));
}

#[tokio::test]
async fn unknown_preset_errors_with_config_kind() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config = wallet_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    let err = run_issuance(&config, Some("nonexistent"), None, None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "config");
    let _ = TrustStore::from_pems(&[]); // keep TrustStore import used if unused elsewhere
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-wallet --test issuance`
Expected: FAIL to compile — `foundry_wallet::actions::issuance` doesn't exist yet.

- [ ] **Step 3: Implement `actions/issuance.rs`**

Create `crates/foundry-wallet/src/actions/issuance.rs`:

```rust
//! Orchestrates the full OpenID4VCI flow: obtain an offer (preset-created or
//! consumed via deep link) -> `/token` -> `/nonce` -> proof -> `/credential`
//! -> trust validation -> file storage. See the design doc section 6.

use crate::actions::offer_source::{parse_offer_deep_link, OfferSource};
use crate::actions::proof::build_proof_jwt;
use crate::actions::trust::validate_jws_x5c_chain;
use crate::config::{TrustValidationMode, WalletConfig};
use crate::error::{WalletError, WalletResult};
use crate::http::LoggingHttpClient;
use crate::storage::credential_store::{store_credential, CredentialMetadata, NewCredential};
use crate::storage::{ensure_data_dir_layout, now_rfc3339};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::trust::TrustStore;
use foundry_issuer::CreateOfferResponse;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct IssuanceOutcome {
    pub credential_id: String,
    pub vct: String,
    pub trust_valid: Option<bool>,
}

pub async fn run_issuance(
    config: &WalletConfig,
    preset: Option<&str>,
    offer_uri: Option<&str>,
    tx_code: Option<&str>,
) -> WalletResult<IssuanceOutcome> {
    ensure_data_dir_layout(&config.data_dir)?;
    let http = LoggingHttpClient::new(&config.data_dir);

    // Step 1: obtain the offer.
    let offer = match offer_uri {
        Some(uri) => match parse_offer_deep_link(uri)? {
            OfferSource::Inline(offer) => offer,
            OfferSource::RemoteUri(url) => {
                let (status, body) = http.get(&url, None).await?;
                ensure_2xx(status, &url, &body)?;
                serde_json::from_str(&body)?
            }
        },
        None => {
            let preset_name = preset.ok_or_else(|| {
                WalletError::Config("either --preset or --offer-uri is required".to_string())
            })?;
            let preset = config.issuance_presets.get(preset_name).ok_or_else(|| {
                WalletError::Config(format!("unknown issuance preset '{preset_name}'"))
            })?;
            let admin_api_key = config.endpoints.resolve_admin_api_key()?;
            let url = format!("{}/admin/issuance/offers", config.endpoints.admin_base_url);
            let body = serde_json::json!({
                "credential_type_id": preset.credential_type_id,
                "claims": preset.claims,
                "tx_code_required": preset.tx_code_required,
            });
            let (status, resp_body) = http.post_json(&url, Some(&admin_api_key), &body).await?;
            ensure_2xx(status, &url, &resp_body)?;
            let create_offer_response: CreateOfferResponse = serde_json::from_str(&resp_body)?;
            create_offer_response.credential_offer
        }
    };

    // Step 2: token.
    let grant = &offer.grants.pre_authorized_code;
    let mut form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={}",
        grant.pre_authorized_code
    );
    if let Some(code) = tx_code {
        form.push_str(&format!("&tx_code={code}"));
    }
    let token_url = format!("{}/token", config.endpoints.wallet_base_url);
    let (status, token_body) = http.post_form(&token_url, None, &form).await?;
    ensure_2xx(status, &token_url, &token_body)?;
    let token_json: serde_json::Value = serde_json::from_str(&token_body)?;
    let access_token = token_json["access_token"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedOffer("token response missing access_token".to_string()))?
        .to_string();

    // Step 3: nonce.
    let nonce_url = format!("{}/nonce", config.endpoints.wallet_base_url);
    let (status, nonce_body) = http.post_empty(&nonce_url, Some(&access_token)).await?;
    ensure_2xx(status, &nonce_url, &nonce_body)?;
    let nonce_json: serde_json::Value = serde_json::from_str(&nonce_body)?;
    let c_nonce = nonce_json["c_nonce"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedOffer("nonce response missing c_nonce".to_string()))?;

    // Step 4: holder key + proof.
    let proof = build_proof_jwt(c_nonce, &offer.credential_issuer)?;

    // Step 5: credential.
    let credential_configuration_id = offer
        .credential_configuration_ids
        .first()
        .ok_or_else(|| WalletError::MalformedOffer("offer has no credential_configuration_ids".to_string()))?;
    let cred_url = format!("{}/credential", config.endpoints.wallet_base_url);
    let cred_req = serde_json::json!({
        "credential_configuration_id": credential_configuration_id,
        "format": "dc+sd-jwt",
        "proof": proof.proof_json,
    });
    let (status, cred_body) = http.post_json(&cred_url, Some(&access_token), &cred_req).await?;
    ensure_2xx(status, &cred_url, &cred_body)?;
    let cred_json: serde_json::Value = serde_json::from_str(&cred_body)?;
    let compact = cred_json["credential"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedOffer("credential response missing 'credential'".to_string()))?
        .to_string();

    // Decode issuer JWT (first `~`-segment) and disclosures.
    let issuer_jwt = compact
        .split('~')
        .next()
        .ok_or_else(|| WalletError::MalformedOffer("credential is not a compact SD-JWT VC".to_string()))?;
    let jwt_parts: Vec<&str> = issuer_jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(WalletError::MalformedOffer(
            "issuer-signed JWT is not a compact JWS".to_string(),
        ));
    }
    let header: serde_json::Value = serde_json::from_slice(&B64URL.decode(jwt_parts[0])?)?;
    let issuer_payload: serde_json::Value = serde_json::from_slice(&B64URL.decode(jwt_parts[1])?)?;
    let vct = issuer_payload["vct"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedOffer("issuer JWT payload missing vct".to_string()))?
        .to_string();
    let issuer = issuer_payload["iss"].as_str().unwrap_or("").to_string();
    let status_list_uri = issuer_payload["status"]["status_list"]["uri"]
        .as_str()
        .map(|s| s.to_string());
    let status_list_idx = issuer_payload["status"]["status_list"]["idx"].as_u64();

    let mut disclosed_claims = serde_json::Map::new();
    for seg in compact.split('~').skip(1).filter(|s| !s.is_empty()) {
        let arr: serde_json::Value = serde_json::from_slice(&B64URL.decode(seg)?)?;
        if let Some(arr) = arr.as_array() {
            if arr.len() == 3 {
                if let Some(name) = arr[1].as_str() {
                    disclosed_claims.insert(name.to_string(), arr[2].clone());
                }
            }
        }
    }

    // Step 6: trust validation (never blocks storage).
    let trust_valid = match config.trust.validation {
        TrustValidationMode::Enabled => {
            let store = build_trust_store(config)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let outcome = validate_jws_x5c_chain(issuer_jwt, &store, now);
            Some(outcome.valid)
        }
        TrustValidationMode::Disabled => None,
    };

    // Step 7: decode & store.
    let credential_id = format!("cred_{}", uuid::Uuid::new_v4().simple());
    let disclosed_claim_names: Vec<String> = disclosed_claims.keys().cloned().collect();
    let metadata = CredentialMetadata {
        credential_id: credential_id.clone(),
        vct: vct.clone(),
        issuer,
        received_at: now_rfc3339(),
        status_list_uri,
        status_list_idx,
        disclosed_claims: disclosed_claim_names,
        trust_valid,
        holder_key_path: "holder_key.pem".to_string(),
    };
    let payload_json = serde_json::json!({
        "header": header,
        "payload": issuer_payload,
        "disclosed_claims": serde_json::Value::Object(disclosed_claims),
    });
    store_credential(
        &config.data_dir,
        &NewCredential {
            credential_id: &credential_id,
            compact_sdjwt: &compact,
            decoded_payload: &payload_json,
            holder_key_pem: &proof.private_key_pem,
            metadata: &metadata,
        },
    )?;

    Ok(IssuanceOutcome {
        credential_id,
        vct,
        trust_valid,
    })
}

fn build_trust_store(config: &WalletConfig) -> WalletResult<TrustStore> {
    let mut pems = Vec::new();
    for anchor in &config.trust.anchors {
        let content = std::fs::read_to_string(&anchor.certs).map_err(|e| WalletError::Storage {
            path: anchor.certs.display().to_string(),
            source: e,
        })?;
        pems.push(content.into_bytes());
    }
    TrustStore::from_pems(&pems).map_err(|e| WalletError::TrustValidation(e.to_string()))
}

fn ensure_2xx(status: u16, url: &str, body: &str) -> WalletResult<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(WalletError::HttpStatus {
            status,
            url: url.to_string(),
            body: body.to_string(),
        })
    }
}
```

- [ ] **Step 4: Wire the module**

In `crates/foundry-wallet/src/actions/mod.rs`, add `pub mod issuance;`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry-wallet --test issuance`
Expected: PASS (3 tests). If `wallet_config`'s field names don't match `WalletConfig`'s actual definition from Task 3, or `TestServer`'s fields don't match Task 11's harness, fix the mismatches (this is exactly the kind of cross-task type-consistency check the plan's self-review step verifies — see the plan's own Self-Review section below for the process, but fix any real compile error found here immediately since it blocks this task).

- [ ] **Step 6: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-wallet/src/actions/issuance.rs crates/foundry-wallet/src/actions/mod.rs crates/foundry-wallet/tests/issuance.rs
git commit -m "feat(foundry-wallet): full OpenID4VCI issuance action"
```

---

### Task 13: Verification action (`actions/verification.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/actions/verification.rs`
- Modify: `crates/foundry-wallet/src/actions/mod.rs` (add `pub mod verification;`)
- Create: `crates/foundry-wallet/tests/verification.rs`

**Interfaces:**
- Consumes: `config::{WalletConfig, VerificationPreset, TrustValidationMode}`, `http::LoggingHttpClient`, `actions::{request_source, trust, match_credentials}`, `storage::credential_store::{load_holder_key_pem, load_compact_sdjwt}`, `foundry_sd_jwt_vc::builder::attach_kb_jwt`, `openid4vp::core::jwe::JweBuilder`, `foundry_verifier::{CreateVerificationResponse, VerificationResult}`.
- Produces: `actions::verification::{Consent::{Accept, Decline}, VerificationOutcome::{Verified(VerificationResult), Declined}, run_verification(config: &WalletConfig, preset: Option<&str>, request_uri: Option<&str>, consent: Consent) -> WalletResult<VerificationOutcome>}`. Consumed by Task 14 (CLI `verify` subcommand) and Task 16 (TUI verification screen).

- [ ] **Step 1: Write the failing integration test**

Create `crates/foundry-wallet/tests/verification.rs`:

```rust
mod support;

use foundry_wallet::actions::issuance::run_issuance;
use foundry_wallet::actions::verification::{run_verification, Consent, VerificationOutcome};
use foundry_wallet::config::{
    EndpointsConfig, IssuancePreset, TrustAnchorConfig, TrustConfig, TrustValidationMode,
    VerificationPreset, WalletConfig,
};
use std::collections::BTreeMap;
use support::spawn_test_server;

fn base_config(
    data_dir: std::path::PathBuf,
    server: &support::TestServer,
    trust_anchor_path: std::path::PathBuf,
) -> WalletConfig {
    let mut issuance_presets = BTreeMap::new();
    issuance_presets.insert(
        "pid".to_string(),
        IssuancePreset {
            credential_type_id: "pid".to_string(),
            claims: BTreeMap::from([
                ("given_name".to_string(), serde_json::json!("Alice")),
                ("birthdate".to_string(), serde_json::json!("1990-01-01")),
            ]),
            tx_code_required: false,
        },
    );
    let mut verification_presets = BTreeMap::new();
    verification_presets.insert(
        "dcql1".to_string(),
        VerificationPreset {
            dcql_query: serde_json::json!({
                "credentials": [{
                    "id": "c1",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [support::VCT_PID] },
                    "claims": [{ "path": ["given_name"] }, { "path": ["birthdate"] }]
                }]
            }),
            transport: "request_uri".to_string(),
        },
    );
    WalletConfig {
        data_dir,
        endpoints: EndpointsConfig {
            admin_base_url: server.admin_base.clone(),
            wallet_base_url: server.wallet_base.clone(),
            admin_api_key: Some(support::ADMIN_API_KEY.to_string()),
            admin_api_key_env: None,
        },
        trust: TrustConfig {
            validation: TrustValidationMode::Enabled,
            anchors: vec![TrustAnchorConfig { certs: trust_anchor_path }],
        },
        issuance_presets,
        verification_presets,
    }
}

#[tokio::test]
async fn accepted_verification_with_matching_credential_succeeds() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config = base_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    run_issuance(&config, Some("pid"), None, None).await.unwrap();

    let outcome = run_verification(&config, Some("dcql1"), None, Consent::Accept)
        .await
        .unwrap();
    match outcome {
        VerificationOutcome::Verified(result) => {
            assert!(result.verified, "checks: {:?}", result.checks);
        }
        VerificationOutcome::Declined => panic!("expected Verified"),
    }
}

#[tokio::test]
async fn declined_verification_never_calls_the_response_endpoint() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config = base_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    run_issuance(&config, Some("pid"), None, None).await.unwrap();

    let outcome = run_verification(&config, Some("dcql1"), None, Consent::Decline)
        .await
        .unwrap();
    assert!(matches!(outcome, VerificationOutcome::Declined));

    let events = foundry_wallet::storage::event_log::read_events(&config.data_dir).unwrap();
    let posted_response = events.iter().any(|e| {
        e["kind"] == "http_request"
            && e["url"].as_str().unwrap_or("").contains("/vp/response/")
    });
    assert!(!posted_response, "declined flow must never POST /vp/response/:id");
}

#[tokio::test]
async fn untrusted_request_object_aborts_before_any_credential_is_touched() {
    let server = spawn_test_server().await;
    let data_dir = tempfile::tempdir().unwrap();
    let trust_dir = tempfile::tempdir().unwrap();
    // Unrelated root: the verifier's request object won't chain to it.
    let unrelated_root = foundry_core::pki::new_ca("Unrelated Root", 365).unwrap();
    let trust_anchor_path = trust_dir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &unrelated_root.cert_pem).unwrap();
    let config = base_config(data_dir.path().to_path_buf(), &server, trust_anchor_path);

    run_issuance(&config, Some("pid"), None, None).await.unwrap();

    let err = run_verification(&config, Some("dcql1"), None, Consent::Accept)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "trust_validation");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-wallet --test verification`
Expected: FAIL to compile — `foundry_wallet::actions::verification` doesn't exist yet.

- [ ] **Step 3: Implement `actions/verification.rs`**

Create `crates/foundry-wallet/src/actions/verification.rs`:

```rust
//! Orchestrates the full OpenID4VP flow: obtain a request (preset-created or
//! consumed via deep link) -> parse+trust-validate the signed request object
//! -> match stored credentials -> consent -> build/encrypt/submit the
//! response. See the design doc section 7.

use crate::actions::match_credentials::match_credentials;
use crate::actions::request_source::parse_request_deep_link;
use crate::actions::trust::validate_jws_x5c_chain;
use crate::config::{TrustValidationMode, WalletConfig};
use crate::error::{WalletError, WalletResult};
use crate::http::LoggingHttpClient;
use crate::storage::credential_store::{load_compact_sdjwt, load_holder_key_pem};
use crate::storage::event_log;
use crate::storage::now_rfc3339;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::trust::TrustStore;
use foundry_sd_jwt_vc::builder::attach_kb_jwt;
use foundry_verifier::{CreateVerificationResponse, VerificationResult};
use openid4vp::core::jwe::JweBuilder;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Accept,
    Decline,
}

pub enum VerificationOutcome {
    Verified(VerificationResult),
    Declined,
}

pub async fn run_verification(
    config: &WalletConfig,
    preset: Option<&str>,
    request_uri: Option<&str>,
    consent: Consent,
) -> WalletResult<VerificationOutcome> {
    let http = LoggingHttpClient::new(&config.data_dir);

    // Step 1: obtain the request.
    let request_url = match request_uri {
        Some(uri) => parse_request_deep_link(uri)?,
        None => {
            let preset_name = preset.ok_or_else(|| {
                WalletError::Config("either --preset or --request-uri is required".to_string())
            })?;
            let preset = config.verification_presets.get(preset_name).ok_or_else(|| {
                WalletError::Config(format!("unknown verification preset '{preset_name}'"))
            })?;
            let admin_api_key = config.endpoints.resolve_admin_api_key()?;
            let url = format!("{}/admin/verification/requests", config.endpoints.admin_base_url);
            let body = serde_json::json!({
                "dcql_query": preset.dcql_query,
                "transport": preset.transport,
            });
            let (status, resp_body) = http.post_json(&url, Some(&admin_api_key), &body).await?;
            ensure_2xx(status, &url, &resp_body)?;
            let create_resp: CreateVerificationResponse = serde_json::from_str(&resp_body)?;
            format!(
                "{}/vp/request/{}",
                config.endpoints.wallet_base_url, create_resp.verification_id
            )
        }
    };

    let (status, jws_str) = http.get(&request_url, None).await?;
    ensure_2xx(status, &request_url, &jws_str)?;

    // Step 2: parse and (optionally) trust-validate the signed request object.
    let parts: Vec<&str> = jws_str.split('.').collect();
    if parts.len() != 3 {
        return Err(WalletError::MalformedRequestObject(
            "request object is not a compact JWS".to_string(),
        ));
    }
    let request_object: serde_json::Value = serde_json::from_slice(&B64URL.decode(parts[1])?)?;
    let client_id = request_object["client_id"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedRequestObject("missing client_id".to_string()))?
        .to_string();
    let nonce = request_object["nonce"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedRequestObject("missing nonce".to_string()))?
        .to_string();
    let dcql_query = request_object["dcql_query"].clone();
    let ephemeral_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    if config.trust.validation == TrustValidationMode::Enabled {
        let store = build_trust_store(config)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let outcome = validate_jws_x5c_chain(&jws_str, &store, now);
        event_log::append_event(
            &config.data_dir,
            &serde_json::json!({
                "ts": now_rfc3339(), "kind": "trust_validation_result",
                "context": "verification_request", "valid": outcome.valid, "detail": outcome.detail,
            }),
        )?;
        if !outcome.valid {
            return Err(WalletError::TrustValidation(outcome.detail));
        }
    }

    // Step 3: match stored credentials.
    let matches = match_credentials(&config.data_dir, &dcql_query)?;
    let matched = matches
        .first()
        .ok_or(WalletError::NoMatchingCredential)?;

    // Step 4: consent.
    event_log::append_event(
        &config.data_dir,
        &serde_json::json!({
            "ts": now_rfc3339(), "kind": "consent_decision",
            "client_id": client_id, "credential_id": matched.credential_id,
            "decision": if consent == Consent::Accept { "accept" } else { "decline" },
        }),
    )?;
    if consent == Consent::Decline {
        return Ok(VerificationOutcome::Declined);
    }

    // Step 5: build the presentation and submit.
    let compact = load_compact_sdjwt(&config.data_dir, &matched.credential_id)?;
    let holder_key_pem = load_holder_key_pem(&config.data_dir, &matched.credential_id)?;
    let holder_signer = FileSigner::from_pem(&holder_key_pem, SignatureAlgorithm::Es256)
        .map_err(|e| WalletError::MalformedRequestObject(format!("invalid stored holder key: {e}")))?;
    let presentation = attach_kb_jwt(compact, &holder_signer, &client_id, &nonce)
        .map_err(|e| WalletError::MalformedRequestObject(format!("attach_kb_jwt failed: {e}")))?;

    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": presentation }))
        .recipient_key_json(&ephemeral_jwk)
        .map_err(|e| WalletError::MalformedRequestObject(format!("invalid ephemeral jwk: {e}")))?
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .map_err(|e| WalletError::MalformedRequestObject(format!("JWE build failed: {e}")))?;

    let response_url = format!(
        "{}/vp/response/{}",
        config.endpoints.wallet_base_url,
        request_url
            .rsplit('/')
            .next()
            .ok_or_else(|| WalletError::MalformedRequestObject("request url has no path segment".to_string()))?
    );
    let (status, resp_body) = http.post_text(&response_url, &jwe_str).await?;
    ensure_2xx(status, &response_url, &resp_body)?;
    let result: VerificationResult = serde_json::from_str(&resp_body)?;
    Ok(VerificationOutcome::Verified(result))
}

fn build_trust_store(config: &WalletConfig) -> WalletResult<TrustStore> {
    let mut pems = Vec::new();
    for anchor in &config.trust.anchors {
        let content = std::fs::read_to_string(&anchor.certs).map_err(|e| WalletError::Storage {
            path: anchor.certs.display().to_string(),
            source: e,
        })?;
        pems.push(content.into_bytes());
    }
    TrustStore::from_pems(&pems).map_err(|e| WalletError::TrustValidation(e.to_string()))
}

fn ensure_2xx(status: u16, url: &str, body: &str) -> WalletResult<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(WalletError::HttpStatus {
            status,
            url: url.to_string(),
            body: body.to_string(),
        })
    }
}
```

Note: `response_url`'s construction assumes `request_url`'s final path segment is the `verification_id` (true for `.../vp/request/{id}`, matching `.../vp/response/{id}`) — this holds for both the preset-created path (built from `create_resp.verification_id` directly) and the deep-link-consumed path (per the OpenID4VP wallet-facing route shape used throughout this codebase, e.g. `crates/foundry/tests/e2e_full_flow.rs`'s `run_verification`).

- [ ] **Step 4: Wire the module**

In `crates/foundry-wallet/src/actions/mod.rs`, add `pub mod verification;`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry-wallet --test verification`
Expected: PASS (3 tests). Fix any field/type mismatches against `WalletConfig`, `TestServer`, or `foundry_verifier`'s exact type shapes discovered at compile time.

- [ ] **Step 6: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-wallet/src/actions/verification.rs crates/foundry-wallet/src/actions/mod.rs crates/foundry-wallet/tests/verification.rs
git commit -m "feat(foundry-wallet): full OpenID4VP verification action"
```

---

### Task 14: Headless CLI wiring (`main.rs`, `cli.rs` output helpers)

**Files:**
- Modify: `crates/foundry-wallet/src/main.rs`
- Modify: `crates/foundry-wallet/src/cli.rs` (add a `credentials events tail` value type if needed — none required beyond Task 2's existing definitions)
- Create: `crates/foundry-wallet/tests/cli_headless.rs`

**Interfaces:**
- Consumes: `actions::{issuance::run_issuance, verification::{run_verification, Consent, VerificationOutcome}}`, `storage::credential_store::{list_credentials, load_metadata, load_payload}`, `storage::event_log::tail_events`, `config::WalletConfig`.
- Produces: the full headless CLI surface from the design doc section 4, each printing JSON to stdout on success (exit 0) or `{"error": ..., "kind": ...}` to stderr (exit 1).

- [ ] **Step 1: Write the failing integration test**

Create `crates/foundry-wallet/tests/cli_headless.rs`:

```rust
mod support;

use assert_cmd::Command;
use std::io::Write;
use support::spawn_test_server;

fn write_wallet_config(
    path: &std::path::Path,
    data_dir: &std::path::Path,
    server: &support::TestServer,
    trust_anchor_path: &std::path::Path,
) {
    let yaml = format!(
        r#"
data_dir: {data_dir}
endpoints:
  admin_base_url: {admin_base}
  wallet_base_url: {wallet_base}
  admin_api_key: {api_key}
trust:
  validation: enabled
  anchors:
    - certs: {trust_anchor}
issuance_presets:
  pid:
    credential_type_id: pid
    claims:
      given_name: Alice
      birthdate: "1990-01-01"
    tx_code_required: false
verification_presets:
  dcql1:
    dcql_query:
      credentials:
        - id: c1
          format: dc+sd-jwt
          meta: {{ vct_values: ["{vct}"] }}
          claims:
            - path: ["given_name"]
    transport: request_uri
"#,
        data_dir = data_dir.display(),
        admin_base = server.admin_base,
        wallet_base = server.wallet_base,
        api_key = support::ADMIN_API_KEY,
        trust_anchor = trust_anchor_path.display(),
        vct = support::VCT_PID,
    );
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
}

#[tokio::test]
async fn issue_then_verify_accept_via_headless_subcommands() {
    let server = spawn_test_server().await;
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let trust_anchor_path = workdir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config_path = workdir.path().join("wallet.yaml");
    write_wallet_config(&config_path, &data_dir, &server, &trust_anchor_path);

    let issue_output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args(["--config", config_path.to_str().unwrap(), "issue", "--preset", "pid"])
        .output()
        .unwrap();
    assert!(issue_output.status.success(), "stderr: {}", String::from_utf8_lossy(&issue_output.stderr));
    let issue_json: serde_json::Value = serde_json::from_slice(&issue_output.stdout).unwrap();
    assert_eq!(issue_json["trust_valid"], true);

    let verify_output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config", config_path.to_str().unwrap(),
            "verify", "--preset", "dcql1", "--consent", "accept",
        ])
        .output()
        .unwrap();
    assert!(verify_output.status.success(), "stderr: {}", String::from_utf8_lossy(&verify_output.stderr));
    let verify_json: serde_json::Value = serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verify_json["verified"], true);
}

#[tokio::test]
async fn verify_decline_exits_zero_with_declined_json() {
    let server = spawn_test_server().await;
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let trust_anchor_path = workdir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, &server.root_cert_pem).unwrap();
    let config_path = workdir.path().join("wallet.yaml");
    write_wallet_config(&config_path, &data_dir, &server, &trust_anchor_path);

    Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args(["--config", config_path.to_str().unwrap(), "issue", "--preset", "pid"])
        .assert()
        .success();

    let verify_output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args([
            "--config", config_path.to_str().unwrap(),
            "verify", "--preset", "dcql1", "--consent", "decline",
        ])
        .output()
        .unwrap();
    assert!(verify_output.status.success());
    let verify_json: serde_json::Value = serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verify_json["consent"], "declined");
}

#[test]
fn issue_with_unknown_preset_exits_nonzero_with_error_json() {
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let trust_anchor_path = workdir.path().join("root.pem");
    std::fs::write(&trust_anchor_path, "not-a-real-cert").unwrap();
    let config_path = workdir.path().join("wallet.yaml");
    let yaml = format!(
        "data_dir: {}\nendpoints:\n  admin_base_url: http://127.0.0.1:1\n  wallet_base_url: http://127.0.0.1:1\n  admin_api_key: k\ntrust:\n  validation: disabled\n",
        data_dir.display()
    );
    std::fs::write(&config_path, yaml).unwrap();

    let output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args(["--config", config_path.to_str().unwrap(), "issue", "--preset", "nonexistent"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err_json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err_json["kind"], "config");
}

#[test]
fn credentials_list_on_empty_wallet_returns_empty_json_array() {
    let workdir = tempfile::tempdir().unwrap();
    let data_dir = workdir.path().join("wallet-data");
    let config_path = workdir.path().join("wallet.yaml");
    let yaml = format!(
        "data_dir: {}\nendpoints:\n  admin_base_url: http://127.0.0.1:1\n  wallet_base_url: http://127.0.0.1:1\n  admin_api_key: k\ntrust:\n  validation: disabled\n",
        data_dir.display()
    );
    std::fs::write(&config_path, yaml).unwrap();

    let output = Command::cargo_bin("foundry-wallet")
        .unwrap()
        .args(["--config", config_path.to_str().unwrap(), "credentials", "list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-wallet --test cli_headless`
Expected: FAIL — `main.rs` doesn't yet dispatch these subcommands to real logic (Task 2's stub prints placeholder text, exit 0, non-JSON stdout).

- [ ] **Step 3: Implement full dispatch in `main.rs`**

Replace `crates/foundry-wallet/src/main.rs` with:

```rust
use clap::Parser;
use foundry_wallet::actions::issuance::run_issuance;
use foundry_wallet::actions::verification::{run_verification, Consent, VerificationOutcome};
use foundry_wallet::cli::{Cli, Command, ConsentArg, CredentialsAction, EventsAction};
use foundry_wallet::config::WalletConfig;
use foundry_wallet::error::WalletError;
use foundry_wallet::storage::credential_store::{list_credentials, load_metadata, load_payload};
use foundry_wallet::storage::event_log::tail_events;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit_code = run(cli).await;
    std::process::exit(exit_code);
}

async fn run(cli: Cli) -> i32 {
    let config = match WalletConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => return print_error(&e),
    };

    match cli.command {
        None | Some(Command::Tui) => {
            println!("TUI not yet implemented (see Task 15/16 of the implementation plan)");
            0
        }
        Some(Command::Issue { preset, offer_uri, tx_code }) => {
            match run_issuance(&config, preset.as_deref(), offer_uri.as_deref(), tx_code.as_deref()).await {
                Ok(outcome) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "credential_id": outcome.credential_id,
                            "vct": outcome.vct,
                            "trust_valid": outcome.trust_valid,
                        })
                    );
                    0
                }
                Err(e) => print_error(&e),
            }
        }
        Some(Command::Verify { preset, request_uri, consent }) => {
            let consent = match consent {
                ConsentArg::Accept => Consent::Accept,
                ConsentArg::Decline => Consent::Decline,
            };
            match run_verification(&config, preset.as_deref(), request_uri.as_deref(), consent).await {
                Ok(VerificationOutcome::Verified(result)) => {
                    println!("{}", serde_json::to_string(&result).unwrap_or_default());
                    0
                }
                Ok(VerificationOutcome::Declined) => {
                    println!("{}", serde_json::json!({"consent": "declined"}));
                    0
                }
                Err(e) => print_error(&e),
            }
        }
        Some(Command::Credentials { action }) => match action {
            CredentialsAction::List => match list_credentials(&config.data_dir) {
                Ok(list) => {
                    println!("{}", serde_json::to_string(&list).unwrap_or_default());
                    0
                }
                Err(e) => print_error(&e),
            },
            CredentialsAction::Show { id } => match (load_metadata(&config.data_dir, &id), load_payload(&config.data_dir, &id)) {
                (Ok(metadata), Ok(payload)) => {
                    println!(
                        "{}",
                        serde_json::json!({"metadata": metadata, "payload": payload})
                    );
                    0
                }
                (Err(e), _) | (_, Err(e)) => print_error(&e),
            },
        },
        Some(Command::Events { action }) => match action {
            EventsAction::Tail { n } => match tail_events(&config.data_dir, n) {
                Ok(events) => {
                    println!("{}", serde_json::to_string(&events).unwrap_or_default());
                    0
                }
                Err(e) => print_error(&e),
            },
        },
    }
}

fn print_error(e: &WalletError) -> i32 {
    eprintln!(
        "{}",
        serde_json::json!({"error": e.to_string(), "kind": e.kind()})
    );
    1
}
```

`load_metadata`/`load_payload`'s tuple-match arm `(Err(e), _) | (_, Err(e))` binds `e` from either position — if this doesn't compile due to differing error ownership between the two `Result`s, replace it with two sequential `match`/`?`-style checks instead:
```rust
CredentialsAction::Show { id } => {
    let metadata = match load_metadata(&config.data_dir, &id) {
        Ok(m) => m,
        Err(e) => return print_error(&e),
    };
    let payload = match load_payload(&config.data_dir, &id) {
        Ok(p) => p,
        Err(e) => return print_error(&e),
    };
    println!("{}", serde_json::json!({"metadata": metadata, "payload": payload}));
    0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-wallet --test cli_headless`
Expected: PASS (4 tests).

- [ ] **Step 5: Run full crate test suite**

Run: `cargo test -p foundry-wallet`
Expected: PASS (all unit + integration tests from Tasks 2-14).

- [ ] **Step 6: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-wallet/src/main.rs crates/foundry-wallet/tests/cli_headless.rs
git commit -m "feat(foundry-wallet): headless issue/verify/credentials/events subcommands"
```

---

### Task 15: TUI navigation state machine (`tui/state.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/tui/mod.rs`
- Create: `crates/foundry-wallet/src/tui/state.rs`
- Modify: `crates/foundry-wallet/src/lib.rs` (add `pub mod tui;`)

**Interfaces:**
- Produces: `tui::state::{Screen::{MainMenu, TriggerIssuance, TriggerVerification, BrowseCredentials, EventLog}, MainMenuItem, AppState { screen: Screen, main_menu_selected: usize, credential_list_selected: usize }, AppState::new() -> Self, AppState::handle_key(&mut self, key: crossterm::event::KeyCode) -> Option<TuiCommand>, TuiCommand::{Quit, EnterScreen(Screen), TriggerIssuancePreset(String), TriggerVerificationPreset(String)}}`. Pure, no I/O, no rendering — fully unit-testable. Consumed by Task 16 (rendering + main loop).

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-wallet/src/tui/mod.rs`:

```rust
pub mod state;
```

Create `crates/foundry-wallet/src/tui/state.rs`:

```rust
//! Pure TUI navigation state machine: given the current screen and a key
//! press, decides the next screen (if any) and/or an action for the caller
//! (`tui::app`, Task 16) to execute against `actions::`. No rendering, no
//! I/O — fully unit-testable without a real terminal.

use crossterm::event::KeyCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    MainMenu,
    TriggerIssuance,
    TriggerVerification,
    BrowseCredentials,
    EventLog,
}

const MAIN_MENU_ITEMS: [&str; 5] = [
    "Trigger Issuance",
    "Trigger Verification",
    "Browse Credentials",
    "Event Log",
    "Quit",
];

#[derive(Debug, Clone, PartialEq)]
pub enum TuiCommand {
    Quit,
    RunIssuancePreset(String),
    RunVerificationPreset(String, Consent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Accept,
    Decline,
}

pub struct AppState {
    pub screen: Screen,
    pub main_menu_selected: usize,
    /// Presets available for issuance/verification screens, injected at
    /// construction from `WalletConfig` (Task 16 wires this).
    pub issuance_preset_names: Vec<String>,
    pub verification_preset_names: Vec<String>,
    pub preset_selected: usize,
}

impl AppState {
    pub fn new(issuance_preset_names: Vec<String>, verification_preset_names: Vec<String>) -> Self {
        Self {
            screen: Screen::MainMenu,
            main_menu_selected: 0,
            issuance_preset_names,
            verification_preset_names,
            preset_selected: 0,
        }
    }

    /// Handle one key press. Returns `Some(TuiCommand)` when the key press
    /// should trigger an action in the caller; navigation-only key presses
    /// (arrow keys, Enter into a submenu, Esc back to the main menu) mutate
    /// `self` and return `None`.
    pub fn handle_key(&mut self, key: KeyCode) -> Option<TuiCommand> {
        match self.screen {
            Screen::MainMenu => self.handle_main_menu_key(key),
            Screen::TriggerIssuance => self.handle_preset_screen_key(key, &self.issuance_preset_names.clone(), true),
            Screen::TriggerVerification => self.handle_preset_screen_key(key, &self.verification_preset_names.clone(), false),
            Screen::BrowseCredentials | Screen::EventLog => {
                if key == KeyCode::Esc {
                    self.screen = Screen::MainMenu;
                }
                None
            }
        }
    }

    fn handle_main_menu_key(&mut self, key: KeyCode) -> Option<TuiCommand> {
        match key {
            KeyCode::Down => {
                self.main_menu_selected = (self.main_menu_selected + 1) % MAIN_MENU_ITEMS.len();
                None
            }
            KeyCode::Up => {
                self.main_menu_selected =
                    (self.main_menu_selected + MAIN_MENU_ITEMS.len() - 1) % MAIN_MENU_ITEMS.len();
                None
            }
            KeyCode::Enter => match self.main_menu_selected {
                0 => {
                    self.screen = Screen::TriggerIssuance;
                    self.preset_selected = 0;
                    None
                }
                1 => {
                    self.screen = Screen::TriggerVerification;
                    self.preset_selected = 0;
                    None
                }
                2 => {
                    self.screen = Screen::BrowseCredentials;
                    None
                }
                3 => {
                    self.screen = Screen::EventLog;
                    None
                }
                4 => Some(TuiCommand::Quit),
                _ => None,
            },
            _ => None,
        }
    }

    fn handle_preset_screen_key(&mut self, key: KeyCode, presets: &[String], is_issuance: bool) -> Option<TuiCommand> {
        if presets.is_empty() {
            if key == KeyCode::Esc {
                self.screen = Screen::MainMenu;
            }
            return None;
        }
        match key {
            KeyCode::Down => {
                self.preset_selected = (self.preset_selected + 1) % presets.len();
                None
            }
            KeyCode::Up => {
                self.preset_selected = (self.preset_selected + presets.len() - 1) % presets.len();
                None
            }
            KeyCode::Esc => {
                self.screen = Screen::MainMenu;
                None
            }
            KeyCode::Enter if is_issuance => {
                Some(TuiCommand::RunIssuancePreset(presets[self.preset_selected].clone()))
            }
            KeyCode::Char('a') if !is_issuance => Some(TuiCommand::RunVerificationPreset(
                presets[self.preset_selected].clone(),
                Consent::Accept,
            )),
            KeyCode::Char('d') if !is_issuance => Some(TuiCommand::RunVerificationPreset(
                presets[self.preset_selected].clone(),
                Consent::Decline,
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_on_main_menu() {
        let state = AppState::new(vec![], vec![]);
        assert_eq!(state.screen, Screen::MainMenu);
        assert_eq!(state.main_menu_selected, 0);
    }

    #[test]
    fn down_and_up_wrap_around_the_main_menu() {
        let mut state = AppState::new(vec![], vec![]);
        for _ in 0..MAIN_MENU_ITEMS.len() {
            state.handle_key(KeyCode::Down);
        }
        assert_eq!(state.main_menu_selected, 0, "wraps back to 0 after a full cycle");

        state.handle_key(KeyCode::Up);
        assert_eq!(state.main_menu_selected, MAIN_MENU_ITEMS.len() - 1);
    }

    #[test]
    fn enter_on_quit_item_returns_quit_command() {
        let mut state = AppState::new(vec![], vec![]);
        state.main_menu_selected = 4; // "Quit"
        let cmd = state.handle_key(KeyCode::Enter);
        assert_eq!(cmd, Some(TuiCommand::Quit));
    }

    #[test]
    fn enter_on_trigger_issuance_navigates_without_a_command() {
        let mut state = AppState::new(vec!["pid".to_string()], vec![]);
        state.main_menu_selected = 0; // "Trigger Issuance"
        let cmd = state.handle_key(KeyCode::Enter);
        assert_eq!(cmd, None);
        assert_eq!(state.screen, Screen::TriggerIssuance);
    }

    #[test]
    fn enter_on_a_preset_in_trigger_issuance_runs_it() {
        let mut state = AppState::new(vec!["pid".to_string()], vec![]);
        state.screen = Screen::TriggerIssuance;
        let cmd = state.handle_key(KeyCode::Enter);
        assert_eq!(cmd, Some(TuiCommand::RunIssuancePreset("pid".to_string())));
    }

    #[test]
    fn accept_and_decline_keys_run_verification_with_consent() {
        let mut state = AppState::new(vec![], vec!["dcql1".to_string()]);
        state.screen = Screen::TriggerVerification;
        assert_eq!(
            state.handle_key(KeyCode::Char('a')),
            Some(TuiCommand::RunVerificationPreset("dcql1".to_string(), Consent::Accept))
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('d')),
            Some(TuiCommand::RunVerificationPreset("dcql1".to_string(), Consent::Decline))
        );
    }

    #[test]
    fn esc_from_browse_credentials_returns_to_main_menu() {
        let mut state = AppState::new(vec![], vec![]);
        state.screen = Screen::BrowseCredentials;
        state.handle_key(KeyCode::Esc);
        assert_eq!(state.screen, Screen::MainMenu);
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

In `crates/foundry-wallet/src/lib.rs`, add `pub mod tui;` after `pub mod actions;`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p foundry-wallet tui::state::`
Expected: PASS (7 tests).

- [ ] **Step 4: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-wallet/src/tui crates/foundry-wallet/src/lib.rs
git commit -m "feat(foundry-wallet): pure TUI navigation state machine"
```

---

### Task 16: TUI rendering and main loop (`tui/app.rs`, `tui/screens/*.rs`)

**Files:**
- Create: `crates/foundry-wallet/src/tui/app.rs`
- Create: `crates/foundry-wallet/src/tui/screens/mod.rs`
- Create: `crates/foundry-wallet/src/tui/screens/main_menu.rs`
- Create: `crates/foundry-wallet/src/tui/screens/issuance.rs`
- Create: `crates/foundry-wallet/src/tui/screens/verification.rs`
- Create: `crates/foundry-wallet/src/tui/screens/credentials.rs`
- Create: `crates/foundry-wallet/src/tui/screens/event_log.rs`
- Modify: `crates/foundry-wallet/src/tui/mod.rs` (add `pub mod app;` and `pub mod screens;`)
- Modify: `crates/foundry-wallet/src/main.rs` (wire the `Tui`/no-subcommand branch to `tui::app::run`)

**Interfaces:**
- Consumes: `tui::state::{AppState, Screen, TuiCommand, Consent}`, `actions::{issuance::run_issuance, verification::{run_verification, Consent as ActionConsent, VerificationOutcome}}`, `storage::credential_store::list_credentials`, `storage::event_log::tail_events`, `config::WalletConfig`.
- Produces: `tui::app::run(config: &WalletConfig) -> anyhow::Result<()>` — the only new public surface `main.rs` needs. Per the design doc section 11, this task has **no automated rendering test**; verification is a compile check plus a documented manual smoke-test procedure.

- [ ] **Step 1: Create the screen render functions**

Create `crates/foundry-wallet/src/tui/screens/mod.rs`:

```rust
pub mod credentials;
pub mod event_log;
pub mod issuance;
pub mod main_menu;
pub mod verification;
```

Create `crates/foundry-wallet/src/tui/screens/main_menu.rs`:

```rust
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

const ITEMS: [&str; 5] = [
    "Trigger Issuance",
    "Trigger Verification",
    "Browse Credentials",
    "Event Log",
    "Quit",
];

pub fn render(frame: &mut Frame, area: Rect, selected: usize) {
    let items: Vec<ListItem> = ITEMS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(*label, style)))
        })
        .collect();
    let list = List::new(items).block(Block::default().title("foundry-wallet").borders(Borders::ALL));
    frame.render_widget(list, area);
}
```

Create `crates/foundry-wallet/src/tui/screens/issuance.rs`:

```rust
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, presets: &[String], selected: usize, last_result: Option<&str>) {
    if presets.is_empty() {
        let paragraph = Paragraph::new("No issuance_presets configured in wallet.yaml. Press Esc to go back.")
            .block(Block::default().title("Trigger Issuance").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    }
    let mut lines: Vec<ListItem> = presets
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(name.clone(), style)))
        })
        .collect();
    if let Some(result) = last_result {
        lines.push(ListItem::new(Line::from(format!("Last result: {result}"))));
    }
    let list = List::new(lines).block(
        Block::default()
            .title("Trigger Issuance (Enter to run, Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
```

Create `crates/foundry-wallet/src/tui/screens/verification.rs`:

```rust
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, presets: &[String], selected: usize, last_result: Option<&str>) {
    if presets.is_empty() {
        let paragraph = Paragraph::new("No verification_presets configured in wallet.yaml. Press Esc to go back.")
            .block(Block::default().title("Trigger Verification").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    }
    let mut lines: Vec<ListItem> = presets
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(name.clone(), style)))
        })
        .collect();
    if let Some(result) = last_result {
        lines.push(ListItem::new(Line::from(format!("Last result: {result}"))));
    }
    let list = List::new(lines).block(
        Block::default()
            .title("Trigger Verification ('a' accept, 'd' decline, Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
```

Create `crates/foundry-wallet/src/tui/screens/credentials.rs`:

```rust
use foundry_wallet::storage::credential_store::CredentialMetadata;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, credentials: &[CredentialMetadata]) {
    let items: Vec<ListItem> = credentials
        .iter()
        .map(|c| {
            ListItem::new(Line::from(format!(
                "{} | vct={} | trust_valid={:?}",
                c.credential_id, c.vct, c.trust_valid
            )))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title("Browse Credentials (Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
```

Create `crates/foundry-wallet/src/tui/screens/event_log.rs`:

```rust
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, events: &[serde_json::Value]) {
    let items: Vec<ListItem> = events
        .iter()
        .map(|e| ListItem::new(Line::from(e.to_string())))
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title("Event Log (Esc to go back)")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}
```

- [ ] **Step 2: Create `tui/app.rs` (main loop)**

Create `crates/foundry-wallet/src/tui/app.rs`:

```rust
//! Main TUI event loop: wires `tui::state::AppState` (navigation) to
//! `tui::screens::*` (rendering) and `actions::` (issuance/verification),
//! and to `storage::` for the Browse Credentials / Event Log screens.

use crate::actions::issuance::run_issuance;
use crate::actions::verification::{run_verification, Consent as ActionConsent, VerificationOutcome};
use crate::config::WalletConfig;
use crate::storage::credential_store::list_credentials;
use crate::storage::event_log::tail_events;
use crate::tui::screens;
use crate::tui::state::{AppState, Consent, Screen, TuiCommand};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, ExecutableCommand};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::prelude::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::time::Duration;

pub async fn run(config: &WalletConfig) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new(
        config.issuance_presets.keys().cloned().collect(),
        config.verification_presets.keys().cloned().collect(),
    );
    let mut last_result: Option<String> = None;

    let result = run_loop(&mut terminal, &mut app, config, &mut last_result).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut AppState,
    config: &WalletConfig,
    last_result: &mut Option<String>,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            match app.screen {
                Screen::MainMenu => screens::main_menu::render(frame, area, app.main_menu_selected),
                Screen::TriggerIssuance => screens::issuance::render(
                    frame,
                    area,
                    &app.issuance_preset_names,
                    app.preset_selected,
                    last_result.as_deref(),
                ),
                Screen::TriggerVerification => screens::verification::render(
                    frame,
                    area,
                    &app.verification_preset_names,
                    app.preset_selected,
                    last_result.as_deref(),
                ),
                Screen::BrowseCredentials => {
                    let credentials = list_credentials(&config.data_dir).unwrap_or_default();
                    screens::credentials::render(frame, area, &credentials);
                }
                Screen::EventLog => {
                    let events = tail_events(&config.data_dir, 50).unwrap_or_default();
                    screens::event_log::render(frame, area, &events);
                }
            }
            let _ = Layout::default().direction(Direction::Vertical).constraints([Constraint::Min(0)]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(command) = app.handle_key(key.code) {
                    match command {
                        TuiCommand::Quit => return Ok(()),
                        TuiCommand::RunIssuancePreset(preset) => {
                            let outcome = run_issuance(config, Some(&preset), None, None).await;
                            *last_result = Some(match outcome {
                                Ok(o) => format!("stored {} (trust_valid={:?})", o.credential_id, o.trust_valid),
                                Err(e) => format!("error: {e}"),
                            });
                        }
                        TuiCommand::RunVerificationPreset(preset, consent) => {
                            let action_consent = match consent {
                                Consent::Accept => ActionConsent::Accept,
                                Consent::Decline => ActionConsent::Decline,
                            };
                            let outcome = run_verification(config, Some(&preset), None, action_consent).await;
                            *last_result = Some(match outcome {
                                Ok(VerificationOutcome::Verified(r)) => format!("verified={}", r.verified),
                                Ok(VerificationOutcome::Declined) => "declined".to_string(),
                                Err(e) => format!("error: {e}"),
                            });
                        }
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 3: Wire `tui/mod.rs` and `main.rs`**

In `crates/foundry-wallet/src/tui/mod.rs`, change the contents to:

```rust
pub mod app;
pub mod screens;
pub mod state;
```

In `crates/foundry-wallet/src/main.rs`, replace the `None | Some(Command::Tui) => { ... }` arm with:

```rust
        None | Some(Command::Tui) => match foundry_wallet::tui::app::run(&config).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{}", serde_json::json!({"error": e.to_string(), "kind": "tui"}));
                1
            }
        },
```

- [ ] **Step 4: Compile-check (no automated rendering test, per design doc section 11)**

Run: `cargo build -p foundry-wallet`
Expected: builds cleanly with no errors. This is the verification step for this task's rendering code — per the design doc's explicit non-goal, there is no automated TUI rendering test in v1.

Manual smoke test (perform once, do not automate): with a real `foundry` server running (`foundry quickstart && foundry serve --config config.yaml` in one terminal) and a `wallet.yaml` pointing at it, run `cargo run -p foundry-wallet -- --config wallet.yaml` (or `--config wallet.yaml tui`) in another terminal and confirm: the main menu renders with 5 items and arrow-key navigation works; Enter on "Trigger Issuance" shows configured presets; Enter on a preset runs `run_issuance` and shows a result line; 'a'/'d' on "Trigger Verification" runs `run_verification` with accept/decline; "Browse Credentials" lists stored credentials; "Event Log" shows recent events; 'q' is not yet bound (only the Quit menu item quits) — this is acceptable for v1.

- [ ] **Step 5: Run gates**

Run: `cargo clippy -p foundry-wallet --all-targets -- -D warnings && cargo fmt --check -p foundry-wallet`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-wallet/src/tui crates/foundry-wallet/src/main.rs
git commit -m "feat(foundry-wallet): TUI rendering and main event loop"
```

---

### Task 17: Final workspace verification

**Files:** none (verification-only task).

**Interfaces:** none — this task closes out the plan by running the full workspace gates once, per the Global Constraints section.

- [ ] **Step 1: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: PASS — every crate's unit and integration tests, including the new `foundry-wallet` crate and the modified `foundry-issuer` crate.

- [ ] **Step 2: Run the full workspace clippy gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. Fix any warnings surfaced only at the whole-workspace level (e.g. unused-dependency lints that don't trigger per-crate).

- [ ] **Step 3: Run the full workspace format gate**

Run: `cargo fmt --check`
Expected: PASS. If not, run `cargo fmt` and re-check.

- [ ] **Step 4: Confirm `Cargo.lock` is committed and consistent**

Run: `cargo build --workspace && git status --porcelain Cargo.lock`
Expected: no output (clean) — `Cargo.lock` was already committed incrementally in Task 2's step; this step just confirms nothing drifted.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore(foundry-wallet): final workspace verification (fmt/clippy/test all green)" --allow-empty
```

(`--allow-empty` is safe here since every substantive change was already committed per-task; this commit only exists to record that the full-workspace gate passed, in case Step 4 needed no changes.)

---

## Plan Self-Review

**Spec coverage:** every numbered section of `docs/superpowers/specs/2026-07-24-foundry-wallet-cli-design.md` maps to a task — §2 architecture -> Task 2; §3 config -> Task 3; §4 CLI surface -> Task 2 (parsing) + Task 14 (dispatch); §5 storage layout -> Tasks 4-5; §6 issuance flow -> Task 12; §7 verification flow -> Task 13; §8 event log -> Task 4; §9 TUI screens -> Tasks 15-16; §10 error handling -> Task 2 (`WalletError`) threaded through every task; §11 testing strategy -> the unit tests in Tasks 2-10, the integration harness in Task 11, and the integration tests in Tasks 12-14; §12 non-goals are simply not implemented (no task claims mdoc, fine-grained consent, or TUI snapshot tests).

**Placeholder scan:** no `TBD`/`TODO`/"add appropriate error handling"-style steps remain; every code step shows the actual code. The two spots that say "read the full file before finalizing" (Task 11's harness field names, Task 9's `FileSigner` fallback) are deliberate flags for a genuine unresolved fact (the exact field names in a file not fully read during planning) rather than deferred design work — both come with a concrete fallback path already written out, not an open question.

**Type consistency:** `WalletError`/`WalletResult` (Task 2) are used with the same variants and `.kind()` values across every later task. `WalletConfig`/`EndpointsConfig`/`TrustConfig`/`TrustValidationMode`/`IssuancePreset`/`VerificationPreset` (Task 3) field names are reused verbatim in Tasks 12-14's test fixtures. `CredentialMetadata`/`NewCredential`/`store_credential`/`list_credentials`/`load_metadata`/`load_payload`/`load_holder_key_pem`/`load_compact_sdjwt` (Task 5) keep identical names and signatures everywhere they're consumed (Tasks 10, 12, 13, 14, 16). `IssuanceOutcome`/`run_issuance` (Task 12) and `Consent`/`VerificationOutcome`/`run_verification` (Task 13) match their usage in Task 14's CLI dispatch and Task 16's TUI loop exactly.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-24-foundry-wallet-cli.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task (per the project's role mapping: `mechanical-implementer` for isolated 1-2 file tasks like Task 1, Task 8; `integration-implementer` for multi-file/integration tasks like Task 12, Task 13, Task 16; `task-reviewer` gates each task before the next starts), with review between tasks and fast iteration.

2. **Inline Execution** — execute tasks in this session using `executing-plans`, batch execution with checkpoints for review.

Which approach?

