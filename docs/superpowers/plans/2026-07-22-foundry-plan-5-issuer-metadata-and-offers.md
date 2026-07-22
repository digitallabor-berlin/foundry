# OpenID4VCI Issuer Metadata & Admin Offer Creation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a new `foundry-issuer` crate that builds OpenID4VCI Credential Issuer Metadata and OAuth Authorization Server Metadata from `Config`, hosts them at the wallet-facing well-known endpoints, and exposes an admin API (`POST /admin/issuance/offers`) that validates claims, allocates a status-list index, generates a pre-authorized code + optional `tx_code`, persists an issuance transaction, and returns a `credential_offer`/`credential_offer_uri`. This phase delivers the **issuance offer lifecycle up to the point a wallet receives an offer** — the token/nonce/credential endpoints that actually issue a signed credential are an explicit follow-up (a separate plan).

**Architecture:** `foundry-issuer` is a new, framework-agnostic workspace crate (no `axum` dependency) containing pure business logic: metadata builders, the `IssuanceTransaction` model with `Storage`-backed persistence, a CSPRNG-based status-list index allocator, pre-authorized-code/tx_code generation, and the `create_offer` orchestration function. The `foundry` (bin) crate owns all HTTP wiring: a new `wallet_router` serving the two well-known metadata endpoints, a new bearer-token admin-auth middleware (finally wiring up the long-unused `AdminConfig.api_key`/`api_key_env` fields), and a new authenticated `POST /admin/issuance/offers` route that calls into `foundry-issuer`. Both routers are served concurrently on their configured listeners (`server.admin.bind`, `server.wallet_facing.bind`) via `tokio::try_join!`.

**Documented divergence from the spec's crate-dependency diagram:** the spec's architecture diagram draws `foundry-issuer ─▶ ... oid4vci`. This plan deliberately does **not** depend on the vendored `oid4vci` crate. Its `CredentialIssuerMetadata`/`CredentialOffer` types are generic over a `CredentialFormatMetadata` trait using `ssi::jwk::JWK` and tag SD-JWT credentials as `"vc+sd-jwt"` — both mismatched with Foundry's needs (Foundry uses `josekit` everywhere else, per plan 3's crypto stack, and targets draft-17's `"dc+sd-jwt"` per the spec's own versioning decision in §1). Fighting those two mismatches (a generic-parameter bridge plus a JWK-library adapter) would cost more than hand-rolling plain `serde`-derived structs for exactly the wire shapes this plan needs. This is an intentional, documented decision (same category as the SD-JWT draft-17-vs-draft-13 divergence already recorded in the spec) — revisit if/when `foundry-issuer` needs the oid4vci crate's client-flow helpers.

**Scope of this divergence — not a rejection of the vendored crates.** This decision is narrowly scoped to two `oid4vci` types (`CredentialIssuerMetadata`, `CredentialOffer`) whose serialization shape mismatches Foundry's stack. It is not a decision to stop using `oid4vci`, and it says nothing about `openid4vp`:
- `oid4vci` is expected to be reused in the **next** plan (credential/token/nonce endpoints) for its `JwtProofVerifier`/`VerifiedProof` (generic JWS key-binding proof verification, format-agnostic — no metadata mismatch applies) and its `client` module, which the spec's own testing strategy (§7, "in-process wallet stub") calls for building an issuance-flow test harness on top of rather than hand-rolling a second OAuth2 client.
- `openid4vp` is a different case: unlike `oid4vci`'s data-only metadata module, it already ships real server-side orchestration (DCQL query matching, a `Verifier` with `request_builder`/`request_signer`/`session`, JWE encrypt/decrypt). The forthcoming `foundry-verifier` plan is expected to build directly on it rather than hand-roll, since reimplementing DCQL matching from scratch would be wasteful and risk correctness bugs a maintained implementation already avoids.
- Both crates are vendored (not external crates.io dependencies) specifically so Foundry can patch them directly per the spec's goal (§2, "Full control over the protocol implementation") — that ownership value holds independent of how much of a given vendored crate any one plan ends up using.

**Tech Stack:** Rust 1.97, edition 2021, `serde`/`serde_json` (wire types), `thiserror` (errors), `rand` 0.8 (CSPRNG, same idiom as `foundry-sd-jwt-vc`), `base64` 0.22 (opaque token/id encoding), `percent-encoding` 2 (new dependency, `credential_offer_uri` construction), `axum` 0.7 (HTTP wiring in `foundry` bin only).

## Prerequisites (verified present)

Plans 1–4 are merged. This plan builds directly on these existing, working APIs (verified against the tree):

- `foundry_core::config::{Config, AdminConfig, CredentialType, ClaimDef, IssuerConfig, StatusListConfig}` — `Config { server, storage, keys, trust_anchors, issuer, credential_types: Vec<CredentialType>, verifier }`; `CredentialType { id: String, format: String, vct: Option<String>, doctype: Option<String>, cryptographic_holder_binding: bool, display: Vec<serde_json::Value>, claims: Vec<ClaimDef> }`; `ClaimDef { path: Vec<String>, selectively_disclosable: bool, display: Vec<serde_json::Value> }`; `IssuerConfig { credential_issuer: String, wallet_attestation, key_attestation, status_list: StatusListConfig }`; `StatusListConfig { enabled: bool, signing_key: Option<String>, list_size: Option<u64>, public_base_url: Option<String> }`; `AdminConfig { bind: String, api_key: Option<String>, api_key_env: Option<String>, swagger_ui_enabled: bool }`. `Config` derives `Debug, Clone, Deserialize`.
- `foundry_core::storage::{Storage, SqliteStorage}` — `trait Storage: Send + Sync { async fn put_kv(&self, namespace: &str, key: &str, value: &str, expires_at: Option<i64>) -> Result<(), StorageError>; async fn get_kv(&self, namespace: &str, key: &str) -> Result<Option<String>, StorageError>; async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError>; async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError>; }`. `SqliteStorage::connect(path: &str) -> Result<SqliteStorage, StorageError>`.
- `foundry_core::error::StorageError` — `#[derive(Debug, Error)] pub enum StorageError { Backend(String), NotFound(String) }`.
- `crates/foundry/src/server.rs` (current, verified): `AppState { pub storage: Arc<dyn Storage> }`; `admin_router(state: AppState) -> Router` with `/health`, `/ready`; `spawn_sweeper(...)`; `serve(cfg: Config) -> anyhow::Result<()>` (single admin listener only, today).
- `crates/foundry/tests/health.rs` (current, verified) constructs `AppState { storage }` directly and calls `admin_router(AppState { storage })` — **this plan changes `AppState`'s shape, so this file must be updated** (Task 8 below shows the exact diff).
- Pattern reference: `crates/foundry-sd-jwt-vc/src/builder.rs`'s `generate_salt()` (`rand::rngs::ThreadRng::default().fill_bytes(&mut bytes)` + `base64::engine::general_purpose::URL_SAFE_NO_PAD`) is the established CSPRNG idiom this plan reuses verbatim for opaque tokens/ids.

## Global Constraints

- Language / runtime: Rust (edition 2021), tokio async runtime. Toolchain pinned at 1.97.
- Crate structure: this plan adds one new crate, `crates/foundry-issuer`, depending **only** on `foundry-core` (no `axum`, no `oid4vci` — see the documented divergence above). HTTP wiring lives entirely in `crates/foundry` (the bin crate), which gains a new `admin_auth` module and additions to `server.rs`.
- Errors: typed via `thiserror` — a new `IssuanceError` enum in `foundry-issuer`, wrapping `foundry_core::error::StorageError` via `#[from]`. **No `unwrap`/`panic`/`expect` in non-test code paths.**
- Randomness: all opaque tokens/ids/tx_codes use a CSPRNG (`rand::rngs::ThreadRng` via `RngCore`), matching the existing `foundry-sd-jwt-vc` idiom. **No entropy harvesting or zero-fallback values.**
- Status-list index allocation: CSPRNG draw + storage check-and-set (get-then-put on a dedicated KV namespace), bounded retries. This is **not** atomic (a documented `TODO(concurrency)`, consistent with the trust module's existing `TODO(trust-hardening)` pattern) — acceptable for this phase's single-process dev deployment; a later phase should add an atomic compare-and-swap primitive to `Storage` if needed.
- Admin API error responses: structured JSON `{ "error": <display>, "message": <display> }` (per spec §7 "Admin API: structured JSON `{ error, message, detail? }`" — `detail` is omitted in this phase, a straightforward future addition).
- Admin auth: bearer-token check against `AdminConfig.api_key` (literal) or `AdminConfig.api_key_env` (resolved from the process environment at `serve()` startup) via a small middleware; **if neither is configured, auth is a no-op (dev mode)** — this must be clearly logged/documented, never silently assumed secure.
- Every code change lands via TDD: failing test first (capture the genuine RED transcript), then minimal implementation, then commit.
- Commit only the files a task declares. Never `git add -A`.

## Non-Goals (this phase)

- **Token/nonce/credential endpoints.** Issuing an actual signed credential (SD-JWT VC or mdoc) in response to a wallet's token request is the next plan. This phase only gets an offer into a wallet's hands.
- **Nested claim path validation.** `ClaimDef.path` supports nested paths (e.g. `["address", "street"]`); this phase validates only the **top-level** path segment's presence in the admin request's claims for non-selectively-disclosable claims. Deep nested validation is a follow-up.
- **Status-list index release/reuse.** Allocated indices are never released back to the pool (no expiry on the "used" marker) — an issued credential's status entry must outlive the issuance transaction's own TTL, and index-reuse policy is a distinct design question left for later.
- **OpenAPI/Swagger UI generation** (`utoipa`) for the admin API — not yet a dependency anywhere in the workspace; deferred.
- **Signed issuer metadata** (`signed_metadata` JWS variant) — this phase serves plain JSON only.

---

## File Structure

**Workspace (modified):**
- `Cargo.toml` (root) — MODIFY: add `crates/foundry-issuer` to members; add `percent-encoding = "2"` to `[workspace.dependencies]`.

**foundry-issuer (new crate):**
- `crates/foundry-issuer/Cargo.toml`
- `crates/foundry-issuer/src/lib.rs`
- `crates/foundry-issuer/src/error.rs`
- `crates/foundry-issuer/src/metadata.rs`
- `crates/foundry-issuer/src/transaction.rs`
- `crates/foundry-issuer/src/status_index.rs`
- `crates/foundry-issuer/src/offer.rs`
- `crates/foundry-issuer/src/create_offer.rs`

**foundry (bin, modified):**
- `crates/foundry/Cargo.toml` — MODIFY: add `foundry-issuer` path dependency.
- `crates/foundry/src/lib.rs` — MODIFY: register `pub mod admin_auth;`.
- `crates/foundry/src/admin_auth.rs` — new.
- `crates/foundry/src/server.rs` — MODIFY: `AppState` gains `config: Arc<Config>`; new `wallet_router`; new authenticated admin route; dual-listener `serve()`.
- `crates/foundry/tests/health.rs` — MODIFY: update `AppState` construction.
- `crates/foundry/tests/issuer_offers.rs` — new integration test.
- `crates/foundry/tests/wallet_metadata.rs` — new integration test.

---

### Task 1: `foundry-issuer` crate skeleton, error taxonomy, workspace wiring

**Files:**
- Modify: `Cargo.toml` (root)
- Create: `crates/foundry-issuer/Cargo.toml`
- Create: `crates/foundry-issuer/src/lib.rs`
- Create: `crates/foundry-issuer/src/error.rs`

**Interfaces:**
- Produces: `foundry_issuer::error::IssuanceError` with variants `UnknownCredentialType(String)`, `ClaimValidation(String)`, `StatusListExhausted(String)`, `Storage(#[from] foundry_core::error::StorageError)`, `Serialization(String)`, `Deserialization(String)`.

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-issuer/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("unknown credential_type_id '{0}'")]
    UnknownCredentialType(String),
    #[error("claim validation failed: {0}")]
    ClaimValidation(String),
    #[error("status list exhausted for credential_type '{0}'")]
    StatusListExhausted(String),
    #[error(transparent)]
    Storage(#[from] foundry_core::error::StorageError),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_credential_type_displays_the_id() {
        let e = IssuanceError::UnknownCredentialType("pid".to_string());
        assert_eq!(e.to_string(), "unknown credential_type_id 'pid'");
    }

    #[test]
    fn storage_error_wraps_transparently() {
        let e: IssuanceError = foundry_core::error::StorageError::NotFound("tx-1".into()).into();
        assert_eq!(e.to_string(), "record not found: tx-1");
    }
}
```

Create `crates/foundry-issuer/src/lib.rs`:

```rust
pub mod error;

pub use error::IssuanceError;
```

Create `crates/foundry-issuer/Cargo.toml`:

```toml
[package]
name = "foundry-issuer"
version = "0.1.0"
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
foundry-core = { path = "../foundry-core" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
rand = { workspace = true }
base64 = { workspace = true }
percent-encoding = { workspace = true }

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3"
```

Add `crates/foundry-issuer` to the root `Cargo.toml`'s `[workspace] members` list (after `"crates/foundry-mdoc",`):

```toml
    "crates/foundry-mdoc",
    "crates/foundry-issuer",
```

Add `percent-encoding = "2"` to the root `Cargo.toml`'s `[workspace.dependencies]` (after the `hex = "0.4"` line):

```toml
percent-encoding = "2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer error::tests -- --nocapture`
Expected: FAIL to compile (crate doesn't exist yet) — since this task creates the crate in one shot, instead confirm it **passes** once all files above are in place:

Run: `cargo test -p foundry-issuer error::tests -- --nocapture`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml crates/foundry-issuer/Cargo.toml crates/foundry-issuer/src/lib.rs crates/foundry-issuer/src/error.rs
git commit -m "feat(issuer): add foundry-issuer crate skeleton with IssuanceError taxonomy"
```

---

### Task 2: Metadata types & builders (Credential Issuer Metadata + Authorization Server Metadata)

**Files:**
- Create: `crates/foundry-issuer/src/metadata.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`

**Interfaces:**
- Consumes: `foundry_core::config::Config`.
- Produces:
  ```rust
  pub struct CredentialIssuerMetadata { pub credential_issuer: String, pub authorization_servers: Vec<String>, pub credential_endpoint: String, pub nonce_endpoint: Option<String>, pub display: Vec<serde_json::Value>, pub credential_configurations_supported: std::collections::BTreeMap<String, CredentialConfigurationSupported> }
  pub struct CredentialConfigurationSupported { pub format: String, pub vct: Option<String>, pub doctype: Option<String>, pub cryptographic_binding_methods_supported: Vec<String>, pub credential_signing_alg_values_supported: Vec<String>, pub proof_types_supported: std::collections::BTreeMap<String, ProofTypeSupported>, pub display: Vec<serde_json::Value>, pub claims: Vec<serde_json::Value> }
  pub struct ProofTypeSupported { pub proof_signing_alg_values_supported: Vec<String> }
  pub struct AuthorizationServerMetadata { pub issuer: String, pub token_endpoint: String, pub nonce_endpoint: Option<String>, pub grant_types_supported: Vec<String>, pub pre_authorized_grant_anonymous_access_supported: bool }
  pub fn build_issuer_metadata(cfg: &Config) -> CredentialIssuerMetadata;
  pub fn build_authorization_server_metadata(cfg: &Config) -> AuthorizationServerMetadata;
  ```

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-issuer/src/metadata.rs`:

```rust
//! OpenID4VCI Credential Issuer Metadata and OAuth Authorization Server
//! Metadata, hand-rolled (see plan header for the documented divergence
//! from the vendored `oid4vci` crate's generic types).

use foundry_core::config::Config;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<serde_json::Value>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfigurationSupported>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialConfigurationSupported {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    pub cryptographic_binding_methods_supported: Vec<String>,
    pub credential_signing_alg_values_supported: Vec<String>,
    pub proof_types_supported: BTreeMap<String, ProofTypeSupported>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    pub grant_types_supported: Vec<String>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

/// Build the Credential Issuer Metadata document, fully derived from
/// `cfg.credential_types` and `cfg.issuer` — nothing hard-coded per credential type.
pub fn build_issuer_metadata(cfg: &Config) -> CredentialIssuerMetadata {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    let mut configs = BTreeMap::new();
    for ct in &cfg.credential_types {
        let cryptographic_binding_methods_supported = if ct.cryptographic_holder_binding {
            vec!["jwk".to_string()]
        } else {
            Vec::new()
        };
        let claims: Vec<serde_json::Value> = ct
            .claims
            .iter()
            .map(|c| {
                serde_json::json!({
                    "path": c.path,
                    "selectively_disclosable": c.selectively_disclosable,
                    "display": c.display,
                })
            })
            .collect();
        configs.insert(
            ct.id.clone(),
            CredentialConfigurationSupported {
                format: ct.format.clone(),
                vct: ct.vct.clone(),
                doctype: ct.doctype.clone(),
                cryptographic_binding_methods_supported,
                credential_signing_alg_values_supported: vec!["ES256".to_string()],
                proof_types_supported: BTreeMap::from([(
                    "jwt".to_string(),
                    ProofTypeSupported {
                        proof_signing_alg_values_supported: vec!["ES256".to_string()],
                    },
                )]),
                display: ct.display.clone(),
                claims,
            },
        );
    }
    CredentialIssuerMetadata {
        credential_issuer: base.to_string(),
        authorization_servers: Vec::new(),
        credential_endpoint: format!("{base}/credential"),
        nonce_endpoint: Some(format!("{base}/nonce")),
        display: Vec::new(),
        credential_configurations_supported: configs,
    }
}

/// Build the OAuth Authorization Server Metadata document.
pub fn build_authorization_server_metadata(cfg: &Config) -> AuthorizationServerMetadata {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    AuthorizationServerMetadata {
        issuer: base.to_string(),
        token_endpoint: format!("{base}/token"),
        nonce_endpoint: Some(format!("{base}/nonce")),
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        ],
        pre_authorized_grant_anonymous_access_supported: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, IssuerConfig, Mode, ServerConfig,
        StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
    };
    use std::collections::BTreeMap as StdBTreeMap;

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "./foundry.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: StdBTreeMap::new(),
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: AttestationMode { mode: Mode::Optional },
                key_attestation: AttestationMode { mode: Mode::Optional },
                status_list: StatusListConfig {
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                cryptographic_holder_binding: true,
                display: vec![serde_json::json!({"name": "Person ID", "locale": "en-US"})],
                claims: vec![ClaimDef {
                    path: vec!["given_name".to_string()],
                    selectively_disclosable: true,
                    display: vec![],
                }],
            }],
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
                signing_key: "verifier_signing".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec!["sha-256".to_string()],
                named_queries: vec![],
                webhook: None,
            },
        }
    }

    #[test]
    fn builds_issuer_metadata_from_credential_types() {
        let cfg = test_config();
        let meta = build_issuer_metadata(&cfg);
        assert_eq!(meta.credential_issuer, "https://issuer.example.com");
        assert_eq!(meta.credential_endpoint, "https://issuer.example.com/credential");
        assert_eq!(meta.nonce_endpoint.as_deref(), Some("https://issuer.example.com/nonce"));
        let pid = meta.credential_configurations_supported.get("pid").unwrap();
        assert_eq!(pid.format, "dc+sd-jwt");
        assert_eq!(pid.vct.as_deref(), Some("https://issuer.example.com/vct/pid"));
        assert_eq!(pid.cryptographic_binding_methods_supported, vec!["jwk".to_string()]);
        assert!(pid.proof_types_supported.contains_key("jwt"));
    }

    #[test]
    fn trims_trailing_slash_from_credential_issuer() {
        let mut cfg = test_config();
        cfg.issuer.credential_issuer = "https://issuer.example.com/".to_string();
        let meta = build_issuer_metadata(&cfg);
        assert_eq!(meta.credential_endpoint, "https://issuer.example.com/credential");
    }

    #[test]
    fn builds_authorization_server_metadata() {
        let cfg = test_config();
        let meta = build_authorization_server_metadata(&cfg);
        assert_eq!(meta.issuer, "https://issuer.example.com");
        assert_eq!(meta.token_endpoint, "https://issuer.example.com/token");
        assert!(meta.pre_authorized_grant_anonymous_access_supported);
        assert_eq!(
            meta.grant_types_supported,
            vec!["urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string()]
        );
    }
}
```

Add to `crates/foundry-issuer/src/lib.rs`:

```rust
pub mod metadata;

pub use metadata::{
    build_authorization_server_metadata, build_issuer_metadata, AuthorizationServerMetadata,
    CredentialConfigurationSupported, CredentialIssuerMetadata, ProofTypeSupported,
};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer metadata::tests -- --nocapture`
Expected: FAIL — `metadata` module/functions not yet defined (before adding the module registration and implementation).

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry-issuer metadata::tests -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-issuer/src/metadata.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): add issuer metadata and authorization server metadata builders"
```

---

### Task 3: `IssuanceTransaction` model + storage persistence

**Files:**
- Create: `crates/foundry-issuer/src/transaction.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`

**Interfaces:**
- Consumes: `foundry_core::storage::Storage`, `IssuanceError`.
- Produces:
  ```rust
  pub struct IssuanceTransaction { pub transaction_id: String, pub credential_type_id: String, pub claims: serde_json::Map<String, serde_json::Value>, pub pre_authorized_code: String, pub tx_code: Option<String>, pub status_list_index: Option<u64>, pub state: IssuanceState, pub created_at: i64 }
  pub enum IssuanceState { Offered, Issued }
  pub async fn save_transaction(storage: &dyn Storage, tx: &IssuanceTransaction, ttl_secs: u64, now_unix: i64) -> Result<(), IssuanceError>;
  pub async fn load_transaction(storage: &dyn Storage, transaction_id: &str) -> Result<Option<IssuanceTransaction>, IssuanceError>;
  ```

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-issuer/src/transaction.rs`:

```rust
//! Issuance transaction model and `Storage`-backed persistence.

use crate::error::IssuanceError;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

const NAMESPACE: &str = "issuance_tx";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuanceTransaction {
    pub transaction_id: String,
    pub credential_type_id: String,
    pub claims: serde_json::Map<String, serde_json::Value>,
    pub pre_authorized_code: String,
    pub tx_code: Option<String>,
    pub status_list_index: Option<u64>,
    pub state: IssuanceState,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    Offered,
    Issued,
}

/// Persist a transaction with a TTL relative to `now_unix`.
pub async fn save_transaction(
    storage: &dyn Storage,
    tx: &IssuanceTransaction,
    ttl_secs: u64,
    now_unix: i64,
) -> Result<(), IssuanceError> {
    let value =
        serde_json::to_string(tx).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let expires_at = now_unix + ttl_secs as i64;
    storage
        .put_kv(NAMESPACE, &tx.transaction_id, &value, Some(expires_at))
        .await?;
    Ok(())
}

/// Load a transaction by id, if present and not yet expired/purged.
pub async fn load_transaction(
    storage: &dyn Storage,
    transaction_id: &str,
) -> Result<Option<IssuanceTransaction>, IssuanceError> {
    let raw = storage.get_kv(NAMESPACE, transaction_id).await?;
    match raw {
        Some(s) => {
            let tx = serde_json::from_str(&s)
                .map_err(|e| IssuanceError::Deserialization(e.to_string()))?;
            Ok(Some(tx))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        // Leak the tempdir so the file isn't removed before the async test body runs.
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    fn sample_tx(id: &str) -> IssuanceTransaction {
        let mut claims = serde_json::Map::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        IssuanceTransaction {
            transaction_id: id.to_string(),
            credential_type_id: "pid".to_string(),
            claims,
            pre_authorized_code: "code-123".to_string(),
            tx_code: Some("4242".to_string()),
            status_list_index: Some(7),
            state: IssuanceState::Offered,
            created_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn save_and_load_round_trips() {
        let storage = test_storage().await;
        let tx = sample_tx("tx-1");
        save_transaction(&storage, &tx, 600, 1_700_000_000).await.unwrap();
        let loaded = load_transaction(&storage, "tx-1").await.unwrap().unwrap();
        assert_eq!(loaded, tx);
    }

    #[tokio::test]
    async fn load_missing_transaction_returns_none() {
        let storage = test_storage().await;
        let loaded = load_transaction(&storage, "does-not-exist").await.unwrap();
        assert!(loaded.is_none());
    }
}
```

Add to `crates/foundry-issuer/src/lib.rs`:

```rust
pub mod transaction;

pub use transaction::{load_transaction, save_transaction, IssuanceState, IssuanceTransaction};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer transaction::tests -- --nocapture`
Expected: FAIL — module not yet registered/implemented.

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry-issuer transaction::tests -- --nocapture`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-issuer/src/transaction.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): add IssuanceTransaction model with storage persistence"
```

---

### Task 4: Status-list index allocator

**Files:**
- Create: `crates/foundry-issuer/src/status_index.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`

**Interfaces:**
- Consumes: `foundry_core::storage::Storage`, `IssuanceError`.
- Produces:
  ```rust
  pub async fn allocate_status_index(storage: &dyn Storage, credential_type_id: &str, list_size: u64) -> Result<u64, IssuanceError>;
  ```

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-issuer/src/status_index.rs`:

```rust
//! CSPRNG-based, storage check-and-set status-list index allocation.
//!
//! TODO(concurrency): the get-then-put pair below is not atomic; concurrent
//! allocators racing on the same index could both succeed. Acceptable for
//! this phase's single-process dev deployment (consistent with
//! `foundry_core::trust`'s existing `TODO(trust-hardening)` pattern); a
//! later phase should add an atomic compare-and-swap primitive to `Storage`.

use crate::error::IssuanceError;
use foundry_core::storage::Storage;
use rand::RngCore;

const USED_NAMESPACE: &str = "status_index_used";
const MAX_ATTEMPTS: u32 = 20;

/// Allocate a unique, unpredictable index in `[0, list_size)` for
/// `credential_type_id`, via CSPRNG draw + storage check-and-set. The
/// allocated index is never released (no expiry on the "used" marker) —
/// index release/reuse policy is out of scope for this phase.
pub async fn allocate_status_index(
    storage: &dyn Storage,
    credential_type_id: &str,
    list_size: u64,
) -> Result<u64, IssuanceError> {
    if list_size == 0 {
        return Err(IssuanceError::StatusListExhausted(
            credential_type_id.to_string(),
        ));
    }
    let mut rng = rand::rngs::ThreadRng::default();
    for _ in 0..MAX_ATTEMPTS {
        let idx = rng.next_u64() % list_size;
        let key = format!("{credential_type_id}:{idx}");
        let existing = storage.get_kv(USED_NAMESPACE, &key).await?;
        if existing.is_none() {
            storage.put_kv(USED_NAMESPACE, &key, "1", None).await?;
            return Ok(idx);
        }
    }
    Err(IssuanceError::StatusListExhausted(
        credential_type_id.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn allocates_index_within_range() {
        let storage = test_storage().await;
        let idx = allocate_status_index(&storage, "pid", 1024).await.unwrap();
        assert!(idx < 1024);
    }

    #[tokio::test]
    async fn never_allocates_the_same_index_twice_for_a_tiny_list() {
        let storage = test_storage().await;
        // list_size=1 forces every draw to land on index 0; the second
        // allocation must exhaust its retries and fail distinctly.
        let first = allocate_status_index(&storage, "pid", 1).await.unwrap();
        assert_eq!(first, 0);
        let err = allocate_status_index(&storage, "pid", 1).await.unwrap_err();
        assert!(matches!(err, IssuanceError::StatusListExhausted(_)));
    }

    #[tokio::test]
    async fn rejects_zero_list_size() {
        let storage = test_storage().await;
        let err = allocate_status_index(&storage, "pid", 0).await.unwrap_err();
        assert!(matches!(err, IssuanceError::StatusListExhausted(_)));
    }

    #[tokio::test]
    async fn different_credential_types_do_not_collide() {
        let storage = test_storage().await;
        // With list_size=1, both credential types independently get index 0 —
        // the namespace key includes credential_type_id, so no cross-type collision.
        let pid_idx = allocate_status_index(&storage, "pid", 1).await.unwrap();
        let mdl_idx = allocate_status_index(&storage, "mdl", 1).await.unwrap();
        assert_eq!(pid_idx, 0);
        assert_eq!(mdl_idx, 0);
    }
}
```

Add to `crates/foundry-issuer/src/lib.rs`:

```rust
pub mod status_index;

pub use status_index::allocate_status_index;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer status_index::tests -- --nocapture`
Expected: FAIL — module not yet registered/implemented.

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry-issuer status_index::tests -- --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-issuer/src/status_index.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): add CSPRNG status-list index allocator"
```

---

### Task 5: Pre-authorized code / tx_code generation + `CredentialOffer` builder

**Files:**
- Create: `crates/foundry-issuer/src/offer.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`

**Interfaces:**
- Consumes: `IssuanceError`.
- Produces:
  ```rust
  pub fn generate_pre_authorized_code() -> String;
  pub fn generate_tx_code(length: usize) -> String;
  pub struct CredentialOffer { pub credential_issuer: String, pub credential_configuration_ids: Vec<String>, pub grants: CredentialOfferGrants }
  pub struct CredentialOfferGrants { pub pre_authorized_code: PreAuthorizedCodeGrant }
  pub struct PreAuthorizedCodeGrant { pub pre_authorized_code: String, pub tx_code: Option<TxCodeDefinition> }
  pub struct TxCodeDefinition { pub input_mode: String, pub length: usize }
  pub fn build_offer_uri(offer: &CredentialOffer) -> Result<String, IssuanceError>;
  ```

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-issuer/src/offer.rs`:

```rust
//! Pre-authorized code / tx_code generation and `CredentialOffer` construction.

use crate::error::IssuanceError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::RngCore;
use serde::Serialize;

/// 32 bytes of CSPRNG entropy, URL-safe base64 (unpadded). Same idiom as
/// `foundry-sd-jwt-vc`'s `generate_salt`.
pub fn generate_pre_authorized_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::ThreadRng::default().fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

/// A numeric `tx_code` of `length` digits (HAIP default input_mode: numeric).
pub fn generate_tx_code(length: usize) -> String {
    let mut rng = rand::rngs::ThreadRng::default();
    (0..length)
        .map(|_| char::from(b'0' + (rng.next_u32() % 10) as u8))
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialOfferGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: PreAuthorizedCodeGrant,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCodeDefinition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxCodeDefinition {
    pub input_mode: String,
    pub length: usize,
}

/// Build a `credential_offer_uri` deep link (`openid-credential-offer://?credential_offer=...`)
/// with the offer JSON percent-encoded per RFC 3986.
pub fn build_offer_uri(offer: &CredentialOffer) -> Result<String, IssuanceError> {
    let json =
        serde_json::to_string(offer).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let encoded = utf8_percent_encode(&json, NON_ALPHANUMERIC).to_string();
    Ok(format!("openid-credential-offer://?credential_offer={encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_authorized_codes_are_random_and_nonempty() {
        let a = generate_pre_authorized_code();
        let b = generate_pre_authorized_code();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn tx_codes_have_the_requested_length_and_are_numeric() {
        let code = generate_tx_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn build_offer_uri_percent_encodes_and_uses_the_correct_scheme() {
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
        let uri = build_offer_uri(&offer).unwrap();
        assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
        // The raw JSON must not appear verbatim (braces/quotes are percent-encoded).
        assert!(!uri.contains('{'));
        assert!(!uri.contains('"'));
    }
}
```

Add to `crates/foundry-issuer/src/lib.rs`:

```rust
pub mod offer;

pub use offer::{
    build_offer_uri, generate_pre_authorized_code, generate_tx_code, CredentialOffer,
    CredentialOfferGrants, PreAuthorizedCodeGrant, TxCodeDefinition,
};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer offer::tests -- --nocapture`
Expected: FAIL — module not yet registered/implemented.

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry-issuer offer::tests -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-issuer/src/offer.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): add pre-authorized code/tx_code generation and CredentialOffer builder"
```

---

### Task 6: `create_offer` orchestration

**Files:**
- Create: `crates/foundry-issuer/src/create_offer.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`

**Interfaces:**
- Consumes: `foundry_core::config::Config`, `foundry_core::storage::Storage`, `save_transaction`, `allocate_status_index`, `generate_pre_authorized_code`, `generate_tx_code`, `build_offer_uri`, `CredentialOffer`/`CredentialOfferGrants`/`PreAuthorizedCodeGrant`/`TxCodeDefinition`, `IssuanceTransaction`/`IssuanceState`, `IssuanceError`.
- Produces:
  ```rust
  pub struct CreateOfferRequest { pub credential_type_id: String, pub claims: serde_json::Map<String, serde_json::Value>, pub tx_code_required: bool }
  pub struct CreateOfferResponse { pub transaction_id: String, pub credential_offer: CredentialOffer, pub credential_offer_uri: String }
  pub async fn create_offer(cfg: &Config, storage: &dyn Storage, req: CreateOfferRequest, now_unix: i64) -> Result<CreateOfferResponse, IssuanceError>;
  ```

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-issuer/src/create_offer.rs`:

```rust
//! Orchestrates offer creation: claim validation, status-index allocation,
//! pre-auth code/tx_code generation, transaction persistence, and offer
//! construction.

use crate::error::IssuanceError;
use crate::offer::{
    build_offer_uri, generate_pre_authorized_code, generate_tx_code, CredentialOffer,
    CredentialOfferGrants, PreAuthorizedCodeGrant, TxCodeDefinition,
};
use crate::status_index::allocate_status_index;
use crate::transaction::{save_transaction, IssuanceState, IssuanceTransaction};
use foundry_core::config::Config;
use foundry_core::storage::Storage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOfferRequest {
    pub credential_type_id: String,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub tx_code_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateOfferResponse {
    pub transaction_id: String,
    pub credential_offer: CredentialOffer,
    pub credential_offer_uri: String,
}

/// Default tx_code length when `tx_code_required` is set (HAIP-typical 4 digits).
const DEFAULT_TX_CODE_LENGTH: usize = 4;

pub async fn create_offer(
    cfg: &Config,
    storage: &dyn Storage,
    req: CreateOfferRequest,
    now_unix: i64,
) -> Result<CreateOfferResponse, IssuanceError> {
    let ct = cfg
        .credential_types
        .iter()
        .find(|c| c.id == req.credential_type_id)
        .ok_or_else(|| IssuanceError::UnknownCredentialType(req.credential_type_id.clone()))?;

    // Every non-selectively-disclosable claim's top-level path segment must
    // be present (nested-path validation is a follow-up — see plan Non-Goals).
    for claim_def in &ct.claims {
        if claim_def.selectively_disclosable {
            continue;
        }
        let top = claim_def.path.first().ok_or_else(|| {
            IssuanceError::ClaimValidation(format!(
                "credential_type '{}' has a claim with an empty path",
                ct.id
            ))
        })?;
        if !req.claims.contains_key(top) {
            return Err(IssuanceError::ClaimValidation(format!(
                "missing required claim '{top}' for credential_type '{}'",
                ct.id
            )));
        }
    }

    let transaction_id = generate_pre_authorized_code();
    let pre_authorized_code = generate_pre_authorized_code();
    let tx_code = if req.tx_code_required {
        Some(generate_tx_code(DEFAULT_TX_CODE_LENGTH))
    } else {
        None
    };

    let status_list_index = if cfg.issuer.status_list.enabled {
        let list_size = cfg.issuer.status_list.list_size.unwrap_or(1_048_576);
        Some(allocate_status_index(storage, &ct.id, list_size).await?)
    } else {
        None
    };

    let tx = IssuanceTransaction {
        transaction_id: transaction_id.clone(),
        credential_type_id: ct.id.clone(),
        claims: req.claims,
        pre_authorized_code: pre_authorized_code.clone(),
        tx_code: tx_code.clone(),
        status_list_index,
        state: IssuanceState::Offered,
        created_at: now_unix,
    };
    save_transaction(storage, &tx, cfg.storage.transaction_ttl_secs, now_unix).await?;

    let offer = CredentialOffer {
        credential_issuer: cfg.issuer.credential_issuer.trim_end_matches('/').to_string(),
        credential_configuration_ids: vec![ct.id.clone()],
        grants: CredentialOfferGrants {
            pre_authorized_code: PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code: tx_code.map(|_| TxCodeDefinition {
                    input_mode: "numeric".to_string(),
                    length: DEFAULT_TX_CODE_LENGTH,
                }),
            },
        },
    };
    let credential_offer_uri = build_offer_uri(&offer)?;

    Ok(CreateOfferResponse {
        transaction_id,
        credential_offer: offer,
        credential_offer_uri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::load_transaction;
    use foundry_core::config::{
        AdminConfig, AttestationMode, ClaimDef, CredentialType, IssuerConfig, Mode, ServerConfig,
        StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
    };
    use foundry_core::storage::SqliteStorage;
    use std::collections::BTreeMap as StdBTreeMap;

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://issuer.example.com".to_string(),
                    bind: "0.0.0.0:8443".to_string(),
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:9000".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "./foundry.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: StdBTreeMap::new(),
            trust_anchors: Vec::new(),
            issuer: IssuerConfig {
                credential_issuer: "https://issuer.example.com".to_string(),
                wallet_attestation: AttestationMode { mode: Mode::Optional },
                key_attestation: AttestationMode { mode: Mode::Optional },
                status_list: StatusListConfig {
                    enabled: true,
                    signing_key: None,
                    list_size: Some(1024),
                    public_base_url: None,
                },
            },
            credential_types: vec![CredentialType {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://issuer.example.com/vct/pid".to_string()),
                doctype: None,
                cryptographic_holder_binding: true,
                display: vec![],
                claims: vec![
                    ClaimDef {
                        path: vec!["birthdate".to_string()],
                        selectively_disclosable: false,
                        display: vec![],
                    },
                    ClaimDef {
                        path: vec!["given_name".to_string()],
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
        }
    }

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("c.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn creates_offer_persists_transaction_and_allocates_status_index() {
        let cfg = test_config();
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: true,
        };
        let resp = create_offer(&cfg, &storage, req, 1_700_000_000).await.unwrap();

        assert_eq!(resp.credential_offer.credential_configuration_ids, vec!["pid".to_string()]);
        assert!(resp.credential_offer_uri.starts_with("openid-credential-offer://"));

        let tx = load_transaction(&storage, &resp.transaction_id).await.unwrap().unwrap();
        assert_eq!(tx.credential_type_id, "pid");
        assert!(tx.status_list_index.is_some());
        assert!(tx.tx_code.is_some());
        assert_eq!(tx.state, IssuanceState::Offered);
    }

    #[tokio::test]
    async fn rejects_unknown_credential_type() {
        let cfg = test_config();
        let storage = test_storage().await;
        let req = CreateOfferRequest {
            credential_type_id: "does-not-exist".to_string(),
            claims: serde_json::Map::new(),
            tx_code_required: false,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000).await.unwrap_err();
        assert!(matches!(err, IssuanceError::UnknownCredentialType(_)));
    }

    #[tokio::test]
    async fn rejects_missing_required_claim() {
        let cfg = test_config();
        let storage = test_storage().await;
        // `birthdate` is not selectively_disclosable, so it's required and omitted here.
        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims: serde_json::Map::new(),
            tx_code_required: false,
        };
        let err = create_offer(&cfg, &storage, req, 1_700_000_000).await.unwrap_err();
        assert!(matches!(err, IssuanceError::ClaimValidation(_)));
    }

    #[tokio::test]
    async fn skips_status_index_allocation_when_disabled() {
        let mut cfg = test_config();
        cfg.issuer.status_list.enabled = false;
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));
        let req = CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
        };
        let resp = create_offer(&cfg, &storage, req, 1_700_000_000).await.unwrap();
        let tx = load_transaction(&storage, &resp.transaction_id).await.unwrap().unwrap();
        assert!(tx.status_list_index.is_none());
        assert!(tx.tx_code.is_none());
    }
}
```

Add to `crates/foundry-issuer/src/lib.rs`:

```rust
pub mod create_offer;

pub use create_offer::{create_offer, CreateOfferRequest, CreateOfferResponse};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-issuer create_offer::tests -- --nocapture`
Expected: FAIL — module not yet registered/implemented.

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry-issuer create_offer::tests -- --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry-issuer/src/create_offer.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): add create_offer orchestration"
```

---

### Task 7: Admin bearer-token auth middleware

**Files:**
- Create: `crates/foundry/src/admin_auth.rs`
- Modify: `crates/foundry/src/lib.rs`

**Interfaces:**
- Consumes: `foundry_core::config::AdminConfig`.
- Produces:
  ```rust
  pub struct AdminApiKey(pub Option<String>);
  impl AdminApiKey { pub fn resolve(cfg: &foundry_core::config::AdminConfig) -> Self; }
  pub async fn require_api_key(State(expected): State<AdminApiKey>, request: Request<axum::body::Body>, next: Next) -> Result<Response, StatusCode>;
  ```

- [ ] **Step 1: Write the failing test**

Create `crates/foundry/src/admin_auth.rs`:

```rust
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
        let cfg = cfg_with(Some("from-literal"), Some("FOUNDRY_TEST_ADMIN_KEY_PRECEDENCE"));
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
```

Add to `crates/foundry/src/lib.rs`:

```rust
pub mod admin_auth;
```

(full updated file):

```rust
pub mod admin_auth;
pub mod cli;
pub mod commands;
pub mod logging;
pub mod server;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry admin_auth::tests -- --nocapture`
Expected: FAIL — module not yet registered/implemented.

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry admin_auth::tests -- --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/src/admin_auth.rs crates/foundry/src/lib.rs
git commit -m "feat(admin): add bearer-token auth middleware resolving AdminConfig.api_key(_env)"
```

---

### Task 8: Wire `POST /admin/issuance/offers`, extend `AppState`, update existing tests

**Files:**
- Modify: `crates/foundry/Cargo.toml`
- Modify: `crates/foundry/src/server.rs`
- Modify: `crates/foundry/tests/health.rs`

**Interfaces:**
- Consumes: `foundry_issuer::{create_offer, CreateOfferRequest, CreateOfferResponse, IssuanceError}`, `crate::admin_auth::{AdminApiKey, require_api_key}`.
- Produces: `AppState { pub storage: Arc<dyn Storage>, pub config: Arc<Config> }`; `admin_router(state: AppState, api_key: AdminApiKey) -> Router` (signature change — now takes `api_key`).

- [ ] **Step 1: Write the failing test**

Update `crates/foundry/tests/health.rs` (full file, replacing the existing content — the only change is the `AppState` construction and the `admin_router` call signature):

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
    StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt; // for `oneshot`

fn test_config() -> Config {
    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
                bind: "0.0.0.0:8443".to_string(),
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled: true,
            },
        },
        storage: StorageConfig {
            path: "./foundry.db".to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode { mode: Mode::Optional },
            key_attestation: AttestationMode { mode: Mode::Optional },
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
        },
    }
}

#[tokio::test]
async fn health_and_ready_return_200() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("h.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config());
    let app = admin_router(AppState { storage, config }, AdminApiKey(None));

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let ready = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
}
```

Add `foundry-issuer` to `crates/foundry/Cargo.toml`'s `[dependencies]` (after `foundry-core = { path = "../foundry-core" }`):

```toml
foundry-issuer = { path = "../foundry-issuer" }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry --test health -- --nocapture`
Expected: FAIL to compile — `AppState` doesn't yet have a `config` field, `admin_router` doesn't yet accept an `AdminApiKey` argument, `foundry::admin_auth` isn't wired into `admin_router`.

- [ ] **Step 3: Implement the admin route and `AppState` extension**

Replace `crates/foundry/src/server.rs` in full:

```rust
use crate::admin_auth::{require_api_key, AdminApiKey};
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
}

pub fn admin_router(state: AppState, api_key: AdminApiKey) -> Router {
    let unauthenticated = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state.clone());

    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);

    unauthenticated.merge(authenticated)
}

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    // Readiness = storage reachable. A cheap purge with a far-past timestamp
    // touches the DB without deleting live rows.
    match state.storage.purge_expired(0).await {
        Ok(_) => Ok("ready"),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn create_offer_handler(
    State(state): State<AppState>,
    Json(req): Json<foundry_issuer::CreateOfferRequest>,
) -> Result<Json<foundry_issuer::CreateOfferResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    foundry_issuer::create_offer(&state.config, state.storage.as_ref(), req, now)
        .await
        .map(Json)
        .map_err(|e| admin_error_response(&e))
}

fn admin_error_response(
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::*;
    let status = match e {
        UnknownCredentialType(_) | ClaimValidation(_) => StatusCode::BAD_REQUEST,
        StatusListExhausted(_) => StatusCode::SERVICE_UNAVAILABLE,
        Storage(_) | Serialization(_) | Deserialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "message": e.to_string() })),
    )
}

pub fn spawn_sweeper(storage: Arc<dyn Storage>, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            ticker.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match storage.purge_expired(now).await {
                Ok(n) if n > 0 => tracing::debug!(purged = n, "swept expired rows"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "sweeper purge failed"),
            }
        }
    })
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let config = Arc::new(cfg.clone());
    let state = AppState {
        storage: storage.clone(),
        config,
    };
    let _sweeper = spawn_sweeper(storage, 60);

    let api_key = AdminApiKey::resolve(&cfg.server.admin);
    if api_key.0.is_none() {
        tracing::warn!("admin API key not configured — admin endpoints are UNAUTHENTICATED (dev only)");
    }
    let admin_app = admin_router(state, api_key);

    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    axum::serve(admin_listener, admin_app).await?;
    Ok(())
}
```

> Note: this task intentionally keeps `serve()` single-listener (admin only) so this task's diff stays reviewable in isolation — Task 9 adds the second, wallet-facing listener and switches `serve()` to run both concurrently.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry --test health -- --nocapture`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/Cargo.toml crates/foundry/src/server.rs crates/foundry/tests/health.rs
git commit -m "feat(admin): wire POST /admin/issuance/offers behind bearer-token auth"
```

---

### Task 9: Wallet-facing well-known endpoints, dual-listener `serve()`, integration tests, workspace gates

**Files:**
- Modify: `crates/foundry/src/server.rs`
- Create: `crates/foundry/tests/issuer_offers.rs`
- Create: `crates/foundry/tests/wallet_metadata.rs`

**Interfaces:**
- Produces: `wallet_router(state: AppState) -> Router` serving `GET /.well-known/openid-credential-issuer` and `GET /.well-known/oauth-authorization-server`; `serve()` now binds both `server.admin.bind` and `server.wallet_facing.bind` concurrently.

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry/tests/wallet_metadata.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use foundry::server::{wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config() -> Config {
    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
                bind: "0.0.0.0:8443".to_string(),
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled: true,
            },
        },
        storage: StorageConfig {
            path: "./foundry.db".to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode { mode: Mode::Optional },
            key_attestation: AttestationMode { mode: Mode::Optional },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: None,
                list_size: None,
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://localhost:8443/vct/pid".to_string()),
            doctype: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                selectively_disclosable: true,
                display: vec![],
            }],
        }],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: Vec::new(),
            named_queries: Vec::new(),
            webhook: None,
        },
    }
}

async fn test_app() -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("w.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config());
    std::mem::forget(dir);
    wallet_router(AppState { storage, config })
}

#[tokio::test]
async fn serves_credential_issuer_metadata() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["credential_issuer"], "https://localhost:8443");
    assert!(json["credential_configurations_supported"]["pid"].is_object());
}

#[tokio::test]
async fn serves_authorization_server_metadata() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["issuer"], "https://localhost:8443");
    assert_eq!(json["token_endpoint"], "https://localhost:8443/token");
}
```

Create `crates/foundry/tests/issuer_offers.rs`:

```rust
use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use foundry::admin_auth::AdminApiKey;
use foundry::server::{admin_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, ClaimDef, Config, CredentialType, IssuerConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config(status_list_enabled: bool) -> Config {
    Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
                bind: "0.0.0.0:8443".to_string(),
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some("test-admin-key".to_string()),
                api_key_env: None,
                swagger_ui_enabled: true,
            },
        },
        storage: StorageConfig {
            path: "./foundry.db".to_string(),
            transaction_ttl_secs: 600,
        },
        keys: BTreeMap::new(),
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode { mode: Mode::Optional },
            key_attestation: AttestationMode { mode: Mode::Optional },
            status_list: StatusListConfig {
                enabled: status_list_enabled,
                signing_key: None,
                list_size: Some(1024),
                public_base_url: None,
            },
        },
        credential_types: vec![CredentialType {
            id: "pid".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://localhost:8443/vct/pid".to_string()),
            doctype: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["given_name".to_string()],
                selectively_disclosable: true,
                display: vec![],
            }],
        }],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "verifier_signing".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: Vec::new(),
            named_queries: Vec::new(),
            webhook: None,
        },
    }
}

async fn test_app(status_list_enabled: bool) -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("o.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(status_list_enabled));
    std::mem::forget(dir);
    admin_router(
        AppState { storage, config },
        AdminApiKey(Some("test-admin-key".to_string())),
    )
}

#[tokio::test]
async fn creates_an_offer_with_valid_bearer_token() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "pid", "claims": {}, "tx_code_required": false });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["transaction_id"].is_string());
    assert!(json["credential_offer_uri"].as_str().unwrap().starts_with("openid-credential-offer://"));
}

#[tokio::test]
async fn rejects_offer_creation_without_bearer_token() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "pid", "claims": {} });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_offer_creation_with_wrong_bearer_token() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "pid", "claims": {} });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer wrong-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_bad_request_for_unknown_credential_type() {
    let app = test_app(true).await;
    let body = serde_json::json!({ "credential_type_id": "does-not-exist", "claims": {} });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/issuance/offers")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["error"].as_str().unwrap().contains("does-not-exist"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p foundry --test wallet_metadata --test issuer_offers -- --nocapture`
Expected: FAIL — `wallet_router` does not yet exist.

- [ ] **Step 3: Implement `wallet_router` and dual-listener `serve()`**

Apply this edit to `crates/foundry/src/server.rs`: add the `wallet_router` function and its handlers, and replace the body of `serve()` to bind both listeners concurrently.

Add (after `admin_router`'s closing brace, before `async fn health()`):

```rust
pub fn wallet_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_server_metadata),
        )
        .with_state(state)
}

async fn issuer_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::CredentialIssuerMetadata> {
    Json(foundry_issuer::build_issuer_metadata(&state.config))
}

async fn auth_server_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::AuthorizationServerMetadata> {
    Json(foundry_issuer::build_authorization_server_metadata(&state.config))
}
```

Replace the `serve()` function body:

```rust
pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let config = Arc::new(cfg.clone());
    let state = AppState {
        storage: storage.clone(),
        config: config.clone(),
    };
    let _sweeper = spawn_sweeper(storage, 60);

    let api_key = AdminApiKey::resolve(&cfg.server.admin);
    if api_key.0.is_none() {
        tracing::warn!("admin API key not configured — admin endpoints are UNAUTHENTICATED (dev only)");
    }
    let admin_app = admin_router(state.clone(), api_key);
    let wallet_app = wallet_router(state);

    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    let wallet_listener = tokio::net::TcpListener::bind(&cfg.server.wallet_facing.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    tracing::info!(bind = %cfg.server.wallet_facing.bind, "foundry wallet-facing server listening");

    tokio::try_join!(
        axum::serve(admin_listener, admin_app).into_future(),
        axum::serve(wallet_listener, wallet_app).into_future(),
    )?;
    Ok(())
}
```

Add `use std::future::IntoFuture;` to the top of `crates/foundry/src/server.rs`'s existing `use` block (needed for `.into_future()` on `axum::serve(...)`, since `tokio::try_join!` needs both arms to be the same concrete future type via `IntoFuture`):

```rust
use std::future::IntoFuture;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p foundry --test wallet_metadata --test issuer_offers -- --nocapture`
Expected: PASS (2 + 4 = 6 tests).

- [ ] **Step 5: Full workspace gates**

```bash
cargo fmt -p foundry-issuer -p foundry -- --check
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
```

Expected: zero warnings, clean format, zero errors, all tests green (including the existing `crates/foundry/tests/{cli_pki,quickstart,sweeper}.rs`, which this plan does not touch and must remain passing unmodified).

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/wallet_metadata.rs crates/foundry/tests/issuer_offers.rs
git commit -m "feat(issuer): add wallet-facing well-known metadata endpoints and dual-listener serve()"
```