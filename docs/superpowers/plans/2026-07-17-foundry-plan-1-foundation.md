# Foundry — Plan 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Foundry Cargo workspace with vendored protocol crates, a `foundry-core` crate (errors, config model + validation, storage trait + SQLite), and a `foundry` binary whose `serve` command boots an axum server with health endpoints and structured console logging.

**Architecture:** A Cargo workspace. Vendored Spruce crates (`oid4vci`, `openid4vp`) live under `crates/` and build as-is. `foundry-core` holds cross-cutting types (error enums, config structs with startup validation, a `Storage` trait with a SQLite implementation). The `foundry` binary wires a `clap` CLI (`serve`, `config validate`) to an `axum` server exposing `/health` and `/ready` on the admin listener, with `tracing` structured console logging.

**Tech Stack:** Rust 1.97, tokio, axum 0.7, clap 4 (derive), serde + serde_yaml + serde_json, sqlx (SQLite, runtime-tokio-rustls), thiserror, tracing + tracing-subscriber.

## Global Constraints

- Language / runtime: Rust (edition 2021), tokio async runtime.
- CLI framework: `clap` v4 with derive macros. No other arg parser.
- Logging: `tracing` + `tracing-subscriber`, structured, **console-only** (stdout/stderr) — no file or remote sinks. Format selectable (human/JSON) via CLI flag `--log-format`; level via `--log-level`.
- Storage: embedded **SQLite** only (no external DB), accessed via `sqlx`. Config points at a file path.
- Config: single YAML **or** JSON file, deserialized into typed serde structs, **validated at startup**; invalid config fails fast with a non-zero exit and an actionable message.
- Errors: typed via `thiserror`; no `unwrap`/`panic` in non-test code paths.
- Vendored crates `oid4vci` and `openid4vp` are **owned copies** (no `.git`, no upstream remote), added as workspace path members. Do not add them as crates.io dependencies anywhere.
- Every code change lands via TDD: failing test first, then minimal implementation, then commit.

---

### Task 1: Initialize Cargo workspace skeleton

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `rust-toolchain.toml`
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace whose `members` list will grow as crates are added; `cargo metadata` succeeds.

- [ ] **Step 1: Create the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "crates/foundry-core",
    "crates/foundry",
]

[workspace.package]
edition = "2021"
rust-version = "1.97"
license = "Apache-2.0"
authors = ["Digital Labor Berlin"]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
axum = "0.7"
clap = { version = "4", features = ["derive", "env"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "sqlite", "macros", "migrate"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
anyhow = "1"
async-trait = "0.1"
```

- [ ] **Step 2: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "1.97.0"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 3: Create `.gitignore`**

```gitignore
/target
**/*.rs.bk
*.db
*.db-journal
*.db-wal
*.db-shm
.env
/keys
/trust
foundry.db
```

- [ ] **Step 4: Verify the workspace is coherent (will fail until crates exist)**

Run: `cargo metadata --no-deps --format-version 1 >/dev/null; echo "exit=$?"`
Expected: non-zero exit with an error that member `crates/foundry-core` is missing. This confirms the workspace file parses and points at the crates we create next.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .gitignore
git commit -m "chore: initialize cargo workspace skeleton"
```

---

### Task 2: Vendor the Spruce `oid4vci` and `openid4vp` crates

**Files:**
- Create: `crates/oid4vci/**` (vendored copy)
- Create: `crates/openid4vp/**` (vendored copy)
- Modify: `Cargo.toml` (add the two members)
- Create: `docs/VENDORING.md`

**Interfaces:**
- Consumes: workspace root from Task 1.
- Produces: two path-member crates `oid4vci` and `openid4vp` that compile via `cargo build -p oid4vci -p openid4vp`.

- [ ] **Step 1: Clone upstream into the workspace and strip git metadata**

```bash
tmpdir=$(mktemp -d)
git clone --depth 1 https://github.com/spruceid/oid4vci-rs "$tmpdir/oid4vci-rs"
git clone --depth 1 https://github.com/spruceid/openid4vp "$tmpdir/openid4vp"
mkdir -p crates/oid4vci crates/openid4vp
# Copy the crate source (repo may be a workspace; copy the primary crate dir).
# Inspect layout first:
ls "$tmpdir/oid4vci-rs"
ls "$tmpdir/openid4vp"
```

Note for the implementer: each upstream repo may be a single crate at the repo
root or a Cargo workspace with the library under a subdirectory (e.g. `oid4vci/`
or similar). Copy the crate that produces the library (the one whose
`Cargo.toml` has `[lib]` / the package named `oid4vci` resp. `openid4vp`) into
`crates/oid4vci` resp. `crates/openid4vp`, preserving `src/`, `Cargo.toml`,
`LICENSE`, and `README.md`. Do **not** copy `.git`.

```bash
# Example if the library is at repo root:
cp -R "$tmpdir/oid4vci-rs/src" crates/oid4vci/src
cp "$tmpdir/oid4vci-rs/Cargo.toml" crates/oid4vci/Cargo.toml
cp "$tmpdir/oid4vci-rs/README.md" crates/oid4vci/README.md 2>/dev/null || true
cp "$tmpdir/oid4vci-rs/LICENSE"* crates/oid4vci/ 2>/dev/null || true
# Repeat analogously for openid4vp.
rm -rf "$tmpdir"
```

- [ ] **Step 2: Pin each vendored crate to the workspace and remove upstream-only workspace wiring**

Edit `crates/oid4vci/Cargo.toml` and `crates/openid4vp/Cargo.toml`:
- Ensure `[package]` has `edition = "2021"` and a concrete `version` (keep upstream's).
- Remove any `[workspace]` table (these are now members, not roots).
- Replace any `xxx.workspace = true` inheritance that referred to the *upstream* workspace with concrete versions copied from upstream's lockfile/manifest.
- Leave their dependencies as normal crates.io deps.

Record provenance in `docs/VENDORING.md`:

```markdown
# Vendored Crates

These crates are **owned copies**, not upstream dependencies. We control the
protocol implementation directly.

| Crate | Upstream | Commit vendored | Date |
|-------|----------|-----------------|------|
| oid4vci | https://github.com/spruceid/oid4vci-rs | <fill: git rev-parse HEAD at clone> | 2026-07-17 |
| openid4vp | https://github.com/spruceid/openid4vp | <fill> | 2026-07-17 |

## Update policy
Changes are made directly in `crates/`. To pull upstream fixes, diff against the
recorded commit and cherry-pick manually. Never re-add as a crates.io dependency.
```

- [ ] **Step 3: Set the workspace members to the crates that exist now**

The workspace uses an **incremental members list**: each task lists only the
crates that exist after it runs (cargo refuses to operate on a workspace whose
member directory is missing). After Task 1 the list still names
`crates/foundry-core` and `crates/foundry`, which do not exist yet — replace the
list so it names exactly the two vendored crates this task creates. Later tasks
(3 and 6) add their crates back.

Modify the root `Cargo.toml` `members` list to exactly:

```toml
members = [
    "crates/oid4vci",
    "crates/openid4vp",
]
```

- [ ] **Step 4: Build the vendored crates to verify they compile as owned copies**

Run: `cargo build -p oid4vci -p openid4vp 2>&1 | tail -20; echo "exit=${PIPESTATUS[0]}"`
Expected: both crates compile (exit=0). If a compile error stems from removed upstream workspace inheritance, fix the offending `Cargo.toml` dependency version inline until it builds.

- [ ] **Step 5: Commit**

```bash
git add crates/oid4vci crates/openid4vp Cargo.toml docs/VENDORING.md
git commit -m "chore: vendor spruce oid4vci and openid4vp as owned workspace crates"
```

---

### Task 3: Create `foundry-core` crate with the error taxonomy

**Files:**
- Create: `crates/foundry-core/Cargo.toml`
- Create: `crates/foundry-core/src/lib.rs`
- Create: `crates/foundry-core/src/error.rs`

**Interfaces:**
- Consumes: workspace from Task 1.
- Produces:
  - `foundry_core::error::ConfigError` (enum, `thiserror::Error`)
  - `foundry_core::error::StorageError` (enum, `thiserror::Error`)
  - `foundry_core::error::CoreError` (enum wrapping the above via `#[from]`)
  - `pub type CoreResult<T> = Result<T, CoreError>;`

- [ ] **Step 1: Write the failing test**

Create `crates/foundry-core/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config ({format}): {message}")]
    Parse { format: String, message: String },
    #[error("config validation failed: {0}")]
    Validation(String),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("record not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation_error_displays_message() {
        let e = ConfigError::Validation("missing key 'issuer_sdjwt'".into());
        assert_eq!(
            e.to_string(),
            "config validation failed: missing key 'issuer_sdjwt'"
        );
    }

    #[test]
    fn core_error_wraps_storage_not_found() {
        let e: CoreError = StorageError::NotFound("tx-123".into()).into();
        assert_eq!(e.to_string(), "record not found: tx-123");
    }
}
```

- [ ] **Step 2: Create the crate manifest and lib entry**

`crates/foundry-core/Cargo.toml`:

```toml
[package]
name = "foundry-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
sqlx = { workspace = true }
thiserror = { workspace = true }
async-trait = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3"
```

`crates/foundry-core/src/lib.rs`:

```rust
pub mod error;
```

**Register the crate in the workspace (incremental members list).** Add
`crates/foundry-core` to the root `Cargo.toml` `members` list so cargo can build
and test it. After this step the list must be exactly:

```toml
members = [
    "crates/oid4vci",
    "crates/openid4vp",
    "crates/foundry-core",
]
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p foundry-core error:: 2>&1 | tail -20`
Expected: FAIL — crate did not previously compile / tests not found before this task. After adding the code it should compile; if the module wasn't wired the test binary reports 0 tests. Confirm the two named tests are collected.

Note: the `git add` in this task's commit step must also stage the modified
root `Cargo.toml` (member registration) in addition to `crates/foundry-core`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core error:: 2>&1 | tail -20`
Expected: PASS — `config_validation_error_displays_message` and `core_error_wraps_storage_not_found` both pass.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core Cargo.toml
git commit -m "feat(core): add error taxonomy for config and storage"
```

---

### Task 4: Config model with load + validation

**Files:**
- Create: `crates/foundry-core/src/config/mod.rs`
- Create: `crates/foundry-core/src/config/model.rs`
- Create: `crates/foundry-core/src/config/validate.rs`
- Modify: `crates/foundry-core/src/lib.rs`
- Create: `crates/foundry-core/tests/config_load.rs`
- Create: `crates/foundry-core/tests/fixtures/minimal.yaml`
- Create: `crates/foundry-core/tests/fixtures/bad-missing-keyref.yaml`

**Interfaces:**
- Consumes: `foundry_core::error::ConfigError` from Task 3.
- Produces:
  - `foundry_core::config::Config` (serde `Deserialize`, top-level struct)
  - `foundry_core::config::Config::load(path: &std::path::Path) -> Result<Config, ConfigError>` — reads file, picks YAML vs JSON by extension (`.json` → JSON, else YAML), deserializes.
  - `foundry_core::config::Config::validate(&self) -> Result<(), ConfigError>` — cross-reference checks.
  - Sub-structs: `ServerConfig`, `WalletFacingConfig`, `AdminConfig`, `StorageConfig`, `KeyEntry`, `TrustAnchor`, `IssuerConfig`, `StatusListConfig`, `CredentialType`, `ClaimDef`, `VerifierConfig` (fields per the design spec §5). Keys map is `BTreeMap<String, KeyEntry>`.

- [ ] **Step 1: Write the failing integration test**

`crates/foundry-core/tests/config_load.rs`:

```rust
use foundry_core::config::Config;
use std::path::Path;

#[test]
fn loads_minimal_yaml_and_validates() {
    let cfg = Config::load(Path::new("tests/fixtures/minimal.yaml"))
        .expect("should load");
    assert_eq!(cfg.issuer.credential_issuer, "https://issuer.example.com");
    assert_eq!(cfg.credential_types.len(), 1);
    assert_eq!(cfg.credential_types[0].id, "pid");
    cfg.validate().expect("minimal config should be valid");
}

#[test]
fn rejects_unresolvable_key_reference() {
    let cfg = Config::load(Path::new("tests/fixtures/bad-missing-keyref.yaml"))
        .expect("should parse");
    let err = cfg.validate().expect_err("should fail validation");
    let msg = err.to_string();
    assert!(
        msg.contains("signing_key") && msg.contains("nonexistent_key"),
        "unexpected error: {msg}"
    );
}
```

- [ ] **Step 2: Create the fixtures**

`crates/foundry-core/tests/fixtures/minimal.yaml`:

```yaml
server:
  wallet_facing:
    public_base_url: https://issuer.example.com
    bind: 0.0.0.0:8443
  admin:
    bind: 127.0.0.1:9000
    api_key: dev-admin-key
storage:
  path: ./foundry.db
  transaction_ttl_secs: 600
keys:
  issuer_sdjwt:
    private_key: ./keys/issuer_ec.pem
    x5c: ./keys/issuer_chain.pem
    alg: ES256
trust_anchors: []
issuer:
  credential_issuer: https://issuer.example.com
  wallet_attestation: { mode: optional }
  key_attestation: { mode: optional }
  status_list:
    enabled: true
    signing_key: issuer_sdjwt
    list_size: 1048576
    public_base_url: https://issuer.example.com/statuslists
credential_types:
  - id: pid
    format: dc+sd-jwt
    vct: https://example.com/vct/pid
    cryptographic_holder_binding: true
    display: [{ name: "Person ID", locale: en-US }]
    claims:
      - path: [given_name]
        selectively_disclosable: true
      - path: [birthdate]
        selectively_disclosable: true
verifier:
  client_id_scheme: x509_san_dns
  signing_key: issuer_sdjwt
  response_encryption: { alg: ECDH-ES, enc: A128GCM }
  transaction_data_hashes_alg: [sha-256]
  named_queries: []
```

`crates/foundry-core/tests/fixtures/bad-missing-keyref.yaml` — identical to
`minimal.yaml` but with `verifier.signing_key: nonexistent_key`.

- [ ] **Step 3: Write the config model**

`crates/foundry-core/src/config/model.rs`:

```rust
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub keys: BTreeMap<String, KeyEntry>,
    #[serde(default)]
    pub trust_anchors: Vec<TrustAnchor>,
    pub issuer: IssuerConfig,
    #[serde(default)]
    pub credential_types: Vec<CredentialType>,
    pub verifier: VerifierConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub wallet_facing: WalletFacingConfig,
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletFacingConfig {
    pub public_base_url: String,
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub bind: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub path: String,
    #[serde(default = "default_ttl")]
    pub transaction_ttl_secs: u64,
}

fn default_ttl() -> u64 { 600 }

#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub private_key: String,
    #[serde(default)]
    pub x5c: Option<String>,
    pub alg: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustAnchor {
    pub name: String,
    pub certs: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuerConfig {
    pub credential_issuer: String,
    #[serde(default)]
    pub wallet_attestation: AttestationMode,
    #[serde(default)]
    pub key_attestation: AttestationMode,
    pub status_list: StatusListConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttestationMode {
    #[serde(default)]
    pub mode: Mode,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Required,
    #[default]
    Optional,
    Disabled,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusListConfig {
    pub enabled: bool,
    #[serde(default)]
    pub signing_key: Option<String>,
    #[serde(default)]
    pub list_size: Option<u64>,
    #[serde(default)]
    pub public_base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialType {
    pub id: String,
    pub format: String,
    #[serde(default)]
    pub vct: Option<String>,
    #[serde(default)]
    pub doctype: Option<String>,
    #[serde(default)]
    pub cryptographic_holder_binding: bool,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
    #[serde(default)]
    pub claims: Vec<ClaimDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaimDef {
    pub path: Vec<String>,
    #[serde(default)]
    pub selectively_disclosable: bool,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifierConfig {
    pub client_id_scheme: String,
    pub signing_key: String,
    #[serde(default)]
    pub response_encryption: Option<serde_json::Value>,
    #[serde(default)]
    pub transaction_data_hashes_alg: Vec<String>,
    #[serde(default)]
    pub named_queries: Vec<serde_json::Value>,
    #[serde(default)]
    pub webhook: Option<serde_json::Value>,
}
```

- [ ] **Step 4: Write load + validate**

`crates/foundry-core/src/config/validate.rs`:

```rust
use super::model::Config;
use crate::error::ConfigError;

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
```

`crates/foundry-core/src/config/mod.rs`:

```rust
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
```

Modify `crates/foundry-core/src/lib.rs`:

```rust
pub mod config;
pub mod error;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p foundry-core --test config_load 2>&1 | tail -20`
Expected: PASS — both `loads_minimal_yaml_and_validates` and `rejects_unresolvable_key_reference`.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-core
git commit -m "feat(core): add config model with file load and startup validation"
```

---

### Task 5: Storage trait + SQLite implementation

**Files:**
- Create: `crates/foundry-core/src/storage/mod.rs`
- Create: `crates/foundry-core/src/storage/sqlite.rs`
- Create: `crates/foundry-core/migrations/0001_init.sql`
- Modify: `crates/foundry-core/src/lib.rs`
- Create: `crates/foundry-core/tests/storage_sqlite.rs`

**Interfaces:**
- Consumes: `foundry_core::error::StorageError` from Task 3.
- Produces:
  - `#[async_trait] foundry_core::storage::Storage` with methods:
    - `async fn put_kv(&self, namespace: &str, key: &str, value: &str, expires_at: Option<i64>) -> Result<(), StorageError>`
    - `async fn get_kv(&self, namespace: &str, key: &str) -> Result<Option<String>, StorageError>`
    - `async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError>`
    - `async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError>` (returns rows deleted)
  - `foundry_core::storage::SqliteStorage` implementing it, with `SqliteStorage::connect(path: &str) -> Result<SqliteStorage, StorageError>` running migrations.

- [ ] **Step 1: Write the failing test**

`crates/foundry-core/tests/storage_sqlite.rs`:

```rust
use foundry_core::storage::{SqliteStorage, Storage};

#[tokio::test]
async fn kv_roundtrip_and_expiry_purge() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    store.put_kv("issuance", "tx-1", "{\"a\":1}", Some(100)).await.unwrap();
    let got = store.get_kv("issuance", "tx-1").await.unwrap();
    assert_eq!(got.as_deref(), Some("{\"a\":1}"));

    // Not found for another namespace.
    assert_eq!(store.get_kv("verification", "tx-1").await.unwrap(), None);

    // Purge anything expiring at or before now=150 -> removes tx-1.
    let removed = store.purge_expired(150).await.unwrap();
    assert_eq!(removed, 1);
    assert_eq!(store.get_kv("issuance", "tx-1").await.unwrap(), None);

    // Delete is idempotent.
    store.delete_kv("issuance", "tx-1").await.unwrap();
}
```

- [ ] **Step 2: Create the migration**

`crates/foundry-core/migrations/0001_init.sql`:

```sql
CREATE TABLE IF NOT EXISTS kv (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    expires_at  INTEGER,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv (expires_at);
```

- [ ] **Step 3: Write the trait**

`crates/foundry-core/src/storage/mod.rs`:

```rust
mod sqlite;
pub use sqlite::SqliteStorage;

use crate::error::StorageError;
use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn put_kv(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        expires_at: Option<i64>,
    ) -> Result<(), StorageError>;

    async fn get_kv(&self, namespace: &str, key: &str)
        -> Result<Option<String>, StorageError>;

    async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError>;

    async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError>;
}
```

- [ ] **Step 4: Write the SQLite implementation**

`crates/foundry-core/src/storage/sqlite.rs`:

```rust
use super::Storage;
use crate::error::StorageError;
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn connect(path: &str) -> Result<SqliteStorage, StorageError> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(SqliteStorage { pool })
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn put_kv(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        expires_at: Option<i64>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO kv (namespace, key, value, expires_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, key) DO UPDATE SET value = ?3, expires_at = ?4",
        )
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_kv(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, StorageError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM kv WHERE namespace = ?1 AND key = ?2")
                .bind(namespace)
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(row.map(|(v,)| v))
    }

    async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM kv WHERE namespace = ?1 AND key = ?2")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError> {
        let res = sqlx::query(
            "DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        )
        .bind(now_unix)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(res.rows_affected())
    }
}
```

Modify `crates/foundry-core/src/lib.rs`:

```rust
pub mod config;
pub mod error;
pub mod storage;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p foundry-core --test storage_sqlite 2>&1 | tail -30`
Expected: PASS — `kv_roundtrip_and_expiry_purge`.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-core
git commit -m "feat(core): add Storage trait with SQLite implementation and migrations"
```

---

### Task 6: `foundry` binary — CLI skeleton with structured console logging

**Files:**
- Create: `crates/foundry/Cargo.toml`
- Create: `crates/foundry/src/main.rs`
- Create: `crates/foundry/src/cli.rs`
- Create: `crates/foundry/src/logging.rs`

**Interfaces:**
- Consumes: `foundry_core::config::Config` from Task 4.
- Produces:
  - `foundry::cli::Cli` (clap `Parser`) with subcommands `Serve { config: PathBuf }`, `Config { action: ConfigAction }` where `ConfigAction::Validate { config: PathBuf }`.
  - Global flags `--log-level <LEVEL>` (default `info`) and `--log-format <human|json>` (default `human`).
  - `foundry::logging::init(level: &str, format: LogFormat)`.

- [ ] **Step 1: Write the failing test (CLI parses subcommands)**

`crates/foundry/src/cli.rs`:

```rust
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "foundry", version, about = "Digital credential issuing & verification service")]
pub struct Cli {
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Human)]
    pub log_format: LogFormat,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Boot the long-running HTTP service.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Config operations.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Validate a config file without serving.
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_serve_with_config() {
        let cli = Cli::parse_from(["foundry", "serve", "--config", "c.yaml"]);
        match cli.command {
            Command::Serve { config } => assert_eq!(config.to_str().unwrap(), "c.yaml"),
            _ => panic!("expected serve"),
        }
    }

    #[test]
    fn parses_config_validate_and_log_flags() {
        let cli = Cli::parse_from([
            "foundry", "--log-level", "debug", "--log-format", "json",
            "config", "validate", "--config", "c.json",
        ]);
        assert_eq!(cli.log_level, "debug");
        assert!(matches!(cli.log_format, LogFormat::Json));
        match cli.command {
            Command::Config { action: ConfigAction::Validate { config } } => {
                assert_eq!(config.to_str().unwrap(), "c.json");
            }
            _ => panic!("expected config validate"),
        }
    }
}
```

- [ ] **Step 2: Create the manifest, logging, and main**

`crates/foundry/Cargo.toml`:

```toml
[package]
name = "foundry"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "foundry"
path = "src/main.rs"

[dependencies]
foundry-core = { path = "../foundry-core" }
tokio = { workspace = true }
axum = { workspace = true }
clap = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
serde_json = { workspace = true }
```

**Register the crate in the workspace (incremental members list).** Add
`crates/foundry` to the root `Cargo.toml` `members` list so cargo can build and
test it. After this step the list must be exactly:

```toml
members = [
    "crates/oid4vci",
    "crates/openid4vp",
    "crates/foundry-core",
    "crates/foundry",
]
```

`crates/foundry/src/logging.rs`:

```rust
use crate::cli::LogFormat;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init(level: &str, format: LogFormat) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Human => {
            fmt().with_env_filter(filter).init();
        }
        LogFormat::Json => {
            fmt().json().with_env_filter(filter).init();
        }
    }
}
```

`crates/foundry/src/main.rs`:

```rust
mod cli;
mod logging;
mod server;

use clap::Parser;
use cli::{Cli, Command, ConfigAction};
use foundry_core::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logging::init(&cli.log_level, cli.log_format);

    match cli.command {
        Command::Config { action: ConfigAction::Validate { config } } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            tracing::info!(path = %config.display(), "config is valid");
            println!("OK: {} is valid", config.display());
            Ok(())
        }
        Command::Serve { config } => {
            let cfg = Config::load(&config)?;
            cfg.validate()?;
            server::serve(cfg).await
        }
    }
}
```

Note: `server` module is created in Task 7; this task will not compile the
`Serve` arm until then. To keep this task independently green, temporarily stub
`server` — create `crates/foundry/src/server.rs` with:

```rust
use foundry_core::config::Config;

pub async fn serve(_cfg: Config) -> anyhow::Result<()> {
    anyhow::bail!("serve not yet implemented")
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p foundry cli:: 2>&1 | tail -20`
Expected: PASS — `parses_serve_with_config` and `parses_config_validate_and_log_flags`.

- [ ] **Step 4: Manually verify `config validate` works end-to-end**

Run: `cargo run -p foundry -- config validate --config crates/foundry-core/tests/fixtures/minimal.yaml 2>&1 | tail -5`
Expected: prints `OK: crates/foundry-core/tests/fixtures/minimal.yaml is valid` and exits 0.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry Cargo.toml
git commit -m "feat(cli): add clap CLI skeleton with structured console logging and config validate"
```

---

### Task 7: `serve` boots axum with health/ready endpoints

**Files:**
- Modify: `crates/foundry/src/server.rs`
- Create: `crates/foundry/tests/health.rs`
- Modify: `crates/foundry/Cargo.toml` (dev-deps)

**Interfaces:**
- Consumes: `foundry_core::config::Config`, `foundry_core::storage::SqliteStorage` + `Storage`.
- Produces:
  - `foundry::server::serve(cfg: Config) -> anyhow::Result<()>` — connects storage, builds the admin router, binds `cfg.server.admin.bind`, serves until shutdown.
  - `foundry::server::admin_router(state: AppState) -> axum::Router` — exposes `GET /health` → `200 "ok"` and `GET /ready` → `200 "ready"` when storage reachable, else `503`.
  - `foundry::server::AppState { storage: Arc<dyn Storage> }`.

- [ ] **Step 1: Write the failing test (router returns 200 on /health and /ready)**

`crates/foundry/tests/health.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use foundry::server::{admin_router, AppState};
use foundry_core::storage::SqliteStorage;
use std::sync::Arc;
use tower::ServiceExt; // for `oneshot`

#[tokio::test]
async fn health_and_ready_return_200() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("h.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let app = admin_router(AppState { storage });

    let health = app
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let ready = app
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
}
```

- [ ] **Step 2: Add dev-dependencies**

Modify `crates/foundry/Cargo.toml`, add:

```toml
[dev-dependencies]
tempfile = "3"
tower = { version = "0.5", features = ["util"] }
foundry-core = { path = "../foundry-core" }
```

Also add to `[dependencies]`: `foundry` needs `Arc` (std) and the `Storage`
trait object — ensure `foundry-core` is already a dep (it is from Task 6).
Add `tower` to `[dependencies]` is not required; only dev.

- [ ] **Step 3: Implement the server**

Replace `crates/foundry/src/server.rs`:

```rust
use axum::{extract::State, http::StatusCode, routing::get, Router};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
}

pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state)
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

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    let storage = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let state = AppState { storage };
    let app = admin_router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
```

To expose `server` as a library target for the integration test, add a lib
alongside the binary. Create `crates/foundry/src/lib.rs`:

```rust
pub mod cli;
pub mod logging;
pub mod server;
```

And change `crates/foundry/src/main.rs` module declarations to use the crate's
own library modules: replace the top `mod cli; mod logging; mod server;` lines
with:

```rust
use foundry::cli::{self, Cli, Command, ConfigAction};
use foundry::logging;
use foundry::server;
```

Add `[lib]` to `crates/foundry/Cargo.toml`:

```toml
[lib]
name = "foundry"
path = "src/lib.rs"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p foundry --test health 2>&1 | tail -30`
Expected: PASS — `health_and_ready_return_200`.

- [ ] **Step 5: Manually verify serve boots**

Run:
```bash
cp crates/foundry-core/tests/fixtures/minimal.yaml /tmp/foundry-min.yaml
sed -i '' 's#127.0.0.1:9000#127.0.0.1:19099#' /tmp/foundry-min.yaml
(cargo run -p foundry -- serve --config /tmp/foundry-min.yaml &) ; sleep 3
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:19099/health
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:19099/ready
pkill -f "target/debug/foundry" || true
```
Expected: two lines `200` and `200`.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry
git commit -m "feat(server): serve boots axum admin server with health and ready endpoints"
```

---

### Task 8: Background expiry sweeper + full workspace check

**Files:**
- Modify: `crates/foundry/src/server.rs`
- Create: `crates/foundry/tests/sweeper.rs`

**Interfaces:**
- Consumes: `AppState`, `Storage::purge_expired`, `Config::storage::transaction_ttl_secs`.
- Produces: `foundry::server::spawn_sweeper(storage: Arc<dyn Storage>, interval_secs: u64) -> tokio::task::JoinHandle<()>` — periodically purges expired rows.

- [ ] **Step 1: Write the failing test**

`crates/foundry/tests/sweeper.rs`:

```rust
use foundry::server::spawn_sweeper;
use foundry_core::storage::{SqliteStorage, Storage};
use std::sync::Arc;

#[tokio::test]
async fn sweeper_purges_expired_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());

    // expires_at in the past relative to wall clock.
    storage.put_kv("issuance", "old", "v", Some(1)).await.unwrap();

    let handle = spawn_sweeper(storage.clone(), 1);
    // Give the sweeper one tick.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    handle.abort();

    assert_eq!(storage.get_kv("issuance", "old").await.unwrap(), None);
}
```

- [ ] **Step 2: Implement the sweeper**

Append to `crates/foundry/src/server.rs`:

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn spawn_sweeper(
    storage: Arc<dyn Storage>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
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
```

Wire it into `serve` — after building `state`, before `axum::serve`:

```rust
    let _sweeper = spawn_sweeper(state.storage.clone(), 60);
```

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p foundry --test sweeper 2>&1 | tail -20`
Expected: PASS — `sweeper_purges_expired_rows`.

- [ ] **Step 4: Verification (fmt, clippy, tests) — scoped to OUR crates**

The vendored crates (`oid4vci`, `openid4vp`, `openid4vp-frontend`) are owned
upstream copies; we do NOT hold them to our fmt/clippy bar, and their tests may
need network. So scope fmt/clippy/test to the crates we author
(`foundry-core`, `foundry`), then do a plain workspace build to confirm
everything (including vendored) still compiles.

First normalize formatting of our crates (this also fixes any missing trailing
newlines left by earlier tasks):

```bash
cargo fmt -p foundry-core -p foundry
```

Then verify:
```bash
cargo fmt -p foundry-core -p foundry -- --check && \
cargo clippy -p foundry-core -p foundry --all-targets -- -D warnings 2>&1 | tail -20 && \
cargo test -p foundry-core -p foundry 2>&1 | tail -30 && \
cargo build --workspace 2>&1 | tail -5
```
Expected: fmt clean, clippy no warnings, all `foundry-core` + `foundry` tests
pass, and the full workspace builds (exit 0). If `cargo fmt` produced changes,
stage them in the commit.

- [ ] **Step 5: Commit (including the workspace lockfile)**

`Cargo.lock` is not yet tracked — it must be committed (this is a binary
workspace; the lockfile belongs in git). Stage it here along with the sweeper
changes and any `cargo fmt` normalization.

```bash
git add crates/foundry crates/foundry-core Cargo.lock
git commit -m "feat(server): add background expiry sweeper; track lockfile; pass workspace check"
```

---

## Self-Review

**1. Spec coverage (Plan 1 slice only):**
- Cargo workspace + vendored owned crates → Tasks 1, 2. ✓
- `foundry-core` error types → Task 3. ✓
- Config model, YAML/JSON load, startup validation, generic credential types → Task 4. ✓
- Embedded SQLite storage + trait seam → Task 5. ✓
- `clap` CLI, structured console-only logging (human/JSON) → Task 6. ✓
- `serve` boots axum, health/ready → Task 7. ✓
- Transaction TTL sweeper → Task 8. ✓
- Out of Plan 1 (deferred to later plans, intentionally): crypto/signer, quickstart, formats, status list, issuer/verifier endpoints, OpenAPI/Swagger. These are Plans 2–8.

**2. Placeholder scan:** No TBD/TODO. The one "fill" markers are in `docs/VENDORING.md` provenance table (actual git revs recorded at vendor time) — that is data to capture, not a code placeholder. Acceptable.

**3. Type consistency:** `Storage` trait methods (`put_kv`, `get_kv`, `delete_kv`, `purge_expired`) are referenced identically in Tasks 5, 7, 8. `AppState { storage: Arc<dyn Storage> }` consistent across Tasks 7–8. `Config` field paths (`server.admin.bind`, `storage.path`, `storage.transaction_ttl_secs`, `verifier.signing_key`) match the model in Task 4. `Cli`/`Command`/`ConfigAction`/`LogFormat` consistent between Tasks 6 and 7.

**Note on ready-check:** `ready` uses `purge_expired(0)` as a cheap DB liveness probe (deletes nothing, since no row has `expires_at <= 0` in practice). Documented inline so it isn't mistaken for a bug.