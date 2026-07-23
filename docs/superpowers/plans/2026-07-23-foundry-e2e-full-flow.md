# Foundry E2E Full-Flow Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real, subprocess-driven end-to-end test that proves `foundry serve` supports issue → verify → revoke → re-verify for an SD-JWT VC credential over genuine HTTP, and close the production gap (no HTTP endpoint serves status list tokens) that this test would otherwise have to fake around.

**Architecture:** A new `GET /statuslists/:id` route (backed by a shared `foundry_core::status_list::sign_status_list_token` helper extracted from the existing CLI command) makes status-list tokens genuinely fetchable over HTTP. A new `#[ignore]`d Cargo integration test (`crates/foundry/tests/e2e_full_flow.rs`) spawns the real `foundry` binary (`quickstart` then `serve`, both with `current_dir` set to a fresh tempdir and pre-selected free ports written into the config before boot), then drives it purely with `reqwest` acting as an admin client, a wallet, and a verifier's relying party, reusing the exact JWT/JWE construction logic already proven in `wallet_issuance.rs`/`wallet_verification.rs`.

**Tech Stack:** Rust, axum, tokio, reqwest (new dev-dependency), josekit, `foundry-sd-jwt-vc`, `openid4vp::core::jwe::JweBuilder`, sqlx/SQLite.

**Reference spec:** `docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md` (read this first — it documents the reasoning behind the port-discovery and status-list-id corrections baked into this plan).

## Global Constraints

- No `.unwrap()`/`.expect()`/`panic!()`/`unreachable!()` in production request-handling paths (`foundry-issuer`, `foundry-verifier`, `foundry::server`) — return typed `Result`s / Axum error responses. Test code (`#[cfg(test)]`, integration test binaries) is exempt.
- `VerificationResult.verified` MUST equal `checks.iter().all(|c| c.passed)` — never hardcoded. Every verification step already pushes a named `CheckResult` (`jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`) — this plan does not change that logic, only proves it end-to-end.
- Policy failures (DCQL mismatch, status revoked/suspended) → HTTP 200 with `verified: false`. Structural/crypto failures → HTTP 400. Network status-fetch failure → HTTP 502. This plan's new route must follow the same typed-error conventions as existing handlers.
- Any new/changed HTTP endpoint must be reflected in the OpenAPI spec (admin or wallet, as appropriate).
- Before considering any task done: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` must all pass (the new e2e test itself stays `#[ignore]`d and is run separately per Task 3+).
- **Adaptation note on TDD granularity:** Tasks 1 and 2 (pure helper function, HTTP route) follow strict red→green TDD. Tasks 3–6 build a single subprocess-driven integration test incrementally — there is no meaningful "watch it fail" state distinct from "doesn't compile yet" for harness/flow code driving a real spawned process, so each of those tasks' acceptance is "write the code, run `cargo test -p foundry --test e2e_full_flow -- --ignored`, confirm it passes with the new step's assertions included."

---

### Task 1: Shared status-list-token signer helper + CLI refactor

**Files:**
- Modify: `crates/foundry-core/src/status_list/mod.rs`
- Modify: `crates/foundry/src/commands.rs:183-251` (the `status_list_token` function)
- Test: `crates/foundry-core/src/status_list/mod.rs` (new `#[test]` in the existing `#[cfg(test)] mod tests` block)

**Interfaces:**
- Produces: `pub fn sign_status_list_token(status_list: &StatusList, sub: String, now_unix: i64, key_path: &str, alg: SignatureAlgorithm, x5c_path: Option<&Path>) -> Result<String, CoreError>` in `foundry_core::status_list` (`x5c_path` takes `&std::path::Path`, not `&str` — a post-Task-1-review fix: an `Option<&str>` parameter forced callers through a lossy/fallible UTF-8 conversion that could silently drop the x5c chain on a non-UTF-8 path instead of erroring) — consumed by Task 2's new HTTP route handler and by this task's refactored `commands.rs::status_list_token`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `crates/foundry-core/src/status_list/mod.rs` (after the existing `use super::*; use crate::error::FormatError;` test imports):

```rust
    #[test]
    fn sign_status_list_token_produces_parseable_jwt_with_expected_sub() {
        use crate::crypto::SignatureAlgorithm;
        use crate::pki::generate_ec_key;

        let km = generate_ec_key(SignatureAlgorithm::Es256).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, &km.private_pem).unwrap();

        let list = StatusList::build(&[0, 1, 0], 2, None).unwrap();
        let token = sign_status_list_token(
            &list,
            "https://issuer.example.com/statuslists/1".to_string(),
            1_700_000_000,
            key_path.to_str().unwrap(),
            SignatureAlgorithm::Es256,
            None,
        )
        .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "must be a compact JWS");
        let payload: Value = serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["sub"], "https://issuer.example.com/statuslists/1");
        assert_eq!(payload["iat"], 1_700_000_000);
        assert_eq!(payload["status_list"]["bits"], 2);
        assert!(payload["status_list"]["lst"].is_string());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p foundry-core sign_status_list_token_produces_parseable_jwt_with_expected_sub`
Expected: FAIL with `cannot find function 'sign_status_list_token' in this scope` (compile error).

- [ ] **Step 3: Implement `sign_status_list_token`**

At the top of `crates/foundry-core/src/status_list/mod.rs`, change:

```rust
use crate::crypto::Signer;
use crate::error::FormatError;
use crate::trust::{cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
```

to:

```rust
use crate::crypto::{FileSigner, SignatureAlgorithm, Signer};
use crate::error::{CoreError, CryptoError, FormatError};
use crate::trust::{build_x5c, cert_ec_public_coords, parse_cert_pem, validate_chain, TrustStore};
```

Then add this function directly after `build_status_list_token` (which ends with `Ok(format!("{signing_input}.{}", B64URL.encode(signature)))\n}`):

```rust
/// Sign a Status List Token (`statuslist+jwt`) for an already-loaded `status_list`,
/// resolving the signer from `key_path`/`alg` and, if given, an x5c chain from
/// `x5c_path`. `key_path`/`x5c_path` must already be resolved to real filesystem
/// paths by the caller — this function has no config-relative-path knowledge, so
/// both the CLI (`foundry status-list token`) and the `/statuslists/:id` HTTP
/// route can share it while resolving paths their own way.
pub fn sign_status_list_token(
    status_list: &StatusList,
    sub: String,
    now_unix: i64,
    key_path: &str,
    alg: SignatureAlgorithm,
    x5c_path: Option<&std::path::Path>,
) -> Result<String, CoreError> {
    let signer = FileSigner::from_pem_file(key_path, alg)?;
    let x5c = match x5c_path {
        Some(path) => {
            let pem_bytes = std::fs::read(path).map_err(|source| CryptoError::KeyRead {
                path: path.display().to_string(),
                source,
            })?;
            Some(build_x5c(&[pem_bytes])?)
        }
        None => None,
    };
    let claims = StatusListTokenClaims {
        sub,
        iat: now_unix,
        exp: Some(now_unix + 86400),
        ttl: None,
    };
    Ok(build_status_list_token(claims, status_list, &signer, x5c)?)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p foundry-core sign_status_list_token_produces_parseable_jwt_with_expected_sub`
Expected: PASS (1 passed).

- [ ] **Step 5: Refactor `commands.rs::status_list_token` to use the shared helper**

In `crates/foundry/src/commands.rs`, the `status_list_token` function currently builds the signer, x5c, and token manually (lines ~183-251). Replace the body from where `let status_list = persistent_list.to_status_list(None)?;` through the final `let token = build_status_list_token(claims, &status_list, &signer, x5c)?;` with a call to the shared helper. Concretely, replace:

```rust
    let status_list = persistent_list.to_status_list(None)?;

    let base_url = cfg
        .issuer
        .status_list
        .public_base_url
        .as_deref()
        .unwrap_or(&cfg.issuer.credential_issuer);
    let sub = format!("{}/{}", base_url.trim_end_matches('/'), credential_type);

    let key_name = cfg
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("issuer.status_list.signing_key is not configured"))?;
    let key_entry = cfg.keys.get(key_name).ok_or_else(|| {
        anyhow::anyhow!("key '{key_name}' referenced by status_list signing_key not found")
    })?;

    let key_file = base_dir.join(&key_entry.private_key);
    let alg = key_entry.alg.parse()?;
    let signer = FileSigner::from_pem_file(&key_file.to_string_lossy(), alg)?;

    let x5c = if let Some(x5c_rel) = &key_entry.x5c {
        let cert_file = base_dir.join(x5c_rel);
        let pem_bytes = std::fs::read(&cert_file)
            .with_context(|| format!("reading x5c cert from {}", cert_file.display()))?;
        Some(foundry_core::trust::build_x5c(&[pem_bytes])?)
    } else {
        None
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("getting system time")?
        .as_secs() as i64;

    let claims = StatusListTokenClaims {
        sub,
        iat: now,
        exp: Some(now + 86400),
        ttl: None,
    };

    let token = build_status_list_token(claims, &status_list, &signer, x5c)?;
    println!("{token}");
    Ok(())
```

with:

```rust
    let status_list = persistent_list.to_status_list(None)?;

    let base_url = cfg
        .issuer
        .status_list
        .public_base_url
        .as_deref()
        .unwrap_or(&cfg.issuer.credential_issuer);
    let sub = format!("{}/{}", base_url.trim_end_matches('/'), credential_type);

    let key_name = cfg
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("issuer.status_list.signing_key is not configured"))?;
    let key_entry = cfg.keys.get(key_name).ok_or_else(|| {
        anyhow::anyhow!("key '{key_name}' referenced by status_list signing_key not found")
    })?;

    let key_file = base_dir.join(&key_entry.private_key);
    let alg = key_entry.alg.parse()?;
    let x5c_file = key_entry.x5c.as_ref().map(|rel| base_dir.join(rel));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("getting system time")?
        .as_secs() as i64;

    let token = foundry_core::status_list::sign_status_list_token(
        &status_list,
        sub,
        now,
        &key_file.to_string_lossy(),
        alg,
        x5c_file.as_deref(),
    )?;
    println!("{token}");
    Ok(())
```

Then remove the now-unused imports in `commands.rs`: `FileSigner` from the `use foundry_core::crypto::{FileSigner, SignatureAlgorithm};` line (keep `SignatureAlgorithm` if still used elsewhere in the file — check with `grep -n "FileSigner\|SignatureAlgorithm" crates/foundry/src/commands.rs` first) and `build_status_list_token` from the `foundry_core::status_list::{...}` import line if no longer referenced.

- [ ] **Step 6: Run full test suite to confirm nothing broke**

Run: `cargo test -p foundry-core -p foundry`
Expected: PASS, including the existing `crates/foundry/tests/cli_status_list.rs` (unchanged CLI behavior/output format).

- [ ] **Step 7: Commit**

```bash
git add crates/foundry-core/src/status_list/mod.rs crates/foundry/src/commands.rs
git commit -m "refactor: extract sign_status_list_token shared helper from CLI command"
```

---

### Task 2: `GET /statuslists/:id` HTTP route + OpenAPI registration

**Files:**
- Modify: `crates/foundry/src/server.rs` (add `status_list_handler`, register route in `wallet_router`)
- Modify: `crates/foundry/src/openapi.rs` (register the new path in `WalletApiDoc`)
- Modify: `crates/foundry/tests/openapi_endpoints.rs` (add `/statuslists/{id}` to the expected wallet paths list)
- Create: `crates/foundry/tests/wallet_status_list_route.rs`

**Interfaces:**
- Consumes: `foundry_core::status_list::{load_status_list, sign_status_list_token}` (Task 1), `foundry_core::crypto::SignatureAlgorithm` (`FromStr`).
- Produces: `status_list_handler` in `crate::server`, reachable at `GET /statuslists/:id` on the wallet-facing listener.

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry/tests/wallet_status_list_route.rs`:

```rust
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry::server::{wallet_router, AppState};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, IssuerConfig, KeyEntry, Mode, ServerConfig,
    StatusListConfig, StorageConfig, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::SignatureAlgorithm;
use foundry_core::status_list::{save_status_list, PersistentStatusList, StatusValue};
use foundry_core::storage::SqliteStorage;
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

async fn setup(status_list_enabled: bool) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let key_path = dir.path().join("statuslist.pem");
    let km = foundry_core::pki::generate_ec_key(SignatureAlgorithm::Es256).unwrap();
    std::fs::write(&key_path, &km.private_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "statuslist_signer".to_string(),
        KeyEntry {
            private_key: key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );

    let config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://issuer.example.com".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: None,
                api_key_env: None,
                swagger_ui_enabled: true,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().unwrap().to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: Vec::new(),
        issuer: IssuerConfig {
            credential_issuer: "https://issuer.example.com".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Optional,
            },
            key_attestation: AttestationMode {
                mode: Mode::Optional,
            },
            status_list: StatusListConfig {
                enabled: status_list_enabled,
                signing_key: Some("statuslist_signer".to_string()),
                list_size: Some(128),
                public_base_url: Some("https://issuer.example.com/statuslists".to_string()),
            },
        },
        credential_types: vec![],
        verifier: VerifierConfig {
            client_id_scheme: "x509_san_dns".to_string(),
            signing_key: "statuslist_signer".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
        },
    };

    (
        AppState {
            storage: Arc::new(storage),
            config: Arc::new(config),
        },
        dir,
    )
}

#[tokio::test]
async fn statuslists_route_returns_signed_token_for_existing_list() {
    let (state, _dir) = setup(true).await;

    let mut list = PersistentStatusList::new("1", 128, 2);
    list.set_status(5, StatusValue::Invalid).unwrap();
    save_status_list(state.storage.as_ref(), &list).await.unwrap();

    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/statuslists/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/statuslist+jwt"
    );

    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let token = String::from_utf8(body.to_vec()).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(payload["sub"], "https://issuer.example.com/statuslists/1");
}

#[tokio::test]
async fn statuslists_route_404s_for_unknown_id() {
    let (state, _dir) = setup(true).await;
    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/statuslists/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn statuslists_route_404s_when_status_list_disabled() {
    let (state, _dir) = setup(false).await;

    let list = PersistentStatusList::new("1", 128, 2);
    save_status_list(state.storage.as_ref(), &list).await.unwrap();

    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/statuslists/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p foundry --test wallet_status_list_route`
Expected: FAIL (compile error — `/statuslists/1` has no route yet; `wallet_router` builds but returns 404 for the unmatched route today, so `statuslists_route_404s_for_unknown_id` and `_disabled` would incidentally pass while `statuslists_route_returns_signed_token_for_existing_list` fails on `assert_eq!(res.status(), StatusCode::OK)` — confirm at least that one fails).

- [ ] **Step 3: Implement the route handler**

In `crates/foundry/src/server.rs`, add this function immediately after `post_response_handler` (which ends just before `pub fn spawn_sweeper`):

```rust
#[utoipa::path(
    get,
    path = "/statuslists/{id}",
    responses(
        (status = 200, description = "Signed Status List Token JWT", content_type = "application/statuslist+jwt", body = String),
        (status = 404)
    )
)]
async fn status_list_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    if !state.config.issuer.status_list.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    let persistent = foundry_core::status_list::load_status_list(state.storage.as_ref(), &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let persistent = match persistent {
        Some(p) => p,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let status_list = persistent
        .to_status_list(None)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let key_name = state
        .config
        .issuer
        .status_list
        .signing_key
        .as_deref()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let key_entry = state
        .config
        .keys
        .get(key_name)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let alg: foundry_core::crypto::SignatureAlgorithm = key_entry
        .alg
        .parse()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let base_url = state
        .config
        .issuer
        .status_list
        .public_base_url
        .as_deref()
        .unwrap_or(&state.config.issuer.credential_issuer);
    let sub = format!("{}/{}", base_url.trim_end_matches('/'), id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let token = foundry_core::status_list::sign_status_list_token(
        &status_list,
        sub,
        now,
        &key_entry.private_key,
        alg,
        key_entry.x5c.as_deref().map(std::path::Path::new),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/statuslist+jwt",
        )],
        token,
    ))
}
```

Then register the route in `wallet_router` — change:

```rust
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler));
```

to:

```rust
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler))
        .route("/statuslists/:id", get(status_list_handler));
```

- [ ] **Step 4: Register the route in the wallet OpenAPI spec**

In `crates/foundry/src/openapi.rs`, in the `WalletApiDoc` derive's `paths(...)` list, change:

```rust
        crate::server::get_request_object_handler,
        crate::server::post_response_handler,
    ),
```

to:

```rust
        crate::server::get_request_object_handler,
        crate::server::post_response_handler,
        crate::server::status_list_handler,
    ),
```

- [ ] **Step 5: Add the new path to the wallet OpenAPI endpoint assertion test**

In `crates/foundry/tests/openapi_endpoints.rs`, in the `for expected in [...]` list inside `wallet_openapi_json_endpoint_returns_valid_spec`, add `"/statuslists/{id}"` alongside the existing entries:

```rust
    for expected in [
        "/.well-known/openid-credential-issuer",
        "/.well-known/oauth-authorization-server",
        "/token",
        "/nonce",
        "/credential",
        "/vp/request/{id}",
        "/vp/response/{id}",
        "/statuslists/{id}",
    ] {
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p foundry --test wallet_status_list_route --test openapi_endpoints`
Expected: PASS (all tests green).

- [ ] **Step 7: Run full workspace gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/src/openapi.rs crates/foundry/tests/openapi_endpoints.rs crates/foundry/tests/wallet_status_list_route.rs
git commit -m "feat: serve GET /statuslists/:id status list tokens over HTTP"
```

---

### Task 3: E2E harness (process spawning, port discovery, readiness, teardown) + smoke test

**Files:**
- Modify: `crates/foundry/Cargo.toml` (add `reqwest` dev-dependency)
- Modify: `crates/foundry/src/server.rs` (log actual bound addresses instead of configured strings)
- Create: `crates/foundry/tests/e2e_full_flow.rs`

**Interfaces:**
- Produces (within `e2e_full_flow.rs`, consumed by Tasks 4-6): `async fn spawn_server() -> (ServerGuard, tempfile::TempDir, u16, u16)` returning `(guard, tempdir, admin_port, wallet_port)`; `struct ServerGuard { fn dump_logs(&self) -> String }` (kills the child on `Drop`).

- [ ] **Step 1: Add the `reqwest` dev-dependency**

In `crates/foundry/Cargo.toml`, add to `[dev-dependencies]`:

```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

- [ ] **Step 2: Fix `serve()` to log the actual bound socket address**

In `crates/foundry/src/server.rs`, inside `pub async fn serve`, change:

```rust
    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    let wallet_listener = tokio::net::TcpListener::bind(&cfg.server.wallet_facing.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    tracing::info!(bind = %cfg.server.wallet_facing.bind, "foundry wallet-facing server listening");
```

to:

```rust
    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    let wallet_listener = tokio::net::TcpListener::bind(&cfg.server.wallet_facing.bind).await?;
    let admin_bound_addr = admin_listener.local_addr()?;
    let wallet_bound_addr = wallet_listener.local_addr()?;
    tracing::info!(bind = %admin_bound_addr, "foundry admin server listening");
    tracing::info!(bind = %wallet_bound_addr, "foundry wallet-facing server listening");
```

This is a genuine, independent production-logging correctness fix (the log now reports where the server actually bound, not the configured string — matters whenever `bind` uses `:0` or a hostname) and this task's e2e smoke test uses it as a secondary sanity check.

- [ ] **Step 3: Write the harness in a new e2e test file**

Create `crates/foundry/tests/e2e_full_flow.rs`:

```rust
//! Real subprocess end-to-end test: boots the actual `foundry` binary
//! (`quickstart` then `serve`) and drives it purely over HTTP as a wallet,
//! admin client, and verifier's relying party. See
//! docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md for the
//! design rationale, including two corrections found during planning:
//! probe-and-release port discovery (not log-parsing) is required because the
//! server's own `issuer.status_list.public_base_url` must be genuinely
//! reachable at boot time; and the status-list storage key is always the
//! literal `"1"` today (see `foundry-issuer/src/credential.rs`), not the
//! credential type id.
//!
//! Run with: `cargo test -p foundry --test e2e_full_flow -- --ignored`

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bind to `127.0.0.1:0`, read the OS-assigned port, then drop the listener
/// to free it. Standard probe-and-release: accepts a small, unavoidable race
/// window in exchange for knowing the port before the config is written.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read bound port").port()
}

/// Keeps the spawned `foundry serve` child alive and kills it on drop, even
/// if the test panics mid-way.
struct ServerGuard {
    child: Child,
    log_lines: Arc<Mutex<Vec<String>>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl ServerGuard {
    fn dump_logs(&self) -> String {
        self.log_lines.lock().unwrap().join("\n")
    }

    /// Poll the captured logs (up to `timeout`) for a substring, so a small
    /// delay in the background reader threads catching up to a fast-printing
    /// child doesn't make this check flaky.
    async fn wait_for_log_containing(&self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self.dump_logs().contains(needle) {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "expected server logs to contain '{needle}'; captured logs:\n{}",
                    self.dump_logs()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Rewrite the `quickstart`-generated config in place: bind both listeners to
/// pre-selected free ports, and point `issuer.status_list.public_base_url` at
/// the real wallet-facing port (required so the server's own status-list
/// HTTP fetch during verification can actually reach itself).
fn rewrite_config_for_e2e(config_path: &Path, admin_port: u16, wallet_port: u16) {
    let original = std::fs::read_to_string(config_path).expect("read generated config.yaml");
    let rewritten = original
        .replace(
            "bind: 0.0.0.0:8443\n",
            &format!("bind: 127.0.0.1:{wallet_port}\n"),
        )
        .replace(
            "bind: 127.0.0.1:9000\n",
            &format!("bind: 127.0.0.1:{admin_port}\n"),
        )
        .replace(
            "public_base_url: https://localhost:8443/statuslists\n",
            &format!("public_base_url: http://127.0.0.1:{wallet_port}/statuslists\n"),
        );
    assert_ne!(
        original, rewritten,
        "expected all three quickstart config lines to be present and rewritten \
         (bind: 0.0.0.0:8443 / bind: 127.0.0.1:9000 / status_list public_base_url) — \
         if this fails, the quickstart config template in commands.rs changed and \
         this rewrite needs updating"
    );
    std::fs::write(config_path, rewritten).expect("write rewritten config.yaml");
}

/// Spawn the real `foundry` binary to run `quickstart`, then `serve`, against
/// pre-selected free ports, with `current_dir` set so the generated
/// config's relative key/db paths resolve correctly (mirrors how `README.md`
/// documents running `foundry serve` from the directory containing its
/// `config.yaml`/`keys/`/`trust/`). Polls `/ready` before returning.
async fn spawn_server() -> (ServerGuard, tempfile::TempDir, u16, u16) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let binary = env!("CARGO_BIN_EXE_foundry");

    let quickstart_status = Command::new(binary)
        .args(["quickstart", "--dir", ".", "--out-config", "config.yaml"])
        .current_dir(dir.path())
        .status()
        .expect("spawn foundry quickstart");
    assert!(quickstart_status.success(), "foundry quickstart failed");

    let config_path = dir.path().join("config.yaml");
    let admin_port = free_port();
    let wallet_port = free_port();
    rewrite_config_for_e2e(&config_path, admin_port, wallet_port);

    let mut child = Command::new(binary)
        .args(["--log-format", "json", "serve", "--config", "config.yaml"])
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn foundry serve");

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let log_lines = Arc::new(Mutex::new(Vec::new()));

    // Drain both streams continuously in background OS threads so the child
    // never blocks on a full pipe buffer once the test stops actively
    // reading (bounded to the last 500 lines to avoid unbounded growth).
    for (name, stream) in [
        ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
        ("stderr", Box::new(stderr)),
    ] {
        let log_lines = log_lines.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stream);
            for line in reader.lines().map_while(Result::ok) {
                let mut lines = log_lines.lock().unwrap();
                lines.push(format!("[{name}] {line}"));
                if lines.len() > 500 {
                    lines.remove(0);
                }
            }
        });
    }

    let guard = ServerGuard {
        child,
        log_lines: log_lines.clone(),
    };

    let client = reqwest::Client::new();
    let ready_url = format!("http://127.0.0.1:{admin_port}/ready");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = client.get(&ready_url).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        if Instant::now() > deadline {
            panic!(
                "server did not become ready in time; captured logs:\n{}",
                guard.dump_logs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Secondary sanity assertion (not the port-discovery mechanism itself):
    // the server's own "listening" log lines should report the same ports we
    // pre-selected, proving the Step 2 logging fix reports the real bound
    // address rather than echoing the configured string verbatim.
    guard
        .wait_for_log_containing(&format!("127.0.0.1:{admin_port}"), Duration::from_secs(2))
        .await;
    guard
        .wait_for_log_containing(&format!("127.0.0.1:{wallet_port}"), Duration::from_secs(2))
        .await;

    (guard, dir, admin_port, wallet_port)
}

#[tokio::test]
#[ignore]
async fn full_flow_issue_verify_revoke_reverify() {
    let (guard, _dir, admin_port, wallet_port) = spawn_server().await;
    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let wallet_base = format!("http://127.0.0.1:{wallet_port}");

    // Smoke check for this task: the server is up and reachable on both
    // pre-selected ports. Tasks 4-6 extend this test with the actual flow.
    let client = reqwest::Client::new();
    let health = client
        .get(format!("{admin_base}/health"))
        .send()
        .await
        .expect("GET /health");
    assert!(health.status().is_success(), "logs:\n{}", guard.dump_logs());

    let metadata = client
        .get(format!(
            "{wallet_base}/.well-known/openid-credential-issuer"
        ))
        .send()
        .await
        .expect("GET /.well-known/openid-credential-issuer");
    assert!(
        metadata.status().is_success(),
        "logs:\n{}",
        guard.dump_logs()
    );
}
```

- [ ] **Step 4: Run the smoke test**

Run: `cargo test -p foundry --test e2e_full_flow -- --ignored`
Expected: PASS (1 passed) — this proves `quickstart` + `serve` boot for real, on dynamically-selected ports, and both listeners respond.

- [ ] **Step 5: Run full workspace gates (the ignored test does not run here, but must still compile)**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/Cargo.toml crates/foundry/src/server.rs crates/foundry/tests/e2e_full_flow.rs
git commit -m "test: add e2e harness (real subprocess boot, dynamic ports) with smoke test"
```

---

### Task 4: Offer creation + SD-JWT VC issuance step

**Files:**
- Modify: `crates/foundry/tests/e2e_full_flow.rs`

**Interfaces:**
- Consumes: `spawn_server()` (Task 3).
- Produces: `struct IssuedCredential { compact: String, status_idx: u64, status_uri: String, holder_signer: foundry_core::crypto::FileSigner }`; `async fn create_offer_and_issue_credential(client: &reqwest::Client, admin_base: &str, wallet_base: &str) -> IssuedCredential` — consumed by Task 5's `run_verification`.

- [ ] **Step 1: Add imports**

At the top of `crates/foundry/tests/e2e_full_flow.rs`, add:

```rust
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::KeyPair as _;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
```

- [ ] **Step 2: Add the proof-JWT builder, `IssuedCredential`, and the issuance flow function**

Add after the `spawn_server` function and before `full_flow_issue_verify_revoke_reverify`:

```rust
/// Build an OpenID4VCI key-proof JWT (`openid4vci-proof+jwt`) bound to
/// `c_nonce` and `issuer`. Ported from
/// `crates/foundry/tests/wallet_issuance.rs::create_proof`.
fn create_proof(c_nonce: &str, issuer: &str) -> (serde_json::Value, EcKeyPair) {
    let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let mut public_jwk = keypair.to_jwk_public_key();
    public_jwk.set_algorithm("ES256");

    let mut header = JwsHeader::new();
    header.set_token_type("openid4vci-proof+jwt");
    header
        .set_claim("jwk", Some(serde_json::to_value(&public_jwk).unwrap()))
        .unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim("aud", Some(serde_json::json!(issuer)))
        .unwrap();
    payload
        .set_claim("nonce", Some(serde_json::json!(c_nonce)))
        .unwrap();

    let private_jwk = keypair.to_jwk_private_key();
    let signer = ES256.signer_from_jwk(&private_jwk).unwrap();
    let jwt_str = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (
        serde_json::json!({ "proof_type": "jwt", "jwt": jwt_str }),
        keypair,
    )
}

/// An issued SD-JWT VC credential plus what later verification/revocation
/// steps need from it: its status-list index/uri, and the holder signing key
/// bound in its `cnf` claim (needed to build a matching KB-JWT later).
struct IssuedCredential {
    compact: String,
    status_idx: u64,
    status_uri: String,
    holder_signer: FileSigner,
}

/// Create a credential offer via the admin API, then perform the full
/// OpenID4VCI pre-authorized_code flow as the wallet: `/token` → `/nonce` →
/// `/credential`. Asserts the disclosed claims match what was requested and
/// returns everything later steps need. Ported (offer/token/nonce/credential
/// shapes) from `crates/foundry/tests/wallet_issuance.rs`.
async fn create_offer_and_issue_credential(
    client: &reqwest::Client,
    admin_base: &str,
    wallet_base: &str,
) -> IssuedCredential {
    let offer_res = client
        .post(format!("{admin_base}/admin/issuance/offers"))
        .bearer_auth("dev-admin-key")
        .json(&serde_json::json!({
            "credential_type_id": "pid",
            "claims": { "given_name": "Alice", "birthdate": "1990-01-01" },
            "tx_code_required": false
        }))
        .send()
        .await
        .expect("POST /admin/issuance/offers");
    assert_eq!(offer_res.status(), reqwest::StatusCode::OK);
    let offer_json: serde_json::Value = offer_res.json().await.unwrap();
    let pre_auth_code = offer_json["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("pre-authorized_code present")
        .to_string();

    let token_form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={pre_auth_code}"
    );
    let token_res = client
        .post(format!("{wallet_base}/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(token_form)
        .send()
        .await
        .expect("POST /token");
    assert_eq!(token_res.status(), reqwest::StatusCode::OK);
    let token_json: serde_json::Value = token_res.json().await.unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    let nonce_res = client
        .post(format!("{wallet_base}/nonce"))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("POST /nonce");
    assert_eq!(nonce_res.status(), reqwest::StatusCode::OK);
    let nonce_json: serde_json::Value = nonce_res.json().await.unwrap();
    let c_nonce = nonce_json["c_nonce"].as_str().unwrap().to_string();

    // `aud` must equal the config's `issuer.credential_issuer` value
    // (`https://localhost:8443` from the quickstart template — a metadata
    // label only, never dereferenced over the network; see the design doc's
    // non-goals), not the real bound socket address.
    let (proof_json, holder_keypair) = create_proof(&c_nonce, "https://localhost:8443");
    let cred_res = client
        .post(format!("{wallet_base}/credential"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "credential_configuration_id": "pid",
            "format": "dc+sd-jwt",
            "proof": proof_json,
        }))
        .send()
        .await
        .expect("POST /credential");
    assert_eq!(cred_res.status(), reqwest::StatusCode::OK);
    let cred_json: serde_json::Value = cred_res.json().await.unwrap();
    let compact = cred_json["credential"].as_str().unwrap().to_string();
    assert!(
        compact.contains('~'),
        "SD-JWT VC compact serialization must contain '~' separators"
    );

    // Parse the issuer-signed JWT (first segment before '~') for the status claim.
    let issuer_jwt = compact.split('~').next().unwrap();
    let jwt_parts: Vec<&str> = issuer_jwt.split('.').collect();
    assert_eq!(jwt_parts.len(), 3, "issuer-signed JWT must be a compact JWS");
    let payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(jwt_parts[1]).unwrap()).unwrap();
    let status_idx = payload["status"]["status_list"]["idx"]
        .as_u64()
        .expect("status.status_list.idx present");
    let status_uri = payload["status"]["status_list"]["uri"]
        .as_str()
        .expect("status.status_list.uri present")
        .to_string();

    // `given_name`/`birthdate` are selectively disclosable in the quickstart
    // `pid` credential type, so they live in disclosure segments
    // (`<jwt>~<d1>~<d2>~...~`), not directly in the issuer JWT payload.
    let mut disclosed: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for seg in compact.split('~').skip(1).filter(|s| !s.is_empty()) {
        let decoded = B64URL.decode(seg).expect("disclosure is valid base64url");
        let arr: serde_json::Value =
            serde_json::from_slice(&decoded).expect("disclosure is a JSON array");
        let arr = arr.as_array().expect("disclosure is [salt, name, value]");
        assert_eq!(arr.len(), 3, "disclosure must be [salt, claim_name, claim_value]");
        disclosed.insert(arr[1].as_str().unwrap().to_string(), arr[2].clone());
    }
    assert_eq!(disclosed.get("given_name"), Some(&serde_json::json!("Alice")));
    assert_eq!(
        disclosed.get("birthdate"),
        Some(&serde_json::json!("1990-01-01"))
    );

    let holder_signer =
        FileSigner::from_pem(&holder_keypair.to_pem_private_key(), SignatureAlgorithm::Es256)
            .unwrap();

    IssuedCredential {
        compact,
        status_idx,
        status_uri,
        holder_signer,
    }
}
```

- [ ] **Step 3: Wire it into the test body**

Change `full_flow_issue_verify_revoke_reverify` to:

```rust
#[tokio::test]
#[ignore]
async fn full_flow_issue_verify_revoke_reverify() {
    let (guard, _dir, admin_port, wallet_port) = spawn_server().await;
    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let wallet_base = format!("http://127.0.0.1:{wallet_port}");
    let client = reqwest::Client::new();

    let issued = create_offer_and_issue_credential(&client, &admin_base, &wallet_base).await;
    assert!(!issued.compact.is_empty(), "logs:\n{}", guard.dump_logs());
}
```

(Remove the Task 3 smoke-check `/health` and metadata GETs — the offer/token/nonce/credential calls above already prove both listeners are reachable and functioning.)

- [ ] **Step 4: Run the test**

Run: `cargo test -p foundry --test e2e_full_flow -- --ignored`
Expected: PASS (1 passed) — proves real end-to-end SD-JWT VC issuance.

- [ ] **Step 5: Run full workspace gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/tests/e2e_full_flow.rs
git commit -m "test: e2e — real offer creation and SD-JWT VC issuance over HTTP"
```

---

### Task 5: Verification happy path

**Files:**
- Modify: `crates/foundry/tests/e2e_full_flow.rs`

**Interfaces:**
- Consumes: `IssuedCredential` (Task 4), `foundry_verifier::{CreateVerificationResponse, VerificationResult, VerificationTransaction, VerificationState}` (already a regular dependency of the `foundry` crate).
- Produces: `async fn run_verification(client: &reqwest::Client, admin_base: &str, wallet_base: &str, issued: &IssuedCredential) -> VerificationResult` — consumed again by Task 6 for the revoked re-check.

- [ ] **Step 1: Add imports**

At the top of `crates/foundry/tests/e2e_full_flow.rs`, add:

```rust
use foundry_sd_jwt_vc::builder::attach_kb_jwt;
use foundry_verifier::{
    CreateVerificationResponse, VerificationResult, VerificationState, VerificationTransaction,
};
use openid4vp::core::jwe::JweBuilder;
```

- [ ] **Step 2: Add `run_verification`**

Add after `create_offer_and_issue_credential`:

```rust
/// Create a verification request via the admin API (DCQL matching the
/// issued `pid` credential's vct and claims), then respond as the wallet:
/// attach a KB-JWT (signed by the same holder key bound in the credential's
/// `cnf` claim) to the already-issued credential, encrypt it into a JWE, and
/// submit it. Returns the decoded `VerificationResult`. Cross-checks the
/// admin-facing transaction record too. Ported (request/response shapes,
/// KB-JWT/JWE construction) from
/// `crates/foundry/tests/wallet_verification.rs::full_verification_flow_end_to_end`.
async fn run_verification(
    client: &reqwest::Client,
    admin_base: &str,
    wallet_base: &str,
    issued: &IssuedCredential,
) -> VerificationResult {
    let create_res = client
        .post(format!("{admin_base}/admin/verification/requests"))
        .bearer_auth("dev-admin-key")
        .json(&serde_json::json!({
            "dcql_query": {
                "credentials": [{
                    "id": "c1",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://localhost:8443/vct/pid"] },
                    "claims": [
                        { "path": ["given_name"] },
                        { "path": ["birthdate"] }
                    ]
                }]
            },
            "transport": "request_uri"
        }))
        .send()
        .await
        .expect("POST /admin/verification/requests");
    assert_eq!(create_res.status(), reqwest::StatusCode::OK);
    let create_resp: CreateVerificationResponse = create_res.json().await.unwrap();
    let verification_id = create_resp.verification_id;

    let get_res = client
        .get(format!("{wallet_base}/vp/request/{verification_id}"))
        .send()
        .await
        .expect("GET /vp/request/:id");
    assert_eq!(get_res.status(), reqwest::StatusCode::OK);
    let jws_str = get_res.text().await.unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    assert_eq!(parts.len(), 3);
    let request_object: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    let presentation =
        attach_kb_jwt(issued.compact.clone(), &issued.holder_signer, &client_id, &nonce)
            .expect("attach_kb_jwt");
    let jwe_str = JweBuilder::new()
        .payload(serde_json::json!({ "vp_token": presentation }))
        .recipient_key_json(&ephem_public_jwk)
        .unwrap()
        .alg("ECDH-ES")
        .enc("A128GCM")
        .build()
        .unwrap();

    let post_res = client
        .post(format!("{wallet_base}/vp/response/{verification_id}"))
        .header("content-type", "text/plain")
        .body(jwe_str)
        .send()
        .await
        .expect("POST /vp/response/:id");
    assert_eq!(post_res.status(), reqwest::StatusCode::OK);
    let result: VerificationResult = post_res.json().await.unwrap();

    let tx_res = client
        .get(format!(
            "{admin_base}/admin/verification/requests/{verification_id}"
        ))
        .bearer_auth("dev-admin-key")
        .send()
        .await
        .expect("GET /admin/verification/requests/:id");
    assert_eq!(tx_res.status(), reqwest::StatusCode::OK);
    let tx: VerificationTransaction = tx_res.json().await.unwrap();
    assert_eq!(tx.state, VerificationState::Verified);

    result
}
```

- [ ] **Step 3: Wire it into the test body (happy path assertions)**

Change the test body to:

```rust
#[tokio::test]
#[ignore]
async fn full_flow_issue_verify_revoke_reverify() {
    let (guard, _dir, admin_port, wallet_port) = spawn_server().await;
    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let wallet_base = format!("http://127.0.0.1:{wallet_port}");
    let client = reqwest::Client::new();

    let issued = create_offer_and_issue_credential(&client, &admin_base, &wallet_base).await;

    let happy = run_verification(&client, &admin_base, &wallet_base, &issued).await;
    assert!(
        happy.verified,
        "happy-path checks={:?} logs={}",
        happy.checks,
        guard.dump_logs()
    );
    for check in &happy.checks {
        assert!(
            check.passed,
            "check {} unexpectedly failed: {:?}",
            check.check, check.detail
        );
    }
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p foundry --test e2e_full_flow -- --ignored`
Expected: PASS (1 passed) — proves the real, live `status_check` succeeds because `/statuslists/1` (Task 2) is genuinely reachable at the port the credential's embedded `status.status_list.uri` points at (Task 3's config rewrite).

- [ ] **Step 5: Run full workspace gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/tests/e2e_full_flow.rs
git commit -m "test: e2e — real OpenID4VP verification happy path over HTTP"
```

---

### Task 6: Revoke + re-verify negative path (completes the test)

**Files:**
- Modify: `crates/foundry/tests/e2e_full_flow.rs`

**Interfaces:**
- Consumes: `IssuedCredential.status_idx`/`status_uri` (Task 4), `run_verification` (Task 5).

- [ ] **Step 1: Extend the test body**

Change the test body's final section to:

```rust
#[tokio::test]
#[ignore]
async fn full_flow_issue_verify_revoke_reverify() {
    let (guard, dir, admin_port, wallet_port) = spawn_server().await;
    let admin_base = format!("http://127.0.0.1:{admin_port}");
    let wallet_base = format!("http://127.0.0.1:{wallet_port}");
    let client = reqwest::Client::new();

    let issued = create_offer_and_issue_credential(&client, &admin_base, &wallet_base).await;

    let happy = run_verification(&client, &admin_base, &wallet_base, &issued).await;
    assert!(
        happy.verified,
        "happy-path checks={:?} logs={}",
        happy.checks,
        guard.dump_logs()
    );
    for check in &happy.checks {
        assert!(
            check.passed,
            "check {} unexpectedly failed: {:?}",
            check.check, check.detail
        );
    }

    // Revoke: the status URI's final path segment is the storage-key `id`
    // to revoke (today always the literal "1" — see credential.rs and the
    // design doc's finding — derived here from the credential rather than
    // hardcoded, so this stays correct if that ever changes).
    let status_id = issued
        .status_uri
        .rsplit('/')
        .next()
        .expect("status uri has a path segment");
    let db_path = dir.path().join("foundry.db");
    let revoke_status = std::process::Command::new(env!("CARGO_BIN_EXE_foundry"))
        .args([
            "status-list",
            "set",
            "--db",
            db_path.to_str().unwrap(),
            "--credential-type",
            status_id,
            "--index",
            &issued.status_idx.to_string(),
            "--status",
            "revoked",
        ])
        .status()
        .expect("spawn foundry status-list set");
    assert!(revoke_status.success(), "foundry status-list set failed");

    // Fresh verification request/response (responses can't be resubmitted —
    // see wallet_verification.rs::resubmitting_a_verification_response_is_rejected).
    let revoked = run_verification(&client, &admin_base, &wallet_base, &issued).await;
    assert!(
        !revoked.verified,
        "revoked credential must not verify; checks={:?}",
        revoked.checks
    );
    let status_check = revoked
        .checks
        .iter()
        .find(|c| c.check == "status_check")
        .expect("status_check present");
    assert!(
        !status_check.passed,
        "status_check must fail after revocation"
    );
    for check in &revoked.checks {
        if check.check != "status_check" {
            assert!(
                check.passed,
                "unrelated check {} should still pass after revocation: {:?}",
                check.check, check.detail
            );
        }
    }
}
```

Note `run_verification`'s existing `assert_eq!(tx.state, VerificationState::Verified)` still holds for the revoked case too — `VerificationState::Verified` means "a verification attempt completed" (state machine progress), not "passed"; the actual pass/fail signal is `VerificationResult.verified` and its `checks`, which this step asserts separately. If this assertion turns out to be `VerificationState::Failed` instead when run against real code (rather than `Verified`), adjust `run_verification`'s cross-check to assert `matches!(tx.state, VerificationState::Verified | VerificationState::Failed)` instead of a single fixed variant, and note which one it actually is.

- [ ] **Step 2: Run the test**

Run: `cargo test -p foundry --test e2e_full_flow -- --ignored`
Expected: PASS (1 passed) — the full issue → verify → revoke → re-verify lifecycle now runs end-to-end against the real binary.

- [ ] **Step 3: Run full workspace gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/tests/e2e_full_flow.rs
git commit -m "test: e2e — revoke via CLI subprocess and assert honest verified:false"
```

---

### Task 7: Documentation + final verification

**Files:**
- Modify: `README.md`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Document how to run the e2e test**

In `README.md`, after the existing "Running the Project" section's server-startup instructions (near where `cargo run -p foundry -- serve --config config.yaml` is documented), add a new subsection:

```markdown
### End-to-End Test (real subprocess, issue → verify → revoke → re-verify)

A full end-to-end test spawns the real `foundry` binary (`quickstart` then
`serve`, on dynamically-selected free ports) and drives it purely over HTTP:
creates a credential offer, issues an SD-JWT VC `pid` credential, verifies it
via OpenID4VP (happy path), revokes it via `foundry status-list set`, and
re-verifies to confirm `verified: false` with `status_check` failing. It is
excluded from the default `cargo test --workspace` run (slower, binds real OS
ports) — run it explicitly:

```bash
cargo test -p foundry --test e2e_full_flow -- --ignored
```

See `docs/superpowers/specs/2026-07-23-foundry-e2e-full-flow-design.md` for
the design rationale.
```

- [ ] **Step 2: Run the full verification gate suite one final time**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check && cargo test -p foundry --test e2e_full_flow -- --ignored`
Expected: all four commands pass cleanly.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document running the e2e full-flow test"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1-2 cover design §4 (status-list route + shared helper, with the corrected `:id` naming and `"1"` behavior). Task 3 covers §5.1-5.2 (process spawning, probe-and-release port discovery, the corrected status-list-reachable config rewrite, the logging fix, RAII teardown, log-draining). Tasks 4-6 cover §6 steps 1-5 (offer, issuance, happy-path verification, revoke, re-verify). Task 7 covers §8 (CI/invocation documentation). §7 (error diagnostics) is covered by `ServerGuard::dump_logs()` used in every assertion message throughout Tasks 3-6.
- **Type consistency:** `IssuedCredential` (introduced Task 4) is consumed unchanged by `run_verification` (Task 5) and by Task 6's revocation step (`status_uri`, `status_idx`). `ServerGuard`/`spawn_server` (Task 3) signatures are used identically in Tasks 4-6. `sign_status_list_token` (Task 1) signature matches its two call sites exactly (refactored `commands.rs`, new `status_list_handler`).
- **Placeholder scan:** no TBD/TODO markers; the one open contingency (Task 6 Step 1's note about `VerificationState::Verified` vs `Failed`) states the concrete fallback action to take if the assumption is wrong, rather than deferring undefined work.