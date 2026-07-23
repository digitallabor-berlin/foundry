# Wallet-Facing OpenAPI Docs & Swagger UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second, independent OpenAPI 3.x spec + Swagger UI dedicated to the OpenID4VCI/OpenID4VP wallet-facing protocol endpoints, served on the wallet-facing listener (`0.0.0.0:8443` by default) at `/api-docs` + `/api-docs/openapi.json`, alongside the existing admin-only docs (renamed from `/swagger-ui` to `/api-docs` for naming consistency).

**Architecture:** Split `crates/foundry/src/openapi.rs` into two `utoipa::OpenApi` documents (`AdminApiDoc`, `WalletApiDoc`). Annotate the 7 currently-unannotated wallet handlers in `crates/foundry/src/server.rs` with `#[utoipa::path(...)]`. Add a `swagger_ui_enabled` toggle to `WalletFacingConfig` (mirroring the existing `AdminConfig` one) and wire `wallet_router()` with the same conditional Swagger-UI-vs-raw-JSON pattern already used in `admin_router()`.

**Tech Stack:** Rust, Axum 0.7, `utoipa` 4 (`axum_extras` feature), `utoipa-swagger-ui` 6.

## Global Constraints

- No `.unwrap()`/`.expect()`/`panic!()`/`unreachable!()` in production request-handling code in `foundry-issuer`, `foundry-verifier`, `foundry::server` (test code is exempt).
- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --check` must all pass before this plan is considered done.
- Follow existing patterns exactly: the admin doc/router already implements the toggle pattern this plan mirrors — do not invent a new pattern.
- No changes to vendored `oid4vci`/`openid4vp` crates.

---

### Task 1: Add `swagger_ui_enabled` toggle to `WalletFacingConfig`

**Files:**
- Modify: `crates/foundry-core/src/config/model.rs` (struct definition)
- Modify (struct-literal call sites, add one field each): `crates/foundry/tests/openapi_endpoints.rs`, `crates/foundry/tests/health.rs`, `crates/foundry/tests/wallet_issuance.rs`, `crates/foundry/tests/wallet_verification.rs`, `crates/foundry/tests/wallet_metadata.rs`, `crates/foundry/tests/issuer_offers.rs`, `crates/foundry-issuer/src/create_offer.rs`, `crates/foundry-issuer/src/metadata.rs`, `crates/foundry-issuer/src/credential.rs`, `crates/foundry-verifier/src/request.rs`, `crates/foundry-verifier/src/verify.rs`
- Test: `crates/foundry-core/tests/config_load.rs`

**Interfaces:**
- Produces: `WalletFacingConfig.swagger_ui_enabled: bool` (defaults to `true` via serde when absent from YAML), reusing the existing private `default_true()` helper already defined in the same file for `AdminConfig::swagger_ui_enabled`.

- [ ] **Step 1: Add the field to `WalletFacingConfig`**

In `crates/foundry-core/src/config/model.rs`, change:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct WalletFacingConfig {
    pub public_base_url: String,
    pub bind: String,
}
```

to:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct WalletFacingConfig {
    pub public_base_url: String,
    pub bind: String,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
}
```

(`default_true()` is already defined later in the same file — do not duplicate it.)

- [ ] **Step 2: Fix every struct-literal call site (compile-only change, no logic change)**

Every file below constructs `WalletFacingConfig { public_base_url: ..., bind: ... }` as a two-field literal. Add `swagger_ui_enabled: true,` as the third field in each. The literal always looks like this (values differ per file, only the field list matters):

```rust
wallet_facing: WalletFacingConfig {
    public_base_url: "...".to_string(),
    bind: "...".to_string(),
    swagger_ui_enabled: true,
},
```

Apply this exact addition (`swagger_ui_enabled: true,` inserted after the `bind` line, before the closing `}`) in:
- `crates/foundry/tests/openapi_endpoints.rs` (line ~17-20)
- `crates/foundry/tests/health.rs` (line ~17-20)
- `crates/foundry/tests/wallet_issuance.rs` (line ~44-47)
- `crates/foundry/tests/wallet_verification.rs` (line ~122-125)
- `crates/foundry/tests/wallet_metadata.rs` (line ~16-19)
- `crates/foundry/tests/issuer_offers.rs` (line ~17-20)
- `crates/foundry-issuer/src/create_offer.rs` (line ~137-140, inside `#[cfg(test)]`)
- `crates/foundry-issuer/src/metadata.rs` (line ~131-134, inside `#[cfg(test)]`)
- `crates/foundry-issuer/src/credential.rs` (line ~239-242, inside `#[cfg(test)]`)
- `crates/foundry-verifier/src/request.rs` (line ~264-267, inside `#[cfg(test)]`)
- `crates/foundry-verifier/src/verify.rs` (line ~248-251, inside `#[cfg(test)]`)

- [ ] **Step 3: Add a config-default test**

In `crates/foundry-core/tests/config_load.rs`, add an assertion to the existing test (the fixture `tests/fixtures/minimal.yaml` does not set `swagger_ui_enabled` under `server.wallet_facing`, so this proves the serde default):

```rust
#[test]
fn loads_minimal_yaml_and_validates() {
    let cfg = Config::load(Path::new("tests/fixtures/minimal.yaml")).expect("should load");
    assert_eq!(cfg.issuer.credential_issuer, "https://issuer.example.com");
    assert_eq!(cfg.credential_types.len(), 1);
    assert_eq!(cfg.credential_types[0].id, "pid");
    assert!(
        cfg.server.wallet_facing.swagger_ui_enabled,
        "swagger_ui_enabled should default to true when omitted from YAML"
    );
    cfg.validate().expect("minimal config should be valid");
}
```

- [ ] **Step 4: Build and test**

Run: `cargo build --workspace --tests`
Expected: builds cleanly (confirms every struct-literal call site was fixed).

Run: `cargo test -p foundry-core`
Expected: `loads_minimal_yaml_and_validates` passes, including the new assertion.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry-core/src/config/model.rs crates/foundry-core/tests/config_load.rs \
  crates/foundry/tests/openapi_endpoints.rs crates/foundry/tests/health.rs \
  crates/foundry/tests/wallet_issuance.rs crates/foundry/tests/wallet_verification.rs \
  crates/foundry/tests/wallet_metadata.rs crates/foundry/tests/issuer_offers.rs \
  crates/foundry-issuer/src/create_offer.rs crates/foundry-issuer/src/metadata.rs \
  crates/foundry-issuer/src/credential.rs crates/foundry-verifier/src/request.rs \
  crates/foundry-verifier/src/verify.rs
git commit -m "feat(config): add swagger_ui_enabled toggle to WalletFacingConfig"
```

---

### Task 2: Add `utoipa::ToSchema` to wallet-facing DTOs

**Files:**
- Modify: `crates/foundry-issuer/src/token.rs`
- Modify: `crates/foundry-issuer/src/credential.rs`
- Modify: `crates/foundry-issuer/src/proof.rs`
- Modify: `crates/foundry-issuer/src/metadata.rs`

**Interfaces:**
- Consumes: nothing new (all types already exist and are re-exported from `foundry_issuer`'s crate root per `crates/foundry-issuer/src/lib.rs`).
- Produces: all wallet-facing DTOs below now implement `utoipa::ToSchema`, ready to be referenced from `#[utoipa::path(...)]` annotations in Task 5.

**Important:** `serde_json::Value` does **not** implement `utoipa::ToSchema` in utoipa 4.2.3 (verified against the vendored crate source — no primitive impl exists). Any field typed `serde_json::Value` or `Vec<serde_json::Value>` must use utoipa's `#[schema(value_type = Object)]` / `#[schema(value_type = Vec<Object>)]` override (a documented utoipa escape hatch for free-form JSON) or the derive will fail to compile.

- [ ] **Step 1: Add `ToSchema` to `token.rs` types**

In `crates/foundry-issuer/src/token.rs`, change:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
```
to:
```rust
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
```

and:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
```
to:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct TokenResponse {
```

and:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NonceResponse {
```
to:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct NonceResponse {
```

- [ ] **Step 2: Add `ToSchema` to `credential.rs` types**

In `crates/foundry-issuer/src/credential.rs`, change:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialRequest {
```
to:
```rust
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CredentialRequest {
```

and:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
```
to:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponse {
```

- [ ] **Step 3: Add `ToSchema` to `proof.rs`'s `ProofObject`**

In `crates/foundry-issuer/src/proof.rs`, change:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofObject {
```
to:
```rust
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ProofObject {
```

- [ ] **Step 4: Add `ToSchema` to `metadata.rs` types, with `value_type` overrides for `serde_json::Value` fields**

In `crates/foundry-issuer/src/metadata.rs`, change the four structs as follows (full replacement of each struct definition):

```rust
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfigurationSupported>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
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
    #[schema(value_type = Vec<Object>)]
    pub display: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub claims: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    pub grant_types_supported: Vec<String>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}
```

- [ ] **Step 5: Build to confirm derives compile**

Run: `cargo build -p foundry-issuer`
Expected: builds cleanly with no errors about missing `ToSchema` impls for `serde_json::Value`.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/token.rs crates/foundry-issuer/src/credential.rs \
  crates/foundry-issuer/src/proof.rs crates/foundry-issuer/src/metadata.rs
git commit -m "feat(issuer): derive utoipa::ToSchema on wallet-facing DTOs"
```

---

### Task 3: Simplify `nonce_handler` to return a typed `NonceResponse`

**Files:**
- Modify: `crates/foundry/src/server.rs:213-236` (the `nonce_handler` function)

**Interfaces:**
- Consumes: `foundry_issuer::NonceResponse` (already returned by `foundry_issuer::refresh_c_nonce`, now `ToSchema`-derived per Task 2).
- Produces: `nonce_handler` returns `Result<Json<foundry_issuer::NonceResponse>, (StatusCode, Json<serde_json::Value>)>` instead of `Result<Json<serde_json::Value>, ...>`. Wire format (`c_nonce`, `c_nonce_expires_in` field names/types) is unchanged — this is a behavior-preserving refactor verified by existing tests.

- [ ] **Step 1: Confirm baseline passes before changing anything**

Run: `cargo test -p foundry --test wallet_issuance`
Expected: PASS (establishes the behavior this refactor must not break — the `mint_c_nonce` test helper in that file calls `POST /nonce` and reads `c_nonce` from the JSON body).

- [ ] **Step 2: Replace the handler body**

In `crates/foundry/src/server.rs`, change:

```rust
async fn nonce_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
                "missing authorization header".into(),
            ))
        })?;

    let access_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
            "invalid bearer authorization header".into(),
        ))
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::refresh_c_nonce(state.storage.as_ref(), access_token, now)
        .await
        .map_err(|e| wallet_error_response(&e))?;

    Ok(Json(serde_json::json!({
        "c_nonce": res.c_nonce,
        "c_nonce_expires_in": res.c_nonce_expires_in
    })))
}
```

to:

```rust
#[utoipa::path(
    post,
    path = "/nonce",
    security(("bearerAuth" = [])),
    responses((status = 200, body = foundry_issuer::NonceResponse))
)]
async fn nonce_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<foundry_issuer::NonceResponse>, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
                "missing authorization header".into(),
            ))
        })?;

    let access_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
            "invalid bearer authorization header".into(),
        ))
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::refresh_c_nonce(state.storage.as_ref(), access_token, now)
        .await
        .map_err(|e| wallet_error_response(&e))?;

    Ok(Json(res))
}
```

Note: the `security(("bearerAuth" = []))` attribute is documentation-only (utoipa doesn't validate it against actual middleware) and matches that this endpoint requires a `Bearer` token per the handler's own logic above. If `utoipa::path` complains about an undeclared `bearerAuth` security scheme (it only warns, doesn't fail the build, since no `#[openapi(security(...))]` is registered at the doc level in this plan), it's safe to drop the `security(...)` line entirely — do that if `cargo build -p foundry` emits any warning about it, to keep the annotation minimal and matching the existing style (the admin doc's annotations carry no `security` blocks either).

- [ ] **Step 3: Build and re-run tests**

Run: `cargo build -p foundry`
Expected: builds cleanly.

Run: `cargo test -p foundry --test wallet_issuance`
Expected: PASS, identical results to Step 1 (byte-identical wire output).

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/src/server.rs
git commit -m "refactor(server): return typed NonceResponse from nonce_handler"
```

---

### Task 4: Split `openapi.rs` into `AdminApiDoc`/`WalletApiDoc` and rename admin UI path to `/api-docs`

**Files:**
- Modify: `crates/foundry/src/openapi.rs`
- Modify: `crates/foundry/src/server.rs` (admin_router + openapi_json_handler + serve())
- Modify: `crates/foundry/tests/openapi_endpoints.rs` (path rename only; the config-field edit was already done in Task 1)

**Interfaces:**
- Consumes: `foundry_issuer`/`foundry_verifier` schema types (unchanged from Plan 8, plus the new ones from Task 2 — those are wired into `WalletApiDoc` in Task 5, not here).
- Produces: `AdminApiDoc` (renamed from `ApiDoc`), `generate_admin_openapi_spec()` (renamed from `generate_openapi_spec()`). `WalletApiDoc` is declared here as an empty-paths scaffold; Task 5 fills in its `paths(...)` list once the wallet handlers are annotated.

- [ ] **Step 1: Rename `ApiDoc` to `AdminApiDoc` and add the `WalletApiDoc` scaffold**

Replace the full contents of `crates/foundry/src/openapi.rs` with:

```rust
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::server::health,
        crate::server::ready,
        crate::server::create_offer_handler,
        crate::server::create_verification_handler,
        crate::server::get_verification_handler,
    ),
    components(schemas(
        foundry_issuer::CreateOfferRequest,
        foundry_issuer::CreateOfferResponse,
        foundry_issuer::CredentialOffer,
        foundry_issuer::CredentialOfferGrants,
        foundry_issuer::PreAuthorizedCodeGrant,
        foundry_issuer::TxCodeDefinition,
        foundry_verifier::request::CreateVerificationRequest,
        foundry_verifier::request::CreateVerificationResponse,
        foundry_verifier::VerificationTransaction,
        foundry_verifier::VerificationState,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
    ))
)]
pub struct AdminApiDoc;

pub fn generate_admin_openapi_spec() -> String {
    AdminApiDoc::openapi().to_json().unwrap_or_default()
}

#[derive(OpenApi)]
#[openapi(paths(), components(schemas()))]
pub struct WalletApiDoc;

pub fn generate_wallet_openapi_spec() -> String {
    WalletApiDoc::openapi().to_json().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_valid_v3_spec(spec_json: &str) {
        assert!(!spec_json.is_empty(), "OpenAPI spec should not be empty");

        let val: serde_json::Value =
            serde_json::from_str(spec_json).expect("OpenAPI spec should be valid JSON");

        let openapi_ver = val
            .get("openapi")
            .and_then(|v| v.as_str())
            .expect("spec should contain 'openapi' version field");

        assert!(
            openapi_ver.starts_with("3."),
            "Expected OpenAPI version 3.x, got '{openapi_ver}'"
        );
    }

    #[test]
    fn admin_openapi_spec_generates_valid_json() {
        assert_valid_v3_spec(&generate_admin_openapi_spec());
    }

    #[test]
    fn wallet_openapi_spec_generates_valid_json() {
        assert_valid_v3_spec(&generate_wallet_openapi_spec());
    }
}
```

- [ ] **Step 1a: Update `crates/foundry/src/lib.rs`'s re-export**

In `crates/foundry/src/lib.rs`, change:

```rust
pub use openapi::{generate_openapi_spec, ApiDoc};
```

to:

```rust
pub use openapi::{
    generate_admin_openapi_spec, generate_wallet_openapi_spec, AdminApiDoc, WalletApiDoc,
};
```

(This crate-root re-export has no external callers found in this workspace, but it must still be updated to match the new names in `openapi.rs` or the crate will fail to compile — `pub use` requires the referenced names to exist.)

- [ ] **Step 2: Update `server.rs`'s admin router — rename path and function call**

In `crates/foundry/src/server.rs`, change:

```rust
    let unauthenticated = if state.config.server.admin.swagger_ui_enabled {
        unauthenticated.merge(
            utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", crate::openapi::ApiDoc::openapi()),
        )
    } else {
        unauthenticated.route("/api-docs/openapi.json", get(openapi_json_handler))
    };
```

to:

```rust
    let unauthenticated = if state.config.server.admin.swagger_ui_enabled {
        unauthenticated.merge(
            utoipa_swagger_ui::SwaggerUi::new("/api-docs")
                .url("/api-docs/openapi.json", crate::openapi::AdminApiDoc::openapi()),
        )
    } else {
        unauthenticated.route("/api-docs/openapi.json", get(openapi_json_handler))
    };
```

And change:

```rust
pub(crate) async fn openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_openapi_spec(),
    )
}
```

to:

```rust
pub(crate) async fn openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_admin_openapi_spec(),
    )
}
```

And in the `serve()` function, change:

```rust
    if let Err(e) = std::fs::write("openapi.json", crate::openapi::generate_openapi_spec()) {
        tracing::warn!(error = %e, "failed to write openapi.json on startup");
    } else {
        tracing::debug!("wrote openapi.json on startup");
    }
```

to:

```rust
    if let Err(e) = std::fs::write("openapi.json", crate::openapi::generate_admin_openapi_spec()) {
        tracing::warn!(error = %e, "failed to write openapi.json on startup");
    } else {
        tracing::debug!("wrote openapi.json on startup");
    }
```

- [ ] **Step 3: Update `openapi_endpoints.rs`'s path assertions**

In `crates/foundry/tests/openapi_endpoints.rs`, change both occurrences of `.uri("/swagger-ui/")` to `.uri("/api-docs/")` (in `swagger_ui_endpoint_returns_html_when_enabled` and `swagger_ui_endpoint_returns_404_when_disabled`).

- [ ] **Step 4: Build and test**

Run: `cargo test -p foundry --test openapi_endpoints`
Expected: all 3 tests (`openapi_json_endpoint_returns_valid_spec`, `swagger_ui_endpoint_returns_html_when_enabled`, `swagger_ui_endpoint_returns_404_when_disabled`) PASS.

Run: `cargo test -p foundry --lib`
Expected: `admin_openapi_spec_generates_valid_json` and `wallet_openapi_spec_generates_valid_json` PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/src/openapi.rs crates/foundry/src/server.rs crates/foundry/tests/openapi_endpoints.rs
git commit -m "refactor(openapi): split into AdminApiDoc/WalletApiDoc, rename /swagger-ui to /api-docs"
```

---

### Task 5: Annotate wallet handlers and wire the wallet-facing Swagger UI/spec

**Files:**
- Modify: `crates/foundry/src/openapi.rs` (fill in `WalletApiDoc`'s `paths`/`components`)
- Modify: `crates/foundry/src/server.rs` (annotate 6 remaining handlers — `nonce_handler` was already annotated in Task 3 — and rewrite `wallet_router`)
- Test: `crates/foundry/tests/openapi_endpoints.rs` (new wallet-doc tests)

**Interfaces:**
- Consumes: `WalletApiDoc` (scaffold from Task 4), all `ToSchema` types from Task 2, `foundry_verifier::VerificationResult` (already `ToSchema`, from Plan 8).
- Produces: `wallet_router(state: AppState) -> Router` now serves `/api-docs` + `/api-docs/openapi.json` alongside the 7 protocol routes, gated on `state.config.server.wallet_facing.swagger_ui_enabled`.

- [ ] **Step 1: Annotate `issuer_metadata` and `auth_server_metadata`**

In `crates/foundry/src/server.rs`, change:

```rust
async fn issuer_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::CredentialIssuerMetadata> {
    Json(foundry_issuer::build_issuer_metadata(&state.config))
}

async fn auth_server_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::AuthorizationServerMetadata> {
    Json(foundry_issuer::build_authorization_server_metadata(
        &state.config,
    ))
}
```

to:

```rust
#[utoipa::path(
    get,
    path = "/.well-known/openid-credential-issuer",
    responses((status = 200, body = foundry_issuer::CredentialIssuerMetadata))
)]
async fn issuer_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::CredentialIssuerMetadata> {
    Json(foundry_issuer::build_issuer_metadata(&state.config))
}

#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    responses((status = 200, body = foundry_issuer::AuthorizationServerMetadata))
)]
async fn auth_server_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::AuthorizationServerMetadata> {
    Json(foundry_issuer::build_authorization_server_metadata(
        &state.config,
    ))
}
```

- [ ] **Step 2: Annotate `token_handler`**

In `crates/foundry/src/server.rs`, change:

```rust
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<Json<foundry_issuer::TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
```

to:

```rust
#[utoipa::path(
    post,
    path = "/token",
    request_body(
        content(
            (foundry_issuer::TokenRequest = "application/json"),
            (foundry_issuer::TokenRequest = "application/x-www-form-urlencoded")
        )
    ),
    responses((status = 200, body = foundry_issuer::TokenResponse))
)]
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<Json<foundry_issuer::TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
```

(Leave the function body untouched — only the attribute above the signature is new.)

- [ ] **Step 3: Annotate `credential_handler`**

In `crates/foundry/src/server.rs`, change:

```rust
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<foundry_issuer::CredentialRequest>,
) -> Result<Json<foundry_issuer::CredentialResponse>, (StatusCode, Json<serde_json::Value>)> {
```

to:

```rust
#[utoipa::path(
    post,
    path = "/credential",
    request_body = foundry_issuer::CredentialRequest,
    responses((status = 200, body = foundry_issuer::CredentialResponse))
)]
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<foundry_issuer::CredentialRequest>,
) -> Result<Json<foundry_issuer::CredentialResponse>, (StatusCode, Json<serde_json::Value>)> {
```

- [ ] **Step 4: Annotate `get_request_object_handler` and `post_response_handler`**

In `crates/foundry/src/server.rs`, change:

```rust
async fn get_request_object_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
```

to:

```rust
#[utoipa::path(
    get,
    path = "/vp/request/{id}",
    responses(
        (status = 200, description = "Signed Request Object JWT", content_type = "application/oauth-authz-req+jwt", body = String),
        (status = 404)
    )
)]
async fn get_request_object_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
```

And change:

```rust
async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    encrypted_jwe_str: String,
) -> Result<Json<foundry_verifier::VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
```

to:

```rust
#[utoipa::path(
    post,
    path = "/vp/response/{id}",
    request_body(content = String, description = "Encrypted JWE compact serialization of the VP Token response"),
    responses((status = 200, body = foundry_verifier::VerificationResult))
)]
async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    encrypted_jwe_str: String,
) -> Result<Json<foundry_verifier::VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
```

- [ ] **Step 5: Fill in `WalletApiDoc`'s `paths`/`components` in `openapi.rs`**

In `crates/foundry/src/openapi.rs`, change:

```rust
#[derive(OpenApi)]
#[openapi(paths(), components(schemas()))]
pub struct WalletApiDoc;
```

to:

```rust
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::server::issuer_metadata,
        crate::server::auth_server_metadata,
        crate::server::token_handler,
        crate::server::nonce_handler,
        crate::server::credential_handler,
        crate::server::get_request_object_handler,
        crate::server::post_response_handler,
    ),
    components(schemas(
        foundry_issuer::CredentialIssuerMetadata,
        foundry_issuer::CredentialConfigurationSupported,
        foundry_issuer::ProofTypeSupported,
        foundry_issuer::AuthorizationServerMetadata,
        foundry_issuer::TokenRequest,
        foundry_issuer::TokenResponse,
        foundry_issuer::NonceResponse,
        foundry_issuer::CredentialRequest,
        foundry_issuer::CredentialResponse,
        foundry_issuer::ProofObject,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
    ))
)]
pub struct WalletApiDoc;
```

(`crate::server::nonce_handler` and `crate::server::token_handler` etc. must be visible to `openapi.rs` — they're already `async fn` at module scope in `server.rs`, same visibility level as the admin handlers already referenced in `AdminApiDoc`, so no visibility changes are needed.)

- [ ] **Step 6: Rewrite `wallet_router` with the Swagger UI/docs conditional**

In `crates/foundry/src/server.rs`, change:

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
        .route("/token", post(token_handler))
        .route("/nonce", post(nonce_handler))
        .route("/credential", post(credential_handler))
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler))
        .with_state(state)
}
```

to:

```rust
pub fn wallet_router(state: AppState) -> Router {
    let router = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_server_metadata),
        )
        .route("/token", post(token_handler))
        .route("/nonce", post(nonce_handler))
        .route("/credential", post(credential_handler))
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler));

    let router = if state.config.server.wallet_facing.swagger_ui_enabled {
        router.merge(
            utoipa_swagger_ui::SwaggerUi::new("/api-docs").url(
                "/api-docs/openapi.json",
                crate::openapi::WalletApiDoc::openapi(),
            ),
        )
    } else {
        router.route("/api-docs/openapi.json", get(wallet_openapi_json_handler))
    };

    router.with_state(state)
}

pub(crate) async fn wallet_openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_wallet_openapi_spec(),
    )
}
```

- [ ] **Step 7: Build**

Run: `cargo build -p foundry`
Expected: builds cleanly. If the `token_handler` multi-content `request_body(content(...))` syntax fails to compile, replace it with the single-content fallback documented as an accepted risk in the design spec:

```rust
#[utoipa::path(
    post,
    path = "/token",
    request_body = foundry_issuer::TokenRequest,
    responses((status = 200, body = foundry_issuer::TokenResponse))
)]
```

(This documents only `application/json`; form-encoding is still accepted by the handler at runtime, just not both-listed in the spec. Only fall back to this if the multi-content syntax in Step 2 does not compile.)

- [ ] **Step 8: Write wallet-doc tests in `openapi_endpoints.rs`**

Add a `wallet_facing_test_config` helper and three new tests to `crates/foundry/tests/openapi_endpoints.rs`. First add the import for `wallet_router`:

```rust
use foundry::server::{admin_router, wallet_router, AppState};
```

(replacing the existing `use foundry::server::{admin_router, AppState};` line). Then add, after the existing `test_config` function:

```rust
fn wallet_facing_test_config(swagger_ui_enabled: bool) -> Config {
    let mut cfg = test_config(true);
    cfg.server.wallet_facing.swagger_ui_enabled = swagger_ui_enabled;
    cfg
}
```

Then append these three tests at the end of the file:

```rust
#[tokio::test]
async fn wallet_openapi_json_endpoint_returns_valid_spec() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(wallet_facing_test_config(true));
    let app = wallet_router(AppState { storage, config });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json_val: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("Response body should be valid JSON");

    assert!(json_val.get("openapi").is_some());
    let paths = json_val
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("paths should be an object");
    for expected in [
        "/.well-known/openid-credential-issuer",
        "/.well-known/oauth-authorization-server",
        "/token",
        "/nonce",
        "/credential",
        "/vp/request/{id}",
        "/vp/response/{id}",
    ] {
        assert!(
            paths.contains_key(expected),
            "wallet OpenAPI spec should document {expected}"
        );
    }
}

#[tokio::test]
async fn wallet_swagger_ui_endpoint_returns_html_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(wallet_facing_test_config(true));
    let app = wallet_router(AppState { storage, config });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);
    assert!(
        html.contains("swagger-ui") || html.contains("html") || html.contains("SwaggerUI"),
        "Wallet Swagger UI endpoint should return HTML content, got: {html}"
    );
}

#[tokio::test]
async fn wallet_swagger_ui_endpoint_returns_404_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(wallet_facing_test_config(false));
    let app = wallet_router(AppState { storage, config });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 9: Run the full test file**

Run: `cargo test -p foundry --test openapi_endpoints`
Expected: all 6 tests PASS (3 existing admin ones + 3 new wallet ones).

Run: `cargo test -p foundry`
Expected: all tests in the `foundry` crate (including `wallet_issuance`, `wallet_verification`, `wallet_metadata`, `issuer_offers`, `health`) still PASS — confirms the new `#[utoipa::path]` attributes didn't change any handler behavior.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry/src/openapi.rs crates/foundry/src/server.rs crates/foundry/tests/openapi_endpoints.rs
git commit -m "feat(openapi): document wallet-facing endpoints, serve Swagger UI on wallet listener"
```

---

### Task 6: Write `openapi-wallet.json` on server startup

**Files:**
- Modify: `crates/foundry/src/server.rs:456-461` (the `serve()` function's startup file writes)

**Interfaces:**
- Consumes: `crate::openapi::generate_wallet_openapi_spec()` (from Task 4).
- Produces: `openapi-wallet.json` written to the working directory on `serve` startup, mirroring the existing `openapi.json` (admin) write — same best-effort semantics (log a warning on failure, don't fail startup).

- [ ] **Step 1: Add the second file write**

In `crates/foundry/src/server.rs`, change:

```rust
pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    if let Err(e) = std::fs::write("openapi.json", crate::openapi::generate_admin_openapi_spec()) {
        tracing::warn!(error = %e, "failed to write openapi.json on startup");
    } else {
        tracing::debug!("wrote openapi.json on startup");
    }
```

to:

```rust
pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    if let Err(e) = std::fs::write("openapi.json", crate::openapi::generate_admin_openapi_spec()) {
        tracing::warn!(error = %e, "failed to write openapi.json on startup");
    } else {
        tracing::debug!("wrote openapi.json on startup");
    }

    if let Err(e) = std::fs::write(
        "openapi-wallet.json",
        crate::openapi::generate_wallet_openapi_spec(),
    ) {
        tracing::warn!(error = %e, "failed to write openapi-wallet.json on startup");
    } else {
        tracing::debug!("wrote openapi-wallet.json on startup");
    }
```

- [ ] **Step 2: Build**

Run: `cargo build -p foundry`
Expected: builds cleanly.

- [ ] **Step 3: Manual smoke test against a running server**

Run (from the repo root, using the existing dev `config.yaml` from `quickstart`):

```bash
pkill -f "target/debug/foundry serve" 2>/dev/null; sleep 1
(cargo run -p foundry -- serve --config config.yaml > /tmp/foundry_serve_task6.log 2>&1 &)
sleep 5
test -f openapi.json && test -f openapi-wallet.json && echo "BOTH_FILES_PRESENT"
curl -s http://127.0.0.1:9000/api-docs/openapi.json -o /dev/null -w "admin api-docs: %{http_code}\n"
curl -s http://localhost:8443/api-docs/openapi.json -o /dev/null -w "wallet api-docs: %{http_code}\n"
pkill -f "target/debug/foundry serve"
```

Expected output: `BOTH_FILES_PRESENT`, `admin api-docs: 200`, `wallet api-docs: 200`.

(Use `ctx_execute` with `language: shell` for this step rather than raw `bash`, per this project's context-mode tooling convention — curl output must not flood the conversation directly.)

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/src/server.rs
git commit -m "feat(server): write openapi-wallet.json on startup, mirroring openapi.json"
```

---

### Task 7: Update README

**Files:**
- Modify: `README.md` (the "API Documentation (OpenAPI / Swagger UI)" section added earlier this session)

**Interfaces:** None (documentation only).

- [ ] **Step 1: Rewrite the section**

In `README.md`, change the admin endpoint bullets:

```markdown
- `GET /swagger-ui` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](#api-documentation-openapi--swagger-ui) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
```

to:

```markdown
- `GET /api-docs` — Interactive OpenAPI/Swagger UI (enabled by default; see [API Documentation](#api-documentation-openapi--swagger-ui) below)
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON)
```

Also add, in the **Wallet-facing Server (`0.0.0.0:8443`)** bullet list (right after the existing `.well-known` entries), two new bullets:

```markdown
- `GET /api-docs` — Interactive OpenAPI/Swagger UI for the wallet-facing (OpenID4VCI/OpenID4VP) endpoints
- `GET /api-docs/openapi.json` — Raw OpenAPI 3.x spec (JSON) for the wallet-facing endpoints
```

Then replace the whole "API Documentation (OpenAPI / Swagger UI)" section body with:

```markdown
#### API Documentation (OpenAPI / Swagger UI)

Foundry auto-generates **two independent** OpenAPI 3.x specifications — one for the admin API, one for the wallet-facing OpenID4VCI/OpenID4VP protocol endpoints — each served from its own listener.

**Admin API** (`127.0.0.1:9000` by default):
- Swagger UI: `http://127.0.0.1:9000/api-docs`
- Raw spec: `http://127.0.0.1:9000/api-docs/openapi.json`
- Toggle: `server.admin.swagger_ui_enabled` (default `true`)
- Startup file: `openapi.json`

**Wallet-facing API** (`0.0.0.0:8443` by default):
- Swagger UI: `http://localhost:8443/api-docs`
- Raw spec: `http://localhost:8443/api-docs/openapi.json`
- Toggle: `server.wallet_facing.swagger_ui_enabled` (default `true`)
- Startup file: `openapi-wallet.json`

All four docs endpoints are unauthenticated, served alongside `/health`/`/ready` on the admin listener and alongside the protocol endpoints on the wallet-facing listener. Since the wallet-facing listener binds `0.0.0.0` by default (publicly reachable), set `server.wallet_facing.swagger_ui_enabled: false` in production if you don't want the docs UI exposed on the public interface — the raw JSON spec at `/api-docs/openapi.json` remains available either way (it does not carry secrets, only route/schema shapes).

Both `openapi.json` and `openapi-wallet.json` are written to the working directory on every `serve` startup — convenient for generating client SDKs or importing into tools like Postman/Insomnia.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document wallet-facing OpenAPI docs, update /swagger-ui to /api-docs"
```

---

### Task 8: Full workspace verification gate

**Files:** None (verification only).

- [ ] **Step 1: Run the full test suite**

Run: `cargo test --workspace`
Expected: all tests PASS across all crates.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings/errors.

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --all -- --check`
Expected: no diff output (all files already formatted).

If Step 2 or 3 report issues, fix them (e.g. `cargo fmt --all` to auto-fix formatting) and re-run Steps 1-3 until all three are clean.

- [ ] **Step 4: Final commit (if fmt/clippy required fixes)**

```bash
git add -A
git commit -m "chore: fmt/clippy fixes for wallet OpenAPI docs feature"
```

(Skip this step entirely if Steps 1-3 were clean on the first run — don't create an empty commit.)