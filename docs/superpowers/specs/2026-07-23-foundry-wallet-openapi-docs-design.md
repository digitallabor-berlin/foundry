# Design: OpenAPI Spec & Swagger UI for Wallet-Facing (OpenID4VCI/OpenID4VP) Endpoints

Date: 2026-07-23
Status: Approved

## Context

Plan 8 added an OpenAPI 3.x spec + Swagger UI for the **admin API only**
(`/admin/issuance/offers`, `/admin/verification/requests`, `/admin/verification/requests/{id}`,
`/health`, `/ready`), served from the admin listener (`127.0.0.1:9000` by default) at
`/swagger-ui` (UI) and `/api-docs/openapi.json` (spec). See
`crates/foundry/src/openapi.rs` and `crates/foundry/src/server.rs`.

The **wallet-facing protocol endpoints** — OpenID4VCI issuance (`/token`, `/nonce`,
`/credential`, `/.well-known/openid-credential-issuer`,
`/.well-known/oauth-authorization-server`) and OpenID4VP verification
(`/vp/request/{id}`, `/vp/response/{id}`) — live in `wallet_router()`, mounted on the
public listener (`0.0.0.0:8443` by default), and currently have **no** OpenAPI
annotations or docs at all.

This design adds a second, independent OpenAPI spec + Swagger UI dedicated to these
wallet-facing protocol endpoints, served on the wallet-facing listener itself.

## Goals

- Document the 7 wallet-facing handlers (`issuer_metadata`, `auth_server_metadata`,
  `token_handler`, `nonce_handler`, `credential_handler`,
  `get_request_object_handler`, `post_response_handler`) with `#[utoipa::path(...)]`,
  matching current behavior exactly (no behavior changes beyond the `nonce_handler`
  simplification below).
- Serve this as its own spec + Swagger UI, independent from the admin one, reachable
  on the wallet-facing bind address/port.
- Add a config toggle mirroring the admin one, defaulting to enabled.
- Standardize the UI path naming across both listeners.

## Non-goals

- No behavior change to the wallet protocol endpoints themselves (request parsing,
  validation, error codes) beyond the `nonce_handler` response-construction cleanup
  described below, which produces byte-identical JSON output.
- No changes to vendored `oid4vci`/`openid4vp` crates.
- No authentication/authorization added to the docs endpoints (they remain
  unauthenticated on both listeners, consistent with `/health`/`/ready` today).

## Design

### 1. Config (`foundry-core`)

Add a mirrored toggle to `WalletFacingConfig` in
`crates/foundry-core/src/config/model.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct WalletFacingConfig {
    pub public_base_url: String,
    pub bind: String,
    #[serde(default = "default_true")]
    pub swagger_ui_enabled: bool,
}
```

Reuses the existing `default_true()` helper already defined for
`AdminConfig::swagger_ui_enabled`. Defaults to `true`.

### 2. Route naming (applies to both listeners)

Rename the existing admin Swagger UI path from `/swagger-ui` to `/api-docs`
(interactive UI), keeping the spec at `/api-docs/openapi.json`
(`utoipa_swagger_ui::SwaggerUi::new("/api-docs")`). This is a small breaking
path rename on the admin listener (shipped in Plan 8, same day); update the
README and existing tests accordingly.

The new wallet-facing docs use the identical convention:
- `GET /api-docs` — Swagger UI (wallet listener, e.g. `http://localhost:8443/api-docs`)
- `GET /api-docs/openapi.json` — raw OpenAPI 3.x spec (wallet listener)

### 3. Route wiring (`crates/foundry/src/server.rs`)

`admin_router()`: change `SwaggerUi::new("/swagger-ui")` to
`SwaggerUi::new("/api-docs")`; no other change to the conditional structure.

`wallet_router()`: apply the same conditional pattern used in `admin_router()`,
gated on `state.config.server.wallet_facing.swagger_ui_enabled`:

```rust
pub fn wallet_router(state: AppState) -> Router {
    let router = Router::new()
        .route("/.well-known/openid-credential-issuer", get(issuer_metadata))
        .route("/.well-known/oauth-authorization-server", get(auth_server_metadata))
        .route("/token", post(token_handler))
        .route("/nonce", post(nonce_handler))
        .route("/credential", post(credential_handler))
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler));

    let router = if state.config.server.wallet_facing.swagger_ui_enabled {
        router.merge(
            utoipa_swagger_ui::SwaggerUi::new("/api-docs")
                .url("/api-docs/openapi.json", crate::openapi::WalletApiDoc::openapi()),
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

### 4. Splitting `crates/foundry/src/openapi.rs` into two specs

- Rename current `ApiDoc` → `AdminApiDoc` (content unchanged), rename
  `generate_openapi_spec()` → `generate_admin_openapi_spec()` for symmetry with
  the new wallet function name. Update the one call site in `server.rs`
  (`openapi_json_handler`) and the startup file-write call.
- Add `WalletApiDoc` covering the 7 wallet-facing handlers, plus
  `generate_wallet_openapi_spec()`.
- Add `#[utoipa::path(...)]` to all 7 currently-unannotated handlers in
  `server.rs`:
  - `issuer_metadata`: `GET /.well-known/openid-credential-issuer`, response
    body = `foundry_issuer::CredentialIssuerMetadata`.
  - `auth_server_metadata`: `GET /.well-known/oauth-authorization-server`,
    response body = `foundry_issuer::AuthorizationServerMetadata`.
  - `token_handler`: `POST /token`, request body documented with both
    `application/json` and `application/x-www-form-urlencoded` content
    variants (utoipa 4's `request_body(content(...))` multi-content syntax),
    schema = `foundry_issuer::TokenRequest` for both; response body =
    `foundry_issuer::TokenResponse`.
  - `nonce_handler`: `POST /nonce`, response body =
    `foundry_issuer::NonceResponse` (see behavior note below).
  - `credential_handler`: `POST /credential`, request body =
    `foundry_issuer::CredentialRequest`, response body =
    `foundry_issuer::CredentialResponse`.
  - `get_request_object_handler`: `GET /vp/request/{id}`, response documented
    as a raw `String` body with content-type `application/oauth-authz-req+jwt`
    (utoipa `content_type` override on the response), plus a 404 response
    variant.
  - `post_response_handler`: `POST /vp/response/{id}`, request body documented
    as a raw `String` (JWE compact serialization, untyped/`text/plain` — no
    `Content-Type` is required or checked by the current implementation, per
    existing tests in `wallet_verification.rs`), response body =
    `foundry_verifier::VerificationResult` (already has `ToSchema`).

- **`nonce_handler` behavior note**: `foundry_issuer::NonceResponse` (in
  `crates/foundry-issuer/src/token.rs`) is already the return type of
  `refresh_c_nonce()` and its two fields (`c_nonce: String`,
  `c_nonce_expires_in: u64`) are byte-identical to what `nonce_handler`
  currently hand-builds via `serde_json::json!({...})`. Simplify the handler
  to `Ok(Json(res))`, dropping the manual JSON construction. This produces
  identical wire output — verified by existing tests in
  `wallet_issuance.rs`/`credential.rs` that assert on `c_nonce` /
  `c_nonce_expires_in` fields — and lets the response carry a real typed
  schema instead of an opaque `object`.

### 5. New `utoipa::ToSchema` derives (all locally-defined types; no vendored
`oid4vci`/`openid4vp` crate changes)

Add `utoipa::ToSchema` to the derive list of:
- `foundry_issuer::token::TokenRequest`, `TokenResponse`, `NonceResponse`
- `foundry_issuer::credential::CredentialRequest`, `CredentialResponse`
- `foundry_issuer::proof::ProofObject` (referenced by `CredentialRequest`)
- `foundry_issuer::metadata::CredentialIssuerMetadata`,
  `CredentialConfigurationSupported`, `ProofTypeSupported`,
  `AuthorizationServerMetadata`

`foundry_verifier::VerificationResult` (used by `post_response_handler`'s
response) already derives `ToSchema` — no change needed there.

### 6. Startup file write (`crates/foundry/src/server.rs`, `serve` command)

Mirror the existing `openapi.json` write with a second file,
`openapi-wallet.json`, written alongside it on `serve` startup using
`generate_wallet_openapi_spec()`. Same best-effort semantics as the existing
write (log a warning on failure, don't fail startup).

### 7. Tests

- Update `crates/foundry/tests/openapi_endpoints.rs`: change `/swagger-ui/`
  references to `/api-docs/`.
- Add a wallet-router equivalent test module (or extend the same file) with:
  - `wallet_openapi_json_endpoint_returns_valid_spec` — asserts `openapi`
    field is `3.x` and `paths` contains all 7 wallet-facing routes.
  - `wallet_swagger_ui_endpoint_returns_html_when_enabled` /
    `_returns_404_when_disabled` — mirrors the existing admin toggle tests,
    using a `wallet_facing.swagger_ui_enabled` variant of `test_config()`.
- Confirm existing `wallet_issuance.rs` / `wallet_verification.rs` integration
  tests still pass unchanged after the `nonce_handler` simplification (no
  test changes expected there — output is byte-identical).

### 8. README

- Update the existing "API Documentation (OpenAPI / Swagger UI)" section:
  rename `/swagger-ui` references to `/api-docs` for the admin server.
  Add a parallel description for the wallet-facing server:
  - Swagger UI: `http://localhost:8443/api-docs` (or wallet `bind` per config)
  - Spec: `http://localhost:8443/api-docs/openapi.json`
  - Toggle: `server.wallet_facing.swagger_ui_enabled` (default `true`)
  - Startup file: `openapi-wallet.json`

## Testing/Verification Gates

Per `AGENTS.md`, before completing:
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`

## Open Risks

- utoipa 4.2.3's multi-content-type `request_body` macro syntax for
  `token_handler` needs to compile cleanly; if the exact macro form doesn't
  fit cleanly, fall back to documenting only `application/json` as the primary
  content type with a description note mentioning form-encoding is also
  accepted, rather than blocking on macro syntax.
- The `/swagger-ui` → `/api-docs` rename on the admin listener is a
  path-breaking change for any existing bookmarks/scripts targeting
  `/swagger-ui` directly (same-day change since Plan 8, low risk).