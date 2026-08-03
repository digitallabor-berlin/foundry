# Admin Console: Trigger Presentation via the Digital Credentials API — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the admin test console a working, same-browser way to exercise the `dc_api` verification transport end-to-end — create a request, invoke the Digital Credentials API, submit the wallet's encrypted response, and see the same pass/fail/claims result already rendered for `request_uri` transport.

**Architecture:** A new admin-authenticated endpoint (`POST /admin/verification/requests/:id/dc-api-response`) shares its verification core with the existing wallet-facing `/vp/response/:id` handler via an extracted `submit_vp_response` helper. The console's JS gains a `<select>` for `transport`, a "Trigger via Digital Credentials API" button, and helper functions aligned with the proven `eudipay-frontend/src/dcApi.js` patterns, calling `navigator.credentials.get()` directly and posting the result to the new endpoint.

**Tech Stack:** Rust (axum, utoipa), vanilla JS in `crates/foundry/assets/console.html`, `cargo test` / `tower::ServiceExt::oneshot` integration tests.

## Global Constraints

- Root AGENTS.md §4.1: no `.unwrap()`/`.expect()`/`panic!()` in production request-handling code in `crates/foundry`. Test files under `tests/` are exempt.
- Root AGENTS.md §4.3: structural/crypto verification failures → HTTP 400; status-list unavailability → HTTP 502. This classification must be **identical** for both `post_response_handler` and the new admin endpoint.
- Root AGENTS.md §4.5: every `#[tracing::instrument]` carries `skip_all`; log field values (e.g. `surface`) are operator-facing API — the new endpoint's traffic must log `surface = "admin"`, never `"wallet"`.
- Root AGENTS.md §6: any endpoint change must be reflected in `openapi.json` (this work never touches `openapi-wallet.json`, since the new route is admin-only).
- Root AGENTS.md §5.1: scoped gate only — this plan touches only `crates/foundry`, so the gate at every task boundary is `cargo test -p foundry`, `cargo clippy -p foundry --all-targets -- -D warnings`, `cargo fmt --check`. Never run `cargo test --workspace` mid-plan.
- Spec: `docs/superpowers/specs/2026-08-03-admin-console-dc-api-design.md` — read it before starting if any task here is unclear on intent.

---

### Task 1: Extract `submit_vp_response` and parameterize the wallet error mapper by `surface`

Pure refactor of `crates/foundry/src/server.rs` — no behavioral change. This creates the shared core the new admin endpoint (Task 2) will call.

**Files:**
- Modify: `crates/foundry/src/server.rs`

**Interfaces:**
- Produces: `async fn submit_vp_response(state: &AppState, id: &str, encrypted_jwe_str: &str, surface: &'static str) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)>` — Task 2's handler calls this with `surface = "admin"`.
- Produces: `fn verifier_wallet_error_response(e: &foundry_verifier::VerificationError, surface: &'static str) -> (StatusCode, Json<serde_json::Value>)` (signature changed — added `surface` param).

- [ ] **Step 1: Add the `surface` parameter to `verifier_wallet_error_response` and update its production call sites**

Replace the existing function body (currently at line ~804 in `crates/foundry/src/server.rs`):

```rust
fn verifier_wallet_error_response(
    e: &foundry_verifier::VerificationError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        StatusUnavailable(_) => (StatusCode::BAD_GATEWAY, "status_unavailable"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    log_typed_error("wallet", e.kind(), e, status);
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": e.to_string(),
        })),
    )
}
```

with:

```rust
/// Maps a `VerificationError` to the OpenID4VP-response HTTP status/error-code
/// classification (root AGENTS.md §4.3). This classification is a property of
/// the response itself, not of which route received it, so it is identical
/// whether the encrypted JWE arrived from a real wallet
/// (`POST /vp/response/:id`) or was relayed by the admin console after a
/// browser-side Digital Credentials API call
/// (`POST /admin/verification/requests/:id/dc-api-response`). Only the
/// `surface` log label differs between the two callers (root AGENTS.md §4.5).
fn verifier_wallet_error_response(
    e: &foundry_verifier::VerificationError,
    surface: &'static str,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        StatusUnavailable(_) => (StatusCode::BAD_GATEWAY, "status_unavailable"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    log_typed_error(surface, e.kind(), e, status);
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": e.to_string(),
        })),
    )
}
```

- [ ] **Step 2: Extract `submit_vp_response` and rewrite `post_response_handler` to use it**

Replace the current `post_response_handler` body (from `async fn post_response_handler` through its closing `}`, currently lines ~923-1008) with:

```rust
/// Shared core of "submit a wallet's encrypted VP Token response for
/// verification": load the transaction, reject if not `Pending`, call
/// `verify_vp_response`, persist the outcome, and map any error through the
/// same classification `post_response_handler` has always used. Used by both
/// the real wallet-facing route (`surface = "wallet"`) and the admin-facing
/// Digital Credentials API route (`surface = "admin"`) added in a later task
/// — see `verifier_wallet_error_response` for why the status/code mapping
/// itself must not vary between the two callers.
async fn submit_vp_response(
    state: &AppState,
    id: &str,
    encrypted_jwe_str: &str,
    surface: &'static str,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx_opt = foundry_verifier::load_verification_transaction(state.storage.as_ref(), id)
        .await
        .map_err(|e| verifier_wallet_error_response(&e, surface))?;
    let mut tx = match tx_opt {
        Some(tx) => tx,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "error_description": format!("verification transaction '{id}' not found")
                })),
            ))
        }
    };

    if tx.state != foundry_verifier::VerificationState::Pending {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "verification response already submitted"
            })),
        ));
    }

    let resolver = match foundry_verifier::HttpStatusListResolver::new() {
        Ok(r) => r,
        Err(e) => return Err(verifier_wallet_error_response(&e, surface)),
    };
    let verify_res =
        foundry_verifier::verify_vp_response(&state.config, &mut tx, encrypted_jwe_str, &resolver)
            .await;

    // Losing this write is its own defect: it makes the admin API and the console
    // disagree with what actually happened. It must not change the response the
    // caller receives, so it is logged rather than propagated.
    if let Err(e) = foundry_verifier::save_verification_transaction(
        state.storage.as_ref(),
        &tx,
        state.config.storage.transaction_ttl_secs,
        now,
    )
    .await
    {
        tracing::error!(
            op = "save_verification_transaction",
            tx_id = %tx.id,
            error.kind = e.kind(),
            error.detail = %foundry_core::obs::truncate(&e.to_string(), DETAIL_MAX),
            "failed to persist the verification verdict; the admin API will not \
             reflect this transaction's outcome"
        );
    }

    match verify_res {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(verifier_wallet_error_response(&e, surface)),
    }
}

/// The OpenID4VP `direct_post.jwt` authorization response body.
///
/// The verifier advertises `response_mode: direct_post.jwt`, so per OpenID4VP
/// 1.0 §8.2/§8.3 the wallet POSTs `application/x-www-form-urlencoded` with the
/// JWE compact serialization in a `response` parameter.
///
/// Deliberately **not** `deny_unknown_fields`: §8 permits additional members
/// (wallets commonly echo `state`), and rejecting them would break conformant
/// wallets.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct VpResponseForm {
    /// JWE compact serialization of the VP Token response.
    response: String,
}

// NOTE: `content = VpResponseForm` must stay **unqualified**. utoipa generates the
// `$ref` from the literal spelling in this attribute, so a qualified path such as
// `crate::server::VpResponseForm` emits a dotted name that never matches the plain
// key `components(schemas(...))` registers — the resolver break fixed in 09b0bb0.
#[utoipa::path(
    post,
    path = "/vp/response/{id}",
    request_body(
        content = VpResponseForm,
        content_type = "application/x-www-form-urlencoded",
        description = "OpenID4VP `direct_post.jwt` authorization response: the `response` \
                       parameter carries the JWE compact serialization of the VP Token"
    ),
    responses((status = 200, body = VerificationResult))
)]
async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body_bytes: axum::body::Bytes,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    // Parse before touching storage: a malformed body is malformed regardless of
    // whether the transaction exists, so rejecting it first keeps the 400
    // deterministic instead of returning 400 or 404 depending on the id.
    let form: VpResponseForm = serde_html_form::from_bytes(&body_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": format!(
                    "expected an application/x-www-form-urlencoded body with a `response` parameter \
                     carrying the JWE (OpenID4VP direct_post.jwt): {e}"
                )
            })),
        )
    })?;

    submit_vp_response(&state, &id, &form.response, "wallet").await
}
```

- [ ] **Step 3: Update the remaining `verifier_wallet_error_response` call sites in the test module**

In the same file's `#[cfg(test)] mod tests`, seven call sites pass only one argument to `verifier_wallet_error_response`. Add `, "wallet"` as the second argument to each:

```rust
let _ = verifier_wallet_error_response(&VerificationError::Decryption("nope".into()));
```
→
```rust
let _ = verifier_wallet_error_response(&VerificationError::Decryption("nope".into()), "wallet");
```

Apply the same one-argument-to-two-argument change to the other six call sites in that test module (search the file for `verifier_wallet_error_response(&VerificationError::` — there are seven total, covering `Decryption("nope"...)`, `Decryption("cek unwrap failed"...)`, `Decryption("x"...)` (twice, in `level_follows_status_class` and `status_mapping_is_unchanged_by_logging`), `StatusUnavailable("dns"...)`, `StatusUnavailable("x"...)`, and `Failed(long.clone())`).

- [ ] **Step 4: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all pass, with zero behavioral change (this step is a pure refactor — `wallet_verification.rs` and the `server.rs` unit tests must pass unchanged).

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/src/server.rs
git commit -m "refactor: extract submit_vp_response helper, parameterize wallet error mapper by surface"
```

---

### Task 2: Add the `POST /admin/verification/requests/:id/dc-api-response` endpoint

**Files:**
- Modify: `crates/foundry/src/server.rs` (new type, new handler, new route)
- Modify: `crates/foundry/src/openapi.rs` (register the new path + schema in `AdminApiDoc`)
- Regenerate: `openapi.json` (byte-identical to generator output, per root AGENTS.md §6)

**Interfaces:**
- Consumes: `submit_vp_response(state, id, encrypted_jwe_str, surface)` from Task 1.
- Produces: `pub(crate) struct AdminDcApiResponseBody { response: String }` and `pub(crate) async fn post_admin_dc_api_response_handler(...)`, both referenced by Task 3's tests and by `openapi.rs`. Route path (axum syntax): `/admin/verification/requests/:id/dc-api-response`.

- [ ] **Step 1: Add the new type and handler to `crates/foundry/src/server.rs`**

Insert immediately after the existing `get_verification_handler` function (which ends around line 862, just before the `#[utoipa::path] get /vp/request/{id}` block):

```rust
/// The Digital Credentials API delivers the wallet's encrypted response as a
/// JS object property (`credentialResponse.data.response`), not a URL-encoded
/// form body, so the admin console submits it here as JSON instead of the
/// `application/x-www-form-urlencoded` shape `VpResponseForm` uses.
/// `foundry-verifier`'s `create_verification_request` always sets
/// `response_mode: "dc_api.jwt"` for `transport: "dc_api"` (never the
/// plaintext `dc_api` mode), so this is always the encrypted-JWE shape — there
/// is no unencrypted variant to additionally support here.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct AdminDcApiResponseBody {
    /// JWE compact serialization of the VP Token response, as delivered in
    /// `credentialResponse.data.response` by `navigator.credentials.get()`.
    response: String,
}

/// Admin-authenticated counterpart to `post_response_handler`, used by the
/// test console to relay the browser's Digital Credentials API response for
/// verification. See `submit_vp_response` for the shared core; the only
/// difference from the wallet-facing route is the request encoding (JSON, not
/// form-urlencoded) and the `surface` log label (`"admin"`, not `"wallet"`).
#[utoipa::path(
    post,
    path = "/admin/verification/requests/{id}/dc-api-response",
    request_body = AdminDcApiResponseBody,
    responses((status = 200, body = VerificationResult))
)]
pub(crate) async fn post_admin_dc_api_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AdminDcApiResponseBody>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    submit_vp_response(&state, &id, &body.response, "admin").await
}
```

- [ ] **Step 2: Register the route in `admin_router`**

In `crates/foundry/src/server.rs`, in the `authenticated` router chain (currently):

```rust
    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route(
            "/admin/verification/requests",
            post(create_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id",
            get(get_verification_handler),
        )
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);
```

add the new route before `.route_layer(...)`:

```rust
    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route(
            "/admin/verification/requests",
            post(create_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id",
            get(get_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id/dc-api-response",
            post(post_admin_dc_api_response_handler),
        )
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);
```

This inherits the same API-key auth as every other `/admin/*` route — no new auth code.

- [ ] **Step 3: Register the path and schema in `crates/foundry/src/openapi.rs`**

In the `AdminApiDoc` derive, change:

```rust
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
        foundry_issuer::AuthorizationCodeGrant,
        foundry_issuer::TxCodeDefinition,
        foundry_verifier::request::CreateVerificationRequest,
        foundry_verifier::request::CreateVerificationResponse,
        foundry_verifier::VerificationTransaction,
        foundry_verifier::VerificationState,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
    ))
```

to:

```rust
    paths(
        crate::server::health,
        crate::server::ready,
        crate::server::create_offer_handler,
        crate::server::create_verification_handler,
        crate::server::get_verification_handler,
        crate::server::post_admin_dc_api_response_handler,
    ),
    components(schemas(
        foundry_issuer::CreateOfferRequest,
        foundry_issuer::CreateOfferResponse,
        foundry_issuer::CredentialOffer,
        foundry_issuer::CredentialOfferGrants,
        foundry_issuer::PreAuthorizedCodeGrant,
        foundry_issuer::AuthorizationCodeGrant,
        foundry_issuer::TxCodeDefinition,
        foundry_verifier::request::CreateVerificationRequest,
        foundry_verifier::request::CreateVerificationResponse,
        foundry_verifier::VerificationTransaction,
        foundry_verifier::VerificationState,
        foundry_verifier::VerificationResult,
        foundry_verifier::CheckResult,
        crate::server::AdminDcApiResponseBody,
    ))
```

- [ ] **Step 4: Regenerate `openapi.json` and confirm the drift test passes**

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo test -p foundry --test openapi_endpoints
```

Expected: `openapi_endpoints.rs` passes, confirming the committed `openapi.json` matches `generate_admin_openapi_spec()` output and every `$ref` resolves.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/src/openapi.rs openapi.json
git commit -m "feat: add POST /admin/verification/requests/:id/dc-api-response"
```

---

### Task 3: Add integration tests for the new endpoint

Per `crates/foundry/tests/AGENTS.md`'s routing rule ("add a router-injection test to the file matching its surface"), these belong in `wallet_verification.rs` — it already owns the full admin-create → response → admin-read verification flow and its `setup_test_app()` helper.

**Files:**
- Modify: `crates/foundry/tests/wallet_verification.rs`

**Interfaces:**
- Consumes: `admin_router`, `AppState`, `AdminApiKey`, `CreateVerificationResponse`, `VerificationResult`, `VerificationState`, `VerificationTransaction` (already imported), `setup_test_app()` (already defined at the top of the file), `foundry_core::crypto::jwe::encrypt_compact`, `foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims}` (already imported).

- [ ] **Step 1: Write the failing happy-path test**

Append to `crates/foundry/tests/wallet_verification.rs` (after the existing `full_verification_flow_end_to_end` test, or anywhere else at module scope):

```rust
#[tokio::test]
async fn dc_api_response_via_admin_endpoint_succeeds() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));

    // 1. Admin POST /admin/verification/requests with transport: "dc_api"
    let create_req_body = serde_json::json!({
        "dcql_query": {
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
            }]
        },
        "transport": "dc_api"
    });

    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);

    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;
    let dc_api_request = create_resp
        .dc_api_request
        .expect("dc_api transport must return dc_api_request");

    let nonce = dc_api_request["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = dc_api_request["client_metadata"]["jwks"]["keys"][0].clone();

    // 2. Issue SD-JWT VC to holder key pair and create KB-JWT. For dc_api the
    //    KB-JWT audience is "origin:<public_base_url>" (OpenID4VP L2543 / IETF
    //    SD-JWT VC Presentation Response L3179), not the x509_hash client_id
    //    used by redirect transports — see foundry-verifier/src/verify.rs's
    //    dc_api audience fallback (no dc_api_expected_origins configured here).
    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));

    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:holder".to_string(),
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/pid".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };

    let issuer_pres = build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();

    let sd_jwt_vc_presentation = attach_kb_jwt(
        issuer_pres,
        &holder_signer,
        "origin:https://localhost:8443",
        &nonce,
        None,
    )
    .unwrap();

    // 3. Encrypt presentation into JWE, as the browser's DigitalCredential
    //    response would contain in credentialResponse.data.response.
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [sd_jwt_vc_presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    // 4. Console relays the response to the new admin endpoint.
    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/admin/verification/requests/{verification_id}/dc-api-response"
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(
            serde_json::json!({ "response": jwe_str }).to_string(),
        ))
        .unwrap();

    let post_resp_res = admin_app.clone().oneshot(post_resp_req).await.unwrap();
    assert_eq!(post_resp_res.status(), StatusCode::OK);

    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_result: VerificationResult = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(verify_result.verified);
    assert_eq!(verify_result.claims["given_name"], "Alice");

    // 5. Admin GET /admin/verification/requests/{id} reflects Verified.
    let get_tx_req = Request::builder()
        .method("GET")
        .uri(format!("/admin/verification/requests/{verification_id}"))
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::empty())
        .unwrap();

    let get_tx_res = admin_app.clone().oneshot(get_tx_req).await.unwrap();
    assert_eq!(get_tx_res.status(), StatusCode::OK);

    let tx_bytes = axum::body::to_bytes(get_tx_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx: VerificationTransaction = serde_json::from_slice(&tx_bytes).unwrap();

    assert_eq!(tx.state, VerificationState::Verified);
}
```

- [ ] **Step 2: Run it to verify it fails (before Task 2's route is registered) or passes (if run after Task 2)**

If this test is written and run strictly after Task 2 is complete (the expected order when following this plan sequentially), it should already pass — this step then just confirms that.

Run: `cargo test -p foundry --test wallet_verification dc_api_response_via_admin_endpoint_succeeds -- --nocapture`

Expected: `PASS`. If it fails with a 404 on the new route, Task 2's route registration was not completed correctly — stop and fix Task 2 before proceeding.

- [ ] **Step 3: Write and run the 404 test**

Append:

```rust
#[tokio::test]
async fn dc_api_response_admin_endpoint_returns_404_for_unknown_id() {
    let (state, _dir, _issuer_cert_pem, _issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));

    let req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests/unknown-id/dc-api-response")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(
            serde_json::json!({ "response": "not-a-real-jwe" }).to_string(),
        ))
        .unwrap();

    let res = admin_app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
```

Run: `cargo test -p foundry --test wallet_verification dc_api_response_admin_endpoint_returns_404_for_unknown_id`

Expected: `PASS`.

- [ ] **Step 4: Write and run the resubmission-rejected test**

Append (reuses the create-request + build-JWE steps from Step 1; submits the same response twice):

```rust
#[tokio::test]
async fn dc_api_response_admin_endpoint_rejects_resubmission() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_test_app().await;
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));

    let create_req_body = serde_json::json!({
        "dcql_query": {
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
            }]
        },
        "transport": "dc_api"
    });

    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;
    let dc_api_request = create_resp.dc_api_request.unwrap();

    let nonce = dc_api_request["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = dc_api_request["client_metadata"]["jwks"]["keys"][0].clone();

    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));

    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: "did:example:holder".to_string(),
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: "https://localhost:8443/vct/pid".to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };

    let issuer_pres = build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();

    let sd_jwt_vc_presentation = attach_kb_jwt(
        issuer_pres,
        &holder_signer,
        "origin:https://localhost:8443",
        &nonce,
        None,
    )
    .unwrap();

    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [sd_jwt_vc_presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/admin/verification/requests/{verification_id}/dc-api-response"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-admin-key")
            .body(Body::from(
                serde_json::json!({ "response": jwe_str }).to_string(),
            ))
            .unwrap()
    };

    let first = admin_app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = admin_app.oneshot(make_req()).await.unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}
```

Run: `cargo test -p foundry --test wallet_verification dc_api_response_admin_endpoint_rejects_resubmission`

Expected: `PASS`.

- [ ] **Step 5: Run the full scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/tests/wallet_verification.rs
git commit -m "test: cover POST /admin/verification/requests/:id/dc-api-response"
```

---

### Task 4: Console UI — `transport` select, DC API button, and JS wiring

**Files:**
- Modify: `crates/foundry/assets/console.html`

**Interfaces:**
- Consumes: `POST /admin/verification/requests/:id/dc-api-response` from Task 2 (JSON body `{"response": "<jwe>"}`, called via the existing `adminFetch` helper already defined in this file).
- Produces: DOM elements `#transport` (now a `<select>`), `#verification-dc-api-btn`; JS functions `hasDigitalCredentialSupport`, `supportsDcApi`, `isDcApiNotSupportedError`, `prepareDcApiRequest`, `invokeDc`, `initDcApiTrigger` — none are consumed outside this file, but Task 5's test asserts on the `#verification-dc-api-btn` id and the `<select id="transport">` markup this task produces.

- [ ] **Step 1: Replace the `transport` text input with a `<select>`**

In `crates/foundry/assets/console.html`, replace:

```html
    <div class="field">
      <label for="transport">transport</label>
      <input type="text" id="transport" value="request_uri">
    </div>
```

with:

```html
    <div class="field">
      <label for="transport">transport</label>
      <select id="transport">
        <option value="request_uri" selected>request_uri (deep link / QR)</option>
        <option value="dc_api">dc_api (Digital Credentials API)</option>
      </select>
    </div>
```

No JS change is needed for this step: `document.getElementById('transport').value.trim() || 'request_uri'` in `initVerification()` already works unchanged against a `<select>`'s `.value`.

- [ ] **Step 2: Add the "Trigger via Digital Credentials API" button and adjust `.open-btn` CSS for button compatibility**

Replace:

```html
    <div class="result hidden" id="verification-result">
      <div class="uri-row">
        <span class="uri-text" id="verification-uri"></span>
        <button class="copy-btn" data-copy-target="verification-uri">Copy</button>
        <a class="open-btn hidden" id="verification-open" target="_self">Open in Wallet</a>
      </div>
```

with:

```html
    <div class="result hidden" id="verification-result">
      <div class="uri-row">
        <span class="uri-text" id="verification-uri"></span>
        <button class="copy-btn" data-copy-target="verification-uri">Copy</button>
        <a class="open-btn hidden" id="verification-open" target="_self">Open in Wallet</a>
        <button class="open-btn hidden" id="verification-dc-api-btn">Trigger via Digital Credentials API</button>
      </div>
```

And update the `.open-btn` CSS rule (it was written only for an `<a>`, which has no default border; a `<button>` needs the browser's default border/background reset explicitly):

```css
  .open-btn {
    display: inline-block;
    background: var(--accent); color: #fff; text-decoration: none;
    border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;
    margin-left: 8px; cursor: pointer;
  }
  .open-btn:hover { background: var(--accent-dark); }
  .open-btn.hidden { display: none; }
```

becomes:

```css
  .open-btn {
    display: inline-block;
    background: var(--accent); color: #fff; text-decoration: none;
    border: none; font: inherit;
    border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;
    margin-left: 8px; cursor: pointer;
  }
  .open-btn:hover { background: var(--accent-dark); }
  .open-btn.hidden { display: none; }
```

- [ ] **Step 3: Add the Digital Credentials API JS helpers**

Insert this block into the `<script>` in `crates/foundry/assets/console.html`, immediately before the existing `function initVerificationModeToggle() {` line (i.e., right after `pollVerification`'s closing `}`):

```js
  // --- Digital Credentials API (dc_api transport) ---
  // Function names and the transient-activation constraint documented on
  // invokeDc are aligned with the proven implementation in
  // eudipay-frontend/src/dcApi.js. Unlike that implementation, there is no
  // fetch-a-signed-request-uri step here: foundry's /admin/verification/requests
  // already returns the full inline, unsigned dc_api_request object, so
  // prepareDcApiRequest is a synchronous wrap, not an async fetch.
  let lastDcApiRequest = null;
  let lastVerificationId = null;

  function hasDigitalCredentialSupport(protocol) {
    if (typeof window === 'undefined' || !window.isSecureContext) return false;
    const dc = window.DigitalCredential;
    if (!dc) return false;
    if (typeof dc.userAgentAllowsProtocol === 'function') {
      try {
        return Boolean(dc.userAgentAllowsProtocol(protocol));
      } catch (e) {
        return false;
      }
    }
    return true;
  }

  function supportsDcApi(method, protocol) {
    if (typeof navigator === 'undefined' || !('credentials' in navigator)) return false;
    if (typeof navigator.credentials[method] !== 'function') return false;
    return hasDigitalCredentialSupport(protocol);
  }

  function isDcApiNotSupportedError(error) {
    const name = error && error.name ? String(error.name) : '';
    const message = error && error.message ? String(error.message) : '';
    return name === 'NotSupportedError'
      || (name === 'TypeError' && /not supported/i.test(message))
      || /CredentialContainer/i.test(message);
  }

  function prepareDcApiRequest(dcApiRequestData) {
    return {
      digital: {
        requests: [{ protocol: 'openid4vp-v1-unsigned', data: dcApiRequestData }]
      }
    };
  }

  // Must be invoked with no preceding await once the click handler starts --
  // Chrome consumes the click's transient activation if any await lands
  // between the click and navigator.credentials.get().
  async function invokeDc(req) {
    const credentialResponse = await navigator.credentials.get(req);
    if (!credentialResponse || credentialResponse.constructor?.name !== 'DigitalCredential') {
      throw new Error('No DigitalCredential returned from navigator.credentials.get');
    }
    return credentialResponse.data;
  }

  function initDcApiTrigger() {
    const dcApiBtn = document.getElementById('verification-dc-api-btn');
    const errorEl = document.getElementById('verification-error');

    dcApiBtn.addEventListener('click', async function () {
      if (!supportsDcApi('get', 'openid4vp-v1-unsigned')) {
        showError(errorEl, new Error('This browser does not support the Digital Credentials API.'));
        return;
      }
      dcApiBtn.disabled = true;
      try {
        const data = await invokeDc(lastDcApiRequest);
        await adminFetch('/admin/verification/requests/' + encodeURIComponent(lastVerificationId) + '/dc-api-response', {
          method: 'POST',
          body: JSON.stringify({ response: data.response })
        });
        // The pollVerification loop already running since "Create Verification
        // Request" was clicked will pick up the Verified/Failed state on its
        // next tick -- no separate render path is introduced here.
      } catch (err) {
        showError(errorEl, isDcApiNotSupportedError(err)
          ? new Error('This browser does not support the Digital Credentials API.')
          : err);
      } finally {
        dcApiBtn.disabled = false;
      }
    });
  }

```

- [ ] **Step 4: Wire the button reveal/hide logic into `initVerification()`'s success handler, and call `initDcApiTrigger()`**

Replace:

```js
        const uri = body.openid4vp_uri || body.request_uri || '';
        const uriEl = document.getElementById('verification-uri');
        const qrEl = document.getElementById('verification-qr');
        const verificationOpenEl = document.getElementById('verification-open');
        qrEl.innerHTML = '';
        if (uri) {
          uriEl.textContent = uri;
          renderQr(qrEl, uri);
          verificationOpenEl.href = uri;
          verificationOpenEl.classList.remove('hidden');
        } else {
          verificationOpenEl.classList.add('hidden');
          if (body.dc_api_request) {
            uriEl.textContent = '(dc_api transport has no scannable URI; use the Digital Credentials API request object returned by the admin endpoint directly)';
          } else {
            uriEl.textContent = '';
          }
        }
```

with:

```js
        const uri = body.openid4vp_uri || body.request_uri || '';
        const uriEl = document.getElementById('verification-uri');
        const qrEl = document.getElementById('verification-qr');
        const verificationOpenEl = document.getElementById('verification-open');
        const dcApiBtn = document.getElementById('verification-dc-api-btn');
        qrEl.innerHTML = '';
        dcApiBtn.classList.add('hidden');
        lastDcApiRequest = null;
        lastVerificationId = null;
        if (uri) {
          uriEl.textContent = uri;
          renderQr(qrEl, uri);
          verificationOpenEl.href = uri;
          verificationOpenEl.classList.remove('hidden');
        } else {
          verificationOpenEl.classList.add('hidden');
          if (body.dc_api_request) {
            uriEl.textContent = '(dc_api transport: click "Trigger via Digital Credentials API" below)';
            lastDcApiRequest = prepareDcApiRequest(body.dc_api_request);
            lastVerificationId = body.verification_id;
            dcApiBtn.classList.remove('hidden');
          } else {
            uriEl.textContent = '';
          }
        }
```

Then, in `initVerification()`, change:

```js
  function initVerification() {
    initVerificationModeToggle();
    const btn = document.getElementById('create-verification-btn');
```

to:

```js
  function initVerification() {
    initVerificationModeToggle();
    initDcApiTrigger();
    const btn = document.getElementById('create-verification-btn');
```

- [ ] **Step 5: Manual smoke check (no automated test for this step — Task 5 covers the structural assertions)**

Run `cargo run -p foundry -- quickstart` in a scratch directory (or reuse an existing dev config) and `cargo run -p foundry -- serve`, then open `/console` in a browser. Confirm:
- The `transport` field is now a dropdown with both options.
- Selecting `dc_api` and clicking "Create Verification Request" reveals "Trigger via Digital Credentials API" instead of a QR code.
- On a browser without DC API support, clicking it shows the "This browser does not support..." error via the existing error banner, without throwing an uncaught exception in the console.

This step has no pass/fail assertion beyond visual confirmation — proceed regardless, since Task 5's structural test is the durable regression guard.

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/assets/console.html
git commit -m "feat: console — trigger dc_api verification via the Digital Credentials API"
```

---

### Task 5: Structural regression test for the console markup

**Files:**
- Modify: `crates/foundry/tests/console.rs`

**Interfaces:**
- Consumes: the `/console` HTML produced by Task 4's changes to `crates/foundry/assets/console.html`.

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry/tests/console.rs`:

```rust
#[tokio::test]
async fn console_has_digital_credentials_api_trigger_for_dc_api_transport() {
    // The console must offer a real way to invoke the dc_api transport in the
    // browser it's running in, not just print a static "use it directly"
    // string: a transport <select> (not free text) with both options, and a
    // button that JS wires to navigator.credentials.get().
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);

    assert!(
        html.contains(r#"<select id="transport">"#),
        "console page should render `transport` as a <select>, not a free-text input"
    );
    assert!(
        html.contains(r#"<option value="request_uri""#),
        "console `transport` select should offer request_uri"
    );
    assert!(
        html.contains(r#"<option value="dc_api">"#),
        "console `transport` select should offer dc_api"
    );
    assert!(
        html.contains(r#"id="verification-dc-api-btn""#),
        "console page should have a button to trigger the Digital Credentials API for dc_api transport"
    );
}
```

- [ ] **Step 2: Run test to verify it passes (if Task 4 is already complete) or fails cleanly (if run standalone before Task 4)**

Run: `cargo test -p foundry --test console console_has_digital_credentials_api_trigger_for_dc_api_transport -- --nocapture`

Expected (after Task 4): `PASS`. If it fails, check that the exact markup strings above (`<select id="transport">`, `<option value="dc_api">`, `id="verification-dc-api-btn"`) are present verbatim in `crates/foundry/assets/console.html`.

- [ ] **Step 3: Run the full scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 4: Commit**

```bash
git add crates/foundry/tests/console.rs
git commit -m "test: console renders a dc_api trigger button and transport select"
```

---

### Task 6: Change record and final scoped verification

**Files:**
- Create: `docs/superpowers/changes/2026-08-03-admin-console-dc-api.md`

- [ ] **Step 1: Write the change record**

```markdown
# Admin Console: Trigger Presentation via the Digital Credentials API

Date: 2026-08-03

## What changed

The admin test console can now exercise the `dc_api` verification transport
end-to-end in the browser it's running in, instead of only printing the raw
`dc_api_request` object as text:

- `transport` in the Verification card is now a `<select>` (`request_uri` /
  `dc_api`) instead of a free-text input.
- Selecting `dc_api` and creating a request reveals a "Trigger via Digital
  Credentials API" button that calls `navigator.credentials.get()` in the
  browser, aligned with the proven patterns in
  `eudipay-frontend/src/dcApi.js`.
- A new admin-authenticated endpoint,
  `POST /admin/verification/requests/:id/dc-api-response`, accepts the
  resulting encrypted JWE as JSON and shares its verification core
  (`submit_vp_response`) with the existing wallet-facing
  `POST /vp/response/:id` — identical HTTP status/error-code classification,
  distinguished only by the `surface` log label (`admin` vs `wallet`).

Issuance is unaffected: the DC API is a presentation-only mechanism in the
pinned OpenID4VP/HAIP specs, with no equivalent in OpenID4VCI.

## Spec and plan

- `docs/superpowers/specs/2026-08-03-admin-console-dc-api-design.md`
- `docs/superpowers/plans/2026-08-03-admin-console-dc-api.md`

## Verification

Scoped gate (root AGENTS.md §5.1), run at each task boundary throughout:
`cargo test -p foundry`, `cargo clippy -p foundry --all-targets -- -D warnings`,
`cargo fmt --check`. No `foundry-verifier` or `foundry-issuer` change was
introduced, so no wider dependent set applied per §5.2.
```

- [ ] **Step 2: Run the scoped gate one final time over the whole feature**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all pass. This is still the scoped gate, not the full workspace gate — root AGENTS.md §5.3's full gate is reserved for branch completion / PR time, per the finishing-a-development-branch skill, and is a separate decision from finishing this plan.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/changes/2026-08-03-admin-console-dc-api.md
git commit -m "docs: add change record for admin console dc_api trigger"
```

---

## Self-Review

**Spec coverage:** Backend endpoint (Task 2), shared error classification (Task 1), console `<select>` + button + JS (Task 4), testing for both backend (Task 3) and console markup (Task 5), OpenAPI registration (Task 2 Step 3-4) — every section of the design spec maps to a task. No issuance-side work was added, matching the spec's explicit non-goal.

**Placeholder scan:** No `TBD`/`TODO` markers; every step shows the actual code to write, not a description of it.

**Type consistency:** `submit_vp_response`'s signature (Task 1) is used identically by `post_response_handler` (Task 1) and `post_admin_dc_api_response_handler` (Task 2). `AdminDcApiResponseBody { response: String }` (Task 2) matches the JSON shape the console's `initDcApiTrigger` (Task 4) sends (`{ response: data.response }`). `dc_api_request`/`verification_id` field names read in Task 3's tests and Task 4's JS match `CreateVerificationResponse`'s actual field names (`foundry-verifier/src/request.rs`).