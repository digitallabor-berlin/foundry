# Admin Console DC API Issuance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the admin test console hand a credential offer to a wallet via the
W3C Digital Credentials API (`navigator.credentials.create()`, Chrome 143+), and
show the operator whether the credential was actually issued.

**Architecture:** `foundry-issuer` composes a second rendering of the
already-built `CredentialOffer` — the DC API `data` payload, offer plus inline
issuer/authorization-server metadata — and returns it as a new
`dc_api_offer` field on `CreateOfferResponse`. A new admin route
`GET /admin/issuance/offers/:id` returns a deliberately narrow projection of the
issuance transaction so the console can poll for `offered → issued`. The console
gains an "Add to Wallet" button that calls `navigator.credentials.create()` and
a status badge fed by that poll. No OpenID4VCI wire behaviour changes.

**Tech Stack:** Rust (Axum, `utoipa`, `serde_json`, `tokio`, `tower`), vanilla
browser JS in a single embedded `console.html`.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-08-04-admin-console-dc-api-issuance-design.md`. Read it before starting.
- **Read first:** `crates/foundry-issuer/AGENTS.md` (Tasks 1, 5) and `crates/foundry/AGENTS.md` (Tasks 2–5).
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside `#[cfg(test)]` and `tests/` (root AGENTS.md §4.1). This includes `as_object_mut()` on a value you just serialized — return an error instead.
- **Every `#[tracing::instrument]` MUST carry `skip_all`** (root AGENTS.md §4.5).
- **Never log:** the pre-authorized code, access token, authorization code, transaction code, `c_nonce`, or the `dc_api_offer` value (it embeds the pre-authorized code).
- **Scoped gate only** (root AGENTS.md §5.1). Per task:
  ```
  cargo test -p foundry-issuer -p foundry
  cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
  cargo fmt --check
  ```
  Drop `-p foundry-issuer` for tasks that touch only `crates/foundry`.
  **Do NOT run `cargo test --workspace`** and **do NOT run `e2e_full_flow`** in a per-task gate. The full gate of §5.3 runs once, at the end of the branch.
- **DC API protocol identifier is `openid4vci-v1`** (verification already uses `openid4vp-v1-unsigned`; do not confuse them).
- **`openapi.json` is committed and byte-compared by `crates/foundry/tests/openapi_endpoints.rs`.** Any change to an admin path or schema requires regenerating it in the same task, or that task's gate fails.
- Run `cargo fmt` (applying) before each commit so `cargo fmt --check` is a no-op.

---

### Task 1: `build_dc_api_offer` and the `dc_api_offer` response field

**Files:**
- Modify: `crates/foundry-issuer/src/offer.rs` (add `build_dc_api_offer` + unit tests)
- Modify: `crates/foundry-issuer/src/create_offer.rs` (add `dc_api_offer` field, populate it, add tests)
- Modify: `crates/foundry-issuer/src/lib.rs:29-32` (export `build_dc_api_offer`)
- Test: `crates/foundry-issuer/src/create_offer.rs` (inline `#[cfg(test)]` module)
- Test: `crates/foundry/tests/issuer_offers.rs` (HTTP-level assertion)

**Interfaces:**
- Consumes: existing `crate::metadata::{build_issuer_metadata, build_authorization_server_metadata}` — both take `&Config` and return owned structs; `CredentialIssuerMetadata.credential_configurations_supported` is a `BTreeMap<String, CredentialConfigurationSupported>`.
- Produces:
  - `foundry_issuer::build_dc_api_offer(cfg: &Config, offer: &CredentialOffer) -> Result<serde_json::Value, IssuanceError>`
  - `CreateOfferResponse.dc_api_offer: serde_json::Value` — a required (non-`Option`) field. Task 4 reads it in the browser as `body.dc_api_offer`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `crates/foundry-issuer/src/create_offer.rs`. Place the helper directly after the existing `test_storage()` function (around line 290).

```rust
    /// `test_config()` plus a second credential type.
    ///
    /// Load-bearing for the narrowing assertion: with only one configured
    /// credential type, "filtered to the offered id" and "not filtered at all"
    /// produce identical output, so the test could not fail.
    fn test_config_two_types() -> Config {
        let mut cfg = test_config();
        cfg.credential_types.push(CredentialType {
            id: "mdl".to_string(),
            format: "mso_mdoc".to_string(),
            vct: None,
            doctype: Some("org.iso.18013.5.1.mDL".to_string()),
            scope: None,
            cryptographic_holder_binding: true,
            display: vec![],
            claims: vec![ClaimDef {
                path: vec!["family_name".to_string()],
                selectively_disclosable: true,
                display: vec![],
            }],
        });
        cfg
    }

    /// The DC API payload must carry the offer's own three members verbatim,
    /// so a wallet reading `dc_api_offer` sees exactly the offer that
    /// `credential_offer_uri` encodes.
    #[tokio::test]
    async fn dc_api_offer_carries_the_offer_and_both_metadata_objects() {
        let cfg = test_config();
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let res = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims,
                tx_code_required: false,
                redirect_uri: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let dc = &res.dc_api_offer;

        assert_eq!(dc["credential_issuer"], "https://issuer.example.com");
        assert_eq!(dc["credential_configuration_ids"], serde_json::json!(["pid"]));
        assert!(
            dc["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
                ["pre-authorized_code"]
                .is_string(),
            "dc_api_offer must carry the pre-authorized_code grant, got: {dc}"
        );
        assert_eq!(
            dc["authorization_server_metadata"]["token_endpoint"],
            "https://issuer.example.com/token"
        );
        assert_eq!(
            dc["credential_issuer_metadata"]["credential_endpoint"],
            "https://issuer.example.com/credential"
        );
    }

    /// `credential_issuer_metadata.credential_configurations_supported` must be
    /// narrowed to the offered ids: the wallet renders its consent screen from
    /// it, and shipping every configured type leaves it guessing which one the
    /// offer is about.
    #[tokio::test]
    async fn dc_api_offer_narrows_credential_configurations_to_the_offered_ids() {
        let cfg = test_config_two_types();
        let storage = test_storage().await;
        let mut claims = serde_json::Map::new();
        claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

        let res = create_offer(
            &cfg,
            &storage,
            CreateOfferRequest {
                credential_type_id: "pid".to_string(),
                claims,
                tx_code_required: false,
                redirect_uri: None,
            },
            1_700_000_000,
        )
        .await
        .unwrap();

        let configs = res.dc_api_offer["credential_issuer_metadata"]
            ["credential_configurations_supported"]
            .as_object()
            .expect("credential_configurations_supported must be an object");

        assert_eq!(
            configs.len(),
            1,
            "expected only the offered configuration, got keys: {:?}",
            configs.keys().collect::<Vec<_>>()
        );
        assert!(
            configs.contains_key("pid"),
            "expected the offered id 'pid', got keys: {:?}",
            configs.keys().collect::<Vec<_>>()
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cargo test -p foundry-issuer dc_api_offer
```
Expected: FAIL — compile error, `no field 'dc_api_offer' on type 'CreateOfferResponse'`.

- [ ] **Step 3: Add `build_dc_api_offer` to `offer.rs`**

At the top of `crates/foundry-issuer/src/offer.rs`, extend the imports:

```rust
use crate::error::IssuanceError;
use crate::metadata::{build_authorization_server_metadata, build_issuer_metadata};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use foundry_core::config::Config;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::RngCore;
use serde::{Deserialize, Serialize};
```

Then add this function immediately after `build_offer_uri`:

```rust
/// Render `offer` as the `data` member of a W3C Digital Credentials API
/// issuance request — `navigator.credentials.create()` with protocol
/// `openid4vci-v1`.
///
/// Sibling of [`build_offer_uri`]: the same offer, rendered for a different
/// wallet-facing transport. Nothing about the OpenID4VCI wire protocol changes
/// — same pre-authorized-code grant, same `/token`, same `/credential`; only
/// the channel by which the offer reaches the wallet differs.
///
/// `openid4vci-v1` is a Chrome origin-trial protocol identifier with **no
/// pinned specification** in `docs/specs/`. The shape below follows Chrome's
/// documentation
/// (<https://developer.chrome.com/blog/digital-credentials-api-143-issuance-ot>),
/// the only normative source that currently exists for it. This is a
/// deliberate, documented departure from root AGENTS.md §4.4's
/// implement-only-against-`docs/specs/` rule; see
/// `docs/superpowers/specs/2026-08-04-admin-console-dc-api-issuance-design.md`.
///
/// `credential_configurations_supported` is narrowed to exactly the
/// configuration ids named in the offer. The wallet renders its consent screen
/// from that map, so shipping every configured credential type would leave it
/// to guess which one the offer is about.
///
/// The returned value embeds the `pre-authorized_code`, exactly as
/// [`CredentialOffer`] and `credential_offer_uri` do. It is a secret: never log
/// it, at any level, under any flag (root AGENTS.md §4.5).
pub fn build_dc_api_offer(
    cfg: &Config,
    offer: &CredentialOffer,
) -> Result<serde_json::Value, IssuanceError> {
    // Serialize the offer rather than hand-building the object: `CredentialOffer`
    // already owns the serde renames for the grant URN key and the hyphenated
    // `pre-authorized_code`, and duplicating them here is how they drift.
    let mut root =
        serde_json::to_value(offer).map_err(|e| IssuanceError::Serialization(e.to_string()))?;

    let mut issuer_metadata = build_issuer_metadata(cfg);
    issuer_metadata
        .credential_configurations_supported
        .retain(|id, _| offer.credential_configuration_ids.contains(id));

    let issuer_metadata = serde_json::to_value(issuer_metadata)
        .map_err(|e| IssuanceError::Serialization(e.to_string()))?;
    let as_metadata = serde_json::to_value(build_authorization_server_metadata(cfg))
        .map_err(|e| IssuanceError::Serialization(e.to_string()))?;

    let obj = root.as_object_mut().ok_or_else(|| {
        IssuanceError::Serialization(
            "CredentialOffer did not serialize to a JSON object".to_string(),
        )
    })?;
    obj.insert("authorization_server_metadata".to_string(), as_metadata);
    obj.insert("credential_issuer_metadata".to_string(), issuer_metadata);

    Ok(root)
}
```

- [ ] **Step 4: Add the field and populate it in `create_offer.rs`**

In `crates/foundry-issuer/src/create_offer.rs`, extend the `crate::offer` import to include `build_dc_api_offer`:

```rust
use crate::offer::{
    build_dc_api_offer, build_offer_uri, generate_pre_authorized_code, generate_tx_code,
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, PreAuthorizedCodeGrant,
    TxCodeDefinition,
};
```

Add the field to `CreateOfferResponse`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateOfferResponse {
    pub transaction_id: String,
    pub credential_offer: CredentialOffer,
    pub credential_offer_uri: String,
    /// The same offer rendered for the W3C Digital Credentials API
    /// (`navigator.credentials.create()`, protocol `openid4vci-v1`) — see
    /// [`build_dc_api_offer`].
    ///
    /// Not `Option`, unlike the verifier's `dc_api_request`: issuance has no
    /// transport fork, so this is always derivable from the offer that was just
    /// built. The caller picks a transport by choosing which field to use.
    #[schema(value_type = Object)]
    pub dc_api_offer: serde_json::Value,
}
```

Replace the function's tail (currently `let credential_offer_uri = build_offer_uri(&offer)?;` through the `Ok(CreateOfferResponse { ... })`) with:

```rust
    let credential_offer_uri = build_offer_uri(&offer)?;
    let dc_api_offer = build_dc_api_offer(cfg, &offer)?;

    Ok(CreateOfferResponse {
        transaction_id,
        credential_offer: offer,
        credential_offer_uri,
        dc_api_offer,
    })
```

- [ ] **Step 5: Export it from `lib.rs`**

In `crates/foundry-issuer/src/lib.rs`, extend the `pub use offer::{...}` block:

```rust
pub use offer::{
    build_dc_api_offer, build_offer_uri, generate_pre_authorized_code, generate_tx_code,
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, PreAuthorizedCodeGrant,
    TxCodeDefinition,
};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run:
```bash
cargo test -p foundry-issuer dc_api_offer
```
Expected: PASS, 2 tests.

- [ ] **Step 7: Add an HTTP-level assertion**

The unit tests above cover the payload shape inside the crate. This one proves
it survives the Axum `Json` serialization boundary and actually reaches an
admin API client — the console reads exactly this.

Append to `crates/foundry/tests/issuer_offers.rs`:

```rust
#[tokio::test]
async fn create_offer_response_carries_a_dc_api_offer() {
    let app = test_app(true).await;
    let body =
        serde_json::json!({ "credential_type_id": "pid", "claims": {}, "tx_code_required": false });
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

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let dc = &json["dc_api_offer"];
    assert!(
        dc.is_object(),
        "dc_api_offer must be present on the create-offer response, got: {json}"
    );
    assert_eq!(dc["credential_issuer"], "https://localhost:8443");
    assert_eq!(dc["credential_configuration_ids"], serde_json::json!(["pid"]));
    assert!(
        dc["authorization_server_metadata"]["token_endpoint"].is_string(),
        "dc_api_offer must inline authorization_server_metadata"
    );
    assert!(
        dc["credential_issuer_metadata"]["credential_configurations_supported"]["pid"].is_object(),
        "dc_api_offer must inline credential_issuer_metadata for the offered id"
    );
}
```

Run:
```bash
cargo test -p foundry --test issuer_offers create_offer_response_carries_a_dc_api_offer
```
Expected: PASS.

- [ ] **Step 8: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. If `cargo test -p foundry` fails on `openapi_endpoints`, that is Step 9 — do it, then re-run.

- [ ] **Step 9: Regenerate the committed admin OpenAPI spec**

`CreateOfferResponse` gained a field, so the committed spec is now stale and
`crates/foundry/tests/openapi_endpoints.rs` compares against it.

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo test -p foundry --test openapi_endpoints
```
Expected: PASS. `openapi-wallet.json` must NOT change — `CreateOfferResponse` is
admin-only. If `git diff --stat openapi-wallet.json` is non-empty, stop and
investigate.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry-issuer/src/offer.rs crates/foundry-issuer/src/create_offer.rs crates/foundry-issuer/src/lib.rs crates/foundry/tests/issuer_offers.rs openapi.json
git commit -m "feat(issuer): render credential offers for the Digital Credentials API"
```

---

### Task 2: `GET /admin/issuance/offers/:id` status endpoint

**Files:**
- Modify: `crates/foundry-issuer/src/transaction.rs:50` (add `utoipa::ToSchema` to `IssuanceState`)
- Modify: `crates/foundry/src/server.rs` (add `AdminIssuanceStatus` + `get_issuance_offer_handler`, register the route at line ~68)
- Modify: `crates/foundry/src/openapi.rs:5-29` (register path + schemas)
- Modify: `openapi.json` (regenerate)
- Test: `crates/foundry/tests/issuer_offers.rs`
- Test: `crates/foundry/tests/wallet_issuance.rs:139-245`

**Interfaces:**
- Consumes: `foundry_issuer::load_transaction(storage: &dyn Storage, transaction_id: &str) -> Result<Option<IssuanceTransaction>, IssuanceError>`; `IssuanceError::kind() -> &'static str`; the existing `internal_error(op, kind, detail) -> StatusCode` helper at `server.rs:240`.
- Produces: `GET /admin/issuance/offers/{id}` → `200` with JSON `{ transaction_id, credential_type_id, state, created_at, status_list_index?, tx_code? }` where `state` is `"offered"` or `"issued"`; `404` for an unknown id. Task 4 polls this and reads `.state` and `.tx_code`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/foundry/tests/issuer_offers.rs`. The file's existing helpers
`test_config(status_list_enabled: bool)` and `test_app(status_list_enabled: bool)`
are reused unchanged.

```rust
/// Helper: create an offer and return the parsed response body.
async fn create_offer_json(app: &axum::Router, tx_code_required: bool) -> serde_json::Value {
    let body = serde_json::json!({
        "credential_type_id": "pid",
        "claims": {},
        "tx_code_required": tx_code_required
    });
    let res = app
        .clone()
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
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: GET the status endpoint, returning (status, parsed body).
async fn get_offer_status(app: &axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/issuance/offers/{id}"))
                .header(AUTHORIZATION, "Bearer test-admin-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn offer_status_reports_offered_for_a_fresh_offer() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (status, json) = get_offer_status(&app, id).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["transaction_id"], id);
    assert_eq!(json["credential_type_id"], "pid");
    assert_eq!(json["state"], "offered");
    assert!(json["created_at"].is_i64());
}

/// The security property from the design doc: `IssuanceTransaction` holds
/// `pre_authorized_code` and `access_token`, which are live bearer credentials
/// against the wallet-facing listener. Returning them would let any admin-key
/// holder redeem an offer intended for a wallet, so the endpoint returns a
/// narrow projection rather than the transaction.
#[tokio::test]
async fn offer_status_never_returns_bearer_credentials_or_claims() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (status, json) = get_offer_status(&app, id).await;
    assert_eq!(status, StatusCode::OK);

    let obj = json.as_object().expect("status response must be an object");
    for forbidden in [
        "pre_authorized_code",
        "access_token",
        "authorization_code",
        "code_challenge",
        "code_challenge_method",
        "dpop_jkt",
        "claims",
        "redirect_uri",
        "issuer_state",
    ] {
        assert!(
            !obj.contains_key(forbidden),
            "offer status must not expose '{forbidden}'; body was: {json}"
        );
    }
}

/// `tx_code` is generated and persisted but surfaced nowhere else, which makes
/// `tx_code_required: true` untestable through the console. Its whole purpose
/// is out-of-band relay to the person completing the flow, and the
/// authenticated operator who created the offer is that channel.
#[tokio::test]
async fn offer_status_returns_the_tx_code_when_one_was_generated() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, true).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (status, json) = get_offer_status(&app, id).await;

    assert_eq!(status, StatusCode::OK);
    let tx_code = json["tx_code"]
        .as_str()
        .expect("tx_code must be present when tx_code_required was set");
    assert_eq!(tx_code.len(), 4, "default tx_code length is 4 digits");
    assert!(tx_code.chars().all(|c| c.is_ascii_digit()));
}

#[tokio::test]
async fn offer_status_omits_the_tx_code_when_none_was_generated() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let (_, json) = get_offer_status(&app, id).await;

    assert!(
        json.get("tx_code").is_none(),
        "tx_code must be omitted when the offer needs none; body was: {json}"
    );
}

#[tokio::test]
async fn offer_status_returns_404_for_an_unknown_transaction_id() {
    let app = test_app(true).await;
    let (status, _) = get_offer_status(&app, "no-such-transaction").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn offer_status_requires_the_admin_bearer_token() {
    let app = test_app(true).await;
    let offer = create_offer_json(&app, false).await;
    let id = offer["transaction_id"].as_str().unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/issuance/offers/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cargo test -p foundry --test issuer_offers offer_status
```
Expected: FAIL — the route does not exist, so the OK assertions see `404`.

- [ ] **Step 3: Add `utoipa::ToSchema` to `IssuanceState`**

In `crates/foundry-issuer/src/transaction.rs` line 50, add the derive.
`VerificationState` in `foundry-verifier` already carries it; this is the same
change for symmetry, and `AdminIssuanceStatus` cannot derive `ToSchema` without
it.

```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    Offered,
    Issued,
}
```

- [ ] **Step 4: Add the type and handler to `server.rs`**

Place both immediately after `create_offer_handler` (which ends around line 196).

```rust
/// Narrow, admin-facing projection of a [`foundry_issuer::IssuanceTransaction`].
///
/// Deliberately **not** the whole transaction, unlike `get_verification_handler`:
/// `IssuanceTransaction` holds `pre_authorized_code` and `access_token`, which
/// are live bearer credentials against the wallet-facing listener. Returning
/// them would let any admin-key holder redeem an offer intended for a wallet,
/// turning a read endpoint into a credential-exfiltration endpoint. Also
/// excluded: `authorization_code`, `code_challenge`, `code_challenge_method`,
/// `dpop_jkt`, `claims`, `redirect_uri`, `issuer_state`.
///
/// `tx_code` **is** included. Its entire purpose is to be relayed out-of-band to
/// the person completing the flow, and the already-authenticated operator who
/// created the offer is that channel; it is surfaced nowhere else today, which
/// makes `tx_code_required: true` untestable through the console. Root
/// AGENTS.md §4.5 forbids *logging* transaction codes and continues to apply
/// unchanged.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AdminIssuanceStatus {
    transaction_id: String,
    credential_type_id: String,
    state: foundry_issuer::IssuanceState,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_list_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_code: Option<String>,
}

/// Read the state of an issuance transaction, so the admin console can show
/// whether a credential was actually issued rather than only that an offer was
/// created.
#[utoipa::path(
    get,
    path = "/admin/issuance/offers/{id}",
    responses(
        (status = 200, body = AdminIssuanceStatus),
        (status = 404, description = "No such issuance transaction")
    )
)]
#[tracing::instrument(skip_all)]
pub(crate) async fn get_issuance_offer_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AdminIssuanceStatus>, StatusCode> {
    let tx = foundry_issuer::load_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|e| internal_error("load_transaction", e.kind(), e))?;
    match tx {
        Some(tx) => Ok(Json(AdminIssuanceStatus {
            transaction_id: tx.transaction_id,
            credential_type_id: tx.credential_type_id,
            state: tx.state,
            created_at: tx.created_at,
            status_list_index: tx.status_list_index,
            tx_code: tx.tx_code,
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}
```

- [ ] **Step 5: Register the route**

In `crates/foundry/src/server.rs`, in the `authenticated` router (line ~67), add
the new route directly after the existing offers route:

```rust
    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route(
            "/admin/issuance/offers/:id",
            get(get_issuance_offer_handler),
        )
        .route(
            "/admin/verification/requests",
            post(create_verification_handler),
        )
```

- [ ] **Step 6: Register the path and schemas in `openapi.rs`**

In `crates/foundry/src/openapi.rs`, add to `AdminApiDoc`'s `paths(...)`:

```rust
        crate::server::get_issuance_offer_handler,
```

and to its `components(schemas(...))`:

```rust
        foundry_issuer::IssuanceState,
        crate::server::AdminIssuanceStatus,
```

- [ ] **Step 7: Run the tests to verify they pass**

Run:
```bash
cargo test -p foundry --test issuer_offers offer_status
```
Expected: PASS, 6 tests.

- [ ] **Step 8: Add the `issued` assertion to the end-to-end issuance test**

In `crates/foundry/tests/wallet_issuance.rs`, inside
`full_issuance_flow_end_to_end`, capture the transaction id where the offer
response is parsed. The existing lines are:

```rust
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();

    let pre_auth_code = offer_json["credential_offer"]["grants"]
```

Insert the capture between them:

```rust
    let offer_json: serde_json::Value = serde_json::from_slice(&offer_bytes).unwrap();

    let transaction_id = offer_json["transaction_id"].as_str().unwrap().to_string();

    let pre_auth_code = offer_json["credential_offer"]["grants"]
```

Then append this to the very end of the same test function, after the existing
`assert!(credential_str.contains('~'));`:

```rust
    // 5. The admin status endpoint must now report the transaction as issued —
    // this is what the console polls to show a real outcome rather than just
    // "an offer was created".
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let status_req = Request::builder()
        .method("GET")
        .uri(format!("/admin/issuance/offers/{transaction_id}"))
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::empty())
        .unwrap();

    let status_res = admin_app.oneshot(status_req).await.unwrap();
    assert_eq!(status_res.status(), StatusCode::OK);

    let status_bytes = axum::body::to_bytes(status_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_json: serde_json::Value = serde_json::from_slice(&status_bytes).unwrap();
    assert_eq!(status_json["state"], "issued");
```

- [ ] **Step 9: Run that test**

Run:
```bash
cargo test -p foundry --test wallet_issuance full_issuance_flow_end_to_end
```
Expected: PASS.

- [ ] **Step 10: Regenerate the committed admin OpenAPI spec**

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo test -p foundry --test openapi_endpoints
```
Expected: PASS. Verify `git diff openapi.json` shows the new
`/admin/issuance/offers/{id}` path and the `AdminIssuanceStatus` +
`IssuanceState` schemas, and that `openapi-wallet.json` is unchanged.

- [ ] **Step 11: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry-issuer -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green.

- [ ] **Step 12: Commit**

```bash
git add crates/foundry-issuer/src/transaction.rs crates/foundry/src/server.rs crates/foundry/src/openapi.rs crates/foundry/tests/issuer_offers.rs crates/foundry/tests/wallet_issuance.rs openapi.json
git commit -m "feat(admin): add GET /admin/issuance/offers/:id status endpoint"
```

---

### Task 3: Console markup and styling for the issuance DC API path

**Files:**
- Modify: `crates/foundry/assets/console.html` (CSS near line 105; issuance card markup near lines 151-158)
- Test: `crates/foundry/tests/console.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces DOM contract consumed by Task 4 — element ids `offer-dc-api-btn`, `issuance-status`, `issuance-tx-code`; CSS classes `badge offered` and `badge issued`.

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry/tests/console.rs`:

```rust
#[tokio::test]
async fn console_has_digital_credentials_api_trigger_for_issuance() {
    // Chrome 143 added navigator.credentials.create() for credential issuance.
    // The console must expose it alongside the existing QR / deep-link
    // affordances, and must be able to report a real outcome (offered ->
    // issued) rather than only that an offer was created.
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
        html.contains(r#"id="offer-dc-api-btn""#),
        "console page should have a button to add the offer to a wallet via the Digital Credentials API"
    );
    assert!(
        html.contains(r#"id="issuance-status""#),
        "console page should have an issuance status badge so the operator sees whether the credential was issued"
    );
    assert!(
        html.contains(r#"id="issuance-tx-code""#),
        "console page should have a place to display the tx_code the wallet will prompt for"
    );
    assert!(
        html.contains("navigator.credentials.create"),
        "console JS should invoke navigator.credentials.create for issuance"
    );
    assert!(
        html.contains("openid4vci-v1"),
        "console JS should use the openid4vci-v1 DC API protocol identifier"
    );
}

#[tokio::test]
async fn console_styles_the_issuance_badge_states() {
    // The stylesheet historically defined only the verification states
    // (pending / verified / failed). The issuance card reports `offered` and
    // `issued`, and renders the server's state name verbatim as the class —
    // so both need rules, or the badge renders unstyled.
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
        html.contains(".badge.offered"),
        "console CSS must style the `offered` issuance state"
    );
    assert!(
        html.contains(".badge.issued"),
        "console CSS must style the `issued` issuance state"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cargo test -p foundry --test console
```
Expected: FAIL on `console_has_digital_credentials_api_trigger_for_issuance`
and `console_styles_the_issuance_badge_states`; the four pre-existing console
tests still pass.

- [ ] **Step 3: Add the badge CSS**

In `crates/foundry/assets/console.html`, after the existing `.badge.failed`
rule (line 105), add:

```css
  /* Issuance states. The issuance badge renders the state name the server
     reported verbatim as its class, so `offered` and `issued` need their own
     rules. Mapping them onto `pending` / `verified` in JS would make the
     rendered class disagree with the reported state — exactly the kind of
     silent translation that makes a debugging tool untrustworthy. */
  .badge.offered { background: rgba(224,168,63,0.18); color: var(--amber); }
  .badge.issued { background: rgba(53,192,122,0.18); color: var(--green); }
```

- [ ] **Step 4: Add the issuance card markup**

Replace the existing `#issuance-result` block (lines ~151-158):

```html
    <div class="result hidden" id="issuance-result">
      <div class="uri-row">
        <span class="uri-text" id="offer-uri"></span>
        <button class="copy-btn" data-copy-target="offer-uri">Copy</button>
        <a class="open-btn hidden" id="offer-open" target="_self">Open in Wallet</a>
      </div>
      <div class="qr-wrap" id="offer-qr"></div>
      <pre class="json" id="offer-json"></pre>
    </div>
```

with:

```html
    <div class="result hidden" id="issuance-result">
      <div class="uri-row">
        <span class="uri-text" id="offer-uri"></span>
        <button class="copy-btn" data-copy-target="offer-uri">Copy</button>
        <a class="open-btn hidden" id="offer-open" target="_self">Open in Wallet</a>
        <button class="open-btn hidden" id="offer-dc-api-btn">Add to Wallet (Digital Credentials API)</button>
      </div>
      <div class="qr-wrap" id="offer-qr"></div>
      <p>Status: <span class="badge offered" id="issuance-status">offered</span></p>
      <p class="hint hidden" id="issuance-tx-code"></p>
      <pre class="json" id="offer-json"></pre>
    </div>
```

A `<button>`, not an `<a>` — it runs JS rather than navigating — reusing the
existing `.open-btn` class and `.hidden` toggle convention, exactly as
`#verification-dc-api-btn` does.

- [ ] **Step 5: Run the tests**

Run:
```bash
cargo test -p foundry --test console
```
Expected: `console_styles_the_issuance_badge_states` PASSES.
`console_has_digital_credentials_api_trigger_for_issuance` still **FAILS** on
its `navigator.credentials.create` / `openid4vci-v1` assertions — that JS
arrives in Task 4. This is expected; do not weaken the test to make it pass.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/assets/console.html crates/foundry/tests/console.rs
git commit -m "feat(console): markup and styling for issuance via the Digital Credentials API"
```

Note for the reviewer: this commit intentionally leaves one test red. Task 4
turns it green. If you are executing tasks in isolation and need every commit
green, merge Tasks 3 and 4 into a single commit.

---

### Task 4: Console JS — invoke `create()` and poll issuance status

**Files:**
- Modify: `crates/foundry/assets/console.html` (JS block: `initIssuance` near line 2606; the DC API helper block near line 2727; `DOMContentLoaded` at the end of the script)

**Interfaces:**
- Consumes: `body.dc_api_offer` and `body.transaction_id` from Task 1's `POST /admin/issuance/offers` response; `GET /admin/issuance/offers/{id}` returning `{ state, tx_code? }` from Task 2; the DOM ids from Task 3; the existing `adminFetch`, `showError`, `clearError`, `renderQr`, `hasDigitalCredentialSupport`, `supportsDcApi`, `isDcApiNotSupportedError`, `POLL_INTERVAL_MS`, `MAX_POLL_FAILURES` helpers.
- Produces: nothing consumed by later tasks.

**Verification note:** there is no JS test harness in this workspace. The
structural test from Task 3 is the automated gate; behavioural verification is
the manual smoke test in Step 7. Do not invent a JS test runner for this task.

- [ ] **Step 1: Generalize `prepareDcApiRequest` over the protocol**

The existing function hardcodes the presentation protocol. Replace it:

```js
  function prepareDcApiRequest(dcApiRequestData, protocol) {
    return {
      digital: {
        requests: [{ protocol: protocol, data: dcApiRequestData }]
      }
    };
  }
```

Update its one existing call site, inside `initVerification`'s success handler:

```js
            lastDcApiRequest = prepareDcApiRequest(body.dc_api_request, 'openid4vp-v1-unsigned');
```

- [ ] **Step 2: Add `invokeDcCreate`**

Add directly after the existing `invokeDc` function:

```js
  // Issuance counterpart of invokeDc, and deliberately NOT symmetric with it:
  // no return-shape assertion. Chrome's documented example for issuance
  // ignores create()'s return value entirely, so asserting
  // `constructor?.name === 'DigitalCredential'` the way invokeDc does would
  // manufacture failures on a successful handoff. Non-throw is the success
  // signal.
  //
  // Same transient-activation constraint as invokeDc: no await may land between
  // the click and navigator.credentials.create(), or Chrome consumes the
  // click's activation and the call is rejected.
  async function invokeDcCreate(req) {
    await navigator.credentials.create(req);
  }
```

- [ ] **Step 3: Add issuance polling**

Insert this **after** `pollVerification` ends and immediately before the
`// --- Digital Credentials API (dc_api transport) ---` comment (line ~2727).

Placement matters: `POLL_INTERVAL_MS` and `MAX_POLL_FAILURES` are declared with
`const` in the `// --- Verification ---` section (line ~2656), which is *below*
the `// --- Issuance ---` section. Putting this block above them would reference
them before their declaration — safe at runtime (nothing runs until a click) but
fragile and confusing. Below them, it reads in order.

```js
  // --- Issuance status polling ---
  // Its own timer, deliberately not shared with the verification card's
  // `pollTimer`: a shared timer would let creating a verification request
  // silently cancel issuance polling.
  let issuancePollTimer = null;
  let issuancePollFailures = 0;

  function stopIssuancePolling() {
    if (issuancePollTimer) {
      clearTimeout(issuancePollTimer);
      issuancePollTimer = null;
    }
  }

  function renderIssuanceStatus(status) {
    const statusEl = document.getElementById('issuance-status');
    const txCodeEl = document.getElementById('issuance-tx-code');

    statusEl.textContent = status.state;
    statusEl.className = 'badge ' + status.state;

    if (status.tx_code) {
      txCodeEl.textContent = 'Transaction code (the wallet will prompt for this): ' + status.tx_code;
      txCodeEl.classList.remove('hidden');
    } else {
      txCodeEl.textContent = '';
      txCodeEl.classList.add('hidden');
    }
  }

  function pollIssuance(id, errorEl) {
    stopIssuancePolling();
    issuancePollFailures = 0;

    function tick() {
      adminFetch('/admin/issuance/offers/' + encodeURIComponent(id), { method: 'GET' })
        .then(function (status) {
          issuancePollFailures = 0;
          renderIssuanceStatus(status);
          if (status.state === 'offered') {
            issuancePollTimer = setTimeout(tick, POLL_INTERVAL_MS);
          }
        })
        .catch(function (err) {
          if (err && err.status) {
            // Hard error (404/500/...): stop polling, surface it.
            showError(errorEl, err);
            return;
          }
          issuancePollFailures += 1;
          if (issuancePollFailures >= MAX_POLL_FAILURES) {
            showError(errorEl, new Error('Gave up polling issuance status after ' + MAX_POLL_FAILURES + ' failed attempts.'));
            return;
          }
          issuancePollTimer = setTimeout(tick, POLL_INTERVAL_MS);
        });
    }

    tick();
  }
```

Do **not** redeclare `POLL_INTERVAL_MS` or `MAX_POLL_FAILURES` — reuse the
existing `const`s from the verification section.

`initIssuance` (earlier in the file) calls `pollIssuance`, `stopIssuancePolling`,
`invokeDcCreate`, and `supportsDcApi`, all declared later. That is fine: `function`
declarations are hoisted within the IIFE, and every call happens inside an event
handler that fires long after the script has finished evaluating. Do not reorder
the file to "fix" this.

- [ ] **Step 4: Wire the issuance card**

Replace the whole `initIssuance` function with this version. The changes are:
module-scoped `lastDcApiOffer` / `lastIssuanceId`, reset discipline at the top
of the click handler, revealing the button, and starting the poll.

```js
  // --- Issuance ---
  let lastDcApiOffer = null;
  let lastIssuanceId = null;

  function initIssuanceDcApiTrigger() {
    const dcApiBtn = document.getElementById('offer-dc-api-btn');
    const errorEl = document.getElementById('issuance-error');

    dcApiBtn.addEventListener('click', async function () {
      if (!supportsDcApi('create', 'openid4vci-v1')) {
        showError(errorEl, new Error('This browser does not support the Digital Credentials API for issuance.'));
        return;
      }
      dcApiBtn.disabled = true;
      try {
        await invokeDcCreate(lastDcApiOffer);
        // Nothing to relay: unlike presentation, the wallet talks directly to
        // the wallet-facing listener (/token, /credential) after the handoff.
        // The pollIssuance loop already running since "Create Offer" was
        // clicked observes the Offered -> Issued transition on its next tick.
      } catch (err) {
        showError(errorEl, isDcApiNotSupportedError(err)
          ? new Error('This browser does not support the Digital Credentials API for issuance.')
          : err);
      } finally {
        dcApiBtn.disabled = false;
      }
    });
  }

  function initIssuance() {
    initIssuanceDcApiTrigger();
    const btn = document.getElementById('create-offer-btn');
    const errorEl = document.getElementById('issuance-error');
    const resultEl = document.getElementById('issuance-result');
    const dcApiBtn = document.getElementById('offer-dc-api-btn');
    const txCodeEl = document.getElementById('issuance-tx-code');

    btn.addEventListener('click', async function () {
      clearError(errorEl);
      resultEl.classList.add('hidden');
      stopIssuancePolling();
      dcApiBtn.classList.add('hidden');
      txCodeEl.classList.add('hidden');
      lastDcApiOffer = null;
      lastIssuanceId = null;

      const credentialTypeId = document.getElementById('cred-type-id').value.trim();
      const claimsRaw = document.getElementById('claims-json').value;
      const txCodeRequired = document.getElementById('tx-code-required').checked;

      let claims;
      try {
        claims = claimsRaw.trim() ? JSON.parse(claimsRaw) : {};
      } catch (e) {
        showError(errorEl, new Error('claims is not valid JSON: ' + e.message));
        return;
      }

      btn.disabled = true;
      try {
        const body = await adminFetch('/admin/issuance/offers', {
          method: 'POST',
          body: JSON.stringify({
            credential_type_id: credentialTypeId,
            claims: claims,
            tx_code_required: txCodeRequired
          })
        });

        document.getElementById('offer-uri').textContent = body.credential_offer_uri;
        document.getElementById('offer-json').textContent = JSON.stringify(body.credential_offer, null, 2);
        renderQr(document.getElementById('offer-qr'), body.credential_offer_uri);
        const offerOpenEl = document.getElementById('offer-open');
        offerOpenEl.href = body.credential_offer_uri;
        offerOpenEl.classList.remove('hidden');

        if (body.dc_api_offer) {
          lastDcApiOffer = prepareDcApiRequest(body.dc_api_offer, 'openid4vci-v1');
          lastIssuanceId = body.transaction_id;
          dcApiBtn.classList.remove('hidden');
        }

        document.getElementById('issuance-status').textContent = 'offered';
        document.getElementById('issuance-status').className = 'badge offered';
        resultEl.classList.remove('hidden');

        pollIssuance(body.transaction_id, errorEl);
      } catch (err) {
        showError(errorEl, err);
      } finally {
        btn.disabled = false;
      }
    });
  }
```

`lastIssuanceId` is assigned for symmetry with the verification card and for
debuggability; the click handler does not need it, because the poll started by
"Create Offer" already carries the id.

- [ ] **Step 5: Run the console test**

Run:
```bash
cargo test -p foundry --test console
```
Expected: all console tests PASS, including
`console_has_digital_credentials_api_trigger_for_issuance` (which was left red
by Task 3).

- [ ] **Step 6: Run the scoped gate**

```bash
cargo fmt
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. `foundry-issuer` is untouched by this task, so it is not in
the gate.

- [ ] **Step 7: Manual smoke test (record the result, do not skip)**

```bash
cargo run -p foundry -- quickstart
cargo run -p foundry -- serve
```

Open `http://127.0.0.1:9000/console`, paste the admin API key, and confirm:

1. "Create Offer" shows the QR, the "Open in Wallet" link, **and** the new "Add
   to Wallet (Digital Credentials API)" button.
2. The status badge reads `offered` in amber.
3. In a browser without the DC API (e.g. Firefox, or Chrome with the flag off),
   clicking the new button shows the "does not support" error and does **not**
   throw an unhandled rejection in the devtools console.
4. Tick `tx_code_required`, click "Create Offer" — a 4-digit transaction code
   appears under the status badge.
5. Click "Create Offer" a second time — the button, the tx-code line, and the
   badge all reset rather than showing stale values.

Report which of these five you observed. If you cannot run a browser, say so
explicitly rather than reporting them as passed.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry/assets/console.html
git commit -m "feat(console): add credentials to a wallet via navigator.credentials.create"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md:251-285` (Admin Test Console section)
- Modify: `crates/foundry/AGENTS.md:49` (admin route table)
- Modify: `crates/foundry-issuer/AGENTS.md` (module map row for `offer.rs`; public surface "Offer:" bullet)
- Modify: `crates/foundry/tests/AGENTS.md` (coverage for `issuer_offers.rs` and `console.rs`)
- Create: `docs/superpowers/changes/2026-08-04-admin-console-dc-api-issuance.md`

**Interfaces:**
- Consumes: everything from Tasks 1-4. No code changes.
- Produces: nothing.

- [ ] **Step 1: Update the README console section**

In `README.md`, replace the existing Issuance bullet (line ~258):

```markdown
- **Issuance**: enter a `credential_type_id` and `claims` JSON, click
  "Create Offer" — get back the `credential_offer_uri` as copyable text and
  as a QR code. Scan it with a real wallet to complete the flow.
```

with:

```markdown
- **Issuance**: enter a `credential_type_id` and `claims` JSON, click
  "Create Offer" — get back the `credential_offer_uri` as copyable text and
  as a QR code. Scan it with a real wallet, tap **Open in Wallet** on the same
  device, or use **Add to Wallet (Digital Credentials API)** to hand the offer
  to the platform's wallet picker (see below). The page polls the transaction
  and shows `offered` → `issued`, plus the transaction code when
  `tx_code_required` is set.
```

- [ ] **Step 2: Add the DC API prerequisites subsection**

In `README.md`, insert this immediately before the paragraph beginning "The
console plus a real wallet app is the supported way to drive an issuance"
(line ~275):

```markdown
##### Digital Credentials API prerequisites

Both "Add to Wallet (Digital Credentials API)" (issuance,
`navigator.credentials.create()`) and "Trigger via Digital Credentials API"
(presentation, `navigator.credentials.get()`) invoke a browser API with
platform requirements the console cannot satisfy on your behalf:

- Chrome 143 or later, and Google Play services 24.0 or later on the Android
  device.
- `chrome://flags/#web-identity-digital-credentials-creation` enabled (issuance
  is an origin trial; `foundry` embeds no origin-trial token, since the console
  is a local testing tool rather than a deployed origin).
- A supported wallet app installed on the Android device.
- **`issuer.credential_issuer` must be reachable from the Android device.** A
  `localhost` or `127.0.0.1` issuer URL fails the cross-device flow even though
  the QR scans correctly and the handoff appears to succeed — the wallet
  resolves `credential_issuer` itself when it calls `/token`. Use a
  LAN-reachable host or a tunnel. This is the failure mode most likely to be
  misread as a `foundry` bug.

The console never gates the buttons on browser sniffing: it always offers them
and reports an unsupported browser at the point of use.

Note that the Digital Credentials API is a **platform handoff channel, not a
protocol**. The payload handed to the wallet is the same OpenID4VCI Credential
Offer the deep link carries, so `/token` and `/credential` behave identically
regardless of which affordance you used.
```

- [ ] **Step 3: Update `crates/foundry/AGENTS.md`**

In the admin route table, add a row directly after the
`/admin/issuance/offers` row (line 49):

```markdown
| `/admin/issuance/offers/:id` | GET | **Bearer** | `get_issuance_offer_handler` → `foundry_issuer::load_transaction`, projected to `AdminIssuanceStatus` |
```

Then add this bullet to that file's **Gotchas** section:

```markdown
- **`AdminIssuanceStatus` is a deliberate narrowing, not laziness.**
  `get_issuance_offer_handler` must never return `pre_authorized_code` or
  `access_token`: both are live bearer credentials against the wallet-facing
  listener, so echoing them would let an admin-key holder redeem an offer meant
  for a wallet. `tx_code` *is* returned on purpose — it is surfaced nowhere else,
  and out-of-band relay to the operator is its entire function. Enforced by
  `offer_status_never_returns_bearer_credentials_or_claims` in
  `tests/issuer_offers.rs`. Note the contrasting older precedent:
  `get_verification_handler` still returns its whole `VerificationTransaction`,
  `ephem_private_jwk` included — a known wart, not a pattern to copy.
```

- [ ] **Step 4: Update `crates/foundry-issuer/AGENTS.md`**

In the Module Map, change the `offer.rs` row to:

```markdown
| `offer.rs` | Offer **primitives**: `CredentialOffer` and its grant structs, `generate_pre_authorized_code()`, `generate_tx_code()`, `build_offer_uri()`, `build_dc_api_offer()` |
```

In "Other public surface", change the **Offer:** bullet to:

```markdown
- **Offer:** `CredentialOffer`, `CredentialOfferGrants`, `PreAuthorizedCodeGrant`,
  `TxCodeDefinition`, `build_offer_uri`, `build_dc_api_offer`,
  `generate_pre_authorized_code`, `generate_tx_code`.
```

Add this bullet to that file's **Gotchas** section:

```markdown
- **`build_dc_api_offer` is the one place in this crate implemented against
  vendor documentation rather than `docs/specs/`.** The `openid4vci-v1`
  protocol identifier is a Chrome origin-trial identifier with no pinned
  specification; the payload shape follows
  <https://developer.chrome.com/blog/digital-credentials-api-143-issuance-ot>.
  A documented deviation from root AGENTS.md §4.4 — see
  `docs/superpowers/specs/2026-08-04-admin-console-dc-api-issuance-design.md`.
  It narrows `credential_configurations_supported` to the offered ids, so it is
  deliberately *not* byte-identical to `GET /.well-known/openid-credential-issuer`.
  Its output embeds the `pre-authorized_code`: never log it.
```

- [ ] **Step 5: Update `crates/foundry/tests/AGENTS.md`**

Replace the `console.rs` row (line 25) and the `issuer_offers.rs` row (line 26)
of the coverage table with:

```markdown
| `console.rs` | `/console` returns HTML when enabled, 404 when disabled; QR SVG has explicit dimensions; the DC API trigger buttons and issuance status badge are present, and `.badge.offered` / `.badge.issued` are styled | `server::console_handler`, `admin.console_enabled` |
| `issuer_offers.rs` | `POST /admin/issuance/offers` succeeds with a valid Bearer token, rejected without one; the response carries a `dc_api_offer` with inlined metadata; `GET /admin/issuance/offers/:id` reports `offered`, returns the `tx_code`, 404s on an unknown id, and **never** returns `pre_authorized_code` / `access_token` / `claims` | `server::create_offer_handler`, `server::get_issuance_offer_handler`, `require_api_key`, `foundry_issuer::create_offer` |
```

- [ ] **Step 6: Write the change record**

Create `docs/superpowers/changes/2026-08-04-admin-console-dc-api-issuance.md`
following the structure of
`docs/superpowers/changes/2026-08-03-admin-console-dc-api.md`: a "What changed"
section, links to this plan and its spec, and a "Verification" section naming
the gate that was actually run (root AGENTS.md §5.5 — name the gate, do not
claim one you did not run).

Cover:
- `dc_api_offer` on `CreateOfferResponse`, built by
  `foundry_issuer::build_dc_api_offer`, with metadata narrowed to the offered
  configuration ids.
- The new `GET /admin/issuance/offers/:id` endpoint and why it returns a
  narrow projection.
- `tx_code` becoming visible to the operator for the first time.
- The console button, status badge, and unconditional polling.
- Explicitly correct the prior change record's claim that "Issuance is
  unaffected: the DC API is a presentation-only mechanism ... with no
  equivalent in OpenID4VCI." Still true of the pinned specs; no longer true of
  the platform.
- The `get_verification_handler` / `ephem_private_jwk` follow-up, left open.

- [ ] **Step 7: Verify no code changed**

```bash
git status --short
```
Expected: only `README.md`, the three `AGENTS.md` files, and the new change
record. No `.rs`, no `.html`, no `openapi*.json`. If code appears here, it
belongs in an earlier task's commit.

- [ ] **Step 8: Commit**

```bash
git add README.md crates/foundry/AGENTS.md crates/foundry-issuer/AGENTS.md crates/foundry/tests/AGENTS.md docs/superpowers/changes/2026-08-04-admin-console-dc-api-issuance.md
git commit -m "docs: record admin console DC API issuance support"
```

---

## Final Gate (run once, after Task 5 — not per task)

Per root AGENTS.md §5.3, exactly one trigger applies here: the branch is
finished and ready for whole-branch review.

```bash
cargo fmt
cargo fmt --check
cargo test --workspace
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
```

Then dispatch the `final-reviewer` agent for the whole-branch review. Do not
re-run this gate after merging (§5.4).