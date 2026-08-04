# DPoP Nonces at the Unauthenticated Freshness Endpoints — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a `DPoP-Nonce` response header from `POST /nonce` and `POST /challenge`, gated on the existing `issuer.dpop.nonce_mode`, so Google Wallet can obtain its first DPoP nonce without a rejection round trip.

**Architecture:** Two Axum handlers in `crates/foundry/src/server.rs` change their return type from a fixed one-element header array to `HeaderMap`, then call the already-existing `dpop_nonce_header(&state, now)` helper — the same one `token_handler` uses. No new configuration, no new helper, no changes to `foundry-issuer`. The rest of the branch is documentation, a conformance-row evidence update, a redaction proof, and an OpenAPI regeneration.

**Tech Stack:** Rust, Axum 0.8 (`HeaderMap`, `IntoResponse`), utoipa (OpenAPI generation), tokio test harness, josekit (test-side JWT signing).

**Design doc:** [`docs/superpowers/specs/2026-08-04-dpop-nonce-freshness-endpoints-design.md`](../specs/2026-08-04-dpop-nonce-freshness-endpoints-design.md) — read it before starting; it records why the gate is `nonce_mode` and not a new key, and why the vendor profile may not override a specification.

## Global Constraints

- **Read `crates/foundry/AGENTS.md` first.** You will be editing `crates/foundry/src/server.rs` and `crates/foundry/tests/`; that file is the module map and is not auto-loaded.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in `crates/foundry/src/`** — root `AGENTS.md` §4.1. Test code (`#[cfg(test)]` and files under `tests/`) is exempt and unwraps freely there, matching the existing style.
- **Every `#[tracing::instrument]` carries `skip_all`** — root `AGENTS.md` §4.5. This plan adds no instrumentation, so the rule is satisfied by not violating it.
- **Never log a DPoP `nonce` value**, at any level, under any flag — root `AGENTS.md` §4.5. This plan adds no log statements at all; Task 3 proves the absence behaviourally.
- **Any behaviour justified only by the vendor profile MUST carry a code comment naming it** — root `AGENTS.md` §4.4, vendor-profile rule. Both header insertions in this plan are such behaviour.
- **Gate is scoped, not workspace** — root `AGENTS.md` §5.1. Every task ends with `cargo test -p foundry`, `cargo clippy -p foundry --all-targets -- -D warnings`, `cargo fmt --check`. **Do not run `cargo test --workspace`** between or at the end of tasks; the §5.3 full gate runs once, after Task 3, before review. While iterating, narrow with `cargo test -p foundry --test conformance_http`.
- **Exact header name:** `DPoP-Nonce`. In code, construct via `axum::http::HeaderName::from_static("dpop-nonce")` — `from_static` requires lowercase input and axum normalises per RFC 9110. This is already how `dpop_nonce_header` does it; do not change it.
- **`HeaderMap::insert`, never `append`** — RFC 9449 §8: "there MUST NOT be more than one DPoP-Nonce header."
- **Branch:** `feature/dpop-nonce-freshness-endpoints`, already created, already carrying the design commit `03a8645`.
- **Already done in `03a8645` — do not redo:** the vendor profile is already checked in at `docs/specs/google-wallet-openid4vci-profile.md`, and root `AGENTS.md` §4.4 already carries its table row and the vendor-profile precedence rule. The design doc's §3.3 and its §7 documentation table describe work that is complete. Read both; change neither.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/foundry/src/server.rs` | Axum routers and handlers for both listeners | Modify `nonce_handler` and `challenge_handler`: return `(HeaderMap, Json<T>)`, insert the conditional nonce header. Modify both `#[utoipa::path]` blocks to document the header. |
| `crates/foundry/tests/conformance_http.rs` | HTTP-level conformance assertions, including the existing DPoP-Nonce block | Add one test helper and four tests; extend one existing test. |
| `crates/foundry/tests/logging_redaction.rs` | Behavioural proof that never-log values never reach a log record | Extend `IssuanceSecrets`, the `drive_issuance_with_challenge_and_nonce` driver, and the existing `issuance_never_logs_challenges_or_dpop_nonces` loop. **No new test** — the existing one already has the harness, the non-vacuity guard, and a positive control. |
| `docs/conformance/openid4vc-conformance.md` | Clause-by-clause conformance record | Extend RFC-9449-0008's evidence and test list. No new row, no status change. |
| `README.md` | Operator-facing documentation | Extend the "Server-Provided DPoP Nonces" section's list of emission points. |
| `openapi-wallet.json` | Committed wallet-facing OpenAPI spec | Regenerate. Drift-tested by `tests/openapi_endpoints.rs`, so forgetting this fails the suite. |

Not touched: `foundry-issuer` (supplies `mint_dpop_nonce`, unmodified), any config model, `openapi.json` (admin spec — neither endpoint is on the admin listener).

---

## Task 1: `/nonce` emits a `DPoP-Nonce` header

**Files:**
- Modify: `crates/foundry/src/server.rs` — `nonce_handler` and its `#[utoipa::path]` attribute
- Test: `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: `dpop_nonce_header(state: &AppState, now_unix: i64) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)>` — already defined in `server.rs`, returns `None` when `state.config.issuer.dpop.nonce_mode == foundry_core::config::Mode::Disabled`. Do not modify it.
- Consumes (test side, all already defined in `conformance_http.rs`): `setup_test_app() -> (AppState, tempfile::TempDir)`, `setup_test_app_with_dpop(dpop: DpopConfig) -> (AppState, tempfile::TempDir)`, `create_pre_auth_offer(&AppState) -> String`, `create_dpop_proof(&EcKeyPair, method: &str, htu: &str, jti: &str, iat: i64, access_token: Option<&str>, nonce: Option<&str>) -> String`, `post_token_with_dpop(&AppState, pre_auth_code: &str, proof: &str) -> axum::http::Response<Body>`, `pop_test_now_secs() -> i64`, `wallet_router(AppState) -> Router`.
- Produces: `nonce_handler` returning `Result<(HeaderMap, Json<NonceResponse>), (StatusCode, Json<serde_json::Value>)>`. Task 2 mirrors this shape for `challenge_handler`; Task 3 documents it.

- [ ] **Step 1: Write the failing tests**

Append to `crates/foundry/tests/conformance_http.rs`, at the end of the existing DPoP-Nonce block — immediately after `no_dpop_nonce_header_is_emitted_when_nonce_mode_is_disabled` (which ends around line 2113) and before the comment `/// A nonce-less proof must NOT be turned into a nonce error...`:

```rust
// ---------------------------------------------------------------------------
// Google Wallet vendor profile (docs/specs/google-wallet-openid4vci-profile.md),
// "Credential Endpoint": "DPoP Nonce is expected to be returned from the c_nonce
// endpoint." No pinned specification requires this; OpenID4VCI 1.1 WG draft
// §8.2-4 standardises it and this repository pins 1.0. See
// docs/superpowers/specs/2026-08-04-dpop-nonce-freshness-endpoints-design.md.
// ---------------------------------------------------------------------------

/// The primary behaviour, under both enabled modes.
#[tokio::test]
async fn the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled() {
    for nonce_mode in [Mode::Optional, Mode::Required] {
        let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
            mode: Mode::Required,
            nonce_mode: nonce_mode.clone(),
            ..DpopConfig::default()
        })
        .await;
        let wallet_app = wallet_router(state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/nonce")
            .body(Body::empty())
            .unwrap();
        let res = wallet_app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK, "nonce_mode: {nonce_mode:?}");
        assert!(
            res.headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| !s.is_empty()),
            "nonce_mode {nonce_mode:?}: /nonce must supply a DPoP-Nonce"
        );
        // RFC 9449 §8: never more than one.
        assert_eq!(res.headers().get_all("DPoP-Nonce").iter().count(), 1);
        // OpenID4VCI §7.2 must survive the return-type change.
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
}

/// The header must carry a *usable* nonce, not merely a well-formed one: the
/// value taken from `/nonce` is accepted by the very next `/token` DPoP proof
/// under `nonce_mode: required`, which is the whole point of emitting it.
/// This is the test that would catch a wrong `Domain` or a wrong TTL.
#[tokio::test]
async fn a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint() {
    let (state, _dir) = setup_test_app_with_dpop(DpopConfig {
        mode: Mode::Required,
        nonce_mode: Mode::Required,
        ..DpopConfig::default()
    })
    .await;
    let pre_auth_code = create_pre_auth_offer(&state).await;

    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let dpop_nonce = nonce_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("/nonce must supply a DPoP-Nonce to retry with")
        .to_string();

    let kp = EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let proof = create_dpop_proof(
        &kp,
        "POST",
        "https://issuer.example.com/token",
        "jti-nonce-endpoint-1",
        pop_test_now_secs(),
        None,
        Some(&dpop_nonce),
    );
    let res = post_token_with_dpop(&state, &pre_auth_code, &proof).await;

    // No `use_dpop_nonce` round trip: the first attempt succeeds.
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a nonce minted by /nonce must satisfy nonce_mode: required at /token"
    );
}
```

Then extend the existing disabled-mode test. Replace its final line (`assert!(cred_res.headers().get("DPoP-Nonce").is_none());`, around line 2112) with:

```rust
    assert!(cred_res.headers().get("DPoP-Nonce").is_none());

    // The default posture must also hold at the unauthenticated freshness
    // endpoint: enabling nothing means emitting nothing, anywhere.
    let wallet_app = wallet_router(state.clone());
    let nonce_req = Request::builder()
        .method("POST")
        .uri("/nonce")
        .body(Body::empty())
        .unwrap();
    let nonce_res = wallet_app.oneshot(nonce_req).await.unwrap();
    assert_eq!(nonce_res.status(), StatusCode::OK);
    assert!(nonce_res.headers().get("DPoP-Nonce").is_none());
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry --test conformance_http -- the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint no_dpop_nonce_header_is_emitted_when_nonce_mode_is_disabled
```

Expected: the first two FAIL. `the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled` fails on `/nonce must supply a DPoP-Nonce`; `a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint` fails at the `.expect("/nonce must supply a DPoP-Nonce to retry with")`. The extended disabled-mode test PASSES already — it asserts an absence that is currently true, which is exactly what makes it a valid negative control after the change.

If either of the first two *passes* at this step, stop: the header is already being emitted from somewhere and the premise of this plan is wrong.

- [ ] **Step 3: Change `nonce_handler`**

In `crates/foundry/src/server.rs`, replace the `#[utoipa::path]` attribute and body of `nonce_handler`. The current form is:

```rust
#[utoipa::path(
    post,
    path = "/nonce",
    responses((status = 200, body = NonceResponse))
)]
async fn nonce_handler(
    State(state): State<AppState>,
) -> Result<
    (
        [(axum::http::HeaderName, &'static str); 1],
        Json<NonceResponse>,
    ),
    (StatusCode, Json<serde_json::Value>),
> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::issue_nonce(state.nonce_secret.as_ref(), now)
        .map_err(|e| wallet_error_response(&e))?;

    // Section 7.2: the Credential Issuer MUST make the response uncacheable
    // by adding a Cache-Control header field including the value `no-store`.
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(res)))
}
```

Replace with:

```rust
#[utoipa::path(
    post,
    path = "/nonce",
    responses(
        (status = 200, body = NonceResponse,
         description = "Uncacheable per Section 7.2 (`Cache-Control: no-store`). \
                        Also carries a fresh `DPoP-Nonce` header when \
                        `issuer.dpop.nonce_mode` is `optional` or `required`."),
    )
)]
async fn nonce_handler(
    State(state): State<AppState>,
) -> Result<(HeaderMap, Json<NonceResponse>), (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::issue_nonce(state.nonce_secret.as_ref(), now)
        .map_err(|e| wallet_error_response(&e))?;

    let mut out = HeaderMap::new();
    // Section 7.2: the Credential Issuer MUST make the response uncacheable
    // by adding a Cache-Control header field including the value `no-store`.
    out.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    // Vendor accommodation, not conformance: the Google Wallet profile
    // (docs/specs/google-wallet-openid4vci-profile.md, "Credential Endpoint")
    // expects the DPoP nonce to be retrieved from this endpoint. OpenID4VCI 1.1
    // WG draft §8.2-4 standardises it; this repository pins 1.0, which does not,
    // so the profile is the only source. Gated on the same `nonce_mode` that
    // governs whether a presented `nonce` is verified at all -- handing out a
    // nonce the server will not check would advertise a freshness guarantee
    // that does not exist. `insert`, not `append`: RFC 9449 §8 forbids a second
    // DPoP-Nonce header.
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }
    Ok((out, Json(res)))
}
```

`HeaderMap` is already in scope in this file (`token_handler` uses it); if the compiler disagrees, add `use axum::http::HeaderMap;` rather than fully qualifying at each use site, matching the existing style.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry --test conformance_http -- the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint no_dpop_nonce_header_is_emitted_when_nonce_mode_is_disabled
```

Expected: all three PASS.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all green. `openapi_endpoints.rs` may now FAIL on committed-spec drift, because the `#[utoipa::path]` description changed — that is expected and is fixed in Task 3, which regenerates the spec. If it fails for that reason, note it and continue; if it fails for any other reason, stop and investigate.

`cargo fmt --check` failing means run `cargo fmt` and re-run.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/conformance_http.rs
git commit -m "feat(server): supply a DPoP nonce from the Nonce Endpoint

The Google Wallet profile expects the DPoP nonce to be retrieved from the
c_nonce endpoint. Gated on the existing issuer.dpop.nonce_mode, so an
unconfigured deployment's response is byte-identical to before.

Proven usable, not merely well-formed: the value taken from /nonce satisfies
nonce_mode: required at /token on the first attempt, with no use_dpop_nonce
round trip."
```

---

## Task 2: `/challenge` emits a `DPoP-Nonce` header

**Files:**
- Modify: `crates/foundry/src/server.rs` — `challenge_handler` and its `#[utoipa::path]` attribute
- Test: `crates/foundry/tests/conformance_http.rs`

**Interfaces:**
- Consumes: `dpop_nonce_header` (as Task 1); `setup_test_app()`; `Mode` and `DpopConfig` from `foundry_core::config`, both already imported in the test file.
- Produces: `setup_test_app_with_dpop_and_challenge_mode(dpop: DpopConfig, challenge_mode: Mode) -> (AppState, tempfile::TempDir)` — a new test helper. No later task consumes it.

**Why a new helper is needed:** the `/challenge` route is only registered when `issuer.wallet_attestation.challenge_mode != Disabled`, and the header is only emitted when `issuer.dpop.nonce_mode != Disabled`. `setup_test_app_with_dpop` sets only the former's counterpart and `setup_test_app_with_challenge_mode` only the latter's; neither sets both, so without a new helper the test would hit a 404 instead of asserting on a header.

- [ ] **Step 1: Write the failing test**

Add the helper next to the existing `setup_test_app_with_dpop` (around line 1718 in `crates/foundry/tests/conformance_http.rs`):

```rust
/// Both knobs at once. The `/challenge` route exists only when
/// `wallet_attestation.challenge_mode` is not `Disabled`, and the `DPoP-Nonce`
/// header is emitted only when `dpop.nonce_mode` is not `Disabled`. Neither
/// existing helper sets both, and setting only one yields a 404 rather than a
/// missing header.
async fn setup_test_app_with_dpop_and_challenge_mode(
    dpop: DpopConfig,
    challenge_mode: Mode,
) -> (AppState, tempfile::TempDir) {
    let (state, dir) = setup_test_app().await;
    let mut cfg = (*state.config).clone();
    cfg.issuer.dpop = dpop;
    cfg.issuer.wallet_attestation.challenge_mode = challenge_mode;
    let state = AppState::new(state.storage.clone(), Arc::new(cfg));
    (state, dir)
}
```

Then append the test to the block Task 1 created, after `a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint`:

```rust
/// Google Wallet vendor profile, "Token Endpoint": "DPoP Nonce is expected to be
/// returned from the Challenge endpoint header. Note: this is not standardized."
/// Standardised nowhere indeed -- ABCA draft -07 §8, which defines this
/// endpoint and which this repository pins, mentions no DPoP interaction at all.
#[tokio::test]
async fn the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled() {
    for nonce_mode in [Mode::Optional, Mode::Required] {
        let (state, _dir) = setup_test_app_with_dpop_and_challenge_mode(
            DpopConfig {
                mode: Mode::Required,
                nonce_mode: nonce_mode.clone(),
                ..DpopConfig::default()
            },
            Mode::Optional,
        )
        .await;
        let wallet_app = wallet_router(state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/challenge")
            .body(Body::empty())
            .unwrap();
        let res = wallet_app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK, "nonce_mode: {nonce_mode:?}");
        assert!(
            res.headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| !s.is_empty()),
            "nonce_mode {nonce_mode:?}: /challenge must supply a DPoP-Nonce"
        );
        // RFC 9449 §8: never more than one.
        assert_eq!(res.headers().get_all("DPoP-Nonce").iter().count(), 1);
        // ABCA §8 must survive the return-type change.
        assert_eq!(
            res.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        // The body is still the §8 document, unchanged.
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!body["attestation_challenge"]
            .as_str()
            .expect("attestation_challenge must be a string")
            .is_empty());
    }
}

/// The negative control for this endpoint: the challenge endpoint enabled but
/// server-provided nonces off must emit no nonce header.
#[tokio::test]
async fn the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled() {
    let (state, _dir) = setup_test_app_with_dpop_and_challenge_mode(
        DpopConfig {
            mode: Mode::Required,
            nonce_mode: Mode::Disabled,
            ..DpopConfig::default()
        },
        Mode::Optional,
    )
    .await;
    let wallet_app = wallet_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/challenge")
        .body(Body::empty())
        .unwrap();
    let res = wallet_app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get("DPoP-Nonce").is_none());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p foundry --test conformance_http -- the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled
```

Expected: `the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled` FAILS on `/challenge must supply a DPoP-Nonce`. `the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled` PASSES already — the negative control asserts a currently-true absence.

A 404 instead of the expected assertion failure means the helper did not set `challenge_mode`; fix the helper, not the test.

- [ ] **Step 3: Change `challenge_handler`**

In `crates/foundry/src/server.rs`, replace the `#[utoipa::path]` attribute and body of `challenge_handler`:

```rust
#[utoipa::path(
    post,
    path = "/challenge",
    responses(
        (status = 200, body = ChallengeResponse,
         description = "ABCA §8 challenge. Uncacheable per §8 (`Cache-Control: no-store`). \
                        Also carries a fresh `DPoP-Nonce` header when \
                        `issuer.dpop.nonce_mode` is `optional` or `required`."),
    )
)]
async fn challenge_handler(
    State(state): State<AppState>,
) -> Result<(HeaderMap, Json<ChallengeResponse>), (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::issue_attestation_challenge(
        state.nonce_secret.as_ref(),
        state.config.issuer.wallet_attestation.pop_max_age_secs,
        now,
    )
    .map_err(|e| wallet_error_response(&e))?;

    let mut out = HeaderMap::new();
    // §8: "The Authorization Server MUST make the response uncacheable by
    // adding a Cache-Control header field including the value no-store."
    out.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    // Vendor accommodation, not conformance: the Google Wallet profile
    // (docs/specs/google-wallet-openid4vci-profile.md, "Token Endpoint")
    // expects the DPoP nonce here and says so explicitly of itself -- "Note:
    // this is not standardized." ABCA draft -07 §8, which defines this
    // endpoint, mentions no DPoP interaction, and no other pinned
    // specification does either, so the profile is the only source. Gated on
    // `nonce_mode` for the same reason as at the Nonce Endpoint. `insert`, not
    // `append`: RFC 9449 §8 forbids a second DPoP-Nonce header.
    if let Some((name, value)) = dpop_nonce_header(&state, now) {
        out.insert(name, value);
    }
    Ok((out, Json(res)))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p foundry --test conformance_http -- the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled
```

Expected: both PASS.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: green apart from the same anticipated `openapi_endpoints.rs` drift failure noted in Task 1 Step 5, which Task 3 resolves.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/src/server.rs crates/foundry/tests/conformance_http.rs
git commit -m "feat(server): supply a DPoP nonce from the ABCA challenge endpoint

The Google Wallet profile expects the DPoP nonce on the challenge response and
states of itself that this is not standardized; ABCA draft -07 §8 mentions no
DPoP interaction. Marked as vendor accommodation in a code comment per
AGENTS.md §4.4's vendor-profile rule.

Gated on the existing issuer.dpop.nonce_mode. Needs a test harness that sets
both challenge_mode and nonce_mode, since setting only one yields a 404."
```

---

## Task 3: Redaction proof, documentation, conformance evidence, OpenAPI

**Files:**
- Test: `crates/foundry/tests/logging_redaction.rs`
- Modify: `docs/conformance/openid4vc-conformance.md` (row RFC-9449-0008)
- Modify: `README.md` ("Server-Provided DPoP Nonces (RFC 9449 §8/§9)" section)
- Modify: `openapi-wallet.json` (regenerated, not hand-edited)
- Check, modify only if stale: `crates/foundry/AGENTS.md`

**Interfaces:**
- Consumes: the two handlers from Tasks 1 and 2, and the test names created there — `the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled`, `a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint`, `the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled`, `the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled`. These exact strings go into the conformance row's test column, so copy them rather than retyping.
- Produces: nothing consumed by a later task. This is the final task.

- [ ] **Step 1: Extend the existing redaction coverage**

**Do not write a new test.** `crates/foundry/tests/logging_redaction.rs` already has `issuance_never_logs_challenges_or_dpop_nonces`, which drives a full attestation + challenge + DPoP-nonce issuance through the real routers via `drive_issuance_with_challenge_and_nonce` (whose `setup_with_challenge_and_dpop_nonce` already sets `challenge_mode`, `dpop.mode` and `dpop.nonce_mode` all to `Mode::Required`), asserts the capture is non-empty, and has a dedicated positive control (`the_capture_harness_would_catch_a_leaked_challenge`). It already asserts the `attestation_challenge` and the `/token`-supplied `dpop_nonce` never reach a log record. Extend it with the two newly-emitted values so they inherit that whole apparatus.

Three edits.

**(a)** Add two fields to `struct IssuanceSecrets`, after the existing `dpop_nonce` field:

```rust
    /// The `DPoP-Nonce` now riding the ABCA §8 challenge response -- empty
    /// unless produced by `drive_issuance_with_challenge_and_nonce`.
    challenge_endpoint_dpop_nonce: String,
    /// The `DPoP-Nonce` now riding the OpenID4VCI §7 Nonce Endpoint response --
    /// empty unless produced by `drive_issuance_with_challenge_and_nonce`.
    nonce_endpoint_dpop_nonce: String,
```

The plain `drive_issuance` also constructs an `IssuanceSecrets`; add `challenge_endpoint_dpop_nonce: String::new(), nonce_endpoint_dpop_nonce: String::new(),` to that literal, matching how it already handles `attestation_challenge` and `dpop_nonce`.

**(b)** In `drive_issuance_with_challenge_and_nonce`, capture both headers. **`body_json` consumes the response**, so the header must be read into a local *first* — this is the one easy way to get this wrong.

Replace the existing challenge block:

```rust
    assert_eq!(challenge_res.status(), StatusCode::OK);
    let attestation_challenge = body_json(challenge_res).await["attestation_challenge"]
        .as_str()
        .expect("attestation_challenge")
        .to_string();
```

with:

```rust
    assert_eq!(challenge_res.status(), StatusCode::OK);
    // Read the header before `body_json`, which consumes the response.
    let challenge_endpoint_dpop_nonce = challenge_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("nonce_mode: required must supply a DPoP-Nonce from /challenge")
        .to_string();
    let attestation_challenge = body_json(challenge_res).await["attestation_challenge"]
        .as_str()
        .expect("attestation_challenge")
        .to_string();
```

and the existing nonce block:

```rust
    assert_eq!(nonce_res.status(), StatusCode::OK);
    let c_nonce = body_json(nonce_res).await["c_nonce"]
        .as_str()
        .expect("c_nonce")
        .to_string();
```

with:

```rust
    assert_eq!(nonce_res.status(), StatusCode::OK);
    // Read the header before `body_json`, which consumes the response.
    let nonce_endpoint_dpop_nonce = nonce_res
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .expect("nonce_mode: required must supply a DPoP-Nonce from /nonce")
        .to_string();
    let c_nonce = body_json(nonce_res).await["c_nonce"]
        .as_str()
        .expect("c_nonce")
        .to_string();
```

Then add both to the `IssuanceSecrets { .. }` literal this function returns:

```rust
        challenge_endpoint_dpop_nonce,
        nonce_endpoint_dpop_nonce,
```

Note that these two `.expect(..)` calls make the driver itself a load-bearing assertion of Tasks 1 and 2: if either handler stops emitting the header, this driver panics and every test using it fails.

**(c)** Extend the loop in `issuance_never_logs_challenges_or_dpop_nonces` from two entries to four:

```rust
    for (label, secret) in [
        ("attestation_challenge", &secrets.attestation_challenge),
        ("dpop_nonce", &secrets.dpop_nonce),
        (
            "challenge_endpoint_dpop_nonce",
            &secrets.challenge_endpoint_dpop_nonce,
        ),
        (
            "nonce_endpoint_dpop_nonce",
            &secrets.nonce_endpoint_dpop_nonce,
        ),
    ] {
```

The loop body needs no change: it already asserts each value is non-empty (so an assertion can never be vacuous) and then that the log does not contain it. Update the test's doc comment to say that the two freshness endpoints now supply nonces too, and that those are secrets for the same reason.

The `sensitive_payloads`-enabled case is already covered by this file's existing pair of tests for the PoP JWT (`token_request_never_logs_the_raw_pop_jwt_or_jti_when_locked` and `..._even_with_sensitive_enabled`) plus `payload_logging_does_not_unlock_private_key_material`, which establish that the flag never unlocks key or freshness material. Do not add a fifth variant of that proof for these two values.

- [ ] **Step 2: Run the test**

```bash
cargo test -p foundry --test logging_redaction -- issuance_never_logs_challenges_or_dpop_nonces the_capture_harness_would_catch_a_leaked_challenge
```

Expected: both PASS. The redaction assertions guard an absence and Tasks 1 and 2 added no log statements, so this should be green on the first run — its value is as a regression guard against a future edit that logs a nonce "just for debugging".

A panic in the driver at either new `.expect(..)` means the corresponding handler is not emitting the header; that is a Task 1 or Task 2 regression, not a test bug. A failure of `the_capture_harness_would_catch_a_leaked_challenge` means the capture is dead and every negative assertion in the file is worthless — fix that before trusting anything else here.

- [ ] **Step 3: Update the conformance report**

In `docs/conformance/openid4vc-conformance.md`, row **RFC-9449-0008** (§8 / §9). The status stays `conforming` — this widens evidence for an already-implemented MAY; it closes no gap, adds no row, and removes no `#[ignore]`.

In the evidence column, after the existing clause `...and on a success response too (§8.2)`, insert:

```
, and, since 2026-08-04, on the two unauthenticated freshness endpoints as well -- `/nonce` and `/challenge` (`nonce_handler`, `challenge_handler`), which no pinned specification requires: the Google Wallet vendor profile (`docs/specs/google-wallet-openid4vci-profile.md`) expects the nonce to be retrieved from there, OpenID4VCI 1.1 WG draft §8.2-4 standardises the `/nonce` case (this repository pins 1.0) and the `/challenge` case is standardised nowhere. Both are gated on the same `issuer.dpop.nonce_mode`, so the `disabled` default emits nothing anywhere
```

Append these four test names to the row's test column, comma-separated, preserving the column's existing format:

```
the_nonce_endpoint_supplies_a_dpop_nonce_when_enabled, a_nonce_from_the_nonce_endpoint_is_accepted_at_the_token_endpoint, the_challenge_endpoint_supplies_a_dpop_nonce_when_enabled, the_challenge_endpoint_emits_no_dpop_nonce_when_nonce_mode_is_disabled
```

- [ ] **Step 4: Update the README**

In `README.md`, in the `### Server-Provided DPoP Nonces (RFC 9449 §8/§9)` section, find the sentence in the **`required`** bullet reading:

```
The same header
  rides a **successful** response too (§8.2), so a wallet always holds a
  usable nonce for its next request, and never more than one `DPoP-Nonce`
  header is ever emitted on a single response.
```

Replace with:

```
The same header
  rides a **successful** response too (§8.2), so a wallet always holds a
  usable nonce for its next request, and never more than one `DPoP-Nonce`
  header is ever emitted on a single response.

Under `optional` and `required` alike, a fresh `DPoP-Nonce` also rides the
responses of the two unauthenticated freshness endpoints — `POST /nonce` and
`POST /challenge` — so a wallet can obtain its first nonce before its first
authenticated request instead of learning it from a rejection. No pinned
specification requires this: it accommodates wallets that expect it, Google
Wallet among them (`docs/specs/google-wallet-openid4vci-profile.md`).
OpenID4VCI 1.1 WG draft §8.2-4 standardises the `/nonce` case; the
`/challenge` case is standardised nowhere.
```

Leave the **`disabled`** bullet's "no `DPoP-Nonce` header is ever emitted" alone — verify it is still literally true (it is: `dpop_nonce_header` returns `None`) rather than rewriting it.

- [ ] **Step 5: Regenerate the wallet OpenAPI spec**

```bash
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
git diff --stat openapi-wallet.json
```

Expected diff: **only** the `description` fields of the `/nonce` and `/challenge` 200 responses. Inspect it — anything else means an unintended annotation change slipped in.

Do not hand-edit this file. Note that `serve()` also rewrites both committed specs from its working directory on startup, so a stray local `serve` or E2E run can produce the same diff; if `openapi.json` (the admin spec) also shows changes, that is that effect and not this task's work — revert it with `git checkout -- openapi.json` unless you can explain the change.

- [ ] **Step 6: Check `crates/foundry/AGENTS.md`**

Read its Module Map and Gotchas sections and confirm nothing there is now false. Specifically: it documents that both committed specs are drift-tested and names the regeneration command, both still true. It does not enumerate handler return types, so the `HeaderMap` change should require no edit. Change it only if you find a stale statement; do not add a changelog entry.

- [ ] **Step 7: Run the scoped gate — now expected fully green**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

Expected: all green, including `openapi_endpoints.rs`, which Step 5 resolved. If the drift test still fails, Step 5 did not run or its output was not saved.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry/tests/logging_redaction.rs docs/conformance/openid4vc-conformance.md README.md openapi-wallet.json
git commit -m "docs: conformance, operator docs, and OpenAPI for nonce-endpoint DPoP nonces

Widens RFC-9449-0008's evidence to the two freshness endpoints (still
conforming -- an already-implemented MAY, no gap closed), documents the
behaviour and its non-standard status for operators, and regenerates the
wallet spec.

Adds a behavioural proof that neither endpoint logs the minted nonce, including
with sensitive_payloads enabled, since key and freshness material is never
unlocked by that flag (AGENTS.md §4.5)."
```

---

## Post-plan: the full gate, once

Only after all three tasks are complete and the branch is ready for review or merge, run the §5.3 full gate **once**:

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/test-output.log
grep -c "FAILED" /tmp/test-output.log
grep "^test result:" /tmp/test-output.log
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings
```

The `tee`-and-grep form is mandatory for the workspace run, per root `AGENTS.md` §5.6: a bare `tail` of that output silently drops earlier binaries' results, including failures. Do not run this between tasks. Do not re-run it after merging (§5.4).

One caveat for the E2E run: it boots the real binary from the repository root, which rewrites both committed OpenAPI specs. Check `git status` afterwards and revert any spurious spec diff.

## Follow-on work, explicitly out of scope

Recorded in full in the design doc §9. In blocking order: roadmap item **D** (`android_keystore_attestation` proof type — a new `proofs` key carrying arrays of X.509 chains, `KeyDescription` extension parsing, `attestationChallenge` ↔ `c_nonce` binding, security-level policy, revocation); roadmap item **E** (credential-type shape, `vct = com.emvco.dpc.card`); confirming with Google whether RFC 9421 message signatures and `credential_identifier` are genuinely required or artifacts of a copied example; deciding whether `wallet_name` should be verified; bumping the ABCA pin from -07 to -10; and the issuer-metadata onboarding hand-off Google requires before integration can begin.