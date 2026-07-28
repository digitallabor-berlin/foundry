# Authorization Code Flow — Implementation Plan

**Spec:** docs/superlight/specs/2026-07-28-authz-code-flow-spec.md
**Branch:** superlight/2026-07-28-authz-code-flow
**Executed with:** superlight Phase 4 (TDD, inline, no subagents by default)

**Goal:** Add a real, minimal OAuth 2.0 Authorization Code + PKCE grant to
`foundry-issuer`, bound to admin-precreated offers, mutually exclusive with
the existing pre-authorized_code grant.
**Architecture:** Mirror the existing pre-auth machinery's shape exactly —
same `Storage` KV secondary-index pattern, same `IssuanceTransaction` record,
same `TokenResponse` output — rather than a new subsystem.
**Global Constraints:** (copied from spec)
- No `.unwrap()`/`.expect()`/`panic!()` in `foundry-issuer` or `foundry::server`
  request-handling code.
- `AUTH_CODE_TTL_SECS = 300` (5 minutes), single-use.
- PKCE method: `S256` only; `plain` rejected.
- `openapi.json` / `openapi-wallet.json` regenerated to reflect all schema/route
  changes.
- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check` all pass clean before done.

## File Structure

- `crates/foundry-issuer/src/transaction.rs` — modify: `Option` fields, new
  namespaces/lookup/save functions
- `crates/foundry-issuer/src/offer.rs` — modify: `CredentialOfferGrants`
  members become `Option`, new `AuthorizationCodeGrant`
- `crates/foundry-issuer/src/create_offer.rs` — modify: `redirect_uri` field,
  mutual-exclusivity validation, grant construction
- `crates/foundry-issuer/src/authorize.rs` — new: `/authorize` request
  handling logic
- `crates/foundry-issuer/src/token.rs` — modify: `authorization_code` grant
  branch, shared token-minting helper
- `crates/foundry-issuer/src/metadata.rs` — modify: new AS metadata fields
- `crates/foundry-issuer/src/lib.rs` — modify: export `authorize` module
- `crates/foundry/src/server.rs` — modify: `/authorize` route + handler
- `crates/foundry/src/openapi.rs` — modify: register new path/schemas
- `openapi.json`, `openapi-wallet.json` — regenerated artifacts
- `crates/foundry/tests/authorization_code_flow.rs` — new: end-to-end HTTP test

---

### Task 1: Data model — transaction storage + offer wire format

**Files:**
- Modify: `crates/foundry-issuer/src/transaction.rs`
- Modify: `crates/foundry-issuer/src/offer.rs`
- Test: their existing `#[cfg(test)]` modules

**Interfaces:**
- Produces (consumed by Tasks 2–4):
  - `IssuanceTransaction.pre_authorized_code: Option<String>` (was `String`)
  - `IssuanceTransaction` new fields: `redirect_uri: Option<String>`,
    `issuer_state: Option<String>`, `authorization_code: Option<String>`,
    `code_challenge: Option<String>`, `code_challenge_method: Option<String>`
  - `pub async fn load_transaction_by_issuer_state(storage: &dyn Storage, issuer_state: &str) -> Result<Option<IssuanceTransaction>, IssuanceError>`
  - `pub async fn load_transaction_by_authorization_code(storage: &dyn Storage, code: &str) -> Result<Option<IssuanceTransaction>, IssuanceError>`
  - `pub async fn save_transaction_with_auth_code(storage: &dyn Storage, tx: &IssuanceTransaction, tx_ttl_secs: u64, auth_code_ttl_secs: u64, now_unix: i64) -> Result<(), IssuanceError>`
  - `save_transaction_with_indices` (signature unchanged) now writes
    `PRE_AUTH_NS` only if `tx.pre_authorized_code.is_some()`, and a new
    `ISSUER_STATE_NS` entry if `tx.issuer_state.is_some()`
  - `offer.rs`: `CredentialOfferGrants { pre_authorized_code: Option<PreAuthorizedCodeGrant>, authorization_code: Option<AuthorizationCodeGrant> }`
    (both `#[serde(skip_serializing_if = "Option::is_none")]`), new
    `pub struct AuthorizationCodeGrant { #[serde(skip_serializing_if = "Option::is_none")] pub issuer_state: Option<String> }`

**Behaviors to test:**
- Save/load round trip with `pre_authorized_code: None`, `issuer_state: Some(_)` set — new shape persists correctly.
- Save/load round trip with `pre_authorized_code: Some(_)` — existing shape still round-trips under the `Option` type.
- `load_transaction_by_issuer_state` finds the transaction by `issuer_state`.
- `load_transaction_by_issuer_state` returns `None` for an unknown value.
- `load_transaction_by_authorization_code` finds the transaction after `save_transaction_with_auth_code`.
- `save_transaction_with_auth_code` with a short `auth_code_ttl_secs` and a
  longer `tx_ttl_secs`: after `purge_expired` at a time past the auth-code TTL
  but before the transaction TTL, the transaction is still loadable by
  `transaction_id` but no longer by `authorization_code` — proves minting a
  code never shortens the parent transaction's lifetime.
- `CredentialOffer` with `authorization_code: Some(_)`, `pre_authorized_code: None`
  serializes with only the `authorization_code` key present (no
  `pre-authorized_code` key at all) — exact JSON key-set assertion.
- `CredentialOffer` with `pre_authorized_code: Some(_)`, `authorization_code: None`
  serializes with only the `pre-authorized_code` key present — regression
  test for existing behavior under the new `Option` type.
- `AuthorizationCodeGrant { issuer_state: Some("abc") }` round-trips through
  serde with the exact `issuer_state` JSON key.

**Verify:** `cargo test -p foundry-issuer transaction:: offer::`

- [ ] Red
- [ ] Green
- [ ] Refactor
- [ ] Verify
- [ ] Commit

---

### Task 2: `create_offer` — request field, validation, grant construction

**Files:**
- Modify: `crates/foundry-issuer/src/create_offer.rs`

**Interfaces:**
- Consumes: Task 1's `IssuanceTransaction` fields, `CredentialOfferGrants`/`AuthorizationCodeGrant`, `save_transaction_with_indices`.
- Produces: `CreateOfferRequest.redirect_uri: Option<String>` (new,
  `#[serde(default)]`) — consumed by Task 6's integration test and by any
  future admin-API caller.

**Behaviors to test:**
- `redirect_uri: None` → offer has `pre-authorized_code` grant, unchanged
  from today (regression — adapt existing tests to the new `Option` field
  types where needed).
- `redirect_uri: Some(uri)` → offer has `authorization_code` grant with a
  generated `issuer_state`, no `pre-authorized_code` member; persisted
  transaction has `issuer_state`/`redirect_uri` set, `pre_authorized_code`/`tx_code` = `None`.
- `redirect_uri: Some(_)` combined with `tx_code_required: true` →
  `IssuanceError::InvalidRequest("tx_code_required is only valid for the pre-authorized_code grant")`.
- `credential_offer_uri` still starts with `openid-credential-offer://` for
  the new grant type (percent-encoding path is grant-agnostic, but assert it
  explicitly since the grants object shape changed).

**Verify:** `cargo test -p foundry-issuer create_offer::`

- [ ] Red
- [ ] Green
- [ ] Refactor
- [ ] Verify
- [ ] Commit

---

### Task 3: `GET /authorize` handler

**Files:**
- Create: `crates/foundry-issuer/src/authorize.rs`
- Modify: `crates/foundry-issuer/src/lib.rs` (export the new module/types)
- Modify: `crates/foundry/src/server.rs` (route + HTTP-layer handler)

**Interfaces:**
- Consumes: Task 1's `load_transaction_by_issuer_state`,
  `save_transaction_with_auth_code`, `IssuanceTransaction` fields.
- Produces (consumed by Task 6's integration test and by `server.rs`):
  ```rust
  pub struct AuthorizeParams {
      pub response_type: String,
      pub client_id: String,
      pub redirect_uri: String,
      pub state: Option<String>,
      pub code_challenge: String,
      pub code_challenge_method: String,
      pub issuer_state: String,
  }

  pub enum AuthorizeOutcome {
      Success { redirect_uri: String, code: String, state: Option<String> },
      ErrorRedirect { redirect_uri: String, error: String, state: Option<String> },
      DirectError(IssuanceError),
  }

  pub async fn handle_authorize_request(
      storage: &dyn Storage,
      params: &AuthorizeParams,
      now_unix: i64,
  ) -> AuthorizeOutcome
  ```
  `server.rs`'s new `authorize_handler` matches on the three variants:
  `Success`/`ErrorRedirect` → axum `Redirect` to `{redirect_uri}?{code|error}=...&state=...`
  (state query param omitted when `None`); `DirectError` → existing
  `wallet_error_response(&e)` (JSON body, no redirect).

**Behaviors to test** (directly against `handle_authorize_request`, same
style as `create_offer.rs`'s test module):
- Valid request (resolvable `issuer_state`, matching `redirect_uri`,
  `code_challenge_method: "S256"`, well-formed `code_challenge`,
  `response_type: "code"`, non-empty `client_id`) → `Success` with a code;
  the transaction is now findable via `load_transaction_by_authorization_code`
  with matching `code_challenge`/`code_challenge_method` persisted.
- Unresolvable `issuer_state` → `DirectError`.
- `redirect_uri` param ≠ stored `tx.redirect_uri` → `DirectError`.
- `code_challenge_method != "S256"` → `ErrorRedirect { error: "invalid_request", .. }`.
- Empty/malformed `code_challenge` (RFC 7636: 43–128 chars, base64url charset) → `ErrorRedirect { error: "invalid_request", .. }`.
- `response_type != "code"` → `ErrorRedirect { error: "invalid_request", .. }`.
- Empty/missing `client_id` → `ErrorRedirect { error: "invalid_request", .. }`.
- `tx.state == IssuanceState::Issued` → `ErrorRedirect { error: "access_denied", .. }`.
- `state` param, when present, is echoed in both `Success` and `ErrorRedirect`;
  when absent, both omit it.

**Verify:** `cargo test -p foundry-issuer authorize::`

- [ ] Red
- [ ] Green
- [ ] Refactor
- [ ] Verify
- [ ] Commit

---

### Task 4: `/token` — `authorization_code` grant

**Files:**
- Modify: `crates/foundry-issuer/src/token.rs`

**Interfaces:**
- Consumes: Task 1's `load_transaction_by_authorization_code`,
  `IssuanceTransaction` fields.
- Produces: `TokenRequest` gains `code: Option<String>`,
  `redirect_uri: Option<String>`, `client_id: Option<String>`,
  `code_verifier: Option<String>`. `handle_token_request` gains an
  `"authorization_code"` branch. Token-minting logic (access_token/c_nonce
  generation + persistence) factored into a private helper shared by both
  grant branches, so `TokenResponse` shape is identical either way.

**Behaviors to test:**
- Happy path: transaction with `authorization_code`/`code_challenge` (S256 of
  a known verifier)/`redirect_uri` set; request with the matching
  `code_verifier` and `redirect_uri` → `TokenResponse` with `access_token`/`c_nonce`;
  the `AUTH_CODE_NS` entry is gone afterward (assert via a second exchange
  attempt failing, see replay test below).
- Wrong `code_verifier` → `InvalidGrant`.
- Mismatched `redirect_uri` → `InvalidGrant`.
- Unknown/expired `code` → `InvalidGrant`.
- Replaying an already-exchanged `code` → `InvalidGrant` (now "missing").
- Transaction already `IssuanceState::Issued` → `InvalidGrant("credential offer has already been claimed")`.
- Existing pre-authorized_code tests in this file still pass unchanged
  (regression — confirms the shared helper didn't change pre-auth behavior).

**Verify:** `cargo test -p foundry-issuer token::`

- [ ] Red
- [ ] Green
- [ ] Refactor
- [ ] Verify
- [ ] Commit

---

### Task 5: Authorization Server Metadata fields

**Files:**
- Modify: `crates/foundry-issuer/src/metadata.rs`

**Interfaces:**
- Produces: `AuthorizationServerMetadata` gains `authorization_endpoint: String`,
  `response_types_supported: Vec<String>`, `code_challenge_methods_supported: Vec<String>`;
  `build_authorization_server_metadata`'s `grant_types_supported` gains
  `"authorization_code"` alongside the existing pre-auth entry.

**Behaviors to test:**
- `build_authorization_server_metadata` for a given `credential_issuer` base
  URL emits `authorization_endpoint == "{base}/authorize"` exactly.
- `response_types_supported == ["code"]`, `code_challenge_methods_supported == ["S256"]`.
- `grant_types_supported` contains both
  `"urn:ietf:params:oauth:grant-type:pre-authorized_code"` and
  `"authorization_code"`.
- Existing `builds_issuer_metadata_from_credential_types`-style test still
  passes (regression — issuer metadata itself is untouched by this task).

**Verify:** `cargo test -p foundry-issuer metadata::`

- [ ] Red
- [ ] Green
- [ ] Refactor
- [ ] Verify
- [ ] Commit

---

### Task 6: End-to-end wiring, OpenAPI regeneration, integration test

**Files:**
- Modify: `crates/foundry/src/openapi.rs` — add `crate::server::authorize_handler`
  to `WalletApiDoc`'s `paths(...)`; add `foundry_issuer::AuthorizationCodeGrant`
  to `AdminApiDoc`'s `components(schemas(...))`.
- Regenerate: `openapi.json`, `openapi-wallet.json` (both files, committed).
- Create: `crates/foundry/tests/authorization_code_flow.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–5, plus `wallet_router`/`AppState` (same
  test-harness pattern as `crates/foundry/tests/wallet_metadata.rs`) and the
  admin router for `create_offer_handler`.
- Produces: nothing further downstream — this is the last task.

**Behaviors to test:**
- `openapi.rs`'s existing `wallet_openapi_spec_generates_valid_json`/
  `admin_openapi_spec_generates_valid_json` tests still pass; add an
  assertion that the generated wallet spec JSON contains `"/authorize"` and
  the admin spec contains `"AuthorizationCodeGrant"`.
- Full HTTP round trip in `authorization_code_flow.rs`: `POST /admin/issuance/offers`
  with `redirect_uri` set → `200` with `credential_offer.grants.authorization_code.issuer_state`
  present; `GET /authorize` with real PKCE `code_verifier`/`code_challenge`
  pair and that `issuer_state` → `302` with a `Location` header containing
  `code=`; `POST /token` (`grant_type=authorization_code`) with that code +
  verifier + matching `redirect_uri`/`client_id` → `200` `TokenResponse`.
- `GET /authorize` with a wrong `redirect_uri` in the same test file → `400`,
  not a redirect (confirms the untrusted-redirect branch reaches the HTTP
  layer correctly, not just the unit-level `handle_authorize_request`).

**Verify:** `cargo test -p foundry && cargo test -p foundry-issuer`, then the
full workspace gate: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`.

- [ ] Red
- [ ] Green
- [ ] Refactor
- [ ] Verify
- [ ] Commit

---

## Progress Log

(Append one line per completed task: date, task, commit SHA.)