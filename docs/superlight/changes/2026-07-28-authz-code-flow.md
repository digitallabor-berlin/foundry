# Authorization Code + PKCE Flow Bound to Pre-Created Offers

**Date:** 2026-07-28
**Type:** feature (implements the fix for a confirmed interop bug)
**Track:** B (investigation → design → spec → plan → TDD → review)
**Branch:** `superlight/2026-07-28-authz-code-flow`
**Spec:** `docs/superlight/specs/2026-07-28-authz-code-flow-spec.md`
**Plan:** `docs/superlight/plans/2026-07-28-authz-code-flow-plan.md`

## Problem

Issuing a credential from `foundry` into the `eudi-pal` iOS wallet
("BankingPal-Pocket") failed with `"Invalid authorization endpoint"` thrown
from inside `eudi-lib-ios-openid4vci-swift`, before any network request to
the issuer's `/token` endpoint completed.

## Root Cause

`eudi-lib-ios-openid4vci-swift` (pinned at v0.35.1 in `eudi-pal`'s
`Package.resolved`, and unchanged through v0.51.0) unconditionally requires
`authorization_endpoint` to be present in the OAuth Authorization Server
Metadata document — see
`Sources/Main/Authorisers/AuthorizationServerClient.swift:230-231`, which
throws before any grant-specific logic runs, even for wallets that only ever
intend to use the `pre-authorized_code` grant.

`foundry`'s `build_authorization_server_metadata` never emitted
`authorization_endpoint` at all: the issuer only supported the
`pre-authorized_code` grant, so no `/authorize` endpoint existed and the
field was correctly omitted per the OpenID4VCI pre-auth-only profile — but
this particular wallet library's client-side validation does not tolerate
that omission.

**Rejected hypothesis:** a placeholder/dummy `authorization_endpoint` value
with no backing endpoint would satisfy the Swift library's null-check. This
was rejected in favor of building a real, working `/authorize` endpoint —
the user chose to implement genuine OAuth 2.0 Authorization Code + PKCE
support rather than a value that would 404 if a wallet ever attempted to use
it.

## Approach

Added a full OAuth 2.0 Authorization Code + PKCE (S256) grant, mutually
exclusive with the existing `pre-authorized_code` grant on any given offer,
bound to admin-precreated offers (no dynamic client registration, no PAR,
no real user login/consent screen — claims are fixed by the admin at offer
creation, and `/authorize` redirects back with `code` immediately, mirroring
`eudi-pal`'s confirmed non-PAR offer-based issuance path).

Rejected alternative: emit a placeholder `authorization_endpoint` field
without real backing logic (an "interop shim"). Rejected because it would
silently break for any wallet that actually attempted the redirect, and
because building the real flow was estimated as comparable effort to a
correctly-tested shim once the shim's edge cases were accounted for.

## Changes

### Data model (Task 1, `890d0e9`)
- `crates/foundry-issuer/src/transaction.rs` — `IssuanceTransaction.pre_authorized_code`
  became `Option<String>`; added `redirect_uri`, `issuer_state`,
  `authorization_code`, `code_challenge`, `code_challenge_method`. New
  storage namespaces/lookups: `ISSUER_STATE_NS`, `AUTH_CODE_NS`,
  `load_transaction_by_issuer_state`, `load_transaction_by_authorization_code`,
  `save_transaction_with_auth_code` (auth-code TTL independent of the parent
  transaction's TTL), `invalidate_authorization_code`.
- `crates/foundry-issuer/src/offer.rs` — `CredentialOfferGrants`'s two grant
  members both became `Option` with `skip_serializing_if`, giving wire-level
  mutual exclusivity (an offer's JSON has exactly one grant member). New
  `AuthorizationCodeGrant { issuer_state: Option<String> }`.
- Mechanical fixes to compile against the new `Option` types:
  `credential.rs`, `create_offer.rs` (stopgap), `token.rs`,
  `foundry-wallet/actions/issuance.rs` (added `WalletError::MalformedOffer`
  handling for the debug wallet's pre-auth-only assumption),
  `foundry-wallet/actions/offer_source.rs`.
- Registered `AuthorizationCodeGrant` in `AdminApiDoc`'s OpenAPI schema list;
  exported from `foundry-issuer/src/lib.rs`.

### `create_offer` (Task 2, `bf43f5f`)
- `crates/foundry-issuer/src/create_offer.rs` — `CreateOfferRequest` gains
  `redirect_uri: Option<String>`. `None` → today's `pre-authorized_code`
  grant, unchanged. `Some(uri)` → `authorization_code` grant: generates
  `issuer_state`, persists `redirect_uri`/`issuer_state`, leaves
  `pre_authorized_code`/`tx_code` unset. Rejects `redirect_uri` combined with
  `tx_code_required` as `IssuanceError::InvalidRequest`.

### `GET /authorize` (Task 3, `4f3a90e`)
- New `crates/foundry-issuer/src/authorize.rs` — `AuthorizeParams`,
  `AuthorizeOutcome` (`Success`/`ErrorRedirect`/`DirectError`),
  `handle_authorize_request`. Resolves `issuer_state` to the transaction;
  unresolvable `issuer_state` or a `redirect_uri` mismatch → `DirectError`
  (400 JSON, no redirect — the redirect target isn't trusted yet). Once the
  `redirect_uri` is validated, all other failures (bad `response_type`,
  non-`S256` `code_challenge_method`, malformed `code_challenge`,
  already-`Issued` transaction) → `ErrorRedirect` back to the wallet.
  Success mints a single-use `authorization_code`
  (`AUTH_CODE_TTL_SECS = 300`).
- `crates/foundry/src/server.rs` — `GET /authorize` route, `AuthorizeQuery`,
  `append_query` helper (percent-encodes `code`/`error`/`state` onto the
  redirect target).

### `/token` (Task 4, `4ef0cd1`)
- `crates/foundry-issuer/src/token.rs` — `TokenRequest` gains `code`,
  `redirect_uri`, `client_id`, `code_verifier` (all `Option`, additive).
  `handle_token_request` dispatches on `grant_type`; both branches share a
  `mint_and_save_tokens` helper so `TokenResponse` shape is identical either
  way. The `authorization_code` branch checks `redirect_uri` equality, then
  RFC 7636 S256 `code_verifier`/`code_challenge` match, and only invalidates
  the code after that full pass — a wrong-`code_verifier` probe does not
  burn a legitimate holder's code.

### Metadata (Task 5, `f79ef86`)
- `crates/foundry-issuer/src/metadata.rs` — `AuthorizationServerMetadata`
  gains `authorization_endpoint` (`"{base}/authorize"`),
  `response_types_supported` (`["code"]`), `code_challenge_methods_supported`
  (`["S256"]`); `grant_types_supported` now lists both grant types,
  unconditionally. **This is the change that actually resolves the original
  interop bug.**

### Wiring, OpenAPI, integration test (Task 6, `ec93876`, `bc43179`)
- Registered `authorize_handler` in `WalletApiDoc`; regenerated
  `openapi.json` and `openapi-wallet.json` throughout Tasks 2, 4, 5, 6.
- New `crates/foundry/tests/authorization_code_flow.rs` — full HTTP round
  trip through the real axum routers.
- Review fix: the `#[utoipa::path]` doc for `/authorize` said `302`; the
  actual `axum::response::Redirect::to` sends `303 See Other`. Fixed the
  doc and regenerated `openapi-wallet.json`.

## Tests

- `crates/foundry-issuer/src/transaction.rs` — round-trip, secondary-index
  lookup, and TTL-independence tests for the new fields/namespaces.
- `crates/foundry-issuer/src/offer.rs` — wire-shape assertions proving
  mutual exclusivity of the two grant members.
- `crates/foundry-issuer/src/create_offer.rs` — `redirect_uri` branch
  behavior and the `tx_code_required` rejection.
- `crates/foundry-issuer/src/authorize.rs` — 9 unit tests covering the happy
  path, unresolvable `issuer_state`, `redirect_uri` mismatch, wrong
  `code_challenge_method`, malformed `code_challenge`, wrong
  `response_type`, empty `client_id`, already-`Issued` transaction, and
  `state` echo/omission.
- `crates/foundry-issuer/src/token.rs` — happy path + replay rejection,
  wrong `code_verifier` (with proof the code survives a failed probe),
  mismatched `redirect_uri`, unknown `code`, already-`Issued` transaction,
  plus a regression test confirming the pre-auth path is unaffected by the
  shared `mint_and_save_tokens` refactor.
- `crates/foundry-issuer/src/metadata.rs` — exact JSON-shape assertions for
  the new AS metadata fields.
- `crates/foundry/tests/authorization_code_flow.rs` — end-to-end HTTP round
  trip (offer creation with real PKCE → `/authorize` → `/token`) through the
  real axum routers, plus a dedicated test proving the untrusted-redirect
  400 path is reached at the HTTP layer, not just unit-tested.
- `crates/foundry/src/openapi.rs` — regression assertions that the admin
  spec contains `AuthorizationCodeGrant` and the wallet spec contains
  `/authorize`.

All verified via `cargo test --workspace`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo fmt --check` — clean at every task
boundary and at final review.

## Review

Phase 5 fresh-eyes diff review (`git diff e6010bd..HEAD`) found one
Important issue: the `/authorize` OpenAPI doc claimed a `302` response
status, but the implementation (`axum::response::Redirect::to`) actually
sends `303 See Other`. Fixed in commit `bc43179` and confirmed against the
regenerated `openapi-wallet.json`.

No other Critical or Important findings. Confirmed: no leftover
placeholders/TODOs/dead code; no `.unwrap()`/`.expect()`/`panic!()` in
`foundry-issuer` or `foundry::server` request-handling paths (AGENTS.md
§4.1); all 12 spec Testing Strategy behaviors covered by tests; no scope
creep; naming/types consistent across all six tasks' interfaces (one
documented signature deviation: `handle_authorize_request` takes an extra
`tx_ttl_secs: u64` parameter not in the plan's original wording, because
`Storage` doesn't expose a stored row's original `expires_at`).