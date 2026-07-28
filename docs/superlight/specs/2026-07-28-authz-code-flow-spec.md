# Authorization Code Flow (bound to pre-created offers)

**Date:** 2026-07-28
**Status:** approved

## Problem

`foundry-issuer` implements only the `urn:ietf:params:oauth:grant-type:pre-authorized_code`
grant. Its `AuthorizationServerMetadata` therefore never emits `authorization_endpoint`
(correctly optional per RFC 8414 when no grant type uses it). The wallet under
test (`eudi-pal`, via `eudi-lib-ios-openid4vci-swift` v0.35.1, confirmed
unchanged through v0.51.0) constructs `AuthorizationServerClient` unconditionally
inside `Issuer.init` regardless of grant type, and that constructor hard-requires
`authorization_endpoint` to be present and parseable — throwing
`ValidationError.error(reason: "Invalid authorization endpoint")` before any
issuance flow can proceed, including pre-auth.

Rather than patch around this with a placeholder endpoint, the issuer will
implement a real, minimal Authorization Code flow (RFC 6749 + PKCE, RFC 7636)
so the capability actually exists — bound to admin-precreated offers, matching
the issuer's existing "admin decides the claims up front" trust model. This
both fixes the interop failure and adds a second real grant type.

## Goal / Non-Goals

**Goal:** A wallet can resolve a credential offer whose `grants` member is
`authorization_code`, complete a standard OAuth 2.0 Authorization
Code + PKCE round trip against `foundry`'s wallet-facing endpoints, and obtain
an `access_token` usable against the existing `/credential` endpoint — with the
credential claims fixed at `create_offer` time exactly as the pre-auth flow
does today.

**Non-Goals (out of scope for this spec):**
- Real user authentication/consent at `/authorize` (claims are already fixed
  by the admin; the endpoint auto-redirects with a code, no login UI).
- Pushed Authorization Requests (RFC 9126) — confirmed unnecessary: the wallet
  path relevant here (`eudi-pal`'s `ensureRegisteredForOffer`, used for all
  `openid-credential-offer://` URIs) sets `requirePAR: false`.
- Wallet-initiated issuance (no pre-created offer) — `/authorize` requires a
  resolvable `issuer_state`; there is no bare/cold-start authorization path.
- Dynamic client registration or `client_id` as a security boundary — public
  native client, no secret; PKCE + exact `redirect_uri` match are the actual
  anchors, per RFC 8252 guidance.
- Both grants simultaneously on one offer — mutually exclusive by design
  (confirmed with user).

## Approach

Chosen: mirror the existing pre-authorized_code machinery (`transaction.rs`,
`token.rs`, `offer.rs`, `metadata.rs`) exactly in shape — same
`Storage`-backed KV secondary-index pattern (`put_kv`/`get_kv`/`delete_kv`
with per-key TTL), same `IssuanceTransaction` record, same `TokenResponse`
shape — rather than introducing a new subsystem.

Rejected alternatives:
- **Placeholder `authorization_endpoint` shim, no real flow** — cheaper, but
  ships a field that lies about capability and doesn't satisfy the user's
  actual need (a working Authorization Code flow was explicitly requested
  after an effort/scope discussion).
- **`CredentialOfferGrants` as a request-level enum with a shared `grant_type`
  tag** — more idiomatic Rust modeling, but changes the wire shape of the
  already-shipped `tx_code_required` field for existing pre-auth callers.
  Rejected in favor of an additive `Option<String>` field on
  `CreateOfferRequest` with runtime mutual-exclusivity validation, to minimize
  blast radius on existing behavior and tests.
- **Full-fidelity flow with real user auth/PAR/dynamic claims** — explicitly
  scoped out; doesn't fit the current admin-precreates-claims trust model and
  would require a new identity subsystem foundry does not have.

## Design

### Data model

**`CreateOfferRequest`** (`crates/foundry-issuer/src/create_offer.rs`) gains:
```rust
#[serde(default)]
pub redirect_uri: Option<String>,
```
- `None` → today's pre-authorized_code grant, unchanged behavior.
- `Some(uri)` → authorization_code grant. If `tx_code_required: true` is also
  set, `create_offer` returns
  `IssuanceError::InvalidRequest("tx_code_required is only valid for the pre-authorized_code grant")`.

**`IssuanceTransaction`** (`crates/foundry-issuer/src/transaction.rs`):
- `pre_authorized_code: String` → `pre_authorized_code: Option<String>`.
- New: `redirect_uri: Option<String>`, `issuer_state: Option<String>`,
  `authorization_code: Option<String>`, `code_challenge: Option<String>`,
  `code_challenge_method: Option<String>`.

**New storage namespaces** (same file), following the existing `PRE_AUTH_NS`
pattern:
- `ISSUER_STATE_NS` — set once at `create_offer`, same TTL as the parent
  transaction (`cfg.storage.transaction_ttl_secs`).
- `AUTH_CODE_NS` — set at `/authorize`, its own short TTL (300s, hardcoded
  constant `AUTH_CODE_TTL_SECS`), deleted via `storage.delete_kv` on
  successful `/token` exchange (single-use enforcement, RFC 6749).

**New functions** in `transaction.rs`:
- `load_transaction_by_issuer_state(storage, issuer_state)`
- `load_transaction_by_authorization_code(storage, code)`
- `save_transaction_with_auth_code(storage, tx, tx_ttl_secs, auth_code_ttl_secs, now_unix)`
  — re-saves the main record at `tx_ttl_secs` (unchanged from its original
  TTL) while writing the `AUTH_CODE_NS` index at its own `auth_code_ttl_secs`,
  so minting a code never shortens the parent transaction's lifetime.
- `save_transaction_with_indices` (existing) extended: only writes the
  `PRE_AUTH_NS` index when `tx.pre_authorized_code.is_some()`; writes
  `ISSUER_STATE_NS` when `tx.issuer_state.is_some()`.

**`CredentialOfferGrants`** (`crates/foundry-issuer/src/offer.rs`): both
members become `Option` with `skip_serializing_if = "Option::is_none"`:
```rust
pub struct CredentialOfferGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code", skip_serializing_if = "Option::is_none")]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    #[serde(rename = "authorization_code", skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,
}

pub struct AuthorizationCodeGrant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}
```
Exactly one member is populated per offer, matching OpenID4VCI's `grants`
object (any subset of members may be present).

### `create_offer` changes

When `req.redirect_uri` is `Some`:
- Generate `issuer_state` via the same CSPRNG helper as
  `generate_pre_authorized_code` (32 bytes, URL-safe base64, unpadded).
- Store `tx.issuer_state`, `tx.redirect_uri`; leave `tx.pre_authorized_code`,
  `tx.tx_code` as `None`.
- Build `CredentialOffer.grants` with `authorization_code: Some(AuthorizationCodeGrant { issuer_state: Some(...) })`,
  `pre_authorized_code: None`.

Existing path (redirect_uri `None`) unchanged except for the now-`Option`
field types.

### `GET /authorize` (new `crates/foundry-issuer/src/authorize.rs` + route in
`crates/foundry/src/server.rs`)

Query params: `response_type`, `client_id`, `redirect_uri`, `state` (optional
but echoed if present), `code_challenge`, `code_challenge_method`,
`issuer_state`, `scope` (ignored — claims are fixed by the offer, not
negotiated here).

1. `issuer_state` missing or unresolvable (via `load_transaction_by_issuer_state`),
   or `redirect_uri` param ≠ `tx.redirect_uri` → **HTTP 400 JSON**
   (`{"error": "invalid_request", "error_description": ...}`), never a
   redirect — the redirect target isn't trusted yet.
2. Past that point, errors redirect to the now-trusted `redirect_uri`:
   - `response_type != "code"`, `client_id` empty/missing, or
     `code_challenge_method != "S256"`, or `code_challenge` empty/malformed
     (RFC 7636: 43–128 chars, unreserved base64url charset) →
     `302 {redirect_uri}?error=invalid_request&state={state}`.
   - `tx.state == IssuanceState::Issued` (offer already claimed) →
     `302 {redirect_uri}?error=access_denied&state={state}`.
3. Success: mint `authorization_code` (same CSPRNG helper), set
   `tx.authorization_code`, `tx.code_challenge`, `tx.code_challenge_method`,
   call `save_transaction_with_auth_code(..., AUTH_CODE_TTL_SECS, now)`,
   `302 {redirect_uri}?code={code}&state={state}`.

`client_id` is validated for presence only, never matched against a stored
value (per the approved design — not a security boundary for this public
client).

### `/token` changes (`crates/foundry-issuer/src/token.rs`)

`TokenRequest` gains (all `Option<String>`): `code`, `redirect_uri`,
`client_id`, `code_verifier`.

`handle_token_request` gains a branch for
`grant_type == "authorization_code"`:
1. `code` required → `load_transaction_by_authorization_code`; missing/expired
   → `InvalidGrant("invalid or expired code")`.
2. `redirect_uri` param must equal `tx.redirect_uri` → else
   `InvalidGrant("redirect_uri mismatch")`.
3. `code_verifier` required; `base64url_no_pad(SHA256(code_verifier))` must
   equal `tx.code_challenge` (only `S256` was ever accepted at `/authorize`,
   so no method branch needed here) → else `InvalidGrant("invalid code_verifier")`.
4. `tx.state == IssuanceState::Issued` → `InvalidGrant("credential offer has already been claimed")`
   (same message as the existing pre-auth check).
5. Mint `access_token`/`c_nonce` via a shared helper factored out of the
   existing pre-auth branch (identical `TokenResponse` shape for both grants).
6. `storage.delete_kv(AUTH_CODE_NS, code)` — single-use; a replayed `code`
   after this point hits step 1's "missing" branch.

The existing pre-authorized_code branch is otherwise unchanged.

### Metadata (`crates/foundry-issuer/src/metadata.rs`)

Unconditional (no new config flag — matches pre-auth's always-on posture).
`AuthorizationServerMetadata` (and its builder `build_authorization_server_metadata`)
gains:
```rust
pub authorization_endpoint: String,           // "{base}/authorize"
pub response_types_supported: Vec<String>,    // ["code"]
pub code_challenge_methods_supported: Vec<String>, // ["S256"]
```
`grant_types_supported` gains `"authorization_code"` alongside the existing
pre-auth entry.

### Error handling

New error paths reuse `IssuanceError::InvalidRequest` / `InvalidGrant`
(no new variants needed). `wallet_error_response` in `server.rs` already maps
both to `(BAD_REQUEST, "invalid_request"/"invalid_grant")` — no change needed
there. `/authorize`'s redirect-based errors are constructed directly in the
new handler (axum `Redirect`), not through `wallet_error_response` (which only
produces JSON bodies, not redirects).

## Global Constraints

- No `.unwrap()`/`.expect()`/`panic!()` in `foundry-issuer` or
  `foundry::server` request-handling code (existing repo-wide invariant,
  AGENTS.md §4.1).
- `AUTH_CODE_TTL_SECS = 300` (5 minutes) — short-lived, single-use code.
- PKCE method: `S256` only; `plain` is rejected (not just deprioritized).
- OpenAPI specs (`openapi.json`) must be regenerated to reflect the new
  `/authorize` route and the extended `CreateOfferRequest`/`TokenRequest`/
  `AuthorizationServerMetadata` schemas (AGENTS.md §6).
- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check` must all pass clean before this is considered done
  (AGENTS.md §5).

## Testing Strategy

Mirrors the existing pre-auth test shape (`create_offer.rs`, `token.rs`,
`metadata.rs` test modules), one behavior per test:

- `create_offer` with `redirect_uri` set produces an offer with
  `grants.authorization_code.issuer_state` and no `pre-authorized_code` member.
- `create_offer` rejects `redirect_uri` + `tx_code_required: true` together.
- `/authorize` happy path: valid `issuer_state`/`redirect_uri`/PKCE →
  `302` with `code` and echoed `state`.
- `/authorize` with unresolvable `issuer_state` → `400` JSON, not a redirect.
- `/authorize` with mismatched `redirect_uri` → `400` JSON, not a redirect.
- `/authorize` with `code_challenge_method != "S256"` → `302` error redirect.
- `/authorize` on an already-`Issued` transaction → `302` `access_denied`.
- `/token` happy path: valid `code` + matching `code_verifier` → same
  `TokenResponse` shape as the pre-auth path.
- `/token` with wrong `code_verifier` → `invalid_grant`.
- `/token` with mismatched `redirect_uri` → `invalid_grant`.
- `/token` replaying an already-exchanged `code` → `invalid_grant` (missing).
- `metadata.rs`: `build_authorization_server_metadata` emits
  `authorization_endpoint`, `response_types_supported`,
  `code_challenge_methods_supported`, and both grant types — exact JSON
  shape assertion, same style as `builds_issuer_metadata_from_credential_types`.

## Open Questions

None.