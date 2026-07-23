# Foundry End-to-End Full-Flow Test — Design

**Date:** 2026-07-23
**Status:** Approved for planning

## 1. Overview

Foundry has extensive in-process integration coverage (`crates/foundry/tests/wallet_issuance.rs`,
`wallet_verification.rs`, etc.) that exercises OpenID4VCI/OpenID4VP protocol logic directly
against the `axum::Router` via `tower::ServiceExt::oneshot`. It also has CLI-subprocess tests
(`cli_openapi.rs`, `cli_status_list.rs`) that spawn the real `foundry` binary for one-shot
commands. Neither proves that the actual `foundry serve` long-running process, booted from a
freshly generated PKI/config via the real CLI, correctly serves a complete issuance +
verification + revocation lifecycle purely over the network, the way a real wallet/verifier
integration would exercise it.

This spec defines a new automated end-to-end (e2e) test that:

1. Spawns the real `foundry` binary to run `quickstart` (generates PKI + config).
2. Spawns the real `foundry` binary to run `serve` (a real, long-running process bound to
   dynamically allocated ports).
3. Drives it purely over HTTP, acting as a real admin client, a real wallet, and a real
   verifier's relying-party client:
   - creates a credential offer,
   - performs OpenID4VCI issuance of an SD-JWT VC `pid` credential,
   - performs OpenID4VP verification of that credential (happy path, `verified: true`),
   - revokes the credential's status-list index via the CLI against the live database,
   - re-verifies and asserts `verified: false` with the `status_check` specifically failing.

It also closes a real production gap discovered during design: `foundry serve` does not
currently expose an HTTP endpoint for status list tokens, even though every credential's
`status` claim points at one (`issuer.status_list.public_base_url`). This spec adds that route
so the e2e test proves genuine end-to-end behavior rather than working around a missing
feature with a side-channel mock server.

## 2. Goals

- Prove, via real subprocess + real network calls, that `foundry serve` supports the full
  issue → verify → revoke → re-verify lifecycle for an SD-JWT VC credential type.
- Close the status-list-serving gap in production code (`/statuslists/:credential_type`).
- Keep the default `cargo test --workspace` run fast — the e2e test must be opt-in
  (`#[ignore]`), documented, and suitable as a distinct CI job.
- Reuse existing crypto/JWT helper logic (from `wallet_issuance.rs` / `wallet_verification.rs`)
  rather than reimplementing JWT/JWE/DCQL construction in a shell script.

## 3. Non-goals

- mdoc credential format coverage (SD-JWT VC only, per scope decision).
- TLS — `foundry serve` is plain HTTP; `public_base_url` values with `https://` are metadata
  labels only, not actual TLS termination. The e2e test connects over plain HTTP to the real
  bound addresses.
- Wallet/key attestation flows — `issuer.wallet_attestation`/`key_attestation` remain
  `mode: optional` (quickstart default), so the credential request only needs a standard
  OpenID4VCI key-proof JWT.
- User-interactive tx_code (PIN) flow — the offer uses `tx_code_required: false`
  (pre-authorized_code grant only).
- Adding a write/admin HTTP endpoint for status revocation — revocation is driven via the
  existing `foundry status-list set` CLI subcommand against the live SQLite file.

## 4. Production change: `/statuslists/:credential_type` route

### Current gap

- `wallet_router` (`crates/foundry/src/server.rs`) registers `/token`, `/nonce`, `/credential`,
  `/vp/request/:id`, `/vp/response/:id`, metadata endpoints, and swagger — but nothing under
  `/statuslists`.
- `commands.rs::status_list_token` already implements the logic to load a
  `PersistentStatusList` from storage, convert it to a `StatusList`, and sign a
  `statuslist+jwt` token — but only reachable via the `foundry status-list token` CLI command,
  not over HTTP.
- The existing `wallet_verification.rs` test works around this by spinning up its own ad hoc
  mock axum server on a random port purely to serve a manually built status list token during
  the test.

### Change

- Extract the shared "load persistent list for `credential_type`, build signed status-list
  token" logic out of `commands.rs::status_list_token` into a reusable function (candidate
  home: `foundry-core` status_list module, or a small helper in `foundry-issuer` alongside
  other issuer-facing logic — final placement decided at planning time), parameterized by
  `Storage`, the resolved signing key material, and the `credential_type`.
- Add `GET /statuslists/:credential_type` to `wallet_router`, **unauthenticated** (status list
  tokens are meant to be publicly fetchable by any relying party per the IETF Token Status
  List convention — consistent with `issuer.status_list.public_base_url` living under the
  wallet-facing, not admin, listener).
- Handler behavior:
  - Loads the `PersistentStatusList` for the path's `credential_type` from storage.
  - If none exists yet, return `404`.
  - If the credential type's `issuer.status_list.enabled` is `false`, return `404`.
  - Otherwise sign and return the `statuslist+jwt` token (`Content-Type` per the Token Status
    List spec, e.g. `application/statuslist+jwt`) with `sub` derived the same way
    `commands.rs::status_list_token` derives it today
    (`{public_base_url}/{credential_type}`).
- Register the new route in the wallet-facing OpenAPI spec generation
  (`crates/foundry/src/openapi.rs`), per AGENTS.md §5 ("Changes to those endpoints must be
  reflected in the specification").
- CLI's `foundry status-list token` and `foundry status-list set` behavior are unchanged.

## 5. Test harness design

New file: `crates/foundry/tests/e2e_full_flow.rs`. A single `#[ignore]`d `#[tokio::test]`
(or a `#[test]` driving a small internal async runtime, matching the crate's existing test
conventions) named e.g. `full_flow_issue_verify_revoke_reverify`.

### 5.1 Process spawning

- `foundry quickstart --dir <tempdir> --out-config <tempdir>/config.yaml` is spawned via
  `std::process::Command::new(env!("CARGO_BIN_EXE_foundry"))`, matching the pattern already
  used in `cli_openapi.rs`. Asserted to exit successfully.
- The generated `config.yaml` is loaded, `server.admin.bind` and `server.wallet_facing.bind`
  are rewritten to `127.0.0.1:0`, and the file is rewritten in place.
- `foundry --log-format json serve --config <tempdir>/config.yaml` is spawned as a long-lived
  child process (`std::process::Command` with piped `stdout`/`stderr`, or `tokio::process`
  for async-friendly line reading).

### 5.2 Port discovery

**Correction from the initial design (found during planning):** `foundry-verifier`'s
`HttpStatusListResolver::fetch()` performs a real, server-initiated `reqwest::Client::get(uri)`
where `uri` is the credential's embedded `status.status_list.uri` — itself derived **at
issuance time** from the static config value `issuer.status_list.public_base_url`
(`credential.rs:132`), fixed before the server ever binds. If the wallet-facing port is left as
an OS-assigned `bind: 127.0.0.1:0` unknown until after boot, `status_list.public_base_url`
would be an unreachable placeholder and the in-process status-check HTTP fetch would fail to
connect — breaking even the happy-path assertion, not just the revocation scenario. No other
`public_base_url`/`credential_issuer` config value has this live-dereference requirement (they
are only echoed into JWT claims compared as strings, or used to build URLs the *test* — not the
server — constructs directly against the real discovered socket).

Therefore port discovery uses **probe-and-release**, not log-line parsing, as the primary
mechanism:

- For both the admin and wallet-facing listeners: bind a `tokio::net::TcpListener` to
  `127.0.0.1:0` in the test process, read `.local_addr()`, then drop the listener to free the
  port. This determines both real ports *before* the config is written.
- Write those exact ports into `server.admin.bind` / `server.wallet_facing.bind`, **and** set
  `issuer.status_list.public_base_url` to `http://127.0.0.1:{wallet_port}/statuslists` so the
  credential's embedded status URI is genuinely reachable once the real server binds to that
  same pre-selected port. Accepts a small, standard probe-and-release race window (another
  process could theoretically grab the port first) — acceptable for a test harness.
- `server.rs`'s log statements are still changed to log the listener's actual resolved address
  (`admin_listener.local_addr()?` / `wallet_listener.local_addr()?`) instead of the configured
  string — this remains a genuine, independent production-logging correctness improvement. The
  test uses it as a **secondary sanity assertion** (the logged address must equal the
  pre-selected port) rather than as the mechanism for learning where to send requests.
- The test reads the child's stdout line-by-line (JSON log format, one object per line) to
  perform that sanity assertion, and to capture diagnostics.
- A background task continuously drains remaining stdout/stderr into an in-memory buffer
  (bounded, e.g. last N KB or last N lines) for later failure diagnostics — this prevents the
  child from blocking on a full OS pipe buffer once the test stops actively reading lines.

### 5.3 Readiness and teardown

- After port discovery, poll `GET http://{admin_addr}/ready` with a short interval and overall
  timeout (e.g. 100ms interval, 5s timeout) until `200 OK`.
- An RAII guard type wraps the child `Child` handle and calls `.kill()` (+ `.wait()`) in its
  `Drop` impl, so the server subprocess is always reaped even if an assertion panics mid-test.

## 6. Test flow (detailed)

All HTTP calls use `reqwest` (new dev-dependency on `crates/foundry/Cargo.toml`).

### Step 1 — Create credential offer

`POST http://{admin_addr}/admin/issuance/offers`
Header: `Authorization: Bearer dev-admin-key`
Body:
```json
{
  "credential_type_id": "pid",
  "claims": { "given_name": "Alice", "birthdate": "1990-01-01" },
  "tx_code_required": false
}
```
Response includes a credential offer (pre-authorized_code grant) per
`CreateOfferResponse`/`foundry-issuer`.

### Step 2 — Issuance (test plays the wallet)

- `POST http://{wallet_addr}/token` with the pre-authorized code from Step 1 → access token.
- `POST http://{wallet_addr}/nonce` (bearer access token) → `c_nonce`.
- Generate an ES256 key pair (holder key) via `josekit`, matching the pattern in
  `wallet_issuance.rs`; build a key-proof JWT bound to the returned nonce and the wallet's
  `credential_issuer` value.
- `POST http://{wallet_addr}/credential` with the proof JWT → `CredentialResponse` containing
  the issued SD-JWT VC (`dc+sd-jwt`).
- Parse the SD-JWT VC (issuer-signed JWT + disclosures) sufficiently to confirm:
  - disclosed claims include `given_name`/`birthdate` matching what was requested,
  - the embedded `cnf` / holder-binding key matches the generated holder key,
  - the `status` claim contains a `status_list` object with a `uri` and `idx`.

### Step 3 — Verification, happy path (test plays wallet responding to a request)

- `POST http://{admin_addr}/admin/verification/requests` with a DCQL query matching the
  `pid` credential type's `vct` and the disclosed claim paths (`given_name`, `birthdate`) →
  `CreateVerificationResponse` with a `request_uri`.
- `GET http://{wallet_addr}/vp/request/:id` → signed request object (JAR); parse it for
  `nonce`, `client_id`, `response_encryption` (ECDH-ES/A128GCM per config), and the DCQL query.
- Build the VP token: an SD-JWT VC presentation (issuer-signed JWT + selected disclosures) with
  a KB-JWT bound to the request's `nonce`/`aud`, matching helper logic from
  `wallet_verification.rs`.
- Encrypt the authorization response per the request's `response_encryption` using the
  verifier's public key (via `openid4vp::core::jwe::JweBuilder`, reusing existing test
  helpers).
- `POST http://{wallet_addr}/vp/response/:id` with the encrypted response.
- `GET http://{admin_addr}/admin/verification/requests/:id` → `VerificationResult`. Assert
  `verified == true` and every entry in `checks` has `passed == true`, including
  `status_check`.

### Step 4 — Revoke

- From Step 2's parsed credential, read `status.status_list.idx`.
- Determine the live SQLite DB path from the (rewritten) config's `storage.path`, resolved
  relative to the config file's directory.
- Run `foundry status-list set --db <resolved-db-path> --credential-type pid --index <idx>
  --status revoked` as a subprocess, while `serve` continues running. (sqlx's default
  `SqliteConnectOptions` busy-timeout tolerates this brief cross-process write; both
  processes access the same on-disk SQLite file.) Assert the subprocess exits successfully.

### Step 5 — Verification, revoked

- Repeat Step 3 in full with a **new** verification request/response (do not reuse the
  Step 3 transaction — status is resolved fresh per verification, and the Step 3 request may
  already be consumed/expired).
- Assert `verified == false`.
- Assert specifically that the `status_check` entry has `passed == false` (and, to catch
  regressions where an unrelated check silently starts failing instead of the intended one,
  assert the other checks — `jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`, `dcql_match`
  — still have `passed == true`).

## 7. Error handling / diagnostics

- Any panic/assertion failure triggers (via a test-scoped guard or explicit `Result`-based
  flow with a final failure handler) a dump of the buffered server stdout/stderr collected
  per §5.2, so CI failures show real server-side context (tracing logs, error responses)
  rather than a bare `assert_eq!` mismatch.
- All fallible steps use `.expect("descriptive context")` / propagate `Result` with context —
  acceptable here since this is test code (`#[cfg(test)]`), per AGENTS.md's unwrap/panic rule
  which only restricts production request-handling paths.

## 8. CI / invocation

- The test is annotated `#[ignore]` so it is excluded from default `cargo test --workspace`.
- Documented in `README.md`: `cargo test -p foundry --test e2e_full_flow -- --ignored`.
- Recommended (not required by this spec) as a separate CI job step, run after the standard
  `cargo test --workspace` / `cargo clippy` / `cargo fmt --check` gates, since it is slower and
  binds real OS ports.

## 9. Files touched (planning-time expectation, not exhaustive)

- `crates/foundry/src/server.rs` — add `/statuslists/:credential_type` route; fix `serve()`'s
  two log statements to report actual bound addresses.
- `crates/foundry/src/openapi.rs` — document the new wallet-facing route.
- `foundry-core` (or `foundry-issuer`) — extract shared status-list-token-building helper used
  by both the CLI command and the new HTTP handler.
- `crates/foundry/src/commands.rs` — `status_list_token` refactored to call the shared helper.
- `crates/foundry/tests/e2e_full_flow.rs` — new test.
- `crates/foundry/Cargo.toml` — add `reqwest` (with `json` feature) as a dev-dependency.
- `README.md` — document how to run the e2e test.

## 10. Open considerations for the implementation plan

- Exact placement of the extracted status-list-token-building helper (foundry-core vs
  foundry-issuer) — decide during planning based on existing module boundaries.
- Exact JSON shape of `tracing_subscriber`'s `fmt().json()` output (field nesting under
  `fields.*`) needs confirming against the actual dependency version when writing the log-line
  parser.
- Whether the DCQL query construction needs new helper types/builders in
  `foundry-verifier`/`openid4vp`, or can reuse existing request-building code paths already
  exercised by `wallet_verification.rs`.