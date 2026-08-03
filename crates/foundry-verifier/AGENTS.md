# AGENTS.md — `crates/foundry-verifier`

## Purpose

The **OpenID4VP verification engine**: builds and signs authorization request
objects, decrypts the wallet's JWE (ECDH-ES) response, delegates credential
verification to the format crates, matches DCQL, and checks Token Status List
revocation/suspension. Produces a `VerificationResult` whose `verified` verdict
is computed from named `CheckResult` records.

**Not** in scope here: HTTP routing and status-code mapping (that is
`crates/foundry`), credential-format cryptography (delegated to
`foundry-sd-jwt-vc` / `foundry-mdoc`), and issuance (`foundry-issuer`).

## Position in the Dependency Graph

- **Depends on:** `foundry-core`, `foundry-sd-jwt-vc`, `foundry-mdoc`. The DCQL
  wire model is foundry-owned (`dcql_model.rs`) — there is no protocol-library
  dependency.
- **Consumed by:** `crates/foundry` (HTTP handlers).
- **Must never depend on:** `foundry-issuer` or `crates/foundry`.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Module declarations and the `pub use` surface |
| `request.rs` | Creates a verification request (`create_verification_request`), generates the nonce + ephemeral ECDH key pair, and builds the signed Request Object JWT (`build_signed_request_object`); derives `client_id` as `x509_hash:<base64url(SHA-256(DER leaf))>` via `foundry_core::trust::x509_hash_client_id_value` (HAIP OpenID4VP L256) |
| `verify.rs` | The orchestrator: JWE decrypt → format-specific verification → DCQL → transaction_data_binding → status, then computes `verified = checks.iter().all(\|c\| c.passed)`. Also flips `tx.state` to `Verified`/`Failed` and stores `tx.result` |
| `dcql.rs` | `PresentedFormat` (`SdJwtVc` \| `MsoMdoc`) and `check_dcql_match`, which returns a `CheckResult` and **never errors** (fail-closed) |
| `dcql_model.rs` | **Crate-private** DCQL wire model per OpenID4VP 1.0 §6/§7: `DcqlQuery`, `DcqlCredentialQuery`, `DcqlClaimsQuery`, `ClaimsPathSegment`, `ClaimValue`, `CredentialFormat`. Three spec non-empty constraints are enforced at deserialization (`credentials`, `claims[].path`, `claims[].values`) because each is fail-closed. `CredentialFormat::Other(String)` is **required**, not cosmetic: without it an unimplemented format would fail parsing and be reported as a malformed query instead of simply not matching. Never add `deny_unknown_fields` — §6 requires unknown properties to be ignored |
| `status.rs` | `StatusListResolver` trait + `HttpStatusListResolver` (10s timeout); `check_status` resolves the Status List Token, verifies it against the trust store, and reads the credential's status bit |
| `transaction.rs` | `VerificationTransaction`, `VerificationState`, `CheckResult`, `VerificationResult`, and `Storage`-backed persistence (namespace `verification_tx`) — **note: the result/check types live here, not in `error.rs`** |
| `error.rs` | The `VerificationError` enum only |

## Key Public Types & Entry Points

- **`verify_vp_response(&Config, &mut VerificationTransaction, encrypted_jwe_str, &dyn StatusListResolver) -> Result<VerificationResult, VerificationError>`**
  — the main entry point, driven by `POST /vp/response/:id`.
- **Request:** `create_verification_request`, `build_signed_request_object`,
  `CreateVerificationRequest`, `CreateVerificationResponse` — driven by
  `POST /admin/verification/requests` and `GET /vp/request/:id`.
- **DCQL:** `check_dcql_match(dcql_query, format, disclosed_claims, doc_type) -> CheckResult`,
  `PresentedFormat`.
- **Transaction Data:** `check_transaction_data_binding(requested_entries, answered_query_id, kb_payload) -> CheckResult`
  (`verify.rs`) — pushed only when `tx.transaction_data` is `Some`; never errors
  (fail-closed), matching `check_dcql_match`'s contract.
- **Status:** `check_status(disclosed_claims, trust_store, resolver, now_unix) -> Result<CheckResult, VerificationError>`,
  `StatusListResolver`, `HttpStatusListResolver`.
- **Transaction / results:** `VerificationTransaction` (fields include `id`,
  `state`, `nonce`, `dcql_query`, `transport`, `response_mode`,
  `ephem_private_jwk`, `ephem_public_jwk`, `transaction_data`, `result`,
  `created_at`), `VerificationState` (`Pending` | `Verified` | `Failed`),
  `VerificationResult { verified, checks, claims }`,
  `CheckResult { check, passed, detail }`,
  `save_verification_transaction`, `load_verification_transaction`.
- **Errors:** `VerificationError` — `NotFound`, `InvalidState`, `Dcql`,
  `Crypto`, `Decryption`, `Failed`, `StatusUnavailable`, `Storage`,
  `CoreCrypto`, `Trust`, `Serialization`.

## Binding Invariants

- **Every `#[tracing::instrument]` in this crate MUST carry `skip_all`.** Without
  it every argument is `Debug`-formatted into the span — including `Config` and
  `VerificationTransaction`, which holds `ephem_private_jwk`, plus raw JWE
  strings. Fields are opt-in, always. Enforced by
  `crates/foundry/tests/instrumentation_hygiene.rs`.
- **Payload-bearing log fields require BOTH `obs::sensitive_enabled()` AND a
  `debug`/`trace` level.** A level alone is not authorisation — `RUST_LOG=debug`
  is ordinary in production. Never log an ephemeral or private JWK at all.
  Redaction tiers: see the "Logging & Observability" section of the root
  [README.md](../../README.md).
- **A policy failure logs at `warn`, not `error`.** A DCQL mismatch or a revoked
  credential is a correct outcome that still returns HTTP 200 with
  `verified: false` (root [AGENTS.md](../../AGENTS.md) §4.3); reserve `error` for
  actual faults such as an unreachable status list.
- **`verified` MUST equal `checks.iter().all(|c| c.passed)`** — never hardcode
  `verified: true`; it is computed once at the end of `do_verify_vp_response` —
  full rule: root [AGENTS.md](../../AGENTS.md) §4.2.
- **Every verification step must push a named `CheckResult`.** The six names in
  the vocabulary are `jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`,
  `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`,
  `transaction_data_binding`. **A single result normally contains four of the
  first five**, because the SD-JWT VC and mdoc checks are mutually exclusive
  (chosen by whether `vp_token` is a JSON string or an object);
  `transaction_data_binding` adds a fifth only when `tx.transaction_data` is
  `Some` — an mdoc presentation with `transaction_data` requested still gets
  the check pushed, recorded as a hard `passed: false` (no KB-JWT exists to
  bind it) — full rule: root [AGENTS.md](../../AGENTS.md) §4.2.
- **The error path of `verify_vp_response` MUST populate `tx.result`.** Setting
  only `tx.state = Failed` leaves the reason inside the returned `Err`, which the
  HTTP layer sends to the *wallet* — so the admin console renders a bare red
  "failed" with no explanation (it shows its checks list only when `tx.result` is
  present). `check_name_for` maps the aborting variant onto the same check
  vocabulary the success path uses.
- **Never skip a push on a failure path.** An omitted `CheckResult` silently
  disappears from `all(passed)` and can turn a failure into a pass — root
  [AGENTS.md](../../AGENTS.md) §4.2.
- **Policy vs. structural classification is split across two crates.** This crate
  encodes it in the return type; `crates/foundry/src/server.rs` maps it to a
  status code in `verifier_wallet_error_response`:
  - **Policy** → return `Ok` with a `CheckResult { passed: false }`, giving
    HTTP 200 + `verified: false`. This is what `dcql_match` failures and
    revoked/suspended/malformed-status outcomes do.
  - **Structural / crypto** → `Decryption(_)` / `Failed(_)` / `Serialization(_)`
    → HTTP **400** `invalid_request`.
  - **Network** → `StatusUnavailable(_)` → HTTP **502** `status_unavailable`.
  - Anything else falls through to HTTP 500, so **adding a new
    `VerificationError` variant without updating that handler silently produces
    a 500** — full rule: root [AGENTS.md](../../AGENTS.md) §4.3.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()`** outside
  `#[cfg(test)]`; return `VerificationError` — root
  [AGENTS.md](../../AGENTS.md) §4.1.
- **`VerificationResult` and friends are `utoipa::ToSchema`** — changing them
  changes `openapi-wallet.json` — root [AGENTS.md](../../AGENTS.md) §6.
- **Gates are scoped by default:** per task, run `cargo test -p foundry-verifier
  -p foundry` (the integration suite lives in `crates/foundry/tests`), plus
  `cargo clippy -p foundry-verifier --all-targets -- -D warnings` and
  `cargo fmt --check`. Save `cargo test --workspace` for the end of a
  development cycle or when unsure of the blast radius — **not** between tasks.
  Full rule: root [AGENTS.md](../../AGENTS.md) §5.

## Tests

No `tests/` directory. Unit coverage is inline `#[cfg(test)]` in `dcql.rs`,
`error.rs`, `request.rs`, `status.rs`, `transaction.rs`, `verify.rs` (including
positive, DCQL-mismatch, and revocation cases). Flow coverage lives in
`crates/foundry/tests/` — see [`../foundry/tests/AGENTS.md`](../foundry/tests/AGENTS.md);
most relevant: `wallet_verification.rs`, `e2e_full_flow.rs`,
`wallet_status_list_route.rs`.

```bash
cargo test -p foundry-verifier
cargo test -p foundry --test wallet_verification
```

## Gotchas

- **`check_status` treats a missing status claim as a PASS.** A credential with
  no `status.status_list` claim is considered non-revocable and the check passes.
  Only a revoked/suspended index, a malformed status claim, or a Status List
  Token that fails trust-anchor/`sub`/`exp` verification produce
  `passed: false`; only an IO/network failure returns
  `Err(VerificationError::StatusUnavailable)`. Do not "tighten" the missing-claim
  case without checking the callers.
- **`check_dcql_match` never returns `Err`** — it always yields a `CheckResult`
  and is deliberately fail-closed (an unparseable `dcql_query` becomes
  `passed: false` with a reason). Do not convert it to a `Result`.
- **`check_dcql_match` is bound to the credential query the presentation
  ANSWERS**, via its `answered_query_id` argument — not to "any credential query
  of the presented format". A presentation must satisfy the query it was keyed
  under, so it cannot be credited to a different query it happens to satisfy.
  An `answered_query_id` absent from the query is a failed check, never an error.
- **`dcql_query` is validated when the request is CREATED**, in
  `create_verification_request`, before the transaction is persisted. An
  unusable query is the operator's `VerificationError::Dcql` (HTTP 400) rather
  than a wallet-visible presentation failure. The fail-closed branch inside
  `check_dcql_match` therefore stays as defence in depth but is not normally
  reachable via the request path.
- **Single-use enforcement is in the HTTP handler, not this crate.**
  `post_response_handler` rejects any transaction whose state is not `Pending`
  with 400 `invalid_request`. `verify_vp_response` itself does not check prior
  state — it only writes the new one.
- **`verify_vp_response` mutates the transaction but does not persist it.** It
  sets `tx.state` and `tx.result`; the caller must call
  `save_verification_transaction` afterwards (the handler does this even on the
  error path).
- **`jwe_decryption` is seeded as `passed: true`, never as a failure.** JWE
  failure is an early `Err(Decryption(..))` → 400, so a `verified: false` result
  will never carry a failed `jwe_decryption` record.
- **`client_id` is derived, not configured:** `x509_hash:<base64url(SHA-256(DER leaf))>`
  (HAIP OpenID4VP L256 / OpenID4VP L616), computed by
  `foundry_core::trust::x509_hash_client_id_value` and re-derived independently by
  both `build_signed_request_object` and `do_verify_vp_response` so the two sides
  cannot drift. GAP-VP-02's SAN cross-check is anchored on
  `server.wallet_facing.public_base_url`'s host, not on the client_id (which no
  longer carries a hostname): `build_signed_request_object` **hard-fails** on a
  mismatch between that host and the configured `x5c` leaf's dNSName SAN entries
  (`foundry_core::trust::match_san_dns`) — what used to be a silent
  audience-binding break for both formats is now a `VerificationError::Crypto`
  raised before the Request Object is ever signed. `x5c` is mandatory for signed
  requests (the identifier *is* the certificate hash), so this check is always
  attempted.
- **`vp_token` is an OpenID4VP 1.0 §8.1 object keyed by DCQL credential query id,
  with ARRAY values** — `{ "<query id>": [ <presentation> ] }` — and that is the
  same shape for **both** credential formats. The credential format comes from
  the `format` **declared by the answered credential query**, never from the JSON
  type of the payload. `select_presentation` (in `verify.rs`) performs the
  selection and returns an already-destructured payload, so no verification arm
  can re-derive the format.
  Never restore type-sniffing (`vp_token.as_str()` ⇒ SD-JWT, `as_object()` ⇒
  mdoc): because a conformant SD-JWT VC envelope is *also* an object, that logic
  routed real SD-JWT presentations into the mdoc branch and reported the
  misleading `mdoc vp_token missing 'mdoc'`. A bare-string `vp_token` was
  foundry's own pre-fix shape and no conformant wallet sends it.
  Per-format payloads: `dc+sd-jwt` → the SD-JWT VC string; `mso_mdoc` →
  `{ "mdoc": <b64url CBOR>, "device_signature": <b64url COSE_Sign1> }`, which is
  **bespoke and NOT interoperable** — see `crates/foundry-mdoc/AGENTS.md`.
  A credential query whose `format` this verifier does not implement
  (`CredentialFormat::Other`) is a structural 400 once answered, even though it
  parses fine so it can simply fail to match inside a multi-credential query.
- **`PresentedFormat::MsoMdoc`** is the variant name (not `Mdoc`), matching
  `dcql_model::CredentialFormat::MsoMdoc` (note: lower-case `d` in `Mdoc` —
  the removed vendored type spelled it `MsoMDoc`).
- **`response_uri` for mdoc device binding is reconstructed**, not stored:
  `{public_base_url}/vp/response/{tx.id}`. Changing the route shape in
  `crates/foundry` silently breaks the device signature check.