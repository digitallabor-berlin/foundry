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
- **Consumed by:** `crates/foundry` (HTTP handlers), `crates/foundry-wallet`.
- **Must never depend on:** `foundry-issuer` or `crates/foundry`.

Full layering rule: root [AGENTS.md](../../AGENTS.md) §3.

## Module Map

| File | Responsibility |
|---|---|
| `lib.rs` | Module declarations and the `pub use` surface |
| `request.rs` | Creates a verification request (`create_verification_request`), generates the nonce + ephemeral ECDH key pair, and builds the signed Request Object JWT (`build_signed_request_object`); derives `client_id` as `x509_san_dns:<host>` from `server.wallet_facing.public_base_url` |
| `verify.rs` | The orchestrator: JWE decrypt → format-specific verification → DCQL → status, then computes `verified = checks.iter().all(\|c\| c.passed)`. Also flips `tx.state` to `Verified`/`Failed` and stores `tx.result` |
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

- **`verified` MUST equal `checks.iter().all(|c| c.passed)`** — never hardcode
  `verified: true`; it is computed once at the end of `do_verify_vp_response` —
  full rule: root [AGENTS.md](../../AGENTS.md) §4.2.
- **Every verification step must push a named `CheckResult`.** The five names in
  the vocabulary are `jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`,
  `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`.
  **A single result contains four of them**, because the SD-JWT VC and mdoc
  checks are mutually exclusive (chosen by whether `vp_token` is a JSON string
  or an object) — full rule: root [AGENTS.md](../../AGENTS.md) §4.2.
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
- **Gates:** `cargo test --workspace`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo fmt --check` — root [AGENTS.md](../../AGENTS.md) §5.

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
- **`client_id` is derived, not configured:** `x509_san_dns:<dns-host-of-public_base_url>`.
  A mismatch between the configured `public_base_url` and the certificate's
  dNSName SAN breaks audience binding for both formats.
- **The mdoc `vp_token` is an envelope object**, `{ "mdoc": <b64url CBOR>,
  "device_signature": <b64url COSE_Sign1> }`, whereas an SD-JWT VC `vp_token`
  is a bare JSON string. That string-vs-object distinction is what selects the
  format branch — a wrongly-typed `vp_token` yields
  `Failed("unsupported vp_token format")`, not a failed check.
- **`PresentedFormat::MsoMdoc`** is the variant name (not `Mdoc`), matching
  `ClaimFormatDesignation::MsoMDoc`.
- **`response_uri` for mdoc device binding is reconstructed**, not stored:
  `{public_base_url}/vp/response/{tx.id}`. Changing the route shape in
  `crates/foundry` silently breaks the device signature check.