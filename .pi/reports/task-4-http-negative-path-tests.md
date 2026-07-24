# Task #4: HTTP-level negative-path integration tests — STATUS: NOT STARTED (exploration only)

## What happened

I spent the entire turn budget on exploration/context-gathering (reading the existing
happy-path tests, the router/AppState setup, the issuer/verifier error types, proof
verification, token handling, credential handling, SD-JWT VC verifier, and TrustStore),
and confirmed the workspace builds cleanly (`cargo build --workspace` — success, 0 errors).
I did **not** write any new test code before hitting the turn limit. No files were
modified or committed by me in this session.

This report exists so a follow-up pass can pick up immediately without re-doing the
discovery work.

## Confirmed environment state

- Branch: `main` (per controller's explicit instruction, committing directly to `main`
  is fine — no worktree needed).
- Latest commits: `1918224` (task #1, replay guards + /nonce) on top of `76f32b9`.
- Working tree has **uncommitted, out-of-scope changes** (not made by me) in:
  `crates/foundry-issuer/src/credential.rs`, `proof.rs`, `transaction.rs` — these are
  pure `rustfmt`-style formatting diffs (multi-line method chains reformatted), no
  logic changes vs. the committed version. They do not block test-writing but the
  follow-up agent should be aware another process may still be touching these files
  concurrently. Recommend `git stash` or `git diff` check before committing new test
  files to avoid bundling unrelated formatting changes into the test commit.
- `cargo build --workspace` succeeds cleanly.
- Task #1 (replay guards / /nonce) is DONE and merged — its replay-guard behavior can be
  relied upon for the "second call rejected" test cases described in the brief.

## Files to modify

- `crates/foundry/tests/wallet_issuance.rs` (currently 1 happy-path test:
  `full_issuance_flow_end_to_end`, ~230 lines). Has helper `setup_test_app()` returning
  `(AppState, TempDir)` and `create_proof(c_nonce, issuer) -> (serde_json::Value, EcKeyPair)`.
- `crates/foundry/tests/wallet_verification.rs` (currently 2 tests: happy path
  `full_verification_flow_end_to_end` and the task-#1-added
  `resubmitting_a_verification_response_is_rejected`). Has helper
  `setup_test_app() -> (AppState, TempDir, issuer_cert_pem, issuer_key_pem)` using a
  real CA (`new_ca`)/leaf (`issue_leaf`) from `foundry_core::pki`, and `der_b64()`.

## Exact behavior/interfaces confirmed for each required negative test

### Issuance (`wallet_issuance.rs`)

1. **Wrong/expired pre-authorized_code → 400 invalid_grant**
   - `handle_token_request` in `token.rs`: `load_transaction_by_pre_auth_code` returns
     `None` for unknown code → `IssuanceError::InvalidGrant("invalid or expired
     pre-authorized_code")`.
   - `wallet_error_response()` in `server.rs` maps `InvalidGrant(_)` →
     `(StatusCode::BAD_REQUEST, "invalid_grant")`.
   - Test recipe: POST `/token` with `pre-authorized_code=totally-bogus-code` (no prior
     offer creation needed) → assert `StatusCode::BAD_REQUEST` and
     `body["error"] == "invalid_grant"`.

2. **Valid code but wrong tx_code → 400 invalid_grant**
   - Requires creating an offer via Admin API with `"tx_code_required": true` (see
     `create_offer.rs` / `CreateOfferRequest.tx_code_required`), extracting
     `pre-authorized_code` from the offer response exactly like the happy-path test,
     then POST `/token` with `tx_code=0000` (or any value != the real one — the real
     tx_code is never returned by the offer endpoint since it's server-only, so a fixed
     wrong guess like `"9999"` is safe — collision probability negligible but if
     determinism is wanted, could inspect via admin `GET` endpoint, but there is no
     admin GET-by-pre-auth-code endpoint, only `GET /admin/verification/requests/{id}`
     for the **verifier** — the issuance side doesn't expose transaction_id-lookup
     over HTTP in this codebase, so blind guessing of a wrong tx_code, e.g. `"0000"`,
     is the pragmatic approach; extremely low false-positive risk with 4-digit space).
   - Assert `StatusCode::BAD_REQUEST`, `body["error"] == "invalid_grant"`.

3. **Valid access_token, proof JWT with bad aud / bad nonce / expired c_nonce → 400 invalid_proof**
   - Need to run the full offer→token flow to get a real `access_token` and `c_nonce`
     (via `/nonce` like the happy path does).
   - `verify_holder_proof()` in `proof.rs` is where aud/nonce checks happen, both
     surface as `IssuanceError::InvalidProof(...)`, and `wallet_error_response()` maps
     `InvalidProof(_)` → `(BAD_REQUEST, "invalid_proof")`.
   - For expired c_nonce: `verify_holder_proof` checks
     `if now_unix > c_nonce_expires_at { return Err(InvalidProof("c_nonce has expired")) }`
     — but note **this check happens inside the pure function**, driven by the
     `now_unix` argument passed into `handle_credential_request` by the HTTP handler
     via `SystemTime::now()` (see `credential_handler` in `server.rs`) — the HTTP
     handler does NOT accept an injectable clock. To trigger "expired c_nonce" at the
     HTTP layer without control over wall-clock time, the test must engineer a
     transaction whose `c_nonce_expires_at` is already in the past relative to
     wall-clock "now" — this requires inserting the `IssuanceTransaction` directly via
     `foundry_issuer::transaction::save_transaction_with_indices` (already used as a
     pattern in `token.rs`/`credential.rs` unit tests) with `c_nonce_expires_at` set to
     e.g. `1` (unix epoch + 1s, long past) and `access_token`/`c_nonce` pre-set, bypassing
     the `/token` HTTP call entirely for this one test case (mirrors how the crate's own
     unit tests build transactions directly — see `credential.rs`'s
     `issues_sd_jwt_vc_credential_successfully` test for the exact pattern:
     construct `IssuanceTransaction { .. }`, call
     `save_transaction_with_indices(&storage_arc_from_state, &tx, 600, now).await`,
     using `state.storage.as_ref()` from `setup_test_app()`'s returned `AppState`).
   - For bad `aud`: reuse `create_proof(c_nonce, "https://not-the-real-issuer.example")`
     (wrong second arg) against a validly-obtained `c_nonce`.
   - For bad `nonce`: reuse `create_proof("wrong-nonce-value", "https://issuer.example.com")`
     against a validly-obtained access_token (the c_nonce embedded in the proof will not
     match the transaction's real c_nonce).
   - All three assert `StatusCode::BAD_REQUEST` and `body["error"] == "invalid_proof"`.

4. **Second `/credential` call with same access_token → rejected (task #1's guard)**
   - `handle_credential_request` in `credential.rs`: after a successful call,
     `tx.state = IssuanceState::Issued; save_transaction_with_indices(...)`. On a second
     call with the same access_token, the guard `if tx.state != IssuanceState::Offered
     { return Err(InvalidGrant("credential offer has already been claimed")) }` fires
     BEFORE proof verification. `wallet_error_response()` maps `InvalidGrant(_)` →
     `(BAD_REQUEST, "invalid_grant")` — **note: this is `invalid_grant`, not a generic
     "rejection"; the brief only says "second call expects rejection", so asserting
     `StatusCode::BAD_REQUEST` (and optionally `body["error"] == "invalid_grant"`) satisfies
     it.** This guard is already present and already covered indirectly by existing
     issuer crate-level unit tests (`token.rs`'s
     `rejects_token_request_for_already_issued_transaction"`), but there is currently
     NO HTTP-level integration test proving the **second `/credential` call** itself
     is rejected — this is the specific gap task #4 must close. The full flow to set
     up for this test: offer → token → nonce → credential (succeeds, 200) → credential
     again with the same access_token and a **freshly regenerated proof** (need a new
     c_nonce via `/nonce` again, since the c_nonce didn't change from before, OR reuse
     the same nonce/proof since the tx is now `Issued` and the guard fires before proof
     verification even runs) → assert `StatusCode::BAD_REQUEST`.

### Verification (`wallet_verification.rs`)

5. **Tampered/garbage JWE → error, not panic**
   - `do_verify_vp_response()` in `verify.rs`: `josekit::jwt::decode_with_decrypter`
     failure → `VerificationError::Decryption(...)`.
   - `verifier_wallet_error_response()` in `server.rs` maps `Decryption(_)` →
     `(BAD_REQUEST, "invalid_request")`.
   - This exact case is ALREADY covered at the unit level by `verify.rs`'s
     `test_verify_vp_response_invalid_jwe` (using literal string
     `"not.a.valid.jwe.token"`), but not at HTTP level. Test recipe: run the create
     request→get request-object steps from the happy path to obtain a real
     `verification_id`, then POST `/vp/response/{id}` with a garbage body like
     `"not-a-real-jwe-at-all"` → assert `StatusCode::BAD_REQUEST`,
     `body["error"] == "invalid_request"`, and (critically) that the call returns
     normally rather than panicking (the `.oneshot()` call completing without a Rust
     panic/unwind is itself the proof — Axum would surface a panic as a 500 from the
     default panic-catching layer, or the test process would abort; either way,
     asserting a clean `BAD_REQUEST` response object rules out a panic).

6. **Untrusted-root SD-JWT VC → rejected**
   - Build a **second, independent CA** (`new_ca("Untrusted Root CA", 365)`) not
     included in `config.trust_anchors` (which in `setup_test_app()` only contains the
     `root` CA), issue a leaf from that untrusted CA, sign the SD-JWT VC with that
     leaf's key, and follow the same encrypt/POST flow as the happy path.
   - `validate_chain()` in `trust/mod.rs` will fail to find the untrusted root in the
     `TrustStore`, surfacing (need to trace exact error variant/message from
     `validate_chain`'s implementation past line 140 — I read only through line ~140;
     the remainder of `validate_chain`'s DN-chaining/anchor-lookup logic and its
     `TrustError` variant for "no matching anchor" was NOT yet read before I ran out of
     turns) → propagates as `foundry_sd_jwt_vc::error::FormatError::SignatureVerification(...)`
     from `verify_sd_jwt_vc()` → `VerificationError::Failed(...)` in `verify.rs`'s
     `do_verify_vp_response` (`.map_err(|e| VerificationError::Failed(e.to_string()))`)
     → `verifier_wallet_error_response()` maps `Failed(_)` → `(BAD_REQUEST,
     "invalid_request")`.
   - **TODO for follow-up**: read the rest of `crates/foundry-core/src/trust/mod.rs`
     (from line ~140 onward) to confirm the exact `TrustError` variant name and confirm
     `validate_chain`'s signature/behavior when no anchor matches, before writing this
     test, to make sure the untrusted-root scenario actually reaches that code path
     (vs., e.g., being rejected earlier for an unrelated reason like a missing SAN).

7. **Unknown/non-existent transaction id → 404 (regression test)**
   - Confirmed in `post_response_handler` in `server.rs`: `tx_opt is None` branch
     returns `(StatusCode::NOT_FOUND, Json({"error": "not_found", ...}))` — already
     implemented correctly. Add a simple regression test: POST
     `/vp/response/some-id-that-was-never-created` with any body → assert
     `StatusCode::NOT_FOUND`.

8. **Second `/vp/response/{id}` call → rejected**
   - **Already implemented as an integration test** by task #1:
     `resubmitting_a_verification_response_is_rejected` in `wallet_verification.rs`
     (see the file content captured during this session — it already does exactly
     what the brief asks: submits once (200), submits again with the identical JWE
     (asserts 400 `invalid_request`), then re-fetches the admin transaction record and
     asserts state remains `Verified`). **No further action needed for this specific
     sub-bullet** — it is done. (The brief anticipated this might still be pending;
     it is not — task #1 already landed it as part of commit `1918224`.)

## Remaining work for the follow-up pass (in priority order)

1. Read `crates/foundry-core/src/trust/mod.rs` fully (lines 140+) to confirm the
   untrusted-root error path/variant before writing test #6.
2. Write test module additions to `crates/foundry/tests/wallet_issuance.rs`:
   - `token_rejects_unknown_pre_authorized_code`
   - `token_rejects_wrong_tx_code`
   - `credential_rejects_proof_with_wrong_audience`
   - `credential_rejects_proof_with_wrong_nonce`
   - `credential_rejects_expired_c_nonce` (direct transaction injection per above)
   - `credential_second_call_with_same_access_token_is_rejected`
3. Write test module additions to `crates/foundry/tests/wallet_verification.rs`:
   - `vp_response_rejects_garbage_jwe`
   - `vp_response_rejects_untrusted_issuer_chain`
   - `vp_response_unknown_transaction_id_returns_404`
   - (replay/second-submission case already exists — no new test needed, but consider
     renaming/cross-referencing it in a doc-comment as satisfying this bullet)
4. Run `cargo test --workspace` and report full pass/fail counts + test names, exactly
   as the brief requires. NOT YET RUN with new tests since none were written.
5. Commit with a conventional message, e.g.
   `test(integration): add HTTP-level negative-path tests for issuance and verification flows`.
6. Before committing, check `git status` for the pre-existing uncommitted formatting-only
   diffs in `credential.rs`/`proof.rs`/`transaction.rs` (from an unrelated concurrent
   process) and exclude them from the test commit (`git add` only the two test files,
   or explicitly `git stash` those three files first) unless the controller has since
   reconciled them.

## Self-assessment

No code was written or committed. This is purely a scoping/discovery report to save the
follow-up agent the ~28 tool calls of exploration already spent here. All interface
contracts needed (error types, status-code mappings, helper functions, config shapes)
have been traced and are documented above with enough precision to write the tests
directly without further exploration, except for item #6 (untrusted-root chain
validation error path), which needs one more file read.