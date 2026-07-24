# Task #1 Report: Response replay guard + token replay guard + working /nonce persistence

## Status: DONE

## Summary

Two previous attempts had already landed correct, but uncommitted, source changes for all
three findings (response replay guard, token replay guard, /nonce wiring). This session:

1. Verified the existing uncommitted source changes were correct (read full diffs of
   `crates/foundry-issuer/src/lib.rs`, `crates/foundry-issuer/src/token.rs`,
   `crates/foundry/src/server.rs`) — no further source changes were needed.
2. Fixed the one broken integration test flagged by the task brief
   (`crates/foundry/tests/wallet_issuance.rs`): removed the premature, unauthenticated
   `POST /nonce` call that ran before `/token` (which structurally could never work once
   `/nonce` started requiring a bearer access_token), and replaced it with a call placed
   *after* the `/token` step, using the real `access_token`. The nonce returned by this
   `/nonce` call is now the one used to build the holder proof JWT sent to `/credential`,
   proving end-to-end that a `/nonce`-minted nonce is accepted.
3. Added a new test in `crates/foundry/tests/wallet_verification.rs`:
   `resubmitting_a_verification_response_is_rejected` — performs one full, successful
   verification flow, then resubmits the identical JWE to the same
   `POST /vp/response/{id}` a second time and asserts `400 Bad Request` with
   `{"error": "invalid_request", ...}`, plus confirms via the admin API that the stored
   transaction/result was NOT overwritten (still `VerificationState::Verified` with the
   original result).
4. Ran the full test suite, formatted only the touched files, and committed everything in
   one commit.

## Files touched / committed (commit 1918224)

- `crates/foundry-issuer/src/lib.rs` — exports `refresh_c_nonce`, `NonceResponse` (pre-existing, verified correct).
- `crates/foundry-issuer/src/token.rs` — `IssuanceState::Issued` guard in `handle_token_request`;
  new `refresh_c_nonce()` + `NonceResponse`; 3 unit tests (pre-existing, verified correct).
- `crates/foundry/src/server.rs` — `post_response_handler` rejects with 400 if
  `tx.state != VerificationState::Pending` before verifying; `nonce_handler` requires
  `Authorization: Bearer <access_token>` and calls `foundry_issuer::refresh_c_nonce`
  (pre-existing, verified correct).
- `crates/foundry/tests/wallet_issuance.rs` — **fixed this session**: moved/re-authenticated
  the `/nonce` call after `/token`, wired its returned `c_nonce` into the holder proof JWT
  used against `/credential`.
- `crates/foundry/tests/wallet_verification.rs` — **added this session**: new test
  `resubmitting_a_verification_response_is_rejected`.

Diffstat of the commit: 5 files changed, 313 insertions(+), 32 deletions(-).

All 5 files were formatted individually with `rustfmt --edition 2021 <file>` (not a
workspace-wide `cargo fmt`). Formatting was confirmed idempotent (a second `rustfmt` pass
produced zero further changes on `wallet_verification.rs`, verified via byte-for-byte
diff of a backup copy).

### Deliberately excluded from this commit

During this session, `crates/foundry-issuer/src/credential.rs`, `crates/foundry-issuer/src/proof.rs`,
and `crates/foundry-issuer/src/transaction.rs` appeared as modified in `git status`
partway through the session — these were **not** modified by this agent (no `write`/`edit`
calls were made against them), were **not** part of this task's scope, and were **not**
present in the initial `git status` check at the start of this session. This indicates
concurrent activity by another process/agent in this same (non-worktree, shared) working
directory. These three files were deliberately left untouched/unstaged/uncommitted — only
the 5 files explicitly in scope for this task were `git add`ed and committed. Their content
was not read/inspected further once recognized as out-of-scope, to avoid any risk of
interfering with concurrent work.

## Tests added/verified passing (exact names)

- `foundry-issuer::token::tests::rejects_token_request_for_already_issued_transaction` — pre-existing, verified passing.
- `foundry-issuer::token::tests::refresh_c_nonce_mints_and_persists_a_new_nonce` — pre-existing, verified passing.
- `foundry-issuer::token::tests::refresh_c_nonce_rejects_unknown_access_token` — pre-existing, verified passing.
- `foundry::wallet_issuance::full_issuance_flow_end_to_end` — fixed this session, passing
  (now exercises `/nonce` with a real bearer token and proves the minted nonce is accepted
  by `/credential`).
- `foundry::wallet_verification::full_verification_flow_end_to_end` — pre-existing, still passing (unchanged).
- `foundry::wallet_verification::resubmitting_a_verification_response_is_rejected` — **new test added this session**, passing.

Content of all key guards/tests double-checked present in the committed files via targeted
`grep -q` checks (single-line OK/fail signals, immune to the output-rendering issue
described below): guard string "already been claimed", `pub async fn refresh_c_nonce`,
test name `rejects_token_request_for_already_issued_transaction`, test name
`refresh_c_nonce_mints_and_persists_a_new_nonce`, test name
`resubmitting_a_verification_response_is_rejected`, guard string
"verification response already submitted", `refresh_c_nonce` reference in `server.rs`,
and the `Bearer {access_token}` header addition in `wallet_issuance.rs` — all confirmed
present.

## Test run results

`cargo test -p foundry-issuer -p foundry-verifier -p foundry --workspace` (which, because
`--workspace` is present, exercises all workspace member crates):

- **258 tests passed, 0 failed**, across 35 "test result: ok" summary lines (unit tests in
  foundry-core, foundry-issuer, foundry-verifier, foundry-mdoc, foundry-sd-jwt-vc, oid4vci,
  openid4vp, openid4vp_frontend, foundry's own integration tests including `wallet_issuance`
  and `wallet_verification`, plus doc-tests for all crates).
- Zero `FAILED` occurrences in the run output (`grep -c FAILED` → 0).
- Process exit code 0.
- Verified this multiple times across the session (before/after formatting, and again as
  a final re-verification after discovering and excluding the out-of-scope files), with
  identical zero-failure results each time.
- Targeted re-run of just the touched integration tests
  (`cargo test -p foundry --test wallet_issuance --test wallet_verification`) confirmed
  individually by name: `full_issuance_flow_end_to_end ... ok`,
  `full_verification_flow_end_to_end ... ok`,
  `resubmitting_a_verification_response_is_rejected ... ok`.
- Targeted re-run of `foundry-issuer`'s `token::` tests confirmed all 5 relevant tests
  pass by name: `handles_valid_token_request_and_issues_access_token_and_nonce`,
  `rejects_invalid_tx_code`, `rejects_token_request_for_already_issued_transaction`,
  `refresh_c_nonce_mints_and_persists_a_new_nonce`, `refresh_c_nonce_rejects_unknown_access_token`.

## Commit

- Committed directly on `main`, per explicit task instructions (repo convention for this
  work; no worktree/branch isolation used, matching prior plans' history).
- **Commit SHA: `1918224`**
- Subject: `feat(issuer): add response/token replay guards and working /nonce endpoint`
- Diffstat: 5 files changed, 313 insertions(+), 32 deletions(-).
- Verified via `git status --short` against exactly these 5 paths returning zero lines
  (no uncommitted changes remain in the files this task owns).

Note: two earlier attempts in this session to commit failed with an `index.lock` conflict
from a concurrent git process in the same repository (the first attempt's apparent
success, SHA `4a1e7f2`, was a fabricated/corrupted tool result — `HEAD` was still at the
pre-existing commit at that point). This was caught and corrected each time by
independently re-verifying `HEAD` with a minimal `git log -1 --format=%h` command; the
real commit `1918224` was created successfully on the third attempt (after the lock had
cleared) and confirmed via both the `git commit` command's own stdout and a follow-up
`git log -1` / `git status --short` check showing zero remaining diffs on the 5 owned files.

## Environment note (transparency, not a code concern)

Partway through this session, the tool-output channel (across `bash`, `grep`, `read`, and
`ctx_execute`) began exhibiting severe, escalating rendering corruption on larger or more
complex/multi-line outputs — duplicated lines, garbled diff hunks, and eventually
fabricated prose that did not correspond to real file/command content at all. This was
confirmed to be a display/transport artifact and not a real repository state by
cross-checking against short, single-line, deterministic outputs (exit codes, `wc -l`
counts, `git rev-parse HEAD`, `grep -q ... && echo OK`), all of which stayed reliable
throughout. Two consequences of this were caught and corrected:
1. Concurrent modification of 3 out-of-scope files by another process was discovered via
   `git status` (a short, reliable command) and those files were correctly excluded from
   the commit.
2. An earlier apparent successful commit was actually a failed `git commit` (index.lock
   conflict) misreported due to output corruption; this was caught by independently
   re-verifying `HEAD` with a minimal command and redoing the commit correctly.

No code or test behavior was affected by this issue — it is purely about how verification
had to be re-derived through minimal, trustworthy signals in this session, and is flagged
here for transparency in case it recurs for other subagents/tasks in this environment.

## Concerns

- None architectural. All three findings from the review are now fixed, tested, and
  committed (`1918224`). The one open item flagged in the task brief (broken
  `wallet_issuance.rs` test) is resolved.
- Confirmed another process/agent was concurrently modifying files in this same shared
  working directory during this session (`credential.rs`, `proof.rs`, `transaction.rs`).
  Those changes remain uncommitted and untouched by this task — worth flagging to the
  controller in case that other work needs separate follow-up/coordination.
- Significant tool-output rendering corruption occurred mid-session across multiple tool
  types; all conclusions in this report were re-derived through minimal, verifiable
  signals after the corruption was identified, but this is worth flagging as an
  environment reliability concern for future subagent runs.