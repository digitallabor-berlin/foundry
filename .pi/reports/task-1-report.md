# Task #1 Report: Add replay/state guards + working /nonce persistence

## Status: BLOCKED

## Reason
Branch safety check failed. The repository is currently on `main` (confirmed via `git rev-parse --abbrev-ref HEAD` → `main`), with no dedicated feature branch or git worktree set up for this task. There is also only one worktree registered (`git worktree list` shows only the main worktree at `/Users/senexi/dev/eudiw/foundry` on `[main]`).

Per the Integration Implementer workflow's mandatory first step ("Verify Branch Safety"), I must NOT make any changes while on `main`/`master`. The controller must set up an isolated worktree or feature branch before implementation work can proceed safely.

## What I verified before stopping
- `git rev-parse --abbrev-ref HEAD` → `main`
- `git status --short` → clean aside from untracked `.pi/tasks/*.json` task-queue metadata files (not related to this task)
- `git worktree list` → only one worktree, on `main`
- `git log --oneline -5` → most recent commits are unrelated feature work (status-list CLI, openapi docs, verification flow plan), confirming no in-progress branch for this task exists yet

## No code changes were made.

## Next steps for controller
1. Create a dedicated git worktree/branch (e.g. `git worktree add ../foundry-task1 -b task1/replay-guards-nonce-persistence` or equivalent) per the `using-git-worktrees` skill.
2. Re-dispatch this task with the working directory pointed at the new worktree/branch.

## Scope recap (for whoever resumes this task)
Three fixes needed in `crates/foundry/src/server.rs` (+ `foundry-issuer`/`foundry-verifier` as needed):
1. **Response replay guard** in `post_response_handler` (~line 359): guard on `tx.state != VerificationState::Pending` before calling `verify_vp_response`; return 400 `invalid_request` if already processed. Add resubmission test.
2. **Already-issued token replay guard** in `token_handler` / `foundry_issuer::handle_token_request` (crates/foundry-issuer/src/token.rs): guard on `tx.state == IssuanceState::Issued`, return `IssuanceError::InvalidGrant(...)`. Add unit test.
3. **/nonce persistence** in `nonce_handler` (~line 217): require Bearer auth like `/credential`, look up tx via `load_transaction_by_access_token`, mint c_nonce + expiry, persist via `save_transaction_with_indices` (consider adding `foundry_issuer::token::refresh_c_nonce(...)`), return same OAuth2-shaped errors on missing/invalid token. Add end-to-end test proving nonce round-trip works with `/credential`.

Must run `cargo test -p foundry-issuer -p foundry-verifier -p foundry --workspace` and report pass/fail counts. Do not run workspace-wide `cargo fmt`; only format touched files.