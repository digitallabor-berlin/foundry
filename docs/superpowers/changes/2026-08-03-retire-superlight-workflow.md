# Retire the `superlight` Workflow — Change Record

**Spec:** [`docs/superpowers/specs/2026-08-03-superlight-workflow-retirement-design.md`](../specs/2026-08-03-superlight-workflow-retirement-design.md)
**Plan:** [`docs/superpowers/plans/2026-08-03-retire-superlight-workflow-plan.md`](../plans/2026-08-03-retire-superlight-workflow-plan.md)

## What changed

- Migrated all 35 files under `docs/superlight/{specs,plans,changes}/` into
  the matching `docs/superpowers/{specs,plans,changes}/` directories via
  `git mv`, so `git log --follow` lineage is preserved. `docs/superlight/` no
  longer exists.
- Added a one-line provenance blockquote to each migrated file, naming its
  original path and this change record.
- Rewrote every internal cross-reference from `docs/superlight/` to
  `docs/superpowers/` across the migrated files, and fixed the 3 external
  references in `crates/foundry/tests/authorization_code_flow.rs`,
  `crates/foundry-issuer/src/attestation.rs`, and
  `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md`.
- Deleted the three stale, fully-merged branches
  `superlight/2026-07-31-observability-logging`,
  `superlight/2026-08-02-conformance-tier4-gaps`, and
  `superlight/2026-08-02-tracing-callsite-interest-flake` (each verified 0
  commits ahead of `main` before deletion).
- Removed the global pi skill `~/.pi/agent/skills/superlight/SKILL.md`, which
  is what actually made `/skill:superlight` reachable. The skill's own
  design paper trail
  (`~/.pi/agent/docs/superpowers/{plans,specs}/2026-07-23-superlight-skill*.md`)
  was deliberately left in place.
- Added a "Workflow Artifacts" guardrail to `AGENTS.md` §7 stating that
  `superpowers` is the only workflow in use and naming the canonical
  `docs/superpowers/{specs,plans,changes}/` paths.

## What was deliberately preserved, not rewritten

- **Git branch names** of the form `superlight/YYYY-MM-DD-<slug>` appearing
  in prose (e.g. inside change records describing which branch a piece of
  work landed on) were left untouched. Rewriting them to `superpowers/...`
  would assert a branch existed that never did.
- **Historical prose** describing the state of the repo at a point in time —
  most notably the "Rejected alternatives" note in
  `docs/superpowers/changes/2026-08-03-remove-foundry-wallet.md`, which
  explicitly argues against rewriting historical docs to "tidy a grep" — was
  left as-is for the same reason.
- **Git commit history** containing `Merge branch 'superlight/…'` messages is
  untouched; it is immutable and is itself part of the track record this
  migration is designed to preserve, not erase.
- `~/.pi/agent/docs/superpowers/{plans,specs}/2026-07-23-superlight-skill*.md`
  — the paper trail of *building* the superlight skill — is out of scope and
  was not touched.
- The plan and design-spec documents for *this* migration
  (`docs/superpowers/plans/2026-08-03-retire-superlight-workflow-plan.md` and
  `docs/superpowers/specs/2026-08-03-superlight-workflow-retirement-design.md`)
  themselves describe `docs/superlight/` as the historical source path in
  their own illustrative text and commands. A first pass of the mechanical
  rewrite over-matched and briefly corrupted these two files into
  self-contradictory text (e.g. a `git mv` command whose source and
  destination were identical); this was caught during execution and both
  files were restored to their original wording before the migrating commit
  was finalized.

## Known pre-existing gap (not introduced or fixed by this migration)

`docs/superpowers/changes/2026-08-01-conformance-tier1-fixes.md` references
a `2026-07-31-openid4vc-conformance-audit.md` change record that has never
existed (the 2026-07-31 audit produced only a spec and a plan, no change
record). The path prefix was rewritten for consistency with every other
reference, but the target still does not resolve. This dangling link
predates this migration and remains open; it is not addressed here.

## Verification

- `grep -rn 'docs/superlight' . --exclude-dir=.git --exclude-dir=target`
  returns hits only in this migration's own meta-documents (the plan and
  design spec listed above, which legitimately discuss the retired path by
  name) and the one deliberately preserved historical line in
  `docs/superpowers/changes/2026-08-03-remove-foundry-wallet.md`.
- `ls docs/superlight` fails (directory does not exist).
- `git branch -a | grep -i superlight` returns no output.
- `cargo fmt --check` and
  `cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings`
  both pass (the only production-adjacent files touched were two Rust doc
  comments).