# Retire the `superlight` Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retire the `superlight` development workflow from this project — consolidating its 35-file `docs/superlight/` paper trail into `docs/superpowers/`, fixing every path reference that would otherwise 404, deleting the 3 stale merged branches, removing the global pi skill so `/skill:superlight` is no longer reachable, and documenting the retirement itself.

**Architecture:** Pure documentation/git-hygiene chore, no production logic touched beyond two Rust doc comments. Executed as a strict sequence of six tasks: migrate paper trail → fix external references → remove branches/global skill → add an AGENTS.md guardrail → write the change record → final verification.

**Tech Stack:** bash, git, awk/sed, cargo fmt/clippy (verification only).

**Spec:** [`docs/superpowers/specs/2026-08-03-superlight-workflow-retirement-design.md`](../specs/2026-08-03-superlight-workflow-retirement-design.md)

## Global Constraints

- Use `git mv`, never delete+recreate, so `git log --follow` lineage survives the move.
- Doc **paths** that would 404 after the move get rewritten `docs/superlight/` → `docs/superpowers/`. Git **branch names** and **historical prose** describing what workflow was used at the time never get rewritten — see Task 1, Step 4 for the one explicit exception file.
- Branch deletion uses `git branch -d` (safe delete), not `-D` — all three target branches were verified to have 0 commits not on `main`.
- The global skill removal (`~/.pi/agent/skills/superlight/`) is in scope and machine-wide, per user confirmation; `~/.pi/agent/docs/superpowers/{plans,specs}/2026-07-23-superlight-skill*.md` (the paper trail of *building* superlight) is explicitly preserved and must not be touched.
- This is a docs-and-comments-only change: the scoped verification gate (AGENTS.md §5.1/§5.2) is `cargo fmt --check` plus `cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings` (the two crates whose files gain a one-line doc-comment edit). No `cargo test --workspace` run is warranted.

---

### Task 1: Migrate the 35-file paper trail into `docs/superpowers/`

**Files:**
- Move (git mv): all 35 files under `docs/superlight/{specs,plans,changes}/` → the matching `docs/superpowers/{specs,plans,changes}/` path (same basename, zero collisions with the 24 files already there).
- Modify: each of the 35 moved files (provenance header insertion + internal cross-reference path rewrite).
- Delete: the now-empty `docs/superlight/` directory tree.

**Interfaces:**
- Consumes: nothing from earlier tasks (this is the first task).
- Produces: the final resting paths of all 35 docs, which Task 5's change record and Task 6's verification both depend on being correct and non-empty.

- [ ] **Step 1: Move all 35 files with `git mv`**

Run from the repo root (`cd /Users/senexi/dev/eudiw/foundry`):

```bash
SPECS=(
  2026-07-28-authz-code-flow-spec.md
  2026-07-30-remove-vendored-crates-spec.md
  2026-07-30-vp-response-form-parsing-spec.md
  2026-07-30-vp-token-envelope-parsing-spec.md
  2026-07-31-observability-logging-spec.md
  2026-07-31-openid4vc-conformance-audit-spec.md
  2026-08-01-conformance-tier1-fixes-spec.md
  2026-08-01-gap-vci-14-client-attestation-pop-spec.md
  2026-08-02-conformance-tier3-fixes-spec.md
  2026-08-02-gap-vp-06-session-transcript-spec.md
)
PLANS=(
  2026-07-28-authz-code-flow-plan.md
  2026-07-30-remove-vendored-crates-plan.md
  2026-07-30-vp-response-form-parsing-plan.md
  2026-07-30-vp-token-envelope-parsing-plan.md
  2026-07-31-observability-logging-plan.md
  2026-07-31-openid4vc-conformance-audit-plan.md
  2026-08-01-conformance-tier1-fixes-plan.md
  2026-08-01-gap-vci-14-client-attestation-pop-plan.md
  2026-08-02-conformance-tier3-fixes-plan.md
  2026-08-02-gap-vp-06-session-transcript-plan.md
)
CHANGES=(
  2026-07-28-authz-code-flow.md
  2026-07-30-plural-proofs-credential-issuance.md
  2026-07-30-remove-vendored-crates.md
  2026-07-30-verifier-encryption-jwk-metadata.md
  2026-07-30-verifier-response-type.md
  2026-07-30-verifier-transaction-data-encoding.md
  2026-07-30-vp-response-form-parsing.md
  2026-07-30-vp-token-envelope-parsing.md
  2026-07-31-observability-logging.md
  2026-08-01-conformance-tier1-fixes.md
  2026-08-01-gap-vci-14-client-attestation-pop.md
  2026-08-02-conformance-tier3-fixes.md
  2026-08-02-gap-vp-06-session-transcript.md
  2026-08-02-tracing-callsite-interest-flake.md
  2026-08-03-remove-foundry-wallet.md
)

for f in "${SPECS[@]}";   do git mv "docs/superlight/specs/$f"   "docs/superpowers/specs/$f";   done
for f in "${PLANS[@]}";   do git mv "docs/superlight/plans/$f"   "docs/superpowers/plans/$f";   done
for f in "${CHANGES[@]}"; do git mv "docs/superlight/changes/$f" "docs/superpowers/changes/$f"; done
```

Expected: no errors; `git status --short` shows 35 `R` (renamed) entries.

- [ ] **Step 2: Verify every moved file starts with an H1, then insert the provenance note**

All 35 files were confirmed (during planning) to start with a `# ` heading on line 1 — this step re-verifies that before mutating, and aborts on any mismatch rather than silently inserting in the wrong place:

```bash
for f in "${SPECS[@]}";   do head -1 "docs/superpowers/specs/$f"   | grep -q '^# ' || echo "NOT H1: specs/$f"; done
for f in "${PLANS[@]}";   do head -1 "docs/superpowers/plans/$f"   | grep -q '^# ' || echo "NOT H1: plans/$f"; done
for f in "${CHANGES[@]}"; do head -1 "docs/superpowers/changes/$f" | grep -q '^# ' || echo "NOT H1: changes/$f"; done
echo "H1 check done"
```

Expected: only the line `H1 check done` prints — no `NOT H1:` lines. If any file fails this check, stop and re-read that file before proceeding (do not force the insertion).

Then insert the provenance blockquote immediately after line 1 in each file:

```bash
insert_provenance() {
  local file="$1" orig="$2"
  awk -v orig="$orig" '
    NR==1 && /^# / {
      print
      print ""
      print "> Migrated from `" orig "` — produced by the retired"
      print "> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`)."
      next
    }
    { print }
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

for f in "${SPECS[@]}";   do insert_provenance "docs/superpowers/specs/$f"   "docs/superlight/specs/$f";   done
for f in "${PLANS[@]}";   do insert_provenance "docs/superpowers/plans/$f"   "docs/superlight/plans/$f";   done
for f in "${CHANGES[@]}"; do insert_provenance "docs/superpowers/changes/$f" "docs/superlight/changes/$f"; done
```

Expected: no errors. Spot-check one file, e.g. `head -5 docs/superpowers/specs/2026-07-28-authz-code-flow-spec.md` — line 1 is the original H1, lines 2-4 are the blank line + two blockquote lines, line 5 resumes the original line 2's content.

- [ ] **Step 3: Rewrite internal `docs/superlight/` cross-references — except one deliberate exception**

12 of the 35 files contain internal cross-references of the form
`docs/superlight/<dir>/<file>.md` pointing at sibling files (Spec/Plan
backlinks, predecessor links, and one self-referential grep instruction in
`2026-07-30-remove-vendored-crates-plan.md`). All of these become stale paths
after the move and must be rewritten.

**Exception:** `docs/superpowers/changes/2026-08-03-remove-foundry-wallet.md`
line "the ~25 files under `docs/superlight/**` and `docs/superpowers/**` that
mention `foundry-wallet` are dated records of what was true when written.
Rewriting them would falsify history" is describing, in the past tense, the
state of the repo *when that change was written* (both directories existed
then). Rewriting it would make it inaccurate. Do not touch this file.

```bash
grep -rl 'docs/superlight/' docs/superpowers | grep -v '2026-08-03-remove-foundry-wallet.md' | xargs sed -i '' 's#docs/superlight/#docs/superpowers/#g'
```

(If running on GNU sed instead of BSD/macOS sed, use `sed -i` without the
trailing `''` argument.)

Expected: the command touches exactly these files (verify with
`grep -rl 'docs/superlight/' docs/superpowers | grep -v remove-foundry-wallet`
returning nothing after the run):
`plans/2026-08-02-conformance-tier3-fixes-plan.md`,
`plans/2026-07-30-vp-token-envelope-parsing-plan.md`,
`plans/2026-07-30-vp-response-form-parsing-plan.md`,
`plans/2026-07-31-openid4vc-conformance-audit-plan.md`,
`plans/2026-07-30-remove-vendored-crates-plan.md` (2 occurrences),
`plans/2026-07-31-observability-logging-plan.md`,
`plans/2026-08-01-gap-vci-14-client-attestation-pop-plan.md`,
`plans/2026-07-28-authz-code-flow-plan.md`,
`plans/2026-08-01-conformance-tier1-fixes-plan.md`,
`specs/2026-07-30-vp-token-envelope-parsing-spec.md`,
`specs/2026-07-31-observability-logging-spec.md`,
`changes/2026-07-30-remove-vendored-crates.md` (2 occurrences),
`changes/2026-08-02-conformance-tier3-fixes.md` (2 occurrences),
`changes/2026-08-01-conformance-tier1-fixes.md`,
`changes/2026-07-30-verifier-response-type.md`,
`changes/2026-07-28-authz-code-flow.md` (2 occurrences),
`changes/2026-07-30-vp-token-envelope-parsing.md` (3 occurrences),
`changes/2026-07-30-vp-response-form-parsing.md` (2 occurrences).

Note: `changes/2026-08-01-conformance-tier1-fixes.md` references
`docs/superpowers/changes/2026-07-31-openid4vc-conformance-audit.md` after
this rewrite — that target **does not exist** (the 2026-07-31 audit produced
only a spec+plan, never a change record). This is a pre-existing dangling
reference that predates this migration; rewriting the prefix keeps it
consistent with everything else, but do not attempt to fix the dangling
target as part of this task — it is out of scope here.

- [ ] **Step 4: Remove the now-empty `docs/superlight/` tree**

```bash
find docs/superlight -type f
```

Expected: no output (all files were moved). Then:

```bash
rmdir docs/superlight/specs docs/superlight/plans docs/superlight/changes docs/superlight
test -d docs/superlight && echo "STILL EXISTS" || echo "gone"
```

Expected: `gone`. (`rmdir` fails loudly if any of the four directories still
contains a file, which is the safety property we want here.)

- [ ] **Step 5: Commit**

```bash
git add -A docs/superlight docs/superpowers
git commit -m "docs: migrate the superlight paper trail into docs/superpowers/

Moves all 35 files under docs/superlight/{specs,plans,changes}/ via git mv,
adds a one-line provenance note to each, and rewrites internal cross-
references from docs/superlight/ to docs/superpowers/ (one line in
2026-08-03-remove-foundry-wallet.md is deliberately left untouched — it is
historical prose about a point in time when both directories existed)."
```

---

### Task 2: Fix the 3 external references to the old `docs/superlight/` paths

**Files:**
- Modify: `crates/foundry/tests/authorization_code_flow.rs:3`
- Modify: `crates/foundry-issuer/src/attestation.rs:266`
- Modify: `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md:9`

**Interfaces:**
- Consumes: the final paths produced by Task 1 (files already live under `docs/superpowers/`).
- Produces: nothing consumed by later tasks — this closes out all remaining `docs/superlight/` path references outside the migrated tree itself.

- [ ] **Step 1: Rewrite the two Rust doc comments**

`crates/foundry/tests/authorization_code_flow.rs`, change:

```rust
//! grant bound to admin-precreated offers (Task 6 of
//! docs/superlight/plans/2026-07-28-authz-code-flow-plan.md).
```

to:

```rust
//! grant bound to admin-precreated offers (Task 6 of
//! docs/superpowers/plans/2026-07-28-authz-code-flow-plan.md).
```

`crates/foundry-issuer/src/attestation.rs`, change:

```rust
/// Every check below cites its ABCA clause; see
/// docs/superlight/specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md
/// for the full table this mirrors. `skip_all` is mandatory: the argument is
```

to:

```rust
/// Every check below cites its ABCA clause; see
/// docs/superpowers/specs/2026-08-01-gap-vci-14-client-attestation-pop-spec.md
/// for the full table this mirrors. `skip_all` is mandatory: the argument is
```

- [ ] **Step 2: Rewrite the markdown cross-reference**

`docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md`, change:

```markdown
> **Superseding note (2026-07-30).** The vendored `oid4vci`, `openid4vp` and
> `openid4vp-frontend` crates were removed from the workspace (see
> `docs/superlight/changes/2026-07-30-remove-vendored-crates.md`). Consequently
```

to:

```markdown
> **Superseding note (2026-07-30).** The vendored `oid4vci`, `openid4vp` and
> `openid4vp-frontend` crates were removed from the workspace (see
> `docs/superpowers/changes/2026-07-30-remove-vendored-crates.md`). Consequently
```

- [ ] **Step 3: Confirm no `docs/superlight` string remains anywhere except deliberately-preserved prose/branch names**

```bash
cd /Users/senexi/dev/eudiw/foundry
grep -rn 'docs/superlight' . --exclude-dir=.git --exclude-dir=target
```

Expected: zero output.

- [ ] **Step 4: Run the scoped verification gate for the two touched crates**

Per AGENTS.md §5.1/§5.2 (doc-comment-only change in `foundry-issuer` and
`foundry`):

```bash
cargo fmt --check
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
```

Expected: both commands exit 0 with no diagnostics.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/tests/authorization_code_flow.rs crates/foundry-issuer/src/attestation.rs docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md
git commit -m "docs: fix the 3 external references to migrated superlight docs"
```

---

### Task 3: Delete stale branches and remove the global `superlight` skill

**Files:**
- None in the `foundry` repo tree (git branch metadata + a file outside the repo).
- Delete: `~/.pi/agent/skills/superlight/SKILL.md` (and its now-empty parent directory).

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Verify the three branches are still fully merged, then delete them**

```bash
cd /Users/senexi/dev/eudiw/foundry
for b in superlight/2026-07-31-observability-logging superlight/2026-08-02-conformance-tier4-gaps superlight/2026-08-02-tracing-callsite-interest-flake; do
  n=$(git rev-list --count main.."$b")
  echo "$b : $n commit(s) not on main"
done
```

Expected: `0 commit(s) not on main` for all three. If any shows a non-zero
count, stop — that branch has unmerged work and must not be deleted with
`-d`.

```bash
git branch -d superlight/2026-07-31-observability-logging
git branch -d superlight/2026-08-02-conformance-tier4-gaps
git branch -d superlight/2026-08-02-tracing-callsite-interest-flake
git branch -a | grep -i superlight
```

Expected: the three `git branch -d` calls each print `Deleted branch
superlight/... (was <sha>)`; the final `grep` returns no output.

- [ ] **Step 2: Remove the global skill**

```bash
ls /Users/senexi/.pi/agent/skills/superlight
rm -rf /Users/senexi/.pi/agent/skills/superlight
ls /Users/senexi/.pi/agent/skills
```

Expected: the final listing shows the skills directory without a
`superlight` entry (e.g. `writing-tech-specs` and any others remain).

- [ ] **Step 3: Confirm the superlight design trail was NOT touched**

```bash
ls /Users/senexi/.pi/agent/docs/superpowers/plans/2026-07-23-superlight-skill.md
ls /Users/senexi/.pi/agent/docs/superpowers/specs/2026-07-23-superlight-skill-design.md
```

Expected: both files still exist (exit 0, path printed). These are
deliberately out of scope and must remain.

No commit — this task changes only git branch refs (not tracked content) and
a file tree outside the `foundry` repository.

---

### Task 4: Add the "Workflow Artifacts" guardrail to `AGENTS.md`

**Files:**
- Modify: `AGENTS.md` (insert a new subsection at the end of §7, before the `---` that precedes §8).

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks (informational guardrail only).

- [ ] **Step 1: Insert the new subsection**

In `AGENTS.md`, find this exact text (end of §7's "Task Tracking (`pi-tasks`)"
subsection, immediately before §8):

```markdown
- Maintain `.superpowers/sdd/progress.md` as the durable, compaction-proof
  source of truth for execution history.

---

## 8. Maintaining These Files
```

Replace it with:

```markdown
- Maintain `.superpowers/sdd/progress.md` as the durable, compaction-proof
  source of truth for execution history.

### Workflow Artifacts

This project used to run a second, lighter-weight workflow called
`superlight` alongside `superpowers`. **As of 2026-08-03, `superpowers` is the
only development workflow in use in this repository.** Specs, plans, and
change records — regardless of which skill or subagent produces them — live
under:

- `docs/superpowers/specs/YYYY-MM-DD-<slug>-spec.md` (or `-design.md`)
- `docs/superpowers/plans/YYYY-MM-DD-<slug>-plan.md`
- `docs/superpowers/changes/YYYY-MM-DD-<slug>.md`

`docs/superlight/` is retired and its historical contents were migrated into
the paths above (see
`docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`). Do not
recreate a `docs/superlight/` directory.

---

## 8. Maintaining These Files
```

- [ ] **Step 2: Verify the edit**

```bash
cd /Users/senexi/dev/eudiw/foundry
grep -n 'Workflow Artifacts' AGENTS.md
grep -c '^## 8\. Maintaining These Files' AGENTS.md
```

Expected: the first `grep` finds the new heading once; the second prints `1`
(the section 8 heading still appears exactly once — the insertion didn't
duplicate or corrupt it).

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md
git commit -m "docs(AGENTS): add Workflow Artifacts guardrail — superpowers is the only workflow"
```

---

### Task 5: Write the change record for this migration

**Files:**
- Create: `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`

**Interfaces:**
- Consumes: the final state produced by Tasks 1-4 (paths, branch list, AGENTS.md section) — this change record describes them, so it must be written last among the content-producing tasks.
- Produces: the target that Task 1's provenance notes and the AGENTS.md guardrail (Task 4) both link to. Its filename must exactly match
  `2026-08-03-retire-superlight-workflow.md` — those links are already written and are not revisited.

- [ ] **Step 1: Write the file**

```markdown
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

## Known pre-existing gap (not introduced or fixed by this migration)

`docs/superpowers/changes/2026-08-01-conformance-tier1-fixes.md` references
a `2026-07-31-openid4vc-conformance-audit.md` change record that has never
existed (the 2026-07-31 audit produced only a spec and a plan, no change
record). The path prefix was rewritten for consistency with every other
reference, but the target still does not resolve. This dangling link
predates this migration and remains open; it is not addressed here.

## Verification

- `grep -rn 'docs/superlight' . --exclude-dir=.git --exclude-dir=target`
  returns no output.
- `ls docs/superlight` fails (directory does not exist).
- `git branch -a | grep -i superlight` returns no output.
- `cargo fmt --check` and
  `cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings`
  both pass (the only production-adjacent files touched were two Rust doc
  comments).
```

- [ ] **Step 2: Commit**

```bash
cd /Users/senexi/dev/eudiw/foundry
git add docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md
git commit -m "docs: change record for retiring the superlight workflow"
```

---

### Task 6: Final verification pass

**Files:** none (verification only — no changes expected).

**Interfaces:**
- Consumes: the final state of the entire tree after Tasks 1-5.
- Produces: nothing — this is the completion gate for the whole plan.

- [ ] **Step 1: Confirm no stray `docs/superlight` references remain**

```bash
cd /Users/senexi/dev/eudiw/foundry
grep -rn 'docs/superlight' . --exclude-dir=.git --exclude-dir=target
test -d docs/superlight && echo "STILL EXISTS" || echo "gone"
```

Expected: the `grep` returns no output; the second line prints `gone`.

- [ ] **Step 2: Confirm branches and global skill are gone, design trail intact**

```bash
git branch -a | grep -i superlight
ls /Users/senexi/.pi/agent/skills/superlight 2>&1
ls /Users/senexi/.pi/agent/docs/superpowers/plans/2026-07-23-superlight-skill.md
ls /Users/senexi/.pi/agent/docs/superpowers/specs/2026-07-23-superlight-skill-design.md
```

Expected: the branch `grep` returns no output; the skills-dir `ls` reports
"No such file or directory"; both design-trail files are found.

- [ ] **Step 3: Confirm the one deliberate exception survived untouched**

```bash
grep -n 'docs/superlight' docs/superpowers/changes/2026-08-03-remove-foundry-wallet.md
```

Expected: exactly one hit — the historical "Rejected alternatives" sentence
— unchanged from its original wording.

- [ ] **Step 4: Run the scoped verification gate one more time**

```bash
cargo fmt --check
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
```

Expected: both exit 0. Per AGENTS.md §5.5, report this as "scoped:
`cargo fmt --check` + `cargo clippy -p foundry-issuer -p foundry` green" — do
not run `cargo test --workspace` for this doc/comment-only change.

- [ ] **Step 5: Report completion**

Summarize: 35 files migrated, 3 external references fixed, 3 branches
deleted, global skill removed, AGENTS.md guardrail added, change record
written, scoped gate green. No further action needed — this is the terminal
task of the plan.