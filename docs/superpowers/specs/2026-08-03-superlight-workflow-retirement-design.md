# Retire the `superlight` Workflow, Consolidate into `superpowers`

## Context

This repository was, for a period, worked on under two parallel development
workflows: the full `superpowers` skillset and a lighter-weight `superlight`
skill (brainstorm → spec → plan → TDD → review, with opt-in subagents and
leaner artifacts). `superlight` wrote its paper trail to `docs/superlight/`
(specs, plans, changes) and used `superlight/YYYY-MM-DD-<slug>` git branches.

Going forward, this project uses **only** the `superpowers` workflow. This
document specifies how to retire `superlight` cleanly: remove it as a usable
workflow, while preserving the track record it produced, consistent with the
instruction that closing out an old workflow must not erase its history.

## Scope

**In scope:**
- 35 tracked files under `docs/superlight/{specs,plans,changes}/`
- 3 in-repo references to `docs/superlight/...` paths (2 Rust doc comments, 1
  markdown cross-reference)
- 3 merged, stale `superlight/*` git branches
- The global pi skill installed at `~/.pi/agent/skills/superlight/SKILL.md`
- `AGENTS.md` (add a guardrail so the convention doesn't silently drift back)

**Out of scope:**
- Git commit history containing `Merge branch 'superlight/…'` messages — these
  are immutable and are themselves part of the track record; they are not
  rewritten or squashed.
- The unrelated `delete` branch (already merged, not part of this migration).
- `~/.pi/agent/docs/superpowers/{plans,specs}/2026-07-23-superlight-skill*.md`
  — the design paper trail for *building* superlight itself. This predates
  and is independent of the foundry-specific artifacts being migrated here,
  and is explicitly preserved per the user's decision.

## Inventory (as verified during exploration)

| Path prefix | Count | Notes |
|---|---|---|
| `docs/superlight/specs/` | 10 | no filename collision with `docs/superpowers/specs/` |
| `docs/superlight/plans/` | 10 | no filename collision with `docs/superpowers/plans/` |
| `docs/superlight/changes/` | 15 | no filename collision with `docs/superpowers/changes/` |
| In-repo references to `docs/superlight/...` | 3 | `crates/foundry/tests/authorization_code_flow.rs:3`, `crates/foundry-issuer/src/attestation.rs:266`, `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md:9` |
| `superlight/*` git branches | 3 | all fully merged into `main` (0 unique commits each) |
| Global skill install | 1 file | `~/.pi/agent/skills/superlight/SKILL.md` |

## Design

### 1. Paper-trail migration (preserve, don't erase)

Each of the 35 files moves via `git mv` from `docs/superlight/<dir>/<name>.md`
to `docs/superpowers/<dir>/<name>.md`. Because there are zero filename
collisions between the two trees, this is a pure directory-prefix rename with
no naming conflicts to resolve.

Using `git mv` (rather than delete + recreate) preserves `git log --follow`
lineage for every file, so the object history survives the move independent
of anything written into the file content.

In addition, each migrated file gets one provenance line inserted directly
after its top-level (`#`) heading:

```
> Migrated from `docs/superlight/<dir>/<name>.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).
```

This makes the file's origin readable in-place, without depending on the
reader knowing to check `git log --follow` or on a directory-path convention
that will disappear.

After all 35 files are moved, the (now-empty) `docs/superlight/` directory is
removed.

### 2. Reference rewriting — path vs. prose vs. branch name

Three distinct kinds of the string `superlight` occur in the tree, and they
are handled differently:

| Kind | Example | Treatment | Rationale |
|---|---|---|---|
| Doc path | `docs/superlight/specs/2026-07-30-remove-vendored-crates-spec.md` | **Rewrite** to `docs/superpowers/...` | The old path will 404 after the move; a stale path is a defect, not history. |
| Git branch name | `superlight/2026-08-01-conformance-tier1-fixes` | **Preserve verbatim** | This names the actual branch that actual work happened on. Rewriting it to `superpowers/...` would assert a branch existed that never did — a fabricated record is worse than an accurate one naming a retired workflow. |
| Prose | "Using superlight", "the superlight workflow" | **Preserve verbatim** | Same reasoning: these sentences describe what happened, in the past tense, under the workflow that was actually used at the time. |

Concretely, this means:
- All ~13 intra-doc cross-references of the form `docs/superlight/<dir>/<file>.md`
  found across the 35 migrated files are rewritten to `docs/superpowers/<dir>/<file>.md`.
- The 3 external references (2 Rust doc comments + 1 markdown cross-reference)
  are rewritten the same way.
- Occurrences of `superlight/YYYY-MM-DD-<slug>` (branch names) and bare prose
  mentions of "superlight" as the name of a workflow are left untouched.

A post-hoc check (`grep -rn 'docs/superlight' . --exclude-dir=.git
--exclude-dir=target`) must return zero hits once the migration is complete —
that is the only completeness bar for rewriting; a residual bare word
"superlight" in prose or a branch name is expected and correct, not a leftover
to clean up.

### 3. Branch cleanup

The three branches — `superlight/2026-07-31-observability-logging`,
`superlight/2026-08-02-conformance-tier4-gaps`,
`superlight/2026-08-02-tracing-callsite-interest-flake` — are each verified
to have 0 commits not present on `main` (`git rev-list --count main..<branch>`
= 0 for all three). They are deleted with `git branch -d` (not `-D`, since a
clean fast-forward-safe delete is expected to succeed given the verified
state). The unrelated `delete` branch is left alone.

### 4. Global skill removal

`~/.pi/agent/skills/superlight/SKILL.md` is deleted (`rm -rf
~/.pi/agent/skills/superlight/`). This is the step that actually makes the
`superlight` workflow unreachable — everything else in this document is
cleanup of its historical output. The skill carries
`disable-model-invocation: true`, so removing it changes exposure from
"reachable only via explicit `/skill:superlight` invocation" to
"not reachable at all."

This is a machine-wide change (outside the `foundry` repo), not scoped to
this project, and was confirmed in scope with the user before being included
here.

### 5. Guardrail and change record

**`AGENTS.md`** gains a short subsection (placed in §7, alongside the existing
SDD role-mapping table) stating:
- `superpowers` is the only development workflow in use in this repository.
- Specs, plans, and change records live under
  `docs/superpowers/{specs,plans,changes}/` respectively.
- `docs/superlight/` is retired; it must not be recreated, and any new work
  should write into the `docs/superpowers/` namespace regardless of which
  skill or subagent produced it.

§8 ("Maintaining These Files") is checked to confirm this new convention is
covered by its existing generic maintenance rules; no separate rule is added
there since §8 already generalizes ("new... module", "protocol behaviour
change", etc.) to cover documentation-location conventions.

**`docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`** is
the change record for this migration itself — written in the same namespace
the migration consolidates into, using the same change-record format as the
other files it now sits alongside. It documents: what moved, why branch names
and prose were preserved rather than rewritten, which branches were deleted,
and that the global skill was removed.

## Verification

This is a documentation- and comment-only change (no production logic is
touched). Per `AGENTS.md` §5.2, the affected surface is: two Rust files
receiving one-line doc-comment edits each, and the `docs/` tree. The scoped
gate is:

```bash
cargo fmt --check
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
grep -rn 'docs/superlight' . --exclude-dir=.git --exclude-dir=target   # must return nothing
ls docs/superlight                                                     # must fail (dir gone)
git branch -a | grep superlight                                        # must return nothing
```

Additionally, every rewritten `docs/superpowers/...` reference is checked to
resolve to a file that actually exists on disk post-move — the failure mode a
blind text substitution could otherwise introduce silently.

No `cargo test --workspace` run is warranted for this change (no production
code paths are touched beyond doc comments); §5.1's scoped gate is sufficient
and §5.3's full-gate triggers do not apply.

## Explicitly out of scope / deferred decisions

- Rewriting `superlight` out of git branch names or historical commit
  messages — never done; commit history is immutable and is treated as
  authoritative provenance, not text to edit.
- Deleting `~/.pi/agent/docs/superpowers/{plans,specs}/2026-07-23-superlight-skill*.md`
  — explicitly retained (this is the paper trail of building the skill, not
  output the skill produced for this project).