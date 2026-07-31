# OpenID4VC Conformance Audit of Issuer & Verifier

**Date:** 2026-07-31
**Status:** approved

## Problem

`AGENTS.md` §4.4 ("Conformance With the Vendored Protocol Specifications") became
normative in commit `92ad839`, which vendored three pinned protocol drafts into
[`docs/specs/`](../../specs/) and declared that all protocol-facing behaviour MUST
align with them:

| Spec | Pinned version | Lines |
|---|---|---|
| `openid-4-verifiable-credential-issuance-1_0.md` | `-17` | 3020 |
| `openid-4-verifiable-presentations-1_0.md` | `-30` | 3561 |
| `openid4vc-high-assurance-interoperability-profile-1_0.md` | `-06` | 830 |

No part of foundry has ever been systematically checked against them. The
issuer and verifier were built from the protocols, but incrementally and
feature-by-feature, so the current state of conformance is not "good" or "bad"
— it is **unknown**, and unknowable without a denominator. There is no list of
what the specs require, no record of which requirements were considered, and no
way to distinguish "examined and correct" from "never looked at".

Two consequences follow. First, §4.4 cannot actually be enforced in review: a
reviewer asked "does this conform?" has nothing to check against but the same
spec text and the same guesswork. Second, requirements foundry never
implemented at all are invisible — nothing in the codebase raises the question,
because absent code produces no diff to review.

## Goal / Non-Goals

### Goal

Produce a durable, clause-indexed conformance record for the OpenID4VCI issuer
and OpenID4VP verifier, backed by executable tests, such that:

- every mandatory clause in the three vendored specs that applies to foundry's
  implemented surface carries an explicit verdict with evidence;
- every deviation found carries a numbered gap entry, a severity, and a test
  that asserts the spec-correct behaviour and will pass on the day the code is
  fixed;
- coverage is arithmetic rather than rhetorical — the fraction of the mandatory
  surface examined is a number, not a claim.

### Non-Goals

- **Fixing non-conformances.** Each deviation gets recorded, not repaired. Fixes
  are follow-up runs, so that each carries its own design decision rather than
  being resolved inline by whoever happened to be holding the audit.
- **Refactoring existing tests or extracting shared fixtures.** Mixing a
  refactor into an audit endangers currently-green tests and blurs what the
  audit actually established.
- **Adding dependencies**, production or dev.
- **Vendoring further specs.** See "Audit boundary" below.
- **Auditing `foundry-wallet`.** It is a debug client, not part of the
  issuer/verifier surface under audit.
- **Changing the OpenAPI specs.** No endpoint changes are in scope; if the audit
  finds that `openapi.json` misdescribes an endpoint, that is recorded as a gap,
  not fixed here.

## Approach

### Chosen: inventory-first audit, tests as evidence, fixes deferred

Three ordered stages:

1. **Extract.** Walk each vendored spec and emit one inventory row per mandatory
   clause — `id`, spec, section, abridged requirement, applies-to
   (`issuer` / `verifier` / `http` / `wallet` / `other`), initial verdict
   `unverified`. Committed as
   the skeleton of the conformance report before any adjudication happens.
2. **Adjudicate.** Per functional area, read the implementation and set each
   applicable row's verdict plus evidence (`file:line`).
3. **Test.** Write conformance tests for the area and link inventory rows to
   test names. Tests that pass document conformance; tests that fail document a
   gap and are marked `#[ignore]` with the gap identifier.

### Rejected alternatives

- **Code-first audit** (walk the implementation, check each behaviour against
  the spec). Rejected because it structurally cannot find *missing* behaviour: a
  MUST that foundry never implemented triggers no question, since there is no
  code to prompt it. Omissions are typically the most serious findings.
- **Area-by-area with no upfront inventory.** Rejected because it produces
  verdicts with no denominator — at the end there is no way to state what
  fraction of the spec was examined, and no way for a later session to
  distinguish "§7.4 checked and fine" from "§7.4 never opened". Since this run
  will span sessions and possibly models, the inventory *is* the resumption
  state.
- **Audit report with no tests.** Rejected because an unverified claim of
  conformance is exactly the situation §4.4 already fails to solve. Executable
  evidence is the point.
- **Audit plus in-run fixes.** Rejected because it fuses discovery with remedy;
  each non-conformance deserves its own design decision.
- **Splitting into two runs (issuer, then verifier).** Rejected because HAIP
  narrows both engines and would have to be audited twice from two angles, and
  because the audit conventions would be decided in run 1 and silently
  inherited by run 2. Session-spanning is handled by the plan file, not by
  chopping the work up.
- **Recording non-conforming behaviour as green assertions** (rather than
  ignored spec-correct ones). Rejected as actively harmful: it encodes the wrong
  behaviour as the expectation, so a later correct fix turns a green test red
  and looks like a regression.

## Design

### Audit boundary

**In scope:**

- `foundry-issuer` (all modules)
- `foundry-verifier` (all modules)
- The protocol routes in `crates/foundry/src/server.rs`: `/token`,
  `/authorize`, `/nonce`, `/credential`, `/vp/request/:id`, `/vp/response/:id`,
  `/statuslists/:id`, and the `.well-known` metadata routes.

**Clause selection:** mandatory clauses only — MUST, MUST NOT, REQUIRED, SHALL,
SHALL NOT — restricted to features foundry actually implements. Per §4.4,
unimplemented optional features are acceptable; they are recorded as
`not-implemented` with no gap and no test. SHOULD / RECOMMENDED clauses receive
a verdict in the inventory but a test only where the test is cheap.

**Out of scope, recorded explicitly rather than omitted silently:**

- `foundry-wallet`.
- SD-JWT VC and mdoc **format internals** — disclosure encoding, CBOR structure,
  MSO layout. Their defining specs (IETF SD-JWT VC, ISO/IEC 18013-5) are not
  vendored under §4.4, and ISO/IEC 18013-5 cannot be vendored (paid standard).
  What *is* in scope is what the three vendored specs say about format
  **usage**: which formats must be supported, required algorithms, key binding
  requirements, and the profile's constraints on `vct` / doctype handling.
- Token Status List **bitstring encoding**, for the same reason — the defining
  spec is not vendored. HAIP's mandate *that* status lists are used is in scope;
  whether the bitset is encoded correctly is not.

Out-of-scope areas appear in the report with the verdict `out-of-scope` and the
reason, so that silence is never mistaken for a pass.

### Conformance report

Path: `docs/conformance/openid4vc-conformance.md`. A **living document owned by
the repository**, not a superlight run artifact — later runs that close a gap
edit it in place. It must never be duplicated into the run changelog, which is
by design an immutable record of this run only.

Three parts:

1. **Summary** — per spec, counts of: total clauses, `conforming`, `gap`,
   `not-implemented`, `not-unit-testable`, `out-of-scope`, `ambiguous`,
   `unverified`.
2. **Gap register** — `| ID | Severity | Spec § | Requirement | Impact | Test |`
3. **Clause inventory** — one table per spec:
   `| ID | § | Requirement | Applies to | Verdict | Evidence | Test |`
4. **Unresolved Ambiguities** — every `ambiguous` clause with both readings and
   why the ambiguity matters.

A one-line pointer to the report is added to `AGENTS.md` §4.4 so the invariant
and the evidence for it are one hop apart.

### Identifiers

- Clauses: `VCI-0001`, `VP-0001`, `HAIP-0001` — zero-padded, sequential in
  document order within each spec.
- Gaps: `GAP-VCI-01`, `GAP-VP-01`, `GAP-HAIP-01`, `GAP-HTTP-01`.

Identifiers are **stable and never renumbered**: `#[ignore]` reason strings,
future runs, and commit messages cite them.

### Verdicts

| Verdict | Meaning |
|---|---|
| `conforming` | Implemented and correct; evidence cites code and a test |
| `gap` | Implemented incorrectly, or mandatory and absent; has a `GAP-*` entry |
| `not-implemented` | Optional feature foundry does not offer; permitted by §4.4 |
| `not-unit-testable` | Transport, deployment, or operational requirement; rationale recorded |
| `out-of-scope` | Outside the audit boundary above; reason recorded |
| `ambiguous` | Clause examined, but genuinely readable two ways; both readings recorded. A terminal verdict, not pending work |
| `unverified` | Not yet adjudicated — the remaining-work marker |

### Severity

| Severity | Definition |
|---|---|
| **Critical** | Accepts something it must reject — forged, replayed, or unauthorized credential or presentation |
| **Important** | A conformant counterparty fails to interoperate |
| **Minor** | No functional consequence (wording, ordering, redundant field) |

Severity is assigned when the finding is made, and the gap register is committed
with the task that found it — so a Critical becomes visible in the repository as
soon as its task lands. There is **no mid-run escalation**: all findings are
triaged together in Phase 5. (This was a deliberate user decision against the
recommendation to halt on Critical; the recommendation and the decision are both
recorded here.)

### Data flow of a single clause

```
spec text
   → inventory row (verdict: unverified)
      → read implementation
         → verdict: conforming    → evidence file:line + test name
         → verdict: gap           → GAP-* entry + severity + #[ignore]d test
         → verdict: not-implemented / not-unit-testable / out-of-scope + rationale
```

### Error handling / edge cases

- **Ambiguous clause** — verdict `ambiguous`, with both readings and the reason
  the ambiguity matters recorded. Never resolved by guessing, and deliberately
  distinct from `unverified`: the clause *was* examined, so it does not block
  completion, but no conformance claim is made for it.
- **Untestable at unit level** — `not-unit-testable` plus rationale.
- **Mandatory clause unreachable through the crate's public API** — recorded as
  a finding in its own right, because it means the behaviour cannot be asserted
  from outside. A test is placed inline in the module only when that is the only
  way to express the check, and each such case is noted in the report.
- **Clause already covered by an existing test** — verdict `conforming`, `Test`
  column cites the existing test. No duplicate is written.
- **Unexpected red in the existing suite** — superlight's debug trigger fires:
  stop, investigate to root cause, then resume. Never re-run and hope.
- **Audit reveals OpenAPI drift** — recorded as a gap (`GAP-HTTP-*`); the
  OpenAPI specs are not regenerated in this run.

## Global Constraints

- Vendored specs are pinned drafts — OpenID4VCI `-17`, OpenID4VP `-30`, HAIP `-06`; the checked-in copies are authoritative over any newer draft found elsewhere.
- Where HAIP is stricter than OpenID4VCI or OpenID4VP, HAIP wins (`AGENTS.md` §4.4).
- No changes to production logic under `crates/*/src/**` — this run adds tests and documentation only. The single permitted exception is appending a test function to an existing `#[cfg(test)] mod tests` block when a mandatory clause is unreachable through the crate's public API; no non-test code may change, and each such case is recorded in the report.
- No modification of existing test *assertions* or existing test files under `tests/`; new conformance tests live in new files.
- No new dependencies added to any `Cargo.toml`, production or dev.
- Gap test attribute format: `#[ignore = "GAP-<AREA>-<NN>: <Spec> §<section> — <requirement>"]`.
- Conformance test naming: `<spec>_<clause-number>_<behaviour>`, snake_case, e.g. `vci_0042_token_endpoint_rejects_reused_pre_auth_code`.
- Clause and gap identifiers are never renumbered once committed.
- Every protocol assertion in a test carries a comment citing spec and section (`AGENTS.md` §4.4).
- Report path is exactly `docs/conformance/openid4vc-conformance.md`.
- No line counts, test counts, or other per-commit-drifting numbers in any `AGENTS.md` (`AGENTS.md` §8) — such counts belong in the report, which is expected to change.
- Gates before any task is complete: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.

## Testing Strategy

### Test files

| File | Covers |
|---|---|
| `crates/foundry-issuer/tests/conformance_vci.rs` | OpenID4VCI + issuer-side HAIP, engine level |
| `crates/foundry-verifier/tests/conformance_vp.rs` | OpenID4VP + verifier-side HAIP, engine level |
| `crates/foundry/tests/conformance_http.rs` | HTTP status codes, error bodies, headers, content types |

Both engine crates currently have **no `tests/` directory** — all their tests
are inline `#[cfg(test)] mod tests`. Introducing `tests/` is a deliberate break
from that convention: protocol conformance is a property of the wire surface,
which is what Rust integration tests address, and organising by spec section
rather than by source module is what makes the files auditable against the
report. A useful side effect is that a mandatory clause which cannot be
expressed through the public API surfaces as a finding rather than being papered
over with `pub(crate)` access.

HTTP-level clauses live in `crates/foundry/tests/` because the handlers do:
`Cache-Control: no-store` cannot be asserted in `foundry-issuer`, which never
sets a header.

### Structure and mapping

Tests are ordered by spec section, not by module. Clauses are **not** 1:1 with
tests — one test may discharge several clauses, and a clause may need none
(`not-implemented`, `out-of-scope`). The inventory's `Test` column carries the
mapping; coverage is counted at clause level, never at test level.

### Gap tests

A test for a failing clause asserts the **spec-correct** behaviour and is
annotated:

```rust
#[ignore = "GAP-VCI-01: OpenID4VCI §6.1 — pre-authorized_code MUST be single-use"]
```

`cargo test --workspace` therefore stays pristine per `AGENTS.md` §5, while
`cargo test --workspace -- --ignored` is the live gap inventory. Closing a gap
in a follow-up run means deleting one attribute.

### Fixtures

Each conformance test file builds its own `Config` and tempdir-backed
`SqliteStorage`, and HTTP tests drive the router via
`tower::ServiceExt::oneshot` — mirroring the pattern already used across the
existing test files. This duplicates boilerplate that is already duplicated;
that is accepted deliberately under the "no refactoring during an audit"
non-goal.

### Completion criteria

- Zero `unverified` rows in the clause inventory. `ambiguous` rows are permitted
  and are listed together in an "Unresolved Ambiguities" section of the report.
- `cargo test --workspace` clean.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `cargo test --workspace -- --ignored` lists exactly the gap tests, and that
  count reconciles against the gap register. A mismatch is a Phase 5 blocker,
  because it means either a gap without evidence or a test without a record.
- Every gap register row has a spec citation, a severity, an impact, and a test.

## Open Questions

None.