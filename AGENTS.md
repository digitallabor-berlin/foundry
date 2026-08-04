# AGENTS.md — Foundry Agent Guidelines

Guidelines for AI agents working in the `foundry` repository.

---

## 1. What Foundry Is

`foundry` is a Rust Cargo workspace implementing an **EUDI Wallet OpenID4VCI
Issuer and OpenID4VP Verifier** service.

For building, running, configuration, CLI usage, Docker, and endpoint examples,
see **[`README.md`](README.md)** — this file does not restate it.

---

## 2. Crate Map & Routing

> **Before reading or editing files under `crates/<x>/`, first read
> `crates/<x>/AGENTS.md`.** These nested files are **NOT auto-loaded** by the
> agent harness — only this root file is. You must open them explicitly. They
> contain the module map, public entry points, test locations, and crate-local
> gotchas you need to land in the right file on the first try.

| Crate | Purpose | Read first |
|---|---|---|
| `crates/foundry-core` | Config, storage traits (SQLite), crypto signers, PKI, trust stores, Token Status List bitsets | [`crates/foundry-core/AGENTS.md`](crates/foundry-core/AGENTS.md) |
| `crates/foundry-sd-jwt-vc` | SD-JWT VC builder + verifier (disclosures, KB-JWT) | [`crates/foundry-sd-jwt-vc/AGENTS.md`](crates/foundry-sd-jwt-vc/AGENTS.md) |
| `crates/foundry-mdoc` | mdoc (`mso_mdoc`) CBOR builder + IssuerAuth/DeviceAuth verifier | [`crates/foundry-mdoc/AGENTS.md`](crates/foundry-mdoc/AGENTS.md) |
| `crates/foundry-issuer` | OpenID4VCI issuance engine (offers, pre-auth codes, `/token`, `/nonce`, `/credential`, holder proofs) | [`crates/foundry-issuer/AGENTS.md`](crates/foundry-issuer/AGENTS.md) |
| `crates/foundry-verifier` | OpenID4VP verification engine (request objects, JWE decryption, credential verification, DCQL, status checks) | [`crates/foundry-verifier/AGENTS.md`](crates/foundry-verifier/AGENTS.md) |
| `crates/foundry` | Binary: CLI, Axum dual-listener HTTP server, OpenAPI, admin auth | [`crates/foundry/AGENTS.md`](crates/foundry/AGENTS.md) |
| `crates/foundry/tests` | Workspace-level integration tests (which file covers what) | [`crates/foundry/tests/AGENTS.md`](crates/foundry/tests/AGENTS.md) |

---

## 3. Dependency Layering

Dependencies flow in **one direction only**:

```
foundry-core
   ↓
foundry-sd-jwt-vc, foundry-mdoc          (credential formats)
   ↓
foundry-issuer, foundry-verifier          (protocol engines)
   ↓
foundry                                   (binary: CLI + HTTP server)
```

**Never introduce an upward or sideways dependency.** In particular
`foundry-core` must not depend on any other `foundry-*` crate, and
`foundry-sd-jwt-vc` / `foundry-mdoc` must not depend on each other or on the
engines. If you need shared behaviour between two crates at the same layer, it
belongs in `foundry-core`.

The workspace contains **no vendored third-party crates**. Every protocol model
foundry relies on is foundry-owned: OpenID4VCI metadata and proof types in
`foundry-issuer`, the DCQL wire model in `foundry-verifier` (`dcql_model.rs`),
and JOSE/JWE primitives in `foundry-core` (`crypto/`). Prefer extending those
over introducing a protocol dependency.

---

## 4. Global Invariants

These are **normative**. Crate-level `AGENTS.md` files carry one-line reminders
that point back here.

### 4.1 No Panics or Unwraps in Request Paths

- Production request-handling logic in `foundry-issuer`, `foundry-verifier`, and
  `foundry::server` MUST NOT use `.unwrap()`, `.expect()`, `panic!()`, or
  `unreachable!()`. Always return typed `Result`s (`IssuanceError`,
  `VerificationError`, or Axum error responses).
- Unwraps are permitted **strictly** inside `#[cfg(test)]` code and integration
  test files under `tests/`.

### 4.2 Honest Verification Verdicts (`verified` flag)

- In `foundry-verifier`, `VerificationResult.verified` MUST equal
  `checks.iter().all(|c| c.passed)`.
- **Never hardcode `verified: true`.**
- Every verification step pushes a named `CheckResult`: `jwe_decryption`,
  `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`,
  `dcql_match`, `status_check`, `transaction_data_binding` (the last only when
  the request carried `transaction_data`).

### 4.3 Policy Failures vs. Structural / Network Failures

- **Policy** failures (DCQL mismatch, status revocation/suspension) →
  HTTP 200 with `verified: false` and detailed check records.
- **Structural / crypto** errors (decryption failure, bad signature) →
  HTTP 400 (`BAD_REQUEST`).
- **Network** status-fetch unavailability → HTTP 502 (`BAD_GATEWAY`).

### 4.4 Conformance With the Vendored Protocol Specifications

The authoritative protocol texts foundry implements are checked into
[`docs/specs/`](docs/specs/). All behaviour — wire formats, parameter names,
error codes, metadata fields, signing/encryption algorithms, and state
transitions — MUST align with them.

| Spec file | Governs |
|---|---|
| [`openid-4-verifiable-credential-issuance-1_0.md`](docs/specs/openid-4-verifiable-credential-issuance-1_0.md) | OpenID4VCI — `foundry-issuer` and the issuer HTTP routes (offers, pre-auth codes, `/token`, `/nonce`, `/credential`, holder proofs, issuer metadata) |
| [`openid-4-verifiable-presentations-1_0.md`](docs/specs/openid-4-verifiable-presentations-1_0.md) | OpenID4VP — `foundry-verifier` and the verifier HTTP routes (authorization/request objects, `vp_token`, response modes, JARM/JWE, DCQL, client ID schemes) |
| [`openid4vc-high-assurance-interoperability-profile-1_0.md`](docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md) | HAIP — the profile that narrows both of the above (mandated SD-JWT VC / mdoc formats, required algorithms, key binding, trust mechanisms). Where HAIP is stricter, **HAIP wins.** |
| [`draft-ietf-oauth-attestation-based-client-auth-07.txt`](docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt) | ABCA — the Client Attestation JWT and Client Attestation PoP JWT formats OpenID4VCI's Wallet Attestation section (Appendix E, L2564/L2600) incorporates by reference; `foundry-issuer`'s `attestation.rs` and the `/token` route. Where OpenID4VCI defers to ABCA, ABCA governs. Kept as `.txt`, not `.md` — verbatim fidelity to the IETF text is the point of a pinned draft. |
| [`rfc9449-dpop.txt`](docs/specs/rfc9449-dpop.txt) | DPoP — the sender-constrained access token mechanism HAIP OpenID4VCI L163 mandates by reference (`MUST support DPoP as defined in [@!RFC9449]`); `foundry-issuer`'s `dpop.rs`, the `/token` route and the `/credential` route. Where HAIP defers to RFC 9449, RFC 9449 governs. Kept as `.txt`, not `.md` — verbatim fidelity to the RFC text is the point of a pinned spec. |

Rules:

- **Consult the spec before implementing or changing protocol-facing
  behaviour.** Do not infer the wire format from existing code, other
  implementations, or memory — open the relevant section in `docs/specs/` and
  follow it.
- **Cite the spec in code and PRs.** New or changed protocol logic MUST carry a
  comment naming the spec and section (e.g.
  `// OpenID4VCI §7.2 — credential response`) so reviewers can verify without
  guessing which text was used.
- **Deliberate deviations MUST be documented** — an inline comment explaining
  *why* (interop workaround, unimplemented optional feature) plus a note in the
  relevant crate's `AGENTS.md` Gotchas section. Silent divergence is a defect.
- **Unimplemented optional features are acceptable; incorrect implementations
  are not.** Prefer a typed "unsupported" error over a non-conformant response.
- These files are **pinned drafts** (see the `seriesInfo` version at the top of
  each). Treat the checked-in copy as the source of truth for this repository,
  not a newer draft found online. Bumping a spec is its own deliberate change:
  update the file, then reconcile the code.
- When dispatching a subagent to protocol work, point it at the specific spec
  file and section — it does not inherit this table.

The clause-by-clause record of where foundry stands against these three specs —
verdicts, evidence, and the register of known gaps — lives in
[`docs/conformance/openid4vc-conformance.md`](docs/conformance/openid4vc-conformance.md).
It is a living document: closing a gap means updating the affected rows there,
not only changing the code.

### 4.5 Observability Must Not Leak

Logging is a request-path concern and is governed like one.

- **Every `#[tracing::instrument]` MUST carry `skip_all`.** Without it, every
  argument is `Debug`-formatted into the span — which in these crates means
  `Config`, `VerificationTransaction` (holding `ephem_private_jwk`), access
  tokens, holder proofs and raw JWEs. Fields are opt-in, always.
- **Never logged, at any level, under any flag:** private and ephemeral JWKs,
  signer keys, the admin API key, access tokens, `c_nonce` values, ABCA
  `attestation_challenge` values, DPoP `nonce` values, the nonce secret,
  pre-authorized codes, authorization codes, transaction codes. Public keys
  appear only as RFC 7638 thumbprints (`foundry_core::obs::thumbprint`).
- **Payload fields require BOTH `foundry_core::obs::sensitive_enabled()` AND a
  `debug`/`trace` level** — never one alone. A level is not authorisation;
  `RUST_LOG=debug` is ordinary in production.
- **Every typed error produces exactly one log record**, emitted inside the
  relevant error mapper in `crates/foundry/src/server.rs` — never at the call
  site (that duplicates) and never nowhere (that is the defect this rule exists
  to prevent). A handler collapsing to a bare `StatusCode` must still log.
- **Level follows meaning:** a policy outcome (DCQL mismatch, revoked
  credential) is `warn` and still HTTP 200 per §4.3; `error` is for actual
  faults.
- **Log field names are operator-facing API.** `request_id`, `tx_id`, `route`,
  `method`, `listener`, `http.status`, `latency_ms`, `error.kind`,
  `error.detail`. Renaming one is a breaking change for whoever is watching the
  logs; update `README.md` too.

Enforced by `crates/foundry/tests/instrumentation_hygiene.rs` (structural) and
`crates/foundry/tests/logging_redaction.rs` (behavioural, with a positive
control). Operator-facing documentation lives in the "Logging & Observability"
section of [`README.md`](README.md).

---

## 5. Verification Gates

The workspace suite is **deliberately slow** (real crypto, subprocess E2E flows,
status-list fixtures). Testing is therefore **scoped by default**; a full run is
a deliberate checkpoint, not a reflex. Running `--workspace` after every edit is
a process defect, not diligence.

### 5.1 Scoped Gate — the default, at every task boundary

For **each individual task**, run only what the change can plausibly break:

```bash
cargo test -p <crate>                                # every crate you touched
cargo test -p <dependent>                            # + affected dependents (§5.2)
cargo clippy -p <crate> --all-targets -- -D warnings
cargo fmt --check                                    # cheap; keep it workspace-wide
```

This — and only this — is the gate for finishing a task, marking a `TaskUpdate`
as `completed`, or handing work to a per-task reviewer. **Do not run
`cargo test --workspace` at the end of, or between, individual tasks.**

**Don't re-run a gate that already ran.** If the task immediately before this
one already ran the scoped gate for the crates you're about to touch and it
came back clean, carry that result forward — do not re-run it again at the
start of the next task as a reflexive sanity check. Only run it again when the
new task touches crates the prior gate didn't cover, or when you've made
further edits since it last ran.

### 5.2 Which Crates Count as "Affected"

Derive the set from the layering in §3: a change can only break the crate itself
and the crates **below** it in that diagram.

| You touched | Also test |
|---|---|
| `foundry` | — (nothing depends on it) |
| `foundry-issuer` / `foundry-verifier` | `foundry` (integration suite) |
| `foundry-sd-jwt-vc` / `foundry-mdoc` | whichever engine consumes the changed format (`foundry-issuer` and/or `foundry-verifier`), then `foundry` |
| `foundry-core` | the direct consumers of the changed module only — e.g. `crypto/` → both engines; `storage/` → `foundry`; `status_list` → `foundry-verifier` + `foundry` |
| `crates/foundry/tests/` | `cargo test -p foundry` (narrow further with `--test <file>` while iterating) |

Purely local edits — a doc comment, a test-only helper, a rename confined to one
private module — need only the owning crate.

### 5.3 Full Gate — reserved for these cases

```bash
cargo fmt                                                    # apply formatting first
cargo fmt --check                                            # verify (no-op after the line above)
cargo test --workspace
cargo test -p foundry --test e2e_full_flow -- --ignored      # E2E: only here, never in the scoped gate
cargo clippy --workspace --all-targets -- -D warnings
```

Run this, **once**, when either of the following holds:

- **The user explicitly asks for it.**
- **You are finishing a development branch** — every task of a plan or feature
  is done and you are about to open a PR, request the final whole-branch
  review, or merge.

These are the **only** two triggers. A scoped run passing is not, by itself,
a reason to escalate — "not confident" or "just to be safe" is not an
exception. If a scoped result feels insufficient (a cross-cutting refactor, a
`foundry-core` signature change, a shared trait or serde shape, a scoped run
that failed in a way that hints at wider breakage), the answer is to **widen
the scoped set** — one more `-p <crate>`, or the layer above per §5.2 — not to
escalate to `--workspace`. If widening repeatedly still leaves you unsure,
say so to the user rather than defaulting to a full run.

The E2E suite (`e2e_full_flow`, `#[ignore]`d by default — see
[`crates/foundry/tests/AGENTS.md`](crates/foundry/tests/AGENTS.md)) follows
the same rule: it runs **only** as part of this Full Gate, never inside a
scoped, per-task gate.

Always run `cargo fmt` (applying, not just checking) before the rest of this
gate, so the full suite runs against an already-formatted tree instead of
failing — or silently drifting — on style alone.

### 5.4 Never Re-Run the Full Suite After Merging

Once work has been merged back to `main`, **do not run `cargo test --workspace`
again to "confirm" the merge.** The full gate of §5.3 was already run once, at
the end of the development cycle, as part of the final review / pre-PR
checkpoint. Re-running it post-merge re-pays the most expensive gate in the
repository for information already established.

- After a merge, the correct action is **none** — report the gate that was
  already run (§5.5 honesty rule) and stop.
- The only exception is a merge that **actually changed the tree beyond the
  reviewed branch** — a non-trivial conflict resolution, or `main` having moved
  in a way that touches the same crates. Then run the **scoped** gate of §5.1
  over the conflicted crates, not the full suite.
- "Just to be safe" is not an exception. If the branch was green and the merge
  was a fast-forward or a clean auto-merge, there is nothing new to verify.

### 5.5 Honesty Rule

Never claim work is complete, fixed, or passing without having run the gate that
actually applies and seen it pass. When reporting, **name the gate you ran** —
e.g. "scoped: `cargo test -p foundry-verifier -p foundry` green" — so the reader
knows what was and was not covered. Claiming a full gate you did not run is
worse than running none.

---

## 6. OpenAPI Specification

HTTP endpoints MUST be documented in the exposed OpenAPI specification. Any
change to an endpoint (path, method, request/response shape, status codes) MUST
be reflected in:

- `openapi.json` — issuer/verifier service
- `openapi-wallet.json` — wallet-facing routes

Specs are generated via `utoipa` annotations in `crates/foundry/src/openapi.rs`;
see `crates/foundry/AGENTS.md` for the regeneration command.

---

## 7. Subagent-Driven Development (SDD): Role → Agent Mapping

When executing plans using subagents (e.g. via
`superpowers:subagent-driven-development`), map roles to specialized agent types:

| SDD Role | Agent `subagent_type` | Typical Scope / Model Tier |
|---|---|---|
| Implementer — transcription / 1–2 files | `mechanical-implementer` | Fast / cheap |
| Implementer — multi-file / integration | `integration-implementer` | Standard |
| Per-task reviewer (spec + quality gate) | `task-reviewer` | Standard |
| Final whole-branch review | `final-reviewer` | Most capable |
| Plan / spec authoring | `architect` | Most capable |
| Fix subagent | matching implementer | Matches original task tier |

**When dispatching a subagent scoped to one crate, tell it to read that crate's
`AGENTS.md` first** — it starts with fresh context and will not have this root
file's routing table.

**Tell each implementer and per-task reviewer which gate applies.** They run the
**scoped** gate of §5.1 — the touched crate plus its affected dependents — and
must not run `cargo test --workspace`. The full gate of §5.3 is run exactly
once, by the `final-reviewer` at the end of the branch (or by you, before
opening the PR). A subagent that reports "workspace green" per task has burned
minutes it should not have.

### Task Tracking (`pi-tasks`)

- Use `TaskCreate` to register tasks with `agentType` set for eligible subagents.
- Use `TaskUpdate` to update status (`in_progress`, `completed`) as tasks start
  and finish.
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

- **New crate** → add a row to the §2 routing table *and* create
  `crates/<new>/AGENTS.md` using the same 7-section template as the existing
  crate files (Purpose / Dependency position / Module map / Public entry points /
  Binding invariants / Tests / Gotchas).
- **New, renamed, or repurposed module** → update that crate's module map.
- **New global invariant** → add it to §4 with a number, and add a one-line
  reminder to every crate file it binds.
- **Endpoint change** → update the OpenAPI specs (§6) and, if routing changed,
  `crates/foundry/AGENTS.md`.
- **Protocol behaviour change** → verify it against the pinned specs in
  `docs/specs/` (§4.4) and cite the section in a code comment. **New or replaced
  spec file in `docs/specs/`** → add or update its row in the §4.4 table.
- **Closing a conformance gap** → update the affected rows in
  `docs/conformance/openid4vc-conformance.md` and remove the `#[ignore]` from
  the test that cites that gap ID. The report is a living document, not a
  historical record.
- **No line counts, test counts, or other per-commit-drifting numbers** in any
  AGENTS.md — stale numbers erode trust in the whole file.
- Design rationale for this structure: `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md`.