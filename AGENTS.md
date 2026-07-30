# AGENTS.md — Foundry Agent Guidelines

Guidelines for AI agents working in the `foundry` repository.

---

## 1. What Foundry Is

`foundry` is a Rust Cargo workspace implementing an **EUDI Wallet OpenID4VCI
Issuer and OpenID4VP Verifier** service, plus a debug wallet client.

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
| `crates/foundry-wallet` | Debug EUDI wallet CLI/TUI for exercising issuance + verification end-to-end | [`crates/foundry-wallet/AGENTS.md`](crates/foundry-wallet/AGENTS.md) |

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
   ↓
foundry-wallet                            (debug client; depends on foundry for E2E subprocess tests)
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
- Likewise, `foundry-wallet`'s `actions/`, `storage/`, `http/`, and `tui/`
  modules MUST return `WalletResult`/`WalletError`.
- Unwraps are permitted **strictly** inside `#[cfg(test)]` code and integration
  test files under `tests/`.

### 4.2 Honest Verification Verdicts (`verified` flag)

- In `foundry-verifier`, `VerificationResult.verified` MUST equal
  `checks.iter().all(|c| c.passed)`.
- **Never hardcode `verified: true`.**
- Every verification step pushes a named `CheckResult`: `jwe_decryption`,
  `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`,
  `dcql_match`, `status_check`.

### 4.3 Policy Failures vs. Structural / Network Failures

- **Policy** failures (DCQL mismatch, status revocation/suspension) →
  HTTP 200 with `verified: false` and detailed check records.
- **Structural / crypto** errors (decryption failure, bad signature) →
  HTTP 400 (`BAD_REQUEST`).
- **Network** status-fetch unavailability → HTTP 502 (`BAD_GATEWAY`).

---

## 5. Verification Gates

**Fast loop while iterating** on a single crate:

```bash
cargo test -p <crate>          # e.g. cargo test -p foundry-verifier
```

**Required before completing any task, opening a PR, or requesting review** —
all three must pass cleanly:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Never claim work is complete without having run these and seen them pass.

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

### Task Tracking (`pi-tasks`)

- Use `TaskCreate` to register tasks with `agentType` set for eligible subagents.
- Use `TaskUpdate` to update status (`in_progress`, `completed`) as tasks start
  and finish.
- Maintain `.superpowers/sdd/progress.md` as the durable, compaction-proof
  source of truth for execution history.

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
- **No line counts, test counts, or other per-commit-drifting numbers** in any
  AGENTS.md — stale numbers erode trust in the whole file.
- Design rationale for this structure: `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md`.