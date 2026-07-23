# AGENTS.md — Foundry Agent Guidelines

Guidelines for AI agents working in the `foundry` repository (EUDI Wallet / OpenID4VCI Issuer & OpenID4VP Verifier Rust service).

---

## 1. Project Architecture & Workspace Layout

`foundry` is a Cargo workspace comprising focused crates:

- `crates/foundry`: Binary crate containing the CLI, Axum server endpoints, and dual-listener HTTP server logic.
- `crates/foundry-core`: Core primitives, configuration models, storage traits (SQLite implementation), PKI/trust stores, and Token Status List bitset handling.
- `crates/foundry-issuer`: OpenID4VCI issuance engine (`/token`, `/nonce`, `/credential`, credential offers, pre-auth codes, proof verification).
- `crates/foundry-verifier`: OpenID4VP verification engine (request object builder, JWE ECDH-ES decryption, SD-JWT VC + mdoc verification, DCQL matching, and status revocation checking).
- `crates/foundry-sd-jwt-vc`: SD-JWT VC builder and verifier with disclosure walking and KB-JWT binding.
- `crates/foundry-mdoc`: mdoc (`mso_mdoc`) CBOR builder and DeviceAuth/IssuerAuth verifier.
- `crates/oid4vci` & `crates/openid4vp`: Vendored protocol baseline models.

---

## 2. Subagent-Driven Development (SDD): Role → Agent Mapping

When executing plans using subagents (e.g. via `superpowers:subagent-driven-development`), map roles to specialized agent types:

| SDD Role | Agent `subagent_type` | Typical Scope / Model Tier |
|---|---|---|
| Implementer — transcription / 1–2 files | `mechanical-implementer` | Fast / cheap |
| Implementer — multi-file / integration | `integration-implementer` | Standard |
| Per-task reviewer (spec + quality gate) | `task-reviewer` | Standard |
| Final whole-branch review | `final-reviewer` | Most capable |
| Plan / spec authoring | `architect` | Most capable |
| Fix subagent | matching implementer | Matches original task tier |

### Dispatch Rules & Model Overrides
- **Model Overrides**: When instructed or when usage limits require, pass `model` explicitly on `Agent` calls (e.g. `model: "gemini-3.6-flash"`).
- **Custom Agent Model Overrides**: Custom agent files in `~/.pi/agent/agents/` specify default models in frontmatter. If overriding a custom agent's model, update its frontmatter or dispatch `general-purpose` with explicit role instructions and model parameters.

---

## 3. Global Development & Quality Constraints

Every task and commit in `foundry` MUST comply with these global constraints:

1. **No Panics or Unwraps in Request Paths**:
   - Production request-handling logic in `foundry-issuer`, `foundry-verifier`, and `foundry::server` MUST NOT use `.unwrap()`, `.expect()`, `panic!()`, or `unreachable!()`.
   - Always return typed `Result`s (`IssuanceError`, `VerificationError`, or Axum error responses). Unwraps are permitted strictly inside `#[cfg(test)]` code.

2. **Honest Verification Verdicts (`verified` flag)**:
   - In `foundry-verifier`, `VerificationResult.verified` MUST equal `checks.iter().all(|c| c.passed)`.
   - Never hardcode `verified: true`.
   - Every verification step pushes a named `CheckResult` (`jwe_decryption`, `sd_jwt_vc_signature_and_kb_jwt`, `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`).

3. **Policy Failures vs. Structural/Network Failures**:
   - Policy failures (e.g., DCQL mismatch, status revocation/suspension) return HTTP 200 with `verified: false` and detailed check records.
   - Structural/crypto errors (decryption fail, bad signature) return HTTP 400 (`BAD_REQUEST`).
   - Network status-fetch unavailability returns HTTP 502 (`BAD_GATEWAY`).

4. **Verification Gates**:
   - Before completing any task or opening a PR/review, ensure all three checks pass cleanly:
     - `cargo test --workspace`
     - `cargo clippy --workspace --all-targets -- -D warnings`
     - `cargo fmt --check`

---

## 4. Superpowers Task Tracking Integration (`pi-tasks`)

To keep task progress in sync with the `pi-tasks` TUI widget:

- Use `TaskCreate` to register tasks with `agentType` set for eligible subagents.
- Use `TaskUpdate` to update status (`in_progress`, `completed`) as tasks start and finish.
- Maintain `.superpowers/sdd/progress.md` as the durable, compaction-proof source of truth for execution history.
