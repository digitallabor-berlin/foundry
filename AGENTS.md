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
  signer keys, the admin API key, access tokens, `c_nonce` values and the nonce
  secret, pre-authorized codes, authorization codes, transaction codes. Public
  keys appear only as RFC 7638 thumbprints (`foundry_core::obs::thumbprint`).
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