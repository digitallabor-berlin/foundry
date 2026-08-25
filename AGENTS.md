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
| --- | --- | --- |
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

- In `foundry-verifier`, `VerificationResult.verified` MUST equal the
  conjunction over **every** `CheckResult` in the result — the top-level
  `checks` **and** every `credentials[i].checks` entry. Use
  `VerificationResult::all_checks()`; `checks.iter().all(..)` alone is
  satisfiable while a per-credential check fails, which is the whole defect
  this rule exists to prevent.
- **Never hardcode `verified: true`.**
- Every verification step pushes a named `CheckResult`, at one of two levels.
  **Cross-cutting** (`result.checks`): `jwe_decryption`, and exactly one of
  `requested_credentials_answered` (DCQL query without `credential_sets`) or
  `credential_sets_satisfied` (with `credential_sets`) — mutually exclusive,
  chosen by the query, the same way the per-credential format checks are chosen
  by the answered query's declared format. **Per-credential**
  (`result.credentials[i].checks`): `sd_jwt_vc_signature_and_kb_jwt` or
  `mdoc_issuer_auth_and_device_signature` (mutually exclusive, chosen by the
  answered credential query's declared format), `dcql_match`, `status_check`,
  and `transaction_data_binding` (only when the request carried
  `transaction_data`).

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
| --- | --- |
| [`openid-4-verifiable-credential-issuance-1_0.md`](docs/specs/openid-4-verifiable-credential-issuance-1_0.md) | OpenID4VCI — `foundry-issuer` and the issuer HTTP routes (offers, pre-auth codes, `/token`, `/nonce`, `/credential`, holder proofs, issuer metadata) |
| [`openid-4-verifiable-presentations-1_0.md`](docs/specs/openid-4-verifiable-presentations-1_0.md) | OpenID4VP — `foundry-verifier` and the verifier HTTP routes (authorization/request objects, `vp_token`, response modes, JARM/JWE, DCQL, client ID schemes) |
| [`openid4vc-high-assurance-interoperability-profile-1_0.md`](docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md) | HAIP — the profile that narrows both of the above (mandated SD-JWT VC / mdoc formats, required algorithms, key binding, trust mechanisms). Where HAIP is stricter, **HAIP wins.** |
| [`draft-ietf-oauth-attestation-based-client-auth-07.txt`](docs/specs/draft-ietf-oauth-attestation-based-client-auth-07.txt) | ABCA — the Client Attestation JWT and Client Attestation PoP JWT formats OpenID4VCI's Wallet Attestation section (Appendix E, L2564/L2600) incorporates by reference; `foundry-issuer`'s `attestation.rs` and the `/token` route. Where OpenID4VCI defers to ABCA, ABCA governs. Kept as `.txt`, not `.md` — verbatim fidelity to the IETF text is the point of a pinned draft. |
| [`rfc9449-dpop.txt`](docs/specs/rfc9449-dpop.txt) | DPoP — the sender-constrained access token mechanism HAIP OpenID4VCI L163 mandates by reference (`MUST support DPoP as defined in [@!RFC9449]`); `foundry-issuer`'s `dpop.rs`, the `/token` route and the `/credential` route. Where HAIP defers to RFC 9449, RFC 9449 governs. Kept as `.txt`, not `.md` — verbatim fidelity to the RFC text is the point of a pinned spec. |
| [`eu-age-verification-annex-a-av-profile.md`](docs/specs/eu-age-verification-annex-a-av-profile.md) | EU Age Verification Solution Technical Specification, **Annex A (normative), "Age Verification Profile"** — the `eu.europa.ec.av.1` Proof of Age attestation: its doctype (§4.1.1), its namespace (§4.1.2), and its closed two-attribute set (§4.1.2, "A Proof of Age Attestation SHALL NOT include any other attribute"). Profiles ISO/IEC 18013-5 and ISO/IEC 23220-2. Authority is **scoped to that one doctype**; where it is stricter than ISO 18013-5 for it, this profile wins. Vendored rather than stubbed because it is CC BY 4.0 — freely redistributable with attribution, which the file's header carries verbatim. Pinned to release 1.0.9 (`5eb8a033`); Annex A only. Note its "Out of Scope" section: OpenID4VCI profiling for ISO mDoc is deferred to ISO/IEC 23220-3, which is **not** vendored — foundry's OpenID4VCI behaviour remains governed by OpenID4VCI 1.0 and HAIP |
| [`paso-core.md`](docs/specs/paso-core.md) | PaSO (Payments and SCA for OpenID) Core — the transaction data model foundry publishes metadata for: the `payload` parameter on an OpenID4VP `transaction_data` entry (§7.1) and the `urn:paso:sca:<domain>:<suffix>:<version>` transaction data type identifier grammar (§5.2) that `Config::validate()` enforces. Vendored verbatim rather than stubbed because it is the repository owner's own document and freely committable. **Scope note:** foundry implements the Attestation Provider role only; PaSO Core's Wallet-side processing (§6, §7.3, §7.4) and the Relying Party and Authorizing Party roles are not implemented |
| [`paso-proof-metadata.md`](docs/specs/paso-proof-metadata.md) | PaSO Proof: Metadata Module — the `credential_metadata_uri` extension to OpenID4VCI Credential Issuer Metadata (§2), the `transaction_data_types` structure with its claims metadata and `ui_labels` (§3), the signed credential metadata JWT `credential-metadata+jwt` (§4), and the ad-hoc `adhoc-transaction-metadata+jwt` (§5). Governs `foundry-issuer`'s `paso_metadata.rs`, the `GET /credential-metadata/:id` route, and `POST /admin/paso/ad-hoc-metadata`. **Unimplemented optional path:** §4/§5.2/§7's `kid`/key-set signing branch — foundry's issuer keys are `x5c`-published and it takes the `x5c` branch only |

One pinned source is **not** a standards-track specification and is governed by
its own rule below:

| Vendor profile | Governs |
|---|---|
| [`google-wallet-openid4vci-profile.md`](docs/specs/google-wallet-openid4vci-profile.md) | Google Wallet's OpenID4VCI implementation — the choices it makes where the specifications permit several, and the two places it expects behaviour no specification defines (a `DPoP-Nonce` header on the ABCA challenge response and on the OpenID4VCI Nonce Endpoint response). Also the source of the real Android Keystore attestation chains used as interop fixtures. Governs foundry's Google-accommodating behaviour only — see the vendor-profile rule below. |

**Vendor-profile rule.** A vendor profile records one implementation's
observable behaviour and requirements. It is normative **only** for what foundry
does when accommodating that implementation. It is **never** grounds for
violating a MUST in a standards-track specification above; where the two
conflict, the specification wins and the conflict is recorded as a known
limitation. Behaviour whose only justification is a vendor profile MUST carry a
code comment naming the profile, so a reader can tell vendor accommodation from
conformance. Do not extend the "where HAIP is stricter, HAIP wins" precedence to
a vendor profile by analogy — that would let accommodation read as conformance.

A third governing source is neither standards-track nor a vendor profile, and its
text is **not present in this repository at all**:

| External reference | Governs |
| --- | --- |
| [`emvco-dpc-schema-framework.md`](docs/specs/emvco-dpc-schema-framework.md) | EMV® Digital Payment Credential Specification — Schema Framework (v1.0, DRAFT Associate Review 2). Governs the shape of the `com.emvco.dpc.card` credential type only: its `vct`, and its three disclosable claims with their types and inclusion requirements. The linked file is a **reference stub**, not the specification — the document is all-rights-reserved and unpublished, so no verbatim copy is committed. |
| [`iso-18013-5-device-auth.md`](docs/specs/iso-18013-5-device-auth.md) | ISO/IEC 18013-5:2021 — the mdoc CBOR internals `foundry-mdoc` builds and verifies: tag-24 embedding of `IssuerSignedItem`s and the `MobileSecurityObject`, the digest basis `valueDigests` commits to, the `bstr` typing of `IssuerSignedItem.random` and of each `valueDigests` `Digest`, `tdate` validity members, and the `DeviceAuthentication` structure a `DeviceSignature` covers. The linked file is a **reference stub**, not the specification — ISO 18013-5 is a paid standard whose licence forbids redistribution. It marks each recorded fact **proven** (reproduced from a captured real presentation) or **derived** (reconstructed from two independent implementations at pinned commits, which agree). Neither status equals having read the standard; do not infer unrecorded behaviour from the stub. |

**External-reference rule.** Where a governing document cannot be committed —
because its licence forbids redistribution, or because it is unpublished — the
stub in `docs/specs/` records its exact title, version and revision, why no copy
is in-tree, where a reader obtains one, and the interface facts foundry relies
on, **restated rather than quoted**. Claim names, types and inclusion
requirements are factual interface information; reproducing the document's prose
is not. Treat the stub as the record of *which* revision the code was built
against — never as a substitute for the text: do not infer unrecorded behaviour
from it, obtain the document. A stub does **not** acquire the precedence of a
standards-track specification, and where the two conflict, the specification
wins. When the pinned revision is a draft under review, expect it to move;
bumping it is a deliberate change, exactly as for the pinned specs above.

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
  pre-authorized codes, the by-reference Credential Offer id (the `:id` of
  `GET /credential-offer/:id` — the document it addresses carries the
  `pre-authorized_code`, so the id is a bearer credential, not a database key),
  authorization codes, transaction codes, the raw
  compact JWE of an encrypted Credential Request, the decrypted Credential
  Request, the plaintext Credential Response when encryption was requested,
  the wallet's `credential_response_encryption.jwk`, the Android key
  attestation `uniqueId` (a privacy-sensitive hardware device identifier that
  survives factory reset), and the EMVCo DPC display-metadata objects
  (`card.last_four`, the cardholder-recognisable `card.alias`, and card-art
  URLs, which may be personalised) — `create_offer` records their *presence*
  only, never their contents. Public keys appear only as RFC 7638 thumbprints
  (`foundry_core::obs::thumbprint`), with one exception: the verbatim
  presentation-request diagnostics (`request_object_jws`,
  `request_object_payload`, `dc_api_request`) reproduce the object as sent,
  which includes the ephemeral **public** JWK in `client_metadata`. Reducing it
  to a thumbprint there would defeat the field's only purpose — replaying the
  exact bytes a wallet rejected. The ephemeral **private** JWK remains
  unloggable in every mode.
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
  `error.detail`, and on per-credential verification records `credential`,
  `credential_type`, `format`, `check`, `passed`, `checks`, `checks_passed`,
  plus `credentials_requested` / `credentials_answered` / `credentials_failed`
  on the verdict record. Renaming one is a breaking change for whoever is
  watching the logs; update `README.md` too.

Enforced by `crates/foundry/tests/instrumentation_hygiene.rs` (structural) and
`crates/foundry/tests/logging_redaction.rs` (behavioural, with a positive
control). Operator-facing documentation lives in the "Logging & Observability"
section of [`README.md`](README.md).

---

## 5. Verification Gates

**`cargo nextest run` is this repository's test runner. Do not use `cargo test`.**

The full workspace suite runs in **seconds** under nextest — every crate, every
test, in about the time a single scoped run used to spend linking. There is
therefore **no scoped gate and no cheaper tier**: always run the whole
workspace. Hand-picking a subset of crates to save time is no longer a saving,
only reduced coverage.

Install it with `cargo install cargo-nextest --locked` (see
<https://nexte.st/docs/installation/>).

### 5.1 The Gate

Run this before finishing a task, marking a `TaskUpdate` as `completed`,
handing work to a reviewer, committing, opening a PR, or merging — every time,
without tiers or exceptions:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- `cargo fmt` **applies** formatting rather than checking it, and runs first, so
  the suite runs against an already-formatted tree instead of failing on style
  alone.
- `--no-fail-fast` reports *every* failure instead of stopping at the first, so
  a single run tells you everything there is to fix.
- `--status-level fail` prints only failures plus a one-line summary. A green
  full-workspace run is roughly ten lines, so nothing is lost to the agent
  harness's output truncation and there is no need to capture it to disk. Drop
  the flag when you want to watch individual tests go by.

A run ends with one line naming the totals, in this shape:

```
     Summary [   <elapsed>] <N> tests run: <N> passed, <M> skipped
```

That line is the evidence §5.3 asks for.

### 5.2 The E2E Suite

`e2e_full_flow` is `#[ignore]`d — it binds real OS ports and drives subprocess
flows, so it stays out of the default run (see
[`crates/foundry/tests/AGENTS.md`](crates/foundry/tests/AGENTS.md)). nextest
skips ignored tests unless asked for them explicitly:

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

Run it before opening a PR or merging — not on every task. To run the whole
workspace including ignored tests, use `--run-ignored all`.

### 5.3 Honesty Rule

Never claim work is complete, fixed, or passing without having run the gate and
seen it pass. When reporting, **name what you ran and quote the summary line**
— e.g. "`cargo nextest run --workspace`: all passed, ignored tests skipped" —
so the reader knows what was and was not covered. Claiming a gate you did not run is
worse than running none.

### 5.4 nextest Gotchas

- **nextest does not run doctests.** `cargo nextest run` silently ignores them.
  Nothing is lost today — the only fenced blocks in this workspace's doc
  comments are ` ```text ` and ` ```cddl `, which rustdoc never compiles. But if
  you write a real Rust doctest, running it is on you: add `cargo test --doc`,
  because nothing else will.
- **Every test gets its own process.** A test can no longer depend on a sibling
  in the same binary having initialised global state first, and process-global
  caches are no longer shared between tests. This is why nextest is structurally
  immune to the class of flake recorded in
  `docs/superpowers/changes/2026-08-02-tracing-callsite-interest-flake.md` — and
  equally, why a test that silently *relied* on such sharing will now fail
  honestly.
- **Filters are positional; there is no `--` separator.** Write
  `cargo nextest run -p foundry --test wallet_issuance full_issuance_flow_end_to_end`.
- **`--nocapture` is spelled `--no-capture`.**

### 5.5 Keeping the Gate Fast

The gate is only fast while `target/` stays small. Cargo caches every distinct
command shape separately and **never evicts**, so artifacts accumulate without
bound. Once `target/` had reached 113 GB — over a million entries in
`target/debug/deps` — identical cold builds ran **15–49× slower**. Not because
cargo re-scans the tree (no-op invocations stay sub-second even then) but because
*writing* new artifacts into a directory that large is slow. The full
investigation, including the recommendations that measurement refuted, is
[`docs/superpowers/changes/2026-08-18-build-performance-investigation.md`](docs/superpowers/changes/2026-08-18-build-performance-investigation.md).

Three rules follow:

- **Prefer the canonical shapes.** §5.1's "one gate, no tiers" is a cache rule as
  much as a coverage rule: every novel `-p` / `--lib` / filter combination mints a
  new fingerprint set, pays a cold build once, and is then retained forever.
  Scoped runs are not cheaper — they are an extra cache.
- **Sweep periodically.** `cargo sweep --time 14`, or `cargo sweep --maxsize 15GB`
  for a hard ceiling; `cargo sweep --installed` after a toolchain bump. Audit with
  `du -sh target` — a healthy full `--all-targets` build is a few GB, not tens.
  Do not wait for the corrective `cargo clean`: deleting a bloated tree takes
  ~20 minutes, far longer than the ~30 s rebuild that follows it.
- **Do not let the editor share the build lock.** `.vscode/settings.json` sets
  `rust-analyzer.cargo.targetDir` so rust-analyzer's `checkOnSave` flycheck gets
  its own directory. Without it, a save in the editor stalls the next `cargo`
  command on `Blocking waiting for file lock on build directory`. Keep it set.

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
| --- | --- | --- |
| Implementer — transcription / 1–2 files | `mechanical-implementer` | Fast / cheap |
| Implementer — multi-file / integration | `integration-implementer` | Standard |
| Per-task reviewer (spec + quality gate) | `task-reviewer` | Standard |
| Final whole-branch review | `final-reviewer` | Most capable |
| Plan / spec authoring | `architect` | Most capable |
| Fix subagent | matching implementer | Matches original task tier |

**When dispatching a subagent scoped to one crate, tell it to read that crate's
`AGENTS.md` first** — it starts with fresh context and will not have this root
file's routing table.

**Tell every implementer and reviewer that the gate is §5.1, and that the runner
is `cargo nextest run`, not `cargo test`.** There is one gate and it is the
whole workspace — a subagent has no cheaper tier to pick and no affected-crate
set to derive. A subagent starting with fresh context will reach for
`cargo test -p <crate>` out of habit unless told otherwise, and will then be
waiting minutes for an answer that nextest returns in seconds. The
`final-reviewer` additionally runs the E2E suite of §5.2 at the end of the
branch.

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
  spec file in `docs/specs/`** → add or update its row in the §4.4 table. A
  governing document that cannot be committed gets a **reference stub** instead,
  under §4.4's external-reference rule.
- **Closing a conformance gap** → update the affected rows in
  `docs/conformance/openid4vc-conformance.md` and remove the `#[ignore]` from
  the test that cites that gap ID. The report is a living document, not a
  historical record.
- **No line counts, test counts, or other per-commit-drifting numbers** in any
  AGENTS.md — stale numbers erode trust in the whole file.
- Design rationale for this structure: `docs/superpowers/specs/2026-07-28-agents-md-discovery-design.md`.
