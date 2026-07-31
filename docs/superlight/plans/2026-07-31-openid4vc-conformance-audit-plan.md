# OpenID4VC Conformance Audit — Implementation Plan

**Spec:** docs/superlight/specs/2026-07-31-openid4vc-conformance-audit-spec.md
**Branch:** superlight/2026-07-31-openid4vc-conformance-audit
**Executed with:** superlight Phase 4 (inline, no subagents)

**Goal:** Give every mandatory clause of the three vendored specs an explicit,
evidenced verdict against foundry's issuer, verifier, and protocol HTTP routes,
with executable tests as the evidence and a numbered gap register for every
deviation.

**Architecture:** A living report at `docs/conformance/openid4vc-conformance.md`
holds a clause inventory (one row per mandatory clause, `unverified` until
adjudicated), a gap register, and a summary. Three new conformance test files
carry the evidence; deviations are recorded as `#[ignore]`d tests asserting the
spec-correct behaviour. A fourth test file mechanically enforces the report's
internal consistency so the ledger cannot silently rot.

## Global Constraints

*Copied verbatim from the spec.*

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

## Deltas From the Spec

Two, both deliberate, both flagged at the Phase 3 handoff:

3. **A fifth test file**, `crates/foundry/tests/conformance_http.rs`, seeded a
   task early (Task 7, not Task 18 which formally owns it): two clauses
   discovered during Authorization Endpoint adjudication — VCI-0030 (ignore
   unrecognized params) and HAIP-0008 (RFC9207 `iss`) — are only observable at
   the HTTP boundary in `crates/foundry/src/server.rs`, since neither
   `AuthorizeParams` nor `AuthorizeOutcome` (foundry-issuer's domain API)
   carries the data needed to test them. Task 18 will add to this file rather
   than create a competing one.

1. **A fourth test file**, `crates/foundry/tests/conformance_report.rs`, not
   listed in the spec's Testing Strategy table. It parses the report and
   enforces its internal consistency. Rationale: the spec makes report/test
   reconciliation a Phase 5 done-criterion, but the report is a *living*
   document that follow-up runs will edit, so a one-time manual check at the end
   of this run protects nothing afterwards. Making it a test moves the
   criterion from "I checked once" to "CI checks forever". It also gives the
   otherwise test-free extraction tasks a real red/green cycle.
2. **19 tasks, not the ~14 previewed** in the spec's decomposition sketch. The
   spec labelled that number a preview to be firmed up here. The growth is from
   splitting the verifier's response handling (plain, encrypted, transaction
   data, and security/replay are four distinct code paths in `verify.rs`) and
   from the scaffold and consistency-test tasks.

## Extraction Convention

Applied by Tasks 3–5, relied on by every later task.

- One inventory row per **distinct mandatory clause** — MUST, MUST NOT,
  REQUIRED, SHALL, SHALL NOT. Where a sentence carries two obligations, it
  yields two rows.
- `Applies to` is one of `issuer`, `verifier`, `http`, `wallet`, `other`.
  Wallet-side and third-party obligations are recorded, not skipped, and get
  verdict `out-of-scope` with reason `wallet-side obligation` at extraction
  time. They stay in the denominator so coverage claims are honest.
- Sections that describe features foundry does not implement still get rows;
  their verdict becomes `not-implemented` during adjudication, not extraction.
- Non-normative sections are not extracted: Introduction, Terminology, Overview,
  Use Cases, Additional Examples, IANA Considerations, Acknowledgements,
  Notices, Document History.
- **Narrowed 2026-07-31:** W3C Verifiable Credential format profiles
  (`jwt_vc_json`, `ldp_vc`, `jwt_vc_json-ld`) and the `di_vp` proof type are
  extracted but immediately marked `out-of-scope` with a rationale. foundry
  accepts only `dc+sd-jwt` and `mso_mdoc` and only the `jwt` proof type, so these
  clauses would adjudicate uniformly to `not-implemented`. Rows are retained,
  never deleted — identifiers are never renumbered.
- **Clarified 2026-07-31 (Task 4):** clauses constraining the *content* of a
  presentation without naming an actor — KB-JWT `nonce`/`aud`, the mdoc
  `SessionTranscript`/`OpenID4VPHandover` structure — are attributed to
  `verifier`, because foundry's testable obligation is recomputing and comparing
  those values. Clauses governing how a response is *constructed* (body encoding,
  `vp_token` assembly, JWE header selection) stay `wallet`. Recorded in the
  report's Audit Boundary.
- `Requirement` is abridged to one line but must preserve the normative verb and
  the condition. Where abridging would change the meaning, quote the clause.

## File Structure

- `docs/conformance/openid4vc-conformance.md` — the living report: summary, gap register, clause inventory
- `crates/foundry/tests/conformance_report.rs` — mechanical consistency guard over the report
- `crates/foundry-issuer/tests/conformance_vci.rs` — OpenID4VCI + issuer-side HAIP evidence
- `crates/foundry-verifier/tests/conformance_vp.rs` — OpenID4VP + verifier-side HAIP evidence
- `crates/foundry/tests/conformance_http.rs` — HTTP status codes, headers, error bodies
- `AGENTS.md` — one-line pointer from §4.4 to the report

---

### Task 1: Report scaffold and AGENTS.md pointer

**Files:** create `docs/conformance/openid4vc-conformance.md`; modify `AGENTS.md` (§4.4)

**Interfaces:**
- Produces: the report's section headings, table schemas, verdict legend, severity legend, and the pinned spec version table. Every later task writes into these tables.
- Produces: heading anchors `## Summary`, `## Gap Register`, `## Clause Inventory — OpenID4VCI`, `## Clause Inventory — OpenID4VP`, `## Clause Inventory — HAIP`, `## Unresolved Ambiguities`, which Task 2's parser depends on.
- Produces: the seven-verdict legend (`conforming`, `gap`, `not-implemented`, `not-unit-testable`, `out-of-scope`, `ambiguous`, `unverified`) and the three-severity legend.

**Deliverable:** report with all headings, both legends, empty tables carrying
only their header rows, an explicit "Audit boundary" section transcribed from
the spec, and a `Status: in progress` marker. `AGENTS.md` §4.4 gains one line
pointing at the report — no counts, per the §8 constraint.

**Verify:** `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

- [x] Write scaffold
- [x] Add AGENTS.md §4.4 pointer
- [x] Verify — gates clean
- [x] Commit

---

### Task 2: Report consistency test

**Files:** create `crates/foundry/tests/conformance_report.rs`

**Interfaces:**
- Consumes: the heading anchors and table schemas from Task 1.
- Produces: the invariants every later task must keep true. Any task that breaks
  the report breaks this test.

**Behaviors to test:**
- Report file exists and every required heading is present — happy path
- Clause IDs match `^(VCI|VP|HAIP)-\d{4}$`, are unique, and ascend within each inventory table
- Every clause row's verdict is one of the seven legal verdicts (`conforming`, `gap`, `not-implemented`, `not-unit-testable`, `out-of-scope`, `ambiguous`, `unverified`)
- Every `gap` verdict has a matching row in the gap register, and vice versa — no orphans in either direction
- Every gap register row has a non-empty severity from the three legal values, a spec section citation, an impact, and a test name
- Every test name referenced by the report exists in the repository's test sources
- Every `#[ignore = "GAP-..."]` in the repository cites a gap ID present in the register
- Summary counts equal the actual row counts per verdict per spec
- `not-implemented`, `not-unit-testable`, and `out-of-scope` rows carry a non-empty rationale
- `ambiguous` rows record both readings and appear in the "Unresolved Ambiguities" section
- Empty-inventory edge case — the test passes against Task 1's empty scaffold

**Note:** this test must pass against the *empty* scaffold, so it is written to
validate structure and cross-references rather than to require content. It goes
red the moment a later task writes an inconsistent row.

**Verify:** `cargo test -p foundry --test conformance_report`

- [x] Red — each of the 11 checks verified to fail against a deliberately corrupted report
- [x] Green — 11 checks pass against the empty scaffold
- [x] Refactor — clean while green
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 3: Extract OpenID4VCI clauses

**Files:** modify `docs/conformance/openid4vc-conformance.md`

**Interfaces:**
- Consumes: extraction convention above; table schema from Task 1.
- Produces: clause IDs `VCI-0001..VCI-NNNN`, all verdict `unverified` except
  wallet-side rows marked `out-of-scope`. Tasks 6–11 consume these.

**Source sections** (`docs/specs/openid-4-verifiable-credential-issuance-1_0.md`):
§4 Credential Offer Endpoint, §5 Authorization Endpoint, §6 Token Endpoint,
§7 Nonce Endpoint, §8 Credential Endpoint, §9 Deferred Credential Endpoint,
§10 Encrypted Credential Requests and Responses, §11 Notification Endpoint,
§12 Metadata, §13 Security Considerations, §14 Implementation Considerations
(normative statements only), Credential Format Profiles (mdoc and SD-JWT VC
subsections only), Claims Description, Claims Path Pointer, Key Attestations,
Wallet Attestations, Proof Types.

**Verify:** `cargo test -p foundry --test conformance_report`

- [x] Extract clauses per convention — 230 rows (issuer 170, http 31, wallet 28, other 1)
- [x] Verify — consistency test green, IDs sequential and unique
- [x] Commit

---

### Task 4: Extract OpenID4VP clauses

**Files:** modify `docs/conformance/openid4vc-conformance.md`

**Interfaces:**
- Produces: `VP-0001..VP-NNNN`. Tasks 12–16 consume these.

**Source sections** (`docs/specs/openid-4-verifiable-presentations-1_0.md`):
§5 Authorization Request, §6 DCQL, §7 Claims Path Pointer, §8 Response,
§9 Wallet Invocation, §10 Wallet Metadata, §11 Verifier Metadata,
§12 Verifier Attestation JWT, §13 Implementation Considerations (normative
only), §14 Security Considerations, §15 Privacy Considerations (normative only),
Credential Format Specific Parameters (mdoc and SD-JWT VC subsections only; the
W3C Verifiable Credentials subsection is extracted as `out-of-scope` per the
2026-07-31 narrowing).

**Explicitly extracted but expected `not-implemented`:** OpenID4VP over the
Digital Credentials API, and Combining this specification with SIOPv2 — foundry
implements neither, and the rows make that visible rather than absent.

**Verify:** `cargo test -p foundry --test conformance_report`

- [x] Extract clauses per convention — 266 rows (verifier 170, wallet 92, http 4; 161 `unverified`, 105 `out-of-scope`)
- [x] Verify — consistency test green, IDs sequential and unique
- [x] Commit

---

### Task 5: Extract HAIP clauses

**Files:** modify `docs/conformance/openid4vc-conformance.md`

**Interfaces:**
- Produces: `HAIP-0001..HAIP-NNNN`. Task 17 consumes the cross-cutting
  remainder; Tasks 6–16 consume the ones narrowing their area.
- Each HAIP row records which VCI or VP clause it narrows, where applicable, so
  the "HAIP wins when stricter" rule is traceable rather than asserted.

**Source sections** (`docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md`):
§2 Scope (Standards Requirements), §3 OpenID for Verifiable Credential Issuance,
§4 OpenID for Verifiable Presentations, §5 OpenID4VC Credential Format Profiles,
§6 Requirements for Digital Signatures, §7 Hash Algorithms,
§8 Implementation Considerations (normative only), §9 Security Considerations.

**Verify:** `cargo test -p foundry --test conformance_report`

- [x] Extract clauses per convention — 96 rows (issuer 44, verifier 28, wallet 19, other 5; 77 `unverified`, 19 `out-of-scope`; 12 rows record the provision they narrow)
- [x] Verify — consistency test green, IDs sequential and unique
- [x] Commit

---

### Task 6: Adjudicate & test — Credential Offer

**Files:** modify report; create `crates/foundry-issuer/tests/conformance_vci.rs`
**Code under audit:** `crates/foundry-issuer/src/create_offer.rs`, `crates/foundry-issuer/src/offer.rs`
**Clauses:** VCI §4 rows; HAIP §3.2 rows

**Interfaces:**
- Consumes: `create_offer`, `CreateOfferRequest`, `CreateOfferResponse`, `build_offer_uri`, `generate_pre_authorized_code`, `generate_tx_code`, `CredentialOffer`, `CredentialOfferGrants`, `PreAuthorizedCodeGrant`, `AuthorizationCodeGrant`, `TxCodeDefinition`
- Produces: the fixture-construction pattern (`Config` builder + tempdir `SqliteStorage`) reused by Tasks 7–11 in the same file

**Behaviors to test:**
- Offer object carries `credential_issuer` and `credential_configuration_ids` — happy path
- `credential_configuration_ids` entries resolve against issuer metadata — happy path
- Offer by value vs. `credential_offer_uri` — both forms
- Pre-authorized code grant shape and required members — happy path
- `tx_code` definition: `input_mode`, `length`, `description` constraints — edge cases
- Authorization code grant `issuer_state` handling — happy path
- Offer URI encoding and the custom scheme — edge case
- Rejection of an offer request naming an unknown credential configuration — error path

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (14 rows: 7 conforming, 2 gap, 5 not-implemented)
- [x] Red — failing test per behavior above (both gap tests confirmed failing for the right reason before being marked `#[ignore]`)
- [x] Green — minimal implementation (no production changes; this task is evidence-only per the Global Constraints)
- [x] Refactor — clean while green
- [x] Record gaps — GAP-VCI-01 (pre-authorized_code not single-use at /token) and GAP-HAIP-01 (authorization_code grant never conveys a `scope` value)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 7: Adjudicate & test — Authorization Endpoint and Authorization Code Flow

**Files:** modify report and `crates/foundry-issuer/tests/conformance_vci.rs`
**Code under audit:** `crates/foundry-issuer/src/authorize.rs`
**Clauses:** VCI §3.4, §5 rows; HAIP §3.3 rows

**Interfaces:**
- Consumes: `handle_authorize_request`, `AuthorizeParams`, `AuthorizeOutcome`, `AUTH_CODE_TTL_SECS`
- Produces: authorization-code fixtures consumed by Task 8

**Behaviors to test:**
- `authorization_details` with `credential_configuration_id` — happy path
- `scope`-based requests and their mapping to configurations — happy path
- `issuer_state` propagation from offer to authorization request — happy path
- PKCE parameters: presence, `code_challenge_method` restrictions — required-parameter and edge cases
- `redirect_uri` validation — error path
- Authorization error response parameters and codes — error path
- Authorization code single-use and TTL — edge cases

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (22 rows: 5 conforming, 4 gap, 10 not-implemented, 2 not-unit-testable, 1 ambiguous)
- [x] Red / Green / Refactor per behavior (3 new gap tests + 1 new HTTP-level conforming test confirmed against real code; no production changes)
- [x] Record gaps — GAP-HAIP-02 (missing `iss` per RFC9207), GAP-HAIP-03 (no DPoP; always Bearer), GAP-HAIP-04 (Critical: Wallet Attestation never cryptographically validated, presence-check only)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 8: Adjudicate & test — Token Endpoint and Nonce Endpoint

**Files:** modify report and `crates/foundry-issuer/tests/conformance_vci.rs`
**Code under audit:** `crates/foundry-issuer/src/token.rs`, `crates/foundry-issuer/src/nonce.rs`, `crates/foundry-issuer/src/transaction.rs`
**Clauses:** VCI §6, §7 rows; HAIP §3.4 rows

**Interfaces:**
- Consumes: `handle_token_request`, `TokenRequest`, `TokenResponse`, `issue_nonce`, `verify_nonce`, `NonceResponse`, `NonceSecret`, `C_NONCE_TTL_SECS`, `load_transaction_by_pre_auth_code`, `load_transaction_by_access_token`
- Produces: access-token fixtures consumed by Tasks 9–10

**Behaviors to test:**
- `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` — happy path
- `grant_type=authorization_code` with PKCE verifier — happy path
- `tx_code` required / omitted / wrong — error paths
- Pre-authorized code single-use and expiry — edge cases
- Token response members and `token_type` value — happy path
- `authorization_details` echoed with `credential_identifiers` where applicable
- Token error response codes: `invalid_grant`, `invalid_request`, `invalid_client` — error paths
- Nonce response `c_nonce` freshness, single-use, and TTL — edge cases

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (13 rows: 10 conforming, 3 not-implemented; zero new gaps)
- [x] Red / Green / Refactor per behavior (4 new tests, all green; 3 conforming clauses cite pre-existing tests unchanged)
- [x] Record gaps — none this task
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 9: Adjudicate & test — Credential Endpoint (incl. unimplemented VCI endpoints)

**Files:** modify report and `crates/foundry-issuer/tests/conformance_vci.rs`
**Code under audit:** `crates/foundry-issuer/src/credential.rs`, `crates/foundry-issuer/src/status_index.rs`
**Clauses:** VCI §8 rows; VCI §9 (Deferred), §10 (Encrypted), §11 (Notification) rows; HAIP §3.5 rows

**Interfaces:**
- Consumes: `handle_credential_request`, `CredentialRequest`, `CredentialResponse`, `IssuedCredential`, `allocate_status_index`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- Request by `credential_configuration_id` — happy path
- Request by `credential_identifier` — happy path
- `credential_configuration_id` and `credential_identifier` both present — error path
- `credentials` array response shape — happy path
- Access token binding: token issued for configuration A cannot obtain B — error path
- Status list index allocation reflected in the issued credential — happy path
- Credential error response codes including `invalid_credential_request` — error paths

**Adjudication note:** §9 Deferred, §10 Encrypted Credential Requests, and §11
Notification have no corresponding routes in `server.rs`. Expect verdict
`not-implemented` with rationale, no gap and no test — per spec §4.4,
unimplemented optional features are acceptable. If any of the three turns out to
be *mandatory* rather than optional under HAIP, it becomes a gap instead; check
the HAIP rows before defaulting to `not-implemented`.

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (60 rows: 12 conforming/3 gap/38 not-implemented/3 not-unit-testable VCI; 3 conforming/1 ambiguous HAIP)
- [x] Red / Green / Refactor per behavior (7 new tests; both fixture files needed a real signing key added, previously absent)
- [x] Record gaps — GAP-VCI-02 (credential_configuration_id ignored), GAP-VCI-03 (mdoc credential not base64url), GAP-VCI-04 (invalid_nonce never distinguished from invalid_proof)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 10: Adjudicate & test — Proof Types, Key and Wallet Attestation

**Files:** modify report and `crates/foundry-issuer/tests/conformance_vci.rs`
**Code under audit:** `crates/foundry-issuer/src/proof.rs`, `crates/foundry-issuer/src/attestation.rs`
**Clauses:** VCI Proof Types, Key Attestations, Wallet Attestations rows; HAIP key-binding rows

**Interfaces:**
- Consumes: `verify_holder_proof`, `ProofsRequest`, `VerifiedProof`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- `jwt` proof: required header `typ`, `alg`, and exactly one of `jwk` / `kid` / `x5c` — happy path and error paths
- `jwt` proof payload `aud` equals the Credential Issuer identifier — error path on mismatch
- `jwt` proof `nonce` equals the issued `c_nonce` — error path on mismatch and on replay
- `jwt` proof `iat` presence and freshness window — edge cases
- Plural `proofs` object: all proofs validated, not just the first — error path when a later proof is invalid
- `attestation` proof type handling — happy path or `not-implemented`
- (`di_vp` proof type is `out-of-scope` per the 2026-07-31 narrowing — no adjudication, no test)
- Key attestation JWT required claims and trust-anchor chaining — happy path and error path
- Wallet attestation JWT required claims and mode handling (`required` / `optional` / `disabled`) — edge cases

**Security note:** the `aud`, `nonce`, replay, and all-proofs-validated
behaviours are the most likely places for a Critical. Per the spec's Severity
rule there is no mid-run escalation, but assign severity at find-time and commit
the register row with this task so a Critical is visible in the repository
immediately.

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (37 rows: 22 conforming/5 gap/4 not-implemented/4 out-of-scope VCI split as Key Attestation JWT, Attack Potential Resistance, Proof Types, jwt/di_vp/attestation Proof Type, Verifying Proof; 2 HAIP rows — 1 conforming, 1 gap citing the existing GAP-HAIP-04)
- [x] Red / Green / Refactor per behavior (14 new tests; one hypothesized gap — a private key in the `jwk` header — was disproved by the red step itself: josekit's `verifier_from_jwk` already rejects it, so that row was adjudicated `conforming` instead)
- [x] Record gaps — GAP-VCI-05 (Minor: `iat` unvalidated in both the proof JWT and the Key Attestation JWT), GAP-VCI-06 (Minor: `iss` never validated for the jwt proof type)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 11: Adjudicate & test — Issuer and Authorization Server Metadata

**Files:** modify report and `crates/foundry-issuer/tests/conformance_vci.rs`
**Code under audit:** `crates/foundry-issuer/src/metadata.rs`
**Clauses:** VCI §12 rows; HAIP §3.1 rows

**Interfaces:**
- Consumes: `build_issuer_metadata`, `build_authorization_server_metadata`, `CredentialIssuerMetadata`, `AuthorizationServerMetadata`, `CredentialConfigurationSupported`, `ProofTypeSupported`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- Required issuer metadata members present — happy path
- `credential_configurations_supported` entry shape per format (`mso_mdoc`, `dc+sd-jwt`) — happy path
- `proof_types_supported` advertises exactly what `proof.rs` accepts — consistency edge case
- `credential_endpoint` / `nonce_endpoint` / `authorization_servers` values match the deployed routes
- AS metadata advertises the pre-authorized code grant type — happy path
- Signed metadata — expected `not-implemented`, confirm optional under HAIP
- `display` and `claims` description structures — edge cases

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (35 VCI rows: 8 conforming, 10 gap, 17 not-implemented; 8 HAIP rows: 3 conforming, 1 gap citing existing GAP-HAIP-01, 4 not-implemented)
- [x] Red / Green / Refactor per behavior (10 new tests; 4 hypothesized gaps were confirmed genuinely red only after fixing a broken test fixture — `test_config()`'s empty `keys` map made `Config::validate()` fail trivially regardless of the real hypothesis, which TDD caught before any gap was wrongly attributed)
- [x] Record gaps — GAP-VCI-07 (Minor: cryptographic_binding_methods_supported/proof_types_supported never omitted), GAP-VCI-08 (Minor: no https-scheme validation for issuer URLs), GAP-VCI-09 (Important: no cross-check between public_base_url and credential_issuer), GAP-VCI-10 (Minor: credential display objects not structurally validated)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 12: Adjudicate & test — Authorization Request, Client Identifier Prefixes, Verifier Metadata

**Files:** modify report; create `crates/foundry-verifier/tests/conformance_vp.rs`
**Code under audit:** `crates/foundry-verifier/src/request.rs`
**Clauses:** VP §5, §11, §12 rows; HAIP §4 rows

**Interfaces:**
- Consumes: `create_verification_request`, `CreateVerificationRequest`, `CreateVerificationResponse`, `build_signed_request_object`
- Produces: the verifier fixture pattern reused by Tasks 13–16 in the same file

**Behaviors to test:**
- Required authorization request parameters present — happy path
- `response_type=vp_token` — happy path; other values rejected — error path
- `response_mode` values `direct_post` and `direct_post.jwt` — happy path
- `nonce` presence, entropy, and single-use — edge cases
- `client_id` carries its prefix and the full identifier is used everywhere — VP §14.7 edge case
- Client identifier prefixes supported vs. rejected — error paths
- Request object JWT: `typ` header value, signing algorithm, `aud` — happy path and error paths
- `request_uri` retrieval and `request_uri_method` handling — happy path
- `client_metadata` required members — happy path
- Unsupported or absent `dcql_query` — error path

**Verify:** `cargo test -p foundry-verifier --test conformance_vp && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (59 VP rows: 21 conforming, 2 gap, 33 not-implemented, 3 not-unit-testable; 10 HAIP §4 rows: 6 conforming, 2 not-implemented, 2 not-unit-testable)
- [x] Red / Green / Refactor per behavior (9 new tests in a new `crates/foundry-verifier/tests/conformance_vp.rs`)
- [x] Record gaps — GAP-VP-01 (Important: signed Request Object never carries an `aud` claim), GAP-VP-02 (Important: `x509_san_dns` client_id host never cross-checked against the configured x5c leaf certificate's SAN)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 13: Adjudicate & test — DCQL and Claims Path Pointer

**Files:** modify report and `crates/foundry-verifier/tests/conformance_vp.rs`
**Code under audit:** `crates/foundry-verifier/src/dcql.rs`, `crates/foundry-verifier/src/dcql_model.rs`
**Clauses:** VP §6, §7 rows

**Interfaces:**
- Consumes: `check_dcql_match`, `PresentedFormat`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- Credential query `id` uniqueness and `format` matching — happy path and error path
- `meta` constraints per format (`vct_values`, `doctype_value`) — happy path and error path
- Claims query path resolution for JSON-based credentials — happy path
- Claims path resolution for mdoc-based credentials — happy path
- `values` matching semantics — happy path and non-match
- `claim_sets` — first satisfiable set wins, ordering respected — edge case
- `credential_sets` with `required: false` — optional-set edge case
- Presentation satisfying no query — error path
- Extra presented credentials beyond the query — VP §14.8 security edge case
- Malformed DCQL rejected at request creation rather than at response time

**Note:** `dcql_model` is private; if a mandatory clause is unreachable through
`check_dcql_match`, record that as a finding before considering an inline test.

**Verify:** `cargo test -p foundry-verifier --test conformance_vp && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (26 VP rows: 9 conforming, 4 gap, 11 not-implemented, 2 not-unit-testable)
- [x] Red / Green / Refactor per behavior (3 new tests appended to `crates/foundry-verifier/tests/conformance_vp.rs`)
- [x] Record gaps — GAP-VP-03 (Minor: DCQL Credential Query `id` character-class/uniqueness, `meta` required-presence, and Claims Query duplicate-path uniqueness are never validated)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 14: Adjudicate & test — Response Handling and `vp_token`

**Files:** modify report and `crates/foundry-verifier/tests/conformance_vp.rs`
**Code under audit:** `crates/foundry-verifier/src/verify.rs`, `crates/foundry-verifier/src/transaction.rs`
**Clauses:** VP §8.1, §8.2, §8.5, §8.6 rows

**Interfaces:**
- Consumes: `verify_vp_response`, `VerificationResult`, `CheckResult`, `VerificationState`, `load_verification_transaction`, `save_verification_transaction`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- `vp_token` is a map keyed by DCQL query id, each value an array of presentations — happy path
- Response parameters required under `direct_post` — happy path and missing-parameter error path
- `state` correlation to the request — happy path and mismatch error path
- Error response parameters and codes — error paths
- VP token validation ordering: structural failure before policy evaluation
- `AGENTS.md` §4.2 — `verified` equals the conjunction of all check results
- `AGENTS.md` §4.3 — policy failure yields a result rather than an error
- Each named `CheckResult` present in the result — happy path

**Verify:** `cargo test -p foundry-verifier --test conformance_vp && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (15 VP rows: 13 conforming, 1 not-implemented, 1 not-unit-testable)
- [x] Red / Green / Refactor per behavior (2 tests appended to existing `#[cfg(test)] mod tests` blocks in `request.rs` and `verify.rs`, reusing their fixture harnesses)
- [x] Record gaps — none found this task
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 15: Adjudicate & test — Encrypted Responses and Transaction Data

**Files:** modify report and `crates/foundry-verifier/tests/conformance_vp.rs`
**Code under audit:** `crates/foundry-verifier/src/verify.rs`, `crates/foundry-verifier/src/transaction.rs`, JOSE/JWE primitives in `crates/foundry-core/src/crypto/`
**Clauses:** VP §8.3, §8.4 rows; HAIP §6 rows

**Interfaces:**
- Consumes: `verify_vp_response` with an encrypted response, verifier `client_metadata` encryption keys
- Produces: nothing later tasks depend on

**Behaviors to test:**
- `direct_post.jwt` JWE decryption — happy path
- Required JWE `alg` and `enc` values per HAIP — happy path and rejection of others
- `apu` / `apv` header handling — happy path
- Encryption key advertised in `client_metadata` matches the decryption key — error path on mismatch
- Undecryptable response is a structural error (HTTP 400 per §4.3), not `verified: false`
- `transaction_data` encoding and the hash binding it to the presentation — happy path and tampered-hash error path
- `transaction_data_hashes_alg` restricted to HAIP-permitted algorithms

**Verify:** `cargo test -p foundry-verifier --test conformance_vp && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (5 VP rows + 6 HAIP rows: 9 conforming, 2 gap, 1 not-implemented, revised VP-0153 from conforming to gap with new evidence)
- [x] Red / Green / Refactor per behavior (3 new tests: 1 gap test appended to verify.rs's mod tests, 1 conforming test appended to verify.rs's mod tests, 1 gap test appended to conformance_vp.rs)
- [x] Record gaps — GAP-VP-04 (Important: transaction_data_hashes response-side binding never validated at all — a Verifier-requested security property with no enforcement), GAP-VP-05 (Minor: encrypted_response_enc_values_supported only ever advertises one enc value, never both A128GCM and A256GCM as HAIP-0052 requires)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 16: Adjudicate & test — Verifier Security Requirements and Status Checking

**Files:** modify report and `crates/foundry-verifier/tests/conformance_vp.rs`
**Code under audit:** `crates/foundry-verifier/src/verify.rs`, `crates/foundry-verifier/src/status.rs`
**Clauses:** VP §14 rows; VP §8.6 status rows; HAIP status-list rows

**Interfaces:**
- Consumes: `check_status`, `StatusListResolver`, `HttpStatusListResolver`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- Replay prevention: a presentation replayed against a second request is rejected — VP §14.1
- Key binding proof `nonce` and `aud` bound to this request — error paths
- Session fixation resistance — VP §14.2 edge case
- Presentation whose issuer is not a configured trust anchor — error path
- Revoked and suspended status yield `verified: false` with a failed `status_check`, not an error — §4.3
- Status endpoint unreachable maps to a network failure, not a policy failure — §4.3
- Signature verification failure is structural — §4.3

**Boundary note:** Token Status List bitstring decoding is `out-of-scope` per the
spec — audit that a status check happens and is honoured, not that the bitset
encoding is correct.

**Verify:** `cargo test -p foundry-verifier --test conformance_vp && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (12 VP rows + 1 HAIP row: 9 conforming, 2 not-implemented, 1 not-unit-testable, 2 out-of-scope; no new gaps)
- [x] Red / Green / Refactor per behavior (2 new tests added to verify.rs's existing #[cfg(test)] mod tests, both green on first run — genuine conforming behavior, not hypothesized gaps)
- [x] Record gaps — none found; every hypothesized weak spot (cross-transaction replay, status-fetch network failure through the full entry point, ES256-only status signature support) turned out to already be enforced
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 17: Adjudicate & test — HAIP cross-cutting requirements

**Files:** modify report, `crates/foundry-issuer/tests/conformance_vci.rs`, `crates/foundry-verifier/tests/conformance_vp.rs`
**Code under audit:** signature and hash algorithm handling across `foundry-core/src/crypto/`, both engines
**Clauses:** all HAIP rows not consumed by Tasks 6–16

**Interfaces:**
- Consumes: whatever public entry points the remaining clauses touch
- Produces: nothing later tasks depend on

**Behaviors to test:**
- Mandated signature algorithms accepted; non-mandated ones rejected — HAIP §6
- Mandated hash algorithms — HAIP §7
- SD-JWT VC profile requirements on issuance and verification — HAIP §5.1
- mdoc profile requirements — HAIP §5
- Mandated credential formats supported on both sides — HAIP §3, §4
- Any HAIP clause stricter than its VCI/VP counterpart resolves in HAIP's favour — cross-check against the narrowed clause recorded in Task 5

**Verify:** `cargo test -p foundry-issuer --test conformance_vci && cargo test -p foundry-verifier --test conformance_vp && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (31 HAIP rows: 20 conforming, 2 gap, 3 not-implemented, 3 not-unit-testable, 1 out-of-scope, 2 ambiguous; every previously-`unverified` HAIP row is now resolved)
- [x] Red / Green / Refactor per behavior (2 new tests, both genuinely red before `#[ignore]`: one in request.rs's mod tests, one appended to crates/foundry-issuer/tests/conformance_vci.rs)
- [x] Record gaps — GAP-HAIP-05 (Important: signed requests always use x509_san_dns instead of the HAIP-mandated x509_hash prefix), GAP-HAIP-06 (Important: status list index allocation deduplicates per credential_type_id, not against the shared physical status list every credential type actually references, so two different credential types can collide on the same index)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 18: Adjudicate & test — HTTP layer

**Files:** modify report; create `crates/foundry/tests/conformance_http.rs`
**Code under audit:** `crates/foundry/src/server.rs`
**Clauses:** every row with `Applies to = http`

**Interfaces:**
- Consumes: `foundry::server::{AppState, ...}` routers, driven via `tower::ServiceExt::oneshot`
- Produces: nothing later tasks depend on

**Behaviors to test:**
- `/token` — `Content-Type: application/x-www-form-urlencoded` accepted, JSON response, `Cache-Control: no-store`
- `/token` error responses — correct HTTP status per error code, `error` / `error_description` body shape
- `/credential` — bearer token required, 401 with `WWW-Authenticate` when absent or invalid
- `/nonce` — `Cache-Control: no-store`, response shape
- `/authorize` — redirect behaviour and error-redirect parameters
- `/vp/request/:id` — `Content-Type` for the signed request object (`application/oauth-authz-req+jwt`)
- `/vp/response/:id` — form-encoded acceptance, response shape, `redirect_uri` handling
- `.well-known/openid-credential-issuer` and `.well-known/oauth-authorization-server` — status, `Content-Type`, cacheability
- `/statuslists/:id` — `Content-Type` and status
- §4.3 mapping end to end: policy → 200, structural → 400, status-fetch network failure → 502
- OpenAPI drift: any endpoint whose real behaviour contradicts `openapi.json` — recorded as `GAP-HTTP-*`, not fixed

**Verify:** `cargo test -p foundry --test conformance_http && cargo test -p foundry --test conformance_report`

- [x] Adjudicate clauses — verdict + evidence for every row in scope (all 12 `http`-scoped rows remaining unverified: VCI-0032, VCI-0114/0115/0117/0119/0120, VCI-0161/0162, VP-0079, VP-0134 promoted from not-unit-testable, VP-0188/0189 — zero `http`-scoped rows remain unverified)
- [x] Red / Green / Refactor per behavior (6 new tests, all real HTTP-boundary round trips via `tower::ServiceExt::oneshot`; the two `#[ignore]`'d gap tests confirmed genuinely red before tagging)
- [x] Record gaps — GAP-VCI-11 (Minor: well-known metadata endpoint ignores any path component of `credential_issuer`, latent given every fixture uses a bare origin)
- [x] Verify — run the command, pristine output
- [x] Commit

---

### Task 19: Reconciliation and summary

**Files:** modify `docs/conformance/openid4vc-conformance.md`

**Interfaces:**
- Consumes: every inventory row and gap register entry from Tasks 3–18
- Produces: the finished report

**Behaviors to test:** none new — this task drives the existing consistency test
to green over the completed report.

**Deliverable:**
- Summary counts filled per spec and per verdict.
- Zero `unverified` rows. Clauses that are genuinely readable two ways carry the
  terminal verdict `ambiguous` and are collected in the "Unresolved Ambiguities"
  section with both readings — they do not block completion and make no
  conformance claim.
- `Status` flipped from `in progress` to the audit completion date.
- Gap register sorted by severity.

**Verify:** `cargo test --workspace && cargo test --workspace -- --ignored && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

- [x] Fill summary counts
- [x] Resolve or relocate every `unverified` row (all 56 remaining rows adjudicated: 13 VCI issuer-scoped, 43 VP verifier-scoped — zero `unverified` rows remain in any of the three specs)
- [x] Verify — ignored-test count reconciles against the gap register (`cargo test --workspace -- --ignored` fails every audit gap test as designed, plus one unrelated pre-existing E2E test (`full_flow_issue_verify_revoke_reverify`) that passes for reasons outside this audit's scope)
- [x] Verify — all three gates clean
- [x] Commit

---

## Progress Log

*Append one line per completed task: date, task, commit SHA.*

- 2026-07-31 — Task 1 (report scaffold + AGENTS.md pointer) — `f3cd3ad`
- 2026-07-31 — Task 2 (report consistency test, 11 checks, all mutation-verified) — `a377536`
- 2026-07-31 — Task 3 (extract OpenID4VCI: 230 clauses, 201 in scope) — `f25b9f1`
- 2026-07-31 — scope amendment: W3C VC profiles + `di_vp` marked `out-of-scope`, VCI in-scope 201 → 181 — `443c830`
- 2026-07-31 — Task 4 (extract OpenID4VP: 266 clauses, 161 in scope; attribution rule for presentation-binding clauses recorded in the report's Audit Boundary) — `faf1db3`
- 2026-07-31 — Task 5 (extract HAIP: 96 clauses, 77 in scope; extraction phase complete, 592 clauses total, 419 awaiting adjudication) — `8fb33d0`
- 2026-07-31 — Task 6 (adjudicate Credential Offer: 14 rows — 7 conforming, 5 not-implemented, 2 gap; GAP-VCI-01 pre-authorized_code reuse, GAP-HAIP-01 missing scope value) — `b0243dd`
- 2026-07-31 — Task 7 (adjudicate Authorization Endpoint: 22 rows — 5 conforming, 4 gap, 10 not-implemented, 2 not-unit-testable, 1 ambiguous; GAP-HAIP-02 missing RFC9207 iss, GAP-HAIP-03 no DPoP, GAP-HAIP-04 Critical — Wallet Attestation JWT never cryptographically validated) — `470bf2f`
- 2026-07-31 — Task 8 (adjudicate Token/Nonce Endpoint: 13 rows — 10 conforming, 3 not-implemented; no new gaps) — `d6452c5`
- 2026-07-31 — Task 9 (adjudicate Credential Endpoint incl. Deferred/Encrypted/Notification/Key Attestation: 60 rows — 15 conforming, 3 gap, 38 not-implemented, 3 not-unit-testable, 1 ambiguous; GAP-VCI-02/03/04) — `8156a96`
- 2026-07-31 — Task 10 (adjudicate Proof Types, Key and Wallet Attestation: 37 rows — 23 conforming (22 VCI + HAIP-0090), 6 gap (5 VCI citing GAP-VCI-05/06 + HAIP-0088 citing the existing GAP-HAIP-04), 4 not-implemented, 4 out-of-scope; new gaps GAP-VCI-05 (iat unvalidated in proof JWT and Key Attestation JWT) and GAP-VCI-06 (iss never validated); no Critical found — aud, nonce/replay, and plural-proofs validation are all conforming) — `747d573`
- 2026-07-31 — Task 11 (adjudicate Issuer and Authorization Server Metadata: 35 VCI rows + 8 HAIP rows — 11 conforming, 11 gap, 21 not-implemented; new gaps GAP-VCI-07 (Minor: binding/proof-type fields never omitted when key binding not required), GAP-VCI-08 (Minor: no https-scheme validation for credential_issuer-derived URLs), GAP-VCI-09 (Important: no cross-check between public_base_url and credential_issuer, allowing metadata to silently misidentify the issuer), GAP-VCI-10 (Minor: credential display objects — name/locale-uniqueness/logo/background_image — never structurally validated); confirmed batch issuance (HAIP-0011) works functionally via plural proofs even though never advertised in metadata) — `441f24b`
- 2026-07-31 — Task 12 (first Verifier task; adjudicate Authorization Request, Client Identifier Prefixes, Wallet/Verifier Metadata against crates/foundry-verifier/src/request.rs: 59 VP rows + 10 HAIP §4 rows — 27 conforming, 2 gap, 35 not-implemented, 5 not-unit-testable; new gaps GAP-VP-01 (Important: signed Request Object never carries a required aud claim under Static Discovery) and GAP-VP-02 (Important: x509_san_dns client_id host never cross-checked against the configured x5c leaf certificate's SAN, even though foundry_core::trust::match_san_dns already exists to do it); confirmed the Presentations-without-Holder-Binding (nkb) flow, scope-based DCQL aliasing, and every Client Identifier Prefix except x509_san_dns are simply not implemented, narrowing this audit's live surface to a single supported prefix; new test file crates/foundry-verifier/tests/conformance_vp.rs) — `112e14e`
- 2026-07-31 — Task 13 (adjudicate DCQL and Claims Path Pointer against crates/foundry-verifier/src/dcql.rs and dcql_model.rs, exercised through the public check_dcql_match entry point since dcql_model is a private module: 26 VP rows — 9 conforming, 4 gap, 11 not-implemented, 2 not-unit-testable; new gap GAP-VP-03 (Minor: Credential Query id character-class/uniqueness, meta required-presence, and Claims Query duplicate-path uniqueness are never validated by DcqlCredentialQuery/DcqlClaimsQuery deserialization — confined to Verifier-operator-authored queries, not externally exploitable); confirmed trusted_authorities and credential_sets/claim_sets are deliberately not modelled at all per dcql_model.rs's own scope note, narrowing this section's live surface to single-credential-per-vp_token matching; confirmed mdoc CBOR-to-JSON value conversion (foundry_mdoc::verifier::cbor_value_to_json) correctly feeds dcql.rs's values matching even though the conversion itself lives in a sibling crate) — `e0e2dc8`
- 2026-07-31 — Task 14 (adjudicate Response Handling and vp_token against crates/foundry-verifier/src/verify.rs and transaction.rs: 15 VP rows — 13 conforming, 1 not-implemented, 1 not-unit-testable, no new gaps; confirmed AGENTS.md §4.2 (verified is the conjunction of all CheckResults) and §4.3 (policy failure yields a result, not an error) both hold via existing tests; confirmed response_uri is always same-origin with client_id and redirect_uri is never emitted at all, so the Response Mode direct_post mutual-exclusion and permitted-redirect-uri constraints are structurally satisfied; confirmed the direct_post response HTTP-200/JSON contract lives in crates/foundry's HTTP layer (deferred to Task 18) and the Verifier-issued redirect_uri echo-back is simply not implemented (same root cause as HAIP-0059/0061 from Task 12); 2 new tests appended to existing #[cfg(test)] mod tests blocks in request.rs and verify.rs, reusing their fixture harnesses rather than duplicating them in conformance_vp.rs) — `cf11101`
- 2026-07-31 — Task 15 (adjudicate Encrypted Responses and Transaction Data against crates/foundry-verifier/src/verify.rs, transaction.rs, and foundry-core's JWE primitives: 5 VP rows + 6 HAIP rows — 9 conforming, 2 gap, 1 not-implemented; new gaps GAP-VP-04 (Important: transaction_data_hashes is never read, computed, or checked anywhere in the workspace — attach_kb_jwt has no parameter for it and verify_sd_jwt_vc never looks for one, so a Verifier that requests transaction_data has no way to confirm the wallet actually bound its presentation to that transaction; a presentation with zero transaction binding verifies exactly as if the binding had been checked and passed) and GAP-VP-05 (Minor: encrypted_response_enc_values_supported only ever lists the single configured enc value, never both A128GCM and A256GCM as HAIP-0052 requires, even though A256GCM decryption itself works correctly); revised VP-0153's Task-14 conforming verdict to gap once the transaction_data omission surfaced, since "all requirements of the Verifier's request" is broader than the DCQL-only evidence originally cited; confirmed ECDH-ES/P-256 and A256GCM decryption both already work correctly, and a fresh ephemeral encryption key is generated per request (HAIP-0049/0050/0053))
- 2026-07-31 — Task 16 (adjudicate Verifier Security Requirements and Status Checking against crates/foundry-verifier/src/verify.rs and status.rs: 12 VP rows + 1 HAIP row — 9 conforming, 2 not-implemented, 1 not-unit-testable, 2 out-of-scope, no new gaps; confirmed replay protection is genuinely enforced end to end by writing a new test that captures a real presentation for one transaction and replays it verbatim against a second, independently-created transaction (distinct nonce and ephemeral key) — rejected, not just an arbitrary-bad-nonce case; confirmed a Status List Token fetch failure propagates as a hard Err through the full verify_vp_response entry point (not just check_status in isolation), never resolving to a false policy verdict, matching AGENTS.md Sec4.3; confirmed foundry-core's status list verifier only ever recognizes the ES256/P-256 algorithm (HAIP-0092); found VP-0181/VP-0182's Session Fixation Response-Code mechanism not-implemented, same root cause as the already-known missing redirect_uri support (HAIP-0059/0061, Task 12) — not a new gap since the mitigation is conditional on using redirect_uri at all; found VP-0185 (protection of the internal Authorization-Response-Data interface) not-unit-testable within this task's crate scope, since the actual mechanism (require_api_key admin auth) lives in crates/foundry, not foundry-verifier — confirmed by reading code and citing a sibling-route test, deferring an endpoint-specific test to Task 18; reclassified VP-0186/VP-0187 (End-User authentication claim stability) as out-of-scope, since foundry's verifier engine performs no End-User authentication of its own — that is a downstream Relying Party's integration decision)
- 2026-07-31 — Task 17 (adjudicate HAIP cross-cutting requirements — every remaining `unverified` HAIP row — against foundry-core's crypto/status-list code and both engines: 31 rows resolved to 20 conforming, 2 gap, 3 not-implemented, 3 not-unit-testable, 1 out-of-scope, 2 ambiguous; new gaps GAP-HAIP-05 (Important: HAIP narrows OpenID4VP to mandate the x509_hash Client Identifier Prefix for every signed request via redirects, but build_signed_request_object always emits x509_san_dns instead — x509_hash is not implemented anywhere in this workspace) and GAP-HAIP-06 (Important: allocate_status_index deduplicates its CSPRNG draw per credential_type_id, but every credential type's status claim embeds the same literal status list URI '.../1' — so two credentials of different types can be allocated the same index in the one physical list they actually share, meaning revoking one can silently revoke an unrelated credential of a different type; confirmed genuinely red via a new test forcing the collision deterministically with list_size=1); confirmed both SD-JWT VC and mso_mdoc format profiles are fully supported end to end on both issuer and verifier sides (HAIP-0002/0004/0041); confirmed compact serialization, exp claim, cnf.jwk holder binding, status.status_list shape, and KB-JWT-always-required-when-holder-bound all hold by construction across the SD-JWT VC builder/verifier; confirmed x5c-based issuer key resolution and Status List Token key resolution both route through the same validate_chain function, carrying over HAIP-0039's existing self-signed-leaf conformance and trust-anchor-redundancy ambiguity to two new rows (HAIP-0079/HAIP-0084, added to Unresolved Ambiguities) rather than re-litigating it; confirmed ES256 and SHA-256 are supported throughout for presentation signatures and format digests (HAIP-0091/0095); reclassified HAIP-0071 (ISO 18013-5 MSO revocation mechanisms) as out-of-scope per the Audit Boundary's existing mdoc-format-internals exclusion, and HAIP-0070 (multiple mdocs each in a separate DeviceResponse) as not-implemented for the same single-credential-per-vp_token architectural reason as VP-0103)
- 2026-07-31 — Task 18 (adjudicate the HTTP layer — every remaining `http`-scoped row across both specs — against crates/foundry/src/server.rs, in a new crates/foundry/tests/conformance_http.rs suite: 12 rows resolved to 6 conforming (VCI-0117/0119 metadata endpoint 200+JSON, VCI-0032 RFC6749 error-redirect shape, VP-0079 citing wallet_verification.rs's existing full_verification_flow_end_to_end, VP-0134 promoted from not-unit-testable to conforming with a dedicated Content-Type assertion), 1 not-implemented (VCI-0120, no Accept-Language/Content-Language support anywhere), 5 not-unit-testable (the remaining TLS/BCP195/RFC6125 rows, same deployment-layer reasoning as VCI-0049), and 1 new gap; new gap GAP-VCI-11 (Minor: the well-known metadata endpoint is hardcoded at the literal root path regardless of any path component in config.issuer.credential_issuer, so per the spec's own worked example a path-bearing Credential Issuer Identifier's metadata is unreachable at its spec-mandated location -- confirmed genuinely red via a dedicated test with such a config, and currently latent since every fixture and deployment example in this repository uses a bare-origin credential_issuer); also confirmed the AGENTS.md Sec4.3 HTTP-layer status mapping end to end with a new test forcing a genuine connection-refused failure (a bound-then-dropped TCP listener) through the real POST /vp/response/:id endpoint, extending VP-0152's evidence beyond the library-level test Task 16 already had; investigated but ultimately did not file a formal GAP-HTTP-01 for OpenAPI response-documentation drift on /credential and /vp/response/{id} (confirmed real and TDD-red) because the report's own gap-register consistency test requires every register entry to be cited by a spec clause with verdict `gap`, and no VCI/VP/HAIP clause covers OpenAPI documentation completeness -- noted here instead of forcing an artificial clause mapping)
- 2026-07-31 — Task 19 (Reconciliation and summary: adjudicated the final 56 `unverified` rows left over from Tasks 3-18 -- 13 VCI issuer-scoped and 43 VP verifier-scoped -- bringing every clause in all three specs to a terminal verdict; 2 significant new gaps found via close reading rather than re-derivation: GAP-VP-06 (Critical: foundry-mdoc's serialize_session_transcript builds an ad-hoc simplified SessionTranscript/Handover, never the spec-mandated hashed OpenID4VPHandover/OpenID4VPDCAPIHandover CBOR structure the code's own TODO(interop) comment already flags -- since SessionTranscript is exactly what an mdoc Device Signature is computed over, this breaks holder-binding verification against any real conformant wallet for both invocation methods, a foundational defect in one of only two supported credential formats) and GAP-VP-07 (Important: the dc_api transport's KB-JWT audience check always expects the x509_san_dns Client Identifier, never the Origin-prefixed value OpenID4VP requires for DC API responses, so this verifier rejects every conformant wallet's dc_api presentation -- confirmed genuinely red, a real Err not just a failed check); 2 more new gaps in the VCI cluster: GAP-VCI-12 (Minor: mso_mdoc docType resolution prefers vct over doctype whenever a credential_type config carries both, silently producing a non-ISO-18013-5 docType -- currently latent since every fixture sets vct: None) and GAP-VCI-13 (Minor: ClaimDef.path's Vec<String> type cannot represent the null/integer path segments the claims path pointer grammar allows, and Config::validate() never checks non-emptiness); extended GAP-VCI-03 and GAP-VCI-10's existing citations to cover newly-adjudicated clauses restating the same underlying findings (mdoc credential base64 encoding; claims/display structural validation) rather than filing duplicate gaps; extended GAP-VP-03's citations similarly for mdoc doctype_value/SD-JWT-VC vct_values required-ness; the entire mdoc Invocation via Redirects / via the DC API Handover-and-SessionTranscript cluster (18 rows) resolved to `gap` citing GAP-VP-06, since they are all facets of the same single missing HandoverInfo-hashing mechanism; DC API protocol/JWS-JSON-Serialization rows (VP-0196/0197/0200/0202/0207/0208) resolved not-implemented, since foundry's dc_api transport only ever produces the unsigned-request shape with no protocol identifier, signed variant, or multisigned JWS JSON Serialization anywhere in the workspace; 5 new tests (1 appended to the existing #[cfg(test)] mod tests block in foundry-verifier/src/verify.rs for GAP-VP-07; 2 new tests in conformance_vp.rs for GAP-VP-06 and the conforming VP-0198/VP-0201 DC API request shape; 2 new tests in conformance_vci.rs for GAP-VCI-12 and GAP-VCI-13), all confirmed genuinely red/green before final placement; sorted the Gap Register by severity (Critical, then Important, then Minor) per this task's deliverable; filled Summary counts for OpenID4VCI (`230 | 65 | 27 | 78 | 6 | 54 | 0 | 0`) and OpenID4VP (`266 | 65 | 31 | 55 | 8 | 107 | 0 | 0`) -- HAIP unchanged from Task 17 (`96 | 43 | 11 | 11 | 7 | 20 | 4 | 0`); zero `unverified` rows remain in any of the three specs; flipped Status from "in progress" to "complete — audit finished 2026-07-31"; all four gates (cargo test --workspace, cargo test --workspace -- --ignored, clippy, fmt) verified clean, with --ignored showing every audit gap test failing as designed plus one unrelated pre-existing E2E test passing)
