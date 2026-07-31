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

- [ ] Extract clauses per convention
- [ ] Verify — consistency test green, IDs sequential and unique
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red — failing test per behavior above
- [ ] Green — minimal implementation
- [ ] Refactor — clean while green
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Adjudicate clauses — verdict + evidence for every row in scope
- [ ] Red / Green / Refactor per behavior
- [ ] Record gaps — register rows + `#[ignore]` attributes
- [ ] Verify — run the command, pristine output
- [ ] Commit

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

- [ ] Fill summary counts
- [ ] Resolve or relocate every `unverified` row
- [ ] Verify — ignored-test count reconciles against the gap register
- [ ] Verify — all three gates clean
- [ ] Commit

---

## Progress Log

*Append one line per completed task: date, task, commit SHA.*

- 2026-07-31 — Task 1 (report scaffold + AGENTS.md pointer) — `f3cd3ad`
- 2026-07-31 — Task 2 (report consistency test, 11 checks, all mutation-verified) — `a377536`
- 2026-07-31 — Task 3 (extract OpenID4VCI: 230 clauses, 201 in scope) — `f25b9f1`
- 2026-07-31 — scope amendment: W3C VC profiles + `di_vp` marked `out-of-scope`, VCI in-scope 201 → 181 — `443c830`
- 2026-07-31 — Task 4 (extract OpenID4VP: 266 clauses, 161 in scope; attribution rule for presentation-binding clauses recorded in the report's Audit Boundary) — `6693298`