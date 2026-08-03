# Conformance Tier 4 — Three Important Gap Closures

**Date:** 2026-08-03
**Type:** fix
**Branch:** conformance-tier4-fixes
**Spec:** docs/superpowers/specs/2026-08-03-conformance-tier4-fixes-spec.md
**Plan:** docs/superpowers/plans/2026-08-03-conformance-tier4-fixes-plan.md

## Why

Tier 4 of the ongoing conformance triage (Tiers 1–3 already landed) closed the
three remaining `Important` entries in
[`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md)'s
Gap Register that did not require deferring to a dedicated cycle:

| Gap | Severity | Site |
|---|---|---|
| GAP-HAIP-05 | Important | Signed Authorization Requests used the `x509_san_dns` Client Identifier Prefix; HAIP OpenID4VP L256 mandates `x509_hash` |
| GAP-HAIP-01 | Important | Credential Issuer metadata and `/authorize` never populated or accepted a `scope` value (HAIP OpenID4VCI L186/L199/L209) |
| GAP-VP-04 | Important | `transaction_data_hashes` (OpenID4VP L3144) was never computed, emitted, or validated on either side of the verification flow |

**Deliberately deferred:** GAP-HAIP-03 (DPoP, RFC 9449) — its own future cycle,
per the batch-scoping decision recorded in the spec ("Tier 4 minus DPoP").

## Approach

Five decisions were put to the user before implementation, since the pinned
specs and existing code did not settle them on their own:

1. **GAP-HAIP-05: unconditional `x509_hash` swap, no config toggle.** HAIP wins
   over OpenID4VP's broader Section 5.9.3 per root `AGENTS.md` §4.4.
2. **Delete `verifier.client_id_scheme` rather than repurpose it.** Research for
   this spec surfaced it as declared, documented, and set in every fixture, but
   never read by any production code path — dead configuration the prefix swap
   would have made permanently single-valued.
3. **`x5c` becomes mandatory for signed requests.** The identifier *is* the
   certificate hash (`x509_hash:<base64url(SHA-256(DER leaf))>`), so a signed
   request with no `x5c` cannot have an identifier at all; the absence is a
   typed `VerificationError::Crypto`, not a panic.
4. **Scope config field defaults to the credential type's own `id`, overridable
   per Ecosystem.** No existing deployment needs to change `config.yaml` to
   pick up HAIP-0014's scope requirement.
5. **`transaction_data_hashes` gets a full closing implementation**: a new
   `CheckResult`, builder support for emitting the claim, and a positive test —
   not merely a negative "reject if missing" check, which a blanket refusal
   would have passed without proving a correctly bound presentation still
   verifies.

Two places where implementation surfaced something the plan's spec had not
anticipated, caught while writing the code rather than assumed from the
register's prose:

- **`do_verify_vp_response` independently recomputes the expected KB-JWT
  audience** for every non-`dc_api` transport. Changing only
  `build_signed_request_object`'s emission would have made every
  redirect-transport verification fail as a silent policy verdict
  (`verified: false`, HTTP 200) rather than a compile error. Both sides were
  re-anchored on the same helpers (`verifier_x5c_leaf_pem`,
  `x509_hash_client_id`, both in `request.rs`) in the same commit.
- **GAP-VP-02's SAN cross-check** was originally anchored on the
  client-id-derived host. Once `client_id` stopped carrying a hostname at all
  (`x509_hash:<hash>` has none), the check had to be re-anchored on
  `server.wallet_facing.public_base_url`'s host instead — a re-derivation, not
  a removal.

## Changes

### GAP-HAIP-05 — `x509_hash` Client Identifier Prefix

- `crates/foundry-core/src/trust/mod.rs` — new
  `x509_hash_client_id_value(leaf_pem: &[u8]) -> Result<String, TrustError>`:
  `base64url(SHA-256(DER leaf))`, unprefixed, per OpenID4VP L616.
- `crates/foundry-verifier/src/request.rs` — `verifier_x5c_leaf_pem(&Config)` and
  `x509_hash_client_id(leaf_pem)` (the latter adding the `x509_hash:` prefix);
  `build_signed_request_object` now requires `x5c` and emits the new prefix; the
  SAN cross-check moved to compare against `public_base_url`'s host instead of
  the (now hostname-free) client id.
- `crates/foundry-verifier/src/verify.rs` — `do_verify_vp_response` recomputes
  `client_id` via the same two helpers; a new `expected_client_id(&Config)` test
  helper replaces every hardcoded `x509_san_dns:localhost` literal.
- `crates/foundry-verifier/tests/conformance_vp.rs` — doc comments and
  VP-0063/VP-0064 re-anchored on the `public_base_url` invariant; new
  `haip_0045_signed_request_x5c_excludes_the_trust_anchor` test.
- Three `foundry`-crate integration fixtures (`wallet_verification.rs`,
  `conformance_http.rs`, `logging_redaction.rs`) previously signed with a bare
  EC key and no certificate at all — mandatory `x5c` required generating a
  CA + leaf pair via `foundry_core::pki` for each and wiring the leaf into
  `config.keys`.
- Register: GAP-HAIP-05 row deleted; HAIP-0043, VP-0068, VP-0069, HAIP-0045
  flipped to `conforming`; HAIP-0055's evidence updated to cite the new prefix.

### Dead config field removed

- `verifier.client_id_scheme` deleted from `VerifierConfig`
  (`crates/foundry-core/src/config/model.rs`), its doc-comment YAML example,
  `config.yaml`, `commands.rs`'s embedded template, and ~19 construction sites
  across `foundry-core`/`foundry-issuer`/`foundry-verifier`/`foundry` test
  files. Non-breaking: no config struct in this workspace sets
  `deny_unknown_fields`, so an existing `config.yaml` that still lists the key
  keeps loading — covered by
  `a_config_still_listing_the_removed_client_id_scheme_key_loads`.

### GAP-HAIP-01 — `scope` in issuer metadata and `/authorize`

- `crates/foundry-core/src/config/model.rs` — `CredentialType.scope: Option<String>`
  and `CredentialType::resolved_scope(&self) -> &str`, defaulting to the
  credential type's own `id`. `Config::validate()` rejects two credential types
  resolving to the same scope, and rejects an explicitly blank scope.
- `crates/foundry-issuer/src/metadata.rs` —
  `CredentialConfigurationSupported.scope: String`, serialized unconditionally
  for every configuration (HAIP OpenID4VCI L186 admits no omission).
- `crates/foundry-issuer/src/authorize.rs` — `AuthorizeParams.scope: Option<String>`;
  `handle_authorize_request` gains a `scopes: &BTreeMap<String, String>`
  parameter (resolved scope → credential type id) and rejects any sent `scope`
  that does not resolve to the transaction's own `credential_type_id`, via
  `AuthorizeOutcome::ErrorRedirect { error: "invalid_scope", .. }` — a redirect,
  not a direct JSON error, per RFC 6749 §4.1.2.1 (the `redirect_uri` has already
  been validated by that point). Absent `scope`, behaviour is unchanged;
  `issuer_state` remains the authoritative binding.
- `crates/foundry/src/server.rs` — `AuthorizeQuery` gains `scope`; the handler
  builds the `scopes` map from `state.config.credential_types` and threads it
  through.
- `openapi-wallet.json` — regenerated (`CredentialConfigurationSupported` now
  carries a required `scope` field); `openapi.json` (admin surface) unaffected.
- `config.yaml` and `commands.rs`'s embedded template — `scope:` documented
  alongside the other `credential_types[]` fields.
- Register: GAP-HAIP-01 row deleted; VCI-0053, VCI-0145, HAIP-0014, HAIP-0023,
  HAIP-0027, HAIP-0028 flipped to `conforming`. VCI-0145 is *re-adjudicated*,
  not merely re-evidenced: the clause targets a multi-issuer Authorization
  Server disambiguating *which* Credential Issuer a scope names, and foundry's
  Authorization Server always serves exactly one, so the clause's precondition
  never creates ambiguity here — a new
  `authorization_server_metadata_issuer_is_independent_of_credential_type_scope`
  test backs the verdict, required by `conformance_report.rs`'s rule that every
  `conforming` verdict cites a real test.

### GAP-VP-04 — `transaction_data_hashes` binding validation

- `crates/foundry-sd-jwt-vc/src/builder.rs` — new
  `TransactionDataBinding<'a> { hashes: &'a [String], alg: Option<&'a str> }`;
  `attach_kb_jwt` and `build_kb_jwt` gain a
  `transaction_data_hashes: Option<TransactionDataBinding<'_>>` parameter,
  emitting `transaction_data_hashes`/`transaction_data_hashes_alg` claims into
  the KB-JWT payload when present (OpenID4VP L3144/L3145). Every pre-existing
  caller across `foundry-sd-jwt-vc`, `foundry-verifier`, and `foundry` gained
  `, None` as its final argument.
- `crates/foundry-sd-jwt-vc/src/verifier.rs` — `verify_sd_jwt_vc`'s
  `VerificationResult` gains `kb_jwt_payload: Value`, the already-signature-
  verified KB-JWT payload; `verify_kb_jwt` now returns it instead of `()`.
- `crates/foundry-verifier/src/request.rs` — `encode_transaction_data` gains a
  `hashes_alg: &[String]` parameter; when non-empty it injects
  `transaction_data_hashes_alg` into each entry *before* base64url encoding
  (preserving the byte-identical-to-what's-hashed guarantee the function's
  contract rests on), sourced from `config.verifier.transaction_data_hashes_alg`
  — a field that existed but was never read before this change.
- `crates/foundry-verifier/src/verify.rs` — new
  `check_transaction_data_binding(requested_entries, answered_query_id,
  kb_payload) -> CheckResult`, pushed only when `tx.transaction_data` is `Some`;
  never returns `Err` (fail-closed, matching `check_dcql_match`'s contract).
  Requires every `transaction_data` entry scoped to the answered credential
  query to be hashed (`sha-256` only, computed over the entry's advertised
  base64url string with no decoding) into the KB-JWT's
  `transaction_data_hashes`; the algorithm must be one the request advertised,
  defaulting to `sha-256`. An mdoc presentation has no KB-JWT to carry the
  binding, so requesting `transaction_data` against one records a hard
  `passed: false` rather than silently skipping the check.
- `crates/foundry-verifier/Cargo.toml` — added `sha2` (already a workspace
  dependency, used elsewhere in the crate's own `[dev-dependencies]`
  transitively via `foundry-sd-jwt-vc`; now a direct dependency of `verify.rs`).
- Root `AGENTS.md` §4.2 and `crates/foundry-verifier/AGENTS.md` — the
  `CheckResult` name vocabulary grows to six names;
  `crates/foundry-verifier/AGENTS.md`'s `request.rs`/`verify.rs` module-map rows
  and its `client_id`-derivation Gotcha, which still described the pre-GAP-
  HAIP-05 `x509_san_dns` behaviour, are corrected in the same commit.
- Register: GAP-VP-04 row deleted; VP-0153, VP-0254, VP-0256 flipped to
  `conforming`.

## Tests

All three formerly-`#[ignore]`d gap-reproduction tests
(`gap_haip_05_signed_request_object_never_uses_x509_hash_prefix`,
`haip_0023_credential_configuration_metadata_carries_a_scope_value`,
`gap_vp_04_transaction_data_hashes_never_validated`) now pass unmodified as the
acceptance criteria. `crates/foundry/tests/conformance_report.rs`'s eleven
self-consistency tests enforce register↔test consistency in both directions
and machine-check the Summary arithmetic for all three specs; each closing
commit updated its own gap row, clause rows, and Summary counts together, as
that suite requires.

**New tests beyond the three:**

- `foundry-core/src/trust/mod.rs` — `x509_hash_client_id_value` pinned against a
  known DER input.
- `conformance_vp.rs` — `haip_0045_signed_request_x5c_excludes_the_trust_anchor`
  (positive control: the trust anchor never appears in the signed request's
  `x5c`).
- `config/model.rs` — `duplicate_resolved_scopes_are_rejected`,
  `distinct_resolved_scopes_are_accepted`, `an_explicitly_blank_scope_is_rejected`,
  `resolved_scope_defaults_to_the_id`,
  `a_config_still_listing_the_removed_client_id_scheme_key_loads`.
- `metadata.rs` — `every_credential_configuration_carries_a_scope`,
  `scope_defaults_to_the_credential_type_id_and_can_be_overridden`,
  `authorization_server_metadata_issuer_is_independent_of_credential_type_scope`.
- `authorization_code_flow.rs` — `authorize_accepts_a_scope_matching_the_offers_credential_type`,
  `authorize_rejects_a_scope_naming_a_different_credential_type`,
  `authorize_without_a_scope_still_succeeds`.
- `builder.rs` (foundry-sd-jwt-vc) — `attach_kb_jwt_emits_transaction_data_hashes_when_asked`,
  `attach_kb_jwt_omits_the_claims_when_not_asked`,
  `attach_kb_jwt_omits_the_alg_when_the_request_did_not_carry_one`.
- `request.rs` (foundry-verifier) — `transaction_data_entries_advertise_the_configured_hash_algorithm`,
  `transaction_data_entries_omit_the_algorithm_when_unconfigured`.
- `verify.rs` (foundry-verifier) — `a_correctly_bound_transaction_data_presentation_verifies`
  (the positive counterpart the negative gap test alone could not prove),
  `a_transaction_data_hash_that_matches_nothing_does_not_verify`,
  `an_unadvertised_transaction_data_hashes_alg_does_not_verify`,
  `no_transaction_data_means_no_binding_check`.

**Per-task scoped gates** (`cargo test -p <touched crates>`, targeted
`clippy`/`fmt`) were run at the end of each of the ten plan tasks, per root
`AGENTS.md` §5.1 — never `cargo test --workspace` between tasks.

**Verified (this task, the only full-gate run in the plan per §5.3):**

```
cargo test --workspace                                   → all green
cargo clippy --workspace --all-targets -- -D warnings     → clean
cargo fmt --check                                          → clean
```

`cargo test -p foundry --test e2e_full_flow -- --ignored` — **not run** on this
pass; the plan called for it as the only live-process proof of the two-sided
`x509_hash` swap, but running it was explicitly declined for this task. Left as
a follow-up rather than claimed as verified.

## Left unfixed

- **The plan's Step 4 live-process proof** (`cargo test -p foundry --test
  e2e_full_flow -- --ignored`) was not run for this task. The full `cargo test
  --workspace` run already exercises the two-sided `x509_hash` swap end-to-end
  within the same process via `test_verify_vp_response_sd_jwt_vc` and the
  `conformance_vp.rs`/`conformance_http.rs` suites, but the real-subprocess
  proof the plan called for specifically remains outstanding.
- **GAP-HAIP-03 (DPoP, RFC 9449)** — deliberately deferred to its own cycle, per
  the batch-scoping decision. Access tokens remain bearer-only, not
  sender-constrained.
- **Tier-5 Minor gaps** — GAP-VCI-11, GAP-VCI-12, GAP-VCI-13, GAP-VCI-05 (both
  sites), GAP-VCI-06, GAP-VCI-07, GAP-VCI-10, GAP-VP-03, GAP-VP-05 — ten
  register rows remain, all Minor, each with a citing `#[ignore]`d test.
- **The `validate_chain` trust-anchor ambiguity** (HAIP-0039/0079/0084) — not a
  register entry, not touched by this batch.
- **PAR (HAIP-0007)** — not a register entry, not touched by this batch.
- **`x509_san_dns`-era evidence text surviving elsewhere in the register.**
  Several `conforming` rows unrelated to this batch's own scope (VP-0030,
  VP-0046, VP-0047, VP-0063–VP-0067, VP-0073, VP-0132, VP-0235, VP-0264,
  VP-0265) still describe `client_id` as `x509_san_dns:<host>` in their
  evidence prose — stale since GAP-HAIP-05, but their verdicts remain correct
  (the underlying mechanism they describe still holds; only the specific
  string is dated). Left for a dedicated documentation pass rather than
  widening this batch's diff into unrelated clause text.