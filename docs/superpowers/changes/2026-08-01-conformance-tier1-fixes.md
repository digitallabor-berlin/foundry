# Conformance Tier 1 — Close the Five Highest-Priority Audit Gaps — Change Record

> Migrated from `docs/superpowers/changes/2026-08-01-conformance-tier1-fixes.md` — produced by the retired
> `superlight` workflow (see `docs/superpowers/changes/2026-08-03-retire-superlight-workflow.md`).

**Date:** 2026-08-01
**Branch:** `superlight/2026-08-01-conformance-tier1-fixes`
**Spec:** [`../specs/2026-08-01-conformance-tier1-fixes-spec.md`](../specs/2026-08-01-conformance-tier1-fixes-spec.md)
**Plan:** [`../plans/2026-08-01-conformance-tier1-fixes-plan.md`](../plans/2026-08-01-conformance-tier1-fixes-plan.md)

## Why

The 2026-07-31 OpenID4VC conformance audit
([`docs/conformance/openid4vc-conformance.md`](../../conformance/openid4vc-conformance.md))
adjudicated 592 clauses across OpenID4VCI, OpenID4VP and HAIP and filed 26
gaps. A same-day triage sorted the register into fix tiers; **Tier 1** is the
five gaps combining high consequence with contained blast radius:

| Gap | Severity | Problem |
|---|---|---|
| GAP-HAIP-04 | Critical | `DefaultAttestationVerifier::verify_wallet_attestation` only checked that the `OAuth-Client-Attestation` header was *present* — any arbitrary non-JWT string was accepted even with `mode = Required`: a full client-authentication bypass. |
| GAP-VCI-03 | Important | The `mso_mdoc` credential response was base64-**standard**-encoded, not base64url, so a conformant base64url-only decoder rejected it. |
| GAP-VCI-01 | Important | `pre-authorized_code` was never invalidated after redemption — unlimited fresh access tokens until the credential was claimed. |
| GAP-HAIP-06 | Important | Status index allocation deduplicated per `credential_type_id`, but every credential type shares one physical status list — two different credential types could draw the same index, so revoking one silently revoked the other. |
| GAP-VP-07 | Important | `do_verify_vp_response` always expected the `x509_san_dns` Client Identifier as the KB-JWT audience, rejecting every conformant wallet's `dc_api` presentation, which the spec requires to bind to the Origin instead. |

Left unfixed: three interoperability blockers against any real wallet, one
security bypass, and one status-integrity defect capable of revoking an
unrelated credential.

## What Changed

### Task 1 — GAP-VCI-03: mso_mdoc base64url encoding (`f5fcb8b`)

`credential.rs`'s mso_mdoc branch switched from `B64STD` to `B64URL` for the
CBOR credential response (OpenID4VCI L976). `B64STD` is now scoped to
`#[cfg(test)]` only. VCI-0071/VCI-0176 → `conforming`.

### Task 2 — GAP-VCI-01: single-use pre-authorized_code (`07323f7`)

New `invalidate_pre_authorized_code` in `transaction.rs` (twin of the existing
`invalidate_authorization_code`), wired into `token.rs`'s
`handle_pre_authorized_code_grant`: the code is burned after `tx_code`
validation succeeds, before tokens are minted (OpenID4VCI L396). Two new unit
tests cover the burn-on-success and no-burn-on-wrong-`tx_code` paths.
VCI-0003/VCI-0012 → `conforming`.

### Task 3 — GAP-HAIP-06: status index dedup keyed on the physical list (`f53dbb5`)

`allocate_status_index` gained a `list_id: &str` parameter; the used-index
dedup key changed from `"{credential_type_id}:{idx}"` to `"{list_id}:{idx}"`
(`credential_type_id` is retained for diagnostics only). `create_offer.rs`
introduced `STATUS_LIST_ID = "1"` and passes it through, matching the single
shared physical list every credential type actually points at (HAIP L329).

**Deviation from the plan, documented in-flight:** the plan's proposed test
used `list_size=2` for both allocations. That is non-deterministic — which of
two colliding draws succeeds first is unspecified — so under repeated runs it
could pass by accident pre-fix or fail by accident post-fix. Replaced with a
`list_size=1` two-phase design: the first allocation is forced to index 0
deterministically, and the second must then either collide (bug) or exhaust
(fix), removing the race. Verified by both directions running clean 15× in a
row before and after the fix, respectively — not asserted, checked.

The pre-existing unit test `different_credential_types_do_not_collide` had
asserted the *bug* (two different credential types silently drawing the same
index 0, framed as "no collision" via key-scoping that scoped by credential
type instead of physical list). Renamed to
`different_credential_types_sharing_one_list_do_not_collide` and rewritten to
assert the corrected behavior (`assert_ne!` under `list_size=2`) — the one
scoped exception, beyond Task 3's own gap test, to "never rewrite an existing
test," because the old test's assertion was itself the defect.

HAIP-0081 → `conforming`.

### Task 4 — GAP-HAIP-04: cryptographically validate Wallet Attestation JWTs (`416063d`)

The largest task: `handle_token_request`'s signature changed from
`attestation_mode: Mode` to `wallet_attestation: &AttestationMode`, rippling
across all 22 call sites (mechanical adaptation only — verified in review,
see below).

`attestation.rs`: new `validate_wallet_attestation_jwt(attestation_jwt,
trust_store, now_unix)` fully validates the JWT — 3-part JWS structure,
`typ == "oauth-client-attestation+jwt"`, `alg` not `none`/symmetric, `x5c`
chain present and checked via `TrustStore::validate_chain`, `exp`/`nbf`
window, and presence of `cnf.jwk`/`sub` claims (parsed but not yet consumed —
see Follow-Ups). `Disabled` skips entirely; `Required` demands presence and
validity; `Optional` tolerates absence but validates if present.

`token.rs` builds a `TrustStore::from_config(&wallet_attestation.trusted_anchors)`
per request and threads it through. `server.rs`'s one production call site
passes `&state.config.issuer.wallet_attestation` directly.

**Bookkeeping surfaced a real extraction miss.** Closing HAIP-0031 required
re-checking every clause in the Wallet Attestation section, which found
L2555's "the Authorization Server MUST verify the attestation is signed by a
trusted issuer" had never been extracted as its own clause. Added **VCI-0231**
(that requirement) → `conforming`, and **VCI-0232** (the Client Attestation
PoP JWT the same section also requires) → `gap`, filed as new **GAP-VCI-14**
(Important) — deliberately deferred per the user's scope decision: PoP
verification is a distinct mechanism (replay store, `aud` policy) out of
scope for this Tier 1 run. HAIP-0088's evidence was split accordingly: the
ES256-signature half is now conforming, the PoP half remains cited to
GAP-VCI-14.

HAIP-0031 → `conforming`; HAIP-0030's citation reworded to point at HAIP-0031
instead of the closed gap.

### Task 5 — GAP-VP-07: accept the Origin-prefixed audience over the DC API (`c233c0e`)

New `VerifierConfig.dc_api_expected_origins: Vec<String>` (`#[serde(default)]`).
`verify_sd_jwt_vc` (foundry-sd-jwt-vc) now takes `expected_audiences: &[String]`
instead of a single `&str`; `verify_kb_jwt` matches the KB-JWT `aud` against
any entry, with both sides normalized by stripping a trailing slash
(`normalize_audience`) — the spec text and RFC 6454 do not agree on
trailing-slash handling for Origin serialization. `do_verify_vp_response`
branches on `tx.transport == "dc_api"`: builds an `origin:`-prefixed audience
list from the new config field, falling back to a single
`public_base_url`-derived origin (logged at `debug`) when unconfigured — every
other transport keeps the unchanged `x509_san_dns:<host>` Client Identifier.

VP-0265 → `conforming`. VP-0209 stays `gap`, re-cited to GAP-VP-06 (its Test
column repointed to that gap's own test) since VP-0209 covers *all* DC API
response formats and mdoc's `SessionTranscript` binding (GAP-VP-06, Tier 2,
out of scope here) is still non-conformant.

Four new unit tests alongside un-ignoring the existing gap test: the
`public_base_url` fallback when unconfigured, trailing-slash normalization in
both directions, `request_uri` transport still rejecting an Origin-prefixed
audience (guards against over-broadening the fix), and a `dc_api` audience
matching neither a configured origin nor the fallback being rejected.

**Documentation location deviated from the plan.** The plan said to document
the new field in `config.yaml` and `README.md`. `README.md` has no per-field
`VerifierConfig` documentation anywhere — no other field
(`named_queries`, `response_encryption`, `client_id_scheme`, `webhook`, ...)
is documented there either, so there was no existing section to extend.
Documented instead where every other `VerifierConfig` field already is: the
`quickstart` config template (`commands.rs`'s `QUICKSTART_CONFIG` constant),
with a spec-cited comment. Separately, the repository's root `config.yaml` /
`wallet.yaml` turned out to be gitignored local dev artifacts with no commit
history of their own — edited locally to mirror the template for convenience,
but that edit carries no git record.

### Task 6 — Reconciliation

No code changes. All four required gates passed cleanly:
`cargo test --workspace`, `cargo test --workspace --no-fail-fast -- --ignored`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.
The `--ignored` sweep was diffed against the predicted set exactly (not just
counted): **23 failing gap tests** — corresponding to **22 open gap register
rows**, since GAP-VCI-05 is cited by two tests (`vci_0186_...` and
`vci_0199_0209_0224_...`) — plus the one unrelated, already-passing
`full_flow_issue_verify_revoke_reverify` E2E test. `openapi.json` /
`openapi-wallet.json` are byte-identical to `main` (no endpoint shape changed
across any of the five tasks), confirmed both by `git diff` and by
`openapi_endpoints.rs`'s own checked-in-vs-generated sync test passing.

## Verification

All four gates clean at every commit, not only at the end — enforced
structurally by `conformance_report.rs`'s 11 consistency checks, which ran as
part of `cargo test --workspace` on every task's commit.

| Claim | How it was verified |
|---|---|
| GAP-HAIP-06's fix is deterministic | The `list_size=1` two-phase test run 15× red and 15× green, not asserted once |
| GAP-VP-07's fallback works | Dedicated test with `dc_api_expected_origins` explicitly cleared to `Vec::new()`, asserting the `public_base_url`-derived audience is accepted |
| GAP-VP-07's fix doesn't over-broaden | Dedicated `request_uri_transport_rejects_origin_prefixed_audience` test — a non-`dc_api` transport must still reject an Origin-prefixed audience |
| GAP-VCI-14's new gap test is genuinely red | Debug-printed the actual `Result` before trusting the `assert!` — caught and fixed a test-only bug first (`TrustAnchor.certs` is a file path, not inline PEM, per `TrustStore::from_config`) that was making the test fail for the *wrong* reason |
| No unwrap/expect/panic/unreachable leaked into production paths | `awk`-scanned every modified file in `foundry-issuer/src`, `foundry-verifier/src`, `foundry/src`, splitting at `#[cfg(test)]`: zero hits outside test modules |
| Every new `#[tracing::instrument]` carries `skip_all` | Grepped the branch diff for both new instrument sites (`attestation.rs`, `status_index.rs`) |
| No sensitive data newly logged | Grepped the branch diff for new `tracing::*!`/`println!`/`eprintln!` calls: exactly one, the non-sensitive `fallback_origin` debug log |
| `verified` still equals `checks.iter().all(passed)` | Diffed `verify.rs` for new `CheckResult`/`checks.push` sites: none added: this closes over the pre-existing check flow, not a new one |
| No unauthorized gap-test rewrites | Diffed every un-ignored test's body against `main`: `haip_0031_...` and `gap_vp_07_...` show only `#[ignore]` removal plus the mechanical `handle_token_request`/`verify_sd_jwt_vc` call-site adaptation forced by the signature changes — no assertion or scenario changes. Only two exceptions, both pre-declared: `gap_haip_06_...`'s `list_size` correction and `different_credential_types_do_not_collide`'s rename+correction |
| `--ignored` set matches the predicted arithmetic exactly | Diffed the full sorted test-name list against the prediction, not just the count |
| No dependency-layering violation | The only `foundry-core` change is a `Vec<String>` field on `VerifierConfig` — no new `foundry-*` dependency |

## Deviations From the Plan

All deliberate, all recorded in the plan's per-task checklists and Progress
Log at the time they were made:

- **Task 3's test design changed from `list_size=2` to `list_size=1`
  two-phase**, because the plan's original design was non-deterministic (see
  above).
- **Task 3 rewrote a second pre-existing test**
  (`different_credential_types_do_not_collide`), beyond the plan's single
  authorized exception, because that test asserted the bug itself.
- **Task 4 filed two new clauses (VCI-0231, VCI-0232) and one new gap
  (GAP-VCI-14)** that the plan anticipated in outline but whose exact wording
  and scope were determined during the bookkeeping pass, not pre-written.
- **Task 5's documentation landed in `commands.rs`'s quickstart template, not
  `README.md`**, because `README.md` has no per-field `VerifierConfig`
  documentation section to extend.

## Follow-Ups

### 1. GAP-VCI-14 — Client Attestation PoP JWT is never verified (filed this run, not fixed)

`validate_wallet_attestation_jwt` now fully validates the Wallet Attestation
JWT itself, but nothing anywhere in this workspace reads the paired
`OAuth-Client-Attestation-PoP` header, and `handle_token_request` has no
parameter for one. A stolen or replayed Wallet Attestation JWT is accepted
identically to a legitimate one — there is no proof the presenter holds the
private key the attestation's `cnf.jwk` names. Fixing this needs a `jti`
replay store and an `aud` policy decision; deliberately scoped out of this
Tier 1 run per the user's choice (c) at the design interview.

### 2. Tier 2–5 gaps remain open

This run closed exactly the five Tier 1 gaps. GAP-VP-06 (mdoc DC API
`SessionTranscript`/`Handover`, Critical, Tier 2) is now cited by an
*additional* clause (VP-0209) as a side effect of Task 5's bookkeeping, but
its own fix is untouched. 21 other gaps (22 register rows minus GAP-VCI-14,
which this run itself filed) remain as before this run.

### 3. The `status_index.rs` `TODO(concurrency)` non-atomic race — pre-existing, out of scope

Noted during Task 3 but not addressed: the read-then-write allocation pattern
in `allocate_status_index` is not atomic under concurrent callers. Explicitly
a non-goal for this run per the spec.

### 4. A test-flake recurred twice during this run, investigated both times, ruled a pre-existing environmental blip rather than a regression

During Task 4 verification, `attestation::tests::rejects_nonce_not_minted_by_this_issuer`
and `attestation::tests::rejects_expired_attestation` both failed once in a
single `cargo test -p foundry-issuer --lib` run; 20 immediate re-runs were
clean. During the final post-changelog gate re-check (Task 6, after all code
was already committed), `cargo test --workspace` failed once in
`foundry-issuer --test conformance_vci` with no test name captured in the
first pass; a second run of that binary alone passed clean (32/0/13), and 15
further immediate re-runs were all clean. Neither occurrence was reproducible
on demand, and neither touched a test this branch modified. Consistent with a
real-wall-clock timing sensitivity in tests that check certificate/attestation
validity windows (`exp`/`nbf`) against `SystemTime::now()`, not a defect
introduced here — but flagged twice now, in two different sessions, so it is
worth a dedicated look (e.g. mocking the clock in these specific tests) if it
recurs a third time. Not filed as its own conformance gap since it is a
test-harness timing property, not a spec-conformance question.

### 5. The 2026-07-31 audit itself still has no changelog

Noted earlier in this session, unrelated to Tier 1 remediation: the
2026-07-31 OpenID4VC conformance audit that produced the gap register this
run closes against has no corresponding
`docs/superpowers/changes/2026-07-31-openid4vc-conformance-audit.md`. Flagged
for follow-up, not addressed here (out of scope for this run's spec).
