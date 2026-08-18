# 2026-08-18 — Multi-credential DCQL verification

## Motivation

foundry's verifier accepted a DCQL query naming several credentials on the
**request** side — `create_verification_request` persisted it, and
`build_signed_request_object` sent it to the wallet — but rejected the answer.
`select_presentation` raised `vp_token answers several credential queries
([...]); this verifier verifies a single credential per vp_token`, which the
HTTP layer turned into **400 `invalid_request`**.

So a *conformant* wallet, doing exactly what foundry's own request asked for,
got an error. The verifier asked a question it could not accept the answer to.

Two further defects were latent in the single-credential result shape, and both
would have become live the moment the limit was lifted. `VerificationResult`
carried one flat `claims` map, so N credentials would have merged into it:

1. **`status_check` against the wrong credential's status list.**
   `check_status` reads `status.status_list` out of the claims map it is handed.
   With a merged map, credential 2's `status` claim displaces credential 1's, so
   one credential's revocation check runs against another's status list — and
   reports a **passing** `status_check` while doing it. This is the
   security-relevant one: a revoked credential can be reported as valid.
2. **Plain claim collision.** Two credentials disclosing `given_name` overwrite
   each other, and the result reports one value as if both credentials agreed
   on it.

## Change

`vp_token` may now answer several DCQL credential queries. Each answered query
becomes one record, in **DCQL declaration order** — not `vp_token` key order,
which depends on the wallet's serialization and on whether `serde_json` was
built with `preserve_order`.

- `select_presentation` → **`select_presentations`**, returning
  `Vec<(String, SelectedPresentation)>`.
- `VerificationResult` gains `credentials: Vec<PresentedCredential>` and
  **loses its flat `claims` field**. `PresentedCredential` is
  `{ query_id, format, claims, checks }` — claims are per credential and are
  never merged, which is what fixes both collisions above.
- `verify_one_credential` + `CredentialVerifyCtx` verify one credential;
  `do_verify_vp_response` loops over them **verify-all, never fail-fast**. Root
  `AGENTS.md` §4.2 defines `verified` as the conjunction of the checks
  performed, which is only meaningful when they were all performed — and "PID
  signature bad, mDL fine" is a far more useful operator verdict than "PID
  signature bad, mDL unknown".
- **`verified` now spans both levels** via `VerificationResult::all_checks()` /
  `derive_verified()`. The old `checks.iter().all(..)` is satisfiable while a
  per-credential check fails, so root `AGENTS.md` §4.2 was amended: this is a
  normative change, not documentation catch-up.
- New cross-cutting check **`requested_credentials_answered`**.
- Duplicate credential query ids are rejected at request creation
  (OpenID4VP 1.0 L745-746), closing **VP-0094**. This is load-bearing rather
  than cosmetic: `select_presentations` matches each credential query against
  `vp_token`'s keys, so two queries sharing an id would both match the same
  entry and one presentation would be verified twice under contradictory
  queries.

### A subset `vp_token` is a policy verdict, not a 400

**Spec finding.** OpenID4VP 1.0 **L1007-1008**: "If the Wallet cannot deliver
all non-optional Credentials requested by the Verifier according to these
rules, it MUST NOT return any Credential(s)." With `credential_sets` absent —
the only case foundry implements — **L993** makes every credential query
non-optional. A subset response is therefore a **wallet MUST-violation**.

It is nonetheless reported as HTTP 200 + `verified: false` with a failed
`requested_credentials_answered` naming the unanswered ids, and the detail
attributes the fault to the wallet. The grounds are the four in the design's
§5 — the spec constrains the wallet here rather than the verifier's status
code; the response is well-formed, so root `AGENTS.md` §4.3's structural
category does not fit; naming the missing query is far more actionable than an
opaque `invalid_request`; and the credentials that *did* arrive are still worth
verifying and reporting.

**Correction on the record:** an earlier draft justified this with VP-0117.
That was a misreading — VP-0117 governs claims *within* a credential, not
credentials within a response. The classification stands on the four grounds
above, not on that citation.

An id the request never asked for stays **structural (400)**: there is no
credential query to attribute a verdict to.

### An unavailable status list stays 502, without becoming lossy

"I could not determine whether this is revoked" is not "this is revoked", so an
unreachable status list keeps its **HTTP 502** (root `AGENTS.md` §4.3);
collapsing the two would let a relying party read an unreachable list as a
clean bill of health.

But propagating it with `?` from inside the loop discarded every check already
collected, and the wrapper's `Err` arm rebuilt `tx.result` from scratch — losing
the "the other credential was fine" half that makes a precise 502 worth having.
`do_verify_vp_response` now returns `VerifyOutcome { result, deferred }`: the
result is persisted first, then the error is re-raised. The error names *which*
credential's status list was unreachable.

This creates a trap the change also closes: an unavailable status pushes **no**
`status_check` record, so the conjunction would compute `true` and persist
`verified: true` on a transaction that just returned 502. The fault is recorded
as a top-level failed `status_check` instead, keeping the verdict derived.

## Non-goals

- **`credential_sets`** (VP-0103 / VP-0104) — alternatives and optionality.
  Still `not-implemented`, and their evidence is re-grounded on this non-goal
  rather than on the single-credential design, which no longer exists.
- **`multiple: true`.** The exactly-one-presentation-per-entry guard stays, and
  is now **spec-cited** to L1166 ("When `multiple` is omitted, or set to
  `false`, the array MUST contain only one Presentation") rather than merely
  conservative. foundry ignores `multiple` (VP-0090), so it never requests more
  than one and the rule always applies.

## Why this is not a §4.5 leak

Per-credential check records carry a `credential` field, and the verdict record
carries `credentials_requested` / `credentials_answered`.

- **`credential`** is a **DCQL credential query id** — operator-authored
  request structure, not a holder value. It is the same reasoning `dcql.rs`
  already records for naming claim paths in a mismatch. Without it,
  `check=dcql_match passed=false` does not say *whose* credential failed, which
  with N credentials is the difference between an actionable log line and a
  guess.
- **`credentials_requested` / `credentials_answered`** are **counts, never
  identifiers**, so they carry no request structure at all. The pair is what
  makes a subset response visible at a glance.

No claim value, disclosed payload or key material is added to any record.

## HAIP-0070 did **not** become conforming

Lifting the single-credential limit removes HAIP-0070's *stated* cause — its
evidence used to read "foundry presents exactly one credential per `vp_token`
by design; the multi-mdoc scenario cannot arise". That scenario now arises, so
the evidence was rewritten. The clause is still **`not-implemented`**, for a
different reason: it requires each mdoc in a separate `DeviceResponse`, and
foundry's mdoc payload is the bespoke `{mdoc, device_signature}` pair rather
than a `DeviceResponse` at all.

Marking it conforming would have claimed interoperability foundry does not
have. A row that overstates conformance is worse than an honest
`not-implemented`.

## Files

| File | Change |
| --- | --- |
| `crates/foundry-verifier/src/request.rs` | Rejects duplicate credential query ids (VP-0094) |
| `crates/foundry-verifier/src/transaction.rs` | `PresentedCredential`; `VerificationResult.credentials` replaces `claims`; `all_checks()`, `derive_verified()` |
| `crates/foundry-verifier/src/verify.rs` | `select_presentations`; `CredentialVerifyCtx`; `verify_one_credential`; `check_requested_credentials_answered`; `VerifyOutcome`; two-level logging |
| `crates/foundry-verifier/src/lib.rs` | Exports `PresentedCredential` |
| `crates/foundry/src/openapi.rs` | Registers `PresentedCredential` in both schema lists |
| `crates/foundry/assets/console.html` | One stacked section per credential instead of a merged claims blob |
| `openapi.json`, `openapi-wallet.json` | Regenerated |
| `AGENTS.md` | §4.2: `verified` spans both levels; check vocabulary split |
| `crates/foundry-verifier/AGENTS.md` | Module map, key types, invariants; the single-credential gotcha inverts |
| `docs/conformance/openid4vc-conformance.md` | VP-0094 closed; GAP-VP-03 narrowed; VP-0103/0104 and HAIP-0070 re-grounded; summary tally |
| `crates/foundry/tests/e2e_full_flow.rs` | Reads `status_check` via `all_checks()`; see the note below |
| `README.md` | Two-level check names; the new `credential` and count fields |

## Tests

- `create_rejects_duplicate_credential_query_ids`,
  `create_accepts_multiple_distinct_credential_queries` (request.rs)
- `all_checks_spans_both_levels_and_derives_the_verdict` (transaction.rs)
- `select_presentations_*` — several answered queries, declaration order,
  subset accepted, unrequested id rejected, empty `vp_token` rejected (verify.rs)
- `verifies_two_credentials_in_one_vp_token`,
  `per_credential_claims_do_not_collide_on_a_shared_claim_name`,
  `a_subset_vp_token_is_a_policy_verdict_naming_the_missing_credential`,
  `requested_credentials_answered_*` (verify.rs)
- `an_unavailable_status_list_returns_502_without_discarding_other_credentials`
  (verify.rs)

**Mutation-checked.** Each of the load-bearing behaviours was confirmed to fail
when the implementation was deliberately broken: restricting the loop to
`take(1)` fails both multi-credential tests; forcing the missing-set to empty
fails the subset test; removing the deferred `status_check` push fails the 502
test. Passing tests written after the implementation prove nothing on their
own.

## Note

**Task 6's coverage limitation.** The observability change adds no new test.
`crates/foundry/tests/logging_redaction.rs` is the only harness that captures
tracing output, but every verification it drives uses a junk JWE and fails
structurally at decryption (HTTP 400) — a flow that never produces
per-credential checks, so it cannot assert on the `credential` field or the
corrected `failed_checks` count. The two-level traversal itself is covered
directly by `all_checks_spans_both_levels_and_derives_the_verdict`. What
remains uncovered is that the emit *sites* call `all_checks()` and populate
`credential` — both single-expression changes visible in review.

**An `#[ignore]`d test escaped the plan's blast radius.**
`crates/foundry/tests/e2e_full_flow.rs` read `status_check` out of the
**top-level** `checks` list. Task 2 moved that check to
`credentials[i].checks`, so the lookup's `.expect("status_check present")`
panicked. It was not caught by any per-task gate for a structural reason worth
recording: the file is `#[ignore]`d (it binds real ports and drives subprocess
flows), so `cargo nextest run --workspace` skips it, and it compiled fine
because `VerificationResult.checks` still exists — only its *contents* changed.
The §5.2 pre-merge E2E run is what surfaced it. Any future change to the check
levels must grep the ignored tests too; a green §5.1 gate does not cover them.

**Follow-up left open:** a `drive_successful_verification` helper in
`logging_redaction.rs`, reusing `wallet_verification.rs`'s presentation
builders, would let the redaction suite assert on per-credential log records.
It would also close a **pre-existing** gap: no test currently proves a
disclosed claim value stays out of the log on a *successful* verification —
today's `PLANTED_CLAIM` assertion covers issuance only.
