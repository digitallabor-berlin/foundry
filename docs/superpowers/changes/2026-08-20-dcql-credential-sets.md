# DCQL `credential_sets` support

**Date:** 2026-08-20
**Crate:** `foundry-verifier` (documentation fallout in `foundry`)
**Design:** [`2026-08-20-dcql-credential-sets-design.md`](../specs/2026-08-20-dcql-credential-sets-design.md)
**Plan:** [`2026-08-20-dcql-credential-sets-plan.md`](../plans/2026-08-20-dcql-credential-sets-plan.md)
**Governing text:** `docs/specs/openid-4-verifiable-presentations-1_0.md`
L726-L728, L879-L894, L989-L1008.

---

## What shipped

`foundry-verifier` can now author and evaluate DCQL `credential_sets`, so one
presentation request can ask for alternatives and for optional credentials:

```json
"credential_sets": [
  { "options": [["girocard"], ["visa"]] },
  { "options": [["pid"], ["av"]] },
  { "options": [["loyalty"]], "required": false }
]
```

Four pieces, in dependency order:

1. **Wire model** (`dcql_model.rs`) — `DcqlCredentialSetQuery` with `options`
   and `required` (default `true`, L892-L894), reached through
   `DcqlQuery::credential_sets() -> Option<&[DcqlCredentialSetQuery]>`. The
   `Option` is load-bearing: absent means every credential query is
   non-optional (L993); present means the set algebra decides (L995-L997).
   Non-emptiness is enforced at deserialization for `credential_sets`, for
   `options`, and for each individual option — the module's existing
   fail-closed treatment of `credentials` and `claims[].path`, extended.
2. **Satisfaction algebra** (new `credential_sets.rs`) — one pure, total
   function. A set is satisfied iff at least one of its `options` is a subset
   of the answered credential query ids (L999-L1001); the check passes iff
   every required set is satisfied (L995-L997). Optional sets are reported in
   `detail`, never decisive.
3. **Create-time validation** (`request.rs`) — three operator-error checks,
   each an HTTP 400 at `POST /admin/verification/requests` rather than a later
   presentation failure that reads as the wallet's fault: a dangling option
   reference, a credential query no set references, and an all-optional query.
4. **Verification wiring** (`verify.rs`) — `check_response_completeness` parses
   the query once and dispatches to exactly one of two mutually-exclusive
   cross-cutting checks: `requested_credentials_answered` when
   `credential_sets` is absent, `credential_sets_satisfied` when present.

`select_presentations` and the per-credential verification path are untouched.

## The five decisions

Recorded in the design doc with the alternatives rejected; not restated here.

1. **Scope** — full `credential_sets` (N sets, N options, `required`
   honoured), closing VP-0103 and VP-0104 outright rather than shipping half
   the feature.
2. **Surplus credentials are verified, not rejected** (design §2.2). The
   accepted cost is stated plainly there: a surplus credential with a revoked
   status sinks the whole verdict, because root `AGENTS.md` §4.2 stays intact.
3. **Two mutually-exclusive cross-cutting checks** (§2.3) —
   `requested_credentials_answered` keeps its exact current meaning and is
   emitted only when `credential_sets` is absent. Check names are
   operator-facing API, so adding one beats silently changing what an existing
   one means; emitting both would fail the conjunctive check whenever a wallet
   correctly omitted an optional credential.
4. **Satisfaction is presence, not validity** (§2.4) — a returned credential
   counts toward its option even if its own checks failed. Validity is already
   reported per credential; folding it in here would make one revoked
   credential produce two failed checks reporting the same fact.
5. **Operator mistakes fail at request-creation time** (§2.5).

## Two refinements adopted during planning

Both deliberate departures from the design doc's prose:

- `check_credential_sets_satisfied` takes `&[DcqlCredentialSetQuery]`, not
  `&DcqlQuery`. The dispatcher has already proven the sets exist, so a slice
  removes a branch that could never be taken.
- `check_requested_credentials_answered` takes a parsed `&DcqlQuery` instead of
  `&Value`. The dispatcher must parse in order to choose a branch; leaving the
  parse inside the branch would parse the same value twice and re-derive a
  decision already made. The parse-failure path moved to the dispatcher, where
  it keeps the legacy check name — without a parsed query there is no way to
  know which algebra was intended.

## Conformance rows moved

| ID | Before | After |
| --- | --- | --- |
| VP-0103 | `not-implemented` | `conforming` |
| VP-0104 | `not-implemented` | `conforming` |
| VP-0090 | `conforming`, evidence listing `credential_sets` among the silently-ignored unknown properties | `conforming`, evidence now listing `multiple`, `trusted_authorities`, `claim_sets` |
| VP-0106 | `not-implemented`, cross-referencing VP-0103 for `claim_sets` | `not-implemented`, re-grounded on `claim_sets` being unmodelled on its own merits (VP-0090) |

VP-0107 and VP-0108 cite VP-0106's evidence rather than VP-0103's, so
re-grounding VP-0106 fixed all three.

The summary table's OpenID4VP row moves `conforming` 93 → 95 and
`not-implemented` 51 → 49. Those numbers were not hand-computed: the report's
own `summary_counts_match_the_inventories` recounts the inventory rows and
compares them against the summary, so the procedure was to flip the two clause
rows, let that test fail, read the true inventory count out of its assertion
message, make the summary match, and re-run it green. That the delta is exactly
∓2 is itself the confirmation that only the two intended rows moved.
`every_test_named_by_the_report_exists` separately verifies that each newly
cited test name resolves to a real test function.

## Still non-goals

Unchanged, each still recorded as it was:

- **`claim_sets`** (VP-0106 through VP-0108) — a separate satisfaction algebra
  over claims within one credential. Still unmodelled. The VP-0090 fixture that
  used `credential_sets` as its example of an ignored unknown property now uses
  `claim_sets`, so the test still proves what it claims.
- **`multiple: true`** — would reopen the "exactly one presentation per entry"
  guard in `select_presentations` (L1166).
- **`trusted_authorities`** (VP-0098 through VP-0102) — unrelated.
- **Credential query id character class** (L745-L746) — still unvalidated, and
  equally unvalidated for `credentials` today. Remains `GAP-VP-03`.
- **Wallet-side option selection or UI hints** (L1010 onward) — which option a
  wallet chooses is the wallet's business.

## Shipped example

The `payment-age-loyalty` named query goes into the **quickstart scaffold** in
`crates/foundry/src/commands.rs`, not into `config.yaml` as the plan said. That
is a correction, not a preference: `config.yaml` is git-ignored and generated —
`git ls-files` does not know it — so an example added there could not be
committed and would reach nobody. As `crates/foundry/tests/quickstart.rs` states
outright, the scaffold "is the only tracked source of this config".

`dpc_card` (`com.emvco.dpc.card`) and `pid` are the two credential types this
issuer actually mints, so a wallet holding both satisfies each required set via
its first option, and the optional loyalty set goes unsatisfied without failing
the verdict. `visa_card`, `av` and `loyalty` name vcts this issuer does not mint
and exist to exercise the alternative and optional branches; the YAML comment
says so. `assert_named_queries_are_valid_dcql` parses every scaffold named
query, so the new one is guarded against silently becoming unparseable.
