# DCQL `credential_sets` — Design

**Date:** 2026-08-20
**Status:** approved (design); implementation plan not yet written
**Crate:** `foundry-verifier` (with documentation fallout in `foundry`)
**Governing spec:** `docs/specs/openid-4-verifiable-presentations-1_0.md`
(OpenID4VP 1.0), "Credential Set Query" (L879-L894) and "Selecting Credentials"
(L989-L1008).

---

## 1. Why

The driving use case is a single presentation request that asks for three things
at once, two of them as alternatives and one of them optional:

> a payment credential (girocard **or** visa), an age assertion (PID **or** a
> dedicated age-verification credential), and — if the holder happens to have one
> — a loyalty card.

DCQL expresses exactly this with `credential_sets`:

```json
"credential_sets": [
  { "options": [["girocard"], ["visa"]] },
  { "options": [["pid"], ["av"]] },
  { "options": [["loyalty"]], "required": false }
]
```

foundry cannot express it today. `credential_sets` is not modelled at all.

### 1.1 What exists today, and the premise that changes

The 2026-08-18 multi-credential work
(`docs/superpowers/specs/2026-08-18-multi-credential-dcql-design.md`) implemented
the **conjunctive** DCQL case and made `credential_sets` an explicit non-goal.
Three artifacts encode that premise:

| Artifact | Today |
| --- | --- |
| `dcql_model.rs` module doc | *"`credential_sets` (§6.2), `claim_sets`, `multiple`, and `trusted_authorities` are not modelled"* — they deserialize as ignored unknown properties (VP-0090). |
| `dcql.rs` module doc | *"Multi-credential and `credential_sets` combination logic is out of scope for this phase."* |
| `check_requested_credentials_answered` (`verify.rs`) | Cites **L993** — "with `credential_sets` absent … every credential query is non-optional" — and fails the verdict when any credential query goes unanswered. |
| `docs/conformance/openid4vc-conformance.md` | VP-0103, VP-0104 recorded `not-implemented`. |

The load-bearing sentence is L993: *"If `credential_sets` is not provided, the
Verifier requests presentations for all Credentials in `credentials` to be
returned."* Every "all credentials are mandatory" assertion in the current code
is downstream of that conditional. Introducing `credential_sets` does not
falsify those assertions — it makes them conditional in code the way they are
already conditional in the spec.

---

## 2. Decisions

Five decisions were settled during brainstorming. Each is recorded with the
alternative that was rejected, because each is the kind of choice a later reader
will otherwise re-litigate.

### 2.1 Scope: both alternatives and optionality

Full `credential_sets`: N sets, each with N options, `required` honoured.
Closes VP-0103 and VP-0104 outright rather than shipping half the feature.

### 2.2 Surplus credentials are verified, not rejected (lenient)

A wallet that returns more than the minimum — both `girocard` *and* `visa`, or a
`loyalty` card that was only optional — gets **every** returned credential fully
verified: signature, `dcql_match`, `status_check`, `transaction_data_binding`.

*Rejected:* rejecting surplus as a non-conformant response (brittle against
wallets that over-share, and it makes the over-sharing invisible), and
"verify-but-exclude-from-the-verdict" quarantining. The latter was rejected
specifically because it would amend root `AGENTS.md` §4.2 — the invariant that
`verified` equals the conjunction over *every* `CheckResult` — and §4.2 exists
precisely to stop `verified` from drifting away from the checks beneath it.
Trading it for tolerance of wallet over-sharing is a bad trade: under the lenient
rule the operator still gets an actionable verdict, because the failing check
names the surplus credential.

**Consequence, stated plainly:** a surplus credential with a revoked status sinks
the whole verdict to `verified: false` even though every required set was
satisfied. That is the accepted cost of keeping §4.2 intact.

### 2.3 Two mutually-exclusive cross-cutting checks

`requested_credentials_answered` keeps its exact current meaning and is emitted
**only when `credential_sets` is absent**. A new `credential_sets_satisfied` is
emitted **only when it is present**. Never both.

This mirrors a pattern §4.2 already blesses: `sd_jwt_vc_signature_and_kb_jwt` and
`mdoc_issuer_auth_and_device_signature` are mutually exclusive, chosen by the
answered query's declared format.

*Rejected:* generalizing `requested_credentials_answered` in place. Check names
are operator-facing API under §4.5, and silently changing what an existing name
*means* is worse than adding one — a dashboard alerting on
`requested_credentials_answered=false` would keep firing while no longer being
able to tell which algebra produced the failure. Also rejected: emitting both,
which would fail the conjunctive check whenever a wallet correctly omitted an
optional credential.

The two checks answer materially different operator questions, and the
distinction is worth the second name:

- `requested_credentials_answered=false` — "the wallet dropped a credential it
  was told was mandatory."
- `credential_sets_satisfied=false` — "the wallet returned a *combination* that
  does not answer the request."

### 2.4 Satisfaction is defined on presence, not validity

A returned credential counts toward its option even if its own `dcql_match`,
`status_check`, or signature check failed.

Rationale: this check answers exactly one question — *did the wallet return a
combination that answers my request?* — and credential validity is already
answered, per credential, by the checks §4.2 places in `credentials[i].checks`.
Folding validity in here would make one revoked credential produce two failed
checks reporting the same fact, and would yield a `credential_sets_satisfied:
false` that does not actually mean the combination was wrong. The codebase
already reasons this way: `check_status` refuses to let "I could not determine
whether this is revoked" mean "this is revoked".

§4.2's conjunction guarantees `verified: false` either way, so no verdict is
weakened — only the attribution stays clean.

### 2.5 Operator mistakes fail at request-creation time (HTTP 400)

Three new semantic validations — alongside the existing id-uniqueness check —
reject an unusable query at
`POST /admin/verification/requests` rather than letting it reach a wallet. This
follows the reasoning already written at `request.rs:253` for the existing id
uniqueness check: this is where *operator* errors become a 400 instead of a later
presentation failure that reads as the wallet's fault.

*Rejected:* accepting with a `warn`. An orphaned credential query has no
legitimate use, and under the lenient rule of §2.2 a wallet that volunteered it
anyway would get it verified and folded into the verdict without ever having been
asked for it.

---

## 3. Wire model and satisfaction algebra

### 3.1 Model (`crates/foundry-verifier/src/dcql_model.rs`, additive)

```rust
/// A Credential Set Query (OpenID4VP 1.0 §6.2, L879-L894).
#[derive(Debug, Clone, Deserialize)]
pub struct DcqlCredentialSetQuery {
    /// L886-L890: REQUIRED. A non-empty array whose every element is a
    /// non-empty array of credential query ids referencing `credentials`.
    #[serde(deserialize_with = "non_empty_options")]
    options: Vec<Vec<String>>,
    /// L892-L894: OPTIONAL. "If omitted, the default value is `true`."
    #[serde(default = "default_true")]
    required: bool,
}
```

`DcqlQuery` gains `credential_sets: Option<Vec<DcqlCredentialSetQuery>>` (via
`#[serde(default, deserialize_with = ...)]` so that a *present but empty* array is
rejected while an absent one stays `None`), plus a `credential_sets()` accessor.

Non-emptiness is enforced at **three** levels: the `credential_sets` array and
each `options` array through the module's existing `non_empty` helper, and each
individual option inside `non_empty_options` itself (one deserializer, both
levels — the inner emptiness check has no separate serde hook to hang off).
This is the same fail-closed rationale the module doc already
gives for `credentials` and `claims[].path` — an empty container that silently
"matches" is the defect being designed out — and it closes VP-0104 structurally,
at deserialization, rather than in procedural validation code.

Inner option elements are `String`, not a newtype: they are credential query ids
compared for equality against `DcqlCredentialQuery::id()`, and the character-class
constraint on ids (L745-L746) is unvalidated today for `credentials` as well
(recorded gap `GAP-VP-03`). Introducing validation on one side only would be
incoherent.

### 3.2 Algebra (new module `crates/foundry-verifier/src/credential_sets.rs`)

> A set is **satisfied** iff at least one of its `options` is a subset of the
> answered credential query ids. The check **passes** iff every set with
> `required != false` is satisfied. Optional sets are evaluated for reporting
> only and can never fail the check.

Per L999-L1001: *"To satisfy a Credential Set Query, the Wallet MUST return
presentations of a set of Credentials that match to one of the `options`."*
Per L995-L997: required sets are conjunctive, non-required ones optional.

Options are *lists*, so an option `["pid", "av"]` means "both together" — the
subset test handles multi-id options without special-casing, and a
partially-answered option satisfies nothing.

For the driving use case the algebra reads: `{girocard|visa}` ∧ `{pid|av}`, with
`{loyalty}` observed but never decisive.

The module exposes one pure function over `(&DcqlQuery, &[PresentedCredential])
→ CheckResult`. It is pure and total: no I/O, no `Result`, fail-closed, matching
`check_dcql_match`'s and `check_requested_credentials_answered`'s contracts.

### 3.3 Detail strings

On **failure**, name the unsatisfied required set and what would have satisfied
it:

```text
required credential set #0 unsatisfied: none of its options
[[girocard], [visa]] was answered; answered: [pid, loyalty]
```

On **pass**, `detail: None` when every set including the optional ones was
satisfied; otherwise a note that an optional set went unanswered:

```text
optional credential set #2 unsatisfied: [[loyalty]]
```

That second case matters because "the holder had no loyalty card" is the one
thing a passing verdict cannot otherwise convey.

Credential query ids are operator-authored request structure, not holder values,
so naming them is permitted under §4.5 — the same justification the existing
check already carries in its own comment.

---

## 4. Create-time validation (`request.rs`)

All of it lands in `create_verification_request`, immediately after the existing
id-uniqueness loop, and all of it raises `VerificationError::Dcql` → HTTP 400 via
`verifier_admin_error_response`.

### 4.1 Structural — no new code

`credential_sets` non-empty, `options` present and non-empty, each option
non-empty: all enforced by the §3.1 deserializers, so they surface through the
*existing* `serde_json::from_value::<DcqlQuery>` call at `request.rs:244` as
`dcql_query is not a valid DCQL query: …`.

### 4.2 Semantic — three new checks, only when `credential_sets` is present

1. **Dangling reference** — an id inside an option that is not the `id` of any
   entry in `credentials`. The set would be permanently unsatisfiable, so no
   wallet response could ever verify.
   > `credential set #0 option #1 references credential query 'vsia', which is not declared in 'credentials'; OpenID4VP 1.0 L890 requires option entries to reference elements in 'credentials'`
2. **Orphaned credential query** — an entry in `credentials` referenced by no
   set. Once `credential_sets` is present, L995-L997 means only what satisfies a
   set is requested, so an orphan is unrequestable.
   > `credential query 'loyalty' is declared in 'credentials' but referenced by no credential set; with 'credential_sets' present, OpenID4VP 1.0 L991-L997 means it would never be requested`
3. **All-optional query** — `credential_sets` containing no set with
   `required != false`. Such a request passes `credential_sets_satisfied`
   unconditionally, including for a `vp_token` of `{}`: `verified: true` with
   zero credentials. Spec-permissible, operationally meaningless — a verification
   request that cannot fail is not a verification.
   > `dcql_query declares no required credential set; every set has required: false, so this request would verify successfully against an empty response`
4. (Retained, unchanged) **duplicate credential query id**, the existing L745-L746
   check.

Ordering: uniqueness (existing) → dangling → orphan → all-optional, so the most
specific typo is reported first.

### 4.3 Deliberately not rejected

Stated explicitly so a reviewer does not read the omissions as oversights:

- **The same id in several sets** — legitimate and useful (a `pid` satisfying both
  an identity set and an age set). Orphan detection therefore works off the
  **union** of all referenced ids, never a partition.
- **A repeated id inside one option** (`["pid", "pid"]`) — inert under a subset
  test; rejecting it would invent a MUST the spec does not state.
- **Duplicate options within a set, or duplicate sets** — inert, same reasoning.
- **Credential query id character class** (`[A-Za-z0-9_-]`, L745-L746) — still
  unvalidated, and equally unvalidated for `credentials` today. This remains
  recorded gap `GAP-VP-03` (Minor); closing it is separate work.

### 4.4 Config-loaded named queries

Unchanged behaviour: `config.yaml`'s `named_queries` are not validated at config
load. They are resolved into `dcql` and validated here, so a malformed set in
config fails the first `POST /admin/verification/requests` that references it,
with the same 400. There is already a test asserting exactly this shape for empty
`credentials`.

---

## 5. Verification wiring (`verify.rs`)

### 5.1 One call site changes

The single site that pushes `check_requested_credentials_answered(&tx.dcql_query,
&result.credentials)` becomes a dispatcher, `check_response_completeness`, which
parses the query once and returns whichever of the two mutually-exclusive checks
of §2.3 applies:

- `credential_sets` absent → `check_requested_credentials_answered`, unchanged.
- `credential_sets` present → `check_credential_sets_satisfied`.

Nothing else in `verify.rs` moves. In particular **`select_presentations` is
untouched**: it iterates `credentials`, skips entries the `vp_token` does not
answer (deferring the verdict to policy), and rejects `vp_token` keys the request
never asked for. All three behaviours remain correct under `credential_sets` —
the first two because a missing entry is exactly what an unchosen alternative
looks like, the third because it is a statement about `credentials`, which
`credential_sets` only references. The `VerifyOutcome` / deferred-error
precedence machinery is likewise unchanged.

### 5.2 The parse-failure branch keeps the legacy name

If `serde_json::from_value::<DcqlQuery>` fails, the dispatcher cannot know which
algebra was intended, so it emits `requested_credentials_answered: false`, exactly
as today. Unreachable in practice — the query was validated at creation and
already parsed successfully by `select_presentations` upstream — but it must fail
closed under *some* name, and keeping the current one makes that path a pure
no-op.

### 5.3 Status code and verdict

An unsatisfied required set is a **policy** outcome under §4.3: HTTP 200 with
`verified: false` and a detailed check record. The response is well-formed; the
wallet simply sent the wrong combination. No new `VerificationError` variant, no
change to `server.rs`'s error mappers, no change to `check_name_for`.

§4.2 needs no mechanism change, only its enumeration: `all_checks()` already
walks `result.checks`, so `credential_sets_satisfied` enters the conjunction
automatically.

### 5.4 Logging

Existing field names only — `tracing::warn!(check = "credential_sets_satisfied",
reason = %reason, …)`, mirroring the existing check verbatim. §4.5's
operator-facing field list gains **no** entries.

`credentials_requested` keeps counting `query.credentials()` and
`credentials_answered` keeps counting presentations received; both remain
factually true under `credential_sets` ("queries in the request" / "presentations
received"), so no log field changes meaning. The set-level story lives in the new
check's `detail`.

The satisfied-required-but-unsatisfied-optional case logs at `debug`: it is not a
policy failure, so `warn` would overstate it, and §4.5 reserves `error` for
faults. Credential query ids are not payload data, so no
`sensitive_enabled()` gate applies.

---

## 6. Documentation, conformance, and a shipped example

### 6.1 A named query in `config.yaml`

The shipped config defines two credential types: `pid` (`dc+sd-jwt`, vct
`https://localhost:8443/vct/pid`) and an EMVCo DPC card (`com.emvco.dpc.card`) —
which is itself a payment credential. The driving use case is therefore
demonstrable with no extra issuer setup:

```yaml
- id: payment-age-loyalty
  dcql:
    credentials:
      - id: dpc_card   # com.emvco.dpc.card — issued by this issuer
      - id: visa_card  # not issued here; exercises the alternative branch
      - id: pid        # .../vct/pid, claims: [birthdate]
      - id: av         # not issued here
      - id: loyalty    # not issued here; exercises the optional branch
    credential_sets:
      - options: [[dpc_card], [visa_card]]   # payment: either
      - options: [[pid], [av]]               # age: either
      - options: [[loyalty]]                 # nice-to-have
        required: false
```

A wallet holding a DPC card and a PID satisfies sets 1 and 2 via each set's first
option, and set 3 goes unsatisfied without failing the verdict. The YAML comment
must say plainly that `visa_card`, `av` and `loyalty` reference vcts this issuer
does not mint and exist to exercise the alternative and optional branches.

### 6.2 Conformance report — more than two rows

`docs/conformance/openid4vc-conformance.md`:

- **VP-0103** (L884, each entry an object with the defined properties) and
  **VP-0104** (L887, `options` non-empty array of non-empty arrays):
  `not-implemented` → `conforming`. Evidence names `DcqlCredentialSetQuery`, the
  three-level `non_empty` deserializers, and the §4.2 create-time validations;
  the Tests column names the new tests.
- **VP-0090** (implementations MUST ignore unknown DCQL properties) — its
  evidence currently *lists* `credential_sets` among the properties silently
  ignored. That becomes false. `credential_sets` must come out of the list, which
  then reads `multiple`, `trusted_authorities`, `claim_sets`.
- **VP-0106 / VP-0107 / VP-0108** (Claims Query `id`) — their evidence says
  `claim_sets` "is not modelled either **(VP-0103)**", cross-referencing a row
  about to flip to `conforming`. Re-ground the cross-reference on `claim_sets`
  being unmodelled on its own merits, or those rows will contradict their own
  citation.
- Any summary counts or `not-implemented` tallies near the top of the report.

`crates/foundry/tests/conformance_report.rs` parses the report and cross-checks
cited test names against actual test functions in the tree, so every test name
written into the Tests column must exist verbatim.

### 6.3 AGENTS.md, README, OpenAPI, module docs

| Target | Change |
| --- | --- |
| Root `AGENTS.md` §4.2 | Add `credential_sets_satisfied` to the cross-cutting enumeration, marked mutually exclusive with `requested_credentials_answered`, in the same phrasing the per-credential format checks use. |
| `crates/foundry-verifier/AGENTS.md` | New `credential_sets.rs` in the module map; Gotchas gains the mutual exclusivity (§2.3) and presence-not-validity (§2.4) rules. |
| `README.md` (Logging & Observability, ~L1014-L1039) | The cross-cutting check enumeration, and the sentence about the failing check naming missing query ids. |
| `transaction.rs` — `VerificationResult::checks` doc comment | Enumerates the cross-cutting checks and is the **source** of the OpenAPI description. |
| `openapi.json` **and** `openapi-wallet.json` | Regenerate: both embed `VerificationResult`. §6 obligation even though no path or schema shape changes. Guarded by `cli_openapi.rs`. |
| `crates/foundry/assets/console.html` | Carries the same enumeration in a comment. |
| `dcql_model.rs` module doc | The scope note claiming `credential_sets` is not modelled becomes false. |
| `dcql.rs` module doc | "Multi-credential and `credential_sets` combination logic is out of scope" becomes false. |
| `docs/superpowers/changes/2026-08-20-dcql-credential-sets.md` | Change record. |

---

## 7. Testing

### 7.1 Unit — `dcql_model.rs`

- `required` defaults to `true` when omitted; `required: false` round-trips.
- Empty `credential_sets`, empty `options`, and an empty option each fail
  deserialization with the field-named message (VP-0104).
- A query carrying `claim_sets` and `multiple` alongside `credential_sets` still
  deserializes — VP-0090 stays true for what remains unmodelled.

### 7.2 Unit — `credential_sets.rs` (the algebra)

- Satisfied via the first option; satisfied via the second option.
- A multi-id option is satisfied only when **every** id is answered; a
  partially-answered multi-id option satisfies nothing.
- Unsatisfied required set → fail, detail naming the set index, its options, and
  the answered ids.
- Unsatisfied **optional** set → pass, with the §3.3 note in `detail`.
- **A credential answered but failing its own checks still satisfies its option**
  — pins §2.4 down.
- The same id referenced by two sets satisfies both.

### 7.3 Unit — `request.rs` (existing async test module)

- Each of the three new semantic validations returns `VerificationError::Dcql`:
  dangling reference, orphaned credential query, all-optional sets.
- The structural failures arrive as the existing "not a valid DCQL query" 400.
- Acceptance: the same id in two sets; the full `payment-age-loyalty` query
  persisting successfully.

### 7.4 Unit — `verify.rs`

- The dispatcher emits `requested_credentials_answered` when `credential_sets` is
  absent and `credential_sets_satisfied` when present, and **never both**
  (asserted by name over `result.checks`).
- The absent path's existing tests stay untouched, as the regression guard.
- A failing set drives `verified: false` through `all_checks()`.

### 7.5 Integration — `crates/foundry/tests/wallet_verification.rs`

This is where a `vp_token` is actually built and posted, so the end-to-end cases
belong here:

- A request carrying `credential_sets`, answered with one option per required set
  → HTTP 200, `verified: true`, `credential_sets_satisfied` passing, optional set
  noted in `detail`.
- A response answering neither payment option → HTTP 200, `verified: false`
  (policy, not 400 — §4.3), detail naming the set.
- Surplus tolerance: answering **both** payment options verifies both credentials
  and still passes the set check (§2.2).

### 7.6 Gate

Root `AGENTS.md` §5.1, verbatim, after every task:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo nextest run`, never `cargo test`. §5.2's `e2e_full_flow` runs once at the
end of the branch.

---

## 8. Non-goals

Explicitly out of scope; each stays recorded as it is today.

- **`claim_sets`** (VP-0106 through VP-0108) — a separate satisfaction algebra
  over claims within one credential. Untouched, still unmodelled.
- **`multiple: true`** — would reopen the "exactly one presentation per entry"
  guard in `select_presentations`, which L1166 currently makes airtight. Separate
  spec.
- **`trusted_authorities`** (VP-0098 through VP-0102) — unrelated.
- **Credential query id character class** (`GAP-VP-03`) — see §4.3.
- **Wallet-side option selection or UI hints** (L1010 onward) — foundry is the
  verifier; which option a wallet chooses is the wallet's business.

---

## 9. Spec citation index

Every citation below must appear in a code comment at the site that implements
it, per root `AGENTS.md` §4.4. All line numbers refer to the pinned
`docs/specs/openid-4-verifiable-presentations-1_0.md`.

| Lines | Clause | Implemented at |
| --- | --- | --- |
| L726-L728 | `credential_sets` is OPTIONAL, a non-empty array of Credential Set Queries | `DcqlQuery::credential_sets` + its `non_empty` deserializer |
| L879-L884 | A Credential Set Query is an object with the defined properties | `DcqlCredentialSetQuery` |
| L886-L890 | `options` REQUIRED: non-empty array of non-empty arrays of ids referencing `credentials` | `non_empty_options`; dangling-reference validation (§4.2.1) |
| L892-L894 | `required` OPTIONAL, default `true` | `#[serde(default = "default_true")]` |
| L991-L994 | With `credential_sets` absent, all of `credentials` is requested | The dispatcher's absent branch (§5.1), unchanged |
| L995-L997 | With it present: all required sets, plus optionally the others | The algebra (§3.2); orphan validation (§4.2.2) |
| L999-L1001 | To satisfy a set, return credentials matching **one** of its `options` | The subset test (§3.2) |
| L1007-L1008 | A wallet that cannot deliver all non-optional credentials MUST return none | `check_requested_credentials_answered`'s existing citation, now correctly scoped to the absent branch |
