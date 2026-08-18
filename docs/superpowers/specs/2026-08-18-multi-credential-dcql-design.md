# Multi-Credential DCQL Verification — Design

**Date:** 2026-08-18
**Status:** Approved for planning
**Scope:** `foundry-verifier`, `foundry` (HTTP layer, console, OpenAPI), root `AGENTS.md`

---

## 1. Context

foundry's verifier accepts a DCQL query naming any number of credential
queries, but verifies **exactly one credential per `vp_token`**. The limit is
deliberate and enforced in four places:

| Location | Enforcement |
| --- | --- |
| `verify.rs` `select_presentation` | Hard `Err` — *"vp_token answers several credential queries; this verifier verifies a single credential per vp_token"* |
| `verify.rs` `select_presentation` | `vp_token[id]` must hold exactly one presentation |
| `dcql.rs` module doc | *"Multi-credential and `credential_sets` combination logic is out of scope for this phase"* |
| `docs/conformance/openid4vc-conformance.md` | VP-0103, VP-0104, HAIP-0070 all `not-implemented` |

The **request** side already works: `create_verification_request` validates only
that the query deserializes as a `DcqlQuery`, so a multi-credential request can
already be created, signed, and advertised to a wallet. Only the response path
refuses it. A wallet answering such a request correctly today receives an
HTTP 400.

This design lifts that limit for the conjunctive case.

### 1.1 What the specification requires

OpenID4VP 1.0, *Selecting Credentials* (**L993**):

> If `credential_sets` is not provided, the Verifier requests presentations for
> all Credentials in `credentials` to be returned.

So with `credential_sets` absent — the only case in scope here — **every**
credential query is non-optional.

*Response Parameters* (**L1161**, `vp_token` at **L1166**):

> REQUIRED. This is a JSON-encoded object containing entries where the key is
> the `id` value used for a Credential Query in the DCQL query and the value is
> an array of one or more Presentations that match the respective Credential
> Query. When `multiple` is omitted, or set to `false`, the array MUST contain
> only one Presentation. There MUST NOT be any entry in the JSON-encoded object
> for optional Credential Queries when there are no matching Credentials for the
> respective Credential Query.

Three facts follow, and each one lands somewhere in this design:

1. The container is an object keyed by credential query id — already how
   `select_presentation` reads it, so no wire-format change.
2. With `multiple` omitted or `false`, an entry's array MUST hold **one**
   presentation. The existing exactly-one guard is therefore **spec-mandated**,
   not merely conservative, and it stays.
3. An entry may be absent only for an **optional** credential query. Under this
   scope nothing is optional, so a complete response has one entry per
   credential query.

*Selecting Credentials* (**L1007-1008**) closes the gap:

> If the Wallet cannot deliver all non-optional Credentials requested by the
> Verifier according to these rules, it MUST NOT return any Credential(s).

**A subset `vp_token` is therefore a wallet MUST-violation**, not a legitimate
partial answer. §5 explains why foundry nonetheless reports it as a policy
verdict rather than a structural error.

---

## 2. Scope and non-goals

**In scope.** A `vp_token` answering N credential queries of a single
conjunctive DCQL request, for the two formats this codebase implements
(`dc+sd-jwt`, `mso_mdoc`), in any mixture.

**Non-goals**, each deliberate and each left in a state where the follow-on work
is legible rather than tangled into this change:

| Non-goal | Why out, and what stays true |
| --- | --- |
| `credential_sets` (**L884**; VP-0103, VP-0104) | Alternatives and optionality (`options`, `required`) are a separate feature with their own satisfaction algebra. `credential_sets` continues to deserialize as an ignored unknown property (VP-0090). Because it is ignored, every credential query remains non-optional, which is exactly the premise §1.1 relies on. |
| `multiple: true` (**L1166**) | Several presentations under one credential query id. The exactly-one guard stays, now with a spec citation. `multiple` continues to be ignored as an unknown property. |
| Request-side changes, *except* duplicate-id rejection | `create_verification_request` already accepts multi-credential queries. The single addition is §2.1. |
| mdoc `DeviceResponse` envelope (HAIP-0070) | foundry's mdoc payload is the bespoke `{mdoc, device_signature}` pair. See §10.2. |

**A note on the interaction.** Ignoring `multiple` while requiring exactly one
presentation is safe *only* because ignoring it means the verifier never asks
for more than one. If `multiple: true` is ever honoured, the guard must move
behind that flag in the same change — otherwise a wallet correctly answering
`multiple: true` gets a 400.

### 2.1 One request-side addition: duplicate credential query ids

Duplicate `id` values across `credentials` are part of GAP-VP-03 (VP-0094;
**L745-746**: *"Within the Authorization Request, the same `id` MUST NOT be
present more than once"*), today unvalidated. Under single-credential
verification that was a self-inflicted operator misconfiguration with bounded
consequences, because every lookup resolved to the first match.

Multi-credential verification makes it **incoherent**, not merely untidy.
`select_presentations` walks declaration order and matches each credential query
against `vp_token`'s keys, so two queries sharing an `id` both match the **same**
entry: one presentation would be verified twice and surface as two `credentials`
entries with identical `query_id`s and potentially opposite `dcql_match`
verdicts. There is no correct behaviour available to choose — the request itself
is ambiguous.

So `create_verification_request` gains a duplicate-`id` check raising
`VerificationError::Dcql` (HTTP 400 on the admin API), beside the existing
validation at request.rs:245 and for the same reason recorded there: an unusable
query should be the operator's error at request-creation time, not a wallet-
visible presentation failure later.

This closes **VP-0094** only. VP-0093's charset constraint and the rest of
GAP-VP-03 remain open — they do not affect this feature's soundness, and
bundling them would widen the change without cause.

---

## 3. Data model

```rust
/// One credential presented in a `vp_token`, with the checks that were run
/// against it and the claims it disclosed.
pub struct PresentedCredential {
    /// The DCQL credential query id this presentation answered.
    pub query_id: String,
    /// `"dc+sd-jwt"` or `"mso_mdoc"`, from the query's declared format.
    pub format: String,
    /// This credential's disclosures ONLY. Never merged with another's.
    pub claims: serde_json::Value,
    /// Checks scoped to this credential.
    pub checks: Vec<CheckResult>,
}

pub struct VerificationResult {
    pub verified: bool,
    /// Cross-cutting checks only. Per-credential checks live in `credentials`.
    pub checks: Vec<CheckResult>,
    pub credentials: Vec<PresentedCredential>,
}
```

`VerificationResult.claims` is **removed**, not deprecated in place. Retaining a
single flat `claims` alongside `credentials` would require defining it for
N > 1, and every available definition is a defect: merging loses data on key
collision, taking the first silently hides the rest, and null makes the field a
lie. A field that cannot be given an honest meaning should not exist.

### 3.1 Why flat claims are a correctness bug, not a presentation choice

Today `disclosed_claims` is one `serde_json::Map` and every verified credential
writes into it. Two consequences at N > 1:

- **Claim collision.** Two SD-JWT VC credentials both disclosing `given_name`:
  the second overwrites the first, and the result reports one value as if both
  credentials agreed.
- **Status collision.** `check_status` reads `status.status_list` out of the map
  it is handed. With claims merged, credential 2's `status` claim displaces
  credential 1's, so **one credential's revocation check runs against another
  credential's status list** — the wrong bit, silently, with a passing
  `status_check`.

The second is a security defect, and it is why per-credential separation is
mandatory rather than cosmetic. Both get a pinned regression test (§9).

### 3.2 Ordering

`credentials` is ordered by the **DCQL query's declaration order**, not by
`vp_token` key order. The loop walks `dcql_query.credentials()` and picks up
whichever are answered.

Two reasons. Output is deterministic regardless of whether `serde_json` is
compiled with `preserve_order` (a `BTreeMap` would sort by key, an `IndexMap`
would follow the wallet's serialization — neither is a property this crate
should depend on). And declaration order is the order the operator authored, so
the console renders predictably across transactions.

---

## 4. Orchestrator control flow

`select_presentation` becomes **`select_presentations`**, returning
`Vec<(String, SelectedPresentation)>` in declaration order.

### 4.1 Structural rejections (HTTP 400)

Unchanged from today except as noted:

| Condition | Note |
| --- | --- |
| `vp_token` is not a JSON object | |
| An entry's value is not an array | |
| An entry's array length ≠ 1 | Now cites L1166 |
| Payload contradicts the query's declared format | |
| Declared format is unimplemented (`CredentialFormat::Other`) | |
| `dcql_query` does not deserialize | |
| **Zero** requested ids answered | Nothing to verify, nothing to attribute |
| An id present in `vp_token` that is **not** in the request | Wallet answered a question nobody asked |
| ~~Several credential queries answered~~ | **Removed** — this is the feature |

### 4.2 Per-credential verification

For each selected credential, in order, with **no early return** — a failure on
one credential must not prevent the next from being verified:

1. Format-specific signature and holder-binding verification →
   `sd_jwt_vc_signature_and_kb_jwt` or
   `mdoc_issuer_auth_and_device_signature`.
2. Disclosed claims collected into **that credential's own** map.
3. `transaction_data_binding`, when `tx.transaction_data` is `Some`. No logic
   change: `check_transaction_data_binding` already filters entries by whether
   their `credential_ids` array contains the answered query id, so it is
   already multi-credential-aware and simply moves inside the loop. The mdoc
   arm still records a hard `passed: false` (no KB-JWT exists to carry the
   binding).
4. `dcql_match` against **its own** `query_id`, preserving today's contract that
   a presentation must satisfy the query it was keyed under.
5. `status_check` against **that credential's** claims.

Verify-all rather than fail-fast, for two reasons. §4.2 of the root
`AGENTS.md` defines `verified` as the conjunction of the checks performed, which
is only meaningful when the checks are actually all performed. And "PID
signature bad, mDL fine" is a materially more useful operator verdict than "PID
signature bad, mDL unknown".

### 4.3 Cross-cutting checks and the verdict

After the loop: one top-level `requested_credentials_answered` (§6), then
`verified` computed **once** over every check at both levels.

---

## 5. Error classification (§4.3)

A `vp_token` answering a strict subset of the requested credential queries is
reported as a **policy verdict**: HTTP 200, `verified: false`, with a failed
top-level `requested_credentials_answered` naming the unanswered query ids. The
credentials that *did* arrive are still fully verified and still appear in
`credentials`.

This is a deliberate choice and the reasoning is recorded here because §1.1
establishes that a subset response violates a wallet MUST (L1007-1008):

- **The specification constrains the wallet, not the verifier's status code.**
  L1007-1008 tells the wallet what not to send. It does not prescribe how a
  verifier reports the violation, so either status is conformant.
- **A subset `vp_token` is not structurally malformed.** It parses, every
  presentation inside it is well-formed, and each verifies on its own merits.
  Root `AGENTS.md` §4.3 reserves 400 for structural and cryptographic faults;
  classifying a well-formed response as structural stretches that category past
  its meaning.
- **Diagnostic value.** A verdict naming the missing credential query is far
  more actionable than an opaque `invalid_request`. This repository has already
  paid for the opposite: a bare *"KB-JWT audience mismatch"* that named neither
  compared value required sensitive payload logging on a live deployment to
  diagnose (`2026-08-18-kb-jwt-audience-mismatch-names-both-values.md`).
- **Real wallets violate MUSTs.** The `web-origin:` accommodation for Google
  Wallet's draft-24 behaviour (`2026-08-18-dc-api-legacy-web-origin-audience.md`)
  is a live example. A verifier whose response to non-conformance is an
  unexplained 400 makes such interop problems expensive to find.

**The failure detail must attribute the fault to the wallet**, naming L1007-1008,
so an operator reading the log learns the wallet omitted a non-optional
credential — not that foundry requested something unusual.

Unchanged: structural and crypto faults → 400; status-fetch unavailability →
502 (§7).

---

## 6. Check vocabulary and the §4.2 amendment

The six existing check names split by level, each keeping its current meaning.
Exactly one name is added.

| Level | Checks |
| --- | --- |
| Top-level (`result.checks`) | `jwe_decryption`, **`requested_credentials_answered`** *(new)* |
| Per-credential (`credentials[i].checks`) | `sd_jwt_vc_signature_and_kb_jwt` \| `mdoc_issuer_auth_and_device_signature`, `dcql_match`, `status_check`, `transaction_data_binding` (conditional) |

`requested_credentials_answered` is deliberately **not** named
`credential_set_satisfied`: `credential_sets` is the DCQL feature explicitly out
of scope (§2), and reusing its vocabulary would suggest it had been implemented.

### 6.1 Root `AGENTS.md` §4.2 amendment

Current text:

> `VerificationResult.verified` MUST equal `checks.iter().all(|c| c.passed)`.

That is no longer sufficient — with checks at two levels it is satisfiable while
a per-credential check fails. It becomes the conjunction over **every**
`CheckResult` in the result: the top-level `checks` **and** every
`credentials[i].checks` entry.

The same amendment applies to the three reminder lines in
`crates/foundry-verifier/AGENTS.md`, and to the assertion in
`crates/foundry/tests/wallet_verification.rs`, which walks only the top level
today and would pass while a per-credential check failed.

`check_dcql_match` and `check_transaction_data_binding` keep their
never-returns-`Err` fail-closed contracts.

---

## 7. The deferred-error path (502)

`check_status` returns `Err(VerificationError::StatusUnavailable)` on a network
failure, which the HTTP layer maps to 502. Root `AGENTS.md` §4.3 makes that
normative, and this design **keeps it**: "I could not determine whether this
credential is revoked" is not "this credential is revoked", and collapsing the
two would invite a relying party to treat an unreachable status list as a clean
bill of health.

Propagating with `?` inside a verify-all loop is nonetheless wrong, because the
wrapper's `Err` arm rebuilds `tx.result` from scratch and would discard every
check already collected — losing precisely the "the mDL was fine" half that
makes the 502 diagnosable. So the internal function returns:

```rust
struct VerifyOutcome {
    result: VerificationResult,
    /// `StatusUnavailable` only. Any other error still returns `Err` directly.
    deferred: Option<VerificationError>,
}
```

The wrapper always persists `outcome.result`, then — when `deferred` is `Some` —
sets `state = Failed` and returns the `Err`, so the wallet still receives a
retryable 502 while the operator keeps the partial picture.

### 7.1 The trap this must not fall into

A credential whose status fetch was unavailable pushes **no** `status_check`
record, because unavailability is not a policy failure. On its own that leaves
`all(passed)` computing `true` — persisting `verified: true` on a transaction
that just returned 502, which the console would faithfully render as a success.

The deferred path therefore **appends a top-level failed `status_check`** whose
detail names the offending `query_id`, mirroring what `check_name_for` already
does on today's error path. `verified` stays derived and comes out `false`
honestly. No branch anywhere assigns `verified` a literal.

---

## 8. Observability (§4.5)

- `failed_checks` currently counts top-level checks only and would under-report
  once most checks are per-credential. It becomes a total across both levels.
- New span fields: `credentials_requested` and `credentials_answered` —
  **counts**, not identifiers.
- Unanswered `query_id`s are named in the `warn` for
  `requested_credentials_answered`. Query ids are operator-authored request
  structure, not holder values — the same reasoning `dcql.rs` already records
  for naming claim paths in a DCQL mismatch.
- Per-credential **claims** are never logged, at any level, under any flag.
- Every `#[tracing::instrument]` keeps `skip_all`.
- A subset response logs at `warn` (a policy outcome, HTTP 200), not `error`.

---

## 9. Testing

TDD: each behaviour gets a failing test before its implementation.

### 9.1 New coverage

| Test | Asserts |
| --- | --- |
| Two-credential happy path (one SD-JWT VC + one mdoc) | Both verify; `verified: true`; two `credentials` entries in declaration order |
| Subset response | HTTP 200, `verified: false`, failed `requested_credentials_answered` naming the missing id; the answered credential still fully verified. Labelled as **non-conformant wallet input** per L1007-1008 |
| Unknown query id in `vp_token` | Structural 400 |
| Zero requested ids answered | Structural 400 |
| **Claim isolation** | Two credentials both disclosing `given_name`; neither value overwrites the other |
| **Status isolation** | One revoked, one not; the failed `status_check` lands on the revoked credential's entry and the other passes |
| Status list unreachable for one credential | 502 **and** `tx.result` retains the other credential's checks; persisted `verified` is `false` |
| Declaration-order determinism | `credentials` order follows the query, not `vp_token` key order |
| `transaction_data` scoped to one of two credentials | The named credential is bound; the other records "no entries scoped to the answered credential query" and passes |
| Per-credential array length ≠ 1 | Still 400, citing L1166 |
| Duplicate credential query `id` in the request | `create_verification_request` returns `VerificationError::Dcql` → HTTP 400 on the admin API, before any transaction is persisted (§2.1) |

### 9.2 Existing coverage to migrate

~20 `vp_token` construction sites in
`crates/foundry/tests/wallet_verification.rs` and ~49 in
`crates/foundry-verifier/src/verify.rs` move to the new result shape;
`select_presentation_rejects_multiple_answered_queries` inverts into an
acceptance test; `wallet_verification.rs`'s `all(|c| c.passed)` assertion walks
both levels.

### 9.3 Gate

Root `AGENTS.md` §5.1, whole workspace, every time:

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Plus the E2E suite (§5.2) before merge:

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

---

## 10. Documentation and conformance

### 10.1 Documentation

| File | Change |
| --- | --- |
| Root `AGENTS.md` §4.2 | Conjunction over both check levels (§6.1) |
| `crates/foundry-verifier/AGENTS.md` | Module map (`select_presentations`), the §4.2 reminders, `VerificationResult` shape, and the single-credential gotcha — which **inverts** |
| `crates/foundry/AGENTS.md` | Only if response mapping changes |
| `openapi-wallet.json` | Regenerated for `PresentedCredential` and the changed `VerificationResult` (§6 of root `AGENTS.md`) |
| `crates/foundry/assets/console.html` | Render per-credential sections instead of one `claims` blob; per-credential checks lists |
| `README.md` | Only where it documents the verification result shape |
| `docs/superpowers/changes/2026-08-18-multi-credential-dcql.md` | Change record |

### 10.2 Conformance

`docs/conformance/openid4vc-conformance.md` is a living document; closing or
re-grounding a row is part of this change, not a follow-up.

- **HAIP-0070** — *"When multiple ISO mdocs are returned each MUST be returned
  in a separate `DeviceResponse` matching its respective DCQL query."* Its
  current evidence cites *"foundry presents exactly one credential per
  `vp_token` by design"*. That cause disappears, but the row does **not** become
  `conforming`: the clause requires a `DeviceResponse` per mdoc, and foundry's
  mdoc payload is the bespoke `{mdoc, device_signature}` pair, which is not a
  `DeviceResponse` at all. It stays `not-implemented` with **rewritten
  evidence** naming the envelope as the real blocker.
- **VP-0103, VP-0104** — stay `not-implemented`; evidence corrected to cite the
  `credential_sets` non-goal (§2) rather than the single-credential design,
  which will no longer exist.
- **VP-0094** (duplicate credential query `id`) — **closed** by §2.1, moving from
  `gap` to `conforming`, because multi-credential verification cannot be sound
  without it.
- **VP-0093** (`id` charset) and the remainder of **GAP-VP-03** — stay open. The
  register entry is narrowed to the constraints still unvalidated once
  uniqueness is enforced, so it no longer claims uniqueness among them.

---

## 11. Files touched

| File | Nature |
| --- | --- |
| `crates/foundry-verifier/src/transaction.rs` | `PresentedCredential`; `VerificationResult` loses `claims`, gains `credentials` |
| `crates/foundry-verifier/src/verify.rs` | `select_presentations`, the per-credential loop, `VerifyOutcome`, `requested_credentials_answered`, observability fields, the error arm |
| `crates/foundry-verifier/src/request.rs` | Duplicate credential query `id` rejection (§2.1) |
| `crates/foundry-verifier/src/dcql.rs` | Module-doc scope note rewritten |
| `crates/foundry-verifier/src/lib.rs` | Export `PresentedCredential` |
| `crates/foundry/src/server.rs` | Result construction/mapping where it touches the changed shape |
| `crates/foundry/src/openapi.rs` | Register `PresentedCredential` |
| `crates/foundry/assets/console.html` | Per-credential rendering |
| `crates/foundry/tests/wallet_verification.rs` | Migration + new flow tests |
| `openapi-wallet.json` | Regenerated |
| Root + verifier `AGENTS.md`, conformance report, change record | Per §10 |

`crates/foundry-verifier/src/status.rs` and `dcql_model.rs` need no change:
`check_status` already takes the claims it should check, and the wire model
already parses multi-credential queries (`parses_spec_multi_credential_example`).

---

## 12. Two decisions this design settles rather than defers

Both of these began as open questions. Leaving either to be resolved inside an
implementation task would have made the same ambiguity someone else's problem.

1. **Duplicate credential query ids are rejected at request creation**, closing
   VP-0094 as part of this change — see §2.1. The alternative (a follow-up
   change) was rejected because this feature is not sound without it.
2. **The console renders one stacked section per credential**, in declaration
   order, each with its own heading (`query_id` and `format`), its own checks
   list, and its own claims block; cross-cutting checks stay in the existing
   top-level list. Accordions and tabs were considered and rejected: both hide
   a failing credential behind a collapsed control, and a verification console's
   job is to show a failure without requiring a click. Stacked sections also
   reuse the existing `.checks` and `.json` DOM patterns rather than introducing
   interactive state.

---

## 13. Verification of this design

Every specification claim above was read from the pinned text at
`docs/specs/openid-4-verifiable-presentations-1_0.md`, not recalled:
L993 (all credentials requested when `credential_sets` is absent), L1007-1008
(wallet MUST NOT return any credential if it cannot deliver all non-optional
ones), L1161/L1166 (`vp_token` shape, the exactly-one rule, absence permitted
only for optional queries), L745-746 (credential query `id` uniqueness), L884
(`credential_sets` entries).

One correction was made during this design: an earlier draft justified the
policy-verdict classification of §5 by citing VP-0117, which governs claims
*within* a credential and does **not** make a subset `vp_token` conformant.
L1007-1008 says the opposite. The classification survived the correction; its
justification is now §5's four grounds rather than a misread clause.
