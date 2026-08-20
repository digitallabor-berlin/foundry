# DCQL `credential_sets` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach `foundry-verifier` to author and evaluate DCQL `credential_sets`, so one presentation request can ask for alternatives ("girocard **or** visa") and optional credentials ("a loyalty card if you have one").

**Architecture:** Purely additive. `dcql_model.rs` grows a `credential_sets` wire model; a new `credential_sets.rs` holds the satisfaction algebra as one pure function; `verify.rs` gains a dispatcher that emits **either** today's `requested_credentials_answered` (when `credential_sets` is absent) **or** a new `credential_sets_satisfied` (when present), never both; `request.rs` rejects unusable queries at creation time with HTTP 400. `select_presentations` and the per-credential verification path are not touched.

**Tech Stack:** Rust 2024 edition, `serde` / `serde_json` (custom `deserialize_with`), `tracing`, `axum`, `cargo nextest`.

**Spec:** [`docs/superpowers/specs/2026-08-20-dcql-credential-sets-design.md`](../specs/2026-08-20-dcql-credential-sets-design.md) — read it before Task 1. Governing protocol text: [`docs/specs/openid-4-verifiable-presentations-1_0.md`](../../specs/openid-4-verifiable-presentations-1_0.md), lines L726-L728, L879-L894, L989-L1008.

## Global Constraints

Every task's requirements implicitly include this section.

- **Test runner is `cargo nextest run`, never `cargo test`.** nextest does not run doctests; do not write any.
- **The gate (root `AGENTS.md` §5.1), run in full after every task — there is no cheaper tier and no affected-crate subset:**

  ```bash
  cargo fmt
  cargo nextest run --workspace --no-fail-fast --status-level fail
  cargo clippy --workspace --all-targets -- -D warnings
  ```

  A green run ends with a line shaped `Summary [ <elapsed>] <N> tests run: <N> passed, <M> skipped`. Quote that line when reporting.
- **No `.unwrap()` / `.expect()` / `panic!()` / `unreachable!()` in request-handling code** (root `AGENTS.md` §4.1). Permitted only inside `#[cfg(test)]` and `tests/`.
- **`verified` must equal the conjunction over every `CheckResult`** (§4.2). Never hardcode `verified: true`. `credential_sets_satisfied` enters the conjunction automatically via `VerificationResult::all_checks()`; do not special-case it.
- **Policy failures → HTTP 200 with `verified: false`; structural/crypto → 400; network → 502** (§4.3). An unsatisfied credential set is **policy**.
- **Every new protocol-facing branch carries a spec citation comment** naming file and line, e.g. `// OpenID4VP 1.0 L999-L1001: to satisfy a set, the wallet returns credentials matching one of its options.` (§4.4)
- **`#[tracing::instrument]` requires `skip_all`.** Log only existing field names: `check`, `reason`. Credential query ids are operator-authored request structure and ARE loggable; holder claim values are not (§4.5).
- **Exact check-name strings** (operator-facing API, §4.5 — do not improvise spelling):
  - `requested_credentials_answered` — emitted **only** when `credential_sets` is absent.
  - `credential_sets_satisfied` — emitted **only** when `credential_sets` is present.
- **Two refinements to the design doc**, deliberate, adopt them as written here:
  1. `check_credential_sets_satisfied` takes `&[DcqlCredentialSetQuery]`, not `&DcqlQuery` — the dispatcher has already proven the sets exist, so a slice removes an unreachable `None` branch.
  2. `check_requested_credentials_answered` is refactored to take a parsed `&DcqlQuery` instead of `&Value`. The dispatcher must parse in order to choose a branch; leaving the parse inside the branch would parse the same value twice and re-derive a decision already made. Its body is otherwise unchanged, and the parse-failure behaviour moves to the dispatcher (design §5.2).

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `crates/foundry-verifier/src/dcql_model.rs` | Modify — add `DcqlCredentialSetQuery`, the `credential_sets` field + accessor, two deserializers, `default_true`. Rewrite the module-doc scope note. | 1 |
| `crates/foundry-verifier/src/credential_sets.rs` | **Create** — the satisfaction algebra and the `credential_sets_satisfied` check. One pure, total function plus a rendering helper. | 2 |
| `crates/foundry-verifier/src/lib.rs` | Modify — declare the new private module. | 2 |
| `crates/foundry-verifier/src/request.rs` | Modify — three create-time validations in `create_verification_request`. | 3 |
| `crates/foundry-verifier/src/verify.rs` | Modify — `check_response_completeness` dispatcher; `check_requested_credentials_answered` signature. | 4 |
| `crates/foundry-verifier/src/dcql.rs` | Modify — module-doc scope note only. | 4 |
| `crates/foundry/tests/wallet_verification.rs` | Modify — parametrize the `pending_verification_*` helper; three end-to-end cases. | 5 |
| `crates/foundry-verifier/AGENTS.md`, root `AGENTS.md`, `README.md`, `crates/foundry-verifier/src/transaction.rs`, `openapi.json`, `openapi-wallet.json`, `crates/foundry/assets/console.html`, `config.yaml`, `docs/conformance/openid4vc-conformance.md`, `docs/superpowers/changes/2026-08-20-dcql-credential-sets.md` | Modify/create — documentation, conformance, generated specs, shipped example. | 6 |

Task order is dependency order: 1 → 2 → 3 → 4 → 5 → 6. Tasks 3 and 4 both depend on 1; 4 depends on 2; 5 depends on 3 and 4; 6 depends on everything (it cites test names that must already exist).

---

### Task 1: `credential_sets` wire model

**Files:**

- Modify: `crates/foundry-verifier/src/dcql_model.rs` (module doc L1-L21; `DcqlQuery` L64-L74; new struct; new deserializers near L44-L62; test module from L228)

**Interfaces:**

- Consumes: nothing (first task).
- Produces:
  - `pub struct DcqlCredentialSetQuery` with `pub fn options(&self) -> &[Vec<String>]` and `pub fn required(&self) -> bool`.
  - `pub fn DcqlQuery::credential_sets(&self) -> Option<&[DcqlCredentialSetQuery]>` — `None` when the member is absent.

- [ ] **Step 1: Write the failing tests**

Append to the existing `mod tests` in `crates/foundry-verifier/src/dcql_model.rs` (it already has `fn parse(v: Value) -> Result<DcqlQuery, serde_json::Error>` and `use serde_json::json;`):

```rust
    /// OpenID4VP 1.0 L892-L894: "If omitted, the default value is `true`."
    #[test]
    fn credential_set_required_defaults_to_true() {
        let q = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "options": [["c1"]] }]
        }))
        .unwrap();

        let sets = q.credential_sets().expect("credential_sets must be modelled");
        assert_eq!(sets.len(), 1);
        assert!(sets[0].required(), "omitted `required` means true");
        assert_eq!(sets[0].options(), [vec!["c1".to_string()]]);
    }

    #[test]
    fn credential_set_required_false_round_trips() {
        let q = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "options": [["c1"]], "required": false }]
        }))
        .unwrap();

        assert!(!q.credential_sets().unwrap()[0].required());
    }

    /// An absent member is `None`, not an empty slice: the two mean different
    /// things to the verifier (all-credentials-required vs. set algebra).
    #[test]
    fn absent_credential_sets_is_none() {
        let q = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }]
        }))
        .unwrap();

        assert!(q.credential_sets().is_none());
    }

    /// A multi-id option means "all of these together" (L887-L888).
    #[test]
    fn options_carry_multi_id_alternatives() {
        let q = parse(json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": {} },
                { "id": "av", "format": "dc+sd-jwt", "meta": {} }
            ],
            "credential_sets": [{ "options": [["pid", "av"], ["av"]] }]
        }))
        .unwrap();

        let sets = q.credential_sets().unwrap();
        assert_eq!(sets[0].options().len(), 2);
        assert_eq!(sets[0].options()[0], vec!["pid".to_string(), "av".to_string()]);
    }

    /// L726-L728: `credential_sets` is a NON-EMPTY array when present. An empty
    /// one is fail-closed-rejected for the same reason `credentials` is: a query
    /// constraining nothing must not silently "match".
    #[test]
    fn rejects_empty_credential_sets() {
        let err = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": []
        }))
        .expect_err("an empty credential_sets array must be rejected");

        assert!(
            err.to_string().contains("credential_sets"),
            "the message must name the field: {err}"
        );
    }

    /// VP-0104 / L886-L890: `options` is REQUIRED and non-empty.
    #[test]
    fn rejects_empty_options_array() {
        let err = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "options": [] }]
        }))
        .expect_err("an empty options array must be rejected");

        assert!(err.to_string().contains("options"), "{err}");
    }

    /// VP-0104 / L889-L890: "The value of each element in the `options` array is
    /// a non-empty array of identifiers."
    #[test]
    fn rejects_an_empty_option() {
        let err = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "options": [["c1"], []] }]
        }))
        .expect_err("an empty option must be rejected");

        let msg = err.to_string();
        assert!(msg.contains("options[1]"), "name the offending index: {msg}");
    }

    /// VP-0104: `options` is REQUIRED, so a set without it is malformed.
    #[test]
    fn rejects_a_credential_set_without_options() {
        parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "required": true }]
        }))
        .expect_err("`options` is REQUIRED");
    }
```

Then **edit the existing test** `ignores_unknown_properties_at_every_level` (currently at L246-L263): its fixture uses `"credential_sets": [{ "options": [["c1"]] }]` as an example of an ignored unknown property. That is now a *known* property, so the test would no longer prove what it claims. Replace that one line with an unknown member that stays unmodelled, and keep everything else identical:

```rust
            "claim_sets": [["gn"]],
```

(`claim_sets` remains a non-goal — design §8 — so it is the honest replacement, and VP-0090's conformance evidence in Task 6 is rewritten to match.)

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier dcql_model
```

Expected: the eight new tests fail to **compile** — `no method named 'credential_sets' found for struct 'DcqlQuery'`. A compile failure is the correct "red" here; the API does not exist yet.

- [ ] **Step 3: Add the deserializers and `default_true`**

In `crates/foundry-verifier/src/dcql_model.rs`, after the existing `non_empty_values` helper (L57-L62), add:

```rust
fn non_empty_credential_sets<'de, D>(
    d: D,
) -> Result<Option<Vec<DcqlCredentialSetQuery>>, D::Error>
where
    D: Deserializer<'de>,
{
    non_empty(d, "credential_sets").map(Some)
}

/// OpenID4VP 1.0 L886-L890: `options` is a non-empty array whose every element
/// is itself a non-empty array of credential query identifiers. Both levels are
/// enforced here because the inner one has no separate serde hook to hang off:
/// `Vec<Vec<String>>` deserializes as a whole.
fn non_empty_options<'de, D>(d: D) -> Result<Vec<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let options: Vec<Vec<String>> = non_empty(d, "options")?;
    if let Some(idx) = options.iter().position(|option| option.is_empty()) {
        return Err(D::Error::custom(format!(
            "`options[{idx}]` must be a non-empty array"
        )));
    }
    Ok(options)
}

fn default_true() -> bool {
    true
}
```

- [ ] **Step 4: Add the struct and wire it into `DcqlQuery`**

Replace `DcqlQuery` (L64-L74) with:

```rust
/// A DCQL query (OpenID4VP 1.0 §6).
#[derive(Debug, Clone, Deserialize)]
pub struct DcqlQuery {
    #[serde(deserialize_with = "non_empty_credentials")]
    credentials: Vec<DcqlCredentialQuery>,
    /// OpenID4VP 1.0 L726-L728: OPTIONAL, a non-empty array of Credential Set
    /// Queries constraining WHICH of `credentials` to return.
    ///
    /// `Option` is load-bearing: absent (`None`) means every credential query is
    /// non-optional (L993), while present means the set algebra decides
    /// (L995-L997). `deserialize_with` runs only when the member is present, so
    /// an absent one stays `None` while a present-but-empty one is rejected.
    #[serde(default, deserialize_with = "non_empty_credential_sets")]
    credential_sets: Option<Vec<DcqlCredentialSetQuery>>,
}

impl DcqlQuery {
    pub fn credentials(&self) -> &[DcqlCredentialQuery] {
        &self.credentials
    }

    /// `None` when the query carries no `credential_sets` member.
    pub fn credential_sets(&self) -> Option<&[DcqlCredentialSetQuery]> {
        self.credential_sets.as_deref()
    }
}
```

Then add the new struct immediately after `DcqlCredentialQuery`'s `impl` block (after L108):

```rust
/// A Credential Set Query (OpenID4VP 1.0 L879-L894).
///
/// One entry expresses a single use case the Verifier needs satisfied, and its
/// `options` are the alternative credential combinations that would satisfy it.
#[derive(Debug, Clone, Deserialize)]
pub struct DcqlCredentialSetQuery {
    #[serde(deserialize_with = "non_empty_options")]
    options: Vec<Vec<String>>,
    /// L892-L894: "OPTIONAL A boolean which indicates whether this set of
    /// Credentials is required ... If omitted, the default value is `true`."
    #[serde(default = "default_true")]
    required: bool,
}

impl DcqlCredentialSetQuery {
    /// Each element is one alternative: a list of credential query ids that
    /// together satisfy this set (L887-L888).
    pub fn options(&self) -> &[Vec<String>] {
        &self.options
    }

    pub fn required(&self) -> bool {
        self.required
    }
}
```

- [ ] **Step 5: Rewrite the module-doc scope note**

The module doc (L1-L21) currently claims `credential_sets` is not modelled. Replace the scope paragraph and extend the non-empty list:

```rust
//! Scope is deliberately the subset [`crate::dcql`] and
//! [`crate::credential_sets`] consume. `claim_sets`, `multiple`, and
//! `trusted_authorities` are not modelled; per §6, unknown properties are
//! ignored rather than rejected, so queries carrying them still deserialize and
//! are evaluated on the parts we do understand.
//!
//! Five non-empty constraints from the spec are enforced at deserialization,
//! because each one is fail-closed:
//!
//! - `credentials` (§6) — a query requesting nothing must not silently "match".
//! - `credential_sets` (L726-L728) — likewise for a query constraining nothing.
//! - `options` and each individual option (L886-L890) — an empty option would
//!   be satisfied by the empty set, making its whole set unconditionally
//!   satisfied.
//! - `claims[].path` (§6.3) — an empty path would resolve to the credential
//!   root and spuriously satisfy any claim requirement.
//! - `claims[].values` (§6.3) — spec requires non-empty when present.
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier dcql_model
```

Expected: PASS, including the pre-existing `ignores_unknown_properties_at_every_level`.

- [ ] **Step 7: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all green. Clippy will flag `DcqlCredentialSetQuery` as never constructed outside tests **only if** you forgot `pub` on the struct or its accessors — it is reachable through `DcqlQuery::credential_sets`, so a dead-code warning means the wiring is wrong.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-verifier/src/dcql_model.rs
git commit -m "feat(verifier): model DCQL credential_sets wire format

Adds DcqlCredentialSetQuery (OpenID4VP 1.0 L879-L894) with options and
required (default true), and DcqlQuery::credential_sets(). Non-emptiness
is enforced at deserialization for credential_sets, options, and each
individual option (VP-0104), matching the module's existing fail-closed
treatment of credentials and claims[].path.

credential_sets is no longer an ignored unknown property, so the VP-0090
test fixture now uses claim_sets, which remains unmodelled."
```

---

### Task 2: The satisfaction algebra

**Files:**

- Create: `crates/foundry-verifier/src/credential_sets.rs`
- Modify: `crates/foundry-verifier/src/lib.rs:1-7` (module declarations)

**Interfaces:**

- Consumes: `DcqlCredentialSetQuery::options()`, `DcqlCredentialSetQuery::required()` (Task 1); `crate::transaction::{CheckResult, PresentedCredential}` (existing — `PresentedCredential` has a `pub query_id: String`).
- Produces: `pub(crate) fn check_credential_sets_satisfied(sets: &[DcqlCredentialSetQuery], answered: &[PresentedCredential]) -> CheckResult`, and `pub(crate) const CHECK_CREDENTIAL_SETS_SATISFIED: &str = "credential_sets_satisfied"`.

- [ ] **Step 1: Create the file with its tests, and declare the module**

Declare the module first, or nothing in the new file compiles at all. In `crates/foundry-verifier/src/lib.rs`, add this as the **first** line, so the list reads `credential_sets`, `dcql`, `dcql_model`, …:

```rust
mod credential_sets;
```

Private, like `dcql_model`: nothing outside the crate needs it, and its output travels inside `VerificationResult`.

Then create `crates/foundry-verifier/src/credential_sets.rs` containing **only** the test module, so the tests fail on the missing function and nothing else:

```rust
#[cfg(test)]
mod tests {
    use crate::dcql_model::DcqlQuery;
    use crate::transaction::{CheckResult, PresentedCredential};

    use super::*;

    /// The `PresentedCredential` fields this check does not read are set to
    /// neutral values: satisfaction is defined on PRESENCE, not validity
    /// (design §2.4), so `checks` is deliberately empty here and a FAILING
    /// credential is covered by its own test below.
    fn answered(ids: &[&str]) -> Vec<PresentedCredential> {
        ids.iter()
            .map(|id| PresentedCredential {
                query_id: (*id).to_string(),
                format: "dc+sd-jwt".to_string(),
                credential_type: None,
                claims: serde_json::json!({}),
                checks: Vec::new(),
            })
            .collect()
    }

    fn sets(v: serde_json::Value) -> DcqlQuery {
        serde_json::from_value(v).expect("fixture must be a valid DCQL query")
    }

    /// The driving use case: payment (girocard|visa), age (pid|av), optional
    /// loyalty. Answered with the FIRST option of each required set.
    fn use_case() -> DcqlQuery {
        sets(serde_json::json!({
            "credentials": [
                { "id": "girocard", "format": "dc+sd-jwt" },
                { "id": "visa", "format": "dc+sd-jwt" },
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "av", "format": "dc+sd-jwt" },
                { "id": "loyalty", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [
                { "options": [["girocard"], ["visa"]] },
                { "options": [["pid"], ["av"]] },
                { "options": [["loyalty"]], "required": false }
            ]
        }))
    }

    #[test]
    fn satisfied_via_the_first_option_of_each_required_set() {
        let q = use_case();
        let check = check_credential_sets_satisfied(
            q.credential_sets().unwrap(),
            &answered(&["girocard", "pid", "loyalty"]),
        );

        assert_eq!(check.check, "credential_sets_satisfied");
        assert!(check.passed, "detail: {:?}", check.detail);
        assert_eq!(
            check.detail, None,
            "every set including the optional one was satisfied, so there is \
             nothing left to report"
        );
    }

    #[test]
    fn satisfied_via_the_second_option_of_each_required_set() {
        let q = use_case();
        let check = check_credential_sets_satisfied(
            q.credential_sets().unwrap(),
            &answered(&["visa", "av", "loyalty"]),
        );

        assert!(check.passed, "detail: {:?}", check.detail);
    }

    /// The optional set going unanswered is not a failure -- but it IS the one
    /// thing a passing verdict cannot otherwise convey, so it lands in `detail`.
    #[test]
    fn an_unsatisfied_optional_set_passes_but_is_reported() {
        let q = use_case();
        let check = check_credential_sets_satisfied(
            q.credential_sets().unwrap(),
            &answered(&["girocard", "pid"]),
        );

        assert!(check.passed, "an optional set can never fail the check");
        let detail = check.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("optional credential set #2"),
            "name the unsatisfied optional set: {detail}"
        );
        assert!(detail.contains("loyalty"), "name its options: {detail}");
    }

    #[test]
    fn an_unsatisfied_required_set_fails_and_names_it() {
        let q = use_case();
        let check =
            check_credential_sets_satisfied(q.credential_sets().unwrap(), &answered(&["pid"]));

        assert!(!check.passed);
        let detail = check.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("required credential set #0"),
            "name the unsatisfied set: {detail}"
        );
        assert!(
            detail.contains("girocard") && detail.contains("visa"),
            "name what would have satisfied it: {detail}"
        );
        assert!(
            detail.contains("pid"),
            "name what the wallet actually answered: {detail}"
        );
    }

    /// Every unsatisfied required set is reported, not just the first: an
    /// operator fixing one wallet bug at a time needs the whole list.
    #[test]
    fn every_unsatisfied_required_set_is_reported() {
        let q = use_case();
        let check = check_credential_sets_satisfied(q.credential_sets().unwrap(), &answered(&[]));

        assert!(!check.passed);
        let detail = check.detail.as_deref().unwrap_or_default();
        assert!(detail.contains("credential set #0"), "{detail}");
        assert!(detail.contains("credential set #1"), "{detail}");
    }

    /// L887-L888: an option is a LIST, so a multi-id option means "all of these
    /// together" -- satisfied only when every id is answered.
    #[test]
    fn a_multi_id_option_needs_every_id() {
        let q = sets(serde_json::json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "av", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [{ "options": [["pid", "av"]] }]
        }));

        assert!(
            check_credential_sets_satisfied(
                q.credential_sets().unwrap(),
                &answered(&["pid", "av"])
            )
            .passed
        );
        assert!(
            !check_credential_sets_satisfied(q.credential_sets().unwrap(), &answered(&["pid"]))
                .passed,
            "a partially-answered option satisfies nothing"
        );
    }

    /// Design §2.4: satisfaction is PRESENCE, not validity. A revoked or
    /// otherwise failing credential still answers its option; its own
    /// `status_check` fails separately and §4.2's conjunction still yields
    /// `verified: false`.
    #[test]
    fn a_failing_credential_still_satisfies_its_option() {
        let q = use_case();
        let mut answered = answered(&["girocard", "pid", "loyalty"]);
        answered[0].checks.push(CheckResult {
            check: "status_check".to_string(),
            passed: false,
            detail: Some("revoked".to_string()),
        });

        let check = check_credential_sets_satisfied(q.credential_sets().unwrap(), &answered);
        assert!(
            check.passed,
            "the combination answers the request; validity is a separate check"
        );
    }

    /// The same id may appear in several sets (a PID satisfying both an identity
    /// and an age set), and answering it satisfies all of them.
    #[test]
    fn one_credential_can_satisfy_several_sets() {
        let q = sets(serde_json::json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt" }],
            "credential_sets": [
                { "options": [["pid"]] },
                { "options": [["pid"]] }
            ]
        }));

        assert!(
            check_credential_sets_satisfied(q.credential_sets().unwrap(), &answered(&["pid"]))
                .passed
        );
    }

    /// Surplus credentials do not disturb the algebra (design §2.2): they are
    /// verified on their own merits elsewhere, and here they are simply extra
    /// members of the answered set.
    #[test]
    fn surplus_answers_do_not_break_satisfaction() {
        let q = use_case();
        let check = check_credential_sets_satisfied(
            q.credential_sets().unwrap(),
            &answered(&["girocard", "visa", "pid", "av", "loyalty"]),
        );

        assert!(check.passed, "detail: {:?}", check.detail);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier credential_sets
```

Expected: a compile error naming `check_credential_sets_satisfied` as not found. Do not proceed until you have seen it — a run reporting "zero tests matched" instead means the module declaration in Step 1 was missed.

- [ ] **Step 3: Write the implementation**

Prepend to `crates/foundry-verifier/src/credential_sets.rs`, above the test module:

```rust
//! DCQL Credential Set Query satisfaction (OpenID4VP 1.0 L879-L894, L989-L1008).
//!
//! `credentials` says WHAT the Verifier will accept; `credential_sets` says
//! WHICH COMBINATIONS of it actually answer the request. This module owns the
//! second question and nothing else.
//!
//! L995-L997: with `credential_sets` present, the Verifier requests "all of the
//! Credential Set Queries ... where the `required` attribute is true or
//! omitted, and optionally, any of the other Credential Set Queries."
//! L999-L1001: "To satisfy a Credential Set Query, the Wallet MUST return
//! presentations of a set of Credentials that match to one of the `options`."
//!
//! Satisfaction is defined on the PRESENCE of an answered credential query, not
//! on whether that credential passed its own checks. This check answers exactly
//! one question -- did the wallet return a combination that answers the request
//! -- while validity is answered per credential by `dcql_match`,
//! `status_check`, and the format-specific signature check. Folding validity in
//! here would make one revoked credential produce two failed checks reporting
//! the same fact, and would yield a `credential_sets_satisfied: false` that does
//! not mean the combination was wrong. Root AGENTS.md §4.2's conjunction
//! guarantees `verified: false` either way.
//!
//! The conjunctive case -- `credential_sets` absent, every credential query
//! non-optional (L993) -- is NOT handled here. It stays in
//! `verify::check_requested_credentials_answered`, and the two checks are
//! mutually exclusive by construction.

use crate::dcql_model::DcqlCredentialSetQuery;
use crate::transaction::{CheckResult, PresentedCredential};

/// Operator-facing check name (root AGENTS.md §4.5). Emitted ONLY when the
/// query carries `credential_sets`; its counterpart
/// `requested_credentials_answered` is emitted only when it does not.
pub(crate) const CHECK_CREDENTIAL_SETS_SATISFIED: &str = "credential_sets_satisfied";

/// Does the answered set of credentials satisfy every required Credential Set
/// Query?
///
/// Takes the sets rather than the whole `DcqlQuery`: the caller has already
/// established that `credential_sets` is present, so a slice removes a branch
/// that could never be taken.
///
/// Never returns `Err` -- fail-closed and total, matching `check_dcql_match` and
/// `check_requested_credentials_answered`.
pub(crate) fn check_credential_sets_satisfied(
    sets: &[DcqlCredentialSetQuery],
    answered: &[PresentedCredential],
) -> CheckResult {
    let answered_ids: Vec<&str> = answered
        .iter()
        .map(|credential| credential.query_id.as_str())
        .collect();

    let mut unsatisfied_required: Vec<String> = Vec::new();
    let mut unsatisfied_optional: Vec<String> = Vec::new();

    for (index, set) in sets.iter().enumerate() {
        // L999-L1001: satisfied by ANY one option, and an option is satisfied
        // only when EVERY id in it was answered.
        let satisfied = set
            .options()
            .iter()
            .any(|option| option.iter().all(|id| answered_ids.contains(&id.as_str())));
        if satisfied {
            continue;
        }

        // L995-L997: required sets are conjunctive; the rest are optional and
        // can never fail this check.
        let described = describe(index, set);
        if set.required() {
            unsatisfied_required.push(described);
        } else {
            unsatisfied_optional.push(described);
        }
    }

    // Credential query ids are operator-authored request structure, not holder
    // values, so naming them in a log record and in `detail` is permitted
    // (root AGENTS.md §4.5).
    if !unsatisfied_required.is_empty() {
        let reason = format!(
            "no answered combination satisfies {}; answered: [{}]",
            unsatisfied_required.join("; "),
            answered_ids.join(", ")
        );
        tracing::warn!(
            check = CHECK_CREDENTIAL_SETS_SATISFIED,
            reason = %reason,
            "the response does not satisfy every required credential set"
        );
        return CheckResult {
            check: CHECK_CREDENTIAL_SETS_SATISFIED.to_string(),
            passed: false,
            detail: Some(reason),
        };
    }

    if unsatisfied_optional.is_empty() {
        return CheckResult {
            check: CHECK_CREDENTIAL_SETS_SATISFIED.to_string(),
            passed: true,
            detail: None,
        };
    }

    // Not a policy failure, so `warn` would overstate it -- but "the holder had
    // no loyalty card" is the one thing a passing verdict cannot otherwise
    // convey, so it is recorded in `detail` and logged at `debug`.
    let detail = format!(
        "{} unsatisfied; answered: [{}]",
        unsatisfied_optional.join("; "),
        answered_ids.join(", ")
    );
    tracing::debug!(
        check = CHECK_CREDENTIAL_SETS_SATISFIED,
        reason = %detail,
        "every required credential set was satisfied; an optional one was not"
    );
    CheckResult {
        check: CHECK_CREDENTIAL_SETS_SATISFIED.to_string(),
        passed: true,
        detail: Some(detail),
    }
}

/// `required credential set #0 (options [[girocard], [visa]])` — the set's
/// index, its obligation, and what would have satisfied it, in one phrase.
fn describe(index: usize, set: &DcqlCredentialSetQuery) -> String {
    let obligation = if set.required() { "required" } else { "optional" };
    let options: Vec<String> = set
        .options()
        .iter()
        .map(|option| format!("[{}]", option.join(", ")))
        .collect();
    format!(
        "{obligation} credential set #{index} (options [{}])",
        options.join(", ")
    )
}
```

The test module's imports from Step 1 now resolve: `DcqlQuery` for the fixtures, `CheckResult` for the failing-credential test, `PresentedCredential` for the `answered` helper.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier credential_sets
```

Expected: PASS, nine tests.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: green. The function has no production caller until Task 4, so a `dead_code` warning is conceivable here. **Do not add `#[allow(dead_code)]`** — the test module exercises it, which normally satisfies the lint. If a warning appears anyway, report it rather than silencing it: it means the item is unreachable in a way Task 4's wiring will also have to solve.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-verifier/src/credential_sets.rs crates/foundry-verifier/src/lib.rs
git commit -m "feat(verifier): add credential_sets satisfaction algebra

check_credential_sets_satisfied: a required set is satisfied when at least
one of its options is a subset of the answered credential query ids
(OpenID4VP 1.0 L999-L1001); the check passes when every required set is
satisfied (L995-L997). Optional sets are reported, never decisive.

Satisfaction is defined on presence, not validity: credential validity is
already reported per credential, and root AGENTS.md §4.2's conjunction
still drives verified: false. Not yet wired into verify.rs."
```

---

### Task 3: Create-time validation

**Files:**

- Modify: `crates/foundry-verifier/src/request.rs` — in `create_verification_request`, after the id-uniqueness loop that ends at L268; tests appended to the existing `mod tests`

**Interfaces:**

- Consumes: `DcqlQuery::credential_sets()`, `DcqlCredentialSetQuery::{options, required}` (Task 1).
- Produces: no new public API. Three new `VerificationError::Dcql` cases out of `create_verification_request`, which the admin API already maps to HTTP 400 via `verifier_admin_error_response`.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `crates/foundry-verifier/src/request.rs`. The module already provides `test_storage().await` and `sample_config("/tmp/fake_key.pem")`; follow the shape of the existing `create_rejects_malformed_dcql_query`.

```rust
    /// A helper for the credential_sets validation tests: everything is
    /// identical except the query under test.
    async fn create_with_query(query: serde_json::Value) -> Result<(), VerificationError> {
        let storage = test_storage().await;
        let config = sample_config("/tmp/fake_key.pem");
        let req = CreateVerificationRequest {
            dcql_query: Some(query),
            named_query_ref: None,
            transport: "request_uri".to_string(),
            transaction_data: None,
        };
        create_verification_request(&config, &storage, req, 1_700_000_000)
            .await
            .map(|_| ())
    }

    /// OpenID4VP 1.0 L889-L890: option entries "reference elements in
    /// `credentials`". A typo'd reference makes its set permanently
    /// unsatisfiable, so no wallet response could ever verify -- an operator
    /// error, caught at 400 rather than surfacing later as the wallet's fault.
    #[tokio::test]
    async fn create_rejects_a_credential_set_option_referencing_an_unknown_id() {
        let err = create_with_query(serde_json::json!({
            "credentials": [{ "id": "visa", "format": "dc+sd-jwt" }],
            "credential_sets": [{ "options": [["vsia"]] }]
        }))
        .await
        .expect_err("a dangling option reference must be rejected");

        let msg = err.to_string();
        assert!(matches!(err, VerificationError::Dcql(_)), "{msg}");
        assert!(msg.contains("vsia"), "name the dangling id: {msg}");
        assert!(msg.contains("credential set #0"), "locate it: {msg}");
    }

    /// L991-L997: with `credential_sets` present, only what satisfies a set is
    /// requested -- so a credential query no set references would never be
    /// asked for at all.
    #[tokio::test]
    async fn create_rejects_a_credential_query_no_set_references() {
        let err = create_with_query(serde_json::json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "orphan", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [{ "options": [["pid"]] }]
        }))
        .await
        .expect_err("an unreferenced credential query must be rejected");

        let msg = err.to_string();
        assert!(matches!(err, VerificationError::Dcql(_)), "{msg}");
        assert!(msg.contains("orphan"), "name the orphan: {msg}");
    }

    /// A request whose every set is optional passes `credential_sets_satisfied`
    /// unconditionally -- including against an empty `vp_token`, yielding
    /// `verified: true` with zero credentials. Spec-permissible, operationally
    /// meaningless: a verification request that cannot fail is not a
    /// verification.
    #[tokio::test]
    async fn create_rejects_an_all_optional_credential_sets_query() {
        let err = create_with_query(serde_json::json!({
            "credentials": [{ "id": "loyalty", "format": "dc+sd-jwt" }],
            "credential_sets": [{ "options": [["loyalty"]], "required": false }]
        }))
        .await
        .expect_err("a query with no required set must be rejected");

        let msg = err.to_string();
        assert!(matches!(err, VerificationError::Dcql(_)), "{msg}");
        assert!(
            msg.contains("no required credential set"),
            "say what is missing: {msg}"
        );
    }

    /// The structural constraints are enforced at deserialization (Task 1), so
    /// they must arrive here as the SAME "not a valid DCQL query" 400 an empty
    /// `credentials` array already produces -- not as a panic or a 500.
    #[tokio::test]
    async fn create_rejects_structurally_invalid_credential_sets() {
        for query in [
            serde_json::json!({
                "credentials": [{ "id": "c1", "format": "dc+sd-jwt" }],
                "credential_sets": []
            }),
            serde_json::json!({
                "credentials": [{ "id": "c1", "format": "dc+sd-jwt" }],
                "credential_sets": [{ "options": [] }]
            }),
            serde_json::json!({
                "credentials": [{ "id": "c1", "format": "dc+sd-jwt" }],
                "credential_sets": [{ "options": [["c1"], []] }]
            }),
        ] {
            let Err(err) = create_with_query(query.clone()).await else {
                panic!("must be rejected: {query}");
            };
            let msg = err.to_string();
            assert!(
                msg.contains("not a valid DCQL query"),
                "structural failures keep the existing message: {msg}"
            );
        }
    }

    /// The same id in several sets is legitimate and useful -- a PID that
    /// satisfies both an identity set and an age set -- so orphan detection
    /// works off the UNION of referenced ids, never a partition.
    #[tokio::test]
    async fn create_accepts_one_credential_query_referenced_by_several_sets() {
        create_with_query(serde_json::json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt" }],
            "credential_sets": [
                { "options": [["pid"]] },
                { "options": [["pid"]], "required": false }
            ]
        }))
        .await
        .expect("an id may appear in several sets");
    }

    /// The driving use case must be creatable end to end.
    #[tokio::test]
    async fn create_accepts_the_payment_age_loyalty_query() {
        create_with_query(serde_json::json!({
            "credentials": [
                { "id": "dpc_card", "format": "dc+sd-jwt" },
                { "id": "visa_card", "format": "dc+sd-jwt" },
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "av", "format": "dc+sd-jwt" },
                { "id": "loyalty", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [
                { "options": [["dpc_card"], ["visa_card"]] },
                { "options": [["pid"], ["av"]] },
                { "options": [["loyalty"]], "required": false }
            ]
        }))
        .await
        .expect("the payment/age/loyalty query must be accepted");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier request::tests
```

Expected: the three rejection tests FAIL (the queries are accepted today); `create_rejects_structurally_invalid_credential_sets` and both acceptance tests PASS already — Task 1 gave you the structural half and the acceptance half needs no new code. That mixed result is correct.

- [ ] **Step 3: Write the validations**

In `create_verification_request`, immediately after the id-uniqueness `for cq in parsed.credentials()` loop (which ends at L268 with its closing brace), insert:

```rust
    // OpenID4VP 1.0 L991-L997: once `credential_sets` is present, the Verifier
    // requests only the combinations those sets describe -- so a set the wallet
    // could never satisfy, or a credential query no set names, is an operator
    // error with no possible wallet response. Caught here, as a 400, for the
    // same reason the id-uniqueness check above is: this is where operator
    // mistakes stop looking like the wallet's fault.
    if let Some(sets) = parsed.credential_sets() {
        let declared: std::collections::HashSet<&str> =
            parsed.credentials().iter().map(|cq| cq.id()).collect();

        // L889-L890: option entries reference elements in `credentials`.
        for (set_index, set) in sets.iter().enumerate() {
            for (option_index, option) in set.options().iter().enumerate() {
                for id in option {
                    if !declared.contains(id.as_str()) {
                        return Err(VerificationError::Dcql(format!(
                            "credential set #{set_index} option #{option_index} references \
                             credential query '{id}', which is not declared in 'credentials'; \
                             OpenID4VP 1.0 requires option entries to reference elements in \
                             'credentials'"
                        )));
                    }
                }
            }
        }

        // The converse: a declared credential query that no set references can
        // never be requested (L991-L997), so it is unreachable dead weight and
        // almost certainly a missing reference.
        let referenced: std::collections::HashSet<&str> = sets
            .iter()
            .flat_map(|set| set.options().iter())
            .flat_map(|option| option.iter())
            .map(String::as_str)
            .collect();
        for cq in parsed.credentials() {
            if !referenced.contains(cq.id()) {
                return Err(VerificationError::Dcql(format!(
                    "credential query '{}' is declared in 'credentials' but referenced by no \
                     credential set; with 'credential_sets' present, OpenID4VP 1.0 requests \
                     only the combinations those sets describe, so it would never be requested",
                    cq.id()
                )));
            }
        }

        // A query whose every set is optional is satisfied by an empty
        // response, so it would report `verified: true` having verified
        // nothing. Not a spec violation -- an operator one.
        if !sets.iter().any(|set| set.required()) {
            return Err(VerificationError::Dcql(
                "dcql_query declares no required credential set; every set has \
                 required: false, so this request would verify successfully against an \
                 empty response"
                    .to_string(),
            ));
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier request::tests
```

Expected: PASS, all of them.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-verifier/src/request.rs
git commit -m "feat(verifier): validate credential_sets at request creation

Three operator-error checks, each an HTTP 400 rather than a later
presentation failure: an option referencing an undeclared credential
query id (OpenID4VP 1.0 L889-L890), a declared credential query no set
references (L991-L997, unrequestable), and a query whose every set is
optional (would verify true against an empty response).

An id referenced by several sets stays legal: orphan detection works off
the union of referenced ids."
```

---

### Task 4: Wire the dispatcher into verification

**Files:**

- Modify: `crates/foundry-verifier/src/verify.rs` — `check_requested_credentials_answered` (L1075-L1145), its call site (L1320-L1324), tests near L3812-L3850
- Modify: `crates/foundry-verifier/src/dcql.rs` — module doc L9-L12 only

**Interfaces:**

- Consumes: `check_credential_sets_satisfied` (Task 2); `DcqlQuery::credential_sets()` (Task 1). `CHECK_CREDENTIAL_SETS_SATISFIED` stays internal to `credential_sets.rs` — `verify.rs` never names that string.
- Produces: `fn check_response_completeness(dcql_query: &Value, answered: &[PresentedCredential]) -> CheckResult` — private to `verify.rs`. `check_requested_credentials_answered` now takes `&DcqlQuery`.

- [ ] **Step 1: Write the failing tests**

In `verify.rs`'s `mod tests`, **replace** `requested_credentials_answered_fails_closed_on_an_unreadable_query` (currently calling `check_requested_credentials_answered(&serde_json::json!({}), &[])`) with the dispatcher-level equivalent, and **edit** `requested_credentials_answered_passes_when_every_query_is_answered` to parse its fixture first. Then add the new dispatch tests:

```rust
    /// The dispatcher owns the parse-failure path, because deciding which of the
    /// two mutually-exclusive checks applies requires reading the query. It must
    /// fail closed under the legacy name: it cannot know which algebra was
    /// intended.
    #[test]
    fn response_completeness_fails_closed_on_an_unreadable_query() {
        let check = check_response_completeness(&serde_json::json!({}), &[]);
        assert_eq!(check.check, "requested_credentials_answered");
        assert!(
            !check.passed,
            "an unreadable query must fail closed, never pass"
        );
    }

    /// Root AGENTS.md §4.2 / design §2.3: the two checks are mutually
    /// exclusive. With `credential_sets` absent, only the conjunctive one.
    #[test]
    fn response_completeness_emits_only_the_conjunctive_check_without_sets() {
        let query = serde_json::json!({"credentials": [
            {"id": "pid", "format": "dc+sd-jwt"}
        ]});
        let check = check_response_completeness(&query, &presented(&["pid"]));

        assert_eq!(check.check, "requested_credentials_answered");
        assert!(check.passed);
    }

    /// And with `credential_sets` present, only the set check.
    #[test]
    fn response_completeness_emits_only_the_set_check_with_sets() {
        let query = serde_json::json!({
            "credentials": [
                {"id": "pid", "format": "dc+sd-jwt"},
                {"id": "av", "format": "dc+sd-jwt"}
            ],
            "credential_sets": [{ "options": [["pid"], ["av"]] }]
        });
        let check = check_response_completeness(&query, &presented(&["av"]));

        assert_eq!(check.check, "credential_sets_satisfied");
        assert!(
            check.passed,
            "the second option was answered: {:?}",
            check.detail
        );
    }

    /// The case the conjunctive check would get WRONG: a wallet that answers
    /// one alternative has not "dropped" the other.
    #[test]
    fn an_unanswered_alternative_is_not_a_missing_credential() {
        let query = serde_json::json!({
            "credentials": [
                {"id": "girocard", "format": "dc+sd-jwt"},
                {"id": "visa", "format": "dc+sd-jwt"}
            ],
            "credential_sets": [{ "options": [["girocard"], ["visa"]] }]
        });
        let check = check_response_completeness(&query, &presented(&["girocard"]));

        assert!(
            check.passed,
            "answering one option satisfies the set: {:?}",
            check.detail
        );
    }

    /// A shared constructor for the dispatch tests; the fields this check does
    /// not read are neutral.
    fn presented(ids: &[&str]) -> Vec<PresentedCredential> {
        ids.iter()
            .map(|id| PresentedCredential {
                query_id: (*id).to_string(),
                format: "dc+sd-jwt".to_string(),
                credential_type: None,
                claims: serde_json::json!({}),
                checks: Vec::new(),
            })
            .collect()
    }
```

Edit the surviving pass test's body so its call site matches the new signature — replace its final two lines with:

```rust
        let query: crate::dcql_model::DcqlQuery = serde_json::from_value(query).unwrap();
        let check = check_requested_credentials_answered(&query, &answered);
        assert_eq!(check.check, "requested_credentials_answered");
        assert!(check.passed);
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo nextest run -p foundry-verifier verify::tests
```

Expected: compile failure — `cannot find function 'check_response_completeness'`.

- [ ] **Step 3: Change `check_requested_credentials_answered` to take a parsed query**

In `verify.rs`, change the signature and delete the parsing prelude (the `let query: DcqlQuery = match serde_json::from_value(...)` block and its error arm — that behaviour moves to the dispatcher). Keep the doc comment, tightening its first paragraph to name the precondition:

```rust
/// Did the wallet answer every credential query the request asked for?
///
/// Applies ONLY when `credential_sets` is absent. OpenID4VP 1.0 L993: with
/// `credential_sets` absent "the Verifier requests presentations for all
/// Credentials in `credentials`", so every credential query is non-optional.
/// L1007-1008: "If the Wallet cannot deliver all non-optional Credentials
/// requested by the Verifier according to these rules, it MUST NOT return any
/// Credential(s)."
///
/// When `credential_sets` IS present, `check_credential_sets_satisfied` answers
/// the question instead and this function is not called
/// (`check_response_completeness` chooses).
///
/// [... keep the existing paragraphs about the policy-verdict rationale ...]
///
/// Never returns `Err` -- fail-closed, matching `check_dcql_match`.
fn check_requested_credentials_answered(
    query: &DcqlQuery,
    answered: &[PresentedCredential],
) -> CheckResult {
    const CHECK: &str = "requested_credentials_answered";

    let missing: Vec<&str> = query
        .credentials()
        .iter()
        .map(|cq| cq.id())
        .filter(|id| !answered.iter().any(|c| c.query_id == *id))
        .collect();

    // [... rest of the body unchanged ...]
}
```

- [ ] **Step 4: Add the dispatcher**

Immediately above `check_requested_credentials_answered`, add:

```rust
/// Choose and run the one cross-cutting completeness check this request calls
/// for.
///
/// OpenID4VP 1.0 L991-L997 defines two different questions, and which one
/// applies is decided by whether `credential_sets` is present:
///
/// - absent (L993) — every credential query is non-optional, so the question is
///   "was each one answered?" → `requested_credentials_answered`.
/// - present (L995-L997) — the sets decide which combinations answer the
///   request → `credential_sets_satisfied`.
///
/// They are mutually exclusive by construction, mirroring the per-credential
/// format checks (root AGENTS.md §4.2). Emitting both would fail the
/// conjunctive check whenever a wallet correctly omitted an optional
/// credential.
fn check_response_completeness(
    dcql_query: &Value,
    answered: &[PresentedCredential],
) -> CheckResult {
    // Not reachable through the request path -- `select_presentations` has
    // already parsed this query successfully, and `create_verification_request`
    // validated it before persisting. Fail closed rather than pass on a query
    // this function cannot read. The legacy check name is deliberate: without a
    // parsed query there is no way to know which algebra was intended.
    let query: DcqlQuery = match serde_json::from_value(dcql_query.clone()) {
        Ok(q) => q,
        Err(e) => {
            let reason = format!("dcql_query is not a valid DCQL query: {e}");
            tracing::warn!(
                check = "requested_credentials_answered",
                reason = %reason,
                "cannot evaluate requested credentials"
            );
            return CheckResult {
                check: "requested_credentials_answered".to_string(),
                passed: false,
                detail: Some(reason),
            };
        }
    };

    match query.credential_sets() {
        Some(sets) => check_credential_sets_satisfied(sets, answered),
        None => check_requested_credentials_answered(&query, answered),
    }
}
```

Add the import at the top of `verify.rs`, next to the existing `use crate::dcql::{PresentedFormat, check_dcql_match};`:

```rust
use crate::credential_sets::check_credential_sets_satisfied;
```

- [ ] **Step 5: Change the call site**

At L1320-L1324, replace the call and update its comment to say which question is being asked:

```rust
    // 4. Set-level policy: does the response answer what the request asked for?
    //    Which question that is -- "every credential query" or "every required
    //    credential set" -- depends on `credential_sets` (OpenID4VP 1.0
    //    L991-L997).
    checks.push(check_response_completeness(&tx.dcql_query, &credentials));
```

- [ ] **Step 6: Rewrite `dcql.rs`'s scope note**

In `crates/foundry-verifier/src/dcql.rs`, replace the scope paragraph (L9-L12), which claims `credential_sets` logic is out of scope:

```rust
//! Scope: this module judges ONE credential against ONE credential query. Which
//! query a presentation answers is decided upstream by
//! `verify::select_presentations`, and which COMBINATIONS of answered queries
//! satisfy the request is decided by [`crate::credential_sets`].
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo nextest run -p foundry-verifier
```

Expected: PASS. In particular the pre-existing subset test (which asserts `requested_credentials_answered` fails and names `diploma`) must still pass — it uses a query with no `credential_sets`, so it takes the unchanged branch. If it fails, the dispatcher is choosing the wrong branch.

- [ ] **Step 8: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: green.

- [ ] **Step 9: Commit**

```bash
git add crates/foundry-verifier/src/verify.rs crates/foundry-verifier/src/dcql.rs
git commit -m "feat(verifier): emit credential_sets_satisfied when sets are present

check_response_completeness parses the query once and dispatches to one of
two mutually-exclusive cross-cutting checks (OpenID4VP 1.0 L991-L997):
requested_credentials_answered when credential_sets is absent, the new
credential_sets_satisfied when present. Never both.

check_requested_credentials_answered now takes a parsed &DcqlQuery, since
the dispatcher must parse to choose a branch; the parse-failure path moves
to the dispatcher and keeps the legacy check name, because without a
parsed query there is no way to know which algebra was intended."
```

---

### Task 5: End-to-end verification through the real server

**Files:**

- Modify: `crates/foundry/tests/wallet_verification.rs` — parametrize `pending_verification_with_vp_token` (L1665-L1680); add three tests

**Interfaces:**

- Consumes: the full wired path (Tasks 1-4).
- Produces: `async fn pending_verification_with_query(dcql_query: serde_json::Value, make_vp_token: impl FnOnce(String) -> serde_json::Value) -> (axum::Router, String, String, tempfile::TempDir)`.

- [ ] **Step 1: Parametrize the existing helper**

`pending_verification_with_vp_token` (L1673) hardcodes a single-credential query. Extract the query as a parameter, keeping both existing entry points working unchanged. Replace its signature and the `create_req_body` literal:

```rust
/// As `pending_verification_with_vp_token`, but lets the caller supply the DCQL
/// query too, so `credential_sets` requests can be driven through the real
/// server.
async fn pending_verification_with_query(
    dcql_query: serde_json::Value,
    make_vp_token: impl FnOnce(String) -> serde_json::Value,
) -> (axum::Router, String, String, tempfile::TempDir) {
    // [... body of the current pending_verification_with_vp_token, with the
    //      create_req_body literal replaced by: ...]
    let create_req_body = serde_json::json!({
        "dcql_query": dcql_query,
        "transport": "request_uri"
    });
    // [... rest unchanged ...]
}

/// As `pending_verification_with_jwe`, but lets the caller decide the `vp_token`
/// shape, so non-conformant envelopes can be driven through the real server
/// instead of only through unit tests.
async fn pending_verification_with_vp_token(
    make_vp_token: impl FnOnce(String) -> serde_json::Value,
) -> (axum::Router, String, String, tempfile::TempDir) {
    pending_verification_with_query(
        serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/pid"] }
            }]
        }),
        make_vp_token,
    )
    .await
}
```

The helper issues exactly one SD-JWT VC and hands its compact serialization to `make_vp_token`, so a `credential_sets` query in these tests must be satisfiable by that one credential.

- [ ] **Step 2: Write the failing tests**

Append to `crates/foundry/tests/wallet_verification.rs`:

```rust
// ---------------------------------------------------------------------------
// DCQL `credential_sets` (OpenID4VP 1.0 L879-L894, L989-L1008)
//
// The helper issues ONE SD-JWT VC, so these queries are shaped so that one
// credential is enough to satisfy every required set -- which is exactly the
// point of alternatives.
// ---------------------------------------------------------------------------

/// A required set with two options, answered by the second; plus an optional set
/// the wallet cannot satisfy. Per L995-L997 that verifies.
#[tokio::test]
async fn credential_sets_alternative_answered_by_one_option_verifies() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_query(
        serde_json::json!({
            "credentials": [
                { "id": "visa_card", "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["https://localhost:8443/vct/visa"] } },
                { "id": "pid", "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["https://localhost:8443/vct/pid"] } },
                { "id": "loyalty", "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["https://localhost:8443/vct/loyalty"] } }
            ],
            "credential_sets": [
                { "options": [["visa_card"], ["pid"]] },
                { "options": [["loyalty"]], "required": false }
            ]
        }),
        |presentation| serde_json::json!({ "pid": [presentation] }),
    )
    .await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let result: VerificationResult = serde_json::from_str(&body).unwrap();
    assert!(result.verified, "one option per required set is enough: {body}");

    let check = result
        .checks
        .iter()
        .find(|c| c.check == "credential_sets_satisfied")
        .expect("the set check must be recorded");
    assert!(check.passed);
    let detail = check.detail.as_deref().unwrap_or_default();
    assert!(
        detail.contains("optional credential set #1"),
        "the unsatisfied optional set is worth reporting: {detail}"
    );

    assert!(
        !result
            .checks
            .iter()
            .any(|c| c.check == "requested_credentials_answered"),
        "the two completeness checks are mutually exclusive: {:?}",
        result.checks
    );
}

/// A response answering NONE of a required set's options is a policy failure:
/// HTTP 200 with `verified: false` (root AGENTS.md §4.3), naming the set.
#[tokio::test]
async fn credential_sets_unsatisfied_required_set_is_a_policy_failure() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_query(
        serde_json::json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["https://localhost:8443/vct/pid"] } },
                { "id": "girocard", "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["https://localhost:8443/vct/girocard"] } },
                { "id": "visa_card", "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["https://localhost:8443/vct/visa"] } }
            ],
            "credential_sets": [
                { "options": [["pid"]] },
                { "options": [["girocard"], ["visa_card"]] }
            ]
        }),
        |presentation| serde_json::json!({ "pid": [presentation] }),
    )
    .await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unsatisfied set is a policy verdict, not a structural error: {body}"
    );

    let result: VerificationResult = serde_json::from_str(&body).unwrap();
    assert!(!result.verified);

    let check = result
        .checks
        .iter()
        .find(|c| c.check == "credential_sets_satisfied")
        .expect("the set check must be recorded");
    assert!(!check.passed);
    let detail = check.detail.as_deref().unwrap_or_default();
    assert!(
        detail.contains("credential set #1"),
        "name the unsatisfied set: {detail}"
    );
    assert!(
        detail.contains("girocard") && detail.contains("visa_card"),
        "name what would have satisfied it: {detail}"
    );

    // The credential that DID arrive is still fully verified and reported.
    assert_eq!(result.credentials.len(), 1);
    assert_eq!(result.credentials[0].query_id, "pid");
    assert!(
        result.credentials[0].checks.iter().all(|c| c.passed),
        "the answered credential's own checks all pass: {:?}",
        result.credentials[0].checks
    );
}

/// The conjunctive path must be untouched: with `credential_sets` absent, the
/// legacy check name is still the one emitted.
#[tokio::test]
async fn without_credential_sets_the_conjunctive_check_is_still_emitted() {
    let (wallet_app, verification_id, jwe_str, _dir) = pending_verification_with_jwe().await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();

    let (status, body) = status_and_body(wallet_app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let result: VerificationResult = serde_json::from_str(&body).unwrap();
    assert!(
        result
            .checks
            .iter()
            .any(|c| c.check == "requested_credentials_answered" && c.passed),
        "checks: {:?}",
        result.checks
    );
    assert!(
        !result
            .checks
            .iter()
            .any(|c| c.check == "credential_sets_satisfied"),
        "checks: {:?}",
        result.checks
    );
}
```

Check the file's existing imports before running: `VerificationResult` must be in scope (the multi-credential test at L1409 already deserializes one — reuse whatever import it uses; add `use foundry_verifier::VerificationResult;` only if it is absent).

- [ ] **Step 3: Run the tests, then prove they can fail**

```bash
cargo nextest run -p foundry --test wallet_verification credential_sets
```

Expected: PASS on the first run. Tasks 1-4 already built the behaviour, so there is no red phase left to observe — which makes these tests worthless until you have shown they *can* fail. **Do that explicitly:** change `credential_sets_satisfied` to a typo in one assertion, re-run, confirm it fails, revert; then do the same for the `verified` assertion in the policy-failure test.

- [ ] **Step 4: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add crates/foundry/tests/wallet_verification.rs
git commit -m "test: credential_sets end-to-end through the wallet routes

Three cases through the real /vp/request -> /vp/response flow: a required
set answered by its second option verifies (with the unsatisfied optional
set reported in detail); a required set answered by none of its options is
HTTP 200 verified:false naming the set (policy, per AGENTS.md 4.3); and
the conjunctive path still emits requested_credentials_answered.

Each asserts the two completeness checks are mutually exclusive.
pending_verification_with_vp_token now delegates to a query-parametrized
pending_verification_with_query."
```

---

### Task 6: Documentation, conformance, generated specs, shipped example

No production code changes. This task is a §4.4/§4.5/§6/§8 obligation and is
**not** optional: several of the files it touches currently assert things that
Tasks 1-5 made false.

**Files:**

- Modify: `crates/foundry-verifier/src/transaction.rs` (`VerificationResult::checks` doc comment, ~L60-L67)
- Modify: `AGENTS.md` (§4.2), `crates/foundry-verifier/AGENTS.md` (module map + Gotchas), `README.md` (~L1010-L1040)
- Modify: `crates/foundry/assets/console.html` (the cross-cutting-checks comment)
- Modify: `config.yaml` (`verifier.named_queries`)
- Modify: `docs/conformance/openid4vc-conformance.md` (VP-0090, VP-0103, VP-0104, VP-0106/0107/0108, summary counts)
- Regenerate: `openapi.json`, `openapi-wallet.json`
- Create: `docs/superpowers/changes/2026-08-20-dcql-credential-sets.md`

**Interfaces:** none — documentation only. Every test name cited in the conformance report must already exist from Tasks 1-5, because `crates/foundry/tests/conformance_report.rs` cross-checks cited names against real test functions.

- [ ] **Step 1: Update the `VerificationResult::checks` doc comment**

In `crates/foundry-verifier/src/transaction.rs`, replace:

```rust
    /// **Cross-cutting checks only** -- `jwe_decryption` and
    /// `requested_credentials_answered`. Per-credential checks live in
    /// `credentials[i].checks`.
```

with:

```rust
    /// **Cross-cutting checks only** -- `jwe_decryption`, plus exactly one of
    /// `requested_credentials_answered` (when the DCQL query carries no
    /// `credential_sets`) or `credential_sets_satisfied` (when it does). The two
    /// are mutually exclusive; they answer different questions (OpenID4VP 1.0
    /// L991-L997). Per-credential checks live in `credentials[i].checks`.
```

- [ ] **Step 2: Regenerate the OpenAPI specs**

That doc comment is the source of the schema description embedded in **both**
generated specs. Find the regeneration command in
`crates/foundry/AGENTS.md` and run it, then confirm both files changed:

```bash
git diff --stat openapi.json openapi-wallet.json
```

Expected: both listed. `crates/foundry/tests/cli_openapi.rs` guards this; if it fails, the specs are stale.

- [ ] **Step 3: Update root `AGENTS.md` §4.2**

Replace the check enumeration sentence so the mutual exclusivity is stated where the invariant lives:

```markdown
  **Cross-cutting** (`result.checks`): `jwe_decryption`, and exactly one of
  `requested_credentials_answered` (DCQL query without `credential_sets`) or
  `credential_sets_satisfied` (with `credential_sets`) — mutually exclusive,
  chosen by the query, the same way the per-credential format checks are chosen
  by the answered query's declared format.
```

- [ ] **Step 4: Update `crates/foundry-verifier/AGENTS.md`**

Read the file first, then: add `credential_sets.rs` to the module map with a one-line responsibility ("DCQL Credential Set Query satisfaction — which combinations of answered credential queries answer the request"); and add two Gotchas entries:

- The two completeness checks are mutually exclusive; adding a third emitter, or emitting both, breaks the operator contract in root `AGENTS.md` §4.2.
- Set satisfaction is defined on **presence**, not validity: a revoked credential still satisfies its option, and `verified: false` arrives via §4.2's conjunction over the credential's own `status_check`. Making the set check validity-aware would double-report one fault.

- [ ] **Step 5: Update `README.md`**

In the Logging & Observability section (~L1010-L1040): extend the cross-cutting check list the same way as §4.2, and extend the sentence about the failing check naming missing query ids so it covers the set case ("…or, for a `credential_sets` request, the unsatisfied set and the options that would have satisfied it"). Do not add or rename any log field.

- [ ] **Step 6: Update `crates/foundry/assets/console.html`**

One comment line currently reads `// Cross-cutting checks only: jwe_decryption, requested_credentials_answered.` Extend it with `credential_sets_satisfied (mutually exclusive with the former)`. Confirm the console renders check names generically:

```bash
rg -n "requested_credentials_answered|checks" crates/foundry/assets/console.html | head -20
```

If any rendering logic special-cases the name, the new check must be handled too; if it iterates `checks` generically, the comment is the only change. `crates/foundry/tests/console.rs` guards the asset.

- [ ] **Step 7: Add the shipped named query to `config.yaml`**

Append to `verifier.named_queries`, after the existing `over18` entry:

```yaml
    # Demonstrates DCQL `credential_sets` (OpenID4VP 1.0 L879-L894): a payment
    # credential (either of two), an age assertion (either of two), and an
    # optional loyalty card. `dpc_card` and `pid` are the two credential types
    # this issuer actually mints, so a wallet holding both satisfies each
    # required set via its FIRST option. `visa_card`, `av` and `loyalty` name
    # vcts this issuer does NOT mint; they exist to exercise the alternative and
    # optional branches, and a wallet will simply never answer them.
    - id: payment-age-loyalty
      dcql:
        credentials:
          - id: dpc_card
            format: dc+sd-jwt
            meta: { vct_values: ["com.emvco.dpc.card"] }
          - id: visa_card
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/visa"] }
          - id: pid
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/pid"] }
            claims:
              - path: [birthdate]
          - id: av
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/av"] }
          - id: loyalty
            format: dc+sd-jwt
            meta: { vct_values: ["https://localhost:8443/vct/loyalty"] }
        credential_sets:
          - options: [[dpc_card], [visa_card]]
          - options: [[pid], [av]]
          - options: [[loyalty]]
            required: false
```

Then verify the shipped config still loads:

```bash
cargo nextest run -p foundry --test quickstart_config
```

- [ ] **Step 8: Update the conformance report**

In `docs/conformance/openid4vc-conformance.md`:

1. **VP-0103** — verdict `not-implemented` → `conforming`. Evidence: *"`DcqlCredentialSetQuery` (dcql_model.rs) models `options` and `required` (default `true`); a non-object entry fails deserialization and `create_verification_request` rejects it as HTTP 400 rather than persisting it"*. Tests: `credential_set_required_defaults_to_true`, `rejects_a_credential_set_without_options`.
2. **VP-0104** — `not-implemented` → `conforming`. Evidence: *"`non_empty_options` rejects an empty `options` array and any empty option at deserialization; `create_verification_request` additionally rejects an option id not declared in `credentials`"*. Tests: `rejects_empty_options_array`, `rejects_an_empty_option`, `create_rejects_a_credential_set_option_referencing_an_unknown_id`.
3. **VP-0090** — remove `credential_sets` from the list of silently-ignored properties, leaving `multiple`, `trusted_authorities`, `claim_sets`. The cited test `ignores_unknown_properties_at_every_level` still exists (Task 1 changed its fixture, not its name).
4. **VP-0106 / VP-0107 / VP-0108** — their evidence cross-references VP-0103 for `claim_sets` being unmodelled. VP-0103 is now `conforming`, so re-ground it: *"`claim_sets` is not modelled by `DcqlCredentialQuery` (dcql_model.rs) — it deserializes as an ignored unknown property (VP-0090) — so the correlation mechanism this clause governs does not exist"*. Drop the `(VP-0103)` pointer.
5. Update any summary counts / `not-implemented` tallies near the top.

Then:

```bash
cargo nextest run -p foundry --test conformance_report
```

Expected: PASS. A failure here almost always means a cited test name does not exist verbatim — fix the citation, not the test.

- [ ] **Step 9: Write the change record**

Create `docs/superpowers/changes/2026-08-20-dcql-credential-sets.md` covering: what shipped; the five decisions and the alternatives rejected (point at the design doc rather than restating the arguments); the two design refinements adopted during planning (slice parameter, parsed-query signature); what remains a non-goal (`claim_sets`, `multiple: true`, `trusted_authorities`, `GAP-VP-03`); and the conformance rows moved.

- [ ] **Step 10: Run the full gate plus the E2E suite**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

The E2E run is the §5.2 obligation for the end of a branch. Quote both summary lines.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "docs: record credential_sets support across specs and conformance

VP-0103 and VP-0104 move to conforming. VP-0090's evidence no longer lists
credential_sets among ignored unknown properties, and VP-0106..0108 stop
cross-referencing VP-0103 for claim_sets.

Adds credential_sets_satisfied to the cross-cutting check enumeration in
root AGENTS.md 4.2, the crate AGENTS.md, README, the VerificationResult
doc comment (hence both regenerated OpenAPI specs) and the console asset,
plus a payment-age-loyalty named query in config.yaml that demonstrates
alternatives and optionality against the two credential types this issuer
actually mints."
```

---

## Plan Self-Review

**Spec coverage:**

| Spec section | Task |
| --- | --- |
| §2.1 full `credential_sets` | 1, 2 |
| §2.2 lenient surplus | 2 (`surplus_answers_do_not_break_satisfaction`) — no production code needed; leniency is the *absence* of a rejection |
| §2.3 two mutually-exclusive checks | 4, asserted in 4 and 5 |
| §2.4 presence not validity | 2 (`a_failing_credential_still_satisfies_its_option`) |
| §2.5 create-time 400s | 3 |
| §3.1 wire model | 1 |
| §3.2 algebra | 2 |
| §3.3 detail strings | 2 |
| §4.1 structural validation | 1 (deserializers), asserted in 3 |
| §4.2 three semantic validations | 3 |
| §4.3 deliberately-not-rejected | 3 (`create_accepts_one_credential_query_referenced_by_several_sets`) |
| §4.4 named queries unchanged | 3 — no code change; existing behaviour |
| §5.1 dispatcher | 4 |
| §5.2 parse-failure branch | 4 (`response_completeness_fails_closed_on_an_unreadable_query`) |
| §5.3 status code / verdict | 5 (`credential_sets_unsatisfied_required_set_is_a_policy_failure`) |
| §5.4 logging | 2 (the `warn`/`debug` records) |
| §6.1 config example | 6 |
| §6.2 conformance | 6 |
| §6.3 docs/OpenAPI | 6 |
| §7 testing | 1-5 |
| §8 non-goals | 6 (change record); `claim_sets` fixture swap in 1 |
| §9 citation index | Comments across 1, 2, 3, 4 |

No gaps.

**Placeholder scan:** every code step carries the actual code. Two steps
deliberately say "read the file first" (Task 6 Steps 4 and 6) because the target
text is a prose section whose exact current wording the implementer must see —
each names the file, the section, and the specific content to add. Task 6 Step 2
defers to `crates/foundry/AGENTS.md` for the OpenAPI regeneration command rather
than guessing it.

**Type consistency:** `check_credential_sets_satisfied(&[DcqlCredentialSetQuery],
&[PresentedCredential]) -> CheckResult` is defined in Task 2 and called with
exactly that shape in Task 4. `DcqlQuery::credential_sets() ->
Option<&[DcqlCredentialSetQuery]>` is defined in Task 1 and consumed in Tasks 2
(tests), 3, and 4. `check_requested_credentials_answered(&DcqlQuery,
&[PresentedCredential])` is changed in Task 4 and its only two callers (the
dispatcher and one test) are both updated there.
`pending_verification_with_query(Value, impl FnOnce(String) -> Value)` is defined
and used in Task 5. Check-name string literals are `credential_sets_satisfied`
and `requested_credentials_answered` everywhere.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-20-dcql-credential-sets-plan.md`.
