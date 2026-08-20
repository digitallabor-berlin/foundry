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
    let obligation = if set.required() {
        "required"
    } else {
        "optional"
    };
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
