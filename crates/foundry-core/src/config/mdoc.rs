//! What foundry knows about specific mdoc doctypes.
//!
//! Two facts are keyed on a doctype string: which namespace its data elements
//! live in, and — for the EUDI Proof of Age attestation — which elements it may
//! carry at all. They live in one module so they cannot drift apart, and in
//! `foundry-core` because both `super::validate` and `foundry-issuer` need them
//! and `foundry-core` is the only crate below both (root AGENTS.md §3).

use super::model::ClaimDef;
use crate::error::ConfigError;

/// The EUDI Proof of Age attestation.
///
/// EU Age Verification Solution Technical Specification, Annex A §4.1.1: "The
/// document type for Proof of Age attestation SHALL be `eu.europa.ec.av.1`."
/// See `docs/specs/eu-age-verification-annex-a-av-profile.md`.
pub const AV_DOCTYPE: &str = "eu.europa.ec.av.1";

/// The ISO/IEC 18013-5 mobile driving licence.
pub const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";

/// The namespace ISO mDL data elements live in.
///
/// Deliberately NOT equal to [`MDL_DOCTYPE`] — that difference is the entire
/// reason this module exists.
const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// The mdoc namespace a doctype's data elements belong to.
///
/// Doctype-as-namespace is the **correct default**, not a fallback: every EUDI
/// attestation uses its doctype verbatim as the namespace — Annex A §4.1.2,
/// "All attributes belong to namespace `eu.europa.ec.av.1`" — and the EMVCo DPC
/// specification does the same. ISO mDL is the exception, carrying elements in
/// `org.iso.18013.5.1` under doctype `org.iso.18013.5.1.mDL`.
///
/// Fails safe: an unrecognised doctype returns itself, which is right for every
/// EUDI attestation foundry might add without touching this function.
pub fn namespace_for_doctype(doctype: &str) -> &str {
    match doctype {
        MDL_DOCTYPE => MDL_NAMESPACE,
        other => other,
    }
}

/// Enforce Annex A §4.1.2's closed attribute set for [`AV_DOCTYPE`].
///
/// §4.1.2 defines exactly two attributes, both encoded `bool` — `age_over_18`
/// (Mandatory in issuance) and a repeatable optional `age_over_NN` — and then
/// closes the set: "A Proof of Age Attestation SHALL NOT include any other
/// attribute."
///
/// Checked at config load so a non-conformant credential type is a startup
/// failure rather than a silently non-conformant credential. `age_over_18` must
/// additionally be `required`: §4.1.2 records it as *Mandatory* in issuance, so
/// a config declaring it optional describes a credential the profile does not
/// admit — presence alone is not enough.
pub fn validate_av_claims(
    credential_type_id: &str,
    claims: &[ClaimDef],
) -> Result<(), ConfigError> {
    for claim in claims {
        let [element] = claim.path.as_slice() else {
            return Err(ConfigError::Validation(format!(
                "credential_type '{credential_type_id}' ({AV_DOCTYPE}) claim path {:?} is not a \
                 single mdoc data element; Annex A §4.1.2 defines a flat attribute set",
                claim.path
            )));
        };
        if !is_age_over_element(element) {
            return Err(ConfigError::Validation(format!(
                "credential_type '{credential_type_id}' ({AV_DOCTYPE}) declares attribute \
                 '{element}'; Annex A §4.1.2 admits only 'age_over_18' and 'age_over_NN', and \
                 states a Proof of Age Attestation SHALL NOT include any other attribute"
            )));
        }
    }

    match claims.iter().find(|c| c.path.as_slice() == ["age_over_18"]) {
        None => Err(ConfigError::Validation(format!(
            "credential_type '{credential_type_id}' ({AV_DOCTYPE}) must declare 'age_over_18'; \
             Annex A §4.1.2 records it as Mandatory in issuance"
        ))),
        Some(c) if !c.is_required() => Err(ConfigError::Validation(format!(
            "credential_type '{credential_type_id}' ({AV_DOCTYPE}) declares 'age_over_18' as \
             optional; Annex A §4.1.2 records it as Mandatory in issuance"
        ))),
        Some(_) => Ok(()),
    }
}

/// `age_over_18`, or `age_over_NN` for a decimal NN.
///
/// A real integer parse, not a prefix match: `age_over_banana` and a bare
/// `age_over_` must both be rejected. Leading zeros are rejected too, since
/// `age_over_08` is not an ISO/IEC 18013-5 §7.2.5 element name even though it
/// parses as a number.
fn is_age_over_element(element: &str) -> bool {
    match element.strip_prefix("age_over_") {
        Some(nn) => nn.parse::<u8>().is_ok() && (nn.len() == 1 || !nn.starts_with('0')),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(path: &str, required: Option<bool>) -> ClaimDef {
        ClaimDef {
            path: vec![path.to_string()],
            required,
            selectively_disclosable: false,
            display: vec![],
        }
    }

    #[test]
    fn mdl_namespace_is_not_the_mdl_doctype() {
        assert_eq!(namespace_for_doctype(MDL_DOCTYPE), "org.iso.18013.5.1");
        assert_ne!(namespace_for_doctype(MDL_DOCTYPE), MDL_DOCTYPE);
    }

    /// Annex A §4.1.2: "All attributes belong to namespace `eu.europa.ec.av.1`"
    /// — identical to the doctype, which is the EUDI convention.
    #[test]
    fn eudi_doctypes_use_the_doctype_as_the_namespace() {
        assert_eq!(namespace_for_doctype(AV_DOCTYPE), AV_DOCTYPE);
    }

    /// Fails safe rather than erroring or guessing.
    #[test]
    fn an_unknown_doctype_resolves_to_itself() {
        assert_eq!(
            namespace_for_doctype("com.example.something.1"),
            "com.example.something.1"
        );
    }

    #[test]
    fn the_two_shipped_av_attributes_are_accepted() {
        let claims = vec![
            claim("age_over_18", Some(true)),
            claim("age_over_16", Some(false)),
        ];
        assert!(validate_av_claims("av", &claims).is_ok());
    }

    #[test]
    fn a_foreign_attribute_is_rejected() {
        let claims = vec![claim("age_over_18", Some(true)), claim("issue_date", None)];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(
            err.contains("issue_date") && err.contains("SHALL NOT include any other attribute"),
            "the error must name the offending attribute and cite the clause: {err}"
        );
    }

    #[test]
    fn omitting_age_over_18_is_rejected() {
        let claims = vec![claim("age_over_16", Some(true))];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(err.contains("must declare 'age_over_18'"), "{err}");
    }

    /// Mandatory in issuance is stronger than merely present.
    #[test]
    fn declaring_age_over_18_optional_is_rejected() {
        let claims = vec![claim("age_over_18", Some(false))];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(err.contains("as optional"), "{err}");
    }

    /// A prefix match would accept all of these; a real parse must not.
    #[test]
    fn age_over_suffix_must_be_a_number() {
        for bad in ["age_over_banana", "age_over_", "age_over_1a", "age_over_08"] {
            let claims = vec![claim("age_over_18", Some(true)), claim(bad, None)];
            assert!(
                validate_av_claims("av", &claims).is_err(),
                "'{bad}' is not an age_over_NN element and must be rejected"
            );
        }
    }

    #[test]
    fn a_nested_claim_path_is_rejected() {
        let claims = vec![
            claim("age_over_18", Some(true)),
            ClaimDef {
                path: vec!["a".to_string(), "b".to_string()],
                required: None,
                selectively_disclosable: false,
                display: vec![],
            },
        ];
        let err = validate_av_claims("av", &claims).unwrap_err().to_string();
        assert!(err.contains("flat attribute set"), "{err}");
    }
}
