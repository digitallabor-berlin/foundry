//! DCQL (Digital Credentials Query Language) satisfaction checking.
//!
//! After a presentation's signatures are verified and its claims disclosed,
//! this module confirms the disclosed credential actually satisfies the
//! verification transaction's DCQL query: correct credential format, correct
//! `vct` (SD-JWT VC) or `doctype` (mso_mdoc), all mandatory claim paths
//! present, and any `values` constraints met.
//!
//! Scope: this codebase presents a single credential per `vp_token`, so we
//! require the presented credential to satisfy at least one credential query
//! of its format. Multi-credential and `credential_sets` combination logic is
//! out of scope for this phase.

use crate::transaction::CheckResult;
use openid4vp::core::credential_format::ClaimFormatDesignation;
use openid4vp::core::dcql_query::{DcqlCredentialClaimsQueryPath, DcqlCredentialQuery, DcqlQuery};
use serde_json::Value;

/// The concrete credential format actually present in the `vp_token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedFormat {
    SdJwtVc,
    MsoMdoc,
}

impl PresentedFormat {
    fn matches(self, designation: &ClaimFormatDesignation) -> bool {
        matches!(
            (self, designation),
            (PresentedFormat::SdJwtVc, ClaimFormatDesignation::DcSdJwt)
                | (PresentedFormat::MsoMdoc, ClaimFormatDesignation::MsoMDoc)
        )
    }
}

fn failed(reason: String) -> CheckResult {
    CheckResult {
        check: "dcql_match".to_string(),
        passed: false,
        detail: Some(reason),
    }
}

/// Check that `disclosed_claims` satisfy `dcql_query` for a credential of
/// `format`. `doc_type` is the mdoc docType (`None` for SD-JWT VC). Returns a
/// `CheckResult { check: "dcql_match", .. }`; never errors (fail-closed).
pub fn check_dcql_match(
    dcql_query: &Value,
    format: PresentedFormat,
    disclosed_claims: &Value,
    doc_type: Option<&str>,
) -> CheckResult {
    let query: DcqlQuery = match serde_json::from_value(dcql_query.clone()) {
        Ok(q) => q,
        Err(e) => return failed(format!("dcql_query is not a valid DCQL query: {e}")),
    };

    let mut first_reason: Option<String> = None;
    for cq in query.credentials() {
        if !format.matches(cq.format()) {
            continue;
        }
        match credential_query_satisfied(cq, format, disclosed_claims, doc_type) {
            Ok(()) => {
                return CheckResult {
                    check: "dcql_match".to_string(),
                    passed: true,
                    detail: Some(format!("matched credential query '{}'", cq.id())),
                };
            }
            Err(reason) => {
                if first_reason.is_none() {
                    first_reason = Some(format!("credential query '{}': {reason}", cq.id()));
                }
            }
        }
    }

    failed(first_reason.unwrap_or_else(|| {
        "no credential query in the DCQL query matches the presented credential format".to_string()
    }))
}

fn credential_query_satisfied(
    cq: &DcqlCredentialQuery,
    format: PresentedFormat,
    claims: &Value,
    doc_type: Option<&str>,
) -> Result<(), String> {
    // --- format-specific metadata constraints ---
    match format {
        PresentedFormat::SdJwtVc => {
            if let Some(vct_values) = cq.meta().get("vct_values").and_then(|v| v.as_array()) {
                let vct = claims.get("vct").and_then(|v| v.as_str()).unwrap_or("");
                if !vct_values.iter().any(|v| v.as_str() == Some(vct)) {
                    return Err(format!("vct '{vct}' not in requested vct_values"));
                }
            }
        }
        PresentedFormat::MsoMdoc => {
            if let Some(want) = cq.meta().get("doctype_value").and_then(|v| v.as_str()) {
                let got = doc_type.unwrap_or("");
                if got != want {
                    return Err(format!("doctype '{got}' does not equal requested '{want}'"));
                }
            }
        }
    }

    // --- claim path + value constraints ---
    if let Some(claim_queries) = cq.claims() {
        for claim in claim_queries.iter() {
            let found = resolve_path(claims, claim.path()).ok_or_else(|| {
                format!(
                    "required claim path {:?} not disclosed",
                    path_debug(claim.path())
                )
            })?;
            if let Some(expected) = claim.values() {
                let ok = expected.iter().any(|e| {
                    use openid4vp::core::dcql_query::DcqlCredentialClaimsQueryValue as V;
                    match e {
                        V::String(s) => found.as_str() == Some(s.as_str()),
                        V::Integer(i) => found.as_i64() == Some(*i as i64),
                        V::Boolean(b) => found.as_bool() == Some(*b),
                    }
                });
                if !ok {
                    return Err(format!(
                        "claim path {:?} value {found} not in requested values",
                        path_debug(claim.path())
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Walk a claims `Value` by a DCQL claims path. Supports `String` (object key)
/// and `Integer` (array index) segments. `Null` (array wildcard) segments are
/// not supported in this phase and cause the lookup to fail (fail-closed).
fn resolve_path<'a>(
    claims: &'a Value,
    path: &[DcqlCredentialClaimsQueryPath],
) -> Option<&'a Value> {
    let mut cur = claims;
    for seg in path {
        match seg {
            DcqlCredentialClaimsQueryPath::String(k) => cur = cur.get(k)?,
            DcqlCredentialClaimsQueryPath::Integer(i) => cur = cur.get(*i)?,
            DcqlCredentialClaimsQueryPath::Null => return None,
        }
    }
    Some(cur)
}

fn path_debug(path: &[DcqlCredentialClaimsQueryPath]) -> Vec<String> {
    path.iter()
        .map(|p| match p {
            DcqlCredentialClaimsQueryPath::String(s) => s.clone(),
            DcqlCredentialClaimsQueryPath::Integer(i) => i.to_string(),
            DcqlCredentialClaimsQueryPath::Null => "null".to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sd_jwt_query(vct: &str) -> Value {
        json!({"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":[vct]},
            "claims":[{"path":["given_name"]}]}]})
    }

    #[test]
    fn sd_jwt_vct_and_claim_present_passes() {
        let q = sd_jwt_query("https://issuer.example/pid");
        let claims = json!({"vct":"https://issuer.example/pid","given_name":"Alice"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(r.passed, "detail={:?}", r.detail);
        assert_eq!(r.check, "dcql_match");
    }

    #[test]
    fn sd_jwt_vct_mismatch_fails() {
        let q = sd_jwt_query("https://issuer.example/OTHER");
        let claims = json!({"vct":"https://issuer.example/pid","given_name":"Alice"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
        assert!(r.detail.unwrap().contains("vct"));
    }

    #[test]
    fn sd_jwt_missing_mandatory_claim_fails() {
        let q = sd_jwt_query("https://issuer.example/pid");
        let claims = json!({"vct":"https://issuer.example/pid"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
        assert!(r.detail.unwrap().contains("given_name"));
    }

    #[test]
    fn sd_jwt_values_constraint_enforced() {
        let q = json!({"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
            "claims":[{"path":["age_over_18"],"values":[true]}]}]});
        let ok = json!({"vct":"x","age_over_18":true});
        assert!(check_dcql_match(&q, PresentedFormat::SdJwtVc, &ok, None).passed);
        let bad = json!({"vct":"x","age_over_18":false});
        assert!(!check_dcql_match(&q, PresentedFormat::SdJwtVc, &bad, None).passed);
    }

    #[test]
    fn mdoc_doctype_and_namespaced_claim() {
        let q = json!({"credentials":[{"id":"mdl","format":"mso_mdoc",
            "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
            "claims":[{"path":["org.iso.18013.5.1","given_name"]}]}]});
        let claims = json!({"org.iso.18013.5.1":{"given_name":"John"}});
        let r = check_dcql_match(
            &q,
            PresentedFormat::MsoMdoc,
            &claims,
            Some("org.iso.18013.5.1.mDL"),
        );
        assert!(r.passed, "detail={:?}", r.detail);
        let bad = check_dcql_match(&q, PresentedFormat::MsoMdoc, &claims, Some("org.iso.WRONG"));
        assert!(!bad.passed);
    }

    #[test]
    fn format_mismatch_fails() {
        let q = json!({"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{}}]});
        let claims = json!({"vct":"x","given_name":"Alice"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
    }

    #[test]
    fn unparseable_query_fails_closed() {
        let q = json!({"credentials":[]}); // NonEmptyVec rejects empty -> parse error
        let claims = json!({"vct":"x"});
        let r = check_dcql_match(&q, PresentedFormat::SdJwtVc, &claims, None);
        assert!(!r.passed);
    }
}
