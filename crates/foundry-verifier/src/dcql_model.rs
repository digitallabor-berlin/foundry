//! DCQL (Digital Credentials Query Language) wire model.
//!
//! Deserialization targets for the subset of DCQL that foundry's verifier
//! evaluates, written against OpenID4VP 1.0 §6 (Digital Credentials Query
//! Language) and §7 (Claims Path Pointer).
//!
//! Scope is deliberately the subset [`crate::dcql`] consumes. `credential_sets`
//! (§6.2), `claim_sets`, `multiple`, and `trusted_authorities` are not modelled;
//! per §6, unknown properties are ignored rather than rejected, so queries
//! carrying them still deserialize and are evaluated on the parts we do
//! understand.
//!
//! Three non-empty constraints from the spec are enforced at deserialization,
//! because each one is fail-closed:
//!
//! - `credentials` (§6) — a query requesting nothing must not silently "match".
//! - `claims[].path` (§6.3) — an empty path would resolve to the credential
//!   root and spuriously satisfy any claim requirement.
//! - `claims[].values` (§6.3) — spec requires non-empty when present.

use serde::de::{Deserializer, Error as _};
use serde::Deserialize;
use serde_json::Value;

/// Deserialize a `Vec<T>`, rejecting an empty array with a field-specific
/// message. Used for the three arrays the spec marks non-empty.
fn non_empty<'de, D, T>(deserializer: D, field: &str) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let items = Vec::<T>::deserialize(deserializer)?;
    if items.is_empty() {
        return Err(D::Error::custom(format!(
            "`{field}` must be a non-empty array"
        )));
    }
    Ok(items)
}

fn non_empty_credentials<'de, D>(d: D) -> Result<Vec<DcqlCredentialQuery>, D::Error>
where
    D: Deserializer<'de>,
{
    non_empty(d, "credentials")
}

fn non_empty_path<'de, D>(d: D) -> Result<Vec<ClaimsPathSegment>, D::Error>
where
    D: Deserializer<'de>,
{
    non_empty(d, "path")
}

fn non_empty_values<'de, D>(d: D) -> Result<Option<Vec<ClaimValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    non_empty(d, "values").map(Some)
}

/// A DCQL query (OpenID4VP 1.0 §6).
#[derive(Debug, Clone, Deserialize)]
pub struct DcqlQuery {
    #[serde(deserialize_with = "non_empty_credentials")]
    credentials: Vec<DcqlCredentialQuery>,
}

impl DcqlQuery {
    pub fn credentials(&self) -> &[DcqlCredentialQuery] {
        &self.credentials
    }
}

/// A Credential Query (OpenID4VP 1.0 §6.1).
#[derive(Debug, Clone, Deserialize)]
pub struct DcqlCredentialQuery {
    id: String,
    format: CredentialFormat,
    #[serde(default)]
    meta: Option<Value>,
    #[serde(default)]
    claims: Option<Vec<DcqlClaimsQuery>>,
}

impl DcqlCredentialQuery {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn format(&self) -> &CredentialFormat {
        &self.format
    }

    /// Format-specific metadata constraints, left opaque: the properties are
    /// defined per Credential Format (§6.1, Appendix B.2.3 / B.3.5), and the
    /// verifier reads them by name.
    ///
    /// Returns `Value::Null` when absent, so `.get(..)` yields `None`.
    pub fn meta(&self) -> &Value {
        self.meta.as_ref().unwrap_or(&Value::Null)
    }

    pub fn claims(&self) -> Option<&Vec<DcqlClaimsQuery>> {
        self.claims.as_ref()
    }
}

/// A Claims Query (OpenID4VP 1.0 §6.3).
#[derive(Debug, Clone, Deserialize)]
pub struct DcqlClaimsQuery {
    #[serde(deserialize_with = "non_empty_path")]
    path: Vec<ClaimsPathSegment>,
    #[serde(default, deserialize_with = "non_empty_values")]
    values: Option<Vec<ClaimValue>>,
}

impl DcqlClaimsQuery {
    pub fn path(&self) -> &[ClaimsPathSegment] {
        &self.path
    }

    pub fn values(&self) -> Option<&Vec<ClaimValue>> {
        self.values.as_ref()
    }
}

/// One component of a claims path pointer (OpenID4VP 1.0 §7.1).
///
/// A string selects an object key, a non-negative integer selects an array
/// index, and `null` selects all elements of the currently selected array.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ClaimsPathSegment {
    String(String),
    Index(u64),
    Wildcard,
}

/// An expected claim value (OpenID4VP 1.0 §6.3): a string, integer, or boolean.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    // `Boolean` precedes `Integer` and `String` because `serde(untagged)` tries
    // variants in declaration order, and JSON booleans must not be coerced.
    Boolean(bool),
    Integer(i64),
    String(String),
}

/// A Credential Format Identifier (OpenID4VP 1.0 Appendix B).
///
/// `Other` is load-bearing rather than cosmetic: without a catch-all, a query
/// naming a format this verifier does not implement would fail *deserialization*
/// and be reported as a malformed query, instead of simply not matching the
/// presented credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum CredentialFormat {
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
    #[serde(untagged)]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(v: Value) -> Result<DcqlQuery, serde_json::Error> {
        serde_json::from_value(v)
    }

    /// OpenID4VP 1.0 Appendix D, first example.
    #[test]
    fn parses_spec_mdoc_example() {
        let q = parse(json!({
            "credentials": [{
                "id": "my_credential",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.7367.1.mVRC" },
                "claims": [
                    { "path": ["org.iso.7367.1", "vehicle_holder"] },
                    { "path": ["org.iso.18013.5.1", "first_name"] }
                ]
            }]
        }))
        .unwrap();

        let cq = &q.credentials()[0];
        assert_eq!(cq.id(), "my_credential");
        assert_eq!(cq.format(), &CredentialFormat::MsoMdoc);
        assert_eq!(
            cq.meta().get("doctype_value").and_then(|v| v.as_str()),
            Some("org.iso.7367.1.mVRC")
        );
        let claims = cq.claims().unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(
            claims[0].path(),
            [
                ClaimsPathSegment::String("org.iso.7367.1".into()),
                ClaimsPathSegment::String("vehicle_holder".into())
            ]
        );
        assert!(claims[0].values().is_none());
    }

    /// OpenID4VP 1.0 Appendix D, multi-credential example.
    #[test]
    fn parses_spec_multi_credential_example() {
        let q = parse(json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
                    "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] },
                        { "path": ["address", "street_address"] }
                    ]
                },
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.7367.1.mVRC" },
                    "claims": [{ "path": ["org.iso.7367.1", "vehicle_holder"] }]
                }
            ]
        }))
        .unwrap();

        assert_eq!(q.credentials().len(), 2);
        assert_eq!(q.credentials()[0].format(), &CredentialFormat::DcSdJwt);
        assert_eq!(q.credentials()[1].format(), &CredentialFormat::MsoMdoc);
    }

    /// §6: "Implementations MUST ignore any unknown properties."
    #[test]
    fn ignores_unknown_properties_at_every_level() {
        let q = parse(json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": {},
                "multiple": true,
                "trusted_authorities": [{ "type": "aki", "values": ["x"] }],
                "claims": [{ "path": ["given_name"], "id": "gn", "future_member": 1 }]
            }],
            "credential_sets": [{ "options": [["c1"]] }],
            "future_top_level": "ignored"
        }))
        .unwrap();

        assert_eq!(q.credentials()[0].id(), "c1");
        assert_eq!(q.credentials()[0].claims().unwrap().len(), 1);
    }

    /// The behaviour-preserving one: an unknown format must NOT fail parsing,
    /// or `check_dcql_match` would report "not a valid DCQL query" instead of
    /// "no credential query matches the presented format".
    #[test]
    fn unknown_format_parses_as_other() {
        let q = parse(json!({
            "credentials": [{ "id": "c1", "format": "jwt_vc_json", "meta": {} }]
        }))
        .unwrap();

        assert_eq!(
            q.credentials()[0].format(),
            &CredentialFormat::Other("jwt_vc_json".to_string())
        );
    }

    #[test]
    fn path_segments_cover_string_index_and_wildcard() {
        let q = parse(json!({
            "credentials": [{
                "id": "c1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["nationalities", 0, "code"] }, { "path": ["degrees", null] }]
            }]
        }))
        .unwrap();

        let claims = q.credentials()[0].claims().unwrap();
        assert_eq!(
            claims[0].path(),
            [
                ClaimsPathSegment::String("nationalities".into()),
                ClaimsPathSegment::Index(0),
                ClaimsPathSegment::String("code".into())
            ]
        );
        assert_eq!(
            claims[1].path(),
            [
                ClaimsPathSegment::String("degrees".into()),
                ClaimsPathSegment::Wildcard
            ]
        );
    }

    #[test]
    fn claim_values_cover_string_integer_and_boolean() {
        let q = parse(json!({
            "credentials": [{
                "id": "c1", "format": "dc+sd-jwt", "meta": {},
                "claims": [
                    { "path": ["given_name"], "values": ["Alice"] },
                    { "path": ["age"], "values": [21] },
                    { "path": ["age_over_18"], "values": [true] }
                ]
            }]
        }))
        .unwrap();

        let claims = q.credentials()[0].claims().unwrap();
        assert_eq!(
            claims[0].values().unwrap(),
            &vec![ClaimValue::String("Alice".into())]
        );
        assert_eq!(claims[1].values().unwrap(), &vec![ClaimValue::Integer(21)]);
        assert_eq!(
            claims[2].values().unwrap(),
            &vec![ClaimValue::Boolean(true)]
        );
    }

    /// Guards the `untagged` variant ordering: `true` must not become
    /// `Integer(1)` or `String("true")`.
    #[test]
    fn boolean_claim_value_is_not_coerced() {
        let q = parse(json!({
            "credentials": [{
                "id": "c1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["flag"], "values": [false] }]
            }]
        }))
        .unwrap();
        let claims = q.credentials()[0].claims().unwrap();
        assert_eq!(
            claims[0].values().unwrap(),
            &vec![ClaimValue::Boolean(false)]
        );
    }

    #[test]
    fn absent_claims_and_meta_are_tolerated() {
        let q = parse(json!({
            "credentials": [{ "id": "c1", "format": "mso_mdoc" }]
        }))
        .unwrap();

        let cq = &q.credentials()[0];
        assert!(cq.claims().is_none());
        assert_eq!(cq.meta(), &Value::Null);
        // The verifier reads meta by name; Null.get(..) must be None, not a panic.
        assert!(cq.meta().get("doctype_value").is_none());
    }

    // --- the three spec-mandated non-empty constraints, all fail-closed ---

    /// §6: `credentials` is a non-empty array. `config.yaml` ships
    /// `dcql: { credentials: [] }`, and today that is a parse error rather than
    /// a query that vacuously matches nothing.
    #[test]
    fn rejects_empty_credentials() {
        assert!(parse(json!({ "credentials": [] })).is_err());
    }

    /// §6.3: `path` is a non-empty array. An empty path would resolve to the
    /// credential root and satisfy any claim requirement.
    #[test]
    fn rejects_empty_claims_path() {
        assert!(parse(json!({
            "credentials": [{
                "id": "c1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": [] }]
            }]
        }))
        .is_err());
    }

    /// §6.3: `values`, when present, is a non-empty array.
    #[test]
    fn rejects_empty_values() {
        assert!(parse(json!({
            "credentials": [{
                "id": "c1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["a"], "values": [] }]
            }]
        }))
        .is_err());
    }

    /// §7.1: array indices are non-negative.
    #[test]
    fn rejects_negative_path_index() {
        assert!(parse(json!({
            "credentials": [{
                "id": "c1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["a", -1] }]
            }]
        }))
        .is_err());
    }

    #[test]
    fn rejects_missing_required_members() {
        assert!(parse(json!({ "credentials": [{ "format": "dc+sd-jwt" }] })).is_err());
        assert!(parse(json!({ "credentials": [{ "id": "c1" }] })).is_err());
        assert!(parse(json!({})).is_err());
    }
}
