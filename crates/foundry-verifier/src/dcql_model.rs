//! DCQL (Digital Credentials Query Language) wire model.
//!
//! Deserialization targets for the subset of DCQL that foundry's verifier
//! evaluates, written against OpenID4VP 1.0 §6 (Digital Credentials Query
//! Language) and §7 (Claims Path Pointer).
//!
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

use serde::Deserialize;
use serde::de::{Deserializer, Error as _};
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

fn non_empty_credential_sets<'de, D>(d: D) -> Result<Option<Vec<DcqlCredentialSetQuery>>, D::Error>
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
            "claim_sets": [["gn"]],
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

    /// §6: `credentials` is a non-empty array — a parse error rather than a query
    /// that vacuously matches nothing. The `quickstart` config scaffold used to
    /// emit `dcql: { credentials: [] }`; `create_verification_request` now parses
    /// the query before persisting it, so an empty one fails the operator's
    /// request instead of reaching a wallet.
    #[test]
    fn rejects_empty_credentials() {
        assert!(parse(json!({ "credentials": [] })).is_err());
    }

    /// §6.3: `path` is a non-empty array. An empty path would resolve to the
    /// credential root and satisfy any claim requirement.
    #[test]
    fn rejects_empty_claims_path() {
        assert!(
            parse(json!({
                "credentials": [{
                    "id": "c1", "format": "dc+sd-jwt", "meta": {},
                    "claims": [{ "path": [] }]
                }]
            }))
            .is_err()
        );
    }

    /// §6.3: `values`, when present, is a non-empty array.
    #[test]
    fn rejects_empty_values() {
        assert!(
            parse(json!({
                "credentials": [{
                    "id": "c1", "format": "dc+sd-jwt", "meta": {},
                    "claims": [{ "path": ["a"], "values": [] }]
                }]
            }))
            .is_err()
        );
    }

    /// §7.1: array indices are non-negative.
    #[test]
    fn rejects_negative_path_index() {
        assert!(
            parse(json!({
                "credentials": [{
                    "id": "c1", "format": "dc+sd-jwt", "meta": {},
                    "claims": [{ "path": ["a", -1] }]
                }]
            }))
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_required_members() {
        assert!(parse(json!({ "credentials": [{ "format": "dc+sd-jwt" }] })).is_err());
        assert!(parse(json!({ "credentials": [{ "id": "c1" }] })).is_err());
        assert!(parse(json!({})).is_err());
    }

    /// OpenID4VP 1.0 L892-L894: "If omitted, the default value is `true`."
    #[test]
    fn credential_set_required_defaults_to_true() {
        let q = parse(json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "options": [["c1"]] }]
        }))
        .unwrap();

        let sets = q
            .credential_sets()
            .expect("credential_sets must be modelled");
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
        assert_eq!(
            sets[0].options()[0],
            vec!["pid".to_string(), "av".to_string()]
        );
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
        assert!(
            msg.contains("options[1]"),
            "name the offending index: {msg}"
        );
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
}
