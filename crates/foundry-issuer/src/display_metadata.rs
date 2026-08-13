//! Structural validation of EMVCo DPC display metadata.
//!
//! The governing document is the EMV® Digital Payment Credential Specification
//! — Schema Framework (Annex A.5 / A.5.1), schema `$id`
//! `com.emvco.dpc.card.meta`. It is an **external reference**, not a
//! standards-track specification: no copy is committed, and
//! `docs/specs/emvco-dpc-schema-framework.md` records which revision this was
//! built against. See
//! `docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`.
//!
//! Two deliberate divergences from A.5.1, both documented in §3.4 of that
//! design:
//!
//! 1. **Unknown members are accepted** at every depth, though the schema
//!    declares `additionalProperties: false`. This is a draft under Associate
//!    Review; a closed model would make each revision a breaking change to
//!    foundry's admin API.
//! 2. **`last_four` and `card_art` are required only at the Credential
//!    Response stage.** The schema marks both required unconditionally, but the
//!    same annex's offer-stage guidance says PII-type data — naming `last_four`
//!    and `alias` — should not appear on a Credential Offer. The two cannot both
//!    be satisfied; foundry validates each stage against the rule that applies
//!    to it. This is the third contradiction recorded in the spec stub.

use crate::error::IssuanceError;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Which protocol structure the display array is bound for. Selects the
/// stage-dependent inclusion rules; see the module docs' divergence 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayStage {
    /// A Credential Offer. `last_four` and `card_art` are optional here.
    Offer,
    /// A Credential Response. `last_four` and `card_art` are required.
    CredentialResponse,
}

/// A.5.1 `LogoImg.theme` enum.
const THEMES: [&str; 3] = ["DEFAULT", "LIGHT", "DARK"];
/// A.5.1 `card.type.code` enum.
const TYPE_CODES: [&str; 3] = ["CREDIT", "DEBIT", "PREPAID"];

fn err(path: &str, msg: &str) -> IssuanceError {
    IssuanceError::InvalidRequest(format!("{path}: {msg}"))
}

fn as_object<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>, IssuanceError> {
    v.as_object()
        .ok_or_else(|| err(path, "must be a JSON object"))
}

fn as_string<'a>(v: &'a Value, path: &str) -> Result<&'a str, IssuanceError> {
    v.as_str().ok_or_else(|| err(path, "must be a string"))
}

fn as_non_empty_string<'a>(v: &'a Value, path: &str) -> Result<&'a str, IssuanceError> {
    let s = as_string(v, path)?;
    if s.is_empty() {
        return Err(err(path, "must not be empty"));
    }
    Ok(s)
}

/// `^[0-9]{4}$` without a regex dependency. `chars()` rather than `bytes()` so
/// a multi-byte digit-looking character cannot pass on length alone.
fn is_four_ascii_digits(s: &str) -> bool {
    s.chars().count() == 4 && s.chars().all(|c| c.is_ascii_digit())
}

/// `^[A-Z]{2}$` without a regex dependency.
fn is_two_ascii_uppercase(s: &str) -> bool {
    s.chars().count() == 2 && s.chars().all(|c| c.is_ascii_uppercase())
}

fn validate_logo_img(v: &Value, path: &str) -> Result<(), IssuanceError> {
    let o = as_object(v, path)?;

    let theme = o
        .get("theme")
        .ok_or_else(|| err(path, "requires `theme`"))?;
    let theme_path = format!("{path}.theme");
    let theme = as_string(theme, &theme_path)?;
    if !THEMES.contains(&theme) {
        return Err(err(&theme_path, "must be one of DEFAULT, LIGHT, DARK"));
    }

    let image_url = o
        .get("image_url")
        .ok_or_else(|| err(path, "requires `image_url`"))?;
    // Type only: A.5.1's `format: uri` is an annotation, not an assertion.
    as_string(image_url, &format!("{path}.image_url"))?;

    Ok(())
}

fn validate_logo_array(v: &Value, path: &str) -> Result<(), IssuanceError> {
    let arr = v.as_array().ok_or_else(|| err(path, "must be an array"))?;
    if arr.is_empty() {
        return Err(err(path, "must contain at least one element"));
    }
    for (i, element) in arr.iter().enumerate() {
        validate_logo_img(element, &format!("{path}[{i}]"))?;
    }
    Ok(())
}

fn validate_branding(v: &Value, path: &str) -> Result<(), IssuanceError> {
    let o = as_object(v, path)?;
    let name = o.get("name").ok_or_else(|| err(path, "requires `name`"))?;
    as_non_empty_string(name, &format!("{path}.name"))?;
    if let Some(logo) = o.get("logo") {
        validate_logo_array(logo, &format!("{path}.logo"))?;
    }
    Ok(())
}

fn validate_issuer(v: &Value, path: &str) -> Result<(), IssuanceError> {
    let o = as_object(v, path)?;

    let branding = o
        .get("branding")
        .ok_or_else(|| err(path, "requires `branding`"))?;
    validate_branding(branding, &format!("{path}.branding"))?;

    if let Some(country) = o.get("country") {
        let country_path = format!("{path}.country");
        let country = as_string(country, &country_path)?;
        if !is_two_ascii_uppercase(country) {
            return Err(err(
                &country_path,
                "must be exactly two ASCII uppercase letters",
            ));
        }
    }

    // Type only, deliberately: `format: uri` / `format: email` are annotations.
    for member in ["website_url", "support_email", "support_phone"] {
        if let Some(value) = o.get(member) {
            as_string(value, &format!("{path}.{member}"))?;
        }
    }

    Ok(())
}

fn validate_network_branding(v: &Value, path: &str) -> Result<(), IssuanceError> {
    let arr = v.as_array().ok_or_else(|| err(path, "must be an array"))?;
    for (i, element) in arr.iter().enumerate() {
        let element_path = format!("{path}[{i}]");
        let o = as_object(element, &element_path)?;

        let network = o
            .get("network")
            .ok_or_else(|| err(&element_path, "requires `network`"))?;
        as_string(network, &format!("{element_path}.network"))?;

        let branding = o
            .get("branding")
            .ok_or_else(|| err(&element_path, "requires `branding`"))?;
        validate_branding(branding, &format!("{element_path}.branding"))?;
    }
    Ok(())
}

fn validate_card(v: &Value, path: &str, stage: DisplayStage) -> Result<(), IssuanceError> {
    let o = as_object(v, path)?;

    match o.get("last_four") {
        Some(value) => {
            let last_four_path = format!("{path}.last_four");
            let s = as_string(value, &last_four_path)?;
            if !is_four_ascii_digits(s) {
                return Err(err(&last_four_path, "must be exactly four ASCII digits"));
            }
        }
        None if stage == DisplayStage::CredentialResponse => {
            return Err(err(path, "requires `last_four` on a Credential Response"));
        }
        None => {}
    }

    match o.get("card_art") {
        Some(value) => validate_logo_array(value, &format!("{path}.card_art"))?,
        None if stage == DisplayStage::CredentialResponse => {
            return Err(err(path, "requires `card_art` on a Credential Response"));
        }
        None => {}
    }

    if let Some(card_type) = o.get("type") {
        let type_path = format!("{path}.type");
        let type_object = as_object(card_type, &type_path)?;
        let code = type_object
            .get("code")
            .ok_or_else(|| err(&type_path, "requires `code`"))?;
        let code_path = format!("{type_path}.code");
        let code = as_string(code, &code_path)?;
        if !TYPE_CODES.contains(&code) {
            return Err(err(&code_path, "must be one of CREDIT, DEBIT, PREPAID"));
        }
        if let Some(label) = type_object.get("label") {
            as_string(label, &format!("{type_path}.label"))?;
        }
    }

    if let Some(alias) = o.get("alias") {
        as_string(alias, &format!("{path}.alias"))?;
    }

    if let Some(issuer) = o.get("issuer") {
        validate_issuer(issuer, &format!("{path}.issuer"))?;
    }

    if let Some(co_branding) = o.get("co_branding") {
        validate_branding(co_branding, &format!("{path}.co_branding"))?;
    }

    if let Some(network_branding) = o.get("network_branding") {
        validate_network_branding(network_branding, &format!("{path}.network_branding"))?;
    }

    Ok(())
}

/// Validate a DPC display array bound for `stage`.
///
/// Returns `IssuanceError::InvalidRequest` whose message names the offending
/// JSON path, so an operator can correct the input without guessing. Never
/// panics: every fallible access goes through the `as_*` helpers above.
pub fn validate_display(display: &[Value], stage: DisplayStage) -> Result<(), IssuanceError> {
    if display.is_empty() {
        return Err(err("display", "must contain at least one entry"));
    }

    // At most one entry per locale, mirroring the OpenID4VCI display-array
    // convention this member borrows. An entry with no `locale` collapses to a
    // single distinct key, so two locale-less entries collide too.
    let mut seen_locales: BTreeSet<String> = BTreeSet::new();

    for (i, entry) in display.iter().enumerate() {
        let path = format!("display[{i}]");
        let o = as_object(entry, &path)?;

        let locale_key = match o.get("locale") {
            Some(locale) => as_non_empty_string(locale, &format!("{path}.locale"))?.to_string(),
            None => String::new(),
        };
        if !seen_locales.insert(locale_key.clone()) {
            let detail = if locale_key.is_empty() {
                "a second entry without a `locale` is not allowed: at most one \
                 display object per locale"
            } else {
                "duplicate `locale`: at most one display object per locale"
            };
            return Err(err(&path, detail));
        }

        let card = o
            .get("card")
            .ok_or_else(|| err(&path, "requires a `card` object"))?;
        validate_card(card, &format!("{path}.card"), stage)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A response-stage-valid object: carries both members the schema requires.
    fn full_card() -> serde_json::Value {
        json!({
            "locale": "en-US",
            "card": {
                "type": { "code": "CREDIT", "label": "Credit Card" },
                "last_four": "4444",
                "alias": "Platinum Credit Card",
                "card_art": [
                    { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
                ],
                "issuer": {
                    "branding": {
                        "name": "Example Bank",
                        "logo": [
                            { "theme": "DARK", "image_url": "https://bank.example/logo.png" }
                        ]
                    },
                    "country": "DE",
                    "website_url": "https://bank.example",
                    "support_email": "help@bank.example",
                    "support_phone": "+49 30 000000"
                },
                "co_branding": { "name": "SkyFly" },
                "network_branding": [
                    {
                        "network": "example_network",
                        "branding": {
                            "name": "Example Network",
                            "logo": [
                                { "theme": "LIGHT", "image_url": "https://network.example/logo.png" }
                            ]
                        }
                    }
                ]
            }
        })
    }

    /// An offer-stage object honouring the specification's offer-stage privacy
    /// guidance: no `last_four`, no `alias`, no personalised art.
    fn non_pii_card() -> serde_json::Value {
        json!({
            "locale": "en-US",
            "card": {
                "type": { "code": "DEBIT" },
                "network_branding": [
                    { "network": "example_network", "branding": { "name": "Example Network" } }
                ]
            }
        })
    }

    fn reject(v: serde_json::Value, stage: DisplayStage) -> String {
        match validate_display(&[v], stage) {
            Err(IssuanceError::InvalidRequest(m)) => m,
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn a_full_object_is_valid_at_both_stages() {
        validate_display(&[full_card()], DisplayStage::CredentialResponse).unwrap();
        validate_display(&[full_card()], DisplayStage::Offer).unwrap();
    }

    /// The whole reason the admin API has two fields: the compliant offer-stage
    /// object omits members the schema marks required, so the stages cannot
    /// share one validation rule.
    #[test]
    fn last_four_and_card_art_are_optional_at_the_offer_stage_only() {
        validate_display(&[non_pii_card()], DisplayStage::Offer).unwrap();

        let msg = reject(non_pii_card(), DisplayStage::CredentialResponse);
        assert!(
            msg.contains("last_four"),
            "response-stage rejection should name the missing member, got: {msg}"
        );
    }

    #[test]
    fn card_art_is_required_at_the_response_stage() {
        let mut v = full_card();
        v["card"].as_object_mut().unwrap().remove("card_art");
        let msg = reject(v, DisplayStage::CredentialResponse);
        assert!(msg.contains("card_art"), "got: {msg}");
    }

    #[test]
    fn an_empty_display_array_is_rejected() {
        match validate_display(&[], DisplayStage::Offer) {
            Err(IssuanceError::InvalidRequest(m)) => assert!(m.contains("display")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn an_entry_without_a_card_is_rejected() {
        let msg = reject(json!({ "locale": "en-US" }), DisplayStage::Offer);
        assert!(msg.contains("card"), "got: {msg}");
    }

    #[test]
    fn last_four_must_be_exactly_four_ascii_digits() {
        for bad in ["444", "44444", "44a4", "", "٤٤٤٤"] {
            let mut v = full_card();
            v["card"]["last_four"] = json!(bad);
            let msg = reject(v, DisplayStage::CredentialResponse);
            assert!(
                msg.contains("last_four"),
                "{bad:?} should be rejected naming last_four, got: {msg}"
            );
        }
    }

    #[test]
    fn card_art_must_not_be_empty_and_each_element_needs_theme_and_image_url() {
        let mut empty = full_card();
        empty["card"]["card_art"] = json!([]);
        assert!(reject(empty, DisplayStage::Offer).contains("card_art"));

        let mut bad_theme = full_card();
        bad_theme["card"]["card_art"] =
            json!([{ "theme": "SEPIA", "image_url": "https://a.example/x.png" }]);
        assert!(reject(bad_theme, DisplayStage::Offer).contains("theme"));

        let mut no_url = full_card();
        no_url["card"]["card_art"] = json!([{ "theme": "DEFAULT" }]);
        assert!(reject(no_url, DisplayStage::Offer).contains("image_url"));
    }

    #[test]
    fn type_code_must_be_one_of_the_three_enum_values() {
        let mut v = full_card();
        v["card"]["type"] = json!({ "code": "CHARGE" });
        assert!(reject(v, DisplayStage::Offer).contains("type.code"));
    }

    #[test]
    fn issuer_country_must_be_two_ascii_uppercase_letters() {
        for bad in ["de", "DEU", "D", "D1"] {
            let mut v = full_card();
            v["card"]["issuer"]["country"] = json!(bad);
            assert!(
                reject(v, DisplayStage::Offer).contains("country"),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn issuer_requires_branding() {
        let mut v = full_card();
        v["card"]["issuer"] = json!({ "country": "DE" });
        assert!(reject(v, DisplayStage::Offer).contains("branding"));
    }

    #[test]
    fn every_branding_needs_a_non_empty_name() {
        let mut v = full_card();
        v["card"]["co_branding"] = json!({ "name": "" });
        assert!(reject(v, DisplayStage::Offer).contains("co_branding.name"));

        let mut w = full_card();
        w["card"]["network_branding"][0]["branding"] = json!({ "logo": [] });
        assert!(reject(w, DisplayStage::Offer).contains("branding"));
    }

    #[test]
    fn network_branding_elements_need_network_and_branding() {
        let mut v = full_card();
        v["card"]["network_branding"] = json!([{ "branding": { "name": "N" } }]);
        assert!(reject(v, DisplayStage::Offer).contains("network"));

        let mut w = full_card();
        w["card"]["network_branding"] = json!([{ "network": "n" }]);
        assert!(reject(w, DisplayStage::Offer).contains("branding"));
    }

    /// At most one display object per locale — the OpenID4VCI convention this
    /// member borrows. Not enforcing it here would import the same
    /// duplicate-locale hole recorded as GAP-VCI-10 for issuer metadata.
    #[test]
    fn a_duplicate_locale_is_rejected() {
        let err = validate_display(&[full_card(), full_card()], DisplayStage::Offer);
        match err {
            Err(IssuanceError::InvalidRequest(m)) => assert!(m.contains("locale"), "got: {m}"),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn two_entries_without_a_locale_are_also_rejected() {
        let mut a = full_card();
        a.as_object_mut().unwrap().remove("locale");
        let b = a.clone();
        match validate_display(&[a, b], DisplayStage::Offer) {
            Err(IssuanceError::InvalidRequest(m)) => assert!(m.contains("locale"), "got: {m}"),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn distinct_locales_are_accepted() {
        let mut a = full_card();
        a["locale"] = json!("en-US");
        let mut b = full_card();
        b["locale"] = json!("de-DE");
        validate_display(&[a, b], DisplayStage::CredentialResponse).unwrap();
    }

    /// Pins the deliberate divergence from the schema's `additionalProperties:
    /// false`. This is Associate Review 2; a closed world would make every
    /// later revision a breaking change to foundry's admin API. If a future
    /// revision makes strictness right, this test is where that decision
    /// becomes visible instead of silent.
    #[test]
    fn unknown_members_are_accepted_at_every_depth() {
        let mut v = full_card();
        v.as_object_mut()
            .unwrap()
            .insert("future_entry_member".into(), json!(1));
        v["card"]
            .as_object_mut()
            .unwrap()
            .insert("future_card_member".into(), json!("x"));
        v["card"]["issuer"]["branding"]
            .as_object_mut()
            .unwrap()
            .insert("future_branding_member".into(), json!(true));
        validate_display(&[v], DisplayStage::CredentialResponse).unwrap();
    }

    /// `format` keywords in the schema are annotations, not assertions, so
    /// foundry checks the JSON type and not the syntax. Recorded as a test so
    /// the omission reads as a decision.
    #[test]
    fn uri_and_email_syntax_is_deliberately_not_validated() {
        let mut v = full_card();
        v["card"]["issuer"]["website_url"] = json!("not a url");
        v["card"]["issuer"]["support_email"] = json!("not an email");
        v["card"]["card_art"] = json!([{ "theme": "DEFAULT", "image_url": "also not a url" }]);
        validate_display(&[v], DisplayStage::CredentialResponse).unwrap();
    }

    #[test]
    fn error_messages_name_the_offending_json_path() {
        let mut v = full_card();
        v["card"]["card_art"] = json!([
            { "theme": "DEFAULT", "image_url": "https://a.example/x.png" },
            { "theme": "NOPE", "image_url": "https://a.example/y.png" }
        ]);
        let msg = reject(v, DisplayStage::Offer);
        assert!(
            msg.contains("display[0].card.card_art[1].theme"),
            "message must locate the fault precisely, got: {msg}"
        );
    }
}
