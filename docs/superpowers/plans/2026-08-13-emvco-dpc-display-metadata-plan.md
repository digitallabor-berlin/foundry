# EMVCo DPC Display Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator attach EMVCo DPC display metadata to a credential offer, and have foundry carry it on both the Credential Offer and the Credential Response.

**Architecture:** An optional `display: Option<Vec<serde_json::Value>>` member on `CredentialOffer` and `CredentialResponse`, supplied per-offer through two new `CreateOfferRequest` fields (`offer_display`, `credential_response_display`), structurally validated at the admin boundary by a new `foundry-issuer` module, and gated to the one credential type whose `vct` is `com.emvco.dpc.card`. The response-stage object is persisted on the `IssuanceTransaction` so it survives from offer creation to `/credential`.

**Tech Stack:** Rust 2024, `serde` / `serde_json`, `utoipa` for OpenAPI, `tracing` for spans, `tokio` + `axum` for the HTTP layer, plain HTML/JS for the admin console. **No new dependencies.**

**Spec:** [`docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`](../specs/2026-08-13-emvco-dpc-display-metadata-design.md)

## Global Constraints

- **Read first:** [`crates/foundry-issuer/AGENTS.md`](../../../crates/foundry-issuer/AGENTS.md) before touching that crate; [`crates/foundry/AGENTS.md`](../../../crates/foundry/AGENTS.md) and [`crates/foundry/tests/AGENTS.md`](../../../crates/foundry/tests/AGENTS.md) before touching the binary or its tests.
- **No panics in request paths** (root `AGENTS.md` §4.1). No `.unwrap()`, `.expect()`, `panic!()` or `unreachable!()` outside `#[cfg(test)]` code and `tests/`.
- **Every `#[tracing::instrument]` carries `skip_all`** (§4.5). Fields are opt-in. Never log display metadata contents at any level under any flag — only `..._present: bool`.
- **Cite the governing document in code comments** (§4.4). The governing text is the EMVCo Schema Framework, an external reference recorded in [`docs/specs/emvco-dpc-schema-framework.md`](../../specs/emvco-dpc-schema-framework.md) — **not** a standards-track spec. Comments must name it so a reader can distinguish accommodation from conformance.
- **Canonical DPC identifier, exact value:** `com.emvco.dpc.card`
- **Theme enum, exact values:** `DEFAULT`, `LIGHT`, `DARK`
- **Card type code enum, exact values:** `CREDIT`, `DEBIT`, `PREPAID`
- **Scoped test gate only** (§5.1). After each task run:
  `cargo test -p foundry-issuer` (and `-p foundry` for tasks touching it),
  `cargo clippy -p <crate> --all-targets -- -D warnings`, `cargo fmt --check`.
  **Never run `cargo test --workspace`** during these tasks; the full gate of §5.3 runs once at the end of the branch.
- **Branch:** `feat/emvco-dpc-display-metadata` (already created; spec committed as `be1e261` and `43b01f6`).

---

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `crates/foundry-issuer/src/display_metadata.rs` | **new.** Owns the whole structural validation vocabulary: `DisplayStage`, `validate_display`, and the private per-node helpers. Nothing else in the crate knows the EMVCo schema shape. | 1 |
| `crates/foundry-issuer/src/lib.rs` | Declares the module, re-exports `DisplayStage` and `validate_display`. | 1 |
| `crates/foundry-issuer/src/offer.rs` | `CredentialOffer.display`. | 2 |
| `crates/foundry-issuer/src/credential.rs` | `CredentialResponse.display` (task 2); populate it from the transaction (task 4). | 2, 4 |
| `crates/foundry-issuer/src/transaction.rs` | `IssuanceTransaction.credential_response_display`. | 2 |
| `crates/foundry-issuer/src/create_offer.rs` | Request fields, the `DPC_VCT` gate, validation calls, span fields, transaction + offer construction. | 3 |
| `crates/foundry/assets/console.html` | Collapsed display-metadata disclosure + request wiring. | 5 |
| `crates/foundry/tests/console.rs` | Asserts the console markup exists. | 5 |
| `openapi.json`, `openapi-wallet.json` | Regenerated. | 6 |
| `crates/foundry/tests/logging_redaction.rs` | Proves `last_four` never reaches the log. | 6 |
| `crates/foundry/tests/wallet_issuance.rs` | End-to-end flow carrying display through `/token` and `/credential`. | 7 |
| Docs (`docs/specs/`, `docs/conformance/`, both `AGENTS.md`, `README.md`, predecessor design doc) | Deviation record, conformance rows, module map, operator docs. | 8 |

`crates/foundry/src/openapi.rs` is deliberately **not** touched: all three affected schemas are already registered in its `components(schemas(...))`, and the new types are not wire types. The utoipa work is a field-level `#[schema(value_type = ...)]` annotation in the module that declares each field.

---

## Task 1: Display metadata validation module

Self-contained and pure — no storage, no config, no async. Everything else depends on it, so it goes first.

**Files:**

- Create: `crates/foundry-issuer/src/display_metadata.rs`
- Modify: `crates/foundry-issuer/src/lib.rs`

**Interfaces:**

- Consumes: `crate::error::IssuanceError` (existing; use the `InvalidRequest(String)` variant).
- Produces:
  - `pub enum DisplayStage { Offer, CredentialResponse }` — derives `Debug, Clone, Copy, PartialEq, Eq`.
  - `pub fn validate_display(display: &[serde_json::Value], stage: DisplayStage) -> Result<(), IssuanceError>`

- [ ] **Step 1: Write the failing tests**

Create `crates/foundry-issuer/src/display_metadata.rs` containing **only** the test module for now, so the first run fails on missing items rather than on a syntax error:

```rust
//! Structural validation of EMVCo DPC display metadata.

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
        bad_theme["card"]["card_art"] = json!([{ "theme": "SEPIA", "image_url": "https://a.example/x.png" }]);
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
        v.as_object_mut().unwrap().insert("future_entry_member".into(), json!(1));
        v["card"].as_object_mut().unwrap().insert("future_card_member".into(), json!("x"));
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-issuer --lib display_metadata`

Expected: **compile failure**. The module is not declared in `lib.rs`, so the tests do not even build. That is the intended first failure.

- [ ] **Step 3: Declare the module and re-export its surface**

In `crates/foundry-issuer/src/lib.rs`, add the module declaration in alphabetical position — between `pub mod credential;` and `pub mod dpop;`:

```rust
pub mod display_metadata;
```

And add a re-export, in alphabetical position between the `pub use credential::{...}` and `pub use dpop::{...}` blocks:

```rust
pub use display_metadata::{DisplayStage, validate_display};
```

- [ ] **Step 4: Run the tests again to confirm the failure moved**

Run: `cargo test -p foundry-issuer --lib display_metadata`

Expected: still failing, now with `cannot find function 'validate_display'` / `cannot find type 'DisplayStage'` — the module exists but is empty. This confirms the tests are reaching the code under test.

- [ ] **Step 5: Write the implementation**

Insert the following **above** the `#[cfg(test)] mod tests` block in `crates/foundry-issuer/src/display_metadata.rs`, replacing the placeholder doc comment:

```rust
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
        return Err(err(
            &theme_path,
            "must be one of DEFAULT, LIGHT, DARK",
        ));
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
                return Err(err(
                    &last_four_path,
                    "must be exactly four ASCII digits",
                ));
            }
        }
        None if stage == DisplayStage::CredentialResponse => {
            return Err(err(
                path,
                "requires `last_four` on a Credential Response",
            ));
        }
        None => {}
    }

    match o.get("card_art") {
        Some(value) => validate_logo_array(value, &format!("{path}.card_art"))?,
        None if stage == DisplayStage::CredentialResponse => {
            return Err(err(
                path,
                "requires `card_art` on a Credential Response",
            ));
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
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib display_metadata`

Expected: PASS, all tests in the module.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

Expected: both clean. If `fmt` complains, run `cargo fmt` and re-check.

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-issuer/src/display_metadata.rs crates/foundry-issuer/src/lib.rs
git commit -m "feat(issuer): structural validation for EMVCo DPC display metadata

Open-world validation of com.emvco.dpc.card.meta: enforces the enums, the
last_four and country patterns, Branding.name, and one display object per
locale, while accepting unknown members because the governing document is a
draft under Associate Review. last_four and card_art are required only at the
Credential Response stage -- the annex's offer-stage privacy guidance and its
own schema contradict each other, so each stage is validated against the rule
that applies to it."
```

---

## Task 2: Wire model and persistence

Adds the fields without wiring them to any behaviour. Splitting this from Task 3 means a reviewer can reject "the wire shape is wrong" separately from "the orchestration is wrong".

**Files:**

- Modify: `crates/foundry-issuer/src/offer.rs` (struct at `:28`, tests at `:176` and `:193`)
- Modify: `crates/foundry-issuer/src/credential.rs` (struct at `:128`, construction at `:470`)
- Modify: `crates/foundry-issuer/src/transaction.rs` (struct at `:10`, test helper at `:232`)
- Modify: `crates/foundry-issuer/src/create_offer.rs` (transaction literals at `:133` and `:164`, offer literal at `:195`)
- Modify: `crates/foundry-issuer/src/token.rs` (test helper at `:441`)
- Modify: `crates/foundry-issuer/src/authorize.rs` (test helper at `:237`)

**Interfaces:**

- Consumes: nothing from Task 1.
- Produces:
  - `CredentialOffer.display: Option<Vec<serde_json::Value>>`
  - `CredentialResponse.display: Option<Vec<serde_json::Value>>`
  - `IssuanceTransaction.credential_response_display: Option<Vec<serde_json::Value>>`

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/offer.rs`:

```rust
/// The no-regression assertion for every credential type that is not DPC.
///
/// Asserted on the serialised object's KEYS, not on a round-tripped `Option`:
/// a `display: null` member would satisfy the weaker check while still
/// changing the bytes every existing wallet receives.
#[test]
fn an_offer_without_display_serialises_without_a_display_key() {
    let offer = pre_auth_offer();
    let value = serde_json::to_value(&offer).unwrap();
    let object = value.as_object().unwrap();
    assert!(
        !object.contains_key("display"),
        "an offer with no display metadata must not carry the key at all, got: {value}"
    );
}

#[test]
fn an_offer_with_display_serialises_the_array_verbatim() {
    let mut offer = pre_auth_offer();
    offer.display = Some(vec![serde_json::json!({
        "locale": "en-US",
        "card": { "type": { "code": "CREDIT" } }
    })]);
    let value = serde_json::to_value(&offer).unwrap();
    assert_eq!(value["display"][0]["card"]["type"]["code"], "CREDIT");
}

/// The DC API payload is built by serialising the offer, so the two transports
/// cannot disagree about `display`. This test is what keeps that true if
/// someone later hand-builds the payload.
#[test]
fn the_dc_api_offer_inherits_display_from_the_offer() {
    let mut offer = pre_auth_offer();
    offer.display = Some(vec![serde_json::json!({
        "locale": "en-US",
        "card": { "type": { "code": "DEBIT" } }
    })]);
    let cfg = dc_api_test_config();
    let payload = build_dc_api_offer(&cfg, &offer, &[]).unwrap();
    assert_eq!(payload["display"][0]["card"]["type"]["code"], "DEBIT");
}
```

> **Note for the implementer:** `offer.rs`'s test module may not already have a
> `Config` helper for `build_dc_api_offer`. Check first — run
> `rg -n "fn .*config" crates/foundry-issuer/src/offer.rs`. If none exists,
> **do not** copy the 80-line `test_config()` from `create_offer.rs`; instead
> drop the third test above and put the equivalent assertion in
> `create_offer.rs`'s test module in Task 3, where `test_config()` already
> exists. Record which you did in the commit message.

Append to the existing `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/transaction.rs`:

```rust
#[tokio::test]
async fn a_transaction_round_trips_its_credential_response_display() {
    let storage = test_storage().await;
    let mut tx = sample_tx("tx-display");
    tx.credential_response_display = Some(vec![serde_json::json!({
        "locale": "en-US",
        "card": { "last_four": "4444" }
    })]);

    save_transaction(&storage, &tx, 600, 1_700_000_000)
        .await
        .unwrap();
    let loaded = load_transaction(&storage, "tx-display")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(loaded.credential_response_display, tx.credential_response_display);
}

/// Transactions are persisted as JSON, so a row written before this field
/// existed must still deserialize after a rolling restart. The literal below is
/// deliberately a hand-written pre-upgrade row, not a serialised struct --
/// serialising the current struct could not detect the regression.
#[test]
fn a_transaction_persisted_before_the_field_existed_still_deserializes() {
    let legacy = r#"{
        "transaction_id": "legacy-1",
        "credential_type_id": "pid",
        "claims": {},
        "pre_authorized_code": "abc",
        "tx_code": null,
        "status_list_index": null,
        "access_token": null,
        "state": "offered",
        "created_at": 1700000000,
        "redirect_uri": null,
        "issuer_state": null,
        "authorization_code": null,
        "code_challenge": null,
        "code_challenge_method": null
    }"#;
    let tx: IssuanceTransaction = serde_json::from_str(legacy).unwrap();
    assert_eq!(tx.credential_response_display, None);
    assert_eq!(tx.dpop_jkt, None);
}
```

Append to the existing `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/credential.rs`:

```rust
#[test]
fn a_credential_response_without_display_serialises_without_a_display_key() {
    let response = CredentialResponse {
        credentials: vec![IssuedCredential {
            credential: "eyJ...".to_string(),
        }],
        notification_id: None,
        display: None,
    };
    let value = serde_json::to_value(&response).unwrap();
    assert!(
        !value.as_object().unwrap().contains_key("display"),
        "got: {value}"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-issuer --lib`

Expected: compile failure — `struct 'CredentialOffer' has no field named 'display'` and the same for the other two structs.

- [ ] **Step 3: Add the three fields**

In `crates/foundry-issuer/src/offer.rs`, add to `CredentialOffer` (after `grants`):

```rust
    /// EMVCo DPC display metadata (`com.emvco.dpc.card.meta`), carried per the
    /// Schema Framework A.5 "Protocol Alignment" proposal.
    ///
    /// **OpenID4VCI 1.0 defines no `display` member on a Credential Offer.**
    /// This is a deliberate, documented divergence justified only by an
    /// external-reference document (root AGENTS.md §4.4) and confined by
    /// `create_offer` to the `com.emvco.dpc.card` credential type. See
    /// `docs/specs/emvco-dpc-schema-framework.md` and
    /// `docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`.
    ///
    /// `skip_serializing_if` is load-bearing: an offer without display metadata
    /// must serialise to exactly the bytes it did before this field existed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub display: Option<Vec<serde_json::Value>>,
```

In `crates/foundry-issuer/src/credential.rs`, add to `CredentialResponse` (after `notification_id`):

```rust
    /// EMVCo DPC display metadata, echoed from the `IssuanceTransaction`.
    ///
    /// **OpenID4VCI 1.0 defines no `display` member on a Credential Response.**
    /// Same divergence, same justification and same confinement as
    /// `CredentialOffer::display`; see that field's comment.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub display: Option<Vec<serde_json::Value>>,
```

In `crates/foundry-issuer/src/transaction.rs`, add to `IssuanceTransaction` (after `dpop_jkt`):

```rust
    /// The response-stage EMVCo DPC display metadata pinned at `create_offer`
    /// time, echoed onto the Credential Response at `/credential`.
    ///
    /// Only the response-stage object is persisted: the offer-stage object is
    /// consumed while building the `CredentialOffer` and never read again.
    ///
    /// `#[serde(default)]` is load-bearing for the same reason as `dpop_jkt`'s:
    /// transactions are persisted as JSON in the KV store, so a row written
    /// before this field existed must still deserialize after a rolling restart.
    #[serde(default)]
    pub credential_response_display: Option<Vec<serde_json::Value>>,
```

> **If utoipa rejects `value_type = Option<Vec<Object>>`:** fall back to
> `#[schema(value_type = Vec<Object>, nullable)]`. The existing precedent for a
> `serde_json::Value` field is `CreateOfferResponse.dc_api_offer`, which uses
> `#[schema(value_type = Object)]`. `IssuanceTransaction` derives no
> `ToSchema`, so it needs no annotation at all.

- [ ] **Step 4: Let the compiler enumerate every struct literal, and fix each**

Run: `cargo build -p foundry-issuer --all-targets`

rustc will report one `missing field` error per literal. There are **nine**:

| File:line | Literal | Add |
| --- | --- | --- |
| `offer.rs:176` | `CredentialOffer` | `display: None,` |
| `offer.rs:193` | `CredentialOffer` | `display: None,` |
| `create_offer.rs:195` | `CredentialOffer` | `display: None,` (Task 3 replaces this) |
| `credential.rs:470` | `CredentialResponse` | `display: None,` (Task 4 replaces this) |
| `transaction.rs:232` | `IssuanceTransaction` | `credential_response_display: None,` |
| `token.rs:441` | `IssuanceTransaction` | `credential_response_display: None,` |
| `authorize.rs:237` | `IssuanceTransaction` | `credential_response_display: None,` |
| `create_offer.rs:133` | `IssuanceTransaction` | `credential_response_display: None,` (Task 3 replaces this) |
| `create_offer.rs:164` | `IssuanceTransaction` | `credential_response_display: None,` (Task 3 replaces this) |

The two `sample_auth_code_tx` helpers (`token.rs:707`, `transaction.rs:251`) mutate a `sample_tx(...)` result rather than writing a literal, so they need no change. **Do not** add `..Default::default()` to any of these — `IssuanceTransaction` implements no `Default`, and adding one would let a future field be silently forgotten.

Re-run `cargo build -p foundry-issuer --all-targets` until it is clean.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib`

Expected: PASS, including the three new `offer.rs` tests (or two, if you dropped the DC API one per the Step 1 note), both new `transaction.rs` tests, and the new `credential.rs` test.

- [ ] **Step 6: Confirm no dependent crate broke**

Run: `cargo build -p foundry --all-targets`

Expected: clean. `foundry` constructs none of these three structs by literal, so nothing should break; if something does, add the field rather than changing the struct.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo test -p foundry-issuer
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 8: Commit**

```bash
git add crates/foundry-issuer/src/
git commit -m "feat(issuer): optional display member on offer, response and transaction

CredentialOffer.display and CredentialResponse.display carry EMVCo DPC display
metadata; IssuanceTransaction.credential_response_display persists the
response-stage object from offer creation to /credential.

All three are Option with skip_serializing_if, so an offer or response without
display metadata serialises to exactly the bytes it did before -- asserted on
the serialised keys rather than a round-tripped Option, since a null would pass
the weaker check. serde(default) on the transaction field keeps pre-upgrade KV
rows deserializable."
```

---

## Task 3: Wire the admin API — request fields, gate, validation

**Files:**

- Modify: `crates/foundry-issuer/src/create_offer.rs`

**Interfaces:**

- Consumes: `crate::display_metadata::{DisplayStage, validate_display}` from Task 1; the three struct fields from Task 2.
- Produces:
  - `CreateOfferRequest.offer_display: Option<Vec<serde_json::Value>>`
  - `CreateOfferRequest.credential_response_display: Option<Vec<serde_json::Value>>`
  - `const DPC_VCT: &str = "com.emvco.dpc.card"` (private to the module)

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/create_offer.rs`:

```rust
/// `test_config()` plus the DPC credential type, so gating has something to
/// accept as well as something to reject.
fn test_config_with_dpc() -> Config {
    let mut cfg = test_config();
    cfg.credential_types.push(CredentialType {
        id: "com.emvco.dpc.card".to_string(),
        format: "dc+sd-jwt".to_string(),
        vct: Some("com.emvco.dpc.card".to_string()),
        doctype: None,
        scope: None,
        cryptographic_holder_binding: true,
        display: vec![],
        claims: vec![
            ClaimDef {
                path: vec!["credential_id".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
            ClaimDef {
                path: vec!["network".to_string()],
                required: Some(true),
                selectively_disclosable: true,
                display: vec![],
            },
        ],
        validity_seconds: None,
    });
    cfg
}

fn dpc_claims() -> serde_json::Map<String, serde_json::Value> {
    let mut claims = serde_json::Map::new();
    claims.insert("credential_id".to_string(), serde_json::json!("cred-1"));
    claims.insert("network".to_string(), serde_json::json!("example_network"));
    claims
}

fn offer_stage_display() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "locale": "en-US",
        "card": {
            "type": { "code": "CREDIT", "label": "Credit Card" },
            "network_branding": [
                { "network": "example_network", "branding": { "name": "Example Network" } }
            ]
        }
    })]
}

fn response_stage_display() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "locale": "en-US",
        "card": {
            "last_four": "4444",
            "alias": "Platinum Credit Card",
            "card_art": [
                { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
            ]
        }
    })]
}

fn dpc_request() -> CreateOfferRequest {
    CreateOfferRequest {
        credential_type_id: "com.emvco.dpc.card".to_string(),
        claims: dpc_claims(),
        tx_code_required: false,
        redirect_uri: None,
        offer_display: Some(offer_stage_display()),
        credential_response_display: Some(response_stage_display()),
    }
}

#[tokio::test]
async fn a_dpc_offer_carries_the_offer_stage_display_and_persists_the_response_stage_one() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let res = create_offer(&cfg, &storage, dpc_request(), 1_700_000_000, &[])
        .await
        .unwrap();

    let display = res
        .credential_offer
        .display
        .as_ref()
        .expect("the offer must carry the offer-stage display array");
    assert_eq!(display[0]["card"]["type"]["code"], "CREDIT");
    assert!(
        display[0]["card"].get("last_four").is_none(),
        "the offer must carry the offer-stage object, not the response-stage one"
    );

    let tx = load_transaction(&storage, &res.transaction_id)
        .await
        .unwrap()
        .unwrap();
    let persisted = tx
        .credential_response_display
        .as_ref()
        .expect("the response-stage display must be persisted on the transaction");
    assert_eq!(persisted[0]["card"]["last_four"], "4444");
}

#[tokio::test]
async fn the_dc_api_offer_carries_the_offer_stage_display() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let res = create_offer(&cfg, &storage, dpc_request(), 1_700_000_000, &[])
        .await
        .unwrap();

    assert_eq!(
        res.dc_api_offer["display"][0]["card"]["type"]["code"],
        "CREDIT",
        "dc_api_offer is built by serialising the offer, so it must inherit display"
    );
}

/// The gate of design §3.5: a non-OpenID4VCI member must not appear on any
/// credential type except the one whose governing document asks for it.
#[tokio::test]
async fn display_metadata_is_rejected_for_a_non_dpc_credential_type() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let mut claims = serde_json::Map::new();
    claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

    let err = create_offer(
        &cfg,
        &storage,
        CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
            redirect_uri: None,
            offer_display: Some(offer_stage_display()),
            credential_response_display: None,
        },
        1_700_000_000,
        &[],
    )
    .await
    .expect_err("display metadata on a non-DPC credential type must be rejected");

    match err {
        IssuanceError::InvalidRequest(m) => assert!(
            m.contains("com.emvco.dpc.card"),
            "the rejection should name the only credential type that may carry it, got: {m}"
        ),
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

/// A rejected request must not leave a transaction or a consumed status index
/// behind: the gate runs before any state is mutated.
#[tokio::test]
async fn a_rejected_display_request_persists_nothing() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let mut claims = serde_json::Map::new();
    claims.insert("birthdate".to_string(), serde_json::json!("1990-01-01"));

    let _ = create_offer(
        &cfg,
        &storage,
        CreateOfferRequest {
            credential_type_id: "pid".to_string(),
            claims,
            tx_code_required: false,
            redirect_uri: None,
            offer_display: Some(offer_stage_display()),
            credential_response_display: None,
        },
        1_700_000_000,
        &[],
    )
    .await;

    assert!(
        load_status_list(&storage, "1").await.unwrap().is_none(),
        "no status list should have been created for a rejected request"
    );
}

/// Structural validation runs at the admin boundary, and the two stages use
/// different rules: an object missing `last_four` is fine on the offer and
/// invalid on the response.
#[tokio::test]
async fn a_response_stage_object_missing_last_four_is_rejected() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let mut req = dpc_request();
    req.credential_response_display = Some(offer_stage_display());

    let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
        .await
        .expect_err("a response-stage object without last_four must be rejected");

    match err {
        IssuanceError::InvalidRequest(m) => assert!(m.contains("last_four"), "got: {m}"),
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn an_offer_stage_object_missing_last_four_is_accepted() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let mut req = dpc_request();
    req.credential_response_display = None;

    create_offer(&cfg, &storage, req, 1_700_000_000, &[])
        .await
        .expect("the offer stage must accept an object without last_four");
}

#[tokio::test]
async fn a_structurally_invalid_display_object_is_rejected() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let mut req = dpc_request();
    req.offer_display = Some(vec![serde_json::json!({
        "locale": "en-US",
        "card": { "type": { "code": "CHARGE" } }
    })]);

    let err = create_offer(&cfg, &storage, req, 1_700_000_000, &[])
        .await
        .expect_err("an invalid type.code must be rejected");

    match err {
        IssuanceError::InvalidRequest(m) => assert!(m.contains("type.code"), "got: {m}"),
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

/// A DPC offer that supplies no display metadata must still serialise without
/// the key -- the gate must not force the member into existence.
#[tokio::test]
async fn a_dpc_offer_without_display_still_omits_the_key() {
    let cfg = test_config_with_dpc();
    let storage = test_storage().await;

    let res = create_offer(
        &cfg,
        &storage,
        CreateOfferRequest {
            credential_type_id: "com.emvco.dpc.card".to_string(),
            claims: dpc_claims(),
            tx_code_required: false,
            redirect_uri: None,
            offer_display: None,
            credential_response_display: None,
        },
        1_700_000_000,
        &[],
    )
    .await
    .unwrap();

    let value = serde_json::to_value(&res.credential_offer).unwrap();
    assert!(!value.as_object().unwrap().contains_key("display"), "got: {value}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-issuer --lib create_offer`

Expected: compile failure — `struct 'CreateOfferRequest' has no field named 'offer_display'`, plus `missing fields` errors on the **13 existing** `CreateOfferRequest` literals in this file's test module.

- [ ] **Step 3: Add the request fields**

In `crates/foundry-issuer/src/create_offer.rs`, add to `CreateOfferRequest` (after `redirect_uri`):

```rust
    /// EMVCo DPC display metadata for the **Credential Offer**.
    ///
    /// Validated with `DisplayStage::Offer`, which treats `last_four` and
    /// `card_art` as optional. That is deliberate: the Schema Framework's
    /// offer-stage guidance says PII-type data should not appear on an offer,
    /// while its schema marks both members required. See design §1.3.
    ///
    /// Accepted only for the `com.emvco.dpc.card` credential type.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub offer_display: Option<Vec<serde_json::Value>>,
    /// EMVCo DPC display metadata for the **Credential Response**.
    ///
    /// Validated with `DisplayStage::CredentialResponse`, which requires
    /// `last_four` and `card_art`. Persisted on the `IssuanceTransaction` and
    /// echoed at `/credential`.
    ///
    /// Accepted only for the `com.emvco.dpc.card` credential type.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub credential_response_display: Option<Vec<serde_json::Value>>,
```

- [ ] **Step 4: Fix the 13 existing test literals**

Run `cargo build -p foundry-issuer --all-targets` and add both fields as `None` to each `CreateOfferRequest { ... }` literal rustc names:

```rust
            offer_display: None,
            credential_response_display: None,
```

Repeat until the build is clean. Do not introduce a `Default` impl.

- [ ] **Step 5: Add the import, the constant, the gate and the validation**

At the top of `crates/foundry-issuer/src/create_offer.rs`, add to the imports:

```rust
use crate::display_metadata::{DisplayStage, validate_display};
```

Immediately below the existing `DEFAULT_TX_CODE_LENGTH` constant, add:

```rust
/// The canonical EMVCo Digital Payment Credential type identifier.
///
/// Behaviour keyed on this constant is justified **only** by the EMV® Digital
/// Payment Credential Specification — Schema Framework, an external-reference
/// document rather than a standards-track specification (root AGENTS.md §4.4,
/// external-reference rule; the stub is
/// `docs/specs/emvco-dpc-schema-framework.md`).
///
/// Confining display metadata to this one `vct` is what keeps a member
/// OpenID4VCI 1.0 does not define off every other credential type's offer and
/// response. The mdoc binding is unimplemented, so only `vct` is consulted.
const DPC_VCT: &str = "com.emvco.dpc.card";
```

Inside `create_offer`, insert this block **immediately after** the `let ct = cfg.credential_types.iter()...?;` binding and **before** the required-claim validation loop:

```rust
    // Gate, then validate -- in that order, and both before any state is
    // mutated, so a rejected request allocates no status index and writes no
    // transaction.
    if (req.offer_display.is_some() || req.credential_response_display.is_some())
        && ct.vct.as_deref() != Some(DPC_VCT)
    {
        return Err(IssuanceError::InvalidRequest(format!(
            "display metadata is only supported for the '{DPC_VCT}' credential \
             type; credential_type '{}' declares vct {:?}",
            ct.id, ct.vct
        )));
    }
    if let Some(display) = req.offer_display.as_deref() {
        validate_display(display, DisplayStage::Offer)?;
    }
    if let Some(display) = req.credential_response_display.as_deref() {
        validate_display(display, DisplayStage::CredentialResponse)?;
    }
```

- [ ] **Step 6: Add the span fields**

Extend the existing `#[tracing::instrument]` attribute's `fields(...)` list with two entries. `skip_all` is already present and MUST stay:

```rust
        // Presence only, never contents: these objects carry `last_four`, a
        // cardholder-recognisable alias and possibly personalised art URLs, all
        // of which are on root AGENTS.md §4.5's never-logged list.
        offer_display_present = req.offer_display.is_some(),
        credential_response_display_present = req.credential_response_display.is_some(),
```

- [ ] **Step 7: Thread the values into the transaction and the offer**

`req.offer_display` and `req.credential_response_display` are moved out of `req` in the branches below, so bind them **before** the `if let Some(redirect_uri) = req.redirect_uri` block:

```rust
    let offer_display = req.offer_display.take();
    let credential_response_display = req.credential_response_display.take();
```

This requires `req` to be mutable. Change the function signature's parameter from `req: CreateOfferRequest` to `mut req: CreateOfferRequest`.

In **both** `IssuanceTransaction { ... }` literals (the `authorization_code` branch and the `pre-authorized_code` branch), replace the `credential_response_display: None,` added in Task 2 with:

```rust
            credential_response_display: credential_response_display.clone(),
```

In the `CredentialOffer { ... }` literal, replace the `display: None,` added in Task 2 with:

```rust
        display: offer_display,
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib create_offer`

Expected: PASS, all new tests plus the 13 pre-existing ones.

- [ ] **Step 9: Run the scoped gate**

```bash
cargo test -p foundry-issuer
cargo test -p foundry
cargo clippy -p foundry-issuer -p foundry --all-targets -- -D warnings
cargo fmt --check
```

`-p foundry` is the affected dependent per root `AGENTS.md` §5.2. Do **not** run `--workspace`.

- [ ] **Step 10: Commit**

```bash
git add crates/foundry-issuer/src/create_offer.rs
git commit -m "feat(issuer): accept and validate DPC display metadata on create_offer

Two independent optional request fields, offer_display and
credential_response_display, each validated against its own stage's rules. A
single field could not express the compliant configuration: any object rich
enough for the response carries members the annex forbids on the offer.

Gated on DPC_VCT so no other credential type gains a member OpenID4VCI 1.0
does not define. Gate and validation both run before any state is mutated, so a
rejected request allocates no status index. The span records presence only --
these objects are on the never-logged list."
```

---

## Task 4: Echo the stored display on the Credential Response

**Files:**

- Modify: `crates/foundry-issuer/src/credential.rs` (construction at `:470`)

**Interfaces:**

- Consumes: `IssuanceTransaction.credential_response_display` (Task 2), `CredentialResponse.display` (Task 2).
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` in `crates/foundry-issuer/src/credential.rs`.

> **Implementer note:** this module's tests already build a full issuance
> scenario. Find the existing happy-path test — `rg -n "async fn " crates/foundry-issuer/src/credential.rs`
> — and model the setup on it rather than inventing a new harness. The
> assertion you are adding is the last two statements; everything before is
> existing-shape setup.

```rust
/// The response half of design §3.6: whatever was pinned on the transaction at
/// offer time appears on the Credential Response, unchanged.
///
/// Validation is deliberately NOT repeated here. The object was validated at
/// the admin boundary and has been inert in storage since; re-validating would
/// turn an operator's input defect into a wallet-facing /credential failure.
#[tokio::test]
async fn the_credential_response_echoes_the_transactions_display_metadata() {
    // ... existing happy-path setup, but with the transaction carrying:
    //     credential_response_display: Some(vec![serde_json::json!({
    //         "locale": "en-US",
    //         "card": {
    //             "last_four": "4444",
    //             "card_art": [
    //                 { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
    //             ]
    //         }
    //     })]),
    // ... then drive handle_credential_request as the happy-path test does.

    let display = response
        .display
        .as_ref()
        .expect("the credential response must echo the transaction's display metadata");
    assert_eq!(display[0]["card"]["last_four"], "4444");
}

/// The no-regression counterpart: a transaction with no display metadata
/// produces a response with no `display` key at all.
#[tokio::test]
async fn a_credential_response_omits_display_when_the_transaction_has_none() {
    // ... the existing happy-path setup verbatim (its transaction already has
    //     credential_response_display: None) ...

    let value = serde_json::to_value(&response).unwrap();
    assert!(
        !value.as_object().unwrap().contains_key("display"),
        "got: {value}"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p foundry-issuer --lib credential`

Expected: the first new test FAILS on the `.expect(...)` — `display` is `None` because nothing populates it yet. The second already passes; that is fine and expected, it is a regression guard rather than a driver.

- [ ] **Step 3: Populate the field**

In `crates/foundry-issuer/src/credential.rs`, in the `Ok(CredentialResponse { ... })` construction, replace the `display: None,` added in Task 2 with:

```rust
        // Echoed verbatim from the transaction, where create_offer pinned and
        // already validated it. Not re-validated here: a defect in an operator's
        // input belongs to the admin boundary that accepted it, not to the
        // wallet's /credential call.
        display: tx.credential_response_display.clone(),
```

`tx` is still in scope — `save_transaction_with_indices` takes it by reference.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p foundry-issuer --lib credential`

Expected: PASS, both new tests.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry-issuer
cargo clippy -p foundry-issuer --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry-issuer/src/credential.rs
git commit -m "feat(issuer): echo the transaction's display metadata on /credential

Completes the offer-plus-response transport of design §3.1. The object is
echoed verbatim from the transaction and deliberately not re-validated: it was
validated at the admin boundary, so a defect there must not surface as a
wallet-facing /credential failure."
```

---

## Task 5: Admin console inputs

**Files:**

- Modify: `crates/foundry/assets/console.html` (markup near `:186`, JS near `:2710`)
- Modify: `crates/foundry/tests/console.rs`

**Interfaces:**

- Consumes: the `offer_display` / `credential_response_display` request fields from Task 3.
- Produces: DOM ids `offer-display-json` and `credential-response-display-json`.

- [ ] **Step 1: Write the failing test**

Append to `crates/foundry/tests/console.rs`, modelled on the existing `console_has_transaction_data_input_for_verification`:

```rust
#[tokio::test]
async fn console_has_display_metadata_inputs_for_dpc_issuance() {
    // EMVCo DPC display metadata is accepted by POST /admin/issuance/offers but
    // was unreachable from the console. Both textareas ship EMPTY with a
    // placeholder, not pre-filled: the default credential_type_id is `pid`, and
    // the server-side gate rejects display metadata for any type other than
    // com.emvco.dpc.card -- a pre-filled textarea would make the console's
    // default "Create Offer" click fail with a 400. See design §3.7.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let config = Arc::new(test_config(true));
    let app = admin_router(AppState::new(storage, config), AdminApiKey(None));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body_bytes);

    assert!(
        html.contains(r#"id="offer-display-json"#),
        "console should have an offer_display textarea"
    );
    assert!(
        html.contains(r#"id="credential-response-display-json"#),
        "console should have a credential_response_display textarea"
    );
    assert!(
        html.contains("DPC display metadata (optional)"),
        "the textareas should sit behind a labelled disclosure"
    );
    assert!(
        html.contains("opt-disclosure"),
        "the disclosure should reuse the optional-input class, not the QR block's"
    );
    assert!(
        html.contains("body.offer_display"),
        "the create-offer handler should put the parsed offer-stage array on the body"
    );
    assert!(
        html.contains("body.credential_response_display"),
        "the create-offer handler should put the parsed response-stage array on the body"
    );
    assert!(
        !html.contains(r#"<textarea id="offer-display-json">{"#),
        "the offer_display textarea must ship empty: a pre-filled value would \
         make the default pid flow fail the server-side DPC gate"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p foundry --test console console_has_display_metadata_inputs_for_dpc_issuance`

Expected: FAIL on the first assertion — no such textarea exists.

- [ ] **Step 3: Add the markup**

In `crates/foundry/assets/console.html`, insert immediately **after** the `claims (JSON)` field `</div>` and **before** `<div class="field checkbox">` (the `tx-code-required` block, around line 187):

```html
    <details class="opt-disclosure">
      <summary>DPC display metadata (optional)</summary>
      <div class="field">
        <label for="offer-display-json">offer_display (JSON array)</label>
        <textarea id="offer-display-json" placeholder='[{"locale": "en-US", "card": {"type": {"code": "CREDIT"}, "network_branding": [{"network": "example_network", "branding": {"name": "Example Network"}}]}}]'></textarea>
      </div>
      <div class="field">
        <label for="credential-response-display-json">credential_response_display (JSON array)</label>
        <textarea id="credential-response-display-json" placeholder='[{"locale": "en-US", "card": {"last_four": "4444", "card_art": [{"theme": "DEFAULT", "image_url": "https://bank.example/card.png"}]}}]'></textarea>
      </div>
    </details>
```

Both textareas are empty. The `offer_display` placeholder deliberately shows a
**non-PII** object (no `last_four`, no `alias`) and the response one shows the
schema-required members, so the two placeholders teach the stage split.

- [ ] **Step 4: Wire the JS**

In the create-offer click handler (around line 2710), after the existing
`const txCodeRequired = ...` line, add:

```javascript
      const offerDisplayRaw = document.getElementById('offer-display-json').value;
      const credentialResponseDisplayRaw = document.getElementById('credential-response-display-json').value;
```

After the existing `claims` parse block, add:

```javascript
      // A blank textarea omits the field entirely rather than sending null or
      // [], because the server rejects an empty display array.
      let offerDisplay = null;
      try {
        offerDisplay = offerDisplayRaw.trim() ? JSON.parse(offerDisplayRaw) : null;
      } catch (e) {
        showError(errorEl, new Error('offer_display is not valid JSON: ' + e.message));
        return;
      }

      let credentialResponseDisplay = null;
      try {
        credentialResponseDisplay = credentialResponseDisplayRaw.trim()
          ? JSON.parse(credentialResponseDisplayRaw)
          : null;
      } catch (e) {
        showError(errorEl, new Error('credential_response_display is not valid JSON: ' + e.message));
        return;
      }
```

Replace the existing inline request body with a named object so the optional
fields can be added conditionally:

```javascript
        const body = {
          credential_type_id: credentialTypeId,
          claims: claims,
          tx_code_required: txCodeRequired
        };
        if (offerDisplay !== null) {
          body.offer_display = offerDisplay;
        }
        if (credentialResponseDisplay !== null) {
          body.credential_response_display = credentialResponseDisplay;
        }

        const responseBody = await adminFetch('/admin/issuance/offers', {
          method: 'POST',
          body: JSON.stringify(body)
        });
```

Then rename the subsequent uses of the old response variable to
`responseBody` throughout the handler — the existing code calls it `body`,
which the request object now shadows. Read the whole handler before editing:
`sed -n '2700,2760p' crates/foundry/assets/console.html`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p foundry --test console`

Expected: PASS, the new test and all pre-existing console tests.

- [ ] **Step 6: Manually verify the default flow still works**

This is the regression the spec correction exists to prevent, and no unit test covers a browser click:

```bash
cargo run -p foundry -- quickstart
```

Open `http://127.0.0.1:9000/console`, leave every field at its default, click **Create Offer**. Expected: a `credential_offer_uri` and a QR code — **not** a `400`. Then expand "DPC display metadata (optional)" and confirm both textareas are empty with grey placeholder text.

- [ ] **Step 7: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 8: Commit**

```bash
git add crates/foundry/assets/console.html crates/foundry/tests/console.rs
git commit -m "feat(console): DPC display metadata inputs on the issuance card

Two JSON textareas behind a collapsed opt-disclosure, matching the
transaction_data precedent. Both ship EMPTY with a placeholder: the default
credential_type_id is pid and the server-side gate rejects display metadata for
non-DPC types, so a pre-filled textarea would break the console's default
Create Offer click. A blank textarea omits the field rather than sending null."
```

---

## Task 6: OpenAPI specs and the redaction gate

**Files:**

- Modify: `openapi.json`, `openapi-wallet.json` (regenerated, not hand-edited)
- Modify: `crates/foundry/tests/logging_redaction.rs`

**Interfaces:**

- Consumes: the schema changes from Tasks 2 and 3.
- Produces: nothing new.

- [ ] **Step 1: Write the failing redaction test**

Append to `crates/foundry/tests/logging_redaction.rs`, following the file's existing pattern (capture at `TRACE`, drive the real router, search the whole buffer):

> **Implementer note:** read the file's existing negative tests first —
> `rg -n "async fn " crates/foundry/tests/logging_redaction.rs` — and reuse its
> `CaptureHandle` setup and its `sensitive_enabled` guard verbatim. Do not
> invent a new capture harness.

```rust
/// Display metadata carries `card.last_four`, a cardholder-recognisable alias
/// and possibly personalised art URLs. Root AGENTS.md §4.5 puts all of it on
/// the never-logged list; `create_offer` records presence only.
///
/// Captured at TRACE so the assertion covers every level -- a leak that only
/// appears at `debug` is still a leak.
#[tokio::test]
async fn display_metadata_never_reaches_the_log() {
    // ... the file's existing capture + admin_router setup, with a config whose
    //     credential_types include a `com.emvco.dpc.card` entry (vct
    //     "com.emvco.dpc.card") ...

    // Distinctive values, so a match cannot be coincidental.
    let body = serde_json::json!({
        "credential_type_id": "com.emvco.dpc.card",
        "claims": { "credential_id": "cred-1", "network": "example_network" },
        "tx_code_required": false,
        "offer_display": [{
            "locale": "en-US",
            "card": { "type": { "code": "CREDIT" } }
        }],
        "credential_response_display": [{
            "locale": "en-US",
            "card": {
                "last_four": "9137",
                "alias": "Unmistakable Alias 8f3a2c",
                "card_art": [
                    { "theme": "DEFAULT", "image_url": "https://bank.example/personalised-7d41e9.png" }
                ]
            }
        }]
    });

    // ... POST it to /admin/issuance/offers through the router, assert 200 ...

    let logs = capture.contents();
    for secret in ["9137", "Unmistakable Alias 8f3a2c", "personalised-7d41e9"] {
        assert!(
            !logs.contains(secret),
            "display metadata leaked into the log: {secret:?} found in:\n{logs}"
        );
    }

    // The positive control for this assertion: presence IS recorded, so the
    // test cannot pass merely because nothing was logged at all.
    assert!(
        logs.contains("credential_response_display_present"),
        "the span should record presence, got:\n{logs}"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails or passes for the right reason**

Run: `cargo test -p foundry --test logging_redaction display_metadata_never_reaches_the_log`

Expected: PASS on the negative assertions (nothing logs the payload today) and
**FAIL** on the positive control until Task 3's span fields are in place. If
Task 3 is already committed, the whole test passes — that is correct, and the
test's value is as a guard against a future `#[instrument]` losing `skip_all`.
If the negative assertions fail, **stop**: that is a real leak, and the fix is
at the emitting site, never a weakened assertion.

- [ ] **Step 3: Regenerate both OpenAPI specs**

```bash
cargo run -p foundry -- openapi --out openapi.json
cargo run -p foundry -- openapi --wallet --out openapi-wallet.json
```

Do **not** hand-edit either file. Per `crates/foundry/AGENTS.md`, the admin spec
is the default and `--wallet` selects the wallet-facing one.

- [ ] **Step 4: Inspect the diff before trusting it**

```bash
git diff --stat openapi.json openapi-wallet.json
git diff openapi.json | grep -A4 -B1 display
```

Expected: `CreateOfferRequest` gains `offer_display` and
`credential_response_display`; `CredentialOffer` and `CredentialResponse` each
gain `display`. All five nullable arrays of generic objects. **No other schema
should change.** If unrelated churn appears, the generated file was stale before
this branch — say so in the commit message rather than silently absorbing it.

- [ ] **Step 5: Run the spec-drift test**

Run: `cargo test -p foundry --test openapi_endpoints`

Expected: PASS. This test compares the committed files against freshly generated
ones, so it fails if Step 3 was skipped.

- [ ] **Step 6: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 7: Commit**

```bash
git add openapi.json openapi-wallet.json crates/foundry/tests/logging_redaction.rs
git commit -m "test(foundry): regenerate OpenAPI specs and gate display-metadata redaction

Both specs regenerated for the five new members. The redaction test drives a
real DPC offer through the real admin router with distinctive last_four, alias
and art-URL values and asserts none reaches the TRACE-level buffer, with the
span's ..._present field as the positive control."
```

---

## Task 7: End-to-end flow test

**Files:**

- Modify: `crates/foundry/tests/wallet_issuance.rs`

**Interfaces:**

- Consumes: everything from Tasks 1–4.
- Produces: nothing new.

- [ ] **Step 1: Add a DPC credential type to this file's own config**

`crates/foundry/tests/wallet_issuance.rs` has a **local** `setup_test_app()` at
`:20` — it does not use `tests/support/mod.rs`, so a credential type added here
affects no other test file. Add a `com.emvco.dpc.card` entry to its
`credential_types`, with `vct: Some("com.emvco.dpc.card".to_string())`,
`format: "dc+sd-jwt"`, and two required selectively-disclosable claims,
`credential_id` and `network`.

Before editing, confirm nothing asserts on the number of credential types:

```bash
rg -n "credential_types|credential_configurations_supported" crates/foundry/tests/wallet_issuance.rs
```

If an assertion counts them, update that assertion in the same commit.

- [ ] **Step 2: Write the failing test**

Model it on the existing `full_issuance_flow_end_to_end` (`:148`) and its helper
`issue_offer_and_get_access_token` (`:361`). Read both first.

```rust
/// The property the whole branch exists for: display metadata supplied once at
/// offer creation reaches the wallet twice -- on the offer for consent, and on
/// the credential response for rendering -- with the offer-stage and
/// response-stage objects kept distinct.
#[tokio::test]
async fn display_metadata_flows_from_offer_creation_through_to_the_credential_response() {
    let (state, _dir) = setup_test_app().await;

    // 1. Create a DPC offer carrying both display objects, via the admin route.
    //    The offer-stage object is deliberately non-PII; the response-stage one
    //    carries last_four and card_art, which the schema requires.
    //    ... POST /admin/issuance/offers with:
    //        "credential_type_id": "com.emvco.dpc.card",
    //        "claims": { "credential_id": "cred-1", "network": "example_network" },
    //        "offer_display": [{ "locale": "en-US",
    //            "card": { "type": { "code": "CREDIT" } } }],
    //        "credential_response_display": [{ "locale": "en-US",
    //            "card": { "last_four": "4444", "card_art": [
    //                { "theme": "DEFAULT", "image_url": "https://bank.example/card.png" }
    //            ] } }]

    // 2. The offer carries the offer-stage object and NOT the response-stage one.
    assert_eq!(
        offer_response["credential_offer"]["display"][0]["card"]["type"]["code"],
        "CREDIT"
    );
    assert!(
        offer_response["credential_offer"]["display"][0]["card"]
            .get("last_four")
            .is_none(),
        "the offer must not carry the response-stage object: the annex's \
         offer-stage guidance excludes PII-type members"
    );

    // 3. Redeem the pre-authorized code at /token, mint a c_nonce, build a
    //    holder proof, and POST /credential -- exactly as
    //    full_issuance_flow_end_to_end does.

    // 4. The credential response carries the response-stage object.
    assert_eq!(
        credential_response["display"][0]["card"]["last_four"],
        "4444"
    );
    assert_eq!(
        credential_response["display"][0]["card"]["card_art"][0]["theme"],
        "DEFAULT"
    );

    // 5. And the credential itself was still issued.
    assert!(credential_response["credentials"][0]["credential"].is_string());
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p foundry --test wallet_issuance display_metadata_flows`

Expected: FAIL initially on the unknown credential type, then pass once Step 1's config entry is in place and Tasks 1–4 are committed. If it fails at `/credential`, the fault is Task 4's population, not this test.

- [ ] **Step 4: Confirm the existing flow tests still pass**

Run: `cargo test -p foundry --test wallet_issuance`

Expected: PASS, including every pre-existing test in the file. A failure here means the added credential type disturbed a shared assertion — fix the assertion, not the config.

- [ ] **Step 5: Run the scoped gate**

```bash
cargo test -p foundry
cargo clippy -p foundry --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/foundry/tests/wallet_issuance.rs
git commit -m "test(foundry): end-to-end DPC display metadata through offer and credential

Drives one flow: create a DPC offer carrying both display objects, redeem the
pre-authorized code, and assert the offer carries the non-PII offer-stage object
while the credential response carries the schema-required response-stage one."
```

---

## Task 8: Documentation

Docs are a first-class deliverable here, not a postscript: the whole feature is a documented deviation from a pinned specification, and root `AGENTS.md` §4.4 makes an undocumented divergence a defect.

**Files:**

- Modify: `docs/specs/emvco-dpc-schema-framework.md`
- Modify: `docs/conformance/openid4vc-conformance.md`
- Modify: `docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`
- Modify: `AGENTS.md` (root, §4.5)
- Modify: `crates/foundry-issuer/AGENTS.md`
- Modify: `README.md`
- Create: `docs/superpowers/changes/2026-08-13-emvco-dpc-display-metadata.md`

- [ ] **Step 1: Update the spec stub**

In `docs/specs/emvco-dpc-schema-framework.md`:

1. **Move** the display-metadata bullet out of "What foundry does not implement" and into "What foundry implements", restating the `com.emvco.dpc.card.meta` interface facts — member names, JSON types, inclusion requirements — as a table, in the same restated-not-quoted style the existing tables use.
2. **Add a third entry** to "Known contradictions in the reviewed draft":

> 1. **The offer-stage guidance forbids `last_four`, the schema requires it, and
>    the annex's own offer-stage example includes it.** All three appear in A.5.
>    No `card` object can be simultaneously schema-valid and compliant with the
>    offer-stage guidance, so foundry validates each protocol stage against the
>    rule that applies to it: `last_four` and `card_art` are required on a
>    Credential Response and optional on a Credential Offer.

1. **Record the deviations** in a new subsection: unknown members accepted
   despite `additionalProperties: false`; `format` keywords not enforced;
   `display` emitted on two structures OpenID4VCI 1.0 does not define, confined
   to this `vct`.

- [ ] **Step 2: Update the conformance register**

In `docs/conformance/openid4vc-conformance.md`, add a gap entry for the
non-standard `display` member on the Credential Offer and Credential Response.
Follow the existing row format exactly — read three neighbouring `GAP-VCI-*`
rows first and match their columns, severity vocabulary and evidence style. The
evidence must state that the member is `Option` with `skip_serializing_if` and
confined to `DPC_VCT`, so a reader can see the blast radius is one credential
type and zero bytes for all others. Name the covering test.

- [ ] **Step 3: Close the predecessor's open issue**

In `docs/superpowers/specs/2026-08-05-emvco-dpc-credential-type-design.md`:

- In §2.1 ("Why display metadata is excluded"), add a short note at the top:
  **"Superseded 2026-08-13.** The exclusion held for that branch; the work is
  now done. Each of the three objections below is answered in §2 of
  [`2026-08-13-emvco-dpc-display-metadata-design.md`](2026-08-13-emvco-dpc-display-metadata-design.md).
  The reasoning is kept because it records *why* it needed its own cycle."
- In §8, mark open issue **2** closed with a pointer to the new design. Leave
  issues 1, 3, 4, 5, 6 and 7 exactly as they are — none is affected.

Do **not** delete the original reasoning. It is the record of a decision, and
the new design argues against it explicitly.

- [ ] **Step 4: Extend the root never-logged list**

In `AGENTS.md` §4.5, in the sentence beginning "**Never logged, at any level,
under any flag:**", add to the list:

```text
the EMVCo DPC display metadata objects (`card.last_four`, `card.alias`, and
card-art URLs, which may be personalised)
```

Keep the existing entries and their order untouched — that list is read as a
checklist, and reordering it makes review diffs lie.

- [ ] **Step 5: Update the issuer crate's module map and gotchas**

In `crates/foundry-issuer/AGENTS.md`:

- Add a **Module Map** row, in the table's existing style:

```text
| `display_metadata.rs` | Structural validation of EMVCo DPC display metadata (`com.emvco.dpc.card.meta`): `DisplayStage` (`Offer` \| `CredentialResponse`) and `validate_display`. Open-world — unknown members pass; `last_four`/`card_art` required only at the response stage |
```

- Add a **Gotchas** entry, because this is exactly the class of surprise that
  section exists for:

```text
- **`CredentialOffer.display` and `CredentialResponse.display` are not
  OpenID4VCI members.** They carry EMVCo DPC display metadata per Schema
  Framework A.5's non-normative transport proposal, and `create_offer` rejects
  them for any credential type whose `vct` is not `DPC_VCT`
  (`com.emvco.dpc.card`). Both are `Option` with `skip_serializing_if`, so every
  other credential type's wire output is unchanged byte-for-byte. Deviation
  recorded in `docs/specs/emvco-dpc-schema-framework.md`; design in
  `docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md`.
- **The offer-stage and response-stage objects follow different rules.**
  `last_four` and `card_art` are required on a Credential Response and optional
  on a Credential Offer. This is not an oversight: the governing annex's schema
  marks both required while its own offer-stage guidance forbids `last_four` as
  PII. Two request fields exist so the compliant split is expressible.
```

- [ ] **Step 6: Update the README**

Two edits, both in places confirmed to exist:

1. Under **"Example: Creating an Offer via Admin API"**, add a second `curl`
   example — a DPC offer carrying both display objects. Show the non-PII
   offer-stage object and the full response-stage object, so the split is
   visible. Add one sentence naming the constraint: display metadata is accepted
   only for a credential type whose `vct` is `com.emvco.dpc.card`.
2. In the **Admin Test Console** section's "Issuance" bullet, add that the card
   has an optional collapsed "DPC display metadata" disclosure with two JSON
   textareas, and that they are empty by default.

Do not add a new top-level README section; these belong where the reader already
is.

- [ ] **Step 7: Write the change record**

Create `docs/superpowers/changes/2026-08-13-emvco-dpc-display-metadata.md`
following the format of the existing records in that directory — read
`docs/superpowers/changes/2026-08-05-emvco-dpc-credential-type.md` first and
match it. Cover: what changed, the five design decisions and why, the three
divergences from A.5.1, the spec correction to §3.7 and the defect it prevented,
and what remains open.

- [ ] **Step 8: Verify every doc claim is true**

Docs are the deliverable here, so check them the way you would check code:

```bash
# Every path and anchor the new docs reference must exist.
rg -o '\[[^]]+\]\(([^)]+)\)' -r '$1' docs/superpowers/changes/2026-08-13-emvco-dpc-display-metadata.md
# The stub must no longer list display metadata as unimplemented.
rg -n "display-metadata schema" docs/specs/emvco-dpc-schema-framework.md
# The never-logged list must mention it.
rg -n "last_four" AGENTS.md
```

Expected: no reference to a nonexistent file; the stub's "does not implement"
section no longer mentions display metadata; §4.5 names it.

- [ ] **Step 9: Run the scoped gate**

```bash
cargo test -p foundry --test conformance_report
cargo fmt --check
```

`conformance_report` parses `docs/conformance/openid4vc-conformance.md`, so a
malformed row added in Step 2 fails here rather than silently. If that test does
not exist under that name, run `cargo test -p foundry` and note which test
covers the report.

- [ ] **Step 10: Commit**

```bash
git add docs/ AGENTS.md README.md crates/foundry-issuer/AGENTS.md
git commit -m "docs: record the DPC display-metadata deviation and close the open issue

Spec stub moves display metadata to implemented, gains the third contradiction
(the annex forbids, requires and demonstrates last_four at the offer stage) and
records three divergences: unknown members accepted despite
additionalProperties:false, format keywords unenforced, and a display member on
two structures OpenID4VCI 1.0 does not define.

Also: conformance rows, root AGENTS.md never-logged list, issuer module map and
gotchas, README examples, and open issue 2 of the predecessor design closed."
```

---

## Final Gate (once, after Task 8)

This is the **only** point in this plan where the full gate of root `AGENTS.md`
§5.3 runs. Per §5.6, capture to disk and grep — a bare `tail` of a
full-workspace run can silently drop an earlier binary's `FAILED` off the top.

```bash
cargo fmt
cargo fmt --check
cargo test --workspace 2>&1 | tee /tmp/foundry-full-gate.log
grep -c "FAILED" /tmp/foundry-full-gate.log        # expect 0 / no output
grep "^test result:" /tmp/foundry-full-gate.log    # one short line per binary
cargo test -p foundry --test e2e_full_flow -- --ignored
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee /tmp/foundry-clippy.log
grep -c "^error" /tmp/foundry-clippy.log           # expect 0 / no output
```

Report the gate by name and paste the `test result:` lines. Do not claim green
without them (§5.5).

---

## Self-Review

Run against the spec after the plan is written; recorded here so a reviewer can
check the same things.

**1. Spec coverage.** Every spec section maps to a task:

| Spec section | Task |
| --- | --- |
| §3.1 Wire model | 2 |
| §3.2 Persistence | 2 |
| §3.3 Admin API (two fields, no auto-strip) | 3 |
| §3.4 Validation (enforced, stage-dependent, not-enforced) | 1 |
| §3.5 Gating on `DPC_VCT` | 3 |
| §3.6 Flow ordering; no re-validation at `/credential` | 3, 4 |
| §3.7 Console (empty textareas, `opt-disclosure`) | 5 |
| §3.8 Observability (`..._present`, never-logged list) | 3, 6, 8 |
| §5 Files touched | all; `openapi.rs` correctly absent |
| §6 Testing (full assertion list) | 1, 2, 3, 4, 7 |
| §4 What this design does not do | no task — correct, these are non-goals |

Two spec test requirements deserve naming because they are easy to satisfy
weakly:

- "asserted on the serialised JSON object's keys, not a deserialized `Option`" —
  Task 2 Step 1 and Task 3 Step 1 both do this explicitly.
- "the same assertion for `dc_api_offer`, and its converse" — Task 2 Step 1
  (with the documented fallback to Task 3) and Task 3 Step 1.

**2. Placeholder scan.** No `TBD`, no "add error handling", no "write tests for
the above". Three tasks intentionally say *read the neighbouring code first*
rather than reproducing an 80-line harness — Task 4 Step 1, Task 6 Step 1, Task 7
Step 2. Each names the exact `rg` command and the exact assertions to add, so the
judgement left to the implementer is "match the existing setup", not "invent the
test". That is a deliberate trade, not a placeholder.

**3. Type consistency.** Checked across tasks:

- `DisplayStage::Offer` / `DisplayStage::CredentialResponse` — same spelling in
  Tasks 1 and 3.
- `validate_display(&[Value], DisplayStage)` — same signature in Task 1's
  definition and Task 3's two call sites (`as_deref()` yields `&[Value]`).
- `offer_display` / `credential_response_display` — the approved names, used
  identically in Tasks 3, 5, 6, 7 and in both OpenAPI specs.
- `IssuanceTransaction.credential_response_display` — same name as the request
  field, deliberately, so the hop from request to storage to response reads
  without translation.
- `CredentialOffer.display` / `CredentialResponse.display` — the wire name from
  the governing document, distinct from the request-field names because the
  request needs to distinguish two objects the wire does not.
- DOM ids `offer-display-json` / `credential-response-display-json` — asserted in
  Task 5's test with exactly the strings the markup uses.

**4. Ordering dependency.** Task 6's redaction test has a positive control on
Task 3's span field, so it can only pass after Task 3. Task 7 depends on Tasks
1–4. Both are stated in-task. Tasks 1→2→3→4 are strictly sequential; 5, 6 and 8
depend on 3 but not on each other.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-08-13-emvco-dpc-display-metadata-plan.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using `executing-plans`, batch execution with checkpoints.

**Which approach?**

Suggested agent mapping if you pick subagent-driven (per root `AGENTS.md` §7):

| Task | Agent | Why |
| --- | --- | --- |
| 1 | `mechanical-implementer` | one new file, complete spec, code given verbatim |
| 2 | `integration-implementer` | six files, compiler-driven literal sweep |
| 3 | `integration-implementer` | ordering matters; 13 existing literals to fix |
| 4 | `mechanical-implementer` | one line plus tests modelled on an existing harness |
| 5 | `integration-implementer` | HTML + JS with a variable-shadowing hazard |
| 6 | `mechanical-implementer` | regenerate, inspect diff, one test |
| 7 | `integration-implementer` | full flow test against an existing harness |
| 8 | `integration-implementer` | seven files, cross-referenced claims |

Per-task review by `task-reviewer`; one `final-reviewer` pass over the whole
branch at the end, which is also where the Final Gate above runs.
