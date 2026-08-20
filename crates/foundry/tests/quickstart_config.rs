//! The config `foundry quickstart` generates must load, validate, and carry the
//! credential types the documentation promises.
//!
//! Guards `QUICKSTART_CONFIG` in `commands.rs` against edits that make it
//! unparseable, fail validation, or silently drop a credential type. The
//! template is a `const &str`, so nothing else in the suite would notice.

use foundry_core::config::Config;

/// Generate a real quickstart tree in a temp dir and load the config it wrote.
///
/// Goes through `commands::quickstart` rather than parsing the template
/// directly, so the generated PKI paths are exercised too — a config that
/// references a key the generator does not produce would pass a bare parse and
/// fail here.
fn quickstart_config() -> Config {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("config.yaml");
    foundry::commands::quickstart(dir.path(), &config_path).expect("quickstart succeeds");
    let cfg = Config::load(&config_path).expect("generated config parses and validates");
    // The loaded config holds paths into `dir`; keep it alive for the caller.
    std::mem::forget(dir);
    cfg
}

#[test]
fn quickstart_config_carries_all_credential_types() {
    let cfg = quickstart_config();
    let ids: Vec<&str> = cfg
        .credential_types
        .iter()
        .map(|ct| ct.id.as_str())
        .collect();
    assert!(ids.contains(&"pid"), "expected pid, got {ids:?}");
    assert!(
        ids.contains(&"com.emvco.dpc.card"),
        "expected com.emvco.dpc.card, got {ids:?}"
    );
    assert!(
        ids.contains(&"eu.europa.ec.av.1"),
        "expected eu.europa.ec.av.1, got {ids:?}"
    );
}

/// The Proof of Age type's shape is the whole point of shipping it: an mdoc
/// identified by `doctype` with no `vct`, and exactly the two attributes EU Age
/// Verification Annex A §4.1.2 admits — `age_over_18` mandatory, one optional
/// `age_over_NN`.
#[test]
fn quickstart_av_type_has_the_expected_shape() {
    let cfg = quickstart_config();
    let av = cfg
        .credential_types
        .iter()
        .find(|ct| ct.id == "eu.europa.ec.av.1")
        .expect("av type present");

    assert_eq!(av.format, "mso_mdoc");
    assert_eq!(av.doctype.as_deref(), Some("eu.europa.ec.av.1"));
    assert_eq!(
        av.vct, None,
        "an mdoc is identified by doctype; vct is rejected at load (OpenID4VCI L2235)"
    );
    assert!(av.cryptographic_holder_binding);
    assert_eq!(av.resolved_validity_seconds(), 7_776_000);

    let names: Vec<&str> = av.claims.iter().map(|c| c.path[0].as_str()).collect();
    assert_eq!(names, vec!["age_over_18", "age_over_16"]);

    let age_over_18 = av
        .claims
        .iter()
        .find(|c| c.path == vec!["age_over_18".to_string()])
        .expect("age_over_18 declared");
    assert!(
        age_over_18.is_required(),
        "Annex A §4.1.2 records age_over_18 as Mandatory in issuance"
    );
}

/// The DPC type's shape is the whole point of shipping it: three claims, two of
/// which are mandatory *and* selectively disclosable, and a 12-hour lifetime.
#[test]
fn quickstart_dpc_type_has_the_expected_shape() {
    let cfg = quickstart_config();
    let dpc = cfg
        .credential_types
        .iter()
        .find(|ct| ct.id == "com.emvco.dpc.card")
        .expect("dpc type present");

    assert_eq!(dpc.format, "dc+sd-jwt");
    assert_eq!(dpc.vct.as_deref(), Some("com.emvco.dpc.card"));
    assert!(dpc.cryptographic_holder_binding);
    assert_eq!(dpc.resolved_validity_seconds(), 43_200);

    let claim = |name: &str| {
        dpc.claims
            .iter()
            .find(|c| c.path == vec![name.to_string()])
            .unwrap_or_else(|| panic!("claim {name} present"))
    };

    // credential_id and network are mandatory in the DPC payload schema and
    // selectively disclosable in the SD-JWT — the combination that `required`
    // exists to express.
    for name in ["credential_id", "network"] {
        let c = claim(name);
        assert!(c.is_required(), "{name} must be required");
        assert!(
            c.selectively_disclosable,
            "{name} must be selectively disclosable"
        );
    }

    let card_id = claim("card_id");
    assert!(!card_id.is_required(), "card_id is optional");
    assert!(card_id.selectively_disclosable);
}

/// Multi-locale display metadata, both on the credential configuration and on
/// each claim.
#[test]
fn quickstart_dpc_type_has_multiple_display_locales() {
    let cfg = quickstart_config();
    let dpc = cfg
        .credential_types
        .iter()
        .find(|ct| ct.id == "com.emvco.dpc.card")
        .expect("dpc type present");

    let locales: Vec<&str> = dpc
        .display
        .iter()
        .filter_map(|d| d.get("locale").and_then(|l| l.as_str()))
        .collect();
    for expected in ["en-US", "de-DE", "fr-FR"] {
        assert!(
            locales.contains(&expected),
            "expected credential-configuration locale {expected}, got {locales:?}"
        );
    }

    for claim in &dpc.claims {
        let claim_locales: Vec<&str> = claim
            .display
            .iter()
            .filter_map(|d| d.get("locale").and_then(|l| l.as_str()))
            .collect();
        assert!(
            claim_locales.contains(&"en-US") && claim_locales.contains(&"de-DE"),
            "claim {:?} must carry at least en-US and de-DE display entries, got {claim_locales:?}",
            claim.path
        );
    }
}
