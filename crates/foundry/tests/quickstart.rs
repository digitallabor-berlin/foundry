use foundry::commands;
use foundry_core::config::Config;
use foundry_verifier::{check_dcql_match, PresentedFormat};

/// Assert every `named_queries[].dcql` in a config is parseable DCQL.
///
/// The scaffold in `commands::quickstart` is the only tracked source of this
/// config — the repository's own `config.yaml` is gitignored and generated — so
/// guarding the scaffold is what stops the defect from shipping again.
///
/// `check_dcql_match` is the only public route to the DCQL model (`dcql_model` is
/// private), and it reports an unparseable query as a failed check whose detail
/// contains "not a valid DCQL query". Any *other* failure detail is fine here —
/// we are asserting parseability, not that empty claims satisfy the query.
fn assert_named_queries_are_valid_dcql(cfg: &Config, source: &str) {
    for nq in &cfg.verifier.named_queries {
        let id = nq.get("id").and_then(|v| v.as_str()).unwrap_or("<unnamed>");
        let dcql = nq
            .get("dcql")
            .or_else(|| nq.get("dcql_query"))
            .unwrap_or(nq);
        let detail = check_dcql_match(
            dcql,
            "unused-answered-id",
            PresentedFormat::SdJwtVc,
            &serde_json::json!({}),
            None,
        )
        .detail
        .unwrap_or_default();
        assert!(
            !detail.contains("not a valid DCQL query"),
            "{source}: named query '{id}' is not valid DCQL: {detail}"
        );
    }
}

#[test]
fn quickstart_emits_valid_pki_and_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.yaml");
    commands::quickstart(dir.path(), &cfg_path).unwrap();

    // Files exist.
    for rel in [
        "trust/root.pem",
        "keys/issuer_sdjwt.pem",
        "keys/issuer_sdjwt-chain.pem",
        "keys/verifier_signing.pem",
        "keys/verifier_signing-chain.pem",
        "keys/statuslist_signer.pem",
        "keys/statuslist_signer-chain.pem",
    ] {
        assert!(dir.path().join(rel).exists(), "missing {rel}");
    }

    // Config parses and passes structural validation.
    let cfg = Config::load(&cfg_path).unwrap();
    cfg.validate().unwrap();

    // Key material resolves relative to the config directory (Task 10 API).
    cfg.validate_key_material(dir.path()).unwrap();

    // The scaffold once shipped `dcql: { credentials: [] }`, which is a DCQL parse
    // error. `Config::validate` does not look inside named queries, so nothing
    // caught it until an operator referenced the query.
    assert_named_queries_are_valid_dcql(&cfg, "quickstart scaffold");
}
