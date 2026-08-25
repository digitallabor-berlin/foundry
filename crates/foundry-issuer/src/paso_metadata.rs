//! PaSO Proof Metadata — the Attestation Provider's published metadata.
//!
//! Two artifacts, both minted per request and never stored:
//!
//! * the **signed credential metadata JWT** (§4, `credential-metadata+jwt`),
//!   served from `credential_metadata_uri`, carrying the credential's
//!   `transaction_data_types`;
//! * the **ad-hoc transaction data metadata JWT** (§5.2,
//!   `adhoc-transaction-metadata+jwt`), minted on an operator's request for a
//!   Relying Party to embed in a `transaction_data` entry's `metadata`
//!   parameter (§5.1).
//!
//! Statelessness is deliberate. §4 requires the Attestation Provider to
//! "rotate signed credential metadata JWTs before their `exp` time"; minting
//! per request satisfies that by construction, with no cache to expire and no
//! rotation task to fail. It matches how every other issuer-minted artifact in
//! this crate works (`challenge.rs`).
//!
//! **Unimplemented optional path:** §4 and §5.2 allow the signing key to be
//! identified by `kid` against a published issuer key set instead of `x5c`.
//! foundry's issuer keys are x5c-published, so it takes the `x5c` branch only,
//! and `Config::validate()` refuses to boot a PaSO deployment whose credential
//! signing key has no chain.

use crate::error::IssuanceError;
use foundry_core::config::{Config, CredentialType, TransactionDataTypeMetadata};
use foundry_core::crypto::FileSigner;
use serde_json::{Map, Value};

/// PaSO Proof Metadata §4 — `typ` of the signed credential metadata JWT.
pub const CREDENTIAL_METADATA_TYP: &str = "credential-metadata+jwt";
/// PaSO Proof Metadata §5.2 — `typ` of the ad-hoc metadata JWT.
pub const ADHOC_METADATA_TYP: &str = "adhoc-transaction-metadata+jwt";

/// A credential type is a PaSO Credential type exactly when it declares
/// `transaction_data_types` (PaSO Proof Metadata §3).
pub fn is_paso_credential_type(ct: &CredentialType) -> bool {
    ct.transaction_data_types.is_some()
}

/// PaSO Proof Metadata §2 — the URL serving this configuration's credential
/// metadata.
///
/// Built from `issuer.credential_issuer`, the same base `build_issuer_metadata`
/// uses for `credential_endpoint` and `nonce_endpoint`. §8 makes the value
/// load-bearing: the Wallet compares the `credential_metadata_uri` claim
/// against the URI it fetched from and rejects a mismatch. This function is the
/// single owner of the string, so the advertised value and the JWT claim cannot
/// drift apart.
pub fn credential_metadata_uri(cfg: &Config, credential_type_id: &str) -> String {
    let base = cfg.issuer.credential_issuer.trim_end_matches('/');
    format!("{base}/credential-metadata/{credential_type_id}")
}

/// The credential type identifier a Wallet binds `sub` against (PaSO Proof
/// Metadata §4, §7 step 6): `vct` for SD-JWT VC, `docType` for mdoc.
///
/// `Config::validate()` already guarantees the relevant field is present for
/// each supported format, so these error arms are unreachable in a booted
/// process — typed rather than `unwrap` per root AGENTS.md §4.1.
fn credential_type_identifier(ct: &CredentialType) -> Result<&str, IssuanceError> {
    match ct.format.as_str() {
        "dc+sd-jwt" => ct.vct.as_deref().ok_or_else(|| {
            IssuanceError::InvalidRequest(format!(
                "credential type '{}' (dc+sd-jwt) has no vct",
                ct.id
            ))
        }),
        "mso_mdoc" => ct.doctype.as_deref().ok_or_else(|| {
            IssuanceError::InvalidRequest(format!(
                "credential type '{}' (mso_mdoc) has no doctype",
                ct.id
            ))
        }),
        other => Err(IssuanceError::InvalidRequest(format!(
            "credential type '{}' has unsupported format '{other}'",
            ct.id
        ))),
    }
}

/// The credential signing key and its certificate chain as `x5c`.
///
/// Same resolution as `credential.rs::handle_credential_request`, so the JWT's
/// chain **is** the credential's chain and §7 step 6's credential binding (same
/// root CA, same leaf Subject) holds by construction rather than by
/// convention.
fn signer_and_chain(cfg: &Config) -> Result<(FileSigner, Vec<String>), IssuanceError> {
    let (name, key) = cfg.credential_signing_key().ok_or_else(|| {
        IssuanceError::InvalidRequest("no credential signing key configured".to_string())
    })?;
    let signer = FileSigner::from_pem_file(&key.private_key, key.alg.parse()?)?;
    let path = key.x5c.as_ref().ok_or_else(|| {
        IssuanceError::InvalidRequest(format!(
            "credential signing key '{name}' has no x5c chain; PaSO Proof Metadata §4 requires one"
        ))
    })?;
    let pem = std::fs::read(path).map_err(|e| {
        IssuanceError::InvalidRequest(format!("failed to read x5c file '{path}': {e}"))
    })?;
    let chain = foundry_core::trust::build_x5c(&[pem])?;
    Ok((signer, chain))
}

/// PaSO Proof Metadata §2 / §3 — the `credential_metadata` object: OpenID4VCI's
/// display and claims, extended with `transaction_data_types`.
///
/// Served verbatim for `Accept: application/json` (§2) and nested under the
/// `credential_metadata` claim for `Accept: application/jwt` (§4), so the
/// signed and unsigned representations can never disagree.
pub fn build_credential_metadata_document(ct: &CredentialType) -> Result<Value, IssuanceError> {
    let mut doc = Map::new();
    if !ct.display.is_empty() {
        doc.insert("display".to_string(), serde_json::json!(ct.display));
    }
    let claims = crate::metadata::claims_description_objects(ct);
    if !claims.is_empty() {
        doc.insert("claims".to_string(), serde_json::json!(claims));
    }
    if let Some(types) = &ct.transaction_data_types {
        let value =
            serde_json::to_value(types).map_err(|e| IssuanceError::Serialization(e.to_string()))?;
        doc.insert("transaction_data_types".to_string(), value);
    }
    Ok(Value::Object(doc))
}

/// PaSO Proof Metadata §4 — the signed credential metadata JWT.
#[tracing::instrument(skip_all, fields(credential_type_id = %ct.id))]
pub fn build_credential_metadata_jwt(
    cfg: &Config,
    ct: &CredentialType,
    now_unix: i64,
) -> Result<String, IssuanceError> {
    let (signer, chain) = signer_and_chain(cfg)?;
    let uri = credential_metadata_uri(cfg, &ct.id);

    // §4: `typ` and `x5c`. `alg` is supplied by `sign_compact` from the signing
    // key, so the header cannot claim an algorithm the key does not use.
    let mut header = Map::new();
    header.insert(
        "typ".to_string(),
        Value::String(CREDENTIAL_METADATA_TYP.to_string()),
    );
    header.insert("x5c".to_string(), serde_json::json!(chain));

    let ttl = cfg.issuer.paso_metadata.ttl_secs as i64;
    let mut payload = Map::new();
    payload.insert(
        "iss".to_string(),
        Value::String(
            cfg.issuer
                .credential_issuer
                .trim_end_matches('/')
                .to_string(),
        ),
    );
    payload.insert(
        "sub".to_string(),
        Value::String(credential_type_identifier(ct)?.to_string()),
    );
    payload.insert("format".to_string(), Value::String(ct.format.clone()));
    payload.insert("iat".to_string(), serde_json::json!(now_unix));
    payload.insert("exp".to_string(), serde_json::json!(now_unix + ttl));
    // §8: the Wallet verifies this equals the URI it fetched from.
    payload.insert("credential_metadata_uri".to_string(), Value::String(uri));
    payload.insert(
        "credential_metadata".to_string(),
        build_credential_metadata_document(ct)?,
    );

    Ok(foundry_core::crypto::jws::sign_compact(
        &header,
        &Value::Object(payload),
        &signer,
    )?)
}

/// PaSO Proof Metadata §5.2 — the ad-hoc transaction data metadata JWT.
///
/// `override_metadata`, when present, replaces the configured
/// `transaction_data_types` entry for this one artifact. That is the whole
/// point of the ad-hoc channel (§1.1: "transaction-specific or updated metadata
/// without rotating the signed credential metadata JWT"), and §5.4 makes a type
/// covered by a valid ad-hoc JWT "considered supported ... even if it is absent
/// from the signed credential metadata" — so an override may legitimately name
/// a type this issuer has not configured.
///
/// An override is held to exactly the config-time structural rules; a channel
/// that accepted shapes the config channel rejects would make validation
/// advisory.
#[tracing::instrument(
    skip_all,
    fields(
        credential_type_id = %ct.id,
        transaction_data_type = %transaction_data_type,
        override_supplied = override_metadata.is_some(),
    )
)]
pub fn build_adhoc_metadata_jwt(
    cfg: &Config,
    ct: &CredentialType,
    transaction_data_type: &str,
    override_metadata: Option<Value>,
    now_unix: i64,
    ttl_secs: Option<u64>,
) -> Result<String, IssuanceError> {
    let metadata: Value = match override_metadata {
        Some(v) => {
            let parsed: TransactionDataTypeMetadata =
                serde_json::from_value(v.clone()).map_err(|e| {
                    IssuanceError::InvalidRequest(format!("metadata override is malformed: {e}"))
                })?;
            foundry_core::config::validate_paso_transaction_data_type_metadata(
                transaction_data_type,
                &parsed,
            )
            .map_err(IssuanceError::InvalidRequest)?;
            v
        }
        None => {
            let configured = ct
                .transaction_data_types
                .as_ref()
                .and_then(|m| m.get(transaction_data_type))
                .ok_or_else(|| {
                    IssuanceError::InvalidRequest(format!(
                        "credential type '{}' does not declare transaction data type '{}', and no \
                         metadata override was supplied",
                        ct.id, transaction_data_type
                    ))
                })?;
            serde_json::to_value(configured)
                .map_err(|e| IssuanceError::Serialization(e.to_string()))?
        }
    };

    let (signer, chain) = signer_and_chain(cfg)?;

    let mut header = Map::new();
    header.insert(
        "typ".to_string(),
        Value::String(ADHOC_METADATA_TYP.to_string()),
    );
    header.insert("x5c".to_string(), serde_json::json!(chain));

    let ttl = ttl_secs.unwrap_or(cfg.issuer.paso_metadata.adhoc_ttl_secs) as i64;
    let mut payload = Map::new();
    payload.insert(
        "iss".to_string(),
        Value::String(
            cfg.issuer
                .credential_issuer
                .trim_end_matches('/')
                .to_string(),
        ),
    );
    payload.insert(
        "sub".to_string(),
        Value::String(credential_type_identifier(ct)?.to_string()),
    );
    payload.insert("format".to_string(), Value::String(ct.format.clone()));
    payload.insert("iat".to_string(), serde_json::json!(now_unix));
    payload.insert("exp".to_string(), serde_json::json!(now_unix + ttl));
    // §5.2: SHALL equal the `type` of the enclosing transaction_data entry.
    payload.insert(
        "transaction_data_type".to_string(),
        Value::String(transaction_data_type.to_string()),
    );
    payload.insert("metadata".to_string(), metadata);

    Ok(foundry_core::crypto::jws::sign_compact(
        &header,
        &Value::Object(payload),
        &signer,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use serde_json::{Value, json};

    /// A `Config` with a real ES256 signing key and an `x5c` chain on disk.
    fn paso_config() -> Config {
        let mut cfg = crate::metadata::tests::test_config();

        let ca = foundry_core::pki::new_ca("Foundry Test Issuer Root", 3650).expect("ca");
        let leaf = foundry_core::pki::issue_leaf(
            &ca.cert_pem,
            &ca.key_pem,
            "issuer.example.com",
            &["issuer.example.com".to_string()],
            365,
        )
        .expect("leaf");

        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("issuer.pem");
        let chain_path = dir.path().join("issuer-chain.pem");
        std::fs::write(&key_path, leaf.key_pem.as_bytes()).expect("write key");
        std::fs::write(&chain_path, leaf.cert_pem.as_bytes()).expect("write chain");
        std::mem::forget(dir);

        cfg.keys.insert(
            "issuer_key".to_string(),
            foundry_core::config::KeyEntry {
                private_key: key_path.to_string_lossy().to_string(),
                x5c: Some(chain_path.to_string_lossy().to_string()),
                alg: "ES256".to_string(),
            },
        );
        cfg.issuer.status_list.signing_key = Some("issuer_key".to_string());
        cfg
    }

    fn paso_credential_type() -> CredentialType {
        let types = serde_json::from_value(json!({
            "urn:paso:sca:global:payment:1": {
                "claims": [
                    { "path": ["transaction_id"], "mandatory": true },
                    {
                        "path": ["amount"],
                        "mandatory": true,
                        "value_type": "iso_currency_amount",
                        "display": [
                            { "locale": "en", "name": "Amount" },
                            { "locale": "de", "name": "Betrag" }
                        ]
                    }
                ],
                "ui_labels": {
                    "affirmative_action_label": [
                        { "locale": "en", "value": "Confirm Payment" }
                    ]
                }
            }
        }))
        .expect("transaction_data_types fixture");

        CredentialType {
            id: "BankPaymentCard".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some("https://bank.example/sca/card".to_string()),
            doctype: None,
            scope: None,
            cryptographic_holder_binding: true,
            display: Vec::new(),
            claims: Vec::new(),
            validity_seconds: None,
            transaction_data_types: Some(types),
        }
    }

    fn decode_part(jwt: &str, index: usize) -> Value {
        let part = jwt.split('.').nth(index).expect("segment");
        serde_json::from_slice(&B64URL.decode(part).expect("b64url")).expect("json")
    }

    #[test]
    fn a_type_declaring_transaction_data_types_is_a_paso_type() {
        assert!(is_paso_credential_type(&paso_credential_type()));

        let mut plain = paso_credential_type();
        plain.transaction_data_types = None;
        assert!(!is_paso_credential_type(&plain));
    }

    /// PaSO Proof Metadata §8 makes the `credential_metadata_uri` claim
    /// load-bearing: the Wallet checks it against the URI it fetched from. It
    /// must therefore use the same base as every sibling issuer endpoint.
    #[test]
    fn the_metadata_uri_uses_the_credential_issuer_base() {
        let cfg = paso_config();
        assert_eq!(
            credential_metadata_uri(&cfg, "BankPaymentCard"),
            "https://issuer.example.com/credential-metadata/BankPaymentCard"
        );
    }

    /// PaSO Proof Metadata §4 — header and every REQUIRED payload claim.
    #[test]
    fn the_credential_metadata_jwt_carries_the_required_claims() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let jwt = build_credential_metadata_jwt(&cfg, &ct, now).expect("build");

        let header = decode_part(&jwt, 0);
        assert_eq!(header["typ"], json!(CREDENTIAL_METADATA_TYP));
        assert_eq!(header["alg"], json!("ES256"));
        assert!(
            header["x5c"].as_array().is_some_and(|c| !c.is_empty()),
            "§4: x5c is REQUIRED when the issuer keys are x5c-published"
        );
        assert!(
            header.get("kid").is_none(),
            "§4: when x5c is used, kid SHALL NOT be"
        );

        let payload = decode_part(&jwt, 1);
        assert_eq!(payload["iss"], json!("https://issuer.example.com"));
        assert_eq!(payload["sub"], json!("https://bank.example/sca/card"));
        assert_eq!(payload["format"], json!("dc+sd-jwt"));
        assert_eq!(payload["iat"], json!(now));
        assert_eq!(payload["exp"], json!(now + 86_400));
        assert_eq!(
            payload["credential_metadata_uri"],
            json!("https://issuer.example.com/credential-metadata/BankPaymentCard")
        );
        assert!(
            payload["credential_metadata"]["transaction_data_types"]
                ["urn:paso:sca:global:payment:1"]["claims"]
                .is_array()
        );
    }

    /// §2 serves the bare object; §4 nests the same object under
    /// `credential_metadata`. They can never disagree.
    #[test]
    fn the_json_document_and_the_jwt_claim_are_identical() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let doc = build_credential_metadata_document(&ct).expect("document");
        let jwt = build_credential_metadata_jwt(&cfg, &ct, 1_710_000_000).expect("build");

        assert_eq!(decode_part(&jwt, 1)["credential_metadata"], doc);
    }

    /// §4 / §7 step 6: `sub` is `vct` for SD-JWT VC, `docType` for mdoc.
    #[test]
    fn an_mdoc_paso_type_uses_doctype_as_sub() {
        let cfg = paso_config();
        let mut ct = paso_credential_type();
        ct.format = "mso_mdoc".to_string();
        ct.vct = None;
        ct.doctype = Some("com.example.bank.paymentcard.1".to_string());

        let payload = decode_part(
            &build_credential_metadata_jwt(&cfg, &ct, 1_710_000_000).expect("build"),
            1,
        );
        assert_eq!(payload["sub"], json!("com.example.bank.paymentcard.1"));
        assert_eq!(payload["format"], json!("mso_mdoc"));
    }

    /// The configured TTL drives `exp`.
    #[test]
    fn the_configured_ttl_drives_the_credential_metadata_exp() {
        let mut cfg = paso_config();
        cfg.issuer.paso_metadata.ttl_secs = 3_600;
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let payload = decode_part(
            &build_credential_metadata_jwt(&cfg, &ct, now).expect("build"),
            1,
        );
        assert_eq!(payload["exp"], json!(now + 3_600));
    }

    /// PaSO Proof Metadata §5.2 — the ad-hoc JWT's own shape.
    #[test]
    fn the_adhoc_jwt_carries_the_configured_metadata_by_default() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let jwt =
            build_adhoc_metadata_jwt(&cfg, &ct, "urn:paso:sca:global:payment:1", None, now, None)
                .expect("build");

        assert_eq!(decode_part(&jwt, 0)["typ"], json!(ADHOC_METADATA_TYP));

        let payload = decode_part(&jwt, 1);
        assert_eq!(
            payload["transaction_data_type"],
            json!("urn:paso:sca:global:payment:1")
        );
        assert_eq!(payload["exp"], json!(now + 300));
        assert_eq!(payload["sub"], json!("https://bank.example/sca/card"));
        // `metadata` is a single `transaction_data_types` entry value, not the
        // whole map.
        assert!(payload["metadata"]["claims"].is_array());
        assert!(payload["metadata"]["ui_labels"].is_object());
        assert!(payload["metadata"]["urn:paso:sca:global:payment:1"].is_null());
    }

    /// §5.4: a valid ad-hoc JWT makes the type "considered supported ... even
    /// if it is absent from the signed credential metadata". An override for an
    /// unconfigured type is therefore legitimate, not an error.
    #[test]
    fn an_override_may_introduce_a_type_absent_from_config() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let override_meta = json!({
            "claims": [{ "path": ["reward_points"], "display": [{ "name": "Points" }] }]
        });

        let jwt = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:com.example.pay:transaction:2",
            Some(override_meta.clone()),
            1_710_000_000,
            None,
        )
        .expect("build");

        let payload = decode_part(&jwt, 1);
        assert_eq!(
            payload["transaction_data_type"],
            json!("urn:paso:sca:com.example.pay:transaction:2")
        );
        assert_eq!(payload["metadata"], override_meta);
    }

    #[test]
    fn an_unconfigured_type_without_an_override_is_rejected() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let err = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:global:unknown:1",
            None,
            1_710_000_000,
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// An override is held to exactly the config-time rules — here §3.1's
    /// "`value_type` MUST NOT be used on claims without a `display` array".
    #[test]
    fn a_structurally_invalid_override_is_rejected() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let err = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:global:payment:1",
            Some(json!({
                "claims": [{ "path": ["amount"], "value_type": "iso_currency_amount" }]
            })),
            1_710_000_000,
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    /// An override naming a type identifier that violates PaSO Core §5.2 is
    /// rejected too — the identifier is validated, not just the body.
    #[test]
    fn an_override_with_a_malformed_type_identifier_is_rejected() {
        let cfg = paso_config();
        let ct = paso_credential_type();

        let err = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:example:not-paso:1",
            Some(json!({ "claims": [{ "path": ["a"] }] })),
            1_710_000_000,
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, IssuanceError::InvalidRequest(_)));
    }

    #[test]
    fn an_explicit_ttl_overrides_the_configured_default() {
        let cfg = paso_config();
        let ct = paso_credential_type();
        let now = 1_710_000_000;

        let jwt = build_adhoc_metadata_jwt(
            &cfg,
            &ct,
            "urn:paso:sca:global:payment:1",
            None,
            now,
            Some(60),
        )
        .expect("build");
        assert_eq!(decode_part(&jwt, 1)["exp"], json!(now + 60));
    }

    /// A credential type with no PaSO types still produces a well-formed
    /// document — it simply carries no `transaction_data_types`. (The route in
    /// Task 7 never serves this case, but the builder must not panic on it.)
    #[test]
    fn a_non_paso_type_yields_a_document_without_transaction_data_types() {
        let mut ct = paso_credential_type();
        ct.transaction_data_types = None;

        let doc = build_credential_metadata_document(&ct).expect("document");
        assert!(doc.get("transaction_data_types").is_none());
    }
}
