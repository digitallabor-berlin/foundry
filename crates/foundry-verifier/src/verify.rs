use crate::dcql::{check_dcql_match, PresentedFormat};
use crate::dcql_model::{CredentialFormat, DcqlQuery};
use crate::error::VerificationError;
use crate::status::{check_status, StatusListResolver};
use crate::transaction::{
    CheckResult, VerificationResult, VerificationState, VerificationTransaction,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use foundry_core::config::Config;
use foundry_core::trust::TrustStore;
use josekit::jwk::Jwk;
use serde_json::Value;

/// The single presentation selected from a `vp_token`, already destructured
/// according to the credential format the DCQL query declared.
///
/// Carrying the typed payload — rather than a `&Value` plus a format tag — keeps
/// every shape check inside `select_presentation`, so the verification arms
/// cannot re-derive the format or trip over an "impossible" type error.
#[derive(Debug)]
enum SelectedPresentation<'a> {
    SdJwtVc(&'a str),
    /// **Non-conformant payload, deliberately retained.** OpenID4VP Annex B
    /// requires a base64url ISO 18013-5 `DeviceResponse` carrying `deviceSigned`
    /// inside each document. This split envelope is what `verify_mdoc` consumes
    /// today, so mdoc is **not** interoperable with real wallets: the envelope
    /// is now conformant, the payload is not. See spec defects 2-3.
    MsoMdoc {
        mdoc_b64: &'a str,
        device_signature_b64: &'a str,
    },
}

impl SelectedPresentation<'_> {
    fn format(&self) -> PresentedFormat {
        match self {
            Self::SdJwtVc(_) => PresentedFormat::SdJwtVc,
            Self::MsoMdoc { .. } => PresentedFormat::MsoMdoc,
        }
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Select the one presentation to verify from an OpenID4VP 1.0 section 8.1
/// `vp_token`.
///
/// `vp_token` is a JSON object keyed by DCQL credential query id whose values are
/// **arrays** of presentations — the same shape for every credential format. The
/// format therefore *cannot* be read off the JSON type of the payload; it is
/// whatever the answered credential query declared. Inferring it from the shape
/// is exactly what made a conformant SD-JWT VC presentation report the
/// misleading `mdoc vp_token missing 'mdoc'`.
///
/// Returns the answered credential query id with the destructured payload. Every
/// failure here is structural (HTTP 400), never a policy verdict.
fn select_presentation<'a>(
    vp_token: &'a Value,
    dcql_query: &Value,
) -> Result<(String, SelectedPresentation<'a>), VerificationError> {
    let entries = vp_token.as_object().ok_or_else(|| {
        VerificationError::Failed(format!(
            "vp_token must be a JSON object keyed by DCQL credential query id \
             (OpenID4VP 1.0 section 8.1), got {}",
            json_type_name(vp_token)
        ))
    })?;

    // The declared format is the only trustworthy source of the credential
    // format, so an unusable dcql_query is fatal rather than a failed check.
    let query: DcqlQuery = serde_json::from_value(dcql_query.clone()).map_err(|e| {
        VerificationError::Failed(format!(
            "cannot determine the requested credential format: this transaction's \
             dcql_query is not a valid DCQL query: {e}"
        ))
    })?;

    let mut answering = query
        .credentials()
        .iter()
        .filter(|cq| entries.contains_key(cq.id()));
    let cq = match (answering.next(), answering.next()) {
        (Some(cq), None) => cq,
        (None, _) => {
            let received: Vec<&str> = entries.keys().map(String::as_str).collect();
            let expected: Vec<&str> = query.credentials().iter().map(|c| c.id()).collect();
            return Err(VerificationError::Failed(format!(
                "vp_token names no credential query from this request: got [{}], \
                 expected one of [{}]",
                received.join(", "),
                expected.join(", ")
            )));
        }
        (Some(_), Some(_)) => {
            let matched: Vec<&str> = query
                .credentials()
                .iter()
                .filter(|c| entries.contains_key(c.id()))
                .map(|c| c.id())
                .collect();
            return Err(VerificationError::Failed(format!(
                "vp_token answers several credential queries ([{}]); this verifier \
                 verifies a single credential per vp_token",
                matched.join(", ")
            )));
        }
    };

    let value = entries.get(cq.id()).unwrap_or(&Value::Null);
    let presentations = value.as_array().ok_or_else(|| {
        VerificationError::Failed(format!(
            "vp_token['{}'] must be an array of presentations \
             (OpenID4VP 1.0 section 8.1), got {}",
            cq.id(),
            json_type_name(value)
        ))
    })?;

    // Exactly one: silently taking [0] of a longer array would verify part of a
    // presentation set while reporting the whole set as satisfied.
    let presentation = match presentations.as_slice() {
        [single] => single,
        other => {
            return Err(VerificationError::Failed(format!(
                "vp_token['{}'] must contain exactly one presentation, got {}",
                cq.id(),
                other.len()
            )))
        }
    };

    let selected = match cq.format() {
        CredentialFormat::DcSdJwt => {
            SelectedPresentation::SdJwtVc(presentation.as_str().ok_or_else(|| {
                VerificationError::Failed(format!(
                    "credential query '{}' declares format dc+sd-jwt, so its \
                     presentation must be an SD-JWT VC string, got {}",
                    cq.id(),
                    json_type_name(presentation)
                ))
            })?)
        }
        CredentialFormat::MsoMdoc => {
            let obj = presentation.as_object().ok_or_else(|| {
                VerificationError::Failed(format!(
                    "credential query '{}' declares format mso_mdoc, so its \
                     presentation must be an object, got {}",
                    cq.id(),
                    json_type_name(presentation)
                ))
            })?;
            let mdoc_b64 = obj.get("mdoc").and_then(|v| v.as_str()).ok_or_else(|| {
                VerificationError::Failed(format!(
                    "mdoc presentation for credential query '{}' is missing 'mdoc'",
                    cq.id()
                ))
            })?;
            let device_signature_b64 = obj
                .get("device_signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VerificationError::Failed(format!(
                        "mdoc presentation for credential query '{}' is missing \
                         'device_signature'",
                        cq.id()
                    ))
                })?;
            SelectedPresentation::MsoMdoc {
                mdoc_b64,
                device_signature_b64,
            }
        }
        // `CredentialFormat::Other` exists so that an unimplemented format inside a
        // multi-credential query simply fails to match rather than invalidating the
        // whole query (see `dcql_model`). Once a wallet has *answered* such a query
        // there is nothing to fall back to: no verifier for the format exists, so
        // this is a request the verifier cannot service.
        CredentialFormat::Other(other) => {
            return Err(VerificationError::Failed(format!(
                "credential query '{}' requests credential format '{}', which this \
                 verifier does not implement",
                cq.id(),
                other
            )))
        }
    };

    Ok((cq.id().to_string(), selected))
}

pub async fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerificationResult, VerificationError> {
    match do_verify_vp_response(config, tx, encrypted_jwe_str, resolver).await {
        Ok(result) => {
            tx.state = if result.verified {
                VerificationState::Verified
            } else {
                VerificationState::Failed
            };
            tx.result = Some(result.clone());
            Ok(result)
        }
        Err(err) => {
            tx.state = VerificationState::Failed;
            Err(err)
        }
    }
}

async fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
    resolver: &dyn StatusListResolver,
) -> Result<VerificationResult, VerificationError> {
    // 1. JWE Decryption
    let jwk_str = serde_json::to_string(&tx.ephem_private_jwk)
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;
    let ephem_jwk = Jwk::from_bytes(jwk_str.as_bytes())
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let decrypter = josekit::jwe::ECDH_ES
        .decrypter_from_jwk(&ephem_jwk)
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let (jwt_payload, _header) = josekit::jwt::decode_with_decrypter(encrypted_jwe_str, &decrypter)
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let response_json = serde_json::to_value(jwt_payload.claims_set())
        .map_err(|e| VerificationError::Decryption(e.to_string()))?;

    let mut checks = vec![CheckResult {
        check: "jwe_decryption".to_string(),
        passed: true,
        detail: None,
    }];

    // 2. vp_token Extraction & Verification
    let vp_token = response_json.get("vp_token").ok_or_else(|| {
        VerificationError::Failed("missing vp_token in response payload".to_string())
    })?;

    let trust_store = TrustStore::from_config(&config.trust_anchors)?;

    let base_url = config
        .server
        .wallet_facing
        .public_base_url
        .trim_end_matches('/');
    let host = crate::request::dns_host_only(base_url);
    let client_id = format!("x509_san_dns:{host}");

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VerificationError::Crypto(e.to_string()))?
        .as_secs();

    // 3. Credential-format-specific signature/binding verification + disclosure.
    //    The format is taken from the answered DCQL credential query, never
    //    inferred from the shape of the payload.
    let (answered_query_id, selected) = select_presentation(vp_token, &tx.dcql_query)?;
    let presented_format = selected.format();
    let mut disclosed_claims = serde_json::Map::new();

    let doc_type: Option<String> = match selected {
        SelectedPresentation::SdJwtVc(jwt_str) => {
            let verified = foundry_sd_jwt_vc::verifier::verify_sd_jwt_vc(
                jwt_str,
                &trust_store,
                &client_id,
                &tx.nonce,
                now_unix,
            )
            .map_err(|e| VerificationError::Failed(e.to_string()))?;

            checks.push(CheckResult {
                check: "sd_jwt_vc_signature_and_kb_jwt".to_string(),
                passed: true,
                detail: None,
            });

            if let Value::Object(map) = verified.claims {
                for (k, v) in map {
                    disclosed_claims.insert(k, v);
                }
            }
            None
        }
        SelectedPresentation::MsoMdoc {
            mdoc_b64,
            device_signature_b64,
        } => {
            let mdoc_bytes = B64URL
                .decode(mdoc_b64)
                .map_err(|e| VerificationError::Failed(format!("mdoc base64 decode: {e}")))?;
            let dev_sig_bytes = B64URL.decode(device_signature_b64).map_err(|e| {
                VerificationError::Failed(format!("device_signature base64 decode: {e}"))
            })?;

            let response_uri = format!("{base_url}/vp/response/{}", tx.id);
            let mdoc_res = foundry_mdoc::verifier::verify_mdoc(
                &mdoc_bytes,
                &trust_store,
                Some(client_id.clone()),
                Some(response_uri),
                tx.nonce.clone(),
                &dev_sig_bytes,
                now_unix,
            )
            .map_err(|e| VerificationError::Failed(format!("mdoc verification failed: {e}")))?;

            checks.push(CheckResult {
                check: "mdoc_issuer_auth_and_device_signature".to_string(),
                passed: true,
                detail: None,
            });

            for (ns, elements) in mdoc_res.claims {
                let mut ns_obj = serde_json::Map::new();
                for (k, v) in elements {
                    ns_obj.insert(k, v);
                }
                disclosed_claims.insert(ns, Value::Object(ns_obj));
            }
            Some(mdoc_res.doc_type)
        }
    };

    let claims_value = Value::Object(disclosed_claims);

    // 4. DCQL query satisfaction (shared across credential formats).
    checks.push(check_dcql_match(
        &tx.dcql_query,
        &answered_query_id,
        presented_format,
        &claims_value,
        doc_type.as_deref(),
    ));

    // 5. Token Status List revocation check (shared across credential formats).
    //    A network failure fetching the token propagates as a hard error.
    checks.push(check_status(&claims_value, &trust_store, resolver, now_unix).await?);

    // 6. Overall verdict is the AND of every check performed.
    let verified = checks.iter().all(|c| c.passed);
    Ok(VerificationResult {
        verified,
        checks,
        claims: claims_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::test_support::MockResolver;
    use crate::transaction::VerificationState;
    use foundry_core::config::{
        AdminConfig, AttestationMode, Config, IssuerConfig, LoggingConfig, Mode, ServerConfig,
        StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
    };
    use foundry_core::crypto::jwe::encrypt_compact;
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_mdoc::builder::{build_mdoc, MdocClaims};
    use foundry_mdoc::types::serialize_session_transcript;
    use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = new_ca("Foundry Dev Root CA", 3650).unwrap();
        let leaf = issue_leaf(
            &root.cert_pem,
            &root.key_pem,
            "localhost",
            &["localhost".to_string()],
            365,
        )
        .unwrap();
        (
            root.cert_pem.into_bytes(),
            leaf.cert_pem.into_bytes(),
            leaf.key_pem.into_bytes(),
        )
    }

    fn holder() -> (FileSigner, serde_json::Value) {
        let jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let kp = EcKeyPair::from_jwk(&jwk).unwrap();
        let signer =
            FileSigner::from_pem(&kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
        let pubjwk = signer.public_jwk().unwrap();
        (signer, pubjwk)
    }

    fn der_b64(pem_bytes: &[u8]) -> String {
        std::str::from_utf8(pem_bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }

    fn test_config(ca_pem: &str) -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("root.pem");
        std::fs::write(&cert_path, ca_pem).unwrap();
        let config = Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://localhost:8443".to_string(),
                    bind: "127.0.0.1:8443".to_string(),
                    swagger_ui_enabled: true,
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:8444".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                    console_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "test.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: Default::default(),
            trust_anchors: vec![TrustAnchor {
                name: "test_ca".to_string(),
                certs: cert_path.to_str().unwrap().to_string(),
            }],
            issuer: IssuerConfig {
                credential_issuer: "https://localhost:8443".to_string(),
                wallet_attestation: AttestationMode {
                    mode: Mode::Disabled,
                    trusted_anchors: Vec::new(),
                },
                key_attestation: AttestationMode {
                    mode: Mode::Disabled,
                    trusted_anchors: Vec::new(),
                },
                status_list: StatusListConfig {
                    enabled: false,
                    signing_key: None,
                    list_size: Some(131072),
                    public_base_url: None,
                },
            },
            credential_types: vec![],
            verifier: VerifierConfig {
                client_id_scheme: "x509_san_dns".to_string(),
                signing_key: "verifier_key".to_string(),
                response_encryption: None,
                transaction_data_hashes_alg: vec![],
                named_queries: vec![],
                webhook: None,
            },
            logging: LoggingConfig::default(),
        };
        (config, dir)
    }

    fn sample_tx() -> (VerificationTransaction, Jwk) {
        let keypair = EcKeyPair::generate(EcCurve::P256).unwrap();
        let public_jwk = keypair.to_jwk_public_key();
        let private_jwk = keypair.to_jwk_private_key();

        let ephem_public_json = serde_json::to_value(&public_jwk).unwrap();
        let ephem_private_json = serde_json::to_value(&private_jwk).unwrap();

        let tx = VerificationTransaction {
            id: "vtx-test-123".to_string(),
            state: VerificationState::Pending,
            nonce: "nonce-99999".to_string(),
            dcql_query: serde_json::json!({
                "credentials": [{"id": "c1", "format": "dc+sd-jwt"}]
            }),
            transport: "direct_post".to_string(),
            response_mode: "direct_post.jwt".to_string(),
            ephem_private_jwk: ephem_private_json,
            ephem_public_jwk: ephem_public_json,
            transaction_data: None,
            result: None,
            created_at: 1_700_000_000,
        };
        (tx, public_jwk)
    }

    #[tokio::test]
    async fn test_verify_vp_response_sd_jwt_vc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();

        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };

        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let client_id = "x509_san_dns:localhost";
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, client_id, &tx.nonce).unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(res.verified);
        assert_eq!(tx.state, VerificationState::Verified);
        assert_eq!(res.claims["given_name"], "Alice");
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "jwe_decryption" && c.passed));
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed));
    }

    /// VP-0125 (OpenID4VP 1.0 Response / Response Parameters, L1172): the
    /// Client MUST ignore any unrecognized response parameters.
    /// `do_verify_vp_response` reads only `vp_token` out of the decrypted JWE
    /// payload; any other top-level member is never inspected, so a response
    /// carrying an unrecognized parameter alongside a valid `vp_token` must
    /// verify identically to one without it.
    #[tokio::test]
    async fn vp_0125_unrecognized_response_parameters_are_ignored() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            "x509_san_dns:localhost",
            &tx.nonce,
        )
        .unwrap();

        // `code`, `iss`, and a made-up future parameter alongside `vp_token`.
        let jwe_str = encrypt_compact(
            &serde_json::json!({
                "vp_token": { "c1": [presentation] },
                "code": "unused-by-this-verifier",
                "iss": "https://verifier.example.com",
                "some_future_response_parameter": { "nested": true }
            }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "unrecognized response parameters must not affect verification: checks={:?}",
            res.checks
        );
    }

    /// GAP-VP-04 -- OpenID4VP 1.0 Response / VP Token Validation (L1523),
    /// Format / IETF SD-JWT VC / Transaction Data (L3144): Verifiers MUST
    /// check that the set of Presentations satisfies all requirements of the
    /// Verifier's request (VP-0153), which includes any `transaction_data`
    /// the Verifier itself requested (VP-0019/VP-0020, conforming --
    /// `encode_transaction_data` validates and advertises it). The SD-JWT VC
    /// profile of Transaction Data binds the request to the presentation via
    /// a `transaction_data_hashes` claim in the Key Binding JWT. Nothing in
    /// this workspace ever reads or checks that claim: `attach_kb_jwt`
    /// (foundry-sd-jwt-vc's builder) has no parameter for it at all, and
    /// `do_verify_vp_response`/`verify_sd_jwt_vc` never look for it either.
    /// A transaction is requested, but never verified to have been bound to
    /// the presentation at all.
    #[tokio::test]
    #[ignore = "GAP-VP-04: OpenID4VP Response / VP Token Validation (L1523); Format / IETF SD-JWT VC / Transaction Data (L3144) — transaction_data_hashes is never read or validated anywhere, so a presentation is accepted as verified even though it does not bind to the transaction_data the Verifier requested"]
    async fn gap_vp_04_transaction_data_hashes_never_validated() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        // The Verifier requested transaction_data for this transaction, per
        // the same base64url-encoded-entry shape `encode_transaction_data`
        // (request.rs) produces and persists on `VerificationTransaction`.
        let td_entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["c1"],
            "amount": 5000
        });
        let td_encoded = B64URL.encode(serde_json::to_vec(&td_entry).unwrap());
        tx.transaction_data = Some(vec![td_encoded]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // A KB-JWT built the only way this codebase can build one: with no
        // `transaction_data_hashes` claim at all, since `attach_kb_jwt` has no
        // parameter for it.
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            "x509_san_dns:localhost",
            &tx.nonce,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            !res.verified,
            "a presentation with no transaction_data_hashes binding must not verify \
             when the Verifier requested transaction_data, but it did: checks={:?}",
            res.checks
        );
    }

    /// HAIP-0049, HAIP-0050, HAIP-0053 (HAIP OpenID4VP, L258-259): the JWE
    /// `alg` value `ECDH-ES` with key agreement on the `P-256` curve MUST be
    /// supported; the JWE `enc` values `A128GCM` and `A256GCM` MUST be
    /// supported by Verifiers; and Verifiers MUST supply ephemeral encryption
    /// public keys specific to each Authorization Request. `sample_tx`
    /// generates a fresh P-256 `EcKeyPair` per call (HAIP-0053, HAIP-0049);
    /// `do_verify_vp_response`'s decrypter is generic over the JWE `enc`
    /// header, so a response encrypted with `A256GCM` decrypts successfully
    /// alongside the `A128GCM` default already exercised by every other test
    /// in this module (HAIP-0050).
    #[tokio::test]
    async fn haip_0049_0050_0053_ecdh_es_p256_and_a256gcm_supported() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        let (tx2, _) = sample_tx();

        // HAIP-0049: the ephemeral encryption key is always P-256.
        assert_eq!(tx.ephem_public_jwk["crv"], "P-256");
        // HAIP-0053: a fresh ephemeral key per Authorization Request.
        assert_ne!(tx.ephem_public_jwk["x"], tx2.ephem_public_jwk["x"]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            "x509_san_dns:localhost",
            &tx.nonce,
        )
        .unwrap();

        // HAIP-0050: encrypt with A256GCM rather than the A128GCM default.
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A256GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(
            res.verified,
            "A256GCM-encrypted responses must decrypt and verify: checks={:?}",
            res.checks
        );
    }

    #[tokio::test]
    async fn test_verify_vp_response_missing_vp_token() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "other_field": "no_vp_token" }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Failed(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_invalid_jwe() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, "not.a.valid.jwe.token", &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Decryption(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_kb_nonce_mismatch() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();

        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        };

        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        let client_id = "x509_san_dns:localhost";
        // Attach KB-JWT with wrong nonce
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, client_id, "wrong-nonce").unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, VerificationError::Failed(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_dcql_vct_mismatch_is_not_verified() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        // Require a vct the credential will NOT have.
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://localhost:8443/vct/OTHER"] }
            }]
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            "x509_san_dns:localhost",
            &tx.nonce,
        )
        .unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();
        assert!(!res.verified, "DCQL vct mismatch must not verify");
        assert_eq!(tx.state, VerificationState::Failed);
        let dcql = res.checks.iter().find(|c| c.check == "dcql_match").unwrap();
        assert!(!dcql.passed);
        // The signature check still passed and is still reported for transparency.
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "sd_jwt_vc_signature_and_kb_jwt" && c.passed));
    }

    /// VP-0175, VP-0177, VP-0179, VP-0180 -- OpenID4VP 1.0 Security /
    /// Preventing Replay (L1789-1795): the Verifier MUST verify the binding
    /// of the proof of possession (the KB-JWT) to audience and `nonce`, MUST
    /// validate that every individual Presentation is linked to the
    /// `client_id` and `nonce` of *its own* request, and MUST reject a
    /// response if any Presentation carries the wrong `nonce`. A captured
    /// presentation is bound (via the KB-JWT's `aud` and `nonce` claims) to
    /// the specific transaction it was produced for; replaying it verbatim
    /// against a second, independently-created transaction exercises
    /// exactly the attack this section defends against, distinct from
    /// `test_verify_vp_response_kb_nonce_mismatch`'s arbitrary bad-nonce
    /// case.
    #[tokio::test]
    async fn vp_0175_0177_0179_0180_presentation_replayed_against_second_transaction_is_rejected() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();

        // Transaction 1: the presentation is legitimately produced for this one.
        let (tx1, _) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            "x509_san_dns:localhost",
            &tx1.nonce,
        )
        .unwrap();

        // Sanity: the presentation verifies fine against the transaction it
        // was actually produced for.
        let mut tx1_for_check = tx1.clone();
        let jwe_for_tx1 = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation.clone()] } }),
            &tx1_for_check.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();
        let resolver = MockResolver { token: None };
        let ok = verify_vp_response(&config, &mut tx1_for_check, &jwe_for_tx1, &resolver)
            .await
            .unwrap();
        assert!(
            ok.verified,
            "sanity check: the presentation must verify against its own transaction"
        );

        // Transaction 2: a wholly separate request (independent nonce and
        // ephemeral encryption key), as if an attacker relayed the captured
        // presentation to a second Authorization Request.
        let keypair2 = EcKeyPair::generate(EcCurve::P256).unwrap();
        let mut tx2 = tx1.clone();
        tx2.id = "vtx-test-456".to_string();
        tx2.nonce = "nonce-replay-attempt".to_string();
        tx2.ephem_public_jwk = serde_json::to_value(keypair2.to_jwk_public_key()).unwrap();
        tx2.ephem_private_jwk = serde_json::to_value(keypair2.to_jwk_private_key()).unwrap();

        let jwe_for_tx2 = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx2.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();
        let err = verify_vp_response(&config, &mut tx2, &jwe_for_tx2, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::Failed(_)),
            "replaying a presentation bound to a different transaction's nonce \
             must be rejected: {err:?}"
        );
        assert_eq!(tx2.state, VerificationState::Failed);
    }

    /// AGENTS.md Sec4.2/Sec4.3, VP-0152 (Response / VP Token Validation,
    /// L1522): a Status List Token that cannot be fetched is a
    /// network/structural failure, not a policy verdict -- it MUST
    /// propagate as `Err`, never resolve to
    /// `Ok(VerificationResult { verified: false, .. })`. `status.rs`'s own
    /// `network_failure_is_hard_error` proves this for `check_status` in
    /// isolation; this test proves the same holds through the full
    /// `verify_vp_response` entry point, including the transaction state
    /// transition on failure.
    #[tokio::test]
    async fn vp_0152_status_endpoint_unreachable_is_a_hard_error_through_full_verification() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            // A status claim is present, so check_status must actually fetch
            // the Status List Token -- and the MockResolver below has none.
            status_list_index: Some(42),
            status_list_uri: Some("https://issuer.example/statuslists/1".to_string()),
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: serde_json::Map::new(),
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();
        let presentation = attach_kb_jwt(
            issuer_pres,
            &holder_signer,
            "x509_san_dns:localhost",
            &tx.nonce,
        )
        .unwrap();
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None }; // errors on fetch
        let err = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::StatusUnavailable(_)),
            "an unreachable status list endpoint must propagate as a hard error, \
             not a policy verdict: {err:?}"
        );
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[tokio::test]
    async fn test_verify_vp_response_mdoc_presentation() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();

        // Device (holder) key.
        let d_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
        let d_jwk_pub = serde_json::to_value(d_kp.to_jwk_public_key()).unwrap();
        let d_signer =
            FileSigner::from_pem(&d_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();

        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // Request an mdoc of the doctype/namespace/element we will issue.
        tx.dcql_query = serde_json::json!({
            "credentials": [{
                "id": "c1",
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build the issued mdoc.
        let mut elements = std::collections::BTreeMap::new();
        elements.insert("given_name".to_string(), serde_json::json!("John"));
        let mut namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        let mdoc_claims = MdocClaims {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces,
            device_key_jwk: d_jwk_pub,
            signed_at: (now - 100) as i64,
            valid_until: (now + 3600) as i64,
        };
        let mdoc_bytes =
            build_mdoc(mdoc_claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // Build the detached DeviceAuth COSE_Sign1 over the OpenID4VP SessionTranscript.
        let client_id = "x509_san_dns:localhost".to_string();
        let response_uri = format!("https://localhost:8443/vp/response/{}", tx.id);
        let transcript =
            serialize_session_transcript(Some(client_id), Some(response_uri), tx.nonce.clone())
                .unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let partial = coset::CoseSign1Builder::new()
            .protected(protected.clone())
            .build();
        let d_tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            partial.protected.clone(),
            None,
            &[],
            &transcript,
        );
        let sig = {
            use foundry_core::crypto::Signer as _;
            d_signer.sign(&d_tbs).unwrap()
        };
        let d_sign = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(sig)
            .build();
        let d_sig_bytes = coset::CborSerializable::to_vec(d_sign).unwrap();

        // Envelope + JWE.
        let vp_token = serde_json::json!({
            "mdoc": B64URL.encode(&mdoc_bytes),
            "device_signature": B64URL.encode(&d_sig_bytes),
        });
        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [vp_token] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(res.verified, "checks={:?}", res.checks);
        assert_eq!(res.claims["org.iso.18013.5.1"]["given_name"], "John");
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "mdoc_issuer_auth_and_device_signature" && c.passed));
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "dcql_match" && c.passed));
        assert!(res
            .checks
            .iter()
            .any(|c| c.check == "status_check" && c.passed));
    }

    // --- select_presentation: the OpenID4VP 1.0 section 8.1 envelope ---
    //
    // These exercise envelope selection directly, with no JWE, no keys and no
    // trust store, so a failure points at the envelope rather than at crypto.

    fn sd_jwt_dcql() -> Value {
        serde_json::json!({"credentials": [{"id": "c1", "format": "dc+sd-jwt"}]})
    }

    fn mdoc_dcql() -> Value {
        serde_json::json!({"credentials": [{"id": "c1", "format": "mso_mdoc"}]})
    }

    /// Assert rejection and hand back the message, so each test can check that the
    /// message actually says something actionable.
    fn rejection_of(vp_token: Value, dcql_query: &Value) -> String {
        match select_presentation(&vp_token, dcql_query) {
            Ok((id, selected)) => {
                panic!("expected rejection, but selected id={id} payload={selected:?}")
            }
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn select_presentation_accepts_conformant_sd_jwt_envelope() {
        let vp = serde_json::json!({"c1": ["header.body.sig~disclosure~kb"]});
        let (id, selected) = select_presentation(&vp, &sd_jwt_dcql()).unwrap();
        assert_eq!(id, "c1");
        match selected {
            SelectedPresentation::SdJwtVc(s) => assert_eq!(s, "header.body.sig~disclosure~kb"),
            other => panic!("expected SdJwtVc, got {other:?}"),
        }
    }

    #[test]
    fn select_presentation_accepts_conformant_mdoc_envelope() {
        let vp = serde_json::json!({"c1": [{"mdoc": "AAAA", "device_signature": "BBBB"}]});
        let (id, selected) = select_presentation(&vp, &mdoc_dcql()).unwrap();
        assert_eq!(id, "c1");
        match selected {
            SelectedPresentation::MsoMdoc {
                mdoc_b64,
                device_signature_b64,
            } => {
                assert_eq!(mdoc_b64, "AAAA");
                assert_eq!(device_signature_b64, "BBBB");
            }
            other => panic!("expected MsoMdoc, got {other:?}"),
        }
    }

    /// The reported production defect: a bare string was foundry's old SD-JWT VC
    /// shape, and no conformant wallet sends it.
    #[test]
    fn select_presentation_rejects_bare_string_vp_token() {
        let msg = rejection_of(serde_json::json!("header.body.sig~"), &sd_jwt_dcql());
        assert!(msg.contains("must be a JSON object"), "{msg}");
        assert!(msg.contains("got a string"), "{msg}");
    }

    /// foundry's old mdoc shape put these keys at the top level of `vp_token`.
    #[test]
    fn select_presentation_rejects_legacy_top_level_mdoc_envelope() {
        let msg = rejection_of(
            serde_json::json!({"mdoc": "AAAA", "device_signature": "BBBB"}),
            &mdoc_dcql(),
        );
        assert!(msg.contains("names no credential query"), "{msg}");
    }

    #[test]
    fn select_presentation_rejects_unknown_query_id_naming_both_sides() {
        let msg = rejection_of(serde_json::json!({"unexpected": ["x"]}), &sd_jwt_dcql());
        assert!(msg.contains("unexpected"), "must name what arrived: {msg}");
        assert!(msg.contains("c1"), "must name what was expected: {msg}");
    }

    #[test]
    fn select_presentation_rejects_multiple_answered_queries() {
        let dcql = serde_json::json!({"credentials": [
            {"id": "a", "format": "dc+sd-jwt"},
            {"id": "b", "format": "dc+sd-jwt"}
        ]});
        let msg = rejection_of(serde_json::json!({"a": ["x"], "b": ["y"]}), &dcql);
        assert!(msg.contains("several credential queries"), "{msg}");
    }

    #[test]
    fn select_presentation_requires_exactly_one_presentation() {
        let dcql = sd_jwt_dcql();
        let empty = rejection_of(serde_json::json!({"c1": []}), &dcql);
        assert!(empty.contains("exactly one presentation"), "{empty}");
        let two = rejection_of(serde_json::json!({"c1": ["x", "y"]}), &dcql);
        assert!(two.contains("exactly one presentation"), "{two}");
    }

    #[test]
    fn select_presentation_requires_an_array_value() {
        let msg = rejection_of(serde_json::json!({"c1": "not-an-array"}), &sd_jwt_dcql());
        assert!(msg.contains("must be an array"), "{msg}");
    }

    /// The payload must match the format the query *declared*. This is where the
    /// old shape-sniffing protection now lives, with a message that names the
    /// declared format instead of guessing.
    #[test]
    fn select_presentation_rejects_payload_contradicting_declared_format() {
        let object_for_sd_jwt = rejection_of(
            serde_json::json!({"c1": [{"mdoc": "A", "device_signature": "B"}]}),
            &sd_jwt_dcql(),
        );
        assert!(
            object_for_sd_jwt.contains("dc+sd-jwt"),
            "{object_for_sd_jwt}"
        );

        let string_for_mdoc = rejection_of(serde_json::json!({"c1": ["a-string"]}), &mdoc_dcql());
        assert!(string_for_mdoc.contains("mso_mdoc"), "{string_for_mdoc}");
    }

    #[test]
    fn select_presentation_rejects_unusable_dcql_query() {
        let msg = rejection_of(
            serde_json::json!({"c1": ["x"]}),
            &serde_json::json!({"credentials": []}),
        );
        assert!(msg.contains("not a valid DCQL query"), "{msg}");
    }

    /// `CredentialFormat::Other` parses fine so that unimplemented formats simply
    /// fail to match inside a multi-credential query. Once one is *answered*,
    /// though, there is no verifier to dispatch to.
    #[test]
    fn select_presentation_rejects_unimplemented_credential_format() {
        let dcql = serde_json::json!({"credentials": [{"id": "c1", "format": "jwt_vc_json"}]});
        let msg = rejection_of(serde_json::json!({"c1": ["x"]}), &dcql);
        assert!(msg.contains("jwt_vc_json"), "{msg}");
        assert!(msg.contains("does not implement"), "{msg}");
    }

    /// GAP-VP-07 / VP-0265 (OpenID4VP mdoc-adjacent IETF SD-JWT VC Presentation
    /// Response, L3179): "Over the DC API the `aud` claim MUST instead be the
    /// Origin prefixed with `origin:`." `do_verify_vp_response` always computes
    /// `expected_audience` as `x509_san_dns:<host>` (the Client Identifier),
    /// regardless of `tx.transport` -- there is no branch anywhere that
    /// switches to an Origin-prefixed audience for `dc_api` transport. A
    /// spec-conformant wallet responding to an *unsigned* DC API request (the
    /// only kind foundry's `dc_api` transport ever issues, since `client_id` is
    /// never included -- see VP-0198/VP-0200) is required by this same clause
    /// to bind its KB-JWT to the Origin, not the Client Identifier -- so this
    /// verifier would reject every genuinely conformant wallet's dc_api
    /// presentation.
    #[tokio::test]
    #[ignore = "GAP-VP-07: OpenID4VP IETF SD-JWT VC Presentation Response (L3179) — over the DC API the KB-JWT `aud` claim MUST be the Origin prefixed with `origin:`, but do_verify_vp_response always expects the x509_san_dns Client Identifier instead, regardless of tx.transport"]
    async fn gap_vp_07_dc_api_transport_never_accepts_origin_prefixed_kb_jwt_audience() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);

        let issuer_signer = FileSigner::from_pem(&leaf_key, SignatureAlgorithm::Es256).unwrap();
        let (holder_signer, holder_pub) = holder();
        let (mut tx, _ephem_pub_jwk) = sample_tx();
        // Same shape `create_verification_request` builds for `transport: "dc_api"`
        // (request.rs): `dc_api.jwt` response_mode, no `client_id` ever emitted.
        tx.transport = "dc_api".to_string();
        tx.response_mode = "dc_api.jwt".to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut select = serde_json::Map::new();
        select.insert("given_name".to_string(), serde_json::json!("Alice"));

        let claims = IssuerClaims {
            iss: "localhost".to_string(),
            sub: "did:example:alice".to_string(),
            iat: (now - 100) as i64,
            exp: (now + 3600) as i64,
            vct: "https://localhost:8443/vct/pid".to_string(),
            cnf_jwk: holder_pub,
            status_list_index: None,
            status_list_uri: None,
            always_disclosed: serde_json::Map::new(),
            selectively_disclosable: select,
        };
        let issuer_pres =
            build_sd_jwt_vc(claims, &issuer_signer, Some(vec![der_b64(&leaf_cert)])).unwrap();

        // OpenID4VP L3179: over the DC API the KB-JWT `aud` MUST be the Origin
        // prefixed with `origin:`, not the Client Identifier -- exactly what a
        // conformant wallet would send back for this unsigned dc_api request.
        let origin_audience = "origin:https://verifier-website.example";
        let presentation =
            attach_kb_jwt(issuer_pres, &holder_signer, origin_audience, &tx.nonce).unwrap();

        let jwe_str = encrypt_compact(
            &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
            &tx.ephem_public_jwk,
            "ECDH-ES",
            "A128GCM",
        )
        .unwrap();

        let resolver = MockResolver { token: None };
        let res = verify_vp_response(&config, &mut tx, &jwe_str, &resolver)
            .await
            .unwrap();

        assert!(
            res.verified,
            "a conformant wallet's Origin-prefixed KB-JWT audience for a dc_api presentation \
             should verify, but do_verify_vp_response rejected it: {:?}",
            res.checks
        );
    }
}
