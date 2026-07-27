use crate::dcql::{check_dcql_match, PresentedFormat};
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
    let mut disclosed_claims = serde_json::Map::new();
    let presented_format;
    let doc_type: Option<String>;

    if let Some(jwt_str) = vp_token.as_str() {
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
        presented_format = PresentedFormat::SdJwtVc;
        doc_type = None;
    } else if let Some(obj) = vp_token.as_object() {
        // mdoc presentation envelope:
        //   { "mdoc": <b64url(issued mdoc CBOR)>,
        //     "device_signature": <b64url(COSE_Sign1 over SessionTranscript)> }
        let mdoc_b64 = obj
            .get("mdoc")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VerificationError::Failed("mdoc vp_token missing 'mdoc'".to_string()))?;
        let dev_sig_b64 = obj
            .get("device_signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VerificationError::Failed("mdoc vp_token missing 'device_signature'".to_string())
            })?;
        let mdoc_bytes = B64URL
            .decode(mdoc_b64)
            .map_err(|e| VerificationError::Failed(format!("mdoc base64 decode: {e}")))?;
        let dev_sig_bytes = B64URL.decode(dev_sig_b64).map_err(|e| {
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
        presented_format = PresentedFormat::MsoMdoc;
        doc_type = Some(mdoc_res.doc_type);
    } else {
        return Err(VerificationError::Failed(
            "unsupported vp_token format".to_string(),
        ));
    }

    let claims_value = Value::Object(disclosed_claims);

    // 4. DCQL query satisfaction (shared across credential formats).
    checks.push(check_dcql_match(
        &tx.dcql_query,
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
        AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
        StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
    };
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_mdoc::builder::{build_mdoc, MdocClaims};
    use foundry_mdoc::types::serialize_session_transcript;
    use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};
    use openid4vp::core::jwe::JweBuilder;
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
                },
                key_attestation: AttestationMode {
                    mode: Mode::Disabled,
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

        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "vp_token": presentation }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
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

    #[tokio::test]
    async fn test_verify_vp_response_missing_vp_token() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let (config, _trust_dir) = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "other_field": "no_vp_token" }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
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

        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "vp_token": presentation }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
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

        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "vp_token": presentation }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
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
        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "vp_token": vp_token }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
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
}
