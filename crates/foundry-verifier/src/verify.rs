use crate::error::VerificationError;
use crate::transaction::{
    CheckResult, VerificationResult, VerificationState, VerificationTransaction,
};
use foundry_core::config::Config;
use foundry_core::trust::TrustStore;
use josekit::jwk::Jwk;
use serde_json::Value;

pub fn verify_vp_response(
    config: &Config,
    tx: &mut VerificationTransaction,
    encrypted_jwe_str: &str,
) -> Result<VerificationResult, VerificationError> {
    match do_verify_vp_response(config, tx, encrypted_jwe_str) {
        Ok(result) => {
            tx.state = VerificationState::Verified;
            tx.result = Some(result.clone());
            Ok(result)
        }
        Err(err) => {
            tx.state = VerificationState::Failed;
            Err(err)
        }
    }
}

fn do_verify_vp_response(
    config: &Config,
    tx: &VerificationTransaction,
    encrypted_jwe_str: &str,
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

    let mut disclosed_claims = serde_json::Map::new();

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
    } else {
        return Err(VerificationError::Failed(
            "unsupported vp_token format".to_string(),
        ));
    }

    // 3. Result Construction
    Ok(VerificationResult {
        verified: true,
        checks,
        claims: Value::Object(disclosed_claims),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::VerificationState;
    use foundry_core::config::{
        AdminConfig, AttestationMode, Config, IssuerConfig, Mode, ServerConfig, StatusListConfig,
        StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
    };
    use foundry_core::crypto::{FileSigner, SignatureAlgorithm, Signer};
    use foundry_core::pki::{issue_leaf, new_ca};
    use foundry_sd_jwt_vc::builder::{attach_kb_jwt, build_sd_jwt_vc, IssuerClaims};
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    use josekit::jwk::{Jwk, KeyPair as _};
    use openid4vp::core::jwe::JweBuilder;
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

    fn test_config(ca_pem: &str) -> Config {
        Config {
            server: ServerConfig {
                wallet_facing: WalletFacingConfig {
                    public_base_url: "https://localhost:8443".to_string(),
                    bind: "127.0.0.1:8443".to_string(),
                },
                admin: AdminConfig {
                    bind: "127.0.0.1:8444".to_string(),
                    api_key: None,
                    api_key_env: None,
                    swagger_ui_enabled: true,
                },
            },
            storage: StorageConfig {
                path: "test.db".to_string(),
                transaction_ttl_secs: 600,
            },
            keys: Default::default(),
            trust_anchors: vec![TrustAnchor {
                name: "test_ca".to_string(),
                certs: ca_pem.to_string(),
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
        }
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

    #[test]
    fn test_verify_vp_response_sd_jwt_vc() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let config = test_config(&ca_str);

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

        let res = verify_vp_response(&config, &mut tx, &jwe_str).unwrap();

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

    #[test]
    fn test_verify_vp_response_missing_vp_token() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let config = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let jwe_str = JweBuilder::new()
            .payload(serde_json::json!({ "other_field": "no_vp_token" }))
            .recipient_key_json(&tx.ephem_public_jwk)
            .unwrap()
            .alg("ECDH-ES")
            .enc("A128GCM")
            .build()
            .unwrap();

        let err = verify_vp_response(&config, &mut tx, &jwe_str).unwrap_err();
        assert!(matches!(err, VerificationError::Failed(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[test]
    fn test_verify_vp_response_invalid_jwe() {
        let (root_pem, _leaf_cert, _leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let config = test_config(&ca_str);
        let (mut tx, _ephem_pub_jwk) = sample_tx();

        let err = verify_vp_response(&config, &mut tx, "not.a.valid.jwe.token").unwrap_err();
        assert!(matches!(err, VerificationError::Decryption(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }

    #[test]
    fn test_verify_vp_response_kb_nonce_mismatch() {
        let (root_pem, leaf_cert, leaf_key) = test_pki();
        let ca_str = String::from_utf8(root_pem).unwrap();
        let config = test_config(&ca_str);

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

        let err = verify_vp_response(&config, &mut tx, &jwe_str).unwrap_err();
        assert!(matches!(err, VerificationError::Failed(_)));
        assert_eq!(tx.state, VerificationState::Failed);
    }
}
