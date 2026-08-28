//! Delivery of verification events to an operator-configured sink
//! (design `docs/superpowers/specs/2026-08-28-verifier-artifact-webhook-design.md`).

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use foundry::admin_auth::AdminApiKey;
use foundry::server::{AppState, admin_router, wallet_router};
use foundry_core::config::{
    AdminConfig, AttestationMode, Config, DpopConfig, IssuerConfig, KeyEntry, LoggingConfig, Mode,
    ServerConfig, StatusListConfig, StorageConfig, TrustAnchor, VerifierConfig, WalletFacingConfig,
};
use foundry_core::crypto::jwe::encrypt_compact;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_core::pki::{issue_leaf, new_ca};
use foundry_core::storage::SqliteStorage;
use foundry_sd_jwt_vc::builder::{IssuerClaims, attach_kb_jwt, build_sd_jwt_vc};
use foundry_verifier::CreateVerificationResponse;
use josekit::jwk::KeyPair as _;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use std::collections::BTreeMap as StdBTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

/// The `vct` the DCQL query in every flow below asks for.
const REQUESTED_VCT: &str = "https://localhost:8443/vct/pid";

fn der_b64(pem_bytes: &[u8]) -> String {
    std::str::from_utf8(pem_bytes)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

/// Copied from `wallet_verification.rs`'s `setup_test_app`, per this
/// repository's convention that fixture helpers are duplicated across test
/// binaries rather than shared (see `support/mod.rs`'s header). The only
/// change is that `verifier.webhook` is populated before `AppState::new`.
///
/// `support::setup_without_encryption` is deliberately NOT used: it names
/// `verifier.signing_key: "verifier_signing"` while its `keys` map holds only
/// `issuer_key`, so `verifier_x5c_leaf_pem` fails and no verification flow can
/// run against it.
async fn setup_with_webhook(
    include_raw_artifacts: bool,
) -> (AppState, tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("foundry.db");
    let issuer_key_path = dir.path().join("issuer.pem");
    let verifier_key_path = dir.path().join("verifier.pem");

    let root = new_ca("Foundry Test Root CA", 365).unwrap();
    let issuer_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();
    let verifier_leaf = issue_leaf(
        &root.cert_pem,
        &root.key_pem,
        "localhost",
        &["localhost".to_string()],
        365,
    )
    .unwrap();

    std::fs::write(&issuer_key_path, &issuer_leaf.key_pem).unwrap();
    std::fs::write(&verifier_key_path, &verifier_leaf.key_pem).unwrap();

    let verifier_cert_path = dir.path().join("verifier_leaf_cert.pem");
    std::fs::write(&verifier_cert_path, &verifier_leaf.cert_pem).unwrap();

    let trust_root_path = dir.path().join("trust_root.pem");
    std::fs::write(&trust_root_path, &root.cert_pem).unwrap();

    let storage = SqliteStorage::connect(db_path.to_str().unwrap())
        .await
        .unwrap();

    let mut keys = StdBTreeMap::new();
    keys.insert(
        "issuer_key".to_string(),
        KeyEntry {
            private_key: issuer_key_path.to_str().unwrap().to_string(),
            x5c: None,
            alg: "ES256".to_string(),
        },
    );
    keys.insert(
        "verifier_key".to_string(),
        KeyEntry {
            private_key: verifier_key_path.to_str().unwrap().to_string(),
            x5c: Some(verifier_cert_path.to_str().unwrap().to_string()),
            alg: "ES256".to_string(),
        },
    );

    let mut config = Config {
        server: ServerConfig {
            wallet_facing: WalletFacingConfig {
                public_base_url: "https://localhost:8443".to_string(),
                bind: "0.0.0.0:8443".to_string(),
                swagger_ui_enabled: true,
            },
            admin: AdminConfig {
                bind: "127.0.0.1:9000".to_string(),
                api_key: Some("test-admin-key".to_string()),
                api_key_env: None,
                swagger_ui_enabled: true,
                console_enabled: true,
            },
        },
        storage: StorageConfig {
            path: db_path.to_str().unwrap().to_string(),
            transaction_ttl_secs: 600,
        },
        keys,
        trust_anchors: vec![TrustAnchor {
            name: "test_ca".to_string(),
            certs: trust_root_path.to_str().unwrap().to_string(),
        }],
        issuer: IssuerConfig {
            credential_issuer: "https://localhost:8443".to_string(),
            wallet_attestation: AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            key_attestation: AttestationMode {
                mode: Mode::Disabled,
                trusted_anchors: Vec::new(),
                pop_max_age_secs: 300,
                challenge_mode: Mode::Disabled,
                android: Default::default(),
            },
            status_list: StatusListConfig {
                enabled: false,
                signing_key: Some("issuer_key".to_string()),
                list_size: None,
                public_base_url: None,
            },
            dpop: DpopConfig::default(),
            request_encryption: None,
            response_encryption: None,
            encrypted_pre_authorized_code: Default::default(),
            access_token_ttl_secs: 600,
            offer_by_reference: false,
            paso_metadata: Default::default(),
        },
        credential_types: vec![],
        verifier: VerifierConfig {
            signing_key: "verifier_key".to_string(),
            response_encryption: None,
            transaction_data_hashes_alg: vec![],
            named_queries: vec![],
            webhook: None,
            dc_api_expected_origins: Vec::new(),
            dc_api_accept_legacy_web_origin_audience: false,
        },
        logging: LoggingConfig::default(),
    };

    config.verifier.webhook = Some(foundry_core::config::WebhookConfig {
        url: "https://audit.example.test/hook".to_string(),
        secret: Some("s3cr3t".to_string()),
        secret_env: None,
        timeout_secs: 5,
        include_raw_artifacts,
    });

    let state = AppState::new(Arc::new(storage), Arc::new(config));

    (state, dir, issuer_leaf.cert_pem, issuer_leaf.key_pem)
}

/// Drive a full presentation over the `request_uri` transport and return the
/// wallet's `POST /vp/response/:id` status and body.
///
/// Lifted from `wallet_verification.rs::full_verification_flow_end_to_end`
/// (steps 1-6), stopping at the wallet's response submission rather than going
/// on to the admin GET. `credential_vct` is the only knob: equal to
/// [`REQUESTED_VCT`] the flow verifies, anything else makes `dcql_match` fail
/// as a **policy** verdict (HTTP 200, `verified: false`) exactly as
/// `wallet_verification.rs::dcql_vct_mismatch_is_rejected` does.
async fn run_presentation(
    state: AppState,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
    credential_vct: &str,
) -> (StatusCode, serde_json::Value) {
    let admin_app = admin_router(state.clone(), AdminApiKey(Some("test-admin-key".into())));
    let wallet_app = wallet_router(state.clone());

    let create_req_body = serde_json::json!({
        "dcql_query": {
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [REQUESTED_VCT] }
            }]
        },
        "transport": "request_uri"
    });

    let create_req = Request::builder()
        .method("POST")
        .uri("/admin/verification/requests")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-admin-key")
        .body(Body::from(create_req_body.to_string()))
        .unwrap();

    let create_res = admin_app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_bytes = axum::body::to_bytes(create_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_resp: CreateVerificationResponse = serde_json::from_slice(&create_bytes).unwrap();
    let verification_id = create_resp.verification_id;

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/vp/request/{verification_id}"))
        .body(Body::empty())
        .unwrap();
    let get_res = wallet_app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let jws_bytes = axum::body::to_bytes(get_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let jws_str = String::from_utf8(jws_bytes.to_vec()).unwrap();
    let parts: Vec<&str> = jws_str.split('.').collect();
    let payload_bytes = B64URL.decode(parts[1]).unwrap();
    let request_object: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let client_id = request_object["client_id"].as_str().unwrap().to_string();
    let nonce = request_object["nonce"].as_str().unwrap().to_string();
    let ephem_public_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    let holder_kp = EcKeyPair::generate(EcCurve::P256).unwrap();
    let holder_pub_jwk = serde_json::to_value(holder_kp.to_jwk_public_key()).unwrap();
    let holder_signer =
        FileSigner::from_pem(&holder_kp.to_pem_private_key(), SignatureAlgorithm::Es256).unwrap();
    let issuer_signer =
        FileSigner::from_pem(issuer_key_pem.as_bytes(), SignatureAlgorithm::Es256).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut select = serde_json::Map::new();
    select.insert("given_name".to_string(), serde_json::json!("Alice"));

    let claims = IssuerClaims {
        iss: "localhost".to_string(),
        sub: None,
        iat: (now - 100) as i64,
        exp: (now + 3600) as i64,
        vct: credential_vct.to_string(),
        cnf_jwk: holder_pub_jwk,
        status_list_index: None,
        status_list_uri: None,
        always_disclosed: serde_json::Map::new(),
        selectively_disclosable: select,
    };
    let issuer_pres = build_sd_jwt_vc(
        claims,
        &issuer_signer,
        Some(vec![der_b64(issuer_cert_pem.as_bytes())]),
    )
    .unwrap();
    let presentation =
        attach_kb_jwt(issuer_pres, &holder_signer, &client_id, &nonce, None).unwrap();

    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": { "c1": [presentation] } }),
        &ephem_public_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .unwrap();

    let post_resp_req = Request::builder()
        .method("POST")
        .uri(format!("/vp/response/{verification_id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("response={jwe_str}")))
        .unwrap();
    let post_resp_res = wallet_app.clone().oneshot(post_resp_req).await.unwrap();
    let status = post_resp_res.status();
    let verify_bytes = axum::body::to_bytes(post_resp_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&verify_bytes).unwrap();

    (status, body)
}

async fn run_successful_presentation(
    state: AppState,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
) -> (StatusCode, serde_json::Value) {
    run_presentation(state, issuer_cert_pem, issuer_key_pem, REQUESTED_VCT).await
}

/// A presentation that decrypts cleanly and then FAILS `dcql_match`.
async fn run_failing_presentation(
    state: AppState,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
) -> (StatusCode, serde_json::Value) {
    run_presentation(
        state,
        issuer_cert_pem,
        issuer_key_pem,
        "https://localhost:8443/vct/OTHER",
    )
    .await
}

#[tokio::test]
async fn an_unconfigured_app_state_holds_no_sink() {
    let (state, _dir) = support::setup_without_encryption().await;
    assert!(
        state.webhook_sink.is_none(),
        "no verifier.webhook config must mean no sink"
    );
}

#[tokio::test]
async fn a_sink_can_be_attached_for_tests() {
    let (state, _dir) = support::setup_without_encryption().await;
    let (sink, _rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);
    assert!(state.webhook_sink.is_some());
}

/// The point of the feature: a FAILED verification still delivers, and carries
/// the token that explains why.
#[tokio::test]
async fn a_failed_verification_delivers_the_verdict_and_the_vp_token() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_with_webhook(true).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    let (status, _body) = run_failing_presentation(state, &issuer_cert_pem, &issuer_key_pem).await;
    // Root AGENTS.md §4.3: a DCQL mismatch is a policy verdict, not a fault.
    assert_eq!(status, StatusCode::OK);

    // The request event fires first (the wallet fetched `/vp/request/:id`),
    // so skip forward to the verdict.
    let event = loop {
        match support::next_event(&mut rx).await {
            e @ foundry_verifier::WebhookEvent::VerificationCompleted { .. } => break e,
            foundry_verifier::WebhookEvent::PresentationRequestDelivered { .. } => continue,
        }
    };

    match event {
        foundry_verifier::WebhookEvent::VerificationCompleted {
            state: tx_state,
            result,
            vp_token,
            ..
        } => {
            assert_eq!(tx_state, foundry_verifier::VerificationState::Failed);
            assert!(!result.verified, "the verdict travels with the event");
            assert!(vp_token.is_some(), "artifacts are on for this fixture");
        }
        other => panic!("expected VerificationCompleted, got {other:?}"),
    }
}

/// With artifacts off, the verdict still travels but the PII does not.
#[tokio::test]
async fn the_verdict_is_delivered_without_artifacts_by_default() {
    let (state, _dir, issuer_cert_pem, issuer_key_pem) = setup_with_webhook(false).await;
    let (sink, mut rx) = support::recording_sink();
    let state = state.with_webhook_sink(sink);

    let (status, _body) =
        run_successful_presentation(state, &issuer_cert_pem, &issuer_key_pem).await;
    assert_eq!(status, StatusCode::OK);

    let event = loop {
        match support::next_event(&mut rx).await {
            e @ foundry_verifier::WebhookEvent::VerificationCompleted { .. } => break e,
            foundry_verifier::WebhookEvent::PresentationRequestDelivered { .. } => continue,
        }
    };

    match event {
        foundry_verifier::WebhookEvent::VerificationCompleted {
            result, vp_token, ..
        } => {
            assert!(result.verified);
            assert!(vp_token.is_none(), "artifacts must be off by default");
        }
        other => panic!("expected VerificationCompleted, got {other:?}"),
    }
}

/// Drop the members of a verdict body that legitimately differ between two
/// runs of the same flow: the credential's `iat`/`exp` are wall-clock seconds
/// and `cnf.jwk` is a freshly generated holder key. Everything else --
/// `verified`, every check name and outcome, `query_id`, `format`,
/// `credential_type`, and the disclosed `given_name` -- is deterministic and
/// stays in the comparison.
///
/// Normalizing rather than asserting a hardcoded body keeps the assertion
/// "identical to no-sink", which is the property under test, instead of an
/// expectation that drifts with the response shape.
fn strip_per_run_members(body: &mut serde_json::Value) {
    let Some(creds) = body.get_mut("credentials").and_then(|c| c.as_array_mut()) else {
        return;
    };
    for cred in creds {
        if let Some(claims) = cred.get_mut("claims").and_then(|c| c.as_object_mut()) {
            claims.remove("iat");
            claims.remove("exp");
            claims.remove("cnf");
        }
    }
}

/// §4.3: a broken sink must not be visible to the wallet.
#[tokio::test]
async fn a_failing_sink_does_not_change_the_wallet_response() {
    // Run the SAME successful flow twice and compare, so the assertion is
    // "identical to no-sink" rather than a hardcoded expectation that could
    // drift with the response shape.
    let (baseline_status, mut baseline_body) = {
        let (state, _dir, cert, key) = setup_with_webhook(true).await;
        // no sink attached
        run_successful_presentation(state, &cert, &key).await
    };

    let (with_sink_status, mut with_sink_body) = {
        let (state, _dir, cert, key) = setup_with_webhook(true).await;
        let state = state.with_webhook_sink(std::sync::Arc::new(support::FailingSink));
        run_successful_presentation(state, &cert, &key).await
    };

    strip_per_run_members(&mut baseline_body);
    strip_per_run_members(&mut with_sink_body);

    assert_eq!(baseline_status, with_sink_status);
    assert_eq!(baseline_body, with_sink_body);
    // Guard against the normalizer hollowing out the comparison.
    assert_eq!(baseline_body["verified"], true);
    assert_eq!(
        baseline_body["credentials"][0]["claims"]["given_name"],
        "Alice"
    );
}
