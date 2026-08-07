//! Google Wallet's `android_keystore_attestation` proof type, end to end through
//! the wallet-facing router.
//!
//! Design: docs/superpowers/specs/2026-08-04-android-keystore-attestation-proof-design.md
//!
//! Every test follows the same order, and the order is load-bearing: create the
//! anchor, build the `AppState` from it, mint a `c_nonce` from *that* state, then
//! build a chain whose `attestationChallenge` is that nonce. Minting before the
//! final state exists risks a nonce the state cannot verify.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use foundry::server::{AppState, wallet_router};
use support::{
    body_json, create_proof, issue_pre_auth_offer_and_get_access_token, mint_c_nonce,
    setup_with_android_keystore, setup_without_encryption, synthetic_android_chain,
};
use tower::ServiceExt;

const ISSUER: &str = "https://issuer.example.com";

async fn post_credential(
    state: &AppState,
    access_token: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    let app = wallet_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(body.to_string()))
        .expect("request builds");
    app.oneshot(req).await.expect("response")
}

async fn get_json(state: &AppState, uri: &str) -> serde_json::Value {
    let app = wallet_router(state.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("response");
    body_json(res).await
}

#[tokio::test]
async fn issues_a_credential_bound_to_the_attested_hardware_key() {
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&ca, nonce.as_bytes());

    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "credential_configuration_id": "pid", "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a genuine chain anchored on a configured root must be accepted"
    );
    let json = body_json(res).await;
    assert_eq!(
        json["credentials"].as_array().map(Vec::len),
        Some(1),
        "one chain yields one credential: {json}"
    );
}

#[tokio::test]
async fn two_chains_yield_two_credentials() {
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let first = synthetic_android_chain(&ca, nonce.as_bytes());
    let second = synthetic_android_chain(&ca, nonce.as_bytes());

    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({
            "credential_configuration_id": "pid",
            "proofs": { "android_keystore_attestation": [first, second] }
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;
    assert_eq!(
        json["credentials"].as_array().map(Vec::len),
        Some(2),
        "{json}"
    );
}

#[tokio::test]
async fn the_default_configuration_rejects_the_proof_type() {
    // `setup_without_encryption` leaves `android.mode` at its `disabled` default.
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_without_encryption().await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&ca, nonce.as_bytes());
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "credential_configuration_id": "pid", "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_proof");
}

#[tokio::test]
async fn an_unanchored_chain_is_400_invalid_proof_never_500() {
    // The HTTP half of the regression test for `IssuanceError::Trust` falling
    // through `wallet_error_response`'s catch-all arm to 500: the chain is
    // signed by a CA the issuer does not trust.
    let trusted = foundry_core::pki::new_ca("Trusted Root", 3650).expect("CA");
    let impostor = foundry_core::pki::new_ca("Impostor Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&trusted.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&impostor, nonce.as_bytes());

    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "credential_configuration_id": "pid", "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "an untrusted chain is a client fault, not a server error"
    );
    assert_eq!(body_json(res).await["error"], "invalid_proof");
}

#[tokio::test]
async fn a_forged_challenge_is_400_invalid_nonce() {
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let chain = synthetic_android_chain(&ca, b"not-a-minted-c-nonce");
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({ "credential_configuration_id": "pid", "proofs": { "android_keystore_attestation": [chain] } }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        "invalid_nonce",
        "a present-but-unauthentic challenge is invalid_nonce, not invalid_proof"
    );
}

#[tokio::test]
async fn two_proof_types_in_one_request_are_rejected() {
    // OpenID4VCI Credential Request (L852): exactly one proof type.
    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (state, _dir) = setup_with_android_keystore(&ca.cert_pem).await;
    let nonce = mint_c_nonce(&state).await;
    let chain = synthetic_android_chain(&ca, nonce.as_bytes());
    let token = issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = post_credential(
        &state,
        &token,
        serde_json::json!({
            "credential_configuration_id": "pid",
            "proofs": {
                "jwt": [create_proof(&nonce, ISSUER)],
                "android_keystore_attestation": [chain],
            }
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_proof");
}

#[tokio::test]
async fn metadata_advertises_the_proof_type_only_when_enabled() {
    let (off, _d1) = setup_without_encryption().await;
    let json = get_json(&off, "/.well-known/openid-credential-issuer").await;
    let configs = json["credential_configurations_supported"]
        .as_object()
        .expect("configurations");
    assert!(
        !configs.is_empty(),
        "the fixture config has credential types"
    );
    for (id, cfg) in configs {
        assert!(
            cfg["proof_types_supported"]["android_keystore_attestation"].is_null(),
            "{id} must not advertise a disabled proof type"
        );
    }

    let ca = foundry_core::pki::new_ca("Synthetic Android Root", 3650).expect("CA");
    let (on, _d2) = setup_with_android_keystore(&ca.cert_pem).await;
    let json = get_json(&on, "/.well-known/openid-credential-issuer").await;
    let configs = json["credential_configurations_supported"]
        .as_object()
        .expect("configurations");
    for (id, cfg) in configs {
        let entry = &cfg["proof_types_supported"]["android_keystore_attestation"];
        assert_eq!(
            entry["proof_signing_alg_values_supported"][0], "ES256",
            "{id}"
        );
        assert_eq!(
            entry["key_attestations_required"]["key_mint_security_level"], "TrustedEnvironment",
            "{id}"
        );
    }
}
