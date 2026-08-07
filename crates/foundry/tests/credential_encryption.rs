//! The Credential Endpoint's encrypted request/response path.
//!
//! Drives the real wallet router over HTTP the way a wallet would: reads the
//! issuer's published JWKS from metadata, builds the request JWE itself with
//! `foundry_core::crypto::jwe`, and decrypts the response with its own key.
//! There is no wallet crate — the test *is* the client.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use foundry::server::wallet_router;
use tower::ServiceExt;

/// The wallet's ephemeral response-encryption keypair, as `(annotated public,
/// bare private)`.
fn wallet_response_key() -> (serde_json::Value, serde_json::Value) {
    let kp =
        josekit::jwk::alg::ec::EcKeyPair::generate(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let mut public = serde_json::to_value(josekit::jwk::KeyPair::to_jwk_public_key(&kp)).unwrap();
    if let Some(o) = public.as_object_mut() {
        o.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    }
    let private = serde_json::to_value(josekit::jwk::KeyPair::to_jwk_private_key(&kp)).unwrap();
    (public, private)
}

#[tokio::test]
async fn an_encrypted_request_yields_an_encrypted_response() {
    let (state, _dir) = support::setup_with_encryption().await;
    let access_token = support::issue_pre_auth_offer_and_get_access_token(&state).await;
    let c_nonce = support::mint_c_nonce(&state).await;
    let proof_jwt = support::create_proof(&c_nonce, "https://issuer.example.com");
    let app = wallet_router(state);

    // The issuer's published request-encryption key, read from metadata exactly
    // as a wallet would.
    let meta_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta: serde_json::Value = support::body_json(meta_res).await;
    let issuer_jwk = meta["credential_request_encryption"]["jwks"]["keys"][0].clone();
    let issuer_kid = issuer_jwk["kid"].as_str().unwrap().to_string();

    let (wallet_public, wallet_private) = wallet_response_key();
    let body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
        "credential_response_encryption": { "jwk": wallet_public, "enc": "A128GCM" },
    });
    let jwe = foundry_core::crypto::jwe::encrypt_compact_with_kid(
        &body,
        &issuer_jwk,
        "ECDH-ES",
        "A256GCM",
        Some(&issuer_kid),
    )
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/jwt")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(jwe))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt"),
        "OpenID4VCI L1186: an encrypted Credential Response uses application/jwt"
    );

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let compact = String::from_utf8(bytes.to_vec()).unwrap();
    let jwk =
        josekit::jwk::Jwk::from_bytes(serde_json::to_string(&wallet_private).unwrap().as_bytes())
            .unwrap();
    let decrypter = josekit::jwe::ECDH_ES.decrypter_from_jwk(&jwk).unwrap();
    let (payload, jwe_header) = josekit::jwt::decode_with_decrypter(&compact, &decrypter).unwrap();
    assert_eq!(
        jwe_header.content_encryption(),
        Some("A128GCM"),
        "OpenID4VCI L969: the issuer encrypts with the wallet's chosen `enc`"
    );
    let decrypted = serde_json::to_value(payload.claims_set()).unwrap();
    assert!(
        decrypted["credentials"][0]["credential"].is_string(),
        "decrypted response was {decrypted}"
    );
}

#[tokio::test]
async fn a_plaintext_request_still_gets_a_plaintext_response() {
    let (state, _dir) = support::setup_with_encryption().await;
    let access_token = support::issue_pre_auth_offer_and_get_access_token(&state).await;
    let c_nonce = support::mint_c_nonce(&state).await;
    let proof_jwt = support::create_proof(&c_nonce, "https://issuer.example.com");
    let body = serde_json::json!({
        "credential_configuration_id": "pid",
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof_jwt] },
    });
    let res = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "encryption is opt-in per request; an unencrypted request stays unencrypted"
    );
}

#[tokio::test]
async fn application_jwt_is_415_when_the_feature_is_off() {
    let (state, _dir) = support::setup_without_encryption().await;
    let access_token = support::issue_pre_auth_offer_and_get_access_token(&state).await;
    let res = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(header::CONTENT_TYPE, "application/jwt")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from("a.b.c.d.e"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "an issuer that cannot decrypt must not appear to accept application/jwt"
    );
}
