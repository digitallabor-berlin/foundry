//! PaSO Proof Metadata §5 — the admin ad-hoc metadata mint endpoint.

mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Value, json};

fn decode_part(jwt: &str, index: usize) -> Value {
    let part = jwt.split('.').nth(index).expect("segment");
    serde_json::from_slice(&B64URL.decode(part).expect("b64url")).expect("json")
}

#[tokio::test]
async fn minting_an_adhoc_metadata_jwt_returns_a_signed_artifact() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1"
            }),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = support::body_json(resp).await;
    let jwt = body["jwt"].as_str().expect("jwt string");

    assert_eq!(
        decode_part(jwt, 0)["typ"],
        json!("adhoc-transaction-metadata+jwt")
    );
    let payload = decode_part(jwt, 1);
    assert_eq!(
        payload["transaction_data_type"],
        json!("urn:paso:sca:global:payment:1")
    );
    assert_eq!(body["exp"], payload["exp"]);
}

/// §5.4: a valid ad-hoc JWT makes a type supported "even if it is absent from
/// the signed credential metadata", so an override may introduce a new type.
#[tokio::test]
async fn an_override_may_introduce_an_unconfigured_type() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:com.example.pay:transaction:2",
                "metadata": {
                    "claims": [
                        { "path": ["reward_points"], "display": [{ "name": "Points" }] }
                    ]
                }
            }),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = support::body_json(resp).await;
    let payload = decode_part(body["jwt"].as_str().expect("jwt"), 1);
    assert_eq!(
        payload["metadata"]["claims"][0]["path"][0],
        json!("reward_points")
    );
}

#[tokio::test]
async fn an_unknown_credential_type_is_a_400() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "NoSuchType",
                "transaction_data_type": "urn:paso:sca:global:payment:1"
            }),
        )
        .await;

    assert_eq!(resp.status(), 400);
}

/// An unconfigured type with no override has nothing to describe — §5.4's
/// "considered supported" only applies when an override actually supplies the
/// metadata.
#[tokio::test]
async fn an_unconfigured_type_without_an_override_is_a_400() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:unknown:1"
            }),
        )
        .await;

    assert_eq!(resp.status(), 400);
}

/// An override is held to exactly the config-time rules of §3.1.
#[tokio::test]
async fn a_structurally_invalid_override_is_a_400() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1",
                "metadata": {
                    "claims": [{ "path": ["amount"], "value_type": "iso_currency_amount" }]
                }
            }),
        )
        .await;

    assert_eq!(resp.status(), 400);
}

/// §5.2: an explicit `ttl_secs` bounds how long a Relying Party may cache and
/// reuse the JWT, and the echoed `exp` must agree with the signed one.
#[tokio::test]
async fn an_explicit_ttl_is_reflected_in_both_exp_values() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1",
                "ttl_secs": 60
            }),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = support::body_json(resp).await;
    let payload = decode_part(body["jwt"].as_str().expect("jwt"), 1);

    let iat = payload["iat"].as_i64().expect("iat");
    assert_eq!(payload["exp"].as_i64(), Some(iat + 60));
    assert_eq!(body["exp"], payload["exp"]);
}

#[tokio::test]
async fn the_route_requires_the_admin_api_key() {
    let env = support::paso_test_env().await;

    let resp = env
        .admin_post_without_key(
            "/admin/paso/ad-hoc-metadata",
            json!({
                "credential_type_id": "BankPaymentCard",
                "transaction_data_type": "urn:paso:sca:global:payment:1"
            }),
        )
        .await;

    assert!(
        resp.status() == 401 || resp.status() == 403,
        "expected an auth rejection, got {}",
        resp.status()
    );
}
