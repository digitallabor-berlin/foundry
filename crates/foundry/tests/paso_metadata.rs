//! PaSO Proof Metadata §2, §4, §7, §8 — the wallet-facing credential metadata
//! endpoint, end to end over HTTP.

mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Value, json};

fn decode_part(jwt: &str, index: usize) -> Value {
    let part = jwt.split('.').nth(index).expect("segment");
    serde_json::from_slice(&B64URL.decode(part).expect("b64url")).expect("json")
}

async fn body_text(res: axum::http::Response<axum::body::Body>) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8 body")
}

/// §2: `Accept: application/jwt` returns the signed form with the media type
/// the spec names.
#[tokio::test]
async fn accept_application_jwt_returns_a_signed_credential_metadata_jwt() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept(
            "/credential-metadata/BankPaymentCard",
            Some("application/jwt"),
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt")
    );

    let jwt = body_text(resp).await;
    assert_eq!(jwt.split('.').count(), 3, "compact JWS has three segments");
    assert_eq!(
        decode_part(&jwt, 0)["typ"],
        json!("credential-metadata+jwt")
    );
}

/// §2: the plain JSON form is the bare `credential_metadata` object — NOT the
/// JWT payload structure of §4. A client must not find `iss`/`exp` here.
#[tokio::test]
async fn accept_application_json_returns_the_bare_metadata_object() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept(
            "/credential-metadata/BankPaymentCard",
            Some("application/json"),
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = support::body_json(resp).await;

    assert!(body["transaction_data_types"]["urn:paso:sca:global:payment:1"]["claims"].is_array());
    assert!(
        body.get("credential_metadata").is_none(),
        "not the JWT envelope"
    );
    assert!(body.get("iss").is_none(), "not the JWT envelope");
    assert!(body.get("exp").is_none(), "not the JWT envelope");
}

/// §2: absent `Accept` defaults to `application/json`.
#[tokio::test]
async fn an_absent_accept_header_defaults_to_json() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/credential-metadata/BankPaymentCard", None)
        .await;

    assert_eq!(resp.status(), 200);
    let body = support::body_json(resp).await;
    assert!(body["transaction_data_types"].is_object());
}

#[tokio::test]
async fn an_unsatisfiable_accept_is_406() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/credential-metadata/BankPaymentCard", Some("text/html"))
        .await;

    assert_eq!(resp.status(), 406);
}

#[tokio::test]
async fn an_unknown_configuration_id_is_404() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept("/credential-metadata/NoSuchType", Some("application/jwt"))
        .await;

    assert_eq!(resp.status(), 404);
}

/// A configured but non-PaSO credential type has no conformant document to
/// return (§3 makes `transaction_data_types` REQUIRED here), so it 404s exactly
/// like an unknown id.
#[tokio::test]
async fn a_non_paso_configuration_id_is_404() {
    let env = support::paso_test_env().await;

    let resp = env
        .wallet_get_with_accept(
            &format!("/credential-metadata/{}", support::NON_PASO_TYPE_ID),
            Some("application/jwt"),
        )
        .await;

    assert_eq!(resp.status(), 404);
}

/// §2: Issuer Metadata advertises the URI for PaSO configurations only, and the
/// advertised value must be exactly what §8's binding check compares against.
#[tokio::test]
async fn issuer_metadata_advertises_the_uri_for_paso_types_only() {
    let env = support::paso_test_env().await;
    let expected = format!(
        "{}/credential-metadata/BankPaymentCard",
        env.credential_issuer()
    );

    let resp = env
        .wallet_get_with_accept("/.well-known/openid-credential-issuer", None)
        .await;
    let md = support::body_json(resp).await;
    let configs = md["credential_configurations_supported"]
        .as_object()
        .expect("configurations");

    let paso = &configs["BankPaymentCard"];
    assert_eq!(
        paso["credential_metadata_uri"].as_str(),
        Some(expected.as_str())
    );

    let non_paso = &configs[support::NON_PASO_TYPE_ID];
    assert!(
        non_paso.get("credential_metadata_uri").is_none(),
        "a non-PaSO configuration must not advertise the URI"
    );
}

/// **The §7 verification test.** foundry publishes; a Wallet verifies. With no
/// wallet client in this repo, this test performs the Wallet's checks in
/// process against a JWT fetched over real HTTP — proving the artifact is
/// verifiable, not merely well-formed.
///
/// Steps mirror §7: (1) `typ`; (2) signature; (3) `x5c` chain; (4) `iss`;
/// (5) `exp`; (6) credential binding via `sub`. Plus §8's URI binding.
#[tokio::test]
async fn a_fetched_metadata_jwt_passes_the_wallet_side_verification() {
    let env = support::paso_test_env().await;
    let url = format!(
        "{}/credential-metadata/BankPaymentCard",
        env.credential_issuer()
    );
    let issuer = env.credential_issuer().to_string();

    let resp = env
        .wallet_get_with_accept(
            "/credential-metadata/BankPaymentCard",
            Some("application/jwt"),
        )
        .await;
    let jwt = body_text(resp).await;

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = decode_part(&jwt, 0);
    let payload = decode_part(&jwt, 1);

    // §7 step 1 -- typ.
    assert_eq!(header["typ"], json!("credential-metadata+jwt"));

    // §7 step 3 -- the chain is present and usable. foundry takes the x5c
    // branch; §4's kid/key-set alternative is unimplemented by design.
    let chain = header["x5c"].as_array().expect("x5c chain");
    assert!(!chain.is_empty());
    assert!(
        header.get("kid").is_none(),
        "§4: with x5c, kid SHALL NOT be used"
    );

    // §7 step 2 -- verify the signature against the leaf certificate's public
    // key. The x5c entry is base64-STANDARD DER; `x5c_entry_to_pem` and
    // `cert_ec_public_coords` are the same pair `status_list.rs` uses to verify
    // a Status List Token's x5c-signed JWS.
    let leaf_b64 = chain[0].as_str().expect("leaf entry is a string");
    let leaf_pem = foundry_core::trust::x5c_entry_to_pem(leaf_b64).expect("leaf pem");
    let leaf = foundry_core::trust::parse_cert_pem(&leaf_pem).expect("parse leaf");
    let (x, y) = foundry_core::trust::cert_ec_public_coords(&leaf).expect("ec coords");

    let jwk_value = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64URL.encode(&x),
        "y": B64URL.encode(&y),
    });
    let jwk = josekit::jwk::Jwk::from_map(
        jwk_value
            .as_object()
            .cloned()
            .expect("jwk value is an object"),
    )
    .expect("jwk");
    let verifier = josekit::jws::ES256
        .verifier_from_jwk(&jwk)
        .expect("verifier");

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = B64URL.decode(parts[2]).expect("b64url signature");
    verifier
        .verify(signing_input.as_bytes(), &signature)
        .expect("§7 step 2: the metadata JWT must verify against its own x5c leaf");

    // A negative control: the same verifier must reject a tampered payload, so
    // the assertion above cannot pass vacuously.
    let tampered = format!("{}.{}", parts[0], B64URL.encode(b"{\"iss\":\"evil\"}"));
    assert!(
        verifier.verify(tampered.as_bytes(), &signature).is_err(),
        "signature verification must actually be checking the payload"
    );

    // §7 step 4 -- iss.
    assert_eq!(payload["iss"].as_str(), Some(issuer.as_str()));

    // §7 step 5 -- exp is in the future.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    assert!(payload["exp"].as_i64().expect("exp") > now);

    // §7 step 6 -- credential binding: `sub` is the credential's type
    // identifier (`vct` for SD-JWT VC), and explicitly not the device-signed
    // namespace `urn:paso:sca:1`.
    assert_eq!(payload["sub"], json!("https://bank.example/sca/card"));
    assert_ne!(payload["sub"], json!("urn:paso:sca:1"));
    assert_eq!(payload["format"], json!("dc+sd-jwt"));

    // §8 -- URI binding: the claim equals the URI the JWT was retrieved from.
    assert_eq!(
        payload["credential_metadata_uri"].as_str(),
        Some(url.as_str())
    );
}

/// §4: minted per request, so two fetches are independently valid artifacts.
/// (They need not be byte-identical — nothing in PaSO requires that, and §8
/// wants retrieval decorrelated from use.)
#[tokio::test]
async fn each_fetch_yields_an_independently_valid_jwt() {
    let env = support::paso_test_env().await;

    for _ in 0..2 {
        let resp = env
            .wallet_get_with_accept(
                "/credential-metadata/BankPaymentCard",
                Some("application/jwt"),
            )
            .await;
        assert_eq!(resp.status(), 200);
        let jwt = body_text(resp).await;
        assert_eq!(
            decode_part(&jwt, 0)["typ"],
            json!("credential-metadata+jwt")
        );
    }
}
