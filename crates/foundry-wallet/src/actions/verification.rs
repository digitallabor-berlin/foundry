//! Orchestrates the full OpenID4VP flow: obtain a request (preset-created or
//! consumed via deep link) -> parse+trust-validate the signed request object
//! -> match stored credentials -> consent -> build/encrypt/submit the
//! response. See the design doc section 7.

use crate::actions::http_util::{build_trust_store, ensure_2xx};
use crate::actions::match_credentials::match_credentials;
use crate::actions::request_source::parse_request_deep_link;
use crate::actions::trust::validate_jws_x5c_chain;
use crate::config::{TrustValidationMode, WalletConfig};
use crate::error::{WalletError, WalletResult};
use crate::http::LoggingHttpClient;
use crate::storage::credential_store::{load_compact_sdjwt, load_holder_key_pem};
use crate::storage::event_log;
use crate::storage::now_rfc3339;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_core::crypto::jwe::encrypt_compact;
use foundry_core::crypto::{FileSigner, SignatureAlgorithm};
use foundry_sd_jwt_vc::builder::attach_kb_jwt;
use foundry_verifier::{CreateVerificationResponse, VerificationResult};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Accept,
    Decline,
}

#[derive(Debug)]
pub enum VerificationOutcome {
    Verified(VerificationResult),
    Declined,
}

pub async fn run_verification(
    config: &WalletConfig,
    preset: Option<&str>,
    request_uri: Option<&str>,
    consent: Consent,
) -> WalletResult<VerificationOutcome> {
    let http = LoggingHttpClient::new(&config.data_dir);

    // Step 1: obtain the request.
    let request_url = match request_uri {
        Some(uri) => parse_request_deep_link(uri)?,
        None => {
            let preset_name = preset.ok_or_else(|| {
                WalletError::Config("either --preset or --request-uri is required".to_string())
            })?;
            let preset = config
                .verification_presets
                .get(preset_name)
                .ok_or_else(|| {
                    WalletError::Config(format!("unknown verification preset '{preset_name}'"))
                })?;
            let admin_api_key = config.endpoints.resolve_admin_api_key()?;
            let url = format!(
                "{}/admin/verification/requests",
                config.endpoints.admin_base_url
            );
            let body = serde_json::json!({
                "dcql_query": preset.dcql_query,
                "transport": preset.transport,
            });
            let (status, resp_body) = http.post_json(&url, Some(&admin_api_key), &body).await?;
            ensure_2xx(status, &url, &resp_body)?;
            let create_resp: CreateVerificationResponse = serde_json::from_str(&resp_body)?;
            // Note: `create_resp.request_uri` is built server-side from the
            // verifier's configured `public_base_url`, which may not be the
            // actually-reachable wallet-facing address the wallet client
            // must hit (e.g. in tests, `public_base_url` is a symbolic issuer
            // hostname while the real listener is on an ephemeral local
            // port). Reconstruct the URL from the wallet's own configured
            // `wallet_base_url` plus the verification_id instead.
            format!(
                "{}/vp/request/{}",
                config.endpoints.wallet_base_url, create_resp.verification_id
            )
        }
    };

    let (status, jws_str) = http.get(&request_url, None).await?;
    ensure_2xx(status, &request_url, &jws_str)?;

    // Step 2: parse and (optionally) trust-validate the signed request object.
    let parts: Vec<&str> = jws_str.split('.').collect();
    if parts.len() != 3 {
        return Err(WalletError::MalformedRequestObject(
            "request object is not a compact JWS".to_string(),
        ));
    }
    let request_object: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(parts[1]).map_err(|e| {
            WalletError::MalformedRequestObject(format!(
                "invalid base64 in request object payload: {e}"
            ))
        })?)?;
    let client_id = request_object["client_id"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedRequestObject("missing client_id".to_string()))?
        .to_string();
    let nonce = request_object["nonce"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedRequestObject("missing nonce".to_string()))?
        .to_string();
    let dcql_query = request_object["dcql_query"].clone();
    let ephemeral_jwk = request_object["client_metadata"]["jwks"]["keys"][0].clone();

    if config.trust.validation == TrustValidationMode::Enabled {
        let store = build_trust_store(config)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let outcome = validate_jws_x5c_chain(&jws_str, &store, now);
        event_log::append_event(
            &config.data_dir,
            &serde_json::json!({
                "ts": now_rfc3339(), "kind": "trust_validation_result",
                "context": "verification_request", "valid": outcome.valid, "detail": outcome.detail,
            }),
        )?;
        if !outcome.valid {
            return Err(WalletError::TrustValidation(outcome.detail));
        }
    }

    // Step 3: match stored credentials.
    let matches = match_credentials(&config.data_dir, &dcql_query)?;
    let matched = matches.first().ok_or(WalletError::NoMatchingCredential)?;

    // Step 4: consent.
    event_log::append_event(
        &config.data_dir,
        &serde_json::json!({
            "ts": now_rfc3339(), "kind": "consent_decision",
            "client_id": client_id, "credential_id": matched.credential_id,
            "decision": if consent == Consent::Accept { "accept" } else { "decline" },
        }),
    )?;
    if consent == Consent::Decline {
        return Ok(VerificationOutcome::Declined);
    }

    // Step 5: build the presentation and submit.
    let compact = load_compact_sdjwt(&config.data_dir, &matched.credential_id)?;
    let holder_key_pem = load_holder_key_pem(&config.data_dir, &matched.credential_id)?;
    let holder_signer =
        FileSigner::from_pem(&holder_key_pem, SignatureAlgorithm::Es256).map_err(|e| {
            WalletError::MalformedRequestObject(format!("invalid stored holder key: {e}"))
        })?;
    let presentation = attach_kb_jwt(compact, &holder_signer, &client_id, &nonce)
        .map_err(|e| WalletError::MalformedRequestObject(format!("attach_kb_jwt failed: {e}")))?;

    // OpenID4VP 1.0 section 8.1: `vp_token` is an object keyed by the DCQL
    // credential query id this presentation answers, and each value is an ARRAY
    // of presentations. A bare string here is what the verifier used to accept,
    // and no conformant wallet sends it. The key is dynamic, so the map is built
    // explicitly rather than through a `json!` key literal.
    let mut vp_token = serde_json::Map::new();
    vp_token.insert(
        matched.query_id.clone(),
        serde_json::Value::Array(vec![serde_json::Value::String(presentation)]),
    );

    // `encrypt_compact` parses the recipient JWK and encrypts in a single step,
    // so the two former failure points (invalid ephemeral JWK, then build
    // failure) collapse into one error. The underlying josekit message still
    // names which of the two actually went wrong.
    let jwe_str = encrypt_compact(
        &serde_json::json!({ "vp_token": serde_json::Value::Object(vp_token) }),
        &ephemeral_jwk,
        "ECDH-ES",
        "A128GCM",
    )
    .map_err(|e| WalletError::MalformedRequestObject(format!("JWE build failed: {e}")))?;

    let response_url = format!(
        "{}/vp/response/{}",
        config.endpoints.wallet_base_url,
        request_url.rsplit('/').next().ok_or_else(|| {
            WalletError::MalformedRequestObject("request url has no path segment".to_string())
        })?
    );
    // OpenID4VP 1.0 §8.2/§8.3: a `direct_post.jwt` response is form-encoded with
    // the JWE in a `response` parameter. No percent-encoding is needed for the
    // value — a JWE compact serialization is base64url (`A-Z a-z 0-9 - _`) plus
    // `.` separators, every one of which is RFC 3986 unreserved.
    let form = format!("response={jwe_str}");
    let (status, resp_body) = http.post_form(&response_url, None, &form).await?;
    ensure_2xx(status, &response_url, &resp_body)?;
    let result: VerificationResult = serde_json::from_str(&resp_body)?;
    Ok(VerificationOutcome::Verified(result))
}
