//! Orchestrates the full OpenID4VCI flow: obtain an offer (preset-created or
//! consumed via deep link) -> `/token` -> `/nonce` -> proof -> `/credential`
//! -> trust validation -> file storage. See the design doc section 6.

use crate::actions::http_util::{build_trust_store, ensure_2xx};
use crate::actions::offer_source::{parse_offer_deep_link, OfferSource};
use crate::actions::proof::build_proof_jwt;
use crate::actions::trust::validate_jws_x5c_chain;
use crate::config::{TrustValidationMode, WalletConfig};
use crate::error::{WalletError, WalletResult};
use crate::http::LoggingHttpClient;
use crate::storage::credential_store::{store_credential, CredentialMetadata, NewCredential};
use crate::storage::{ensure_data_dir_layout, event_log, now_rfc3339};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use foundry_issuer::CreateOfferResponse;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct IssuanceOutcome {
    pub credential_id: String,
    pub vct: String,
    pub trust_valid: Option<bool>,
}

pub async fn run_issuance(
    config: &WalletConfig,
    preset: Option<&str>,
    offer_uri: Option<&str>,
    tx_code: Option<&str>,
) -> WalletResult<IssuanceOutcome> {
    ensure_data_dir_layout(&config.data_dir)?;
    let http = LoggingHttpClient::new(&config.data_dir);

    // Step 1: obtain the offer.
    let offer = match offer_uri {
        Some(uri) => match parse_offer_deep_link(uri)? {
            OfferSource::Inline(offer) => offer,
            OfferSource::RemoteUri(url) => {
                let (status, body) = http.get(&url, None).await?;
                ensure_2xx(status, &url, &body)?;
                serde_json::from_str(&body)?
            }
        },
        None => {
            let preset_name = preset.ok_or_else(|| {
                WalletError::Config("either --preset or --offer-uri is required".to_string())
            })?;
            let preset = config.issuance_presets.get(preset_name).ok_or_else(|| {
                WalletError::Config(format!("unknown issuance preset '{preset_name}'"))
            })?;
            let admin_api_key = config.endpoints.resolve_admin_api_key()?;
            let url = format!("{}/admin/issuance/offers", config.endpoints.admin_base_url);
            let body = serde_json::json!({
                "credential_type_id": preset.credential_type_id,
                "claims": preset.claims,
                "tx_code_required": preset.tx_code_required,
            });
            let (status, resp_body) = http.post_json(&url, Some(&admin_api_key), &body).await?;
            ensure_2xx(status, &url, &resp_body)?;
            let create_offer_response: CreateOfferResponse = serde_json::from_str(&resp_body)?;
            create_offer_response.credential_offer
        }
    };

    // Step 2: token.
    let grant = offer.grants.pre_authorized_code.as_ref().ok_or_else(|| {
        WalletError::MalformedOffer(
            "offer has no pre-authorized_code grant; this debug wallet only supports the pre-authorized_code flow"
                .to_string(),
        )
    })?;
    let mut form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={}",
        grant.pre_authorized_code
    );
    if let Some(code) = tx_code {
        form.push_str(&format!("&tx_code={code}"));
    }
    let token_url = format!("{}/token", config.endpoints.wallet_base_url);
    let (status, token_body) = http.post_form(&token_url, None, &form).await?;
    ensure_2xx(status, &token_url, &token_body)?;
    let token_json: serde_json::Value = serde_json::from_str(&token_body)?;
    let access_token = token_json["access_token"]
        .as_str()
        .ok_or_else(|| {
            WalletError::MalformedOffer("token response missing access_token".to_string())
        })?
        .to_string();

    // Step 3: nonce.
    let nonce_url = format!("{}/nonce", config.endpoints.wallet_base_url);
    let (status, nonce_body) = http.post_empty(&nonce_url, Some(&access_token)).await?;
    ensure_2xx(status, &nonce_url, &nonce_body)?;
    let nonce_json: serde_json::Value = serde_json::from_str(&nonce_body)?;
    let c_nonce = nonce_json["c_nonce"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedOffer("nonce response missing c_nonce".to_string()))?;

    // Step 4: holder key + proof.
    let proof = build_proof_jwt(c_nonce, &offer.credential_issuer)?;

    // Step 5: credential.
    let credential_configuration_id =
        offer.credential_configuration_ids.first().ok_or_else(|| {
            WalletError::MalformedOffer("offer has no credential_configuration_ids".to_string())
        })?;
    let cred_url = format!("{}/credential", config.endpoints.wallet_base_url);
    let cred_req = serde_json::json!({
        "credential_configuration_id": credential_configuration_id,
        "format": "dc+sd-jwt",
        "proofs": { "jwt": [proof.jwt] },
    });
    let (status, cred_body) = http
        .post_json(&cred_url, Some(&access_token), &cred_req)
        .await?;
    ensure_2xx(status, &cred_url, &cred_body)?;
    let cred_json: serde_json::Value = serde_json::from_str(&cred_body)?;
    let compact = cred_json["credentials"][0]["credential"]
        .as_str()
        .ok_or_else(|| {
            WalletError::MalformedOffer(
                "credential response missing 'credentials[0].credential'".to_string(),
            )
        })?
        .to_string();

    // Decode issuer JWT (first `~`-segment) and disclosures.
    let issuer_jwt = compact.split('~').next().ok_or_else(|| {
        WalletError::MalformedOffer("credential is not a compact SD-JWT VC".to_string())
    })?;
    let jwt_parts: Vec<&str> = issuer_jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(WalletError::MalformedOffer(
            "issuer-signed JWT is not a compact JWS".to_string(),
        ));
    }
    let header: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(jwt_parts[0]).map_err(|e| {
            WalletError::MalformedOffer(format!("invalid base64 in JWT header: {e}"))
        })?)?;
    let issuer_payload: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(jwt_parts[1]).map_err(|e| {
            WalletError::MalformedOffer(format!("invalid base64 in JWT payload: {e}"))
        })?)?;
    let vct = issuer_payload["vct"]
        .as_str()
        .ok_or_else(|| WalletError::MalformedOffer("issuer JWT payload missing vct".to_string()))?
        .to_string();
    let issuer = issuer_payload["iss"].as_str().unwrap_or("").to_string();
    let status_list_uri = issuer_payload["status"]["status_list"]["uri"]
        .as_str()
        .map(|s| s.to_string());
    let status_list_idx = issuer_payload["status"]["status_list"]["idx"].as_u64();

    let mut disclosed_claims = serde_json::Map::new();
    for seg in compact.split('~').skip(1).filter(|s| !s.is_empty()) {
        let arr: serde_json::Value = serde_json::from_slice(&B64URL.decode(seg).map_err(|e| {
            WalletError::MalformedOffer(format!("invalid base64 in disclosure: {e}"))
        })?)?;
        if let Some(arr) = arr.as_array() {
            if arr.len() == 3 {
                if let Some(name) = arr[1].as_str() {
                    disclosed_claims.insert(name.to_string(), arr[2].clone());
                }
            }
        }
    }

    // Step 6: trust validation (never blocks storage -- unlike verification,
    // a failed trust check here is recorded (both in the event log and in
    // this credential's stored metadata) but the flow proceeds regardless).
    let trust_valid = match config.trust.validation {
        TrustValidationMode::Enabled => {
            let store = build_trust_store(config)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let outcome = validate_jws_x5c_chain(issuer_jwt, &store, now);
            event_log::append_event(
                &config.data_dir,
                &serde_json::json!({
                    "ts": now_rfc3339(), "kind": "trust_validation_result",
                    "context": "issuer_credential", "valid": outcome.valid, "detail": outcome.detail,
                }),
            )?;
            Some(outcome.valid)
        }
        TrustValidationMode::Disabled => None,
    };

    // Step 7: decode & store.
    let credential_id = format!("cred_{}", uuid::Uuid::new_v4().simple());
    let disclosed_claim_names: Vec<String> = disclosed_claims.keys().cloned().collect();
    let metadata = CredentialMetadata {
        credential_id: credential_id.clone(),
        vct: vct.clone(),
        issuer,
        received_at: now_rfc3339(),
        status_list_uri,
        status_list_idx,
        disclosed_claims: disclosed_claim_names,
        trust_valid,
        holder_key_path: "holder_key.pem".to_string(),
    };
    let payload_json = serde_json::json!({
        "header": header,
        "payload": issuer_payload,
        "disclosed_claims": serde_json::Value::Object(disclosed_claims),
    });
    store_credential(
        &config.data_dir,
        &NewCredential {
            credential_id: &credential_id,
            compact_sdjwt: &compact,
            decoded_payload: &payload_json,
            holder_key_pem: &proof.private_key_pem,
            metadata: &metadata,
        },
    )?;

    Ok(IssuanceOutcome {
        credential_id,
        vct,
        trust_valid,
    })
}
