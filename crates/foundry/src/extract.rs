//! Content-type-aware body extraction for the Credential Endpoint.
//!
//! OpenID4VCI §Credential Request (L848) permits the Credential Request to be
//! encrypted on top of TLS, in which case §Encrypted Messages (L1186) requires
//! the body to be a JWT with media type `application/jwt`; L875 requires an
//! unencrypted request to use `application/json`.
//!
//! Rejections are mapped **here** because an extractor rejection short-circuits
//! before any handler runs, so `credential_error_response` never sees it. Root
//! `AGENTS.md` §4.5 requires exactly one log record per typed error emitted in
//! its mapper, so this module owns that mapper for this path — and delegates the
//! protocol arm to `wallet_error_response` so the body and log shape are
//! identical to the engine's.

use crate::server::{AppState, wallet_error_response};
use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use foundry_issuer::IssuanceError;
use serde::de::DeserializeOwned;

/// A request body that arrived either as `application/json` or as an
/// `application/jwt` JWE.
pub struct MaybeEncrypted<T> {
    pub value: T,
    /// Whether the body arrived encrypted. Feeds `handle_credential_request`,
    /// which needs it for OpenID4VCI L960 and L1192.
    pub was_encrypted: bool,
}

pub enum MaybeEncryptedRejection {
    /// L875 / VCI-0062: anything that is neither `application/json` nor a
    /// supported `application/jwt`.
    UnsupportedMediaType,
    /// A structurally bad encrypted body: wrong `alg`, unadvertised `enc`,
    /// absent or unknown `kid`, undecryptable ciphertext, or claims that are not
    /// a Credential Request.
    Issuance(IssuanceError),
    /// The plaintext path's own rejection, passed through unchanged.
    Json(axum::extract::rejection::JsonRejection),
}

impl IntoResponse for MaybeEncryptedRejection {
    fn into_response(self) -> Response {
        match self {
            // 415 is a transport-level refusal with no OAuth error body, which is
            // exactly what axum's `Json` extractor produced before this extractor
            // existed. `vci_0062_credential_request_requires_json_content_type`
            // pins the status.
            MaybeEncryptedRejection::UnsupportedMediaType => {
                tracing::warn!(
                    listener = "wallet",
                    "error.kind" = "unsupported_media_type",
                    "credential request rejected: unsupported Content-Type"
                );
                StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
            }
            // `wallet_error_response` emits the single log record; this arm adds
            // none of its own.
            MaybeEncryptedRejection::Issuance(e) => {
                let (status, body) = wallet_error_response(&e);
                (status, body).into_response()
            }
            MaybeEncryptedRejection::Json(r) => r.into_response(),
        }
    }
}

/// Is `value` the given media type, ignoring parameters such as `; charset=utf-8`?
fn is_media_type(value: Option<&str>, expected: &str) -> bool {
    value
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(expected)
        })
        .unwrap_or(false)
}

#[async_trait::async_trait]
impl<T> FromRequest<AppState> for MaybeEncrypted<T>
where
    T: DeserializeOwned + Send + 'static,
{
    type Rejection = MaybeEncryptedRejection;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        if is_media_type(content_type.as_deref(), "application/json") {
            let Json(value) = Json::<T>::from_request(req, state)
                .await
                .map_err(MaybeEncryptedRejection::Json)?;
            return Ok(Self {
                value,
                was_encrypted: false,
            });
        }

        if !is_media_type(content_type.as_deref(), "application/jwt") {
            return Err(MaybeEncryptedRejection::UnsupportedMediaType);
        }

        // L1183–L1192 is only reachable when the mechanism is configured. An
        // issuer with no decryption keys must not appear to accept the media
        // type, so this is 415 rather than a 400 the wallet cannot act on.
        let Some(re) = &state.config.issuer.request_encryption else {
            return Err(MaybeEncryptedRejection::UnsupportedMediaType);
        };
        if state.request_decryption_keys.is_empty() {
            return Err(MaybeEncryptedRejection::UnsupportedMediaType);
        }

        let body = String::from_request(req, state).await.map_err(|_| {
            MaybeEncryptedRejection::Issuance(IssuanceError::InvalidCredentialRequest(
                "an application/jwt body must be a UTF-8 compact JWE".to_string(),
            ))
        })?;

        let claims = foundry_core::crypto::jwe::decrypt_compact(
            &body,
            &state.request_decryption_keys,
            &re.enc_values_supported,
        )
        .map_err(|e| {
            // The message names only the structural defect; `CryptoError`'s
            // Display never echoes key material or ciphertext.
            MaybeEncryptedRejection::Issuance(IssuanceError::InvalidCredentialRequest(format!(
                "Credential Request decryption failed: {e}"
            )))
        })?;

        let value = serde_json::from_value(claims).map_err(|e| {
            MaybeEncryptedRejection::Issuance(IssuanceError::InvalidCredentialRequest(format!(
                "decrypted Credential Request is not well formed: {e}"
            )))
        })?;

        Ok(Self {
            value,
            was_encrypted: true,
        })
    }
}

/// A Credential Response body, plaintext or encrypted.
///
/// `IntoResponse` cannot fail but encryption can, so the encryption happens in
/// the handler (where it becomes a typed error) and this type only carries the
/// already-computed body plus its media type.
pub enum CredentialResponseBody {
    /// L971: `application/json`.
    Json(foundry_issuer::CredentialResponse),
    /// L1186: `application/jwt`, carrying the compact JWE as the raw body — not
    /// a JSON-quoted string.
    Jwt(String),
}

impl IntoResponse for CredentialResponseBody {
    fn into_response(self) -> Response {
        match self {
            CredentialResponseBody::Json(res) => Json(res).into_response(),
            CredentialResponseBody::Jwt(compact) => {
                ([(header::CONTENT_TYPE, "application/jwt")], compact).into_response()
            }
        }
    }
}
