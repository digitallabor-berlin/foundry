use crate::admin_auth::{require_api_key, AdminApiKey};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use foundry_issuer::{CreateOfferRequest, CreateOfferResponse};
use foundry_verifier::{
    CreateVerificationRequest, CreateVerificationResponse, VerificationTransaction,
};
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use utoipa::OpenApi;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
}

pub fn admin_router(state: AppState, api_key: AdminApiKey) -> Router {
    let unauthenticated = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready));

    let unauthenticated = if state.config.server.admin.swagger_ui_enabled {
        unauthenticated.merge(utoipa_swagger_ui::SwaggerUi::new("/api-docs").url(
            "/api-docs/openapi.json",
            crate::openapi::AdminApiDoc::openapi(),
        ))
    } else {
        unauthenticated.route("/api-docs/openapi.json", get(openapi_json_handler))
    };

    let unauthenticated = unauthenticated.with_state(state.clone());

    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route(
            "/admin/verification/requests",
            post(create_verification_handler),
        )
        .route(
            "/admin/verification/requests/:id",
            get(get_verification_handler),
        )
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);

    unauthenticated.merge(authenticated)
}

pub fn wallet_router(state: AppState) -> Router {
    let router = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_server_metadata),
        )
        .route("/token", post(token_handler))
        .route("/nonce", post(nonce_handler))
        .route("/credential", post(credential_handler))
        .route("/vp/request/:id", get(get_request_object_handler))
        .route("/vp/response/:id", post(post_response_handler));

    let router = if state.config.server.wallet_facing.swagger_ui_enabled {
        router.merge(utoipa_swagger_ui::SwaggerUi::new("/api-docs").url(
            "/api-docs/openapi.json",
            crate::openapi::WalletApiDoc::openapi(),
        ))
    } else {
        router.route("/api-docs/openapi.json", get(wallet_openapi_json_handler))
    };

    router.with_state(state)
}

pub(crate) async fn wallet_openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_wallet_openapi_spec(),
    )
}

#[utoipa::path(
    get,
    path = "/.well-known/openid-credential-issuer",
    responses((status = 200, body = foundry_issuer::CredentialIssuerMetadata))
)]
async fn issuer_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::CredentialIssuerMetadata> {
    Json(foundry_issuer::build_issuer_metadata(&state.config))
}

#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    responses((status = 200, body = foundry_issuer::AuthorizationServerMetadata))
)]
async fn auth_server_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::AuthorizationServerMetadata> {
    Json(foundry_issuer::build_authorization_server_metadata(
        &state.config,
    ))
}

pub(crate) async fn openapi_json_handler(
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::openapi::generate_admin_openapi_spec(),
    )
}

#[utoipa::path(get, path = "/health", responses((status = 200, body = String)))]
pub(crate) async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(get, path = "/ready", responses((status = 200, body = String)))]
pub(crate) async fn ready(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    // Readiness = storage reachable. A cheap purge with a far-past timestamp
    // touches the DB without deleting live rows.
    match state.storage.purge_expired(0).await {
        Ok(_) => Ok("ready"),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[utoipa::path(
    post,
    path = "/admin/issuance/offers",
    request_body = CreateOfferRequest,
    responses((status = 200, body = CreateOfferResponse))
)]
pub(crate) async fn create_offer_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateOfferRequest>,
) -> Result<Json<CreateOfferResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    foundry_issuer::create_offer(&state.config, state.storage.as_ref(), req, now)
        .await
        .map(Json)
        .map_err(|e| admin_error_response(&e))
}

fn admin_error_response(
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::*;
    let status = match e {
        UnknownCredentialType(_) | ClaimValidation(_) => StatusCode::BAD_REQUEST,
        StatusListExhausted(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "message": e.to_string() })),
    )
}

fn wallet_error_response(
    e: &foundry_issuer::IssuanceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_issuer::IssuanceError::*;
    let (status, code) = match e {
        InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
        InvalidProof(_) => (StatusCode::BAD_REQUEST, "invalid_proof"),
        InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        UnknownCredentialType(_) | ClaimValidation(_) => {
            (StatusCode::BAD_REQUEST, "invalid_credential_request")
        }
        StatusListExhausted(_) => (StatusCode::SERVICE_UNAVAILABLE, "server_error"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": e.to_string(),
        })),
    )
}

#[utoipa::path(
    post,
    path = "/token",
    request_body = foundry_issuer::TokenRequest,
    responses((status = 200, body = foundry_issuer::TokenResponse))
)]
async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<Json<foundry_issuer::TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req: foundry_issuer::TokenRequest = if content_type.contains("application/json") {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(
                e.to_string(),
            ))
        })?
    } else {
        serde_html_form::from_bytes(&body_bytes).map_err(|e| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(
                e.to_string(),
            ))
        })?
    };

    let attestation_hdr = headers
        .get("OAuth-Client-Attestation")
        .and_then(|v| v.to_str().ok());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    foundry_issuer::handle_token_request(
        state.storage.as_ref(),
        &req,
        state.config.issuer.wallet_attestation.mode.clone(),
        attestation_hdr,
        now,
    )
    .await
    .map(Json)
    .map_err(|e| wallet_error_response(&e))
}

#[utoipa::path(
    post,
    path = "/nonce",
    responses((status = 200, body = foundry_issuer::NonceResponse))
)]
async fn nonce_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<foundry_issuer::NonceResponse>, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
                "missing authorization header".into(),
            ))
        })?;

    let access_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
            "invalid bearer authorization header".into(),
        ))
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let res = foundry_issuer::refresh_c_nonce(state.storage.as_ref(), access_token, now)
        .await
        .map_err(|e| wallet_error_response(&e))?;

    Ok(Json(res))
}

#[utoipa::path(
    post,
    path = "/credential",
    request_body = foundry_issuer::CredentialRequest,
    responses((status = 200, body = foundry_issuer::CredentialResponse))
)]
async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<foundry_issuer::CredentialRequest>,
) -> Result<Json<foundry_issuer::CredentialResponse>, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
                "missing authorization header".into(),
            ))
        })?;

    let access_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        wallet_error_response(&foundry_issuer::IssuanceError::InvalidGrant(
            "invalid bearer authorization header".into(),
        ))
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    foundry_issuer::handle_credential_request(
        &state.config,
        state.storage.as_ref(),
        access_token,
        &req,
        now,
    )
    .await
    .map(Json)
    .map_err(|e| wallet_error_response(&e))
}

fn verifier_admin_error_response(
    e: &foundry_verifier::VerificationError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let status = match e {
        Dcql(_) | Serialization(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "message": e.to_string() })),
    )
}

fn verifier_wallet_error_response(
    e: &foundry_verifier::VerificationError,
) -> (StatusCode, Json<serde_json::Value>) {
    use foundry_verifier::VerificationError::*;
    let (status, code) = match e {
        Decryption(_) | Failed(_) | Serialization(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        StatusUnavailable(_) => (StatusCode::BAD_GATEWAY, "status_unavailable"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": e.to_string(),
        })),
    )
}

#[utoipa::path(
    post,
    path = "/admin/verification/requests",
    request_body = CreateVerificationRequest,
    responses((status = 200, body = CreateVerificationResponse))
)]
pub(crate) async fn create_verification_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateVerificationRequest>,
) -> Result<Json<CreateVerificationResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    foundry_verifier::create_verification_request(&state.config, state.storage.as_ref(), req, now)
        .await
        .map(Json)
        .map_err(|e| verifier_admin_error_response(&e))
}

#[utoipa::path(
    get,
    path = "/admin/verification/requests/{id}",
    responses((status = 200, body = VerificationTransaction), (status = 404))
)]
pub(crate) async fn get_verification_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<VerificationTransaction>, StatusCode> {
    let tx = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match tx {
        Some(tx) => Ok(Json(tx)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[utoipa::path(
    get,
    path = "/vp/request/{id}",
    responses(
        (status = 200, description = "Signed Request Object JWT", content_type = "application/oauth-authz-req+jwt", body = String),
        (status = 404)
    )
)]
async fn get_request_object_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    let tx = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tx = match tx {
        Some(tx) => tx,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let jws_str = foundry_verifier::build_signed_request_object(&state.config, &tx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/oauth-authz-req+jwt",
        )],
        jws_str,
    ))
}

#[utoipa::path(
    post,
    path = "/vp/response/{id}",
    request_body(content = String, description = "Encrypted JWE compact serialization of the VP Token response"),
    responses((status = 200, body = foundry_verifier::VerificationResult))
)]
async fn post_response_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    encrypted_jwe_str: String,
) -> Result<Json<foundry_verifier::VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx_opt = foundry_verifier::load_verification_transaction(state.storage.as_ref(), &id)
        .await
        .map_err(|e| verifier_wallet_error_response(&e))?;
    let mut tx = match tx_opt {
        Some(tx) => tx,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "error_description": format!("verification transaction '{id}' not found")
                })),
            ))
        }
    };

    if tx.state != foundry_verifier::VerificationState::Pending {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "verification response already submitted"
            })),
        ));
    }

    let resolver = match foundry_verifier::HttpStatusListResolver::new() {
        Ok(r) => r,
        Err(e) => return Err(verifier_wallet_error_response(&e)),
    };
    let verify_res =
        foundry_verifier::verify_vp_response(&state.config, &mut tx, &encrypted_jwe_str, &resolver)
            .await;

    let _ = foundry_verifier::save_verification_transaction(
        state.storage.as_ref(),
        &tx,
        state.config.storage.transaction_ttl_secs,
        now,
    )
    .await;

    match verify_res {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(verifier_wallet_error_response(&e)),
    }
}

pub fn spawn_sweeper(storage: Arc<dyn Storage>, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            ticker.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match storage.purge_expired(now).await {
                Ok(n) if n > 0 => tracing::debug!(purged = n, "swept expired rows"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "sweeper purge failed"),
            }
        }
    })
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    if let Err(e) = std::fs::write(
        "openapi.json",
        crate::openapi::generate_admin_openapi_spec(),
    ) {
        tracing::warn!(error = %e, "failed to write openapi.json on startup");
    } else {
        tracing::debug!("wrote openapi.json on startup");
    }

    if let Err(e) = std::fs::write(
        "openapi-wallet.json",
        crate::openapi::generate_wallet_openapi_spec(),
    ) {
        tracing::warn!(error = %e, "failed to write openapi-wallet.json on startup");
    } else {
        tracing::debug!("wrote openapi-wallet.json on startup");
    }

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let config = Arc::new(cfg.clone());
    let state = AppState {
        storage: storage.clone(),
        config: config.clone(),
    };
    let _sweeper = spawn_sweeper(storage, 60);

    let api_key = AdminApiKey::resolve(&cfg.server.admin);
    if api_key.0.is_none() {
        tracing::warn!(
            "admin API key not configured — admin endpoints are UNAUTHENTICATED (dev only)"
        );
    }
    let admin_app = admin_router(state.clone(), api_key);
    let wallet_app = wallet_router(state);

    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    let wallet_listener = tokio::net::TcpListener::bind(&cfg.server.wallet_facing.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    tracing::info!(bind = %cfg.server.wallet_facing.bind, "foundry wallet-facing server listening");

    tokio::try_join!(
        axum::serve(admin_listener, admin_app).into_future(),
        axum::serve(wallet_listener, wallet_app).into_future(),
    )?;
    Ok(())
}
