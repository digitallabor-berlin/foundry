use crate::admin_auth::{require_api_key, AdminApiKey};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
}

pub fn admin_router(state: AppState, api_key: AdminApiKey) -> Router {
    let unauthenticated = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state.clone());

    let authenticated = Router::new()
        .route("/admin/issuance/offers", post(create_offer_handler))
        .route_layer(middleware::from_fn_with_state(api_key, require_api_key))
        .with_state(state);

    unauthenticated.merge(authenticated)
}

pub fn wallet_router(state: AppState) -> Router {
    Router::new()
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
        .with_state(state)
}

async fn issuer_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::CredentialIssuerMetadata> {
    Json(foundry_issuer::build_issuer_metadata(&state.config))
}

async fn auth_server_metadata(
    State(state): State<AppState>,
) -> Json<foundry_issuer::AuthorizationServerMetadata> {
    Json(foundry_issuer::build_authorization_server_metadata(
        &state.config,
    ))
}

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    // Readiness = storage reachable. A cheap purge with a far-past timestamp
    // touches the DB without deleting live rows.
    match state.storage.purge_expired(0).await {
        Ok(_) => Ok("ready"),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn create_offer_handler(
    State(state): State<AppState>,
    Json(req): Json<foundry_issuer::CreateOfferRequest>,
) -> Result<Json<foundry_issuer::CreateOfferResponse>, (StatusCode, Json<serde_json::Value>)> {
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
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(e.to_string()))
        })?
    } else {
        serde_html_form::from_bytes(&body_bytes).map_err(|e| {
            wallet_error_response(&foundry_issuer::IssuanceError::InvalidRequest(e.to_string()))
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

async fn nonce_handler() -> Json<serde_json::Value> {
    let c_nonce = format!("cn_{}", uuid::Uuid::new_v4().simple());
    Json(serde_json::json!({
        "c_nonce": c_nonce,
        "c_nonce_expires_in": 600
    }))
}

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
