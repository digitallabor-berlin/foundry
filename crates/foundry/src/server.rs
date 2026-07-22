use crate::admin_auth::{require_api_key, AdminApiKey};
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
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
        Storage(_) | Serialization(_) | Deserialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "message": e.to_string() })),
    )
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
        config,
    };
    let _sweeper = spawn_sweeper(storage, 60);

    let api_key = AdminApiKey::resolve(&cfg.server.admin);
    if api_key.0.is_none() {
        tracing::warn!(
            "admin API key not configured — admin endpoints are UNAUTHENTICATED (dev only)"
        );
    }
    let admin_app = admin_router(state, api_key);

    let admin_listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    axum::serve(admin_listener, admin_app).await?;
    Ok(())
}
