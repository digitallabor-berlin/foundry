use axum::{extract::State, http::StatusCode, routing::get, Router};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
}

pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state)
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

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    let storage = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let state = AppState { storage };
    let app = admin_router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    axum::serve(listener, app).await?;
    Ok(())
}