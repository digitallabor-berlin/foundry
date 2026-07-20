use axum::{extract::State, http::StatusCode, routing::get, Router};
use foundry_core::config::Config;
use foundry_core::storage::{SqliteStorage, Storage};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    let storage = Arc::new(SqliteStorage::connect(&cfg.storage.path).await?);
    let state = AppState { storage };
    let _sweeper = spawn_sweeper(state.storage.clone(), 60);
    let app = admin_router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.admin.bind).await?;
    tracing::info!(bind = %cfg.server.admin.bind, "foundry admin server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
