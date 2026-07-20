use axum::body::Body;
use axum::http::{Request, StatusCode};
use foundry::server::{admin_router, AppState};
use foundry_core::storage::SqliteStorage;
use std::sync::Arc;
use tower::ServiceExt; // for `oneshot`

#[tokio::test]
async fn health_and_ready_return_200() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("h.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());
    let app = admin_router(AppState { storage });

    let health = app
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let ready = app
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
}