use foundry::server::spawn_sweeper;
use foundry_core::storage::{SqliteStorage, Storage};
use std::sync::Arc;

#[tokio::test]
async fn sweeper_purges_expired_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let storage = Arc::new(SqliteStorage::connect(db.to_str().unwrap()).await.unwrap());

    // expires_at in the past relative to wall clock.
    storage
        .put_kv("issuance", "old", "v", Some(1))
        .await
        .unwrap();

    let handle = spawn_sweeper(storage.clone(), 1);
    // Give the sweeper one tick.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    handle.abort();

    assert_eq!(storage.get_kv("issuance", "old").await.unwrap(), None);
}
