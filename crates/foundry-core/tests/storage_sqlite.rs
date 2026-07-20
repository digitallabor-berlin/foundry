use foundry_core::storage::{SqliteStorage, Storage};

#[tokio::test]
async fn kv_roundtrip_and_expiry_purge() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    store.put_kv("issuance", "tx-1", "{\"a\":1}", Some(100)).await.unwrap();
    let got = store.get_kv("issuance", "tx-1").await.unwrap();
    assert_eq!(got.as_deref(), Some("{\"a\":1}"));

    // Not found for another namespace.
    assert_eq!(store.get_kv("verification", "tx-1").await.unwrap(), None);

    // Purge anything expiring at or before now=150 -> removes tx-1.
    let removed = store.purge_expired(150).await.unwrap();
    assert_eq!(removed, 1);
    assert_eq!(store.get_kv("issuance", "tx-1").await.unwrap(), None);

    // Delete is idempotent.
    store.delete_kv("issuance", "tx-1").await.unwrap();
}