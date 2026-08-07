use foundry_core::storage::{SqliteStorage, Storage};

#[tokio::test]
async fn kv_roundtrip_and_expiry_purge() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    store
        .put_kv("issuance", "tx-1", "{\"a\":1}", Some(100))
        .await
        .unwrap();
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

/// `insert_kv_if_absent` first claim for a `(namespace, key)` succeeds.
#[tokio::test]
async fn insert_kv_if_absent_first_claim_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    let claimed = store
        .insert_kv_if_absent("jti", "key-1", "1", Some(1000))
        .await
        .unwrap();
    assert!(claimed);
    assert_eq!(
        store.get_kv("jti", "key-1").await.unwrap().as_deref(),
        Some("1")
    );
}

/// A second claim of the same `(namespace, key)` must be rejected -- this is
/// the entire anti-replay mechanism GAP-VCI-14 depends on.
#[tokio::test]
async fn insert_kv_if_absent_second_claim_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    let first = store
        .insert_kv_if_absent("jti", "key-1", "1", Some(1000))
        .await
        .unwrap();
    assert!(first);

    let second = store
        .insert_kv_if_absent("jti", "key-1", "1", Some(1000))
        .await
        .unwrap();
    assert!(!second, "a replayed claim of the same key must be rejected");
}

/// A rejected (`false`) claim must leave the existing row's value and
/// `expires_at` untouched -- `insert_kv_if_absent` is `DO NOTHING`, not an
/// upsert like `put_kv`. This is the property that distinguishes it from
/// the existing get-then-put pattern in `status_index.rs`.
#[tokio::test]
async fn insert_kv_if_absent_rejected_claim_does_not_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    store
        .insert_kv_if_absent("jti", "key-1", "original", Some(1000))
        .await
        .unwrap();

    let second = store
        .insert_kv_if_absent("jti", "key-1", "replayed", Some(9999))
        .await
        .unwrap();
    assert!(!second);

    // Value and expiry from the *first* claim must survive untouched.
    assert_eq!(
        store.get_kv("jti", "key-1").await.unwrap().as_deref(),
        Some("original")
    );
    let removed_before = store.purge_expired(1000).await.unwrap();
    assert_eq!(
        removed_before, 1,
        "row must expire at the first claim's expires_at (1000), not the second's (9999)"
    );
}

/// The same key string under a different namespace is independent -- proves
/// the claim is scoped to `(namespace, key)`, not `key` alone.
#[tokio::test]
async fn insert_kv_if_absent_scoped_per_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    assert!(
        store
            .insert_kv_if_absent("jti-a", "same-key", "1", None)
            .await
            .unwrap()
    );
    assert!(
        store
            .insert_kv_if_absent("jti-b", "same-key", "1", None)
            .await
            .unwrap()
    );
}

/// `put_kv`'s upsert behaviour must be unaffected by the new method: a plain
/// `put_kv` on a key already claimed via `insert_kv_if_absent` still
/// overwrites, exactly as it does today.
#[tokio::test]
async fn put_kv_still_overwrites_a_key_claimed_by_insert_kv_if_absent() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = SqliteStorage::connect(db.to_str().unwrap())
        .await
        .expect("connect");

    store
        .insert_kv_if_absent("jti", "key-1", "first", Some(1000))
        .await
        .unwrap();
    store
        .put_kv("jti", "key-1", "overwritten", Some(2000))
        .await
        .unwrap();

    assert_eq!(
        store.get_kv("jti", "key-1").await.unwrap().as_deref(),
        Some("overwritten")
    );
}
