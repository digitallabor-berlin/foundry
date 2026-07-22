//! CSPRNG-based, storage check-and-set status-list index allocation.
//!
//! TODO(concurrency): the get-then-put pair below is not atomic; concurrent
//! allocators racing on the same index could both succeed. Acceptable for
//! this phase's single-process dev deployment (consistent with
//! `foundry_core::trust`'s existing `TODO(trust-hardening)` pattern); a
//! later phase should add an atomic compare-and-swap primitive to `Storage`.

use crate::error::IssuanceError;
use foundry_core::storage::Storage;
use rand::RngCore;

const USED_NAMESPACE: &str = "status_index_used";
const MAX_ATTEMPTS: u32 = 20;

/// Allocate a unique, unpredictable index in `[0, list_size)` for
/// `credential_type_id`, via CSPRNG draw + storage check-and-set. The
/// allocated index is never released (no expiry on the "used" marker) —
/// index release/reuse policy is out of scope for this phase.
pub async fn allocate_status_index(
    storage: &dyn Storage,
    credential_type_id: &str,
    list_size: u64,
) -> Result<u64, IssuanceError> {
    if list_size == 0 {
        return Err(IssuanceError::StatusListExhausted(
            credential_type_id.to_string(),
        ));
    }
    let mut rng = rand::rngs::ThreadRng::default();
    for _ in 0..MAX_ATTEMPTS {
        let idx = rng.next_u64() % list_size;
        let key = format!("{credential_type_id}:{idx}");
        let existing = storage.get_kv(USED_NAMESPACE, &key).await?;
        if existing.is_none() {
            storage.put_kv(USED_NAMESPACE, &key, "1", None).await?;
            return Ok(idx);
        }
    }
    Err(IssuanceError::StatusListExhausted(
        credential_type_id.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_core::storage::SqliteStorage;

    async fn test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.db");
        std::mem::forget(dir);
        SqliteStorage::connect(db.to_str().unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn allocates_index_within_range() {
        let storage = test_storage().await;
        let idx = allocate_status_index(&storage, "pid", 1024).await.unwrap();
        assert!(idx < 1024);
    }

    #[tokio::test]
    async fn never_allocates_the_same_index_twice_for_a_tiny_list() {
        let storage = test_storage().await;
        // list_size=1 forces every draw to land on index 0; the second
        // allocation must exhaust its retries and fail distinctly.
        let first = allocate_status_index(&storage, "pid", 1).await.unwrap();
        assert_eq!(first, 0);
        let err = allocate_status_index(&storage, "pid", 1).await.unwrap_err();
        assert!(matches!(err, IssuanceError::StatusListExhausted(_)));
    }

    #[tokio::test]
    async fn rejects_zero_list_size() {
        let storage = test_storage().await;
        let err = allocate_status_index(&storage, "pid", 0).await.unwrap_err();
        assert!(matches!(err, IssuanceError::StatusListExhausted(_)));
    }

    #[tokio::test]
    async fn different_credential_types_do_not_collide() {
        let storage = test_storage().await;
        // With list_size=1, both credential types independently get index 0 —
        // the namespace key includes credential_type_id, so no cross-type collision.
        let pid_idx = allocate_status_index(&storage, "pid", 1).await.unwrap();
        let mdl_idx = allocate_status_index(&storage, "mdl", 1).await.unwrap();
        assert_eq!(pid_idx, 0);
        assert_eq!(mdl_idx, 0);
    }
}