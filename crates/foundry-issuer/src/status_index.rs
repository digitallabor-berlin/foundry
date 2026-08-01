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

/// Allocate a unique, unpredictable index in `[0, list_size)` within the
/// physical status list identified by `list_id`, via CSPRNG draw + storage
/// check-and-set. The allocated index is never released (no expiry on the
/// "used" marker) — index release/reuse policy is out of scope for this
/// phase.
///
/// HAIP SD-JWT VC Profile (L329): each Credential MUST have its own unique,
/// unpredictable status list index even when multiple Credentials reference
/// the same status list URI. The used-marker key is therefore scoped to
/// `list_id` — the physical list every allocation actually draws against —
/// not to `credential_type_id`. Every credential type currently embeds the
/// same literal list id (`"1"`, see `create_offer.rs`), so scoping dedup to
/// `credential_type_id` instead would let two credentials of different types
/// draw the same index in the one list they actually share; scoping to
/// `list_id` makes allocation scope identical to physical-list scope by
/// construction, regardless of how many credential types end up sharing a
/// list. `credential_type_id` is retained only for diagnostics (the tracing
/// field and the `StatusListExhausted` payload).
#[tracing::instrument(skip_all, fields(list_id = %list_id, credential_type_id = %credential_type_id, list_size))]
pub async fn allocate_status_index(
    storage: &dyn Storage,
    list_id: &str,
    credential_type_id: &str,
    list_size: u64,
) -> Result<u64, IssuanceError> {
    if list_size == 0 {
        return Err(IssuanceError::StatusListExhausted(
            credential_type_id.to_string(),
        ));
    }
    for _ in 0..MAX_ATTEMPTS {
        let idx = rand::rngs::ThreadRng::default().next_u64() % list_size;
        let key = format!("{list_id}:{idx}");
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
        let idx = allocate_status_index(&storage, "1", "pid", 1024)
            .await
            .unwrap();
        assert!(idx < 1024);
    }

    #[tokio::test]
    async fn never_allocates_the_same_index_twice_for_a_tiny_list() {
        let storage = test_storage().await;
        // list_size=1 forces every draw to land on index 0; the second
        // allocation must exhaust its retries and fail distinctly.
        let first = allocate_status_index(&storage, "1", "pid", 1)
            .await
            .unwrap();
        assert_eq!(first, 0);
        let err = allocate_status_index(&storage, "1", "pid", 1)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::StatusListExhausted(_)));
    }

    #[tokio::test]
    async fn rejects_zero_list_size() {
        let storage = test_storage().await;
        let err = allocate_status_index(&storage, "1", "pid", 0)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuanceError::StatusListExhausted(_)));
    }

    /// GAP-HAIP-06 regression guard, crate-local twin of
    /// `gap_haip_06_status_index_can_collide_across_credential_types_sharing_one_list`
    /// in `tests/conformance_vci.rs`. Two different credential types
    /// allocating against the *same physical list* (as every credential type
    /// does in production — see `create_offer.rs`'s literal `"1"`) must never
    /// be handed the same index: dedup scope must equal physical-list scope,
    /// regardless of `credential_type_id`.
    ///
    /// `list_size=1` is deliberate and deterministic in both directions:
    /// every draw is forced to index 0, so a scheme keyed per
    /// `credential_type_id` (the bug) lets a second credential type
    /// independently succeed with the same index a different type already
    /// took, while a scheme keyed per physical list (the fix) correctly
    /// reports the list exhausted instead of colliding.
    ///
    /// Superseded here is `different_credential_types_do_not_collide`'s
    /// former assertion that `pid_idx == 0 && mdl_idx == 0` was "no
    /// cross-type collision" reasoning about the storage key rather than the
    /// physical bit position both credentials actually shared — that was the
    /// bug this test guards against, not a demonstration of correctness.
    #[tokio::test]
    async fn different_credential_types_sharing_one_list_do_not_collide() {
        let storage = test_storage().await;
        let pid_idx = allocate_status_index(&storage, "1", "pid", 1)
            .await
            .unwrap();
        assert_eq!(pid_idx, 0);

        let mdl_result = allocate_status_index(&storage, "1", "mdl", 1).await;
        assert!(
            mdl_result.is_err(),
            "a second credential type must not be able to draw an index into a physical \
             status list whose only slot index {pid_idx} is already taken by a different \
             credential type, but got {mdl_result:?}"
        );
    }
}
