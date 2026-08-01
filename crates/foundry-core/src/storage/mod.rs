mod sqlite;
pub use sqlite::SqliteStorage;

use crate::error::StorageError;
use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn put_kv(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        expires_at: Option<i64>,
    ) -> Result<(), StorageError>;

    async fn get_kv(&self, namespace: &str, key: &str) -> Result<Option<String>, StorageError>;

    /// Atomically claims `(namespace, key)`: returns `true` if this call
    /// claimed it, `false` if it was already held. Unlike `put_kv` (an
    /// upsert), a rejected claim leaves the existing row's `value` and
    /// `expires_at` untouched. This atomicity is the entire mechanism behind
    /// `jti` replay detection (GAP-VCI-14) -- a get-then-put pattern has a
    /// TOCTOU window where two concurrent replays could both observe
    /// "absent" and both be accepted.
    async fn insert_kv_if_absent(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        expires_at: Option<i64>,
    ) -> Result<bool, StorageError>;

    async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError>;

    async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError>;
}
