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

    async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError>;

    async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError>;
}
