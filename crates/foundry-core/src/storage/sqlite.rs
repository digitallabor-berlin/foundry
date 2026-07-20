use super::Storage;
use crate::error::StorageError;
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn connect(path: &str) -> Result<SqliteStorage, StorageError> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(SqliteStorage { pool })
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn put_kv(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        expires_at: Option<i64>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO kv (namespace, key, value, expires_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, key) DO UPDATE SET value = ?3, expires_at = ?4",
        )
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_kv(&self, namespace: &str, key: &str) -> Result<Option<String>, StorageError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM kv WHERE namespace = ?1 AND key = ?2")
                .bind(namespace)
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(row.map(|(v,)| v))
    }

    async fn delete_kv(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM kv WHERE namespace = ?1 AND key = ?2")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn purge_expired(&self, now_unix: i64) -> Result<u64, StorageError> {
        let res = sqlx::query("DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <= ?1")
            .bind(now_unix)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(res.rows_affected())
    }
}
