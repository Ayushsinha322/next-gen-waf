use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("clickhouse: {0}")]
    ClickHouse(String),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("storage not configured")]
    NotConfigured,
}
