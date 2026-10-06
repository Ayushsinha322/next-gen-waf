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

impl StorageError {
    /// The backend did not answer in time, as opposed to answering with an
    /// error. The Valkey client reports its own response timeout as an I/O
    /// `TimedOut` error, which a caller counting timeouts must not file as an
    /// ordinary failure.
    pub fn is_timeout(&self) -> bool {
        match self {
            StorageError::Redis(e) => e.is_timeout(),
            _ => false,
        }
    }
}
