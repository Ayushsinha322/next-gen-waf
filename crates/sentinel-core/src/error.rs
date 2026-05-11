use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("rule error: {0}")]
    Rule(String),

    #[error("plugin error: {0}")]
    Plugin(String),
}

pub type Result<T> = std::result::Result<T, SentinelError>;
