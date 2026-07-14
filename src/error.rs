use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("storage error: {0}")]
    Store(#[from] sled::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SentinelError>;
