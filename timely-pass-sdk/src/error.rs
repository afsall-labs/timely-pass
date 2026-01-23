use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("Invalid period: {0}")]
    InvalidPeriod(String),
}

pub type Result<T> = std::result::Result<T, Error>;
