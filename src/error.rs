use thiserror::Error;

#[derive(Debug, Error)]
pub enum PbringError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("keychain is locked")]
    KeychainLocked,

    #[error("pasteboard error: {0}")]
    Pasteboard(String),

    #[error("entry not found: {0}")]
    EntryNotFound(i64),
}

pub type Result<T> = std::result::Result<T, PbringError>;
