pub mod backup;
pub mod models;
pub mod ssh_config;
pub mod store;

use core_crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("invalid master password")]
    InvalidPassword,
    #[error("item not found: {0}")]
    NotFound(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid backup format: {0}")]
    InvalidBackup(String),
}

pub type VaultResult<T> = Result<T, VaultError>;
