pub mod client;
pub mod protocol;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("network/http error: {0}")]
    Http(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("vault error: {0}")]
    Vault(#[from] core_vault::VaultError),
    #[error("crypto error: {0}")]
    Crypto(#[from] core_crypto::CryptoError),
    #[error("server returned status {status}: {body}")]
    Server { status: u16, body: String },
    #[error("not signed in to a sync account")]
    NotSignedIn,
}

pub type SyncResult<T> = Result<T, SyncError>;
