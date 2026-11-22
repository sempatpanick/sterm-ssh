pub mod cipher;
pub mod kdf;
pub mod keychain;
pub mod ssh_keygen;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed: invalid key or tampered ciphertext")]
    Decrypt,
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("invalid nonce length: expected 12, got {0}")]
    InvalidNonceLength(usize),
    #[error("os keychain error: {0}")]
    Keychain(String),
    #[error("ssh key error: {0}")]
    SshKey(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
