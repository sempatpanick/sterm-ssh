pub mod manager;
pub mod types;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("host key rejected for {hostname}:{port}")]
    HostKeyRejected { hostname: String, port: u16 },
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("channel error: {0}")]
    Channel(String),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("proxy jump cycle or chain error: {0}")]
    ProxyJump(String),
}

pub type SshResult<T> = Result<T, SshError>;
