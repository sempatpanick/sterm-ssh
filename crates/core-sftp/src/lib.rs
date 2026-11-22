pub mod manager;
pub mod types;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SftpError {
    #[error("ssh error: {0}")]
    Ssh(#[from] core_ssh::SshError),
    #[error("sftp protocol error: {0}")]
    Protocol(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sftp session not found: {0}")]
    SessionNotFound(String),
    #[error("transfer cancelled")]
    Cancelled,
    #[error("file too large for inline editor ({size} bytes; max {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },
}

pub type SftpResult<T> = Result<T, SftpError>;
