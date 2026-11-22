use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub enum SshAuthMethod {
    Password {
        password: String,
    },
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
    Certificate {
        pem: String,
        passphrase: Option<String>,
        certificate: String,
    },
    SshAgent,
    KeyboardInteractive,
    None,
}

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuthMethod,
    pub keepalive_secs: u32,
}

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    /// Ordered list of jump hosts from outermost bastion to inner jump host.
    pub jump_chain: Vec<SshTarget>,
    pub target: SshTarget,
    pub cols: u32,
    pub rows: u32,
    pub startup_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostKeyStatus {
    Unknown,
    Mismatch { expected_fingerprint: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKeyChallenge {
    pub challenge_id: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub public_key_b64: String,
    pub status: HostKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyboardInteractivePrompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyboardInteractiveChallenge {
    pub challenge_id: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KeyboardInteractivePrompt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload", rename_all = "snake_case")]
pub enum TerminalEvent {
    Output { data: Vec<u8> },
    Closed { reason: String },
    Error { message: String },
}
