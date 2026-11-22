use serde::{Deserialize, Serialize};

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Host,
    Group,
    Credential,
    KnownHost,
    Snippet,
    PortForward,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Group => "group",
            Self::Credential => "credential",
            Self::KnownHost => "known_host",
            Self::Snippet => "snippet",
            Self::PortForward => "port_forward",
        }
    }

    pub fn from_str_tag(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "group" => Some(Self::Group),
            "credential" => Some(Self::Credential),
            "known_host" => Some(Self::KnownHost),
            "snippet" => Some(Self::Snippet),
            "port_forward" => Some(Self::PortForward),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRecord {
    pub id: String,
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub group_id: Option<String>,
    pub tags: Vec<String>,
    pub credential_id: Option<String>,
    pub jump_host_id: Option<String>,
    pub terminal_theme: Option<String>,
    pub keepalive_secs: u32,
    pub startup_command: Option<String>,
    pub notes: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub color: Option<String>,
    pub default_username: Option<String>,
    pub default_credential_id: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    PrivateKey,
    Certificate,
    SshAgent,
    KeyboardInteractive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: String,
    pub label: String,
    pub kind: CredentialKind,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key_pem: Option<String>,
    pub passphrase: Option<String>,
    #[serde(default)]
    pub certificate_openssh: Option<String>,
    pub public_key_openssh: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub updated_at: i64,
}

/// Sanitized credential metadata safe to send to the React UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSummary {
    pub id: String,
    pub label: String,
    pub kind: CredentialKind,
    pub username: Option<String>,
    pub has_passphrase: bool,
    #[serde(default)]
    pub has_certificate: bool,
    pub public_key_openssh: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub updated_at: i64,
}

impl From<&CredentialRecord> for CredentialSummary {
    fn from(c: &CredentialRecord) -> Self {
        Self {
            id: c.id.clone(),
            label: c.label.clone(),
            kind: c.kind.clone(),
            username: c.username.clone(),
            has_passphrase: c.passphrase.as_deref().is_some_and(|s| !s.is_empty()),
            has_certificate: c
                .certificate_openssh
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty()),
            public_key_openssh: c.public_key_openssh.clone(),
            fingerprint_sha256: c.fingerprint_sha256.clone(),
            updated_at: c.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownHostRecord {
    pub id: String,
    pub hostname: String,
    pub port: u16,
    pub key_algorithm: String,
    pub fingerprint_sha256: String,
    pub public_key_b64: String,
    pub trusted_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRecord {
    pub id: String,
    pub command: String,
    pub label: Option<String>,
    pub host_id: Option<String>,
    pub pinned: bool,
    pub use_count: u32,
    pub last_used_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardKind {
    Local,
    Remote,
    DynamicSocks5,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortForwardRecord {
    pub id: String,
    pub label: String,
    pub host_id: String,
    pub kind: PortForwardKind,
    pub bind_address: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    #[serde(default)]
    pub auto_start: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
    pub keychain_enabled: bool,
    pub vault_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub hosts: Vec<HostRecord>,
    pub groups: Vec<GroupRecord>,
    pub credentials: Vec<CredentialSummary>,
    pub known_hosts: Vec<KnownHostRecord>,
    pub commands: Vec<CommandRecord>,
    #[serde(default)]
    pub port_forwards: Vec<PortForwardRecord>,
}

/// Wire-ready opaque encrypted envelope used for cross-platform zero-knowledge sync.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedItemEnvelope {
    pub id: String,
    pub entity_type: String,
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub schema_version: u32,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
    pub sync_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncApplyResult {
    pub applied: usize,
    pub conflicts: Vec<String>,
}
