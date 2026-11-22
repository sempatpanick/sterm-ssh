use core_crypto::kdf::KdfParams;
use core_vault::models::EncryptedItemEnvelope;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltResponse {
    pub kdf_salt_b64: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_key_b64: String,
    pub kdf_salt_b64: String,
    pub kdf_params: KdfParams,
    pub wrapped_dek_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub account_id: String,
    pub email: String,
    pub access_token: String,
    pub kdf_salt_b64: String,
    pub kdf_params: KdfParams,
    pub wrapped_dek_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPushRequest {
    pub items: Vec<EncryptedItemEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedAck {
    pub id: String,
    pub sync_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPushResponse {
    pub synced: Vec<SyncedAck>,
    pub server_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPullResponse {
    pub items: Vec<EncryptedItemEnvelope>,
    pub server_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSessionInfo {
    pub server_url: String,
    pub account_id: String,
    pub email: String,
    pub access_token: String,
    pub last_synced_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRunReport {
    pub pulled: usize,
    pub pushed: usize,
    pub conflicts: Vec<String>,
    pub server_seq: i64,
    pub synced_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    pub account_id: String,
    pub email: String,
    pub created_at: i64,
    pub item_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_auth_key_b64: String,
    pub new_auth_key_b64: String,
    pub new_kdf_salt_b64: String,
    pub new_kdf_params: KdfParams,
    pub new_wrapped_dek_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    pub current_auth_key_b64: String,
}
