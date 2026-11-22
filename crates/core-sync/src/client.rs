use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use core_crypto::{
    cipher::{unwrap_dek, wrap_dek},
    kdf::{derive_keys, generate_salt, KdfParams},
};
use core_vault::store::VaultStore;
use reqwest::Client;

use crate::protocol::{
    AccountProfile, AuthResponse, ChangePasswordRequest, DeleteAccountRequest, LoginRequest,
    RegisterRequest, SaltRequest, SaltResponse, SyncPullResponse, SyncPushRequest,
    SyncPushResponse, SyncRunReport, SyncSessionInfo,
};
use crate::{SyncError, SyncResult};

pub struct SyncClient {
    http: Client,
}

impl Default for SyncClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncClient {
    pub fn new() -> Self {
        Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .expect("reqwest client"),
        }
    }

    fn endpoint(base: &str, path: &str) -> String {
        format!("{}{}", base.trim_end_matches('/'), path)
    }

    /// Registers a new zero-knowledge sync account using the local vault's salt, KDF params,
    /// and wrapped DEK. Only the HKDF-derived `auth_key` is transmitted to the server.
    pub async fn register(
        &self,
        server_url: &str,
        email: &str,
        master_password: &str,
        vault: &VaultStore,
    ) -> SyncResult<SyncSessionInfo> {
        let (salt, params, wrapped_dek) = vault.get_crypto_envelope()?;
        let derived = derive_keys(master_password, &salt, &params)?;

        let req = RegisterRequest {
            email: email.trim().to_lowercase(),
            auth_key_b64: B64.encode(derived.auth_key.as_bytes()),
            kdf_salt_b64: B64.encode(&salt),
            kdf_params: params,
            wrapped_dek_b64: B64.encode(&wrapped_dek),
        };

        let resp = self
            .http
            .post(Self::endpoint(server_url, "/v1/auth/register"))
            .json(&req)
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::Server {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let auth: AuthResponse = resp
            .json()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        Ok(SyncSessionInfo {
            server_url: server_url.trim_end_matches('/').to_string(),
            account_id: auth.account_id,
            email: auth.email,
            access_token: auth.access_token,
            last_synced_at: None,
        })
    }

    /// Logs into an existing account on any platform (macOS or Windows), adopts the account's
    /// wrapped DEK locally using the master password, and returns the authenticated session.
    pub async fn login(
        &self,
        server_url: &str,
        email: &str,
        master_password: &str,
        vault: &mut VaultStore,
        enable_os_keychain: bool,
    ) -> SyncResult<SyncSessionInfo> {
        let normalized_email = email.trim().to_lowercase();
        let salt_resp = self
            .http
            .post(Self::endpoint(server_url, "/v1/auth/salt"))
            .json(&SaltRequest {
                email: normalized_email.clone(),
            })
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !salt_resp.status().is_success() {
            return Err(SyncError::Server {
                status: salt_resp.status().as_u16(),
                body: salt_resp.text().await.unwrap_or_default(),
            });
        }

        let salt_info: SaltResponse = salt_resp
            .json()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;
        let salt = B64
            .decode(&salt_info.kdf_salt_b64)
            .map_err(|e| SyncError::Auth(e.to_string()))?;

        let derived = derive_keys(master_password, &salt, &salt_info.kdf_params)?;

        let login_resp = self
            .http
            .post(Self::endpoint(server_url, "/v1/auth/login"))
            .json(&LoginRequest {
                email: normalized_email,
                auth_key_b64: B64.encode(derived.auth_key.as_bytes()),
            })
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !login_resp.status().is_success() {
            return Err(SyncError::Server {
                status: login_resp.status().as_u16(),
                body: login_resp.text().await.unwrap_or_default(),
            });
        }

        let auth: AuthResponse = login_resp
            .json()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        let wrapped_dek = B64
            .decode(&auth.wrapped_dek_b64)
            .map_err(|e| SyncError::Auth(e.to_string()))?;

        vault.adopt_remote_vault_envelope(
            &salt,
            &auth.kdf_params,
            &wrapped_dek,
            master_password,
            enable_os_keychain,
        )?;

        Ok(SyncSessionInfo {
            server_url: server_url.trim_end_matches('/').to_string(),
            account_id: auth.account_id,
            email: auth.email,
            access_token: auth.access_token,
            last_synced_at: None,
        })
    }

    /// Performs a full delta Pull -> Merge -> Push cycle with zero-knowledge encrypted blobs.
    pub async fn sync_now(
        &self,
        session: &SyncSessionInfo,
        vault: &VaultStore,
    ) -> SyncResult<SyncRunReport> {
        let cursor = vault.get_sync_cursor()?;

        // 1. Pull remote deltas
        let pull_url = format!(
            "{}?since={cursor}",
            Self::endpoint(&session.server_url, "/v1/sync/changes")
        );
        let pull_resp = self
            .http
            .get(&pull_url)
            .bearer_auth(&session.access_token)
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !pull_resp.status().is_success() {
            return Err(SyncError::Server {
                status: pull_resp.status().as_u16(),
                body: pull_resp.text().await.unwrap_or_default(),
            });
        }

        let pull_data: SyncPullResponse = pull_resp
            .json()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        let apply_res = vault.apply_remote_envelopes(&pull_data.items)?;
        let mut latest_seq = pull_data.server_seq.max(cursor);

        // 2. Push local dirty envelopes
        let dirty = vault.list_dirty_envelopes()?;
        let mut pushed = 0usize;

        if !dirty.is_empty() {
            let push_resp = self
                .http
                .post(Self::endpoint(&session.server_url, "/v1/sync/push"))
                .bearer_auth(&session.access_token)
                .json(&SyncPushRequest { items: dirty })
                .send()
                .await
                .map_err(|e| SyncError::Http(e.to_string()))?;

            if !push_resp.status().is_success() {
                return Err(SyncError::Server {
                    status: push_resp.status().as_u16(),
                    body: push_resp.text().await.unwrap_or_default(),
                });
            }

            let push_data: SyncPushResponse = push_resp
                .json()
                .await
                .map_err(|e| SyncError::Http(e.to_string()))?;
            let acks: Vec<(String, i64)> = push_data
                .synced
                .iter()
                .map(|a| (a.id.clone(), a.sync_revision))
                .collect();
            pushed = acks.len();
            vault.mark_envelopes_synced(&acks)?;
            latest_seq = latest_seq.max(push_data.server_seq);
        }

        vault.set_sync_cursor(latest_seq)?;

        Ok(SyncRunReport {
            pulled: apply_res.applied,
            pushed,
            conflicts: apply_res.conflicts,
            server_seq: latest_seq,
            synced_at: Utc::now().timestamp_millis(),
        })
    }

    pub async fn get_profile(&self, session: &SyncSessionInfo) -> SyncResult<AccountProfile> {
        let resp = self
            .http
            .get(Self::endpoint(&session.server_url, "/v1/account/me"))
            .bearer_auth(&session.access_token)
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::Server {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        resp.json()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))
    }

    /// Changes the account password both on the server and in the local encrypted vault
    /// by re-wrapping the Vault DEK with a fresh salt + derived keys.
    pub async fn change_password(
        &self,
        session: &SyncSessionInfo,
        current_password: &str,
        new_password: &str,
        vault: &mut VaultStore,
    ) -> SyncResult<SyncSessionInfo> {
        let (old_salt, old_params, old_wrapped_dek) = vault.get_crypto_envelope()?;
        let old_derived = derive_keys(current_password, &old_salt, &old_params)?;
        let dek = unwrap_dek(&old_derived.vault_key, &old_wrapped_dek)?;

        let new_salt = generate_salt();
        let new_params = KdfParams::default();
        let new_derived = derive_keys(new_password, &new_salt, &new_params)?;
        let new_wrapped_dek = wrap_dek(&new_derived.vault_key, &dek)?;

        let req = ChangePasswordRequest {
            current_auth_key_b64: B64.encode(old_derived.auth_key.as_bytes()),
            new_auth_key_b64: B64.encode(new_derived.auth_key.as_bytes()),
            new_kdf_salt_b64: B64.encode(new_salt),
            new_kdf_params: new_params.clone(),
            new_wrapped_dek_b64: B64.encode(&new_wrapped_dek),
        };

        let resp = self
            .http
            .post(Self::endpoint(&session.server_url, "/v1/account/change-password"))
            .bearer_auth(&session.access_token)
            .json(&req)
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::Server {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let auth: AuthResponse = resp
            .json()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        vault.apply_rekeyed_envelope(&new_salt, &new_params, &new_wrapped_dek, &new_derived.vault_key)?;

        Ok(SyncSessionInfo {
            server_url: session.server_url.clone(),
            account_id: auth.account_id,
            email: auth.email,
            access_token: auth.access_token,
            last_synced_at: session.last_synced_at,
        })
    }

    /// Permanently deletes the server account + encrypted blobs and wipes the local vault.
    pub async fn delete_account(
        &self,
        session: &SyncSessionInfo,
        current_password: &str,
        vault: &mut VaultStore,
    ) -> SyncResult<()> {
        let (salt, params, _) = vault.get_crypto_envelope()?;
        let derived = derive_keys(current_password, &salt, &params)?;

        let resp = self
            .http
            .delete(Self::endpoint(&session.server_url, "/v1/account"))
            .bearer_auth(&session.access_token)
            .json(&DeleteAccountRequest {
                current_auth_key_b64: B64.encode(derived.auth_key.as_bytes()),
            })
            .send()
            .await
            .map_err(|e| SyncError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::Server {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        vault.reset_local_vault()?;
        Ok(())
    }
}
