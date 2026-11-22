use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use core_crypto::{
    cipher::{unwrap_dek, wrap_dek},
    kdf::{derive_keys, generate_salt, KdfParams},
    keychain,
    ssh_keygen::{inspect_openssh_certificate, inspect_private_key},
};
use core_sftp::{
    manager::SftpManager,
    types::{FileEntry, TransferProgress},
};
use core_ssh::{
    manager::{HostKeyVerifier, SshSessionManager},
    types::{
        ConnectRequest, HostKeyChallenge, KeyboardInteractiveChallenge, SshAuthMethod, SshTarget,
        TerminalEvent,
    },
};
use core_sync::{
    client::SyncClient,
    protocol::{
        AuthResponse, ChangePasswordRequest, DeleteAccountRequest, LoginRequest, RegisterRequest,
        SaltRequest, SaltResponse, SyncPullResponse, SyncPushRequest, SyncPushResponse,
        SyncRunReport, SyncSessionInfo,
    },
};
use core_vault::{
    models::{CredentialKind, CredentialRecord, HostRecord, KnownHostRecord},
    ssh_config::LocalSshDiscovery,
    store::VaultStore,
};
use tokio::sync::mpsc;

/// Events pushed from Tokio async SSH/SFTP/Sync tasks to the GPUI UI loop.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum UiEvent {
    SshConnected {
        tab_id: String,
        session_id: String,
        label: String,
        hostname: String,
        port: u16,
        username: String,
    },
    SshConnectFailed {
        tab_id: String,
        error: String,
        is_auth_error: bool,
    },
    TerminalOutput {
        tab_id: String,
        event: TerminalEvent,
    },
    TerminalResize {
        tab_id: String,
        cols: u16,
        rows: u16,
    },
    HostKeyPrompt(HostKeyChallenge),
    KbiPrompt(KeyboardInteractiveChallenge),
    SftpConnected {
        session_id: String,
        host_label: String,
        remote_cwd: String,
        local_cwd: String,
    },
    SftpLocalListed {
        path: String,
        entries: Vec<FileEntry>,
    },
    SftpRemoteListed {
        session_id: String,
        path: String,
        entries: Vec<FileEntry>,
    },
    SftpTransfer(TransferProgress),
    SftpRemoteTextLoaded {
        session_id: String,
        remote_path: String,
        content: String,
    },
    SftpError(String),
    SftpNotice(String),
    SyncCompleted {
        status: PublicSyncStatus,
        report: Option<SyncRunReport>,
        message: String,
    },
    SyncFailed(String),
    VaultUnlocked {
        status: core_vault::models::VaultStatus,
        message: String,
    },
    VaultActionFailed(String),
    SettingsActionDone {
        message: String,
        is_error: bool,
        sync_status: Option<PublicSyncStatus>,
    },
    SyncAccountDeleted,
    LocalSshDiscovered(LocalSshDiscovery),
}

#[derive(Debug, Clone, Default)]
pub struct PublicSyncStatus {
    pub signed_in: bool,
    pub server_url: Option<String>,
    pub email: Option<String>,
    pub last_synced_at: Option<i64>,
}

impl PublicSyncStatus {
    pub fn from_session(s: &Option<SyncSessionInfo>) -> Self {
        match s {
            Some(info) => Self {
                signed_in: true,
                server_url: Some(info.server_url.clone()),
                email: Some(info.email.clone()),
                last_synced_at: info.last_synced_at,
            },
            None => Self::default(),
        }
    }
}

/// Shared pure-Rust backend services used directly by the GPUI interface (zero IPC).
pub struct BackendServices {
    pub rt: Arc<tokio::runtime::Runtime>,
    pub vault: Arc<Mutex<VaultStore>>,
    pub ssh: Arc<SshSessionManager>,
    pub sftp: Arc<SftpManager>,
    pub _sync_client: Arc<SyncClient>,
    pub sync_session: Arc<Mutex<Option<SyncSessionInfo>>>,
    pub ui_tx: mpsc::UnboundedSender<UiEvent>,
    /// Tracks SSH sessions opened solely for standalone SFTP (without a terminal tab).
    pub sftp_only_sessions: Arc<Mutex<HashSet<String>>>,
}

impl BackendServices {
    pub fn init() -> (Arc<Self>, mpsc::UnboundedReceiver<UiEvent>) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("sterm-tokio")
            .build()
            .expect("failed to build tokio runtime");

        // Share the exact same encrypted vault path as Tauri (`app.sterm.ssh`) so local data,
        // OS Keychain unlock keys, and E2EE Sync accounts stay 100% consistent.
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("app.sterm.ssh");
        let _ = std::fs::create_dir_all(&data_dir);
        let db_path = data_dir.join("sterm-vault.db");

        let mut vault = VaultStore::open(&db_path).expect("failed to open encrypted vault db");
        let _ = vault.try_unlock_from_os_keychain();

        // Only attach a saved OS Keychain sync session if it belongs to this vault's account_id
        // so we never pull ciphertexts encrypted with a different vault DEK.
        let vault_account_id = vault.get_meta_string("account_id").ok().flatten();
        let saved_sync = keychain::load_sync_secret()
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str::<SyncSessionInfo>(&s).ok())
            .filter(|info| {
                vault_account_id
                    .as_deref()
                    .is_some_and(|aid| aid == info.account_id)
            });

        let (ui_tx, ui_rx) = mpsc::unbounded_channel();

        let services = Arc::new(Self {
            rt: Arc::new(rt),
            vault: Arc::new(Mutex::new(vault)),
            ssh: Arc::new(SshSessionManager::new()),
            sftp: Arc::new(SftpManager::new()),
            _sync_client: Arc::new(SyncClient::new()),
            sync_session: Arc::new(Mutex::new(saved_sync)),
            ui_tx,
            sftp_only_sessions: Arc::new(Mutex::new(HashSet::new())),
        });

        (services, ui_rx)
    }

    pub fn verifier(self: &Arc<Self>) -> Arc<dyn HostKeyVerifier> {
        Arc::new(GpuiHostKeyVerifier {
            vault: Arc::clone(&self.vault),
            ssh: Arc::clone(&self.ssh),
            ui_tx: self.ui_tx.clone(),
        })
    }

    pub fn sync_status(&self) -> PublicSyncStatus {
        let guard = self.sync_session.lock().ok();
        match guard {
            Some(g) => PublicSyncStatus::from_session(&g),
            None => PublicSyncStatus::default(),
        }
    }
}

pub struct GpuiHostKeyVerifier {
    pub vault: Arc<Mutex<VaultStore>>,
    pub ssh: Arc<SshSessionManager>,
    pub ui_tx: mpsc::UnboundedSender<UiEvent>,
}

#[async_trait]
impl HostKeyVerifier for GpuiHostKeyVerifier {
    async fn lookup_known_host(&self, hostname: &str, port: u16) -> Option<String> {
        let vault = self.vault.lock().ok()?;
        vault
            .find_known_host(hostname, port)
            .ok()
            .flatten()
            .map(|k| k.fingerprint_sha256)
    }

    async fn prompt_user(&self, challenge: HostKeyChallenge) -> bool {
        let rx = self.ssh.register_challenge(challenge.challenge_id.clone());
        if self.ui_tx.send(UiEvent::HostKeyPrompt(challenge)).is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    async fn save_known_host(&self, challenge: HostKeyChallenge) {
        if let Ok(vault) = self.vault.lock() {
            let existing_id = vault
                .find_known_host(&challenge.hostname, challenge.port)
                .ok()
                .flatten()
                .map(|k| k.id)
                .unwrap_or_default();

            let _ = vault.upsert_known_host(KnownHostRecord {
                id: existing_id,
                hostname: challenge.hostname,
                port: challenge.port,
                key_algorithm: challenge.algorithm,
                fingerprint_sha256: challenge.fingerprint_sha256,
                public_key_b64: challenge.public_key_b64,
                trusted_at: chrono::Utc::now().timestamp_millis(),
            });
        }
    }

    async fn prompt_keyboard_interactive(
        &self,
        challenge: KeyboardInteractiveChallenge,
    ) -> Option<Vec<String>> {
        let rx = self
            .ssh
            .register_kbi_challenge(challenge.challenge_id.clone());
        if self.ui_tx.send(UiEvent::KbiPrompt(challenge)).is_err() {
            return None;
        }
        rx.await.ok().flatten()
    }
}

pub fn is_ssh_auth_error(err: &core_ssh::SshError) -> bool {
    matches!(err, core_ssh::SshError::Auth(_) | core_ssh::SshError::InvalidKey(_))
}

#[expect(clippy::too_many_arguments, reason = "maps directly onto validated CredentialRecord fields")]
pub fn build_validated_credential(
    id: String,
    label: String,
    kind: CredentialKind,
    username: Option<String>,
    password: Option<String>,
    private_key_pem: Option<String>,
    passphrase: Option<String>,
    certificate_openssh: Option<String>,
) -> Result<CredentialRecord, String> {
    let mut public_key_openssh = None;
    let mut fingerprint_sha256 = None;

    if matches!(kind, CredentialKind::PrivateKey | CredentialKind::Certificate)
        && let Some(ref pem) = private_key_pem
            && !pem.trim().is_empty() {
                let (pk, fp) =
                    inspect_private_key(pem, passphrase.as_deref()).map_err(|e| e.to_string())?;
                public_key_openssh = Some(pk);
                fingerprint_sha256 = Some(fp);
            }

    if kind == CredentialKind::Certificate {
        let cert_str = certificate_openssh
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "OpenSSH certificate is required".to_string())?;
        let cert_fp = inspect_openssh_certificate(cert_str).map_err(|e| e.to_string())?;
        if fingerprint_sha256.is_none() {
            fingerprint_sha256 = Some(cert_fp);
        }
    }

    Ok(CredentialRecord {
        id,
        label,
        kind,
        username,
        password,
        private_key_pem,
        passphrase,
        certificate_openssh,
        public_key_openssh,
        fingerprint_sha256,
        updated_at: 0,
    })
}

fn resolve_target(
    vault: &VaultStore,
    host: &HostRecord,
    override_password: Option<String>,
) -> Result<SshTarget, String> {
    // Inherit default credential/username from parent group chain if unset on the host itself.
    let mut effective_cred_id = host.credential_id.clone();
    let mut effective_username = host.username.clone();
    if (effective_cred_id.is_none() || effective_username.trim().is_empty())
        && let Ok(groups) = vault.list_groups() {
            let mut cursor = host.group_id.clone();
            let mut seen = HashSet::new();
            while let Some(gid) = cursor {
                if !seen.insert(gid.clone()) {
                    break;
                }
                if let Some(grp) = groups.iter().find(|g| g.id == gid) {
                    if effective_cred_id.is_none() {
                        effective_cred_id = grp.default_credential_id.clone();
                    }
                    if effective_username.trim().is_empty()
                        && let Some(ref du) = grp.default_username
                            && !du.trim().is_empty() {
                                effective_username = du.clone();
                            }
                    cursor = grp.parent_id.clone();
                } else {
                    break;
                }
            }
        }

    let auth = if let Some(pw) = override_password.filter(|s| !s.is_empty()) {
        SshAuthMethod::Password { password: pw }
    } else if let Some(ref cred_id) = effective_cred_id {
        let cred = vault.get_credential(cred_id).map_err(|e| e.to_string())?;
        match cred.kind {
            CredentialKind::Password => SshAuthMethod::Password {
                password: cred.password.unwrap_or_default(),
            },
            CredentialKind::PrivateKey => SshAuthMethod::PrivateKey {
                pem: cred
                    .private_key_pem
                    .ok_or_else(|| "credential is missing private key PEM".to_string())?,
                passphrase: cred.passphrase,
            },
            CredentialKind::Certificate => SshAuthMethod::Certificate {
                pem: cred
                    .private_key_pem
                    .ok_or_else(|| "certificate credential is missing private key PEM".to_string())?,
                passphrase: cred.passphrase,
                certificate: cred
                    .certificate_openssh
                    .ok_or_else(|| {
                        "certificate credential is missing OpenSSH certificate".to_string()
                    })?,
            },
            CredentialKind::SshAgent => SshAuthMethod::SshAgent,
            CredentialKind::KeyboardInteractive => SshAuthMethod::KeyboardInteractive,
        }
    } else {
        SshAuthMethod::None
    };

    Ok(SshTarget {
        hostname: host.hostname.clone(),
        port: host.port,
        username: effective_username,
        auth,
        keepalive_secs: host.keepalive_secs,
    })
}

pub fn build_connect_request_for_host(
    vault: &VaultStore,
    host_id: &str,
    cols: u32,
    rows: u32,
    override_password: Option<String>,
) -> Result<(HostRecord, ConnectRequest), String> {
    let target_host = vault.get_host(host_id).map_err(|e| e.to_string())?;

    let mut visited = HashSet::new();
    visited.insert(target_host.id.clone());

    let mut reversed_hops: Vec<SshTarget> = Vec::new();
    let mut cursor = target_host.jump_host_id.clone();

    while let Some(jump_id) = cursor {
        if !visited.insert(jump_id.clone()) {
            return Err("ProxyJump cycle detected in host configuration".to_string());
        }
        let jump_host = vault.get_host(&jump_id).map_err(|e| e.to_string())?;
        reversed_hops.push(resolve_target(vault, &jump_host, None)?);
        cursor = jump_host.jump_host_id.clone();
    }
    reversed_hops.reverse();

    let target = resolve_target(vault, &target_host, override_password)?;
    let req = ConnectRequest {
        jump_chain: reversed_hops,
        target,
        cols,
        rows,
        startup_command: target_host.startup_command.clone(),
    };
    Ok((target_host, req))
}

fn reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("reqwest client")
}

pub async fn run_sync_register(
    services: Arc<BackendServices>,
    server_url: String,
    email: String,
    master_password: String,
    enable_os_keychain: bool,
) -> Result<PublicSyncStatus, String> {
    let normalized_email = email.trim().to_lowercase();
    let base = server_url.trim_end_matches('/').to_string();

    let (salt, params, wrapped_dek) = {
        let mut vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        if !vault.is_initialized().map_err(|e| e.to_string())? {
            vault
                .initialize_vault(&master_password, enable_os_keychain)
                .map_err(|e| e.to_string())?;
        } else if !vault.is_unlocked() {
            // Preserve existing offline local vault if the supplied password unlocks it;
            // refuse to silently wipe un-synced local hosts/keys if a different password is given.
            let prev_account = vault.get_meta_string("account_id").ok().flatten();
            if vault
                .unlock_with_password(&master_password, Some(enable_os_keychain))
                .is_err()
            {
                if prev_account.is_some() {
                    // Switching away from a previously synced server account — safe to re-init cache.
                    vault.reset_local_vault().map_err(|e| e.to_string())?;
                    vault
                        .initialize_vault(&master_password, enable_os_keychain)
                        .map_err(|e| e.to_string())?;
                } else {
                    return Err(
                        "An offline local vault already exists on this device. Unlock it offline first (or enter its master password) so your saved hosts are preserved when creating an account."
                            .to_string(),
                    );
                }
            }
        }
        vault.get_crypto_envelope().map_err(|e| e.to_string())?
    };

    let derived = derive_keys(&master_password, &salt, &params).map_err(|e| e.to_string())?;
    let req = RegisterRequest {
        email: normalized_email,
        auth_key_b64: B64.encode(derived.auth_key.as_bytes()),
        kdf_salt_b64: B64.encode(&salt),
        kdf_params: params,
        wrapped_dek_b64: B64.encode(&wrapped_dek),
    };

    let http = reqwest_client();
    let resp = http
        .post(format!("{base}/v1/auth/register"))
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("Cannot reach sync server ({base}): {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Registration failed ({status}): {body}"));
    }

    let auth: AuthResponse = resp.json().await.map_err(|e| e.to_string())?;
    {
        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        let _ = vault.set_meta_string("account_id", &auth.account_id);
        let _ = vault.set_meta_string("account_email", &auth.email);
        let _ = vault.set_meta_string("server_url", &base);
    }

    let session = SyncSessionInfo {
        server_url: base,
        account_id: auth.account_id,
        email: auth.email,
        access_token: auth.access_token,
        last_synced_at: None,
    };

    if enable_os_keychain
        && let Ok(serialized) = serde_json::to_string(&session) {
            let _ = keychain::store_sync_secret(&serialized);
        }

    let mut guard = services
        .sync_session
        .lock()
        .map_err(|_| "sync lock".to_string())?;
    *guard = Some(session);
    Ok(PublicSyncStatus::from_session(&guard))
}

pub async fn run_sync_login(
    services: Arc<BackendServices>,
    server_url: String,
    email: String,
    master_password: String,
    enable_os_keychain: bool,
) -> Result<PublicSyncStatus, String> {
    let normalized_email = email.trim().to_lowercase();
    let http = reqwest_client();
    let base = server_url.trim_end_matches('/').to_string();

    let salt_resp = http
        .post(format!("{base}/v1/auth/salt"))
        .json(&SaltRequest {
            email: normalized_email.clone(),
        })
        .send()
        .await
        .map_err(|e| format!("Cannot reach sync server ({base}): {e}"))?;

    if !salt_resp.status().is_success() {
        return Err(format!("Server salt lookup failed ({})", salt_resp.status()));
    }

    let salt_info: SaltResponse = salt_resp.json().await.map_err(|e| e.to_string())?;
    let salt = B64
        .decode(&salt_info.kdf_salt_b64)
        .map_err(|e| e.to_string())?;
    let derived =
        derive_keys(&master_password, &salt, &salt_info.kdf_params).map_err(|e| e.to_string())?;

    let login_resp = http
        .post(format!("{base}/v1/auth/login"))
        .json(&LoginRequest {
            email: normalized_email,
            auth_key_b64: B64.encode(derived.auth_key.as_bytes()),
        })
        .send()
        .await
        .map_err(|e| format!("Cannot reach sync server ({base}): {e}"))?;

    if !login_resp.status().is_success() {
        let status = login_resp.status();
        let body = login_resp.text().await.unwrap_or_default();
        return Err(format!("Sign in failed ({status}): {body}"));
    }

    let auth: AuthResponse = login_resp.json().await.map_err(|e| e.to_string())?;
    let wrapped_dek = B64
        .decode(&auth.wrapped_dek_b64)
        .map_err(|e| e.to_string())?;

    {
        let mut vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        let previous_account = vault.get_meta_string("account_id").ok().flatten();
        // If user created local hosts offline before signing in, preserve and merge them under the new DEK!
        let preserved_offline = if previous_account.is_none()
            && vault.is_initialized().unwrap_or(false)
        {
            if !vault.is_unlocked() {
                let _ = vault.unlock_with_password(&master_password, None);
            }
            if vault.is_unlocked() {
                let hosts = vault.list_hosts().unwrap_or_default();
                let groups = vault.list_groups().unwrap_or_default();
                let creds = vault.list_credentials_full().unwrap_or_default();
                let known = vault.list_known_hosts().unwrap_or_default();
                let cmds = vault.list_commands().unwrap_or_default();
                Some((hosts, groups, creds, known, cmds))
            } else {
                None
            }
        } else {
            None
        };

        if previous_account.as_deref() != Some(auth.account_id.as_str()) {
            vault.reset_local_vault().map_err(|e| e.to_string())?;
        }
        vault
            .adopt_remote_vault_envelope(
                &salt,
                &auth.kdf_params,
                &wrapped_dek,
                &master_password,
                enable_os_keychain,
            )
            .map_err(|e| e.to_string())?;
        let _ = vault.set_meta_string("account_id", &auth.account_id);
        let _ = vault.set_meta_string("account_email", &auth.email);
        let _ = vault.set_meta_string("server_url", &base);

        if let Some((hosts, groups, creds, known, cmds)) = preserved_offline {
            for g in groups {
                let _ = vault.upsert_group(g);
            }
            for c in creds {
                let _ = vault.upsert_credential(c);
            }
            for kh in known {
                let _ = vault.upsert_known_host(kh);
            }
            for h in hosts {
                let _ = vault.upsert_host(h);
            }
            for cmd in cmds {
                let _ = vault.upsert_command(cmd);
            }
        }
    }

    let session = SyncSessionInfo {
        server_url: base,
        account_id: auth.account_id,
        email: auth.email,
        access_token: auth.access_token,
        last_synced_at: None,
    };

    if enable_os_keychain
        && let Ok(serialized) = serde_json::to_string(&session) {
            let _ = keychain::store_sync_secret(&serialized);
        }

    let mut guard = services
        .sync_session
        .lock()
        .map_err(|_| "sync lock".to_string())?;
    *guard = Some(session);
    Ok(PublicSyncStatus::from_session(&guard))
}

pub async fn run_sync_now(
    services: Arc<BackendServices>,
) -> Result<(PublicSyncStatus, SyncRunReport), String> {
    let session = {
        let guard = services
            .sync_session
            .lock()
            .map_err(|_| "sync lock".to_string())?;
        guard.clone().ok_or_else(|| "not signed in".to_string())?
    };

    let cursor = {
        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault.get_sync_cursor().map_err(|e| e.to_string())?
    };

    let http = reqwest_client();
    let base = session.server_url.trim_end_matches('/');

    let pull_resp = http
        .get(format!("{base}/v1/sync/changes?since={cursor}"))
        .bearer_auth(&session.access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !pull_resp.status().is_success() {
        return Err(format!("sync pull failed ({})", pull_resp.status()));
    }
    let pull_data: SyncPullResponse = pull_resp.json().await.map_err(|e| e.to_string())?;

    let (apply_res, dirty) = {
        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        let apply = vault
            .apply_remote_envelopes(&pull_data.items)
            .map_err(|e| e.to_string())?;
        let dirty = vault.list_dirty_envelopes().map_err(|e| e.to_string())?;
        (apply, dirty)
    };

    let mut latest_seq = pull_data.server_seq.max(cursor);
    let mut pushed = 0usize;

    if !dirty.is_empty() {
        let push_resp = http
            .post(format!("{base}/v1/sync/push"))
            .bearer_auth(&session.access_token)
            .json(&SyncPushRequest { items: dirty })
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !push_resp.status().is_success() {
            return Err(format!("sync push failed ({})", push_resp.status()));
        }
        let push_data: SyncPushResponse = push_resp.json().await.map_err(|e| e.to_string())?;
        let acks: Vec<(String, i64)> = push_data
            .synced
            .iter()
            .map(|a| (a.id.clone(), a.sync_revision))
            .collect();
        pushed = acks.len();

        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault
            .mark_envelopes_synced(&acks)
            .map_err(|e| e.to_string())?;
        latest_seq = latest_seq.max(push_data.server_seq);
    }

    {
        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault
            .set_sync_cursor(latest_seq)
            .map_err(|e| e.to_string())?;
    }

    let synced_at = chrono::Utc::now().timestamp_millis();
    let status = {
        let mut guard = services
            .sync_session
            .lock()
            .map_err(|_| "sync lock".to_string())?;
        if let Some(ref mut info) = *guard {
            info.last_synced_at = Some(synced_at);
            if let Ok(serialized) = serde_json::to_string(info) {
                let _ = keychain::store_sync_secret(&serialized);
            }
        }
        PublicSyncStatus::from_session(&guard)
    };

    Ok((
        status,
        SyncRunReport {
            pulled: apply_res.applied,
            pushed,
            conflicts: apply_res.conflicts,
            server_seq: latest_seq,
            synced_at,
        },
    ))
}

pub async fn run_sync_change_password(
    services: Arc<BackendServices>,
    current_password: String,
    new_password: String,
) -> Result<PublicSyncStatus, String> {
    let session = {
        let guard = services
            .sync_session
            .lock()
            .map_err(|_| "sync lock".to_string())?;
        guard.clone().ok_or_else(|| "not signed in".to_string())?
    };

    let (old_salt, old_params, old_wrapped_dek) = {
        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault.get_crypto_envelope().map_err(|e| e.to_string())?
    };

    let old_derived =
        derive_keys(&current_password, &old_salt, &old_params).map_err(|e| e.to_string())?;
    let dek = unwrap_dek(&old_derived.vault_key, &old_wrapped_dek)
        .map_err(|_| "Current password is incorrect.".to_string())?;

    let new_salt = generate_salt();
    let new_params = KdfParams::default();
    let new_derived =
        derive_keys(&new_password, &new_salt, &new_params).map_err(|e| e.to_string())?;
    let new_wrapped_dek = wrap_dek(&new_derived.vault_key, &dek).map_err(|e| e.to_string())?;

    let http = reqwest_client();
    let base = session.server_url.trim_end_matches('/');
    let resp = http
        .post(format!("{base}/v1/account/change-password"))
        .bearer_auth(&session.access_token)
        .json(&ChangePasswordRequest {
            current_auth_key_b64: B64.encode(old_derived.auth_key.as_bytes()),
            new_auth_key_b64: B64.encode(new_derived.auth_key.as_bytes()),
            new_kdf_salt_b64: B64.encode(new_salt),
            new_kdf_params: new_params.clone(),
            new_wrapped_dek_b64: B64.encode(&new_wrapped_dek),
        })
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Password change failed ({status}): {body}"));
    }

    let auth: AuthResponse = resp.json().await.map_err(|e| e.to_string())?;

    {
        let mut vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault
            .apply_rekeyed_envelope(
                &new_salt,
                &new_params,
                &new_wrapped_dek,
                &new_derived.vault_key,
            )
            .map_err(|e| e.to_string())?;
    }

    let updated = SyncSessionInfo {
        server_url: session.server_url,
        account_id: auth.account_id,
        email: auth.email,
        access_token: auth.access_token,
        last_synced_at: session.last_synced_at,
    };

    if let Ok(serialized) = serde_json::to_string(&updated) {
        let _ = keychain::store_sync_secret(&serialized);
    }

    let mut guard = services
        .sync_session
        .lock()
        .map_err(|_| "sync lock".to_string())?;
    *guard = Some(updated);
    Ok(PublicSyncStatus::from_session(&guard))
}

pub async fn run_sync_delete_account(
    services: Arc<BackendServices>,
    current_password: String,
) -> Result<(), String> {
    let session = {
        let guard = services
            .sync_session
            .lock()
            .map_err(|_| "sync lock".to_string())?;
        guard.clone().ok_or_else(|| "not signed in".to_string())?
    };

    let (salt, params, _) = {
        let vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault.get_crypto_envelope().map_err(|e| e.to_string())?
    };

    let derived = derive_keys(&current_password, &salt, &params).map_err(|e| e.to_string())?;
    let http = reqwest_client();
    let base = session.server_url.trim_end_matches('/');

    let resp = http
        .delete(format!("{base}/v1/account"))
        .bearer_auth(&session.access_token)
        .json(&DeleteAccountRequest {
            current_auth_key_b64: B64.encode(derived.auth_key.as_bytes()),
        })
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Account deletion failed ({status}): {body}"));
    }

    let _ = keychain::clear_sync_secret();
    let _ = keychain::clear_vault_key_from_os_keychain();
    {
        let mut vault = services.vault.lock().map_err(|_| "vault lock".to_string())?;
        vault.reset_local_vault().map_err(|e| e.to_string())?;
    }
    let mut guard = services
        .sync_session
        .lock()
        .map_err(|_| "sync lock".to_string())?;
    *guard = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_ssh_auth_error;
    use core_ssh::SshError;

    #[test]
    fn ssh_auth_error_distinguishes_auth_from_network_errors() {
        assert!(is_ssh_auth_error(&SshError::Auth("bad password".into())));
        assert!(!is_ssh_auth_error(&SshError::HostKeyRejected {
            hostname: "example.com".into(),
            port: 22,
        }));
        assert!(!is_ssh_auth_error(&SshError::Connect(
            "connection refused".into()
        )));
    }
}
