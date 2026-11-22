use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use core_crypto::{
    cipher::{build_record_aad, decrypt_aead, encrypt_aead, unwrap_dek, wrap_dek},
    kdf::{derive_keys, generate_salt, KdfParams, SecretKey},
    keychain,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use crate::{
    models::{
        CommandRecord, CredentialRecord, CredentialSummary, EncryptedItemEnvelope, EntityType,
        GroupRecord, HostRecord, KnownHostRecord, SyncApplyResult, VaultSnapshot, VaultStatus,
        CURRENT_SCHEMA_VERSION,
    },
    VaultError, VaultResult,
};

pub struct VaultStore {
    conn: Connection,
    dek: Option<SecretKey>,
    kdf_params: KdfParams,
}

impl VaultStore {
    pub fn open(path: &Path) -> VaultResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let store = Self {
            conn,
            dek: None,
            kdf_params: KdfParams::default(),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> VaultResult<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn,
            dek: None,
            kdf_params: KdfParams::fast_for_tests(),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn with_kdf_params(mut self, params: KdfParams) -> Self {
        self.kdf_params = params;
        self
    }

    fn migrate(&self) -> VaultResult<()> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_items (
                id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                schema_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                deleted_at INTEGER,
                sync_revision INTEGER NOT NULL DEFAULT 0,
                dirty INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_vault_items_type
                ON vault_items(entity_type, deleted_at);
            CREATE INDEX IF NOT EXISTS idx_vault_items_dirty
                ON vault_items(dirty);
            ",
        )?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> VaultResult<Option<Vec<u8>>> {
        let val = self
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(val)
    }

    fn set_meta(&self, key: &str, value: &[u8]) -> VaultResult<()> {
        self.conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn is_initialized(&self) -> VaultResult<bool> {
        Ok(self.get_meta("wrapped_dek")?.is_some())
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    pub fn status(&self) -> VaultResult<VaultStatus> {
        let initialized = self.is_initialized()?;
        let vault_id = self
            .get_meta("vault_id")?
            .and_then(|b| String::from_utf8(b).ok());
        let keychain_enabled = self
            .get_meta("keychain_enabled")?
            .map(|b| b == b"1")
            .unwrap_or(false);

        Ok(VaultStatus {
            initialized,
            unlocked: self.dek.is_some(),
            keychain_enabled,
            vault_id,
        })
    }

    pub fn initialize_vault(
        &mut self,
        master_password: &str,
        enable_os_keychain: bool,
    ) -> VaultResult<VaultStatus> {
        if self.is_initialized()? {
            return Err(VaultError::AlreadyInitialized);
        }

        let salt = generate_salt();
        let derived = derive_keys(master_password, &salt, &self.kdf_params)?;
        let dek = SecretKey::generate();
        let wrapped_dek = wrap_dek(&derived.vault_key, &dek)?;
        let vault_id = Uuid::now_v7().to_string();

        self.set_meta("vault_id", vault_id.as_bytes())?;
        self.set_meta("kdf_salt", &salt)?;
        self.set_meta("kdf_params", &serde_json::to_vec(&self.kdf_params)?)?;
        self.set_meta("wrapped_dek", &wrapped_dek)?;
        self.set_meta("sync_cursor", b"0")?;

        if enable_os_keychain {
            keychain::store_vault_key_in_os_keychain(&derived.vault_key)?;
            self.set_meta("keychain_enabled", b"1")?;
        } else {
            self.set_meta("keychain_enabled", b"0")?;
        }

        self.dek = Some(dek);
        self.status()
    }

    /// Clears all cached local vault items and metadata (used when switching accounts or deleting an account).
    pub fn reset_local_vault(&mut self) -> VaultResult<()> {
        self.dek = None;
        self.conn.execute_batch(
            "
            DELETE FROM vault_items;
            DELETE FROM vault_meta;
            ",
        )?;
        Ok(())
    }

    pub fn get_meta_string(&self, key: &str) -> VaultResult<Option<String>> {
        Ok(self
            .get_meta(key)?
            .and_then(|b| String::from_utf8(b).ok()))
    }

    pub fn set_meta_string(&self, key: &str, value: &str) -> VaultResult<()> {
        self.set_meta(key, value.as_bytes())
    }

    /// Re-wraps the DEK with a newly derived vault key (e.g. after a server-confirmed password change).
    pub fn apply_rekeyed_envelope(
        &mut self,
        new_salt: &[u8],
        new_kdf_params: &KdfParams,
        new_wrapped_dek: &[u8],
        new_vault_key: &SecretKey,
    ) -> VaultResult<()> {
        let dek = unwrap_dek(new_vault_key, new_wrapped_dek)
            .map_err(|_| VaultError::InvalidPassword)?;
        self.set_meta("kdf_salt", new_salt)?;
        self.set_meta("kdf_params", &serde_json::to_vec(new_kdf_params)?)?;
        self.set_meta("wrapped_dek", new_wrapped_dek)?;
        if self
            .get_meta("keychain_enabled")?
            .map(|b| b == b"1")
            .unwrap_or(false)
        {
            let _ = keychain::store_vault_key_in_os_keychain(new_vault_key);
        }
        self.dek = Some(dek);
        Ok(())
    }

    /// Initializes or replaces the local vault's cryptographic envelope using salt/params/DEK
    /// downloaded from an existing E2EE synced account on another platform (macOS/Windows).
    pub fn adopt_remote_vault_envelope(
        &mut self,
        salt: &[u8],
        kdf_params: &KdfParams,
        wrapped_dek: &[u8],
        master_password: &str,
        enable_os_keychain: bool,
    ) -> VaultResult<VaultStatus> {
        let derived = derive_keys(master_password, salt, kdf_params)?;
        let dek = unwrap_dek(&derived.vault_key, wrapped_dek)
            .map_err(|_| VaultError::InvalidPassword)?;

        if self.get_meta("vault_id")?.is_none() {
            let vault_id = Uuid::now_v7().to_string();
            self.set_meta("vault_id", vault_id.as_bytes())?;
        }
        self.set_meta("kdf_salt", salt)?;
        self.set_meta("kdf_params", &serde_json::to_vec(kdf_params)?)?;
        self.set_meta("wrapped_dek", wrapped_dek)?;
        self.set_meta("sync_cursor", b"0")?;

        if enable_os_keychain {
            let _ = keychain::store_vault_key_in_os_keychain(&derived.vault_key);
            self.set_meta("keychain_enabled", b"1")?;
        }

        self.dek = Some(dek);
        self.status()
    }

    pub fn get_crypto_envelope(&self) -> VaultResult<(Vec<u8>, KdfParams, Vec<u8>)> {
        let salt = self.get_meta("kdf_salt")?.ok_or(VaultError::NotInitialized)?;
        let params_bytes = self
            .get_meta("kdf_params")?
            .ok_or(VaultError::NotInitialized)?;
        let params: KdfParams = serde_json::from_slice(&params_bytes)?;
        let wrapped_dek = self
            .get_meta("wrapped_dek")?
            .ok_or(VaultError::NotInitialized)?;
        Ok((salt, params, wrapped_dek))
    }

    pub fn unlock_with_password(
        &mut self,
        master_password: &str,
        store_in_keychain: Option<bool>,
    ) -> VaultResult<VaultStatus> {
        let (salt, params, wrapped_dek) = self.get_crypto_envelope()?;
        let derived = derive_keys(master_password, &salt, &params)?;
        let dek = unwrap_dek(&derived.vault_key, &wrapped_dek)
            .map_err(|_| VaultError::InvalidPassword)?;

        if let Some(enable) = store_in_keychain {
            if enable {
                keychain::store_vault_key_in_os_keychain(&derived.vault_key)?;
                self.set_meta("keychain_enabled", b"1")?;
            } else {
                keychain::clear_vault_key_from_os_keychain()?;
                self.set_meta("keychain_enabled", b"0")?;
            }
        }

        self.dek = Some(dek);
        self.status()
    }

    pub fn try_unlock_from_os_keychain(&mut self) -> VaultResult<bool> {
        if !self.is_initialized()? {
            return Ok(false);
        }
        let enabled = self
            .get_meta("keychain_enabled")?
            .map(|b| b == b"1")
            .unwrap_or(false);
        if !enabled {
            return Ok(false);
        }
        let Some(vault_key) = keychain::load_vault_key_from_os_keychain()? else {
            return Ok(false);
        };
        let wrapped_dek = self
            .get_meta("wrapped_dek")?
            .ok_or(VaultError::NotInitialized)?;
        match unwrap_dek(&vault_key, &wrapped_dek) {
            Ok(dek) => {
                self.dek = Some(dek);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub fn lock(&mut self) {
        self.dek = None;
    }

    pub fn change_master_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> VaultResult<()> {
        let (salt, params, wrapped_dek) = self.get_crypto_envelope()?;
        let old_derived = derive_keys(current_password, &salt, &params)?;
        let dek = unwrap_dek(&old_derived.vault_key, &wrapped_dek)
            .map_err(|_| VaultError::InvalidPassword)?;

        let new_salt = generate_salt();
        let new_derived = derive_keys(new_password, &new_salt, &self.kdf_params)?;
        let new_wrapped_dek = wrap_dek(&new_derived.vault_key, &dek)?;

        self.set_meta("kdf_salt", &new_salt)?;
        self.set_meta("kdf_params", &serde_json::to_vec(&self.kdf_params)?)?;
        self.set_meta("wrapped_dek", &new_wrapped_dek)?;

        if self
            .get_meta("keychain_enabled")?
            .map(|b| b == b"1")
            .unwrap_or(false)
        {
            keychain::store_vault_key_in_os_keychain(&new_derived.vault_key)?;
        }

        self.dek = Some(dek);
        Ok(())
    }

    fn require_dek(&self) -> VaultResult<&SecretKey> {
        self.dek.as_ref().ok_or(VaultError::Locked)
    }

    fn put_item<T: Serialize>(
        &self,
        id: &str,
        entity_type: EntityType,
        item: &T,
        updated_at: i64,
    ) -> VaultResult<()> {
        let dek = self.require_dek()?;
        let plaintext = serde_json::to_vec(item)?;
        let aad = build_record_aad(id, entity_type.as_str(), CURRENT_SCHEMA_VERSION);
        let blob = encrypt_aead(dek, &plaintext, &aad)?;

        self.conn.execute(
            "INSERT INTO vault_items
                (id, entity_type, ciphertext, nonce, schema_version, updated_at, deleted_at, sync_revision, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, 1)
             ON CONFLICT(id) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                nonce = excluded.nonce,
                schema_version = excluded.schema_version,
                updated_at = excluded.updated_at,
                deleted_at = NULL,
                dirty = 1",
            params![
                id,
                entity_type.as_str(),
                blob.ciphertext,
                blob.nonce.as_slice(),
                CURRENT_SCHEMA_VERSION,
                updated_at
            ],
        )?;
        Ok(())
    }

    fn list_items<T: DeserializeOwned>(&self, entity_type: EntityType) -> VaultResult<Vec<T>> {
        let dek = self.require_dek()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, ciphertext, nonce, schema_version
             FROM vault_items
             WHERE entity_type = ?1 AND deleted_at IS NULL
             ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map(params![entity_type.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u32>(3)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, ciphertext, nonce, schema_version) = row?;
            let aad = build_record_aad(&id, entity_type.as_str(), schema_version);
            let Ok(plain) = decrypt_aead(dek, &nonce, &ciphertext, &aad) else {
                // Skip undecryptable rows (e.g. from a mismatched DEK) so valid records stay visible.
                continue;
            };
            if let Ok(parsed) = serde_json::from_slice::<T>(&plain) {
                out.push(parsed);
            }
        }
        Ok(out)
    }

    fn get_item<T: DeserializeOwned>(&self, id: &str, entity_type: EntityType) -> VaultResult<T> {
        let dek = self.require_dek()?;
        let row = self
            .conn
            .query_row(
                "SELECT ciphertext, nonce, schema_version
                 FROM vault_items
                 WHERE id = ?1 AND entity_type = ?2 AND deleted_at IS NULL",
                params![id, entity_type.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| VaultError::NotFound(id.to_string()))?;

        let (ciphertext, nonce, schema_version) = row;
        let aad = build_record_aad(id, entity_type.as_str(), schema_version);
        let plain = decrypt_aead(dek, &nonce, &ciphertext, &aad)?;
        Ok(serde_json::from_slice(&plain)?)
    }

    pub fn soft_delete_item(&self, id: &str) -> VaultResult<()> {
        let _ = self.require_dek()?;
        let now = Utc::now().timestamp_millis();
        let changed = self.conn.execute(
            "UPDATE vault_items
             SET deleted_at = ?2, updated_at = ?2, dirty = 1
             WHERE id = ?1 AND deleted_at IS NULL",
            params![id, now],
        )?;
        if changed == 0 {
            return Err(VaultError::NotFound(id.to_string()));
        }
        Ok(())
    }

    // --- Hosts ---
    pub fn upsert_host(&self, mut host: HostRecord) -> VaultResult<HostRecord> {
        if host.id.is_empty() {
            host.id = Uuid::now_v7().to_string();
        }
        host.updated_at = Utc::now().timestamp_millis();
        self.put_item(&host.id, EntityType::Host, &host, host.updated_at)?;
        Ok(host)
    }

    pub fn list_hosts(&self) -> VaultResult<Vec<HostRecord>> {
        self.list_items(EntityType::Host)
    }

    pub fn get_host(&self, id: &str) -> VaultResult<HostRecord> {
        self.get_item(id, EntityType::Host)
    }

    // --- Groups ---
    pub fn upsert_group(&self, mut group: GroupRecord) -> VaultResult<GroupRecord> {
        if group.id.is_empty() {
            group.id = Uuid::now_v7().to_string();
        }
        group.updated_at = Utc::now().timestamp_millis();
        self.put_item(&group.id, EntityType::Group, &group, group.updated_at)?;
        Ok(group)
    }

    pub fn list_groups(&self) -> VaultResult<Vec<GroupRecord>> {
        self.list_items(EntityType::Group)
    }

    // --- Credentials ---
    pub fn upsert_credential(&self, mut cred: CredentialRecord) -> VaultResult<CredentialSummary> {
        if cred.id.is_empty() {
            cred.id = Uuid::now_v7().to_string();
        }
        cred.updated_at = Utc::now().timestamp_millis();
        self.put_item(&cred.id, EntityType::Credential, &cred, cred.updated_at)?;
        Ok(CredentialSummary::from(&cred))
    }

    pub fn list_credentials_summary(&self) -> VaultResult<Vec<CredentialSummary>> {
        let all: Vec<CredentialRecord> = self.list_items(EntityType::Credential)?;
        Ok(all.iter().map(CredentialSummary::from).collect())
    }

    pub fn list_credentials_full(&self) -> VaultResult<Vec<CredentialRecord>> {
        self.list_items(EntityType::Credential)
    }

    pub fn get_credential(&self, id: &str) -> VaultResult<CredentialRecord> {
        self.get_item(id, EntityType::Credential)
    }

    // --- Known Hosts ---
    pub fn upsert_known_host(&self, mut kh: KnownHostRecord) -> VaultResult<KnownHostRecord> {
        if kh.id.is_empty() {
            kh.id = Uuid::now_v7().to_string();
        }
        if kh.trusted_at == 0 {
            kh.trusted_at = Utc::now().timestamp_millis();
        }
        self.put_item(&kh.id, EntityType::KnownHost, &kh, kh.trusted_at)?;
        Ok(kh)
    }

    pub fn list_known_hosts(&self) -> VaultResult<Vec<KnownHostRecord>> {
        self.list_items(EntityType::KnownHost)
    }

    pub fn find_known_host(
        &self,
        hostname: &str,
        port: u16,
    ) -> VaultResult<Option<KnownHostRecord>> {
        let all = self.list_known_hosts()?;
        Ok(all
            .into_iter()
            .find(|k| k.hostname.eq_ignore_ascii_case(hostname) && k.port == port))
    }

    // --- Stored Commands & Snippets ---
    pub fn upsert_command(&self, mut cmd: CommandRecord) -> VaultResult<CommandRecord> {
        let now = Utc::now().timestamp_millis();
        if cmd.id.is_empty() {
            cmd.id = Uuid::now_v7().to_string();
        }
        if cmd.last_used_at == 0 {
            cmd.last_used_at = now;
        }
        cmd.updated_at = now;
        self.put_item(&cmd.id, EntityType::Snippet, &cmd, cmd.updated_at)?;
        Ok(cmd)
    }

    pub fn list_commands(&self) -> VaultResult<Vec<CommandRecord>> {
        self.list_items(EntityType::Snippet)
    }

    /// Records a command executed in a terminal, deduplicating against existing entries
    /// by exact command text (and host scope) and incrementing its frecency counter.
    pub fn record_command_usage(
        &self,
        command: &str,
        host_id: Option<String>,
    ) -> VaultResult<CommandRecord> {
        let trimmed = command.trim();
        let existing = self.list_commands()?;
        let now = Utc::now().timestamp_millis();

        if let Some(mut found) = existing
            .into_iter()
            .find(|c| c.command == trimmed && (c.host_id == host_id || c.host_id.is_none()))
        {
            found.use_count = found.use_count.saturating_add(1);
            found.last_used_at = now;
            found.updated_at = now;
            self.put_item(&found.id, EntityType::Snippet, &found, found.updated_at)?;
            return Ok(found);
        }

        self.upsert_command(CommandRecord {
            id: String::new(),
            command: trimmed.to_string(),
            label: None,
            host_id,
            pinned: false,
            use_count: 1,
            last_used_at: now,
            updated_at: now,
        })
    }

    pub fn snapshot(&self) -> VaultResult<VaultSnapshot> {
        Ok(VaultSnapshot {
            hosts: self.list_hosts()?,
            groups: self.list_groups()?,
            credentials: self.list_credentials_summary()?,
            known_hosts: self.list_known_hosts()?,
            commands: self.list_commands()?,
        })
    }

    // --- Sync primitives (zero-knowledge encrypted envelopes) ---
    pub fn get_sync_cursor(&self) -> VaultResult<i64> {
        let raw = self.get_meta("sync_cursor")?;
        Ok(raw
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0))
    }

    pub fn set_sync_cursor(&self, cursor: i64) -> VaultResult<()> {
        self.set_meta("sync_cursor", cursor.to_string().as_bytes())
    }

    pub fn list_dirty_envelopes(&self) -> VaultResult<Vec<EncryptedItemEnvelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, entity_type, ciphertext, nonce, schema_version, updated_at, deleted_at, sync_revision
             FROM vault_items
             WHERE dirty = 1",
        )?;

        let rows = stmt.query_map([], |row| {
            let ct: Vec<u8> = row.get(2)?;
            let nonce: Vec<u8> = row.get(3)?;
            Ok(EncryptedItemEnvelope {
                id: row.get(0)?,
                entity_type: row.get(1)?,
                ciphertext_b64: B64.encode(ct),
                nonce_b64: B64.encode(nonce),
                schema_version: row.get(4)?,
                updated_at: row.get(5)?,
                deleted_at: row.get(6)?,
                sync_revision: row.get(7)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn mark_envelopes_synced(&self, items: &[(String, i64)]) -> VaultResult<()> {
        for (id, rev) in items {
            self.conn.execute(
                "UPDATE vault_items SET dirty = 0, sync_revision = ?2 WHERE id = ?1",
                params![id, rev],
            )?;
        }
        Ok(())
    }

    /// Applies encrypted envelopes pulled from the sync server.
    /// If a local item is also dirty and has a newer/divergent edit, records a conflict id
    /// while resolving deterministically by `updated_at` (last-write-wins).
    pub fn apply_remote_envelopes(
        &self,
        envelopes: &[EncryptedItemEnvelope],
    ) -> VaultResult<SyncApplyResult> {
        let mut applied = 0usize;
        let mut conflicts = Vec::new();

        for env in envelopes {
            let ciphertext = B64
                .decode(&env.ciphertext_b64)
                .map_err(|e| VaultError::InvalidBackup(e.to_string()))?;
            let nonce = B64
                .decode(&env.nonce_b64)
                .map_err(|e| VaultError::InvalidBackup(e.to_string()))?;

            let existing = self
                .conn
                .query_row(
                    "SELECT updated_at, dirty, sync_revision FROM vault_items WHERE id = ?1",
                    params![&env.id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
                )
                .optional()?;

            if let Some((local_updated, local_dirty, _local_rev)) = existing {
                if local_dirty == 1 {
                    conflicts.push(env.id.clone());
                    if local_updated > env.updated_at {
                        // Local edit wins; keep dirty = 1 so it pushes on next cycle with updated revision
                        self.conn.execute(
                            "UPDATE vault_items SET sync_revision = ?2 WHERE id = ?1",
                            params![&env.id, env.sync_revision],
                        )?;
                        continue;
                    }
                }
            }

            self.conn.execute(
                "INSERT INTO vault_items
                    (id, entity_type, ciphertext, nonce, schema_version, updated_at, deleted_at, sync_revision, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)
                 ON CONFLICT(id) DO UPDATE SET
                    entity_type = excluded.entity_type,
                    ciphertext = excluded.ciphertext,
                    nonce = excluded.nonce,
                    schema_version = excluded.schema_version,
                    updated_at = excluded.updated_at,
                    deleted_at = excluded.deleted_at,
                    sync_revision = excluded.sync_revision,
                    dirty = 0",
                params![
                    &env.id,
                    &env.entity_type,
                    ciphertext,
                    nonce,
                    env.schema_version,
                    env.updated_at,
                    env.deleted_at,
                    env.sync_revision,
                ],
            )?;
            applied += 1;
        }

        Ok(SyncApplyResult { applied, conflicts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CredentialKind;

    #[test]
    fn vault_lifecycle_crud_and_rekey() {
        let mut store = VaultStore::open_in_memory().expect("open");
        assert!(!store.is_initialized().unwrap());

        store.initialize_vault("master-123", false).expect("init");
        assert!(store.is_unlocked());

        let host = store
            .upsert_host(HostRecord {
                id: String::new(),
                label: "Prod API".into(),
                hostname: "10.0.0.5".into(),
                port: 22,
                username: "deploy".into(),
                group_id: None,
                tags: vec!["prod".into()],
                credential_id: None,
                jump_host_id: None,
                terminal_theme: Some("obsidian".into()),
                keepalive_secs: 30,
                startup_command: None,
                notes: None,
                updated_at: 0,
            })
            .expect("upsert host");

        let _cred = store
            .upsert_credential(CredentialRecord {
                id: String::new(),
                label: "Deploy Key".into(),
                kind: CredentialKind::Password,
                username: Some("deploy".into()),
                password: Some("s3cr3t".into()),
                private_key_pem: None,
                passphrase: None,
                certificate_openssh: None,
                public_key_openssh: None,
                fingerprint_sha256: None,
                updated_at: 0,
            })
            .expect("upsert cred");

        store.lock();
        assert!(store.list_hosts().is_err());
        assert!(store.unlock_with_password("wrong", None).is_err());

        store
            .unlock_with_password("master-123", None)
            .expect("unlock");
        assert_eq!(store.list_hosts().unwrap().len(), 1);

        // Re-key master password
        store
            .change_master_password("master-123", "new-master-456")
            .expect("rekey");
        store.lock();
        assert!(store.unlock_with_password("master-123", None).is_err());
        store
            .unlock_with_password("new-master-456", None)
            .expect("unlock new");
        assert_eq!(store.get_host(&host.id).unwrap().hostname, "10.0.0.5");

        store.soft_delete_item(&host.id).expect("delete");
        assert!(store.list_hosts().unwrap().is_empty());
        assert!(!store.list_dirty_envelopes().unwrap().is_empty());
    }
}
