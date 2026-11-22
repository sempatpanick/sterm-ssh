use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use core_crypto::{
    cipher::{decrypt_aead, encrypt_aead},
    kdf::{derive_keys, generate_salt, KdfParams},
};
use serde::{Deserialize, Serialize};

use crate::{
    models::{
        CommandRecord, CredentialRecord, GroupRecord, HostRecord, KnownHostRecord,
        PortForwardRecord,
    },
    store::VaultStore,
    VaultError, VaultResult,
};

const BACKUP_MAGIC: &str = "STERM_VAULT_BACKUP_V1";
const BACKUP_AAD: &[u8] = b"sterm-backup-envelope-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEnvelope {
    magic: String,
    salt_b64: String,
    kdf_params: KdfParams,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupPayload {
    hosts: Vec<HostRecord>,
    groups: Vec<GroupRecord>,
    credentials: Vec<CredentialRecord>,
    known_hosts: Vec<KnownHostRecord>,
    #[serde(default)]
    commands: Vec<CommandRecord>,
    #[serde(default)]
    port_forwards: Vec<PortForwardRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupImportReport {
    pub hosts: usize,
    pub groups: usize,
    pub credentials: usize,
    pub known_hosts: usize,
    #[serde(default)]
    pub port_forwards: usize,
}

pub fn export_encrypted_backup(
    store: &VaultStore,
    backup_passphrase: &str,
    dest_path: &Path,
) -> VaultResult<()> {
    let payload = BackupPayload {
        hosts: store.list_hosts()?,
        groups: store.list_groups()?,
        credentials: store.list_credentials_full()?,
        known_hosts: store.list_known_hosts()?,
        commands: store.list_commands()?,
        port_forwards: store.list_port_forwards()?,
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let salt = generate_salt();
    let kdf_params = KdfParams::default();
    let derived = derive_keys(backup_passphrase, &salt, &kdf_params)?;
    let blob = encrypt_aead(&derived.vault_key, &plaintext, BACKUP_AAD)?;

    let env = BackupEnvelope {
        magic: BACKUP_MAGIC.to_string(),
        salt_b64: B64.encode(salt),
        kdf_params,
        nonce_b64: B64.encode(blob.nonce),
        ciphertext_b64: B64.encode(blob.ciphertext),
    };
    let json = serde_json::to_vec_pretty(&env)?;
    std::fs::write(dest_path, json)?;
    Ok(())
}

pub fn import_encrypted_backup(
    store: &VaultStore,
    backup_passphrase: &str,
    src_path: &Path,
) -> VaultResult<BackupImportReport> {
    let raw = std::fs::read(src_path)?;
    let env: BackupEnvelope =
        serde_json::from_slice(&raw).map_err(|e| VaultError::InvalidBackup(e.to_string()))?;

    if env.magic != BACKUP_MAGIC {
        return Err(VaultError::InvalidBackup(format!(
            "unsupported backup header: {}",
            env.magic
        )));
    }

    let salt = B64
        .decode(&env.salt_b64)
        .map_err(|e| VaultError::InvalidBackup(e.to_string()))?;
    let nonce = B64
        .decode(&env.nonce_b64)
        .map_err(|e| VaultError::InvalidBackup(e.to_string()))?;
    let ciphertext = B64
        .decode(&env.ciphertext_b64)
        .map_err(|e| VaultError::InvalidBackup(e.to_string()))?;

    let derived = derive_keys(backup_passphrase, &salt, &env.kdf_params)?;
    let plaintext = decrypt_aead(&derived.vault_key, &nonce, &ciphertext, BACKUP_AAD)
        .map_err(|_| VaultError::InvalidPassword)?;

    let payload: BackupPayload = serde_json::from_slice(&plaintext)?;

    let mut report = BackupImportReport {
        hosts: 0,
        groups: 0,
        credentials: 0,
        known_hosts: 0,
        port_forwards: 0,
    };

    for g in payload.groups {
        store.upsert_group(g)?;
        report.groups += 1;
    }
    for c in payload.credentials {
        store.upsert_credential(c)?;
        report.credentials += 1;
    }
    for kh in payload.known_hosts {
        store.upsert_known_host(kh)?;
        report.known_hosts += 1;
    }
    for h in payload.hosts {
        store.upsert_host(h)?;
        report.hosts += 1;
    }
    for cmd in payload.commands {
        store.upsert_command(cmd)?;
    }
    for pf in payload.port_forwards {
        store.upsert_port_forward(pf)?;
        report.port_forwards += 1;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_backup_export_and_restore() {
        let src_pw = uuid::Uuid::new_v4().to_string();
        let dst_pw = uuid::Uuid::new_v4().to_string();
        let archive_pw = uuid::Uuid::new_v4().to_string();
        let wrong_pw = uuid::Uuid::new_v4().to_string();

        let mut src = VaultStore::open_in_memory().unwrap();
        src.initialize_vault(&src_pw, false).unwrap();
        src.upsert_host(HostRecord {
            id: String::new(),
            label: "Edge".into(),
            hostname: "edge.internal".into(),
            port: 22,
            username: "admin".into(),
            group_id: None,
            tags: vec![],
            credential_id: None,
            jump_host_id: None,
            terminal_theme: None,
            keepalive_secs: 30,
            startup_command: None,
            notes: None,
            auth_mode: Default::default(),
            forward_agent: false,
            proxy_url: None,
            favorite: false,
            last_connected_at: None,
            updated_at: 0,
        })
        .unwrap();

        let tmp = std::env::temp_dir().join("sterm-test-backup.sterm-vault");
        export_encrypted_backup(&src, &archive_pw, &tmp).unwrap();

        let mut dst = VaultStore::open_in_memory().unwrap();
        dst.initialize_vault(&dst_pw, false).unwrap();

        // Wrong backup password fails
        assert!(import_encrypted_backup(&dst, &wrong_pw, &tmp).is_err());

        // Correct password restores
        let rep = import_encrypted_backup(&dst, &archive_pw, &tmp).unwrap();
        assert_eq!(rep.hosts, 1);
        assert_eq!(dst.list_hosts().unwrap()[0].hostname, "edge.internal");

        let _ = std::fs::remove_file(&tmp);
    }
}
