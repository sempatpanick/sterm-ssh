use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use core_ssh::manager::SshSessionManager;
use dashmap::DashMap;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::types::{FileEntry, TransferDirection, TransferProgress, TransferStatus};
use crate::{SftpError, SftpResult};

const CHUNK_SIZE: usize = 64 * 1024;
const MAX_INLINE_EDIT_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB

pub struct SftpManager {
    sessions: DashMap<String, Arc<SftpSession>>,
    transfers: DashMap<String, CancellationToken>,
}

impl Default for SftpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            transfers: DashMap::new(),
        }
    }

    pub async fn attach_to_ssh(
        &self,
        ssh: &SshSessionManager,
        session_id: &str,
    ) -> SftpResult<String> {
        if let Some(existing) = self.sessions.get(session_id) {
            let cwd = existing
                .canonicalize(".")
                .await
                .unwrap_or_else(|_| "/".to_string());
            return Ok(cwd);
        }

        let stream = ssh.open_sftp_stream(session_id).await?;
        let sftp = SftpSession::new(stream)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;
        let cwd = sftp
            .canonicalize(".")
            .await
            .unwrap_or_else(|_| "/".to_string());

        self.sessions.insert(session_id.to_string(), Arc::new(sftp));
        Ok(cwd)
    }

    fn get_session(&self, session_id: &str) -> SftpResult<Arc<SftpSession>> {
        self.sessions
            .get(session_id)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| SftpError::SessionNotFound(session_id.to_string()))
    }

    pub async fn close(&self, session_id: &str) {
        if let Some((_, sftp)) = self.sessions.remove(session_id) {
            let _ = sftp.close().await;
        }
    }

    pub fn default_local_dir() -> String {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .to_string_lossy()
            .to_string()
    }

    pub async fn list_local_dir(path: &str) -> SftpResult<(String, Vec<FileEntry>)> {
        let dir_path = normalize_local_dir_path(path);
        let canonical = tokio::fs::canonicalize(&dir_path)
            .await
            .unwrap_or(dir_path.clone());
        let mut rd = tokio::fs::read_dir(&canonical).await?;
        let mut entries = Vec::new();

        while let Some(ent) = rd.next_entry().await? {
            let meta = match ent.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ft = ent.file_type().await.ok();
            let modified_at = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            #[cfg(unix)]
            let permissions = {
                use std::os::unix::fs::PermissionsExt;
                Some(meta.permissions().mode() & 0o7777)
            };
            #[cfg(not(unix))]
            let permissions = None;

            entries.push(FileEntry {
                name: ent.file_name().to_string_lossy().to_string(),
                path: ent.path().to_string_lossy().to_string(),
                is_dir: meta.is_dir(),
                is_symlink: ft.map(|f| f.is_symlink()).unwrap_or(false),
                size: meta.len(),
                modified_at,
                permissions,
            });
        }

        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        // Strip Windows verbatim prefix `\\?\` for clean display
        let display_path = canonical
            .to_string_lossy()
            .strip_prefix(r"\\?\")
            .map(|s| s.to_string())
            .unwrap_or_else(|| canonical.to_string_lossy().to_string());

        Ok((display_path, entries))
    }

    pub async fn list_remote_dir(
        &self,
        session_id: &str,
        path: &str,
    ) -> SftpResult<(String, Vec<FileEntry>)> {
        let sftp = self.get_session(session_id)?;
        let trimmed = strip_surrounding_quotes(path.trim());
        let target = if trimmed.is_empty() || trimmed == "~" {
            ".".to_string()
        } else if let Some(rest) = trimmed.strip_prefix("~/") {
            let home = sftp
                .canonicalize(".")
                .await
                .map_err(|e| SftpError::Protocol(e.to_string()))?;
            let rest = rest.trim_start_matches('/');
            if rest.is_empty() {
                home
            } else if home == "/" {
                format!("/{rest}")
            } else {
                format!("{}/{rest}", home.trim_end_matches('/'))
            }
        } else {
            trimmed.to_string()
        };

        let resolved = sftp
            .canonicalize(&target)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;

        let read_dir = sftp
            .read_dir(&resolved)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;

        let mut entries = Vec::new();
        for item in read_dir {
            let name = item.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let meta = item.metadata();
            let full_path = if resolved == "/" {
                format!("/{name}")
            } else {
                format!("{}/{name}", resolved.trim_end_matches('/'))
            };
            entries.push(FileEntry {
                name,
                path: full_path,
                is_dir: meta.is_dir(),
                is_symlink: meta.is_symlink(),
                size: meta.size.unwrap_or(0),
                modified_at: meta.mtime.map(|m| m as u64),
                permissions: meta.permissions.map(|p| p & 0o7777),
            });
        }

        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        Ok((resolved, entries))
    }

    pub async fn remote_mkdir(&self, session_id: &str, remote_path: &str) -> SftpResult<()> {
        let sftp = self.get_session(session_id)?;
        sftp.create_dir(remote_path)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))
    }

    pub async fn remote_rename(
        &self,
        session_id: &str,
        old_path: &str,
        new_path: &str,
    ) -> SftpResult<()> {
        let sftp = self.get_session(session_id)?;
        sftp.rename(old_path, new_path)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))
    }

    pub async fn remote_delete(
        &self,
        session_id: &str,
        remote_path: &str,
        is_dir: bool,
    ) -> SftpResult<()> {
        let sftp = self.get_session(session_id)?;
        if is_dir {
            sftp.remove_dir(remote_path)
                .await
                .map_err(|e| SftpError::Protocol(e.to_string()))
        } else {
            sftp.remove_file(remote_path)
                .await
                .map_err(|e| SftpError::Protocol(e.to_string()))
        }
    }

    pub async fn remote_chmod(
        &self,
        session_id: &str,
        remote_path: &str,
        mode: u32,
    ) -> SftpResult<()> {
        let sftp = self.get_session(session_id)?;
        let attrs = FileAttributes {
            permissions: Some(mode & 0o7777),
            ..Default::default()
        };
        sftp.set_metadata(remote_path, attrs)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))
    }

    pub async fn read_remote_text(&self, session_id: &str, remote_path: &str) -> SftpResult<String> {
        let sftp = self.get_session(session_id)?;
        let meta = sftp
            .metadata(remote_path)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;
        let size = meta.size.unwrap_or(0);
        if size > MAX_INLINE_EDIT_BYTES {
            return Err(SftpError::FileTooLarge {
                size,
                max: MAX_INLINE_EDIT_BYTES,
            });
        }
        let bytes = sftp
            .read(remote_path)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub async fn write_remote_text(
        &self,
        session_id: &str,
        remote_path: &str,
        content: &str,
    ) -> SftpResult<()> {
        let sftp = self.get_session(session_id)?;
        let mut remote_file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;
        remote_file.write_all(content.as_bytes()).await?;
        remote_file.flush().await?;
        Ok(())
    }

    pub fn cancel_transfer(&self, transfer_id: &str) -> bool {
        if let Some((_, tok)) = self.transfers.remove(transfer_id) {
            tok.cancel();
            true
        } else {
            false
        }
    }

    pub async fn upload_file<F>(
        &self,
        session_id: &str,
        local_path: &Path,
        remote_path: &str,
        mut on_progress: F,
    ) -> SftpResult<String>
    where
        F: FnMut(TransferProgress),
    {
        let sftp = self.get_session(session_id)?;
        let transfer_id = Uuid::now_v7().to_string();
        let token = CancellationToken::new();
        self.transfers.insert(transfer_id.clone(), token.clone());

        let meta = tokio::fs::metadata(local_path).await?;
        let total_bytes = meta.len();
        let file_name = local_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let mut local_file = tokio::fs::File::open(local_path).await?;
        let mut remote_file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;

        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut transferred = 0u64;

        let res: SftpResult<()> = async {
            loop {
                if token.is_cancelled() {
                    return Err(SftpError::Cancelled);
                }
                let n = local_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                remote_file.write_all(&buf[..n]).await?;
                transferred += n as u64;
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Upload,
                    file_name: file_name.clone(),
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Running,
                    error: None,
                });
            }
            remote_file.flush().await?;
            Ok(())
        }
        .await;

        self.transfers.remove(&transfer_id);

        match res {
            Ok(()) => {
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Upload,
                    file_name,
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Completed,
                    error: None,
                });
                Ok(transfer_id)
            }
            Err(SftpError::Cancelled) => {
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Upload,
                    file_name,
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Cancelled,
                    error: None,
                });
                Err(SftpError::Cancelled)
            }
            Err(e) => {
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Upload,
                    file_name,
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Failed,
                    error: Some(e.to_string()),
                });
                Err(e)
            }
        }
    }

    pub async fn download_file<F>(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &Path,
        mut on_progress: F,
    ) -> SftpResult<String>
    where
        F: FnMut(TransferProgress),
    {
        let sftp = self.get_session(session_id)?;
        let transfer_id = Uuid::now_v7().to_string();
        let token = CancellationToken::new();
        self.transfers.insert(transfer_id.clone(), token.clone());

        let meta = sftp
            .metadata(remote_path)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;
        let total_bytes = meta.size.unwrap_or(0);
        let file_name = remote_path
            .rsplit('/')
            .next()
            .unwrap_or("file")
            .to_string();

        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut remote_file = sftp
            .open(remote_path)
            .await
            .map_err(|e| SftpError::Protocol(e.to_string()))?;
        let mut local_file = tokio::fs::File::create(local_path).await?;

        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut transferred = 0u64;

        let res: SftpResult<()> = async {
            loop {
                if token.is_cancelled() {
                    return Err(SftpError::Cancelled);
                }
                let n = remote_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                local_file.write_all(&buf[..n]).await?;
                transferred += n as u64;
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Download,
                    file_name: file_name.clone(),
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Running,
                    error: None,
                });
            }
            local_file.flush().await?;
            Ok(())
        }
        .await;

        self.transfers.remove(&transfer_id);

        match res {
            Ok(()) => {
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Download,
                    file_name,
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Completed,
                    error: None,
                });
                Ok(transfer_id)
            }
            Err(SftpError::Cancelled) => {
                let _ = tokio::fs::remove_file(local_path).await;
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Download,
                    file_name,
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Cancelled,
                    error: None,
                });
                Err(SftpError::Cancelled)
            }
            Err(e) => {
                on_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Download,
                    file_name,
                    local_path: local_path.to_string_lossy().to_string(),
                    remote_path: remote_path.to_string(),
                    bytes_transferred: transferred,
                    total_bytes,
                    status: TransferStatus::Failed,
                    error: Some(e.to_string()),
                });
                Err(e)
            }
        }
    }
}

fn strip_surrounding_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn normalize_local_dir_path(path: &str) -> PathBuf {
    let trimmed = strip_surrounding_quotes(path.trim()).trim();
    if trimmed.is_empty() || trimmed == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let rest = rest.trim_start_matches(['/', '\\']);
        return if rest.is_empty() {
            home
        } else {
            home.join(rest)
        };
    }
    // Windows bare drive shorthand like "C:" -> "C:\\"
    let bytes = trimmed.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return PathBuf::from(format!("{trimmed}\\"));
    }
    PathBuf::from(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_local_quotes_tilde_and_drive() {
        assert_eq!(strip_surrounding_quotes(r#""C:\Users\me""#), r"C:\Users\me");
        assert_eq!(strip_surrounding_quotes("'/var/log'"), "/var/log");
        assert_eq!(strip_surrounding_quotes("/var/log"), "/var/log");

        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        assert_eq!(normalize_local_dir_path(""), home);
        assert_eq!(normalize_local_dir_path("  ~  "), home);
        assert_eq!(normalize_local_dir_path("~/Documents"), home.join("Documents"));
        assert_eq!(normalize_local_dir_path(r"~\Downloads"), home.join("Downloads"));
        assert_eq!(normalize_local_dir_path("C:"), PathBuf::from(r"C:\"));
        assert_eq!(
            normalize_local_dir_path(r#" "C:\Temp" "#),
            PathBuf::from(r"C:\Temp")
        );
    }
}
