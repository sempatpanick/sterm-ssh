use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use core_crypto::ssh_keygen::inspect_private_key;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};

use crate::{
    models::{CredentialKind, CredentialRecord, GroupRecord, HostRecord},
    store::VaultStore,
    VaultResult,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedSshHost {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub forward_agent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshImportSummary {
    pub imported_hosts: usize,
    pub imported_keys: usize,
    pub skipped_duplicates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSshDiscovery {
    pub ssh_dir_path: String,
    pub new_hosts_count: usize,
    pub new_keys_count: usize,
    pub host_aliases: Vec<String>,
    pub key_names: Vec<String>,
    pub auto_import_enabled: bool,
    pub prompt_dismissed: bool,
}

pub fn default_ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

pub fn default_ssh_config_path() -> Option<PathBuf> {
    default_ssh_dir().map(|d| d.join("config"))
}

pub fn expand_tilde(path_str: &str) -> PathBuf {
    let trimmed = path_str.trim().trim_matches('"');
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(trimmed)
}

#[derive(Default, Clone)]
struct RawBlock {
    patterns: Vec<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    forward_agent: Option<bool>,
}

/// Expands `Include` directives recursively (up to depth 5) relative to the ssh directory.
fn load_config_with_includes(path: &Path, ssh_dir: &Path, depth: usize) -> String {
    if depth > 5 {
        return String::new();
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let mut combined = String::new();
    for raw_line in content.lines() {
        let stripped = raw_line.split('#').next().unwrap_or("").trim();
        let lower = stripped.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("include ") {
            let orig_rest = stripped[stripped.len() - rest.len()..].trim();
            for pattern in orig_rest.split_whitespace() {
                for inc_path in resolve_include_paths(pattern, ssh_dir) {
                    combined.push('\n');
                    combined.push_str(&load_config_with_includes(&inc_path, ssh_dir, depth + 1));
                    combined.push('\n');
                }
            }
        } else {
            combined.push_str(raw_line);
            combined.push('\n');
        }
    }
    combined
}

fn resolve_include_paths(pattern: &str, ssh_dir: &Path) -> Vec<PathBuf> {
    let expanded = expand_tilde(pattern);
    let full = if expanded.is_absolute() {
        expanded
    } else {
        ssh_dir.join(expanded)
    };

    let full_str = full.to_string_lossy();
    if !full_str.contains('*') {
        return if full.is_file() { vec![full] } else { vec![] };
    }

    let Some(parent) = full.parent() else {
        return vec![];
    };
    let Some(file_pat) = full.file_name().and_then(|s| s.to_str()) else {
        return vec![];
    };
    let Ok(rd) = std::fs::read_dir(parent) else {
        return vec![];
    };

    let mut matches = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if simple_glob_match(file_pat, &name) {
            matches.push(p);
        }
    }
    matches.sort();
    matches
}

fn simple_glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return text.starts_with(prefix) && text.ends_with(suffix);
    }
    pattern == text
}

/// Parses an OpenSSH config string (supporting `Host`, `HostName`, `User`, `Port`,
/// `IdentityFile`, `ProxyJump`, `ForwardAgent`, and global `Host *` defaults).
pub fn parse_ssh_config_str(content: &str) -> Vec<ParsedSshHost> {
    let mut blocks: Vec<RawBlock> = Vec::new();
    let mut current: Option<RawBlock> = None;

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let (key, val) = if let Some((k, v)) = line.split_once('=') {
            (k.trim().to_ascii_lowercase(), v.trim().to_string())
        } else {
            let mut parts = line.splitn(2, char::is_whitespace);
            let k = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let v = parts.next().unwrap_or("").trim().to_string();
            (k, v)
        };

        if val.is_empty() {
            continue;
        }

        let unquoted = val.trim_matches('"').to_string();

        if key == "host" {
            if let Some(prev) = current.take() {
                blocks.push(prev);
            }
            let patterns = unquoted
                .split_whitespace()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            current = Some(RawBlock {
                patterns,
                ..Default::default()
            });
            continue;
        }

        let blk = current.get_or_insert_with(|| RawBlock {
            patterns: vec!["*".to_string()],
            ..Default::default()
        });

        match key.as_str() {
            "hostname" => blk.hostname.get_or_insert(unquoted),
            "user" => blk.user.get_or_insert(unquoted),
            "port" => {
                if let Ok(p) = unquoted.parse::<u16>() {
                    blk.port.get_or_insert(p);
                }
                continue;
            }
            "identityfile" => blk.identity_file.get_or_insert(unquoted),
            "proxyjump" => blk.proxy_jump.get_or_insert(unquoted),
            "forwardagent" => {
                blk.forward_agent
                    .get_or_insert(unquoted.eq_ignore_ascii_case("yes"));
                continue;
            }
            _ => continue,
        };
    }

    if let Some(last) = current {
        blocks.push(last);
    }

    // Collect `Host *` defaults
    let mut default_user: Option<String> = None;
    let mut default_port: Option<u16> = None;
    let mut default_identity: Option<String> = None;
    let mut default_forward_agent = false;

    for b in &blocks {
        if b.patterns.iter().any(|p| p == "*") {
            if default_user.is_none() {
                default_user.clone_from(&b.user);
            }
            if default_port.is_none() {
                default_port = b.port;
            }
            if default_identity.is_none() {
                default_identity.clone_from(&b.identity_file);
            }
            if let Some(fa) = b.forward_agent {
                default_forward_agent = fa;
            }
        }
    }

    let fallback_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());

    let mut parsed = Vec::new();
    for b in blocks {
        for pat in &b.patterns {
            if pat.contains('*') || pat.contains('?') || pat.starts_with('!') {
                continue;
            }
            parsed.push(ParsedSshHost {
                alias: pat.clone(),
                hostname: b.hostname.clone().unwrap_or_else(|| pat.clone()),
                port: b.port.or(default_port).unwrap_or(22),
                username: b
                    .user
                    .clone()
                    .or_else(|| default_user.clone())
                    .unwrap_or_else(|| fallback_user.clone()),
                identity_file: b.identity_file.clone().or_else(|| default_identity.clone()),
                proxy_jump: b.proxy_jump.clone(),
                forward_agent: b.forward_agent.unwrap_or(default_forward_agent),
            });
        }
    }

    parsed
}

pub fn parse_ssh_config_file(path: &Path) -> VaultResult<Vec<ParsedSshHost>> {
    let ssh_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let text = load_config_with_includes(path, ssh_dir, 0);
    Ok(parse_ssh_config_str(&text))
}

fn read_key_metadata(key_path: &Path, pem: &str) -> (Option<String>, Option<String>) {
    if let Ok((pk, fp)) = inspect_private_key(pem, None) {
        return (Some(pk), Some(fp));
    }
    // Fallback for passphrase-protected keys: inspect sibling `<key>.pub`
    let mut pub_path = key_path.as_os_str().to_os_string();
    pub_path.push(".pub");
    if let Ok(pub_text) = std::fs::read_to_string(PathBuf::from(pub_path)) {
        let trimmed = pub_text.trim();
        if let Ok(pk) = PublicKey::from_openssh(trimmed) {
            let fp = pk.fingerprint(HashAlg::Sha256).to_string();
            return (Some(trimmed.to_string()), Some(fp));
        }
    }
    (None, None)
}

fn looks_like_private_key(content: &str) -> bool {
    let first = content.lines().next().unwrap_or("").trim();
    first.starts_with("-----BEGIN ") && first.contains("PRIVATE KEY-----")
}

fn import_key_file_if_new(
    store: &VaultStore,
    key_path: &Path,
    username_hint: Option<String>,
    existing_labels: &mut HashSet<String>,
    existing_fps: &mut HashSet<String>,
    label_to_id: &mut HashMap<String, String>,
    fp_to_id: &mut HashMap<String, String>,
) -> VaultResult<(Option<String>, bool)> {
    let Ok(pem) = std::fs::read_to_string(key_path) else {
        return Ok((None, false));
    };
    if !looks_like_private_key(&pem) {
        return Ok((None, false));
    }

    let file_name = key_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("id_ssh")
        .to_string();
    let label = format!("~/.ssh/{file_name}");
    let label_lower = label.to_ascii_lowercase();
    let (pub_key, fp) = read_key_metadata(key_path, &pem);

    if let Some(ref f) = fp {
        if existing_fps.contains(f) {
            return Ok((fp_to_id.get(f).cloned(), false));
        }
    }
    if existing_labels.contains(&label_lower) {
        return Ok((label_to_id.get(&label_lower).cloned(), false));
    }

    let summary = store.upsert_credential(CredentialRecord {
        id: String::new(),
        label: label.clone(),
        kind: CredentialKind::PrivateKey,
        username: username_hint,
        password: None,
        private_key_pem: Some(pem),
        passphrase: None,
        certificate_openssh: None,
        public_key_openssh: pub_key,
        fingerprint_sha256: fp.clone(),
        updated_at: 0,
    })?;

    existing_labels.insert(label_lower.clone());
    label_to_id.insert(label_lower, summary.id.clone());
    if let Some(f) = fp {
        existing_fps.insert(f.clone());
        fp_to_id.insert(f, summary.id.clone());
    }
    Ok((Some(summary.id), true))
}

/// Imports parsed SSH hosts (and referenced identity files) into the encrypted vault,
/// wiring up `ProxyJump` references automatically when jump targets exist.
pub fn import_parsed_hosts(
    store: &VaultStore,
    entries: &[ParsedSshHost],
) -> VaultResult<SshImportSummary> {
    import_parsed_hosts_with_dir(store, entries, default_ssh_dir().as_deref())
}

fn import_parsed_hosts_with_dir(
    store: &VaultStore,
    entries: &[ParsedSshHost],
    ssh_dir: Option<&Path>,
) -> VaultResult<SshImportSummary> {
    let existing_hosts = store.list_hosts()?;
    let mut alias_to_id: HashMap<String, String> = existing_hosts
        .iter()
        .map(|h| (h.label.to_ascii_lowercase(), h.id.clone()))
        .collect();

    let existing_creds = store.list_credentials_summary()?;
    let mut existing_labels: HashSet<String> = existing_creds
        .iter()
        .map(|c| c.label.to_ascii_lowercase())
        .collect();
    let mut existing_fps: HashSet<String> = existing_creds
        .iter()
        .filter_map(|c| c.fingerprint_sha256.clone())
        .collect();
    let mut label_to_id: HashMap<String, String> = existing_creds
        .iter()
        .map(|c| (c.label.to_ascii_lowercase(), c.id.clone()))
        .collect();
    let mut fp_to_id: HashMap<String, String> = existing_creds
        .iter()
        .filter_map(|c| c.fingerprint_sha256.clone().map(|f| (f, c.id.clone())))
        .collect();

    let mut imported_hosts = 0usize;
    let mut imported_keys = 0usize;
    let mut skipped_duplicates = 0usize;
    let mut pending_jumps: Vec<(HostRecord, String)> = Vec::new();

    for entry in entries {
        if alias_to_id.contains_key(&entry.alias.to_ascii_lowercase()) {
            skipped_duplicates += 1;
            continue;
        }

        let mut credential_id: Option<String> = None;
        if let Some(ref id_file) = entry.identity_file {
            let expanded = expand_tilde(id_file);
            let resolved = if expanded.is_absolute() {
                expanded
            } else if let Some(dir) = ssh_dir {
                dir.join(expanded)
            } else {
                expanded
            };
            let (cid, created) = import_key_file_if_new(
                store,
                &resolved,
                Some(entry.username.clone()),
                &mut existing_labels,
                &mut existing_fps,
                &mut label_to_id,
                &mut fp_to_id,
            )?;
            credential_id = cid;
            if created {
                imported_keys += 1;
            }
        }

        let saved = store.upsert_host(HostRecord {
            id: String::new(),
            label: entry.alias.clone(),
            hostname: entry.hostname.clone(),
            port: entry.port,
            username: entry.username.clone(),
            group_id: None,
            tags: vec!["ssh-config".to_string()],
            credential_id,
            jump_host_id: None,
            terminal_theme: None,
            keepalive_secs: 30,
            startup_command: None,
            notes: Some("Imported from ~/.ssh/config".to_string()),
            auth_mode: Default::default(),
            forward_agent: entry.forward_agent,
            proxy_url: None,
            favorite: false,
            last_connected_at: None,
            updated_at: 0,
        })?;

        alias_to_id.insert(entry.alias.to_ascii_lowercase(), saved.id.clone());
        if let Some(ref jump) = entry.proxy_jump {
            pending_jumps.push((saved, jump.clone()));
        }
        imported_hosts += 1;
    }

    // Second pass: resolve ProxyJump aliases to jump_host_id
    for (mut host, jump_alias) in pending_jumps {
        let primary_jump = jump_alias.split(',').next().unwrap_or(&jump_alias).trim();
        if let Some(jump_id) = alias_to_id.get(&primary_jump.to_ascii_lowercase()) {
            if jump_id != &host.id {
                host.jump_host_id = Some(jump_id.clone());
                let _ = store.upsert_host(host);
            }
        }
    }

    Ok(SshImportSummary {
        imported_hosts,
        imported_keys,
        skipped_duplicates,
    })
}

/// Read-only scan of `~/.ssh` reporting how many unimported hosts and private keys exist,
/// plus the user's saved opt-in preference (`auto_import_enabled`, `prompt_dismissed`).
pub fn detect_local_ssh_dir(
    store: &VaultStore,
    ssh_dir_override: Option<&Path>,
) -> VaultResult<LocalSshDiscovery> {
    let auto_import_enabled = store
        .get_meta_string("ssh_auto_import_enabled")?
        .as_deref()
        == Some("1");
    let prompt_dismissed = store
        .get_meta_string("ssh_import_prompt_dismissed")?
        .as_deref()
        == Some("1");

    let Some(ssh_dir) = ssh_dir_override
        .map(PathBuf::from)
        .or_else(default_ssh_dir)
    else {
        return Ok(LocalSshDiscovery {
            ssh_dir_path: String::new(),
            new_hosts_count: 0,
            new_keys_count: 0,
            host_aliases: vec![],
            key_names: vec![],
            auto_import_enabled,
            prompt_dismissed,
        });
    };

    let ssh_dir_path = ssh_dir.to_string_lossy().to_string();
    if !ssh_dir.is_dir() {
        return Ok(LocalSshDiscovery {
            ssh_dir_path,
            new_hosts_count: 0,
            new_keys_count: 0,
            host_aliases: vec![],
            key_names: vec![],
            auto_import_enabled,
            prompt_dismissed,
        });
    }

    let existing_hosts: HashSet<String> = store
        .list_hosts()?
        .into_iter()
        .map(|h| h.label.to_ascii_lowercase())
        .collect();
    let existing_creds = store.list_credentials_summary()?;
    let existing_labels: HashSet<String> = existing_creds
        .iter()
        .map(|c| c.label.to_ascii_lowercase())
        .collect();
    let existing_fps: HashSet<String> = existing_creds
        .iter()
        .filter_map(|c| c.fingerprint_sha256.clone())
        .collect();

    let mut host_aliases = Vec::new();
    let config_path = ssh_dir.join("config");
    if config_path.is_file() {
        if let Ok(parsed) = parse_ssh_config_file(&config_path) {
            for h in parsed {
                if !existing_hosts.contains(&h.alias.to_ascii_lowercase()) {
                    host_aliases.push(h.alias);
                }
            }
        }
    }

    let mut key_names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&ssh_dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            let lower = name.to_ascii_lowercase();
            if lower == "config"
                || lower.starts_with("known_hosts")
                || lower.starts_with("authorized_keys")
                || lower.ends_with(".pub")
                || lower.ends_with(".ppk")
            {
                continue;
            }
            if ent.metadata().map(|m| m.len() > 262_144).unwrap_or(true) {
                continue;
            }
            let Ok(pem) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !looks_like_private_key(&pem) {
                continue;
            }
            let label_lower = format!("~/.ssh/{name}").to_ascii_lowercase();
            let (_, fp) = read_key_metadata(&path, &pem);
            let already = existing_labels.contains(&label_lower)
                || fp.as_ref().is_some_and(|f| existing_fps.contains(f));
            if !already {
                key_names.push(name);
            }
        }
    }
    key_names.sort();

    Ok(LocalSshDiscovery {
        ssh_dir_path,
        new_hosts_count: host_aliases.len(),
        new_keys_count: key_names.len(),
        host_aliases,
        key_names,
        auto_import_enabled,
        prompt_dismissed,
    })
}

/// Scans an `.ssh` directory (defaulting to `~/.ssh`) for:
/// 1. `config` (including `Include` directives) -> hosts + linked keys + ProxyJump chains
/// 2. Any standalone private key files (e.g. `id_ed25519`, `id_rsa`, `*.pem`) -> Keychain
///
/// Fully idempotent: skips already-imported hosts and keys cleanly.
pub fn sync_local_ssh_dir(
    store: &VaultStore,
    ssh_dir_override: Option<&Path>,
) -> VaultResult<SshImportSummary> {
    let Some(ssh_dir) = ssh_dir_override
        .map(PathBuf::from)
        .or_else(default_ssh_dir)
    else {
        return Ok(SshImportSummary {
            imported_hosts: 0,
            imported_keys: 0,
            skipped_duplicates: 0,
        });
    };

    if !ssh_dir.is_dir() {
        return Ok(SshImportSummary {
            imported_hosts: 0,
            imported_keys: 0,
            skipped_duplicates: 0,
        });
    }

    let mut total = SshImportSummary {
        imported_hosts: 0,
        imported_keys: 0,
        skipped_duplicates: 0,
    };

    // 1. Parse & import ~/.ssh/config (+ Includes)
    let config_path = ssh_dir.join("config");
    if config_path.is_file() {
        let parsed = parse_ssh_config_file(&config_path)?;
        let res = import_parsed_hosts_with_dir(store, &parsed, Some(&ssh_dir))?;
        total.imported_hosts += res.imported_hosts;
        total.imported_keys += res.imported_keys;
        total.skipped_duplicates += res.skipped_duplicates;
    }

    // 2. Discover standalone private keys in ~/.ssh (e.g. id_ed25519, id_rsa, custom .pem)
    let existing_creds = store.list_credentials_summary()?;
    let mut existing_labels: HashSet<String> = existing_creds
        .iter()
        .map(|c| c.label.to_ascii_lowercase())
        .collect();
    let mut existing_fps: HashSet<String> = existing_creds
        .iter()
        .filter_map(|c| c.fingerprint_sha256.clone())
        .collect();
    let mut label_to_id: HashMap<String, String> = existing_creds
        .iter()
        .map(|c| (c.label.to_ascii_lowercase(), c.id.clone()))
        .collect();
    let mut fp_to_id: HashMap<String, String> = existing_creds
        .iter()
        .filter_map(|c| c.fingerprint_sha256.clone().map(|f| (f, c.id.clone())))
        .collect();

    if let Ok(rd) = std::fs::read_dir(&ssh_dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            let lower = name.to_ascii_lowercase();
            if lower == "config"
                || lower.starts_with("known_hosts")
                || lower.starts_with("authorized_keys")
                || lower.ends_with(".pub")
                || lower.ends_with(".ppk")
            {
                continue;
            }
            // Skip oversized files (> 256 KiB cannot be an SSH private key)
            if ent.metadata().map(|m| m.len() > 262_144).unwrap_or(true) {
                continue;
            }
            let (_, created) = import_key_file_if_new(
                store,
                &path,
                None,
                &mut existing_labels,
                &mut existing_fps,
                &mut label_to_id,
                &mut fp_to_id,
            )?;
            if created {
                total.imported_keys += 1;
            }
        }
    }

    Ok(total)
}

/// Exports vault hosts into a clean, standards-compliant OpenSSH `~/.ssh/config` file.
pub fn export_hosts_to_ssh_config(hosts: &[HostRecord], groups: &[GroupRecord]) -> String {
    let mut out = String::from("# Exported by STerm SSH\n\n");
    let sanitize_alias = |label: &str| -> String {
        let s: String = label
            .trim()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        if s.is_empty() {
            "host".to_string()
        } else {
            s
        }
    };

    let id_to_alias: HashMap<&str, String> = hosts
        .iter()
        .map(|h| (h.id.as_str(), sanitize_alias(&h.label)))
        .collect();
    let group_names: HashMap<&str, &str> = groups
        .iter()
        .map(|g| (g.id.as_str(), g.name.as_str()))
        .collect();

    for h in hosts {
        let alias = sanitize_alias(&h.label);
        let mut meta = Vec::new();
        if let Some(gname) = h
            .group_id
            .as_deref()
            .and_then(|gid| group_names.get(gid))
        {
            meta.push(format!("group:{gname}"));
        }
        if !h.tags.is_empty() {
            meta.push(format!("tags:{}", h.tags.join(",")));
        }
        if !meta.is_empty() {
            out.push_str(&format!("# {} ({})\n", h.label, meta.join(" · ")));
        }
        out.push_str(&format!("Host {alias}\n"));
        out.push_str(&format!("    HostName {}\n", h.hostname));
        if h.port != 22 {
            out.push_str(&format!("    Port {}\n", h.port));
        }
        if !h.username.is_empty() {
            out.push_str(&format!("    User {}\n", h.username));
        }
        if let Some(jump_alias) = h
            .jump_host_id
            .as_deref()
            .and_then(|jid| id_to_alias.get(jid))
        {
            out.push_str(&format!("    ProxyJump {jump_alias}\n"));
        }
        if h.forward_agent {
            out.push_str("    ForwardAgent yes\n");
        }
        if h.keepalive_secs > 0 {
            out.push_str(&format!("    ServerAliveInterval {}\n", h.keepalive_secs));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::ssh_keygen::generate_ed25519_keypair;

    #[test]
    fn parses_ssh_config_with_proxy_jump_and_wildcards() {
        let cfg = r#"
            # Bastion & internal nodes
            Host bastion
                HostName 203.0.113.10
                User ops
                Port 2222
                IdentityFile ~/.ssh/id_ed25519

            Host app-1 app-2
                HostName 10.0.1.20
                ProxyJump bastion

            Host *
                User ubuntu
                ForwardAgent yes
        "#;

        let hosts = parse_ssh_config_str(cfg);
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].alias, "bastion");
        assert_eq!(hosts[0].port, 2222);
        assert_eq!(hosts[0].username, "ops");
        assert_eq!(hosts[1].alias, "app-1");
        assert_eq!(hosts[1].username, "ubuntu");
        assert_eq!(hosts[1].proxy_jump.as_deref(), Some("bastion"));
        assert!(hosts[1].forward_agent);

        let mut store = VaultStore::open_in_memory().unwrap();
        store.initialize_vault("pw", false).unwrap();
        let summary = import_parsed_hosts(&store, &hosts).unwrap();
        assert_eq!(summary.imported_hosts, 3);

        let stored = store.list_hosts().unwrap();
        let bastion = stored.iter().find(|h| h.label == "bastion").unwrap();
        let app1 = stored.iter().find(|h| h.label == "app-1").unwrap();
        assert_eq!(app1.jump_host_id.as_deref(), Some(bastion.id.as_str()));
        assert!(bastion.forward_agent);

        let exported = export_hosts_to_ssh_config(&stored, &[]);
        assert!(exported.contains("Host bastion"));
        assert!(exported.contains("ForwardAgent yes"));
        assert!(exported.contains("ProxyJump bastion"));
    }

    #[test]
    fn sync_local_ssh_dir_discovers_includes_and_standalone_keys_idempotently() {
        let dir = std::env::temp_dir().join(format!("sterm-ssh-dir-test-{}", uuid::Uuid::now_v7()));
        let sub = dir.join("config.d");
        std::fs::create_dir_all(&sub).unwrap();

        let kp = generate_ed25519_keypair("dev@local", None).unwrap();
        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, &kp.private_key_openssh).unwrap();
        std::fs::write(dir.join("id_ed25519.pub"), &kp.public_key_openssh).unwrap();

        std::fs::write(
            dir.join("config"),
            "Include config.d/*.conf\nHost main-box\n  HostName 10.20.30.40\n  User deploy\n",
        )
        .unwrap();
        std::fs::write(
            sub.join("staging.conf"),
            "Host staging-box\n  HostName 10.20.30.41\n  User ubuntu\n",
        )
        .unwrap();

        let mut store = VaultStore::open_in_memory().unwrap();
        store.initialize_vault("pw", false).unwrap();

        let first = sync_local_ssh_dir(&store, Some(&dir)).unwrap();
        assert_eq!(first.imported_hosts, 2);
        assert_eq!(first.imported_keys, 1);

        // Second run must be completely idempotent
        let second = sync_local_ssh_dir(&store, Some(&dir)).unwrap();
        assert_eq!(second.imported_hosts, 0);
        assert_eq!(second.imported_keys, 0);
        assert_eq!(second.skipped_duplicates, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
