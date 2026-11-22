//! Command recording guards, frecency-ranked suggestions, and minimal terminal insert payloads.
//!
//! Typed pure-Rust integration of `src/lib/command-suggestions.ts` (behavior-verified in `rust/lib-rs`).

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use core_vault::models::CommandRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionSource {
    Saved,
    History,
    Starter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedCommand {
    pub id: String,
    pub command: String,
    pub label: Option<String>,
    pub host_id: Option<String>,
    pub pinned: bool,
    pub use_count: u32,
    pub source: SuggestionSource,
}

pub const STARTER_COMMANDS: [(&str, &str); 10] = [
    ("ls -lah", "List files with sizes & hidden"),
    ("docker ps -a", "List all Docker containers"),
    ("docker logs -f --tail 100 ", "Follow container logs"),
    ("systemctl status ", "Inspect systemd service"),
    ("journalctl -f -n 100 -u ", "Tail service journal logs"),
    ("df -h", "Check disk space usage"),
    ("free -h", "Check memory & swap usage"),
    ("ss -tulpn", "Show listening TCP/UDP ports"),
    ("tail -f ", "Follow log file output"),
    ("htop", "Interactive process monitor"),
];

const IGNORED_COMMANDS: [&str; 8] = [
    "ls", "cd", "pwd", "clear", "cls", "exit", "logout", "history",
];

fn is_ws(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

fn has_keyword_ws_colon(haystack: &str, keyword: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(keyword) {
        let after = &haystack[start + pos + keyword.len()..];
        if after.trim_start_matches(is_ws).starts_with(':') {
            return true;
        }
        start += pos + 1;
    }
    false
}

/// Guards against storing passwords, leading-space private commands, or trivial noise.
pub fn should_record_command(raw_line: &str, recent_output_tail: &str) -> bool {
    if raw_line.is_empty() || raw_line.starts_with(' ') || raw_line.starts_with('\t') {
        return false;
    }
    let trimmed = raw_line.trim_matches(is_ws);
    let len = trimmed.encode_utf16().count();
    if !(3..=500).contains(&len) {
        return false;
    }
    let lower = trimmed.to_lowercase();
    if IGNORED_COMMANDS.contains(&lower.as_str()) {
        return false;
    }

    let tail_units: Vec<u16> = recent_output_tail.encode_utf16().collect();
    let tail_start = tail_units.len().saturating_sub(160);
    let lower_tail = String::from_utf16_lossy(&tail_units[tail_start..]).to_lowercase();
    !(has_keyword_ws_colon(&lower_tail, "password")
        || has_keyword_ws_colon(&lower_tail, "otp")
        || lower_tail.contains("passphrase")
        || lower_tail.contains("enter pin")
        || lower_tail.contains("verification code")
        || lower_tail.contains("[sudo]"))
}

/// Ranks stored snippets, learned command history, and starter suggestions by
/// prefix match, pinned status, current host affinity, and frecency.
pub fn rank_command_suggestions(
    stored: &[CommandRecord],
    raw_query: &str,
    current_host_id: Option<&str>,
    limit: usize,
) -> Vec<SuggestedCommand> {
    let query = raw_query.trim_matches(is_ws).to_lowercase();
    let mut seen: HashSet<String> = HashSet::new();
    let mut scored: Vec<(f64, SuggestedCommand)> = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0);

    for rec in stored {
        let cmd_lower = rec.command.to_lowercase();
        let label_lower = rec.label.as_deref().unwrap_or("").to_lowercase();

        let match_score = if query.is_empty() {
            10.0
        } else if cmd_lower == query {
            continue;
        } else if cmd_lower.starts_with(&query) {
            120.0
        } else if cmd_lower.contains(&query) {
            70.0
        } else if label_lower.contains(&query) {
            50.0
        } else {
            continue;
        };

        seen.insert(cmd_lower);

        let pinned_boost = if rec.pinned { 45.0 } else { 0.0 };
        let host_boost = match (current_host_id, rec.host_id.as_deref()) {
            (Some(cid), Some(rid)) if !cid.is_empty() && cid == rid => 30.0,
            _ => 0.0,
        };
        let freq_boost = 35.0_f64.min((f64::from(rec.use_count) + 1.0).log2() * 10.0);
        let age_hours = 0.0_f64.max((now - rec.last_used_at as f64) / 3_600_000.0);
        let recency_boost = 0.0_f64.max(20.0 - (age_hours + 1.0).log2() * 3.0);

        scored.push((
            match_score + pinned_boost + host_boost + freq_boost + recency_boost,
            SuggestedCommand {
                id: rec.id.clone(),
                command: rec.command.clone(),
                label: rec.label.clone(),
                host_id: rec.host_id.clone(),
                pinned: rec.pinned,
                use_count: rec.use_count,
                source: if rec.pinned {
                    SuggestionSource::Saved
                } else {
                    SuggestionSource::History
                },
            },
        ));
    }

    for (cmd, label) in STARTER_COMMANDS {
        let cmd_lower = cmd.to_lowercase();
        if seen.contains(&cmd_lower) {
            continue;
        }
        let match_score = if query.is_empty() {
            1.0
        } else if cmd_lower == query {
            continue;
        } else if cmd_lower.starts_with(&query) {
            40.0
        } else if cmd_lower.contains(&query) || label.to_lowercase().contains(&query) {
            20.0
        } else {
            continue;
        };

        scored.push((
            match_score,
            SuggestedCommand {
                id: format!("starter:{cmd}"),
                command: cmd.to_string(),
                label: Some(label.to_string()),
                host_id: None,
                pinned: false,
                use_count: 0,
                source: SuggestionSource::Starter,
            },
        ));
    }

    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    scored.into_iter().take(limit).map(|(_, item)| item).collect()
}

/// Computes minimal VT payload: missing suffix when typed line is a prefix, or Ctrl+U + command.
pub fn compute_insert_payload(
    current_typed_line: &str,
    selected_command: &str,
    execute: bool,
) -> String {
    let suffix = if !current_typed_line.is_empty() && selected_command.starts_with(current_typed_line)
    {
        &selected_command[current_typed_line.len()..]
    } else if !current_typed_line.is_empty() {
        return if execute {
            format!("\x15{selected_command}\r")
        } else {
            format!("\x15{selected_command}")
        };
    } else {
        selected_command
    };

    if execute {
        format!("{suffix}\r")
    } else {
        suffix.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_pinned_and_host_affine_prefix_matches_first() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let sample = vec![
            CommandRecord {
                id: "c1".into(),
                command: "docker compose up -d".into(),
                label: Some("Start stack".into()),
                host_id: Some("host-a".into()),
                pinned: true,
                use_count: 12,
                last_used_at: now - 1000,
                updated_at: now,
            },
            CommandRecord {
                id: "c2".into(),
                command: "docker ps --format 'table {{.Names}}\\t{{.Status}}'".into(),
                label: None,
                host_id: None,
                pinned: false,
                use_count: 3,
                last_used_at: now - 50_000,
                updated_at: now,
            },
        ];

        let res = rank_command_suggestions(&sample, "docker", Some("host-a"), 5);
        assert_eq!(res[0].command, "docker compose up -d");
        assert_eq!(res[0].source, SuggestionSource::Saved);
        assert!(res.iter().any(|r| r.command.starts_with("docker ps --format")));
    }

    #[test]
    fn computes_suffix_or_ctrl_u_payload() {
        assert_eq!(
            compute_insert_payload("docker c", "docker compose up -d", false),
            "ompose up -d"
        );
        assert_eq!(
            compute_insert_payload("compose", "docker compose up -d", true),
            "\x15docker compose up -d\r"
        );
    }

    #[test]
    fn rejects_private_and_password_prompt_commands() {
        assert!(!should_record_command(" secret-token-cmd", "user@host:~$ "));
        assert!(!should_record_command(
            "my-secret-pass",
            "[sudo] password for ops: "
        ));
        assert!(should_record_command(
            "systemctl restart nginx",
            "ops@prod:~$ "
        ));
    }
}
