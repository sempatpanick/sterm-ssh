use std::path::PathBuf;

use core_sftp::types::{FileEntry, TransferDirection, TransferProgress, TransferStatus};
use gpui::{
    div, prelude::*, px, Context, Half, Pixels, Point, Render, UniformListScrollHandle, Window,
};

use crate::theme::{format_bytes, ThemeMode, ThemePalette};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpPaneSide {
    Local,
    Remote,
}

/// Payload carried by GPUI's native `on_drag` / `on_drop` system when dragging files
/// between the Local pane and the Remote pane.
#[derive(Debug, Clone)]
pub struct DraggedSftpFile {
    pub side: SftpPaneSide,
    pub name: String,
    pub full_path: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Floating pill rendered under the mouse cursor during a drag operation.
pub struct DragFilePill {
    pub label: String,
    pub direction_hint: String,
    pub position: Point<Pixels>,
    pub theme_mode: ThemeMode,
}

impl DragFilePill {
    pub fn new(file: &DraggedSftpFile, position: Point<Pixels>, theme_mode: ThemeMode) -> Self {
        let direction_hint = match file.side {
            SftpPaneSide::Local => "Drop on Remote to Upload".to_string(),
            SftpPaneSide::Remote => "Drop on Local to Download".to_string(),
        };
        Self {
            label: format!("{} ({})", file.name, format_bytes(file.size)),
            direction_hint,
            position,
            theme_mode,
        }
    }
}

impl Render for DragFilePill {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let t = ThemePalette::for_mode(self.theme_mode);
        let width = px(220.0);
        let height = px(44.0);

        div()
            .pl(self.position.x - width.half())
            .pt(self.position.y - height.half())
            .child(
                div()
                    .w(width)
                    .h(height)
                    .px_3()
                    .rounded_xl()
                    .bg(t.island_bg)
                    .border_1()
                    .border_color(t.accent)
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .justify_center()
                    .child(
                        div()
                            .text_xs()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(t.island_fg)
                            .truncate()
                            .child(self.label.clone()),
                    )
                    .child(
                        div()
                            .text_size(px(10.0))
                            .text_color(t.accent)
                            .truncate()
                            .child(self.direction_hint.clone()),
                    ),
            )
    }
}

#[derive(Debug, Clone)]
pub struct SftpWorkspaceState {
    pub session_id: Option<String>,
    pub host_id: Option<String>,
    pub host_label: Option<String>,
    pub local_path: String,
    pub remote_path: String,
    pub local_entries: Vec<FileEntry>,
    pub remote_entries: Vec<FileEntry>,
    pub show_hidden: bool,
    pub local_scroll_handle: UniformListScrollHandle,
    pub remote_scroll_handle: UniformListScrollHandle,
    pub selected_local: Option<String>,
    pub selected_remote: Option<String>,
    pub connecting: bool,
    pub loading_local: bool,
    pub loading_remote: bool,
    pub transfers: Vec<TransferProgress>,
}

impl SftpWorkspaceState {
    pub fn new(default_local: String) -> Self {
        Self {
            session_id: None,
            host_id: None,
            host_label: None,
            local_path: default_local,
            remote_path: "/".to_string(),
            local_entries: Vec::new(),
            remote_entries: Vec::new(),
            show_hidden: false,
            local_scroll_handle: UniformListScrollHandle::new(),
            remote_scroll_handle: UniformListScrollHandle::new(),
            selected_local: None,
            selected_remote: None,
            connecting: false,
            loading_local: false,
            loading_remote: false,
            transfers: Vec::new(),
        }
    }

    pub fn visible_local_indices(&self) -> Vec<usize> {
        self.local_entries
            .iter()
            .enumerate()
            .filter(|(_, e)| self.show_hidden || !e.name.starts_with('.'))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn visible_remote_indices(&self) -> Vec<usize> {
        self.remote_entries
            .iter()
            .enumerate()
            .filter(|(_, e)| self.show_hidden || !e.name.starts_with('.'))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn clear_finished_transfers(&mut self) {
        self.transfers
            .retain(|t| matches!(t.status, TransferStatus::Running));
    }

    pub fn reset_local_scroll(&self) {
        self.local_scroll_handle
            .0
            .borrow()
            .base_handle
            .set_offset(Point::default());
    }

    pub fn reset_remote_scroll(&self) {
        self.remote_scroll_handle
            .0
            .borrow()
            .base_handle
            .set_offset(Point::default());
    }

    pub fn upsert_transfer(&mut self, progress: TransferProgress) {
        if let Some(existing) = self
            .transfers
            .iter_mut()
            .find(|t| t.transfer_id == progress.transfer_id)
        {
            *existing = progress;
        } else {
            self.transfers.insert(0, progress);
            if self.transfers.len() > 25 {
                self.transfers.truncate(25);
            }
        }
    }

    pub fn active_transfer(&self) -> Option<&TransferProgress> {
        self.transfers
            .iter()
            .find(|t| matches!(t.status, TransferStatus::Running))
            .or_else(|| self.transfers.first())
    }

    pub fn running_count(&self) -> usize {
        self.transfers
            .iter()
            .filter(|t| matches!(t.status, TransferStatus::Running))
            .count()
    }
}

pub fn join_remote_path(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), name)
    }
}

pub fn parent_remote_path(dir: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((parent, _)) => parent.to_string(),
        None => "/".to_string(),
    }
}

pub fn parent_local_path(dir: &str) -> String {
    let p = PathBuf::from(dir);
    p.parent()
        .map(|parent| parent.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| dir.to_string())
}

fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

pub fn resolve_local_input(current_dir: &str, input: &str) -> String {
    let trimmed = strip_quotes(input.trim()).trim();
    if trimmed.is_empty() {
        return current_dir.to_string();
    }
    if trimmed == "~" || trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        return trimmed.to_string();
    }
    // Windows bare drive shorthand like "C:" -> "C:\\"
    let bytes = trimmed.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return format!("{trimmed}\\");
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        trimmed.to_string()
    } else {
        PathBuf::from(current_dir)
            .join(path)
            .to_string_lossy()
            .to_string()
    }
}

pub fn resolve_remote_input(current_dir: &str, input: &str) -> String {
    let trimmed = strip_quotes(input.trim()).trim();
    if trimmed.is_empty() {
        return current_dir.to_string();
    }
    if trimmed == "~" || trimmed.starts_with("~/") || trimmed.starts_with('/') {
        return trimmed.to_string();
    }
    join_remote_path(current_dir, trimmed)
}

pub fn transfer_percent(t: &TransferProgress) -> u8 {
    if t.total_bytes == 0 {
        return if matches!(t.status, TransferStatus::Completed) {
            100
        } else {
            0
        };
    }
    ((t.bytes_transferred.saturating_mul(100)) / t.total_bytes).min(100) as u8
}

pub fn direction_arrow(dir: &TransferDirection) -> &'static str {
    match dir {
        TransferDirection::Upload => "↑",
        TransferDirection::Download => "↓",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_join_and_parent() {
        assert_eq!(join_remote_path("/", "app.yml"), "/app.yml");
        assert_eq!(join_remote_path("/var/www", "app.yml"), "/var/www/app.yml");
        assert_eq!(join_remote_path("/var/www/", "app.yml"), "/var/www/app.yml");

        assert_eq!(parent_remote_path("/var/www/app"), "/var/www");
        assert_eq!(parent_remote_path("/var"), "/");
        assert_eq!(parent_remote_path("/"), "/");
    }

    #[test]
    fn resolve_remote_input_handles_absolute_relative_and_tilde() {
        assert_eq!(resolve_remote_input("/var/www", "  /etc/nginx  "), "/etc/nginx");
        assert_eq!(resolve_remote_input("/var/www", "'/opt/app'"), "/opt/app");
        assert_eq!(resolve_remote_input("/var/www", "~"), "~");
        assert_eq!(resolve_remote_input("/var/www", "~/logs"), "~/logs");
        assert_eq!(resolve_remote_input("/var/www", "html"), "/var/www/html");
        assert_eq!(resolve_remote_input("/", "etc"), "/etc");
        assert_eq!(resolve_remote_input("/var/www", "   "), "/var/www");
    }

    #[test]
    fn resolve_local_input_handles_quotes_tilde_drive_and_relative() {
        assert_eq!(resolve_local_input(r"C:\Users\me", "   "), r"C:\Users\me");
        assert_eq!(resolve_local_input(r"C:\Users\me", "~"), "~");
        assert_eq!(resolve_local_input(r"C:\Users\me", "~/Desktop"), "~/Desktop");
        assert_eq!(resolve_local_input(r"C:\Users\me", "D:"), r"D:\");
        assert_eq!(
            resolve_local_input(r"C:\Users\me", "Documents"),
            PathBuf::from(r"C:\Users\me").join("Documents").to_string_lossy()
        );
    }

    #[test]
    fn transfer_progress_percent_bounds() {
        let running = TransferProgress {
            transfer_id: "1".into(),
            direction: TransferDirection::Upload,
            file_name: "a.bin".into(),
            local_path: "a.bin".into(),
            remote_path: "/a.bin".into(),
            bytes_transferred: 75,
            total_bytes: 100,
            status: TransferStatus::Running,
            error: None,
        };
        assert_eq!(transfer_percent(&running), 75);

        let empty_done = TransferProgress {
            bytes_transferred: 0,
            total_bytes: 0,
            status: TransferStatus::Completed,
            ..running
        };
        assert_eq!(transfer_percent(&empty_done), 100);
    }

    #[test]
    fn sftp_hidden_filter_and_clear_finished_work() {
        let mut st = SftpWorkspaceState::new("/tmp".into());
        st.remote_entries = vec![
            FileEntry {
                name: ".env".into(),
                path: "/app/.env".into(),
                is_dir: false,
                is_symlink: false,
                size: 12,
                modified_at: None,
                permissions: Some(0o600),
            },
            FileEntry {
                name: "docker-compose.yml".into(),
                path: "/app/docker-compose.yml".into(),
                is_dir: false,
                is_symlink: false,
                size: 420,
                modified_at: None,
                permissions: Some(0o644),
            },
        ];
        assert_eq!(st.visible_remote_indices(), vec![1]);
        st.show_hidden = true;
        assert_eq!(st.visible_remote_indices(), vec![0, 1]);

        st.upsert_transfer(TransferProgress {
            transfer_id: "done".into(),
            direction: TransferDirection::Upload,
            file_name: "a".into(),
            local_path: "a".into(),
            remote_path: "/a".into(),
            bytes_transferred: 10,
            total_bytes: 10,
            status: TransferStatus::Completed,
            error: None,
        });
        st.upsert_transfer(TransferProgress {
            transfer_id: "active".into(),
            direction: TransferDirection::Download,
            file_name: "b".into(),
            local_path: "b".into(),
            remote_path: "/b".into(),
            bytes_transferred: 5,
            total_bytes: 10,
            status: TransferStatus::Running,
            error: None,
        });
        st.clear_finished_transfers();
        assert_eq!(st.transfers.len(), 1);
        assert_eq!(st.transfers[0].transfer_id, "active");
    }
}
