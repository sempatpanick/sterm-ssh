use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use core_crypto::ssh_keygen::generate_ed25519_keypair;
use core_sftp::{
    manager::SftpManager,
    types::{TransferDirection, TransferProgress, TransferStatus},
};
use core_ssh::{
    manager::SshSessionManager,
    types::{
        AgentIdentityInfo, ConnectRequest, HostKeyChallenge, KeyboardInteractiveChallenge,
        SshAuthMethod, SshTarget, TerminalEvent, TunnelStats,
    },
};
use core_vault::{
    backup::{export_encrypted_backup, import_encrypted_backup},
    models::{
        CommandRecord, CredentialKind, GroupRecord, HostAuthMode, HostRecord, PortForwardKind,
        PortForwardRecord, VaultSnapshot, VaultStatus,
    },
    ssh_config::{
        default_ssh_config_path, detect_local_ssh_dir, export_hosts_to_ssh_config,
        import_parsed_hosts, parse_ssh_config_file, sync_local_ssh_dir, LocalSshDiscovery,
        ParsedSshHost,
    },
};
use gpui::{
    div, ease_out_quint, prelude::*, px, Animation, AnimationExt as _, ClipboardItem, Context,
    Entity, ExternalPaths, FocusHandle, Focusable, KeyDownEvent, MouseButton, MouseDownEvent,
    MouseMoveEvent, MouseUpEvent, PathPromptOptions, Render, ScrollWheelEvent, WeakEntity, Window,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::backend::{
    awake_monotonic_duration, build_connect_request_for_host, build_remote_cd_command,
    build_ssh_copy_id_command, build_validated_credential, detect_system_sleep_gap,
    is_ssh_auth_error, open_file_in_external_editor, run_sync_change_password,
    run_sync_delete_account, run_sync_login, run_sync_now, run_sync_register, verify_os_biometric,
    BackendServices, PublicSyncStatus, UiEvent,
};
use crate::command_suggestions::{
    compute_insert_payload, extract_template_vars, rank_command_suggestions, render_template,
    should_record_command, SuggestedCommand, SuggestionSource,
};
use crate::icons::{icon_svg, Icon};
use crate::keybindings::{KeyBinding, ShortcutAction};
use crate::local_shell::{LocalShellManager, LocalShellSpec};
use crate::motion::{animate_page_enter, indeterminate_bar, loading_dots, pulsing_dot};
use crate::sftp::{
    direction_arrow, join_remote_path, parent_local_path, parent_remote_path, reorder_vec_by_id,
    resolve_local_input, resolve_remote_input, transfer_percent, DragTabPill, DraggedSftpFile,
    DraggedWorkspaceTab, SftpPaneSide, SftpTabSnapshot, SftpWorkspaceState,
};
use crate::split_tree::{
    close_pane as tree_close_pane, collect_pane_ids, create_leaf, split_pane as tree_split_pane,
    update_split_ratio, SplitDirection, SplitNode,
};
use crate::terminal::{
    keystroke_to_vt_bytes, terminal_line_height_scaled, TerminalTab, DEFAULT_TERM_COLS,
    DEFAULT_TERM_ROWS,
};
use crate::text_field::{TextField, TextFieldEvent};
use crate::theme::{env_badge_for_host, ThemeMode, ThemePalette, UiSettings};
use crate::tooltip::StermTooltip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPage {
    Hosts,
    Sftp,
    Snippets,
    Tunnels,
    Keychain,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    Appearance,
    Terminal,
    Account,
    Security,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainTab {
    Credentials,
    KnownHosts,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScreenMode {
    Login,
    Register,
    Offline,
}

#[derive(Debug, Clone)]
pub struct WorkspaceTab {
    pub id: String,
    pub title: String,
    pub root: SplitNode,
    pub active_pane_id: String,
    pub broadcast_input: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SavedPaneNode {
    Leaf {
        host_id: Option<String>,
        is_local: bool,
        local_shell_program: Option<String>,
        local_shell_label: Option<String>,
        local_cwd: Option<String>,
    },
    Split {
        direction_vertical: bool,
        ratio: f32,
        first: Box<SavedPaneNode>,
        second: Box<SavedPaneNode>,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SavedWorkspaceTab {
    pub title: String,
    pub root: SavedPaneNode,
    #[serde(default)]
    pub broadcast_input: bool,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SavedWorkspaceSession {
    pub tabs: Vec<SavedWorkspaceTab>,
    pub active_tab_index: Option<usize>,
}

#[derive(Debug, Clone)]
enum RestorePaneKind {
    Ssh {
        host_id: String,
    },
    Local {
        program: Option<String>,
        label: Option<String>,
        cwd: Option<String>,
    },
}

fn saved_node_from_split(node: &SplitNode, terminal_tabs: &[TerminalTab]) -> Option<SavedPaneNode> {
    match node {
        SplitNode::Leaf { pane_id } => {
            let pane = terminal_tabs.iter().find(|p| &p.tab_id == pane_id)?;
            if pane.is_local {
                Some(SavedPaneNode::Leaf {
                    host_id: None,
                    is_local: true,
                    local_shell_program: Some(pane.hostname.clone()),
                    local_shell_label: Some(pane.label.clone()),
                    local_cwd: pane.current_cwd().map(|s| s.to_string()),
                })
            } else {
                pane.host_id.as_ref().map(|hid| SavedPaneNode::Leaf {
                    host_id: Some(hid.clone()),
                    is_local: false,
                    local_shell_program: None,
                    local_shell_label: None,
                    local_cwd: None,
                })
            }
        }
        SplitNode::Split {
            direction,
            ratio,
            first,
            second,
            ..
        } => {
            let a = saved_node_from_split(first, terminal_tabs);
            let b = saved_node_from_split(second, terminal_tabs);
            match (a, b) {
                (Some(first), Some(second)) => Some(SavedPaneNode::Split {
                    direction_vertical: *direction == SplitDirection::Vertical,
                    ratio: *ratio,
                    first: Box::new(first),
                    second: Box::new(second),
                }),
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            }
        }
    }
}

fn split_node_from_saved(
    saved: &SavedPaneNode,
    hosts: &[HostRecord],
    out_panes: &mut Vec<(String, RestorePaneKind)>,
) -> Option<SplitNode> {
    match saved {
        SavedPaneNode::Leaf {
            host_id,
            is_local,
            local_shell_program,
            local_shell_label,
            local_cwd,
        } => {
            let pane_id = Uuid::now_v7().to_string();
            if *is_local {
                out_panes.push((
                    pane_id.clone(),
                    RestorePaneKind::Local {
                        program: local_shell_program.clone(),
                        label: local_shell_label.clone(),
                        cwd: local_cwd.clone(),
                    },
                ));
                Some(create_leaf(pane_id))
            } else if let Some(hid) = host_id
                && hosts.iter().any(|h| &h.id == hid)
            {
                out_panes.push((
                    pane_id.clone(),
                    RestorePaneKind::Ssh {
                        host_id: hid.clone(),
                    },
                ));
                Some(create_leaf(pane_id))
            } else {
                None
            }
        }
        SavedPaneNode::Split {
            direction_vertical,
            ratio,
            first,
            second,
        } => {
            let left = split_node_from_saved(first, hosts, out_panes);
            let right = split_node_from_saved(second, hosts, out_panes);
            match (left, right) {
                (Some(f), Some(s)) => Some(SplitNode::Split {
                    id: Uuid::now_v7().to_string(),
                    direction: if *direction_vertical {
                        SplitDirection::Vertical
                    } else {
                        SplitDirection::Horizontal
                    },
                    ratio: ratio.clamp(0.15, 0.85),
                    first: Box::new(f),
                    second: Box::new(s),
                }),
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    DeleteHost {
        id: String,
        label: String,
    },
    DeleteGroup {
        id: String,
        name: String,
    },
    DeleteCredential {
        id: String,
        label: String,
        used_by_count: usize,
    },
    RevokeKnownHost {
        id: String,
        label: String,
    },
    DeleteCommand {
        id: String,
        command: String,
    },
    DeleteTunnel {
        id: String,
        label: String,
    },
    DeleteRemoteFile {
        path: String,
        is_dir: bool,
        name: String,
    },
    OverwriteUpload {
        local_path: String,
        file_name: String,
    },
    OverwriteDownload {
        remote_path: String,
        file_name: String,
    },
    SignOut,
}

#[derive(Debug, Clone)]
pub enum ActiveModal {
    CommandPalette,
    QuickConnect,
    HostEditor {
        editing_id: Option<String>,
    },
    GroupEditor {
        editing_id: Option<String>,
    },
    CredentialEditor {
        editing_id: Option<String>,
    },
    TunnelEditor {
        editing_id: Option<String>,
    },
    DeployKey {
        label: String,
        public_key: String,
    },
    SnippetVars {
        command: String,
        vars: Vec<String>,
    },
    SshConfigImport {
        entries: Vec<ParsedSshHost>,
        selected: Vec<bool>,
    },
    SplitHostPicker {
        workspace_tab_id: String,
        target_pane_id: String,
        direction: SplitDirection,
    },
    RemoteEditor {
        session_id: String,
        remote_path: String,
    },
    RemoteChmod {
        session_id: String,
        remote_path: String,
    },
    RemoteRename {
        session_id: String,
        old_path: String,
        old_name: String,
    },
    HostKey(HostKeyChallenge),
    KeyboardInteractive(KeyboardInteractiveChallenge),
    Confirm(ConfirmAction),
    ShortcutsHelp,
}

pub struct StermAdminApp {
    pub services: Arc<BackendServices>,
    pub settings: UiSettings,
    pub theme_mode: ThemeMode,
    pub sidebar_collapsed: bool,
    pub page: AdminPage,
    pub settings_tab: SettingsTab,
    pub settings_tab_epoch: u64,
    pub settings_busy: bool,
    pub island_open: bool,

    // Smooth UI motion epochs & async loading states
    pub page_epoch: u64,
    pub modal_epoch: u64,
    pub island_epoch: u64,
    pub toast_epoch: u64,
    pub sidebar_epoch: u64,
    pub unlock_busy: bool,
    pub sync_busy: bool,

    // Vault & Sync state
    pub vault_status: VaultStatus,
    pub snapshot: VaultSnapshot,
    pub sync_status: PublicSyncStatus,
    pub selected_group_filter: Option<String>, // None = All
    pub selected_tag_filter: Option<String>,
    pub toast: Option<(String, bool)>, // (message, is_error)
    pub ssh_discovery: Option<LocalSshDiscovery>,
    pub ssh_auto_import_enabled: bool,
    pub ssh_discovery_allow_auto: bool,

    // Workspace tabs (top bar) + live terminal panes (indexed by pane.tab_id)
    pub workspace_tabs: Vec<WorkspaceTab>,
    pub active_workspace_tab_id: Option<String>, // None = Vault page view
    pub terminal_tabs: Vec<TerminalTab>,
    pub focused_pane_tab_id: Option<String>,
    pub terminal_focus: FocusHandle,
    pub app_focus: FocusHandle,

    // Active terminal search & inline suggestions UI state
    pub term_search_open: bool,
    pub term_search_input: Entity<TextField>,
    pub term_retry_password: Entity<TextField>,
    pub suggestions_manual_open: bool,
    pub suggestions_dismissed: bool,
    pub suggestions_selected_idx: usize,

    // Dual-pane SFTP workspace
    pub sftp_state: SftpWorkspaceState,
    pub sftp_host_filter: Entity<TextField>,

    // Modals & FIFO security challenge queues (prevents simultaneous drops!)
    pub modal: Option<ActiveModal>,
    pub pending_host_keys: VecDeque<HostKeyChallenge>,
    pub pending_kbi: VecDeque<KeyboardInteractiveChallenge>,
    pub kbi_inputs: Vec<Entity<TextField>>,

    // Command Palette (Ctrl/Cmd+K)
    pub palette_query: Entity<TextField>,
    pub palette_quick_auth: CredentialKind,
    pub palette_quick_password: Entity<TextField>,

    // Auth / Unlock screen state
    pub auth_mode: AuthScreenMode,
    pub auth_stay_signed_in: bool,
    pub auth_editing_server: bool,
    pub auth_email: Entity<TextField>,
    pub auth_server_url: Entity<TextField>,
    pub unlock_password: Entity<TextField>,
    pub unlock_confirm: Entity<TextField>,

    // Hosts & Snippets search/create inputs
    pub server_search: Entity<TextField>,
    pub snippet_search: Entity<TextField>,
    pub snippet_cmd_input: Entity<TextField>,
    pub snippet_label_input: Entity<TextField>,
    pub snippet_host_id: Option<String>,
    pub editing_snippet_id: Option<String>,

    // Quick Connect / Full Host Editor fields
    pub qc_label: Entity<TextField>,
    pub qc_hostname: Entity<TextField>,
    pub qc_port: Entity<TextField>,
    pub qc_username: Entity<TextField>,
    pub qc_password: Entity<TextField>,
    pub qc_group_name: Entity<TextField>,
    pub qc_tags: Entity<TextField>,
    pub qc_keepalive: Entity<TextField>,
    pub qc_startup_cmd: Entity<TextField>,
    pub qc_notes: Entity<TextField>,
    pub qc_auth_choice: CredentialKind,
    pub qc_key_pem: Entity<TextField>,
    pub qc_key_passphrase: Entity<TextField>,
    pub qc_cert_openssh: Entity<TextField>,
    pub selected_credential_id: Option<String>,
    pub selected_jump_host_id: Option<String>,
    pub selected_terminal_theme: Option<String>,
    pub qc_auth_mode: HostAuthMode,
    pub qc_forward_agent: bool,
    pub qc_proxy_url: Entity<TextField>,
    pub qc_favorite: bool,

    // Group Editor fields
    pub grp_name_input: Entity<TextField>,
    pub grp_default_user_input: Entity<TextField>,
    pub grp_default_cred_id: Option<String>,
    pub grp_parent_id: Option<String>,

    // SFTP editable path bars + inline mkdir + Remote modals
    pub sftp_local_path_input: Entity<TextField>,
    pub sftp_remote_path_input: Entity<TextField>,
    pub sftp_mkdir_input: Entity<TextField>,
    pub remote_editor_input: Entity<TextField>,
    pub chmod_input: Entity<TextField>,
    pub rename_input: Entity<TextField>,

    // Credential Editor fields
    pub key_auth_choice: CredentialKind,
    pub cred_label: Entity<TextField>,
    pub cred_username: Entity<TextField>,
    pub cred_secret: Entity<TextField>,
    pub cred_passphrase: Entity<TextField>,
    pub cred_cert: Entity<TextField>,

    // Settings / Account / Sync / Backup / Delete Account fields
    pub sync_url: Entity<TextField>,
    pub sync_email: Entity<TextField>,
    pub sync_password: Entity<TextField>,
    pub pw_current: Entity<TextField>,
    pub pw_new: Entity<TextField>,
    pub pw_confirm: Entity<TextField>,
    pub delete_account_pw: Entity<TextField>,
    pub backup_path: Entity<TextField>,
    pub backup_passphrase: Entity<TextField>,

    // Phase 3: Port Forwarding, Docked SFTP Drawer, Snippet Templates & Auto-Lock
    pub sftp_drawer_open: bool,
    pub active_tunnels: HashMap<String, TunnelStats>,
    pub last_activity_at: Instant,
    pub tun_kind: PortForwardKind,
    pub tun_host_id: Option<String>,
    pub tun_label: Entity<TextField>,
    pub tun_bind_addr: Entity<TextField>,
    pub tun_bind_port: Entity<TextField>,
    pub tun_target_host: Entity<TextField>,
    pub tun_target_port: Entity<TextField>,
    pub tun_auto_start: bool,
    pub snippet_var_inputs: Vec<Entity<TextField>>,

    // Phase 4: Host Latency Ping, Keychain Tabs & Live SSH Agent Inspector
    pub host_latencies: HashMap<String, Option<u64>>,
    pub latency_probing: bool,
    pub keychain_tab: KeychainTab,
    pub keychain_search: Entity<TextField>,
    pub agent_identities: Vec<AgentIdentityInfo>,
    pub agent_error: Option<String>,

    // Phase 5: Multiple SFTP Tabs, OSC 7 CD-Following, Custom Keybindings, Session Restore & Sleep Lock
    pub sftp_tabs: Vec<SftpTabSnapshot>,
    pub active_sftp_tab_id: String,
    pub sftp_drawer_follow_cwd: bool,
    pub last_drawer_followed_cwd: Option<String>,
    pub recording_shortcut: Option<ShortcutAction>,
    pub sessions_restored_once: bool,
}

impl Focusable for StermAdminApp {
    fn focus_handle(&self, _cx: &gpui::App) -> FocusHandle {
        self.app_focus.clone()
    }
}

impl StermAdminApp {
    pub fn new(
        services: Arc<BackendServices>,
        mut ui_rx: mpsc::UnboundedReceiver<UiEvent>,
        cx: &mut Context<Self>,
    ) -> Self {
        let vault_status = services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.status().ok())
            .unwrap_or(VaultStatus {
                initialized: false,
                unlocked: false,
                keychain_enabled: false,
                vault_id: None,
            });

        let snapshot = if vault_status.unlocked {
            services
                .vault
                .lock()
                .ok()
                .and_then(|v| v.snapshot().ok())
                .unwrap_or_else(empty_snapshot)
        } else {
            empty_snapshot()
        };

        let sync_status = services.sync_status();
        let default_local = SftpManager::default_local_dir();

        let saved_email = services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.get_meta_string("account_email").ok().flatten())
            .or_else(|| sync_status.email.clone())
            .unwrap_or_default();
        let saved_server = services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.get_meta_string("server_url").ok().flatten())
            .or_else(|| sync_status.server_url.clone())
            .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());
        let ssh_auto_import_enabled = services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.get_meta_string("ssh_auto_import_enabled").ok().flatten())
            .as_deref()
            == Some("1");

        let auth_email = cx.new(|cx| TextField::new("Email", cx).with_value(saved_email.clone()));
        let auth_server_url = cx.new(|cx| {
            TextField::new("http://127.0.0.1:8787", cx).with_value(saved_server.clone())
        });
        let unlock_password = cx.new(|cx| TextField::new("Password", cx).with_masked(true));
        let unlock_confirm =
            cx.new(|cx| TextField::new("Confirm password", cx).with_masked(true));

        let server_search =
            cx.new(|cx| TextField::new("Filter hosts, IPs, tags...", cx).with_compact(true));
        let snippet_search =
            cx.new(|cx| TextField::new("Filter snippets & history...", cx).with_compact(true));
        let snippet_cmd_input = cx.new(|cx| {
            TextField::new("Command (e.g. docker compose logs -f)", cx).with_monospace(true)
        });
        let snippet_label_input =
            cx.new(|cx| TextField::new("Description / note (optional)", cx));

        let palette_query = cx.new(|cx| {
            TextField::new("Search hosts, snippets, or type user@host:22...", cx)
        });
        let palette_quick_password = cx.new(|cx| {
            TextField::new("Password (optional)", cx)
                .with_masked(true)
                .with_compact(true)
        });

        let term_search_input = cx.new(|cx| {
            TextField::new("Find in terminal...", cx)
                .with_monospace(true)
                .with_compact(true)
        });
        let term_retry_password = cx.new(|cx| {
            TextField::new("Enter SSH password", cx)
                .with_masked(true)
                .with_compact(true)
        });

        let sftp_host_filter = cx.new(|cx| {
            TextField::new("Search host to connect SFTP...", cx).with_compact(true)
        });

        let qc_label = cx.new(|cx| TextField::new("Display name (e.g. prod-api-01)", cx));
        let qc_hostname = cx.new(|cx| TextField::new("Hostname or IP (e.g. 10.0.4.12)", cx));
        let qc_port = cx.new(|cx| TextField::new("22", cx).with_value("22"));
        let qc_username = cx.new(|cx| TextField::new("Username (e.g. root or ubuntu)", cx));
        let qc_password =
            cx.new(|cx| TextField::new("Password (leave blank to keep/prompt)", cx).with_masked(true));
        let qc_group_name = cx.new(|cx| TextField::new("Group (e.g. Production)", cx));
        let qc_tags = cx.new(|cx| TextField::new("prod, aws, k8s (comma separated)", cx));
        let qc_keepalive = cx.new(|cx| TextField::new("30", cx).with_value("30"));
        let qc_startup_cmd = cx.new(|cx| {
            TextField::new("Startup command (e.g. tmux attach || tmux new)", cx).with_monospace(true)
        });
        let qc_notes = cx.new(|cx| TextField::new("Server notes (optional)", cx));
        let qc_key_pem = cx.new(|cx| {
            TextField::new("-----BEGIN OPENSSH PRIVATE KEY-----", cx)
                .with_multiline(true)
                .with_monospace(true)
        });
        let qc_key_passphrase =
            cx.new(|cx| TextField::new("Key passphrase (optional)", cx).with_masked(true));
        let qc_cert_openssh = cx.new(|cx| {
            TextField::new("ssh-ed25519-cert-v01@openssh.com ...", cx).with_monospace(true)
        });
        let qc_proxy_url = cx.new(|cx| {
            TextField::new("Proxy URL (e.g. socks5://127.0.0.1:1080 or http://proxy:8080)", cx)
                .with_monospace(true)
        });
        let keychain_search =
            cx.new(|cx| TextField::new("Filter credentials, keys, known hosts...", cx).with_compact(true));

        let grp_name_input = cx.new(|cx| TextField::new("Group name (e.g. Production)", cx));
        let grp_default_user_input =
            cx.new(|cx| TextField::new("Default username for hosts in group (optional)", cx));

        let sftp_local_path_input = cx.new(|cx| {
            TextField::new("Enter local path...", cx)
                .with_value(default_local.clone())
                .with_monospace(true)
                .with_compact(true)
        });
        let sftp_remote_path_input = cx.new(|cx| {
            TextField::new("Enter remote path...", cx)
                .with_value("/")
                .with_monospace(true)
                .with_compact(true)
        });
        let sftp_mkdir_input =
            cx.new(|cx| TextField::new("New remote folder name...", cx).with_compact(true));
        let remote_editor_input = cx.new(|cx| {
            TextField::new("Remote file contents...", cx)
                .with_multiline(true)
                .with_monospace(true)
        });
        let chmod_input = cx.new(|cx| TextField::new("644", cx).with_monospace(true));
        let rename_input = cx.new(|cx| TextField::new("New name...", cx).with_monospace(true));

        let cred_label = cx.new(|cx| TextField::new("Credential label (e.g. prod-key)", cx));
        let cred_username = cx.new(|cx| TextField::new("Default username (optional)", cx));
        let cred_secret = cx.new(|cx| {
            TextField::new("Password or OpenSSH Private Key PEM...", cx)
                .with_multiline(true)
                .with_monospace(true)
        });
        let cred_passphrase =
            cx.new(|cx| TextField::new("Key passphrase (optional)", cx).with_masked(true));
        let cred_cert = cx.new(|cx| {
            TextField::new("OpenSSH Certificate (*-cert.pub)", cx).with_monospace(true)
        });

        let sync_url = cx.new(|cx| {
            TextField::new("http://127.0.0.1:8787", cx).with_value(
                sync_status
                    .server_url
                    .clone()
                    .unwrap_or_else(|| "http://127.0.0.1:8787".to_string()),
            )
        });
        let sync_email = cx.new(|cx| {
            TextField::new("you@example.com", cx)
                .with_value(sync_status.email.clone().unwrap_or_default())
        });
        let sync_password =
            cx.new(|cx| TextField::new("Account master password", cx).with_masked(true));

        let default_backup_path = dirs::desktop_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("sterm-backup.sterm-vault")
            .to_string_lossy()
            .to_string();

        let pw_current =
            cx.new(|cx| TextField::new("Current master password", cx).with_masked(true));
        let pw_new =
            cx.new(|cx| TextField::new("New master password (min 8 chars)", cx).with_masked(true));
        let pw_confirm =
            cx.new(|cx| TextField::new("Confirm new master password", cx).with_masked(true));
        let delete_account_pw =
            cx.new(|cx| TextField::new("Confirm master password to delete", cx).with_masked(true));
        let backup_path = cx.new(|cx| {
            TextField::new("Backup file path (.sterm-vault)", cx).with_value(default_backup_path)
        });
        let backup_passphrase =
            cx.new(|cx| TextField::new("Backup encryption passphrase", cx).with_masked(true));

        let tun_label = cx.new(|cx| TextField::new("Tunnel label (e.g. Prod Postgres)", cx));
        let tun_bind_addr =
            cx.new(|cx| TextField::new("127.0.0.1", cx).with_value("127.0.0.1"));
        let tun_bind_port =
            cx.new(|cx| TextField::new("Local/Remote port (e.g. 5432)", cx).with_value("8080"));
        let tun_target_host =
            cx.new(|cx| TextField::new("Target host (e.g. 127.0.0.1)", cx).with_value("127.0.0.1"));
        let tun_target_port =
            cx.new(|cx| TextField::new("Target port (e.g. 5432)", cx).with_value("5432"));

        // --- TextField event subscriptions ---
        cx.subscribe(&auth_email, |this, _, ev: &TextFieldEvent, cx| {
            if matches!(ev, TextFieldEvent::Submit(_)) {
                this.submit_unlock_or_init(cx);
            }
        })
        .detach();
        cx.subscribe(&unlock_password, |this, _, ev: &TextFieldEvent, cx| {
            if matches!(ev, TextFieldEvent::Submit(_)) {
                this.submit_unlock_or_init(cx);
            }
        })
        .detach();
        cx.subscribe(&unlock_confirm, |this, _, ev: &TextFieldEvent, cx| {
            if matches!(ev, TextFieldEvent::Submit(_)) {
                this.submit_unlock_or_init(cx);
            }
        })
        .detach();

        for filter_field in [&server_search, &snippet_search, &sftp_host_filter, &keychain_search] {
            cx.subscribe(filter_field, |_this, _, ev: &TextFieldEvent, cx| {
                if matches!(ev, TextFieldEvent::Changed(_)) {
                    cx.notify();
                }
            })
            .detach();
        }

        cx.subscribe(&palette_query, |this, _, ev: &TextFieldEvent, cx| match ev {
            TextFieldEvent::Changed(_) => cx.notify(),
            TextFieldEvent::Cancel => {
                this.modal = None;
                cx.notify();
            }
            TextFieldEvent::Submit(_) => {
                this.submit_palette_primary(cx);
            }
        })
        .detach();

        cx.subscribe(
            &palette_quick_password,
            |this, _, ev: &TextFieldEvent, cx| match ev {
                TextFieldEvent::Submit(_) => this.submit_palette_primary(cx),
                TextFieldEvent::Cancel => {
                    this.modal = None;
                    cx.notify();
                }
                TextFieldEvent::Changed(_) => {}
            },
        )
        .detach();

        cx.subscribe(
            &term_search_input,
            |this, _, ev: &TextFieldEvent, cx| match ev {
                TextFieldEvent::Changed(q) => {
                    this.run_terminal_search(q.clone(), cx);
                }
                TextFieldEvent::Submit(_) => {
                    this.step_terminal_search(true, cx);
                }
                TextFieldEvent::Cancel => {
                    this.term_search_open = false;
                    cx.notify();
                }
            },
        )
        .detach();

        cx.subscribe(
            &term_retry_password,
            |this, _, ev: &TextFieldEvent, cx| {
                if matches!(ev, TextFieldEvent::Submit(_)) {
                    this.submit_active_pane_password_retry(cx);
                }
            },
        )
        .detach();

        cx.subscribe(
            &sftp_local_path_input,
            |this, field, ev: &TextFieldEvent, cx| match ev {
                TextFieldEvent::Submit(path) => this.navigate_local_to_input(path.clone(), cx),
                TextFieldEvent::Cancel => {
                    let current = this.sftp_state.local_path.clone();
                    field.update(cx, |tf, cx| tf.set_value(current, cx));
                }
                TextFieldEvent::Changed(_) => {}
            },
        )
        .detach();
        cx.subscribe(
            &sftp_remote_path_input,
            |this, field, ev: &TextFieldEvent, cx| match ev {
                TextFieldEvent::Submit(path) => this.navigate_remote_to_input(path.clone(), cx),
                TextFieldEvent::Cancel => {
                    let current = this.sftp_state.remote_path.clone();
                    field.update(cx, |tf, cx| tf.set_value(current, cx));
                }
                TextFieldEvent::Changed(_) => {}
            },
        )
        .detach();
        cx.subscribe(&sftp_mkdir_input, |this, _, ev: &TextFieldEvent, cx| {
            if matches!(ev, TextFieldEvent::Submit(_)) {
                this.create_remote_dir(cx);
            }
        })
        .detach();

        // Bridge all Tokio async backend events to GPUI UI loop
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            while let Some(ev) = ui_rx.recv().await {
                let mut batch = vec![ev];
                while let Ok(next) = ui_rx.try_recv() {
                    batch.push(next);
                }
                let updated = this.update(cx, |app, cx| {
                    for item in batch {
                        app.handle_ui_event(item, cx);
                    }
                    cx.notify();
                });
                if updated.is_err() {
                    break;
                }
            }
        })
        .detach();

        let saved_settings: UiSettings = services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.get_meta_string("gpui_settings").ok().flatten())
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();

        // Default to Local-First Offline when uninitialized (fixes audit P0 blocker!),
        // or Login when previously synced.
        let initial_auth_mode = if !vault_status.initialized || sync_status.server_url.is_none() {
            AuthScreenMode::Offline
        } else {
            AuthScreenMode::Login
        };

        let first_sftp_id = Uuid::now_v7().to_string();
        let initial_sftp_state = SftpWorkspaceState::new(default_local.clone());

        let mut app = Self {
            services,
            theme_mode: saved_settings.theme_mode,
            settings: saved_settings,
            sidebar_collapsed: false,
            page: AdminPage::Hosts,
            settings_tab: SettingsTab::Appearance,
            settings_tab_epoch: 1,
            settings_busy: false,
            island_open: false,
            page_epoch: 1,
            modal_epoch: 1,
            island_epoch: 1,
            toast_epoch: 1,
            sidebar_epoch: 0,
            unlock_busy: false,
            sync_busy: false,
            vault_status,
            snapshot,
            sync_status,
            selected_group_filter: None,
            selected_tag_filter: None,
            toast: None,
            ssh_discovery: None,
            ssh_auto_import_enabled,
            ssh_discovery_allow_auto: false,
            workspace_tabs: Vec::new(),
            active_workspace_tab_id: None,
            terminal_tabs: Vec::new(),
            focused_pane_tab_id: None,
            terminal_focus: cx.focus_handle(),
            app_focus: cx.focus_handle(),
            term_search_open: false,
            term_search_input,
            term_retry_password,
            suggestions_manual_open: false,
            suggestions_dismissed: false,
            suggestions_selected_idx: 0,
            sftp_state: initial_sftp_state.clone(),
            sftp_host_filter,
            modal: None,
            pending_host_keys: VecDeque::new(),
            pending_kbi: VecDeque::new(),
            kbi_inputs: Vec::new(),
            palette_query,
            palette_quick_auth: CredentialKind::Password,
            palette_quick_password,
            auth_mode: initial_auth_mode,
            auth_stay_signed_in: true,
            auth_editing_server: false,
            auth_email,
            auth_server_url,
            unlock_password,
            unlock_confirm,
            server_search,
            snippet_search,
            snippet_cmd_input,
            snippet_label_input,
            snippet_host_id: None,
            editing_snippet_id: None,
            qc_label,
            qc_hostname,
            qc_port,
            qc_username,
            qc_password,
            qc_group_name,
            qc_tags,
            qc_keepalive,
            qc_startup_cmd,
            qc_notes,
            qc_auth_choice: CredentialKind::Password,
            qc_key_pem,
            qc_key_passphrase,
            qc_cert_openssh,
            selected_credential_id: None,
            selected_jump_host_id: None,
            selected_terminal_theme: None,
            qc_auth_mode: HostAuthMode::Credential,
            qc_forward_agent: false,
            qc_proxy_url,
            qc_favorite: false,
            grp_name_input,
            grp_default_user_input,
            grp_default_cred_id: None,
            grp_parent_id: None,
            sftp_local_path_input,
            sftp_remote_path_input,
            sftp_mkdir_input,
            remote_editor_input,
            chmod_input,
            rename_input,
            key_auth_choice: CredentialKind::PrivateKey,
            cred_label,
            cred_username,
            cred_secret,
            cred_passphrase,
            cred_cert,
            sync_url,
            sync_email,
            sync_password,
            pw_current,
            pw_new,
            pw_confirm,
            delete_account_pw,
            backup_path,
            backup_passphrase,
            sftp_drawer_open: false,
            active_tunnels: HashMap::new(),
            last_activity_at: Instant::now(),
            tun_kind: PortForwardKind::Local,
            tun_host_id: None,
            tun_label,
            tun_bind_addr,
            tun_bind_port,
            tun_target_host,
            tun_target_port,
            tun_auto_start: false,
            snippet_var_inputs: Vec::new(),
            host_latencies: HashMap::new(),
            latency_probing: false,
            keychain_tab: KeychainTab::Credentials,
            keychain_search,
            agent_identities: Vec::new(),
            agent_error: None,
            sftp_tabs: vec![SftpTabSnapshot {
                id: first_sftp_id.clone(),
                label: "SFTP 1".to_string(),
                state: initial_sftp_state,
            }],
            active_sftp_tab_id: first_sftp_id,
            sftp_drawer_follow_cwd: true,
            last_drawer_followed_cwd: None,
            recording_shortcut: None,
            sessions_restored_once: false,
        };

        // Background ticker: polls active SSH tunnel stats (2s), checks OS sleep wake gap, and checks Auto-Lock idle timer (15s)
        {
            let bg_services = Arc::clone(&app.services);
            app.services.rt.spawn(async move {
                let mut tick: u64 = 0;
                let mut prev_wall = std::time::SystemTime::now();
                let mut prev_awake = awake_monotonic_duration();
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    tick = tick.wrapping_add(1);
                    let now_wall = std::time::SystemTime::now();
                    let now_awake = awake_monotonic_duration();
                    let wall_elapsed = now_wall.duration_since(prev_wall).unwrap_or(Duration::ZERO);
                    let awake_elapsed = now_awake.saturating_sub(prev_awake);
                    prev_wall = now_wall;
                    prev_awake = now_awake;
                    if let Some(slept_secs) =
                        detect_system_sleep_gap(wall_elapsed, awake_elapsed, Duration::from_secs(20))
                    {
                        let _ = bg_services
                            .ui_tx
                            .send(UiEvent::SystemSleepDetected { slept_secs });
                    }
                    let stats = bg_services.ssh.list_tunnels();
                    if !stats.is_empty() {
                        let _ = bg_services
                            .ui_tx
                            .send(UiEvent::TunnelStatsSnapshot(stats));
                    }
                    if tick.is_multiple_of(7) {
                        let _ = bg_services.ui_tx.send(UiEvent::IdleLockTick);
                    }
                }
            });
        }

        app.sync_text_field_appearances(cx);
        app.refresh_local_dir(default_local);
        if app.vault_status.unlocked {
            app.spawn_detect_local_ssh();
            app.maybe_auto_sync(cx);
            app.restore_saved_sessions_if_enabled(cx);
        }
        app
    }

    pub fn set_toast(&mut self, msg: impl Into<String>, is_error: bool) {
        self.toast = Some((msg.into(), is_error));
        self.toast_epoch = self.toast_epoch.wrapping_add(1);
    }

    pub fn navigate_to(&mut self, target: AdminPage, cx: &mut Context<Self>) {
        self.active_workspace_tab_id = None;
        if self.page != target {
            self.page = target;
            self.page_epoch = self.page_epoch.wrapping_add(1);
        }
        if target == AdminPage::Sftp && !self.sftp_state.is_left_remote() {
            self.refresh_local_dir(self.sftp_state.local_path.clone());
        }
        if target == AdminPage::Keychain && self.keychain_tab == KeychainTab::Agent {
            self.refresh_agent_identities(cx);
        }
        cx.notify();
    }

    pub fn open_modal(&mut self, modal: ActiveModal, cx: &mut Context<Self>) {
        self.recording_shortcut = None;
        self.modal = Some(modal);
        self.modal_epoch = self.modal_epoch.wrapping_add(1);
        cx.notify();
    }

    pub fn open_command_palette(&mut self, cx: &mut Context<Self>) {
        self.palette_query.update(cx, |f, cx| f.clear(cx));
        self.palette_quick_password.update(cx, |f, cx| f.clear(cx));
        self.palette_quick_auth = CredentialKind::Password;
        self.open_modal(ActiveModal::CommandPalette, cx);
    }

    pub fn toggle_sidebar(&mut self, cx: &mut Context<Self>) {
        self.sidebar_collapsed = !self.sidebar_collapsed;
        self.sidebar_epoch = self.sidebar_epoch.wrapping_add(1);
        cx.notify();
    }

    pub fn toggle_island(&mut self, cx: &mut Context<Self>) {
        self.island_open = !self.island_open;
        if self.island_open {
            self.island_epoch = self.island_epoch.wrapping_add(1);
        }
        cx.notify();
    }

    pub fn is_any_loading(&self) -> bool {
        self.unlock_busy
            || self.sync_busy
            || self.settings_busy
            || self.sftp_state.connecting
            || self.sftp_state.loading_local
            || self.sftp_state.loading_remote
            || self.sftp_state.running_count() > 0
            || self
                .terminal_tabs
                .iter()
                .any(|t| !t.connected && t.status_line == "Connecting...")
    }

    pub fn sync_text_field_appearances(&self, cx: &mut Context<Self>) {
        let mode = self.settings.theme_mode;
        let accent = self.settings.accent;
        let fields = [
            &self.auth_email,
            &self.auth_server_url,
            &self.unlock_password,
            &self.unlock_confirm,
            &self.server_search,
            &self.snippet_search,
            &self.snippet_cmd_input,
            &self.snippet_label_input,
            &self.palette_query,
            &self.palette_quick_password,
            &self.term_search_input,
            &self.term_retry_password,
            &self.sftp_host_filter,
            &self.qc_label,
            &self.qc_hostname,
            &self.qc_port,
            &self.qc_username,
            &self.qc_password,
            &self.qc_group_name,
            &self.qc_tags,
            &self.qc_keepalive,
            &self.qc_startup_cmd,
            &self.qc_notes,
            &self.qc_key_pem,
            &self.qc_key_passphrase,
            &self.qc_cert_openssh,
            &self.qc_proxy_url,
            &self.keychain_search,
            &self.grp_name_input,
            &self.grp_default_user_input,
            &self.sftp_local_path_input,
            &self.sftp_remote_path_input,
            &self.sftp_mkdir_input,
            &self.remote_editor_input,
            &self.chmod_input,
            &self.rename_input,
            &self.cred_label,
            &self.cred_username,
            &self.cred_secret,
            &self.cred_passphrase,
            &self.cred_cert,
            &self.sync_url,
            &self.sync_email,
            &self.sync_password,
            &self.pw_current,
            &self.pw_new,
            &self.pw_confirm,
            &self.delete_account_pw,
            &self.backup_path,
            &self.backup_passphrase,
            &self.tun_label,
            &self.tun_bind_addr,
            &self.tun_bind_port,
            &self.tun_target_host,
            &self.tun_target_port,
        ];
        for f in fields {
            f.update(cx, |tf, cx| {
                tf.set_appearance(mode, accent);
                cx.notify();
            });
        }
        for f in &self.kbi_inputs {
            f.update(cx, |tf, cx| {
                tf.set_appearance(mode, accent);
                cx.notify();
            });
        }
        for f in &self.snippet_var_inputs {
            f.update(cx, |tf, cx| {
                tf.set_appearance(mode, accent);
                cx.notify();
            });
        }
    }

    pub fn save_settings(&mut self, cx: &mut Context<Self>) {
        self.theme_mode = self.settings.theme_mode;
        for pane in &mut self.terminal_tabs {
            pane.line_height_mult = self.settings.terminal_line_height;
        }
        self.sync_text_field_appearances(cx);
        if let Ok(json) = serde_json::to_string(&self.settings)
            && let Ok(vault) = self.services.vault.lock() {
                let _ = vault.set_meta_string("gpui_settings", &json);
            }
        self.persist_workspace_sessions();
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Native OS File Pickers via GPUI App::prompt_for_paths / prompt_for_new_path
    // -------------------------------------------------------------------------

    pub fn pick_file_into_field(&self, target: Entity<TextField>, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select file".into()),
        });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            if let Ok(Ok(Some(paths))) = rx.await
                && let Some(path) = paths.into_iter().next() {
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            let _ = this.update(cx, |app, cx| {
                                target.update(cx, |tf, cx| tf.set_value(content, cx));
                                app.set_toast(
                                    format!("Loaded {}", path.file_name().unwrap_or_default().to_string_lossy()),
                                    false,
                                );
                                cx.notify();
                            });
                        }
                        Err(e) => {
                            let _ = this.update(cx, |app, cx| {
                                app.set_toast(format!("Failed to read file: {e}"), true);
                                cx.notify();
                            });
                        }
                    }
                }
        })
        .detach();
    }

    pub fn pick_backup_export_path(&self, cx: &mut Context<Self>) {
        let start_dir = dirs::desktop_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let rx = cx.prompt_for_new_path(&start_dir, Some("sterm-backup.sterm-vault"));
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            if let Ok(Ok(Some(path))) = rx.await {
                let p_str = path.to_string_lossy().to_string();
                let _ = this.update(cx, |app, cx| {
                    app.backup_path.update(cx, |tf, cx| tf.set_value(p_str, cx));
                    cx.notify();
                });
            }
        })
        .detach();
    }

    pub fn pick_backup_import_path(&self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select .sterm-vault backup".into()),
        });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            if let Ok(Ok(Some(paths))) = rx.await
                && let Some(path) = paths.into_iter().next() {
                    let p_str = path.to_string_lossy().to_string();
                    let _ = this.update(cx, |app, cx| {
                        app.backup_path.update(cx, |tf, cx| tf.set_value(p_str, cx));
                        cx.notify();
                    });
                }
        })
        .detach();
    }

    // -------------------------------------------------------------------------
    // Local ~/.ssh Auto-Discovery & Selective Config Import Modal
    // -------------------------------------------------------------------------

    pub fn spawn_detect_local_ssh(&self) {
        let services = Arc::clone(&self.services);
        self.services.rt.spawn_blocking(move || {
            let discovered = services
                .vault
                .lock()
                .ok()
                .and_then(|v| detect_local_ssh_dir(&v, None).ok());
            if let Some(info) = discovered {
                let _ = services.ui_tx.send(UiEvent::LocalSshDiscovered(info));
            }
        });
    }

    pub fn confirm_local_ssh_discovery(
        &mut self,
        import_now: bool,
        enable_auto: bool,
        cx: &mut Context<Self>,
    ) {
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                v.set_meta_string("ssh_auto_import_enabled", if enable_auto { "1" } else { "0" })
                    .map_err(|e| e.to_string())?;
                v.set_meta_string("ssh_import_prompt_dismissed", "1")
                    .map_err(|e| e.to_string())?;
                if import_now {
                    sync_local_ssh_dir(&v, None).map_err(|e| e.to_string())
                } else {
                    Ok(core_vault::ssh_config::SshImportSummary {
                        imported_hosts: 0,
                        imported_keys: 0,
                        skipped_duplicates: 0,
                    })
                }
            });

        self.ssh_auto_import_enabled = enable_auto;
        self.ssh_discovery = None;
        match res {
            Ok(summary) if import_now => {
                self.reload_vault_snapshot();
                self.set_toast(
                    format!(
                        "Imported {} host(s) and {} key(s) from ~/.ssh.",
                        summary.imported_hosts, summary.imported_keys
                    ),
                    false,
                );
                self.maybe_auto_sync(cx);
            }
            Ok(_) => {}
            Err(e) => self.set_toast(format!("~/.ssh import failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn toggle_auto_import_ssh(&mut self, cx: &mut Context<Self>) {
        let next = !self.ssh_auto_import_enabled;
        self.confirm_local_ssh_discovery(next, next, cx);
    }

    pub fn open_ssh_config_import_modal(&mut self, custom_path: Option<PathBuf>, cx: &mut Context<Self>) {
        let path = custom_path.or_else(default_ssh_config_path);
        let Some(cfg_path) = path else {
            self.set_toast("Could not resolve ~/.ssh/config path.", true);
            cx.notify();
            return;
        };
        match parse_ssh_config_file(&cfg_path) {
            Ok(entries) => {
                let selected = vec![true; entries.len()];
                self.open_modal(ActiveModal::SshConfigImport { entries, selected }, cx);
            }
            Err(e) => {
                self.set_toast(format!("Failed to read {}: {e}", cfg_path.display()), true);
                cx.notify();
            }
        }
    }

    pub fn pick_custom_ssh_config(&self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select SSH config file".into()),
        });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            if let Ok(Ok(Some(paths))) = rx.await
                && let Some(path) = paths.into_iter().next() {
                    let _ = this.update(cx, |app, cx| {
                        app.open_ssh_config_import_modal(Some(path), cx);
                    });
                }
        })
        .detach();
    }

    pub fn import_selected_ssh_config(&mut self, cx: &mut Context<Self>) {
        let chosen: Vec<ParsedSshHost> = match &self.modal {
            Some(ActiveModal::SshConfigImport { entries, selected }) => entries
                .iter()
                .zip(selected.iter())
                .filter(|&(_e, &sel)| sel).map(|(e, &_sel)| e.clone())
                .collect(),
            _ => return,
        };
        if chosen.is_empty() {
            self.set_toast("Select at least one host to import.", true);
            cx.notify();
            return;
        }
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| import_parsed_hosts(&v, &chosen).map_err(|e| e.to_string()));
        match res {
            Ok(summary) => {
                self.modal = None;
                self.reload_vault_snapshot();
                self.set_toast(
                    format!(
                        "Imported {} host(s), {} key(s) ({} duplicate skipped).",
                        summary.imported_hosts, summary.imported_keys, summary.skipped_duplicates
                    ),
                    false,
                );
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("SSH config import failed: {e}"), true),
        }
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Vault Auth, Password, Delete Account, Encrypted Backup
    // -------------------------------------------------------------------------

    pub fn submit_change_password(&mut self, cx: &mut Context<Self>) {
        if self.settings_busy {
            return;
        }
        let current_pw = self.pw_current.read(cx).value().to_string();
        let new_pw = self.pw_new.read(cx).value().to_string();
        let confirm_pw = self.pw_confirm.read(cx).value().to_string();

        if current_pw.is_empty() || new_pw.len() < 8 {
            self.set_toast(
                "Enter your current password and a new password (min 8 characters).",
                true,
            );
            cx.notify();
            return;
        }
        if new_pw != confirm_pw {
            self.set_toast("New passwords do not match.", true);
            cx.notify();
            return;
        }

        self.settings_busy = true;
        cx.notify();

        let services = Arc::clone(&self.services);
        let signed_in = self.sync_status.signed_in;
        self.services.rt.spawn(async move {
            if signed_in {
                match run_sync_change_password(Arc::clone(&services), current_pw, new_pw).await {
                    Ok(status) => {
                        let _ = services.ui_tx.send(UiEvent::SettingsActionDone {
                            message: "Master password updated locally & on E2EE sync server.".into(),
                            is_error: false,
                            sync_status: Some(status),
                        });
                    }
                    Err(e) => {
                        let _ = services.ui_tx.send(UiEvent::SettingsActionDone {
                            message: e,
                            is_error: true,
                            sync_status: None,
                        });
                    }
                }
            } else {
                let services_for_blocking = Arc::clone(&services);
                let res = tokio::task::spawn_blocking(move || {
                    let mut vault = services_for_blocking
                        .vault
                        .lock()
                        .map_err(|_| "vault lock".to_string())?;
                    vault
                        .change_master_password(&current_pw, &new_pw)
                        .map_err(|e| e.to_string())
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                match res {
                    Ok(()) => {
                        let _ = services.ui_tx.send(UiEvent::SettingsActionDone {
                            message: "Local vault master password changed successfully.".into(),
                            is_error: false,
                            sync_status: None,
                        });
                    }
                    Err(e) => {
                        let _ = services.ui_tx.send(UiEvent::SettingsActionDone {
                            message: format!("Password change failed: {e}"),
                            is_error: true,
                            sync_status: None,
                        });
                    }
                }
            }
        });
    }

    pub fn submit_delete_account(&mut self, cx: &mut Context<Self>) {
        if self.settings_busy || !self.sync_status.signed_in {
            return;
        }
        let pw = self.delete_account_pw.read(cx).value().to_string();
        if pw.is_empty() {
            self.set_toast("Enter your master password to delete your server account.", true);
            cx.notify();
            return;
        }
        self.settings_busy = true;
        cx.notify();
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match run_sync_delete_account(Arc::clone(&services), pw).await {
                Ok(()) => {
                    let _ = services.ui_tx.send(UiEvent::SyncAccountDeleted);
                }
                Err(e) => {
                    let _ = services.ui_tx.send(UiEvent::SettingsActionDone {
                        message: e,
                        is_error: true,
                        sync_status: None,
                    });
                }
            }
        });
    }

    pub fn export_vault_backup(&mut self, cx: &mut Context<Self>) {
        let dest = self.backup_path.read(cx).value().trim().to_string();
        let pass = self.backup_passphrase.read(cx).value().to_string();
        if dest.is_empty() || pass.len() < 6 {
            self.set_toast(
                "Choose a backup file path and enter a passphrase (min 6 characters).",
                true,
            );
            cx.notify();
            return;
        }
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                export_encrypted_backup(&v, &pass, &PathBuf::from(&dest)).map_err(|e| e.to_string())
            });
        match res {
            Ok(()) => {
                self.backup_passphrase.update(cx, |f, cx| f.clear(cx));
                self.set_toast(format!("Encrypted backup exported to {dest}"), false);
            }
            Err(e) => self.set_toast(format!("Backup export failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn import_vault_backup(&mut self, cx: &mut Context<Self>) {
        let src = self.backup_path.read(cx).value().trim().to_string();
        let pass = self.backup_passphrase.read(cx).value().to_string();
        if src.is_empty() || pass.is_empty() {
            self.set_toast("Choose the backup file path and enter its passphrase.", true);
            cx.notify();
            return;
        }
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                import_encrypted_backup(&v, &pass, &PathBuf::from(&src)).map_err(|e| e.to_string())
            });
        match res {
            Ok(report) => {
                self.backup_passphrase.update(cx, |f, cx| f.clear(cx));
                self.reload_vault_snapshot();
                self.set_toast(
                    format!(
                        "Restored {} host(s), {} group(s), {} credential(s).",
                        report.hosts, report.groups, report.credentials
                    ),
                    false,
                );
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Backup import failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn reload_vault_snapshot(&mut self) {
        let mut load_err: Option<String> = None;
        if let Ok(vault) = self.services.vault.lock() {
            if let Ok(st) = vault.status() {
                self.vault_status = st;
            }
            if self.vault_status.unlocked {
                match vault.snapshot() {
                    Ok(snap) => self.snapshot = snap,
                    Err(e) => {
                        self.snapshot = empty_snapshot();
                        load_err = Some(format!("Failed to load vault items: {e}"));
                    }
                }
            } else {
                self.snapshot = empty_snapshot();
            }
        }
        if let Some(msg) = load_err {
            self.set_toast(msg, true);
        }
    }

    pub fn maybe_auto_sync(&mut self, cx: &mut Context<Self>) {
        if self.settings.auto_sync
            && self.sync_status.signed_in
            && self.vault_status.unlocked
            && !self.sync_busy
        {
            self.trigger_sync_now(cx);
        }
    }

    pub fn submit_unlock_or_init(&mut self, cx: &mut Context<Self>) {
        if self.unlock_busy {
            return;
        }
        let pw = self.unlock_password.read(cx).value().to_string();
        let stay_signed_in = self.auth_stay_signed_in;

        match self.auth_mode {
            AuthScreenMode::Offline => {
                if pw.trim().len() < 4 {
                    self.set_toast("Password must be at least 4 characters.", true);
                    cx.notify();
                    return;
                }
                let is_init = self.vault_status.initialized;
                if !is_init {
                    let confirm = self.unlock_confirm.read(cx).value().to_string();
                    if !confirm.is_empty() && confirm != pw {
                        self.set_toast("Passwords do not match.", true);
                        cx.notify();
                        return;
                    }
                }
                self.unlock_busy = true;
                self.toast = None;
                cx.notify();

                let services = Arc::clone(&self.services);
                self.services.rt.spawn_blocking(move || {
                    let res = services
                        .vault
                        .lock()
                        .map_err(|_| "vault lock".to_string())
                        .and_then(|mut v| {
                            if !is_init {
                                v.initialize_vault(&pw, stay_signed_in)
                                    .map_err(|e| e.to_string())
                            } else {
                                v.unlock_with_password(&pw, Some(stay_signed_in))
                                    .map_err(|e| e.to_string())
                            }
                        });
                    match res {
                        Ok(status) => {
                            let _ = services.ui_tx.send(UiEvent::VaultUnlocked {
                                status,
                                message: if is_init {
                                    "Local encrypted vault unlocked.".into()
                                } else {
                                    "Created local encrypted vault.".into()
                                },
                            });
                        }
                        Err(e) => {
                            let _ = services
                                .ui_tx
                                .send(UiEvent::VaultActionFailed(format!("Unlock failed: {e}")));
                        }
                    }
                });
            }
            AuthScreenMode::Login | AuthScreenMode::Register => {
                let is_register = self.auth_mode == AuthScreenMode::Register;
                let server_url = self.auth_server_url.read(cx).value().trim().to_string();
                let email = self.auth_email.read(cx).value().trim().to_string();

                if server_url.is_empty() || email.is_empty() || pw.is_empty() {
                    self.set_toast("Enter your email and password.", true);
                    cx.notify();
                    return;
                }
                if is_register {
                    if pw.len() < 8 {
                        self.set_toast("Password must be at least 8 characters.", true);
                        cx.notify();
                        return;
                    }
                    let confirm = self.unlock_confirm.read(cx).value().to_string();
                    if confirm != pw {
                        self.set_toast("Passwords do not match.", true);
                        cx.notify();
                        return;
                    }
                }

                self.unlock_busy = true;
                self.toast = None;
                cx.notify();

                let services = Arc::clone(&self.services);
                self.services.rt.spawn(async move {
                    let res = if is_register {
                        run_sync_register(
                            Arc::clone(&services),
                            server_url,
                            email,
                            pw,
                            stay_signed_in,
                        )
                        .await
                    } else {
                        run_sync_login(
                            Arc::clone(&services),
                            server_url,
                            email,
                            pw,
                            stay_signed_in,
                        )
                        .await
                    };
                    match res {
                        Ok(status) => {
                            let _ = services.ui_tx.send(UiEvent::SyncCompleted {
                                status,
                                report: None,
                                message: if is_register {
                                    "Account created and vault unlocked.".into()
                                } else {
                                    "Signed in and vault unlocked.".into()
                                },
                            });
                        }
                        Err(e) => {
                            let _ = services.ui_tx.send(UiEvent::VaultActionFailed(e));
                        }
                    }
                });
            }
        }
    }

    pub fn lock_vault(&mut self, cx: &mut Context<Self>) {
        if let Ok(mut v) = self.services.vault.lock() {
            v.lock();
        }
        self.recording_shortcut = None;
        self.modal = None;
        self.reload_vault_snapshot();
        self.set_toast("Vault locked.", false);
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Confirmation Dialog Execution (Zero Accidental Destructive Actions)
    // -------------------------------------------------------------------------

    pub fn request_confirm(&mut self, action: ConfirmAction, cx: &mut Context<Self>) {
        self.open_modal(ActiveModal::Confirm(action), cx);
    }

    pub fn execute_confirmed_action(&mut self, action: ConfirmAction, cx: &mut Context<Self>) {
        self.modal = None;
        match action {
            ConfirmAction::DeleteHost { id, label } => self.delete_vault_item(id, &label, cx),
            ConfirmAction::DeleteGroup { id, name } => {
                if self.selected_group_filter.as_deref() == Some(id.as_str()) {
                    self.selected_group_filter = None;
                }
                self.delete_vault_item(id, &name, cx);
            }
            ConfirmAction::DeleteCredential { id, label, .. } => {
                self.delete_vault_item(id, &label, cx)
            }
            ConfirmAction::RevokeKnownHost { id, label } => self.delete_vault_item(id, &label, cx),
            ConfirmAction::DeleteCommand { id, command } => {
                self.delete_vault_item(id, &command, cx)
            }
            ConfirmAction::DeleteTunnel { id, label } => {
                self.stop_port_forward(id.clone(), label.clone(), cx);
                self.delete_vault_item(id, &label, cx);
            }
            ConfirmAction::DeleteRemoteFile { path, is_dir, name } => {
                self.delete_remote_entry(path, is_dir, name);
                cx.notify();
            }
            ConfirmAction::OverwriteUpload {
                local_path,
                file_name,
            } => {
                self.upload_local_file(local_path, file_name, cx);
            }
            ConfirmAction::OverwriteDownload {
                remote_path,
                file_name,
            } => {
                self.download_remote_file(remote_path, file_name, cx);
            }
            ConfirmAction::SignOut => self.trigger_sync_logout(cx),
        }
    }

    // -------------------------------------------------------------------------
    // Host, Group, Credential & Snippet CRUD (Preserves ALL Metadata!)
    // -------------------------------------------------------------------------

    pub fn open_add_host_modal(&mut self, editing: Option<&HostRecord>, cx: &mut Context<Self>) {
        if let Some(h) = editing {
            let group_name = h
                .group_id
                .as_ref()
                .and_then(|gid| self.snapshot.groups.iter().find(|g| &g.id == gid))
                .map(|g| g.name.clone())
                .unwrap_or_default();
            let existing_cred_kind = h
                .credential_id
                .as_ref()
                .and_then(|cid| self.snapshot.credentials.iter().find(|c| &c.id == cid))
                .map(|c| c.kind.clone());

            self.qc_label.update(cx, |f, cx| f.set_value(h.label.clone(), cx));
            self.qc_hostname
                .update(cx, |f, cx| f.set_value(h.hostname.clone(), cx));
            self.qc_port
                .update(cx, |f, cx| f.set_value(h.port.to_string(), cx));
            self.qc_username
                .update(cx, |f, cx| f.set_value(h.username.clone(), cx));
            self.qc_password.update(cx, |f, cx| f.clear(cx));
            self.qc_key_pem.update(cx, |f, cx| f.clear(cx));
            self.qc_key_passphrase.update(cx, |f, cx| f.clear(cx));
            self.qc_cert_openssh.update(cx, |f, cx| f.clear(cx));
            self.qc_group_name
                .update(cx, |f, cx| f.set_value(group_name, cx));
            self.qc_tags
                .update(cx, |f, cx| f.set_value(h.tags.join(", "), cx));
            self.qc_keepalive
                .update(cx, |f, cx| f.set_value(h.keepalive_secs.to_string(), cx));
            self.qc_startup_cmd.update(cx, |f, cx| {
                f.set_value(h.startup_command.clone().unwrap_or_default(), cx)
            });
            self.qc_notes
                .update(cx, |f, cx| f.set_value(h.notes.clone().unwrap_or_default(), cx));
            self.qc_proxy_url.update(cx, |f, cx| {
                f.set_value(h.proxy_url.clone().unwrap_or_default(), cx)
            });
            self.selected_credential_id = h.credential_id.clone();
            self.selected_jump_host_id = h.jump_host_id.clone();
            self.selected_terminal_theme = h.terminal_theme.clone();
            self.qc_auth_mode = h.auth_mode;
            self.qc_forward_agent = h.forward_agent;
            self.qc_favorite = h.favorite;
            self.qc_auth_choice = match h.auth_mode {
                HostAuthMode::SshAgent => CredentialKind::SshAgent,
                HostAuthMode::KeyboardInteractive => CredentialKind::KeyboardInteractive,
                HostAuthMode::Credential => existing_cred_kind.unwrap_or(CredentialKind::Password),
            };
            self.open_modal(
                ActiveModal::HostEditor {
                    editing_id: Some(h.id.clone()),
                },
                cx,
            );
        } else {
            self.qc_label.update(cx, |f, cx| f.clear(cx));
            self.qc_hostname.update(cx, |f, cx| f.clear(cx));
            self.qc_port.update(cx, |f, cx| f.set_value("22", cx));
            self.qc_username.update(cx, |f, cx| f.set_value("root", cx));
            self.qc_password.update(cx, |f, cx| f.clear(cx));
            self.qc_key_pem.update(cx, |f, cx| f.clear(cx));
            self.qc_key_passphrase.update(cx, |f, cx| f.clear(cx));
            self.qc_cert_openssh.update(cx, |f, cx| f.clear(cx));
            self.qc_group_name.update(cx, |f, cx| f.clear(cx));
            self.qc_tags.update(cx, |f, cx| f.clear(cx));
            let ka = self.settings.ssh_keepalive_secs.to_string();
            self.qc_keepalive.update(cx, |f, cx| f.set_value(ka, cx));
            self.qc_startup_cmd.update(cx, |f, cx| f.clear(cx));
            self.qc_notes.update(cx, |f, cx| f.clear(cx));
            self.qc_proxy_url.update(cx, |f, cx| f.clear(cx));
            self.selected_credential_id = None;
            self.selected_jump_host_id = None;
            self.selected_terminal_theme = None;
            self.qc_auth_mode = HostAuthMode::Credential;
            self.qc_forward_agent = false;
            self.qc_favorite = false;
            self.qc_auth_choice = CredentialKind::Password;
            self.open_modal(ActiveModal::HostEditor { editing_id: None }, cx);
        }
    }

    pub fn open_quick_connect_modal(&mut self, cx: &mut Context<Self>) {
        self.qc_hostname.update(cx, |f, cx| f.clear(cx));
        self.qc_port.update(cx, |f, cx| f.set_value("22", cx));
        self.qc_username.update(cx, |f, cx| f.set_value("root", cx));
        self.qc_password.update(cx, |f, cx| f.clear(cx));
        self.qc_auth_choice = CredentialKind::Password;
        self.open_modal(ActiveModal::QuickConnect, cx);
    }

    pub fn save_host_from_modal(&mut self, editing_id: Option<String>, cx: &mut Context<Self>) {
        let label = self.qc_label.read(cx).value().trim().to_string();
        let hostname = self.qc_hostname.read(cx).value().trim().to_string();
        let port: u16 = self.qc_port.read(cx).value().trim().parse().unwrap_or(22);
        let username = self.qc_username.read(cx).value().trim().to_string();
        let inline_pw = self.qc_password.read(cx).value().to_string();
        let inline_pem = self.qc_key_pem.read(cx).value().trim().to_string();
        let inline_passphrase = self.qc_key_passphrase.read(cx).value().to_string();
        let inline_cert = self.qc_cert_openssh.read(cx).value().trim().to_string();
        let group_name = self.qc_group_name.read(cx).value().trim().to_string();
        let tags: Vec<String> = self
            .qc_tags
            .read(cx)
            .value()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let keepalive_secs: u32 = self
            .qc_keepalive
            .read(cx)
            .value()
            .trim()
            .parse()
            .unwrap_or(self.settings.ssh_keepalive_secs);
        let startup_command = {
            let s = self.qc_startup_cmd.read(cx).value().trim().to_string();
            (!s.is_empty()).then_some(s)
        };
        let notes = {
            let s = self.qc_notes.read(cx).value().trim().to_string();
            (!s.is_empty()).then_some(s)
        };

        if hostname.is_empty() || username.is_empty() || port == 0 {
            self.set_toast("Provide a valid hostname, username, and port (1–65535).", true);
            cx.notify();
            return;
        }

        let display_label = if label.is_empty() {
            hostname.clone()
        } else {
            label
        };

        // Look up previous host record so updating an existing password updates in-place (no orphan creds!)
        let existing_host = editing_id
            .as_deref()
            .and_then(|eid| self.snapshot.hosts.iter().find(|h| h.id == eid))
            .cloned();
        let existing_cred = existing_host
            .as_ref()
            .and_then(|h| h.credential_id.as_deref())
            .and_then(|cid| self.snapshot.credentials.iter().find(|c| c.id == cid))
            .cloned();

        let result: Result<(), String> = (|| {
            let vault = self.services.vault.lock().map_err(|_| "vault lock")?;

            let group_id = if !group_name.is_empty() {
                if let Some(existing) = self
                    .snapshot
                    .groups
                    .iter()
                    .find(|g| g.name.eq_ignore_ascii_case(&group_name))
                {
                    Some(existing.id.clone())
                } else {
                    let created = vault
                        .upsert_group(GroupRecord {
                            id: String::new(),
                            name: group_name.clone(),
                            parent_id: None,
                            color: None,
                            default_username: None,
                            default_credential_id: None,
                            updated_at: 0,
                        })
                        .map_err(|e| e.to_string())?;
                    Some(created.id)
                }
            } else {
                None
            };

            let mut credential_id = if self.qc_auth_mode == HostAuthMode::Credential {
                self.selected_credential_id.clone()
            } else {
                None
            };
            let mut effective_auth_mode = self.qc_auth_mode;
            let proxy_url = {
                let p = self.qc_proxy_url.read(cx).value().trim().to_string();
                (!p.is_empty()).then_some(p)
            };

            if effective_auth_mode == HostAuthMode::Credential {
                match self.qc_auth_choice {
                    CredentialKind::Password if !inline_pw.is_empty() => {
                        let reuse_id = existing_cred
                            .as_ref()
                            .filter(|c| c.kind == CredentialKind::Password)
                            .map(|c| c.id.clone())
                            .unwrap_or_default();
                        let cred_label = existing_cred
                            .as_ref()
                            .filter(|c| c.kind == CredentialKind::Password)
                            .map(|c| c.label.clone())
                            .unwrap_or_else(|| format!("{display_label} (Password)"));
                        let rec = build_validated_credential(
                            reuse_id,
                            cred_label,
                            CredentialKind::Password,
                            Some(username.clone()),
                            Some(inline_pw),
                            None,
                            None,
                            None,
                        )?;
                        let saved = vault.upsert_credential(rec).map_err(|e| e.to_string())?;
                        credential_id = Some(saved.id);
                    }
                    CredentialKind::PrivateKey if !inline_pem.is_empty() => {
                        let rec = build_validated_credential(
                            String::new(),
                            format!("{display_label} (Key)"),
                            CredentialKind::PrivateKey,
                            Some(username.clone()),
                            None,
                            Some(inline_pem),
                            (!inline_passphrase.is_empty()).then_some(inline_passphrase),
                            None,
                        )?;
                        let saved = vault.upsert_credential(rec).map_err(|e| e.to_string())?;
                        credential_id = Some(saved.id);
                    }
                    CredentialKind::Certificate
                        if !inline_pem.is_empty() || !inline_cert.is_empty() =>
                    {
                        if inline_pem.is_empty() || inline_cert.is_empty() {
                            return Err(
                                "Provide both the private key PEM and OpenSSH certificate (*-cert.pub)."
                                    .to_string(),
                            );
                        }
                        let rec = build_validated_credential(
                            String::new(),
                            format!("{display_label} (Certificate)"),
                            CredentialKind::Certificate,
                            Some(username.clone()),
                            None,
                            Some(inline_pem),
                            (!inline_passphrase.is_empty()).then_some(inline_passphrase),
                            Some(inline_cert),
                        )?;
                        let saved = vault.upsert_credential(rec).map_err(|e| e.to_string())?;
                        credential_id = Some(saved.id);
                    }
                    CredentialKind::SshAgent if credential_id.is_none() => {
                        // Decoupled from Keychain: store directly on HostRecord.auth_mode!
                        effective_auth_mode = HostAuthMode::SshAgent;
                    }
                    CredentialKind::KeyboardInteractive if credential_id.is_none() => {
                        // Decoupled from Keychain: store directly on HostRecord.auth_mode!
                        effective_auth_mode = HostAuthMode::KeyboardInteractive;
                    }
                    _ => {}
                }
            }

            vault
                .upsert_host(HostRecord {
                    id: editing_id.unwrap_or_default(),
                    label: display_label.clone(),
                    hostname,
                    port,
                    username,
                    group_id,
                    tags,
                    credential_id,
                    jump_host_id: self.selected_jump_host_id.clone(),
                    terminal_theme: self.selected_terminal_theme.clone(),
                    keepalive_secs,
                    startup_command,
                    notes,
                    auth_mode: effective_auth_mode,
                    forward_agent: self.qc_forward_agent,
                    proxy_url,
                    favorite: self.qc_favorite,
                    last_connected_at: existing_host.as_ref().and_then(|h| h.last_connected_at),
                    updated_at: existing_host.map(|h| h.updated_at).unwrap_or(0),
                })
                .map_err(|e| e.to_string())?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.modal = None;
                self.reload_vault_snapshot();
                self.set_toast(format!("Saved host '{display_label}'."), false);
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Failed to save host: {e}"), true),
        }
        cx.notify();
    }

    pub fn open_group_editor(&mut self, editing: Option<&GroupRecord>, cx: &mut Context<Self>) {
        if let Some(g) = editing {
            self.grp_name_input
                .update(cx, |f, cx| f.set_value(g.name.clone(), cx));
            self.grp_default_user_input.update(cx, |f, cx| {
                f.set_value(g.default_username.clone().unwrap_or_default(), cx)
            });
            self.grp_default_cred_id = g.default_credential_id.clone();
            self.grp_parent_id = g.parent_id.clone();
            self.open_modal(
                ActiveModal::GroupEditor {
                    editing_id: Some(g.id.clone()),
                },
                cx,
            );
        } else {
            self.grp_name_input.update(cx, |f, cx| f.clear(cx));
            self.grp_default_user_input.update(cx, |f, cx| f.clear(cx));
            self.grp_default_cred_id = None;
            self.grp_parent_id = None;
            self.open_modal(ActiveModal::GroupEditor { editing_id: None }, cx);
        }
    }

    pub fn save_group_from_modal(&mut self, editing_id: Option<String>, cx: &mut Context<Self>) {
        let name = self.grp_name_input.read(cx).value().trim().to_string();
        if name.is_empty() {
            self.set_toast("Group name is required.", true);
            cx.notify();
            return;
        }
        let default_user = {
            let u = self.grp_default_user_input.read(cx).value().trim().to_string();
            (!u.is_empty()).then_some(u)
        };
        let existing = editing_id
            .as_deref()
            .and_then(|eid| self.snapshot.groups.iter().find(|g| g.id == eid))
            .cloned();
        let parent_id = self
            .grp_parent_id
            .clone()
            .filter(|pid| editing_id.as_deref() != Some(pid.as_str()));

        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                v.upsert_group(GroupRecord {
                    id: editing_id.unwrap_or_default(),
                    name: name.clone(),
                    parent_id,
                    color: existing.as_ref().and_then(|g| g.color.clone()),
                    default_username: default_user,
                    default_credential_id: self.grp_default_cred_id.clone(),
                    updated_at: existing.map(|g| g.updated_at).unwrap_or(0),
                })
                .map_err(|e| e.to_string())
            });
        match res {
            Ok(_) => {
                self.modal = None;
                self.reload_vault_snapshot();
                self.set_toast(format!("Saved group '{name}'."), false);
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Save group failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn open_credential_editor(
        &mut self,
        editing_id: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if let Some(ref cid) = editing_id {
            if let Some(c) = self.snapshot.credentials.iter().find(|c| &c.id == cid).cloned() {
                self.key_auth_choice = c.kind.clone();
                self.cred_label
                    .update(cx, |f, cx| f.set_value(c.label.clone(), cx));
                self.cred_username.update(cx, |f, cx| {
                    f.set_value(c.username.clone().unwrap_or_default(), cx)
                });
                self.cred_secret.update(cx, |f, cx| f.clear(cx));
                self.cred_passphrase.update(cx, |f, cx| f.clear(cx));
                self.cred_cert.update(cx, |f, cx| f.clear(cx));
            }
        } else {
            self.key_auth_choice = CredentialKind::PrivateKey;
            self.cred_label.update(cx, |f, cx| f.clear(cx));
            self.cred_username.update(cx, |f, cx| f.clear(cx));
            self.cred_secret.update(cx, |f, cx| f.clear(cx));
            self.cred_passphrase.update(cx, |f, cx| f.clear(cx));
            self.cred_cert.update(cx, |f, cx| f.clear(cx));
        }
        self.open_modal(ActiveModal::CredentialEditor { editing_id }, cx);
    }

    pub fn save_credential_from_modal(
        &mut self,
        editing_id: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let label = self.cred_label.read(cx).value().trim().to_string();
        let username = self.cred_username.read(cx).value().trim().to_string();
        let secret = self.cred_secret.read(cx).value().to_string();
        let passphrase = self.cred_passphrase.read(cx).value().to_string();
        let cert = self.cred_cert.read(cx).value().trim().to_string();

        if label.is_empty() {
            self.set_toast("Credential label is required.", true);
            cx.notify();
            return;
        }

        let kind = self.key_auth_choice.clone();
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                // When editing an existing credential, preserve secret/key/cert if user left input blank
                let prev = editing_id
                    .as_deref()
                    .and_then(|id| v.get_credential(id).ok());

                let (password, private_key_pem, final_passphrase, final_cert) = match kind {
                    CredentialKind::Password => {
                        let pw = if !secret.is_empty() {
                            Some(secret)
                        } else {
                            prev.and_then(|p| p.password)
                        };
                        if pw.as_deref().unwrap_or("").is_empty() {
                            return Err("Password is required.".to_string());
                        }
                        (pw, None, None, None)
                    }
                    CredentialKind::PrivateKey => {
                        let pem = if !secret.trim().is_empty() {
                            Some(secret.trim().to_string())
                        } else {
                            prev.as_ref().and_then(|p| p.private_key_pem.clone())
                        };
                        if pem.as_deref().unwrap_or("").is_empty() {
                            return Err("Private Key PEM is required.".to_string());
                        }
                        let pp = if !passphrase.is_empty() {
                            Some(passphrase)
                        } else {
                            prev.and_then(|p| p.passphrase)
                        };
                        (None, pem, pp, None)
                    }
                    CredentialKind::Certificate => {
                        let pem = if !secret.trim().is_empty() {
                            Some(secret.trim().to_string())
                        } else {
                            prev.as_ref().and_then(|p| p.private_key_pem.clone())
                        };
                        let c = if !cert.is_empty() {
                            Some(cert)
                        } else {
                            prev.as_ref().and_then(|p| p.certificate_openssh.clone())
                        };
                        let pp = if !passphrase.is_empty() {
                            Some(passphrase)
                        } else {
                            prev.and_then(|p| p.passphrase)
                        };
                        (None, pem, pp, c)
                    }
                    CredentialKind::SshAgent | CredentialKind::KeyboardInteractive => {
                        (None, None, None, None)
                    }
                };

                let rec = build_validated_credential(
                    editing_id.unwrap_or_default(),
                    label.clone(),
                    kind,
                    (!username.is_empty()).then_some(username),
                    password,
                    private_key_pem,
                    final_passphrase,
                    final_cert,
                )?;
                v.upsert_credential(rec).map_err(|e| e.to_string())
            });

        match res {
            Ok(_) => {
                self.modal = None;
                self.reload_vault_snapshot();
                self.set_toast(format!("Saved credential '{label}'."), false);
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Save credential failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn save_snippet_from_page(&mut self, cx: &mut Context<Self>) {
        let cmd = self.snippet_cmd_input.read(cx).value().trim().to_string();
        let label = self.snippet_label_input.read(cx).value().trim().to_string();
        if cmd.is_empty() {
            self.set_toast("Command text is required.", true);
            cx.notify();
            return;
        }
        let existing = self
            .editing_snippet_id
            .as_deref()
            .and_then(|id| self.snapshot.commands.iter().find(|c| c.id == id))
            .cloned();
        let now = chrono::Utc::now().timestamp_millis();
        let rec = CommandRecord {
            id: self.editing_snippet_id.take().unwrap_or_default(),
            command: cmd.clone(),
            label: (!label.is_empty()).then_some(label),
            host_id: self.snippet_host_id.clone(),
            pinned: true,
            use_count: existing.as_ref().map(|c| c.use_count).unwrap_or(1),
            last_used_at: existing.as_ref().map(|c| c.last_used_at).unwrap_or(now),
            updated_at: 0,
        };
        let save_err = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| v.upsert_command(rec).map_err(|e| e.to_string()))
            .err();
        if let Some(e) = save_err {
            self.set_toast(format!("Save snippet failed: {e}"), true);
            cx.notify();
            return;
        }
        self.snippet_cmd_input.update(cx, |f, cx| f.clear(cx));
        self.snippet_label_input.update(cx, |f, cx| f.clear(cx));
        self.snippet_host_id = None;
        self.reload_vault_snapshot();
        self.set_toast(format!("Saved snippet '{cmd}'."), false);
        self.maybe_auto_sync(cx);
        cx.notify();
    }

    pub fn toggle_pin_command(&mut self, item: &SuggestedCommand, host_id: Option<String>, cx: &mut Context<Self>) {
        let now = chrono::Utc::now().timestamp_millis();
        let rec = if item.source == SuggestionSource::Starter {
            CommandRecord {
                id: String::new(),
                command: item.command.clone(),
                label: item.label.clone(),
                host_id,
                pinned: true,
                use_count: 1,
                last_used_at: now,
                updated_at: 0,
            }
        } else if let Some(existing) = self.snapshot.commands.iter().find(|c| c.id == item.id) {
            let mut updated = existing.clone();
            updated.pinned = !updated.pinned;
            updated
        } else {
            return;
        };
        if let Ok(vault) = self.services.vault.lock() {
            let _ = vault.upsert_command(rec);
        }
        self.reload_vault_snapshot();
        self.maybe_auto_sync(cx);
        cx.notify();
    }

    pub fn record_command_usage(&mut self, cmd: &str, host_id: Option<String>, cx: &mut Context<Self>) {
        if let Ok(vault) = self.services.vault.lock() {
            let _ = vault.record_command_usage(cmd, host_id);
        }
        self.reload_vault_snapshot();
        self.maybe_auto_sync(cx);
    }

    pub fn delete_vault_item(&mut self, id: String, label: &str, cx: &mut Context<Self>) {
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| v.soft_delete_item(&id).map_err(|e| e.to_string()));
        match res {
            Ok(()) => {
                self.reload_vault_snapshot();
                self.set_toast(format!("Removed '{label}'."), false);
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Delete failed: {e}"), true),
        }
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Workspace Tabs, Nested Split Panes & SSH Sessions
    // -------------------------------------------------------------------------

    pub fn active_workspace_tab(&self) -> Option<&WorkspaceTab> {
        let id = self.active_workspace_tab_id.as_deref()?;
        self.workspace_tabs.iter().find(|t| t.id == id)
    }

    pub fn active_pane_id(&self) -> Option<String> {
        if let Some(ws) = self.active_workspace_tab() {
            return Some(ws.active_pane_id.clone());
        }
        self.focused_pane_tab_id
            .clone()
            .filter(|id| self.terminal_tabs.iter().any(|p| &p.tab_id == id))
            .or_else(|| self.terminal_tabs.first().map(|p| p.tab_id.clone()))
    }

    fn spawn_ssh_for_pane(
        &self,
        pane_id: String,
        req: ConnectRequest,
        label: String,
        old_session_to_close: Option<String>,
    ) {
        let hostname = req.target.hostname.clone();
        let port = req.target.port;
        let username = req.target.username.clone();
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            if let Some(sid) = old_session_to_close {
                let _ = services.ssh.close_session(&sid).await;
            }
            let verifier = services.verifier();
            let ui_tx = services.ui_tx.clone();
            let pane_for_stream = pane_id.clone();
            match services
                .ssh
                .connect_shell(req, verifier, move |ev| {
                    let _ = ui_tx.send(UiEvent::TerminalOutput {
                        tab_id: pane_for_stream.clone(),
                        event: ev,
                    });
                })
                .await
            {
                Ok(session_id) => {
                    let _ = services.ui_tx.send(UiEvent::SshConnected {
                        tab_id: pane_id,
                        session_id,
                        label,
                        hostname,
                        port,
                        username,
                    });
                }
                Err(e) => {
                    let is_auth = is_ssh_auth_error(&e);
                    let _ = services.ui_tx.send(UiEvent::SshConnectFailed {
                        tab_id: pane_id,
                        error: e.to_string(),
                        is_auth_error: is_auth,
                    });
                }
            }
        });
    }

    pub fn connect_host_ssh(
        &mut self,
        host_id: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.connect_host_ssh_impl(host_id, None, None, Some(window), cx);
    }

    pub fn connect_host_ssh_no_window(&mut self, host_id: String, cx: &mut Context<Self>) {
        self.connect_host_ssh_impl(host_id, None, None, None, cx);
    }

    pub fn connect_host_ssh_with_startup(
        &mut self,
        host_id: String,
        startup_command: Option<String>,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        self.connect_host_ssh_impl(host_id, startup_command, None, window, cx);
    }

    fn connect_host_ssh_impl(
        &mut self,
        host_id: String,
        startup_override: Option<String>,
        split_into: Option<(String, String, SplitDirection)>,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        let built = {
            let vault = match self.services.vault.lock() {
                Ok(v) => v,
                Err(_) => return,
            };
            build_connect_request_for_host(
                &vault,
                &host_id,
                DEFAULT_TERM_COLS as u32,
                DEFAULT_TERM_ROWS as u32,
                None,
            )
        };

        let (host, mut req) = match built {
            Ok(v) => v,
            Err(e) => {
                self.set_toast(format!("Cannot connect: {e}"), true);
                cx.notify();
                return;
            }
        };
        if let Some(cmd) = startup_override {
            req.startup_command = Some(cmd);
        }

        let pane_id = Uuid::now_v7().to_string();
        let mut pane = TerminalTab::connecting(
            pane_id.clone(),
            Some(host.id.clone()),
            host.label.clone(),
            host.hostname.clone(),
            host.port,
            host.username.clone(),
        );
        let group_name = host
            .group_id
            .as_deref()
            .and_then(|gid| self.snapshot.groups.iter().find(|g| g.id == gid))
            .map(|g| g.name.as_str());
        let dummy_t = ThemePalette::from_settings(&self.settings);
        pane.env_label = env_badge_for_host(&host.tags, group_name, &dummy_t).map(|(_, lbl)| lbl);
        pane.theme_id = host.terminal_theme.clone();
        pane.line_height_mult = self.settings.terminal_line_height;
        self.terminal_tabs.push(pane);

        if let Some((ws_id, target_pane_id, direction)) = split_into {
            let split_id = Uuid::now_v7().to_string();
            if let Some(ws) = self.workspace_tabs.iter_mut().find(|w| w.id == ws_id) {
                ws.root = tree_split_pane(
                    ws.root.clone(),
                    &target_pane_id,
                    &pane_id,
                    direction,
                    &split_id,
                );
                ws.active_pane_id = pane_id.clone();
                self.active_workspace_tab_id = Some(ws_id);
            }
        } else {
            let ws_id = Uuid::now_v7().to_string();
            self.workspace_tabs.push(WorkspaceTab {
                id: ws_id.clone(),
                title: host.label.clone(),
                root: create_leaf(pane_id.clone()),
                active_pane_id: pane_id.clone(),
                broadcast_input: false,
            });
            self.active_workspace_tab_id = Some(ws_id);
        }

        self.focused_pane_tab_id = Some(pane_id.clone());
        self.page_epoch = self.page_epoch.wrapping_add(1);
        if let Some(w) = window {
            w.focus(&self.terminal_focus);
        }

        self.spawn_ssh_for_pane(pane_id, req, host.label, None);
        self.persist_workspace_sessions();
        cx.notify();
    }

    pub fn split_pane_duplicate_or_host(
        &mut self,
        workspace_tab_id: String,
        target_pane_id: String,
        direction: SplitDirection,
        host_override: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if let Some(hid) = host_override {
            self.connect_host_ssh_impl(
                hid,
                None,
                Some((workspace_tab_id, target_pane_id, direction)),
                None,
                cx,
            );
            return;
        }
        // Duplicate the target pane's saved host if it has one; otherwise open split host picker
        if let Some(hid) = self
            .terminal_tabs
            .iter()
            .find(|p| p.tab_id == target_pane_id)
            .and_then(|p| p.host_id.clone())
        {
            self.connect_host_ssh_impl(
                hid,
                None,
                Some((workspace_tab_id, target_pane_id, direction)),
                None,
                cx,
            );
        } else {
            self.open_modal(
                ActiveModal::SplitHostPicker {
                    workspace_tab_id,
                    target_pane_id,
                    direction,
                },
                cx,
            );
        }
    }

    pub fn adjust_split_ratio(
        &mut self,
        workspace_tab_id: &str,
        split_id: &str,
        new_ratio: f32,
        cx: &mut Context<Self>,
    ) {
        if let Some(ws) = self
            .workspace_tabs
            .iter_mut()
            .find(|w| w.id == workspace_tab_id)
        {
            ws.root = update_split_ratio(ws.root.clone(), split_id, new_ratio);
            self.persist_workspace_sessions();
            cx.notify();
        }
    }

    pub fn focus_pane_in_workspace(
        &mut self,
        workspace_tab_id: &str,
        pane_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(ws) = self
            .workspace_tabs
            .iter_mut()
            .find(|w| w.id == workspace_tab_id)
        {
            ws.active_pane_id = pane_id.to_string();
        }
        self.focused_pane_tab_id = Some(pane_id.to_string());
        window.focus(&self.terminal_focus);
        cx.notify();
    }

    pub fn select_workspace_tab(
        &mut self,
        workspace_tab_id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.active_workspace_tab_id = workspace_tab_id.clone();
        if let Some(id) = workspace_tab_id
            && let Some(ws) = self.workspace_tabs.iter().find(|w| w.id == id) {
                self.focused_pane_tab_id = Some(ws.active_pane_id.clone());
                window.focus(&self.terminal_focus);
            }
        self.persist_workspace_sessions();
        cx.notify();
    }

    pub fn reorder_workspace_tabs(
        &mut self,
        dragged_id: &str,
        target_id: &str,
        cx: &mut Context<Self>,
    ) {
        if reorder_vec_by_id(&mut self.workspace_tabs, dragged_id, target_id, |w| &w.id) {
            self.persist_workspace_sessions();
            cx.notify();
        }
    }

    fn is_session_referenced_by_sftp(&self, session_id: &str) -> bool {
        if self.sftp_state.session_id.as_deref() == Some(session_id)
            || self.sftp_state.left_remote_session_id.as_deref() == Some(session_id)
        {
            return true;
        }
        self.sftp_tabs.iter().any(|tab| {
            tab.state.session_id.as_deref() == Some(session_id)
                || tab.state.left_remote_session_id.as_deref() == Some(session_id)
        })
    }

    fn close_pane_session_safely(&self, session_id: String) {
        // Session ref-counting: if any SFTP tab or drawer is actively using this SSH session, keep transport alive!
        if self.is_session_referenced_by_sftp(&session_id) {
            if let Ok(mut set) = self.services.sftp_only_sessions.lock() {
                set.insert(session_id);
            }
            return;
        }
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            services.sftp.close(&session_id).await;
            let _ = services.ssh.close_session(&session_id).await;
        });
    }

    pub fn close_pane_in_workspace(
        &mut self,
        workspace_tab_id: String,
        pane_id: String,
        cx: &mut Context<Self>,
    ) {
        if let Some(pos) = self.terminal_tabs.iter().position(|p| p.tab_id == pane_id) {
            let mut removed = self.terminal_tabs.remove(pos);
            removed.manually_closed = true;
            removed.stop_transcript();
            if let Some(sid) = removed.session_id {
                if removed.is_local {
                    self.services.local_shells.close(&sid);
                } else {
                    self.close_pane_session_safely(sid);
                }
            }
        }
        if let Some(ws_pos) = self
            .workspace_tabs
            .iter()
            .position(|w| w.id == workspace_tab_id)
        {
            let next_root = tree_close_pane(self.workspace_tabs[ws_pos].root.clone(), &pane_id);
            match next_root {
                None => {
                    self.workspace_tabs.remove(ws_pos);
                    if self.active_workspace_tab_id.as_deref() == Some(workspace_tab_id.as_str()) {
                        self.active_workspace_tab_id =
                            self.workspace_tabs.last().map(|w| w.id.clone());
                    }
                }
                Some(r) => {
                    let remaining = collect_pane_ids(&r);
                    let ws = &mut self.workspace_tabs[ws_pos];
                    ws.root = r;
                    if ws.active_pane_id == pane_id {
                        ws.active_pane_id = remaining.into_iter().next().unwrap_or_default();
                    }
                }
            }
        }
        self.focused_pane_tab_id = self.active_pane_id();
        self.persist_workspace_sessions();
        cx.notify();
    }

    pub fn close_workspace_tab(&mut self, workspace_tab_id: String, cx: &mut Context<Self>) {
        if let Some(ws_pos) = self
            .workspace_tabs
            .iter()
            .position(|w| w.id == workspace_tab_id)
        {
            let ws = self.workspace_tabs.remove(ws_pos);
            let pane_ids = collect_pane_ids(&ws.root);
            for pid in pane_ids {
                if let Some(pos) = self.terminal_tabs.iter().position(|p| p.tab_id == pid) {
                    let mut removed = self.terminal_tabs.remove(pos);
                    removed.manually_closed = true;
                    removed.stop_transcript();
                    if let Some(sid) = removed.session_id {
                        if removed.is_local {
                            self.services.local_shells.close(&sid);
                        } else {
                            self.close_pane_session_safely(sid);
                        }
                    }
                }
            }
            if self.active_workspace_tab_id.as_deref() == Some(workspace_tab_id.as_str()) {
                self.active_workspace_tab_id = self.workspace_tabs.last().map(|w| w.id.clone());
            }
            self.focused_pane_tab_id = self.active_pane_id();
        }
        self.persist_workspace_sessions();
        cx.notify();
    }

    pub fn persist_workspace_sessions(&self) {
        if !self.vault_status.unlocked || !self.settings.restore_sessions {
            return;
        }
        let mut tabs = Vec::new();
        let mut active_tab_index = None;
        for ws in &self.workspace_tabs {
            if let Some(root) = saved_node_from_split(&ws.root, &self.terminal_tabs) {
                if self.active_workspace_tab_id.as_deref() == Some(ws.id.as_str()) {
                    active_tab_index = Some(tabs.len());
                }
                tabs.push(SavedWorkspaceTab {
                    title: ws.title.clone(),
                    root,
                    broadcast_input: ws.broadcast_input,
                });
            }
        }
        let session = SavedWorkspaceSession {
            tabs,
            active_tab_index,
        };
        if let Ok(json) = serde_json::to_string(&session)
            && let Ok(vault) = self.services.vault.lock()
        {
            let _ = vault.set_meta_string("saved_workspace_sessions", &json);
        }
    }

    pub fn restore_saved_sessions_if_enabled(&mut self, cx: &mut Context<Self>) {
        if !self.settings.restore_sessions
            || self.sessions_restored_once
            || !self.vault_status.unlocked
            || !self.workspace_tabs.is_empty()
        {
            return;
        }
        self.sessions_restored_once = true;

        let saved: SavedWorkspaceSession = match self
            .services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.get_meta_string("saved_workspace_sessions").ok().flatten())
            .and_then(|raw| serde_json::from_str(&raw).ok())
        {
            Some(s) => s,
            None => return,
        };
        if saved.tabs.is_empty() {
            return;
        }

        let avail_shells = LocalShellManager::available_shells();
        let dummy_t = ThemePalette::from_settings(&self.settings);
        let mut restored_tabs = 0usize;

        for saved_tab in saved.tabs {
            let mut out_panes = Vec::new();
            let Some(root) =
                split_node_from_saved(&saved_tab.root, &self.snapshot.hosts, &mut out_panes)
            else {
                continue;
            };
            let mut root_opt = Some(root);

            for (pane_id, kind) in out_panes {
                match kind {
                    RestorePaneKind::Local {
                        program,
                        label,
                        cwd,
                    } => {
                        let shell = avail_shells
                            .iter()
                            .find(|s| {
                                program.as_deref() == Some(s.program.as_str())
                                    || label.as_deref() == Some(s.label.as_str())
                            })
                            .cloned()
                            .unwrap_or_else(LocalShellManager::default_shell);
                        let initial_dir = cwd
                            .as_deref()
                            .map(std::path::PathBuf::from)
                            .filter(|p| p.is_dir());
                        let ui_tx = self.services.ui_tx.clone();
                        let pane_for_stream = pane_id.clone();
                        match self.services.local_shells.spawn(
                            &shell,
                            initial_dir,
                            DEFAULT_TERM_COLS,
                            DEFAULT_TERM_ROWS,
                            move |ev| {
                                let _ = ui_tx.send(UiEvent::TerminalOutput {
                                    tab_id: pane_for_stream.clone(),
                                    event: ev,
                                });
                            },
                        ) {
                            Ok(sid) => {
                                let mut pane = TerminalTab::local_shell(
                                    pane_id,
                                    shell.label,
                                    sid,
                                    shell.program,
                                );
                                pane.line_height_mult = self.settings.terminal_line_height;
                                self.terminal_tabs.push(pane);
                            }
                            Err(_) => {
                                root_opt = root_opt.and_then(|r| tree_close_pane(r, &pane_id));
                            }
                        }
                    }
                    RestorePaneKind::Ssh { host_id } => {
                        let built = self.services.vault.lock().ok().and_then(|v| {
                            build_connect_request_for_host(
                                &v,
                                &host_id,
                                DEFAULT_TERM_COLS as u32,
                                DEFAULT_TERM_ROWS as u32,
                                None,
                            )
                            .ok()
                        });
                        if let Some((host, req)) = built {
                            let mut pane = TerminalTab::connecting(
                                pane_id.clone(),
                                Some(host.id.clone()),
                                host.label.clone(),
                                host.hostname.clone(),
                                host.port,
                                host.username.clone(),
                            );
                            let group_name = host
                                .group_id
                                .as_deref()
                                .and_then(|gid| {
                                    self.snapshot.groups.iter().find(|g| g.id == gid)
                                })
                                .map(|g| g.name.as_str());
                            pane.env_label = env_badge_for_host(&host.tags, group_name, &dummy_t)
                                .map(|(_, lbl)| lbl);
                            pane.theme_id = host.terminal_theme.clone();
                            pane.line_height_mult = self.settings.terminal_line_height;
                            self.terminal_tabs.push(pane);
                            self.spawn_ssh_for_pane(pane_id, req, host.label, None);
                        } else {
                            root_opt = root_opt.and_then(|r| tree_close_pane(r, &pane_id));
                        }
                    }
                }
            }

            if let Some(final_root) = root_opt {
                let pane_ids = collect_pane_ids(&final_root);
                let active_pane_id = pane_ids.into_iter().next().unwrap_or_default();
                self.workspace_tabs.push(WorkspaceTab {
                    id: Uuid::now_v7().to_string(),
                    title: saved_tab.title,
                    root: final_root,
                    active_pane_id,
                    broadcast_input: saved_tab.broadcast_input,
                });
                restored_tabs += 1;
            }
        }

        if restored_tabs > 0 {
            if let Some(ix) = saved.active_tab_index
                && let Some(ws) = self.workspace_tabs.get(ix)
            {
                self.active_workspace_tab_id = Some(ws.id.clone());
                self.focused_pane_tab_id = Some(ws.active_pane_id.clone());
            }
            self.page_epoch = self.page_epoch.wrapping_add(1);
            self.set_toast(format!("Restored {restored_tabs} workspace tab(s)."), false);
            cx.notify();
        }
    }

    pub fn reconnect_terminal_pane(
        &mut self,
        pane_id: String,
        override_password: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let Some(pane_info) = self
            .terminal_tabs
            .iter()
            .find(|t| t.tab_id == pane_id)
            .map(|t| {
                (
                    t.host_id.clone(),
                    t.label.clone(),
                    t.hostname.clone(),
                    t.port,
                    t.username.clone(),
                    t.cols as u32,
                    t.rows as u32,
                    t.session_id.clone(),
                )
            })
        else {
            return;
        };

        let (host_id, label, hostname, port, username, cols, rows, old_sid) = pane_info;

        let req = if let Some(hid) = host_id {
            let built = {
                let vault = match self.services.vault.lock() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                build_connect_request_for_host(&vault, &hid, cols, rows, override_password)
            };
            match built {
                Ok((_, req)) => req,
                Err(e) => {
                    self.set_toast(format!("Cannot reconnect: {e}"), true);
                    cx.notify();
                    return;
                }
            }
        } else {
            let auth = match override_password.filter(|p| !p.is_empty()) {
                Some(password) => SshAuthMethod::Password { password },
                None => SshAuthMethod::SshAgent,
            };
            ConnectRequest {
                jump_chain: Vec::new(),
                target: SshTarget {
                    hostname: hostname.clone(),
                    port,
                    username: username.clone(),
                    auth,
                    keepalive_secs: self.settings.ssh_keepalive_secs,
                    forward_agent: false,
                    proxy_url: None,
                },
                cols,
                rows,
                startup_command: None,
            }
        };

        if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == pane_id) {
            tab.session_id = None;
            tab.connected = false;
            tab.is_auth_error = false;
            tab.last_error = None;
            tab.status_line = "Connecting...".to_string();
            tab.append_system_line(&format!("Reconnecting to {username}@{hostname}:{port}..."));
        }

        self.spawn_ssh_for_pane(pane_id, req, label, old_sid);
        cx.notify();
    }

    pub fn submit_active_pane_password_retry(&mut self, cx: &mut Context<Self>) {
        let Some(pane_id) = self.active_pane_id() else {
            return;
        };
        let pw = self.term_retry_password.read(cx).value().to_string();
        if pw.is_empty() {
            return;
        }
        self.term_retry_password.update(cx, |f, cx| f.clear(cx));
        self.reconnect_terminal_pane(pane_id, Some(pw), cx);
    }

    pub fn save_quick_pane_to_vault(&mut self, pane_id: String, cx: &mut Context<Self>) {
        let Some(pane) = self.terminal_tabs.iter().find(|p| p.tab_id == pane_id).cloned_meta() else {
            return;
        };
        let (label, hostname, port, username) = pane;
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                v.upsert_host(HostRecord {
                    id: String::new(),
                    label: label.clone(),
                    hostname,
                    port,
                    username,
                    group_id: None,
                    tags: vec!["quick-connect".into()],
                    credential_id: None,
                    jump_host_id: None,
                    terminal_theme: None,
                    keepalive_secs: self.settings.ssh_keepalive_secs,
                    startup_command: None,
                    notes: None,
                    auth_mode: HostAuthMode::Credential,
                    forward_agent: false,
                    proxy_url: None,
                    favorite: false,
                    last_connected_at: None,
                    updated_at: 0,
                })
                .map_err(|e| e.to_string())
            });
        match res {
            Ok(saved) => {
                if let Some(p) = self.terminal_tabs.iter_mut().find(|p| p.tab_id == pane_id) {
                    p.host_id = Some(saved.id);
                }
                self.reload_vault_snapshot();
                self.set_toast(format!("Saved '{label}' to Vault."), false);
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Failed to save host: {e}"), true),
        }
        cx.notify();
    }

    #[expect(clippy::too_many_arguments, reason = "GPUI action entry point with explicit quick-connect fields")]
    pub fn launch_quick_connect(
        &mut self,
        hostname: String,
        port: u16,
        username: String,
        auth_kind: CredentialKind,
        password: String,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        if hostname.is_empty() || username.is_empty() {
            self.set_toast("Hostname and Username are required.", true);
            cx.notify();
            return;
        }
        self.modal = None;
        let auth = match auth_kind {
            CredentialKind::SshAgent => SshAuthMethod::SshAgent,
            CredentialKind::KeyboardInteractive => SshAuthMethod::KeyboardInteractive,
            _ => {
                if !password.is_empty() {
                    SshAuthMethod::Password { password }
                } else {
                    SshAuthMethod::SshAgent
                }
            }
        };

        let req = ConnectRequest {
            jump_chain: Vec::new(),
            target: SshTarget {
                hostname: hostname.clone(),
                port,
                username: username.clone(),
                auth,
                keepalive_secs: self.settings.ssh_keepalive_secs,
                forward_agent: false,
                proxy_url: None,
            },
            cols: DEFAULT_TERM_COLS as u32,
            rows: DEFAULT_TERM_ROWS as u32,
            startup_command: None,
        };

        let pane_id = Uuid::now_v7().to_string();
        let ws_id = Uuid::now_v7().to_string();
        let label = format!("{username}@{hostname}");
        let mut pane = TerminalTab::connecting(
            pane_id.clone(),
            None,
            label.clone(),
            hostname.clone(),
            port,
            username.clone(),
        );
        pane.line_height_mult = self.settings.terminal_line_height;
        self.terminal_tabs.push(pane);
        self.workspace_tabs.push(WorkspaceTab {
            id: ws_id.clone(),
            title: label.clone(),
            root: create_leaf(pane_id.clone()),
            active_pane_id: pane_id.clone(),
            broadcast_input: false,
        });
        self.active_workspace_tab_id = Some(ws_id);
        self.focused_pane_tab_id = Some(pane_id.clone());
        self.page_epoch = self.page_epoch.wrapping_add(1);
        if let Some(w) = window {
            w.focus(&self.terminal_focus);
        }

        self.spawn_ssh_for_pane(pane_id, req, label, None);
        cx.notify();
    }

    pub fn submit_quick_connect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let hostname = self.qc_hostname.read(cx).value().trim().to_string();
        let port: u16 = self.qc_port.read(cx).value().trim().parse().unwrap_or(22);
        let username = self.qc_username.read(cx).value().trim().to_string();
        let password = self.qc_password.read(cx).value().to_string();
        let kind = self.qc_auth_choice.clone();
        self.launch_quick_connect(hostname, port, username, kind, password, Some(window), cx);
    }

    pub fn parse_quick_target(query: &str) -> Option<(String, String, u16)> {
        let trimmed = query.trim();
        let (user, rest) = trimmed.split_once('@')?;
        if user.is_empty() || user.contains(char::is_whitespace) || rest.is_empty() {
            return None;
        }
        let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
            let parsed = p.parse::<u16>().ok()?;
            if parsed == 0 {
                return None;
            }
            (h, parsed)
        } else {
            (rest, 22)
        };
        if host.is_empty() || host.contains(char::is_whitespace) {
            return None;
        }
        Some((user.to_string(), host.to_string(), port))
    }

    pub fn submit_palette_primary(&mut self, cx: &mut Context<Self>) {
        let query = self.palette_query.read(cx).value().trim().to_string();
        if let Some((user, host, port)) = Self::parse_quick_target(&query) {
            let pw = self.palette_quick_password.read(cx).value().to_string();
            let auth = self.palette_quick_auth.clone();
            self.launch_quick_connect(host, port, user, auth, pw, None, cx);
            return;
        }
        let q = query.to_lowercase();
        if let Some(host) = self.snapshot.hosts.iter().find(|h| {
            q.is_empty()
                || h.label.to_lowercase().contains(&q)
                || h.hostname.to_lowercase().contains(&q)
                || h.username.to_lowercase().contains(&q)
                || h.tags.iter().any(|t| t.to_lowercase().contains(&q))
        }) {
            let hid = host.id.clone();
            self.modal = None;
            self.connect_host_ssh_no_window(hid, cx);
        }
    }

    // -------------------------------------------------------------------------
    // Terminal Search & Inline Command Suggestions
    // -------------------------------------------------------------------------

    pub fn run_terminal_search(&mut self, query: String, cx: &mut Context<Self>) {
        if let Some(pid) = self.active_pane_id()
            && let Some(pane) = self.terminal_tabs.iter_mut().find(|p| p.tab_id == pid) {
                pane.update_search(&query);
            }
        cx.notify();
    }

    pub fn step_terminal_search(&mut self, forward: bool, cx: &mut Context<Self>) {
        if let Some(pid) = self.active_pane_id()
            && let Some(pane) = self.terminal_tabs.iter_mut().find(|p| p.tab_id == pid) {
                if forward {
                    pane.next_search_match();
                } else {
                    pane.prev_search_match();
                }
            }
        cx.notify();
    }

    pub fn suggestions_for_active_pane(&self) -> (Vec<SuggestedCommand>, bool, String, Option<String>) {
        let Some(pid) = self.active_pane_id() else {
            return (Vec::new(), false, String::new(), None);
        };
        let Some(pane) = self.terminal_tabs.iter().find(|p| p.tab_id == pid) else {
            return (Vec::new(), false, String::new(), None);
        };
        let limit = if self.suggestions_manual_open { 8 } else { 5 };
        let list = rank_command_suggestions(
            &self.snapshot.commands,
            &pane.typed_line,
            pane.host_id.as_deref(),
            limit,
        );
        let visible = pane.connected
            && !self.term_search_open
            && !pane.is_alternate_screen()
            && (self.suggestions_manual_open
                || (!self.suggestions_dismissed
                    && pane.typed_line.trim().len() >= 2
                    && !list.is_empty()));
        (list, visible, pane.typed_line.clone(), pane.host_id.clone())
    }

    pub fn apply_suggestion_to_active_pane(
        &mut self,
        item: &SuggestedCommand,
        execute: bool,
        cx: &mut Context<Self>,
    ) {
        let Some(pid) = self.active_pane_id() else {
            return;
        };
        let (sid, typed, host_id) = match self.terminal_tabs.iter_mut().find(|p| p.tab_id == pid) {
            Some(p) if p.connected => {
                let sid = match p.session_id.clone() {
                    Some(s) => s,
                    None => return,
                };
                let typed = p.typed_line.clone();
                if execute {
                    p.typed_line.clear();
                } else {
                    p.typed_line = item.command.clone();
                }
                (sid, typed, p.host_id.clone())
            }
            _ => return,
        };

        let payload = compute_insert_payload(&typed, &item.command, execute);
        let _ = sid;
        self.write_bytes_to_target_panes(&pid, payload.into_bytes());

        self.suggestions_manual_open = false;
        self.suggestions_dismissed = !execute;
        self.suggestions_selected_idx = 0;
        if execute {
            self.record_command_usage(&item.command, host_id, cx);
        }
        cx.notify();
    }

    pub fn run_snippet_in_active_terminal(&mut self, command: String, cx: &mut Context<Self>) {
        let vars = extract_template_vars(&command);
        if !vars.is_empty() {
            let mode = self.settings.theme_mode;
            let accent = self.settings.accent;
            self.snippet_var_inputs = vars
                .iter()
                .map(|v| {
                    let f = cx.new(|cx| TextField::new(format!("Value for {v}..."), cx));
                    f.update(cx, |tf, _| tf.set_appearance(mode, accent));
                    f
                })
                .collect();
            self.open_modal(ActiveModal::SnippetVars { command, vars }, cx);
            return;
        }
        self.execute_command_in_active_terminal(command, cx);
    }

    pub fn submit_snippet_vars(
        &mut self,
        command: String,
        vars: Vec<String>,
        cx: &mut Context<Self>,
    ) {
        let pairs: Vec<(String, String)> = vars
            .into_iter()
            .zip(self.snippet_var_inputs.iter())
            .map(|(k, f)| (k, f.read(cx).value().to_string()))
            .collect();
        self.snippet_var_inputs.clear();
        self.modal = None;
        let rendered = render_template(&command, &pairs);
        self.execute_command_in_active_terminal(rendered, cx);
    }

    fn execute_command_in_active_terminal(&mut self, command: String, cx: &mut Context<Self>) {
        let Some(ws_id) = self
            .active_workspace_tab_id
            .clone()
            .or_else(|| self.workspace_tabs.first().map(|w| w.id.clone()))
        else {
            self.set_toast("Open a terminal tab first to run a snippet.", true);
            cx.notify();
            return;
        };
        if self.active_workspace_tab_id.is_none() {
            self.active_workspace_tab_id = Some(ws_id);
        }
        let Some(pid) = self.active_pane_id() else {
            return;
        };
        let host_id = self
            .terminal_tabs
            .iter_mut()
            .find(|p| p.tab_id == pid && p.connected)
            .map(|p| {
                p.typed_line.clear();
                p.host_id.clone()
            });
        let Some(host_id) = host_id else {
            self.set_toast("Active terminal is not connected.", true);
            cx.notify();
            return;
        };
        self.write_bytes_to_target_panes(&pid, format!("{command}\r").into_bytes());
        self.record_command_usage(&command, host_id, cx);
        cx.notify();
    }

    /// Writes terminal input bytes to either the active pane OR all connected panes in the active
    /// workspace when Broadcast Input is enabled (seamlessly routing SSH and Local PTY shells).
    pub fn write_bytes_to_target_panes(&self, active_pane_id: &str, bytes: Vec<u8>) {
        let broadcast_targets: Vec<String> = self
            .active_workspace_tab()
            .filter(|ws| ws.broadcast_input)
            .map(|ws| collect_pane_ids(&ws.root))
            .unwrap_or_else(|| vec![active_pane_id.to_string()]);

        for pid in broadcast_targets {
            if let Some(pane) = self
                .terminal_tabs
                .iter()
                .find(|p| p.tab_id == pid && p.connected)
                && let Some(sid) = pane.session_id.clone()
            {
                let payload = bytes.clone();
                if pane.is_local {
                    let _ = self.services.local_shells.write_input(&sid, &payload);
                } else {
                    let services = Arc::clone(&self.services);
                    self.services.rt.spawn(async move {
                        let _ = services.ssh.write_input(&sid, payload).await;
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Phase 3: Local Shell (portable-pty), Broadcast Input, Transcript & Docked SFTP
    // -------------------------------------------------------------------------

    pub fn open_local_shell(
        &mut self,
        spec: Option<LocalShellSpec>,
        split_into: Option<(String, String, SplitDirection)>,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        self.open_local_shell_in_dir(spec, None, split_into, window, cx);
    }

    pub fn open_local_shell_in_dir(
        &mut self,
        spec: Option<LocalShellSpec>,
        initial_cwd: Option<PathBuf>,
        split_into: Option<(String, String, SplitDirection)>,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        let shell = spec.unwrap_or_else(LocalShellManager::default_shell);
        let pane_id = Uuid::now_v7().to_string();
        let ui_tx = self.services.ui_tx.clone();
        let pane_for_stream = pane_id.clone();

        let session_id = match self.services.local_shells.spawn(
            &shell,
            initial_cwd,
            DEFAULT_TERM_COLS,
            DEFAULT_TERM_ROWS,
            move |ev| {
                let _ = ui_tx.send(UiEvent::TerminalOutput {
                    tab_id: pane_for_stream.clone(),
                    event: ev,
                });
            },
        ) {
            Ok(sid) => sid,
            Err(e) => {
                self.set_toast(format!("Local shell error: {e}"), true);
                cx.notify();
                return;
            }
        };

        let mut pane = TerminalTab::local_shell(
            pane_id.clone(),
            shell.label.clone(),
            session_id,
            shell.program,
        );
        pane.line_height_mult = self.settings.terminal_line_height;
        self.terminal_tabs.push(pane);

        if let Some((ws_id, target_pane_id, direction)) = split_into {
            let split_id = Uuid::now_v7().to_string();
            if let Some(ws) = self.workspace_tabs.iter_mut().find(|w| w.id == ws_id) {
                ws.root = tree_split_pane(
                    ws.root.clone(),
                    &target_pane_id,
                    &pane_id,
                    direction,
                    &split_id,
                );
                ws.active_pane_id = pane_id.clone();
                self.active_workspace_tab_id = Some(ws_id);
            }
        } else {
            let ws_id = Uuid::now_v7().to_string();
            self.workspace_tabs.push(WorkspaceTab {
                id: ws_id.clone(),
                title: shell.label,
                root: create_leaf(pane_id.clone()),
                active_pane_id: pane_id.clone(),
                broadcast_input: false,
            });
            self.active_workspace_tab_id = Some(ws_id);
        }

        self.focused_pane_tab_id = Some(pane_id);
        self.modal = None;
        self.page_epoch = self.page_epoch.wrapping_add(1);
        if let Some(w) = window {
            w.focus(&self.terminal_focus);
        }
        self.persist_workspace_sessions();
        cx.notify();
    }

    pub fn toggle_broadcast_input(&mut self, workspace_tab_id: &str, cx: &mut Context<Self>) {
        if let Some(ws) = self
            .workspace_tabs
            .iter_mut()
            .find(|w| w.id == workspace_tab_id)
        {
            ws.broadcast_input = !ws.broadcast_input;
            let state = if ws.broadcast_input {
                "Broadcast Input ENABLED — keystrokes send to ALL panes in this tab."
            } else {
                "Broadcast Input disabled."
            };
            self.set_toast(state, false);
        }
        self.persist_workspace_sessions();
        cx.notify();
    }

    pub fn toggle_sftp_drawer_follow_cwd(&mut self, cx: &mut Context<Self>) {
        self.sftp_drawer_follow_cwd = !self.sftp_drawer_follow_cwd;
        if self.sftp_drawer_follow_cwd
            && self.sftp_drawer_open
            && let Some(pid) = self.active_pane_id()
            && let Some((sid, cwd)) = self
                .terminal_tabs
                .iter()
                .find(|p| p.tab_id == pid && !p.is_local)
                .and_then(|p| Some((p.session_id.as_deref()?, p.current_cwd()?.to_string())))
            && self.sftp_state.session_id.as_deref() == Some(sid)
            && self.sftp_state.remote_path != cwd
        {
            self.last_drawer_followed_cwd = Some(cwd.clone());
            self.refresh_remote_dir(cwd);
        }
        cx.notify();
    }

    pub fn toggle_sftp_drawer(&mut self, pane_id: &str, cx: &mut Context<Self>) {
        if self.sftp_drawer_open {
            self.sftp_drawer_open = false;
            cx.notify();
            return;
        }
        let info = self
            .terminal_tabs
            .iter()
            .find(|p| p.tab_id == pane_id && p.connected && !p.is_local)
            .and_then(|p| {
                p.session_id.clone().map(|sid| {
                    (
                        sid,
                        p.label.clone(),
                        p.host_id.clone(),
                        p.current_cwd().map(|s| s.to_string()),
                    )
                })
            });
        let Some((session_id, host_label, host_id, pane_cwd)) = info else {
            self.set_toast("Connect an SSH pane first to open the docked SFTP drawer.", true);
            cx.notify();
            return;
        };
        self.sftp_drawer_open = true;
        if self.sftp_state.session_id.as_deref() != Some(session_id.as_str()) {
            self.close_previous_sftp_if_standalone();
            self.sftp_state.connecting = true;
            self.sftp_state.host_id = host_id;
            self.last_drawer_followed_cwd = pane_cwd.clone();
            let follow_cwd = self.sftp_drawer_follow_cwd;
            let target_sftp_tab = Some(self.active_sftp_tab_id.clone());
            let services = Arc::clone(&self.services);
            self.services.rt.spawn(async move {
                match services.sftp.attach_to_ssh(&services.ssh, &session_id).await {
                    Ok(remote_cwd) => {
                        let local_cwd = SftpManager::default_local_dir();
                        let (effective_cwd, prelisted) =
                            if follow_cwd && let Some(ref cwd) = pane_cwd {
                                match services.sftp.list_remote_dir(&session_id, cwd).await {
                                    Ok((resolved, entries)) => {
                                        (resolved.clone(), Some((resolved, entries)))
                                    }
                                    Err(_) => (remote_cwd.clone(), None),
                                }
                            } else {
                                (remote_cwd.clone(), None)
                            };
                        let _ = services.ui_tx.send(UiEvent::SftpConnected {
                            session_id: session_id.clone(),
                            host_label,
                            remote_cwd: effective_cwd.clone(),
                            local_cwd,
                            sftp_tab_id: target_sftp_tab,
                        });
                        if let Some((resolved, entries)) = prelisted {
                            let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                                session_id,
                                path: resolved,
                                entries,
                            });
                        } else if let Ok((resolved, entries)) =
                            services.sftp.list_remote_dir(&session_id, &effective_cwd).await
                        {
                            let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                                session_id,
                                path: resolved,
                                entries,
                            });
                        }
                    }
                    Err(e) => {
                        let _ = services
                            .ui_tx
                            .send(UiEvent::SftpError(format!("SFTP drawer error: {e}")));
                    }
                }
            });
        } else {
            if self.sftp_state.host_id.is_none() {
                self.sftp_state.host_id = host_id;
            }
            if self.sftp_drawer_follow_cwd
                && let Some(cwd) = pane_cwd
                && self.sftp_state.remote_path != cwd
            {
                self.last_drawer_followed_cwd = Some(cwd.clone());
                self.refresh_remote_dir(cwd);
            }
        }
        cx.notify();
    }

    pub fn toggle_pane_transcript(&mut self, pane_id: String, cx: &mut Context<Self>) {
        let already_logging = self
            .terminal_tabs
            .iter()
            .find(|p| p.tab_id == pane_id)
            .is_some_and(|p| p.transcript_file.is_some());

        if already_logging {
            if let Some(p) = self.terminal_tabs.iter_mut().find(|p| p.tab_id == pane_id) {
                let saved_path = p.transcript_path.clone();
                p.stop_transcript();
                let msg = saved_path
                    .map(|path| format!("Saved session log to {}", path.display()))
                    .unwrap_or_else(|| "Stopped session transcript logging.".into());
                self.set_toast(msg, false);
            }
            cx.notify();
            return;
        }

        let suggested = self
            .terminal_tabs
            .iter()
            .find(|p| p.tab_id == pane_id)
            .map(|p| {
                let safe: String = p
                    .label
                    .chars()
                    .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
                    .collect();
                format!(
                    "sterm-{safe}-{}.log",
                    chrono::Utc::now().format("%Y%m%d-%H%M%S")
                )
            })
            .unwrap_or_else(|| "sterm-session.log".into());

        let start_dir = dirs::desktop_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let rx = cx.prompt_for_new_path(&start_dir, Some(&suggested));
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            if let Ok(Ok(Some(path))) = rx.await {
                let _ = this.update(cx, |app, cx| {
                    if let Some(pane) = app.terminal_tabs.iter_mut().find(|p| p.tab_id == pane_id) {
                        match pane.start_transcript(path.clone()) {
                            Ok(()) => app.set_toast(
                                format!("Recording session log → {}", path.display()),
                                false,
                            ),
                            Err(e) => app.set_toast(e, true),
                        }
                    }
                    cx.notify();
                });
            }
        })
        .detach();
    }

    // -------------------------------------------------------------------------
    // Phase 3: SSH Port Forwarding (-L / -R / -D SOCKS5)
    // -------------------------------------------------------------------------

    pub fn open_tunnel_editor(
        &mut self,
        editing: Option<&PortForwardRecord>,
        cx: &mut Context<Self>,
    ) {
        if let Some(pf) = editing {
            self.tun_kind = pf.kind;
            self.tun_host_id = Some(pf.host_id.clone());
            self.tun_auto_start = pf.auto_start;
            self.tun_label
                .update(cx, |f, cx| f.set_value(pf.label.clone(), cx));
            self.tun_bind_addr
                .update(cx, |f, cx| f.set_value(pf.bind_address.clone(), cx));
            self.tun_bind_port
                .update(cx, |f, cx| f.set_value(pf.bind_port.to_string(), cx));
            self.tun_target_host.update(cx, |f, cx| {
                f.set_value(
                    pf.target_host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                    cx,
                )
            });
            self.tun_target_port.update(cx, |f, cx| {
                f.set_value(
                    pf.target_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "5432".into()),
                    cx,
                )
            });
            self.open_modal(
                ActiveModal::TunnelEditor {
                    editing_id: Some(pf.id.clone()),
                },
                cx,
            );
        } else {
            self.tun_kind = PortForwardKind::Local;
            self.tun_host_id = self.snapshot.hosts.first().map(|h| h.id.clone());
            self.tun_auto_start = false;
            self.tun_label.update(cx, |f, cx| f.clear(cx));
            self.tun_bind_addr
                .update(cx, |f, cx| f.set_value("127.0.0.1", cx));
            self.tun_bind_port
                .update(cx, |f, cx| f.set_value("8080", cx));
            self.tun_target_host
                .update(cx, |f, cx| f.set_value("127.0.0.1", cx));
            self.tun_target_port
                .update(cx, |f, cx| f.set_value("5432", cx));
            self.open_modal(ActiveModal::TunnelEditor { editing_id: None }, cx);
        }
    }

    pub fn save_tunnel_from_modal(&mut self, editing_id: Option<String>, cx: &mut Context<Self>) {
        let label = self.tun_label.read(cx).value().trim().to_string();
        let bind_address = self.tun_bind_addr.read(cx).value().trim().to_string();
        let bind_port: u16 = self.tun_bind_port.read(cx).value().trim().parse().unwrap_or(0);
        let target_host = self.tun_target_host.read(cx).value().trim().to_string();
        let target_port: u16 = self
            .tun_target_port
            .read(cx)
            .value()
            .trim()
            .parse()
            .unwrap_or(0);
        let Some(host_id) = self.tun_host_id.clone() else {
            self.set_toast("Select an SSH host for this tunnel.", true);
            cx.notify();
            return;
        };
        if bind_address.is_empty() || bind_port == 0 {
            self.set_toast("Provide a valid bind address and port (1–65535).", true);
            cx.notify();
            return;
        }
        if self.tun_kind != PortForwardKind::DynamicSocks5
            && (target_host.is_empty() || target_port == 0)
        {
            self.set_toast("Provide a valid target host and port.", true);
            cx.notify();
            return;
        }
        let display_label = if label.is_empty() {
            match self.tun_kind {
                PortForwardKind::Local => format!("-L {bind_port} → {target_host}:{target_port}"),
                PortForwardKind::Remote => format!("-R {bind_port} → {target_host}:{target_port}"),
                PortForwardKind::DynamicSocks5 => format!("-D SOCKS5 :{bind_port}"),
            }
        } else {
            label
        };

        let rec = PortForwardRecord {
            id: editing_id.unwrap_or_default(),
            label: display_label.clone(),
            host_id,
            kind: self.tun_kind,
            bind_address,
            bind_port,
            target_host: (self.tun_kind != PortForwardKind::DynamicSocks5).then_some(target_host),
            target_port: (self.tun_kind != PortForwardKind::DynamicSocks5).then_some(target_port),
            auto_start: self.tun_auto_start,
            updated_at: 0,
        };
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| v.upsert_port_forward(rec).map_err(|e| e.to_string()));
        match res {
            Ok(_) => {
                self.modal = None;
                self.reload_vault_snapshot();
                self.set_toast(format!("Saved tunnel '{display_label}'."), false);
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Save tunnel failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn start_port_forward(&mut self, pf: PortForwardRecord, cx: &mut Context<Self>) {
        // Reuse an already-connected SSH session for this host if available, else open transport-only
        let existing_sid = self
            .terminal_tabs
            .iter()
            .find(|p| p.connected && !p.is_local && p.host_id.as_deref() == Some(pf.host_id.as_str()))
            .and_then(|p| p.session_id.clone());

        let connect_req = if existing_sid.is_none() {
            let built = self
                .services
                .vault
                .lock()
                .ok()
                .and_then(|v| build_connect_request_for_host(&v, &pf.host_id, 80, 24, None).ok());
            match built {
                Some((_, req)) => Some(req),
                None => {
                    self.set_toast("Tunnel host could not be resolved from vault.", true);
                    cx.notify();
                    return;
                }
            }
        } else {
            None
        };

        let services = Arc::clone(&self.services);
        let tid = pf.id.clone();
        let label = pf.label.clone();
        self.services.rt.spawn(async move {
            let (session_id, opened_dedicated) = if let Some(sid) = existing_sid {
                (sid, false)
            } else if let Some(req) = connect_req {
                let verifier = services.verifier();
                match services.ssh.connect_transport_only(req, verifier).await {
                    Ok(sid) => (sid, true),
                    Err(e) => {
                        let _ = services.ui_tx.send(UiEvent::TunnelError {
                            tunnel_id: tid,
                            message: format!("SSH connect failed for '{label}': {e}"),
                        });
                        return;
                    }
                }
            } else {
                return;
            };

            let start_res = match pf.kind {
                PortForwardKind::Local => {
                    services
                        .ssh
                        .start_local_forward(
                            &session_id,
                            tid.clone(),
                            pf.bind_address.clone(),
                            pf.bind_port,
                            pf.target_host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                            pf.target_port.unwrap_or(80),
                        )
                        .await
                }
                PortForwardKind::DynamicSocks5 => {
                    services
                        .ssh
                        .start_dynamic_socks5(
                            &session_id,
                            tid.clone(),
                            pf.bind_address.clone(),
                            pf.bind_port,
                        )
                        .await
                }
                PortForwardKind::Remote => {
                    services
                        .ssh
                        .start_remote_forward(
                            &session_id,
                            tid.clone(),
                            pf.bind_address.clone(),
                            pf.bind_port,
                            pf.target_host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                            pf.target_port.unwrap_or(80),
                        )
                        .await
                }
            };

            match start_res {
                Ok(bound_port) => {
                    if opened_dedicated
                        && let Ok(mut map) = services.tunnel_only_sessions.lock()
                    {
                        map.insert(tid.clone(), session_id.clone());
                    }
                    let _ = services.ui_tx.send(UiEvent::TunnelStarted {
                        tunnel_id: tid,
                        session_id,
                        bound_port,
                        label,
                    });
                }
                Err(e) => {
                    if opened_dedicated {
                        let _ = services.ssh.close_session(&session_id).await;
                    }
                    let _ = services.ui_tx.send(UiEvent::TunnelError {
                        tunnel_id: tid,
                        message: format!("Failed to start '{label}': {e}"),
                    });
                }
            }
        });
        cx.notify();
    }

    pub fn stop_port_forward(&mut self, tunnel_id: String, label: String, cx: &mut Context<Self>) {
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let _ = services.ssh.stop_tunnel(&tunnel_id).await;
            let dedicated_sid = services
                .tunnel_only_sessions
                .lock()
                .ok()
                .and_then(|mut m| m.remove(&tunnel_id));
            if let Some(sid) = dedicated_sid {
                let _ = services.ssh.close_session(&sid).await;
            }
            let _ = services.ui_tx.send(UiEvent::TunnelStopped { tunnel_id, label });
        });
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Phase 3: 1-Click ssh-copy-id (Deploy Public Key to Host)
    // -------------------------------------------------------------------------

    pub fn open_deploy_key_modal(
        &mut self,
        label: String,
        public_key: String,
        cx: &mut Context<Self>,
    ) {
        self.open_modal(ActiveModal::DeployKey { label, public_key }, cx);
    }

    pub fn deploy_key_to_host(
        &mut self,
        host_id: String,
        public_key: String,
        cx: &mut Context<Self>,
    ) {
        let built = self
            .services
            .vault
            .lock()
            .ok()
            .and_then(|v| build_connect_request_for_host(&v, &host_id, 80, 24, None).ok());
        let Some((host, req)) = built else {
            self.set_toast("Host could not be resolved from vault.", true);
            cx.notify();
            return;
        };
        self.modal = None;
        self.set_toast(format!("Deploying public key to {}...", host.label), false);

        let cmd = build_ssh_copy_id_command(&public_key);
        let services = Arc::clone(&self.services);
        let host_label = host.label;
        self.services.rt.spawn(async move {
            let verifier = services.verifier();
            let result = match services.ssh.exec_command(req, verifier, &cmd).await {
                Ok((0, _)) => Ok(format!("Public key deployed to {host_label} (~/.ssh/authorized_keys).")),
                Ok((code, out)) => Err(format!(
                    "Remote command exited with status {code}: {}",
                    out.trim()
                )),
                Err(e) => Err(format!("Deploy key failed: {e}")),
            };
            let _ = services
                .ui_tx
                .send(UiEvent::KeyDeployed { host_label, result });
        });
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Phase 4: Audit Closure — Host Favorites/Clone/Ping/Export, Rekey, Agent,
    // OS Keychain Toggle, Biometric Unlock, Remote↔Remote SFTP & External Edit
    // -------------------------------------------------------------------------

    pub fn toggle_host_favorite(&mut self, host_id: String, cx: &mut Context<Self>) {
        let Some(mut host) = self
            .snapshot
            .hosts
            .iter()
            .find(|h| h.id == host_id)
            .cloned()
        else {
            return;
        };
        host.favorite = !host.favorite;
        let starred = host.favorite;
        let label = host.label.clone();
        let save_err = self
            .services
            .vault
            .lock()
            .ok()
            .and_then(|v| v.upsert_host(host).err());
        if let Some(e) = save_err {
            self.set_toast(format!("Failed to update host: {e}"), true);
            cx.notify();
            return;
        }
        self.reload_vault_snapshot();
        self.maybe_auto_sync(cx);
        self.set_toast(
            if starred {
                format!("Pinned '{label}' to Favorites.")
            } else {
                format!("Removed '{label}' from Favorites.")
            },
            false,
        );
        cx.notify();
    }

    pub fn clone_host(&mut self, host_id: String, cx: &mut Context<Self>) {
        let Some(mut copy) = self
            .snapshot
            .hosts
            .iter()
            .find(|h| h.id == host_id)
            .cloned()
        else {
            return;
        };
        copy.id = String::new();
        copy.label = format!("{} (Copy)", copy.label);
        copy.last_connected_at = None;
        let label = copy.label.clone();
        let save_res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| v.upsert_host(copy).map_err(|e| e.to_string()));
        match save_res {
            Ok(_) => {
                self.reload_vault_snapshot();
                self.maybe_auto_sync(cx);
                self.set_toast(format!("Cloned host as '{label}'."), false);
            }
            Err(e) => self.set_toast(format!("Clone failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn probe_all_host_latencies(&mut self, cx: &mut Context<Self>) {
        let targets: Vec<(String, String, u16)> = self
            .snapshot
            .hosts
            .iter()
            .map(|h| (h.id.clone(), h.hostname.clone(), h.port))
            .collect();
        if targets.is_empty() {
            return;
        }
        self.latency_probing = true;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let mut handles = Vec::with_capacity(targets.len());
            for (id, host, port) in targets {
                handles.push(tokio::spawn(async move {
                    let rtt = SshSessionManager::probe_tcp_latency(&host, port, 1500).await;
                    (id, rtt)
                }));
            }
            let mut results = Vec::with_capacity(handles.len());
            for h in handles {
                if let Ok(pair) = h.await {
                    results.push(pair);
                }
            }
            let _ = services.ui_tx.send(UiEvent::HostLatencies(results));
        });
        cx.notify();
    }

    pub fn export_ssh_config_dialog(&mut self, cx: &mut Context<Self>) {
        let content = export_hosts_to_ssh_config(&self.snapshot.hosts, &self.snapshot.groups);
        let start_dir = dirs::home_dir()
            .map(|h| h.join(".ssh"))
            .filter(|p| p.exists())
            .or_else(dirs::desktop_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let rx = cx.prompt_for_new_path(&start_dir, Some("sterm-ssh-config"));
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            if let Ok(Ok(Some(path))) = rx.await {
                let res = std::fs::write(&path, content);
                let _ = this.update(cx, |app, cx| {
                    match res {
                        Ok(()) => app.set_toast(
                            format!("Exported OpenSSH config → {}", path.display()),
                            false,
                        ),
                        Err(e) => app.set_toast(format!("Export failed: {e}"), true),
                    }
                    cx.notify();
                });
            }
        })
        .detach();
    }

    pub fn rekey_terminal_pane(&mut self, pane_id: String, cx: &mut Context<Self>) {
        let sid = self
            .terminal_tabs
            .iter()
            .find(|p| p.tab_id == pane_id && p.connected && !p.is_local)
            .and_then(|p| p.session_id.clone());
        let Some(session_id) = sid else {
            return;
        };
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services.ssh.rekey_session(&session_id).await {
                Ok(()) => {
                    let _ = services.ui_tx.send(UiEvent::SftpNotice(
                        "SSH session keys rotated (transport rekey complete).".into(),
                    ));
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("SSH rekey failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn refresh_agent_identities(&mut self, cx: &mut Context<Self>) {
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let res = SshSessionManager::list_local_agent_identities().await;
            let _ = services.ui_tx.send(UiEvent::AgentIdentitiesLoaded(res));
        });
        cx.notify();
    }

    pub fn toggle_os_keychain_unlock(&mut self, cx: &mut Context<Self>) {
        let next = !self.vault_status.keychain_enabled;
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|v| {
                v.set_keychain_unlock_enabled(next)
                    .map_err(|e| e.to_string())
            });
        match res {
            Ok(status) => {
                self.vault_status = status;
                if !next && self.settings.biometric_unlock {
                    self.settings.biometric_unlock = false;
                    self.save_settings(cx);
                }
                self.set_toast(
                    if next {
                        "Vault key saved in OS Keychain for quick unlock."
                    } else {
                        "Removed vault key from OS Keychain."
                    },
                    false,
                );
            }
            Err(e) => self.set_toast(format!("OS Keychain update failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn trigger_biometric_unlock(&mut self, cx: &mut Context<Self>) {
        if self.unlock_busy {
            return;
        }
        if !self.settings.biometric_unlock {
            self.unlock_with_os_keychain(cx);
            return;
        }
        self.unlock_busy = true;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn_blocking(move || {
            let res = verify_os_biometric("Unlock STerm SSH Vault");
            let _ = services.ui_tx.send(UiEvent::BiometricUnlockResult(res));
        });
        cx.notify();
    }

    pub fn unlock_with_os_keychain(&mut self, cx: &mut Context<Self>) {
        self.unlock_busy = false;
        let res = self
            .services
            .vault
            .lock()
            .map_err(|_| "vault lock".to_string())
            .and_then(|mut v| {
                let unlocked = v.try_unlock_from_os_keychain().map_err(|e| e.to_string())?;
                if unlocked {
                    v.status().map(Some).map_err(|e| e.to_string())
                } else {
                    Ok(None)
                }
            });
        match res {
            Ok(Some(status)) => {
                self.vault_status = status;
                self.reload_vault_snapshot();
                self.page_epoch = self.page_epoch.wrapping_add(1);
                self.set_toast("Vault unlocked via OS Keychain.", false);
                self.spawn_detect_local_ssh();
                self.maybe_auto_sync(cx);
                self.restore_saved_sessions_if_enabled(cx);
            }
            Ok(None) => {
                self.set_toast(
                    "No saved OS Keychain key found. Enter your master password to unlock.",
                    true,
                );
            }
            Err(e) => {
                self.set_toast(format!("OS Keychain unlock failed: {e}"), true);
            }
        }
        cx.notify();
    }

    /// Returns hierarchical display name for a group (`Parent / Child`).
    pub fn group_display_path(&self, group_id: &str) -> String {
        let mut parts = Vec::new();
        let mut cursor = Some(group_id.to_string());
        let mut depth = 0;
        while let Some(gid) = cursor {
            if depth > 6 {
                break;
            }
            depth += 1;
            if let Some(g) = self.snapshot.groups.iter().find(|g| g.id == gid) {
                parts.push(g.name.clone());
                cursor = g.parent_id.clone();
            } else {
                break;
            }
        }
        parts.reverse();
        parts.join(" / ")
    }

    // --- Remote ↔ Remote SFTP & External Editor Watch-Upload + Retry ---

    fn is_session_referenced_elsewhere(&self, sid: &str, ignore_sftp_tab_id: Option<&str>) -> bool {
        if self
            .terminal_tabs
            .iter()
            .any(|p| p.session_id.as_deref() == Some(sid))
        {
            return true;
        }
        if ignore_sftp_tab_id != Some(self.active_sftp_tab_id.as_str())
            && (self.sftp_state.session_id.as_deref() == Some(sid)
                || self.sftp_state.left_remote_session_id.as_deref() == Some(sid))
        {
            return true;
        }
        self.sftp_tabs.iter().any(|tab| {
            Some(tab.id.as_str()) != ignore_sftp_tab_id
                && (tab.state.session_id.as_deref() == Some(sid)
                    || tab.state.left_remote_session_id.as_deref() == Some(sid))
        })
    }

    fn release_sftp_session_if_unused(&self, sid: String, ignore_sftp_tab_id: Option<&str>) {
        if self.is_session_referenced_elsewhere(&sid, ignore_sftp_tab_id) {
            return;
        }
        let is_standalone = self
            .services
            .sftp_only_sessions
            .lock()
            .map(|mut s| s.remove(&sid))
            .unwrap_or(false);
        if is_standalone {
            let services = Arc::clone(&self.services);
            self.services.rt.spawn(async move {
                services.sftp.close(&sid).await;
                let _ = services.ssh.close_session(&sid).await;
            });
        }
    }

    fn close_left_remote_sftp_if_standalone(&self) {
        if let Some(prev_sid) = self.sftp_state.left_remote_session_id.clone() {
            self.release_sftp_session_if_unused(prev_sid, Some(&self.active_sftp_tab_id));
        }
    }

    pub fn reset_sftp_left_to_local(&mut self, cx: &mut Context<Self>) {
        self.close_left_remote_sftp_if_standalone();
        self.sftp_state.left_remote_session_id = None;
        self.sftp_state.left_remote_host_id = None;
        self.sftp_state.left_remote_host_label = None;
        self.sftp_state.selected_local = None;
        self.sftp_state.selected_local_paths.clear();
        let default_local = SftpManager::default_local_dir();
        self.sftp_state.local_path = default_local.clone();
        self.sftp_local_path_input
            .update(cx, |f, cx| f.set_value(default_local.clone(), cx));
        self.sync_active_sftp_tab_from_state();
        self.refresh_local_dir(default_local);
        cx.notify();
    }

    pub fn open_sftp_left_remote(&mut self, host_id: String, cx: &mut Context<Self>) {
        let built = {
            let vault = match self.services.vault.lock() {
                Ok(v) => v,
                Err(_) => return,
            };
            build_connect_request_for_host(&vault, &host_id, 80, 24, None)
        };
        let (host, req) = match built {
            Ok(v) => v,
            Err(e) => {
                self.set_toast(format!("Left SFTP connect failed: {e}"), true);
                cx.notify();
                return;
            }
        };

        self.close_left_remote_sftp_if_standalone();
        self.sftp_state.loading_local = true;
        let services = Arc::clone(&self.services);
        let label = host.label.clone();
        let hid = host.id.clone();
        self.services.rt.spawn(async move {
            let verifier = services.verifier();
            match services.ssh.connect_transport_only(req, verifier).await {
                Ok(session_id) => {
                    if let Ok(mut set) = services.sftp_only_sessions.lock() {
                        set.insert(session_id.clone());
                    }
                    match services.sftp.attach_to_ssh(&services.ssh, &session_id).await {
                        Ok(remote_cwd) => {
                            let _ = services.ui_tx.send(UiEvent::SftpLeftRemoteConnected {
                                session_id: session_id.clone(),
                                host_id: hid,
                                host_label: label,
                                remote_cwd: remote_cwd.clone(),
                            });
                            if let Ok((resolved, entries)) =
                                services.sftp.list_remote_dir(&session_id, &remote_cwd).await
                            {
                                let _ = services.ui_tx.send(UiEvent::SftpLeftRemoteListed {
                                    session_id,
                                    path: resolved,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ = services
                                .ui_tx
                                .send(UiEvent::SftpError(format!("Left SFTP error: {e}")));
                        }
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Left SSH transport error: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn refresh_left_pane(&mut self, path: String) {
        if let Some(sid) = self.sftp_state.left_remote_session_id.clone() {
            self.sftp_state.loading_local = true;
            let services = Arc::clone(&self.services);
            self.services.rt.spawn(async move {
                match services.sftp.list_remote_dir(&sid, &path).await {
                    Ok((resolved, entries)) => {
                        let _ = services.ui_tx.send(UiEvent::SftpLeftRemoteListed {
                            session_id: sid,
                            path: resolved,
                            entries,
                        });
                    }
                    Err(e) => {
                        let _ = services
                            .ui_tx
                            .send(UiEvent::SftpError(format!("Left remote dir error: {e}")));
                    }
                }
            });
        } else {
            self.refresh_local_dir(path);
        }
    }

    pub fn transfer_left_to_right(
        &mut self,
        src_path: String,
        name: String,
        is_dir: bool,
        cx: &mut Context<Self>,
    ) {
        if let Some(left_sid) = self.sftp_state.left_remote_session_id.clone() {
            let Some(right_sid) = self.sftp_state.session_id.clone() else {
                self.set_toast("Connect a Right remote host first.", true);
                cx.notify();
                return;
            };
            let dst_path = join_remote_path(&self.sftp_state.remote_path, &name);
            let dst_dir = self.sftp_state.remote_path.clone();
            let services = Arc::clone(&self.services);
            self.services.rt.spawn(async move {
                let tx = services.ui_tx.clone();
                let res = if is_dir {
                    services
                        .sftp
                        .transfer_remote_dir_to_remote(
                            &left_sid,
                            &src_path,
                            &right_sid,
                            &dst_path,
                            move |p| {
                                let _ = tx.send(UiEvent::SftpTransfer(p));
                            },
                        )
                        .await
                        .map(|n| format!("Transferred folder '{name}' ({n} file(s)) Remote → Remote."))
                } else {
                    services
                        .sftp
                        .transfer_remote_to_remote(
                            &left_sid,
                            &src_path,
                            &right_sid,
                            &dst_path,
                            move |p| {
                                let _ = tx.send(UiEvent::SftpTransfer(p));
                            },
                        )
                        .await
                        .map(|_| format!("Transferred '{name}' Remote → Remote."))
                };
                match res {
                    Ok(msg) => {
                        let _ = services.ui_tx.send(UiEvent::SftpNotice(msg));
                        if let Ok((resolved, entries)) =
                            services.sftp.list_remote_dir(&right_sid, &dst_dir).await
                        {
                            let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                                session_id: right_sid,
                                path: resolved,
                                entries,
                            });
                        }
                    }
                    Err(e) => {
                        let _ = services
                            .ui_tx
                            .send(UiEvent::SftpError(format!("Remote→Remote failed: {e}")));
                    }
                }
            });
            cx.notify();
            return;
        }
        if is_dir {
            self.upload_local_dir(src_path, name, cx);
        } else {
            self.upload_local_file_checked(src_path, name, cx);
        }
    }

    pub fn transfer_right_to_left(
        &mut self,
        src_path: String,
        name: String,
        is_dir: bool,
        cx: &mut Context<Self>,
    ) {
        if let Some(left_sid) = self.sftp_state.left_remote_session_id.clone() {
            let Some(right_sid) = self.sftp_state.session_id.clone() else {
                return;
            };
            let dst_path = join_remote_path(&self.sftp_state.local_path, &name);
            let dst_dir = self.sftp_state.local_path.clone();
            let services = Arc::clone(&self.services);
            self.services.rt.spawn(async move {
                let tx = services.ui_tx.clone();
                let res = if is_dir {
                    services
                        .sftp
                        .transfer_remote_dir_to_remote(
                            &right_sid,
                            &src_path,
                            &left_sid,
                            &dst_path,
                            move |p| {
                                let _ = tx.send(UiEvent::SftpTransfer(p));
                            },
                        )
                        .await
                        .map(|n| format!("Transferred folder '{name}' ({n} file(s)) Remote ← Remote."))
                } else {
                    services
                        .sftp
                        .transfer_remote_to_remote(
                            &right_sid,
                            &src_path,
                            &left_sid,
                            &dst_path,
                            move |p| {
                                let _ = tx.send(UiEvent::SftpTransfer(p));
                            },
                        )
                        .await
                        .map(|_| format!("Transferred '{name}' Remote ← Remote."))
                };
                match res {
                    Ok(msg) => {
                        let _ = services.ui_tx.send(UiEvent::SftpNotice(msg));
                        if let Ok((resolved, entries)) =
                            services.sftp.list_remote_dir(&left_sid, &dst_dir).await
                        {
                            let _ = services.ui_tx.send(UiEvent::SftpLeftRemoteListed {
                                session_id: left_sid,
                                path: resolved,
                                entries,
                            });
                        }
                    }
                    Err(e) => {
                        let _ = services
                            .ui_tx
                            .send(UiEvent::SftpError(format!("Remote←Remote failed: {e}")));
                    }
                }
            });
            cx.notify();
            return;
        }
        if is_dir {
            self.download_remote_dir(src_path, name, cx);
        } else {
            self.download_remote_file_checked(src_path, name, cx);
        }
    }

    /// Downloads a remote file to a temp path, launches the user's external editor, and watches
    /// for file saves to automatically sync edits back to the remote host over SFTP.
    pub fn open_remote_in_external_editor(
        &mut self,
        remote_path: String,
        name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let temp_dir = std::env::temp_dir().join("sterm-external-edit");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_path = temp_dir.join(format!("{}-{safe_name}", Uuid::now_v7()));
        let services = Arc::clone(&self.services);

        self.set_toast(format!("Opening '{name}' in external editor (auto-upload on save)..."), false);
        self.services.rt.spawn(async move {
            if let Err(e) = services
                .sftp
                .download_file(&session_id, &remote_path, &temp_path, |_| {})
                .await
            {
                let _ = services
                    .ui_tx
                    .send(UiEvent::SftpError(format!("External edit download failed: {e}")));
                return;
            }
            if let Err(e) = open_file_in_external_editor(&temp_path) {
                let _ = services.ui_tx.send(UiEvent::SftpError(e));
                return;
            }

            let mut last_mtime = std::fs::metadata(&temp_path).and_then(|m| m.modified()).ok();
            // Poll for saves every 1.5s for up to 30 minutes while session remains alive
            for _ in 0..1200 {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                if !temp_path.exists() {
                    break;
                }
                let cur_mtime = std::fs::metadata(&temp_path).and_then(|m| m.modified()).ok();
                if cur_mtime.is_some() && cur_mtime != last_mtime {
                    last_mtime = cur_mtime;
                    let tx = services.ui_tx.clone();
                    match services
                        .sftp
                        .upload_file(&session_id, &temp_path, &remote_path, move |p| {
                            let _ = tx.send(UiEvent::SftpTransfer(p));
                        })
                        .await
                    {
                        Ok(_) => {
                            let _ = services.ui_tx.send(UiEvent::SftpNotice(format!(
                                "Auto-uploaded saved edits → {remote_path}"
                            )));
                        }
                        Err(e) => {
                            let _ = services.ui_tx.send(UiEvent::SftpError(format!(
                                "Auto-upload failed for {name}: {e}"
                            )));
                            break;
                        }
                    }
                }
            }
        });
        cx.notify();
    }

    pub fn retry_failed_transfer(&mut self, tr: TransferProgress, cx: &mut Context<Self>) {
        match tr.direction {
            TransferDirection::Upload => {
                self.upload_local_file(tr.local_path, tr.file_name, cx);
            }
            TransferDirection::Download => {
                self.download_remote_file(tr.remote_path, tr.file_name, cx);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Terminal Selection, Mouse, Scroll & Global/Terminal Key Handling
    // -------------------------------------------------------------------------

    pub fn copy_terminal_selection(&mut self, tab_id: &str, cx: &mut Context<Self>) -> bool {
        let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) else {
            return false;
        };
        if let Some(text) = tab.selected_text() {
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            tab.clear_selection();
            self.set_toast("Copied selection to clipboard.", false);
            cx.notify();
            return true;
        }
        false
    }

    pub fn paste_into_terminal(&mut self, tab_id: &str, cx: &mut Context<Self>) {
        let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) else {
            return;
        };
        if !tab.connected {
            return;
        }
        let Some(session_id) = tab.session_id.clone() else {
            return;
        };
        if let Some(text) = cx.read_from_clipboard().and_then(|c| c.text()) {
            if text.is_empty() {
                return;
            }
            tab.clear_selection();
            tab.scroll_to_bottom();
            let normalized = text.replace("\r\n", "\r").replace('\n', "\r");
            let _ = session_id;
            self.write_bytes_to_target_panes(tab_id, normalized.into_bytes());
            cx.notify();
        }
    }

    pub fn terminal_mouse_down(
        &mut self,
        workspace_tab_id: &str,
        tab_id: &str,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.last_activity_at = Instant::now();
        self.focus_pane_in_workspace(workspace_tab_id, tab_id, window, cx);
        let font_size = self.settings.terminal_font_size;

        let mut opened_url: Option<String> = None;
        if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) {
            if (event.modifiers.control || event.modifiers.platform)
                && let Some((row, col)) = tab.pixel_to_cell(event.position, font_size)
                    && let Some(found) = tab.url_at(row, col) {
                        opened_url = Some(found.url);
                        tab.clear_selection();
                    }
            if opened_url.is_none() {
                if event.click_count >= 3 {
                    tab.begin_line_selection(event.position, font_size);
                } else if event.click_count == 2 {
                    tab.begin_word_selection(event.position, font_size);
                } else {
                    tab.begin_char_selection(event.position, font_size, event.modifiers.shift);
                }
            }
        }
        if let Some(url) = opened_url {
            cx.open_url(&url);
            self.set_toast(format!("Opened {url}"), false);
        }
        cx.notify();
    }

    pub fn terminal_mouse_move(
        &mut self,
        tab_id: &str,
        event: &MouseMoveEvent,
        cx: &mut Context<Self>,
    ) {
        let font_size = self.settings.terminal_font_size;
        let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) else {
            return;
        };
        let mut changed = false;
        let mut start_auto_scroll = false;

        if tab.is_selecting {
            if !event.dragging() {
                changed = tab.finish_selection();
            } else {
                changed = tab.update_selection_drag(event.position, font_size);
                if tab.drag_scroll_step(event.position, font_size).is_some()
                    && !tab.drag_scroll_active
                {
                    tab.drag_scroll_active = true;
                    start_auto_scroll = true;
                }
            }
        } else {
            let next_url = tab
                .pixel_to_cell(event.position, font_size)
                .and_then(|(row, col)| tab.url_at(row, col));
            if tab.hovered_url != next_url {
                tab.hovered_url = next_url;
                changed = true;
            }
        }

        if start_auto_scroll {
            self.spawn_terminal_drag_scroll(tab_id.to_string(), cx);
        }
        if changed {
            cx.notify();
        }
    }

    fn spawn_terminal_drag_scroll(&self, tab_id: String, cx: &mut Context<Self>) {
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(50))
                    .await;
                let keep_going = this.update(cx, |app, cx| {
                    let font_size = app.settings.terminal_font_size;
                    let Some(tab) = app.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id)
                    else {
                        return false;
                    };
                    if !tab.is_selecting {
                        tab.drag_scroll_active = false;
                        return false;
                    }
                    let Some(pos) = tab.drag_mouse_pos else {
                        tab.drag_scroll_active = false;
                        return false;
                    };
                    let Some(step) = tab.drag_scroll_step(pos, font_size) else {
                        tab.drag_scroll_active = false;
                        return false;
                    };
                    let prev_offset = tab.scrollback_offset();
                    tab.scroll_lines(step);
                    let sel_changed = tab.update_selection_drag(pos, font_size);
                    if tab.scrollback_offset() != prev_offset || sel_changed {
                        cx.notify();
                    }
                    true
                });
                if !matches!(keep_going, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
    }

    pub fn terminal_mouse_up(
        &mut self,
        tab_id: &str,
        _event: &MouseUpEvent,
        cx: &mut Context<Self>,
    ) {
        if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id)
            && tab.finish_selection() {
                cx.notify();
            }
    }

    pub fn terminal_right_click(
        &mut self,
        workspace_tab_id: &str,
        tab_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.last_activity_at = Instant::now();
        self.focus_pane_in_workspace(workspace_tab_id, tab_id, window, cx);
        if !self.copy_terminal_selection(tab_id, cx) {
            self.paste_into_terminal(tab_id, cx);
        }
    }

    pub fn terminal_scroll_wheel(
        &mut self,
        tab_id: &str,
        event: &ScrollWheelEvent,
        cx: &mut Context<Self>,
    ) {
        let font_size = self.settings.terminal_font_size;
        let line_h = terminal_line_height_scaled(font_size, self.settings.terminal_line_height);
        let dy = f32::from(event.delta.pixel_delta(px(line_h)).y);
        let lines = (dy / line_h).round() as i32;
        let step = if lines == 0 {
            if dy > 0.0 {
                3
            } else if dy < 0.0 {
                -3
            } else {
                0
            }
        } else {
            lines
        };
        if step != 0
            && let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) {
                tab.scroll_lines(step);
                if tab.is_selecting {
                    tab.update_selection_drag(event.position, font_size);
                } else {
                    tab.hovered_url = tab
                        .pixel_to_cell(event.position, font_size)
                        .and_then(|(row, col)| tab.url_at(row, col));
                }
                cx.notify();
            }
    }

    pub fn handle_global_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.last_activity_at = Instant::now();
        let ks = &event.keystroke;
        let mod_key = ks.modifiers.control || ks.modifiers.platform;

        if self.vault_status.unlocked
            && matches!(self.modal, Some(ActiveModal::ShortcutsHelp))
            && let Some(action) = self.recording_shortcut
        {
            if ks.key == "escape" {
                self.recording_shortcut = None;
                cx.notify();
                return;
            }
            let raw = ks.key.trim().to_ascii_lowercase();
            if matches!(
                raw.as_str(),
                "control"
                    | "shift"
                    | "alt"
                    | "platform"
                    | "meta"
                    | "super"
                    | "capslock"
                    | "fn"
            ) {
                return;
            }
            if let Some(binding) = KeyBinding::from_keystroke(ks) {
                let prev = self.settings.keybindings.get(action).clone();
                let mut swapped_with: Option<ShortcutAction> = None;
                for other in ShortcutAction::ALL {
                    if other != action && *self.settings.keybindings.get(other) == binding {
                        self.settings.keybindings.set(other, prev.clone());
                        swapped_with = Some(other);
                        break;
                    }
                }
                self.settings.keybindings.set(action, binding.clone());
                self.recording_shortcut = None;
                self.save_settings(cx);
                let msg = match swapped_with {
                    Some(other) => format!(
                        "Bound '{}' to {} (swapped with '{}').",
                        action.label(),
                        binding.display(),
                        other.label()
                    ),
                    None => format!("Bound '{}' to {}.", action.label(), binding.display()),
                };
                self.set_toast(msg, false);
                return;
            }
            self.set_toast("Include Ctrl/Cmd, Alt, or use F1-F12 for shortcuts.", true);
            cx.notify();
            return;
        }

        if ks.key == "escape"
            && let Some(ref modal) = self.modal
        {
            // Never bypass mandatory HostKey/KBI responses silently on Escape without resolving
            match modal {
                ActiveModal::HostKey(_) | ActiveModal::KeyboardInteractive(_) => {}
                _ => {
                    self.recording_shortcut = None;
                    self.modal = None;
                    cx.notify();
                    return;
                }
            }
        }

        if !self.vault_status.unlocked {
            return;
        }

        if self.settings.keybindings.matches(ShortcutAction::CommandPalette, ks) {
            self.open_command_palette(cx);
        } else if self.settings.keybindings.matches(ShortcutAction::ShortcutsHelp, ks) {
            self.open_modal(ActiveModal::ShortcutsHelp, cx);
        } else if self.settings.keybindings.matches(ShortcutAction::OpenLocalShell, ks) {
            self.open_local_shell_in_dir(None, None, None, Some(_window), cx);
        } else if mod_key
            && ks.key.len() == 1
            && let Some(digit) = ks.key.chars().next().and_then(|c| c.to_digit(10))
            && (1..=9).contains(&digit)
        {
            if digit == 1 {
                self.select_workspace_tab(None, _window, cx);
            } else if let Some(ws) = self.workspace_tabs.get((digit - 2) as usize) {
                let wid = ws.id.clone();
                self.select_workspace_tab(Some(wid), _window, cx);
            }
        } else if self.settings.keybindings.matches(ShortcutAction::LockVault, ks) {
            self.lock_vault(cx);
        } else if self.settings.keybindings.matches(ShortcutAction::CloseTab, ks) {
            if let Some(ws_id) = self.active_workspace_tab_id.clone() {
                self.close_workspace_tab(ws_id, cx);
            }
        } else if self.settings.keybindings.matches(ShortcutAction::SplitHorizontal, ks)
            && let (Some(ws_id), Some(pid)) =
                (self.active_workspace_tab_id.clone(), self.active_pane_id())
        {
            self.split_pane_duplicate_or_host(ws_id, pid, SplitDirection::Horizontal, None, cx);
        } else if self.settings.keybindings.matches(ShortcutAction::SplitVertical, ks)
            && let (Some(ws_id), Some(pid)) =
                (self.active_workspace_tab_id.clone(), self.active_pane_id())
        {
            self.split_pane_duplicate_or_host(ws_id, pid, SplitDirection::Vertical, None, cx);
        }
    }

    pub fn handle_terminal_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.modal.is_some() || self.active_workspace_tab_id.is_none() {
            return;
        }
        let Some(tab_id) = self.active_pane_id() else {
            return;
        };

        let ks = &event.keystroke;
        let mod_key = ks.modifiers.control || ks.modifiers.platform;

        // Global customizable shortcuts while terminal is focused
        if self.settings.keybindings.matches(ShortcutAction::CommandPalette, ks) {
            self.open_command_palette(cx);
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::ShortcutsHelp, ks) {
            self.open_modal(ActiveModal::ShortcutsHelp, cx);
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::OpenLocalShell, ks) {
            self.open_local_shell_in_dir(None, None, None, Some(_window), cx);
            return;
        }
        if mod_key
            && ks.key.len() == 1
            && let Some(digit) = ks.key.chars().next().and_then(|c| c.to_digit(10))
            && (1..=9).contains(&digit)
        {
            if digit == 1 {
                self.select_workspace_tab(None, _window, cx);
            } else if let Some(ws) = self.workspace_tabs.get((digit - 2) as usize) {
                let wid = ws.id.clone();
                self.select_workspace_tab(Some(wid), _window, cx);
            }
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::TerminalSearch, ks) {
            self.term_search_open = !self.term_search_open;
            cx.notify();
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::SplitHorizontal, ks) {
            if let Some(ws_id) = self.active_workspace_tab_id.clone() {
                self.split_pane_duplicate_or_host(
                    ws_id,
                    tab_id,
                    SplitDirection::Horizontal,
                    None,
                    cx,
                );
            }
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::SplitVertical, ks) {
            if let Some(ws_id) = self.active_workspace_tab_id.clone() {
                self.split_pane_duplicate_or_host(
                    ws_id,
                    tab_id,
                    SplitDirection::Vertical,
                    None,
                    cx,
                );
            }
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::CloseTab, ks) {
            if let Some(ws_id) = self.active_workspace_tab_id.clone() {
                self.close_workspace_tab(ws_id, cx);
            }
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::LockVault, ks) {
            self.lock_vault(cx);
            return;
        }
        if self.settings.keybindings.matches(ShortcutAction::ToggleSuggestions, ks) {
            self.suggestions_manual_open = !self.suggestions_manual_open;
            self.suggestions_dismissed = false;
            self.suggestions_selected_idx = 0;
            cx.notify();
            return;
        }

        // Suggestions popover navigation when visible
        let (suggestions, sug_visible, _, _) = self.suggestions_for_active_pane();
        if sug_visible && !suggestions.is_empty() {
            if (ks.modifiers.alt && ks.key == "down")
                || (ks.modifiers.control && ks.key.eq_ignore_ascii_case("n"))
            {
                self.suggestions_selected_idx =
                    (self.suggestions_selected_idx + 1) % suggestions.len();
                cx.notify();
                return;
            }
            if (ks.modifiers.alt && ks.key == "up")
                || (ks.modifiers.control && ks.key.eq_ignore_ascii_case("p"))
            {
                self.suggestions_selected_idx =
                    (self.suggestions_selected_idx + suggestions.len() - 1) % suggestions.len();
                cx.notify();
                return;
            }
            if ks.key == "tab" && !ks.modifiers.shift
                && let Some(item) = suggestions.get(self.suggestions_selected_idx).cloned() {
                    self.apply_suggestion_to_active_pane(&item, false, cx);
                    return;
                }
            if ks.modifiers.alt && ks.key == "enter"
                && let Some(item) = suggestions.get(self.suggestions_selected_idx).cloned() {
                    self.apply_suggestion_to_active_pane(&item, true, cx);
                    return;
                }
            if ks.key == "escape" {
                self.suggestions_manual_open = false;
                self.suggestions_dismissed = true;
                cx.notify();
                return;
            }
        }

        // Copy / Paste
        if (ks.key.eq_ignore_ascii_case("c") && mod_key)
            || (ks.key == "insert" && ks.modifiers.control && !ks.modifiers.shift)
        {
            let has_selection = self
                .terminal_tabs
                .iter_mut()
                .find(|t| t.tab_id == tab_id)
                .and_then(|t| t.selected_text())
                .is_some();
            if ks.modifiers.platform || ks.modifiers.shift || ks.key == "insert" || has_selection {
                self.copy_terminal_selection(&tab_id, cx);
                return;
            }
        }

        if (ks.key.eq_ignore_ascii_case("v") && mod_key)
            || (ks.key == "insert" && ks.modifiers.shift && !ks.modifiers.control)
        {
            self.paste_into_terminal(&tab_id, cx);
            return;
        }

        if ks.modifiers.shift
            && !ks.modifiers.control
            && !ks.modifiers.alt
            && !ks.modifiers.platform
            && (ks.key == "pageup" || ks.key == "pagedown")
        {
            if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) {
                let page = (tab.rows as i32 - 1).max(1);
                tab.scroll_lines(if ks.key == "pageup" { page } else { -page });
                cx.notify();
            }
            return;
        }

        if ks.key == "escape" {
            if self.term_search_open {
                self.term_search_open = false;
                cx.notify();
                return;
            }
            if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id)
                && tab.selection.is_some() {
                    tab.clear_selection();
                    cx.notify();
                    return;
                }
        }

        let Some(bytes) = keystroke_to_vt_bytes(ks) else {
            return;
        };

        // Track typed command line cleanly for command history & suggestions
        let mut command_to_record: Option<(String, Option<String>)> = None;
        let session_id = self
            .terminal_tabs
            .iter_mut()
            .find(|t| t.tab_id == tab_id && t.connected)
            .and_then(|t| {
                t.clear_selection();
                t.scroll_to_bottom();
                if t.is_alternate_screen() {
                    t.typed_line.clear();
                } else if bytes == b"\r" || bytes == b"\n" {
                    let submitted = std::mem::take(&mut t.typed_line);
                    self.suggestions_manual_open = false;
                    self.suggestions_dismissed = false;
                    self.suggestions_selected_idx = 0;
                    if should_record_command(&submitted, &t.recent_output_tail) {
                        command_to_record =
                            Some((submitted.trim().to_string(), t.host_id.clone()));
                    }
                } else if bytes == b"\x7f" || bytes == b"\x08" {
                    t.typed_line.pop();
                    if t.typed_line.is_empty() {
                        self.suggestions_dismissed = false;
                    }
                } else if bytes == b"\x03" || bytes == b"\x15" || bytes == b"\x04" {
                    t.typed_line.clear();
                    self.suggestions_dismissed = false;
                } else if bytes.starts_with(b"\x1b") {
                    if bytes == b"\x1b[A" || bytes == b"\x1b[B" {
                        t.typed_line.clear();
                    }
                } else if let Ok(s) = std::str::from_utf8(&bytes) {
                    let printable: String = s.chars().filter(|c| !c.is_control()).collect();
                    if !printable.is_empty() {
                        t.typed_line.push_str(&printable);
                        self.suggestions_dismissed = false;
                    }
                }
                t.session_id.clone()
            });

        let Some(_session_id) = session_id else {
            return;
        };

        self.last_activity_at = Instant::now();
        self.write_bytes_to_target_panes(&tab_id, bytes);

        if let Some((cmd, hid)) = command_to_record {
            self.record_command_usage(&cmd, hid, cx);
        }
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Dual-Pane SFTP Operations (Ref-Counted + Rename + Chmod + Hidden + Drag-Drop)
    // -------------------------------------------------------------------------

    fn sftp_tab_label_for(state: &SftpWorkspaceState, fallback_ix: usize) -> String {
        match (&state.left_remote_host_label, &state.host_label) {
            (Some(l), Some(r)) => format!("{l} ↔ {r}"),
            (None, Some(r)) => r.clone(),
            (Some(l), None) => format!("{l} ↔ Local"),
            (None, None) => format!("SFTP {}", fallback_ix + 1),
        }
    }

    pub fn sync_active_sftp_tab_from_state(&mut self) {
        if let Some(ix) = self
            .sftp_tabs
            .iter()
            .position(|tab| tab.id == self.active_sftp_tab_id)
        {
            self.sftp_tabs[ix].state = self.sftp_state.clone();
            self.sftp_tabs[ix].label = Self::sftp_tab_label_for(&self.sftp_state, ix);
        }
    }

    pub fn new_sftp_tab(&mut self, cx: &mut Context<Self>) {
        self.sync_active_sftp_tab_from_state();
        let id = Uuid::now_v7().to_string();
        let idx = self.sftp_tabs.len() + 1;
        let fresh = SftpWorkspaceState::new(SftpManager::default_local_dir());
        let local = fresh.local_path.clone();
        let remote = fresh.remote_path.clone();
        self.sftp_tabs.push(SftpTabSnapshot {
            id: id.clone(),
            label: format!("SFTP {idx}"),
            state: fresh.clone(),
        });
        self.active_sftp_tab_id = id;
        self.sftp_state = fresh;
        self.sftp_local_path_input
            .update(cx, |f, cx| f.set_value(local.clone(), cx));
        self.sftp_remote_path_input
            .update(cx, |f, cx| f.set_value(remote, cx));
        self.refresh_local_dir(local);
        cx.notify();
    }

    pub fn select_sftp_tab(&mut self, tab_id: String, cx: &mut Context<Self>) {
        if self.active_sftp_tab_id == tab_id {
            return;
        }
        self.sync_active_sftp_tab_from_state();
        if let Some(tab) = self.sftp_tabs.iter().find(|t| t.id == tab_id) {
            self.active_sftp_tab_id = tab_id;
            self.sftp_state = tab.state.clone();
            let local = self.sftp_state.local_path.clone();
            let remote = self.sftp_state.remote_path.clone();
            self.sftp_local_path_input
                .update(cx, |f, cx| f.set_value(local, cx));
            self.sftp_remote_path_input
                .update(cx, |f, cx| f.set_value(remote, cx));
        }
        cx.notify();
    }

    pub fn close_sftp_tab(&mut self, tab_id: String, cx: &mut Context<Self>) {
        self.sync_active_sftp_tab_from_state();
        if self.sftp_tabs.len() <= 1 {
            let right_sid = self.sftp_state.session_id.take();
            let left_sid = self.sftp_state.left_remote_session_id.take();
            let fresh = SftpWorkspaceState::new(SftpManager::default_local_dir());
            let local = fresh.local_path.clone();
            let remote = fresh.remote_path.clone();
            self.sftp_state = fresh.clone();
            if let Some(first) = self.sftp_tabs.first_mut() {
                first.label = "SFTP 1".to_string();
                first.state = fresh;
            }
            self.sftp_local_path_input
                .update(cx, |f, cx| f.set_value(local.clone(), cx));
            self.sftp_remote_path_input
                .update(cx, |f, cx| f.set_value(remote, cx));
            if let Some(sid) = right_sid {
                self.release_sftp_session_if_unused(sid, None);
            }
            if let Some(sid) = left_sid {
                self.release_sftp_session_if_unused(sid, None);
            }
            self.refresh_local_dir(local);
            cx.notify();
            return;
        }
        if let Some(pos) = self.sftp_tabs.iter().position(|t| t.id == tab_id) {
            let removed = self.sftp_tabs.remove(pos);
            if self.active_sftp_tab_id == tab_id {
                let next_ix = pos.min(self.sftp_tabs.len() - 1);
                let next = &self.sftp_tabs[next_ix];
                self.active_sftp_tab_id = next.id.clone();
                self.sftp_state = next.state.clone();
                let local = self.sftp_state.local_path.clone();
                let remote = self.sftp_state.remote_path.clone();
                self.sftp_local_path_input
                    .update(cx, |f, cx| f.set_value(local, cx));
                self.sftp_remote_path_input
                    .update(cx, |f, cx| f.set_value(remote, cx));
            }
            if let Some(sid) = removed.state.session_id {
                self.release_sftp_session_if_unused(sid, None);
            }
            if let Some(sid) = removed.state.left_remote_session_id {
                self.release_sftp_session_if_unused(sid, None);
            }
        }
        cx.notify();
    }

    pub fn reorder_sftp_tabs(&mut self, dragged_id: &str, target_id: &str, cx: &mut Context<Self>) {
        self.sync_active_sftp_tab_from_state();
        if reorder_vec_by_id(&mut self.sftp_tabs, dragged_id, target_id, |t| &t.id) {
            cx.notify();
        }
    }

    fn resolve_host_id_for_sftp_session(
        &self,
        preferred_host_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Option<String> {
        if let Some(hid) = preferred_host_id
            && self.snapshot.hosts.iter().any(|h| h.id == hid)
        {
            return Some(hid.to_string());
        }
        if let Some(sid) = session_id
            && let Some(pane) = self
                .terminal_tabs
                .iter()
                .find(|p| !p.is_local && p.session_id.as_deref() == Some(sid))
        {
            if let Some(hid) = pane.host_id.as_ref() {
                return Some(hid.clone());
            }
            if let Some(found) = self.snapshot.hosts.iter().find(|h| {
                h.hostname == pane.hostname && h.port == pane.port && h.username == pane.username
            }) {
                return Some(found.id.clone());
            }
        }
        None
    }

    pub fn open_local_terminal_here(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.sftp_state.is_left_remote() {
            let dir = self.sftp_state.local_path.clone();
            let hid = self.resolve_host_id_for_sftp_session(
                self.sftp_state.left_remote_host_id.as_deref(),
                self.sftp_state.left_remote_session_id.as_deref(),
            );
            if let Some(host_id) = hid {
                let startup = build_remote_cd_command(&dir);
                self.connect_host_ssh_with_startup(host_id, startup, Some(window), cx);
                self.set_toast(format!("Opening SSH terminal at {dir}..."), false);
            } else {
                self.set_toast(
                    "Save this host to the Vault first to open a new SSH terminal at a directory.",
                    true,
                );
                cx.notify();
            }
            return;
        }
        let dir = self.sftp_state.local_path.clone();
        self.open_local_shell_in_dir(
            None,
            Some(PathBuf::from(&dir)),
            None,
            Some(window),
            cx,
        );
    }

    pub fn open_remote_terminal_here(
        &mut self,
        target_dir: String,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        let hid = self.resolve_host_id_for_sftp_session(
            self.sftp_state.host_id.as_deref(),
            self.sftp_state.session_id.as_deref(),
        );
        if let Some(host_id) = hid {
            let startup = build_remote_cd_command(&target_dir);
            self.connect_host_ssh_with_startup(host_id, startup, window, cx);
            self.set_toast(format!("Opening SSH terminal at {target_dir}..."), false);
        } else {
            self.set_toast(
                "Save this host to the Vault first to open a new SSH terminal at a directory.",
                true,
            );
            cx.notify();
        }
    }

    fn close_previous_sftp_if_standalone(&self) {
        if let Some(prev_sid) = self.sftp_state.session_id.clone() {
            self.release_sftp_session_if_unused(prev_sid, Some(&self.active_sftp_tab_id));
        }
    }

    pub fn open_sftp_for_host(&mut self, host_id: String, cx: &mut Context<Self>) {
        let built = {
            let vault = match self.services.vault.lock() {
                Ok(v) => v,
                Err(_) => return,
            };
            build_connect_request_for_host(&vault, &host_id, 80, 24, None)
        };
        let (host, req) = match built {
            Ok(v) => v,
            Err(e) => {
                self.set_toast(format!("SFTP connect failed: {e}"), true);
                cx.notify();
                return;
            }
        };

        self.close_previous_sftp_if_standalone();
        self.active_workspace_tab_id = None;
        self.page = AdminPage::Sftp;
        self.page_epoch = self.page_epoch.wrapping_add(1);
        self.sftp_state.connecting = true;
        self.sftp_state.host_id = Some(host.id.clone());
        let target_sftp_tab = Some(self.active_sftp_tab_id.clone());
        self.sync_active_sftp_tab_from_state();
        self.refresh_local_dir(self.sftp_state.local_path.clone());

        let services = Arc::clone(&self.services);
        let label = host.label.clone();
        self.services.rt.spawn(async move {
            let verifier = services.verifier();
            match services.ssh.connect_transport_only(req, verifier).await {
                Ok(session_id) => {
                    if let Ok(mut set) = services.sftp_only_sessions.lock() {
                        set.insert(session_id.clone());
                    }
                    match services.sftp.attach_to_ssh(&services.ssh, &session_id).await {
                        Ok(remote_cwd) => {
                            let local_cwd = SftpManager::default_local_dir();
                            let _ = services.ui_tx.send(UiEvent::SftpConnected {
                                session_id: session_id.clone(),
                                host_label: label,
                                remote_cwd: remote_cwd.clone(),
                                local_cwd,
                                sftp_tab_id: target_sftp_tab,
                            });
                            if let Ok((resolved, entries)) =
                                services.sftp.list_remote_dir(&session_id, &remote_cwd).await
                            {
                                let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                                    session_id,
                                    path: resolved,
                                    entries,
                                });
                            }
                        }
                        Err(e) => {
                            let _ = services
                                .ui_tx
                                .send(UiEvent::SftpError(format!("SFTP subsystem error: {e}")));
                        }
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("SSH transport error: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn attach_sftp_to_session(
        &mut self,
        session_id: String,
        host_label: String,
        cx: &mut Context<Self>,
    ) {
        self.sync_active_sftp_tab_from_state();
        if let Some(existing_id) = self
            .sftp_tabs
            .iter()
            .find(|t| t.state.session_id.as_deref() == Some(session_id.as_str()))
            .map(|t| t.id.clone())
        {
            self.select_sftp_tab(existing_id, cx);
            self.active_workspace_tab_id = None;
            self.page = AdminPage::Sftp;
            self.page_epoch = self.page_epoch.wrapping_add(1);
            let cur = self.sftp_state.remote_path.clone();
            self.refresh_remote_dir(cur);
            cx.notify();
            return;
        }
        if self.sftp_state.session_id.is_some()
            && self.sftp_state.session_id.as_deref() != Some(session_id.as_str())
        {
            self.new_sftp_tab(cx);
        }
        let pane_host_id = self
            .terminal_tabs
            .iter()
            .find(|p| p.session_id.as_deref() == Some(session_id.as_str()))
            .and_then(|p| p.host_id.clone());
        self.active_workspace_tab_id = None;
        self.page = AdminPage::Sftp;
        self.page_epoch = self.page_epoch.wrapping_add(1);
        self.sftp_state.connecting = true;
        self.sftp_state.host_id = pane_host_id;
        let target_sftp_tab = Some(self.active_sftp_tab_id.clone());
        self.sync_active_sftp_tab_from_state();
        self.refresh_local_dir(self.sftp_state.local_path.clone());

        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services.sftp.attach_to_ssh(&services.ssh, &session_id).await {
                Ok(remote_cwd) => {
                    let local_cwd = SftpManager::default_local_dir();
                    let _ = services.ui_tx.send(UiEvent::SftpConnected {
                        session_id: session_id.clone(),
                        host_label,
                        remote_cwd: remote_cwd.clone(),
                        local_cwd,
                        sftp_tab_id: target_sftp_tab,
                    });
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &remote_cwd).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Failed to open SFTP: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn refresh_local_dir(&mut self, path: String) {
        self.sftp_state.loading_local = true;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match SftpManager::list_local_dir(&path).await {
                Ok((resolved, entries)) => {
                    let _ = services.ui_tx.send(UiEvent::SftpLocalListed {
                        path: resolved,
                        entries,
                    });
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Local dir error: {e}")));
                }
            }
        });
    }

    pub fn refresh_remote_dir(&mut self, path: String) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        self.sftp_state.loading_remote = true;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services.sftp.list_remote_dir(&session_id, &path).await {
                Ok((resolved, entries)) => {
                    let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                        session_id,
                        path: resolved,
                        entries,
                    });
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Remote dir error: {e}")));
                }
            }
        });
    }

    pub fn navigate_local_up(&mut self) {
        if self.sftp_state.is_left_remote() {
            let parent = parent_remote_path(&self.sftp_state.local_path);
            self.refresh_left_pane(parent);
        } else {
            let parent = parent_local_path(&self.sftp_state.local_path);
            self.refresh_local_dir(parent);
        }
    }

    pub fn navigate_remote_up(&mut self) {
        let parent = parent_remote_path(&self.sftp_state.remote_path);
        self.refresh_remote_dir(parent);
    }

    pub fn navigate_local_to_input(&mut self, input: String, cx: &mut Context<Self>) {
        if self.sftp_state.is_left_remote() {
            let target = resolve_remote_input(&self.sftp_state.local_path, &input);
            self.refresh_left_pane(target);
        } else {
            let target = resolve_local_input(&self.sftp_state.local_path, &input);
            self.refresh_local_dir(target);
        }
        cx.notify();
    }

    pub fn navigate_remote_to_input(&mut self, input: String, cx: &mut Context<Self>) {
        if self.sftp_state.session_id.is_none() {
            self.set_toast("Connect an SFTP remote host first.", true);
            cx.notify();
            return;
        }
        let target = resolve_remote_input(&self.sftp_state.remote_path, &input);
        self.refresh_remote_dir(target);
        cx.notify();
    }

    pub fn upload_local_file(
        &mut self,
        local_path: String,
        file_name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            self.set_toast("Connect an SFTP remote host before uploading.", true);
            cx.notify();
            return;
        };
        let remote_dest = join_remote_path(&self.sftp_state.remote_path, &file_name);
        let remote_dir = self.sftp_state.remote_path.clone();
        let services = Arc::clone(&self.services);

        self.services.rt.spawn(async move {
            let tx = services.ui_tx.clone();
            let res = services
                .sftp
                .upload_file(
                    &session_id,
                    &PathBuf::from(&local_path),
                    &remote_dest,
                    move |p| {
                        let _ = tx.send(UiEvent::SftpTransfer(p));
                    },
                )
                .await;
            match res {
                Ok(_) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpNotice(format!("Uploaded {file_name} to Remote.")));
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &remote_dir).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Upload failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn download_remote_file(
        &mut self,
        remote_path: String,
        file_name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            self.set_toast("Connect an SFTP remote host first.", true);
            cx.notify();
            return;
        };
        let local_dir = self.sftp_state.local_path.clone();
        let local_dest = PathBuf::from(&local_dir).join(&file_name);
        let services = Arc::clone(&self.services);

        self.services.rt.spawn(async move {
            let tx = services.ui_tx.clone();
            let res = services
                .sftp
                .download_file(&session_id, &remote_path, &local_dest, move |p| {
                    let _ = tx.send(UiEvent::SftpTransfer(p));
                })
                .await;
            match res {
                Ok(_) => {
                    let _ = services.ui_tx.send(UiEvent::SftpNotice(format!(
                        "Downloaded {file_name} to Local."
                    )));
                    if let Ok((resolved, entries)) = SftpManager::list_local_dir(&local_dir).await {
                        let _ = services.ui_tx.send(UiEvent::SftpLocalListed {
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Download failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn upload_local_file_checked(
        &mut self,
        local_path: String,
        file_name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            self.set_toast("Connect an SFTP remote host before uploading.", true);
            cx.notify();
            return;
        };
        let remote_dest = join_remote_path(&self.sftp_state.remote_path, &file_name);
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let exists = services
                .sftp
                .remote_exists(&session_id, &remote_dest)
                .await
                .unwrap_or(false);
            let _ = services.ui_tx.send(UiEvent::SftpOverwriteCheck {
                direction: TransferDirection::Upload,
                local_path,
                remote_path: remote_dest,
                name: file_name,
                exists,
            });
        });
    }

    pub fn download_remote_file_checked(
        &mut self,
        remote_path: String,
        file_name: String,
        cx: &mut Context<Self>,
    ) {
        if self.sftp_state.session_id.is_none() {
            self.set_toast("Connect an SFTP remote host first.", true);
            cx.notify();
            return;
        }
        let local_dest = PathBuf::from(&self.sftp_state.local_path).join(&file_name);
        if local_dest.exists() {
            self.request_confirm(
                ConfirmAction::OverwriteDownload {
                    remote_path,
                    file_name,
                },
                cx,
            );
        } else {
            self.download_remote_file(remote_path, file_name, cx);
        }
    }

    pub fn upload_local_dir(
        &mut self,
        local_dir: String,
        dir_name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            self.set_toast("Connect an SFTP remote host before uploading.", true);
            cx.notify();
            return;
        };
        let remote_dest = join_remote_path(&self.sftp_state.remote_path, &dir_name);
        let remote_parent = self.sftp_state.remote_path.clone();
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let tx = services.ui_tx.clone();
            match services
                .sftp
                .upload_dir_recursive(&session_id, &PathBuf::from(&local_dir), &remote_dest, move |p| {
                    let _ = tx.send(UiEvent::SftpTransfer(p));
                })
                .await
            {
                Ok(count) => {
                    let _ = services.ui_tx.send(UiEvent::SftpNotice(format!(
                        "Uploaded folder '{dir_name}' ({count} file(s))."
                    )));
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &remote_parent).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Folder upload failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn download_remote_dir(
        &mut self,
        remote_dir: String,
        dir_name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            self.set_toast("Connect an SFTP remote host first.", true);
            cx.notify();
            return;
        };
        let local_parent = self.sftp_state.local_path.clone();
        let local_dest = PathBuf::from(&local_parent).join(&dir_name);
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let tx = services.ui_tx.clone();
            match services
                .sftp
                .download_dir_recursive(&session_id, &remote_dir, &local_dest, move |p| {
                    let _ = tx.send(UiEvent::SftpTransfer(p));
                })
                .await
            {
                Ok(count) => {
                    let _ = services.ui_tx.send(UiEvent::SftpNotice(format!(
                        "Downloaded folder '{dir_name}' ({count} file(s))."
                    )));
                    if let Ok((resolved, entries)) = SftpManager::list_local_dir(&local_parent).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpLocalListed {
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Folder download failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn batch_upload_selected(&mut self, cx: &mut Context<Self>) {
        let paths: Vec<_> = self
            .sftp_state
            .local_entries
            .iter()
            .filter(|e| self.sftp_state.selected_local_paths.contains(&e.path))
            .cloned()
            .collect();
        self.sftp_state.selected_local_paths.clear();
        for entry in paths {
            self.transfer_left_to_right(entry.path, entry.name, entry.is_dir, cx);
        }
        cx.notify();
    }

    pub fn batch_download_selected(&mut self, cx: &mut Context<Self>) {
        let paths: Vec<_> = self
            .sftp_state
            .remote_entries
            .iter()
            .filter(|e| self.sftp_state.selected_remote_paths.contains(&e.path))
            .cloned()
            .collect();
        self.sftp_state.selected_remote_paths.clear();
        for entry in paths {
            self.transfer_right_to_left(entry.path, entry.name, entry.is_dir, cx);
        }
        cx.notify();
    }

    pub fn handle_drop_on_remote(&mut self, dragged: &DraggedSftpFile, cx: &mut Context<Self>) {
        if dragged.side != SftpPaneSide::Local {
            return;
        }
        self.transfer_left_to_right(
            dragged.full_path.clone(),
            dragged.name.clone(),
            dragged.is_dir,
            cx,
        );
    }

    pub fn handle_drop_on_local(&mut self, dragged: &DraggedSftpFile, cx: &mut Context<Self>) {
        if dragged.side != SftpPaneSide::Remote {
            return;
        }
        self.transfer_right_to_left(
            dragged.full_path.clone(),
            dragged.name.clone(),
            dragged.is_dir,
            cx,
        );
    }

    pub fn handle_external_drop_on_remote(&mut self, paths: &ExternalPaths, cx: &mut Context<Self>) {
        for p in paths.paths() {
            if let Some(name) = p.file_name().map(|n| n.to_string_lossy().to_string()) {
                if p.is_dir() {
                    self.upload_local_dir(p.to_string_lossy().to_string(), name, cx);
                } else if p.is_file() {
                    self.upload_local_file_checked(p.to_string_lossy().to_string(), name, cx);
                }
            }
        }
    }

    pub fn create_remote_dir(&mut self, cx: &mut Context<Self>) {
        let name = self.sftp_mkdir_input.read(cx).value().trim().to_string();
        if name.is_empty() {
            return;
        }
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        let target = join_remote_path(&self.sftp_state.remote_path, &name);
        let dir_now = self.sftp_state.remote_path.clone();
        self.sftp_mkdir_input.update(cx, |f, cx| f.clear(cx));

        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services.sftp.remote_mkdir(&session_id, &target).await {
                Ok(()) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpNotice(format!("Created folder '{name}'.")));
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &dir_now).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("mkdir failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn open_remote_chmod_modal(
        &mut self,
        remote_path: String,
        current_mode: u32,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        let octal = format!("{:03o}", current_mode & 0o777);
        self.chmod_input
            .update(cx, |f, cx| f.set_value(octal, cx));
        self.open_modal(
            ActiveModal::RemoteChmod {
                session_id,
                remote_path,
            },
            cx,
        );
    }

    pub fn submit_remote_chmod(
        &mut self,
        session_id: String,
        remote_path: String,
        cx: &mut Context<Self>,
    ) {
        let raw = self.chmod_input.read(cx).value().trim().to_string();
        let Ok(mode) = u32::from_str_radix(&raw, 8) else {
            self.set_toast("Enter a valid octal mode (e.g. 644, 755, 600).", true);
            cx.notify();
            return;
        };
        if mode > 0o7777 {
            self.set_toast("Octal mode must be between 000 and 7777.", true);
            cx.notify();
            return;
        }
        self.modal = None;
        let dir_now = self.sftp_state.remote_path.clone();
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services
                .sftp
                .remote_chmod(&session_id, &remote_path, mode)
                .await
            {
                Ok(()) => {
                    let _ = services.ui_tx.send(UiEvent::SftpNotice(format!(
                        "Updated permissions to {:03o}.",
                        mode & 0o777
                    )));
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &dir_now).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("chmod failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn open_remote_rename_modal(
        &mut self,
        old_path: String,
        old_name: String,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        self.rename_input
            .update(cx, |f, cx| f.set_value(old_name.clone(), cx));
        self.open_modal(
            ActiveModal::RemoteRename {
                session_id,
                old_path,
                old_name,
            },
            cx,
        );
    }

    pub fn submit_remote_rename(
        &mut self,
        session_id: String,
        old_path: String,
        cx: &mut Context<Self>,
    ) {
        let new_name = self.rename_input.read(cx).value().trim().to_string();
        if new_name.is_empty() || new_name.contains('/') {
            self.set_toast("Enter a valid file or folder name (without '/').", true);
            cx.notify();
            return;
        }
        let dir_now = self.sftp_state.remote_path.clone();
        let new_path = join_remote_path(&parent_remote_path(&old_path), &new_name);
        self.modal = None;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services
                .sftp
                .remote_rename(&session_id, &old_path, &new_path)
                .await
            {
                Ok(()) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpNotice(format!("Renamed to '{new_name}'.")));
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &dir_now).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Rename failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    pub fn delete_remote_entry(&mut self, remote_path: String, is_dir: bool, name: String) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        let dir_now = self.sftp_state.remote_path.clone();
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services
                .sftp
                .remote_delete(&session_id, &remote_path, is_dir)
                .await
            {
                Ok(()) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpNotice(format!("Deleted '{name}'.")));
                    if let Ok((resolved, entries)) =
                        services.sftp.list_remote_dir(&session_id, &dir_now).await
                    {
                        let _ = services.ui_tx.send(UiEvent::SftpRemoteListed {
                            session_id,
                            path: resolved,
                            entries,
                        });
                    }
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Delete failed: {e}")));
                }
            }
        });
    }

    pub fn open_remote_text_editor(&mut self, remote_path: String) {
        let Some(session_id) = self.sftp_state.session_id.clone() else {
            return;
        };
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services.sftp.read_remote_text(&session_id, &remote_path).await {
                Ok(content) => {
                    let _ = services.ui_tx.send(UiEvent::SftpRemoteTextLoaded {
                        session_id,
                        remote_path,
                        content,
                    });
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Open file failed: {e}")));
                }
            }
        });
    }

    pub fn save_remote_text_editor(
        &mut self,
        session_id: String,
        remote_path: String,
        cx: &mut Context<Self>,
    ) {
        let content = self.remote_editor_input.read(cx).value().to_string();
        self.modal = None;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match services
                .sftp
                .write_remote_text(&session_id, &remote_path, &content)
                .await
            {
                Ok(()) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpNotice(format!("Saved {remote_path}.")));
                }
                Err(e) => {
                    let _ = services
                        .ui_tx
                        .send(UiEvent::SftpError(format!("Save failed: {e}")));
                }
            }
        });
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Keygen & Sync Actions
    // -------------------------------------------------------------------------

    pub fn generate_ed25519_key(&mut self, cx: &mut Context<Self>) {
        let count = self.snapshot.credentials.len() + 1;
        let label = format!("sterm-ed25519-{count}");
        let res = generate_ed25519_keypair(&format!("{label}@sterm"), None)
            .map_err(|e| e.to_string())
            .and_then(|kp| {
                let vault = self.services.vault.lock().map_err(|_| "vault lock")?;
                vault
                    .upsert_credential(core_vault::models::CredentialRecord {
                        id: String::new(),
                        label: label.clone(),
                        kind: CredentialKind::PrivateKey,
                        username: None,
                        password: None,
                        private_key_pem: Some(kp.private_key_openssh.clone()),
                        passphrase: None,
                        certificate_openssh: None,
                        public_key_openssh: Some(kp.public_key_openssh.clone()),
                        fingerprint_sha256: Some(kp.fingerprint_sha256.clone()),
                        updated_at: 0,
                    })
                    .map_err(|e| e.to_string())?;
                Ok(kp.public_key_openssh)
            });

        match res {
            Ok(pubkey) => {
                cx.write_to_clipboard(ClipboardItem::new_string(pubkey));
                self.reload_vault_snapshot();
                self.set_toast(
                    format!("Generated Ed25519 key '{label}' (public key copied to clipboard)."),
                    false,
                );
                self.maybe_auto_sync(cx);
            }
            Err(e) => self.set_toast(format!("Key generation failed: {e}"), true),
        }
        cx.notify();
    }

    pub fn trigger_sync_auth(&mut self, is_register: bool, cx: &mut Context<Self>) {
        let server_url = self.sync_url.read(cx).value().trim().to_string();
        let email = self.sync_email.read(cx).value().trim().to_string();
        let pw = self.sync_password.read(cx).value().to_string();

        if server_url.is_empty() || email.is_empty() || pw.is_empty() {
            self.set_toast("Server URL, Email, and Password are required.", true);
            cx.notify();
            return;
        }

        self.sync_busy = true;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            let res = if is_register {
                run_sync_register(Arc::clone(&services), server_url, email, pw, true).await
            } else {
                run_sync_login(Arc::clone(&services), server_url, email, pw, true).await
            };
            match res {
                Ok(status) => {
                    let _ = services.ui_tx.send(UiEvent::SyncCompleted {
                        status,
                        report: None,
                        message: if is_register {
                            "Account created & connected to E2EE Sync.".into()
                        } else {
                            "Signed in to E2EE Sync.".into()
                        },
                    });
                }
                Err(e) => {
                    let _ = services.ui_tx.send(UiEvent::SyncFailed(e));
                }
            }
        });
        cx.notify();
    }

    pub fn trigger_sync_now(&mut self, cx: &mut Context<Self>) {
        self.sync_busy = true;
        let services = Arc::clone(&self.services);
        self.services.rt.spawn(async move {
            match run_sync_now(Arc::clone(&services)).await {
                Ok((status, report)) => {
                    let msg = if report.conflicts.is_empty() {
                        format!(
                            "E2EE Sync complete: pulled {}, pushed {} item(s).",
                            report.pulled, report.pushed
                        )
                    } else {
                        format!(
                            "Synced (pulled {}, pushed {}), {} conflict(s) resolved by latest timestamp.",
                            report.pulled,
                            report.pushed,
                            report.conflicts.len()
                        )
                    };
                    let _ = services.ui_tx.send(UiEvent::SyncCompleted {
                        status,
                        report: Some(report),
                        message: msg,
                    });
                }
                Err(e) => {
                    let _ = services.ui_tx.send(UiEvent::SyncFailed(e));
                }
            }
        });
        cx.notify();
    }

    pub fn trigger_sync_logout(&mut self, cx: &mut Context<Self>) {
        let _ = core_crypto::keychain::clear_sync_secret();
        let _ = core_crypto::keychain::clear_vault_key_from_os_keychain();
        if let Ok(mut v) = self.services.vault.lock() {
            v.lock();
        }
        if let Ok(mut g) = self.services.sync_session.lock() {
            *g = None;
        }
        self.sync_status = PublicSyncStatus::default();
        self.auth_mode = AuthScreenMode::Login;
        self.reload_vault_snapshot();
        self.set_toast("Signed out.", false);
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // FIFO Challenge Queue Pump (HostKey + Multi-Prompt KBI)
    // -------------------------------------------------------------------------

    pub fn pump_challenge_queue(&mut self, cx: &mut Context<Self>) {
        if matches!(
            self.modal,
            Some(ActiveModal::HostKey(_)) | Some(ActiveModal::KeyboardInteractive(_))
        ) {
            return;
        }
        if let Some(ch) = self.pending_host_keys.pop_front() {
            self.open_modal(ActiveModal::HostKey(ch), cx);
            return;
        }
        if let Some(ch) = self.pending_kbi.pop_front() {
            let mode = self.settings.theme_mode;
            let accent = self.settings.accent;
            let prompt_count = ch.prompts.len().max(1);
            self.kbi_inputs = (0..prompt_count)
                .map(|idx| {
                    let echo = ch.prompts.get(idx).map(|p| p.echo).unwrap_or(false);
                    let ph = ch
                        .prompts
                        .get(idx)
                        .map(|p| p.prompt.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| format!("Response {}", idx + 1));
                    let field = cx.new(|cx| TextField::new(ph, cx).with_masked(!echo));
                    field.update(cx, |tf, _| tf.set_appearance(mode, accent));
                    field
                })
                .collect();
            self.open_modal(ActiveModal::KeyboardInteractive(ch), cx);
        }
    }

    pub fn resolve_host_key_modal(&mut self, challenge_id: String, accepted: bool, cx: &mut Context<Self>) {
        self.services.ssh.resolve_challenge(&challenge_id, accepted);
        self.modal = None;
        if accepted {
            self.reload_vault_snapshot();
            self.maybe_auto_sync(cx);
        }
        self.pump_challenge_queue(cx);
        cx.notify();
    }

    pub fn resolve_kbi_modal(&mut self, challenge_id: String, submit: bool, cx: &mut Context<Self>) {
        let answers = if submit {
            Some(
                self.kbi_inputs
                    .iter()
                    .map(|f| f.read(cx).value().to_string())
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        self.services.ssh.resolve_kbi_challenge(&challenge_id, answers);
        self.kbi_inputs.clear();
        self.modal = None;
        self.pump_challenge_queue(cx);
        cx.notify();
    }

    // -------------------------------------------------------------------------
    // Backend Event Dispatcher
    // -------------------------------------------------------------------------

    fn handle_ui_event(&mut self, ev: UiEvent, cx: &mut Context<Self>) {
        match ev {
            UiEvent::SshConnected {
                tab_id,
                session_id,
                label,
                ..
            } => {
                let mut sync_info = None;
                let mut connected_host_id = None;
                if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) {
                    tab.session_id = Some(session_id.clone());
                    tab.connected = true;
                    tab.is_auth_error = false;
                    tab.reconnect_attempts = 0;
                    tab.last_error = None;
                    tab.status_line = "Live · SSH-2.0".to_string();
                    connected_host_id = tab.host_id.clone();
                    let cols = tab.cols;
                    let rows = tab.rows;
                    if let Ok(mut last) = tab.last_pty_size.lock() {
                        *last = (cols, rows);
                    }
                    tab.pty_resize_seq
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if cols != DEFAULT_TERM_COLS || rows != DEFAULT_TERM_ROWS {
                        sync_info = Some((cols, rows));
                    }
                }
                if let Some((cols, rows)) = sync_info {
                    let services = Arc::clone(&self.services);
                    self.services.rt.spawn(async move {
                        let _ = services.ssh.resize(&session_id, cols as u32, rows as u32).await;
                    });
                }
                if let Some(hid) = connected_host_id {
                    if let Ok(v) = self.services.vault.lock() {
                        let _ = v.mark_host_connected(&hid);
                    }
                    self.reload_vault_snapshot();
                    let auto_tunnels: Vec<PortForwardRecord> = self
                        .snapshot
                        .port_forwards
                        .iter()
                        .filter(|pf| {
                            pf.host_id == hid
                                && pf.auto_start
                                && !self.active_tunnels.contains_key(&pf.id)
                        })
                        .cloned()
                        .collect();
                    for pf in auto_tunnels {
                        self.start_port_forward(pf, cx);
                    }
                }
                self.set_toast(format!("Connected to {label}."), false);
            }
            UiEvent::SshConnectFailed {
                tab_id,
                error,
                is_auth_error,
            } => {
                if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) {
                    tab.connected = false;
                    tab.is_auth_error = is_auth_error;
                    tab.last_error = Some(error.clone());
                    tab.status_line = "Connection failed".to_string();
                    tab.append_system_line(&format!("Connection failed: {error}"));
                }
                self.set_toast(format!("SSH error: {error}"), true);
            }
            UiEvent::TerminalOutput { tab_id, event } => {
                let mut schedule_reconnect: Option<(String, u32)> = None;
                let mut follow_candidate: Option<(String, String)> = None;
                if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id) {
                    match event {
                        TerminalEvent::Output { data } => {
                            tab.feed_bytes(&data);
                            if self.sftp_drawer_open
                                && self.sftp_drawer_follow_cwd
                                && !tab.is_local
                                && let Some(sid) = tab.session_id.as_ref()
                                && let Some(cwd) = tab.current_cwd()
                            {
                                follow_candidate = Some((sid.clone(), cwd.to_string()));
                            }
                        }
                        TerminalEvent::Closed { reason } => {
                            tab.connected = false;
                            tab.status_line = format!("Closed: {reason}");
                            tab.append_system_line(&format!("Session closed ({reason})."));
                            if self.settings.auto_reconnect
                                && !tab.is_local
                                && !tab.manually_closed
                                && !tab.is_auth_error
                                && tab.host_id.is_some()
                                && tab.reconnect_attempts < 5
                                && !reason.to_lowercase().contains("closed by user")
                            {
                                tab.reconnect_attempts += 1;
                                let attempt = tab.reconnect_attempts;
                                let delay_secs = (1u64 << attempt).min(30);
                                tab.status_line =
                                    format!("Reconnecting in {delay_secs}s ({attempt}/5)...");
                                schedule_reconnect = Some((tab_id.clone(), attempt));
                            }
                        }
                        TerminalEvent::Error { message } => {
                            tab.connected = false;
                            tab.last_error = Some(message.clone());
                            tab.status_line = "Error".to_string();
                            tab.append_system_line(&format!("Error: {message}"));
                        }
                    }
                }
                if let Some((sid, cwd)) = follow_candidate
                    && self.active_pane_id().as_deref() == Some(tab_id.as_str())
                    && self.sftp_state.session_id.as_deref() == Some(sid.as_str())
                    && self.last_drawer_followed_cwd.as_deref() != Some(cwd.as_str())
                    && self.sftp_state.remote_path != cwd
                {
                    self.last_drawer_followed_cwd = Some(cwd.clone());
                    self.refresh_remote_dir(cwd);
                }
                if let Some((pid, attempt)) = schedule_reconnect {
                    let delay_secs = (1u64 << attempt).min(30);
                    let tx = self.services.ui_tx.clone();
                    self.services.rt.spawn(async move {
                        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                        let _ = tx.send(UiEvent::AutoReconnectTrigger {
                            pane_id: pid,
                            attempt,
                        });
                    });
                }
            }
            UiEvent::TerminalResize { tab_id, cols, rows } => {
                if let Some(tab) = self.terminal_tabs.iter_mut().find(|t| t.tab_id == tab_id)
                    && tab.resize(cols, rows)
                    && let Some(sid) = tab.session_id.clone()
                {
                    let target_cols = tab.cols;
                    let target_rows = tab.rows;
                    if tab.is_local {
                        let _ = self
                            .services
                            .local_shells
                            .resize(&sid, target_cols, target_rows);
                    } else {
                        let seq = tab
                            .pty_resize_seq
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            + 1;
                        let seq_ref = Arc::clone(&tab.pty_resize_seq);
                        let last_pty_ref = Arc::clone(&tab.last_pty_size);
                        let services = Arc::clone(&self.services);
                        self.services.rt.spawn(async move {
                            tokio::time::sleep(Duration::from_millis(180)).await;
                            if seq_ref.load(std::sync::atomic::Ordering::SeqCst) != seq {
                                return;
                            }
                            let should_send = match last_pty_ref.lock() {
                                Ok(mut last) => {
                                    if *last != (target_cols, target_rows) {
                                        *last = (target_cols, target_rows);
                                        true
                                    } else {
                                        false
                                    }
                                }
                                Err(_) => true,
                            };
                            if should_send {
                                let _ = services
                                    .ssh
                                    .resize(&sid, target_cols as u32, target_rows as u32)
                                    .await;
                            }
                        });
                    }
                }
            }
            UiEvent::HostKeyPrompt(ch) => {
                self.pending_host_keys.push_back(ch);
                self.pump_challenge_queue(cx);
            }
            UiEvent::KbiPrompt(ch) => {
                self.pending_kbi.push_back(ch);
                self.pump_challenge_queue(cx);
            }
            UiEvent::SftpConnected {
                session_id,
                host_label,
                remote_cwd,
                local_cwd,
                sftp_tab_id,
            } => {
                let is_active_target = sftp_tab_id
                    .as_deref()
                    .is_none_or(|id| id == self.active_sftp_tab_id.as_str());
                if is_active_target {
                    self.sftp_state.connecting = false;
                    self.sftp_state.session_id = Some(session_id);
                    self.sftp_state.host_label = Some(host_label.clone());
                    self.sftp_state.remote_path = remote_cwd.clone();
                    self.sftp_remote_path_input
                        .update(cx, |f, cx| f.set_value(remote_cwd, cx));
                    self.sftp_state.selected_remote = None;
                    self.sftp_state.reset_remote_scroll();
                    self.sftp_state.local_path = local_cwd.clone();
                    self.sftp_local_path_input
                        .update(cx, |f, cx| f.set_value(local_cwd.clone(), cx));
                    self.sync_active_sftp_tab_from_state();
                    self.refresh_local_dir(local_cwd);
                } else if let Some(tid) = sftp_tab_id
                    && let Some(ix) = self.sftp_tabs.iter().position(|t| t.id == tid)
                {
                    let tab = &mut self.sftp_tabs[ix];
                    tab.state.connecting = false;
                    tab.state.session_id = Some(session_id);
                    tab.state.host_label = Some(host_label.clone());
                    tab.state.remote_path = remote_cwd;
                    tab.state.selected_remote = None;
                    tab.state.local_path = local_cwd;
                    tab.label = Self::sftp_tab_label_for(&tab.state, ix);
                }
                self.set_toast(format!("SFTP connected to {host_label}."), false);
            }
            UiEvent::SftpLocalListed { path, entries } => {
                self.sftp_state.loading_local = false;
                if self.sftp_state.local_path != path {
                    self.sftp_state.selected_local = None;
                    self.sftp_state.reset_local_scroll();
                }
                self.sftp_state.local_path = path.clone();
                self.sftp_local_path_input
                    .update(cx, |f, cx| f.set_value(path, cx));
                self.sftp_state.local_entries = entries;
                self.sync_active_sftp_tab_from_state();
            }
            UiEvent::SftpRemoteListed {
                session_id,
                path,
                entries,
            } => {
                self.sftp_state.loading_remote = false;
                if self.sftp_state.session_id.as_deref() == Some(&session_id) {
                    if self.sftp_state.remote_path != path {
                        self.sftp_state.selected_remote = None;
                        self.sftp_state.reset_remote_scroll();
                    }
                    self.sftp_state.remote_path = path.clone();
                    self.sftp_remote_path_input
                        .update(cx, |f, cx| f.set_value(path.clone(), cx));
                    self.sftp_state.remote_entries = entries.clone();
                    self.sync_active_sftp_tab_from_state();
                }
                for tab in &mut self.sftp_tabs {
                    if tab.id != self.active_sftp_tab_id
                        && tab.state.session_id.as_deref() == Some(&session_id)
                    {
                        tab.state.loading_remote = false;
                        tab.state.remote_path = path.clone();
                        tab.state.remote_entries = entries.clone();
                    }
                }
            }
            UiEvent::SftpTransfer(progress) => {
                self.sftp_state.upsert_transfer(progress);
                self.sync_active_sftp_tab_from_state();
            }
            UiEvent::SftpRemoteTextLoaded {
                session_id,
                remote_path,
                content,
            } => {
                self.remote_editor_input
                    .update(cx, |f, cx| f.set_value(content, cx));
                self.open_modal(
                    ActiveModal::RemoteEditor {
                        session_id,
                        remote_path,
                    },
                    cx,
                );
            }
            UiEvent::SftpError(err) => {
                self.sftp_state.connecting = false;
                self.sftp_state.loading_local = false;
                self.sftp_state.loading_remote = false;
                self.set_toast(err, true);
            }
            UiEvent::SftpNotice(msg) => {
                self.set_toast(msg, false);
            }
            UiEvent::SyncCompleted {
                status,
                report,
                message,
            } => {
                self.unlock_busy = false;
                self.sync_busy = false;
                self.sync_status = status;
                self.unlock_password.update(cx, |f, cx| f.clear(cx));
                self.unlock_confirm.update(cx, |f, cx| f.clear(cx));
                self.sync_password.update(cx, |f, cx| f.clear(cx));
                self.reload_vault_snapshot();
                self.page_epoch = self.page_epoch.wrapping_add(1);
                let has_conflicts = report
                    .as_ref()
                    .is_some_and(|r| !r.conflicts.is_empty());
                self.set_toast(message, has_conflicts);
                if report.is_none() {
                    if let Ok(v) = self.services.vault.lock()
                        && let Ok(st) = v.status()
                    {
                        self.vault_status = st;
                    }
                    self.spawn_detect_local_ssh();
                    self.maybe_auto_sync(cx);
                    self.restore_saved_sessions_if_enabled(cx);
                }
            }
            UiEvent::SyncFailed(err) => {
                self.sync_busy = false;
                self.set_toast(format!("Sync failed: {err}"), true);
            }
            UiEvent::VaultUnlocked { status, message } => {
                self.unlock_busy = false;
                self.vault_status = status;
                self.unlock_password.update(cx, |f, cx| f.clear(cx));
                self.unlock_confirm.update(cx, |f, cx| f.clear(cx));
                self.reload_vault_snapshot();
                self.page_epoch = self.page_epoch.wrapping_add(1);
                self.set_toast(message, false);
                self.spawn_detect_local_ssh();
                self.maybe_auto_sync(cx);
                self.restore_saved_sessions_if_enabled(cx);
            }
            UiEvent::VaultActionFailed(err) => {
                self.unlock_busy = false;
                self.set_toast(err, true);
            }
            UiEvent::SettingsActionDone {
                message,
                is_error,
                sync_status,
            } => {
                self.settings_busy = false;
                if let Some(st) = sync_status {
                    self.sync_status = st;
                }
                if !is_error {
                    self.pw_current.update(cx, |f, cx| f.clear(cx));
                    self.pw_new.update(cx, |f, cx| f.clear(cx));
                    self.pw_confirm.update(cx, |f, cx| f.clear(cx));
                }
                self.set_toast(message, is_error);
            }
            UiEvent::SyncAccountDeleted => {
                self.settings_busy = false;
                self.sync_status = PublicSyncStatus::default();
                self.delete_account_pw.update(cx, |f, cx| f.clear(cx));
                self.workspace_tabs.clear();
                self.active_workspace_tab_id = None;
                self.terminal_tabs.clear();
                self.reload_vault_snapshot();
                self.auth_mode = AuthScreenMode::Offline;
                self.set_toast("Server account and local vault cache deleted.", false);
            }
            UiEvent::LocalSshDiscovered(info) => {
                self.ssh_auto_import_enabled = info.auto_import_enabled;
                let has_new = info.new_hosts_count > 0 || info.new_keys_count > 0;
                if !has_new {
                    self.ssh_discovery = None;
                } else if info.auto_import_enabled {
                    self.confirm_local_ssh_discovery(true, true, cx);
                } else if !info.prompt_dismissed {
                    self.ssh_discovery = Some(info);
                }
            }
            UiEvent::TunnelStarted {
                tunnel_id,
                bound_port,
                label,
                ..
            } => {
                for st in self.services.ssh.list_tunnels() {
                    self.active_tunnels.insert(st.tunnel_id.clone(), st);
                }
                self.set_toast(
                    format!("Tunnel '{label}' active on port {bound_port}."),
                    false,
                );
                let _ = tunnel_id;
            }
            UiEvent::TunnelStopped { tunnel_id, label } => {
                self.active_tunnels.remove(&tunnel_id);
                self.set_toast(format!("Stopped tunnel '{label}'."), false);
            }
            UiEvent::TunnelError { tunnel_id, message } => {
                self.active_tunnels.remove(&tunnel_id);
                self.set_toast(message, true);
            }
            UiEvent::TunnelStatsSnapshot(list) => {
                self.active_tunnels.clear();
                for st in list {
                    self.active_tunnels.insert(st.tunnel_id.clone(), st);
                }
            }
            UiEvent::KeyDeployed { result, .. } => match result {
                Ok(msg) => self.set_toast(msg, false),
                Err(e) => self.set_toast(e, true),
            },
            UiEvent::SftpOverwriteCheck {
                direction,
                local_path,
                remote_path,
                name,
                exists,
            } => match direction {
                TransferDirection::Upload => {
                    if exists {
                        self.request_confirm(
                            ConfirmAction::OverwriteUpload {
                                local_path,
                                file_name: name,
                            },
                            cx,
                        );
                    } else {
                        self.upload_local_file(local_path, name, cx);
                    }
                }
                TransferDirection::Download => {
                    if exists {
                        self.request_confirm(
                            ConfirmAction::OverwriteDownload {
                                remote_path,
                                file_name: name,
                            },
                            cx,
                        );
                    } else {
                        self.download_remote_file(remote_path, name, cx);
                    }
                }
            },
            UiEvent::AutoReconnectTrigger { pane_id, attempt } => {
                let should_retry = self.settings.auto_reconnect
                    && self.terminal_tabs.iter().any(|p| {
                        p.tab_id == pane_id
                            && !p.connected
                            && !p.manually_closed
                            && !p.is_auth_error
                            && p.reconnect_attempts == attempt
                    });
                if should_retry {
                    self.reconnect_terminal_pane(pane_id, None, cx);
                }
            }
            UiEvent::IdleLockTick => {
                let mins = self.settings.auto_lock_minutes;
                if mins > 0
                    && self.vault_status.unlocked
                    && self.last_activity_at.elapsed() >= Duration::from_secs(u64::from(mins) * 60)
                {
                    self.lock_vault(cx);
                    self.set_toast(format!("Vault auto-locked after {mins}m of inactivity."), false);
                }
            }
            UiEvent::SystemSleepDetected { slept_secs } => {
                if self.settings.lock_on_sleep && self.vault_status.unlocked {
                    self.lock_vault(cx);
                    self.set_toast(
                        format!("Vault locked after system sleep ({slept_secs}s)."),
                        false,
                    );
                }
            }
            UiEvent::HostLatencies(results) => {
                self.latency_probing = false;
                for (id, rtt) in results {
                    self.host_latencies.insert(id, rtt);
                }
            }
            UiEvent::AgentIdentitiesLoaded(res) => match res {
                Ok(list) => {
                    self.agent_identities = list;
                    self.agent_error = None;
                }
                Err(e) => {
                    self.agent_identities.clear();
                    self.agent_error = Some(e);
                }
            },
            UiEvent::SftpLeftRemoteConnected {
                session_id,
                host_id,
                host_label,
                remote_cwd,
            } => {
                self.sftp_state.loading_local = false;
                self.sftp_state.left_remote_session_id = Some(session_id);
                self.sftp_state.left_remote_host_id = Some(host_id);
                self.sftp_state.left_remote_host_label = Some(host_label.clone());
                self.sftp_state.local_path = remote_cwd.clone();
                self.sftp_local_path_input
                    .update(cx, |f, cx| f.set_value(remote_cwd, cx));
                self.sftp_state.selected_local = None;
                self.sftp_state.selected_local_paths.clear();
                self.sftp_state.reset_local_scroll();
                self.sync_active_sftp_tab_from_state();
                self.set_toast(
                    format!("Mounted remote host '{host_label}' on Left SFTP pane."),
                    false,
                );
            }
            UiEvent::SftpLeftRemoteListed {
                session_id,
                path,
                entries,
            } => {
                self.sftp_state.loading_local = false;
                if self.sftp_state.left_remote_session_id.as_deref() == Some(&session_id) {
                    if self.sftp_state.local_path != path {
                        self.sftp_state.selected_local = None;
                        self.sftp_state.reset_local_scroll();
                    }
                    self.sftp_state.local_path = path.clone();
                    self.sftp_local_path_input
                        .update(cx, |f, cx| f.set_value(path.clone(), cx));
                    self.sftp_state.local_entries = entries.clone();
                    self.sync_active_sftp_tab_from_state();
                }
                for tab in &mut self.sftp_tabs {
                    if tab.id != self.active_sftp_tab_id
                        && tab.state.left_remote_session_id.as_deref() == Some(&session_id)
                    {
                        tab.state.loading_local = false;
                        tab.state.local_path = path.clone();
                        tab.state.local_entries = entries.clone();
                    }
                }
            }
            UiEvent::BiometricUnlockResult(res) => match res {
                Ok(true) => {
                    self.unlock_with_os_keychain(cx);
                }
                Ok(false) => {
                    self.unlock_busy = false;
                    self.set_toast("Biometric verification was cancelled or did not match.", true);
                }
                Err(e) => {
                    self.unlock_busy = false;
                    self.set_toast(format!("Biometric unlock unavailable: {e}"), true);
                }
            },
        }
    }
}

trait PaneMetaExt {
    fn cloned_meta(&self) -> Option<(String, String, u16, String)>;
}

impl PaneMetaExt for Option<&TerminalTab> {
    fn cloned_meta(&self) -> Option<(String, String, u16, String)> {
        self.map(|p| (p.label.clone(), p.hostname.clone(), p.port, p.username.clone()))
    }
}

fn empty_snapshot() -> VaultSnapshot {
    VaultSnapshot {
        hosts: Vec::new(),
        groups: Vec::new(),
        credentials: Vec::new(),
        known_hosts: Vec::new(),
        commands: Vec::new(),
        port_forwards: Vec::new(),
    }
}

impl Render for StermAdminApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = ThemePalette::from_settings(&self.settings);

        if !self.vault_status.unlocked {
            return self.render_unlock_screen(&t, cx).into_any_element();
        }

        // Unified 5-Section Vault Rail with crisp vector SVG icons
        let nav_items: [(AdminPage, Icon, &str, Option<usize>); 5] = [
            (
                AdminPage::Hosts,
                Icon::Server,
                "Hosts",
                Some(self.snapshot.hosts.len()),
            ),
            (AdminPage::Sftp, Icon::FolderSync, "SFTP", None),
            (
                AdminPage::Snippets,
                Icon::Zap,
                "Snippets",
                Some(self.snapshot.commands.iter().filter(|c| c.pinned).count()),
            ),
            (
                AdminPage::Tunnels,
                Icon::Network,
                "Tunnels",
                Some(self.active_tunnels.len()),
            ),
            (
                AdminPage::Keychain,
                Icon::KeyRound,
                "Keychain",
                Some(self.snapshot.credentials.len()),
            ),
        ];

        let collapsed = self.sidebar_collapsed;
        let sidebar_epoch = self.sidebar_epoch;
        let is_loading = self.is_any_loading();
        let xfer_running = self.sftp_state.running_count() > 0;
        let has_transfers = !self.sftp_state.transfers.is_empty();
        let in_vault = self.active_workspace_tab_id.is_none();

        let sidebar_inner = div()
            .h_full()
            .flex_shrink_0()
            .bg(t.bg_sidebar)
            .border_r_1()
            .border_color(t.border)
            .p_2p5()
            .flex()
            .flex_col()
            .justify_between()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    // Brand + Collapse Toggle
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .pb_2p5()
                            .mb_1()
                            .border_b_1()
                            .border_color(t.border)
                            .when(!collapsed, |this| {
                                this.child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .child(
                                            div()
                                                .w(px(24.0))
                                                .h(px(24.0))
                                                .rounded_md()
                                                .bg(t.accent_solid)
                                                .text_color(gpui::white())
                                                .text_xs()
                                                .font_weight(gpui::FontWeight::BOLD)
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .child("S"),
                                        )
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                                .text_color(t.text_primary)
                                                .whitespace_nowrap()
                                                .child("STerm SSH"),
                                        ),
                                )
                            })
                            .child(
                                div()
                                    .id("collapse-sidebar")
                                    .w(px(26.0))
                                    .h(px(26.0))
                                    .rounded_md()
                                    .bg(t.bg_subtle)
                                    .text_color(t.text_muted)
                                    .text_xs()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover).text_color(t.text_primary))
                                    .tooltip(StermTooltip::text(
                                        if collapsed {
                                            "Expand Sidebar"
                                        } else {
                                            "Collapse Sidebar"
                                        },
                                        t,
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_sidebar(cx);
                                    }))
                                    .child(icon_svg(Icon::Sidebar, 14.0, t.text_muted)),
                            ),
                    )
                    // Quick Connect / Command Palette button (Ctrl/Cmd+K)
                    .child(
                        div()
                            .id("sidebar-cmd-palette")
                            .mb_1p5()
                            .w_full()
                            .h(px(32.0))
                            .px_2p5()
                            .rounded_lg()
                            .bg(t.bg_canvas)
                            .border_1()
                            .border_color(t.border_strong)
                            .flex()
                            .items_center()
                            .justify_between()
                            .cursor_pointer()
                            .hover(|s| s.border_color(t.accent).text_color(t.text_primary))
                            .when(collapsed, |el| {
                                el.tooltip(StermTooltip::with_shortcut(
                                    "Quick Connect & Omnibar",
                                    self.settings.keybindings.display(ShortcutAction::CommandPalette),
                                    t,
                                ))
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_command_palette(cx);
                            }))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child(icon_svg(Icon::Search, 13.0, t.text_muted))
                                    .when(!collapsed, |el| el.child("Quick Connect")),
                            )
                            .when(!collapsed, |el| {
                                el.child(
                                    div()
                                        .text_size(px(10.0))
                                        .font_family("Consolas")
                                        .text_color(t.text_muted)
                                        .child(
                                            self.settings
                                                .keybindings
                                                .display(ShortcutAction::CommandPalette),
                                        ),
                                )
                            }),
                    )
                    // 5 Primary Vault Nav Items
                    .children(nav_items.into_iter().map(|(target, icon, label, badge)| {
                        let active = in_vault && self.page == target;
                        let icon_color = if active { t.accent } else { t.text_muted };
                        div()
                            .id(("nav", target as usize))
                            .relative()
                            .w_full()
                            .h(px(34.0))
                            .px_2p5()
                            .rounded_lg()
                            .flex()
                            .items_center()
                            .justify_between()
                            .cursor_pointer()
                            .bg(if active {
                                t.accent_soft
                            } else {
                                gpui::transparent_black()
                            })
                            .text_color(icon_color)
                            .hover(|s| {
                                if active {
                                    s
                                } else {
                                    s.bg(t.bg_subtle).text_color(t.text_primary)
                                }
                            })
                            .when(collapsed, |el| el.tooltip(StermTooltip::text(label, t)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.navigate_to(target, cx);
                            }))
                            .when(active, |el| {
                                el.child(
                                    div()
                                        .absolute()
                                        .left_0()
                                        .top(px(7.0))
                                        .bottom(px(7.0))
                                        .w(px(3.0))
                                        .rounded_full()
                                        .bg(t.accent),
                                )
                            })
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2p5()
                                    .child(icon_svg(icon, 15.0, icon_color))
                                    .when(!collapsed, |el| {
                                        el.child(
                                            div()
                                                .text_xs()
                                                .font_weight(gpui::FontWeight::MEDIUM)
                                                .whitespace_nowrap()
                                                .child(label),
                                        )
                                    }),
                            )
                            .when(!collapsed && badge.is_some(), |el| {
                                let count = badge.unwrap_or(0);
                                el.child(
                                    div()
                                        .px_1p5()
                                        .py(px(1.0))
                                        .rounded_full()
                                        .bg(if active { t.bg_card } else { t.bg_subtle })
                                        .text_size(px(10.0))
                                        .font_family("Consolas")
                                        .child(count.to_string()),
                                )
                            })
                    })),
            )
            // Minimal Utility Footer: Settings (single canonical entry!) + Sync status + Lock Vault
            .child(
                div()
                    .pt_2p5()
                    .border_t_1()
                    .border_color(t.border)
                    .flex()
                    .flex_col()
                    .gap_1()
                    // Sync status indicator (navigates to Settings -> Account & Sync)
                    .child(
                        div()
                            .id("sidebar-sync-pill")
                            .px_2p5()
                            .py_1p5()
                            .rounded_lg()
                            .bg(t.bg_subtle)
                            .flex()
                            .items_center()
                            .justify_between()
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_hover))
                            .when(collapsed, |el| {
                                el.tooltip(StermTooltip::text(
                                    if self.sync_status.signed_in {
                                        "E2EE Sync (Connected)"
                                    } else {
                                        "Local Vault (Offline)"
                                    },
                                    t,
                                ))
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.settings_tab = SettingsTab::Account;
                                this.navigate_to(AdminPage::Settings, cx);
                            }))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(if self.sync_busy && self.settings.animations_enabled {
                                        pulsing_dot("sync-dot-pulse", 8.0, t.accent)
                                            .into_any_element()
                                    } else {
                                        div()
                                            .w(px(8.0))
                                            .h(px(8.0))
                                            .rounded_full()
                                            .bg(if self.sync_status.signed_in {
                                                t.success
                                            } else {
                                                t.text_muted
                                            })
                                            .into_any_element()
                                    })
                                    .when(!collapsed, |el| {
                                        el.child(
                                            div()
                                                .text_xs()
                                                .font_weight(gpui::FontWeight::MEDIUM)
                                                .text_color(t.text_primary)
                                                .whitespace_nowrap()
                                                .child(if self.sync_status.signed_in {
                                                    "E2EE Sync"
                                                } else {
                                                    "Local Vault"
                                                }),
                                        )
                                    }),
                            )
                            .when(!collapsed, |el| {
                                el.child(
                                    div()
                                        .text_size(px(10.0))
                                        .font_family("Consolas")
                                        .text_color(if self.sync_status.signed_in {
                                            t.success
                                        } else {
                                            t.text_muted
                                        })
                                        .child(if self.sync_status.signed_in { "ON" } else { "OFF" }),
                                )
                            }),
                    )
                    // Settings (single canonical entry point!)
                    .child({
                        let active = in_vault && self.page == AdminPage::Settings;
                        div()
                            .id("nav-settings")
                            .w_full()
                            .h(px(32.0))
                            .px_2p5()
                            .rounded_lg()
                            .flex()
                            .items_center()
                            .gap_2p5()
                            .cursor_pointer()
                            .bg(if active {
                                t.accent_soft
                            } else {
                                gpui::transparent_black()
                            })
                            .text_color(if active { t.accent } else { t.text_muted })
                            .hover(|s| {
                                if active {
                                    s
                                } else {
                                    s.bg(t.bg_subtle).text_color(t.text_primary)
                                }
                            })
                            .when(collapsed, |el| el.tooltip(StermTooltip::text("Settings", t)))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.navigate_to(AdminPage::Settings, cx);
                            }))
                            .child(icon_svg(
                                Icon::Settings,
                                14.0,
                                if active { t.accent } else { t.text_muted },
                            ))
                            .when(!collapsed, |el| {
                                el.child(
                                    div()
                                        .text_xs()
                                        .font_weight(gpui::FontWeight::MEDIUM)
                                        .child("Settings"),
                                )
                            })
                    })
                    // Lock Vault (safe — Sign Out lives safely inside Settings -> Account & Sync!)
                    .child(
                        div()
                            .id("lock-vault-btn")
                            .w_full()
                            .h(px(32.0))
                            .px_2p5()
                            .rounded_lg()
                            .flex()
                            .items_center()
                            .gap_2p5()
                            .text_color(t.text_muted)
                            .cursor_pointer()
                            .hover(|s| s.bg(t.danger_soft).text_color(t.danger))
                            .when(collapsed, |el| {
                                el.tooltip(StermTooltip::with_shortcut(
                                    "Lock Vault",
                                    self.settings.keybindings.display(ShortcutAction::LockVault),
                                    t,
                                ))
                            })
                            .on_click(cx.listener(|this, _, _, cx| this.lock_vault(cx)))
                            .child(icon_svg(Icon::Lock, 14.0, t.text_muted))
                            .when(!collapsed, |el| {
                                el.child(
                                    div()
                                        .text_xs()
                                        .font_weight(gpui::FontWeight::MEDIUM)
                                        .child("Lock Vault"),
                                )
                            }),
                    ),
            );

        let sidebar = if sidebar_epoch == 0 {
            sidebar_inner
                .w(if collapsed { px(58.0) } else { px(208.0) })
                .into_any_element()
        } else {
            let (from_w, to_w) = if collapsed { (208.0, 58.0) } else { (58.0, 208.0) };
            sidebar_inner
                .with_animation(
                    ("sidebar-slide", sidebar_epoch),
                    Animation::new(Duration::from_millis(200)).with_easing(ease_out_quint()),
                    move |el, delta| el.w(px(from_w + (to_w - from_w) * delta)),
                )
                .into_any_element()
        };

        // Persistent Top Session Tab Strip (Vault Home + Active Terminal Split Tabs + Active Transfer Pill + Quick Connect)
        let top_tab_bar = div()
            .h(px(44.0))
            .w_full()
            .flex_shrink_0()
            .bg(t.bg_sidebar)
            .border_b_1()
            .border_color(t.border)
            .px_2p5()
            .flex()
            .items_center()
            .justify_between()
            .gap_2()
            // Left: [Vault] + Live Terminal Workspace Tabs + [+]
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .min_w_0()
                    .flex_1()
                    .overflow_hidden()
                    .child(
                        div()
                            .id("top-tab-vault")
                            .px_3()
                            .py_1()
                            .rounded_lg()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .text_xs()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .cursor_pointer()
                            .bg(if in_vault {
                                t.accent_soft
                            } else {
                                gpui::transparent_black()
                            })
                            .text_color(if in_vault {
                                t.accent
                            } else {
                                t.text_secondary
                            })
                            .hover(|s| {
                                if in_vault {
                                    s
                                } else {
                                    s.bg(t.bg_subtle).text_color(t.text_primary)
                                }
                            })
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.select_workspace_tab(None, window, cx);
                            }))
                            .child("▤")
                            .child("Vault"),
                    )
                    .children(self.workspace_tabs.iter().enumerate().map(|(ix, ws)| {
                        let is_selected =
                            self.active_workspace_tab_id.as_deref() == Some(ws.id.as_str());
                        let pane_ids = collect_pane_ids(&ws.root);
                        let pane_count = pane_ids.len();
                        let any_connected = pane_ids.iter().any(|pid| {
                            self.terminal_tabs
                                .iter()
                                .any(|p| &p.tab_id == pid && p.connected)
                        });
                        let any_connecting = pane_ids.iter().any(|pid| {
                            self.terminal_tabs.iter().any(|p| {
                                &p.tab_id == pid
                                    && !p.connected
                                    && p.status_line == "Connecting..."
                            })
                        });
                        let wid_sel = ws.id.clone();
                        let wid_drag = ws.id.clone();
                        let wid_drop = ws.id.clone();
                        let wid_close = ws.id.clone();
                        let title_drag = ws.title.clone();
                        let theme_mode_drag = self.settings.theme_mode;
                        let accent_drop = t.accent;
                        let close_sc = self.settings.keybindings.display(ShortcutAction::CloseTab);

                        div()
                            .id(("ws-tab", ix))
                            .max_w(px(210.0))
                            .px_2p5()
                            .py_1()
                            .rounded_lg()
                            .border_1()
                            .border_color(if is_selected {
                                t.border_strong
                            } else {
                                gpui::transparent_black()
                            })
                            .bg(if is_selected {
                                t.bg_card
                            } else {
                                gpui::transparent_black()
                            })
                            .text_color(if is_selected {
                                t.text_primary
                            } else {
                                t.text_secondary
                            })
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .text_xs()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .cursor_pointer()
                            .hover(|s| {
                                if is_selected {
                                    s
                                } else {
                                    s.bg(t.bg_subtle).text_color(t.text_primary)
                                }
                            })
                            .on_drag(
                                DraggedWorkspaceTab {
                                    tab_id: wid_drag,
                                    label: title_drag,
                                },
                                move |dragged, pos, _, cx| {
                                    cx.new(|_| {
                                        DragTabPill::new(
                                            dragged.label.clone(),
                                            pos,
                                            theme_mode_drag,
                                        )
                                    })
                                },
                            )
                            .drag_over::<DraggedWorkspaceTab>(move |s, _, _, _| {
                                s.border_color(accent_drop)
                            })
                            .on_drop(cx.listener(
                                move |this, dragged: &DraggedWorkspaceTab, _, cx| {
                                    this.reorder_workspace_tabs(&dragged.tab_id, &wid_drop, cx);
                                },
                            ))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.select_workspace_tab(Some(wid_sel.clone()), window, cx);
                            }))
                            .child(div().w(px(6.0)).h(px(6.0)).rounded_full().bg(
                                if any_connected {
                                    t.success
                                } else if any_connecting {
                                    t.warning
                                } else {
                                    t.danger
                                },
                            ))
                            .child(div().truncate().child(ws.title.clone()))
                            .when(pane_count > 1, |el| {
                                el.child(
                                    div()
                                        .px_1()
                                        .rounded_sm()
                                        .bg(t.bg_subtle)
                                        .text_size(px(9.0))
                                        .font_family("Consolas")
                                        .text_color(t.text_muted)
                                        .child(format!("{pane_count}p")),
                                )
                            })
                            .child(
                                div()
                                    .id(("ws-tab-close", ix))
                                    .ml_0p5()
                                    .px_1()
                                    .rounded_sm()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .hover(|s| s.bg(t.danger_soft).text_color(t.danger))
                                    .tooltip(StermTooltip::with_shortcut(
                                        "Close Tab",
                                        close_sc,
                                        t,
                                    ))
                                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                        cx.stop_propagation();
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        cx.stop_propagation();
                                        this.close_workspace_tab(wid_close.clone(), cx);
                                    }))
                                    .child("✕"),
                            )
                    }))
                    .child(
                        div()
                            .id("top-tab-new-qc")
                            .px_2()
                            .py_1()
                            .rounded_lg()
                            .text_xs()
                            .text_color(t.text_muted)
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_subtle).text_color(t.text_primary))
                            .tooltip(StermTooltip::text("Quick SSH Connect", t))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_quick_connect_modal(cx);
                            }))
                            .child("+"),
                    ),
            )
            // Right: Active-only Dynamic Transfer Island + Quick Connect CTA
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .flex_shrink_0()
                    .when(is_loading, |el| el.child(loading_dots("hdr-load", t.accent)))
                    .when(has_transfers, |el| {
                        let (island_dot, island_text) =
                            if let Some(tr) = self.sftp_state.active_transfer() {
                                let pct = transfer_percent(tr);
                                let arrow = direction_arrow(&tr.direction);
                                match tr.status {
                                    TransferStatus::Running => {
                                        (t.accent, format!("{arrow} {} · {pct}%", tr.file_name))
                                    }
                                    TransferStatus::Completed => {
                                        (t.success, format!("✓ {} · Done", tr.file_name))
                                    }
                                    TransferStatus::Failed => {
                                        (t.danger, format!("✕ {} · Failed", tr.file_name))
                                    }
                                    TransferStatus::Cancelled => {
                                        (t.warning, format!("⊘ {} · Cancelled", tr.file_name))
                                    }
                                }
                            } else {
                                (t.success, "⇄ Transfers".to_string())
                            };
                        el.child(
                            div()
                                .id("dynamic-transfer-island")
                                .px_3()
                                .py_1()
                                .rounded_full()
                                .bg(t.island_bg)
                                .border_1()
                                .border_color(if xfer_running {
                                    t.accent
                                } else {
                                    t.island_border
                                })
                                .text_color(t.island_fg)
                                .text_xs()
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .hover(|s| s.border_color(t.accent))
                                .flex()
                                .items_center()
                                .gap_1p5()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.toggle_island(cx);
                                }))
                                .child(div().w(px(6.0)).h(px(6.0)).rounded_full().bg(island_dot))
                                .child(island_text)
                                .child(if self.island_open { "▴" } else { "▾" }),
                        )
                    })
                    .child(
                        div()
                            .id("top-tab-local-shell")
                            .px_2p5()
                            .py_1()
                            .rounded_lg()
                            .border_1()
                            .border_color(t.border)
                            .flex()
                            .items_center()
                            .gap_1()
                            .text_xs()
                            .text_color(t.text_secondary)
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_subtle).text_color(t.text_primary))
                            .tooltip(StermTooltip::with_shortcut(
                                "Open Local Shell",
                                self.settings
                                    .keybindings
                                    .display(ShortcutAction::OpenLocalShell),
                                t,
                            ))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_local_shell(None, None, Some(window), cx);
                            }))
                            .child(icon_svg(Icon::Terminal, 13.0, t.text_secondary))
                            .child("Local"),
                    )
                    .child(
                        div()
                            .id("header-quick-connect")
                            .px_2p5()
                            .py_1()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .hover(|s| s.opacity(0.92))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_quick_connect_modal(cx);
                            }))
                            .child("+ Connect"),
                    ),
            );

        let page_body = if let Some(ws_id) = self.active_workspace_tab_id.clone() {
            self.render_workspace_terminal_tab(&ws_id, &t, window, cx)
                .into_any_element()
        } else {
            match self.page {
                AdminPage::Hosts => self.render_servers_page(&t, cx).into_any_element(),
                AdminPage::Sftp => self.render_sftp_page(&t, cx).into_any_element(),
                AdminPage::Snippets => self.render_snippets_page(&t, cx).into_any_element(),
                AdminPage::Tunnels => self.render_tunnels_page(&t, cx).into_any_element(),
                AdminPage::Keychain => self.render_keychain_page(&t, cx).into_any_element(),
                AdminPage::Settings => self.render_settings_page(&t, cx).into_any_element(),
            }
        };

        let animated_page = if self.settings.animations_enabled && in_vault {
            animate_page_enter(self.page_epoch, page_body).into_any_element()
        } else {
            div().size_full().child(page_body).into_any_element()
        };

        let mut root = div()
            .size_full()
            .relative()
            .track_focus(&self.app_focus)
            .on_key_down(cx.listener(Self::handle_global_key_down))
            .flex()
            .bg(t.bg_canvas)
            .text_color(t.text_primary)
            .child(sidebar)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .child(top_tab_bar)
                    .when(is_loading, |el| {
                        el.child(indeterminate_bar("global-top-loader", t.bg_subtle, t.accent))
                    })
                    .when_some(self.toast.clone(), |el, (msg, is_err)| {
                        let toast_epoch = self.toast_epoch;
                        el.child(
                            div()
                                .mx_4()
                                .mt_2()
                                .px_3()
                                .py_1p5()
                                .rounded_lg()
                                .border_1()
                                .bg(if is_err { t.danger_soft } else { t.success_soft })
                                .border_color(if is_err { t.danger } else { t.success })
                                .text_xs()
                                .text_color(if is_err { t.danger } else { t.success })
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(msg)
                                .child(
                                    div()
                                        .id("dismiss-toast")
                                        .px_1p5()
                                        .cursor_pointer()
                                        .tooltip(StermTooltip::text("Dismiss Notification", t))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.toast = None;
                                            cx.notify();
                                        }))
                                        .child("✕"),
                                )
                                .with_animation(
                                    ("toast-slide", toast_epoch),
                                    Animation::new(Duration::from_millis(180))
                                        .with_easing(ease_out_quint()),
                                    |el, delta| el.opacity(delta),
                                ),
                        )
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .min_w_0()
                            .p(if in_vault { px(16.0) } else { px(6.0) })
                            .child(animated_page),
                    ),
            );

        if self.island_open {
            root = root.child(self.render_transfer_island_popover(&t, cx));
        }

        if let Some(modal) = self.modal.clone() {
            root = root.child(self.render_modal(&t, modal, cx));
        }

        root.into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use core_vault::models::{HostAuthMode, HostRecord};

    use super::{
        saved_node_from_split, split_node_from_saved, RestorePaneKind, SavedPaneNode,
        SavedWorkspaceSession, SavedWorkspaceTab, StermAdminApp,
    };
    use crate::split_tree::{create_leaf, SplitDirection, SplitNode};
    use crate::terminal::TerminalTab;

    #[test]
    fn parse_quick_target_handles_default_and_custom_ports() {
        assert_eq!(
            StermAdminApp::parse_quick_target("deploy@prod.example.com"),
            Some(("deploy".into(), "prod.example.com".into(), 22))
        );
        assert_eq!(
            StermAdminApp::parse_quick_target("  root@10.0.0.5:2222  "),
            Some(("root".into(), "10.0.0.5".into(), 2222))
        );
        assert_eq!(StermAdminApp::parse_quick_target("root@host:0"), None);
        assert_eq!(StermAdminApp::parse_quick_target("not-an-ssh-target"), None);
        assert_eq!(StermAdminApp::parse_quick_target("@host"), None);
    }

    #[test]
    fn saved_workspace_session_roundtrip_and_split_conversion() {
        let mut local = TerminalTab::local_shell(
            "p-local".into(),
            "PowerShell".into(),
            "sid-local".into(),
            "pwsh.exe".into(),
        );
        local.feed_bytes(b"\x1b]7;file://host/C:/Users/dev\x07");
        let ssh_saved = TerminalTab::connecting(
            "p-ssh".into(),
            Some("host-1".into()),
            "Prod".into(),
            "10.0.0.1".into(),
            22,
            "root".into(),
        );
        let ssh_saved_2 = TerminalTab::connecting(
            "p-ssh-2".into(),
            Some("host-2".into()),
            "Staging".into(),
            "10.0.0.4".into(),
            22,
            "deploy".into(),
        );
        let ssh_deleted = TerminalTab::connecting(
            "p-deleted".into(),
            Some("host-missing".into()),
            "Gone".into(),
            "10.0.0.2".into(),
            22,
            "root".into(),
        );
        let ssh_adhoc = TerminalTab::connecting(
            "p-adhoc".into(),
            None,
            "Adhoc".into(),
            "10.0.0.3".into(),
            22,
            "root".into(),
        );

        let root = SplitNode::Split {
            id: "s1".into(),
            direction: SplitDirection::Vertical,
            ratio: 0.65,
            first: Box::new(create_leaf("p-local")),
            second: Box::new(SplitNode::Split {
                id: "s2".into(),
                direction: SplitDirection::Horizontal,
                ratio: 0.4,
                first: Box::new(create_leaf("p-ssh")),
                second: Box::new(SplitNode::Split {
                    id: "s3".into(),
                    direction: SplitDirection::Horizontal,
                    ratio: 0.5,
                    first: Box::new(create_leaf("p-deleted")),
                    second: Box::new(SplitNode::Split {
                        id: "s4".into(),
                        direction: SplitDirection::Horizontal,
                        ratio: 0.5,
                        first: Box::new(create_leaf("p-ssh-2")),
                        second: Box::new(create_leaf("p-adhoc")),
                    }),
                }),
            }),
        };

        let saved_node = saved_node_from_split(
            &root,
            &[local, ssh_saved, ssh_saved_2, ssh_deleted, ssh_adhoc],
        )
        .unwrap();
        let session = SavedWorkspaceSession {
            tabs: vec![SavedWorkspaceTab {
                title: "Work".into(),
                root: saved_node,
                broadcast_input: true,
            }],
            active_tab_index: Some(0),
        };
        let raw = serde_json::to_string(&session).unwrap();
        let decoded: SavedWorkspaceSession = serde_json::from_str(&raw).unwrap();
        assert_eq!(decoded.active_tab_index, Some(0));
        assert!(decoded.tabs[0].broadcast_input);

        let hosts = vec![
            HostRecord {
                id: "host-1".into(),
                label: "Prod".into(),
                hostname: "10.0.0.1".into(),
                port: 22,
                username: "root".into(),
                group_id: None,
                tags: Vec::new(),
                credential_id: None,
                jump_host_id: None,
                terminal_theme: None,
                keepalive_secs: 30,
                startup_command: None,
                notes: None,
                auth_mode: HostAuthMode::Credential,
                forward_agent: false,
                proxy_url: None,
                favorite: false,
                last_connected_at: None,
                updated_at: 0,
            },
            HostRecord {
                id: "host-2".into(),
                label: "Staging".into(),
                hostname: "10.0.0.4".into(),
                port: 22,
                username: "deploy".into(),
                group_id: None,
                tags: Vec::new(),
                credential_id: None,
                jump_host_id: None,
                terminal_theme: None,
                keepalive_secs: 30,
                startup_command: None,
                notes: None,
                auth_mode: HostAuthMode::Credential,
                forward_agent: false,
                proxy_url: None,
                favorite: false,
                last_connected_at: None,
                updated_at: 0,
            },
        ];
        let mut out_panes = Vec::new();
        let rebuilt = split_node_from_saved(&decoded.tabs[0].root, &hosts, &mut out_panes).unwrap();
        assert_eq!(out_panes.len(), 3);
        assert!(matches!(
            &out_panes[0].1,
            RestorePaneKind::Local { program: Some(p), cwd: Some(c), .. }
            if p == "pwsh.exe" && c.contains("Users/dev")
        ));
        assert!(matches!(
            &out_panes[1].1,
            RestorePaneKind::Ssh { host_id } if host_id == "host-1"
        ));
        assert!(matches!(
            &out_panes[2].1,
            RestorePaneKind::Ssh { host_id } if host_id == "host-2"
        ));
        match rebuilt {
            SplitNode::Split {
                direction: SplitDirection::Vertical,
                ratio,
                second,
                ..
            } => {
                assert!((ratio - 0.65).abs() < f32::EPSILON);
                match *second {
                    SplitNode::Split {
                        direction: SplitDirection::Horizontal,
                        ratio: r2,
                        ..
                    } => assert!((r2 - 0.4).abs() < f32::EPSILON),
                    other => panic!("expected inner horizontal split, got {other:?}"),
                }
            }
            other => panic!("expected outer vertical split, got {other:?}"),
        }

        // Deleted host alone returns None cleanly
        let deleted_only = SavedPaneNode::Leaf {
            host_id: Some("host-missing".into()),
            is_local: false,
            local_shell_program: None,
            local_shell_label: None,
            local_cwd: None,
        };
        let mut none_panes = Vec::new();
        assert!(split_node_from_saved(&deleted_only, &hosts, &mut none_panes).is_none());
    }
}
