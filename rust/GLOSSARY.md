# Domain Glossary — STerm SSH TS → Rust GPUI Port

| Domain Term (TS / Original) | Meaning | Rust Type / Module / Function |
|---|---|---|
| `SplitDirection` (`"horizontal" \| "vertical"`) | Axis of a terminal split container | `SplitDirection::{Horizontal, Vertical}` in `split_tree` |
| `SplitNode` (`leaf \| split`) | Recursive binary layout tree of terminal panes | `SplitNode::{Leaf { pane_id }, Split { id, direction, ratio, first, second }}` |
| `createLeaf` / `splitPane` / `closePane` / `updateSplitRatio` / `collectPaneIds` | Pure layout tree transforms (ratio clamped `0.15..=0.85`) | `create_leaf`, `split_pane`, `close_pane`, `update_split_ratio`, `collect_pane_ids` |
| `CommandRecord` | Persisted snippet or learned shell command in encrypted vault | `core_vault::models::CommandRecord` |
| `SuggestedCommand` | Ranked autocomplete suggestion (`saved \| history \| starter`) | `SuggestedCommand` / `SuggestionSource` in `command_suggestions` |
| `shouldRecordCommand` | Privacy/noise filter rejecting leading-space, trivial, or password-prompt inputs | `should_record_command(raw_line, recent_output_tail) -> bool` |
| `rankCommandSuggestions` | Frecency + prefix + pinned + host-affinity ranker with starter tips | `rank_command_suggestions(stored, raw_query, current_host_id, limit)` |
| `computeInsertPayload` | Minimal VT byte sequence: missing suffix or `\x15` + full command (+ `\r` if execute) | `compute_insert_payload(current_typed_line, selected_command, execute)` |
| `TerminalThemePreset` / `TERMINAL_THEMES` | Curated terminal color palettes (6 presets incl. Antigravity CLI Dark & Light) | `TerminalThemeId` / `TerminalPaletteSpec` in `crates/sterm-gpui/src/theme.rs` |
| `TerminalFontPreset` / `TERMINAL_FONT_PRESETS` | Monospace font presets | `TERMINAL_FONT_PRESETS` in `crates/sterm-gpui/src/theme.rs` |
| `TerminalCursorStyle` (`bar \| block \| underline`) | Terminal cursor rendering shape | `TerminalCursorStyle::{Bar, Block, Underline}` |
| `HostKeyChallenge` | Pending TOFU unknown/mismatch verification prompt | `core_ssh::types::HostKeyChallenge` (queued in `VecDeque`) |
| `KeyboardInteractiveChallenge` | Pending PAM / 2FA / multi-prompt challenge | `core_ssh::types::KeyboardInteractiveChallenge` (queued in `VecDeque`) |
| `LocalSshDiscovery` | Read-only scan of `~/.ssh` for unimported hosts & keys | `core_vault::ssh_config::LocalSshDiscovery` |
| `ParsedSshHost` | Parsed entry from `~/.ssh/config` (with `Include` expansion) | `core_vault::ssh_config::ParsedSshHost` |
| `HostRecord` | Saved SSH server profile (label, host, port, user, group, tags, credential, jump host, theme, keepalive, startup command, notes) | `core_vault::models::HostRecord` |
| `CredentialRecord` / `CredentialSummary` | Encrypted credential (`Password`, `PrivateKey`, `Certificate`, `SshAgent`, `KeyboardInteractive`) | `core_vault::models::{CredentialRecord, CredentialSummary}` |
| `VaultSection` (Top-level Vault nav) | Unified sidebar sections: `Hosts`, `Sftp`, `Snippets`, `Keychain`, `Settings` | `AdminPage` in `crates/sterm-gpui/src/app.rs` |
| `WorkspaceTab` (Top tab strip) | Persistent session tabs above content (`Vault` home + active Terminal split tabs) | `WorkspaceTerminalTab` + `active_workspace_tab_id: Option<String>` |
