# Migration Map — STerm SSH Full Pure-Rust GPUI Migration

## Goal
Migrate STerm SSH completely off Tauri + React (`src/`, `src-tauri/`, Node/npm) into the standalone pure-Rust native GPUI desktop application (`crates/sterm-gpui`), achieving 100% feature parity, fixing all Phase 1 audit safety/data-loss issues, adopting the unified Phase 2 Information Architecture, updating CI/CD to release native GPUI builds, and retiring all Tauri/React/Node artifacts.

## ADR Index
See [DECISIONS.md](DECISIONS.md):
- **ADR-001**: Converge on `crates/sterm-gpui` as sole desktop binary
- **ADR-002**: Combined Tauri parity + Phase 1 safety fixes + Phase 2 IA cleanup
- **ADR-003**: Replace web/Tauri dependencies with GPUI native APIs (`prompt_for_paths`, `vt100`, `core-*`)
- **ADR-004**: Behavioral equivalence bar (`rust-anything gate`) & SQLite/sync compatibility
- **ADR-005**: Windows x64 & macOS arm64/x64 native GPUI CI/CD release pipeline
- **ADR-006**: Wave checkpoints & safe cutover retirement of Tauri

## Units & Wave Plan

### Wave 0 — Pure TypeScript Logic Units (`rust-anything` Bridged, Recorded & Gated)
| Unit | Original Files | Target Rust Crate / Module | State | Gate / Notes |
|---|---|---|---|---|
| `src/styles/` | `src/styles/terminal-themes.ts` | `rust/styles-rs` → `crates/sterm-gpui/src/theme.rs` | **done** (2026-11-22) | `gate` PASS (12/12 checks, **422/422** recorded cases match, 0 warnings); themes/cursor/line-height integrated in `sterm-gpui` |
| `src/lib/` (pure logic) | `src/lib/split-tree.ts`, `src/lib/command-suggestions.ts` (`tauri-api.ts` superseded by `backend.rs`) | `rust/lib-rs` → `crates/sterm-gpui/src/{split_tree.rs,command_suggestions.rs}` | **done** (2026-11-22) | `gate` PASS (12/12 checks, **1,918/1,918** recorded cases incl. all Vitest calls, 0 warnings); typed modules integrated in `sterm-gpui` |

### Wave 1 — GPUI Backend, State Parity & Phase 1 Safety Fixes
| Unit | Scope | Target | State | Notes |
|---|---|---|---|---|
| `gpui-state-safety` | Preserve host metadata on edit, safe offline→account migration, group default username/credential inheritance, FIFO host-key & KBI challenge queues, multi-prompt KBI, MITM expected fingerprint, SFTP session ref-counting, `sftp_remote_rename`, `sftp_remote_chmod`, `sync_delete_account`, `detect_local_ssh_dir` / `sync_local_ssh_dir`, command recording/upsert, sync conflict toast, auth-error classification | `crates/sterm-gpui/src/{backend.rs,app.rs,sftp.rs}` | **done** (2026-11-22) | Verified by unit tests + clippy (`-D warnings`) |

### Wave 2 — GPUI UI Parity & Unified Information Architecture
| Unit | Scope | Target | State | Notes |
|---|---|---|---|---|
| `gpui-ia-chrome` | Persistent Top Session Tab Strip (`Vault` + Terminal tabs), retire redundant `Overview` & `E2EE Sync` sidebar pages, unified 4-item Vault rail (`Hosts`, `SFTP`, `Snippets`, `Keychain`) + bottom `E2EE Sync` pill / `Settings` / `Lock`, `Ctrl/Cmd+K` Command Palette + global shortcuts, active-only Transfer Island with `Clear Finished` | `crates/sterm-gpui/src/{app.rs,views.rs,modals.rs}` | **done** (2026-11-22) | Verified cleanly |
| `gpui-terminal-parity` | Arbitrary nested horizontal/vertical `SplitNode` panes (with ratio nudge controls & `SplitHostPicker`), in-terminal Search (`Ctrl/Cmd+F`), smart-positioned `Ctrl+Space` Command Suggestions popover + command tracking, line-height & `Bar`/`Block`/`Underline` cursor rendering, auth-only inline password retry banner, Save Quick-Connect to Vault | `crates/sterm-gpui/src/{terminal.rs,views.rs,app.rs,modals.rs}` | **done** (2026-11-22) | 31/31 `sterm-gpui` unit tests pass |
| `gpui-vault-sftp-settings` | Full `HostEditor` (ProxyJump picker, Tags, Per-Host Theme, Keepalive, Startup Command, Notes, native key/cert file pickers), `GroupEditor` with default username/credential, full `CredentialEditor` (all 5 kinds + Edit + Copy PubKey + usage count), `~/.ssh` Discovery Banner + Selective Import Preview Modal, `Snippets` page, SFTP (interactive `chmod` matrix, rename, dotfiles toggle, searchable host picker removing 6-host cap, delete confirmations), Native GPUI OS file dialogs (`prompt_for_paths` / `prompt_for_new_path`), Unified 4-tab `Settings` (with Delete Account, offline→cloud sync upgrade form, `~/.ssh` auto-import, Auto-Sync under Account & Sync) | `crates/sterm-gpui/src/{modals.rs,views.rs,settings_view.rs,app.rs}` | **done** (2026-11-22) | 0 clippy warnings (`-D warnings`) |

### Wave 3 — Lift, CI/CD Cutover & Tauri Retirement
| Unit | Scope | Target | State | Notes |
|---|---|---|---|---|
| `cutover-ci-cleanup` | Updated `.github/workflows/release.yml` for native `sterm-gpui` (Windows x64 + macOS arm64/x64), updated `README.md` & `docs/flow-and-feature-audit.md`, retired `src/`, `src-tauri/`, Node/npm files & temporary `rust/*-rs` bridge crates, verified `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo build --release -p sterm-gpui` | Root workspace & `.github/` | **done** (2026-11-22) | Pure-Rust standalone workspace |

## Out of Scope (Deferred to Post-Migration Phase 3 Roadmap)
- SSH Port Forwarding (`-L`/`-R`/`-D` SOCKS5)
- Local Shell (`portable-pty`)
- Recursive SFTP directory transfers
- SSH Agent Forwarding & HTTP/SOCKS proxy
- Auto-Lock idle timer & Biometric unlock
- Lucide SVG icon pack replacement (ADR-003)
