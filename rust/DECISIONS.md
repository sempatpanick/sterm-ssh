# Architecture Decision Records — STerm SSH Pure-Rust GPUI Migration

## ADR-001: Converge on `crates/sterm-gpui` as the Sole Desktop Binary
Status: accepted (2026-11-22)
Context: The repository contains two desktop frontends sharing five pure-Rust core crates (`core-crypto`, `core-vault`, `core-ssh`, `core-sftp`, `core-sync`): the legacy Tauri v2 + React frontend (`src/`, `src-tauri/`) and the native GPUI frontend (`crates/sterm-gpui/`). `sterm-gpui` compiles cleanly with zero Tauri/Node dependencies.
Decision: Converge directly onto `crates/sterm-gpui` as the single standalone desktop app. Port pure TypeScript logic units (`src/styles/`, `src/lib/split-tree.ts`, `src/lib/command-suggestions.ts`) through the `rust-anything` pipeline (`bridge` → `record` → `port.rs` → `build` → `diff` → `gate`) to prove behavioral equivalence, then integrate their gated Rust code cleanly into `crates/sterm-gpui` and port the remaining React UI features natively in GPUI.
Consequences: No duplicate `rust/app` binary is scaffolded; `rust/` holds migration governance (`MAP.md`, `DECISIONS.md`, `GLOSSARY.md`, `HANDOFF.md`, `research/`) and temporary gated bridge crates until lift/cutover.

## ADR-002: Combined Parity + Phase 1 Safety Fixes + Phase 2 IA Cleanup
Status: accepted (2026-11-22)
Context: `docs/flow-and-feature-audit.md` identified both missing Tauri-only features in GPUI and critical safety/IA issues (GPUI host-edit wiping tags/theme/startup_command/notes, offline→account reset wipe, single global challenge slots, single-prompt KBI, missing MITM expected fingerprint, 6-host SFTP cap, unwired `sftp_remote_rename`, zero-confirmation deletes, redundant `Overview` & `E2EE Sync` pages, sidebar-trapped Terminals).
Decision: Include full Tauri feature parity, Phase 1 safety fixes, and Phase 2 unified Information Architecture (persistent Top Session Tab Strip, `Hosts` as default home, top-level `Snippets` page, unified 4-tab `Settings`, `Keychain` with Credentials + Known Hosts) during the GPUI migration so UI views are built once in their final target shape.
Consequences: `Overview` and standalone `E2EE Sync` sidebar pages are retired in favor of `Hosts` (with Recent/Pinned summary) and `Settings → Account & Sync`; active SSH terminals move to a persistent top window tab strip.

## ADR-003: Replace External Web/Tauri Dependencies with Native Rust / GPUI APIs
Status: accepted (2026-11-22)
Context: `rust-anything analyze --whole-app` flagged 11 npm dependencies (`react`, `react-dom`, `zustand`, `lucide-react`, `@tauri-apps/api`, `@tauri-apps/plugin-dialog`, `@xterm/xterm`, and 4 `@xterm/addon-*`).
Decision:
- `react`, `react-dom`, `zustand` → `gpui 0.2.2` entity/view state (`StermAdminApp`).
- `@tauri-apps/api` → Direct in-process calls to `core-crypto`, `core-vault`, `core-ssh`, `core-sftp`, `core-sync` via `BackendServices` (zero IPC).
- `@tauri-apps/plugin-dialog` → `gpui 0.2.2` built-in `App::prompt_for_paths` and `App::prompt_for_new_path` (zero extra crates).
- `@xterm/xterm` + `@xterm/addon-{fit,search,web-links,webgl}` → `vt100 0.18.1` + GPUI GPU terminal renderer (`crates/sterm-gpui/src/terminal.rs`), extended with in-terminal search, arbitrary nested splits, and command suggestions.
- `lucide-react` → Crisp monochrome symbol glyphs during migration (optional Lucide SVG asset pack deferred to a visual polish pass).
Consequences: Zero Node.js, WebView2, or extra dialog crates required in the final desktop binary.

## ADR-004: Behavioral Equivalence Bar & On-Disk Compatibility
Status: accepted (2026-11-22)
Context: Pure TypeScript utilities (`split-tree`, `command-suggestions`, `terminal-themes`) have Vitest tests and subtle edge cases (ratio clamping `[0.15, 0.85]`, frecency `log2` scoring, prefix/Ctrl+U insert payloads, password-prompt recording guards). Users also have existing local SQLite vaults and sync server accounts.
Decision: Pure TS logic ports must pass `rust-anything diff` and `rust-anything gate` 100% (exact match on `split-tree` and `terminal-themes`; exact or `1e-9` float tolerance on `command-suggestions` if floating-point math differs). `sterm-gpui` must maintain 100% backward compatibility with `app.sterm.ssh/sterm-vault.db`, `.sterm-vault` backup archives, and `sterm-sync-server` v1 HTTP protocol.
Consequences: No breaking schema or wire changes; existing user vaults and cross-platform sync continue working seamlessly.

## ADR-005: Target Platforms & Native CI/CD Release Pipeline
Status: accepted (2026-11-22)
Context: `.github/workflows/release.yml` currently invokes `npm install`, `npm test`, and `tauri-apps/tauri-action@v0`, which only packages the legacy Tauri app.
Decision: Target Windows (`x86_64-pc-windows-msvc`) and macOS (`aarch64-apple-darwin`, `x86_64-apple-darwin`). Replace the Tauri release workflow with pure-Rust CI (`cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo build --release -p sterm-gpui`) producing native Windows `.zip`/`.exe` and macOS `.app` bundle `.tar.gz`/`.dmg` release artifacts with zero Node.js steps.
Consequences: Faster, self-contained native CI builds and smaller desktop distributions.

## ADR-006: Wave Checkpoints & Safe Cutover Retirement of Tauri
Status: accepted (2026-11-22)
Context: Removing `src/` and `src-tauri/` before porting all features would forfeit the reference implementation and Vitest characterization baseline.
Decision: Keep `src/` and `src-tauri/` intact as read-only reference through Waves 0–2, checking in with the user after each wave:
- **Wave 0**: Gated pure-Rust ports (`src/styles/`, `src/lib/` pure logic) via `rust-anything`.
- **Wave 1**: GPUI backend/state parity & Phase 1 safety fixes (FIFO challenge queues, multi-prompt KBI, host metadata preservation, offline→cloud safe sync, delete account, local `~/.ssh` discovery, SFTP session ref-counting & rename/chmod).
- **Wave 2**: GPUI UI parity & unified IA (Top Session Tab Strip, Nested Split Tree, Terminal Search, `⌘K` Command Palette, Snippets page + inline `Ctrl+Space` popover, full Host/Credential/Import/Chmod modals, native file dialogs, unified 4-tab Settings).
- **Wave 3**: CI `release.yml` cutover, `README.md` + `docs/` update, removal of `src/`, `src-tauri/`, Node/npm artifacts, and temporary bridge crates, verified by full `cargo test --workspace` + `cargo clippy --workspace -- -D warnings`.
Consequences: Safe, reversible progression with verifiable green gates at every checkpoint.
