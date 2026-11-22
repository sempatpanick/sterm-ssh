# STerm SSH — Native Pure-Rust SSH & SFTP Client (macOS & Windows)

STerm SSH is a clean-room, local-first desktop SSH & SFTP client built **100% in Rust** with **GPUI** (hardware-accelerated native UI), **russh**, **russh-sftp**, and optional zero-knowledge end-to-end encrypted (E2EE) cross-platform sync. Zero Node.js, zero Electron, zero WebView.

## Features

- **Native GPUI Terminal Workspace**: Persistent top session tab strip (`Vault` + live terminal tabs), arbitrary nested horizontal/vertical **split panes** (duplicate host or split with any saved host), VT100/ANSI emulator with scrollback reflow, OSC-8/URL detection (`Ctrl+Click`), in-terminal **Search** (`Ctrl/Cmd+F`), smart-positioned **Command Suggestions** (`Ctrl+Space`), 7 curated terminal themes (including Antigravity CLI Dark/Light, Tokyo Night, Nord, Catppuccin Mocha), configurable line height & cursor style (`Bar` / `Block` / `Underline`), and `Ctrl/Cmd+K` **Command Palette & Quick Connect**.
- **Pure-Rust SSH Engine (`russh`)**: Password, Ed25519/RSA/ECDSA Private Key, OpenSSH Certificate, local SSH Agent, and multi-prompt **Keyboard-Interactive (2FA / PAM)** auth; multi-hop **ProxyJump / Bastion** chaining; group default username & credential inheritance; keepalives; and FIFO-queued **TOFU SHA-256 host key verification** with MITM expected-fingerprint mismatch alerts.
- **Local-First Encrypted Vault**: Argon2id KDF + HKDF-SHA256 domain separation + AES-256-GCM per-record AEAD encryption in local SQLite (`app.sterm.ssh/sterm-vault.db`), optional **OS Keychain** quick unlock (Windows Credential Manager & macOS Keychain), automatic `~/.ssh` discovery + selective `~/.ssh/config` import preview, reusable **Snippets** & learned command history, built-in Ed25519 key generator, native OS file dialogs, and portable encrypted `.sterm-vault` backup export/import.
- **Dual-Pane SFTP File Manager (`russh-sftp`)**: Side-by-side Local & Remote file browsers with ref-counted SSH transport sharing, searchable host picker, dotfile toggle, native drag-and-drop & OS external file drop, chunked streaming uploads/downloads in the Dynamic Transfer Island, visual `chmod` permission matrix, remote rename, mkdir, and inline remote text editor.
- **Zero-Knowledge Cross-Platform Account Sync**: Optional self-hosted Rust (`axum` + SQLite + Docker) sync server (`server/sync-server`) with lossless offline-to-cloud vault upgrade, conflict-aware bidirectional sync, master password rotation, and full account deletion.

## Development

### Prerequisites
- Rust stable toolchain (`rustup`, `cargo`)
- **Windows**: Visual Studio C++ Build Tools (MSVC)
- **macOS**: Xcode Command Line Tools (`xcode-select --install`)

### Run Locally
```bash
cargo run -p sterm-gpui
```

### Run Tests & Clippy
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### Build Native Release Binary
```bash
cargo build --release -p sterm-gpui
```
Cross-platform GitHub Actions release builds for Windows (`x86_64-pc-windows-msvc`) and macOS (`aarch64-apple-darwin` & `x86_64-apple-darwin`) are preconfigured in [`.github/workflows/release.yml`](.github/workflows/release.yml).

### Optional Self-Hosted E2EE Sync Server
```bash
cargo run --release --package sterm-sync-server
# or via Docker:
docker build -f server/sync-server/Dockerfile -t sterm-sync-server .
docker run -p 8787:8787 -v sterm-data:/data -e STERM_JWT_SECRET="strong-random-secret" sterm-sync-server
```
