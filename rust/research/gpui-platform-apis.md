# Primary Source Research — GPUI 0.2.2 Native Dialog & Platform APIs

Source inspected: `~/.cargo/registry/src/index.crates.io-*/gpui-0.2.2/src/app.rs` and `platform.rs`.

## Native File Dialogs (Replacing `@tauri-apps/plugin-dialog`)
- `App::prompt_for_paths(&self, options: PathPromptOptions) -> oneshot::Receiver<Result<Option<Vec<PathBuf>>>>` (`app.rs:1116`)
  - `PathPromptOptions { files: bool, directories: bool, multiple: bool, prompt: Option<SharedString> }` (`platform.rs:1330`)
  - Use for: `.sterm-vault` backup import, loading SSH private key PEM files, loading OpenSSH certificate files (`*-cert.pub`), picking custom SSH config files.
- `App::prompt_for_new_path(&self, directory: &Path, suggested_name: Option<&str>) -> oneshot::Receiver<Result<Option<PathBuf>>>` (`app.rs:1129`)
  - Use for: `.sterm-vault` backup export (default suggested name: `Some("sterm-backup.sterm-vault")`).
- `App::reveal_path(&self, path: &Path)` (`app.rs:1138`) — reveal local SFTP item in Windows Explorer / macOS Finder.
- `App::open_with_system(&self, path: &Path)` (`app.rs:1143`) — open local file with OS default app.

## Semantic Traps
- `prompt_for_paths` and `prompt_for_new_path` return `futures::channel::oneshot::Receiver` (GPUI's `cx.spawn` async loop awaits them cleanly without blocking the UI thread; never `.recv()` synchronously).
- Result is `Result<Option<Vec<PathBuf>>>`: `Ok(None)` means the user cancelled the dialog (not an error); `Ok(Some(paths))` contains selected paths.
- Remember to use `cx.spawn(async move |this, cx| ...)` to receive the path and update entity state inside `this.update(cx, ...)`.
