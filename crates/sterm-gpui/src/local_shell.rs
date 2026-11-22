use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use core_ssh::types::TerminalEvent;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct LocalShellSpec {
    pub label: String,
    pub program: String,
    pub args: Vec<String>,
}

struct ActiveLocalShell {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

/// Pure-Rust local PTY shell manager (PowerShell / cmd / WSL on Windows, Zsh / Bash on macOS & Linux).
#[derive(Clone, Default)]
pub struct LocalShellManager {
    sessions: Arc<Mutex<HashMap<String, ActiveLocalShell>>>,
}

impl LocalShellManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn available_shells() -> Vec<LocalShellSpec> {
        #[cfg(windows)]
        {
            let mut shells = Vec::new();
            let has_pwsh = std::process::Command::new("pwsh.exe")
                .arg("--version")
                .output()
                .is_ok();
            if has_pwsh {
                shells.push(LocalShellSpec {
                    label: "PowerShell 7".into(),
                    program: "pwsh.exe".into(),
                    args: vec!["-NoLogo".into()],
                });
            }
            shells.push(LocalShellSpec {
                label: "Windows PowerShell".into(),
                program: "powershell.exe".into(),
                args: vec!["-NoLogo".into()],
            });
            shells.push(LocalShellSpec {
                label: "Command Prompt".into(),
                program: "cmd.exe".into(),
                args: Vec::new(),
            });
            if std::path::Path::new(r"C:\Windows\System32\wsl.exe").exists() {
                shells.push(LocalShellSpec {
                    label: "WSL".into(),
                    program: "wsl.exe".into(),
                    args: Vec::new(),
                });
            }
            shells
        }
        #[cfg(not(windows))]
        {
            let mut shells = Vec::new();
            if let Ok(env_shell) = std::env::var("SHELL")
                && !env_shell.trim().is_empty()
            {
                let name = std::path::Path::new(&env_shell)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Shell".into());
                shells.push(LocalShellSpec {
                    label: format!("Default ({name})"),
                    program: env_shell,
                    args: vec!["-l".into()],
                });
            }
            for (lbl, prog) in [("Zsh", "/bin/zsh"), ("Bash", "/bin/bash"), ("Sh", "/bin/sh")] {
                if std::path::Path::new(prog).exists()
                    && !shells.iter().any(|s| s.program == prog)
                {
                    shells.push(LocalShellSpec {
                        label: lbl.into(),
                        program: prog.into(),
                        args: Vec::new(),
                    });
                }
            }
            if shells.is_empty() {
                shells.push(LocalShellSpec {
                    label: "Shell".into(),
                    program: "/bin/sh".into(),
                    args: Vec::new(),
                });
            }
            shells
        }
    }

    pub fn default_shell() -> LocalShellSpec {
        Self::available_shells()
            .into_iter()
            .next()
            .unwrap_or_else(|| LocalShellSpec {
                label: "Shell".into(),
                program: if cfg!(windows) {
                    "powershell.exe".into()
                } else {
                    "/bin/sh".into()
                },
                args: Vec::new(),
            })
    }

    pub fn spawn<F>(
        &self,
        spec: &LocalShellSpec,
        initial_cwd: Option<std::path::PathBuf>,
        cols: u16,
        rows: u16,
        mut on_event: F,
    ) -> Result<String, String>
    where
        F: FnMut(TerminalEvent) + Send + 'static,
    {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: rows.max(4),
                cols: cols.max(20),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("openpty failed: {e}"))?;

        let mut cmd = CommandBuilder::new(&spec.program);
        for arg in &spec.args {
            cmd.arg(arg);
        }
        if let Some(dir) = initial_cwd.filter(|p| p.is_dir()).or_else(dirs::home_dir) {
            cmd.cwd(dir);
        }
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("failed to spawn {}: {e}", spec.program))?;
        drop(pair.slave);

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("pty reader failed: {e}"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("pty writer failed: {e}"))?;

        let session_id = format!("local-{}", Uuid::now_v7());
        {
            let mut map = self.sessions.lock().map_err(|_| "local shell lock")?;
            map.insert(
                session_id.clone(),
                ActiveLocalShell {
                    master: pair.master,
                    writer,
                    child,
                },
            );
        }

        let sid_thread = session_id.clone();
        let sessions_ref = Arc::clone(&self.sessions);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        on_event(TerminalEvent::Closed {
                            reason: "local shell exited".into(),
                        });
                        break;
                    }
                    Ok(n) => {
                        on_event(TerminalEvent::Output {
                            data: buf[..n].to_vec(),
                        });
                    }
                    Err(e) => {
                        on_event(TerminalEvent::Closed {
                            reason: format!("local shell closed ({e})"),
                        });
                        break;
                    }
                }
            }
            if let Ok(mut map) = sessions_ref.lock() {
                map.remove(&sid_thread);
            }
        });

        Ok(session_id)
    }

    pub fn write_input(&self, session_id: &str, bytes: &[u8]) -> Result<(), String> {
        let mut map = self.sessions.lock().map_err(|_| "local shell lock")?;
        let shell = map
            .get_mut(session_id)
            .ok_or_else(|| "local shell session not found".to_string())?;
        shell
            .writer
            .write_all(bytes)
            .and_then(|()| shell.writer.flush())
            .map_err(|e| e.to_string())
    }

    pub fn resize(&self, session_id: &str, cols: u16, rows: u16) -> Result<(), String> {
        let map = self.sessions.lock().map_err(|_| "local shell lock")?;
        let shell = map
            .get(session_id)
            .ok_or_else(|| "local shell session not found".to_string())?;
        shell
            .master
            .resize(PtySize {
                rows: rows.max(4),
                cols: cols.max(20),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())
    }

    pub fn close(&self, session_id: &str) {
        if let Ok(mut map) = self.sessions.lock()
            && let Some(mut shell) = map.remove(session_id)
        {
            let _ = shell.child.kill();
        }
    }
}
