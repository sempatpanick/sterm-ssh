use gpui::Keystroke;
use serde::{Deserialize, Serialize};

/// Bindable workspace actions customizable by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutAction {
    CommandPalette,
    ShortcutsHelp,
    SplitHorizontal,
    SplitVertical,
    TerminalSearch,
    ToggleSuggestions,
    CloseTab,
    LockVault,
    OpenLocalShell,
}

impl ShortcutAction {
    pub const ALL: [Self; 9] = [
        Self::CommandPalette,
        Self::OpenLocalShell,
        Self::SplitHorizontal,
        Self::SplitVertical,
        Self::TerminalSearch,
        Self::ToggleSuggestions,
        Self::CloseTab,
        Self::LockVault,
        Self::ShortcutsHelp,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::CommandPalette => "Command Omnibar",
            Self::ShortcutsHelp => "Keyboard Shortcuts",
            Self::SplitHorizontal => "Split Horizontally",
            Self::SplitVertical => "Split Vertically",
            Self::TerminalSearch => "Terminal Search",
            Self::ToggleSuggestions => "Command Suggestions",
            Self::CloseTab => "Close Workspace Tab",
            Self::LockVault => "Lock Encrypted Vault",
            Self::OpenLocalShell => "Open Local Shell",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::CommandPalette => "Open Command Omnibar & Quick Connect",
            Self::ShortcutsHelp => "Open Keyboard Shortcuts & Keybindings modal",
            Self::SplitHorizontal => "Split active terminal horizontally (side-by-side)",
            Self::SplitVertical => "Split active terminal vertically (top/bottom)",
            Self::TerminalSearch => "Toggle scrollback search in active terminal",
            Self::ToggleSuggestions => "Toggle inline command suggestions & snippets",
            Self::CloseTab => "Close current active workspace tab",
            Self::LockVault => "Lock encrypted vault immediately",
            Self::OpenLocalShell => "Open a new Local PTY shell workspace tab",
        }
    }
}

/// Serializable keyboard shortcut chord (`Ctrl/Cmd`, `Shift`, `Alt` + key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBinding {
    pub key: String,
    #[serde(default)]
    pub ctrl_or_cmd: bool,
    #[serde(default)]
    pub shift: bool,
    #[serde(default)]
    pub alt: bool,
}

impl KeyBinding {
    pub fn new(key: &str, ctrl_or_cmd: bool, shift: bool, alt: bool) -> Self {
        Self {
            key: key.to_ascii_lowercase(),
            ctrl_or_cmd,
            shift,
            alt,
        }
    }

    pub fn matches(&self, ks: &Keystroke) -> bool {
        let mod_pressed = ks.modifiers.control || ks.modifiers.platform;
        if mod_pressed != self.ctrl_or_cmd || ks.modifiers.alt != self.alt {
            return false;
        }
        // On some keyboard layouts typing '?' arrives with key == "?" and shift == true even when bound to "/".
        let slash_alias = self.key == "/" && !self.shift && ks.key == "?";
        if slash_alias {
            return true;
        }
        if ks.modifiers.shift != self.shift {
            return false;
        }
        ks.key.eq_ignore_ascii_case(&self.key)
    }

    pub fn from_keystroke(ks: &Keystroke) -> Option<Self> {
        let raw = ks.key.trim().to_ascii_lowercase();
        if raw.is_empty()
            || matches!(
                raw.as_str(),
                "control"
                    | "shift"
                    | "alt"
                    | "platform"
                    | "meta"
                    | "super"
                    | "capslock"
                    | "fn"
                    | "escape"
            )
        {
            return None;
        }
        let ctrl_or_cmd = ks.modifiers.control || ks.modifiers.platform;
        let is_fn_key = raw.starts_with('f') && raw[1..].parse::<u8>().is_ok_and(|n| (1..=12).contains(&n));
        if !ctrl_or_cmd && !ks.modifiers.alt && !is_fn_key {
            return None;
        }
        let normalized_key = if raw == "?" && !ks.modifiers.shift {
            "/".to_string()
        } else {
            raw
        };
        Some(Self {
            key: normalized_key,
            ctrl_or_cmd,
            shift: ks.modifiers.shift,
            alt: ks.modifiers.alt,
        })
    }

    pub fn display(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.ctrl_or_cmd {
            parts.push(if cfg!(target_os = "macos") {
                "Cmd".to_string()
            } else {
                "Ctrl".to_string()
            });
        }
        if self.alt {
            parts.push("Alt".to_string());
        }
        if self.shift {
            parts.push("Shift".to_string());
        }
        let key_lbl = match self.key.as_str() {
            "space" => "Space".to_string(),
            "enter" => "Enter".to_string(),
            "tab" => "Tab".to_string(),
            k if k.len() == 1 => k.to_ascii_uppercase(),
            k => k.to_ascii_uppercase(),
        };
        parts.push(key_lbl);
        parts.join("+")
    }
}

/// Persisted customizable keymap stored in `UiSettings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyBindingsConfig {
    pub command_palette: KeyBinding,
    pub shortcuts_help: KeyBinding,
    pub split_horizontal: KeyBinding,
    pub split_vertical: KeyBinding,
    pub terminal_search: KeyBinding,
    pub toggle_suggestions: KeyBinding,
    pub close_tab: KeyBinding,
    pub lock_vault: KeyBinding,
    pub open_local_shell: KeyBinding,
}

impl Default for KeyBindingsConfig {
    fn default() -> Self {
        Self {
            command_palette: KeyBinding::new("k", true, false, false),
            shortcuts_help: KeyBinding::new("/", true, false, false),
            split_horizontal: KeyBinding::new("d", true, false, false),
            split_vertical: KeyBinding::new("d", true, true, false),
            terminal_search: KeyBinding::new("f", true, false, false),
            toggle_suggestions: KeyBinding::new("space", true, false, false),
            close_tab: KeyBinding::new("w", true, false, false),
            lock_vault: KeyBinding::new("l", true, true, false),
            open_local_shell: KeyBinding::new("t", true, true, false),
        }
    }
}

impl KeyBindingsConfig {
    pub fn get(&self, action: ShortcutAction) -> &KeyBinding {
        match action {
            ShortcutAction::CommandPalette => &self.command_palette,
            ShortcutAction::ShortcutsHelp => &self.shortcuts_help,
            ShortcutAction::SplitHorizontal => &self.split_horizontal,
            ShortcutAction::SplitVertical => &self.split_vertical,
            ShortcutAction::TerminalSearch => &self.terminal_search,
            ShortcutAction::ToggleSuggestions => &self.toggle_suggestions,
            ShortcutAction::CloseTab => &self.close_tab,
            ShortcutAction::LockVault => &self.lock_vault,
            ShortcutAction::OpenLocalShell => &self.open_local_shell,
        }
    }

    pub fn set(&mut self, action: ShortcutAction, binding: KeyBinding) {
        match action {
            ShortcutAction::CommandPalette => self.command_palette = binding,
            ShortcutAction::ShortcutsHelp => self.shortcuts_help = binding,
            ShortcutAction::SplitHorizontal => self.split_horizontal = binding,
            ShortcutAction::SplitVertical => self.split_vertical = binding,
            ShortcutAction::TerminalSearch => self.terminal_search = binding,
            ShortcutAction::ToggleSuggestions => self.toggle_suggestions = binding,
            ShortcutAction::CloseTab => self.close_tab = binding,
            ShortcutAction::LockVault => self.lock_vault = binding,
            ShortcutAction::OpenLocalShell => self.open_local_shell = binding,
        }
    }

    pub fn matches(&self, action: ShortcutAction, ks: &Keystroke) -> bool {
        self.get(action).matches(ks)
    }

    pub fn display(&self, action: ShortcutAction) -> String {
        self.get(action).display()
    }

    pub fn reset_defaults(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::Modifiers;

    fn ks(key: &str, control: bool, shift: bool, alt: bool) -> Keystroke {
        Keystroke {
            modifiers: Modifiers {
                control,
                alt,
                shift,
                platform: false,
                function: false,
            },
            key: key.to_string(),
            key_char: None,
        }
    }

    #[test]
    fn keybinding_matching_validation_and_roundtrip() {
        let mut cfg = KeyBindingsConfig::default();
        assert!(cfg.matches(ShortcutAction::CommandPalette, &ks("k", true, false, false)));
        assert!(!cfg.matches(ShortcutAction::CommandPalette, &ks("k", true, true, false)));
        assert!(cfg.matches(ShortcutAction::SplitVertical, &ks("D", true, true, false)));
        assert!(cfg.matches(ShortcutAction::ShortcutsHelp, &ks("?", true, false, false)));

        // Unmodified letter keys cannot be captured as accidental global hotkeys
        assert!(KeyBinding::from_keystroke(&ks("a", false, false, false)).is_none());
        let captured = KeyBinding::from_keystroke(&ks("p", true, true, false)).unwrap();
        assert_eq!(captured.key, "p");
        assert!(captured.ctrl_or_cmd && captured.shift && !captured.alt);

        // Function keys are accepted standalone
        assert!(KeyBinding::from_keystroke(&ks("F5", false, false, false)).is_some());

        cfg.set(ShortcutAction::OpenLocalShell, captured.clone());
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: KeyBindingsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.get(ShortcutAction::OpenLocalShell), &captured);

        cfg.reset_defaults();
        assert_eq!(
            cfg.get(ShortcutAction::OpenLocalShell),
            &KeyBinding::new("t", true, true, false)
        );
    }
}
