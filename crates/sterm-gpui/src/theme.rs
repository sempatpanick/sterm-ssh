use gpui::{hsla, rgb, Hsla};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccentPreset {
    Blue,
    Indigo,
    Emerald,
    Rose,
    Amber,
}

impl AccentPreset {
    pub const ALL: [Self; 5] = [
        Self::Blue,
        Self::Indigo,
        Self::Emerald,
        Self::Rose,
        Self::Amber,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Blue => "Cobalt Blue",
            Self::Indigo => "Linear Indigo",
            Self::Emerald => "Mint Emerald",
            Self::Rose => "Raycast Rose",
            Self::Amber => "Warm Amber",
        }
    }

    pub fn swatch_hex(self) -> u32 {
        match self {
            Self::Blue => 0x2563EB,
            Self::Indigo => 0x6366F1,
            Self::Emerald => 0x10B981,
            Self::Rose => 0xE11D48,
            Self::Amber => 0xD97706,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalThemeId {
    AdminDark,
    AntigravityDark,
    AntigravityLight,
    Obsidian,
    TokyoNight,
    Nord,
    Catppuccin,
}

impl TerminalThemeId {
    pub const ALL: [Self; 7] = [
        Self::AdminDark,
        Self::AntigravityDark,
        Self::AntigravityLight,
        Self::Obsidian,
        Self::TokyoNight,
        Self::Nord,
        Self::Catppuccin,
    ];

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "admin-dark" | "admin_dark" => Some(Self::AdminDark),
            "antigravity-cli" | "antigravity_dark" => Some(Self::AntigravityDark),
            "antigravity-cli-light" | "antigravity_light" => Some(Self::AntigravityLight),
            "obsidian" => Some(Self::Obsidian),
            "tokyo-night" | "tokyo_night" => Some(Self::TokyoNight),
            "nord" => Some(Self::Nord),
            "catppuccin" => Some(Self::Catppuccin),
            _ => None,
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::AdminDark => "admin-dark",
            Self::AntigravityDark => "antigravity-cli",
            Self::AntigravityLight => "antigravity-cli-light",
            Self::Obsidian => "obsidian",
            Self::TokyoNight => "tokyo-night",
            Self::Nord => "nord",
            Self::Catppuccin => "catppuccin",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AdminDark => "Admin Slate",
            Self::AntigravityDark => "Antigravity CLI Dark",
            Self::AntigravityLight => "Antigravity CLI Light",
            Self::Obsidian => "Obsidian",
            Self::TokyoNight => "Tokyo Night",
            Self::Nord => "Nord",
            Self::Catppuccin => "Catppuccin Mocha",
        }
    }

    /// Returns `(bg_hex, fg_hex, cursor_hex)`.
    pub fn colors(self) -> (u32, u32, u32) {
        match self {
            Self::AdminDark => (0x0B0F19, 0xE2E8F0, 0x60A5FA),
            Self::AntigravityDark => (0x131314, 0xE3E3E3, 0xA8C7FA),
            Self::AntigravityLight => (0xFFFFFF, 0x1F1F1F, 0x0B57D0),
            Self::Obsidian => (0x0C0D10, 0xE5E9F0, 0x38BDF8),
            Self::TokyoNight => (0x1A1B26, 0xC0CAF5, 0x7AA2F7),
            Self::Nord => (0x2E3440, 0xD8DEE9, 0x88C0D0),
            Self::Catppuccin => (0x1E1E2E, 0xCDD6F4, 0xF5E0DC),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TerminalCursorStyle {
    #[default]
    Bar,
    Block,
    Underline,
}

impl TerminalCursorStyle {
    pub const ALL: [Self; 3] = [Self::Bar, Self::Block, Self::Underline];

    pub fn label(self) -> &'static str {
        match self {
            Self::Bar => "Bar",
            Self::Block => "Block",
            Self::Underline => "Underline",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    pub theme_mode: ThemeMode,
    pub accent: AccentPreset,
    pub compact_density: bool,
    pub animations_enabled: bool,
    pub terminal_theme: TerminalThemeId,
    pub terminal_font: String,
    pub terminal_font_size: f32,
    pub terminal_line_height: f32,
    pub terminal_cursor_style: TerminalCursorStyle,
    pub ssh_keepalive_secs: u32,
    pub auto_sync: bool,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            theme_mode: ThemeMode::Light,
            accent: AccentPreset::Blue,
            compact_density: false,
            animations_enabled: true,
            terminal_theme: TerminalThemeId::AdminDark,
            terminal_font: "Consolas".to_string(),
            terminal_font_size: 13.0,
            terminal_line_height: 1.42,
            terminal_cursor_style: TerminalCursorStyle::Block,
            ssh_keepalive_secs: 30,
            auto_sync: true,
        }
    }
}

/// Admin Studio visual tokens matching the approved Light & Dark adaptive palette.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct ThemePalette {
    pub mode: ThemeMode,
    pub bg_canvas: Hsla,
    pub bg_sidebar: Hsla,
    pub bg_card: Hsla,
    pub bg_subtle: Hsla,
    pub bg_hover: Hsla,
    pub border: Hsla,
    pub border_strong: Hsla,
    pub text_primary: Hsla,
    pub text_secondary: Hsla,
    pub text_muted: Hsla,
    pub accent: Hsla,
    pub accent_solid: Hsla,
    pub accent_soft: Hsla,
    pub success: Hsla,
    pub success_soft: Hsla,
    pub warning: Hsla,
    pub warning_soft: Hsla,
    pub danger: Hsla,
    pub danger_soft: Hsla,
    pub island_bg: Hsla,
    pub island_fg: Hsla,
    pub island_border: Hsla,
    pub terminal_bg: Hsla,
    pub terminal_fg: Hsla,
    pub terminal_cursor: Hsla,
}

impl ThemePalette {
    pub fn for_mode(mode: ThemeMode) -> Self {
        Self::from_settings(&UiSettings {
            theme_mode: mode,
            ..Default::default()
        })
    }

    pub fn from_settings(settings: &UiSettings) -> Self {
        let (accent_light, accent_dark, accent_soft_light, accent_soft_dark) = match settings.accent
        {
            AccentPreset::Blue => (
                rgb(0x2563EB).into(),
                rgb(0x60A5FA).into(),
                rgb(0xEFF6FF).into(),
                hsla(213.0 / 360.0, 0.94, 0.68, 0.16),
            ),
            AccentPreset::Indigo => (
                rgb(0x4F46E5).into(),
                rgb(0x818CF8).into(),
                rgb(0xEEF2FF).into(),
                hsla(234.0 / 360.0, 0.89, 0.74, 0.16),
            ),
            AccentPreset::Emerald => (
                rgb(0x059669).into(),
                rgb(0x34D399).into(),
                rgb(0xECFDF5).into(),
                hsla(158.0 / 360.0, 0.64, 0.52, 0.16),
            ),
            AccentPreset::Rose => (
                rgb(0xE11D48).into(),
                rgb(0xFB7185).into(),
                rgb(0xFFF1F2).into(),
                hsla(351.0 / 360.0, 0.95, 0.71, 0.16),
            ),
            AccentPreset::Amber => (
                rgb(0xD97706).into(),
                rgb(0xFBBF24).into(),
                rgb(0xFFFBEB).into(),
                hsla(43.0 / 360.0, 0.96, 0.56, 0.16),
            ),
        };
        let accent_solid: Hsla = rgb(settings.accent.swatch_hex()).into();
        let (t_bg, t_fg, t_cur) = settings.terminal_theme.colors();

        match settings.theme_mode {
            ThemeMode::Light => Self {
                mode: ThemeMode::Light,
                bg_canvas: rgb(0xF4F6F9).into(),
                bg_sidebar: rgb(0xFFFFFF).into(),
                bg_card: rgb(0xFFFFFF).into(),
                bg_subtle: rgb(0xF1F5F9).into(),
                bg_hover: rgb(0xE8EEF5).into(),
                border: hsla(220.0 / 360.0, 0.30, 0.14, 0.10),
                border_strong: hsla(220.0 / 360.0, 0.30, 0.14, 0.20),
                text_primary: rgb(0x0F172A).into(),
                text_secondary: rgb(0x334155).into(),
                text_muted: rgb(0x64748B).into(),
                accent: accent_light,
                accent_solid,
                accent_soft: accent_soft_light,
                success: rgb(0x16A34A).into(),
                success_soft: rgb(0xECFDF5).into(),
                warning: rgb(0xD97706).into(),
                warning_soft: rgb(0xFFFBEB).into(),
                danger: rgb(0xDC2626).into(),
                danger_soft: rgb(0xFEF2F2).into(),
                island_bg: rgb(0x0F172A).into(),
                island_fg: rgb(0xF8FAFC).into(),
                island_border: hsla(210.0 / 360.0, 0.40, 0.95, 0.16),
                terminal_bg: rgb(t_bg).into(),
                terminal_fg: rgb(t_fg).into(),
                terminal_cursor: rgb(t_cur).into(),
            },
            ThemeMode::Dark => Self {
                mode: ThemeMode::Dark,
                bg_canvas: rgb(0x0F1117).into(),
                bg_sidebar: rgb(0x141720).into(),
                bg_card: rgb(0x171B26).into(),
                bg_subtle: rgb(0x1E2332).into(),
                bg_hover: rgb(0x252B3D).into(),
                border: hsla(0.0, 0.0, 1.0, 0.09),
                border_strong: hsla(0.0, 0.0, 1.0, 0.18),
                text_primary: rgb(0xF3F4F6).into(),
                text_secondary: rgb(0xCBD5E1).into(),
                text_muted: rgb(0x94A3B8).into(),
                accent: accent_dark,
                accent_solid,
                accent_soft: accent_soft_dark,
                success: rgb(0x34D399).into(),
                success_soft: hsla(158.0 / 360.0, 0.64, 0.52, 0.15),
                warning: rgb(0xFBBF24).into(),
                warning_soft: hsla(43.0 / 360.0, 0.96, 0.56, 0.15),
                danger: rgb(0xF87171).into(),
                danger_soft: hsla(0.0, 0.91, 0.71, 0.15),
                island_bg: rgb(0x090C12).into(),
                island_fg: rgb(0xF8FAFC).into(),
                island_border: hsla(0.0, 0.0, 1.0, 0.14),
                terminal_bg: rgb(t_bg).into(),
                terminal_fg: rgb(t_fg).into(),
                terminal_cursor: rgb(t_cur).into(),
            },
        }
    }
}

/// Converts a `vt100::Color` (Default, 256-color indexed, or 24-bit RGB) into GPUI `Hsla`.
pub fn vt_color_to_hsla(color: vt100::Color, fallback: Hsla) -> Hsla {
    match color {
        vt100::Color::Default => fallback,
        vt100::Color::Rgb(r, g, b) => {
            let hex = ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
            rgb(hex).into()
        }
        vt100::Color::Idx(idx) => ansi_256_to_hsla(idx),
    }
}

fn ansi_256_to_hsla(idx: u8) -> Hsla {
    const ANSI_16: [u32; 16] = [
        0x1E293B, // 0 black
        0xF87171, // 1 red
        0x34D399, // 2 green
        0xFBBF24, // 3 yellow
        0x60A5FA, // 4 blue
        0xC084FC, // 5 magenta
        0x38BDF8, // 6 cyan
        0xE2E8F0, // 7 white
        0x64748B, // 8 bright black
        0xFCA5A5, // 9 bright red
        0x6EE7B7, // 10 bright green
        0xFDE68A, // 11 bright yellow
        0x93C5FD, // 12 bright blue
        0xD8B4FE, // 13 bright magenta
        0x7DD3FC, // 14 bright cyan
        0xFFFFFF, // 15 bright white
    ];

    if idx < 16 {
        return rgb(ANSI_16[idx as usize]).into();
    }
    if idx < 232 {
        let i = idx - 16;
        let r = i / 36;
        let g = (i % 36) / 6;
        let b = i % 6;
        let to_u8 = |v: u8| if v == 0 { 0u32 } else { 55 + (v as u32) * 40 };
        let hex = (to_u8(r) << 16) | (to_u8(g) << 8) | to_u8(b);
        return rgb(hex).into();
    }
    let gray = 8 + ((idx - 232) as u32) * 10;
    let hex = (gray << 16) | (gray << 8) | gray;
    rgb(hex).into()
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}
