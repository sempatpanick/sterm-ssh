use std::time::Duration;

use gpui::{
    div, ease_out_quint, prelude::*, px, rgb, Animation, AnimationExt as _, Context, FontWeight,
};

use crate::app::{ConfirmAction, SettingsTab, StermAdminApp};
use crate::icons::{icon_svg, Icon};
use crate::motion::loading_dots;
use crate::theme::{
    AccentPreset, TerminalCursorStyle, TerminalThemeId, ThemeMode, ThemePalette,
};

impl StermAdminApp {
    /// Unified 4-tab Admin Settings:
    /// Appearance & GUI, Terminal & SSH, Account & Sync, and Vault & Backup.
    pub fn render_settings_page(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let tabs: [(SettingsTab, Icon, &str); 4] = [
            (SettingsTab::Appearance, Icon::Settings, "Appearance & GUI"),
            (SettingsTab::Terminal, Icon::Terminal, "Terminal & SSH"),
            (SettingsTab::Account, Icon::Network, "Account & Sync"),
            (SettingsTab::Security, Icon::Shield, "Vault & Backup"),
        ];

        let tab_body = match self.settings_tab {
            SettingsTab::Appearance => self.render_settings_appearance(t, cx).into_any_element(),
            SettingsTab::Terminal => self.render_settings_terminal(t, cx).into_any_element(),
            SettingsTab::Account => self.render_settings_account(t, cx).into_any_element(),
            SettingsTab::Security => self.render_settings_security(t, cx).into_any_element(),
        };

        let body_animated = if self.settings.animations_enabled {
            div()
                .flex_1()
                .min_h_0()
                .child(tab_body)
                .with_animation(
                    ("settings-tab-enter", self.settings_tab_epoch),
                    Animation::new(Duration::from_millis(190)).with_easing(ease_out_quint()),
                    |el, delta| el.opacity(delta).pt(px((1.0 - delta) * 8.0)),
                )
                .into_any_element()
        } else {
            div().flex_1().min_h_0().child(tab_body).into_any_element()
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .p_1()
                            .rounded_xl()
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .shadow_sm()
                            .children(tabs.into_iter().enumerate().map(|(ix, (tab, icon, label))| {
                                let active = self.settings_tab == tab;
                                div()
                                    .id(("set-tab", ix))
                                    .px_3()
                                    .py_1p5()
                                    .rounded_lg()
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
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
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        if this.settings_tab != tab {
                                            this.settings_tab = tab;
                                            this.settings_tab_epoch =
                                                this.settings_tab_epoch.wrapping_add(1);
                                            cx.notify();
                                        }
                                    }))
                                    .child(icon_svg(
                                        icon,
                                        13.0,
                                        if active { t.accent } else { t.text_muted },
                                    ))
                                    .child(label)
                            })),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(t.text_muted)
                            .child("Preferences save automatically"),
                    ),
            )
            .child(
                div()
                    .id("settings-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(body_animated),
            )
    }

    // -------------------------------------------------------------------------
    // Tab 1: Appearance & GUI Settings
    // -------------------------------------------------------------------------
    fn render_settings_appearance(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .grid()
            .grid_cols(2)
            .gap_3p5()
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Theme & Accent"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child("Customize Admin Studio surface theme and highlight color."),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_secondary)
                                    .child("Appearance Mode"),
                            )
                            .child(
                                div()
                                    .grid()
                                    .grid_cols(2)
                                    .gap_2()
                                    .children(
                                        [
                                            (ThemeMode::Light, "☀ Light Studio", "Crisp daylight cards"),
                                            (ThemeMode::Dark, "☾ Dark Studio", "Low-glare slate cards"),
                                        ]
                                        .into_iter()
                                        .enumerate()
                                        .map(|(ix, (mode, title, desc))| {
                                            let active = self.settings.theme_mode == mode;
                                            div()
                                                .id(("set-mode", ix))
                                                .p_3()
                                                .rounded_xl()
                                                .border_1()
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active { t.accent } else { t.border })
                                                .hover(|s| s.border_color(t.accent))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.settings.theme_mode = mode;
                                                    this.save_settings(cx);
                                                }))
                                                .child(
                                                    div()
                                                        .text_xs()
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .text_color(if active {
                                                            t.accent
                                                        } else {
                                                            t.text_primary
                                                        })
                                                        .child(title),
                                                )
                                                .child(
                                                    div()
                                                        .text_size(px(11.0))
                                                        .text_color(t.text_muted)
                                                        .child(desc),
                                                )
                                        }),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_secondary)
                                    .child("Accent Color"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_2()
                                    .children(AccentPreset::ALL.into_iter().enumerate().map(
                                        |(ix, preset)| {
                                            let active = self.settings.accent == preset;
                                            div()
                                                .id(("set-accent", ix))
                                                .px_2p5()
                                                .py_1p5()
                                                .rounded_lg()
                                                .border_1()
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .text_xs()
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active {
                                                    t.accent
                                                } else {
                                                    t.border
                                                })
                                                .hover(|s| s.border_color(t.accent))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.settings.accent = preset;
                                                    this.save_settings(cx);
                                                }))
                                                .child(
                                                    div()
                                                        .w(px(12.0))
                                                        .h(px(12.0))
                                                        .rounded_full()
                                                        .bg(rgb(preset.swatch_hex())),
                                                )
                                                .child(preset.label())
                                        },
                                    )),
                            ),
                    ),
            )
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3p5()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Interface, Motion & Local SSH"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child("Control UI transitions, layout density, and ~/.ssh auto-import."),
                            ),
                    )
                    .child(self.settings_toggle_row(
                        t,
                        "set-anim-toggle",
                        "Smooth UI Animations",
                        "Page fade/glide transitions, modal springs, and loading motion",
                        self.settings.animations_enabled,
                        cx.listener(|this, _, _, cx| {
                            this.settings.animations_enabled = !this.settings.animations_enabled;
                            this.save_settings(cx);
                        }),
                    ))
                    .child(self.settings_toggle_row(
                        t,
                        "set-density-toggle",
                        "Compact Table Density",
                        "Show tighter row spacing for high-volume server inventories",
                        self.settings.compact_density,
                        cx.listener(|this, _, _, cx| {
                            this.settings.compact_density = !this.settings.compact_density;
                            this.save_settings(cx);
                        }),
                    ))
                    .child(self.settings_toggle_row(
                        t,
                        "set-sidebar-toggle",
                        "Collapsed Sidebar Rail",
                        "Keep left Vault navigation in slim icon-only rail mode",
                        self.sidebar_collapsed,
                        cx.listener(|this, _, _, cx| {
                            this.toggle_sidebar(cx);
                        }),
                    ))
                    .child(self.settings_toggle_row(
                        t,
                        "set-autoimport-ssh",
                        "Auto-Import Local ~/.ssh",
                        "Automatically import new hosts and keys discovered in ~/.ssh on unlock",
                        self.ssh_auto_import_enabled,
                        cx.listener(|this, _, _, cx| {
                            this.toggle_auto_import_ssh(cx);
                        }),
                    )),
            )
    }

    // -------------------------------------------------------------------------
    // Tab 2: Terminal & SSH Preferences (+ Line Height & Cursor Style!)
    // -------------------------------------------------------------------------
    fn render_settings_terminal(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let fonts = [
            "Consolas",
            "Cascadia Mono",
            "JetBrains Mono",
            "Fira Code",
            "SF Mono",
        ];
        let sizes = [12.0f32, 13.0, 14.0, 15.0, 16.0];
        let line_heights = [1.2f32, 1.3, 1.42, 1.55, 1.65];
        let keepalives = [(0u32, "Off"), (15, "15s"), (30, "30s"), (60, "60s")];

        div()
            .grid()
            .grid_cols(2)
            .gap_3p5()
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Terminal Palette & Typography"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child("Updates apply immediately to all live SSH panes."),
                            ),
                    )
                    // 7 Terminal Themes (including Antigravity Dark & Light)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_secondary)
                                    .child("Color Scheme"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_1p5()
                                    .children(TerminalThemeId::ALL.into_iter().enumerate().map(
                                        |(ix, tid)| {
                                            let active = self.settings.terminal_theme == tid;
                                            let (bg_hex, _, cur_hex) = tid.colors();
                                            div()
                                                .id(("set-t-theme", ix))
                                                .px_2p5()
                                                .py_1p5()
                                                .rounded_lg()
                                                .border_1()
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .text_xs()
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active {
                                                    t.accent
                                                } else {
                                                    t.border
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.settings.terminal_theme = tid;
                                                    this.save_settings(cx);
                                                }))
                                                .child(
                                                    div()
                                                        .w(px(14.0))
                                                        .h(px(14.0))
                                                        .rounded_sm()
                                                        .bg(rgb(bg_hex))
                                                        .border_1()
                                                        .border_color(rgb(cur_hex)),
                                                )
                                                .child(tid.label())
                                        },
                                    )),
                            ),
                    )
                    // Font Family
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_secondary)
                                    .child("Monospace Font"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_1p5()
                                    .children(fonts.into_iter().enumerate().map(|(ix, fname)| {
                                        let active = self.settings.terminal_font == fname;
                                        div()
                                            .id(("set-font", ix))
                                            .px_2p5()
                                            .py_1()
                                            .rounded_lg()
                                            .border_1()
                                            .text_xs()
                                            .font_family(fname)
                                            .cursor_pointer()
                                            .bg(if active { t.accent_soft } else { t.bg_subtle })
                                            .border_color(if active { t.accent } else { t.border })
                                            .text_color(if active { t.accent } else { t.text_primary })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.settings.terminal_font = fname.to_string();
                                                this.save_settings(cx);
                                            }))
                                            .child(fname)
                                    })),
                            ),
                    )
                    // Font Size + Line Height
                    .child(
                        div()
                            .grid()
                            .grid_cols(2)
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text_secondary)
                                            .child("Font Size"),
                                    )
                                    .child(div().flex().flex_wrap().gap_1().children(
                                        sizes.into_iter().enumerate().map(|(ix, sz)| {
                                            let active =
                                                (self.settings.terminal_font_size - sz).abs() < 0.1;
                                            div()
                                                .id(("set-fsize", ix))
                                                .px_2()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .text_xs()
                                                .font_family("Consolas")
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active {
                                                    t.accent
                                                } else {
                                                    t.border
                                                })
                                                .text_color(if active {
                                                    t.accent
                                                } else {
                                                    t.text_primary
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.settings.terminal_font_size = sz;
                                                    this.save_settings(cx);
                                                }))
                                                .child(format!("{}px", sz as u32))
                                        }),
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text_secondary)
                                            .child("Line Height"),
                                    )
                                    .child(div().flex().flex_wrap().gap_1().children(
                                        line_heights.into_iter().enumerate().map(|(ix, lh)| {
                                            let active = (self.settings.terminal_line_height - lh)
                                                .abs()
                                                < 0.04;
                                            div()
                                                .id(("set-lh", ix))
                                                .px_2()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .text_xs()
                                                .font_family("Consolas")
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active {
                                                    t.accent
                                                } else {
                                                    t.border
                                                })
                                                .text_color(if active {
                                                    t.accent
                                                } else {
                                                    t.text_primary
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.settings.terminal_line_height = lh;
                                                    this.save_settings(cx);
                                                }))
                                                .child(format!("{lh:.2}"))
                                        }),
                                    )),
                            ),
                    )
                    // Cursor Style + SSH Keepalive
                    .child(
                        div()
                            .grid()
                            .grid_cols(2)
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text_secondary)
                                            .child("Cursor Style"),
                                    )
                                    .child(div().flex().gap_1().children(
                                        TerminalCursorStyle::ALL.into_iter().enumerate().map(
                                            |(ix, style)| {
                                                let active =
                                                    self.settings.terminal_cursor_style == style;
                                                div()
                                                    .id(("set-cur", ix))
                                                    .px_2p5()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .text_xs()
                                                    .cursor_pointer()
                                                    .bg(if active {
                                                        t.accent_soft
                                                    } else {
                                                        t.bg_subtle
                                                    })
                                                    .border_color(if active {
                                                        t.accent
                                                    } else {
                                                        t.border
                                                    })
                                                    .text_color(if active {
                                                        t.accent
                                                    } else {
                                                        t.text_primary
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.settings.terminal_cursor_style = style;
                                                        this.save_settings(cx);
                                                    }))
                                                    .child(style.label())
                                            },
                                        ),
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text_secondary)
                                            .child("SSH Keepalive"),
                                    )
                                    .child(div().flex().gap_1().children(
                                        keepalives.into_iter().enumerate().map(|(ix, (secs, lbl))| {
                                            let active = self.settings.ssh_keepalive_secs == secs;
                                            div()
                                                .id(("set-ka", ix))
                                                .px_2()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .text_xs()
                                                .font_family("Consolas")
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active {
                                                    t.accent
                                                } else {
                                                    t.border
                                                })
                                                .text_color(if active {
                                                    t.accent
                                                } else {
                                                    t.text_primary
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.settings.ssh_keepalive_secs = secs;
                                                    this.save_settings(cx);
                                                }))
                                                .child(lbl)
                                        }),
                                    )),
                            ),
                    )
                    // Auto-Reconnect Toggle (Phase 3)
                    .child(self.settings_toggle_row(
                        t,
                        "set-autoreconnect-toggle",
                        "Auto-Reconnect SSH Sessions",
                        "Automatically retry dropped SSH connections with exponential backoff (up to 5 attempts)",
                        self.settings.auto_reconnect,
                        cx.listener(|this, _, _, cx| {
                            this.settings.auto_reconnect = !this.settings.auto_reconnect;
                            this.save_settings(cx);
                        }),
                    )),
            )
            // Right Card: Live Terminal Preview
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Live Terminal Preview"),
                    )
                    .child({
                        let lh_px =
                            (self.settings.terminal_font_size * self.settings.terminal_line_height)
                                .round();
                        let cur_el = match self.settings.terminal_cursor_style {
                            TerminalCursorStyle::Block => div()
                                .w(px(8.0))
                                .h(px(self.settings.terminal_font_size + 2.0))
                                .bg(t.terminal_cursor),
                            TerminalCursorStyle::Bar => div()
                                .w(px(2.0))
                                .h(px(self.settings.terminal_font_size + 2.0))
                                .bg(t.terminal_cursor),
                            TerminalCursorStyle::Underline => div()
                                .w(px(8.0))
                                .h(px(2.0))
                                .mt(px(self.settings.terminal_font_size))
                                .bg(t.terminal_cursor),
                        };
                        div()
                            .flex_1()
                            .min_h(px(230.0))
                            .rounded_xl()
                            .bg(t.terminal_bg)
                            .border_1()
                            .border_color(t.border)
                            .p_3p5()
                            .font_family(self.settings.terminal_font.clone())
                            .text_size(px(self.settings.terminal_font_size))
                            .line_height(px(lh_px))
                            .text_color(t.terminal_fg)
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .gap_1()
                                    .child(div().text_color(t.success).child("deploy@prod-api-01"))
                                    .child(div().text_color(t.terminal_cursor).child("~/app"))
                                    .child("$ systemctl status sterm"),
                            )
                            .child(div().text_color(t.success).child("● Active: running (14 days)"))
                            .child(
                                div()
                                    .opacity(0.75)
                                    .child("  Transport: russh · Ed25519 · TOFU verified"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .mt_2()
                                    .child("$ ")
                                    .child(cur_el),
                            )
                    }),
            )
    }

    // -------------------------------------------------------------------------
    // Tab 3: Account & E2EE Sync (Canonical Sync Center + Offline Upgrade + Delete Account!)
    // -------------------------------------------------------------------------
    fn render_settings_account(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .grid()
            .grid_cols(2)
            .gap_3p5()
            // Left Column: E2EE Account Session OR Offline Upgrade Sign-In/Register Form
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3p5()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("E2EE Cloud Sync"),
                            )
                            .child(
                                div()
                                    .px_2p5()
                                    .py_0p5()
                                    .rounded_full()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .bg(if self.sync_status.signed_in {
                                        t.success_soft
                                    } else {
                                        t.bg_subtle
                                    })
                                    .text_color(if self.sync_status.signed_in {
                                        t.success
                                    } else {
                                        t.text_muted
                                    })
                                    .child(if self.sync_status.signed_in {
                                        "Signed In"
                                    } else {
                                        "Local Only"
                                    }),
                            ),
                    )
                    .when(self.sync_status.signed_in, |el| {
                        el.child(
                            div()
                                .p_3()
                                .rounded_xl()
                                .bg(t.bg_subtle)
                                .flex()
                                .flex_col()
                                .gap_1()
                                .text_xs()
                                .child(format!(
                                    "Email: {}",
                                    self.sync_status.email.as_deref().unwrap_or("-")
                                ))
                                .child(format!(
                                    "Sync Server: {}",
                                    self.sync_status.server_url.as_deref().unwrap_or("-")
                                ))
                                .child(format!(
                                    "Vault ID: {}",
                                    self.vault_status.vault_id.as_deref().unwrap_or("-")
                                ))
                                .child(format!(
                                    "Last Synced: {}",
                                    self.sync_status
                                        .last_synced_at
                                        .and_then(chrono::DateTime::from_timestamp_millis)
                                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                        .unwrap_or_else(|| "Not synced yet".to_string())
                                )),
                        )
                        .child(self.settings_toggle_row(
                            t,
                            "set-autosync-toggle",
                            "Automatic E2EE Sync",
                            "Automatically push host, key, and snippet changes in the background",
                            self.settings.auto_sync,
                            cx.listener(|this, _, _, cx| {
                                this.settings.auto_sync = !this.settings.auto_sync;
                                this.save_settings(cx);
                            }),
                        ))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .id("set-sync-now")
                                        .px_3p5()
                                        .py_1p5()
                                        .rounded_lg()
                                        .bg(t.accent_solid)
                                        .text_color(gpui::white())
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .cursor_pointer()
                                        .hover(|s| s.opacity(0.92))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.trigger_sync_now(cx);
                                        }))
                                        .when(self.sync_busy, |s| {
                                            s.child(loading_dots("set-sync-dots", gpui::white()))
                                                .child("Syncing...")
                                        })
                                        .when(!self.sync_busy, |s| s.child("Sync Now")),
                                )
                                .child(
                                    div()
                                        .id("set-lock-vault")
                                        .px_3()
                                        .py_1p5()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(t.border_strong)
                                        .text_xs()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_subtle))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.lock_vault(cx);
                                        }))
                                        .child("Lock Vault"),
                                )
                                .child(
                                    div()
                                        .id("set-logout-btn")
                                        .px_3()
                                        .py_1p5()
                                        .rounded_lg()
                                        .bg(t.danger_soft)
                                        .border_1()
                                        .border_color(t.danger)
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(t.danger)
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.request_confirm(ConfirmAction::SignOut, cx);
                                        }))
                                        .child("Sign Out"),
                                ),
                        )
                    })
                    // Offline Local Vault -> Connect E2EE Sync (preserves existing local data!)
                    .when(!self.sync_status.signed_in, |el| {
                        el.child(
                            div()
                                .text_xs()
                                .text_color(t.text_muted)
                                .child("Sign in or create an account to sync your existing local vault across devices with zero-knowledge E2EE."),
                        )
                        .child(self.labeled_field(t, "Sync Server URL", self.sync_url.clone()))
                        .child(self.labeled_field(t, "Account Email", self.sync_email.clone()))
                        .child(self.labeled_field(
                            t,
                            "Account Master Password",
                            self.sync_password.clone(),
                        ))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .pt_1()
                                .child(
                                    div()
                                        .id("set-sync-signin")
                                        .flex_1()
                                        .py_2()
                                        .rounded_lg()
                                        .bg(t.accent_solid)
                                        .text_color(gpui::white())
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_center()
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.trigger_sync_auth(false, cx);
                                        }))
                                        .child("Sign In & Merge"),
                                )
                                .child(
                                    div()
                                        .id("set-sync-register")
                                        .flex_1()
                                        .py_2()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(t.border_strong)
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_center()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_subtle))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.trigger_sync_auth(true, cx);
                                        }))
                                        .child("Create Account"),
                                ),
                        )
                    }),
            )
            // Right Column: Change Master Password + Danger Zone (Delete Account)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3p5()
                    .child(
                        div()
                            .rounded_xl()
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .shadow_sm()
                            .p_4()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_0p5()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child("Change Master Password"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(t.text_muted)
                                            .child("Re-wraps your AES-256-GCM vault key with a new Argon2id password."),
                                    ),
                            )
                            .child(self.labeled_field(
                                t,
                                "Current Password",
                                self.pw_current.clone(),
                            ))
                            .child(self.labeled_field(t, "New Password", self.pw_new.clone()))
                            .child(self.labeled_field(
                                t,
                                "Confirm New Password",
                                self.pw_confirm.clone(),
                            ))
                            .child(
                                div()
                                    .id("set-change-pw-btn")
                                    .px_3p5()
                                    .py_2()
                                    .rounded_lg()
                                    .bg(t.accent_solid)
                                    .text_color(gpui::white())
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .gap_2()
                                    .cursor_pointer()
                                    .hover(|s| s.opacity(0.92))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_change_password(cx);
                                    }))
                                    .when(self.settings_busy, |s| {
                                        s.child(loading_dots("set-pw-dots", gpui::white()))
                                            .child("Updating...")
                                    })
                                    .when(!self.settings_busy, |s| s.child("Update Password")),
                            ),
                    )
                    // Danger Zone: Delete Server Account (full parity with Tauri!)
                    .when(self.sync_status.signed_in, |el| {
                        el.child(
                            div()
                                .rounded_xl()
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.danger)
                                .shadow_sm()
                                .p_4()
                                .flex()
                                .flex_col()
                                .gap_2p5()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(t.danger)
                                        .child("Danger Zone — Delete Server Account"),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(t.text_muted)
                                        .child("Permanently deletes your sync account, encrypted server blobs, and local vault cache."),
                                )
                                .child(self.labeled_field(
                                    t,
                                    "Confirm Master Password",
                                    self.delete_account_pw.clone(),
                                ))
                                .child(
                                    div()
                                        .id("set-delete-acct-btn")
                                        .px_3p5()
                                        .py_2()
                                        .rounded_lg()
                                        .bg(t.danger)
                                        .text_color(gpui::white())
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_center()
                                        .cursor_pointer()
                                        .hover(|s| s.opacity(0.92))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.submit_delete_account(cx);
                                        }))
                                        .child("Permanently Delete Account"),
                                ),
                        )
                    }),
            )
    }

    // -------------------------------------------------------------------------
    // Tab 4: Vault & Encrypted Backup (+ Native GPUI OS File Dialogs!)
    // -------------------------------------------------------------------------
    fn render_settings_security(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .grid()
            .grid_cols(2)
            .gap_3p5()
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_0p5()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Portable Encrypted Backup (.sterm-vault)"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child("Export or restore an Argon2id + AES-256-GCM encrypted vault archive."),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text_secondary)
                                            .child("Archive Path"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .gap_1p5()
                                            .child(
                                                div()
                                                    .id("set-bkp-browse-save")
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border_strong)
                                                    .text_size(px(11.0))
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_subtle))
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.pick_backup_export_path(cx);
                                                    }))
                                                    .child("Save As..."),
                                            )
                                            .child(
                                                div()
                                                    .id("set-bkp-browse-open")
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border_strong)
                                                    .text_size(px(11.0))
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_subtle))
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.pick_backup_import_path(cx);
                                                    }))
                                                    .child("Browse File..."),
                                            ),
                                    ),
                            )
                            .child(self.backup_path.clone()),
                    )
                    .child(self.labeled_field(
                        t,
                        "Backup Passphrase",
                        self.backup_passphrase.clone(),
                    ))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .pt_1()
                            .child(
                                div()
                                    .id("set-export-backup")
                                    .flex_1()
                                    .py_2()
                                    .rounded_lg()
                                    .bg(t.accent_solid)
                                    .text_color(gpui::white())
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_center()
                                    .cursor_pointer()
                                    .hover(|s| s.opacity(0.92))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.export_vault_backup(cx);
                                    }))
                                    .child("Export Backup"),
                            )
                            .child(
                                div()
                                    .id("set-import-backup")
                                    .flex_1()
                                    .py_2()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.import_vault_backup(cx);
                                    }))
                                    .child("Import Backup"),
                            ),
                    ),
            )
            .child(
                div()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .p_4()
                    .flex()
                    .flex_col()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2p5()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Vault Auto-Lock & Diagnostics"),
                            )
                            // Auto-Lock Idle Timer Selector (Phase 3)
                            .child(
                                div()
                                    .p_3()
                                    .rounded_xl()
                                    .bg(t.bg_subtle)
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(t.text_primary)
                                            .child("Auto-Lock Vault After Inactivity"),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_muted)
                                            .child("Locks the decrypted vault key in memory when idle."),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap_1p5()
                                            .pt_0p5()
                                            .children(
                                                [
                                                    (0u32, "Off"),
                                                    (5, "5m"),
                                                    (15, "15m"),
                                                    (30, "30m"),
                                                    (60, "60m"),
                                                ]
                                                .into_iter()
                                                .enumerate()
                                                .map(|(ix, (mins, lbl))| {
                                                    let active =
                                                        self.settings.auto_lock_minutes == mins;
                                                    div()
                                                        .id(("set-autolock", ix))
                                                        .px_2p5()
                                                        .py_1()
                                                        .rounded_md()
                                                        .border_1()
                                                        .text_xs()
                                                        .font_family("Consolas")
                                                        .cursor_pointer()
                                                        .bg(if active {
                                                            t.accent_soft
                                                        } else {
                                                            t.bg_card
                                                        })
                                                        .border_color(if active {
                                                            t.accent
                                                        } else {
                                                            t.border
                                                        })
                                                        .text_color(if active {
                                                            t.accent
                                                        } else {
                                                            t.text_primary
                                                        })
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.settings.auto_lock_minutes =
                                                                    mins;
                                                                this.save_settings(cx);
                                                            },
                                                        ))
                                                        .child(lbl)
                                                }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .p_3()
                                    .rounded_xl()
                                    .bg(t.bg_subtle)
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .text_xs()
                                    .child(format!(
                                        "OS Keychain Unlock: {}",
                                        if self.vault_status.keychain_enabled {
                                            "Enabled"
                                        } else {
                                            "Disabled"
                                        }
                                    ))
                                    .child(format!("Hosts: {}", self.snapshot.hosts.len()))
                                    .child(format!("Groups: {}", self.snapshot.groups.len()))
                                    .child(format!(
                                        "Port Forward Tunnels: {} ({} active)",
                                        self.snapshot.port_forwards.len(),
                                        self.active_tunnels.len()
                                    ))
                                    .child(format!(
                                        "Credentials & Keys: {}",
                                        self.snapshot.credentials.len()
                                    ))
                                    .child(format!(
                                        "Trusted Known Hosts: {}",
                                        self.snapshot.known_hosts.len()
                                    ))
                                    .child(format!(
                                        "Saved Snippets & History: {}",
                                        self.snapshot.commands.len()
                                    )),
                            ),
                    )
                    .child(
                        div()
                            .id("set-import-ssh-cfg")
                            .py_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(t.border_strong)
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .text_center()
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_subtle))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_ssh_config_import_modal(None, cx);
                            }))
                            .child("Import ~/.ssh/config (Selective Preview)..."),
                    ),
            )
    }

    fn settings_toggle_row(
        &self,
        t: &ThemePalette,
        id: &'static str,
        title: &'static str,
        subtitle: &'static str,
        enabled: bool,
        on_click: impl Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
    ) -> impl IntoElement {
        div()
            .id(id)
            .p_2p5()
            .rounded_xl()
            .bg(t.bg_subtle)
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .cursor_pointer()
            .hover(|s| s.bg(t.bg_hover))
            .on_click(on_click)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .min_w_0()
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(t.text_primary)
                            .child(title),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(t.text_muted)
                            .child(subtitle),
                    ),
            )
            .child(
                div()
                    .w(px(36.0))
                    .h(px(20.0))
                    .p(px(2.0))
                    .rounded_full()
                    .flex_shrink_0()
                    .bg(if enabled { t.accent_solid } else { t.border_strong })
                    .flex()
                    .items_center()
                    .when(enabled, |el| el.justify_end())
                    .child(
                        div()
                            .w(px(16.0))
                            .h(px(16.0))
                            .rounded_full()
                            .bg(gpui::white())
                            .shadow_sm(),
                    ),
            )
    }
}
