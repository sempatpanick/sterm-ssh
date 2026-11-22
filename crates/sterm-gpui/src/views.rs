use std::time::Duration;

use core_sftp::types::TransferStatus;
use core_vault::models::{CredentialKind, HostAuthMode, PortForwardKind};
use gpui::{
    div, ease_out_quint, prelude::*, px, relative, uniform_list, Animation, AnimationExt as _,
    AnyElement, ClipboardItem, Context, ExternalPaths, FontWeight, MouseButton, Window,
};

use crate::app::{
    ActiveModal, AdminPage, AuthScreenMode, ConfirmAction, KeychainTab, StermAdminApp,
};
use crate::command_suggestions::SuggestionSource;
use crate::icons::{icon_svg, Icon};
use crate::keybindings::ShortcutAction;
use crate::motion::{indeterminate_bar, loading_dots, loading_dots_indexed};
use crate::sftp::{
    direction_arrow, transfer_percent, DragFilePill, DragTabPill, DraggedSftpFile,
    DraggedSftpTab, SftpPaneSide,
};
use crate::split_tree::{SplitDirection, SplitNode};
use crate::theme::{env_badge_for_host, format_bytes, TerminalThemeId, ThemePalette};
use crate::tooltip::StermTooltip;

impl StermAdminApp {
    // =========================================================================
    // 1. Local-First / E2EE Account Auth & Unlock Screen
    // =========================================================================
    pub fn render_unlock_screen(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let mode = self.auth_mode;
        let busy = self.unlock_busy;
        let is_init = self.vault_status.initialized;
        let server_display = self.auth_server_url.read(cx).value().to_string();

        let subtitle = match mode {
            AuthScreenMode::Offline => {
                if is_init {
                    "Unlock your AES-256-GCM local vault (zero server required)"
                } else {
                    "Create an encrypted local vault — add E2EE Sync anytime later"
                }
            }
            AuthScreenMode::Login => "Sign in to sync across macOS & Windows",
            AuthScreenMode::Register => "Create your E2EE synced account",
        };

        let submit_label = match mode {
            AuthScreenMode::Offline => {
                if is_init {
                    "Unlock Local Vault"
                } else {
                    "Create Local Vault"
                }
            }
            AuthScreenMode::Login => "Sign In & Unlock",
            AuthScreenMode::Register => "Create Account",
        };

        let auth_tabs = [
            (AuthScreenMode::Offline, "Local Vault"),
            (AuthScreenMode::Login, "Sign In"),
            (AuthScreenMode::Register, "Create Account"),
        ];

        let unlock_card = div()
            .w(px(430.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_xl()
            .overflow_hidden()
            .flex()
            .flex_col()
            .when(busy, |el| {
                el.child(indeterminate_bar("unlock-top-bar", t.bg_subtle, t.accent))
            })
            .child(
                div()
                    .p_6()
                    .flex()
                    .flex_col()
                    .gap_4()
                    // Brand Header
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_center()
                            .gap_1p5()
                            .child(
                                div()
                                    .w(px(40.0))
                                    .h(px(40.0))
                                    .rounded_xl()
                                    .bg(t.accent_soft)
                                    .text_color(t.accent)
                                    .font_family("Consolas")
                                    .font_weight(FontWeight::BOLD)
                                    .text_sm()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(">_"),
                            )
                            .child(
                                div()
                                    .text_base()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(t.text_primary)
                                    .child("STerm SSH"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .text_center()
                                    .child(subtitle),
                            ),
                    )
                    // 3-Tab Switcher: Local Vault | Sign In | Create Account
                    .child(
                        div()
                            .grid()
                            .grid_cols(3)
                            .gap_1()
                            .p_1()
                            .rounded_xl()
                            .bg(t.bg_subtle)
                            .children(auth_tabs.into_iter().enumerate().map(|(ix, (m, lbl))| {
                                let active = mode == m;
                                div()
                                    .id(("auth-tab", ix))
                                    .py_1p5()
                                    .rounded_lg()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_center()
                                    .cursor_pointer()
                                    .bg(if active {
                                        t.bg_card
                                    } else {
                                        gpui::transparent_black()
                                    })
                                    .text_color(if active {
                                        t.text_primary
                                    } else {
                                        t.text_muted
                                    })
                                    .when(active, |s| s.shadow_sm())
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.auth_mode = m;
                                        this.toast = None;
                                        cx.notify();
                                    }))
                                    .child(lbl)
                            })),
                    )
                    // Notice / Error banner
                    .when_some(self.toast.clone(), |el, (msg, is_err)| {
                        el.child(
                            div()
                                .px_3()
                                .py_2()
                                .rounded_lg()
                                .border_1()
                                .bg(if is_err { t.danger_soft } else { t.success_soft })
                                .border_color(if is_err { t.danger } else { t.success })
                                .text_xs()
                                .text_color(if is_err { t.danger } else { t.success })
                                .child(msg),
                        )
                    })
                    .when(mode != AuthScreenMode::Offline, |el| {
                        el.child(self.labeled_field(t, "Email", self.auth_email.clone()))
                    })
                    .child(self.labeled_field(t, "Master Password", self.unlock_password.clone()))
                    .when(
                        mode == AuthScreenMode::Register
                            || (mode == AuthScreenMode::Offline && !is_init),
                        |el| {
                            el.child(self.labeled_field(
                                t,
                                "Confirm Password",
                                self.unlock_confirm.clone(),
                            ))
                        },
                    )
                    // Stay Signed In / OS Keychain
                    .child(
                        div()
                            .id("auth-stay-signed-in")
                            .flex()
                            .items_center()
                            .gap_2()
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.auth_stay_signed_in = !this.auth_stay_signed_in;
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .w(px(15.0))
                                    .h(px(15.0))
                                    .rounded(px(4.0))
                                    .border_1()
                                    .border_color(if self.auth_stay_signed_in {
                                        t.accent_solid
                                    } else {
                                        t.border_strong
                                    })
                                    .bg(if self.auth_stay_signed_in {
                                        t.accent_solid
                                    } else {
                                        t.bg_card
                                    })
                                    .text_color(gpui::white())
                                    .text_size(px(10.0))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(if self.auth_stay_signed_in { "✓" } else { "" }),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_secondary)
                                    .child("Remember vault key in OS Keychain on this device"),
                            ),
                    )
                    // Primary Submit Button
                    .child(
                        div()
                            .id("unlock-submit-btn")
                            .w_full()
                            .h(px(38.0))
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
                                this.submit_unlock_or_init(cx);
                            }))
                            .when(busy, |el| {
                                el.child(loading_dots("unlock-btn-dots", gpui::white()))
                                    .child("Unlocking...")
                            })
                            .when(!busy, |el| el.child(submit_label)),
                    )
                    // Biometric / OS Keychain Quick-Unlock Button (when keychain key is saved)
                    .when(is_init && self.vault_status.keychain_enabled, |el| {
                        let bio_lbl = if self.settings.biometric_unlock {
                            "Unlock with Biometrics (Windows Hello / Touch ID)"
                        } else {
                            "Quick Unlock with OS Keychain"
                        };
                        el.child(
                            div()
                                .id("unlock-biometric-btn")
                                .w_full()
                                .h(px(36.0))
                                .rounded_lg()
                                .bg(t.bg_subtle)
                                .border_1()
                                .border_color(t.border_strong)
                                .text_color(t.text_primary)
                                .text_xs()
                                .font_weight(FontWeight::MEDIUM)
                                .flex()
                                .items_center()
                                .justify_center()
                                .gap_2()
                                .cursor_pointer()
                                .hover(|s| s.border_color(t.accent).text_color(t.accent))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.trigger_biometric_unlock(cx);
                                }))
                                .child(icon_svg(Icon::Shield, 13.0, t.accent))
                                .child(bio_lbl),
                        )
                    })
                    // Account Server URL editor (Sign In & Create Account)
                    .when(mode != AuthScreenMode::Offline, |el| {
                        el.child(
                            div()
                                .pt_3()
                                .border_t_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .gap_1p5()
                                .when(self.auth_editing_server, |s| {
                                    s.child(
                                        div()
                                            .text_size(px(10.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_muted)
                                            .child("SYNC SERVER URL"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child(div().flex_1().child(self.auth_server_url.clone()))
                                            .child(
                                                div()
                                                    .id("auth-server-done")
                                                    .px_2p5()
                                                    .py_1p5()
                                                    .rounded_lg()
                                                    .bg(t.bg_subtle)
                                                    .border_1()
                                                    .border_color(t.border_strong)
                                                    .text_xs()
                                                    .cursor_pointer()
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.auth_editing_server = false;
                                                        cx.notify();
                                                    }))
                                                    .child("Done"),
                                            ),
                                    )
                                })
                                .when(!self.auth_editing_server, |s| {
                                    s.child(
                                        div()
                                            .id("auth-server-edit")
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .gap_1p5()
                                            .text_size(px(11.0))
                                            .font_family("Consolas")
                                            .text_color(t.text_muted)
                                            .cursor_pointer()
                                            .hover(|h| h.text_color(t.text_primary))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.auth_editing_server = true;
                                                cx.notify();
                                            }))
                                            .child("☁")
                                            .child(server_display),
                                    )
                                }),
                        )
                    }),
            );

        div()
            .size_full()
            .bg(t.bg_canvas)
            .text_color(t.text_primary)
            .flex()
            .items_center()
            .justify_center()
            .p_6()
            .child(unlock_card)
    }

    // =========================================================================
    // 2. Hosts Vault Home Page (Groups, Tags, ~/.ssh Discovery, Inventory Table)
    // =========================================================================
    pub fn render_servers_page(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let query = self.server_search.read(cx).value().trim().to_lowercase();
        let active_group = self.selected_group_filter.clone();
        let active_tag = self.selected_tag_filter.clone();
        let compact = self.settings.compact_density;
        let is_grid = self.settings.host_view_grid;

        let mut quick_hosts: Vec<_> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| h.favorite || h.last_connected_at.is_some())
            .cloned()
            .collect();
        quick_hosts.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| b.last_connected_at.cmp(&a.last_connected_at))
                .then_with(|| a.label.cmp(&b.label))
        });
        quick_hosts.truncate(6);

        let filtered: Vec<_> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| {
                if let Some(ref gid) = active_group
                    && h.group_id.as_deref() != Some(gid.as_str()) {
                        return false;
                    }
                if let Some(ref tag) = active_tag
                    && !h.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                        return false;
                    }
                if query.is_empty() {
                    return true;
                }
                h.label.to_lowercase().contains(&query)
                    || h.hostname.to_lowercase().contains(&query)
                    || h.username.to_lowercase().contains(&query)
                    || h.tags.iter().any(|tag| tag.to_lowercase().contains(&query))
            })
            .cloned()
            .collect();

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            // Favorites & Recently Connected Quick-Launch Strip
            .when(!quick_hosts.is_empty(), |el| {
                el.child(
                    div()
                        .px_3()
                        .py_2()
                        .rounded_xl()
                        .bg(t.bg_card)
                        .border_1()
                        .border_color(t.border)
                        .shadow_sm()
                        .flex()
                        .items_center()
                        .gap_2()
                        .overflow_x_hidden()
                        .child(
                            div()
                                .text_size(px(10.0))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(t.text_muted)
                                .whitespace_nowrap()
                                .child("QUICK LAUNCH"),
                        )
                        .children(quick_hosts.into_iter().enumerate().map(|(ix, qh)| {
                            let hid = qh.id.clone();
                            let prefix = if qh.favorite { "★" } else { "⏱" };
                            let rtt = self.host_latencies.get(&qh.id).copied().flatten();
                            div()
                                .id(("quick-host", ix))
                                .px_2p5()
                                .py_1()
                                .rounded_lg()
                                .bg(t.bg_subtle)
                                .border_1()
                                .border_color(t.border)
                                .hover(|s| s.border_color(t.accent).bg(t.accent_soft))
                                .flex()
                                .items_center()
                                .gap_1p5()
                                .flex_shrink_0()
                                .cursor_pointer()
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.connect_host_ssh(hid.clone(), window, cx);
                                }))
                                .child(
                                    div()
                                        .text_size(px(11.0))
                                        .text_color(if qh.favorite {
                                            t.warning
                                        } else {
                                            t.text_muted
                                        })
                                        .child(prefix),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(t.text_primary)
                                        .child(qh.label),
                                )
                                .when_some(rtt, |s, ms| {
                                    s.child(
                                        div()
                                            .text_size(px(10.0))
                                            .font_family("Consolas")
                                            .text_color(if ms < 100 {
                                                t.success
                                            } else {
                                                t.warning
                                            })
                                            .child(format!("{ms}ms")),
                                    )
                                })
                        })),
                )
            })
            // Local ~/.ssh Auto-Discovery Banner (first-launch / newly detected hosts & keys)
            .when_some(self.ssh_discovery.clone(), |el, info| {
                let preview = info
                    .host_aliases
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                el.child(
                    div()
                        .px_4()
                        .py_3()
                        .rounded_xl()
                        .bg(t.accent_soft)
                        .border_1()
                        .border_color(t.accent)
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_0p5()
                                .min_w_0()
                                .child(
                                    div()
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(t.accent)
                                        .child(format!(
                                            "Found {} new host(s) and {} key(s) in {}",
                                            info.new_hosts_count,
                                            info.new_keys_count,
                                            info.ssh_dir_path
                                        )),
                                )
                                .when(!preview.is_empty(), |s| {
                                    s.child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_family("Consolas")
                                            .text_color(t.text_secondary)
                                            .child(format!("Detected: {preview}")),
                                    )
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .flex_shrink_0()
                                .child(
                                    div()
                                        .id("ssh-disc-auto")
                                        .flex()
                                        .items_center()
                                        .gap_1p5()
                                        .text_size(px(11.0))
                                        .text_color(t.text_secondary)
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.ssh_discovery_allow_auto =
                                                !this.ssh_discovery_allow_auto;
                                            cx.notify();
                                        }))
                                        .child(if self.ssh_discovery_allow_auto {
                                            "☑ Auto-import"
                                        } else {
                                            "☐ Auto-import"
                                        }),
                                )
                                .child(
                                    div()
                                        .id("ssh-disc-skip")
                                        .px_2p5()
                                        .py_1()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(t.border_strong)
                                        .bg(t.bg_card)
                                        .text_xs()
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.confirm_local_ssh_discovery(false, false, cx);
                                        }))
                                        .child("Skip"),
                                )
                                .child(
                                    div()
                                        .id("ssh-disc-import")
                                        .px_3()
                                        .py_1()
                                        .rounded_lg()
                                        .bg(t.accent_solid)
                                        .text_color(gpui::white())
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            let auto = this.ssh_discovery_allow_auto;
                                            this.confirm_local_ssh_discovery(true, auto, cx);
                                        }))
                                        .child("Import to Vault"),
                                ),
                        ),
                )
            })
            // Toolbar: Group Filter Pills + Tag Filter + Search + Import SSH Config + Add Host
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2p5()
                    .flex_wrap()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .flex_wrap()
                            .child(
                                div()
                                    .id("grp-filter-all")
                                    .px_2p5()
                                    .py_1()
                                    .rounded_lg()
                                    .border_1()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .cursor_pointer()
                                    .bg(if active_group.is_none() {
                                        t.accent_soft
                                    } else {
                                        t.bg_card
                                    })
                                    .border_color(if active_group.is_none() {
                                        t.accent
                                    } else {
                                        t.border
                                    })
                                    .text_color(if active_group.is_none() {
                                        t.accent
                                    } else {
                                        t.text_secondary
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.selected_group_filter = None;
                                        cx.notify();
                                    }))
                                    .child(format!("All ({})", self.snapshot.hosts.len())),
                            )
                            .children(self.snapshot.groups.iter().enumerate().map(|(ix, g)| {
                                let is_sel = active_group.as_deref() == Some(g.id.as_str());
                                let gid = g.id.clone();
                                let g_edit = g.clone();
                                let g_path = self.group_display_path(&g.id);
                                let count = self
                                    .snapshot
                                    .hosts
                                    .iter()
                                    .filter(|h| h.group_id.as_deref() == Some(g.id.as_str()))
                                    .count();
                                div()
                                    .id(("grp-pill", ix))
                                    .px_2p5()
                                    .py_1()
                                    .rounded_lg()
                                    .border_1()
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .cursor_pointer()
                                    .bg(if is_sel { t.accent_soft } else { t.bg_card })
                                    .border_color(if is_sel { t.accent } else { t.border })
                                    .text_color(if is_sel { t.accent } else { t.text_secondary })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_group_filter = Some(gid.clone());
                                        cx.notify();
                                    }))
                                    .child(format!("{g_path} ({count})"))
                                    .when(is_sel, |el| {
                                        el.child(
                                            div()
                                                .id(("grp-edit-btn", ix))
                                                .px_1()
                                                .rounded_sm()
                                                .text_size(px(10.0))
                                                .hover(|s| s.bg(t.bg_card))
                                                .tooltip(StermTooltip::text("Edit Group", *t))
                                                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                                    cx.stop_propagation();
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    cx.stop_propagation();
                                                    this.open_group_editor(Some(&g_edit), cx);
                                                }))
                                                .child("✎"),
                                        )
                                    })
                            }))
                            .child(
                                div()
                                    .id("grp-add-new")
                                    .px_2()
                                    .py_1()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(t.border)
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle).text_color(t.text_primary))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_group_editor(None, cx);
                                    }))
                                    .child("+ Group"),
                            )
                            .when_some(active_tag, |el, tag| {
                                el.child(
                                    div()
                                        .id("clear-tag-filter")
                                        .px_2()
                                        .py_1()
                                        .rounded_lg()
                                        .bg(t.accent_soft)
                                        .border_1()
                                        .border_color(t.accent)
                                        .text_xs()
                                        .text_color(t.accent)
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.selected_tag_filter = None;
                                            cx.notify();
                                        }))
                                        .child(format!("#{tag} ✕")),
                                )
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .child(div().w(px(200.0)).child(self.server_search.clone()))
                            .child(
                                div()
                                    .id("hosts-ping-btn")
                                    .px_2p5()
                                    .py_1p5()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .bg(t.bg_card)
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.probe_all_host_latencies(cx);
                                    }))
                                    .child(if self.latency_probing {
                                        "Pinging..."
                                    } else {
                                        "Ping"
                                    }),
                            )
                            .child(
                                div()
                                    .id("hosts-view-toggle")
                                    .px_2p5()
                                    .py_1p5()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .bg(t.bg_card)
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.settings.host_view_grid =
                                            !this.settings.host_view_grid;
                                        this.save_settings(cx);
                                    }))
                                    .child(if is_grid { "Table" } else { "Grid" }),
                            )
                            .child(
                                div()
                                    .id("hosts-import-ssh")
                                    .px_2p5()
                                    .py_1p5()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .bg(t.bg_card)
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_ssh_config_import_modal(None, cx);
                                    }))
                                    .child("Import"),
                            )
                            .child(
                                div()
                                    .id("hosts-export-ssh")
                                    .px_2p5()
                                    .py_1p5()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .bg(t.bg_card)
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.export_ssh_config_dialog(cx);
                                    }))
                                    .child("Export"),
                            )
                            .child(
                                div()
                                    .id("hosts-add-btn")
                                    .px_3p5()
                                    .py_1p5()
                                    .rounded_lg()
                                    .bg(t.accent_solid)
                                    .text_color(gpui::white())
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .cursor_pointer()
                                    .hover(|s| s.opacity(0.92))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_add_host_modal(None, cx);
                                    }))
                                    .child("+ Add Host"),
                            ),
                    ),
            )
            // Hosts Table or 3-Col Card Grid
            .child(if is_grid {
                div()
                    .id("hosts-grid-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .when(filtered.is_empty(), |el| {
                        el.child(
                            div()
                                .py_12()
                                .rounded_xl()
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border)
                                .flex()
                                .flex_col()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(t.text_secondary)
                                        .child("No servers match the current filter"),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(t.text_muted)
                                        .child("Add a server, import ~/.ssh/config, or press Ctrl+K for Quick Connect."),
                                ),
                        )
                    })
                    .when(!filtered.is_empty(), |el| {
                        el.child(
                            div()
                                .grid()
                                .grid_cols(3)
                                .gap_3()
                                .children(filtered.iter().cloned().enumerate().map(|(ix, h)| {
                                    let group_name = h
                                        .group_id
                                        .as_deref()
                                        .map(|gid| self.group_display_path(gid));
                                    let env_badge =
                                        env_badge_for_host(&h.tags, group_name.as_deref(), t);
                                    let is_live = self.terminal_tabs.iter().any(|p| {
                                        p.host_id.as_deref() == Some(h.id.as_str()) && p.connected
                                    });
                                    let latency = self.host_latencies.get(&h.id).copied();
                                    let auth_label = match h.auth_mode {
                                        HostAuthMode::SshAgent => "Agent",
                                        HostAuthMode::KeyboardInteractive => "2FA",
                                        HostAuthMode::Credential => h
                                            .credential_id
                                            .as_deref()
                                            .and_then(|cid| {
                                                self.snapshot
                                                    .credentials
                                                    .iter()
                                                    .find(|c| c.id == cid)
                                            })
                                            .map(|c| match c.kind {
                                                CredentialKind::Password => "Password",
                                                CredentialKind::PrivateKey => "Key",
                                                CredentialKind::Certificate => "Cert",
                                                CredentialKind::SshAgent => "Agent",
                                                CredentialKind::KeyboardInteractive => "2FA",
                                            })
                                            .unwrap_or("Default"),
                                    };
                                    let hid_fav = h.id.clone();
                                    let hid_ssh = h.id.clone();
                                    let hid_sftp = h.id.clone();
                                    let hid_clone = h.id.clone();
                                    let host_edit = h.clone();
                                    let hid_del = h.id.clone();
                                    let hlabel_del = h.label.clone();

                                    div()
                                        .id(("host-card", ix))
                                        .p_3p5()
                                        .rounded_xl()
                                        .bg(t.bg_card)
                                        .border_1()
                                        .border_color(t.border)
                                        .shadow_sm()
                                        .hover(|s| s.border_color(t.accent))
                                        .flex()
                                        .flex_col()
                                        .justify_between()
                                        .gap_2p5()
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
                                                        .gap_1p5()
                                                        .child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_1p5()
                                                                .min_w_0()
                                                                .child(
                                                                    div()
                                                                        .id(("hc-fav", ix))
                                                                        .text_xs()
                                                                        .cursor_pointer()
                                                                        .tooltip(StermTooltip::text(
                                                                            if h.favorite {
                                                                                "Remove from Favorites"
                                                                            } else {
                                                                                "Pin to Favorites"
                                                                            },
                                                                            *t,
                                                                        ))
                                                                        .text_color(if h.favorite {
                                                                            t.warning
                                                                        } else {
                                                                            t.text_muted
                                                                        })
                                                                        .on_click(cx.listener(
                                                                            move |this, _, _, cx| {
                                                                                this.toggle_host_favorite(
                                                                                    hid_fav.clone(),
                                                                                    cx,
                                                                                );
                                                                            },
                                                                        ))
                                                                        .child(if h.favorite {
                                                                            "★"
                                                                        } else {
                                                                            "☆"
                                                                        }),
                                                                )
                                                                .child(
                                                                    div()
                                                                        .w(px(7.0))
                                                                        .h(px(7.0))
                                                                        .rounded_full()
                                                                        .flex_shrink_0()
                                                                        .bg(if is_live {
                                                                            t.success
                                                                        } else {
                                                                            t.border_strong
                                                                        }),
                                                                )
                                                                .child(
                                                                    div()
                                                                        .text_xs()
                                                                        .font_weight(
                                                                            FontWeight::SEMIBOLD,
                                                                        )
                                                                        .text_color(t.text_primary)
                                                                        .truncate()
                                                                        .child(h.label.clone()),
                                                                ),
                                                        )
                                                        .child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_1()
                                                                .flex_shrink_0()
                                                                .when_some(
                                                                    env_badge,
                                                                    |s, (ecol, elbl)| {
                                                                        s.child(
                                                                            div()
                                                                                .px_1()
                                                                                .py(px(1.0))
                                                                                .rounded_sm()
                                                                                .border_1()
                                                                                .border_color(ecol)
                                                                                .text_size(px(9.0))
                                                                                .font_weight(
                                                                                    FontWeight::BOLD,
                                                                                )
                                                                                .text_color(ecol)
                                                                                .child(elbl),
                                                                        )
                                                                    },
                                                                )
                                                                .when_some(latency, |s, opt_ms| {
                                                                    let (txt, col) = match opt_ms {
                                                                        Some(ms) if ms < 100 => (
                                                                            format!("{ms}ms"),
                                                                            t.success,
                                                                        ),
                                                                        Some(ms) => (
                                                                            format!("{ms}ms"),
                                                                            t.warning,
                                                                        ),
                                                                        None => (
                                                                            "offline".to_string(),
                                                                            t.danger,
                                                                        ),
                                                                    };
                                                                    s.child(
                                                                        div()
                                                                            .text_size(px(10.0))
                                                                            .font_family("Consolas")
                                                                            .text_color(col)
                                                                            .child(txt),
                                                                    )
                                                                }),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .font_family("Consolas")
                                                        .text_size(px(11.0))
                                                        .text_color(t.text_secondary)
                                                        .truncate()
                                                        .child(format!(
                                                            "{}@{}:{}",
                                                            h.username, h.hostname, h.port
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .flex_wrap()
                                                        .gap_1()
                                                        .when_some(group_name, |s, gn| {
                                                            s.child(
                                                                div()
                                                                    .px_1p5()
                                                                    .py_0p5()
                                                                    .rounded_sm()
                                                                    .bg(t.bg_subtle)
                                                                    .text_size(px(10.0))
                                                                    .text_color(t.text_secondary)
                                                                    .child(gn),
                                                            )
                                                        })
                                                        .child(
                                                            div()
                                                                .px_1p5()
                                                                .py_0p5()
                                                                .rounded_sm()
                                                                .bg(t.bg_subtle)
                                                                .text_size(px(10.0))
                                                                .text_color(t.text_muted)
                                                                .child(auth_label),
                                                        )
                                                        .when(h.forward_agent, |s| {
                                                            s.child(
                                                                div()
                                                                    .px_1()
                                                                    .py_0p5()
                                                                    .rounded_sm()
                                                                    .bg(t.accent_soft)
                                                                    .text_size(px(9.0))
                                                                    .font_family("Consolas")
                                                                    .text_color(t.accent)
                                                                    .child("-A"),
                                                            )
                                                        })
                                                        .when(h.proxy_url.is_some(), |s| {
                                                            s.child(
                                                                div()
                                                                    .px_1()
                                                                    .py_0p5()
                                                                    .rounded_sm()
                                                                    .bg(t.accent_soft)
                                                                    .text_size(px(9.0))
                                                                    .text_color(t.accent)
                                                                    .child("Proxy"),
                                                            )
                                                        }),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .justify_between()
                                                .pt_1p5()
                                                .border_t_1()
                                                .border_color(t.border)
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .gap_1()
                                                        .child(
                                                            div()
                                                                .id(("hc-ssh", ix))
                                                                .px_2p5()
                                                                .py_1()
                                                                .rounded_md()
                                                                .bg(t.accent_solid)
                                                                .text_color(gpui::white())
                                                                .text_size(px(11.0))
                                                                .font_weight(FontWeight::SEMIBOLD)
                                                                .cursor_pointer()
                                                                .on_click(cx.listener(
                                                                    move |this, _, window, cx| {
                                                                        this.connect_host_ssh(
                                                                            hid_ssh.clone(),
                                                                            window,
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                                .child("SSH"),
                                                        )
                                                        .child(
                                                            div()
                                                                .id(("hc-sftp", ix))
                                                                .px_2()
                                                                .py_1()
                                                                .rounded_md()
                                                                .border_1()
                                                                .border_color(t.border_strong)
                                                                .text_size(px(11.0))
                                                                .text_color(t.text_secondary)
                                                                .cursor_pointer()
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        this.open_sftp_for_host(
                                                                            hid_sftp.clone(),
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                                .child("SFTP"),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .gap_1()
                                                        .child(
                                                            div()
                                                                .id(("hc-clone", ix))
                                                                .px_1p5()
                                                                .py_1()
                                                                .rounded_md()
                                                                .text_size(px(10.0))
                                                                .text_color(t.text_muted)
                                                                .cursor_pointer()
                                                                .hover(|s| s.bg(t.bg_subtle))
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        this.clone_host(
                                                                            hid_clone.clone(),
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                                .child("Clone"),
                                                        )
                                                        .child(
                                                            div()
                                                                .id(("hc-edit", ix))
                                                                .px_1p5()
                                                                .py_1()
                                                                .rounded_md()
                                                                .text_size(px(10.0))
                                                                .text_color(t.text_muted)
                                                                .cursor_pointer()
                                                                .hover(|s| s.bg(t.bg_subtle))
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        this.open_add_host_modal(
                                                                            Some(&host_edit),
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                                .child("Edit"),
                                                        )
                                                        .child(
                                                            div()
                                                                .id(("hc-del", ix))
                                                                .px_1()
                                                                .py_1()
                                                                .rounded_md()
                                                                .text_size(px(10.0))
                                                                .text_color(t.text_muted)
                                                                .cursor_pointer()
                                                                .hover(|s| {
                                                                    s.bg(t.danger_soft)
                                                                        .text_color(t.danger)
                                                                })
                                                                .tooltip(StermTooltip::text(
                                                                    "Delete Host",
                                                                    *t,
                                                                ))
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        this.request_confirm(
                                                                            ConfirmAction::DeleteHost {
                                                                                id: hid_del.clone(),
                                                                                label: hlabel_del
                                                                                    .clone(),
                                                                            },
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                                .child("✕"),
                                                        ),
                                                ),
                                        )
                                })),
                        )
                    })
                    .into_any_element()
            } else {
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .flex()
                    .flex_col()
                    .overflow_hidden()
                    // Table Header
                    .child(
                        div()
                            .px_4()
                            .py_2()
                            .bg(t.bg_subtle)
                            .border_b_1()
                            .border_color(t.border)
                            .grid()
                            .grid_cols(12)
                            .gap_2()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text_muted)
                            .child(div().col_span(3).child("SERVER"))
                            .child(div().col_span(3).child("ADDRESS"))
                            .child(div().col_span(2).child("GROUP & TAGS"))
                            .child(div().col_span(1).child("AUTH"))
                            .child(div().col_span(3).text_right().child("ACTIONS")),
                    )
                    // Table Body
                    .child(
                        div()
                            .id("hosts-table-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .when(filtered.is_empty(), |el| {
                                el.child(
                                    div()
                                        .py_12()
                                        .flex()
                                        .flex_col()
                                        .items_center()
                                        .gap_2()
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_weight(FontWeight::MEDIUM)
                                                .text_color(t.text_secondary)
                                                .child("No servers match the current filter"),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(t.text_muted)
                                                .child("Add a server, import ~/.ssh/config, or press Ctrl+K for Quick Connect."),
                                        ),
                                )
                            })
                            .children(filtered.into_iter().enumerate().map(|(ix, h)| {
                                let group_name = h
                                    .group_id
                                    .as_deref()
                                    .map(|gid| self.group_display_path(gid));
                                let jump_label = h
                                    .jump_host_id
                                    .as_deref()
                                    .and_then(|jid| {
                                        self.snapshot.hosts.iter().find(|x| x.id == jid)
                                    })
                                    .map(|j| j.label.clone());
                                let auth_label = match h.auth_mode {
                                    HostAuthMode::SshAgent => "Agent",
                                    HostAuthMode::KeyboardInteractive => "2FA",
                                    HostAuthMode::Credential => h
                                        .credential_id
                                        .as_deref()
                                        .and_then(|cid| {
                                            self.snapshot.credentials.iter().find(|c| c.id == cid)
                                        })
                                        .map(|c| match c.kind {
                                            CredentialKind::Password => "Password",
                                            CredentialKind::PrivateKey => "Key",
                                            CredentialKind::Certificate => "Cert",
                                            CredentialKind::SshAgent => "Agent",
                                            CredentialKind::KeyboardInteractive => "2FA",
                                        })
                                        .unwrap_or("Default"),
                                };
                                let latency = self.host_latencies.get(&h.id).copied();

                                let is_live = self.terminal_tabs.iter().any(|p| {
                                    p.host_id.as_deref() == Some(h.id.as_str()) && p.connected
                                });
                                let env_badge =
                                    env_badge_for_host(&h.tags, group_name.as_deref(), t);

                                let hid_fav = h.id.clone();
                                let hid_ssh = h.id.clone();
                                let hid_sftp = h.id.clone();
                                let hid_clone = h.id.clone();
                                let host_edit = h.clone();
                                let hid_del = h.id.clone();
                                let hlabel_del = h.label.clone();

                                div()
                                    .id(("host-row", ix))
                                    .px_4()
                                    .py(if compact { px(7.0) } else { px(11.0) })
                                    .border_b_1()
                                    .border_color(t.border)
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .grid()
                                    .grid_cols(12)
                                    .gap_2()
                                    .items_center()
                                    // Col 1: Star + Live dot + Server Name + Env Badge + ProxyJump/Proxy/-A
                                    .child(
                                        div()
                                            .col_span(3)
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .id(("hr-fav", ix))
                                                    .text_xs()
                                                    .flex_shrink_0()
                                                    .cursor_pointer()
                                                    .tooltip(StermTooltip::text(
                                                        if h.favorite {
                                                            "Remove from Favorites"
                                                        } else {
                                                            "Pin to Favorites"
                                                        },
                                                        *t,
                                                    ))
                                                    .text_color(if h.favorite {
                                                        t.warning
                                                    } else {
                                                        t.text_muted
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.toggle_host_favorite(
                                                            hid_fav.clone(),
                                                            cx,
                                                        );
                                                    }))
                                                    .child(if h.favorite { "★" } else { "☆" }),
                                            )
                                            .child(
                                                div()
                                                    .w(px(7.0))
                                                    .h(px(7.0))
                                                    .rounded_full()
                                                    .flex_shrink_0()
                                                    .bg(if is_live {
                                                        t.success
                                                    } else {
                                                        t.border_strong
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .min_w_0()
                                                    .child(
                                                        div()
                                                            .flex()
                                                            .items_center()
                                                            .gap_1p5()
                                                            .min_w_0()
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .font_weight(
                                                                        FontWeight::SEMIBOLD,
                                                                    )
                                                                    .text_color(t.text_primary)
                                                                    .truncate()
                                                                    .child(h.label.clone()),
                                                            )
                                                            .when_some(
                                                                env_badge,
                                                                |el, (ecol, elbl)| {
                                                                    let ebg = match elbl {
                                                                        "PROD" => t.danger_soft,
                                                                        "STAGING" => t.warning_soft,
                                                                        _ => t.success_soft,
                                                                    };
                                                                    el.child(
                                                                        div()
                                                                            .px_1()
                                                                            .py(px(1.0))
                                                                            .rounded_sm()
                                                                            .flex_shrink_0()
                                                                            .bg(ebg)
                                                                            .border_1()
                                                                            .border_color(ecol)
                                                                            .text_size(px(9.0))
                                                                            .font_weight(
                                                                                FontWeight::BOLD,
                                                                            )
                                                                            .text_color(ecol)
                                                                            .child(elbl),
                                                                    )
                                                                },
                                                            )
                                                            .when(h.forward_agent, |el| {
                                                                el.child(
                                                                    div()
                                                                        .px_1()
                                                                        .py(px(1.0))
                                                                        .rounded_sm()
                                                                        .flex_shrink_0()
                                                                        .bg(t.accent_soft)
                                                                        .text_size(px(9.0))
                                                                        .font_family("Consolas")
                                                                        .text_color(t.accent)
                                                                        .child("-A"),
                                                                )
                                                            }),
                                                    )
                                                    .when_some(jump_label, |s, jl| {
                                                        s.child(
                                                            div()
                                                                .text_size(px(10.0))
                                                                .text_color(t.accent)
                                                                .truncate()
                                                                .child(format!("↳ via {jl}")),
                                                        )
                                                    })
                                                    .when_some(h.proxy_url.clone(), |s, px_url| {
                                                        s.child(
                                                            div()
                                                                .text_size(px(10.0))
                                                                .font_family("Consolas")
                                                                .text_color(t.text_muted)
                                                                .truncate()
                                                                .child(format!("⇄ {px_url}")),
                                                        )
                                                    }),
                                            ),
                                    )
                                    // Col 2: Address + TCP Latency Ping Pill
                                    .child(
                                        div()
                                            .col_span(3)
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .font_family("Consolas")
                                                    .text_xs()
                                                    .text_color(t.text_secondary)
                                                    .truncate()
                                                    .child(format!(
                                                        "{}@{}:{}",
                                                        h.username, h.hostname, h.port
                                                    )),
                                            )
                                            .when_some(latency, |s, opt_ms| {
                                                let (txt, col, bg) = match opt_ms {
                                                    Some(ms) if ms < 100 => {
                                                        (format!("{ms}ms"), t.success, t.success_soft)
                                                    }
                                                    Some(ms) => {
                                                        (format!("{ms}ms"), t.warning, t.warning_soft)
                                                    }
                                                    None => {
                                                        ("offline".to_string(), t.danger, t.danger_soft)
                                                    }
                                                };
                                                s.child(
                                                    div()
                                                        .px_1p5()
                                                        .py(px(1.0))
                                                        .rounded_sm()
                                                        .flex_shrink_0()
                                                        .bg(bg)
                                                        .font_family("Consolas")
                                                        .text_size(px(10.0))
                                                        .text_color(col)
                                                        .child(txt),
                                                )
                                            }),
                                    )
                                    // Col 3: Group + Clickable Tags
                                    .child(
                                        div()
                                            .col_span(2)
                                            .flex()
                                            .items_center()
                                            .gap_1()
                                            .flex_wrap()
                                            .when_some(group_name, |s, gn| {
                                                s.child(
                                                    div()
                                                        .px_1p5()
                                                        .py_0p5()
                                                        .rounded_sm()
                                                        .bg(t.bg_subtle)
                                                        .border_1()
                                                        .border_color(t.border)
                                                        .text_size(px(10.0))
                                                        .text_color(t.text_secondary)
                                                        .child(gn),
                                                )
                                            })
                                            .children(h.tags.iter().take(2).enumerate().map(
                                                |(t_ix, tag)| {
                                                    let tag_click = tag.clone();
                                                    div()
                                                        .id(("htag", ix * 10 + t_ix))
                                                        .px_1p5()
                                                        .py_0p5()
                                                        .rounded_sm()
                                                        .bg(t.accent_soft)
                                                        .text_size(px(10.0))
                                                        .text_color(t.accent)
                                                        .cursor_pointer()
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.selected_tag_filter =
                                                                    Some(tag_click.clone());
                                                                cx.notify();
                                                            },
                                                        ))
                                                        .child(format!("#{tag}"))
                                                },
                                            )),
                                    )
                                    // Col 4: Auth
                                    .child(
                                        div()
                                            .col_span(1)
                                            .text_size(px(11.0))
                                            .text_color(t.text_muted)
                                            .child(auth_label),
                                    )
                                    // Col 5: Actions (SSH, SFTP, Clone, Edit, Delete)
                                    .child(
                                        div()
                                            .col_span(3)
                                            .flex()
                                            .items_center()
                                            .justify_end()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .id(("host-ssh", ix))
                                                    .px_2p5()
                                                    .py_1()
                                                    .rounded_md()
                                                    .bg(t.accent_solid)
                                                    .text_color(gpui::white())
                                                    .text_size(px(11.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .cursor_pointer()
                                                    .hover(|s| s.opacity(0.92))
                                                    .on_click(cx.listener(
                                                        move |this, _, window, cx| {
                                                            this.connect_host_ssh(
                                                                hid_ssh.clone(),
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("SSH"),
                                            )
                                            .child(
                                                div()
                                                    .id(("host-sftp", ix))
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border_strong)
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_secondary)
                                                    .cursor_pointer()
                                                    .hover(|s| {
                                                        s.bg(t.bg_hover)
                                                            .text_color(t.text_primary)
                                                    })
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.open_sftp_for_host(
                                                                hid_sftp.clone(),
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("SFTP"),
                                            )
                                            .child(
                                                div()
                                                    .id(("host-clone", ix))
                                                    .px_1p5()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_muted)
                                                    .cursor_pointer()
                                                    .hover(|s| {
                                                        s.bg(t.bg_hover)
                                                            .text_color(t.text_primary)
                                                    })
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.clone_host(hid_clone.clone(), cx);
                                                        },
                                                    ))
                                                    .child("Clone"),
                                            )
                                            .child(
                                                div()
                                                    .id(("host-edit", ix))
                                                    .px_1p5()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_muted)
                                                    .cursor_pointer()
                                                    .hover(|s| {
                                                        s.bg(t.bg_hover)
                                                            .text_color(t.text_primary)
                                                    })
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.open_add_host_modal(
                                                                Some(&host_edit),
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("Edit"),
                                            )
                                            .child(
                                                div()
                                                    .id(("host-del", ix))
                                                    .px_1()
                                                    .py_1()
                                                    .rounded_md()
                                                    .text_size(px(11.0))
                                                    .text_color(t.text_muted)
                                                    .cursor_pointer()
                                                    .hover(|s| {
                                                        s.bg(t.danger_soft).text_color(t.danger)
                                                    })
                                                    .tooltip(StermTooltip::text("Delete Host", *t))
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.request_confirm(
                                                                ConfirmAction::DeleteHost {
                                                                    id: hid_del.clone(),
                                                                    label: hlabel_del.clone(),
                                                                },
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("✕"),
                                            ),
                                    )
                            })),
                    )
                    .into_any_element()
            })
    }

    // =========================================================================
    // 3. Live SSH Workspace Tab (Arbitrary Nested Split Panes + Search + Suggestions)
    // =========================================================================
    pub fn render_workspace_terminal_tab(
        &self,
        ws_id: &str,
        t: &ThemePalette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let Some(ws) = self.workspace_tabs.iter().find(|w| w.id == ws_id).cloned() else {
            return div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_xs()
                .text_color(t.text_muted)
                .child("No active terminal workspace.")
                .into_any_element();
        };

        let term_focused = self.terminal_focus.is_focused(window);
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .track_focus(&self.terminal_focus)
            .on_key_down(cx.listener(Self::handle_terminal_key_down))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(self.render_split_node(
                        &ws.id,
                        &ws.active_pane_id,
                        ws.broadcast_input,
                        &ws.root,
                        t,
                        term_focused,
                        cx,
                    )),
            )
            .when(self.sftp_drawer_open, |el| {
                el.child(self.render_sftp_drawer(t, cx))
            })
            .into_any_element()
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "GPUI recursive split-tree renderer needs explicit workspace flags"
    )]
    fn render_split_node(
        &self,
        ws_id: &str,
        active_pane_id: &str,
        broadcast_input: bool,
        node: &SplitNode,
        t: &ThemePalette,
        term_focused: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        match node {
            SplitNode::Leaf { pane_id } => self.render_terminal_pane(
                ws_id,
                pane_id,
                pane_id == active_pane_id,
                broadcast_input,
                t,
                term_focused,
                cx,
            ),
            SplitNode::Split {
                id,
                direction,
                ratio,
                first,
                second,
            } => {
                let first_el = self.render_split_node(
                    ws_id,
                    active_pane_id,
                    broadcast_input,
                    first,
                    t,
                    term_focused,
                    cx,
                );
                let second_el = self.render_split_node(
                    ws_id,
                    active_pane_id,
                    broadcast_input,
                    second,
                    t,
                    term_focused,
                    cx,
                );
                let ws_dec = ws_id.to_string();
                let ws_inc = ws_id.to_string();
                let sid_dec = id.clone();
                let sid_inc = id.clone();
                let r = *ratio;

                match direction {
                    SplitDirection::Horizontal => div()
                        .size_full()
                        .min_w_0()
                        .min_h_0()
                        .flex()
                        .flex_row()
                        .gap_1()
                        .child(div().w(relative(r)).h_full().min_w_0().min_h_0().child(first_el))
                        // Compact split divider with ratio nudge controls
                        .child(
                            div()
                                .w(px(12.0))
                                .h_full()
                                .flex_shrink_0()
                                .flex()
                                .flex_col()
                                .items_center()
                                .justify_center()
                                .gap_1()
                                .child(
                                    div()
                                        .id(gpui::SharedString::from(format!("sp-l-{id}")))
                                        .text_size(px(9.0))
                                        .text_color(t.text_muted)
                                        .cursor_pointer()
                                        .hover(|s| s.text_color(t.accent))
                                        .tooltip(StermTooltip::text("Shrink Left Pane", *t))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.adjust_split_ratio(
                                                &ws_dec,
                                                &sid_dec,
                                                r - 0.08,
                                                cx,
                                            );
                                        }))
                                        .child("◀"),
                                )
                                .child(
                                    div()
                                        .id(gpui::SharedString::from(format!("sp-r-{id}")))
                                        .text_size(px(9.0))
                                        .text_color(t.text_muted)
                                        .cursor_pointer()
                                        .hover(|s| s.text_color(t.accent))
                                        .tooltip(StermTooltip::text("Expand Left Pane", *t))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.adjust_split_ratio(
                                                &ws_inc,
                                                &sid_inc,
                                                r + 0.08,
                                                cx,
                                            );
                                        }))
                                        .child("▶"),
                                ),
                        )
                        .child(div().flex_1().h_full().min_w_0().min_h_0().child(second_el))
                        .into_any_element(),
                    SplitDirection::Vertical => div()
                        .size_full()
                        .min_w_0()
                        .min_h_0()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(div().h(relative(r)).w_full().min_w_0().min_h_0().child(first_el))
                        .child(
                            div()
                                .h(px(12.0))
                                .w_full()
                                .flex_shrink_0()
                                .flex()
                                .flex_row()
                                .items_center()
                                .justify_center()
                                .gap_2()
                                .child(
                                    div()
                                        .id(gpui::SharedString::from(format!("sp-u-{id}")))
                                        .text_size(px(9.0))
                                        .text_color(t.text_muted)
                                        .cursor_pointer()
                                        .hover(|s| s.text_color(t.accent))
                                        .tooltip(StermTooltip::text("Shrink Top Pane", *t))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.adjust_split_ratio(
                                                &ws_dec,
                                                &sid_dec,
                                                r - 0.08,
                                                cx,
                                            );
                                        }))
                                        .child("▲"),
                                )
                                .child(
                                    div()
                                        .id(gpui::SharedString::from(format!("sp-d-{id}")))
                                        .text_size(px(9.0))
                                        .text_color(t.text_muted)
                                        .cursor_pointer()
                                        .hover(|s| s.text_color(t.accent))
                                        .tooltip(StermTooltip::text("Expand Top Pane", *t))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.adjust_split_ratio(
                                                &ws_inc,
                                                &sid_inc,
                                                r + 0.08,
                                                cx,
                                            );
                                        }))
                                        .child("▼"),
                                ),
                        )
                        .child(div().flex_1().w_full().min_w_0().min_h_0().child(second_el))
                        .into_any_element(),
                }
            }
        }
    }

    #[expect(clippy::too_many_arguments, reason = "GPUI terminal pane renderer needs explicit workspace/pane flags")]
    fn render_terminal_pane(
        &self,
        ws_id: &str,
        pane_id: &str,
        is_active: bool,
        broadcast_input: bool,
        t: &ThemePalette,
        term_focused: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let Some(pane) = self.terminal_tabs.iter().find(|p| p.tab_id == pane_id) else {
            return div().size_full().into_any_element();
        };

        let is_connecting = !pane.connected && pane.status_line == "Connecting...";
        let show_auth_retry = !pane.connected && pane.is_auth_error;
        let has_selection = pane.has_selection();
        let is_recording = pane.transcript_file.is_some();
        let is_local = pane.is_local;
        let scrollback_off = pane.scrollback_offset();
        let hovered_url = pane.hovered_url.as_ref().map(|u| u.url.clone());
        let match_count = pane.search_matches.len();
        let active_match_num = if match_count > 0 {
            pane.active_match_idx + 1
        } else {
            0
        };
        let cursor_bottom = pane.cursor_in_bottom_half();

        let env_stripe = pane.env_label.map(|lbl| {
            let (col, soft) = match lbl {
                "PROD" => (t.danger, t.danger_soft),
                "STAGING" => (t.warning, t.warning_soft),
                _ => (t.success, t.success_soft),
            };
            (lbl, col, soft)
        });

        let (suggestions, sug_visible, _, _) = if is_active {
            self.suggestions_for_active_pane()
        } else {
            (Vec::new(), false, String::new(), None)
        };

        let pid_str = pane_id.to_string();
        let ws_str = ws_id.to_string();

        // Action clones
        let pid_copy = pid_str.clone();
        let pid_paste = pid_str.clone();
        let pid_clear = pid_str.clone();
        let sid_sftp = if is_local {
            None
        } else {
            pane.session_id.clone()
        };
        let lbl_sftp = pane.label.clone();
        let ws_bcast = ws_str.clone();
        let pid_log = pid_str.clone();
        let pid_rekey = pid_str.clone();
        let pid_drawer = pid_str.clone();
        let ws_spl_h = ws_str.clone();
        let pid_spl_h = pid_str.clone();
        let ws_spl_v = ws_str.clone();
        let pid_spl_v = pid_str.clone();
        let ws_spl_pick = ws_str.clone();
        let pid_spl_pick = pid_str.clone();
        let pid_save_qc = pid_str.clone();
        let pid_reconn = pid_str.clone();
        let ws_close = ws_str.clone();
        let pid_close = pid_str.clone();
        let ws_md = ws_str.clone();
        let pid_md = pid_str.clone();
        let pid_mm = pid_str.clone();
        let pid_mu = pid_str.clone();
        let ws_rc = ws_str.clone();
        let pid_rc = pid_str.clone();
        let pid_sw = pid_str.clone();
        let pid_live = pid_str.clone();
        let pane_host_id = pane.host_id.clone();

        let screen_el = pane.render_screen(
            t,
            &self.settings.terminal_font,
            self.settings.terminal_font_size,
            self.settings.terminal_cursor_style,
            is_active && term_focused,
            self.services.ui_tx.clone(),
        );
        let pane_term_bg: gpui::Hsla = pane
            .theme_id
            .as_deref()
            .and_then(TerminalThemeId::from_slug)
            .map(|tid| gpui::rgb(tid.colors().0).into())
            .unwrap_or(t.terminal_bg);

        let pane_border = if broadcast_input {
            t.warning
        } else if is_active {
            t.accent
        } else {
            t.border
        };

        div()
            .size_full()
            .min_w_0()
            .min_h_0()
            .rounded_xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(pane_border)
            .overflow_hidden()
            .flex()
            .flex_col()
            // Environment Safety Color Stripe (PROD=red, STAGING=amber, DEV/LOCAL=green)
            .when_some(env_stripe, |el, (_, col, _)| {
                el.child(div().h(px(3.0)).w_full().flex_shrink_0().bg(col))
            })
            // Compact 32px Pane Header
            .child(
                div()
                    .h(px(32.0))
                    .px_2p5()
                    .flex_shrink_0()
                    .bg(t.bg_subtle)
                    .border_b_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .min_w_0()
                            .child(div().w(px(7.0)).h(px(7.0)).rounded_full().flex_shrink_0().bg(
                                if pane.connected {
                                    t.success
                                } else if is_connecting {
                                    t.warning
                                } else {
                                    t.danger
                                },
                            ))
                            .when_some(env_stripe, |el, (lbl, col, soft)| {
                                el.child(
                                    div()
                                        .px_1()
                                        .py(px(1.0))
                                        .rounded_sm()
                                        .flex_shrink_0()
                                        .bg(soft)
                                        .border_1()
                                        .border_color(col)
                                        .text_size(px(9.0))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(col)
                                        .child(lbl),
                                )
                            })
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(t.text_primary)
                                    .truncate()
                                    .child(pane.label.clone()),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .font_family("Consolas")
                                    .text_color(t.text_muted)
                                    .truncate()
                                    .child(if is_local {
                                        "Local PTY".to_string()
                                    } else {
                                        format!("{}@{}:{}", pane.username, pane.hostname, pane.port)
                                    }),
                            )
                            .when(broadcast_input, |el| {
                                el.child(
                                    div()
                                        .px_1p5()
                                        .py(px(1.0))
                                        .rounded_sm()
                                        .flex_shrink_0()
                                        .bg(t.warning_soft)
                                        .border_1()
                                        .border_color(t.warning)
                                        .flex()
                                        .items_center()
                                        .gap_1()
                                        .text_size(px(9.0))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(t.warning)
                                        .child(icon_svg(Icon::Broadcast, 10.0, t.warning))
                                        .child("BROADCAST"),
                                )
                            }),
                    )
                    // Pane toolbar actions (crisp embedded Lucide SVG icons)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .flex_shrink_0()
                            // Command Suggestions
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-sug-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::with_shortcut(
                                        "Command Suggestions",
                                        self.settings
                                            .keybindings
                                            .display(ShortcutAction::ToggleSuggestions),
                                        *t,
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.suggestions_manual_open =
                                            !this.suggestions_manual_open;
                                        this.suggestions_dismissed = false;
                                        cx.notify();
                                    }))
                                    .child(icon_svg(
                                        Icon::Zap,
                                        13.0,
                                        if is_active && self.suggestions_manual_open {
                                            t.accent
                                        } else {
                                            t.text_muted
                                        },
                                    )),
                            )
                            // In-Terminal Search
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-find-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::with_shortcut(
                                        "Find in Terminal",
                                        self.settings
                                            .keybindings
                                            .display(ShortcutAction::TerminalSearch),
                                        *t,
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.term_search_open = !this.term_search_open;
                                        cx.notify();
                                    }))
                                    .child(icon_svg(
                                        Icon::Search,
                                        13.0,
                                        if is_active && self.term_search_open {
                                            t.accent
                                        } else {
                                            t.text_muted
                                        },
                                    )),
                            )
                            // Broadcast Input Toggle (multiplex keystrokes across all split panes)
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-bcast-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .bg(if broadcast_input {
                                        t.warning_soft
                                    } else {
                                        gpui::transparent_black()
                                    })
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::text(
                                        if broadcast_input {
                                            "Disable Broadcast Input"
                                        } else {
                                            "Broadcast Input to All Panes"
                                        },
                                        *t,
                                    ))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.toggle_broadcast_input(&ws_bcast, cx);
                                    }))
                                    .child(icon_svg(
                                        Icon::Broadcast,
                                        13.0,
                                        if broadcast_input {
                                            t.warning
                                        } else {
                                            t.text_muted
                                        },
                                    )),
                            )
                            // Session Transcript Recorder
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-log-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .bg(if is_recording {
                                        t.danger_soft
                                    } else {
                                        gpui::transparent_black()
                                    })
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::text(
                                        if is_recording {
                                            "Stop Recording Transcript"
                                        } else {
                                            "Record Session Transcript (.log)"
                                        },
                                        *t,
                                    ))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.toggle_pane_transcript(pid_log.clone(), cx);
                                    }))
                                    .child(icon_svg(
                                        Icon::Record,
                                        13.0,
                                        if is_recording { t.danger } else { t.text_muted },
                                    )),
                            )
                            .when(has_selection, |el| {
                                el.child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-cp-{pid_copy}")))
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .bg(t.accent_soft)
                                        .text_size(px(10.0))
                                        .text_color(t.accent)
                                        .cursor_pointer()
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.copy_terminal_selection(&pid_copy, cx);
                                        }))
                                        .child("Copy"),
                                )
                            })
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-pst-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover).text_color(t.text_primary))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.paste_into_terminal(&pid_paste, cx);
                                    }))
                                    .child("Paste"),
                            )
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-clr-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover).text_color(t.text_primary))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        if let Some(p) = this
                                            .terminal_tabs
                                            .iter_mut()
                                            .find(|p| p.tab_id == pid_clear)
                                        {
                                            p.clear_buffer();
                                        }
                                        cx.notify();
                                    }))
                                    .child("Clear"),
                            )
                            // SSH Session Transport Rekey + Docked SFTP Drawer (for connected SSH panes)
                            .when(!is_local && pane.connected, |el| {
                                el.child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-rekey-{pid_str}")))
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_hover))
                                        .tooltip(StermTooltip::text(
                                            "Rotate SSH Session Keys (Rekey)",
                                            *t,
                                        ))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.rekey_terminal_pane(pid_rekey.clone(), cx);
                                        }))
                                        .child(icon_svg(Icon::Shield, 13.0, t.text_muted)),
                                )
                                .child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-drw-{pid_str}")))
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .bg(if self.sftp_drawer_open {
                                            t.accent_soft
                                        } else {
                                            gpui::transparent_black()
                                        })
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_hover))
                                        .tooltip(StermTooltip::text(
                                            if self.sftp_drawer_open {
                                                "Hide SFTP Drawer"
                                            } else {
                                                "Toggle Docked SFTP Drawer"
                                            },
                                            *t,
                                        ))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.toggle_sftp_drawer(&pid_drawer, cx);
                                        }))
                                        .child(icon_svg(
                                            Icon::Files,
                                            13.0,
                                            if self.sftp_drawer_open {
                                                t.accent
                                            } else {
                                                t.text_muted
                                            },
                                        )),
                                )
                            })
                            .when_some(sid_sftp, |el, sid| {
                                el.child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-sftp-{pid_str}")))
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .text_size(px(10.0))
                                        .text_color(t.text_secondary)
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_hover).text_color(t.accent))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.attach_sftp_to_session(
                                                sid.clone(),
                                                lbl_sftp.clone(),
                                                cx,
                                            );
                                        }))
                                        .child("SFTP"),
                                )
                            })
                            // Split Right (Horizontal)
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-sph-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::with_shortcut(
                                        "Split Pane Horizontally",
                                        self.settings
                                            .keybindings
                                            .display(ShortcutAction::SplitHorizontal),
                                        *t,
                                    ))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.split_pane_duplicate_or_host(
                                            ws_spl_h.clone(),
                                            pid_spl_h.clone(),
                                            SplitDirection::Horizontal,
                                            None,
                                            cx,
                                        );
                                    }))
                                    .child(icon_svg(Icon::SplitH, 13.0, t.text_muted)),
                            )
                            // Split Down (Vertical)
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-spv-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::with_shortcut(
                                        "Split Pane Vertically",
                                        self.settings
                                            .keybindings
                                            .display(ShortcutAction::SplitVertical),
                                        *t,
                                    ))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.split_pane_duplicate_or_host(
                                            ws_spl_v.clone(),
                                            pid_spl_v.clone(),
                                            SplitDirection::Vertical,
                                            None,
                                            cx,
                                        );
                                    }))
                                    .child(icon_svg(Icon::SplitV, 13.0, t.text_muted)),
                            )
                            // Split with different host or local shell picker
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-spp-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover).text_color(t.text_primary))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.open_modal(
                                            ActiveModal::SplitHostPicker {
                                                workspace_tab_id: ws_spl_pick.clone(),
                                                target_pane_id: pid_spl_pick.clone(),
                                                direction: SplitDirection::Horizontal,
                                            },
                                            cx,
                                        );
                                    }))
                                    .child("+Split"),
                            )
                            // Save Quick-Connect session to Vault (SSH only)
                            .when(pane.host_id.is_none() && !is_local, |el| {
                                el.child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-save-{pid_str}")))
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .bg(t.accent_soft)
                                        .text_size(px(10.0))
                                        .text_color(t.accent)
                                        .cursor_pointer()
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.save_quick_pane_to_vault(pid_save_qc.clone(), cx);
                                        }))
                                        .child("★ Save"),
                                )
                            })
                            // Reconnect (SSH only)
                            .when(!is_local, |el| {
                                el.child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-rec-{pid_str}")))
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_hover))
                                        .tooltip(StermTooltip::text(
                                            "Reconnect SSH Session",
                                            *t,
                                        ))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.reconnect_terminal_pane(
                                                pid_reconn.clone(),
                                                None,
                                                cx,
                                            );
                                        }))
                                        .child(icon_svg(Icon::Refresh, 13.0, t.text_muted)),
                                )
                            })
                            // Close Pane
                            .child(
                                div()
                                    .id(gpui::SharedString::from(format!("p-cls-{pid_str}")))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.danger_soft))
                                    .tooltip(StermTooltip::text("Close Pane", *t))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.close_pane_in_workspace(
                                            ws_close.clone(),
                                            pid_close.clone(),
                                            cx,
                                        );
                                    }))
                                    .child(icon_svg(Icon::Close, 13.0, t.text_muted)),
                            ),
                    ),
            )
            // Auth-Only Inline Password Retry Banner (fixes audit false-positive on network errors!)
            .when(show_auth_retry, |el| {
                el.child(
                    div()
                        .px_3()
                        .py_2()
                        .bg(t.danger_soft)
                        .border_b_1()
                        .border_color(t.danger)
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .text_xs()
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(t.danger)
                                .child("Authentication rejected — retry with password:"),
                        )
                        .child(div().w(px(220.0)).child(self.term_retry_password.clone()))
                        .child(
                            div()
                                .id(gpui::SharedString::from(format!("p-retry-go-{pid_str}")))
                                .px_3()
                                .py_1()
                                .rounded_md()
                                .bg(t.accent_solid)
                                .text_color(gpui::white())
                                .text_xs()
                                .font_weight(FontWeight::SEMIBOLD)
                                .cursor_pointer()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.submit_active_pane_password_retry(cx);
                                }))
                                .child("Connect"),
                        ),
                )
            })
            // Terminal Canvas Container (with Floating Search Bar & Smart Suggestions Overlay)
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .bg(pane_term_bg)
                    .px_2p5()
                    .py_2()
                    .flex()
                    .flex_col()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, ev, window, cx| {
                            this.terminal_mouse_down(&ws_md, &pid_md, ev, window, cx);
                        }),
                    )
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, _, window, cx| {
                            this.terminal_right_click(&ws_rc, &pid_rc, window, cx);
                        }),
                    )
                    .on_mouse_move(cx.listener(move |this, ev, _, cx| {
                        this.terminal_mouse_move(&pid_mm, ev, cx);
                    }))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |this, ev, _, cx| {
                            this.terminal_mouse_up(&pid_mu, ev, cx);
                        }),
                    )
                    .on_scroll_wheel(cx.listener(move |this, ev, _, cx| {
                        this.terminal_scroll_wheel(&pid_sw, ev, cx);
                    }))
                    .child(screen_el)
                    // Floating Search Bar (Ctrl+F)
                    .when(is_active && self.term_search_open, |el| {
                        el.child(
                            div()
                                .absolute()
                                .top_2()
                                .right_3()
                                .p_1p5()
                                .rounded_xl()
                                .bg(t.bg_card)
                                .border_1()
                                .border_color(t.border_strong)
                                .shadow_lg()
                                .flex()
                                .items_center()
                                .gap_1p5()
                                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                    cx.stop_propagation();
                                })
                                .child(div().w(px(190.0)).child(self.term_search_input.clone()))
                                .child(
                                    div()
                                        .text_size(px(11.0))
                                        .font_family("Consolas")
                                        .text_color(t.text_muted)
                                        .child(format!("{active_match_num}/{match_count}")),
                                )
                                .child(
                                    div()
                                        .id("term-find-prev")
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .text_xs()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_subtle))
                                        .tooltip(StermTooltip::text("Previous Match", *t))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.step_terminal_search(false, cx);
                                        }))
                                        .child("▲"),
                                )
                                .child(
                                    div()
                                        .id("term-find-next")
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .text_xs()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_subtle))
                                        .tooltip(StermTooltip::text("Next Match", *t))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.step_terminal_search(true, cx);
                                        }))
                                        .child("▼"),
                                )
                                .child(
                                    div()
                                        .id("term-find-close")
                                        .px_1p5()
                                        .py_0p5()
                                        .rounded_md()
                                        .text_xs()
                                        .text_color(t.text_muted)
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.danger_soft).text_color(t.danger))
                                        .tooltip(StermTooltip::with_shortcut(
                                            "Close Search",
                                            "Esc",
                                            *t,
                                        ))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.term_search_open = false;
                                            cx.notify();
                                        }))
                                        .child("✕"),
                                ),
                        )
                    })
                    // Smart-Positioned Inline Command Suggestions Overlay (never covers active prompt!)
                    .when(sug_visible && !suggestions.is_empty(), |el| {
                        let popover = div()
                            .absolute()
                            .left_3()
                            .w(px(460.0))
                            .when(cursor_bottom, |p| p.top_2())
                            .when(!cursor_bottom, |p| p.bottom_2())
                            .p_2()
                            .rounded_xl()
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border_strong)
                            .shadow_xl()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                cx.stop_propagation();
                            })
                            .child(
                                div()
                                    .px_1p5()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .child("COMMANDS · Tab insert · Alt+↵ run · Alt+↑/↓ navigate")
                                    .child("Esc"),
                            )
                            .children(suggestions.into_iter().enumerate().map(|(ix, item)| {
                                let selected = ix == self.suggestions_selected_idx;
                                let item_fill = item.clone();
                                let item_run = item.clone();
                                let item_pin = item.clone();
                                let hid_pin = pane_host_id.clone();
                                let badge = match item.source {
                                    SuggestionSource::Saved => "pinned".to_string(),
                                    SuggestionSource::History => format!("{}×", item.use_count),
                                    SuggestionSource::Starter => "tip".to_string(),
                                };
                                div()
                                    .id(("sug-row", ix))
                                    .px_2()
                                    .py_1()
                                    .rounded_lg()
                                    .bg(if selected {
                                        t.accent_soft
                                    } else {
                                        gpui::transparent_black()
                                    })
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .cursor_pointer()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.apply_suggestion_to_active_pane(
                                            &item_fill, false, cx,
                                        );
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .font_family("Consolas")
                                                    .text_color(if selected {
                                                        t.accent
                                                    } else {
                                                        t.text_primary
                                                    })
                                                    .truncate()
                                                    .child(item.command.clone()),
                                            )
                                            .when_some(item.label.clone(), |s, lbl| {
                                                s.child(
                                                    div()
                                                        .text_size(px(10.0))
                                                        .text_color(t.text_muted)
                                                        .truncate()
                                                        .child(lbl),
                                                )
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1()
                                            .flex_shrink_0()
                                            .child(
                                                div()
                                                    .px_1()
                                                    .rounded_sm()
                                                    .bg(t.bg_subtle)
                                                    .text_size(px(9.0))
                                                    .font_family("Consolas")
                                                    .text_color(t.text_muted)
                                                    .child(badge),
                                            )
                                            .child(
                                                div()
                                                    .id(("sug-pin", ix))
                                                    .px_1()
                                                    .rounded_sm()
                                                    .text_size(px(10.0))
                                                    .text_color(if item.pinned {
                                                        t.accent
                                                    } else {
                                                        t.text_muted
                                                    })
                                                    .hover(|s| s.bg(t.bg_hover))
                                                    .tooltip(StermTooltip::text(
                                                        if item.pinned {
                                                            "Unpin Snippet"
                                                        } else {
                                                            "Pin as Snippet"
                                                        },
                                                        *t,
                                                    ))
                                                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                                        cx.stop_propagation();
                                                    })
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            cx.stop_propagation();
                                                            this.toggle_pin_command(
                                                                &item_pin,
                                                                hid_pin.clone(),
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("★"),
                                            )
                                            .child(
                                                div()
                                                    .id(("sug-run", ix))
                                                    .px_1p5()
                                                    .py_0p5()
                                                    .rounded_sm()
                                                    .bg(t.accent_solid)
                                                    .text_color(gpui::white())
                                                    .text_size(px(10.0))
                                                    .tooltip(StermTooltip::with_shortcut(
                                                        "Run Command",
                                                        "Alt+Enter",
                                                        *t,
                                                    ))
                                                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                                        cx.stop_propagation();
                                                    })
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            cx.stop_propagation();
                                                            this.apply_suggestion_to_active_pane(
                                                                &item_run, true, cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("↵"),
                                            ),
                                    )
                            }));
                        el.child(popover)
                    }),
            )
            // Compact Pane Footer (Status, Transcript REC, Scrollback Jump-to-Live, Hovered URL hint)
            .child(
                div()
                    .h(px(24.0))
                    .px_2p5()
                    .flex_shrink_0()
                    .bg(t.bg_subtle)
                    .border_t_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .text_size(px(10.0))
                    .font_family("Consolas")
                    .text_color(t.text_muted)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(format!(
                                "{} · {}×{}",
                                pane.status_line, pane.cols, pane.rows
                            ))
                            .when(is_recording, |el| {
                                el.child(
                                    div()
                                        .px_1p5()
                                        .py(px(1.0))
                                        .rounded_sm()
                                        .bg(t.danger_soft)
                                        .text_color(t.danger)
                                        .font_weight(FontWeight::BOLD)
                                        .child("● REC"),
                                )
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .when_some(hovered_url, |el, url| {
                                el.child(
                                    div()
                                        .text_color(t.accent)
                                        .truncate()
                                        .max_w(px(300.0))
                                        .child(format!("Ctrl+Click: {url}")),
                                )
                            })
                            .when(scrollback_off > 0, |el| {
                                el.child(
                                    div()
                                        .id(gpui::SharedString::from(format!("p-live-{pid_str}")))
                                        .px_2()
                                        .py_0p5()
                                        .rounded_sm()
                                        .bg(t.accent_soft)
                                        .text_color(t.accent)
                                        .cursor_pointer()
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if let Some(p) = this
                                                .terminal_tabs
                                                .iter_mut()
                                                .find(|p| p.tab_id == pid_live)
                                            {
                                                p.scroll_to_bottom();
                                            }
                                            cx.notify();
                                        }))
                                        .child(format!("↓ +{scrollback_off} lines · Jump to Live")),
                                )
                            }),
                    ),
            )
            .into_any_element()
    }

    /// Compact Terminal-docked SFTP File Drawer (drop OS files to upload, click dirs to browse).
    fn render_sftp_drawer(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let visible_remote = self.sftp_state.visible_remote_indices();
        let connected = self.sftp_state.session_id.is_some();
        let host_lbl = self
            .sftp_state
            .host_label
            .clone()
            .unwrap_or_else(|| "Remote".to_string());

        div()
            .h(px(210.0))
            .w_full()
            .flex_shrink_0()
            .rounded_xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_sm()
            .overflow_hidden()
            .flex()
            .flex_col()
            .drag_over::<ExternalPaths>(|s, _, _, _| s.border_color(gpui::rgb(0x10B981)))
            .on_drop(cx.listener(|this, ext: &ExternalPaths, _, cx| {
                this.handle_external_drop_on_remote(ext, cx);
            }))
            .child(
                div()
                    .h(px(32.0))
                    .px_3()
                    .flex_shrink_0()
                    .bg(t.bg_subtle)
                    .border_b_1()
                    .border_color(t.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .min_w_0()
                            .child(icon_svg(Icon::Files, 13.0, t.accent))
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(t.text_primary)
                                    .child(format!("SFTP · {host_lbl}")),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .font_family("Consolas")
                                    .text_color(t.text_muted)
                                    .truncate()
                                    .child(self.sftp_state.remote_path.clone()),
                            )
                            .when(self.sftp_state.connecting || self.sftp_state.loading_remote, |el| {
                                el.child(loading_dots("drawer-dots", t.accent))
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .flex_shrink_0()
                            .child(
                                div()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .child("Drop files here to upload"),
                            )
                            .child(
                                div()
                                    .id("sftp-drawer-follow")
                                    .px_2()
                                    .py_0p5()
                                    .rounded_md()
                                    .border_1()
                                    .cursor_pointer()
                                    .bg(if self.sftp_drawer_follow_cwd {
                                        t.accent_soft
                                    } else {
                                        gpui::transparent_black()
                                    })
                                    .border_color(if self.sftp_drawer_follow_cwd {
                                        t.accent
                                    } else {
                                        t.border
                                    })
                                    .text_size(px(10.0))
                                    .text_color(if self.sftp_drawer_follow_cwd {
                                        t.accent
                                    } else {
                                        t.text_muted
                                    })
                                    .tooltip(StermTooltip::text(
                                        "Auto-follow terminal directory changes (OSC 7)",
                                        *t,
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_sftp_drawer_follow_cwd(cx);
                                    }))
                                    .child(if self.sftp_drawer_follow_cwd {
                                        "● Follow cd"
                                    } else {
                                        "○ Follow cd"
                                    }),
                            )
                            .child(
                                div()
                                    .id("sftp-drawer-up")
                                    .px_2()
                                    .py_0p5()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(t.border)
                                    .text_xs()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::text("Parent Directory", *t))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.navigate_remote_up();
                                        cx.notify();
                                    }))
                                    .child("↑"),
                            )
                            .child(
                                div()
                                    .id("sftp-drawer-term")
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::text("Open New SSH Terminal Here", *t))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        let cur = this.sftp_state.remote_path.clone();
                                        this.open_remote_terminal_here(cur, Some(window), cx);
                                    }))
                                    .child(icon_svg(Icon::Terminal, 12.0, t.accent)),
                            )
                            .child(
                                div()
                                    .id("sftp-drawer-ref")
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover))
                                    .tooltip(StermTooltip::text("Refresh Remote Directory", *t))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let cur = this.sftp_state.remote_path.clone();
                                        this.refresh_remote_dir(cur);
                                        cx.notify();
                                    }))
                                    .child(icon_svg(Icon::Refresh, 12.0, t.text_muted)),
                            )
                            .child(
                                div()
                                    .id("sftp-drawer-full")
                                    .px_2()
                                    .py_0p5()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(t.border)
                                    .text_size(px(10.0))
                                    .text_color(t.text_secondary)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_hover).text_color(t.accent))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.navigate_to(AdminPage::Sftp, cx);
                                    }))
                                    .child("Full SFTP"),
                            )
                            .child(
                                div()
                                    .id("sftp-drawer-close")
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_md()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.danger_soft))
                                    .tooltip(StermTooltip::text("Close SFTP Drawer", *t))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.sftp_drawer_open = false;
                                        cx.notify();
                                    }))
                                    .child(icon_svg(Icon::Close, 12.0, t.text_muted)),
                            ),
                    ),
            )
            .child(if !connected {
                div()
                    .flex_1()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_xs()
                    .text_color(t.text_muted)
                    .child("Attaching SFTP subsystem...")
                    .into_any_element()
            } else {
                div()
                    .id("sftp-drawer-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(visible_remote.into_iter().enumerate().map(|(ix, real_ix)| {
                        let entry = self.sftp_state.remote_entries[real_ix].clone();
                        let is_dir = entry.is_dir;
                        let p_nav = entry.path.clone();
                        let p_dl = entry.path.clone();
                        let n_dl = entry.name.clone();
                        let p_ed = entry.path.clone();

                        div()
                            .id(("drw-row", ix))
                            .h(px(28.0))
                            .px_3()
                            .border_b_1()
                            .border_color(t.border)
                            .hover(|s| s.bg(t.bg_subtle))
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if is_dir {
                                    this.refresh_remote_dir(p_nav.clone());
                                    cx.notify();
                                }
                            }))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .min_w_0()
                                    .child(if is_dir { "📁" } else { "📄" })
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(t.text_primary)
                                            .truncate()
                                            .child(entry.name),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .flex_shrink_0()
                                    .child(
                                        div()
                                            .text_size(px(10.0))
                                            .font_family("Consolas")
                                            .text_color(t.text_muted)
                                            .child(if is_dir {
                                                "dir".to_string()
                                            } else {
                                                format_bytes(entry.size)
                                            }),
                                    )
                                    .child(
                                        div()
                                            .id(("drw-dl", ix))
                                            .px_1p5()
                                            .py(px(1.0))
                                            .rounded_sm()
                                            .bg(t.accent_soft)
                                            .text_size(px(10.0))
                                            .text_color(t.accent)
                                            .tooltip(StermTooltip::text(
                                                if is_dir {
                                                    "Download Folder"
                                                } else {
                                                    "Download File"
                                                },
                                                *t,
                                            ))
                                            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                                cx.stop_propagation();
                                            })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                cx.stop_propagation();
                                                if is_dir {
                                                    this.download_remote_dir(
                                                        p_dl.clone(),
                                                        n_dl.clone(),
                                                        cx,
                                                    );
                                                } else {
                                                    this.download_remote_file_checked(
                                                        p_dl.clone(),
                                                        n_dl.clone(),
                                                        cx,
                                                    );
                                                }
                                            }))
                                            .child("↓"),
                                    )
                                    .when(!is_dir, |el| {
                                        el.child(
                                            div()
                                                .id(("drw-ed", ix))
                                                .px_1p5()
                                                .py(px(1.0))
                                                .rounded_sm()
                                                .text_size(px(10.0))
                                                .text_color(t.text_muted)
                                                .hover(|s| s.bg(t.bg_hover))
                                                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                                    cx.stop_propagation();
                                                })
                                                .on_click(cx.listener(move |this, _, _, _| {
                                                    this.open_remote_text_editor(p_ed.clone());
                                                }))
                                                .child("Edit"),
                                        )
                                    }),
                            )
                    }))
                    .into_any_element()
            })
    }

    // =========================================================================
    // 4. Dual-Pane SFTP File Manager (Searchable Hosts, Hidden Toggle, Chmod, Rename, Drag-Drop)
    // =========================================================================
    pub fn render_sftp_page(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let host_filter = self.sftp_host_filter.read(cx).value().trim().to_lowercase();
        let matching_hosts: Vec<_> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| {
                host_filter.is_empty()
                    || h.label.to_lowercase().contains(&host_filter)
                    || h.hostname.to_lowercase().contains(&host_filter)
            })
            .cloned()
            .collect();

        let visible_local = self.sftp_state.visible_local_indices();
        let visible_remote = self.sftp_state.visible_remote_indices();
        let local_count = visible_local.len();
        let remote_count = visible_remote.len();
        let connected = self.sftp_state.session_id.is_some();
        let left_is_remote = self.sftp_state.is_left_remote();
        let left_title = self
            .sftp_state
            .left_remote_host_label
            .clone()
            .unwrap_or_else(|| "Local".to_string());
        let left_hosts = matching_hosts.clone();

        let t_local = *t;
        let t_remote = *t;
        let theme_mode_local = self.settings.theme_mode;
        let theme_mode_remote = self.settings.theme_mode;
        let theme_mode_tabs = self.settings.theme_mode;
        let accent_tab_drop = t.accent;
        let active_sftp_tab_id = self.active_sftp_tab_id.clone();

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            // Multi-SFTP Tab Strip (drag-to-reorder + create/switch/close)
            .child(
                div()
                    .id("sftp-tabs-bar")
                    .flex()
                    .items_center()
                    .gap_1p5()
                    .overflow_x_scroll()
                    .children(self.sftp_tabs.iter().enumerate().map(|(ix, tab)| {
                        let active = tab.id == active_sftp_tab_id;
                        let tid_sel = tab.id.clone();
                        let tid_drag = tab.id.clone();
                        let tid_drop = tab.id.clone();
                        let tid_close = tab.id.clone();
                        let label_drag = tab.label.clone();

                        div()
                            .id(("sftp-tab", ix))
                            .px_2p5()
                            .py_1()
                            .rounded_lg()
                            .border_1()
                            .border_color(if active { t.accent } else { t.border })
                            .bg(if active { t.accent_soft } else { t.bg_card })
                            .text_color(if active {
                                t.accent
                            } else {
                                t.text_secondary
                            })
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .flex_shrink_0()
                            .cursor_pointer()
                            .hover(|s| {
                                if active {
                                    s
                                } else {
                                    s.bg(t.bg_subtle).text_color(t.text_primary)
                                }
                            })
                            .on_drag(
                                DraggedSftpTab {
                                    sftp_tab_id: tid_drag,
                                    label: label_drag,
                                },
                                move |dragged, pos, _, cx| {
                                    cx.new(|_| {
                                        DragTabPill::new(
                                            dragged.label.clone(),
                                            pos,
                                            theme_mode_tabs,
                                        )
                                    })
                                },
                            )
                            .drag_over::<DraggedSftpTab>(move |s, _, _, _| {
                                s.border_color(accent_tab_drop)
                            })
                            .on_drop(cx.listener(
                                move |this, dragged: &DraggedSftpTab, _, cx| {
                                    this.reorder_sftp_tabs(&dragged.sftp_tab_id, &tid_drop, cx);
                                },
                            ))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.select_sftp_tab(tid_sel.clone(), cx);
                            }))
                            .child(icon_svg(
                                Icon::Files,
                                11.0,
                                if active { t.accent } else { t.text_muted },
                            ))
                            .child(tab.label.clone())
                            .child(
                                div()
                                    .id(("sftp-tab-close", ix))
                                    .ml_0p5()
                                    .px_1()
                                    .rounded_sm()
                                    .text_size(px(10.0))
                                    .text_color(t.text_muted)
                                    .hover(|s| s.bg(t.danger_soft).text_color(t.danger))
                                    .tooltip(StermTooltip::text("Close SFTP Tab", *t))
                                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                        cx.stop_propagation();
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        cx.stop_propagation();
                                        this.close_sftp_tab(tid_close.clone(), cx);
                                    }))
                                    .child("✕"),
                            )
                    }))
                    .child(
                        div()
                            .id("sftp-tab-new")
                            .px_2p5()
                            .py_1()
                            .rounded_lg()
                            .border_1()
                            .border_color(t.border)
                            .bg(t.bg_card)
                            .text_xs()
                            .text_color(t.text_muted)
                            .flex_shrink_0()
                            .cursor_pointer()
                            .hover(|s| s.border_color(t.accent).text_color(t.accent))
                            .tooltip(StermTooltip::text("New SFTP Tab", *t))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.new_sftp_tab(cx);
                            }))
                            .child("+"),
                    ),
            )
            // Top SFTP Host Connection Bar (NO 6-host cap!)
            .child(
                div()
                    .p_3()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .flex()
                    .flex_col()
                    .gap_2()
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
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_primary)
                                            .child(match &self.sftp_state.host_label {
                                                Some(lbl) => format!("SFTP Connected: {lbl}"),
                                                None => "Select a Host to Mount SFTP".to_string(),
                                            }),
                                    )
                                    .when(self.sftp_state.connecting, |el| {
                                        el.child(loading_dots("sftp-conn-dots", t.accent))
                                    }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().w(px(220.0)).child(self.sftp_host_filter.clone()))
                                    .child(
                                        div()
                                            .id("sftp-toggle-hidden")
                                            .px_2p5()
                                            .py_1()
                                            .rounded_lg()
                                            .border_1()
                                            .text_xs()
                                            .cursor_pointer()
                                            .bg(if self.sftp_state.show_hidden {
                                                t.accent_soft
                                            } else {
                                                t.bg_subtle
                                            })
                                            .border_color(if self.sftp_state.show_hidden {
                                                t.accent
                                            } else {
                                                t.border
                                            })
                                            .text_color(if self.sftp_state.show_hidden {
                                                t.accent
                                            } else {
                                                t.text_secondary
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.sftp_state.show_hidden =
                                                    !this.sftp_state.show_hidden;
                                                cx.notify();
                                            }))
                                            .child(if self.sftp_state.show_hidden {
                                                "● Dotfiles Shown"
                                            } else {
                                                "○ Show Dotfiles"
                                            }),
                                    ),
                            ),
                    )
                    // Scrollable Host Chips Row
                    .child(
                        div()
                            .id("sftp-host-chips")
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .overflow_x_scroll()
                            .children(matching_hosts.into_iter().enumerate().map(|(ix, h)| {
                                let active =
                                    self.sftp_state.host_id.as_deref() == Some(h.id.as_str());
                                let hid = h.id.clone();
                                div()
                                    .id(("sftp-hchip", ix))
                                    .px_2p5()
                                    .py_1()
                                    .rounded_lg()
                                    .border_1()
                                    .flex_shrink_0()
                                    .text_xs()
                                    .cursor_pointer()
                                    .bg(if active { t.accent_soft } else { t.bg_subtle })
                                    .border_color(if active { t.accent } else { t.border })
                                    .text_color(if active { t.accent } else { t.text_primary })
                                    .hover(|s| s.border_color(t.accent))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.open_sftp_for_host(hid.clone(), cx);
                                    }))
                                    .child(h.label)
                            })),
                    ),
            )
            // Dual File Panes: Local | Remote
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    // LEFT PANE: LOCAL FILESYSTEM
                    .child(
                        div()
                            .h_full()
                            .min_h_0()
                            .rounded_xl()
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .shadow_sm()
                            .flex()
                            .flex_col()
                            .overflow_hidden()
                            .drag_over::<DraggedSftpFile>(|s, _, _, _| s.border_color(gpui::rgb(0x2563EB)))
                            .on_drop(cx.listener(|this, dragged: &DraggedSftpFile, _, cx| {
                                this.handle_drop_on_local(dragged, cx);
                            }))
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .bg(t.bg_subtle)
                                    .border_b_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(if left_is_remote {
                                                t.accent
                                            } else {
                                                t.text_primary
                                            })
                                            .whitespace_nowrap()
                                            .child(left_title),
                                    )
                                    .child(
                                        div()
                                            .id("sftp-loc-up")
                                            .px_2()
                                            .py_0p5()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border)
                                            .text_xs()
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .tooltip(StermTooltip::text("Parent Directory", *t))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.navigate_local_up();
                                                cx.notify();
                                            }))
                                            .child("↑"),
                                    )
                                    .child(div().flex_1().child(self.sftp_local_path_input.clone()))
                                    .when(
                                        connected && !self.sftp_state.selected_local_paths.is_empty(),
                                        |el| {
                                            let n = self.sftp_state.selected_local_paths.len();
                                            el.child(
                                                div()
                                                    .id("sftp-loc-batch-up")
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_md()
                                                    .bg(t.accent_solid)
                                                    .text_color(gpui::white())
                                                    .text_size(px(10.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .cursor_pointer()
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.batch_upload_selected(cx);
                                                    }))
                                                    .child(if left_is_remote {
                                                        format!("Copy ({n}) →")
                                                    } else {
                                                        format!("Upload ({n}) →")
                                                    }),
                                            )
                                        },
                                    )
                                    .child(
                                        div()
                                            .id("sftp-loc-term")
                                            .px_1p5()
                                            .py_0p5()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border)
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .tooltip(StermTooltip::text(
                                                if left_is_remote {
                                                    "Open SSH Terminal Here"
                                                } else {
                                                    "Open Local Terminal Here"
                                                },
                                                *t,
                                            ))
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.open_local_terminal_here(window, cx);
                                            }))
                                            .child(icon_svg(Icon::Terminal, 12.0, t.accent)),
                                    )
                                    .child(
                                        div()
                                            .id("sftp-loc-ref")
                                            .px_2()
                                            .py_0p5()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border)
                                            .text_xs()
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .tooltip(StermTooltip::text("Refresh Left Pane", *t))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let cur = this.sftp_state.local_path.clone();
                                                this.refresh_left_pane(cur);
                                                cx.notify();
                                            }))
                                            .child("↻"),
                                    ),
                            )
                            // Left Pane Source Switcher (Local PC or Remote Host for Remote ↔ Remote transfers!)
                            .child(
                                div()
                                    .id("sftp-left-src-bar")
                                    .px_3()
                                    .py_1()
                                    .border_b_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .overflow_x_scroll()
                                    .child(
                                        div()
                                            .text_size(px(10.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_muted)
                                            .flex_shrink_0()
                                            .child("SOURCE:"),
                                    )
                                    .child(
                                        div()
                                            .id("sftp-left-local")
                                            .px_2()
                                            .py(px(2.0))
                                            .rounded_md()
                                            .border_1()
                                            .flex_shrink_0()
                                            .text_size(px(10.0))
                                            .cursor_pointer()
                                            .bg(if !left_is_remote {
                                                t.accent_soft
                                            } else {
                                                t.bg_subtle
                                            })
                                            .border_color(if !left_is_remote {
                                                t.accent
                                            } else {
                                                t.border
                                            })
                                            .text_color(if !left_is_remote {
                                                t.accent
                                            } else {
                                                t.text_secondary
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.reset_sftp_left_to_local(cx);
                                            }))
                                            .child("Local PC"),
                                    )
                                    .children(left_hosts.into_iter().enumerate().map(|(ix, h)| {
                                        let active = self
                                            .sftp_state
                                            .left_remote_host_id
                                            .as_deref()
                                            == Some(h.id.as_str());
                                        let hid = h.id.clone();
                                        div()
                                            .id(("sftp-lhchip", ix))
                                            .px_2()
                                            .py(px(2.0))
                                            .rounded_md()
                                            .border_1()
                                            .flex_shrink_0()
                                            .text_size(px(10.0))
                                            .cursor_pointer()
                                            .bg(if active { t.accent_soft } else { t.bg_subtle })
                                            .border_color(if active { t.accent } else { t.border })
                                            .text_color(if active {
                                                t.accent
                                            } else {
                                                t.text_secondary
                                            })
                                            .hover(|s| s.border_color(t.accent))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.open_sftp_left_remote(hid.clone(), cx);
                                            }))
                                            .child(h.label)
                                    })),
                            )
                            .child(
                                div().flex_1().min_h_0().child(
                                    uniform_list(
                                        "sftp-local-list",
                                        local_count,
                                        cx.processor(move |this, range: std::ops::Range<usize>, _window, cx| {
                                            range
                                                .map(|vis_ix| {
                                                    let real_ix = visible_local[vis_ix];
                                                    let entry =
                                                        this.sftp_state.local_entries[real_ix].clone();
                                                    let checked = this
                                                        .sftp_state
                                                        .selected_local_paths
                                                        .contains(&entry.path);
                                                    let selected = checked
                                                        || this
                                                            .sftp_state
                                                            .selected_local
                                                            .as_deref()
                                                            == Some(entry.path.as_str());
                                                    let drag_payload = DraggedSftpFile {
                                                        side: SftpPaneSide::Local,
                                                        name: entry.name.clone(),
                                                        full_path: entry.path.clone(),
                                                        size: entry.size,
                                                        is_dir: entry.is_dir,
                                                    };
                                                    let p_click = entry.path.clone();
                                                    let p_chk = entry.path.clone();
                                                    let is_dir = entry.is_dir;
                                                    let p_up = entry.path.clone();
                                                    let n_up = entry.name.clone();

                                                    div()
                                                        .id(("loc-row", vis_ix))
                                                        .h(px(34.0))
                                                        .px_3()
                                                        .border_b_1()
                                                        .border_color(t_local.border)
                                                        .bg(if selected {
                                                            t_local.accent_soft
                                                        } else {
                                                            gpui::transparent_black()
                                                        })
                                                        .hover(|s| s.bg(t_local.bg_subtle))
                                                        .flex()
                                                        .items_center()
                                                        .justify_between()
                                                        .gap_2()
                                                        .cursor_pointer()
                                                        .on_drag(
                                                            drag_payload,
                                                            move |payload, pos, _, cx| {
                                                                cx.new(|_| {
                                                                    DragFilePill::new(
                                                                        payload,
                                                                        pos,
                                                                        theme_mode_local,
                                                                    )
                                                                })
                                                            },
                                                        )
                                                        .on_click(cx.listener(
                                                            move |this, ev: &gpui::ClickEvent, _, cx| {
                                                                if ev.click_count() >= 2 && is_dir {
                                                                    this.refresh_left_pane(
                                                                        p_click.clone(),
                                                                    );
                                                                } else {
                                                                    this.sftp_state.selected_local =
                                                                        Some(p_click.clone());
                                                                }
                                                                cx.notify();
                                                            },
                                                        ))
                                                        .child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_2()
                                                                .min_w_0()
                                                                .child(
                                                                    div()
                                                                        .id(("loc-chk", vis_ix))
                                                                        .w(px(14.0))
                                                                        .h(px(14.0))
                                                                        .rounded(px(3.0))
                                                                        .flex_shrink_0()
                                                                        .border_1()
                                                                        .border_color(if checked {
                                                                            t_local.accent_solid
                                                                        } else {
                                                                            t_local.border_strong
                                                                        })
                                                                        .bg(if checked {
                                                                            t_local.accent_solid
                                                                        } else {
                                                                            gpui::transparent_black()
                                                                        })
                                                                        .text_color(gpui::white())
                                                                        .text_size(px(9.0))
                                                                        .flex()
                                                                        .items_center()
                                                                        .justify_center()
                                                                        .on_mouse_down(
                                                                            MouseButton::Left,
                                                                            |_, _, cx| {
                                                                                cx.stop_propagation();
                                                                            },
                                                                        )
                                                                        .on_click(cx.listener(
                                                                            move |this, _, _, cx| {
                                                                                cx.stop_propagation();
                                                                                this.sftp_state
                                                                                    .toggle_local_select(
                                                                                        p_chk.clone(),
                                                                                    );
                                                                                cx.notify();
                                                                            },
                                                                        ))
                                                                        .child(if checked {
                                                                            "✓"
                                                                        } else {
                                                                            ""
                                                                        }),
                                                                )
                                                                .child(if entry.is_dir {
                                                                    "📁"
                                                                } else {
                                                                    "📄"
                                                                })
                                                                .child(
                                                                    div()
                                                                        .text_xs()
                                                                        .text_color(
                                                                            t_local.text_primary,
                                                                        )
                                                                        .truncate()
                                                                        .child(entry.name),
                                                                ),
                                                        )
                                                        .child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_2()
                                                                .flex_shrink_0()
                                                                .child(
                                                                    div()
                                                                        .text_size(px(11.0))
                                                                        .font_family("Consolas")
                                                                        .text_color(
                                                                            t_local.text_muted,
                                                                        )
                                                                        .child(if entry.is_dir {
                                                                            "—".to_string()
                                                                        } else {
                                                                            format_bytes(entry.size)
                                                                        }),
                                                                )
                                                                .when(connected, |el| {
                                                                    el.child(
                                                                        div()
                                                                            .id(("loc-up", vis_ix))
                                                                            .px_1p5()
                                                                            .py_0p5()
                                                                            .rounded_sm()
                                                                            .bg(t_local.accent_soft)
                                                                            .text_size(px(10.0))
                                                                            .text_color(t_local.accent)
                                                                            .tooltip(StermTooltip::text(
                                                                                if left_is_remote {
                                                                                    "Copy to Right Host"
                                                                                } else if is_dir {
                                                                                    "Upload Folder"
                                                                                } else {
                                                                                    "Upload File"
                                                                                },
                                                                                t_local,
                                                                            ))
                                                                            .on_mouse_down(
                                                                                MouseButton::Left,
                                                                                |_, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                },
                                                                            )
                                                                            .on_click(cx.listener(
                                                                                move |this, _, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                    this.transfer_left_to_right(
                                                                                        p_up.clone(),
                                                                                        n_up.clone(),
                                                                                        is_dir,
                                                                                        cx,
                                                                                    );
                                                                                },
                                                                            ))
                                                                            .child("→"),
                                                                    )
                                                                }),
                                                        )
                                                })
                                                .collect()
                                        }),
                                    )
                                    .size_full()
                                    .track_scroll(self.sftp_state.local_scroll_handle.clone()),
                                ),
                            ),
                    )
                    // RIGHT PANE: REMOTE SFTP FILESYSTEM
                    .child(
                        div()
                            .h_full()
                            .min_h_0()
                            .rounded_xl()
                            .bg(t.bg_card)
                            .border_1()
                            .border_color(t.border)
                            .shadow_sm()
                            .flex()
                            .flex_col()
                            .overflow_hidden()
                            .drag_over::<DraggedSftpFile>(|s, _, _, _| s.border_color(gpui::rgb(0x2563EB)))
                            .drag_over::<ExternalPaths>(|s, _, _, _| s.border_color(gpui::rgb(0x10B981)))
                            .on_drop(cx.listener(|this, dragged: &DraggedSftpFile, _, cx| {
                                this.handle_drop_on_remote(dragged, cx);
                            }))
                            .on_drop(cx.listener(|this, ext: &ExternalPaths, _, cx| {
                                this.handle_external_drop_on_remote(ext, cx);
                            }))
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .bg(t.bg_subtle)
                                    .border_b_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_primary)
                                            .child("Remote"),
                                    )
                                    .child(
                                        div()
                                            .id("sftp-rem-up")
                                            .px_2()
                                            .py_0p5()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border)
                                            .text_xs()
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .tooltip(StermTooltip::text("Parent Directory", *t))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.navigate_remote_up();
                                                cx.notify();
                                            }))
                                            .child("↑"),
                                    )
                                    .child(div().flex_1().child(self.sftp_remote_path_input.clone()))
                                    .when(
                                        connected
                                            && !self.sftp_state.selected_remote_paths.is_empty(),
                                        |el| {
                                            let n = self.sftp_state.selected_remote_paths.len();
                                            el.child(
                                                div()
                                                    .id("sftp-rem-batch-dl")
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_md()
                                                    .bg(t.accent_solid)
                                                    .text_color(gpui::white())
                                                    .text_size(px(10.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .cursor_pointer()
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.batch_download_selected(cx);
                                                    }))
                                                    .child(if left_is_remote {
                                                        format!("← Copy ({n})")
                                                    } else {
                                                        format!("← Download ({n})")
                                                    }),
                                            )
                                        },
                                    )
                                    .when(connected, |el| {
                                        el.child(
                                            div()
                                                .id("sftp-rem-term")
                                                .px_1p5()
                                                .py_0p5()
                                                .rounded_md()
                                                .border_1()
                                                .border_color(t.border)
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .cursor_pointer()
                                                .hover(|s| s.bg(t.bg_hover))
                                                .tooltip(StermTooltip::text(
                                                    "Open SSH Terminal Here",
                                                    *t,
                                                ))
                                                .on_click(cx.listener(|this, _, window, cx| {
                                                    let cur = this.sftp_state.remote_path.clone();
                                                    this.open_remote_terminal_here(
                                                        cur,
                                                        Some(window),
                                                        cx,
                                                    );
                                                }))
                                                .child(icon_svg(Icon::Terminal, 12.0, t.accent)),
                                        )
                                    })
                                    .child(
                                        div()
                                            .id("sftp-rem-ref")
                                            .px_2()
                                            .py_0p5()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border)
                                            .text_xs()
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_hover))
                                            .tooltip(StermTooltip::text(
                                                "Refresh Remote Directory",
                                                *t,
                                            ))
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let cur = this.sftp_state.remote_path.clone();
                                                this.refresh_remote_dir(cur);
                                                cx.notify();
                                            }))
                                            .child("↻"),
                                    ),
                            )
                            // Inline mkdir bar when connected
                            .when(connected, |el| {
                                el.child(
                                    div()
                                        .px_3()
                                        .py_1p5()
                                        .border_b_1()
                                        .border_color(t.border)
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .child(div().flex_1().child(self.sftp_mkdir_input.clone()))
                                        .child(
                                            div()
                                                .id("sftp-mkdir-btn")
                                                .px_2p5()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .border_color(t.border_strong)
                                                .text_size(px(11.0))
                                                .cursor_pointer()
                                                .hover(|s| s.bg(t.bg_subtle))
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.create_remote_dir(cx);
                                                }))
                                                .child("+ Folder"),
                                        ),
                                )
                            })
                            .child(if !connected {
                                div()
                                    .flex_1()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child("Pick a host above (or click SFTP in any terminal) to browse remote files.")
                                    .into_any_element()
                            } else {
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .child(
                                        uniform_list(
                                            "sftp-remote-list",
                                            remote_count,
                                            cx.processor(move |this, range: std::ops::Range<usize>, _window, cx| {
                                                range
                                                    .map(|vis_ix| {
                                                        let real_ix = visible_remote[vis_ix];
                                                        let entry = this.sftp_state.remote_entries
                                                            [real_ix]
                                                            .clone();
                                                        let checked = this
                                                            .sftp_state
                                                            .selected_remote_paths
                                                            .contains(&entry.path);
                                                        let selected = checked
                                                            || this
                                                                .sftp_state
                                                                .selected_remote
                                                                .as_deref()
                                                                == Some(entry.path.as_str());
                                                        let drag_payload = DraggedSftpFile {
                                                            side: SftpPaneSide::Remote,
                                                            name: entry.name.clone(),
                                                            full_path: entry.path.clone(),
                                                            size: entry.size,
                                                            is_dir: entry.is_dir,
                                                        };
                                                        let p_click = entry.path.clone();
                                                        let p_chk = entry.path.clone();
                                                        let is_dir = entry.is_dir;
                                                        let p_dl = entry.path.clone();
                                                        let n_dl = entry.name.clone();
                                                        let p_edit = entry.path.clone();
                                                        let p_ext = entry.path.clone();
                                                        let n_ext = entry.name.clone();
                                                        let p_ren = entry.path.clone();
                                                        let n_ren = entry.name.clone();
                                                        let p_chmod = entry.path.clone();
                                                        let perms = entry.permissions.unwrap_or(0o644);
                                                        let p_del = entry.path.clone();
                                                        let n_del = entry.name.clone();
                                                        let p_term = entry.path.clone();

                                                        div()
                                                            .id(("rem-row", vis_ix))
                                                            .h(px(34.0))
                                                            .px_3()
                                                            .border_b_1()
                                                            .border_color(t_remote.border)
                                                            .bg(if selected {
                                                                t_remote.accent_soft
                                                            } else {
                                                                gpui::transparent_black()
                                                            })
                                                            .hover(|s| s.bg(t_remote.bg_subtle))
                                                            .flex()
                                                            .items_center()
                                                            .justify_between()
                                                            .gap_2()
                                                            .cursor_pointer()
                                                            .on_drag(
                                                                drag_payload,
                                                                move |payload, pos, _, cx| {
                                                                    cx.new(|_| {
                                                                        DragFilePill::new(
                                                                            payload,
                                                                            pos,
                                                                            theme_mode_remote,
                                                                        )
                                                                    })
                                                                },
                                                            )
                                                            .on_click(cx.listener(
                                                                move |this, ev: &gpui::ClickEvent, _, cx| {
                                                                    if ev.click_count() >= 2 && is_dir {
                                                                        this.refresh_remote_dir(
                                                                            p_click.clone(),
                                                                        );
                                                                    } else {
                                                                        this.sftp_state
                                                                            .selected_remote =
                                                                            Some(p_click.clone());
                                                                    }
                                                                    cx.notify();
                                                                },
                                                            ))
                                                            .child(
                                                                div()
                                                                    .flex()
                                                                    .items_center()
                                                                    .gap_2()
                                                                    .min_w_0()
                                                                    .child(
                                                                        div()
                                                                            .id(("rem-chk", vis_ix))
                                                                            .w(px(14.0))
                                                                            .h(px(14.0))
                                                                            .rounded(px(3.0))
                                                                            .flex_shrink_0()
                                                                            .border_1()
                                                                            .border_color(if checked {
                                                                                t_remote.accent_solid
                                                                            } else {
                                                                                t_remote.border_strong
                                                                            })
                                                                            .bg(if checked {
                                                                                t_remote.accent_solid
                                                                            } else {
                                                                                gpui::transparent_black()
                                                                            })
                                                                            .text_color(gpui::white())
                                                                            .text_size(px(9.0))
                                                                            .flex()
                                                                            .items_center()
                                                                            .justify_center()
                                                                            .on_mouse_down(
                                                                                MouseButton::Left,
                                                                                |_, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                },
                                                                            )
                                                                            .on_click(cx.listener(
                                                                                move |this, _, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                    this.sftp_state
                                                                                        .toggle_remote_select(
                                                                                            p_chk.clone(),
                                                                                        );
                                                                                    cx.notify();
                                                                                },
                                                                            ))
                                                                            .child(if checked {
                                                                                "✓"
                                                                            } else {
                                                                                ""
                                                                            }),
                                                                    )
                                                                    .child(if entry.is_dir {
                                                                        "📁"
                                                                    } else {
                                                                        "📄"
                                                                    })
                                                                    .child(
                                                                        div()
                                                                            .text_xs()
                                                                            .text_color(
                                                                                t_remote
                                                                                    .text_primary,
                                                                            )
                                                                            .truncate()
                                                                            .child(entry.name),
                                                                    ),
                                                            )
                                                            .child(
                                                                div()
                                                                    .flex()
                                                                    .items_center()
                                                                    .gap_1()
                                                                    .flex_shrink_0()
                                                                    // Clickable octal permissions badge (opens Chmod modal!)
                                                                    .child(
                                                                        div()
                                                                            .id(("rem-chm", vis_ix))
                                                                            .px_1()
                                                                            .py_0p5()
                                                                            .rounded_sm()
                                                                            .bg(t_remote.bg_subtle)
                                                                            .font_family("Consolas")
                                                                            .text_size(px(10.0))
                                                                            .text_color(
                                                                                t_remote.text_muted,
                                                                            )
                                                                            .hover(|s| {
                                                                                s.text_color(
                                                                                    t_remote.accent,
                                                                                )
                                                                            })
                                                                            .on_mouse_down(
                                                                                MouseButton::Left,
                                                                                |_, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                },
                                                                            )
                                                                            .on_click(cx.listener(
                                                                                move |this, _, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                    this.open_remote_chmod_modal(
                                                                                        p_chmod.clone(),
                                                                                        perms,
                                                                                        cx,
                                                                                    );
                                                                                },
                                                                            ))
                                                                            .child(format!(
                                                                                "{:03o}",
                                                                                perms & 0o777
                                                                            )),
                                                                    )
                                                                    .child(
                                                                        div()
                                                                            .id(("rem-dl", vis_ix))
                                                                            .px_1p5()
                                                                            .py_0p5()
                                                                            .rounded_sm()
                                                                            .bg(t_remote
                                                                                .accent_soft)
                                                                            .text_size(px(10.0))
                                                                            .text_color(
                                                                                t_remote.accent,
                                                                            )
                                                                            .tooltip(StermTooltip::text(
                                                                                if left_is_remote {
                                                                                    "Copy to Left Host"
                                                                                } else if is_dir {
                                                                                    "Download Folder"
                                                                                } else {
                                                                                    "Download File"
                                                                                },
                                                                                t_remote,
                                                                            ))
                                                                            .on_mouse_down(
                                                                                MouseButton::Left,
                                                                                |_, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                },
                                                                            )
                                                                            .on_click(cx.listener(
                                                                                move |this, _, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                    this.transfer_right_to_left(
                                                                                        p_dl.clone(),
                                                                                        n_dl.clone(),
                                                                                        is_dir,
                                                                                        cx,
                                                                                    );
                                                                                },
                                                                            ))
                                                                            .child("←"),
                                                                    )
                                                                    .when(!entry.is_dir, |el| {
                                                                        el.child(
                                                                            div()
                                                                                .id(("rem-ed", vis_ix))
                                                                                .px_1p5()
                                                                                .py_0p5()
                                                                                .rounded_sm()
                                                                                .text_size(px(10.0))
                                                                                .text_color(
                                                                                    t_remote
                                                                                        .text_muted,
                                                                                )
                                                                                .hover(|s| {
                                                                                    s.bg(
                                                                                        t_remote
                                                                                            .bg_hover,
                                                                                    )
                                                                                })
                                                                                .on_mouse_down(
                                                                                    MouseButton::Left,
                                                                                    |_, _, cx| {
                                                                                        cx.stop_propagation();
                                                                                    },
                                                                                )
                                                                                .on_click(cx.listener(
                                                                                    move |this, _, _, _| {
                                                                                        this.open_remote_text_editor(
                                                                                            p_edit.clone(),
                                                                                        );
                                                                                    },
                                                                                ))
                                                                                .child("Edit"),
                                                                        )
                                                                        .child(
                                                                            div()
                                                                                .id(("rem-ext", vis_ix))
                                                                                .px_1()
                                                                                .py_0p5()
                                                                                .rounded_sm()
                                                                                .text_size(px(10.0))
                                                                                .text_color(
                                                                                    t_remote
                                                                                        .accent,
                                                                                )
                                                                                .hover(|s| {
                                                                                    s.bg(
                                                                                        t_remote
                                                                                            .accent_soft,
                                                                                    )
                                                                                })
                                                                                .on_mouse_down(
                                                                                    MouseButton::Left,
                                                                                    |_, _, cx| {
                                                                                        cx.stop_propagation();
                                                                                    },
                                                                                )
                                                                                .on_click(cx.listener(
                                                                                    move |this, _, _, cx| {
                                                                                        cx.stop_propagation();
                                                                                        this.open_remote_in_external_editor(
                                                                                            p_ext.clone(),
                                                                                            n_ext.clone(),
                                                                                            cx,
                                                                                        );
                                                                                    },
                                                                                ))
                                                                                .child("Ext"),
                                                                        )
                                                                    })
                                                                    .when(is_dir, |el| {
                                                                        el.child(
                                                                            div()
                                                                                .id((
                                                                                    "rem-term",
                                                                                    vis_ix,
                                                                                ))
                                                                                .px_1()
                                                                                .py_0p5()
                                                                                .rounded_sm()
                                                                                .flex()
                                                                                .items_center()
                                                                                .justify_center()
                                                                                .hover(|s| {
                                                                                    s.bg(
                                                                                        t_remote
                                                                                            .accent_soft,
                                                                                    )
                                                                                })
                                                                                .tooltip(
                                                                                    StermTooltip::text(
                                                                                        "Open SSH Terminal in Folder",
                                                                                        t_remote,
                                                                                    ),
                                                                                )
                                                                                .on_mouse_down(
                                                                                    MouseButton::Left,
                                                                                    |_, _, cx| {
                                                                                        cx.stop_propagation();
                                                                                    },
                                                                                )
                                                                                .on_click(
                                                                                    cx.listener(
                                                                                        move |this,
                                                                                              _,
                                                                                              window,
                                                                                              cx| {
                                                                                            cx.stop_propagation();
                                                                                            this.open_remote_terminal_here(
                                                                                                p_term.clone(),
                                                                                                Some(window),
                                                                                                cx,
                                                                                            );
                                                                                        },
                                                                                    ),
                                                                                )
                                                                                .child(icon_svg(
                                                                                    Icon::Terminal,
                                                                                    11.0,
                                                                                    t_remote.accent,
                                                                                )),
                                                                        )
                                                                    })
                                                                    .child(
                                                                        div()
                                                                            .id(("rem-ren", vis_ix))
                                                                            .px_1()
                                                                            .py_0p5()
                                                                            .rounded_sm()
                                                                            .text_size(px(10.0))
                                                                            .text_color(
                                                                                t_remote.text_muted,
                                                                            )
                                                                            .hover(|s| {
                                                                                s.bg(t_remote.bg_hover)
                                                                            })
                                                                            .on_mouse_down(
                                                                                MouseButton::Left,
                                                                                |_, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                },
                                                                            )
                                                                            .on_click(cx.listener(
                                                                                move |this, _, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                    this.open_remote_rename_modal(
                                                                                        p_ren.clone(),
                                                                                        n_ren.clone(),
                                                                                        cx,
                                                                                    );
                                                                                },
                                                                            ))
                                                                            .child("Ren"),
                                                                    )
                                                                    .child(
                                                                        div()
                                                                            .id(("rem-del", vis_ix))
                                                                            .px_1()
                                                                            .py_0p5()
                                                                            .rounded_sm()
                                                                            .text_size(px(10.0))
                                                                            .text_color(
                                                                                t_remote.text_muted,
                                                                            )
                                                                            .hover(|s| {
                                                                                s.bg(t_remote
                                                                                    .danger_soft)
                                                                                    .text_color(
                                                                                        t_remote
                                                                                            .danger,
                                                                                    )
                                                                            })
                                                                            .tooltip(StermTooltip::text(
                                                                                if is_dir {
                                                                                    "Delete Remote Folder"
                                                                                } else {
                                                                                    "Delete Remote File"
                                                                                },
                                                                                t_remote,
                                                                            ))
                                                                            .on_mouse_down(
                                                                                MouseButton::Left,
                                                                                |_, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                },
                                                                            )
                                                                            .on_click(cx.listener(
                                                                                move |this, _, _, cx| {
                                                                                    cx.stop_propagation();
                                                                                    this.request_confirm(
                                                                                        ConfirmAction::DeleteRemoteFile {
                                                                                            path: p_del.clone(),
                                                                                            is_dir,
                                                                                            name: n_del.clone(),
                                                                                        },
                                                                                        cx,
                                                                                    );
                                                                                },
                                                                            ))
                                                                            .child("✕"),
                                                                    ),
                                                            )
                                                    })
                                                    .collect()
                                            }),
                                        )
                                        .size_full()
                                        .track_scroll(self.sftp_state.remote_scroll_handle.clone()),
                                    )
                                    .into_any_element()
                            }),
                    ),
            )
    }

    // =========================================================================
    // 5. Snippets & Learned Command History Library Page
    // =========================================================================
    pub fn render_snippets_page(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let q = self.snippet_search.read(cx).value().trim().to_lowercase();
        let mut pinned: Vec<_> = self
            .snapshot
            .commands
            .iter()
            .filter(|c| {
                c.pinned
                    && (q.is_empty()
                        || c.command.to_lowercase().contains(&q)
                        || c.label
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q))
            })
            .cloned()
            .collect();
        pinned.sort_by_key(|a| std::cmp::Reverse(a.use_count));

        let mut history: Vec<_> = self
            .snapshot
            .commands
            .iter()
            .filter(|c| {
                !c.pinned
                    && (q.is_empty()
                        || c.command.to_lowercase().contains(&q)
                        || c.label
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q))
            })
            .cloned()
            .collect();
        history.sort_by_key(|a| std::cmp::Reverse(a.last_used_at));

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            // Add / Edit Snippet Composer Card
            .child(
                div()
                    .p_3p5()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .flex()
                    .flex_col()
                    .gap_2p5()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(if self.editing_snippet_id.is_some() {
                                                "Edit Pinned Snippet"
                                            } else {
                                                "New Reusable Command Snippet"
                                            }),
                                    )
                                    .child(
                                        div()
                                            .px_1p5()
                                            .py(px(1.0))
                                            .rounded_sm()
                                            .bg(t.bg_subtle)
                                            .text_size(px(10.0))
                                            .font_family("Consolas")
                                            .text_color(t.text_muted)
                                            .child("Supports {{variable}} templates"),
                                    ),
                            )
                            .child(div().w(px(240.0)).child(self.snippet_search.clone())),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().flex_1().child(self.snippet_cmd_input.clone()))
                            .child(div().w(px(240.0)).child(self.snippet_label_input.clone()))
                            .when(self.editing_snippet_id.is_some(), |el| {
                                el.child(
                                    div()
                                        .id("snip-cancel-edit")
                                        .px_3()
                                        .py_1p5()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(t.border_strong)
                                        .text_xs()
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.editing_snippet_id = None;
                                            this.snippet_host_id = None;
                                            this.snippet_cmd_input.update(cx, |f, cx| f.clear(cx));
                                            this.snippet_label_input
                                                .update(cx, |f, cx| f.clear(cx));
                                            cx.notify();
                                        }))
                                        .child("Cancel"),
                                )
                            })
                            .child(
                                div()
                                    .id("snip-save-btn")
                                    .px_3p5()
                                    .py_1p5()
                                    .rounded_lg()
                                    .bg(t.accent_solid)
                                    .text_color(gpui::white())
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .cursor_pointer()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.save_snippet_from_page(cx);
                                    }))
                                    .child(if self.editing_snippet_id.is_some() {
                                        "Update"
                                    } else {
                                        "+ Save Snippet"
                                    }),
                            ),
                    ),
            )
            // 2 Columns: Pinned Snippets | Learned History
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(self.render_command_list_card(
                        t,
                        "pinned-scroll",
                        &format!("Pinned Snippets ({})", pinned.len()),
                        pinned,
                        cx,
                    ))
                    .child(self.render_command_list_card(
                        t,
                        "history-scroll",
                        &format!("Learned Command History ({})", history.len()),
                        history,
                        cx,
                    )),
            )
    }

    fn render_command_list_card(
        &self,
        t: &ThemePalette,
        scroll_id: &'static str,
        title: &str,
        items: Vec<core_vault::models::CommandRecord>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .h_full()
            .min_h_0()
            .rounded_xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border)
            .shadow_sm()
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(
                div()
                    .px_4()
                    .py_2p5()
                    .bg(t.bg_subtle)
                    .border_b_1()
                    .border_color(t.border)
                    .text_xs()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(t.text_primary)
                    .child(title.to_string()),
            )
            .child(
                div()
                    .id(scroll_id)
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_2p5()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .when(items.is_empty(), |el| {
                        el.child(
                            div()
                                .py_8()
                                .text_center()
                                .text_xs()
                                .text_color(t.text_muted)
                                .child("No commands here yet. Commands run in SSH panes are learned automatically."),
                        )
                    })
                    .children(items.into_iter().enumerate().map(|(ix, rec)| {
                        let cmd_run = rec.command.clone();
                        let rec_edit = rec.clone();
                        let rec_pin = rec.clone();
                        let id_del = rec.id.clone();
                        let cmd_del = rec.command.clone();
                        let host_name = rec.host_id.as_deref().and_then(|hid| {
                            self.snapshot
                                .hosts
                                .iter()
                                .find(|h| h.id == hid)
                                .map(|h| h.label.clone())
                        });

                        div()
                            .id((scroll_id, ix))
                            .p_2p5()
                            .rounded_lg()
                            .bg(t.bg_subtle)
                            .hover(|s| s.bg(t.bg_hover))
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_0p5()
                                    .min_w_0()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_family("Consolas")
                                            .text_color(t.text_primary)
                                            .truncate()
                                            .child(rec.command.clone()),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .text_size(px(10.0))
                                            .text_color(t.text_muted)
                                            .child(format!("{}×", rec.use_count))
                                            .when_some(host_name, |s, hn| s.child(format!("· {hn}")))
                                            .when_some(rec.label.clone(), |s, l| {
                                                s.child(format!("· {l}"))
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .flex_shrink_0()
                                    .child(
                                        div()
                                            .id((scroll_id, 10000 + ix))
                                            .px_2()
                                            .py_0p5()
                                            .rounded_md()
                                            .bg(t.accent_solid)
                                            .text_color(gpui::white())
                                            .text_size(px(10.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .cursor_pointer()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.run_snippet_in_active_terminal(
                                                    cmd_run.clone(),
                                                    cx,
                                                );
                                            }))
                                            .child("▶ Run"),
                                    )
                                    .child(
                                        div()
                                            .id((scroll_id, 20000 + ix))
                                            .px_1p5()
                                            .py_0p5()
                                            .rounded_md()
                                            .text_size(px(11.0))
                                            .text_color(if rec.pinned {
                                                t.accent
                                            } else {
                                                t.text_muted
                                            })
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_card))
                                            .tooltip(StermTooltip::text(
                                                if rec.pinned {
                                                    "Unpin Snippet"
                                                } else {
                                                    "Pin to Snippets"
                                                },
                                                *t,
                                            ))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let mut updated = rec_pin.clone();
                                                updated.pinned = !updated.pinned;
                                                if let Ok(v) = this.services.vault.lock() {
                                                    let _ = v.upsert_command(updated);
                                                }
                                                this.reload_vault_snapshot();
                                                this.maybe_auto_sync(cx);
                                                cx.notify();
                                            }))
                                            .child("★"),
                                    )
                                    .child(
                                        div()
                                            .id((scroll_id, 30000 + ix))
                                            .px_1p5()
                                            .py_0p5()
                                            .rounded_md()
                                            .text_size(px(10.0))
                                            .text_color(t.text_muted)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_card).text_color(t.text_primary))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.editing_snippet_id = Some(rec_edit.id.clone());
                                                this.snippet_host_id = rec_edit.host_id.clone();
                                                this.snippet_cmd_input.update(cx, |f, cx| {
                                                    f.set_value(rec_edit.command.clone(), cx)
                                                });
                                                this.snippet_label_input.update(cx, |f, cx| {
                                                    f.set_value(
                                                        rec_edit.label.clone().unwrap_or_default(),
                                                        cx,
                                                    )
                                                });
                                                cx.notify();
                                            }))
                                            .child("Edit"),
                                    )
                                    .child(
                                        div()
                                            .id((scroll_id, 40000 + ix))
                                            .px_1p5()
                                            .py_0p5()
                                            .rounded_md()
                                            .text_size(px(10.0))
                                            .text_color(t.text_muted)
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.danger_soft).text_color(t.danger))
                                            .tooltip(StermTooltip::text("Delete Command", *t))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.request_confirm(
                                                    ConfirmAction::DeleteCommand {
                                                        id: id_del.clone(),
                                                        command: cmd_del.clone(),
                                                    },
                                                    cx,
                                                );
                                            }))
                                            .child("✕"),
                                    ),
                            )
                    })),
            )
    }

    // =========================================================================
    // 5b. SSH Port Forwarding Tunnels Page (-L / -R / -D SOCKS5 + Live Stats)
    // =========================================================================
    pub fn render_tunnels_page(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let active_count = self.active_tunnels.len();
        let total_count = self.snapshot.port_forwards.len();

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            // Top Header Card
            .child(
                div()
                    .p_3p5()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2p5()
                            .child(
                                div()
                                    .w(px(34.0))
                                    .h(px(34.0))
                                    .rounded_lg()
                                    .bg(t.accent_soft)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(icon_svg(Icon::Network, 16.0, t.accent)),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_0p5()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text_primary)
                                                    .child("SSH Port Forwarding (-L / -R / -D SOCKS5)"),
                                            )
                                            .child(
                                                div()
                                                    .px_2()
                                                    .py(px(1.0))
                                                    .rounded_full()
                                                    .bg(if active_count > 0 {
                                                        t.success_soft
                                                    } else {
                                                        t.bg_subtle
                                                    })
                                                    .text_size(px(10.0))
                                                    .font_family("Consolas")
                                                    .text_color(if active_count > 0 {
                                                        t.success
                                                    } else {
                                                        t.text_muted
                                                    })
                                                    .child(format!(
                                                        "{active_count}/{total_count} active"
                                                    )),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(t.text_muted)
                                            .child("Saved in your E2EE vault. Reuses active SSH sessions or opens lightweight transport-only tunnels."),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .id("tunnels-new-btn")
                            .px_3p5()
                            .py_1p5()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .hover(|s| s.opacity(0.92))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_tunnel_editor(None, cx);
                            }))
                            .child("+ New Tunnel"),
                    ),
            )
            // Tunnels List Card
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .flex()
                    .flex_col()
                    .overflow_hidden()
                    .child(
                        div()
                            .px_4()
                            .py_2()
                            .bg(t.bg_subtle)
                            .border_b_1()
                            .border_color(t.border)
                            .grid()
                            .grid_cols(12)
                            .gap_2()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text_muted)
                            .child(div().col_span(3).child("TUNNEL & HOST"))
                            .child(div().col_span(4).child("ROUTE"))
                            .child(div().col_span(2).child("STATUS & TRAFFIC"))
                            .child(div().col_span(3).text_right().child("ACTIONS")),
                    )
                    .child(
                        div()
                            .id("tunnels-table-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .when(self.snapshot.port_forwards.is_empty(), |el| {
                                el.child(
                                    div()
                                        .py_12()
                                        .flex()
                                        .flex_col()
                                        .items_center()
                                        .gap_2p5()
                                        .child(icon_svg(Icon::Network, 26.0, t.text_muted))
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_weight(FontWeight::MEDIUM)
                                                .text_color(t.text_secondary)
                                                .child("No port forwarding tunnels configured yet"),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(t.text_muted)
                                                .child("Create a Local (-L), Remote (-R), or Dynamic SOCKS5 (-D) tunnel over any vault host."),
                                        )
                                        .child(
                                            div()
                                                .id("tunnels-empty-add")
                                                .mt_1()
                                                .px_3p5()
                                                .py_1p5()
                                                .rounded_lg()
                                                .bg(t.accent_solid)
                                                .text_color(gpui::white())
                                                .text_xs()
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .cursor_pointer()
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.open_tunnel_editor(None, cx);
                                                }))
                                                .child("+ Create First Tunnel"),
                                        ),
                                )
                            })
                            .children(self.snapshot.port_forwards.iter().enumerate().map(
                                |(ix, pf)| {
                                    let stats = self.active_tunnels.get(&pf.id).cloned();
                                    let is_active = stats.is_some();
                                    let host_label = self
                                        .snapshot
                                        .hosts
                                        .iter()
                                        .find(|h| h.id == pf.host_id)
                                        .map(|h| h.label.clone())
                                        .unwrap_or_else(|| "Unknown Host".to_string());

                                    let (kind_tag, kind_col, kind_bg) = match pf.kind {
                                        PortForwardKind::Local => ("-L LOCAL", t.accent, t.accent_soft),
                                        PortForwardKind::Remote => {
                                            ("-R REMOTE", t.warning, t.warning_soft)
                                        }
                                        PortForwardKind::DynamicSocks5 => {
                                            ("-D SOCKS5", t.success, t.success_soft)
                                        }
                                    };

                                    let route_str = match pf.kind {
                                        PortForwardKind::Local => format!(
                                            "{}:{}  →  {}:{}",
                                            pf.bind_address,
                                            pf.bind_port,
                                            pf.target_host.as_deref().unwrap_or("127.0.0.1"),
                                            pf.target_port.unwrap_or(0)
                                        ),
                                        PortForwardKind::Remote => format!(
                                            "remote {}:{}  →  local {}:{}",
                                            pf.bind_address,
                                            pf.bind_port,
                                            pf.target_host.as_deref().unwrap_or("127.0.0.1"),
                                            pf.target_port.unwrap_or(0)
                                        ),
                                        PortForwardKind::DynamicSocks5 => {
                                            format!("SOCKS5  {}:{}", pf.bind_address, pf.bind_port)
                                        }
                                    };

                                    let pf_start = pf.clone();
                                    let pf_edit = pf.clone();
                                    let tid_stop = pf.id.clone();
                                    let lbl_stop = pf.label.clone();
                                    let tid_del = pf.id.clone();
                                    let lbl_del = pf.label.clone();

                                    div()
                                        .id(("tun-row", ix))
                                        .px_4()
                                        .py_3()
                                        .border_b_1()
                                        .border_color(t.border)
                                        .hover(|s| s.bg(t.bg_subtle))
                                        .grid()
                                        .grid_cols(12)
                                        .gap_2()
                                        .items_center()
                                        // Col 1: Status dot + Label + Host
                                        .child(
                                            div()
                                                .col_span(3)
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .min_w_0()
                                                .child(
                                                    div()
                                                        .w(px(7.0))
                                                        .h(px(7.0))
                                                        .rounded_full()
                                                        .flex_shrink_0()
                                                        .bg(if is_active {
                                                            t.success
                                                        } else {
                                                            t.border_strong
                                                        }),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_col()
                                                        .min_w_0()
                                                        .child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_1p5()
                                                                .min_w_0()
                                                                .child(
                                                                    div()
                                                                        .text_xs()
                                                                        .font_weight(
                                                                            FontWeight::SEMIBOLD,
                                                                        )
                                                                        .text_color(t.text_primary)
                                                                        .truncate()
                                                                        .child(pf.label.clone()),
                                                                )
                                                                .when(pf.auto_start, |el| {
                                                                    el.child(
                                                                        div()
                                                                            .px_1()
                                                                            .py(px(1.0))
                                                                            .rounded_sm()
                                                                            .flex_shrink_0()
                                                                            .bg(t.accent_soft)
                                                                            .text_size(px(9.0))
                                                                            .font_weight(
                                                                                FontWeight::BOLD,
                                                                            )
                                                                            .text_color(t.accent)
                                                                            .child("AUTO"),
                                                                    )
                                                                }),
                                                        )
                                                        .child(
                                                            div()
                                                                .text_size(px(10.0))
                                                                .text_color(t.text_muted)
                                                                .truncate()
                                                                .child(format!("via {host_label}")),
                                                        ),
                                                ),
                                        )
                                        // Col 2: Kind badge + Route
                                        .child(
                                            div()
                                                .col_span(4)
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .min_w_0()
                                                .child(
                                                    div()
                                                        .px_1p5()
                                                        .py(px(1.0))
                                                        .rounded_sm()
                                                        .flex_shrink_0()
                                                        .bg(kind_bg)
                                                        .text_size(px(9.0))
                                                        .font_family("Consolas")
                                                        .font_weight(FontWeight::BOLD)
                                                        .text_color(kind_col)
                                                        .child(kind_tag),
                                                )
                                                .child(
                                                    div()
                                                        .text_xs()
                                                        .font_family("Consolas")
                                                        .text_color(t.text_secondary)
                                                        .truncate()
                                                        .child(route_str),
                                                ),
                                        )
                                        // Col 3: Live Traffic Stats
                                        .child(
                                            div()
                                                .col_span(2)
                                                .flex()
                                                .flex_col()
                                                .min_w_0()
                                                .child(if let Some(st) = stats {
                                                    div()
                                                        .flex()
                                                        .flex_col()
                                                        .child(
                                                            div()
                                                                .text_size(px(10.0))
                                                                .font_weight(FontWeight::SEMIBOLD)
                                                                .text_color(t.success)
                                                                .child(format!(
                                                                    "Active · {} conn",
                                                                    st.active_connections
                                                                )),
                                                        )
                                                        .child(
                                                            div()
                                                                .text_size(px(10.0))
                                                                .font_family("Consolas")
                                                                .text_color(t.text_muted)
                                                                .child(format!(
                                                                    "↑{}  ↓{}",
                                                                    format_bytes(st.bytes_tx),
                                                                    format_bytes(st.bytes_rx)
                                                                )),
                                                        )
                                                        .into_any_element()
                                                } else {
                                                    div()
                                                        .text_xs()
                                                        .text_color(t.text_muted)
                                                        .child("Stopped")
                                                        .into_any_element()
                                                }),
                                        )
                                        // Col 4: Start/Stop, Edit, Delete
                                        .child(
                                            div()
                                                .col_span(3)
                                                .flex()
                                                .items_center()
                                                .justify_end()
                                                .gap_1p5()
                                                .child(if is_active {
                                                    div()
                                                        .id(("tun-stop", ix))
                                                        .px_2p5()
                                                        .py_1()
                                                        .rounded_md()
                                                        .bg(t.danger_soft)
                                                        .border_1()
                                                        .border_color(t.danger)
                                                        .text_color(t.danger)
                                                        .text_size(px(11.0))
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .cursor_pointer()
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.stop_port_forward(
                                                                    tid_stop.clone(),
                                                                    lbl_stop.clone(),
                                                                    cx,
                                                                );
                                                            },
                                                        ))
                                                        .child("■ Stop")
                                                        .into_any_element()
                                                } else {
                                                    div()
                                                        .id(("tun-start", ix))
                                                        .px_2p5()
                                                        .py_1()
                                                        .rounded_md()
                                                        .bg(t.accent_solid)
                                                        .text_color(gpui::white())
                                                        .text_size(px(11.0))
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .cursor_pointer()
                                                        .hover(|s| s.opacity(0.92))
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.start_port_forward(
                                                                    pf_start.clone(),
                                                                    cx,
                                                                );
                                                            },
                                                        ))
                                                        .child("▶ Start")
                                                        .into_any_element()
                                                })
                                                .child(
                                                    div()
                                                        .id(("tun-edit", ix))
                                                        .px_2()
                                                        .py_1()
                                                        .rounded_md()
                                                        .border_1()
                                                        .border_color(t.border)
                                                        .text_size(px(11.0))
                                                        .text_color(t.text_muted)
                                                        .cursor_pointer()
                                                        .hover(|s| {
                                                            s.bg(t.bg_hover)
                                                                .text_color(t.text_primary)
                                                        })
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.open_tunnel_editor(
                                                                    Some(&pf_edit),
                                                                    cx,
                                                                );
                                                            },
                                                        ))
                                                        .child("Edit"),
                                                )
                                                .child(
                                                    div()
                                                        .id(("tun-del", ix))
                                                        .px_1p5()
                                                        .py_1()
                                                        .rounded_md()
                                                        .text_size(px(11.0))
                                                        .text_color(t.text_muted)
                                                        .cursor_pointer()
                                                        .hover(|s| {
                                                            s.bg(t.danger_soft).text_color(t.danger)
                                                        })
                                                        .tooltip(StermTooltip::text(
                                                            "Delete Tunnel",
                                                            *t,
                                                        ))
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.request_confirm(
                                                                    ConfirmAction::DeleteTunnel {
                                                                        id: tid_del.clone(),
                                                                        label: lbl_del.clone(),
                                                                    },
                                                                    cx,
                                                                );
                                                            },
                                                        ))
                                                        .child("✕"),
                                                ),
                                        )
                                },
                            )),
                    ),
            )
    }

    // =========================================================================
    // 6. Keychain, Trusted Known Hosts & Live SSH Agent Inspector
    // =========================================================================
    pub fn render_keychain_page(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        let q = self.keychain_search.read(cx).value().trim().to_lowercase();

        let filtered_creds: Vec<_> = self
            .snapshot
            .credentials
            .iter()
            .filter(|c| {
                q.is_empty()
                    || c.label.to_lowercase().contains(&q)
                    || c.username
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || c.fingerprint_sha256
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
            })
            .cloned()
            .collect();

        let filtered_kh: Vec<_> = self
            .snapshot
            .known_hosts
            .iter()
            .filter(|kh| {
                q.is_empty()
                    || kh.hostname.to_lowercase().contains(&q)
                    || kh.key_algorithm.to_lowercase().contains(&q)
                    || kh.fingerprint_sha256.to_lowercase().contains(&q)
            })
            .cloned()
            .collect();

        let filtered_agent: Vec<_> = self
            .agent_identities
            .iter()
            .filter(|id| {
                q.is_empty()
                    || id.comment.to_lowercase().contains(&q)
                    || id.algorithm.to_lowercase().contains(&q)
                    || id.fingerprint_sha256.to_lowercase().contains(&q)
            })
            .cloned()
            .collect();

        let tabs = [
            (
                KeychainTab::Credentials,
                format!("Credentials ({})", self.snapshot.credentials.len()),
            ),
            (
                KeychainTab::KnownHosts,
                format!("Known Hosts ({})", self.snapshot.known_hosts.len()),
            ),
            (
                KeychainTab::Agent,
                format!("SSH Agent ({})", self.agent_identities.len()),
            ),
        ];

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            // Top Sub-Tab & Search Bar
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2p5()
                    .flex_wrap()
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
                            .children(tabs.into_iter().enumerate().map(|(ix, (tab, lbl))| {
                                let active = self.keychain_tab == tab;
                                div()
                                    .id(("kc-tab", ix))
                                    .px_3()
                                    .py_1p5()
                                    .rounded_lg()
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
                                        this.keychain_tab = tab;
                                        if tab == KeychainTab::Agent {
                                            this.refresh_agent_identities(cx);
                                        } else {
                                            cx.notify();
                                        }
                                    }))
                                    .child(lbl)
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().w(px(230.0)).child(self.keychain_search.clone()))
                            .when(self.keychain_tab == KeychainTab::Credentials, |el| {
                                el.child(
                                    div()
                                        .id("kc-gen-ed25519")
                                        .px_2p5()
                                        .py_1p5()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(t.border_strong)
                                        .bg(t.bg_card)
                                        .text_xs()
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_hover))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.generate_ed25519_key(cx);
                                        }))
                                        .child("Generate Ed25519"),
                                )
                                .child(
                                    div()
                                        .id("kc-add-cred")
                                        .px_3()
                                        .py_1p5()
                                        .rounded_lg()
                                        .bg(t.accent_solid)
                                        .text_color(gpui::white())
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .cursor_pointer()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.open_credential_editor(None, cx);
                                        }))
                                        .child("+ Add Credential"),
                                )
                            })
                            .when(self.keychain_tab == KeychainTab::Agent, |el| {
                                el.child(
                                    div()
                                        .id("kc-agent-refresh")
                                        .px_3()
                                        .py_1p5()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(t.border_strong)
                                        .bg(t.bg_card)
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .cursor_pointer()
                                        .hover(|s| s.bg(t.bg_subtle))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.refresh_agent_identities(cx);
                                        }))
                                        .child("↻ Refresh Agent"),
                                )
                            }),
                    ),
            )
            // Tab Body Card
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_xl()
                    .bg(t.bg_card)
                    .border_1()
                    .border_color(t.border)
                    .shadow_sm()
                    .flex()
                    .flex_col()
                    .overflow_hidden()
                    .child(match self.keychain_tab {
                        KeychainTab::Credentials => div()
                            .id("kc-creds-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .when(filtered_creds.is_empty(), |el| {
                                el.child(
                                    div()
                                        .py_10()
                                        .text_center()
                                        .text_xs()
                                        .text_color(t.text_muted)
                                        .child(if self.snapshot.credentials.is_empty() {
                                            "No credentials stored yet. Generate an Ed25519 key or add an existing key/password."
                                        } else {
                                            "No credentials match your search query."
                                        }),
                                )
                            })
                            .children(filtered_creds.into_iter().enumerate().map(|(ix, c)| {
                                let used_by = self
                                    .snapshot
                                    .hosts
                                    .iter()
                                    .filter(|h| h.credential_id.as_deref() == Some(c.id.as_str()))
                                    .count();
                                let kind_lbl = match c.kind {
                                    CredentialKind::Password => "Password",
                                    CredentialKind::PrivateKey => "Private Key",
                                    CredentialKind::Certificate => "Certificate",
                                    CredentialKind::SshAgent => "SSH Agent",
                                    CredentialKind::KeyboardInteractive => "2FA / PAM",
                                };
                                let cid_edit = c.id.clone();
                                let cid_del = c.id.clone();
                                let clbl_del = c.label.clone();
                                let pubkey = c.public_key_openssh.clone();

                                div()
                                    .id(("kc-cred", ix))
                                    .p_3()
                                    .rounded_xl()
                                    .bg(t.bg_subtle)
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap_0p5()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap_1p5()
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .truncate()
                                                            .child(c.label.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .px_1p5()
                                                            .py_0p5()
                                                            .rounded_sm()
                                                            .bg(t.bg_card)
                                                            .text_size(px(10.0))
                                                            .text_color(t.accent)
                                                            .child(kind_lbl),
                                                    )
                                                    .child(
                                                        div()
                                                            .px_1p5()
                                                            .py_0p5()
                                                            .rounded_sm()
                                                            .bg(t.bg_card)
                                                            .text_size(px(10.0))
                                                            .text_color(t.text_muted)
                                                            .child(format!(
                                                                "Used by {used_by} host(s)"
                                                            )),
                                                    ),
                                            )
                                            .when_some(c.fingerprint_sha256.clone(), |s, fp| {
                                                s.child(
                                                    div()
                                                        .text_size(px(10.0))
                                                        .font_family("Consolas")
                                                        .text_color(t.text_muted)
                                                        .truncate()
                                                        .child(fp),
                                                )
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1()
                                            .flex_shrink_0()
                                            .when_some(pubkey, |el, pk| {
                                                let pk_deploy = pk.clone();
                                                let lbl_deploy = c.label.clone();
                                                el.child(
                                                    div()
                                                        .id(("kc-deploy-pk", ix))
                                                        .px_2()
                                                        .py_1()
                                                        .rounded_md()
                                                        .bg(t.accent_soft)
                                                        .border_1()
                                                        .border_color(t.accent)
                                                        .text_size(px(10.0))
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .text_color(t.accent)
                                                        .cursor_pointer()
                                                        .hover(|s| s.opacity(0.9))
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.open_deploy_key_modal(
                                                                    lbl_deploy.clone(),
                                                                    pk_deploy.clone(),
                                                                    cx,
                                                                );
                                                            },
                                                        ))
                                                        .child("Deploy Key"),
                                                )
                                                .child(
                                                    div()
                                                        .id(("kc-cp-pk", ix))
                                                        .px_2()
                                                        .py_1()
                                                        .rounded_md()
                                                        .border_1()
                                                        .border_color(t.border_strong)
                                                        .bg(t.bg_card)
                                                        .text_size(px(10.0))
                                                        .cursor_pointer()
                                                        .hover(|s| s.text_color(t.accent))
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                cx.write_to_clipboard(
                                                                    ClipboardItem::new_string(
                                                                        pk.clone(),
                                                                    ),
                                                                );
                                                                this.set_toast(
                                                                    "Public key copied to clipboard.",
                                                                    false,
                                                                );
                                                                cx.notify();
                                                            },
                                                        ))
                                                        .child("Copy PubKey"),
                                                )
                                            })
                                            .child(
                                                div()
                                                    .id(("kc-edit", ix))
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border)
                                                    .text_size(px(10.0))
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_card))
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.open_credential_editor(
                                                                Some(cid_edit.clone()),
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("Edit"),
                                            )
                                            .child(
                                                div()
                                                    .id(("kc-del", ix))
                                                    .px_1p5()
                                                    .py_1()
                                                    .rounded_md()
                                                    .text_size(px(10.0))
                                                    .text_color(t.text_muted)
                                                    .cursor_pointer()
                                                    .hover(|s| {
                                                        s.bg(t.danger_soft).text_color(t.danger)
                                                    })
                                                    .tooltip(StermTooltip::text(
                                                        "Delete Credential",
                                                        *t,
                                                    ))
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.request_confirm(
                                                                ConfirmAction::DeleteCredential {
                                                                    id: cid_del.clone(),
                                                                    label: clbl_del.clone(),
                                                                    used_by_count: used_by,
                                                                },
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child("✕"),
                                            ),
                                    )
                            }))
                            .into_any_element(),
                        KeychainTab::KnownHosts => div()
                            .id("kc-kh-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .when(filtered_kh.is_empty(), |el| {
                                el.child(
                                    div()
                                        .py_10()
                                        .text_center()
                                        .text_xs()
                                        .text_color(t.text_muted)
                                        .child(if self.snapshot.known_hosts.is_empty() {
                                            "Verified server host keys (TOFU) will appear here after your first SSH connection."
                                        } else {
                                            "No known hosts match your search query."
                                        }),
                                )
                            })
                            .children(filtered_kh.into_iter().enumerate().map(|(ix, kh)| {
                                let id_rev = kh.id.clone();
                                let lbl_rev = format!("{}:{}", kh.hostname, kh.port);
                                div()
                                    .id(("kc-kh", ix))
                                    .p_3()
                                    .rounded_xl()
                                    .bg(t.bg_subtle)
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap_0p5()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .font_family("Consolas")
                                                    .child(format!(
                                                        "{}:{} ({})",
                                                        kh.hostname, kh.port, kh.key_algorithm
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .font_family("Consolas")
                                                    .text_color(t.text_muted)
                                                    .truncate()
                                                    .child(kh.fingerprint_sha256.clone()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id(("kc-kh-rev", ix))
                                            .px_2()
                                            .py_1()
                                            .rounded_md()
                                            .text_size(px(10.0))
                                            .text_color(t.danger)
                                            .bg(t.danger_soft)
                                            .cursor_pointer()
                                            .flex_shrink_0()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.request_confirm(
                                                    ConfirmAction::RevokeKnownHost {
                                                        id: id_rev.clone(),
                                                        label: lbl_rev.clone(),
                                                    },
                                                    cx,
                                                );
                                            }))
                                            .child("Revoke"),
                                    )
                            }))
                            .into_any_element(),
                        KeychainTab::Agent => div()
                            .id("kc-agent-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .when_some(self.agent_error.clone(), |el, err| {
                                el.child(
                                    div()
                                        .p_3()
                                        .rounded_xl()
                                        .bg(t.warning_soft)
                                        .border_1()
                                        .border_color(t.warning)
                                        .text_xs()
                                        .text_color(t.warning)
                                        .child(format!("Local SSH Agent unavailable: {err}")),
                                )
                            })
                            .when(
                                self.agent_error.is_none() && filtered_agent.is_empty(),
                                |el| {
                                    el.child(
                                        div()
                                            .py_10()
                                            .text_center()
                                            .text_xs()
                                            .text_color(t.text_muted)
                                            .child(if self.agent_identities.is_empty() {
                                                "Local OS SSH Agent is running with 0 loaded keys. Add keys with `ssh-add` or click Refresh."
                                            } else {
                                                "No loaded agent keys match your search query."
                                            }),
                                    )
                                },
                            )
                            .children(filtered_agent.into_iter().enumerate().map(|(ix, id)| {
                                let fp_copy = id.fingerprint_sha256.clone();
                                div()
                                    .id(("kc-ag", ix))
                                    .p_3()
                                    .rounded_xl()
                                    .bg(t.bg_subtle)
                                    .border_1()
                                    .border_color(t.border)
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap_0p5()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap_1p5()
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .truncate()
                                                            .child(if id.comment.is_empty() {
                                                                format!("Agent Key #{}", ix + 1)
                                                            } else {
                                                                id.comment
                                                            }),
                                                    )
                                                    .child(
                                                        div()
                                                            .px_1p5()
                                                            .py_0p5()
                                                            .rounded_sm()
                                                            .bg(t.bg_card)
                                                            .font_family("Consolas")
                                                            .text_size(px(10.0))
                                                            .text_color(t.accent)
                                                            .child(id.algorithm),
                                                    )
                                                    .when(id.is_certificate, |s| {
                                                        s.child(
                                                            div()
                                                                .px_1p5()
                                                                .py_0p5()
                                                                .rounded_sm()
                                                                .bg(t.success_soft)
                                                                .text_size(px(10.0))
                                                                .text_color(t.success)
                                                                .child("CERT"),
                                                        )
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .font_family("Consolas")
                                                    .text_color(t.text_muted)
                                                    .truncate()
                                                    .child(id.fingerprint_sha256),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id(("kc-ag-cp", ix))
                                            .px_2()
                                            .py_1()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border_strong)
                                            .bg(t.bg_card)
                                            .text_size(px(10.0))
                                            .cursor_pointer()
                                            .flex_shrink_0()
                                            .hover(|s| s.text_color(t.accent))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                cx.write_to_clipboard(ClipboardItem::new_string(
                                                    fp_copy.clone(),
                                                ));
                                                this.set_toast(
                                                    "Key fingerprint copied to clipboard.",
                                                    false,
                                                );
                                                cx.notify();
                                            }))
                                            .child("Copy SHA256"),
                                    )
                            }))
                            .into_any_element(),
                    }),
            )
    }

    // =========================================================================
    // 7. Transfer Island Popover (Aligned right_4 + Clear Finished Button)
    // =========================================================================
    pub fn render_transfer_island_popover(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let island_epoch = self.island_epoch;

        div()
            .id("transfer-island-popover")
            .absolute()
            .top(px(50.0))
            .right_4()
            .w(px(360.0))
            .max_h(px(400.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_3p5()
            .flex()
            .flex_col()
            .gap_2p5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!(
                                "SFTP Transfers ({})",
                                self.sftp_state.transfers.len()
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .id("island-clear-done")
                                    .text_size(px(11.0))
                                    .text_color(t.accent)
                                    .cursor_pointer()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.sftp_state.clear_finished_transfers();
                                        if this.sftp_state.transfers.is_empty() {
                                            this.island_open = false;
                                        }
                                        cx.notify();
                                    }))
                                    .child("Clear Finished"),
                            )
                            .child(
                                div()
                                    .id("island-close")
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .cursor_pointer()
                                    .tooltip(StermTooltip::text("Close Transfer Panel", *t))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.island_open = false;
                                        cx.notify();
                                    }))
                                    .child("✕"),
                            ),
                    ),
            )
            .child(
                div()
                    .id("island-list")
                    .max_h(px(310.0))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(self.sftp_state.transfers.iter().enumerate().map(|(ix, tr)| {
                        let pct = transfer_percent(tr);
                        let arrow = direction_arrow(&tr.direction);
                        let running = matches!(tr.status, TransferStatus::Running);
                        let failed = matches!(tr.status, TransferStatus::Failed);
                        let speed_eta = self.sftp_state.transfer_speed_eta(tr);
                        let tr_retry = tr.clone();
                        div()
                            .p_2p5()
                            .rounded_lg()
                            .bg(t.bg_subtle)
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::MEDIUM)
                                            .truncate()
                                            .child(format!("{arrow} {}", tr.file_name)),
                                    )
                                    .child(if running {
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .flex_shrink_0()
                                            .when_some(speed_eta, |el, s| {
                                                el.child(
                                                    div()
                                                        .text_size(px(10.0))
                                                        .font_family("Consolas")
                                                        .text_color(t.text_muted)
                                                        .child(s),
                                                )
                                            })
                                            .child(loading_dots_indexed("tr-dots", ix, t.accent))
                                            .into_any_element()
                                    } else if failed {
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .flex_shrink_0()
                                            .child(
                                                div()
                                                    .id(("tr-retry", ix))
                                                    .px_1p5()
                                                    .py(px(1.0))
                                                    .rounded_sm()
                                                    .bg(t.danger_soft)
                                                    .border_1()
                                                    .border_color(t.danger)
                                                    .text_size(px(10.0))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.danger)
                                                    .cursor_pointer()
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.retry_failed_transfer(
                                                            tr_retry.clone(),
                                                            cx,
                                                        );
                                                    }))
                                                    .child("↻ Retry"),
                                            )
                                            .into_any_element()
                                    } else {
                                        div()
                                            .text_size(px(10.0))
                                            .font_family("Consolas")
                                            .text_color(match tr.status {
                                                TransferStatus::Completed => t.success,
                                                TransferStatus::Failed => t.danger,
                                                _ => t.warning,
                                            })
                                            .child(format!("{pct}%"))
                                            .into_any_element()
                                    }),
                            )
                            .when_some(tr.error.clone(), |el, err| {
                                el.child(
                                    div()
                                        .text_size(px(10.0))
                                        .text_color(t.danger)
                                        .truncate()
                                        .child(err),
                                )
                            })
                            .child(
                                div()
                                    .w_full()
                                    .h(px(4.0))
                                    .rounded_full()
                                    .bg(t.border)
                                    .overflow_hidden()
                                    .child(
                                        div()
                                            .h_full()
                                            .w(relative((pct as f32 / 100.0).clamp(0.0, 1.0)))
                                            .bg(match tr.status {
                                                TransferStatus::Failed => t.danger,
                                                TransferStatus::Completed => t.success,
                                                _ => t.accent_solid,
                                            }),
                                    ),
                            )
                    })),
            )
            .with_animation(
                ("island-pop", island_epoch),
                Animation::new(Duration::from_millis(160)).with_easing(ease_out_quint()),
                |el, delta| el.opacity(delta),
            )
    }
}
