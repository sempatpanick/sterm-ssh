use core_ssh::types::HostKeyStatus;
use core_vault::models::CredentialKind;
use gpui::{div, prelude::*, px, rgb, AnyElement, Context, Entity, FontWeight, MouseButton};

use crate::app::{ActiveModal, ConfirmAction, StermAdminApp};
use crate::motion::animate_modal_enter;
use crate::text_field::TextField;
use crate::theme::{TerminalThemeId, ThemePalette};

impl StermAdminApp {
    pub fn render_modal(
        &self,
        t: &ThemePalette,
        modal: ActiveModal,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let can_backdrop_dismiss = !matches!(
            modal,
            ActiveModal::HostKey(_) | ActiveModal::KeyboardInteractive(_)
        );

        let card: AnyElement = match modal {
            ActiveModal::CommandPalette => self.render_command_palette_modal(t, cx).into_any_element(),
            ActiveModal::QuickConnect => self.render_quick_connect_modal(t, cx).into_any_element(),
            ActiveModal::HostEditor { editing_id } => {
                self.render_host_editor_modal(t, editing_id, cx).into_any_element()
            }
            ActiveModal::GroupEditor { editing_id } => {
                self.render_group_editor_modal(t, editing_id, cx).into_any_element()
            }
            ActiveModal::CredentialEditor { editing_id } => self
                .render_credential_editor_modal(t, editing_id, cx)
                .into_any_element(),
            ActiveModal::SshConfigImport { entries, selected } => self
                .render_ssh_config_import_modal(t, entries, selected, cx)
                .into_any_element(),
            ActiveModal::SplitHostPicker {
                workspace_tab_id,
                target_pane_id,
                direction,
            } => self
                .render_split_host_picker_modal(t, workspace_tab_id, target_pane_id, direction, cx)
                .into_any_element(),
            ActiveModal::RemoteEditor {
                session_id,
                remote_path,
            } => self
                .render_remote_editor_modal(t, session_id, remote_path, cx)
                .into_any_element(),
            ActiveModal::RemoteChmod {
                session_id,
                remote_path,
            } => self
                .render_remote_chmod_modal(t, session_id, remote_path, cx)
                .into_any_element(),
            ActiveModal::RemoteRename {
                session_id,
                old_path,
                old_name,
            } => self
                .render_remote_rename_modal(t, session_id, old_path, old_name, cx)
                .into_any_element(),
            ActiveModal::HostKey(ch) => self.render_host_key_modal(t, ch, cx).into_any_element(),
            ActiveModal::KeyboardInteractive(ch) => {
                self.render_kbi_modal(t, ch, cx).into_any_element()
            }
            ActiveModal::Confirm(action) => {
                self.render_confirm_modal(t, action, cx).into_any_element()
            }
        };

        let animated_card = if self.settings.animations_enabled {
            animate_modal_enter(self.modal_epoch, card).into_any_element()
        } else {
            card
        };

        div()
            .id("modal-backdrop")
            .absolute()
            .inset_0()
            .bg(gpui::hsla(0.0, 0.0, 0.0, 0.48))
            .flex()
            .items_center()
            .justify_center()
            .p_6()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    if can_backdrop_dismiss {
                        this.modal = None;
                        cx.notify();
                    }
                }),
            )
            .child(
                div()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                        cx.stop_propagation();
                    })
                    .child(animated_card),
            )
    }

    // -------------------------------------------------------------------------
    // 1. Command Palette (Ctrl/Cmd+K)
    // -------------------------------------------------------------------------
    fn render_command_palette_modal(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let query = self.palette_query.read(cx).value().trim().to_string();
        let q = query.to_lowercase();
        let quick_target = Self::parse_quick_target(&query);

        let matched_hosts: Vec<_> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| {
                q.is_empty()
                    || h.label.to_lowercase().contains(&q)
                    || h.hostname.to_lowercase().contains(&q)
                    || h.username.to_lowercase().contains(&q)
                    || h.tags.iter().any(|tag| tag.to_lowercase().contains(&q))
            })
            .take(8)
            .cloned()
            .collect();

        let matched_snippets: Vec<_> = self
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
            .take(5)
            .cloned()
            .collect();

        div()
            .w(px(580.0))
            .max_h(px(620.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.modal_header(
                t,
                "Command Palette & Quick Connect",
                "Search saved hosts, pinned snippets, or type user@host:port to connect immediately.",
                cx,
            ))
            .child(self.palette_query.clone())
            // Quick Connect instant action when user types user@host[:port]
            .when_some(quick_target, |el, (user, host, port)| {
                let auth_modes = [
                    (CredentialKind::Password, "Password"),
                    (CredentialKind::SshAgent, "SSH Agent"),
                    (CredentialKind::KeyboardInteractive, "2FA / PAM"),
                ];
                let u_go = user.clone();
                let h_go = host.clone();
                el.child(
                    div()
                        .p_3()
                        .rounded_xl()
                        .bg(t.accent_soft)
                        .border_1()
                        .border_color(t.accent)
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(t.accent)
                                        .font_family("Consolas")
                                        .child(format!("Quick SSH → {user}@{host}:{port}")),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap_1()
                                        .children(auth_modes.into_iter().enumerate().map(
                                            |(ix, (kind, lbl))| {
                                                let active = self.palette_quick_auth == kind;
                                                let k_set = kind.clone();
                                                div()
                                                    .id(("pal-auth", ix))
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_md()
                                                    .text_size(px(11.0))
                                                    .cursor_pointer()
                                                    .bg(if active {
                                                        t.accent_solid
                                                    } else {
                                                        t.bg_card
                                                    })
                                                    .text_color(if active {
                                                        gpui::white()
                                                    } else {
                                                        t.text_secondary
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.palette_quick_auth = k_set.clone();
                                                        cx.notify();
                                                    }))
                                                    .child(lbl)
                                            },
                                        )),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .when(self.palette_quick_auth == CredentialKind::Password, |s| {
                                    s.child(div().flex_1().child(self.palette_quick_password.clone()))
                                })
                                .child(
                                    div()
                                        .id("pal-quick-go")
                                        .px_3p5()
                                        .py_1p5()
                                        .rounded_lg()
                                        .bg(t.accent_solid)
                                        .text_color(gpui::white())
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .cursor_pointer()
                                        .on_click(cx.listener(move |this, _, window, cx| {
                                            let pw = this
                                                .palette_quick_password
                                                .read(cx)
                                                .value()
                                                .to_string();
                                            let auth = this.palette_quick_auth.clone();
                                            this.launch_quick_connect(
                                                h_go.clone(),
                                                port,
                                                u_go.clone(),
                                                auth,
                                                pw,
                                                Some(window),
                                                cx,
                                            );
                                        }))
                                        .child("Connect SSH"),
                                ),
                        ),
                )
            })
            // Matching Hosts + Snippets scroll area
            .child(
                div()
                    .id("palette-results-scroll")
                    .max_h(px(360.0))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(10.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text_muted)
                            .child(format!("SAVED HOSTS ({})", matched_hosts.len())),
                    )
                    .when(matched_hosts.is_empty(), |el| {
                        el.child(
                            div()
                                .py_2()
                                .text_xs()
                                .text_color(t.text_muted)
                                .child("No matching hosts. Type user@host:22 above for Quick Connect."),
                        )
                    })
                    .children(matched_hosts.into_iter().enumerate().map(|(ix, h)| {
                        let hid_ssh = h.id.clone();
                        let hid_sftp = h.id.clone();
                        div()
                            .id(("pal-host", ix))
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .bg(t.bg_subtle)
                            .hover(|s| s.bg(t.bg_hover))
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.modal = None;
                                this.connect_host_ssh(hid_ssh.clone(), window, cx);
                            }))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .min_w_0()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.text_primary)
                                            .child(h.label.clone()),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_family("Consolas")
                                            .text_color(t.text_muted)
                                            .child(format!(
                                                "{}@{}:{}",
                                                h.username, h.hostname, h.port
                                            )),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .id(("pal-host-sftp", ix))
                                            .px_2()
                                            .py_1()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border_strong)
                                            .text_size(px(11.0))
                                            .text_color(t.text_secondary)
                                            .hover(|s| s.bg(t.bg_card).text_color(t.text_primary))
                                            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                                cx.stop_propagation();
                                            })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                cx.stop_propagation();
                                                this.modal = None;
                                                this.open_sftp_for_host(hid_sftp.clone(), cx);
                                            }))
                                            .child("SFTP"),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .py_1()
                                            .rounded_md()
                                            .bg(t.accent_soft)
                                            .text_size(px(11.0))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(t.accent)
                                            .child("SSH ↵"),
                                    ),
                            )
                    }))
                    .when(!matched_snippets.is_empty(), |el| {
                        el.child(
                            div()
                                .pt_2()
                                .text_size(px(10.0))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(t.text_muted)
                                .child("PINNED SNIPPETS (RUN IN ACTIVE TERMINAL)"),
                        )
                        .children(matched_snippets.into_iter().enumerate().map(|(ix, cmd)| {
                            let cmd_str = cmd.command.clone();
                            div()
                                .id(("pal-snip", ix))
                                .px_3()
                                .py_1p5()
                                .rounded_lg()
                                .bg(t.bg_subtle)
                                .hover(|s| s.bg(t.bg_hover))
                                .flex()
                                .items_center()
                                .justify_between()
                                .gap_2()
                                .cursor_pointer()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.modal = None;
                                    this.run_snippet_in_active_terminal(cmd_str.clone(), cx);
                                }))
                                .child(
                                    div()
                                        .text_xs()
                                        .font_family("Consolas")
                                        .text_color(t.text_primary)
                                        .truncate()
                                        .child(cmd.command),
                                )
                                .when_some(cmd.label, |s, lbl| {
                                    s.child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(t.text_muted)
                                            .child(lbl),
                                    )
                                })
                        }))
                    }),
            )
    }

    // -------------------------------------------------------------------------
    // 2. Quick Connect Modal
    // -------------------------------------------------------------------------
    fn render_quick_connect_modal(
        &self,
        t: &ThemePalette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let auth_choices = [
            (CredentialKind::Password, "Password"),
            (CredentialKind::SshAgent, "SSH Agent"),
            (CredentialKind::KeyboardInteractive, "2FA / Interactive"),
        ];

        div()
            .w(px(460.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(self.modal_header(
                t,
                "Quick SSH Connect",
                "Open a live terminal session immediately. You can save it to the Vault from the terminal header.",
                cx,
            ))
            .child(self.labeled_field(t, "Hostname or IP", self.qc_hostname.clone()))
            .child(
                div()
                    .grid()
                    .grid_cols(3)
                    .gap_2p5()
                    .child(div().col_span(2).child(self.labeled_field(
                        t,
                        "Username",
                        self.qc_username.clone(),
                    )))
                    .child(self.labeled_field(t, "Port", self.qc_port.clone())),
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
                            .child("Authentication"),
                    )
                    .child(div().flex().gap_1p5().children(auth_choices.into_iter().enumerate().map(
                        |(ix, (kind, lbl))| {
                            let active = self.qc_auth_choice == kind;
                            let k_set = kind.clone();
                            div()
                                .id(("qc-auth", ix))
                                .px_2p5()
                                .py_1()
                                .rounded_lg()
                                .border_1()
                                .text_xs()
                                .cursor_pointer()
                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                .border_color(if active { t.accent } else { t.border })
                                .text_color(if active { t.accent } else { t.text_secondary })
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.qc_auth_choice = k_set.clone();
                                    cx.notify();
                                }))
                                .child(lbl)
                        },
                    ))),
            )
            .when(self.qc_auth_choice == CredentialKind::Password, |el| {
                el.child(self.labeled_field(
                    t,
                    "Password (leave empty to try SSH Agent)",
                    self.qc_password.clone(),
                ))
            })
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .pt_2()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("modal-qc-submit")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .hover(|s| s.opacity(0.92))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.submit_quick_connect(window, cx);
                            }))
                            .child("Connect SSH"),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 3. Full Host Editor Modal (Complete Feature Parity + ProxyJump + Native File Pickers)
    // -------------------------------------------------------------------------
    fn render_host_editor_modal(
        &self,
        t: &ThemePalette,
        editing_id: Option<String>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_edit = editing_id.is_some();
        let auth_modes = [
            (CredentialKind::Password, "Password"),
            (CredentialKind::PrivateKey, "Private Key"),
            (CredentialKind::Certificate, "Certificate"),
            (CredentialKind::SshAgent, "SSH Agent"),
            (CredentialKind::KeyboardInteractive, "2FA / PAM"),
        ];

        let jump_candidates: Vec<_> = self
            .snapshot
            .hosts
            .iter()
            .filter(|h| editing_id.as_deref() != Some(h.id.as_str()))
            .cloned()
            .collect();

        let editing_for_save = editing_id.clone();

        div()
            .w(px(640.0))
            .max_h(px(740.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.modal_header(
                t,
                if is_edit {
                    "Edit Server Profile"
                } else {
                    "Add Server to Vault"
                },
                "Encrypted with AES-256-GCM before persisting locally or syncing.",
                cx,
            ))
            .child(
                div()
                    .id("host-editor-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .pr_1()
                    .flex()
                    .flex_col()
                    .gap_3()
                    // Row 1: Label & Group
                    .child(
                        div()
                            .grid()
                            .grid_cols(2)
                            .gap_2p5()
                            .child(self.labeled_field(t, "Display Label", self.qc_label.clone()))
                            .child(self.labeled_field(
                                t,
                                "Group (existing or new)",
                                self.qc_group_name.clone(),
                            )),
                    )
                    // Row 2: Hostname, Port, Username
                    .child(
                        div()
                            .grid()
                            .grid_cols(4)
                            .gap_2p5()
                            .child(div().col_span(2).child(self.labeled_field(
                                t,
                                "Hostname / IP",
                                self.qc_hostname.clone(),
                            )))
                            .child(self.labeled_field(t, "Port", self.qc_port.clone()))
                            .child(self.labeled_field(t, "Username", self.qc_username.clone())),
                    )
                    // Auth mode selector
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
                                    .child("Authentication Method"),
                            )
                            .child(div().flex().flex_wrap().gap_1p5().children(
                                auth_modes.into_iter().enumerate().map(|(ix, (kind, lbl))| {
                                    let active = self.qc_auth_choice == kind;
                                    let k_set = kind.clone();
                                    div()
                                        .id(("he-auth", ix))
                                        .px_2p5()
                                        .py_1()
                                        .rounded_lg()
                                        .border_1()
                                        .text_xs()
                                        .cursor_pointer()
                                        .bg(if active { t.accent_soft } else { t.bg_subtle })
                                        .border_color(if active { t.accent } else { t.border })
                                        .text_color(if active {
                                            t.accent
                                        } else {
                                            t.text_secondary
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.qc_auth_choice = k_set.clone();
                                            cx.notify();
                                        }))
                                        .child(lbl)
                                }),
                            )),
                    )
                    // Saved Keychain Credential Picker (reuse existing credentials!)
                    .when(!self.snapshot.credentials.is_empty(), |el| {
                        el.child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(
                                    div()
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(t.text_secondary)
                                        .child("Saved Keychain Credential (optional)"),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .gap_1p5()
                                        .child(
                                            div()
                                                .id("he-cred-none")
                                                .px_2()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .text_size(px(11.0))
                                                .cursor_pointer()
                                                .bg(if self.selected_credential_id.is_none() {
                                                    t.accent_soft
                                                } else {
                                                    t.bg_subtle
                                                })
                                                .border_color(
                                                    if self.selected_credential_id.is_none() {
                                                        t.accent
                                                    } else {
                                                        t.border
                                                    },
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.selected_credential_id = None;
                                                    cx.notify();
                                                }))
                                                .child("None / Group Default"),
                                        )
                                        .children(self.snapshot.credentials.iter().enumerate().map(
                                            |(ix, c)| {
                                                let cid = c.id.clone();
                                                let active = self.selected_credential_id.as_deref()
                                                    == Some(c.id.as_str());
                                                let ckind = c.kind.clone();
                                                div()
                                                    .id(("he-cred", ix))
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .text_size(px(11.0))
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
                                                        this.selected_credential_id =
                                                            Some(cid.clone());
                                                        this.qc_auth_choice = ckind.clone();
                                                        cx.notify();
                                                    }))
                                                    .child(c.label.clone())
                                            },
                                        )),
                                ),
                        )
                    })
                    // Inline Auth Secret Inputs (depending on selected auth mode)
                    .when(self.qc_auth_choice == CredentialKind::Password, |el| {
                        el.child(self.labeled_field(
                            t,
                            if is_edit {
                                "Update Password (leave blank to keep existing)"
                            } else {
                                "Inline Password (optional)"
                            },
                            self.qc_password.clone(),
                        ))
                    })
                    .when(
                        matches!(
                            self.qc_auth_choice,
                            CredentialKind::PrivateKey | CredentialKind::Certificate
                        ),
                        |el| {
                            let pem_field = self.qc_key_pem.clone();
                            let cert_field = self.qc_cert_openssh.clone();
                            el.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
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
                                                    .child("Private Key PEM (paste or load from file)"),
                                            )
                                            .child(
                                                div()
                                                    .id("he-pick-key")
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_md()
                                                    .border_1()
                                                    .border_color(t.border_strong)
                                                    .text_size(px(11.0))
                                                    .cursor_pointer()
                                                    .hover(|s| s.bg(t.bg_subtle))
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.pick_file_into_field(
                                                            pem_field.clone(),
                                                            cx,
                                                        );
                                                    }))
                                                    .child("Browse Key File..."),
                                            ),
                                    )
                                    .child(self.qc_key_pem.clone())
                                    .child(self.labeled_field(
                                        t,
                                        "Key Passphrase (optional)",
                                        self.qc_key_passphrase.clone(),
                                    ))
                                    .when(
                                        self.qc_auth_choice == CredentialKind::Certificate,
                                        |s| {
                                            s.child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .justify_between()
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .font_weight(FontWeight::MEDIUM)
                                                            .text_color(t.text_secondary)
                                                            .child("OpenSSH Certificate (*-cert.pub)"),
                                                    )
                                                    .child(
                                                        div()
                                                            .id("he-pick-cert")
                                                            .px_2()
                                                            .py_0p5()
                                                            .rounded_md()
                                                            .border_1()
                                                            .border_color(t.border_strong)
                                                            .text_size(px(11.0))
                                                            .cursor_pointer()
                                                            .hover(|h| h.bg(t.bg_subtle))
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.pick_file_into_field(
                                                                        cert_field.clone(),
                                                                        cx,
                                                                    );
                                                                },
                                                            ))
                                                            .child("Browse Cert File..."),
                                                    ),
                                            )
                                            .child(self.qc_cert_openssh.clone())
                                        },
                                    ),
                            )
                        },
                    )
                    // Jump Host / Bastion (ProxyJump)
                    .when(!jump_candidates.is_empty(), |el| {
                        el.child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(
                                    div()
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(t.text_secondary)
                                        .child("Jump Host / Bastion (ProxyJump)"),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .gap_1p5()
                                        .child(
                                            div()
                                                .id("he-jump-none")
                                                .px_2()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .text_size(px(11.0))
                                                .cursor_pointer()
                                                .bg(if self.selected_jump_host_id.is_none() {
                                                    t.accent_soft
                                                } else {
                                                    t.bg_subtle
                                                })
                                                .border_color(
                                                    if self.selected_jump_host_id.is_none() {
                                                        t.accent
                                                    } else {
                                                        t.border
                                                    },
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.selected_jump_host_id = None;
                                                    cx.notify();
                                                }))
                                                .child("Direct Connection"),
                                        )
                                        .children(jump_candidates.into_iter().enumerate().map(
                                            |(ix, jh)| {
                                                let jid = jh.id.clone();
                                                let active = self.selected_jump_host_id.as_deref()
                                                    == Some(jh.id.as_str());
                                                div()
                                                    .id(("he-jump", ix))
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_md()
                                                    .border_1()
                                                    .text_size(px(11.0))
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
                                                        this.selected_jump_host_id =
                                                            Some(jid.clone());
                                                        cx.notify();
                                                    }))
                                                    .child(format!("via {}", jh.label))
                                            },
                                        )),
                                ),
                        )
                    })
                    // Per-Host Terminal Theme Override
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_secondary)
                                    .child("Terminal Theme Override"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .id("he-theme-default")
                                            .px_2()
                                            .py_1()
                                            .rounded_md()
                                            .border_1()
                                            .text_size(px(11.0))
                                            .cursor_pointer()
                                            .bg(if self.selected_terminal_theme.is_none() {
                                                t.accent_soft
                                            } else {
                                                t.bg_subtle
                                            })
                                            .border_color(
                                                if self.selected_terminal_theme.is_none() {
                                                    t.accent
                                                } else {
                                                    t.border
                                                },
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.selected_terminal_theme = None;
                                                cx.notify();
                                            }))
                                            .child("Workspace Default"),
                                    )
                                    .children(TerminalThemeId::ALL.into_iter().enumerate().map(
                                        |(ix, tid)| {
                                            let slug = tid.slug();
                                            let active = self.selected_terminal_theme.as_deref()
                                                == Some(slug);
                                            let (bg_hex, _, cur_hex) = tid.colors();
                                            div()
                                                .id(("he-theme", ix))
                                                .px_2()
                                                .py_1()
                                                .rounded_md()
                                                .border_1()
                                                .flex()
                                                .items_center()
                                                .gap_1p5()
                                                .text_size(px(11.0))
                                                .cursor_pointer()
                                                .bg(if active { t.accent_soft } else { t.bg_subtle })
                                                .border_color(if active {
                                                    t.accent
                                                } else {
                                                    t.border
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.selected_terminal_theme =
                                                        Some(slug.to_string());
                                                    cx.notify();
                                                }))
                                                .child(
                                                    div()
                                                        .w(px(10.0))
                                                        .h(px(10.0))
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
                    // Metadata: Tags, Keepalive, Startup Command, Notes
                    .child(
                        div()
                            .grid()
                            .grid_cols(3)
                            .gap_2p5()
                            .child(div().col_span(2).child(self.labeled_field(
                                t,
                                "Tags (comma-separated)",
                                self.qc_tags.clone(),
                            )))
                            .child(self.labeled_field(
                                t,
                                "Keepalive (secs)",
                                self.qc_keepalive.clone(),
                            )),
                    )
                    .child(self.labeled_field(
                        t,
                        "Startup Command (optional)",
                        self.qc_startup_cmd.clone(),
                    ))
                    .child(self.labeled_field(t, "Notes (optional)", self.qc_notes.clone())),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .pt_2()
                    .border_t_1()
                    .border_color(t.border)
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("modal-host-save")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .hover(|s| s.opacity(0.92))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.save_host_from_modal(editing_for_save.clone(), cx);
                            }))
                            .child(if is_edit { "Save Changes" } else { "Save Server" }),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 4. Group Editor Modal (with Default Username & Default Credential Inheritance)
    // -------------------------------------------------------------------------
    fn render_group_editor_modal(
        &self,
        t: &ThemePalette,
        editing_id: Option<String>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_edit = editing_id.is_some();
        let save_id = editing_id.clone();
        let del_info = editing_id.as_deref().and_then(|eid| {
            self.snapshot
                .groups
                .iter()
                .find(|g| g.id == eid)
                .map(|g| (g.id.clone(), g.name.clone()))
        });

        div()
            .w(px(460.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(self.modal_header(
                t,
                if is_edit { "Edit Group" } else { "New Host Group" },
                "Hosts in this group inherit default username and credential when not overridden.",
                cx,
            ))
            .child(self.labeled_field(t, "Group Name", self.grp_name_input.clone()))
            .child(self.labeled_field(
                t,
                "Default Username (optional)",
                self.grp_default_user_input.clone(),
            ))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(t.text_secondary)
                            .child("Default Keychain Credential"),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_1p5()
                            .child(
                                div()
                                    .id("grp-cred-none")
                                    .px_2()
                                    .py_1()
                                    .rounded_md()
                                    .border_1()
                                    .text_size(px(11.0))
                                    .cursor_pointer()
                                    .bg(if self.grp_default_cred_id.is_none() {
                                        t.accent_soft
                                    } else {
                                        t.bg_subtle
                                    })
                                    .border_color(if self.grp_default_cred_id.is_none() {
                                        t.accent
                                    } else {
                                        t.border
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.grp_default_cred_id = None;
                                        cx.notify();
                                    }))
                                    .child("None"),
                            )
                            .children(self.snapshot.credentials.iter().enumerate().map(|(ix, c)| {
                                let cid = c.id.clone();
                                let active =
                                    self.grp_default_cred_id.as_deref() == Some(c.id.as_str());
                                div()
                                    .id(("grp-cred", ix))
                                    .px_2()
                                    .py_1()
                                    .rounded_md()
                                    .border_1()
                                    .text_size(px(11.0))
                                    .cursor_pointer()
                                    .bg(if active { t.accent_soft } else { t.bg_subtle })
                                    .border_color(if active { t.accent } else { t.border })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.grp_default_cred_id = Some(cid.clone());
                                        cx.notify();
                                    }))
                                    .child(c.label.clone())
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .pt_2()
                    .child(div().when_some(del_info, |el, (gid, gname)| {
                        el.child(
                            div()
                                .id("grp-delete-btn")
                                .px_3()
                                .py_2()
                                .rounded_lg()
                                .bg(t.danger_soft)
                                .text_color(t.danger)
                                .text_xs()
                                .font_weight(FontWeight::SEMIBOLD)
                                .cursor_pointer()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.request_confirm(
                                        ConfirmAction::DeleteGroup {
                                            id: gid.clone(),
                                            name: gname.clone(),
                                        },
                                        cx,
                                    );
                                }))
                                .child("Delete Group"),
                        )
                    }))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(self.cancel_modal_btn(t, cx))
                            .child(
                                div()
                                    .id("grp-save-btn")
                                    .px_4()
                                    .py_2()
                                    .rounded_lg()
                                    .bg(t.accent_solid)
                                    .text_color(gpui::white())
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .cursor_pointer()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.save_group_from_modal(save_id.clone(), cx);
                                    }))
                                    .child("Save Group"),
                            ),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 5. Credential Editor Modal (All 5 CredentialKinds + Create/Edit + Native Pickers)
    // -------------------------------------------------------------------------
    fn render_credential_editor_modal(
        &self,
        t: &ThemePalette,
        editing_id: Option<String>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_edit = editing_id.is_some();
        let save_id = editing_id;
        let kinds = [
            (CredentialKind::PrivateKey, "Private Key"),
            (CredentialKind::Password, "Password"),
            (CredentialKind::Certificate, "Certificate"),
            (CredentialKind::SshAgent, "SSH Agent"),
            (CredentialKind::KeyboardInteractive, "2FA / PAM"),
        ];
        let secret_field = self.cred_secret.clone();
        let cert_field = self.cred_cert.clone();

        div()
            .w(px(540.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(self.modal_header(
                t,
                if is_edit {
                    "Edit Keychain Credential"
                } else {
                    "Add Keychain Credential"
                },
                "Private keys and certificates are validated before saving to the encrypted vault.",
                cx,
            ))
            .child(div().flex().flex_wrap().gap_1p5().children(kinds.into_iter().enumerate().map(
                |(ix, (kind, lbl))| {
                    let active = self.key_auth_choice == kind;
                    let k_set = kind.clone();
                    div()
                        .id(("cred-kind", ix))
                        .px_2p5()
                        .py_1()
                        .rounded_lg()
                        .border_1()
                        .text_xs()
                        .cursor_pointer()
                        .bg(if active { t.accent_soft } else { t.bg_subtle })
                        .border_color(if active { t.accent } else { t.border })
                        .text_color(if active { t.accent } else { t.text_secondary })
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.key_auth_choice = k_set.clone();
                            cx.notify();
                        }))
                        .child(lbl)
                },
            )))
            .child(
                div()
                    .grid()
                    .grid_cols(2)
                    .gap_2p5()
                    .child(self.labeled_field(t, "Label", self.cred_label.clone()))
                    .child(self.labeled_field(
                        t,
                        "Default Username (optional)",
                        self.cred_username.clone(),
                    )),
            )
            .when(self.key_auth_choice == CredentialKind::Password, |el| {
                el.child(self.labeled_field(
                    t,
                    if is_edit {
                        "New Password (leave blank to keep existing)"
                    } else {
                        "Password"
                    },
                    self.cred_secret.clone(),
                ))
            })
            .when(
                matches!(
                    self.key_auth_choice,
                    CredentialKind::PrivateKey | CredentialKind::Certificate
                ),
                |el| {
                    el.child(
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
                                            .child(if is_edit {
                                                "Private Key PEM (blank to keep existing)"
                                            } else {
                                                "Private Key PEM"
                                            }),
                                    )
                                    .child(
                                        div()
                                            .id("cred-pick-key")
                                            .px_2()
                                            .py_0p5()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(t.border_strong)
                                            .text_size(px(11.0))
                                            .cursor_pointer()
                                            .hover(|s| s.bg(t.bg_subtle))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.pick_file_into_field(secret_field.clone(), cx);
                                            }))
                                            .child("Browse Key File..."),
                                    ),
                            )
                            .child(self.cred_secret.clone()),
                    )
                    .child(self.labeled_field(
                        t,
                        "Key Passphrase (optional)",
                        self.cred_passphrase.clone(),
                    ))
                    .when(self.key_auth_choice == CredentialKind::Certificate, |s| {
                        s.child(
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
                                                .child("OpenSSH Certificate (*-cert.pub)"),
                                        )
                                        .child(
                                            div()
                                                .id("cred-pick-cert")
                                                .px_2()
                                                .py_0p5()
                                                .rounded_md()
                                                .border_1()
                                                .border_color(t.border_strong)
                                                .text_size(px(11.0))
                                                .cursor_pointer()
                                                .hover(|h| h.bg(t.bg_subtle))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.pick_file_into_field(
                                                        cert_field.clone(),
                                                        cx,
                                                    );
                                                }))
                                                .child("Browse Cert File..."),
                                        ),
                                )
                                .child(self.cred_cert.clone()),
                        )
                    })
                },
            )
            .when(
                matches!(
                    self.key_auth_choice,
                    CredentialKind::SshAgent | CredentialKind::KeyboardInteractive
                ),
                |el| {
                    el.child(
                        div()
                            .p_2p5()
                            .rounded_lg()
                            .bg(t.bg_subtle)
                            .text_xs()
                            .text_color(t.text_muted)
                            .child(if self.key_auth_choice == CredentialKind::SshAgent {
                                "Uses your local OS SSH Agent (ssh-agent / Pageant / 1Password) at connect time."
                            } else {
                                "Prompts dynamically for PAM / 2FA OTP challenges when connecting."
                            }),
                    )
                },
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .pt_2()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("modal-cred-save")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.save_credential_from_modal(save_id.clone(), cx);
                            }))
                            .child(if is_edit {
                                "Save Changes"
                            } else {
                                "Save Credential"
                            }),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 6. Selective SSH Config Import Preview Modal
    // -------------------------------------------------------------------------
    fn render_ssh_config_import_modal(
        &self,
        t: &ThemePalette,
        entries: Vec<core_vault::ssh_config::ParsedSshHost>,
        selected: Vec<bool>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let selected_count = selected.iter().filter(|&&s| s).count();
        let total = entries.len();

        div()
            .w(px(620.0))
            .max_h(px(660.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.modal_header(
                t,
                "Import SSH Config Hosts",
                "Review parsed hosts from ~/.ssh/config or choose another OpenSSH config file.",
                cx,
            ))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_xs()
                            .text_color(t.text_muted)
                            .child(format!("{selected_count} of {total} host(s) selected")),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .child(
                                div()
                                    .id("ssh-imp-all")
                                    .px_2()
                                    .py_1()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .text_size(px(11.0))
                                    .cursor_pointer()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        if let Some(ActiveModal::SshConfigImport {
                                            selected, ..
                                        }) = &mut this.modal
                                        {
                                            let all_on = selected.iter().all(|&s| s);
                                            for s in selected.iter_mut() {
                                                *s = !all_on;
                                            }
                                            cx.notify();
                                        }
                                    }))
                                    .child(if selected_count == total && total > 0 {
                                        "Deselect All"
                                    } else {
                                        "Select All"
                                    }),
                            )
                            .child(
                                div()
                                    .id("ssh-imp-browse")
                                    .px_2p5()
                                    .py_1()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(t.border_strong)
                                    .text_size(px(11.0))
                                    .cursor_pointer()
                                    .hover(|s| s.bg(t.bg_subtle))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.pick_custom_ssh_config(cx);
                                    }))
                                    .child("Browse File..."),
                            ),
                    ),
            )
            .child(
                div()
                    .id("ssh-imp-list")
                    .max_h(px(360.0))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .when(entries.is_empty(), |el| {
                        el.child(
                            div()
                                .py_6()
                                .text_center()
                                .text_xs()
                                .text_color(t.text_muted)
                                .child("No concrete Host entries found in this SSH config file."),
                        )
                    })
                    .children(entries.into_iter().enumerate().map(|(ix, entry)| {
                        let is_checked = selected.get(ix).copied().unwrap_or(false);
                        div()
                            .id(("ssh-imp-row", ix))
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(if is_checked { t.accent } else { t.border })
                            .bg(if is_checked { t.accent_soft } else { t.bg_subtle })
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(ActiveModal::SshConfigImport { selected, .. }) =
                                    &mut this.modal
                                {
                                    if let Some(slot) = selected.get_mut(ix) {
                                        *slot = !*slot;
                                    }
                                    cx.notify();
                                }
                            }))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2p5()
                                    .min_w_0()
                                    .child(
                                        div()
                                            .w(px(15.0))
                                            .h(px(15.0))
                                            .rounded(px(4.0))
                                            .border_1()
                                            .border_color(if is_checked {
                                                t.accent_solid
                                            } else {
                                                t.border_strong
                                            })
                                            .bg(if is_checked {
                                                t.accent_solid
                                            } else {
                                                t.bg_card
                                            })
                                            .text_color(gpui::white())
                                            .text_size(px(10.0))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .child(if is_checked { "✓" } else { "" }),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(t.text_primary)
                                                    .child(entry.alias),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_family("Consolas")
                                                    .text_color(t.text_muted)
                                                    .child(format!(
                                                        "{}@{}:{}",
                                                        entry.username, entry.hostname, entry.port
                                                    )),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .when_some(entry.proxy_jump, |s, pj| {
                                        s.child(
                                            div()
                                                .px_1p5()
                                                .py_0p5()
                                                .rounded_sm()
                                                .bg(t.bg_card)
                                                .text_size(px(10.0))
                                                .text_color(t.accent)
                                                .child(format!("via {pj}")),
                                        )
                                    })
                                    .when(entry.identity_file.is_some(), |s| {
                                        s.child(
                                            div()
                                                .px_1p5()
                                                .py_0p5()
                                                .rounded_sm()
                                                .bg(t.bg_card)
                                                .text_size(px(10.0))
                                                .text_color(t.text_muted)
                                                .child("key"),
                                        )
                                    }),
                            )
                    })),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .pt_2()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("ssh-imp-submit")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.import_selected_ssh_config(cx);
                            }))
                            .child(format!("Import Selected ({selected_count})")),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 7. Split Host Picker Modal (Split pane with a DIFFERENT saved host!)
    // -------------------------------------------------------------------------
    fn render_split_host_picker_modal(
        &self,
        t: &ThemePalette,
        workspace_tab_id: String,
        target_pane_id: String,
        direction: crate::split_tree::SplitDirection,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .w(px(460.0))
            .max_h(px(540.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.modal_header(
                t,
                "Split Pane with Host",
                "Choose a saved server to open in the new split pane.",
                cx,
            ))
            .child(
                div()
                    .id("split-host-list")
                    .max_h(px(340.0))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .when(self.snapshot.hosts.is_empty(), |el| {
                        el.child(
                            div()
                                .py_4()
                                .text_xs()
                                .text_color(t.text_muted)
                                .text_center()
                                .child("No saved hosts yet. Add one from the Vault tab."),
                        )
                    })
                    .children(self.snapshot.hosts.iter().enumerate().map(|(ix, h)| {
                        let ws = workspace_tab_id.clone();
                        let pid = target_pane_id.clone();
                        let hid = h.id.clone();
                        div()
                            .id(("split-pick", ix))
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .bg(t.bg_subtle)
                            .hover(|s| s.bg(t.bg_hover))
                            .flex()
                            .items_center()
                            .justify_between()
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.modal = None;
                                this.split_pane_duplicate_or_host(
                                    ws.clone(),
                                    pid.clone(),
                                    direction,
                                    Some(hid.clone()),
                                    cx,
                                );
                            }))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(h.label.clone()),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .font_family("Consolas")
                                            .text_color(t.text_muted)
                                            .child(format!(
                                                "{}@{}:{}",
                                                h.username, h.hostname, h.port
                                            )),
                                    ),
                            )
                            .child(div().text_xs().text_color(t.accent).child("Open ↵"))
                    })),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .child(self.cancel_modal_btn(t, cx)),
            )
    }

    // -------------------------------------------------------------------------
    // 8. Remote Text File Editor Modal
    // -------------------------------------------------------------------------
    fn render_remote_editor_modal(
        &self,
        t: &ThemePalette,
        session_id: String,
        remote_path: String,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let sid = session_id;
        let path_save = remote_path.clone();
        div()
            .w(px(720.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.modal_header(t, "Remote File Editor", &remote_path, cx))
            .child(self.remote_editor_input.clone())
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("modal-remote-save")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.save_remote_text_editor(sid.clone(), path_save.clone(), cx);
                            }))
                            .child("Save to Server"),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 9. Remote Chmod Modal (Octal + Quick Presets + Interactive rwx Matrix)
    // -------------------------------------------------------------------------
    fn render_remote_chmod_modal(
        &self,
        t: &ThemePalette,
        session_id: String,
        remote_path: String,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let current_raw = self.chmod_input.read(cx).value().trim().to_string();
        let mode_bits = u32::from_str_radix(&current_raw, 8).unwrap_or(0o644) & 0o777;
        let presets = [("600", "Private Key"), ("644", "Standard File"), ("755", "Executable / Dir"), ("777", "World RWX")];
        let roles = [("Owner", 6u32), ("Group", 3u32), ("Other", 0u32)];
        let perms = [("Read (r)", 4u32), ("Write (w)", 2u32), ("Exec (x)", 1u32)];

        let sid = session_id;
        let path_save = remote_path.clone();

        div()
            .w(px(460.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(self.modal_header(t, "Change Permissions (chmod)", &remote_path, cx))
            .child(self.labeled_field(t, "Octal Mode", self.chmod_input.clone()))
            // Quick presets
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_1p5()
                    .children(presets.into_iter().enumerate().map(|(ix, (oct, desc))| {
                        let active = current_raw == oct;
                        div()
                            .id(("chmod-pre", ix))
                            .px_2p5()
                            .py_1()
                            .rounded_md()
                            .border_1()
                            .text_size(px(11.0))
                            .cursor_pointer()
                            .bg(if active { t.accent_soft } else { t.bg_subtle })
                            .border_color(if active { t.accent } else { t.border })
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.chmod_input
                                    .update(cx, |f, cx| f.set_value(oct.to_string(), cx));
                                cx.notify();
                            }))
                            .child(format!("{oct} · {desc}"))
                    })),
            )
            // Visual rwx bit matrix
            .child(
                div()
                    .p_3()
                    .rounded_xl()
                    .bg(t.bg_subtle)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(roles.into_iter().enumerate().map(|(r_ix, (role, shift))| {
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(t.text_secondary)
                                    .child(role),
                            )
                            .child(div().flex().gap_2().children(perms.into_iter().enumerate().map(
                                |(p_ix, (plbl, bit))| {
                                    let mask = bit << shift;
                                    let is_set = (mode_bits & mask) != 0;
                                    let next_bits = mode_bits ^ mask;
                                    div()
                                        .id(("chmod-bit", r_ix * 10 + p_ix))
                                        .px_2()
                                        .py_0p5()
                                        .rounded_md()
                                        .border_1()
                                        .text_size(px(11.0))
                                        .cursor_pointer()
                                        .bg(if is_set { t.accent_soft } else { t.bg_card })
                                        .border_color(if is_set { t.accent } else { t.border })
                                        .text_color(if is_set { t.accent } else { t.text_muted })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            let next = format!("{:03o}", next_bits);
                                            this.chmod_input
                                                .update(cx, |f, cx| f.set_value(next, cx));
                                            cx.notify();
                                        }))
                                        .child(plbl)
                                },
                            )))
                    })),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("chmod-submit")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.submit_remote_chmod(sid.clone(), path_save.clone(), cx);
                            }))
                            .child("Apply Permissions"),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 10. Remote Rename Modal
    // -------------------------------------------------------------------------
    fn render_remote_rename_modal(
        &self,
        t: &ThemePalette,
        session_id: String,
        old_path: String,
        old_name: String,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let sid = session_id;
        let op = old_path;
        div()
            .w(px(420.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(self.modal_header(t, "Rename Remote Entry", &format!("Current: {old_name}"), cx))
            .child(self.labeled_field(t, "New Name", self.rename_input.clone()))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("rename-submit")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.submit_remote_rename(sid.clone(), op.clone(), cx);
                            }))
                            .child("Rename"),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 11. Host Key TOFU & MITM Mismatch Modal (Shows Expected Fingerprint!)
    // -------------------------------------------------------------------------
    fn render_host_key_modal(
        &self,
        t: &ThemePalette,
        ch: core_ssh::types::HostKeyChallenge,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let (is_mismatch, expected_fp) = match &ch.status {
            HostKeyStatus::Mismatch {
                expected_fingerprint,
            } => (true, Some(expected_fingerprint.clone())),
            HostKeyStatus::Unknown => (false, None),
        };
        let cid_ok = ch.challenge_id.clone();
        let cid_no = ch.challenge_id.clone();

        div()
            .w(px(520.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(if is_mismatch { t.danger } else { t.warning })
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::BOLD)
                    .text_color(if is_mismatch { t.danger } else { t.warning })
                    .child(if is_mismatch {
                        "⚠ WARNING: REMOTE HOST KEY CHANGED (POSSIBLE MITM)"
                    } else {
                        "Verify SSH Host Key (TOFU)"
                    }),
            )
            .child(
                div()
                    .p_3()
                    .rounded_xl()
                    .bg(if is_mismatch {
                        t.danger_soft
                    } else {
                        t.bg_subtle
                    })
                    .font_family("Consolas")
                    .text_xs()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .child(format!("Host: {}:{}", ch.hostname, ch.port))
                    .child(format!("Algorithm: {}", ch.algorithm))
                    .child(format!("Presented SHA256: {}", ch.fingerprint_sha256))
                    .when_some(expected_fp, |el, exp| {
                        el.child(
                            div()
                                .text_color(t.danger)
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(format!("Expected SHA256:  {exp}")),
                        )
                    }),
            )
            .when(is_mismatch, |el| {
                el.child(
                    div()
                        .text_xs()
                        .text_color(t.danger)
                        .child("Only replace this key if the server was intentionally rebuilt or re-keyed."),
                )
            })
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        div()
                            .id("hk-reject")
                            .px_3p5()
                            .py_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(t.border_strong)
                            .text_xs()
                            .cursor_pointer()
                            .hover(|s| s.bg(t.bg_subtle))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.resolve_host_key_modal(cid_no.clone(), false, cx);
                            }))
                            .child("Reject Connection"),
                    )
                    .child(
                        div()
                            .id("hk-accept")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(if is_mismatch { t.danger } else { t.accent_solid })
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.resolve_host_key_modal(cid_ok.clone(), true, cx);
                            }))
                            .child(if is_mismatch {
                                "Replace & Trust Key"
                            } else {
                                "Trust & Save Key"
                            }),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 12. Multi-Prompt Keyboard-Interactive (2FA / PAM) Modal
    // -------------------------------------------------------------------------
    fn render_kbi_modal(
        &self,
        t: &ThemePalette,
        ch: core_ssh::types::KeyboardInteractiveChallenge,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let cid_ok = ch.challenge_id.clone();
        let cid_no = ch.challenge_id.clone();
        let header_sub = if !ch.instructions.trim().is_empty() {
            ch.instructions.clone()
        } else {
            format!("{}@{}:{}", ch.username, ch.hostname, ch.port)
        };

        div()
            .w(px(460.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.border_strong)
            .shadow_2xl()
            .p_5()
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
                            .child(if ch.name.trim().is_empty() {
                                "Interactive Authentication (2FA / PAM)".to_string()
                            } else {
                                ch.name.clone()
                            }),
                    )
                    .child(div().text_xs().text_color(t.text_muted).child(header_sub)),
            )
            .children(self.kbi_inputs.iter().enumerate().map(|(ix, field)| {
                let lbl = ch
                    .prompts
                    .get(ix)
                    .map(|p| p.prompt.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| format!("Prompt {}", ix + 1));
                self.labeled_field(t, &lbl, field.clone())
            }))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        div()
                            .id("kbi-cancel")
                            .px_3p5()
                            .py_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(t.border_strong)
                            .text_xs()
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.resolve_kbi_modal(cid_no.clone(), false, cx);
                            }))
                            .child("Cancel"),
                    )
                    .child(
                        div()
                            .id("kbi-submit")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.accent_solid)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.resolve_kbi_modal(cid_ok.clone(), true, cx);
                            }))
                            .child("Submit Response"),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // 13. Destructive Action Confirmation Modal
    // -------------------------------------------------------------------------
    fn render_confirm_modal(
        &self,
        t: &ThemePalette,
        action: ConfirmAction,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let (title, body, cta) = match &action {
            ConfirmAction::DeleteHost { label, .. } => (
                "Delete Server Profile?",
                format!("Remove '{label}' from your encrypted vault? Existing credentials in Keychain will remain untouched."),
                "Delete Server",
            ),
            ConfirmAction::DeleteGroup { name, .. } => (
                "Delete Group?",
                format!("Remove group '{name}'? Hosts inside it will remain in your vault under 'All'."),
                "Delete Group",
            ),
            ConfirmAction::DeleteCredential {
                label,
                used_by_count,
                ..
            } => (
                "Delete Credential?",
                if *used_by_count > 0 {
                    format!("WARNING: '{label}' is currently referenced by {used_by_count} host(s). Deleting it will break automated login for those hosts.")
                } else {
                    format!("Permanently delete credential '{label}' from your vault?")
                },
                "Delete Credential",
            ),
            ConfirmAction::RevokeKnownHost { label, .. } => (
                "Revoke Trusted Host Key?",
                format!("Remove '{label}' from trusted known hosts? You will be prompted to verify its fingerprint on next connect."),
                "Revoke Host Key",
            ),
            ConfirmAction::DeleteCommand { command, .. } => (
                "Delete Snippet?",
                format!("Remove '{command}' from saved snippets and history?"),
                "Delete Snippet",
            ),
            ConfirmAction::DeleteRemoteFile { name, is_dir, .. } => (
                if *is_dir {
                    "Delete Remote Folder?"
                } else {
                    "Delete Remote File?"
                },
                format!("Permanently delete '{name}' on the remote server? This cannot be undone."),
                "Delete Remote",
            ),
            ConfirmAction::SignOut => (
                "Sign Out of E2EE Sync?",
                "This clears your saved sync token and locks the local vault. Your encrypted vault remains safely stored on the sync server.".to_string(),
                "Sign Out",
            ),
        };

        div()
            .w(px(430.0))
            .rounded_2xl()
            .bg(t.bg_card)
            .border_1()
            .border_color(t.danger)
            .shadow_2xl()
            .p_5()
            .flex()
            .flex_col()
            .gap_3p5()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::BOLD)
                    .text_color(t.danger)
                    .child(title),
            )
            .child(div().text_xs().text_color(t.text_secondary).child(body))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .pt_1()
                    .child(self.cancel_modal_btn(t, cx))
                    .child(
                        div()
                            .id("confirm-execute-btn")
                            .px_4()
                            .py_2()
                            .rounded_lg()
                            .bg(t.danger)
                            .text_color(gpui::white())
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .cursor_pointer()
                            .hover(|s| s.opacity(0.92))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.execute_confirmed_action(action.clone(), cx);
                            }))
                            .child(cta),
                    ),
            )
    }

    // -------------------------------------------------------------------------
    // Shared Modal Helpers
    // -------------------------------------------------------------------------
    pub fn modal_header(
        &self,
        t: &ThemePalette,
        title: &str,
        subtitle: &str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .flex()
            .items_start()
            .justify_between()
            .gap_2()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_0p5()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.text_primary)
                            .child(title.to_string()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(t.text_muted)
                            .child(subtitle.to_string()),
                    ),
            )
            .child(
                div()
                    .id("modal-close-x")
                    .px_1p5()
                    .py_0p5()
                    .rounded_md()
                    .text_xs()
                    .text_color(t.text_muted)
                    .cursor_pointer()
                    .hover(|s| s.bg(t.bg_subtle).text_color(t.text_primary))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.modal = None;
                        cx.notify();
                    }))
                    .child("✕"),
            )
    }

    pub fn cancel_modal_btn(&self, t: &ThemePalette, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("modal-cancel-btn")
            .px_3p5()
            .py_2()
            .rounded_lg()
            .border_1()
            .border_color(t.border_strong)
            .text_xs()
            .text_color(t.text_secondary)
            .cursor_pointer()
            .hover(|s| s.bg(t.bg_subtle).text_color(t.text_primary))
            .on_click(cx.listener(|this, _, _, cx| {
                this.modal = None;
                cx.notify();
            }))
            .child("Cancel")
    }

    pub fn labeled_field(
        &self,
        t: &ThemePalette,
        label: &str,
        field: Entity<TextField>,
    ) -> impl IntoElement + use<> {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .text_xs()
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(t.text_secondary)
                    .child(label.to_string()),
            )
            .child(field)
    }
}
