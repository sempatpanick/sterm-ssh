use gpui::{
    div, hsla, prelude::*, px, AnyView, App, FontWeight, SharedString, Window,
};

use crate::theme::ThemePalette;

/// Styled native GPUI hover tooltip view for icon-only buttons and collapsed sidebar items.
pub struct StermTooltip {
    text: SharedString,
    shortcut: Option<SharedString>,
    t: ThemePalette,
}

impl StermTooltip {
    /// Builds a GPUI tooltip factory displaying a plain text label.
    pub fn text(
        text: impl Into<SharedString>,
        t: ThemePalette,
    ) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
        let label: SharedString = text.into();
        move |_window, cx| {
            let label = label.clone();
            cx.new(move |_| Self {
                text: label,
                shortcut: None,
                t,
            })
            .into()
        }
    }

    /// Builds a GPUI tooltip factory displaying a label alongside a keyboard shortcut cap.
    pub fn with_shortcut(
        text: impl Into<SharedString>,
        shortcut: impl Into<SharedString>,
        t: ThemePalette,
    ) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
        let label: SharedString = text.into();
        let sc: SharedString = shortcut.into();
        move |_window, cx| {
            let label = label.clone();
            let sc = sc.clone();
            cx.new(move |_| Self {
                text: label,
                shortcut: Some(sc),
                t,
            })
            .into()
        }
    }
}

impl Render for StermTooltip {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        // Outer offset gives slight cursor clearance; GPUI clamps to viewport edges automatically.
        div().pl(px(8.0)).pt(px(14.0)).child(
            div()
                .px_2p5()
                .py_1()
                .rounded_md()
                .bg(self.t.island_bg)
                .border_1()
                .border_color(self.t.island_border)
                .shadow_lg()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(11.0))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(self.t.island_fg)
                        .whitespace_nowrap()
                        .child(self.text.clone()),
                )
                .when_some(self.shortcut.clone(), |el, sc| {
                    el.child(
                        div()
                            .px_1()
                            .py(px(1.0))
                            .rounded_sm()
                            .bg(hsla(0.0, 0.0, 1.0, 0.12))
                            .font_family("Consolas")
                            .text_size(px(10.0))
                            .text_color(self.t.island_fg)
                            .whitespace_nowrap()
                            .child(sc),
                    )
                }),
        )
    }
}
