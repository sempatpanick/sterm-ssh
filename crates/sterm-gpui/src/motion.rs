use std::time::Duration;

use gpui::{
    div, ease_in_out, ease_out_quint, prelude::*, pulsating_between, px, relative, Animation,
    AnimationExt as _, ElementId, Hsla,
};

/// Smooth 3-dot staggered GPU loading indicator (120fps, zero external assets).
pub fn loading_dots(id_prefix: &'static str, color: Hsla) -> impl IntoElement {
    loading_dots_indexed(id_prefix, 0, color)
}

/// Indexed variant of `loading_dots` so multiple simultaneous instances have unique animation IDs.
pub fn loading_dots_indexed(
    id_prefix: &'static str,
    group: usize,
    color: Hsla,
) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap(px(4.0))
        .children((0..3usize).map(move |idx| {
            let phase_offset = (idx as f32) * 0.22;
            div()
                .w(px(5.0))
                .h(px(5.0))
                .rounded_full()
                .bg(color)
                .with_animation(
                    (id_prefix, group.wrapping_mul(8).wrapping_add(idx)),
                    Animation::new(Duration::from_millis(900)).repeat(),
                    move |el, delta| {
                        let shifted = (delta + 1.0 - phase_offset) % 1.0;
                        let wave = (shifted * std::f32::consts::TAU).sin() * 0.5 + 0.5;
                        let opacity = 0.25 + wave * 0.75;
                        let lift = wave * 2.5;
                        el.opacity(opacity).mb(px(lift))
                    },
                )
        }))
}

/// Sleek indeterminate sliding progress bar (Linear / Vercel style) for active async work.
pub fn indeterminate_bar(
    id: impl Into<ElementId>,
    track_color: Hsla,
    bar_color: Hsla,
) -> impl IntoElement {
    div()
        .w_full()
        .h(px(2.5))
        .bg(track_color)
        .overflow_hidden()
        .relative()
        .child(
            div()
                .absolute()
                .top_0()
                .h_full()
                .w(relative(0.34))
                .rounded_full()
                .bg(bar_color)
                .with_animation(
                    id,
                    Animation::new(Duration::from_millis(1150))
                        .repeat()
                        .with_easing(ease_in_out),
                    |el, delta| {
                        // Slide smoothly from -34% to 100% across the bar
                        let left_frac = -0.34 + delta * 1.34;
                        el.left(relative(left_frac))
                    },
                ),
        )
}

/// Breathing status dot for live SSH connections, running SFTP transfers, and active sync.
pub fn pulsing_dot(id: impl Into<ElementId>, size_px: f32, color: Hsla) -> impl IntoElement {
    div()
        .w(px(size_px))
        .h(px(size_px))
        .rounded_full()
        .bg(color)
        .with_animation(
            id,
            Animation::new(Duration::from_millis(1600))
                .repeat()
                .with_easing(pulsating_between(0.38, 1.0)),
            |el, delta| el.opacity(delta),
        )
}

/// Smooth quintic ease-out page transition (fade + gentle upward slide).
pub fn animate_page_enter(
    epoch: u64,
    content: impl IntoElement + 'static,
) -> impl IntoElement {
    div()
        .size_full()
        .child(content)
        .with_animation(
            ("page-transition", epoch),
            Animation::new(Duration::from_millis(220)).with_easing(ease_out_quint()),
            |el, delta| el.opacity(delta).pt(px((1.0 - delta) * 10.0)),
        )
}

/// Smooth modal card entrance (fade + subtle spring-like upward glide).
pub fn animate_modal_enter(
    epoch: u64,
    content: impl IntoElement + 'static,
) -> impl IntoElement {
    div()
        .child(content)
        .with_animation(
            ("modal-card-enter", epoch),
            Animation::new(Duration::from_millis(210)).with_easing(ease_out_quint()),
            |el, delta| el.opacity(delta).pt(px((1.0 - delta) * 14.0)),
        )
}
