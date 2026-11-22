mod app;
mod backend;
mod command_suggestions;
mod modals;
mod motion;
mod settings_view;
mod sftp;
mod split_tree;
mod terminal;
mod text_field;
mod theme;
mod views;

use gpui::{
    px, size, App, Application, Bounds, TitlebarOptions, WindowBounds, WindowOptions, prelude::*,
};

use crate::app::StermAdminApp;
use crate::backend::BackendServices;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "off,sterm_gpui=info".into()),
        )
        .init();

    let (services, ui_rx) = BackendServices::init();

    Application::new().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1320.0), px(840.0)), cx);
        let services_clone = services.clone();

        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("STerm SSH — Admin Studio".into()),
                    appears_transparent: false,
                    traffic_light_position: None,
                }),
                ..Default::default()
            },
            move |_window, cx| cx.new(|cx| StermAdminApp::new(services_clone, ui_rx, cx)),
        )
        .expect("failed to open STerm GPUI window");

        cx.activate(true);
    });
}
