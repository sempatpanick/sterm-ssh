use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use sterm_sync_server::{build_router, db::SyncDb, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_path = std::env::var("STERM_SYNC_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data/sterm-sync.db"));
    let bind_addr = std::env::var("STERM_SYNC_BIND").unwrap_or_else(|_| "0.0.0.0:8787".into());
    let jwt_secret = std::env::var("STERM_JWT_SECRET")
        .unwrap_or_else(|_| "change-me-in-production-sterm-sync-jwt-secret".into());
    let salt_pepper = std::env::var("STERM_SALT_PEPPER")
        .unwrap_or_else(|_| "change-me-in-production-sterm-salt-pepper".into());

    let db = SyncDb::open(&db_path).expect("failed to open sync database");
    let state = AppState {
        db: Arc::new(Mutex::new(db)),
        jwt_secret,
        salt_pepper,
    };

    let router = build_router(state);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind address");
    info!("STerm SSH E2EE Sync Server listening on http://{bind_addr}");
    axum::serve(listener, router).await.expect("server error");
}
