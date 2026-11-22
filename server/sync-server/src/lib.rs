pub mod auth;
pub mod db;
pub mod sync;

use std::sync::{Arc, Mutex};

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::db::SyncDb;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<SyncDb>>,
    pub jwt_secret: String,
    pub salt_pepper: String,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/auth/salt", post(auth::get_salt))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/account/me", get(auth::get_me))
        .route("/v1/account/change-password", post(auth::change_password))
        .route("/v1/account", delete(auth::delete_account))
        .route("/v1/sync/changes", get(sync::pull_changes))
        .route("/v1/sync/push", post(sync::push_changes))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::ssh_keygen::generate_ed25519_keypair;
    use core_sync::client::SyncClient;
    use core_vault::{
        models::{CredentialKind, CredentialRecord, HostRecord},
        store::VaultStore,
    };
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn end_to_end_zero_knowledge_cross_platform_sync() {
        let db = SyncDb::open_in_memory().expect("db");
        let jwt_secret = uuid::Uuid::new_v4().to_string();
        let salt_pepper = uuid::Uuid::new_v4().to_string();
        let initial_pw = uuid::Uuid::new_v4().to_string();
        let rotated_pw = uuid::Uuid::new_v4().to_string();
        let state = AppState {
            db: Arc::new(Mutex::new(db)),
            jwt_secret,
            salt_pepper,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_url = format!("http://{addr}");

        let router = build_router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = SyncClient::new();

        // Device A (Windows) creates local encrypted vault and registers account
        let mut windows_vault = VaultStore::open_in_memory().unwrap();
        windows_vault.initialize_vault(&initial_pw, false).unwrap();

        let kp = generate_ed25519_keypair("ops@sterm", None).unwrap();
        let cred = windows_vault
            .upsert_credential(CredentialRecord {
                id: String::new(),
                label: "Prod Root Key".into(),
                kind: CredentialKind::PrivateKey,
                username: Some("root".into()),
                password: None,
                private_key_pem: Some(kp.private_key_openssh.clone()),
                passphrase: None,
                certificate_openssh: None,
                public_key_openssh: Some(kp.public_key_openssh.clone()),
                fingerprint_sha256: Some(kp.fingerprint_sha256.clone()),
                updated_at: 0,
            })
            .unwrap();

        let host = windows_vault
            .upsert_host(HostRecord {
                id: String::new(),
                label: "Tokyo Production".into(),
                hostname: "198.51.100.42".into(),
                port: 2222,
                username: "root".into(),
                group_id: None,
                tags: vec!["prod".into(), "ap-northeast".into()],
                credential_id: Some(cred.id.clone()),
                jump_host_id: None,
                terminal_theme: Some("obsidian".into()),
                keepalive_secs: 30,
                startup_command: None,
                notes: Some("cluster-note-fixture".into()),
                updated_at: 0,
            })
            .unwrap();

        let win_session = client
            .register(&server_url, "dev@example.com", &initial_pw, &windows_vault)
            .await
            .expect("register");

        let push_report = client.sync_now(&win_session, &windows_vault).await.expect("push");
        assert_eq!(push_report.pushed, 2);

        // Zero-knowledge assertion: server SQLite contains ZERO plaintext strings
        {
            let guard = state.db.lock().unwrap();
            let raw_dump = guard.debug_dump_ciphertexts().unwrap();
            assert!(!raw_dump.contains("198.51.100.42"));
            assert!(!raw_dump.contains("Tokyo Production"));
            assert!(!raw_dump.contains("cluster-note-fixture"));
            assert!(!raw_dump.contains("OPENSSH PRIVATE KEY"));
        }

        // Device B (macOS) starts fresh, logs into the same account, and pulls encrypted vault
        let mut macos_vault = VaultStore::open_in_memory().unwrap();
        let mac_session = client
            .login(
                &server_url,
                "dev@example.com",
                &initial_pw,
                &mut macos_vault,
                false,
            )
            .await
            .expect("login");

        let pull_report = client.sync_now(&mac_session, &macos_vault).await.expect("pull");
        assert_eq!(pull_report.pulled, 2);

        let synced_hosts = macos_vault.list_hosts().unwrap();
        assert_eq!(synced_hosts.len(), 1);
        assert_eq!(synced_hosts[0].hostname, "198.51.100.42");
        assert_eq!(synced_hosts[0].label, "Tokyo Production");

        let synced_cred = macos_vault.get_credential(&cred.id).unwrap();
        assert_eq!(
            synced_cred.private_key_pem.as_deref(),
            Some(kp.private_key_openssh.as_str())
        );

        // Delete host on macOS -> sync -> Windows pulls tombstone and removes host
        macos_vault.soft_delete_item(&host.id).unwrap();
        client.sync_now(&mac_session, &macos_vault).await.unwrap();
        client.sync_now(&win_session, &windows_vault).await.unwrap();
        assert!(windows_vault.list_hosts().unwrap().is_empty());

        // Profile check
        let profile = client.get_profile(&win_session).await.expect("profile");
        assert_eq!(profile.email, "dev@example.com");
        assert_eq!(profile.item_count, 1); // 1 remaining credential

        // Change password on Windows -> new password works immediately on fresh macOS login
        let updated_win_session = client
            .change_password(
                &win_session,
                &initial_pw,
                &rotated_pw,
                &mut windows_vault,
            )
            .await
            .expect("change password");

        let mut fresh_macos = VaultStore::open_in_memory().unwrap();
        // Old password must fail
        assert!(client
            .login(
                &server_url,
                "dev@example.com",
                &initial_pw,
                &mut fresh_macos,
                false
            )
            .await
            .is_err());
        // New password succeeds and decrypts synced credential
        let fresh_session = client
            .login(
                &server_url,
                "dev@example.com",
                &rotated_pw,
                &mut fresh_macos,
                false,
            )
            .await
            .expect("login with new password");
        client.sync_now(&fresh_session, &fresh_macos).await.unwrap();
        assert_eq!(fresh_macos.list_credentials_summary().unwrap().len(), 1);

        // Delete account -> subsequent login fails
        client
            .delete_account(&updated_win_session, &rotated_pw, &mut windows_vault)
            .await
            .expect("delete account");
        let mut after_del = VaultStore::open_in_memory().unwrap();
        assert!(client
            .login(
                &server_url,
                "dev@example.com",
                &rotated_pw,
                &mut after_del,
                false
            )
            .await
            .is_err());
    }
}
