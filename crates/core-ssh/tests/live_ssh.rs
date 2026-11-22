use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use core_ssh::manager::{AcceptAllHostKeys, HostKeyVerifier, SshSessionManager};
use core_ssh::types::{
    ConnectRequest, HostKeyChallenge, KeyboardInteractiveChallenge, SshAuthMethod, SshTarget,
    TerminalEvent,
};
use russh::keys::ssh_key::{
    self,
    certificate::{Builder as CertBuilder, CertType},
    rand_core::{Infallible, TryCryptoRng, TryRng},
};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
use russh::server::{
    self, Auth, ChannelOpenHandle, Msg, Response, Server as _, Session, VerifiedPublicKey,
};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

struct TestRng;

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, dst);
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

fn test_rng() -> TestRng {
    TestRng
}

#[derive(Clone)]
struct EchoSshServer {
    allowed_password: String,
    allowed_pubkey: PublicKey,
    allowed_cert_ca: Option<PublicKey>,
    allowed_kbi_code: Option<String>,
}

impl server::Server for EchoSshServer {
    type Handler = EchoSessionHandler;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        EchoSessionHandler {
            allowed_password: self.allowed_password.clone(),
            allowed_pubkey: self.allowed_pubkey.clone(),
            allowed_cert_ca: self.allowed_cert_ca.clone(),
            allowed_kbi_code: self.allowed_kbi_code.clone(),
            last_resize: None,
            tunnel_channels: std::collections::HashSet::new(),
        }
    }
}

struct EchoSessionHandler {
    allowed_password: String,
    allowed_pubkey: PublicKey,
    allowed_cert_ca: Option<PublicKey>,
    allowed_kbi_code: Option<String>,
    last_resize: Option<(u32, u32)>,
    tunnel_channels: std::collections::HashSet<ChannelId>,
}

impl server::Handler for EchoSessionHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == "tester" && password == self.allowed_password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if user == "tester" && key.public_key == &self.allowed_pubkey {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        if user == "tester" {
            if let Some(ref ca) = self.allowed_cert_ca {
                if certificate.signature_key() == ca.key_data()
                    && certificate.valid_principals().iter().any(|p| p == user)
                {
                    return Ok(Auth::Accept);
                }
            }
        }
        Ok(Auth::reject())
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        let Some(ref expected) = self.allowed_kbi_code else {
            return Ok(Auth::reject());
        };
        if user != "tester" {
            return Ok(Auth::reject());
        }
        match response {
            None => Ok(Auth::Partial {
                name: Cow::Borrowed("2FA Verification"),
                instructions: Cow::Borrowed("Enter your 6-digit OTP code"),
                prompts: Cow::Owned(vec![(Cow::Borrowed("Verification code: "), false)]),
            }),
            Some(mut resp) => {
                let first = resp
                    .next()
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                if first == *expected {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.last_resize = Some((col_width, row_height));
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_success(channel);
        let _ = session.data(channel, b"STERM_READY\n".as_slice());
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.last_resize = Some((col_width, row_height));
        let msg = format!("RESIZED:{col_width}x{row_height}\n");
        let _ = session.data(channel, msg.into_bytes());
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let addr = format!("{host_to_connect}:{port_to_connect}");
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(mut target) => {
                self.tunnel_channels.insert(channel.id());
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                });
            }
            Err(_) => {
                reply
                    .reject(russh::ChannelOpenFailure::ConnectFailed)
                    .await;
            }
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        let _ = session.channel_success(channel);
        let reply = format!("EXEC_OK:{cmd}\n");
        let _ = session.data(channel, reply.into_bytes());
        let _ = session.exit_status_request(channel, 0);
        let _ = session.eof(channel);
        let _ = session.close(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.tunnel_channels.contains(&channel) {
            return Ok(());
        }
        let mut echoed = b"ECHO:".to_vec();
        echoed.extend_from_slice(data);
        let _ = session.data(channel, echoed);
        Ok(())
    }
}

struct RejectHostKey;

#[async_trait]
impl HostKeyVerifier for RejectHostKey {
    async fn lookup_known_host(&self, _h: &str, _p: u16) -> Option<String> {
        Some("SHA256:expected-different-fingerprint".into())
    }
    async fn prompt_user(&self, _c: HostKeyChallenge) -> bool {
        false
    }
    async fn save_known_host(&self, _c: HostKeyChallenge) {}
}

async fn spawn_test_sshd(
    allowed_password: String,
    client_pubkey: PublicKey,
    allowed_cert_ca: Option<PublicKey>,
    allowed_kbi_code: Option<String>,
) -> u16 {
    let mut cfg = server::Config::default();
    let host_key = PrivateKey::random(&mut test_rng(), Algorithm::Ed25519).unwrap();
    cfg.keys.push(host_key);
    let cfg = Arc::new(cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut srv = EchoSshServer {
        allowed_password,
        allowed_pubkey: client_pubkey,
        allowed_cert_ca,
        allowed_kbi_code,
    };

    tokio::spawn(async move {
        let _ = srv.run_on_socket(cfg, &listener).await;
    });

    port
}

struct KbiAutoResponder {
    code: String,
}

#[async_trait]
impl HostKeyVerifier for KbiAutoResponder {
    async fn lookup_known_host(&self, _h: &str, _p: u16) -> Option<String> {
        None
    }
    async fn prompt_user(&self, _c: HostKeyChallenge) -> bool {
        true
    }
    async fn save_known_host(&self, _c: HostKeyChallenge) {}
    async fn prompt_keyboard_interactive(
        &self,
        challenge: KeyboardInteractiveChallenge,
    ) -> Option<Vec<String>> {
        assert_eq!(challenge.prompts.len(), 1);
        Some(vec![self.code.clone()])
    }
}

#[tokio::test]
async fn live_ssh_password_pubkey_pty_resize_and_tofu() {
    let client_key = PrivateKey::random(&mut test_rng(), Algorithm::Ed25519).unwrap();
    let client_pem = client_key
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let test_pw = format!("ssh-fixture-{}", rand::random::<u64>());
    let port = spawn_test_sshd(test_pw.clone(), client_key.public_key().clone(), None, None).await;

    let mgr = SshSessionManager::new();

    // 1. TOFU mismatch rejected cleanly
    let rejected = mgr
        .connect_shell(
            ConnectRequest {
                jump_chain: vec![],
                target: SshTarget {
                    hostname: "127.0.0.1".into(),
                    port,
                    username: "tester".into(),
                    auth: SshAuthMethod::Password {
                        password: test_pw,
                    },
                    keepalive_secs: 0,
                },
                cols: 80,
                rows: 24,
                startup_command: None,
            },
            Arc::new(RejectHostKey),
            |_| {},
        )
        .await;
    assert!(rejected.is_err());

    // 2. Ed25519 PublicKey auth + PTY echo + window_change resize
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let sid = mgr
        .connect_shell(
            ConnectRequest {
                jump_chain: vec![],
                target: SshTarget {
                    hostname: "127.0.0.1".into(),
                    port,
                    username: "tester".into(),
                    auth: SshAuthMethod::PrivateKey {
                        pem: client_pem,
                        passphrase: None,
                    },
                    keepalive_secs: 0,
                },
                cols: 100,
                rows: 30,
                startup_command: None,
            },
            Arc::new(AcceptAllHostKeys),
            move |ev| {
                if let TerminalEvent::Output { data } = ev {
                    let _ = tx.send(String::from_utf8_lossy(&data).to_string());
                }
            },
        )
        .await
        .expect("connect via Ed25519 key");

    let banner = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(banner.contains("STERM_READY"));

    mgr.write_input(&sid, b"hello-sterm".to_vec()).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(echoed.contains("ECHO:hello-sterm"));

    mgr.resize(&sid, 132, 43).await.unwrap();
    let resized = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(resized.contains("RESIZED:132x43"));

    mgr.close_session(&sid).await.unwrap();
}

#[tokio::test]
async fn live_ssh_certificate_and_keyboard_interactive_auth() {
    let ca_key = PrivateKey::random(&mut test_rng(), Algorithm::Ed25519).unwrap();
    let user_key = PrivateKey::random(&mut test_rng(), Algorithm::Ed25519).unwrap();
    let user_pem = user_key
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder =
        CertBuilder::new_with_random_nonce(&mut test_rng(), user_key.public_key(), now - 60, now + 3600)
            .unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.key_id("tester-cert").unwrap();
    builder.valid_principal("tester").unwrap();
    let cert = builder.sign(&ca_key).unwrap();
    let cert_openssh = cert.to_openssh().unwrap();

    let otp_code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    let port = spawn_test_sshd(
        format!("ssh-fixture-{}", rand::random::<u64>()),
        user_key.public_key().clone(),
        Some(ca_key.public_key().clone()),
        Some(otp_code.clone()),
    )
    .await;

    let mgr = SshSessionManager::new();

    // 1. OpenSSH Certificate auth
    let sid_cert = mgr
        .connect_shell(
            ConnectRequest {
                jump_chain: vec![],
                target: SshTarget {
                    hostname: "127.0.0.1".into(),
                    port,
                    username: "tester".into(),
                    auth: SshAuthMethod::Certificate {
                        pem: user_pem,
                        passphrase: None,
                        certificate: cert_openssh,
                    },
                    keepalive_secs: 0,
                },
                cols: 80,
                rows: 24,
                startup_command: None,
            },
            Arc::new(AcceptAllHostKeys),
            |_| {},
        )
        .await
        .expect("connect via OpenSSH certificate");
    mgr.close_session(&sid_cert).await.unwrap();

    // 2. Keyboard-Interactive (2FA / PAM) auth
    let sid_kbi = mgr
        .connect_shell(
            ConnectRequest {
                jump_chain: vec![],
                target: SshTarget {
                    hostname: "127.0.0.1".into(),
                    port,
                    username: "tester".into(),
                    auth: SshAuthMethod::KeyboardInteractive,
                    keepalive_secs: 0,
                },
                cols: 80,
                rows: 24,
                startup_command: None,
            },
            Arc::new(KbiAutoResponder { code: otp_code }),
            |_| {},
        )
        .await
        .expect("connect via keyboard-interactive");
    mgr.close_session(&sid_kbi).await.unwrap();
}

#[tokio::test]
async fn live_ssh_rekey_and_keepalive_stays_connected() {
    let client_key = PrivateKey::random(&mut test_rng(), Algorithm::Ed25519).unwrap();
    let test_pw = format!("ssh-fixture-{}", rand::random::<u64>());
    let port = spawn_test_sshd(test_pw.clone(), client_key.public_key().clone(), None, None).await;

    let mgr = SshSessionManager::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<TerminalEvent>();
    let sid = mgr
        .connect_shell(
            ConnectRequest {
                jump_chain: vec![],
                target: SshTarget {
                    hostname: "127.0.0.1".into(),
                    port,
                    username: "tester".into(),
                    auth: SshAuthMethod::Password { password: test_pw },
                    keepalive_secs: 1,
                },
                cols: 80,
                rows: 24,
                startup_command: None,
            },
            Arc::new(AcceptAllHostKeys),
            move |ev| {
                let _ = tx.send(ev);
            },
        )
        .await
        .expect("connect with keepalive");

    // Wait for initial banner
    match tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        TerminalEvent::Output { data } => {
            assert!(String::from_utf8_lossy(&data).contains("STERM_READY"));
        }
        other => panic!("unexpected event before banner: {other:?}"),
    }

    // Trigger two consecutive transport rekeys (simulating multi-hour sessions) + keepalive interval
    for round in 1..=2 {
        mgr.rekey_session(&sid).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let payload = format!("after-rekey-{round}");
        mgr.write_input(&sid, payload.as_bytes().to_vec())
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            TerminalEvent::Output { data } => {
                let text = String::from_utf8_lossy(&data);
                assert!(
                    text.contains(&format!("ECHO:{payload}")),
                    "expected echo after rekey {round}, got {text:?}"
                );
            }
            other => panic!("session unexpectedly closed/errored after rekey {round}: {other:?}"),
        }
    }

    mgr.close_session(&sid).await.unwrap();
}

#[tokio::test]
async fn live_ssh_local_and_socks5_port_forwarding_and_exec() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let client_key = PrivateKey::random(&mut test_rng(), Algorithm::Ed25519).unwrap();
    let test_pw = format!("ssh-fixture-{}", rand::random::<u64>());
    let ssh_port =
        spawn_test_sshd(test_pw.clone(), client_key.public_key().clone(), None, None).await;

    // Spawn a tiny TCP backend echo service to reach through the SSH tunnel
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let mut out = b"TUNNELED:".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    let _ = s.write_all(&out).await;
                }
            });
        }
    });

    let mgr = SshSessionManager::new();
    let req = ConnectRequest {
        jump_chain: vec![],
        target: SshTarget {
            hostname: "127.0.0.1".into(),
            port: ssh_port,
            username: "tester".into(),
            auth: SshAuthMethod::Password {
                password: test_pw.clone(),
            },
            keepalive_secs: 0,
        },
        cols: 80,
        rows: 24,
        startup_command: None,
    };

    // 1. One-shot exec_command (used by ssh-copy-id)
    let (code, out) = mgr
        .exec_command(req.clone(), Arc::new(AcceptAllHostKeys), "echo hi")
        .await
        .expect("exec_command");
    assert_eq!(code, 0);
    assert!(out.contains("EXEC_OK:echo hi"));

    // 2. Local Port Forward (-L)
    let sid = mgr
        .connect_transport_only(req, Arc::new(AcceptAllHostKeys))
        .await
        .expect("transport");
    let local_port = mgr
        .start_local_forward(
            &sid,
            "tun-local".into(),
            "127.0.0.1".into(),
            0,
            "127.0.0.1".into(),
            backend_port,
        )
        .await
        .expect("start_local_forward");

    {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", local_port))
            .await
            .unwrap();
        client.write_all(b"ping-local").await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"TUNNELED:ping-local");
    }

    // 3. Dynamic SOCKS5 Proxy (-D)
    let socks_port = mgr
        .start_dynamic_socks5(&sid, "tun-socks".into(), "127.0.0.1".into(), 0)
        .await
        .expect("start_dynamic_socks5");

    {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .unwrap();
        // Greeting: SOCKS5, 1 method = NO AUTH
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting_resp = [0u8; 2];
        client.read_exact(&mut greeting_resp).await.unwrap();
        assert_eq!(greeting_resp, [0x05, 0x00]);

        // CONNECT 127.0.0.1:backend_port
        let mut req_pkt = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req_pkt.extend_from_slice(&backend_port.to_be_bytes());
        client.write_all(&req_pkt).await.unwrap();
        let mut conn_resp = [0u8; 10];
        client.read_exact(&mut conn_resp).await.unwrap();
        assert_eq!(conn_resp[1], 0x00);

        client.write_all(b"ping-socks").await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"TUNNELED:ping-socks");
    }

    assert_eq!(mgr.list_tunnels().len(), 2);
    mgr.stop_tunnel("tun-local").await.unwrap();
    mgr.stop_tunnel("tun-socks").await.unwrap();
    assert!(mgr.list_tunnels().is_empty());
    mgr.close_session(&sid).await.unwrap();
}
