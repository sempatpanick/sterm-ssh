use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use dashmap::DashMap;
use russh::client::{
    self, ChannelOpenHandle, DisconnectReason, Handle, KeyboardInteractiveAuthResponse, Msg,
    Session,
};
use russh::keys::{
    agent::{
        client::{AgentClient, AgentStream},
        AgentIdentity,
    },
    decode_secret_key,
    key::PrivateKeyWithHashAlg,
    Certificate, HashAlg, PublicKeyBase64, PublicKeyOrCertificate,
};
use russh::{Channel, ChannelMsg, ChannelStream};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::types::{
    AgentIdentityInfo, ConnectRequest, HostKeyChallenge, HostKeyStatus,
    KeyboardInteractiveChallenge, KeyboardInteractivePrompt, SshAuthMethod, SshTarget,
    TerminalEvent, TunnelKind, TunnelStats,
};
use crate::{SshError, SshResult};

/// Callback bridge between the pure-Rust SSH engine and the Vault + UI prompts.
#[async_trait]
pub trait HostKeyVerifier: Send + Sync {
    /// Returns the stored SHA-256 fingerprint for `(hostname, port)` if previously trusted.
    async fn lookup_known_host(&self, hostname: &str, port: u16) -> Option<String>;

    /// Prompts the user to verify an unknown or changed host key; returns true if accepted.
    async fn prompt_user(&self, challenge: HostKeyChallenge) -> bool;

    /// Persists an accepted host key in the vault.
    async fn save_known_host(&self, challenge: HostKeyChallenge);

    /// Prompts the user to answer a keyboard-interactive (PAM / 2FA / TOTP) challenge.
    /// Returns `None` if cancelled or unsupported.
    async fn prompt_keyboard_interactive(
        &self,
        _challenge: KeyboardInteractiveChallenge,
    ) -> Option<Vec<String>> {
        None
    }
}

/// Auto-accept verifier strictly for automated integration tests.
pub struct AcceptAllHostKeys;

#[async_trait]
impl HostKeyVerifier for AcceptAllHostKeys {
    async fn lookup_known_host(&self, _hostname: &str, _port: u16) -> Option<String> {
        None
    }
    async fn prompt_user(&self, _challenge: HostKeyChallenge) -> bool {
        true
    }
    async fn save_known_host(&self, _challenge: HostKeyChallenge) {}
}

#[derive(Clone)]
struct TunnelCounters {
    active_connections: Arc<AtomicU64>,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
}

impl TunnelCounters {
    fn new() -> Self {
        Self {
            active_connections: Arc::new(AtomicU64::new(0)),
            bytes_tx: Arc::new(AtomicU64::new(0)),
            bytes_rx: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[derive(Clone)]
struct RemoteForwardEntry {
    target_host: String,
    target_port: u16,
    counters: TunnelCounters,
}

type RemoteForwardMap = Arc<DashMap<u32, RemoteForwardEntry>>;

struct StermClientHandler {
    hostname: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier>,
    disconnect_reason: Arc<Mutex<Option<String>>>,
    remote_forwards: RemoteForwardMap,
    forward_agent: bool,
}

impl client::Handler for StermClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let server_key = server_public_key.public_key();
        let fingerprint = server_key.fingerprint(HashAlg::Sha256).to_string();
        let algorithm = server_key.algorithm().to_string();
        let public_key_b64 = B64.encode(server_key.public_key_bytes());

        if let Some(expected) = self
            .verifier
            .lookup_known_host(&self.hostname, self.port)
            .await
        {
            if expected == fingerprint {
                return Ok(true);
            }
            let challenge = HostKeyChallenge {
                challenge_id: Uuid::now_v7().to_string(),
                hostname: self.hostname.clone(),
                port: self.port,
                algorithm,
                fingerprint_sha256: fingerprint,
                public_key_b64,
                status: HostKeyStatus::Mismatch {
                    expected_fingerprint: expected,
                },
            };
            let accepted = self.verifier.prompt_user(challenge.clone()).await;
            if accepted {
                self.verifier.save_known_host(challenge).await;
            }
            return Ok(accepted);
        }

        let challenge = HostKeyChallenge {
            challenge_id: Uuid::now_v7().to_string(),
            hostname: self.hostname.clone(),
            port: self.port,
            algorithm,
            fingerprint_sha256: fingerprint,
            public_key_b64,
            status: HostKeyStatus::Unknown,
        };
        let accepted = self.verifier.prompt_user(challenge.clone()).await;
        if accepted {
            self.verifier.save_known_host(challenge).await;
        }
        Ok(accepted)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(entry) = self
            .remote_forwards
            .get(&connected_port)
            .map(|r| r.value().clone())
        else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let addr = format!("{}:{}", entry.target_host, entry.target_port);
            let Ok(mut local) = TcpStream::connect(&addr).await else {
                warn!("Remote forward failed to reach local target {addr}");
                return;
            };
            let _ = local.set_nodelay(true);
            entry
                .counters
                .active_connections
                .fetch_add(1, Ordering::Relaxed);
            let mut ssh_stream = channel.into_stream();
            if let Ok((from_ssh, to_ssh)) =
                tokio::io::copy_bidirectional(&mut ssh_stream, &mut local).await
            {
                entry.counters.bytes_rx.fetch_add(from_ssh, Ordering::Relaxed);
                entry.counters.bytes_tx.fetch_add(to_ssh, Ordering::Relaxed);
            }
            entry
                .counters
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
        });
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.forward_agent {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        reply.accept().await;
        tokio::spawn(async move {
            let mut ssh_stream = channel.into_stream();
            #[cfg(unix)]
            {
                let Ok(sock_path) = std::env::var("SSH_AUTH_SOCK") else {
                    warn!("Agent forwarding channel opened, but SSH_AUTH_SOCK is unset");
                    return;
                };
                match tokio::net::UnixStream::connect(&sock_path).await {
                    Ok(mut agent) => {
                        let _ = tokio::io::copy_bidirectional(&mut ssh_stream, &mut agent).await;
                    }
                    Err(e) => warn!("Agent forwarding failed to connect to {sock_path}: {e}"),
                }
            }
            #[cfg(windows)]
            {
                match tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(r"\\.\pipe\openssh-ssh-agent")
                {
                    Ok(mut pipe) => {
                        let _ = tokio::io::copy_bidirectional(&mut ssh_stream, &mut pipe).await;
                    }
                    Err(e) => {
                        warn!("Agent forwarding failed to open Windows OpenSSH agent pipe: {e}")
                    }
                }
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = &mut ssh_stream;
            }
        });
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                let msg = if info.message.trim().is_empty() {
                    format!("remote disconnected ({:?})", info.reason_code)
                } else {
                    format!("remote disconnected: {}", info.message.trim())
                };
                warn!("SSH disconnected {}:{}: {msg}", self.hostname, self.port);
                if let Ok(mut guard) = self.disconnect_reason.lock() {
                    *guard = Some(msg);
                }
                Ok(())
            }
            DisconnectReason::Error(e) => {
                let msg = format!("connection lost: {e}");
                warn!("SSH transport error {}:{}: {e}", self.hostname, self.port);
                if let Ok(mut guard) = self.disconnect_reason.lock() {
                    *guard = Some(msg);
                }
                Err(e)
            }
        }
    }
}

enum ShellControl {
    Input(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Close,
}

struct ActiveSession {
    handle: Arc<Handle<StermClientHandler>>,
    /// Keep jump host handles alive for the lifetime of the tunneled session.
    _jump_handles: Vec<Handle<StermClientHandler>>,
    shell_tx: Option<mpsc::Sender<ShellControl>>,
    remote_forwards: RemoteForwardMap,
}

struct ActiveTunnel {
    tunnel_id: String,
    session_id: String,
    kind: TunnelKind,
    bind_address: String,
    bind_port: u16,
    target_host: Option<String>,
    target_port: Option<u16>,
    cancel: CancellationToken,
    counters: TunnelCounters,
}

pub struct SshSessionManager {
    sessions: Arc<DashMap<String, ActiveSession>>,
    tunnels: Arc<DashMap<String, ActiveTunnel>>,
    pending_challenges: DashMap<String, oneshot::Sender<bool>>,
    pending_kbi_challenges: DashMap<String, oneshot::Sender<Option<Vec<String>>>>,
}

impl Default for SshSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SshSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            tunnels: Arc::new(DashMap::new()),
            pending_challenges: DashMap::new(),
            pending_kbi_challenges: DashMap::new(),
        }
    }

    pub fn register_challenge(&self, challenge_id: String) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.pending_challenges.insert(challenge_id, tx);
        rx
    }

    pub fn resolve_challenge(&self, challenge_id: &str, accepted: bool) -> bool {
        if let Some((_, tx)) = self.pending_challenges.remove(challenge_id) {
            let _ = tx.send(accepted);
            true
        } else {
            false
        }
    }

    pub fn register_kbi_challenge(
        &self,
        challenge_id: String,
    ) -> oneshot::Receiver<Option<Vec<String>>> {
        let (tx, rx) = oneshot::channel();
        self.pending_kbi_challenges.insert(challenge_id, tx);
        rx
    }

    pub fn resolve_kbi_challenge(
        &self,
        challenge_id: &str,
        responses: Option<Vec<String>>,
    ) -> bool {
        if let Some((_, tx)) = self.pending_kbi_challenges.remove(challenge_id) {
            let _ = tx.send(responses);
            true
        } else {
            false
        }
    }

    async fn connect_tcp_with_keepalive(addr: &str) -> SshResult<tokio::net::TcpStream> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| SshError::Connect(format!("{addr}: {e}")))?;
        if let Err(e) = stream.set_nodelay(true) {
            debug!("TCP set_nodelay failed for {addr}: {e}");
        }
        let sock_ref = SockRef::from(&stream);
        let tcp_keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));
        if let Err(e) = sock_ref.set_tcp_keepalive(&tcp_keepalive) {
            debug!("TCP set_tcp_keepalive failed for {addr}: {e}");
        }
        Ok(stream)
    }

    /// Connects directly to `target_host:target_port`, or tunnels via an HTTP CONNECT or SOCKS5
    /// proxy when `proxy_url` (`socks5://[user:pass@]host:port` or `http://[user:pass@]host:port`) is set.
    pub async fn dial_tcp_or_proxy(
        target_host: &str,
        target_port: u16,
        proxy_url: Option<&str>,
    ) -> SshResult<tokio::net::TcpStream> {
        let Some(raw) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) else {
            return Self::connect_tcp_with_keepalive(&format!("{target_host}:{target_port}")).await;
        };

        let parsed = parse_proxy_url(raw)?;
        let proxy_addr = format!("{}:{}", parsed.host, parsed.port);
        let mut stream = Self::connect_tcp_with_keepalive(&proxy_addr).await?;

        match parsed.scheme {
            ProxyScheme::Http => {
                let mut req = format!(
                    "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: Keep-Alive\r\n"
                );
                if let Some((ref u, ref p)) = parsed.auth {
                    let cred = B64.encode(format!("{u}:{p}"));
                    req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
                }
                req.push_str("\r\n");
                stream
                    .write_all(req.as_bytes())
                    .await
                    .map_err(|e| SshError::Connect(format!("HTTP proxy write failed: {e}")))?;

                let mut resp = Vec::with_capacity(256);
                let mut byte = [0u8; 1];
                while resp.len() < 8192 {
                    stream
                        .read_exact(&mut byte)
                        .await
                        .map_err(|e| SshError::Connect(format!("HTTP proxy read failed: {e}")))?;
                    resp.push(byte[0]);
                    if resp.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let header = String::from_utf8_lossy(&resp);
                let status_line = header.lines().next().unwrap_or("");
                if !status_line.contains(" 200") {
                    return Err(SshError::Connect(format!(
                        "HTTP proxy rejected CONNECT: {status_line}"
                    )));
                }
                Ok(stream)
            }
            ProxyScheme::Socks5 => {
                let methods: &[u8] = if parsed.auth.is_some() {
                    &[0x05, 0x02, 0x00, 0x02]
                } else {
                    &[0x05, 0x01, 0x00]
                };
                stream
                    .write_all(methods)
                    .await
                    .map_err(|e| SshError::Connect(format!("SOCKS5 greeting failed: {e}")))?;
                let mut choice = [0u8; 2];
                stream
                    .read_exact(&mut choice)
                    .await
                    .map_err(|e| SshError::Connect(format!("SOCKS5 greeting reply failed: {e}")))?;
                if choice[0] != 0x05 {
                    return Err(SshError::Connect("invalid SOCKS5 server version".into()));
                }
                match choice[1] {
                    0x00 => {}
                    0x02 => {
                        let (u, p) = parsed.auth.ok_or_else(|| {
                            SshError::Connect("SOCKS5 proxy requires username/password".into())
                        })?;
                        let mut auth_buf = Vec::with_capacity(3 + u.len() + p.len());
                        auth_buf.push(0x01);
                        auth_buf.push(u.len().min(255) as u8);
                        auth_buf.extend_from_slice(&u.as_bytes()[..u.len().min(255)]);
                        auth_buf.push(p.len().min(255) as u8);
                        auth_buf.extend_from_slice(&p.as_bytes()[..p.len().min(255)]);
                        stream.write_all(&auth_buf).await.map_err(|e| {
                            SshError::Connect(format!("SOCKS5 auth write failed: {e}"))
                        })?;
                        let mut auth_rep = [0u8; 2];
                        stream.read_exact(&mut auth_rep).await.map_err(|e| {
                            SshError::Connect(format!("SOCKS5 auth reply failed: {e}"))
                        })?;
                        if auth_rep[1] != 0x00 {
                            return Err(SshError::Connect(
                                "SOCKS5 proxy authentication rejected".into(),
                            ));
                        }
                    }
                    _ => {
                        return Err(SshError::Connect(format!(
                            "SOCKS5 proxy refused auth methods (code 0x{:02x})",
                            choice[1]
                        )));
                    }
                }

                // SOCKS5 CONNECT request
                let mut req = vec![0x05, 0x01, 0x00];
                if let Ok(ip4) = target_host.parse::<Ipv4Addr>() {
                    req.push(0x01);
                    req.extend_from_slice(&ip4.octets());
                } else if let Ok(ip6) = target_host.parse::<Ipv6Addr>() {
                    req.push(0x04);
                    req.extend_from_slice(&ip6.octets());
                } else {
                    let host_bytes = target_host.as_bytes();
                    if host_bytes.len() > 255 {
                        return Err(SshError::Connect("target hostname too long for SOCKS5".into()));
                    }
                    req.push(0x03);
                    req.push(host_bytes.len() as u8);
                    req.extend_from_slice(host_bytes);
                }
                req.extend_from_slice(&target_port.to_be_bytes());
                stream
                    .write_all(&req)
                    .await
                    .map_err(|e| SshError::Connect(format!("SOCKS5 CONNECT failed: {e}")))?;

                let mut head = [0u8; 4];
                stream
                    .read_exact(&mut head)
                    .await
                    .map_err(|e| SshError::Connect(format!("SOCKS5 reply failed: {e}")))?;
                if head[0] != 0x05 || head[1] != 0x00 {
                    return Err(SshError::Connect(format!(
                        "SOCKS5 CONNECT rejected (status 0x{:02x})",
                        head[1]
                    )));
                }
                match head[3] {
                    0x01 => {
                        let mut skip = [0u8; 6];
                        stream.read_exact(&mut skip).await.map_err(|e| {
                            SshError::Connect(format!("SOCKS5 reply body failed: {e}"))
                        })?;
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.map_err(|e| {
                            SshError::Connect(format!("SOCKS5 reply body failed: {e}"))
                        })?;
                        let mut skip = vec![0u8; len[0] as usize + 2];
                        stream.read_exact(&mut skip).await.map_err(|e| {
                            SshError::Connect(format!("SOCKS5 reply body failed: {e}"))
                        })?;
                    }
                    0x04 => {
                        let mut skip = [0u8; 18];
                        stream.read_exact(&mut skip).await.map_err(|e| {
                            SshError::Connect(format!("SOCKS5 reply body failed: {e}"))
                        })?;
                    }
                    _ => {}
                }
                Ok(stream)
            }
        }
    }

    /// Probes TCP reachability and returns round-trip connection latency in milliseconds.
    pub async fn probe_tcp_latency(hostname: &str, port: u16, timeout_ms: u64) -> Option<u64> {
        let addr = format!("{hostname}:{port}");
        let start = std::time::Instant::now();
        let res = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            tokio::net::TcpStream::connect(&addr),
        )
        .await;
        match res {
            Ok(Ok(_)) => Some(start.elapsed().as_millis().max(1) as u64),
            _ => None,
        }
    }

    /// Lists identities currently loaded in the local OS SSH Agent (OpenSSH / Pageant / macOS Keychain Agent).
    pub async fn list_local_agent_identities() -> Result<Vec<AgentIdentityInfo>, String> {
        fn map_identities(raw: Vec<AgentIdentity>) -> Vec<AgentIdentityInfo> {
            raw.into_iter()
                .map(|id| match id {
                    AgentIdentity::PublicKey { key, comment } => AgentIdentityInfo {
                        comment,
                        algorithm: key.algorithm().to_string(),
                        fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
                        is_certificate: false,
                    },
                    AgentIdentity::Certificate {
                        certificate,
                        comment,
                    } => AgentIdentityInfo {
                        comment,
                        algorithm: certificate.algorithm().to_string(),
                        fingerprint_sha256: certificate
                            .public_key()
                            .fingerprint(HashAlg::Sha256)
                            .to_string(),
                        is_certificate: true,
                    },
                })
                .collect()
        }

        #[cfg(unix)]
        {
            let mut agent = AgentClient::connect_env()
                .await
                .map_err(|e| format!("SSH agent unavailable (check SSH_AUTH_SOCK): {e}"))?;
            let ids = agent
                .request_identities()
                .await
                .map_err(|e| format!("request_identities failed: {e}"))?;
            Ok(map_identities(ids))
        }

        #[cfg(windows)]
        {
            if let Ok(mut agent) =
                AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await
            {
                if let Ok(ids) = agent.request_identities().await {
                    return Ok(map_identities(ids));
                }
            }
            if let Ok(mut pageant) = AgentClient::connect_pageant().await {
                if let Ok(ids) = pageant.request_identities().await {
                    return Ok(map_identities(ids));
                }
            }
            Err("No local SSH agent running (start Windows OpenSSH Authentication Agent or Pageant).".into())
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = map_identities;
            Err("Local SSH agent inspection is not supported on this platform.".into())
        }
    }

    async fn connect_single(
        target: &SshTarget,
        verifier: Arc<dyn HostKeyVerifier>,
        tunnel: Option<&Handle<StermClientHandler>>,
    ) -> SshResult<(
        Handle<StermClientHandler>,
        Arc<Mutex<Option<String>>>,
        RemoteForwardMap,
    )> {
        let mut config = client::Config {
            nodelay: true,
            inactivity_timeout: None,
            ..Default::default()
        };
        if target.keepalive_secs > 0 {
            config.keepalive_interval = Some(Duration::from_secs(target.keepalive_secs as u64));
            // Keep sending SSH keepalives to prevent NAT/firewall/sshd idle timeouts,
            // while setting keepalive_max = 0 so temporary network stalls or OS sleep/wake
            // cycles don't prematurely terminate the session (matching OpenSSH's default).
            // OS TCP keepalive + TCP retransmission still detect genuinely dead peers.
            config.keepalive_max = 0;
        }
        let config = Arc::new(config);
        let disconnect_reason = Arc::new(Mutex::new(None));
        let remote_forwards: RemoteForwardMap = Arc::new(DashMap::new());
        let handler = StermClientHandler {
            hostname: target.hostname.clone(),
            port: target.port,
            verifier: Arc::clone(&verifier),
            disconnect_reason: Arc::clone(&disconnect_reason),
            remote_forwards: Arc::clone(&remote_forwards),
            forward_agent: target.forward_agent,
        };

        let mut handle = match tunnel {
            None => {
                let addr = format!("{}:{}", target.hostname, target.port);
                let stream = Self::dial_tcp_or_proxy(
                    &target.hostname,
                    target.port,
                    target.proxy_url.as_deref(),
                )
                .await?;
                client::connect_stream(config, stream, handler)
                    .await
                    .map_err(|e| SshError::Connect(format!("{}: {}", addr, e)))?
            }
            Some(parent_handle) => {
                let channel = parent_handle
                    .channel_open_direct_tcpip(
                        target.hostname.clone(),
                        target.port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| SshError::ProxyJump(e.to_string()))?;
                client::connect_stream(config, channel.into_stream(), handler)
                    .await
                    .map_err(|e| SshError::Connect(e.to_string()))?
            }
        };

        Self::authenticate(&mut handle, target, verifier.as_ref()).await?;
        Ok((handle, disconnect_reason, remote_forwards))
    }

    async fn try_agent_identities<S>(
        handle: &mut Handle<StermClientHandler>,
        target: &SshTarget,
        agent: &mut AgentClient<S>,
    ) -> SshResult<bool>
    where
        S: AgentStream + Unpin + Send + 'static,
    {
        let identities = agent
            .request_identities()
            .await
            .map_err(|e| SshError::Auth(format!("SSH agent request_identities failed: {e}")))?;

        if identities.is_empty() {
            return Ok(false);
        }

        for identity in identities {
            let auth_res = match identity {
                AgentIdentity::PublicKey { key, .. } => {
                    let hash_alg = if key.algorithm().is_rsa() {
                        Some(HashAlg::Sha256)
                    } else {
                        None
                    };
                    handle
                        .authenticate_publickey_with(target.username.clone(), key, hash_alg, agent)
                        .await
                }
                AgentIdentity::Certificate { certificate, .. } => {
                    let hash_alg = if certificate.algorithm().is_rsa() {
                        Some(HashAlg::Sha256)
                    } else {
                        None
                    };
                    handle
                        .authenticate_certificate_with(
                            target.username.clone(),
                            certificate,
                            hash_alg,
                            agent,
                        )
                        .await
                }
            };
            match auth_res {
                Ok(res) if res.success() => return Ok(true),
                Ok(_) => continue,
                Err(e) => {
                    debug!("SSH agent identity attempt failed: {e}");
                }
            }
        }
        Ok(false)
    }

    async fn authenticate_with_agent(
        handle: &mut Handle<StermClientHandler>,
        target: &SshTarget,
    ) -> SshResult<bool> {
        #[cfg(unix)]
        {
            let mut agent = AgentClient::connect_env().await.map_err(|e| {
                SshError::Auth(format!(
                    "could not connect to local SSH agent (check SSH_AUTH_SOCK): {e}"
                ))
            })?;
            let ok = Self::try_agent_identities(handle, target, &mut agent).await?;
            if !ok {
                return Err(SshError::Auth(format!(
                    "no SSH agent identity accepted for {}@{}:{} (verify keys are loaded with `ssh-add -l`)",
                    target.username, target.hostname, target.port
                )));
            }
            Ok(true)
        }

        #[cfg(windows)]
        {
            let mut errors: Vec<String> = Vec::new();
            let mut connected_any = false;

            // 1. Windows OpenSSH Authentication Agent named pipe
            match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
                Ok(mut agent) => {
                    connected_any = true;
                    match Self::try_agent_identities(handle, target, &mut agent).await {
                        Ok(true) => return Ok(true),
                        Ok(false) => {}
                        Err(e) => errors.push(format!("OpenSSH agent: {e}")),
                    }
                }
                Err(e) => errors.push(format!("OpenSSH agent pipe unavailable: {e}")),
            }

            // 2. Fallback to Pageant (PuTTY / KeePassXC / GPG4Win)
            match AgentClient::connect_pageant().await {
                Ok(mut pageant) => {
                    connected_any = true;
                    match Self::try_agent_identities(handle, target, &mut pageant).await {
                        Ok(true) => return Ok(true),
                        Ok(false) => {}
                        Err(e) => errors.push(format!("Pageant: {e}")),
                    }
                }
                Err(e) => errors.push(format!("Pageant unavailable: {e}")),
            }

            if connected_any {
                Err(SshError::Auth(format!(
                    "no SSH agent identity accepted for {}@{}:{} (verify keys are loaded with `ssh-add -l`)",
                    target.username, target.hostname, target.port
                )))
            } else {
                Err(SshError::Auth(format!(
                    "could not connect to Windows SSH agent ({})",
                    errors.join("; ")
                )))
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (handle, target);
            Err(SshError::Auth(
                "SSH agent authentication is not supported on this platform".into(),
            ))
        }
    }

    async fn authenticate_keyboard_interactive(
        handle: &mut Handle<StermClientHandler>,
        target: &SshTarget,
        verifier: &dyn HostKeyVerifier,
        mut prefill_password: Option<&str>,
    ) -> SshResult<bool> {
        let mut response = handle
            .authenticate_keyboard_interactive_start(target.username.clone(), None)
            .await
            .map_err(|e| SshError::Auth(e.to_string()))?;

        const MAX_KBI_ROUNDS: usize = 16;
        for _ in 0..MAX_KBI_ROUNDS {
            match response {
                KeyboardInteractiveAuthResponse::Success => return Ok(true),
                KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
                KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => {
                    let answers = if prompts.is_empty() {
                        Vec::new()
                    } else if prompts.len() == 1
                        && !prompts[0].echo
                        && prefill_password.is_some()
                    {
                        // Auto-supply password once for PAM/keyboard-interactive password prompts.
                        let pw = prefill_password.take().unwrap_or_default();
                        vec![pw.to_string()]
                    } else {
                        let challenge = KeyboardInteractiveChallenge {
                            challenge_id: Uuid::now_v7().to_string(),
                            hostname: target.hostname.clone(),
                            port: target.port,
                            username: target.username.clone(),
                            name,
                            instructions,
                            prompts: prompts
                                .into_iter()
                                .map(|p| KeyboardInteractivePrompt {
                                    prompt: p.prompt,
                                    echo: p.echo,
                                })
                                .collect(),
                        };
                        match verifier.prompt_keyboard_interactive(challenge).await {
                            Some(ans) => ans,
                            None => {
                                return Err(SshError::Auth(
                                    "keyboard-interactive authentication cancelled".into(),
                                ))
                            }
                        }
                    };

                    response = handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await
                        .map_err(|e| SshError::Auth(e.to_string()))?;
                }
            }
        }

        Err(SshError::Auth(
            "too many keyboard-interactive authentication rounds".into(),
        ))
    }

    async fn authenticate(
        handle: &mut Handle<StermClientHandler>,
        target: &SshTarget,
        verifier: &dyn HostKeyVerifier,
    ) -> SshResult<()> {
        let ok = match &target.auth {
            SshAuthMethod::Password { password } => {
                let pw_res = handle
                    .authenticate_password(target.username.clone(), password.clone())
                    .await
                    .map_err(|e| SshError::Auth(e.to_string()))?;
                if pw_res.success() {
                    true
                } else {
                    // Some servers disable `password` auth and require PAM `keyboard-interactive`.
                    Self::authenticate_keyboard_interactive(
                        handle,
                        target,
                        verifier,
                        Some(password.as_str()),
                    )
                    .await
                    .unwrap_or(false)
                }
            }
            SshAuthMethod::PrivateKey { pem, passphrase } => {
                let key = decode_secret_key(pem, passphrase.as_deref())
                    .map_err(|e| SshError::InvalidKey(e.to_string()))?;
                let hash_alg = if key.algorithm().is_rsa() {
                    Some(HashAlg::Sha256)
                } else {
                    None
                };
                let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                handle
                    .authenticate_publickey(target.username.clone(), key_with_alg)
                    .await
                    .map_err(|e| SshError::Auth(e.to_string()))?
                    .success()
            }
            SshAuthMethod::Certificate {
                pem,
                passphrase,
                certificate,
            } => {
                let key = decode_secret_key(pem, passphrase.as_deref())
                    .map_err(|e| SshError::InvalidKey(e.to_string()))?;
                let cert = Certificate::from_openssh(certificate.trim())
                    .map_err(|e| SshError::InvalidKey(format!("invalid OpenSSH certificate: {e}")))?;
                handle
                    .authenticate_openssh_cert(target.username.clone(), Arc::new(key), cert)
                    .await
                    .map_err(|e| SshError::Auth(e.to_string()))?
                    .success()
            }
            SshAuthMethod::SshAgent => Self::authenticate_with_agent(handle, target).await?,
            SshAuthMethod::KeyboardInteractive => {
                Self::authenticate_keyboard_interactive(handle, target, verifier, None).await?
            }
            SshAuthMethod::None => handle
                .authenticate_none(target.username.clone())
                .await
                .map_err(|e| SshError::Auth(e.to_string()))?
                .success(),
        };

        if !ok {
            return Err(SshError::Auth(format!(
                "authentication rejected for {}@{}:{}",
                target.username, target.hostname, target.port
            )));
        }
        Ok(())
    }

    /// Establishes an SSH session (optionally traversing one or more ProxyJump hops)
    /// and optionally opens an interactive PTY shell streaming events to `on_event`.
    pub async fn connect_shell<F>(
        &self,
        req: ConnectRequest,
        verifier: Arc<dyn HostKeyVerifier>,
        mut on_event: F,
    ) -> SshResult<String>
    where
        F: FnMut(TerminalEvent) + Send + 'static,
    {
        let (target_handle, jump_handles, disconnect_reason, remote_forwards) =
            self.connect_chain(&req, verifier).await?;
        let target_handle = Arc::new(target_handle);

        let mut channel = target_handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::Channel(e.to_string()))?;

        channel
            .request_pty(false, "xterm-256color", req.cols, req.rows, 0, 0, &[])
            .await
            .map_err(|e| SshError::Channel(e.to_string()))?;

        if req.target.forward_agent {
            if let Err(e) = channel.agent_forward(false).await {
                warn!("SSH agent forwarding request failed: {e}");
            }
        }

        channel
            .request_shell(false)
            .await
            .map_err(|e| SshError::Channel(e.to_string()))?;

        if let Some(cmd) = req.startup_command {
            let trimmed = cmd.trim();
            if !trimmed.is_empty() {
                let mut bytes = trimmed.as_bytes().to_vec();
                bytes.push(b'\n');
                let _ = channel.data(bytes.as_slice()).await;
            }
        }

        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<ShellControl>(256);
        let session_id = Uuid::now_v7().to_string();

        self.sessions.insert(
            session_id.clone(),
            ActiveSession {
                handle: Arc::clone(&target_handle),
                _jump_handles: jump_handles,
                shell_tx: Some(ctrl_tx),
                remote_forwards,
            },
        );

        let sid_log = session_id.clone();
        let sessions = Arc::clone(&self.sessions);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(ctrl) = ctrl_rx.recv() => {
                        match ctrl {
                            ShellControl::Input(bytes) => {
                                if let Err(e) = channel.data(bytes.as_slice()).await {
                                    on_event(TerminalEvent::Error { message: e.to_string() });
                                    break;
                                }
                            }
                            ShellControl::Resize { cols, rows } => {
                                if let Err(e) = channel.window_change(cols, rows, 0, 0).await {
                                    warn!("resize_pty failed for {sid_log}: {e}");
                                }
                            }
                            ShellControl::Close => {
                                let _ = channel.eof().await;
                                let _ = channel.close().await;
                                on_event(TerminalEvent::Closed { reason: "closed by user".into() });
                                break;
                            }
                        }
                    }
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { data }) => {
                                on_event(TerminalEvent::Output { data: data.to_vec() });
                            }
                            Some(ChannelMsg::ExtendedData { data, .. }) => {
                                on_event(TerminalEvent::Output { data: data.to_vec() });
                            }
                            Some(ChannelMsg::ExitStatus { exit_status }) => {
                                debug!("session {sid_log} exited with code {exit_status}");
                            }
                            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                                // Yield once so StermClientHandler::disconnected can record any transport error.
                                tokio::task::yield_now().await;
                                let reason = disconnect_reason
                                    .lock()
                                    .ok()
                                    .and_then(|g| g.clone())
                                    .unwrap_or_else(|| "remote closed session".into());
                                on_event(TerminalEvent::Closed { reason });
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
            sessions.remove(&sid_log);
        });

        Ok(session_id)
    }

    /// Connects a transport-only SSH session (e.g., for direct SFTP or Port Forwarding without spawning a PTY).
    pub async fn connect_transport_only(
        &self,
        req: ConnectRequest,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> SshResult<String> {
        let (target_handle, jump_handles, _disconnect_reason, remote_forwards) =
            self.connect_chain(&req, verifier).await?;
        let session_id = Uuid::now_v7().to_string();
        self.sessions.insert(
            session_id.clone(),
            ActiveSession {
                handle: Arc::new(target_handle),
                _jump_handles: jump_handles,
                shell_tx: None,
                remote_forwards,
            },
        );
        Ok(session_id)
    }

    /// Executes a one-shot non-interactive command over SSH (e.g., `ssh-copy-id` public key deployment)
    /// and returns `(exit_code, combined_output)`.
    pub async fn exec_command(
        &self,
        req: ConnectRequest,
        verifier: Arc<dyn HostKeyVerifier>,
        command: &str,
    ) -> SshResult<(u32, String)> {
        let (target_handle, _jump_handles, _, _) = self.connect_chain(&req, verifier).await?;
        let mut channel = target_handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::Channel(e.to_string()))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| SshError::Channel(e.to_string()))?;

        let mut output = Vec::new();
        let mut exit_code: u32 = 0;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => output.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => output.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status,
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = target_handle
            .disconnect(russh::Disconnect::ByApplication, "done", "en")
            .await;
        Ok((exit_code, String::from_utf8_lossy(&output).to_string()))
    }

    async fn connect_chain(
        &self,
        req: &ConnectRequest,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> SshResult<(
        Handle<StermClientHandler>,
        Vec<Handle<StermClientHandler>>,
        Arc<Mutex<Option<String>>>,
        RemoteForwardMap,
    )> {
        let mut jump_handles: Vec<Handle<StermClientHandler>> = Vec::new();

        for hop in &req.jump_chain {
            let (h, _, _) =
                Self::connect_single(hop, Arc::clone(&verifier), jump_handles.last()).await?;
            jump_handles.push(h);
        }

        let (target_handle, disconnect_reason, remote_forwards) =
            Self::connect_single(&req.target, verifier, jump_handles.last()).await?;
        Ok((
            target_handle,
            jump_handles,
            disconnect_reason,
            remote_forwards,
        ))
    }

    /// Initiates an SSH transport key re-exchange on an active session.
    pub async fn rekey_session(&self, session_id: &str) -> SshResult<()> {
        let handle = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            Arc::clone(&entry.handle)
        };
        handle
            .rekey_soon()
            .await
            .map_err(|e| SshError::Channel(format!("rekey failed: {e}")))
    }

    pub async fn write_input(&self, session_id: &str, data: Vec<u8>) -> SshResult<()> {
        let tx = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            entry
                .shell_tx
                .clone()
                .ok_or_else(|| SshError::Channel("session has no interactive PTY".into()))?
        };
        tx.send(ShellControl::Input(data))
            .await
            .map_err(|_| SshError::Channel("shell stream closed".into()))
    }

    pub async fn resize(&self, session_id: &str, cols: u32, rows: u32) -> SshResult<()> {
        let tx = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            entry
                .shell_tx
                .clone()
                .ok_or_else(|| SshError::Channel("session has no interactive PTY".into()))?
        };
        tx.send(ShellControl::Resize { cols, rows })
            .await
            .map_err(|_| SshError::Channel("shell stream closed".into()))
    }

    /// Opens a multiplexed SFTP subsystem stream over an active SSH session.
    pub async fn open_sftp_stream(
        &self,
        session_id: &str,
    ) -> SshResult<ChannelStream<russh::client::Msg>> {
        let handle = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            Arc::clone(&entry.handle)
        };

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::Channel(e.to_string()))?;

        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SshError::Channel(format!("failed to request sftp subsystem: {e}")))?;

        Ok(channel.into_stream())
    }

    /// Starts a Local Port Forward (`-L bind_address:bind_port:target_host:target_port`).
    /// Returns the actual bound local port (useful when `bind_port == 0`).
    pub async fn start_local_forward(
        &self,
        session_id: &str,
        tunnel_id: String,
        bind_address: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    ) -> SshResult<u16> {
        let handle = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            Arc::clone(&entry.handle)
        };

        let bind_str = format!("{bind_address}:{bind_port}");
        let listener = TcpListener::bind(&bind_str)
            .await
            .map_err(|e| SshError::Channel(format!("failed to bind {bind_str}: {e}")))?;
        let actual_port = listener
            .local_addr()
            .map_err(|e| SshError::Channel(e.to_string()))?
            .port();

        let cancel = CancellationToken::new();
        let counters = TunnelCounters::new();
        self.tunnels.insert(
            tunnel_id.clone(),
            ActiveTunnel {
                tunnel_id: tunnel_id.clone(),
                session_id: session_id.to_string(),
                kind: TunnelKind::Local,
                bind_address: bind_address.clone(),
                bind_port: actual_port,
                target_host: Some(target_host.clone()),
                target_port: Some(target_port),
                cancel: cancel.clone(),
                counters: counters.clone(),
            },
        );

        let tunnels_map = Arc::clone(&self.tunnels);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((mut stream, peer)) = accepted else { break; };
                        let _ = stream.set_nodelay(true);
                        let handle_c = Arc::clone(&handle);
                        let target_h = target_host.clone();
                        let cnt = counters.clone();
                        tokio::spawn(async move {
                            let Ok(channel) = handle_c
                                .channel_open_direct_tcpip(
                                    target_h,
                                    target_port as u32,
                                    peer.ip().to_string(),
                                    peer.port() as u32,
                                )
                                .await
                            else {
                                return;
                            };
                            cnt.active_connections.fetch_add(1, Ordering::Relaxed);
                            let mut ssh_stream = channel.into_stream();
                            if let Ok((to_ssh, from_ssh)) =
                                tokio::io::copy_bidirectional(&mut stream, &mut ssh_stream).await
                            {
                                cnt.bytes_tx.fetch_add(to_ssh, Ordering::Relaxed);
                                cnt.bytes_rx.fetch_add(from_ssh, Ordering::Relaxed);
                            }
                            cnt.active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                }
            }
            tunnels_map.remove(&tunnel_id);
        });

        Ok(actual_port)
    }

    /// Starts a Dynamic SOCKS5 Proxy (`-D bind_address:bind_port`) over an active SSH session.
    pub async fn start_dynamic_socks5(
        &self,
        session_id: &str,
        tunnel_id: String,
        bind_address: String,
        bind_port: u16,
    ) -> SshResult<u16> {
        let handle = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            Arc::clone(&entry.handle)
        };

        let bind_str = format!("{bind_address}:{bind_port}");
        let listener = TcpListener::bind(&bind_str)
            .await
            .map_err(|e| SshError::Channel(format!("failed to bind SOCKS5 {bind_str}: {e}")))?;
        let actual_port = listener
            .local_addr()
            .map_err(|e| SshError::Channel(e.to_string()))?
            .port();

        let cancel = CancellationToken::new();
        let counters = TunnelCounters::new();
        self.tunnels.insert(
            tunnel_id.clone(),
            ActiveTunnel {
                tunnel_id: tunnel_id.clone(),
                session_id: session_id.to_string(),
                kind: TunnelKind::DynamicSocks5,
                bind_address: bind_address.clone(),
                bind_port: actual_port,
                target_host: None,
                target_port: None,
                cancel: cancel.clone(),
                counters: counters.clone(),
            },
        );

        let tunnels_map = Arc::clone(&self.tunnels);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break; };
                        let _ = stream.set_nodelay(true);
                        let handle_c = Arc::clone(&handle);
                        let cnt = counters.clone();
                        tokio::spawn(async move {
                            let _ = handle_socks5_client(stream, peer, handle_c, cnt).await;
                        });
                    }
                }
            }
            tunnels_map.remove(&tunnel_id);
        });

        Ok(actual_port)
    }

    /// Starts a Remote Port Forward (`-R bind_address:bind_port:target_host:target_port`).
    pub async fn start_remote_forward(
        &self,
        session_id: &str,
        tunnel_id: String,
        bind_address: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    ) -> SshResult<u16> {
        let (handle, remote_forwards) = {
            let entry = self
                .sessions
                .get(session_id)
                .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;
            (Arc::clone(&entry.handle), Arc::clone(&entry.remote_forwards))
        };

        let counters = TunnelCounters::new();
        let bound_port = handle
            .tcpip_forward(bind_address.clone(), bind_port as u32)
            .await
            .map_err(|e| SshError::Channel(format!("remote tcpip_forward failed: {e}")))?;
        let final_port = if bound_port > 0 {
            bound_port as u16
        } else {
            bind_port
        };

        remote_forwards.insert(
            final_port as u32,
            RemoteForwardEntry {
                target_host: target_host.clone(),
                target_port,
                counters: counters.clone(),
            },
        );

        let cancel = CancellationToken::new();
        self.tunnels.insert(
            tunnel_id.clone(),
            ActiveTunnel {
                tunnel_id,
                session_id: session_id.to_string(),
                kind: TunnelKind::Remote,
                bind_address,
                bind_port: final_port,
                target_host: Some(target_host),
                target_port: Some(target_port),
                cancel,
                counters,
            },
        );
        Ok(final_port)
    }

    /// Stops an active port forward tunnel cleanly.
    pub async fn stop_tunnel(&self, tunnel_id: &str) -> SshResult<()> {
        if let Some((_, tunnel)) = self.tunnels.remove(tunnel_id) {
            tunnel.cancel.cancel();
            if tunnel.kind == TunnelKind::Remote {
                if let Some(session) = self.sessions.get(&tunnel.session_id) {
                    session.remote_forwards.remove(&(tunnel.bind_port as u32));
                    let _ = session
                        .handle
                        .cancel_tcpip_forward(tunnel.bind_address, tunnel.bind_port as u32)
                        .await;
                }
            }
        }
        Ok(())
    }

    pub fn list_tunnels(&self) -> Vec<TunnelStats> {
        self.tunnels
            .iter()
            .map(|entry| {
                let t = entry.value();
                TunnelStats {
                    tunnel_id: t.tunnel_id.clone(),
                    session_id: t.session_id.clone(),
                    kind: t.kind,
                    bind_address: t.bind_address.clone(),
                    bind_port: t.bind_port,
                    target_host: t.target_host.clone(),
                    target_port: t.target_port,
                    active_connections: t.counters.active_connections.load(Ordering::Relaxed),
                    bytes_tx: t.counters.bytes_tx.load(Ordering::Relaxed),
                    bytes_rx: t.counters.bytes_rx.load(Ordering::Relaxed),
                    running: !t.cancel.is_cancelled(),
                }
            })
            .collect()
    }

    pub async fn close_session(&self, session_id: &str) -> SshResult<()> {
        let to_stop: Vec<String> = self
            .tunnels
            .iter()
            .filter(|e| e.value().session_id == session_id)
            .map(|e| e.key().clone())
            .collect();
        for tid in to_stop {
            let _ = self.stop_tunnel(&tid).await;
        }
        if let Some((_, session)) = self.sessions.remove(session_id) {
            if let Some(tx) = session.shell_tx {
                let _ = tx.send(ShellControl::Close).await;
            }
            let _ = session
                .handle
                .disconnect(russh::Disconnect::ByApplication, "closed", "en")
                .await;
        }
        Ok(())
    }

    pub fn active_session_ids(&self) -> Vec<String> {
        self.sessions.iter().map(|e| e.key().clone()).collect()
    }
}

/// Minimal RFC 1928 SOCKS5 (no-auth, CONNECT IPv4/Domain/IPv6) handler backed by SSH `direct-tcpip`.
async fn handle_socks5_client(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    handle: Arc<Handle<StermClientHandler>>,
    counters: TunnelCounters,
) -> std::io::Result<()> {
    // 1. Greeting: VER(1) NMETHODS(1) METHODS(N)
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[0x05, 0xFF]).await;
        return Ok(());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // 2. Request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT(2)
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        // Only CONNECT (0x01) is supported
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Ok(());
    }
    let dest_host = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        _ => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let dest_port = u16::from_be_bytes(port_buf);

    let channel = match handle
        .channel_open_direct_tcpip(
            dest_host,
            dest_port as u32,
            peer.ip().to_string(),
            peer.port() as u32,
        )
        .await
    {
        Ok(ch) => ch,
        Err(_) => {
            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }
    };

    // Success reply
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    counters.active_connections.fetch_add(1, Ordering::Relaxed);
    let mut ssh_stream = channel.into_stream();
    if let Ok((to_ssh, from_ssh)) =
        tokio::io::copy_bidirectional(&mut stream, &mut ssh_stream).await
    {
        counters.bytes_tx.fetch_add(to_ssh, Ordering::Relaxed);
        counters.bytes_rx.fetch_add(from_ssh, Ordering::Relaxed);
    }
    counters.active_connections.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyScheme {
    Http,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedProxy {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    auth: Option<(String, String)>,
}

fn parse_proxy_url(raw: &str) -> SshResult<ParsedProxy> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, rest, default_port) = if let Some(r) = trimmed.strip_prefix("socks5://") {
        (ProxyScheme::Socks5, r, 1080u16)
    } else if let Some(r) = trimmed.strip_prefix("socks5h://") {
        (ProxyScheme::Socks5, r, 1080u16)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (ProxyScheme::Http, r, 8080u16)
    } else {
        return Err(SshError::Connect(format!(
            "unsupported proxy URL '{raw}' (use socks5://host:port or http://host:port)"
        )));
    };

    let (auth, host_port) = if let Some((userinfo, hp)) = rest.rsplit_once('@') {
        let (u, p) = userinfo
            .split_once(':')
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .unwrap_or_else(|| (userinfo.to_string(), String::new()));
        (Some((u, p)), hp)
    } else {
        (None, rest)
    };

    let (host, port) = if let Some(bracket_rest) = host_port.strip_prefix('[') {
        let (ipv6, after) = bracket_rest
            .split_once(']')
            .ok_or_else(|| SshError::Connect(format!("invalid IPv6 proxy host in '{raw}'")))?;
        let port = after
            .strip_prefix(':')
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| SshError::Connect(format!("invalid proxy port in '{raw}'")))?
            .unwrap_or(default_port);
        (ipv6.to_string(), port)
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| SshError::Connect(format!("invalid proxy port in '{raw}'")))?;
        (h.to_string(), port)
    } else {
        (host_port.to_string(), default_port)
    };

    if host.is_empty() || port == 0 {
        return Err(SshError::Connect(format!("invalid proxy address in '{raw}'")));
    }

    Ok(ParsedProxy {
        scheme,
        host,
        port,
        auth,
    })
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn parses_socks5_and_http_proxy_urls() {
        let p1 = parse_proxy_url("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(p1.scheme, ProxyScheme::Socks5);
        assert_eq!(p1.host, "127.0.0.1");
        assert_eq!(p1.port, 1080);
        assert!(p1.auth.is_none());

        let u = uuid::Uuid::new_v4().to_string();
        let v = uuid::Uuid::new_v4().to_string();
        let p2 = parse_proxy_url(&format!("http://{u}:{v}@proxy.corp:3128/")).unwrap();
        assert_eq!(p2.scheme, ProxyScheme::Http);
        assert_eq!(p2.host, "proxy.corp");
        assert_eq!(p2.port, 3128);
        assert_eq!(p2.auth, Some((u, v)));

        assert!(parse_proxy_url("ftp://bad:21").is_err());
    }
}
