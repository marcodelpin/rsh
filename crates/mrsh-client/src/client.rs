//! Core client — TLS connect, ed25519 auth, request/response.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use anyhow::{Context, Result, bail};
use mrsh_core::{auth, protocol, tls, wire};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// TCP keepalive interval — detects dead connections within ~40s.
const TCP_KEEPALIVE_SECS: u64 = 15;
const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 5;
#[cfg(not(target_os = "windows"))]
const TCP_KEEPALIVE_RETRIES: u32 = 5;

/// Client version reported during auth.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capabilities advertised to server.
const CLIENT_CAPS: &[&str] = &["bin-patch", "shell", "self-update", "zstd", "binary-proto"];

/// Connected and authenticated client.
pub struct RshClient<S> {
    stream: S,
    pub server_version: Option<String>,
    pub server_caps: Vec<String>,
    pub mux_enabled: bool,
    /// Server's DeviceID (reported during auth, for relay rediscovery).
    pub server_device_id: Option<String>,
    /// Server's rendezvous server address (reported during auth).
    pub server_rendezvous: Option<String>,
}

/// Connection options.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub key_path: Option<String>,
    /// Username for password auth (when set, uses password auth instead of pubkey).
    pub password_user: Option<String>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 8822,
            key_path: None,
            password_user: None,
        }
    }
}

/// The concrete client stream type (TLS over TCP).
pub type TlsClient = RshClient<tokio_rustls::client::TlsStream<TcpStream>>;

/// Connect and authenticate, returning a ready-to-use client.
pub async fn connect(opts: &ConnectOptions) -> Result<TlsClient> {
    let stream = tcp_connect(&opts.host, opts.port).await?;
    let tls_stream = tls_wrap(stream, &opts.host).await?;
    if let Some(ref user) = opts.password_user {
        // rsh-zan0: bounded password resolution. No password available
        // (non-interactive, nothing piped) → fall back to key auth instead of
        // blocking forever; `-u` identity is honored by the SSH-first/fallback
        // paths in dispatch, NOT by the native transport.
        match read_password(user, &opts.host) {
            Ok(pw) => auth_password(tls_stream, user, pw).await,
            Err(e) => {
                tracing::warn!(
                    "password auth for -u {user} skipped ({e}); using key auth — \
                     native exec runs as the service user, -u applies to SSH fallback"
                );
                auth_client(tls_stream, &opts.key_path).await
            }
        }
    } else {
        auth_client(tls_stream, &opts.key_path).await
    }
}

/// Ports to try when no port is specified (-p omitted, no config port).
/// Order: tray (9822) first — user session has mapped drives, GUI, screenshots.
/// Then service (8822) — SYSTEM, for admin ops or when no user is logged in.
/// Then SSH (22) — TLS first (mrsh may listen on 22), SSH fallback handled by caller.
pub const AUTO_TRY_PORTS: &[u16] = &[9822, 8822, 22];

/// Short timeout per port during auto-try (seconds).
const AUTO_TRY_TIMEOUT_SECS: u64 = 3;

/// Connect with auto-try: race all ports in parallel, return first success.
/// Prefers tray (9822) over service (8822) over SSH (22) when both connect
/// within the same timeout window.
pub async fn connect_auto_try(opts: &ConnectOptions) -> Result<(TlsClient, u16)> {
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::channel::<(TlsClient, u16)>(1);
    let mut handles = Vec::new();

    // rsh-zan0: resolve the password ONCE before spawning the port tasks.
    // The old per-task `auth_password` raced three concurrent stdin readers
    // (and an unbounded read could block a worker forever). No password
    // available → all ports use key auth (warn emitted by read_password path).
    let resolved_password: Option<String> = match opts.password_user {
        Some(ref user) => match read_password(user, &opts.host) {
            Ok(pw) => Some(pw),
            Err(e) => {
                tracing::warn!(
                    "password auth for -u {user} skipped ({e}); auto-try uses key auth — \
                     -u applies to SSH fallback identity"
                );
                None
            }
        },
        None => None,
    };

    for &port in AUTO_TRY_PORTS {
        let host = opts.host.clone();
        let key_path = opts.key_path.clone();
        let password_user = opts.password_user.clone();
        let password = resolved_password.clone();
        let tx = tx.clone();

        let handle = tokio::spawn(async move {
            debug!("auto-try: attempting {}:{}", host, port);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(AUTO_TRY_TIMEOUT_SECS),
                async {
                    let stream = tcp_connect(&host, port).await?;
                    let tls_stream = tls_wrap(stream, &host).await?;
                    if let (Some(user), Some(pw)) = (&password_user, password.clone()) {
                        auth_password(tls_stream, user, pw).await
                    } else {
                        auth_client(tls_stream, &key_path).await
                    }
                },
            )
            .await;

            match result {
                Ok(Ok(client)) => {
                    let _ = tx.send((client, port)).await;
                }
                Ok(Err(e)) => {
                    debug!("auto-try port {} failed: {}", port, e);
                }
                Err(_) => {
                    debug!("auto-try port {} timed out", port);
                }
            }
        });
        handles.push(handle);
    }
    drop(tx); // Close sender so rx completes when all tasks done

    // Wait for first successful connection or all failures
    match tokio::time::timeout(
        std::time::Duration::from_secs(AUTO_TRY_TIMEOUT_SECS + 1),
        rx.recv(),
    )
    .await
    {
        Ok(Some((client, port))) => {
            if port != AUTO_TRY_PORTS[0] {
                debug!("connected on port {} (auto-try)", port);
            }
            // rsh-wz1i: surface tray-not-reachable explicitly to the operator.
            // When auto-try lands on 8822 (SYSTEM service) it means 9822 (tray)
            // refused — any USERPROFILE / GUI / browser op will silently run in
            // SYSTEM context which is almost never the user's intent.
            if port == 8822 {
                emit_tray_warn(&opts.host);
            }
            Ok((client, port))
        }
        _ => Err(anyhow::anyhow!(
            "failed to connect to {} on any port ({:?})",
            opts.host,
            AUTO_TRY_PORTS
        )),
    }
}

/// Emit a stderr warning that the tray (9822) wasn't reachable and the
/// client landed on the SYSTEM service (8822) instead. Suppressible via
/// `MRSH_NO_TRAY_WARN=1` for scripted callers that know what they're doing.
pub(crate) fn emit_tray_warn(host: &str) {
    if std::env::var_os("MRSH_NO_TRAY_WARN").is_some() {
        return;
    }
    eprintln!(
        "WARN: tray (9822) not reachable on {host}; using SYSTEM service (8822).\n\
         \x20 USERPROFILE / GUI / browser ops will run in SYSTEM context, NOT a user session.\n\
         \x20 Hint: mrsh -h {host} exec 'schtasks /run /tn mrsh-tray'  # then retry with -p 9822\n\
         \x20 (suppress with MRSH_NO_TRAY_WARN=1)"
    );
}

/// Connect and authenticate over an existing TCP stream (e.g. from relay).
pub async fn connect_over_stream(
    stream: TcpStream,
    server_name: &str,
    key_path: &Option<String>,
) -> Result<TlsClient> {
    let tls_stream = tls_wrap(stream, server_name).await?;
    auth_client(tls_stream, key_path).await
}

// ── Transport target resolution ──────────────────────────────────
//
// A `-h <value>` argument usually names a TCP target (host/IP/DeviceID).
// As of rsh-ozx the value can also be an `fs://` URI pointing at a shared
// spool directory — in that case the client dispatches to the filesystem
// transport (`connect_via_filesystem`) instead of TCP.

/// What the client will connect over.
#[derive(Debug, Clone)]
pub enum Target {
    /// Plain host/IP/DeviceID. Port/relay resolution is up to the caller.
    Tcp(String),
    /// Shared-filesystem spool directory (parsed from `fs://…`).
    Fs(PathBuf),
}

/// Parse a `-h` value into a [`Target`].
///
/// * `fs:///absolute/path` → [`Target::Fs`] (URL-decoded path).
/// * `fs://C:/path` or `fs://./rel` → [`Target::Fs`] (Windows-friendly form).
/// * anything else → [`Target::Tcp`] (unchanged).
///
/// Only the `fs://` scheme is recognised — all other strings (including
/// other schemes like `tcp://` or `relay://`) are returned as `Tcp(host)`
/// verbatim so existing behaviour is preserved.
pub fn parse_target(host: &str) -> Target {
    const FS_PREFIX: &str = "fs://";
    if let Some(rest) = host.strip_prefix(FS_PREFIX) {
        // `fs:///abs` → "/abs"; `fs://C:/path` → "C:/path"; `fs://./rel` → "./rel".
        // We do not percent-decode here; spool paths are expected to be plain.
        let path = if let Some(stripped) = rest.strip_prefix('/') {
            // `fs:///abs/path` on POSIX becomes "/abs/path".
            // On Windows `fs:///C:/path` becomes "C:/path" (strip leading slash).
            #[cfg(target_os = "windows")]
            {
                let trimmed = stripped.trim_start_matches('/');
                if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' {
                    trimmed.to_string()
                } else {
                    format!("/{}", stripped)
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                format!("/{}", stripped)
            }
        } else {
            rest.to_string()
        };
        Target::Fs(PathBuf::from(path))
    } else {
        Target::Tcp(host.to_string())
    }
}

/// Combined `AsyncRead + AsyncWrite` trait used for dyn dispatch.
///
/// Rust trait objects can only list one non-auto trait; `Send`/`Unpin` are
/// auto traits and may be added. Introducing `AsyncIo` lets us build a
/// `dyn AsyncIo + Send + Unpin` stream for type-erased clients.
pub trait AsyncIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncIo for T {}

/// Type-erased authenticated client.
///
/// The stream is boxed so the same variable can hold either a TCP+TLS
/// session or an fs-transport+TLS session. All methods on [`RshClient`]
/// are generic on `S: AsyncRead + AsyncWrite + Unpin`, so this alias is
/// a drop-in replacement for [`TlsClient`] / [`FsClient`] in call sites
/// that may take either transport.
pub type AnyStream = Pin<Box<dyn AsyncIo + Send + Unpin + 'static>>;
pub type AnyClient = RshClient<AnyStream>;

impl<S> RshClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Erase the concrete stream type, producing an [`AnyClient`].
    ///
    /// Used at call sites that want to treat TCP and fs-transport clients
    /// uniformly without duplicating every command branch.
    pub fn erase_stream(self) -> AnyClient {
        RshClient {
            stream: Box::pin(self.stream),
            server_version: self.server_version,
            server_caps: self.server_caps,
            mux_enabled: self.mux_enabled,
            server_device_id: self.server_device_id,
            server_rendezvous: self.server_rendezvous,
        }
    }
}

/// Connect to either a TCP host or an `fs://` spool directory.
///
/// Returns a type-erased [`AnyClient`] so the caller does not have to
/// branch on the transport. The `opts.host` field is parsed with
/// [`parse_target`]; `opts.port` and `opts.password_user` are only used
/// for the TCP branch.
///
/// For `Target::Fs(path)` the TOFU "peer_id" is derived from the spool
/// path (last path component), so known_hosts entries stay stable across
/// sessions pointing at the same spool.
pub async fn connect_any(opts: &ConnectOptions) -> Result<AnyClient> {
    match parse_target(&opts.host) {
        Target::Tcp(_) => {
            let client = connect(opts).await?;
            Ok(client.erase_stream())
        }
        Target::Fs(path) => {
            let peer_id = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("fs-spool")
                .to_string();
            let client = connect_via_filesystem(&path, &peer_id, &opts.key_path).await?;
            Ok(client.erase_stream())
        }
    }
}

/// Password-based authentication.
///
/// The password is resolved by the caller (terminal prompt or bounded piped
/// read via [`read_password`]) so auto-try can resolve it ONCE instead of
/// racing three concurrent stdin readers (rsh-zan0).
/// Sends auth request with type="password", receives AuthResult directly.
async fn auth_password<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    username: &str,
    password: String,
) -> Result<RshClient<S>> {
    let mut client = RshClient {
        stream,
        server_version: None,
        server_caps: Vec::new(),
        mux_enabled: false,
        server_device_id: None,
        server_rendezvous: None,
    };

    let auth_req = protocol::AuthRequest {
        auth_type: "password".to_string(),
        public_key: None,
        key_type: None,
        username: Some(username.to_string()),
        password: Some(password),
        version: Some(CLIENT_VERSION.to_string()),
        want_mux: None, // MUX channel protocol not yet implemented in Rust client
        caps: Some(CLIENT_CAPS.iter().map(|s| s.to_string()).collect()),
    };
    wire::send_json(&mut client.stream, &auth_req)
        .await
        .context("send password auth request")?;

    // Password auth: no challenge, direct result
    let result: protocol::AuthResult = wire::recv_json(&mut client.stream)
        .await
        .context("receive auth result")?;

    if !result.success {
        bail!(
            "password authentication failed: {}",
            result.error.unwrap_or_default()
        );
    }

    client.server_version = result.version.clone();
    client.server_caps = result.caps.unwrap_or_default();
    client.mux_enabled = result.mux_enabled.unwrap_or(false);
    client.server_device_id = result.device_id;
    client.server_rendezvous = result.rendezvous_server;
    debug!(
        "authenticated via password (server: {})",
        result.version.as_deref().unwrap_or("unknown")
    );
    Ok(client)
}

/// How long to wait for a piped (non-terminal) password line before giving up.
const PIPED_PASSWORD_TIMEOUT_SECS: u64 = 3;

/// Read password from terminal (hidden) or piped stdin (one line, BOUNDED).
///
/// rsh-zan0: the non-terminal branch used an unbounded `read_line` — with an
/// inherited-but-silent pipe (agent sessions, CI, cron) the client blocked
/// forever BEFORE any relay/SSH fallback could run (`mrsh -u <user> exec`
/// hung with zero output). Now a piped password must arrive within
/// `PIPED_PASSWORD_TIMEOUT_SECS`; EOF or timeout returns a clear error so the
/// caller can fall back to key auth and the dispatch chain (relay/SSH).
fn read_password(username: &str, host: &str) -> Result<String> {
    use std::io::{BufRead, Write};

    if std::io::stdin().is_terminal() {
        // Interactive terminal: show prompt, hide input
        eprint!("{}@{}'s password: ", username, host);
        std::io::stderr().flush().ok();
        let password = rpassword::read_password().context("read password from terminal")?;
        Ok(password)
    } else {
        // Piped/automated: read one line, bounded. The reader thread may
        // outlive a timeout (std stdin reads are not cancellable) — harmless
        // for a short-lived CLI process.
        let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<Option<String>>>();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            let res = stdin.lock().read_line(&mut line).map(|n| {
                if n == 0 {
                    None // EOF — nothing piped
                } else {
                    Some(line.trim_end().to_string())
                }
            });
            let _ = tx.send(res);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(PIPED_PASSWORD_TIMEOUT_SECS)) {
            Ok(Ok(Some(pw))) => Ok(pw),
            Ok(Ok(None)) => bail!(
                "no password on stdin (EOF) — use a TTY, pipe a password, or rely on key auth"
            ),
            Ok(Err(e)) => Err(e).context("read password from stdin"),
            Err(_) => bail!(
                "no password piped within {}s (stdin open but silent) — \
                 non-interactive password auth skipped",
                PIPED_PASSWORD_TIMEOUT_SECS
            ),
        }
    }
}

/// Common auth logic for both direct and relay connections.
async fn auth_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    key_path: &Option<String>,
) -> Result<RshClient<S>> {
    let key_pair = if let Some(path) = key_path {
        auth::load_ssh_key(Path::new(path)).with_context(|| format!("load key: {}", path))?
    } else {
        auth::discover_key_or_explain()? // rsh-m852: explains the id_rsa-present case
    };

    let mut client = RshClient {
        stream,
        server_version: None,
        server_caps: Vec::new(),
        mux_enabled: false,
        server_device_id: None,
        server_rendezvous: None,
    };

    // Try binary auth first — server auto-detects by first byte.
    // If server is too old (doesn't understand binary), it will reject,
    // and we can't retry on the same connection (auth state corrupted).
    // So we always use binary — old servers that don't understand will
    // return an auth error, which is the correct behavior (upgrade server).
    client.authenticate_binary(&key_pair).await?;
    Ok(client)
}

/// Parse a host string into a SocketAddr, handling IPv6 link-local with scope ID.
/// Returns `Some(addr)` for IPv6 addresses, `None` for hostnames/IPv4 (use tokio resolve).
fn parse_ipv6_host(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    if host.contains('%') {
        // IPv6 link-local with scope ID: fe80::1%15 or fe80::1%eth0
        let (ip_part, scope_part) = host.rsplit_once('%')?;
        let ip: std::net::Ipv6Addr = ip_part
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()?;
        let scope_id: u32 = scope_part.parse().unwrap_or({
            #[cfg(unix)]
            {
                use std::ffi::CString;
                if let Ok(name) = CString::new(scope_part) {
                    unsafe { libc::if_nametoindex(name.as_ptr()) }
                } else {
                    0
                }
            }
            #[cfg(not(unix))]
            {
                0
            }
        });
        Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            ip, port, 0, scope_id,
        )))
    } else if host.starts_with('[') {
        // Bracketed IPv6: [::1]
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let ip: std::net::Ipv6Addr = bare.parse().ok()?;
        Some(std::net::SocketAddr::from((ip, port)))
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        // Bare IPv6
        Some(std::net::SocketAddr::from((ip, port)))
    } else {
        None
    }
}

/// Strip scope ID from host for TLS SNI (rustls doesn't understand `%interface`).
fn tls_host_name(host: &str) -> &str {
    let h = if host.contains('%') {
        host.rsplit_once('%').map(|(h, _)| h).unwrap_or(host)
    } else {
        host
    };
    h.trim_start_matches('[').trim_end_matches(']')
}

/// Enable TCP keepalive on a stream so dead connections are detected promptly.
/// Without this, a peer that drops silently (crash, network loss) leaves the
/// local side hanging on read indefinitely.
fn set_tcp_keepalive(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS))
        .with_interval(std::time::Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS));
    #[cfg(not(target_os = "windows"))]
    let keepalive = keepalive.with_retries(TCP_KEEPALIVE_RETRIES);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        debug!("failed to set TCP keepalive: {}", e);
    }
}

/// TCP connect with timeout. Supports IPv6 link-local addresses with scope ID
/// (e.g., `fe80::1%eth0` or `fe80::1%15`).
async fn tcp_connect(host: &str, port: u16) -> Result<TcpStream> {
    if let Some(addr) = parse_ipv6_host(host, port) {
        debug!("connecting to {}", addr);
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(30), TcpStream::connect(addr))
                .await
                .context("connection timed out")?
                .with_context(|| format!("connect to {}", addr))?;
        stream.set_nodelay(true).ok();
        set_tcp_keepalive(&stream);
        return Ok(stream);
    }

    // Hostname or IPv4 — let tokio resolve
    let display_addr = format!("{}:{}", host, port);
    debug!("connecting to {}", display_addr);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        TcpStream::connect(&display_addr),
    )
    .await
    .context("connection timed out")?
    .with_context(|| format!("connect to {}", display_addr))?;
    stream.set_nodelay(true).ok();
    set_tcp_keepalive(&stream);
    Ok(stream)
}

/// Wrap a TCP stream in TLS using TOFU (Trust-On-First-Use) verification.
async fn tls_wrap(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = tls::client_config_tofu(None);
    let connector = TlsConnector::from(config);
    let tls_host = tls_host_name(host);
    let server_name =
        rustls::pki_types::ServerName::try_from(tls_host.to_string()).unwrap_or_else(|_| {
            rustls::pki_types::ServerName::IpAddress(
                tls_host
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                    .into(),
            )
        });
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake failed")?;
    debug!("TLS handshake complete");
    Ok(tls_stream)
}

impl<S> RshClient<S> {
    /// Create a client wrapping an existing stream (for crate-internal testing).
    #[cfg(test)]
    pub(crate) fn new_mock(stream: S) -> Self {
        RshClient {
            stream,
            server_version: Some("test-server".to_string()),
            server_caps: Vec::new(),
            mux_enabled: false,
            server_device_id: None,
            server_rendezvous: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RshClient<S> {
    /// Authenticate using binary protocol (binproto).
    /// Same challenge-response flow, but binary encoding instead of JSON.
    async fn authenticate_binary(&mut self, key_pair: &auth::SshKeyPair) -> Result<()> {
        use mrsh_core::binproto::{self, msg};

        let pub_key_raw = key_pair.public_key_bytes();
        let caps: Vec<&str> = CLIENT_CAPS.to_vec();
        let payload = binproto::build_auth_request(&pub_key_raw, CLIENT_VERSION, &caps);

        // Step 1: Send binary AUTH_REQUEST
        binproto::send_msg(&mut self.stream, msg::AUTH_REQUEST, &payload)
            .await
            .context("send binary auth request")?;

        // Step 2: Receive challenge or error
        let (type_id, challenge_data) = binproto::recv_msg(&mut self.stream)
            .await
            .context("recv binary auth challenge")?;

        match type_id {
            msg::AUTH_CHALLENGE => {
                // challenge_data is raw 32 bytes
                if challenge_data.len() != 32 {
                    bail!("invalid challenge size: {}", challenge_data.len());
                }
            }
            msg::AUTH_FAIL => {
                let err = binproto::parse_error(&challenge_data).unwrap_or_default();
                bail!("auth rejected: {}", err);
            }
            other => bail!("unexpected message type 0x{:02x} during auth", other),
        }

        // Step 3: Sign and send response (raw 64-byte signature)
        let signature = key_pair.sign_challenge(&challenge_data);
        binproto::send_msg(&mut self.stream, msg::AUTH_RESPONSE, &signature)
            .await
            .context("send binary auth response")?;

        // Step 4: Receive AUTH_OK or AUTH_FAIL
        let (type_id, result_data) = binproto::recv_msg(&mut self.stream)
            .await
            .context("recv binary auth result")?;

        match type_id {
            msg::AUTH_OK => {
                let fields = binproto::parse_auth_ok_full(&result_data)?;
                self.server_version = Some(fields.version);
                self.server_caps = fields.caps;
                self.server_device_id = fields.device_id;
                self.server_rendezvous = fields.rendezvous_server;
                debug!(
                    "authenticated via binary protocol (server: {}{})",
                    self.server_version.as_deref().unwrap_or("unknown"),
                    self.server_device_id
                        .as_ref()
                        .map(|id| format!(", device_id={}", id))
                        .unwrap_or_default()
                );
                Ok(())
            }
            msg::AUTH_FAIL => {
                let err = binproto::parse_error(&result_data).unwrap_or_default();
                bail!("authentication failed: {}", err);
            }
            // TOTP not yet supported in binary protocol
            msg::TOTP_CHALLENGE => {
                bail!("TOTP over binary protocol not yet supported");
            }
            other => bail!("unexpected message type 0x{:02x} after signature", other),
        }
    }

    /// Check if server supports binary protocol.
    /// Check if server advertises a specific capability.
    pub fn supports(&self, cap: &str) -> bool {
        self.server_caps.iter().any(|c| c == cap)
    }

    pub fn supports_binary_proto(&self) -> bool {
        self.server_caps.iter().any(|c| c == "binary-proto")
    }

    /// Check if server supports streaming exec (stdout/stderr chunks as they arrive).
    pub fn supports_stream_exec(&self) -> bool {
        self.server_caps.iter().any(|c| c == "stream-exec")
    }

    /// True if connected to user-session tray (has desktop, mapped drives, GUI).
    pub fn is_tray(&self) -> bool {
        self.supports("tray")
    }

    /// True if connected to SYSTEM service (admin privileges, no desktop).
    pub fn is_system(&self) -> bool {
        self.supports("system")
    }

    /// True if connected to a Linux server (no "window" cap = no Windows GUI).
    /// v1.10.23+: prefers the explicit "linux" cap when advertised, falls back
    /// to the pre-existing "no Windows caps" heuristic for older servers.
    pub fn is_linux(&self) -> bool {
        self.supports("linux")
            || (!self.supports("window") && !self.is_tray() && !self.is_system())
    }

    /// True if the server was built against musl libc. Used by `fleet update`
    /// to pick the statically-linked `mrsh-linux-musl` binary for Alpine-like
    /// targets (e.g. rendezvous.example.com). Only populated on v1.10.23+ servers.
    pub fn is_linux_musl(&self) -> bool {
        self.supports("linux-musl")
    }

    /// Describe the server instance: type, capabilities, limitations, and hints.
    /// Returns a multi-line string for display on stderr.
    pub fn describe_instance(&self, port: u16) -> String {
        let version = self.server_version.as_deref().unwrap_or("unknown");

        // Linux server check first (rsh-veqw): a Linux daemon may also advertise
        // the "system" cap, but it's not a Windows SYSTEM session-0 service —
        // Windows-specific banner ("session 0 — no desktop", "registry HKLM")
        // is wrong on Linux. Treat Linux as a separate case.
        if self.is_linux() {
            return format!(
                "  instance: LINUX DAEMON (port {port}, v{version})\n\
                 \x20 session:  daemon — runs as configured user (typically non-root)\n\
                 \x20 can:      exec, push/pull, shell (PTY), tunnel, screenshot (X/Wayland if avail)\n\
                 \x20 cannot:   Windows-specific (registry, services, GUI automation)"
            );
        }

        if self.is_tray() {
            format!(
                "  instance: USER TRAY (port {port}, v{version})\n\
                 \x20 session:  interactive desktop — user context\n\
                 \x20 can:      screenshot, window, mapped drives, GUI, clipboard, exec, push/pull\n\
                 \x20 cannot:   install services (no SYSTEM privileges)\n\
                 \x20 for admin: mrsh -h <host> -p 8822 (SYSTEM service)"
            )
        } else if self.is_system() {
            format!(
                "  instance: SYSTEM SERVICE (port {port}, v{version})\n\
                 \x20 session:  session 0 — no desktop\n\
                 \x20 can:      exec as SYSTEM, install services, registry HKLM, push/pull\n\
                 \x20 cannot:   screenshot, window list, mapped drives, GUI automation\n\
                 \x20 for desktop: mrsh -h <host> -p 9822 (user tray)"
            )
        } else {
            // Old server (pre-1.10.23) without explicit linux/system/tray caps.
            // Best-effort platform inference from "window" cap (Windows-only).
            let platform = if self.server_caps.iter().any(|c| c == "window") {
                "windows"
            } else {
                "linux"
            };
            format!(
                "  instance: server (port {port}, v{version}, {platform})\n\
                 \x20 caps:     {}",
                self.server_caps.join(", ")
            )
        }
    }

    /// Execute a command via binary protocol. Returns (exit_code, output).
    pub async fn exec_binary(
        &mut self,
        command: &str,
        env_vars: &[String],
    ) -> Result<(u32, Vec<u8>)> {
        use mrsh_core::binproto::{self, msg};
        let payload = binproto::build_exec(command, env_vars);
        binproto::send_msg(&mut self.stream, msg::EXEC, &payload)
            .await
            .context("send binary EXEC")?;
        let (type_id, data) = binproto::recv_msg(&mut self.stream)
            .await
            .context("recv binary EXEC_RESULT")?;
        match type_id {
            msg::EXEC_RESULT => binproto::parse_exec_result(&data),
            msg::ERROR => {
                let err = binproto::parse_error(&data).unwrap_or_default();
                bail!("exec error: {}", err);
            }
            other => bail!("unexpected response 0x{:02x} for EXEC", other),
        }
    }

    /// Execute a command with streaming output — prints stdout/stderr as chunks arrive.
    /// Returns the process exit code.
    pub async fn exec_stream(&mut self, command: &str, env_vars: &[String]) -> Result<i32> {
        use mrsh_core::binproto::{self, msg};
        use std::io::Write;

        let payload = binproto::build_exec(command, env_vars);
        binproto::send_msg(&mut self.stream, msg::EXEC_STREAM, &payload)
            .await
            .context("send EXEC_STREAM")?;

        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();

        loop {
            let (type_id, data) = binproto::recv_msg(&mut self.stream)
                .await
                .context("recv streaming exec")?;

            match type_id {
                msg::EXEC_STDOUT => {
                    stdout.write_all(&data)?;
                    stdout.flush()?;
                }
                msg::EXEC_STDERR => {
                    stderr.write_all(&data)?;
                    stderr.flush()?;
                }
                msg::EXEC_EXIT => {
                    let exit_code = if data.len() >= 4 {
                        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                    } else {
                        1
                    };
                    return Ok(exit_code as i32);
                }
                msg::ERROR => {
                    let err = binproto::parse_error(&data).unwrap_or_default();
                    bail!("exec error: {}", err);
                }
                other => {
                    tracing::debug!("exec_stream: ignoring unknown msg 0x{:02x}", other);
                }
            }
        }
    }

    /// Push a file via binary protocol (streaming from disk).
    pub async fn push_binary(
        &mut self,
        local_path: &std::path::Path,
        remote_path: &str,
    ) -> Result<u64> {
        use mrsh_core::binproto::{self, msg};
        use std::io::Read;

        let file_size = std::fs::metadata(local_path)
            .map(|m| m.len())
            .context("stat local file")?;

        // Send PUSH_START
        let payload = binproto::build_push_start(file_size, remote_path);
        binproto::send_msg(&mut self.stream, msg::PUSH_START, &payload)
            .await
            .context("send PUSH_START")?;

        // Stream chunks from disk
        let mut file = std::fs::File::open(local_path).context("open file")?;
        let mut buf = vec![0u8; 10 * 1024 * 1024]; // 10MB chunks
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buf).context("read chunk")?;
            if n == 0 {
                break;
            }
            binproto::send_msg(&mut self.stream, msg::PUSH_DATA, &buf[..n])
                .await
                .context("send PUSH_DATA")?;
            total += n as u64;
        }

        // Send PUSH_END
        binproto::send_empty(&mut self.stream, msg::PUSH_END)
            .await
            .context("send PUSH_END")?;

        // Receive ack
        let (type_id, data) = binproto::recv_msg(&mut self.stream)
            .await
            .context("recv push ack")?;
        match type_id {
            msg::PUSH_OK => Ok(total),
            msg::ERROR => {
                let err = binproto::parse_error(&data).unwrap_or_default();
                bail!("push error: {}", err);
            }
            other => bail!("unexpected response 0x{:02x} for PUSH", other),
        }
    }

    /// Pull a file via binary protocol. Returns file data.
    pub async fn pull_binary(&mut self, remote_path: &str) -> Result<Vec<u8>> {
        use mrsh_core::binproto::{self, msg};

        let payload = binproto::build_pull_req(remote_path);
        binproto::send_msg(&mut self.stream, msg::PULL_REQ, &payload)
            .await
            .context("send PULL_REQ")?;

        let mut data = Vec::new();
        loop {
            let (type_id, chunk) = binproto::recv_msg(&mut self.stream)
                .await
                .context("recv PULL_DATA")?;
            match type_id {
                msg::PULL_DATA => data.extend_from_slice(&chunk),
                msg::PULL_END => break,
                msg::ERROR => {
                    let err = binproto::parse_error(&chunk).unwrap_or_default();
                    bail!("pull error: {}", err);
                }
                other => bail!("unexpected response 0x{:02x} for PULL", other),
            }
        }
        Ok(data)
    }

    /// Ping via binary protocol.
    pub async fn ping_binary(&mut self) -> Result<()> {
        use mrsh_core::binproto::{self, msg};
        binproto::send_empty(&mut self.stream, msg::PING).await?;
        let (type_id, _) = binproto::recv_msg(&mut self.stream).await?;
        if type_id != msg::PONG {
            bail!("expected PONG, got 0x{:02x}", type_id);
        }
        Ok(())
    }

    /// Send a request and receive the response.
    pub async fn request(&mut self, req: &protocol::Request) -> Result<protocol::Response> {
        wire::send_json(&mut self.stream, req)
            .await
            .context("send request")?;
        // Use compressed recv if server supports zstd (backward-compatible: auto-detects flag byte)
        let resp: protocol::Response = if self.server_caps.iter().any(|c| c == "zstd") {
            wire::recv_json_compressed(&mut self.stream).await
        } else {
            wire::recv_json(&mut self.stream).await
        }
        .context("receive response")?;
        Ok(resp)
    }

    /// Get mutable access to the underlying stream (for hijack commands).
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consume client, returning the stream (for hijack commands).
    pub fn into_stream(self) -> S {
        self.stream
    }
}

/// Build a simple request with just a type.
pub fn simple_request(req_type: &str) -> protocol::Request {
    protocol::Request {
        req_type: req_type.to_string(),
        command: None,
        path: None,
        content: None,
        binary: None,
        gzip: None,
        sync_type: None,
        delta: None,
        signatures: None,
        paths: None,
        batch_patches: None,
        env_vars: None,
        track: None,
        version: None,
        allow_downgrade: None,
        insecure_no_verify: None,
    }
}

/// Shared-filesystem transport client (see `mrsh_core::fs_transport`).
///
/// The FsStream is wrapped in TLS so payload on disk is encrypted — same
/// security envelope as the TCP+TLS path.
pub type FsClient = RshClient<tokio_rustls::client::TlsStream<mrsh_core::fs_transport::FsStream>>;

/// Connect to an mrsh server through a shared spool directory.
///
/// Creates a new session (random id), writes the `ready.server` marker,
/// performs a TLS handshake (TOFU verifier) over the session's [`FsStream`],
/// and runs the standard binary auth handshake. Returns an authenticated client.
///
/// The server side must be running `mrsh_server::fs_listener::run_fs_listener`
/// on the same `spool_dir` with a matching `TlsAcceptor`.
///
/// `peer_id` seeds the TOFU known_hosts entry; use a stable label for the
/// target (e.g. the target's DeviceID or shared-spool name).
pub async fn connect_via_filesystem(
    spool_dir: &Path,
    peer_id: &str,
    key_path: &Option<String>,
) -> Result<FsClient> {
    use mrsh_core::fs_transport::{FsStream, Role, ensure_session_dirs, generate_session_id};
    use tokio::io::AsyncWriteExt as _;
    use tokio_rustls::TlsConnector;

    let session = generate_session_id();
    let session_dir = ensure_session_dirs(spool_dir, &session).context("ensure session dirs")?;
    let stream = FsStream::open(spool_dir, &session, Role::Client).context("open FsStream client")?;

    // Signal to the listener that the session layout is ready for pickup.
    let ready_tmp = session_dir.join("ready.server.tmp");
    let ready_final = session_dir.join("ready.server");
    {
        let mut f = tokio::fs::File::create(&ready_tmp)
            .await
            .context("create ready marker tmp")?;
        f.write_all(b"ready").await.context("write ready marker")?;
        f.flush().await.ok();
    }
    tokio::fs::rename(&ready_tmp, &ready_final)
        .await
        .context("publish ready marker")?;

    // TLS over the filesystem stream — same envelope as TCP path.
    // Peer id acts as the TOFU server_name so known_hosts entries are stable
    // across sessions pointing at the same target.
    let tls_name = format!("fs-{}", peer_id);
    let config = mrsh_core::tls::client_config_tofu(None);
    let connector = TlsConnector::from(config);
    let server_name = rustls::pki_types::ServerName::try_from(tls_name.clone())
        .map_err(|e| anyhow::anyhow!("invalid tls server name {}: {}", tls_name, e))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake over fs-transport")?;

    auth_client(tls_stream, key_path)
        .await
        .context("fs-transport auth")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_options_default() {
        let opts = ConnectOptions::default();
        assert_eq!(opts.port, 8822);
        assert!(opts.host.is_empty());
        assert!(opts.key_path.is_none());
    }

    #[test]
    fn simple_request_creates_correct_type() {
        let req = simple_request("ping");
        assert_eq!(req.req_type, "ping");
        assert!(req.command.is_none());
    }

    #[test]
    fn client_version_is_set() {
        assert!(!CLIENT_VERSION.is_empty());
    }

    #[test]
    fn client_caps_include_essentials() {
        assert!(CLIENT_CAPS.contains(&"shell"));
        assert!(CLIENT_CAPS.contains(&"self-update"));
    }

    #[tokio::test]
    async fn tcp_connect_refuses_bad_port() {
        let result = tcp_connect("127.0.0.1", 1).await;
        assert!(result.is_err());
    }

    /// connect_over_stream takes an existing TcpStream and wraps in TLS.
    /// Verifies the relay path: stream is reused (no TCP dial), TLS attempted.
    /// Error should be a TLS/IO error, NOT a TCP connect error.
    #[tokio::test]
    async fn connect_over_stream_uses_provided_stream() {
        use tokio::net::TcpListener;

        // Bind a listener; spawn a task that accepts + immediately drops
        // (sends TCP FIN), causing the TLS handshake to fail with EOF quickly.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await; // accept then drop → sends FIN
        });

        let stream = TcpStream::connect(addr).await.unwrap();

        // connect_over_stream wraps the stream in TLS then authenticates.
        // Expect TLS handshake EOF (not connect refused).
        let result = connect_over_stream(stream, "127.0.0.1", &None).await;
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected TLS/auth error"),
        };
        assert!(
            !err.contains("Connection refused"),
            "expected TLS/IO error, got connect-refused: {err}"
        );
    }

    /// connect_over_stream with explicit bad key path returns an error.
    #[tokio::test]
    async fn connect_over_stream_bad_key_path_errors() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();

        let bad_key = Some("/nonexistent/path/to/key".to_string());
        let result = connect_over_stream(stream, "127.0.0.1", &bad_key).await;
        // Either key-load fails (if checked before TLS) or TLS fails first.
        assert!(result.is_err(), "expected error from bad key/no-server");
    }

    // --- IPv6 address parsing ---

    #[test]
    fn parse_ipv6_link_local_with_numeric_scope() {
        let addr = parse_ipv6_host("fe80::1%23", 8822).unwrap();
        match addr {
            std::net::SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), "fe80::1".parse::<std::net::Ipv6Addr>().unwrap());
                assert_eq!(v6.port(), 8822);
                assert_eq!(v6.scope_id(), 23);
            }
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_ipv6_link_local_long_address() {
        let addr = parse_ipv6_host("fe80::b081:2dcc:ec06:ea07%15", 9822).unwrap();
        match addr {
            std::net::SocketAddr::V6(v6) => {
                assert_eq!(v6.scope_id(), 15);
                assert_eq!(v6.port(), 9822);
            }
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_ipv6_bracketed() {
        let addr = parse_ipv6_host("[::1]", 8822).unwrap();
        assert_eq!(
            addr,
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8822u16))
        );
    }

    #[test]
    fn parse_ipv6_bare() {
        let addr = parse_ipv6_host("::1", 8822).unwrap();
        assert_eq!(addr.port(), 8822);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn parse_ipv6_returns_none_for_ipv4() {
        assert!(parse_ipv6_host("192.168.1.1", 8822).is_none());
    }

    #[test]
    fn parse_ipv6_returns_none_for_hostname() {
        assert!(parse_ipv6_host("desktop-tlc-800", 8822).is_none());
    }

    #[test]
    fn parse_ipv6_non_numeric_scope_on_windows() {
        // Non-numeric scope on Windows → scope_id 0 (no if_nametoindex)
        let addr = parse_ipv6_host("fe80::1%eth0", 8822).unwrap();
        match addr {
            std::net::SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), "fe80::1".parse::<std::net::Ipv6Addr>().unwrap());
                // scope_id is 0 on Windows (no if_nametoindex), resolved on Linux
            }
            _ => panic!("expected V6"),
        }
    }

    // --- TLS host name stripping ---

    #[test]
    fn tls_host_strips_scope_id() {
        assert_eq!(tls_host_name("fe80::1%23"), "fe80::1");
    }

    #[test]
    fn tls_host_strips_brackets_and_scope() {
        assert_eq!(tls_host_name("[fe80::1]%23"), "fe80::1");
    }

    #[test]
    fn tls_host_strips_brackets() {
        assert_eq!(tls_host_name("[::1]"), "::1");
    }

    #[test]
    fn tls_host_passes_through_ipv4() {
        assert_eq!(tls_host_name("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn tls_host_passes_through_hostname() {
        assert_eq!(tls_host_name("desktop-tlc-800"), "desktop-tlc-800");
    }

    // --- IPv6 tcp_connect ---

    #[tokio::test]
    async fn tcp_connect_ipv6_loopback() {
        // Bind IPv6 loopback, connect to it
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = tcp_connect("::1", port).await;
        assert!(
            result.is_ok(),
            "IPv6 loopback connect failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn tcp_connect_ipv6_bracketed_loopback() {
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = tcp_connect("[::1]", port).await;
        assert!(
            result.is_ok(),
            "bracketed IPv6 connect failed: {:?}",
            result.err()
        );
    }

    // --- parse_target / fs:// URI parsing ---

    #[test]
    fn parse_target_plain_hostname_is_tcp() {
        match parse_target("desktop-tlc-800") {
            Target::Tcp(h) => assert_eq!(h, "desktop-tlc-800"),
            Target::Fs(p) => panic!("expected Tcp, got Fs({})", p.display()),
        }
    }

    #[test]
    fn parse_target_ipv4_is_tcp() {
        match parse_target("192.168.1.1") {
            Target::Tcp(h) => assert_eq!(h, "192.168.1.1"),
            Target::Fs(p) => panic!("expected Tcp, got Fs({})", p.display()),
        }
    }

    #[test]
    fn parse_target_device_id_is_tcp() {
        match parse_target("903470645") {
            Target::Tcp(h) => assert_eq!(h, "903470645"),
            Target::Fs(p) => panic!("expected Tcp, got Fs({})", p.display()),
        }
    }

    #[test]
    fn parse_target_user_at_host_is_tcp() {
        // `-h` parsing strips user@ upstream; Target only sees the host part,
        // but either way it must not be mistaken for fs://.
        match parse_target("user@host.example") {
            Target::Tcp(h) => assert_eq!(h, "user@host.example"),
            Target::Fs(p) => panic!("expected Tcp, got Fs({})", p.display()),
        }
    }

    #[test]
    fn parse_target_fs_absolute_posix() {
        // `fs:///abs/path` → absolute path on POSIX, drive-prefixed on Windows.
        match parse_target("fs:///tmp/mrsh-spool") {
            Target::Fs(p) => {
                #[cfg(not(target_os = "windows"))]
                assert_eq!(p, std::path::PathBuf::from("/tmp/mrsh-spool"));
                #[cfg(target_os = "windows")]
                assert_eq!(p, std::path::PathBuf::from("/tmp/mrsh-spool"));
            }
            Target::Tcp(h) => panic!("expected Fs, got Tcp({})", h),
        }
    }

    #[test]
    fn parse_target_fs_windows_drive() {
        // `fs:///C:/path` on Windows → `C:/path`; on POSIX it's an absolute path.
        match parse_target("fs:///C:/shared/mrsh-spool") {
            Target::Fs(p) => {
                #[cfg(target_os = "windows")]
                assert_eq!(p, std::path::PathBuf::from("C:/shared/mrsh-spool"));
                #[cfg(not(target_os = "windows"))]
                assert_eq!(p, std::path::PathBuf::from("/C:/shared/mrsh-spool"));
            }
            Target::Tcp(h) => panic!("expected Fs, got Tcp({})", h),
        }
    }

    #[test]
    fn parse_target_fs_relative_allowed() {
        // `fs://./rel/spool` — no leading `/` after scheme → relative path preserved.
        match parse_target("fs://./rel/spool") {
            Target::Fs(p) => assert_eq!(p, std::path::PathBuf::from("./rel/spool")),
            Target::Tcp(h) => panic!("expected Fs, got Tcp({})", h),
        }
    }

    #[test]
    fn parse_target_other_scheme_stays_tcp() {
        // We only recognise fs://. Anything else is passed through as a host
        // so existing user workflows keep working.
        match parse_target("tcp://example.com") {
            Target::Tcp(h) => assert_eq!(h, "tcp://example.com"),
            Target::Fs(p) => panic!("expected Tcp, got Fs({})", p.display()),
        }
    }
}
