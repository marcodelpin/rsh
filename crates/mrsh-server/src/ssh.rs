//! SSH server via russh — accepts standard SSH clients on the same port as TLS.
//!
//! Protocol detection in `listener.rs` peeks the first byte:
//!   0x16 → TLS (mrsh native)
//!   0x53 → SSH (this module, via `russh::server::run_stream`)
//!
//! Reuses existing infrastructure:
//! - Auth: ed25519 from `auth.rs` authorized_keys
//! - Exec: PowerShell via `exec.rs`
//! - Port forwarding: `tunnel.rs` direct-tcpip
//!
//! # Feature gate
//!
//! Compiled only with `--features ssh`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::handler::ServerContext;

// Re-export detection function (always available, even without ssh feature)
/// SSH protocol magic prefix for version exchange.
const SSH_VERSION_PREFIX: &[u8] = b"SSH-";

/// Check if the first bytes of a connection look like an SSH handshake.
pub fn is_ssh_handshake(buf: &[u8]) -> bool {
    buf.len() >= SSH_VERSION_PREFIX.len() && buf.starts_with(SSH_VERSION_PREFIX)
}

// ── russh server implementation ─────────────────────────────────

/// Handle an SSH connection using russh.
///
/// `stream` is the raw TCP stream with the first byte (0x53) already replayed
/// via PeekStream. russh handles the full SSH protocol from here.
pub async fn handle_ssh_connection<S>(stream: S, ctx: Arc<ServerContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[cfg(feature = "ssh")]
    {
        handle_ssh_connection_impl(stream, ctx).await
    }

    #[cfg(not(feature = "ssh"))]
    {
        let _ = ctx;
        // Without ssh feature, send version + close (stub behavior)
        handle_ssh_stub(stream).await
    }
}

#[cfg(not(feature = "ssh"))]
async fn handle_ssh_stub<S>(mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    info!("SSH connection detected — ssh feature not enabled, disconnecting");
    let version_line = b"SSH-2.0-mrsh_stub\r\n";
    stream.write_all(version_line).await.ok();

    // Read client version (up to 255 bytes)
    let mut buf = [0u8; 1];
    let mut count = 0usize;
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                count += 1;
                if buf[0] == b'\n' || count > 255 {
                    break;
                }
            }
        }
    }

    stream.shutdown().await.ok();
    Ok(())
}

// ── Full SSH server (behind feature gate) ───────────────────────

#[cfg(feature = "ssh")]
mod impl_ssh {
    use super::*;
    use russh::server::{Auth, Handler, Msg, Session};
    use russh::{Channel, ChannelId, Pty};

    /// Per-connection SSH session handler.
    pub(super) struct SshHandler {
        ctx: Arc<ServerContext>,
        /// Active channels (session channels for exec/shell).
        channels: HashMap<ChannelId, Channel<Msg>>,
        /// PTY dimensions per channel.
        pty_sizes: HashMap<ChannelId, (u32, u32)>,
    }

    impl SshHandler {
        pub fn new(ctx: Arc<ServerContext>) -> Self {
            Self {
                ctx,
                channels: HashMap::new(),
                pty_sizes: HashMap::new(),
            }
        }
    }

    impl Handler for SshHandler {
        type Error = anyhow::Error;

        /// Ed25519 public key auth — check against authorized_keys.
        async fn auth_publickey(
            &mut self,
            user: &str,
            public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            debug!("SSH auth: user={}", user);

            // Extract raw public key bytes from the russh key
            let raw_bytes = match public_key.key_data() {
                russh::keys::ssh_key::public::KeyData::Ed25519(ed) => {
                    ed.0.to_vec()
                }
                _ => {
                    warn!("SSH auth rejected: unsupported key type");
                    return Ok(Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                }
            };

            // Compare raw key bytes against authorized_keys
            for ak in &self.ctx.authorized_keys {
                if ak.key_type == "ssh-ed25519" && ak.key_data == raw_bytes {
                    info!("SSH auth accepted for user={} comment={:?}", user, ak.comment);
                    return Ok(Auth::Accept);
                }
            }

            warn!("SSH auth rejected for user={}", user);
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }

        /// Accept session channel opens.
        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            debug!("SSH channel_open_session: {}", channel.id());
            self.channels.insert(channel.id(), channel);
            Ok(true)
        }

        /// Handle PTY request — store dimensions for later ConPTY creation.
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _term: &str,
            col_width: u32,
            row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("SSH pty_request: ch={} {}x{}", channel, col_width, row_height);
            self.pty_sizes.insert(channel, (col_width, row_height));
            session.channel_success(channel)?;
            Ok(())
        }

        /// Handle exec request — run PowerShell command, or SCP protocol.
        async fn exec_request(
            &mut self,
            channel_id: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let command = String::from_utf8_lossy(data).to_string();
            info!("SSH exec: ch={} cmd={}", channel_id, &command[..80.min(command.len())]);

            session.channel_success(channel_id)?;

            // SCP: intercept and handle bidirectionally on the channel stream
            if crate::scp::is_scp_command(&command) {
                if let Some(channel) = self.channels.remove(&channel_id) {
                    let addr = format!("ssh-ch{}", channel_id);
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        let exit_code = crate::scp::handle_scp(&mut stream, &command, &addr).await;
                        let _ = stream.shutdown().await;
                        info!("SCP finished: ch={} exit={}", addr, exit_code);
                    });
                }
                return Ok(());
            }

            // Execute via PowerShell (same as mrsh exec handler)
            let env_vars: &[String] = &[];
            let resp = crate::exec::handle_exec(&command, env_vars).await;

            // Send output
            if let Some(ref output) = resp.output {
                session.data(channel_id, output.as_bytes().to_vec())?;
            }
            if let Some(ref error) = resp.error {
                session.extended_data(channel_id, 1, error.as_bytes().to_vec())?;
            }

            // Send exit status
            let exit_code = if resp.success { 0u32 } else { 1u32 };
            session.exit_status_request(channel_id, exit_code)?;
            session.eof(channel_id)?;
            session.close(channel_id)?;

            Ok(())
        }

        /// Handle shell request — interactive ConPTY session.
        async fn shell_request(
            &mut self,
            channel_id: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let (cols, rows) = self.pty_sizes.get(&channel_id).copied().unwrap_or((80, 24));
            info!("SSH shell: ch={} {}x{}", channel_id, cols, rows);

            session.channel_success(channel_id)?;

            // Get the channel for streaming I/O
            if let Some(channel) = self.channels.remove(&channel_id) {
                let mut stream = channel.into_stream();

                // Spawn shell handler in background
                tokio::spawn(async move {
                    let size = format!("{}x{}", cols, rows);
                    let env_vars = Vec::new();
                    if let Err(e) = crate::shell::handle_shell(&mut stream, &size, &env_vars).await {
                        warn!("SSH shell error: {}", e);
                    }
                });
            }

            Ok(())
        }

        /// Handle window resize.
        async fn window_change_request(
            &mut self,
            channel: ChannelId,
            col_width: u32,
            row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("SSH window_change: ch={} {}x{}", channel, col_width, row_height);
            self.pty_sizes.insert(channel, (col_width, row_height));
            // Note: resize of active ConPTY shell is handled internally by shell.rs
            Ok(())
        }

        /// Handle incoming data on a channel.
        async fn data(
            &mut self,
            _channel: ChannelId,
            _data: &[u8],
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            // Data routing is handled by the channel stream (shell/exec own the I/O)
            Ok(())
        }

        /// Handle direct-tcpip channel open (ssh -L port forwarding).
        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            originator_address: &str,
            originator_port: u32,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            let target = format!("{}:{}", host_to_connect, port_to_connect);
            info!(
                "SSH direct-tcpip: {} -> {} (from {}:{})",
                channel.id(), target, originator_address, originator_port
            );

            // Check allowed tunnels
            if !self.ctx.allowed_tunnels.is_empty() {
                let allowed = self.ctx.allowed_tunnels.iter().any(|pattern| {
                    pattern == &target
                        || pattern == &format!("{}:*", host_to_connect)
                        || pattern == "*"
                });
                if !allowed {
                    warn!("SSH tunnel denied: {} not in allowed_tunnels", target);
                    return Ok(false);
                }
            }

            // Spawn tunnel handler
            let mut stream = channel.into_stream();
            tokio::spawn(async move {
                match tokio::net::TcpStream::connect(&target).await {
                    Ok(mut target_stream) => {
                        if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await {
                            debug!("SSH tunnel {} closed: {}", target, e);
                        }
                    }
                    Err(e) => {
                        warn!("SSH tunnel connect to {} failed: {}", target, e);
                    }
                }
            });

            Ok(true)
        }

        /// Handle channel EOF.
        async fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("SSH channel_eof: {}", channel);
            session.close(channel)?;
            Ok(())
        }

        /// Handle channel close.
        async fn channel_close(
            &mut self,
            channel: ChannelId,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("SSH channel_close: {}", channel);
            self.channels.remove(&channel);
            self.pty_sizes.remove(&channel);
            Ok(())
        }

        /// Handle env request — store for later exec/shell.
        async fn env_request(
            &mut self,
            _channel: ChannelId,
            variable_name: &str,
            variable_value: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("SSH env: {}={}", variable_name, variable_value);
            // TODO: pass env vars to exec/shell when supported
            session.channel_success(_channel)?;
            Ok(())
        }

        /// Handle agent forwarding request (ssh -A).
        async fn agent_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            info!("SSH agent forwarding requested on channel {}", channel);
            session.channel_success(channel)?;
            Ok(true) // Accept agent forwarding
        }

        /// Handle subsystem request — SFTP.
        async fn subsystem_request(
            &mut self,
            channel_id: ChannelId,
            name: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            info!("SSH subsystem: {}", name);
            if name == "sftp" {
                if let Some(channel) = self.channels.remove(&channel_id) {
                    session.channel_success(channel_id)?;
                    let stream = channel.into_stream();
                    let sftp_handler = SftpHandler::new();
                    tokio::spawn(async move {
                        if let Err(e) = russh_sftp::server::run(stream, sftp_handler).await {
                            warn!("SFTP session error: {}", e);
                        }
                    });
                } else {
                    session.channel_failure(channel_id)?;
                }
            } else {
                warn!("SSH subsystem not supported: {}", name);
                session.channel_failure(channel_id)?;
            }
            Ok(())
        }

        /// Handle reverse port forwarding request (ssh -R).
        async fn tcpip_forward(
            &mut self,
            address: &str,
            port: &mut u32,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            info!("SSH tcpip_forward: {}:{}", address, port);
            // Bind a local listener and forward connections back to client
            let bind_addr = format!("{}:{}", address, port);
            let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("SSH -R bind {} failed: {}", bind_addr, e);
                    return Ok(false);
                }
            };
            // Update port if 0 (server chooses)
            if *port == 0 {
                *port = listener.local_addr().map(|a| a.port() as u32).unwrap_or(0);
            }
            let handle = session.handle();
            let fwd_addr = address.to_string();
            let fwd_port = *port;
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            debug!("SSH -R connection from {} to {}:{}", peer, fwd_addr, fwd_port);
                            let h = handle.clone();
                            let addr = fwd_addr.clone();
                            tokio::spawn(async move {
                                match h.channel_open_forwarded_tcpip(
                                    addr, fwd_port, peer.ip().to_string(), peer.port() as u32,
                                ).await {
                                    Ok(channel) => {
                                        let mut ch_stream = channel.into_stream();
                                        let mut tcp_stream = stream;
                                        tokio::io::copy_bidirectional(&mut ch_stream, &mut tcp_stream).await.ok();
                                    }
                                    Err(e) => {
                                        warn!("SSH -R channel open failed: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            debug!("SSH -R listener closed: {}", e);
                            break;
                        }
                    }
                }
            });
            Ok(true)
        }

        /// Cancel reverse port forwarding.
        async fn cancel_tcpip_forward(
            &mut self,
            address: &str,
            port: u32,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            info!("SSH cancel_tcpip_forward: {}:{}", address, port);
            // TODO: track active listeners and drop them
            Ok(true)
        }
    }

    /// SFTP handler — filesystem operations over SSH SFTP subsystem.
    struct SftpHandler;

    impl SftpHandler {
        fn new() -> Self { Self }
    }

    impl russh_sftp::server::Handler for SftpHandler {
        type Error = russh_sftp::protocol::StatusCode;

        fn unimplemented(&self) -> Self::Error {
            russh_sftp::protocol::StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            version: u32,
            _extensions: HashMap<String, String>,
        ) -> Result<russh_sftp::protocol::Version, Self::Error> {
            debug!("SFTP init: version {}", version);
            Ok(russh_sftp::protocol::Version::new())
        }

        async fn close(
            &mut self,
            id: u32,
            _handle: String,
        ) -> Result<russh_sftp::protocol::Status, Self::Error> {
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en".to_string(),
            })
        }

        async fn opendir(
            &mut self,
            id: u32,
            path: String,
        ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
            debug!("SFTP opendir: {}", path);
            // Return the path as the handle — we'll read it in readdir
            Ok(russh_sftp::protocol::Handle { id, handle: path })
        }

        async fn readdir(
            &mut self,
            id: u32,
            handle: String,
        ) -> Result<russh_sftp::protocol::Name, Self::Error> {
            debug!("SFTP readdir: {}", handle);
            let path = std::path::Path::new(&handle);
            match std::fs::read_dir(path) {
                Ok(entries) => {
                    let files: Vec<russh_sftp::protocol::File> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let attrs = russh_sftp::protocol::FileAttributes::default();
                            russh_sftp::protocol::File::new(name, attrs)
                        })
                        .collect();
                    if files.is_empty() {
                        Err(russh_sftp::protocol::StatusCode::Eof)
                    } else {
                        Ok(russh_sftp::protocol::Name { id, files })
                    }
                }
                Err(_) => Err(russh_sftp::protocol::StatusCode::NoSuchFile),
            }
        }

        async fn realpath(
            &mut self,
            id: u32,
            path: String,
        ) -> Result<russh_sftp::protocol::Name, Self::Error> {
            debug!("SFTP realpath: {}", path);
            let resolved = std::fs::canonicalize(&path)
                .unwrap_or_else(|_| std::path::PathBuf::from(&path));
            let name = resolved.to_string_lossy().to_string();
            Ok(russh_sftp::protocol::Name {
                id,
                files: vec![russh_sftp::protocol::File::dummy(&name)],
            })
        }

        async fn stat(
            &mut self,
            id: u32,
            path: String,
        ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
            debug!("SFTP stat: {}", path);
            match std::fs::metadata(&path) {
                Ok(meta) => {
                    let mut attrs = russh_sftp::protocol::FileAttributes::default();
                    attrs.size = Some(meta.len());
                    Ok(russh_sftp::protocol::Attrs { id, attrs })
                }
                Err(_) => Err(russh_sftp::protocol::StatusCode::NoSuchFile),
            }
        }

        async fn open(
            &mut self,
            id: u32,
            filename: String,
            _pflags: russh_sftp::protocol::PFlags,
            _attrs: russh_sftp::protocol::FileAttributes,
        ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
            debug!("SFTP open: {}", filename);
            Ok(russh_sftp::protocol::Handle { id, handle: filename })
        }

        async fn read(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            len: u32,
        ) -> Result<russh_sftp::protocol::Data, Self::Error> {
            use std::io::{Read, Seek, SeekFrom};
            debug!("SFTP read: {} offset={} len={}", handle, offset, len);
            let mut file = std::fs::File::open(&handle)
                .map_err(|_| russh_sftp::protocol::StatusCode::NoSuchFile)?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|_| russh_sftp::protocol::StatusCode::Failure)?;
            let mut buf = vec![0u8; len as usize];
            let n = file.read(&mut buf)
                .map_err(|_| russh_sftp::protocol::StatusCode::Failure)?;
            if n == 0 {
                return Err(russh_sftp::protocol::StatusCode::Eof);
            }
            buf.truncate(n);
            Ok(russh_sftp::protocol::Data { id, data: buf.into() })
        }

        async fn write(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            data: bytes::Bytes,
        ) -> Result<russh_sftp::protocol::Status, Self::Error> {
            use std::io::{Seek, SeekFrom, Write};
            debug!("SFTP write: {} offset={} len={}", handle, offset, data.len());
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&handle)
                .map_err(|_| russh_sftp::protocol::StatusCode::PermissionDenied)?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|_| russh_sftp::protocol::StatusCode::Failure)?;
            file.write_all(&data)
                .map_err(|_| russh_sftp::protocol::StatusCode::Failure)?;
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en".to_string(),
            })
        }

        async fn remove(
            &mut self,
            id: u32,
            filename: String,
        ) -> Result<russh_sftp::protocol::Status, Self::Error> {
            debug!("SFTP remove: {}", filename);
            std::fs::remove_file(&filename)
                .map_err(|_| russh_sftp::protocol::StatusCode::NoSuchFile)?;
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en".to_string(),
            })
        }

        async fn mkdir(
            &mut self,
            id: u32,
            path: String,
            _attrs: russh_sftp::protocol::FileAttributes,
        ) -> Result<russh_sftp::protocol::Status, Self::Error> {
            debug!("SFTP mkdir: {}", path);
            std::fs::create_dir_all(&path)
                .map_err(|_| russh_sftp::protocol::StatusCode::PermissionDenied)?;
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en".to_string(),
            })
        }

        async fn rmdir(
            &mut self,
            id: u32,
            path: String,
        ) -> Result<russh_sftp::protocol::Status, Self::Error> {
            debug!("SFTP rmdir: {}", path);
            std::fs::remove_dir(&path)
                .map_err(|_| russh_sftp::protocol::StatusCode::NoSuchFile)?;
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en".to_string(),
            })
        }

        async fn rename(
            &mut self,
            id: u32,
            oldpath: String,
            newpath: String,
        ) -> Result<russh_sftp::protocol::Status, Self::Error> {
            debug!("SFTP rename: {} -> {}", oldpath, newpath);
            std::fs::rename(&oldpath, &newpath)
                .map_err(|_| russh_sftp::protocol::StatusCode::Failure)?;
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Build russh server config, loading the persistent server_key.
    ///
    /// Tries to load from `server_key_path` (OpenSSH format).
    /// Falls back to ephemeral key if load fails (with warning).
    pub(super) fn build_config(server_key_path: Option<&std::path::Path>) -> russh::server::Config {
        let host_key = if let Some(path) = server_key_path {
            match russh::keys::load_secret_key(path, None) {
                Ok(key) => {
                    info!("SSH host key loaded from {:?}", path);
                    key
                }
                Err(e) => {
                    warn!("SSH: failed to load server_key from {:?}: {}, using ephemeral", path, e);
                    generate_ephemeral_key()
                }
            }
        } else {
            warn!("SSH: no server_key path, using ephemeral key (TOFU will break on restart)");
            generate_ephemeral_key()
        };

        russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            ..Default::default()
        }
    }

    fn generate_ephemeral_key() -> russh::keys::PrivateKey {
        use russh::keys::ssh_key::rand_core::OsRng;
        russh::keys::PrivateKey::random(&mut OsRng, russh::keys::ssh_key::Algorithm::Ed25519)
            .expect("generate ephemeral SSH host key")
    }
}

#[cfg(feature = "ssh")]
async fn handle_ssh_connection_impl<S>(stream: S, ctx: Arc<ServerContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("SSH connection — handling via russh");

    let config = Arc::new(impl_ssh::build_config(ctx.server_key_path.as_deref()));
    let handler = impl_ssh::SshHandler::new(ctx);

    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            // RunningSession implements Future — await to wait for session end
            if let Err(e) = session.await {
                debug!("SSH session ended: {:?}", e);
            }
            Ok(())
        }
        Err(e) => {
            warn!("SSH session error: {}", e);
            Ok(()) // Don't propagate — connection errors are normal
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ssh_handshake_detects_ssh2() {
        assert!(is_ssh_handshake(b"SSH-2.0-OpenSSH_9.6"));
        assert!(is_ssh_handshake(b"SSH-2.0-PuTTY_Release_0.80"));
        assert!(is_ssh_handshake(b"SSH-2.0-rsh_5.1\r\n"));
    }

    #[test]
    fn is_ssh_handshake_detects_ssh1() {
        assert!(is_ssh_handshake(b"SSH-1.99-OpenSSH_3.4"));
    }

    #[test]
    fn is_ssh_handshake_rejects_tls() {
        assert!(!is_ssh_handshake(&[0x16, 0x03, 0x01, 0x00]));
    }

    #[test]
    fn is_ssh_handshake_rejects_http() {
        assert!(!is_ssh_handshake(b"GET / HTTP/1.1"));
        assert!(!is_ssh_handshake(b"POST /api"));
    }

    #[test]
    fn is_ssh_handshake_rejects_empty() {
        assert!(!is_ssh_handshake(b""));
        assert!(!is_ssh_handshake(b"SS"));
        assert!(!is_ssh_handshake(b"SSH"));
    }

    #[test]
    fn is_ssh_handshake_rejects_partial_prefix() {
        assert!(!is_ssh_handshake(b"SSX-"));
        assert!(!is_ssh_handshake(b"SsH-"));
    }

    #[test]
    fn is_ssh_handshake_exact_prefix() {
        assert!(is_ssh_handshake(b"SSH-"));
    }

    #[tokio::test]
    async fn handle_ssh_connection_sends_version_and_closes() {
        use crate::session::SessionStore;
        use tokio::io::AsyncReadExt;

        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "test".to_string(),
            banner: None,
            caps: vec![],
            session_store: SessionStore::new(),
            rate_limiter: crate::ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
            server_key_path: None,
        });

        let (mut client, server) = tokio::io::duplex(4096);

        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            handle_ssh_connection(server, ctx_clone).await
        });

        // Client should receive server version string
        let mut version_buf = vec![0u8; 256];
        let n = client.read(&mut version_buf).await.unwrap();
        let version_str = String::from_utf8_lossy(&version_buf[..n]);
        assert!(
            version_str.starts_with("SSH-2.0-"),
            "expected SSH version string, got: {}",
            version_str
        );

        // Client sends its version string
        use tokio::io::AsyncWriteExt;
        client
            .write_all(b"SSH-2.0-TestClient_1.0\r\n")
            .await
            .unwrap();

        // Handler should finish (either stub or russh handles it)
        // Drop client to signal EOF
        drop(client);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn handle_ssh_connection_client_disconnects_early() {
        use crate::session::SessionStore;

        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "test".to_string(),
            banner: None,
            caps: vec![],
            session_store: SessionStore::new(),
            rate_limiter: crate::ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
            server_key_path: None,
        });

        let (client, server) = tokio::io::duplex(4096);
        drop(client);

        let result = handle_ssh_connection(server, ctx).await;
        assert!(result.is_ok(), "should handle early disconnect gracefully");
    }
}
