//! Server mode — TLS listener, authentication, relay registration.
//! Extracted from main.rs to reduce its size.

use std::sync::Arc;
use anyhow::{Context, Result, bail};
use tracing::info;

// ── Server mode (cross-platform) ──────────────────────────────

/// Run the server: load TLS certs, authorized keys, start listeners.
/// `with_tray`: true = show system tray icon (Windows only), false = headless.
pub async fn run_server_mode(port: u16, with_tray: bool) -> Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    run_server_mode_inner(port, with_tray, cancel).await
}

/// Run server with an externally provided cancel token (from service control).
pub async fn run_server_mode_with_cancel(
    port: u16,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    run_server_mode_inner(port, false, cancel).await
}

/// Resolve the DeviceID with fallback chain:
/// 1. Config `device_id` field (if set) → use it
/// 2. Legacy `device_id` file in data_dir (from old Go installs) → use it
/// 3. Neither → generate a new 9-digit numeric ID, save to config
pub fn resolve_device_id(config: &mrsh_core::config::Config, data_dir: &std::path::Path) -> String {
    let config_id = config.device_id.clone().unwrap_or_default();
    if !config_id.is_empty() {
        return config_id;
    }

    // Fallback 1: read device_id file from data dir (legacy Go installs)
    let file_id = std::fs::read_to_string(data_dir.join("device_id"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let id = if file_id.is_empty() {
        // Fallback 2: generate a new 9-digit numeric device ID
        use rand::Rng;
        let n: u32 = rand::thread_rng().gen_range(100_000_000..999_999_999);
        n.to_string()
    } else {
        file_id
    };

    // Persist to config so it's stable across restarts
    let mut cfg = mrsh_core::config::Config::load();
    cfg.device_id = Some(id.clone());
    if let Err(e) = cfg.save() {
        tracing::warn!("could not save device_id to config: {}", e);
    } else {
        tracing::info!("generated and saved DeviceID {}", id);
    }

    id
}

/// Build the list of capabilities this server supports.
/// Advertised to clients during auth handshake so they know what commands are available.
pub fn build_server_caps_with_mode(tray_mode: bool) -> Vec<String> {
    let mut caps = build_server_caps();
    if tray_mode {
        caps.push("tray".to_string());
    } else {
        caps.push("system".to_string());
    }
    caps
}

pub fn build_server_caps() -> Vec<String> {
    let mut caps = vec![
        "exec".to_string(),
        "stream-exec".to_string(),
        "log-query".to_string(),
        "push".to_string(),
        "pull".to_string(),
        "self-update".to_string(),
        "bin-patch".to_string(),
        "info".to_string(),
        "ps".to_string(),
        "kill".to_string(),
        "ls".to_string(),
        "cat".to_string(),
        "tail".to_string(),
        "clip".to_string(),
        "screenshot".to_string(),
    ];

    #[cfg(windows)]
    {
        caps.extend([
            "shell".to_string(),
            "session".to_string(),
            "recording".to_string(),
            "mouse".to_string(),
            "keyboard".to_string(),
            "window".to_string(),
            "service".to_string(),
            "reboot".to_string(),
            "shutdown".to_string(),
            "sleep".to_string(),
            "lock".to_string(),
        ]);
    }

    #[cfg(not(windows))]
    {
        caps.push("shell".to_string());
        caps.push("reboot".to_string());
        caps.push("shutdown".to_string());
    }

    #[cfg(feature = "quic")]
    caps.push("quic".to_string());

    caps.push("zstd".to_string());

    caps
}

pub async fn run_server_mode_inner(
    port: u16,
    _with_tray: bool,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    use mrsh_core::{auth, tls};
    use mrsh_server::{handler::ServerContext, listener, session};
    use tokio_rustls::TlsAcceptor;

    let data_dir = crate::server_data_dir();
    std::fs::create_dir_all(&data_dir)?;

    info!("server starting: port={}, tray={}", port, _with_tray);

    // Load or generate TLS certificate
    let (certs, key) = tls::load_or_generate_cert(&data_dir)?;
    let tls_config = tls::server_config(certs, key)?;
    #[cfg(feature = "quic")]
    let tls_config_for_quic = tls_config.clone();
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Load authorized keys from ALL possible locations (service + user + legacy)
    let authorized_keys = {
        let mut all_keys: Vec<auth::AuthorizedKey> = Vec::new();
        let mut seen_key_data: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let ak_paths = crate::all_authorized_keys_paths();
        let mut loaded_any = false;

        for ak_path in &ak_paths {
            if ak_path.exists() {
                // Use strict=true only for the primary data_dir path
                let strict = ak_path.starts_with(&data_dir);
                match auth::load_authorized_keys(ak_path, strict) {
                    Ok(keys) => {
                        let count_before = all_keys.len();
                        for key in keys {
                            if seen_key_data.insert(key.key_data.clone()) {
                                all_keys.push(key);
                            }
                        }
                        let added = all_keys.len() - count_before;
                        if added > 0 {
                            tracing::info!(
                                "loaded {} key(s) from {}",
                                added,
                                ak_path.display()
                            );
                        }
                        loaded_any = true;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "failed to load authorized_keys from {}: {}",
                            ak_path.display(),
                            e
                        );
                    }
                }
            }
        }

        if !loaded_any {
            tracing::warn!(
                "no authorized_keys found in any location: {:?}",
                ak_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>()
            );
        }

        all_keys
    };

    // Load revoked keys (optional — empty set if file doesn't exist)
    let rk_path = data_dir.join("revoked_keys");
    let revoked_keys = if rk_path.exists() {
        auth::load_revoked_keys(&rk_path)?
    } else {
        std::collections::HashSet::new()
    };

    let caps = build_server_caps_with_mode(_with_tray);

    // Load TOTP secrets (optional — empty vec if file doesn't exist)
    let totp_path = data_dir.join("totp_secrets");
    let totp_secrets = if totp_path.exists() {
        auth::load_totp_secrets(&totp_path)?
    } else {
        Vec::new()
    };

    let totp_recovery_path = {
        let p = data_dir.join("totp_recovery");
        if p.exists() { Some(p) } else { None }
    };

    // Resolve device_id and rendezvous server early (needed by ServerContext for auth response)
    let preload_config = mrsh_core::config::Config::load();
    let server_device_id = {
        let id = resolve_device_id(&preload_config, &data_dir);
        if id.is_empty() { None } else { Some(id) }
    };
    let server_rendezvous = {
        let rdv = match option_env!("MRSH_RDV_SERVER") {
            Some(rdv) if !rdv.is_empty() => vec![rdv.to_string()],
            _ => preload_config.get_rendezvous_servers(),
        };
        rdv.into_iter().next() // first/primary rendezvous server
    };

    // Initialize connection notification channel (for tray toast notifications)
    let _notify_rx = mrsh_server::notify::init();

    let ctx = Arc::new(ServerContext {
        authorized_keys,
        revoked_keys,
        server_version: {
            let v = env!("CARGO_PKG_VERSION").to_string();
            match option_env!("MRSH_VERSION_SUFFIX") {
                Some(s) if !s.is_empty() => format!("{}-{}", v, s),
                _ => v,
            }
        },
        banner: option_env!("MRSH_BANNER").map(|s| s.to_string()),
        caps,
        session_store: session::SessionStore::new(),
        rate_limiter: mrsh_server::ratelimit::AuthRateLimiter::new(),
        allowed_tunnels: load_allowed_tunnels(&data_dir),
        totp_secrets,
        totp_recovery_path,
        server_key_path: Some(data_dir.join("server_key")),
        device_id: server_device_id.clone(),
        rendezvous_server: server_rendezvous.clone(),
        authorized_keys_paths: crate::all_authorized_keys_paths(),
    });

    // Clone TLS acceptor and ctx for relay handler before moving into ServerConfig.
    let relay_tls_acceptor = tls_acceptor.clone();
    let relay_ctx = ctx.clone();

    let config = listener::ServerConfig {
        command_port: port,
        tls_acceptor,
        ctx,
        ip_acl: load_ip_acl(&data_dir),
        #[cfg(feature = "quic")]
        tls_config: tls_config_for_quic,
    };

    // Spawn rendezvous registration loop with relay notification support.
    let tray_device_id;
    {
        let user_config = mrsh_core::config::Config::load();
        // Compile-time override: MRSH_RDV_SERVER=host:port bakes the rendezvous server
        let rdv_servers = match option_env!("MRSH_RDV_SERVER") {
            Some(rdv) if !rdv.is_empty() => vec![rdv.to_string()],
            _ => user_config.get_rendezvous_servers(),
        };
        let device_id = resolve_device_id(&user_config, &data_dir);
        tray_device_id = device_id.clone();
        let rdv_key = user_config.rendezvous_key.clone().unwrap_or_default();
        // Compute group_hash from enrollment_token (if present in config).
        let group_hash = if let Some(ref token) = user_config.enrollment_token {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(token.as_bytes());
            let digest = h.finalize();
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
        } else {
            String::new()
        };
        let hostname = std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let platform = std::env::consts::OS.to_string();

        // Spawn LAN discovery responder (non-fatal if port busy).
        {
            let cancel_disc = cancel.clone();
            let disc_id = device_id.clone();
            let disc_host = hostname.clone();
            let disc_platform = platform.clone();
            let disc_port = port;
            tokio::spawn(async move {
                mrsh_relay::discovery::run_discovery_responder(
                    cancel_disc, disc_id, disc_host, disc_platform, disc_port,
                ).await;
            });
        }

        if !rdv_servers.is_empty() && !device_id.is_empty() {
            let (relay_tx, mut relay_rx) =
                tokio::sync::mpsc::channel::<mrsh_relay::rendezvous::RelayNotification>(16);

            // Registration + relay notification listener.
            let cancel_reg = cancel.clone();
            let svc_port = port;
            let enrollment_token_for_crypto = user_config.enrollment_token.clone().unwrap_or_default();
            let reg_hostname = hostname.clone();
            tokio::spawn(async move {
                // Build encrypted network info for LAN discovery
                let net_info_blob = if !enrollment_token_for_crypto.is_empty() {
                    let info = mrsh_relay::net_crypto::collect_network_info(
                        &reg_hostname, svc_port, crate::TRAY_PORT,
                    );
                    let (_, group_pub) = mrsh_relay::net_crypto::derive_group_keypair(
                        &enrollment_token_for_crypto,
                    );
                    let gh = {
                        use sha2::Digest;
                        let d = sha2::Sha256::digest(enrollment_token_for_crypto.as_bytes());
                        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    };
                    mrsh_relay::net_crypto::encrypt_network_info(&info, &[(gh, group_pub)])
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                // Build port info for registration
                let this_caps = build_server_caps_with_mode(_with_tray);
                let mut reg_ports = vec![
                    mrsh_relay::proto::PortInfo {
                        port: svc_port as u32,
                        instance_type: if _with_tray { "tray".into() } else { "system".into() },
                        caps: this_caps,
                    },
                ];
                // On Windows, both instances register — tray includes the other port too
                #[cfg(windows)]
                if _with_tray {
                    // Tray instance also reports service port (8822)
                    let mut sys_caps = build_server_caps_with_mode(false);
                    // system caps differ from tray caps
                    reg_ports.push(mrsh_relay::proto::PortInfo {
                        port: crate::DEFAULT_PORT as u32,
                        instance_type: "system".into(),
                        caps: sys_caps.drain(..).collect(),
                    });
                }

                let client = mrsh_relay::rendezvous::Client {
                    servers: rdv_servers,
                    licence_key: rdv_key.clone(),
                    local_id: device_id,
                    group_hash,
                    hostname,
                    platform,
                    service_port: svc_port,
                    encrypted_net_info: net_info_blob,
                    ports: reg_ports,
                };
                client.run_registration_loop(cancel_reg, relay_tx).await;
            });

            // Relay acceptance handler: receives notifications from hbbs and
            // connects to hbbr to complete the relay pairing.
            let cancel_relay = cancel.clone();
            let relay_key = user_config.rendezvous_key.clone().unwrap_or_default();
            if relay_key.is_empty() {
                tracing::warn!("relay key is EMPTY — relay auth will fail. Add RendezvousKey to config.");
            } else {
                tracing::info!("relay key: {}…", &relay_key[..relay_key.len().min(8)]);
            }
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_relay.cancelled() => break,
                        Some(notif) = relay_rx.recv() => {
                            let acceptor = relay_tls_acceptor.clone();
                            let ctx = relay_ctx.clone();
                            let key = relay_key.clone();
                            tokio::spawn(async move {
                                if let Err(e) = accept_relay_connection(notif, acceptor, ctx, &key).await {
                                    tracing::warn!("relay accept: {}", e);
                                }
                            });
                        }
                    }
                }
            });
        }
    }

    #[cfg(target_os = "windows")]
    if _with_tray {
        use mrsh_server::tray;

        // Tray mode — run listener in background, tray on main thread
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { listener::run_server(config, cancel_clone).await });

        // Tray blocks the current thread's message loop
        let tray_cancel = cancel.clone();
        let tray_port = port;
        let tray_id = tray_device_id.clone();
        let tray_handle =
            tokio::task::spawn_blocking(move || tray::run_tray(tray_cancel, tray_port, tray_id));

        // Wait for either to finish — log which side exited and why
        tokio::select! {
            result = server_handle => {
                match &result {
                    Ok(Ok(())) => tracing::warn!("tray: server listener exited cleanly — shutting down"),
                    Ok(Err(e)) => tracing::error!("tray: server listener failed: {} — shutting down", e),
                    Err(e) => tracing::error!("tray: server listener panicked: {} — shutting down", e),
                }
                cancel.cancel(); // signal tray to exit gracefully
                // Give tray a moment to process WM_QUIT from cancel check
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                result??;
            }
            result = tray_handle => {
                match &result {
                    Ok(Ok(())) => tracing::info!("tray: message loop exited cleanly"),
                    Ok(Err(e)) => tracing::error!("tray: message loop failed: {}", e),
                    Err(e) => tracing::error!("tray: message loop panicked: {}", e),
                }
                cancel.cancel(); // stop server listener
                result??;
            }
        }
        return Ok(());
    }

    // Service, console, or daemon mode — listener blocks, no tray
    listener::run_server(config, cancel).await?;

    Ok(())
}

/// Accept an incoming relay connection: connect to hbbr, TLS accept, dispatch.
///
/// Called when hbbs sends a RelayResponse notification indicating a client
/// wants to connect to this server via relay. We connect to hbbr with the
/// same UUID so hbbr can pair us with the client.
pub async fn accept_relay_connection(
    notif: mrsh_relay::rendezvous::RelayNotification,
    acceptor: tokio_rustls::TlsAcceptor,
    ctx: Arc<mrsh_server::handler::ServerContext>,
    licence_key: &str,
) -> Result<()> {
    let relay_addr = if notif.relay_server.contains(':') {
        notif.relay_server.clone()
    } else {
        format!("{}:21117", notif.relay_server)
    };

    info!(
        "relay accept: connecting to hbbr {} uuid={}",
        relay_addr, notif.uuid
    );

    let relay_stream = mrsh_relay::relay::connect_relay(&relay_addr, &notif.uuid, licence_key)
        .await
        .context("relay: connect to hbbr")?;

    info!("relay accept: connected to hbbr (target_port={})", notif.target_port);

    // Route BEFORE TLS accept — proxy forwards raw TCP so the target port
    // (e.g. tray) handles its own TLS handshake with the client.
    //
    // target_port == 0:            tray-first — try tray, fallback to SYSTEM.
    // target_port == DEFAULT_PORT: explicit service — TLS accept here (SYSTEM).
    // target_port == other:        explicit port — proxy raw stream to that port.

    // Explicit non-default port (e.g. 9822 = tray) — proxy raw stream directly.
    if notif.target_port != 0 && notif.target_port != crate::DEFAULT_PORT {
        info!("relay accept: proxying raw stream to explicit port {}", notif.target_port);
        let local_stream = tokio::net::TcpStream::connect(
            format!("127.0.0.1:{}", notif.target_port),
        )
        .await
        .context(format!("connect to local port {}", notif.target_port))?;

        return relay_proxy_bidirectional(relay_stream, local_stream).await;
    }

    // Tray-first (target_port == 0): single connect attempt to tray.
    // If tray is up, proxy raw stream. If not, fall through to SYSTEM context.
    if notif.target_port == 0 {
        let tray_addr = format!("127.0.0.1:{}", crate::TRAY_PORT);
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::net::TcpStream::connect(&tray_addr),
        ).await {
            Ok(Ok(tray_stream)) => {
                info!("relay accept: tray available, routing to port {}", crate::TRAY_PORT);
                return relay_proxy_bidirectional(relay_stream, tray_stream).await;
            }
            _ => {
                info!("relay accept: tray not available, handling in SYSTEM context");
            }
        }
    }

    // SYSTEM context (target_port == DEFAULT_PORT, or tray-first fallback).
    // TLS accept and handle the connection ourselves.
    info!("relay accept: TLS handshake for SYSTEM context");

    let tls_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        acceptor.accept(relay_stream),
    )
    .await;

    let tls_stream = match tls_result {
        Err(_) => {
            tracing::error!("relay accept: TLS handshake timed out after 30s");
            anyhow::bail!("relay: TLS accept timeout");
        }
        Ok(Err(e)) => {
            tracing::error!("relay accept: TLS handshake failed: {:?}", e);
            anyhow::bail!("relay: TLS accept: {}", e);
        }
        Ok(Ok(s)) => s,
    };

    mrsh_server::handler::handle_connection(tls_stream, &ctx, None).await?;

    Ok(())
}

/// Bidirectional proxy between a relay stream and a local TCP stream.
/// Used to forward relay connections to a different local port (e.g. tray).
async fn relay_proxy_bidirectional(
    relay_stream: tokio::net::TcpStream,
    local_stream: tokio::net::TcpStream,
) -> Result<()> {
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);
    let (mut local_read, mut local_write) = tokio::io::split(local_stream);

    tokio::select! {
        r = tokio::io::copy(&mut relay_read, &mut local_write) => {
            if let Err(e) = r { tracing::debug!("relay→local: {}", e); }
        }
        r = tokio::io::copy(&mut local_read, &mut relay_write) => {
            if let Err(e) = r { tracing::debug!("local→relay: {}", e); }
        }
    }
    Ok(())
}

/// Get all local IPv4 addresses (for LAN detection).

/// Handle a command over SSH fallback (when target has no mrsh service).
/// Returns exit code for the process.
#[cfg(feature = "ssh")]
pub async fn run_ssh_command(
    ssh: mrsh_client::ssh_client::SshSession,
    cmd: &str,
    args: &[String],
) -> Result<i32> {
    match cmd {
        "exec" => {
            if args.len() < 2 {
                bail!("exec requires a command");
            }
            let command = args[1..].join(" ");
            let (exit_code, output) = ssh.exec(&command).await?;
            print!("{}", output);
            Ok(exit_code as i32)
        }
        "ping" => {
            let (code, output) = ssh.exec("echo pong").await?;
            print!("{}", output);
            Ok(code as i32)
        }
        "push" => {
            if args.len() < 3 {
                bail!("push requires <local> <remote>");
            }
            let local_path = std::path::Path::new(&args[1]);
            let bytes = ssh.push(local_path, &args[2]).await?;
            println!("pushed {} bytes via SSH", bytes);
            Ok(0)
        }
        "pull" => {
            if args.len() < 3 {
                bail!("pull requires <remote> <local>");
            }
            let data = ssh.pull(&args[1]).await?;
            std::fs::write(&args[2], &data)?;
            println!("pulled {} bytes via SSH", data.len());
            Ok(0)
        }
        other => {
            bail!("command '{}' not supported over SSH fallback (only exec, ping, push, pull)", other);
        }
    }
}

pub fn load_ip_acl(data_dir: &std::path::Path) -> mrsh_server::listener::IpAccessControl {
    let load_file = |name: &str| -> Vec<String> {
        let path = data_dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let entries: Vec<String> = content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| l.to_string())
                    .collect();
                if !entries.is_empty() {
                    info!("loaded {} IP rules from {}", entries.len(), path.display());
                }
                entries
            }
            Err(_) => vec![],
        }
    };

    let allow = load_file("allowed_ips");
    let deny = load_file("denied_ips");

    if allow.is_empty() && deny.is_empty() {
        mrsh_server::listener::IpAccessControl::allow_all()
    } else {
        mrsh_server::listener::IpAccessControl::new(&allow, &deny)
    }
}

pub fn load_allowed_tunnels(data_dir: &std::path::Path) -> Vec<String> {
    let path = data_dir.join("allowed_tunnels");
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let targets: Vec<String> = content
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_string())
                .collect();
            if !targets.is_empty() {
                info!(
                    "loaded {} tunnel restrictions from {}",
                    targets.len(),
                    path.display()
                );
            }
            targets
        }
        Err(_) => vec![], // file not found = all allowed
    }
}
