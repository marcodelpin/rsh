//! Server mode — TLS listener, authentication, relay registration.
//! Extracted from main.rs to reduce its size.

use anyhow::{Context, Result, bail};
use std::sync::Arc;
use tracing::info;

// ── Server mode (cross-platform) ──────────────────────────────

/// Run the server: load TLS certs, authorized keys, start listeners.
/// `with_tray`: true = show system tray icon (Windows only), false = headless.
#[allow(dead_code)] // kept for API compat; callers now use *_with_fs_spool variants
pub async fn run_server_mode(port: u16, with_tray: bool) -> Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    run_server_mode_inner(port, with_tray, cancel, fs_spool_from_config()).await
}

/// Same as [`run_server_mode`] but also accepts FS-transport sessions from
/// the given shared-spool directory. Passing `None` keeps the TCP-only path.
pub async fn run_server_mode_with_fs_spool(
    port: u16,
    with_tray: bool,
    fs_spool: Option<std::path::PathBuf>,
) -> Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    run_server_mode_inner(
        port,
        with_tray,
        cancel,
        fs_spool.or_else(fs_spool_from_config),
    )
    .await
}

/// Run server with an externally provided cancel token (from service control).
#[allow(dead_code)] // kept for API compat; callers now use *_with_cancel_and_spool
pub async fn run_server_mode_with_cancel(
    port: u16,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    run_server_mode_inner(port, false, cancel, fs_spool_from_config()).await
}

/// Same as [`run_server_mode_with_cancel`] but with an explicit spool dir.
/// The SCM service path passes `None` and picks the value up from config.
pub async fn run_server_mode_with_cancel_and_spool(
    port: u16,
    cancel: tokio_util::sync::CancellationToken,
    fs_spool: Option<std::path::PathBuf>,
) -> Result<()> {
    run_server_mode_inner(
        port,
        false,
        cancel,
        fs_spool.or_else(fs_spool_from_config),
    )
    .await
}

/// Read `fs_spool` from the persisted config (if any). Installed services pick
/// the value up at startup without needing the CLI flag re-supplied.
fn fs_spool_from_config() -> Option<std::path::PathBuf> {
    let cfg = mrsh_core::config::Config::load();
    cfg.fs_spool.as_ref().map(std::path::PathBuf::from)
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
        // rsh-6i9e: advertise arch-suffixed cap so future Windows-on-ARM
        // builds route correctly via fleet update. Old clients ignore unknown
        // caps; the legacy "window"/"tray" markers still identify Windows.
        #[cfg(target_arch = "x86_64")]
        caps.push("windows-x86_64".to_string());
        #[cfg(target_arch = "aarch64")]
        caps.push("windows-aarch64".to_string());
    }

    #[cfg(not(windows))]
    {
        caps.push("shell".to_string());
        caps.push("reboot".to_string());
        caps.push("shutdown".to_string());
        // rsh-lic: advertise "linux" so clients can auto-pick the right binary
        // in fleet update. Musl builds add an extra "linux-musl" cap so rdv
        // (Alpine) and similar hosts get the static binary.
        caps.push("linux".to_string());
        #[cfg(target_env = "musl")]
        caps.push("linux-musl".to_string());
        // rsh-6i9e: advertise CPU arch so fleet update can route x86_64
        // vs aarch64 binaries. Backward-compatible: old clients keep the
        // "linux" cap and route via the legacy heuristic; new clients prefer
        // the arch-specific cap when present.
        #[cfg(target_arch = "x86_64")]
        caps.push("linux-x86_64".to_string());
        #[cfg(target_arch = "aarch64")]
        caps.push("linux-aarch64".to_string());
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
    fs_spool: Option<std::path::PathBuf>,
) -> Result<()> {
    use mrsh_core::{auth, tls};
    use mrsh_server::{handler::ServerContext, listener, session};
    use tokio_rustls::TlsAcceptor;

    let data_dir = crate::server_data_dir();
    std::fs::create_dir_all(&data_dir)?;

    // Clean up residual binaries from previous self-update or rename-swap deploys.
    // These accumulate over time: mrsh-prev.exe, mrsh-new.exe, mrsh-update.exe, *.bak
    #[cfg(target_os = "windows")]
    {
        let canonical = data_dir.join("mrsh.exe");
        if canonical.exists() {
            for name in &[
                "mrsh-prev.exe",
                "mrsh-new.exe",
                "mrsh-update.exe",
                "mrsh.exe.bak",
                "mrsh.exe.incoming", // rsh-q2az: leftover from an interrupted atomic swap
            ] {
                let residual = data_dir.join(name);
                if residual.exists() {
                    match std::fs::remove_file(&residual) {
                        Ok(()) => info!("cleaned residual: {}", name),
                        Err(e) => tracing::debug!("residual {} locked (in use?): {}", name, e),
                    }
                }
            }
        }
    }

    // Kill zombie listeners from previous self-update or restart that are
    // still bound to our port. SO_REUSEADDR lets us bind anyway, but zombies
    // accept connections and never complete the handshake, causing timeouts.
    let zombies_killed = mrsh_server::zombie::kill_zombie_listeners(port);
    let stream_zombies = mrsh_server::zombie::kill_zombie_listeners(port + 1);
    if zombies_killed > 0 || stream_zombies > 0 {
        info!(
            "zombie cleanup: killed {} command + {} stream stale listener(s)",
            zombies_killed, stream_zombies
        );
    }

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
        let mut seen_key_data: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
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
                            tracing::info!("loaded {} key(s) from {}", added, ak_path.display());
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
                ak_paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
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

    // Clone for the FS-transport listener (runs alongside TCP when --fs-spool is set).
    let fs_tls_acceptor = tls_acceptor.clone();
    let fs_ctx = ctx.clone();
    let fs_cancel = cancel.clone();

    let config = listener::ServerConfig {
        command_port: port,
        tls_acceptor,
        ctx,
        ip_acl: load_ip_acl(&data_dir),
        #[cfg(feature = "quic")]
        tls_config: tls_config_for_quic,
    };

    // ── FS-transport listener (optional, runs in parallel with TCP) ──
    //
    // When `--fs-spool <DIR>` is provided (or FsSpool is set in config),
    // spawn `mrsh_server::fs_listener::run_fs_listener` on the same
    // cancellation token as the TCP path. Clients connect with
    // `-h fs:///<DIR>`; auth/TLS/session handling are identical.
    if let Some(ref spool) = fs_spool {
        let spool_dir = spool.clone();
        info!("fs-transport listener enabled on {}", spool_dir.display());
        tokio::spawn(async move {
            if let Err(e) = mrsh_server::fs_listener::run_fs_listener(
                spool_dir,
                fs_tls_acceptor,
                fs_ctx,
                fs_cancel,
            )
            .await
            {
                tracing::error!("fs-transport listener error: {:#}", e);
            }
        });
    }

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
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
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
                    cancel_disc,
                    disc_id,
                    disc_host,
                    disc_platform,
                    disc_port,
                )
                .await;
            });
        }

        if !rdv_servers.is_empty() && !device_id.is_empty() {
            let (relay_tx, mut relay_rx) =
                tokio::sync::mpsc::channel::<mrsh_relay::rendezvous::RelayNotification>(16);

            // Registration + relay notification listener.
            let cancel_reg = cancel.clone();
            let svc_port = port;
            let enrollment_token_for_crypto =
                user_config.enrollment_token.clone().unwrap_or_default();
            let reg_hostname = hostname.clone();
            let data_dir_for_reg = data_dir.clone();
            // rsh-5264.5: pre-resolve staged-rollout settings before the move
            // closure consumes user_config. The hostname is the local machine's
            // hostname; if user_config has a `Host <hostname>` block with
            // `AutoUpgrade`/`Track` set, those win over the global default.
            let reg_auto_upgrade = user_config.auto_upgrade_for(&hostname);
            let reg_track = user_config.track_for(&hostname);
            tokio::spawn(async move {
                // Build encrypted network info for LAN discovery
                let net_info_blob = if !enrollment_token_for_crypto.is_empty() {
                    let info = mrsh_relay::net_crypto::collect_network_info(
                        &reg_hostname,
                        svc_port,
                        crate::TRAY_PORT,
                    );
                    let (_, group_pub) =
                        mrsh_relay::net_crypto::derive_group_keypair(&enrollment_token_for_crypto);
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
                let mut reg_ports = vec![mrsh_relay::proto::PortInfo {
                    port: svc_port as u32,
                    instance_type: if _with_tray {
                        "tray".into()
                    } else {
                        "system".into()
                    },
                    caps: this_caps,
                }];
                // On Windows, both instances register — tray includes the other port too
                #[cfg(windows)]
                if _with_tray {
                    // Tray instance also reports service port (8822)
                    let mut sys_caps = build_server_caps_with_mode(false);
                    // system caps differ from tray caps
                    reg_ports.push(mrsh_relay::proto::PortInfo {
                        port: crate::DEFAULT_PORT as u32,
                        instance_type: "system".into(),
                        caps: std::mem::take(&mut sys_caps),
                    });
                }

                // rsh-5264.1: reconcile any in-flight self-update marker, then
                // load the persisted record. The reconcile turns the pending
                // marker → success on first start of the new binary.
                let upd = mrsh_server::update_status::reconcile_on_startup(&data_dir_for_reg);
                // rsh-5264.5: pre-resolved staged-rollout settings (closure
                // captures the values from outer scope before user_config is
                // moved). global default + per-host override already applied.
                let local_auto_upgrade = reg_auto_upgrade.unwrap_or(false);
                let local_track = reg_track.clone().unwrap_or_else(|| "stable".to_string());
                let client = mrsh_relay::rendezvous::Client {
                    servers: rdv_servers.clone(),
                    licence_key: rdv_key.clone(),
                    local_id: device_id.clone(),
                    group_hash: group_hash.clone(),
                    hostname: hostname.clone(),
                    platform: platform.clone(),
                    service_port: svc_port,
                    encrypted_net_info: net_info_blob.clone(),
                    // sys-8z5gn: keep the token + tray port so the registration
                    // loop can re-encrypt fresh net info on network change.
                    enrollment_token: enrollment_token_for_crypto.clone(),
                    tray_port: crate::TRAY_PORT,
                    ports: reg_ports.clone(),
                    // rsh-5264.1 heartbeat-feedback
                    current_version: env!("CARGO_PKG_VERSION").to_string(),
                    last_update_status: upd.status.clone(),
                    last_update_at_unix: upd.ts,
                    // rsh-5264.5 staged-rollout
                    track: local_track.clone(),
                    auto_upgrade: local_auto_upgrade,
                };

                // rsh-5264.4: if the watchdog is armed (set by selfupdate
                // before swap, preserved by reconcile_on_startup), spawn a
                // parallel probe task that uses `register_once` to observe
                // heartbeat outcomes independently of the long-lived UDP
                // keepalive. On N consecutive failures it triggers rollback.
                if upd.watchdog_active {
                    let probe_client = mrsh_relay::rendezvous::Client {
                        servers: rdv_servers.clone(),
                        licence_key: rdv_key.clone(),
                        local_id: device_id.clone(),
                        group_hash: group_hash.clone(),
                        hostname: hostname.clone(),
                        platform: platform.clone(),
                        service_port: svc_port,
                        encrypted_net_info: net_info_blob.clone(),
                        // sys-8z5gn
                        enrollment_token: enrollment_token_for_crypto.clone(),
                        tray_port: crate::TRAY_PORT,
                        ports: reg_ports.clone(),
                        current_version: env!("CARGO_PKG_VERSION").to_string(),
                        last_update_status: upd.status.clone(),
                        last_update_at_unix: upd.ts,
                        // rsh-5264.5 staged-rollout
                        track: local_track.clone(),
                        auto_upgrade: local_auto_upgrade,
                    };
                    let probe_data_dir = data_dir_for_reg.clone();
                    let probe_cancel = cancel_reg.clone();
                    tokio::spawn(async move {
                        run_watchdog_probe(probe_client, probe_data_dir, probe_cancel).await;
                    });
                }

                // rsh-5264.5: spawn the per-track auto-upgrade query loop in
                // parallel with the registration keepalive. This task polls
                // rdv every AUTO_UPGRADE_QUERY_INTERVAL for a newer version
                // matching our (platform, track) tuple. The actual self-update
                // SWAP is out of scope for this PR — we only log the would-
                // upgrade decision so the gate logic can be observed in the
                // field. Real swap is invoked separately (operator `mrsh
                // self-update` or future automation).
                {
                    let upgrade_client = mrsh_relay::rendezvous::Client {
                        servers: rdv_servers.clone(),
                        licence_key: rdv_key.clone(),
                        local_id: device_id.clone(),
                        group_hash: group_hash.clone(),
                        hostname: hostname.clone(),
                        platform: platform.clone(),
                        service_port: svc_port,
                        encrypted_net_info: net_info_blob.clone(),
                        // sys-8z5gn
                        enrollment_token: enrollment_token_for_crypto.clone(),
                        tray_port: crate::TRAY_PORT,
                        ports: reg_ports.clone(),
                        current_version: env!("CARGO_PKG_VERSION").to_string(),
                        last_update_status: upd.status.clone(),
                        last_update_at_unix: upd.ts,
                        track: local_track.clone(),
                        auto_upgrade: local_auto_upgrade,
                    };
                    let upgrade_cancel = cancel_reg.clone();
                    let upgrade_data_dir = data_dir_for_reg.clone();
                    let upgrade_track = local_track.clone();
                    let upgrade_platform = platform.clone();
                    tokio::spawn(async move {
                        run_auto_upgrade_query_loop(
                            upgrade_client,
                            local_auto_upgrade,
                            upgrade_track,
                            upgrade_platform,
                            upgrade_data_dir,
                            upgrade_cancel,
                        )
                        .await;
                    });
                }

                client.run_registration_loop(cancel_reg, relay_tx).await;
            });

            // Relay acceptance handler: receives notifications from hbbs and
            // connects to hbbr to complete the relay pairing.
            let cancel_relay = cancel.clone();
            let relay_key = user_config.rendezvous_key.clone().unwrap_or_default();
            if relay_key.is_empty() {
                tracing::warn!(
                    "relay key is EMPTY — relay auth will fail. Add RendezvousKey to config."
                );
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

/// Debug mode: listener only, no relay/rdv/discovery/tray.
/// Foreground, verbose logging, for diagnostics and recovery.
#[allow(dead_code)] // kept for API compat; callers now use *_with_fs_spool variant
pub async fn run_debug_mode(port: u16) -> Result<()> {
    run_debug_mode_with_fs_spool(port, fs_spool_from_config()).await
}

/// Debug mode with an explicit FS-transport spool dir (overrides config).
pub async fn run_debug_mode_with_fs_spool(
    port: u16,
    fs_spool: Option<std::path::PathBuf>,
) -> Result<()> {
    use mrsh_core::{auth, tls};
    use mrsh_server::{handler::ServerContext, listener, session};
    use tokio_rustls::TlsAcceptor;

    let data_dir = crate::server_data_dir();
    std::fs::create_dir_all(&data_dir)?;

    info!("debug server starting on port {}", port);

    let (certs, key) = tls::load_or_generate_cert(&data_dir)?;
    let tls_config = tls::server_config(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Load authorized keys from ALL locations
    let authorized_keys = {
        let mut all_keys: Vec<auth::AuthorizedKey> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for ak_path in &crate::all_authorized_keys_paths() {
            if ak_path.exists()
                && let Ok(keys) = auth::load_authorized_keys(ak_path, false) {
                    for key in keys {
                        if seen.insert(key.key_data.clone()) {
                            all_keys.push(key);
                        }
                    }
                    info!("loaded keys from {}", ak_path.display());
                }
        }
        info!("{} authorized key(s) total", all_keys.len());
        all_keys
    };

    let revoked_keys = {
        let rk_path = data_dir.join("revoked_keys");
        if rk_path.exists() {
            auth::load_revoked_keys(&rk_path)?
        } else {
            std::collections::HashSet::new()
        }
    };

    let cancel = tokio_util::sync::CancellationToken::new();

    let ctx = std::sync::Arc::new(ServerContext {
        authorized_keys,
        revoked_keys,
        server_version: format!("{}-debug", env!("CARGO_PKG_VERSION")),
        banner: Some("mrsh debug server".to_string()),
        caps: build_server_caps_with_mode(false),
        session_store: session::SessionStore::new(),
        rate_limiter: mrsh_server::ratelimit::AuthRateLimiter::new(),
        allowed_tunnels: vec![],
        totp_secrets: vec![],
        totp_recovery_path: None,
        server_key_path: Some(data_dir.join("server_key")),
        device_id: None,
        rendezvous_server: None,
        authorized_keys_paths: crate::all_authorized_keys_paths(),
    });

    // Clone for fs-transport listener before ctx/tls_acceptor are moved.
    let fs_tls_acceptor = tls_acceptor.clone();
    let fs_ctx = ctx.clone();
    let fs_cancel = cancel.clone();

    let config = listener::ServerConfig {
        command_port: port,
        tls_acceptor,
        ctx,
        ip_acl: load_ip_acl(&data_dir),
        #[cfg(feature = "quic")]
        tls_config: {
            let (certs2, key2) = tls::load_or_generate_cert(&data_dir)?;
            tls::server_config(certs2, key2)?
        },
    };

    // FS-transport listener (debug mode) — runs alongside TCP when `--fs-spool` set.
    if let Some(ref spool) = fs_spool {
        let spool_dir = spool.clone();
        info!("fs-transport listener enabled on {}", spool_dir.display());
        tokio::spawn(async move {
            if let Err(e) = mrsh_server::fs_listener::run_fs_listener(
                spool_dir,
                fs_tls_acceptor,
                fs_ctx,
                fs_cancel,
            )
            .await
            {
                tracing::error!("fs-transport listener error: {:#}", e);
            }
        });
    }

    // Ctrl+C handler
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("Ctrl+C received, shutting down debug server");
        cancel_clone.cancel();
    });

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

    info!(
        "relay accept: connected to hbbr (target_port={})",
        notif.target_port
    );

    // Route BEFORE TLS accept — proxy forwards raw TCP so the target port
    // (e.g. tray) handles its own TLS handshake with the client.
    //
    // target_port == 0:            tray-first — try tray, fallback to SYSTEM.
    // target_port == DEFAULT_PORT: explicit service — TLS accept here (SYSTEM).
    // target_port == other:        explicit port — proxy raw stream to that port.

    // Explicit non-default port (e.g. 9822 = tray) — proxy raw stream directly.
    if notif.target_port != 0 && notif.target_port != crate::DEFAULT_PORT {
        info!(
            "relay accept: proxying raw stream to explicit port {}",
            notif.target_port
        );
        let local_stream =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", notif.target_port))
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
        )
        .await
        {
            Ok(Ok(tray_stream)) => {
                info!(
                    "relay accept: tray available, routing to port {}",
                    crate::TRAY_PORT
                );
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
    host: &str,
    cmd: &str,
    args: &[String],
    shell_env_vars: &[String],
) -> Result<i32> {
    match cmd {
        "exec" => {
            if args.len() < 2 {
                bail!("exec requires a command");
            }
            // rsh-oom9: `exec --detach <cmd>` must behave identically over the SSH
            // fallback as over the mrsh-TLS path — strip the flag and run the shared
            // detached-runner wrapper instead of shipping `--detach` literally.
            let detach = args[1..].iter().any(|a| a == "--detach");
            let cmd_words: Vec<&str> = args[1..]
                .iter()
                .map(|s| s.as_str())
                .filter(|a| *a != "--detach")
                .collect();
            if cmd_words.is_empty() {
                bail!("exec requires a command");
            }
            let command = cmd_words.join(" ");
            if detach {
                let wrapper = mrsh_client::commands::build_detach_wrapper(&command);
                let (_code, output) = ssh.exec(&wrapper).await?;
                let dir = mrsh_client::commands::parse_detach_handle(&output)?;
                let token = mrsh_client::commands::detach_token(&dir);
                println!("mrsh-detach started  handle={token}  (dir: {dir})");
                println!("follow: mrsh -h {host} dlog {token}");
                Ok(0)
            } else {
                // rsh-1cp1: stream output live (was buffered-at-end — a connection
                // drop on a long-running command lost ALL output AND returned exit 0).
                let exit_code = ssh.exec_streamed(&command).await?;
                Ok(exit_code as i32)
            }
        }
        "dlog" => {
            // rsh-oom9: poll a detached job (companion to `exec --detach`) over SSH.
            let id = match args.get(1) {
                Some(s) => s.as_str(),
                None => bail!("dlog requires a detach id (the handle from `exec --detach`)"),
            };
            let q = mrsh_client::commands::build_dlog_query(id)?;
            let (code, output) = ssh.exec(&q).await?;
            print!("{output}");
            Ok(code as i32)
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
        "shell" => {
            let exit_code = ssh.shell(shell_env_vars).await?;
            Ok(exit_code as i32)
        }
        other => {
            bail!(
                "command '{}' not supported over SSH fallback (only exec, dlog, ping, push, pull, shell)",
                other
            );
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

/// rsh-5264.4: Watchdog probe that observes heartbeat outcomes after a
/// self-update. Runs in parallel with the long-lived UDP keepalive loop
/// (`run_registration_loop`) which doesn't surface per-attempt success.
///
/// Probes via `register_once` every 30s. On N=3 consecutive failures the
/// state machine in `update_status::record_heartbeat_outcome` returns
/// `WatchdogAction::RollbackTriggered` and the probe invokes
/// `watchdog::execute_rollback()` to restore the previous binary.
///
/// Exits when:
///   * watchdog state transitions to disarmed (success or rollback)
///   * `cancel` is fired (server shutdown)
///   * `MAX_WATCHDOG_DURATION` elapses (15min safety bound)
async fn run_watchdog_probe(
    client: mrsh_relay::rendezvous::Client,
    data_dir: std::path::PathBuf,
    cancel: tokio_util::sync::CancellationToken,
) {
    use mrsh_server::{update_status, watchdog};
    use std::time::Duration;

    // Probe every 30s. Acceptance: clear within first heartbeat (~30s),
    // rollback within 15min on faulty binary (3×30s = 90s lower bound).
    const PROBE_INTERVAL: Duration = Duration::from_secs(30);
    // Hard upper bound for the probe lifetime; if we got here and never
    // observed a definitive outcome, the operator probably already fixed
    // things manually.
    const MAX_WATCHDOG_DURATION: Duration = Duration::from_secs(15 * 60);

    let started_at = std::time::Instant::now();
    let mut interval = tokio::time::interval(PROBE_INTERVAL);
    // First tick fires immediately — desired (try heartbeat ASAP after
    // post-update startup). Subsequent ticks wait 30s.

    info!(
        "watchdog probe: armed (probe_interval={:?}, max_duration={:?})",
        PROBE_INTERVAL, MAX_WATCHDOG_DURATION
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("watchdog probe: cancelled");
                return;
            }
            _ = interval.tick() => {}
        }

        if started_at.elapsed() > MAX_WATCHDOG_DURATION {
            tracing::warn!(
                "watchdog probe: exceeded max duration {:?}, giving up",
                MAX_WATCHDOG_DURATION
            );
            return;
        }

        // If watchdog has been disarmed by a concurrent path (e.g. the
        // operator manually edited last_update.json), exit cleanly.
        let current = update_status::read(&data_dir);
        if !current.watchdog_active {
            info!("watchdog probe: state disarmed externally — exiting");
            return;
        }

        // Probe heartbeat. Bound the total time so a deeply broken network
        // path doesn't stall the probe loop.
        let success = match tokio::time::timeout(
            Duration::from_secs(15),
            client.register_once(),
        )
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::warn!("watchdog probe: register_once failed: {}", e);
                false
            }
            Err(_) => {
                tracing::warn!("watchdog probe: register_once timed out");
                false
            }
        };

        match update_status::record_heartbeat_outcome(&data_dir, success) {
            update_status::WatchdogAction::Continue => continue,
            update_status::WatchdogAction::ClearWatchdog => {
                info!(
                    "watchdog probe: first successful heartbeat → cleared (binary healthy)"
                );
                return;
            }
            update_status::WatchdogAction::RollbackTriggered => {
                tracing::error!(
                    "watchdog probe: 3 consecutive heartbeat failures → executing rollback"
                );
                if let Err(e) = watchdog::execute_rollback() {
                    tracing::error!("watchdog probe: rollback failed: {}", e);
                }
                return;
            }
        }
    }
}

/// rsh-5264.5: rdv-driven auto-upgrade query loop.
///
/// Polls rdv every [`AUTO_UPGRADE_QUERY_INTERVAL`] for a newer version on the
/// configured (platform, track) tuple. When an update is available AND the
/// host is opted-in (`auto_upgrade=true`) AND the watchdog is clear, logs the
/// would-upgrade decision and applies a randomized jitter delay (0..[`AUTO_UPGRADE_JITTER_SECS`])
/// before what *would* be the swap.
///
/// The actual self-update swap call is OUT OF SCOPE for this PR (rsh-5264.5
/// is the gate-logic + visibility phase). Real automation happens via the
/// operator's `mrsh self-update` invocation or a future glue task.
///
/// Loop exits when `cancel` fires.
#[allow(clippy::too_many_arguments)]
async fn run_auto_upgrade_query_loop(
    client: mrsh_relay::rendezvous::Client,
    auto_upgrade: bool,
    track: String,
    platform: String,
    data_dir: std::path::PathBuf,
    cancel: tokio_util::sync::CancellationToken,
) {
    use mrsh_server::update_status;
    use std::time::Duration;

    /// Initial delay before the first query — gives registration time to
    /// settle so the first heartbeat reaches rdv before we ask for an advert.
    const STARTUP_DELAY: Duration = Duration::from_secs(60);
    /// Cadence between version queries against rdv.
    const AUTO_UPGRADE_QUERY_INTERVAL: Duration = Duration::from_secs(15 * 60);
    /// Maximum jitter applied before a would-upgrade swap. 5 minutes spreads
    /// concurrent fleet upgrades across a window so rdv + binary distribution
    /// don't see a thundering herd.
    const AUTO_UPGRADE_JITTER_SECS: u64 = 300;

    // The current_version is read from the static client we were built with;
    // recompute the canonical platform string for the query (the one in
    // RegisterPeer is the OS family — `windows` / `linux` — but rdv stores
    // adverts keyed by build platform: `windows-msvc`, `linux-glibc`, etc).
    let query_platform = canonical_build_platform(&platform);
    let current_version = env!("CARGO_PKG_VERSION").to_string();

    info!(
        "auto-upgrade loop: track={} platform={} current={} auto_upgrade={} \
         query_interval={:?} jitter_max={}s",
        track,
        query_platform,
        current_version,
        auto_upgrade,
        AUTO_UPGRADE_QUERY_INTERVAL,
        AUTO_UPGRADE_JITTER_SECS
    );

    // Initial delay before first query.
    tokio::select! {
        _ = cancel.cancelled() => return,
        _ = tokio::time::sleep(STARTUP_DELAY) => {}
    }

    let mut interval = tokio::time::interval(AUTO_UPGRADE_QUERY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("auto-upgrade loop: cancelled");
                return;
            }
            _ = interval.tick() => {}
        }

        // Query rdv for the latest version on (platform, track).
        let advert = match tokio::time::timeout(
            Duration::from_secs(15),
            client.query_version(&query_platform, &track, &current_version),
        )
        .await
        {
            Ok(Ok(advert)) => advert,
            Ok(Err(e)) => {
                tracing::debug!("auto-upgrade loop: query_version failed: {}", e);
                continue;
            }
            Err(_) => {
                tracing::debug!("auto-upgrade loop: query_version timed out");
                continue;
            }
        };

        let Some(advert) = advert else {
            tracing::debug!(
                "auto-upgrade loop: no update for {}|{} (current {})",
                query_platform,
                track,
                current_version
            );
            continue;
        };

        // We have a newer version. Apply the gate logic.
        let upd = update_status::read(&data_dir);
        let watchdog_clear = !upd.watchdog_active;

        if !auto_upgrade {
            info!(
                "auto-upgrade loop: would-upgrade SKIPPED (auto_upgrade=false) \
                 — track={} latest={} current={} (host not opted in)",
                track, advert.latest_version, current_version
            );
            continue;
        }

        if !watchdog_clear {
            tracing::warn!(
                "auto-upgrade loop: would-upgrade SKIPPED (watchdog armed) \
                 — track={} latest={} current={}",
                track,
                advert.latest_version,
                current_version
            );
            continue;
        }

        // rsh-994l: both gates pass — log, apply jitter, then perform the
        // autonomous fetch+verify+swap. This is the real automation the
        // rsh-5264.5 gate-logic phase deferred ("would-upgrade APPROVED" used
        // to log-and-sleep only).
        let jitter_secs = jitter_seconds(AUTO_UPGRADE_JITTER_SECS);
        info!(
            "auto-upgrade loop: would-upgrade APPROVED — track={} latest={} \
             current={} jitter={}s (out of 0..{}) — fetch+verify+swap after jitter",
            track,
            advert.latest_version,
            current_version,
            jitter_secs,
            AUTO_UPGRADE_JITTER_SECS
        );

        // Jitter spreads concurrent fleet upgrades across a window so rdv +
        // binary distribution don't see a thundering herd.
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(jitter_secs)) => {}
        }

        // rsh-994l: re-read the watchdog gate after the jitter sleep. A
        // concurrent operator update (or a prior loop iteration) may have armed
        // it during the jitter window; if so, abort this swap and re-evaluate
        // next query interval.
        if update_status::read(&data_dir).watchdog_active {
            tracing::warn!(
                "auto-upgrade loop: swap ABORTED post-jitter (watchdog armed during jitter) \
                 — track={} latest={}",
                track,
                advert.latest_version
            );
            continue;
        }

        // rsh-994l: autonomous secure swap. insecure_no_verify is ALWAYS false
        // here — a host that cannot verify the signature (empty-pubkey build)
        // MUST NOT auto-swap; it fails verification and stays on the current
        // binary until migrated (rsh-sey2). Reuses the operator self-update
        // fetch+verify+atomic-swap path (rsh-q2az atomic swap).
        info!(
            "auto-upgrade loop: starting autonomous fetch+verify+swap — track={} target={}",
            track,
            advert.latest_version
        );
        let resp = mrsh_server::selfupdate::fetch_verify_and_swap(
            &client,
            &query_platform,
            &track,
            &advert.latest_version,
            false,
        )
        .await;
        if resp.success {
            info!(
                "auto-upgrade loop: autonomous swap scheduled — track={} target={} \
                 (service will restart; watchdog armed for auto-rollback)",
                track,
                advert.latest_version
            );
            // The swap helper is about to stop/replace/restart this process.
            // Stop querying mid-swap; the restarted (new) binary spawns a fresh
            // loop on startup.
            return;
        }
        tracing::warn!(
            "auto-upgrade loop: autonomous swap FAILED — track={} target={}: {} \
             (staying on current binary; will retry next query interval)",
            track,
            advert.latest_version,
            resp.error.as_deref().unwrap_or("unknown error")
        );
    }
}

/// rsh-5264.5: map the OS family (as used in `RegisterPeer.platform`) to the
/// canonical build-platform string used by rdv `VersionAdvert`.
///
/// On Windows the canonical build platform is `windows-msvc`. On Linux we
/// distinguish `linux-musl` from `linux-glibc` — best-effort by inspecting
/// the running binary's interpreter (statically-linked musl builds report
/// `linux-musl`, glibc builds report `linux-glibc`). On macOS: `macos`.
///
/// Falls back to the os_family value verbatim when classification fails so
/// callers can still match on partial keys during rollout.
fn canonical_build_platform(os_family: &str) -> String {
    let os = os_family.to_ascii_lowercase();
    if os == "windows" {
        return "windows-msvc".to_string();
    }
    if os == "macos" {
        return "macos".to_string();
    }
    if os == "linux" {
        // Best-effort musl detection: the musl ld interpreter has "musl" in
        // its name. We inspect the kernel version vDSO marker as a proxy
        // through the env var the build sets when running on musl.
        // For the 5264.5 gate-only milestone we use a compile-time hint via
        // the target_env cfg. Runtime detection is added in the swap phase.
        #[cfg(target_env = "musl")]
        {
            return "linux-musl".to_string();
        }
        #[cfg(not(target_env = "musl"))]
        {
            return "linux-glibc".to_string();
        }
    }
    os
}

/// rsh-5264.5: pick a jitter value in `0..max_secs` (inclusive lower, exclusive
/// upper). Uses the OS RNG to avoid synchronized fleets when many hosts boot
/// simultaneously.
fn jitter_seconds(max_secs: u64) -> u64 {
    if max_secs == 0 {
        return 0;
    }
    use rand::Rng;
    rand::thread_rng().gen_range(0..max_secs)
}
