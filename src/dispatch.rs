//! Async dispatch entry point.
//!
//! `async_main` is the single async entry called by `main()` once the tokio
//! runtime is built. It handles arg normalization, the local subcommand
//! family (no-host needed), then host resolution / mux / connect / SSH
//! fallback / relay, and finally hands off to `dispatch_client::run_command`
//! (or `dispatch_quic::run` when `--quic` is set) for the actual remote
//! command execution.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mrsh_client::client::{AnyClient, ConnectOptions, Target, parse_target};
use tracing::info;

use crate::cli::{Cli, DEFAULT_PORT, LOCAL_COMMANDS, TRAY_PORT, compute_timeout_secs, unmangle_msys_remote};
use crate::lan_detect::{LanFirst, LanProbeResult, probe_lan};
use crate::ssh_fallback::run_ssh_fallback;
use crate::{fleet_cmd, help, keygen, local_cmds, rdv_publish, release_cmd, server_mode};

pub(crate) async fn async_main(mut cli: Cli) -> Result<()> {
    // Normalize path arguments (Git Bash /c/Users → C:/Users, WSL /mnt/c → C:/, etc.)
    // Only normalize args that look like paths — skip command name (args[0])
    // and content arguments (exec command text, write content).
    let cmd_peek = cli.args.first().map(|s| s.as_str()).unwrap_or("");
    let args_normalized: Vec<String> = cli
        .args
        .iter()
        .enumerate()
        .map(|(i, a)| {
            if i == 0 {
                // Command name — never normalize
                a.clone()
            } else if cmd_peek == "exec" || (cmd_peek == "write" && i >= 2) {
                // exec: arg is PowerShell command text — don't normalize
                // write: args[2+] is content — don't normalize
                a.clone()
            } else if (cmd_peek == "push" && i == 2)
                || (cmd_peek == "pull" && i == 1)
                || (cmd_peek == "sync-dir" && i == 2)
            {
                // Remote path: push <local> <REMOTE>, pull <REMOTE> <local>,
                // sync-dir <local> <REMOTE> — don't normalize remote paths.
                // MSYS may have already converted /home/user → C:/.../home/user
                // before we see it. Detect and silently auto-fix (use RUST_LOG=debug
                // to see the conversion). Hint user about MSYS_NO_PATHCONV=1 in help.
                if let Some(fixed) = unmangle_msys_remote(a) {
                    tracing::debug!("auto-fixed MSYS path: '{}' → '{}'", a, fixed);
                    fixed
                } else {
                    a.clone()
                }
            } else {
                mrsh_core::path::normalize(a)
            }
        })
        .collect();
    let args = &args_normalized;
    // Default: "version" without -h, "shell" with -h
    let cmd = args
        .first()
        .map(|s| s.as_str())
        .unwrap_or(if cli.host.is_some() {
            "shell"
        } else {
            "version"
        });

    // Help (--help flag or "help" subcommand)
    if cli.help || cmd == "help" {
        help::print_usage();
        return Ok(());
    }

    // ── Local commands (no -h needed) ────────────────────────
    match cmd {
        "version" => {
            let version = env!("CARGO_PKG_VERSION");
            let suffix = option_env!("MRSH_VERSION_SUFFIX").unwrap_or("");
            if suffix.is_empty() {
                println!("mrsh {}", version);
            } else {
                println!("mrsh {}-{}", version, suffix);
            }
            return Ok(());
        }
        "fleet" => {
            return fleet_cmd::run_fleet(&args[1..]).await;
        }
        "discover" => {
            let timeout_secs: u64 = args
                .get(1)
                .and_then(|s| s.strip_prefix("--timeout=").or(Some(s.as_str())))
                .and_then(|s| s.parse().ok())
                .unwrap_or(3);
            let config = mrsh_core::config::Config::load();
            let local_id = config.device_id.clone().unwrap_or_default();
            eprintln!("Scanning LAN for mrsh peers ({timeout_secs}s)...");
            let peers = mrsh_relay::discovery::discover_lan(
                mrsh_relay::discovery::DISCOVERY_PORT,
                std::time::Duration::from_secs(timeout_secs),
                &local_id,
            )
            .await;
            if peers.is_empty() {
                println!("No peers found.");
            } else {
                println!(
                    "{:<20} {:<16} {:<10} {:<6}",
                    "HOSTNAME", "IP", "PLATFORM", "PORT"
                );
                println!("{}", "-".repeat(54));
                for p in &peers {
                    let port = if p.service_port > 0 {
                        p.service_port.to_string()
                    } else {
                        "-".to_string()
                    };
                    println!(
                        "{:<20} {:<16} {:<10} {:<6}",
                        p.hostname,
                        p.addr.ip(),
                        p.platform,
                        port
                    );
                }
                println!("\nFound {} peer(s)", peers.len());
            }
            return Ok(());
        }
        "nat" => {
            eprintln!("Detecting NAT type (querying STUN servers)...");
            let info = mrsh_relay::stun::detect_nat_type(std::time::Duration::from_secs(3)).await;
            println!("NAT type: {}", info.nat_type);
            if let Some(addr) = info.external_addr {
                println!("External address: {}", addr);
            }
            return Ok(());
        }
        "wake" => {
            if args.len() < 2 {
                bail!("wake requires a host name or MAC address (aa:bb:cc:dd:ee:ff)");
            }
            let arg = &args[1];
            // If arg is a MAC literal, use it directly. Otherwise treat as
            // a host name and look up MacAddress in config. See mac_form.rs.
            let looks_like_mac = crate::mac_form::is_mac_form(arg);
            let (mac, resolved_from) = if looks_like_mac {
                (arg.clone(), None)
            } else {
                let config = mrsh_core::config::Config::load();
                match config.find_host(arg).and_then(|h| h.mac.clone()) {
                    Some(m) => (m, Some(arg.clone())),
                    None => bail!(
                        "no MacAddress configured for host '{}' in ~/.mrsh/config — \
                         add 'MacAddress aa:bb:cc:dd:ee:ff' to the Host block, \
                         or pass a MAC directly",
                        arg
                    ),
                }
            };
            mrsh_client::shell::send_wol(&mac)?;
            match resolved_from {
                Some(host) => println!("WoL packet sent to {host} ({mac})"),
                None => println!("WoL packet sent to {mac}"),
            }
            return Ok(());
        }
        "recording" => {
            let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if sub == "export" {
                // Local-only: convert .log+.time to asciicast
                let rest = &args[2..];
                let mut width: u32 = 120;
                let mut height: u32 = 35;
                let mut log_file = String::new();
                let mut out_file = String::new();
                for a in rest {
                    if let Some(w) = a.strip_prefix("--width=") {
                        width = w.parse().unwrap_or(120);
                    } else if let Some(h) = a.strip_prefix("--height=") {
                        height = h.parse().unwrap_or(35);
                    } else if log_file.is_empty() {
                        log_file = a.clone();
                    } else {
                        out_file = a.clone();
                    }
                }
                if log_file.is_empty() {
                    bail!("Usage: mrsh recording export <file.log> [output.cast]");
                }
                if out_file.is_empty() {
                    out_file = log_file
                        .strip_suffix(".log")
                        .unwrap_or(&log_file)
                        .to_string()
                        + ".cast";
                }
                mrsh_client::recording::export_asciicast(&log_file, &out_file, width, height)?;
                println!("Exported to {}", out_file);
                return Ok(());
            }
            // "list" with no -h → fall through to client section
            if cli.host.is_none() && sub != "list" {
                bail!("Usage: mrsh recording <export|list>");
            }
            // list with -h falls through to client commands
        }
        "keygen" => {
            let output = args.get(1).map(std::path::PathBuf::from);
            return keygen::run_keygen(output.as_deref());
        }
        "keys" => {
            return keygen::run_keys(&args[1..]);
        }
        "totp-setup" => {
            let fingerprint = args.get(1).map(|s| s.as_str());
            return keygen::run_totp_setup(fingerprint);
        }
        "totp-verify" => {
            if args.len() < 3 {
                bail!("Usage: mrsh totp-verify <fingerprint> <code>");
            }
            return keygen::run_totp_verify(&args[1], &args[2]);
        }
        "cfg" | "config-edit" => {
            mrsh_client::config_tui::run_config_tui()?;
            return Ok(());
        }
        "connect" => match mrsh_client::host_picker::run_host_picker()? {
            mrsh_client::host_picker::PickerResult::Selected(host) => {
                let target = host.hostname.as_deref().unwrap_or(&host.pattern);
                let port = if host.port > 0 { host.port } else { 8822 };
                eprintln!("Connecting to {} ({}:{})...", host.pattern, target, port);
                let opts = ConnectOptions {
                    host: target.to_string(),
                    port,
                    key_path: host.identity_file.clone(),
                    password_user: cli.user.clone(),
                };
                let mut client = mrsh_client::client::connect(&opts).await?;
                let env_vars: Vec<String> = cli
                    .shell
                    .as_ref()
                    .map(|s| vec![format!("MRSH_SHELL={}", s)])
                    .unwrap_or_default();
                mrsh_client::shell::run_shell(&mut client, &env_vars).await?;
                return Ok(());
            }
            mrsh_client::host_picker::PickerResult::Cancelled => {
                return Ok(());
            }
        },
        "log" => {
            return local_cmds::run_log_query(&args[1..]);
        }
        "logs" => {
            mrsh_client::log_viewer::run_log_viewer()?;
            return Ok(());
        }
        "dash" | "dashboard" => {
            mrsh_client::dashboard::run_dashboard().await?;
            return Ok(());
        }
        "pack" | "install-pack" => {
            return local_cmds::run_install_pack(&args[1..]);
        }
        "relay" => {
            return fleet_cmd::run_relay_server(&args[1..]).await;
        }
        "rdv" | "rendezvous" => {
            // rsh-5264.3: `mrsh rdv publish <binary> --platform <p> --track <t> --version <v>`
            // is an OPERATOR command (sends a UDP `PublishVersionRequest` to the configured
            // rendezvous server). Any other first-token (or no token) keeps the legacy
            // behaviour of running the rendezvous server itself.
            if args.get(1).map(|s| s.as_str()) == Some("publish") {
                return rdv_publish::run_publish(&args[2..]).await;
            }
            if args.get(1).map(|s| s.as_str()) == Some("query") {
                return rdv_publish::run_query(&args[2..]).await;
            }
            return fleet_cmd::run_rendezvous_server(&args[1..]).await;
        }
        "release" => {
            return release_cmd::run(&args[1..]);
        }
        _ => {}
    }

    // ── --mux-stop: stop running master ─────────────────────
    if cli.mux_stop {
        let host = cli.host.as_deref().unwrap_or_else(|| {
            eprintln!("error: -h <host> required for --mux-stop");
            std::process::exit(1);
        });
        return mrsh_client::mux::stop_master(host, cli.port.unwrap_or(DEFAULT_PORT)).await;
    }

    // ── Server mode: no -h, no local command ────────────────
    if cli.host.is_none() && !LOCAL_COMMANDS.contains(&cmd) {
        let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
        #[cfg(target_os = "windows")]
        {
            // Windows: default to tray server mode (user session, port 9822)
            info!("no -h flag, launching tray server mode");
            return server_mode::run_server_mode_with_fs_spool(TRAY_PORT, true, spool).await;
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Linux: default to foreground server mode (port 8822)
            let _ = TRAY_PORT;
            info!("no -h flag, launching server mode");
            return server_mode::run_server_mode_with_fs_spool(DEFAULT_PORT, false, spool).await;
        }
    }

    // ── Client commands (require -h) ─────────────────────────
    let host_raw = cli.host.as_deref().unwrap_or_else(|| {
        eprintln!("error: -h <host> required");
        std::process::exit(1);
    });

    // Parse user@host syntax — like ssh. If -u is also given, CLI flag wins.
    let (host, user_from_host): (&str, Option<String>) = if let Some(at_pos) = host_raw.find('@') {
        let user = &host_raw[..at_pos];
        let rest = &host_raw[at_pos + 1..];
        (rest, Some(user.to_string()))
    } else {
        (host_raw, None)
    };
    // Merge: -u flag takes precedence over user@host syntax
    if cli.user.is_none() {
        cli.user = user_from_host;
    }

    // Resolve from config
    let config = mrsh_core::config::Config::load();
    let host_config = config.find_host(host);
    let port_explicit = cli.port.is_some(); // user passed -p explicitly
    let (mut resolved_host, mut resolved_port, port_from_config) = if let Some(hc) = host_config {
        let cfg_port = hc.port;
        (
            hc.hostname.as_deref().unwrap_or(host).to_string(),
            cli.port.unwrap_or(cfg_port),
            cli.port.is_none() && cfg_port != 8822, // config specified non-default port
        )
    } else {
        (host.to_string(), cli.port.unwrap_or(DEFAULT_PORT), false)
    };
    // Auto-try ports when neither -p nor config specified a port
    let auto_try_ports = !port_explicit && !port_from_config;

    // rsh-le15: -i flag wins, else the resolved Host block's IdentityFile (the
    // TLS/relay path here previously ignored config IdentityFile).
    let effective_key = config.resolve_identity_file(host, &cli.key);

    // ── Auto-mux: try UDS before opening new connection ──────
    if !cli.no_mux
        && !cli.master
        && let Some(mux_req) = mrsh_client::mux::build_mux_request(cmd, args)
        && let Some(resp) = mrsh_client::mux::try_request(host, resolved_port, &mux_req).await
    {
        if resp.success {
            if let Some(ref output) = resp.output {
                print!("{}", output);
            }
        } else {
            let msg = resp.error.as_deref().unwrap_or("unknown error");
            eprintln!("error: {}", msg);
            std::process::exit(1);
        }
        return Ok(());
    }
    // No master running → fall through to normal connect

    // Check for DeviceID — from config or raw host
    let device_id = host_config.and_then(|hc| hc.device_id.clone()).or_else(|| {
        if mrsh_relay::rendezvous::is_device_id(host) {
            Some(host.to_string())
        } else {
            None
        }
    });

    // ── QUIC transport (experimental, --quic flag) ───────────
    #[cfg(feature = "quic")]
    if cli.use_quic {
        return crate::dispatch_quic::run(
            &cli,
            args,
            cmd,
            &resolved_host,
            resolved_port,
        )
        .await;
    }

    // ── fs:// transport: short-circuit relay/SSH/DeviceID logic ──
    //
    // When `-h fs:///path/to/spool` is given we connect through a shared
    // filesystem instead of TCP. The relay/rendezvous/SSH-fallback paths
    // below do not apply (no port, no DeviceID, no hbbs). Parsing is done
    // via `parse_target`; the spool path's last component seeds TOFU.
    let fs_target = matches!(parse_target(host), Target::Fs(_));

    // Determine if host was specified as a bare DeviceID (numeric-only).
    // If so, relay is the ONLY path. If host is IP/hostname with DeviceID
    // from config, try direct first with relay as fallback.
    let host_is_device_id = !fs_target && mrsh_relay::rendezvous::is_device_id(host);

    // ── LAN-first probe (rsh-x9l5) ──────────────────────────────
    //
    // When no explicit Hostname is set in the config (the resolved host is
    // the raw alias), try to reach `<host>.local` via mDNS before falling
    // back to the rendezvous relay.  This avoids the ~5 s rdv round-trip
    // when the target is on the same LAN.
    //
    // Skip when:
    //   - The host config has an explicit Hostname directive (direct already works)
    //   - LanFirst=no in the host config (user opted out)
    //   - Bare DeviceID (relay is the only option anyway)
    //   - fs:// transport (no TCP involved)
    let lan_first_policy = host_config
        .map(|hc| hc.lan_first)
        .unwrap_or(LanFirst::Auto);
    let has_explicit_hostname = host_config
        .and_then(|hc| hc.hostname.as_deref())
        .is_some();

    if !fs_target && !host_is_device_id && !has_explicit_hostname {
        match lan_first_policy {
            LanFirst::No => {
                // Opted out — skip probe entirely.
                tracing::debug!("lan-detect: LanFirst=no for {}, skipping probe", host);
            }
            LanFirst::Auto | LanFirst::Yes => {
                match probe_lan(host, resolved_port).await {
                    LanProbeResult::Reachable { resolved_ip } => {
                        info!(
                            "lan-detect: using direct LAN path for {} via {}",
                            host, resolved_ip
                        );
                        resolved_host = resolved_ip;
                    }
                    LanProbeResult::Unreachable { reason } => {
                        if lan_first_policy == LanFirst::Yes {
                            anyhow::bail!(
                                "LanFirst=yes for '{}' but LAN probe failed: {}",
                                host,
                                reason
                            );
                        }
                        // Auto: silently fall through to rdv.
                        tracing::debug!(
                            "lan-detect: LAN probe for {} failed ({}), falling back to rdv",
                            host,
                            reason
                        );
                    }
                }
            }
        }
    }

    // Helper: build relay options from config + device_id
    #[cfg(not(feature = "no-relay"))]
    let make_relay_opts =
        |dev_id: &str, port: u16| mrsh_client::relay_connect::RelayConnectOptions {
            device_id: dev_id.to_string(),
            rendezvous_server: config
                .rendezvous_server
                .as_deref()
                .unwrap_or("localhost:21116")
                .to_string(),
            rendezvous_key: config.rendezvous_key.clone().unwrap_or_default(),
            key_path: effective_key.clone(),
            server_name: resolved_host.clone(),
            port,
            target_port: if auto_try_ports { 0 } else { port },
            force_relay: false,
            enrollment_token: config.enrollment_token.clone().unwrap_or_default(),
            // sys-1qgww: pass own DeviceID so connect_via_relay can short-circuit
            // self-loops (target == self) to 127.0.0.1 instead of going via relay.
            own_device_id: config.device_id.clone(),
        };

    // ── rsh-zan0: SSH-first when -u is given non-interactively ─────────
    //
    // `-u <user>` intends an SSH-style identity ("run as <user>"). The native
    // transport can only honor it via password auth, which needs a TTY or a
    // piped password — in agent/CI/cron contexts (stdin = silent pipe) the old
    // code blocked forever reading stdin. Honor the identity directly: try SSH
    // (port 22, key auth, as <user>) BEFORE the native chain. On failure fall
    // through — the native chain now uses a BOUNDED password read (client.rs)
    // and key-auth fallback, so it can no longer hang.
    // Skipped when the user pinned a port (-p / config) — respect their choice.
    {
        use std::io::IsTerminal;
        if cli.user.is_some()
            && !fs_target
            && !host_is_device_id
            && auto_try_ports
            && !std::io::stdin().is_terminal()
            && mrsh_client::ssh_client::ssh_client_available()
        {
            tracing::debug!(
                "-u {:?} with non-interactive stdin: trying SSH-first on {}:22",
                cli.user,
                resolved_host
            );
            match run_ssh_fallback(
                &resolved_host,
                22,
                &cli.key,
                cli.user.as_deref(),
                cli.shell.as_deref(),
                cmd,
                args,
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!("SSH-first with -u failed ({e}); continuing native chain");
                }
            }
        }
    }

    let mut client: AnyClient = if fs_target {
        // fs:// URI — dispatch through connect_any (filesystem transport).
        // No port/DeviceID/SSH-fallback apply; spool path comes from the URI.
        let fs_opts = ConnectOptions {
            host: host.to_string(),
            port: resolved_port,
            key_path: effective_key.clone(),
            password_user: cli.user.clone(),
        };
        mrsh_client::client::connect_any(&fs_opts)
            .await
            .context("fs:// connect")?
    } else if host_is_device_id {
        // Bare DeviceID: relay is the only path
        #[cfg(feature = "no-relay")]
        bail!("relay connections disabled in this build");
        #[cfg(not(feature = "no-relay"))]
        {
            let dev_id = device_id.as_ref().unwrap();
            mrsh_client::relay_connect::connect_via_relay(&make_relay_opts(dev_id, resolved_port))
                .await?
                .erase_stream()
        }
    } else {
        // IP/hostname: try direct first
        let direct_opts = ConnectOptions {
            host: resolved_host.clone(),
            port: resolved_port,
            key_path: effective_key.clone(),
            password_user: cli.user.clone(),
        };
        let direct_result = if auto_try_ports {
            mrsh_client::client::connect_auto_try(&direct_opts)
                .await
                .map(|(c, p)| {
                    resolved_port = p;
                    c
                })
        } else {
            mrsh_client::client::connect(&direct_opts).await
        };

        match direct_result {
            Ok(client) => client.erase_stream(),
            Err(direct_err) => {
                // When -p is explicit, respect the user's port choice:
                // - NEVER fall back to SSH on port 22 (different port)
                // - Relay is OK because it uses the same target_port
                if port_explicit {
                    #[cfg(not(feature = "no-relay"))]
                    if let Some(ref dev_id) = device_id {
                        tracing::debug!(
                            "direct port {} failed, trying relay via {}",
                            resolved_port,
                            dev_id
                        );
                        match mrsh_client::relay_connect::connect_via_relay(&make_relay_opts(
                            dev_id,
                            resolved_port,
                        ))
                        .await
                        {
                            Ok(client) => {
                                eprintln!("connected via relay (direct failed)");
                                client.erase_stream()
                            }
                            Err(_) => {
                                return Err(direct_err.context(format!(
                                    "explicit port {} failed, relay also failed",
                                    resolved_port
                                )));
                            }
                        }
                    } else {
                        return Err(direct_err.context(format!(
                            "explicit port {} failed, no relay available",
                            resolved_port
                        )));
                    }
                    #[cfg(feature = "no-relay")]
                    return Err(
                        direct_err.context(format!("explicit port {} failed", resolved_port))
                    );
                } else {
                    // Auto-try mode: direct failed, try relay then SSH fallback
                    #[cfg(not(feature = "no-relay"))]
                    if let Some(ref dev_id) = device_id {
                        tracing::debug!("direct failed, trying relay via {}", dev_id);
                        match mrsh_client::relay_connect::connect_via_relay(&make_relay_opts(
                            dev_id,
                            resolved_port,
                        ))
                        .await
                        {
                            Ok(client) => {
                                eprintln!("connected via relay (direct failed)");
                                client.erase_stream()
                            }
                            Err(_) => {
                                // Relay also failed — try SSH fallback on port 22
                                if mrsh_client::ssh_client::ssh_client_available() {
                                    tracing::debug!("relay failed, trying SSH on port 22");
                                    return run_ssh_fallback(
                                        &resolved_host,
                                        22,
                                        &cli.key,
                                        cli.user.as_deref(),
                                        cli.shell.as_deref(),
                                        cmd,
                                        args,
                                    )
                                    .await;
                                }
                                return Err(direct_err);
                            }
                        }
                    } else {
                        // No relay — try SSH fallback on port 22
                        if mrsh_client::ssh_client::ssh_client_available() {
                            tracing::debug!("direct TLS failed, trying SSH on port 22");
                            return run_ssh_fallback(
                                &resolved_host,
                                22,
                                &cli.key,
                                cli.user.as_deref(),
                                cli.shell.as_deref(),
                                cmd,
                                args,
                            )
                            .await;
                        }
                        return Err(direct_err);
                    }
                }
            }
        }
    };

    // ── Save server's DeviceID + rendezvous to client config ───
    //
    // rsh-uu3y: skip save when the server-reported rendezvous is `localhost:21116`.
    // That is the local rdv address inside a tray (port 9822) running on a user
    // session. Saving it as the client's RendezvousServer for this alias points
    // future relay resolves at the wrong rdv, and the tray's DeviceID (different
    // from the service's) overwrites the correct config value. Net effect:
    // every subsequent `mrsh -h <alias>` via auto-try corrupts the config and
    // breaks relay-via-DeviceID for the service.
    let reported_rdv_is_localhost = client
        .server_rendezvous
        .as_deref()
        .is_some_and(|s| s.starts_with("localhost:") || s.starts_with("127.0.0.1:"));
    if (client.server_device_id.is_some() || client.server_rendezvous.is_some())
        && !reported_rdv_is_localhost
    {
        let mut cfg = mrsh_core::config::Config::load();
        if cfg.update_host_relay_info(
            host,
            client.server_device_id.as_deref(),
            client.server_rendezvous.as_deref(),
        ) {
            if let Err(e) = cfg.save() {
                tracing::debug!("failed to save relay info to config: {}", e);
            } else {
                tracing::debug!(
                    "saved relay info for {}: device_id={:?}, rdv={:?}",
                    host,
                    client.server_device_id,
                    client.server_rendezvous
                );
            }
        }
    } else if reported_rdv_is_localhost {
        tracing::debug!(
            "skipping relay info save: server reported rdv={:?} (likely tray rdv, would corrupt config)",
            client.server_rendezvous
        );
    }

    // ── Show server instance info ──────────────────────────────
    // Always show for interactive commands; with -v for others.
    let is_interactive_cmd = matches!(
        cmd,
        "shell" | "attach" | "browse" | "sftp" | "connect" | "dash" | "logs"
    );
    if cli.verbose > 0 || is_interactive_cmd {
        eprintln!("{}", client.describe_instance(resolved_port));
    }

    // rsh-j7yf: HARD BLOCK desktop-dependent commands on SYSTEM service.
    // Previously we emitted a soft warning and let the call proceed — but the
    // server-side guard either bails with a long error the agent doesn't read,
    // or (for `ss` which falls through to exec) returns a PowerShell
    // CommandNotFoundException that looks like a missing tool. Either way the
    // agent gets a black or empty screenshot. Refuse the request outright with
    // a clear hint pointing at the tray.
    //
    // Bypass: `MRSH_SYSTEM_FORCE=1` for operators who knowingly want the
    // service-context behavior (e.g. testing the server-side guard itself).
    if client.is_system() {
        let desktop_cmds = ["screenshot", "ss", "window", "clip", "mouse", "key"];
        if desktop_cmds.contains(&cmd) && std::env::var_os("MRSH_SYSTEM_FORCE").is_none() {
            // args[0] is the command itself; cmd_args is the remainder.
            let cmd_args = if args.len() > 1 {
                args[1..].join(" ")
            } else {
                String::new()
            };
            let suffix = if cmd_args.is_empty() {
                String::new()
            } else {
                format!(" {}", cmd_args)
            };
            eprintln!(
                "error: '{}' requires the tray (port 9822, user session) — not the SYSTEM \
                 service (port 8822, no desktop).\n\
                 \x20 USERPROFILE / GUI / browser / screenshot ops fail silently or return \
                 black on SYSTEM context.\n\
                 \n\
                 Retry on the tray:\n\
                 \x20 mrsh -h {} -p 9822 {}{}\n\
                 \n\
                 If the tray is not running:\n\
                 \x20 mrsh -h {} exec 'schtasks /run /tn mrsh-tray'\n\
                 \x20 # wait 3-5 s, then re-run with -p 9822\n\
                 \n\
                 Override (rare, knowingly bypass): MRSH_SYSTEM_FORCE=1 mrsh -h {} -p 8822 {}{}",
                cmd,
                host, cmd, suffix,
                host,
                host, cmd, suffix,
            );
            std::process::exit(2);
        }
    }

    // ── Control master mode (-M) ──────────────────────────────
    if cli.master {
        return mrsh_client::mux::run_master(host, resolved_port, client).await;
    }

    // ── Session logging ────────────────────────────────────────
    let tracker = if config.is_session_log_enabled(host) {
        let cmd_args = if args.len() > 1 {
            Some(args[1..].join(" "))
        } else {
            None
        };
        // Rotate old logs on session start (cheap: just readdir)
        let log_dir = config.session_log_dir();
        mrsh_client::session_log::rotate_logs(&log_dir, config.session_log_retain);
        Some(mrsh_client::session_log::SessionTracker::start(
            host,
            resolved_port,
            cmd,
            cmd_args.as_deref(),
            &log_dir,
        ))
    } else {
        None
    };

    // ── SOCKS5 dynamic proxy (-D flag) ───────────────────────
    if let Some(socks_port) = cli.dynamic_port {
        // Drop the initial client — SOCKS5 creates new connections per request
        drop(client);

        let connect_opts = Arc::new(ConnectOptions {
            host: resolved_host.clone(),
            port: resolved_port,
            key_path: effective_key.clone(),
            password_user: cli.user.clone(),
        });

        eprintln!(
            "SOCKS5 proxy: 127.0.0.1:{} → {}:{}",
            socks_port, resolved_host, resolved_port
        );

        let connect_fn = move || {
            let opts = connect_opts.clone();
            async move {
                // connect_any dispatches to fs-transport for `fs://` hosts,
                // otherwise to TCP — matches the initial-session behaviour.
                let client = mrsh_client::client::connect_any(&opts).await?;
                Ok(client.into_stream())
            }
        };

        mrsh_client::socks::run_socks5(socks_port, connect_fn).await?;
        return Ok(());
    }

    // Streaming exec runs without outer timeout — output flow keeps connection alive.
    if cmd == "exec" && client.supports_stream_exec() {
        if args.len() < 2 {
            bail!("exec requires a command");
        }
        let raw_command = args[1..].join(" ");
        // Prepend shell prefix if --cmd or --sh flag used
        let command = if cli.use_cmd {
            format!("CMD:{}", raw_command)
        } else if cli.use_sh {
            format!("SH:{}", raw_command)
        } else {
            raw_command
        };
        let exit_code = mrsh_client::commands::exec_stream(&mut client, &command, &[]).await?;
        // Finish session log
        if let Some(tracker) = tracker {
            tracker.finish(exit_code);
        }
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    // Determine operation timeout: explicit --timeout overrides per-command defaults.
    let timeout_secs = compute_timeout_secs(cli.timeout, cmd);

    let cmd_future = crate::dispatch_client::run_command(
        client,
        &cli,
        cmd,
        args,
        host,
        &resolved_host,
        resolved_port,
        device_id.as_deref(),
        &config,
        auto_try_ports,
    );

    let cmd_result: Result<()> = if timeout_secs > 0 {
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), cmd_future).await {
            Ok(result) => result,
            Err(_) => bail!(
                "operation timed out after {}s (use --timeout to override)",
                timeout_secs
            ),
        }
    } else {
        cmd_future.await
    };

    // Finish session log
    if let Some(tracker) = tracker {
        tracker.finish(if cmd_result.is_ok() { 0 } else { 1 });
    }

    cmd_result
}
