//! Fleet, relay, and rendezvous server CLI commands.

use anyhow::{Result, bail};
use mrsh_client::client::ConnectOptions;

/// rsh-5264.5: parse a string as a bool, accepting common forms.
/// Returns `None` on unrecognized input so the caller can decide how to error.
fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Some(true),
        "false" | "no" | "0" | "off" => Some(false),
        _ => None,
    }
}

/// Minimum acceptable binary size. Matches `selfupdate::MIN_BINARY_SIZE`.
/// A binary below this threshold is almost certainly not a real mrsh build.
const MIN_FLEET_BINARY_SIZE: usize = 1_000_000;

/// Load a binary from disk, returning `Ok(None)` if the file is absent.
/// `kind` is used purely for error messages. Rejects files smaller than
/// `MIN_FLEET_BINARY_SIZE` (hard-fail rather than silent push of a stub).
fn load_optional_binary(path: &str, kind: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() < MIN_FLEET_BINARY_SIZE {
                bail!(
                    "{} binary {} is too small ({} bytes) — expected >1MB",
                    kind,
                    path,
                    bytes.len()
                );
            }
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "note: {} binary {} not found — hosts that need it will be SKIPPED",
                kind, path
            );
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!("read {}: {}", path, e)),
    }
}

/// Run the relay server (hbbr).
pub async fn run_relay_server(args: &[String]) -> Result<()> {
    let mut port: u16 = 21117;
    let mut key = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(21117);
            }
            "--key" | "-k" => {
                i += 1;
                key = args.get(i).cloned().unwrap_or_default();
            }
            _ => {
                if let Some(p) = args[i].strip_prefix("--port=") {
                    port = p.parse().unwrap_or(21117);
                } else if let Some(k) = args[i].strip_prefix("--key=") {
                    key = k.to_string();
                } else {
                    bail!("unknown relay arg: {}", args[i]);
                }
            }
        }
        i += 1;
    }

    let server = mrsh_relay::relay::RelayServer::new(&key);
    let addr = format!("0.0.0.0:{port}");
    eprintln!("relay server (hbbr) listening on {addr}");
    server.listen_and_serve(&addr).await
}

/// Run the rendezvous server (hbbs).
pub async fn run_rendezvous_server(args: &[String]) -> Result<()> {
    let mut port: u16 = 21116;
    let mut key = String::new();
    let mut relay = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(21116);
            }
            "--key" | "-k" => {
                i += 1;
                key = args.get(i).cloned().unwrap_or_default();
            }
            "--relay" | "-r" => {
                i += 1;
                relay = args.get(i).cloned().unwrap_or_default();
            }
            _ => {
                if let Some(p) = args[i].strip_prefix("--port=") {
                    port = p.parse().unwrap_or(21116);
                } else if let Some(k) = args[i].strip_prefix("--key=") {
                    key = k.to_string();
                } else if let Some(r) = args[i].strip_prefix("--relay=") {
                    relay = r.to_string();
                } else {
                    bail!("unknown rendezvous arg: {}", args[i]);
                }
            }
        }
        i += 1;
    }

    if relay.is_empty() {
        bail!("--relay <host:port> is required (address of hbbr relay server)");
    }

    let server = mrsh_relay::rendezvous::RendezvousServer::new(&key, &relay);
    let addr = format!("0.0.0.0:{port}");
    eprintln!("rendezvous server (hbbs) listening on {addr} (relay: {relay})");
    server.listen_and_serve(&addr).await
}

/// Fleet status and update across configured hosts.
pub async fn run_fleet(args: &[String]) -> Result<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("status");
    let config = mrsh_core::config::Config::load();

    match action {
        "status" => {
            let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
            // sys-poal: --refresh / -r re-probes hosts on the auto-try ports
            // (9822/8822/22) when the configured port fails, catching cases
            // where the config's port is stale but the host is reachable.
            let refresh = args
                .iter()
                .any(|a| a == "-r" || a == "--refresh" || a == "--retry-ports");
            // rsh-5264.5: --show-track is currently a no-op flag because the
            // formatter auto-shows TRACK/AUTO_UPG columns whenever any host
            // reports those fields. Accepted for forward compat with operator
            // muscle memory ("show me the tracks") and to make the intent
            // explicit in scripts.
            let _show_track =
                args.iter().any(|a| a == "--show-track" || a == "--tracks");
            // desk-xqq: --json emits machine-readable JSON to stdout; all
            // tracing output (warn/info/debug) goes to stderr via the
            // subscriber (set up in main), so stdout is JSON-clean.
            let json_out = args.iter().any(|a| a == "--json");
            let opts = mrsh_client::fleet::StatusOpts {
                refresh_alt_ports: refresh,
            };
            let statuses = mrsh_client::fleet::status_with_opts(&config, opts).await;

            // desk-xqq task2: dedup HostKeyChanged warnings — emit one summary
            // warn per drifted host instead of one warn per TLS handshake
            // (which fires in the TLS verifier for every connection attempt).
            // The TLS-layer warn! was downgraded to debug! in mrsh-core/tls.rs.
            {
                let drifted: Vec<&str> = statuses
                    .iter()
                    .filter(|s| {
                        s.error_kind
                            == Some(mrsh_client::fleet::ProbeErrorKind::HostKeyChanged)
                    })
                    .map(|s| s.name.as_str())
                    .collect();
                if !drifted.is_empty() {
                    tracing::warn!(
                        "host key changed for {} host(s): {} — run `mrsh --accept-host-key` to accept new keys",
                        drifted.len(),
                        drifted.join(", ")
                    );
                }
            }

            if json_out {
                // desk-xqq task1: JSON output to stdout.
                // Uses serde_json::json! macro (avoids needing serde derive in
                // the root crate which only depends on serde_json, not serde).
                let hosts_json: Vec<serde_json::Value> = statuses
                    .iter()
                    .map(|s| {
                        let mut obj = serde_json::json!({
                            "name": s.name,
                            "reachable": s.online,
                            "server_version": s.version.as_deref()
                                .or(s.rdv_version.as_deref()),
                            "device_id": s.device_id.as_deref(),
                            "latency_ms": s.latency_ms,
                        });
                        if let Some(err) = s.error.as_deref() {
                            obj["error"] = serde_json::Value::String(err.to_string());
                        }
                        obj
                    })
                    .collect();
                let reachable_count =
                    statuses.iter().filter(|s| s.online).count();
                let out = serde_json::json!({
                    "hosts": hosts_json,
                    "total": statuses.len(),
                    "reachable_count": reachable_count,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{}",
                    mrsh_client::fleet::format_status_table_inner(&statuses, verbose)
                );
            }
        }
        "update" => {
            // rsh-lic: per-OS binary selection. Flags override defaults, which
            // are resolved against `deploy/` so the Windows positional arg
            // (legacy v1.10.22 usage) still works when no --windows is passed.
            let mut windows_path: Option<String> = None;
            let mut linux_path: Option<String> = None;
            let mut linux_musl_path: Option<String> = None;
            // rsh-6i9e: aarch64 binary path for ARM Linux head-units / SBCs.
            let mut linux_aarch64_path: Option<String> = None;
            let mut dry_run = false;
            let mut refresh_ports = false;
            let mut legacy_positional: Option<String> = None;

            let mut i = 1;
            while i < args.len() {
                let a = &args[i];
                match a.as_str() {
                    "--windows" => {
                        i += 1;
                        windows_path = args.get(i).cloned();
                    }
                    "--linux" | "--linux-gnu" => {
                        i += 1;
                        linux_path = args.get(i).cloned();
                    }
                    "--linux-musl" | "--musl" => {
                        i += 1;
                        linux_musl_path = args.get(i).cloned();
                    }
                    "--linux-aarch64" | "--linux-arm64" | "--aarch64" => {
                        i += 1;
                        linux_aarch64_path = args.get(i).cloned();
                    }
                    "--dry-run" | "-n" => {
                        dry_run = true;
                    }
                    "--refresh" | "-r" => {
                        refresh_ports = true;
                    }
                    s if s.starts_with("--windows=") => {
                        windows_path = Some(s.strip_prefix("--windows=").unwrap().to_string());
                    }
                    s if s.starts_with("--linux=") => {
                        linux_path = Some(s.strip_prefix("--linux=").unwrap().to_string());
                    }
                    s if s.starts_with("--linux-musl=") => {
                        linux_musl_path =
                            Some(s.strip_prefix("--linux-musl=").unwrap().to_string());
                    }
                    s if s.starts_with("--linux-aarch64=") => {
                        linux_aarch64_path =
                            Some(s.strip_prefix("--linux-aarch64=").unwrap().to_string());
                    }
                    s if s.starts_with("--linux-arm64=") => {
                        linux_aarch64_path =
                            Some(s.strip_prefix("--linux-arm64=").unwrap().to_string());
                    }
                    // Legacy positional: a single path, interpreted as Windows
                    // binary (matches pre-rsh-lic behavior).
                    s if !s.starts_with('-') && legacy_positional.is_none() => {
                        legacy_positional = Some(s.to_string());
                    }
                    other => {
                        bail!("unknown fleet update arg: {}", other);
                    }
                }
                i += 1;
            }

            let windows_resolved = windows_path
                .clone()
                .or(legacy_positional.clone())
                .unwrap_or_else(|| {
                    mrsh_client::fleet::OsKind::Windows
                        .default_binary_path()
                        .to_string()
                });

            let linux_resolved = linux_path.clone().unwrap_or_else(|| {
                mrsh_client::fleet::OsKind::LinuxGnu
                    .default_binary_path()
                    .to_string()
            });

            let linux_musl_resolved = linux_musl_path.clone().unwrap_or_else(|| {
                mrsh_client::fleet::OsKind::LinuxMusl
                    .default_binary_path()
                    .to_string()
            });

            let linux_aarch64_resolved = linux_aarch64_path.clone().unwrap_or_else(|| {
                mrsh_client::fleet::OsKind::LinuxAarch64
                    .default_binary_path()
                    .to_string()
            });

            // Load each binary best-effort. Missing files are OK — hosts that
            // need that OS will be reported as SKIPPED in the plan instead of
            // mis-pushing the wrong PE.
            let windows_bytes = load_optional_binary(&windows_resolved, "windows")?;
            let linux_bytes = load_optional_binary(&linux_resolved, "linux")?;
            let linux_musl_bytes = load_optional_binary(&linux_musl_resolved, "linux-musl")?;
            let linux_aarch64_bytes =
                load_optional_binary(&linux_aarch64_resolved, "linux-aarch64")?;

            if windows_bytes.is_none()
                && linux_bytes.is_none()
                && linux_musl_bytes.is_none()
                && linux_aarch64_bytes.is_none()
            {
                bail!(
                    "no binaries found: tried {}, {}, {}, {}",
                    windows_resolved,
                    linux_resolved,
                    linux_musl_resolved,
                    linux_aarch64_resolved
                );
            }

            let binaries = mrsh_client::fleet::FleetBinaries {
                windows: windows_bytes,
                linux_gnu: linux_bytes,
                linux_musl: linux_musl_bytes,
                linux_aarch64: linux_aarch64_bytes,
            };

            let target_version = env!("CARGO_PKG_VERSION");
            eprintln!(
                "Fleet update → v{} (windows={}B, linux={}B, linux-musl={}B, linux-aarch64={}B){}",
                target_version,
                binaries.windows.as_ref().map(|b| b.len()).unwrap_or(0),
                binaries.linux_gnu.as_ref().map(|b| b.len()).unwrap_or(0),
                binaries.linux_musl.as_ref().map(|b| b.len()).unwrap_or(0),
                binaries
                    .linux_aarch64
                    .as_ref()
                    .map(|b| b.len())
                    .unwrap_or(0),
                if dry_run { " [DRY-RUN]" } else { "" }
            );

            let opts = mrsh_client::fleet::UpdateOpts {
                dry_run,
                refresh_ports,
            };
            let results =
                mrsh_client::fleet::update_fleet_multi(&config, &binaries, target_version, opts)
                    .await;

            if !dry_run {
                println!("{}", mrsh_client::fleet::format_update_results(&results));

                // After-update status: re-probe from scratch so the user sees
                // the post-update state (sys-poal + rsh-lic: stale version
                // after rename-swap is only visible if we re-probe).
                eprintln!("\nPost-update status:");
                let after_opts = mrsh_client::fleet::StatusOpts {
                    refresh_alt_ports: refresh_ports,
                };
                let after =
                    mrsh_client::fleet::status_with_opts(&config, after_opts).await;
                println!("{}", mrsh_client::fleet::format_status_table(&after));
            }
        }
        "config" => {
            // rsh-5264.5: when `--host <H>` is supplied with `--auto-upgrade`
            // and/or `--track`, treat as a staged-rollout setter and update
            // the local config (so the next time the local mrsh server reads
            // its config, it picks up the new track / auto_upgrade for that
            // host block). Without `--host`, fall back to the legacy fleet
            // rendezvous-drift check.
            let mut target_host: Option<String> = None;
            let mut set_auto_upgrade: Option<bool> = None;
            let mut set_track: Option<String> = None;
            let mut show_track_flag = false;
            let mut i = 1;
            while i < args.len() {
                let a = &args[i];
                match a.as_str() {
                    "--host" | "-h" => {
                        i += 1;
                        target_host = args.get(i).cloned();
                    }
                    "--auto-upgrade" => {
                        i += 1;
                        set_auto_upgrade = args.get(i).and_then(|v| parse_bool(v));
                    }
                    "--track" => {
                        i += 1;
                        set_track = args.get(i).cloned();
                    }
                    "--show-track" => {
                        show_track_flag = true;
                    }
                    s if s.starts_with("--host=") => {
                        target_host = Some(s.strip_prefix("--host=").unwrap().to_string());
                    }
                    s if s.starts_with("--auto-upgrade=") => {
                        set_auto_upgrade =
                            parse_bool(s.strip_prefix("--auto-upgrade=").unwrap());
                    }
                    s if s.starts_with("--track=") => {
                        set_track = Some(s.strip_prefix("--track=").unwrap().to_string());
                    }
                    _ => {}
                }
                i += 1;
            }

            // Setter mode: --host + (--auto-upgrade or --track) → write config.
            if target_host.is_some()
                && (set_auto_upgrade.is_some() || set_track.is_some())
            {
                let host_name = target_host.unwrap();
                if let Some(ref track) = set_track
                    && !matches!(track.as_str(), "stable" | "canary" | "dev")
                {
                    bail!(
                        "invalid track {:?} (allowed: stable, canary, dev)",
                        track
                    );
                }

                let mut cfg = mrsh_core::config::Config::load();

                // Find or create host block.
                let existing = cfg.hosts.iter_mut().find(|h| {
                    h.pattern.eq_ignore_ascii_case(&host_name)
                        || h.hostname
                            .as_deref()
                            .map(|n| n.eq_ignore_ascii_case(&host_name))
                            .unwrap_or(false)
                });
                let host_block = match existing {
                    Some(h) => h,
                    None => {
                        let mut nh = mrsh_core::config::HostConfig::default();
                        nh.pattern = host_name.clone();
                        nh.port = 8822;
                        cfg.hosts.push(nh);
                        cfg.hosts.last_mut().unwrap()
                    }
                };

                if let Some(au) = set_auto_upgrade {
                    host_block.auto_upgrade = Some(au);
                }
                if let Some(t) = set_track {
                    host_block.track = Some(t);
                }

                cfg.save()?;
                println!(
                    "Updated config for host '{}': auto_upgrade={:?} track={:?}",
                    host_name,
                    set_auto_upgrade,
                    cfg.find_host(&host_name).and_then(|h| h.track.clone())
                );
                println!(
                    "(applies on next mrsh server restart on '{}')",
                    host_name
                );
                return Ok(());
            }

            // Legacy: fleet-wide rendezvous drift check (or with
            // --show-track, also rendered with TRACK/AUTO_UPG columns).
            if show_track_flag {
                let statuses =
                    mrsh_client::fleet::status_with_opts(&config, Default::default()).await;
                println!(
                    "{}",
                    mrsh_client::fleet::format_status_table_inner(&statuses, false)
                );
                return Ok(());
            }

            let statuses = mrsh_client::fleet::status(&config).await;
            let online: Vec<_> = statuses.iter().filter(|s| s.online).collect();

            if online.is_empty() {
                eprintln!("No hosts online.");
                return Ok(());
            }

            let expected_rdv = config.rendezvous_server.clone().unwrap_or_default();

            println!("Expected rendezvous: {}", expected_rdv);
            println!();

            for host in &online {
                let opts = ConnectOptions {
                    host: host.hostname.clone(),
                    port: host.port,
                    key_path: None,
                    password_user: None,
                };
                match mrsh_client::client::connect(&opts).await {
                    Ok(mut c) => match mrsh_client::commands::native(&mut c, "config").await {
                        Ok(cfg) => {
                            let matches = cfg.contains(&expected_rdv);
                            let mark = if matches { "OK" } else { "DRIFT" };
                            println!("{:<20} [{}]", host.name, mark);
                            if !matches {
                                println!("  remote: {}", cfg.trim());
                            }
                        }
                        Err(e) => println!("{:<20} [ERROR: {}]", host.name, e),
                    },
                    Err(e) => println!("{:<20} [CONNECT FAILED: {}]", host.name, e),
                }
            }
        }
        "discover" => {
            // Fleet discovery via rendezvous group query.
            let mut group_name = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--group" | "-g" => {
                        i += 1;
                        group_name = args.get(i).cloned();
                    }
                    other if other.starts_with("--group=") => {
                        group_name = Some(other.strip_prefix("--group=").unwrap().to_string());
                    }
                    _ => {}
                }
                i += 1;
            }
            let group_name = group_name.ok_or_else(|| {
                anyhow::anyhow!(
                    "--group <name> required\nUsage: mrsh fleet discover --group <name>"
                )
            })?;

            // Look up enrollment token
            let token = mrsh_client::install_pack::get_group_token(&group_name)?;

            // Build rendezvous client
            let rdv_server = config
                .rendezvous_server
                .clone()
                .unwrap_or_else(|| "localhost:21116".to_string());

            let rdv_client = mrsh_relay::rendezvous::Client {
                servers: vec![rdv_server.clone()],
                licence_key: config.rendezvous_key.clone().unwrap_or_default(),
                local_id: String::new(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
                encrypted_net_info: Vec::new(),
                // sys-8z5gn: operator-side client, no registration refresh loop.
                enrollment_token: String::new(),
                tray_port: 0,
                ports: Vec::new(),
                // rsh-5264.1: client doesn't report server version
                current_version: String::new(),
                last_update_status: String::new(),
                last_update_at_unix: 0,
                // rsh-5264.5: client doesn't have a track / auto_upgrade setting.
                track: String::new(),
                auto_upgrade: false,
            };

            eprintln!("Querying {} for group '{}'...", rdv_server, group_name);
            let peers = rdv_client.query_group(&token).await?;

            if peers.is_empty() {
                println!("No peers found in group '{}'.", group_name);
                return Ok(());
            }

            // Detect which peers are on the same LAN
            let local_addrs = crate::get_local_addrs();

            println!(
                "{:<15} {:<20} {:<10} {:<22} {:<8} LAN IPs",
                "DEVICE ID", "HOSTNAME", "PLATFORM", "WAN ADDRESS", "NETWORK"
            );
            println!("{}", "-".repeat(100));

            let mut lan_count = 0;
            for peer in &peers {
                let addr_str = peer
                    .addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "relay-only".to_string());

                // Decrypt network info blob (used for LAN flag AND LAN IPs column).
                let blob_ip_strs: Vec<String> = if !peer.encrypted_net_info.is_empty() {
                    match mrsh_relay::net_crypto::decrypt_network_info(
                        &peer.encrypted_net_info,
                        &token,
                    ) {
                        Ok(Some(info)) => {
                            info.interfaces.iter().map(|iface| iface.ip.clone()).collect()
                        }
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                };

                // LAN detection: WAN address /24 match OR any decrypted blob IP /24 match.
                let wan_is_lan = peer
                    .addr
                    .is_some_and(|a| crate::is_same_lan(a, &local_addrs));
                let blob_is_lan = blob_ip_strs.iter().any(|s| {
                    s.parse::<std::net::Ipv4Addr>()
                        .map(|ip| crate::ipv4_same_lan(ip, &local_addrs))
                        .unwrap_or(false)
                });
                let is_lan = wan_is_lan || blob_is_lan;
                if is_lan {
                    lan_count += 1;
                }
                let net_label = if is_lan { "LAN" } else { "WAN/Relay" };

                let lan_display = if blob_ip_strs.is_empty() {
                    "(no blob)".to_string()
                } else {
                    blob_ip_strs.join(", ")
                };

                println!(
                    "{:<15} {:<20} {:<10} {:<22} {:<8} {}",
                    peer.device_id, peer.hostname, peer.platform, addr_str, net_label, lan_display
                );
            }

            println!("\n{} peer(s) total, {} on LAN", peers.len(), lan_count);
        }
        other => bail!(
            "unknown fleet action: {} (use status|update|config|discover)",
            other
        ),
    }

    Ok(())
}
