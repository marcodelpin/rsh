//! Fleet, relay, and rendezvous server CLI commands.

use anyhow::{Result, bail};
use mrsh_client::client::ConnectOptions;

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
            let statuses = mrsh_client::fleet::status(&config).await;
            println!("{}", mrsh_client::fleet::format_status_table_inner(&statuses, verbose));
        }
        "update" => {
            let binary_path = args.get(1).map(|s| s.as_str()).unwrap_or("deploy/rsh.exe");

            let binary_data = std::fs::read(binary_path)
                .map_err(|e| anyhow::anyhow!("read {}: {}", binary_path, e))?;

            if binary_data.len() < 1_000_000 {
                bail!(
                    "binary {} is too small ({} bytes) — expected >1MB",
                    binary_path,
                    binary_data.len()
                );
            }

            let target_version = env!("CARGO_PKG_VERSION");
            eprintln!(
                "Fleet update: {} ({} bytes) → v{}",
                binary_path,
                binary_data.len(),
                target_version
            );

            // Show current status first
            let statuses = mrsh_client::fleet::status(&config).await;
            println!("{}\n", mrsh_client::fleet::format_status_table(&statuses));

            let results =
                mrsh_client::fleet::update_fleet(&config, &binary_data, target_version).await;
            println!("{}", mrsh_client::fleet::format_update_results(&results));
        }
        "config" => {
            // Check rendezvous config consistency across fleet
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
            let group_name = group_name
                .ok_or_else(|| anyhow::anyhow!("--group <name> required\nUsage: mrsh fleet discover --group <name>"))?;

            // Look up enrollment token
            let token = mrsh_client::install_pack::get_group_token(&group_name)?;

            // Build rendezvous client
            let rdv_server = config.rendezvous_server.clone()
                .unwrap_or_else(|| "localhost:21116".to_string());

            let rdv_client = mrsh_relay::rendezvous::Client {
                servers: vec![rdv_server.clone()],
                licence_key: config.rendezvous_key.clone().unwrap_or_default(),
                local_id: String::new(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
            };

            eprintln!("Querying {} for group '{}'...", rdv_server, group_name);
            let peers = rdv_client.query_group(&token).await?;

            if peers.is_empty() {
                println!("No peers found in group '{}'.", group_name);
                return Ok(());
            }

            // Detect which peers are on the same LAN
            let local_addrs = crate::get_local_addrs();

            println!("{:<15} {:<20} {:<10} {:<22} {:<8} LAST SEEN",
                "DEVICE ID", "HOSTNAME", "PLATFORM", "ADDRESS", "NETWORK");
            println!("{}", "-".repeat(90));

            for peer in &peers {
                let addr_str = peer.addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "relay-only".to_string());

                let is_lan = peer.addr.is_some_and(|a| crate::is_same_lan(a, &local_addrs));
                let net_label = if is_lan { "LAN" } else { "WAN/Relay" };

                let ago = {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let diff = now.saturating_sub(peer.last_seen_secs);
                    if diff < 60 { format!("{}s ago", diff) }
                    else if diff < 3600 { format!("{}m ago", diff / 60) }
                    else { format!("{}h ago", diff / 3600) }
                };

                println!("{:<15} {:<20} {:<10} {:<22} {:<8} {}",
                    peer.device_id, peer.hostname, peer.platform, addr_str, net_label, ago);
            }

            let lan_count = peers.iter()
                .filter(|p| p.addr.is_some_and(|a| crate::is_same_lan(a, &local_addrs)))
                .count();
            println!("\n{} peer(s) total, {} on LAN", peers.len(), lan_count);
        }
        other => bail!("unknown fleet action: {} (use status|update|config|discover)", other),
    }

    Ok(())
}
