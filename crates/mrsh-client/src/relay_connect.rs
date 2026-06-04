//! Relay connection — resolve DeviceID via rendezvous, connect via P2P or relay.
//! Extracted from main.rs for reuse by fleet and other callers.

use anyhow::{Context, Result, bail};
use tracing::{debug, info};

use crate::client::{ConnectOptions, TlsClient};

/// Options for connecting via relay (rendezvous + P2P/hbbr).
#[derive(Debug, Clone)]
pub struct RelayConnectOptions {
    /// Target device ID (numeric or alphanumeric).
    pub device_id: String,
    /// Rendezvous server address (host:port). Defaults to hbbs port 21116.
    pub rendezvous_server: String,
    /// Rendezvous key (licence_key for hbbs authentication).
    pub rendezvous_key: String,
    /// SSH key path for TLS auth after relay connection.
    pub key_path: Option<String>,
    /// Server name for TLS SNI (used in cert verification).
    pub server_name: String,
    /// Port for P2P direct connection attempts.
    pub port: u16,
    /// Port to request via relay protocol.
    /// - `0` = tray-first: server tries tray (9822), falls back to SYSTEM (8822).
    /// - Non-zero = explicit: server routes to exactly this port.
    /// When omitted from construction, defaults to `port` (explicit behavior).
    pub target_port: u16,
    /// Skip P2P attempts and go directly to relay. Set this after the first
    /// connection used relay (saves 5s P2P timeout on reconnections).
    pub force_relay: bool,
    /// Enrollment token for decrypting server's network info (LAN discovery).
    /// Empty string = no LAN probe (not enrolled in any group).
    pub enrollment_token: String,
    /// This node's own DeviceID (from client config).  When non-empty and equal
    /// to `device_id`, the connection short-circuits to `127.0.0.1` instead of
    /// routing through the public rendezvous/relay (sys-1qgww).
    pub own_device_id: Option<String>,
}

/// P2P timeout when relay is available (shortened to let relay win faster).
const P2P_TIMEOUT_SECS: u64 = 5;

/// rsh-npyw: load ALL group tokens from ~/.mrsh/groups.json (or legacy
/// ~/.rsh/groups.json). Used as fallback when the active config doesn't set
/// `EnrollmentToken` — many clients have RendezvousKey but no explicit
/// enrollment, yet they ARE members of one or more groups whose token can
/// decrypt the peer's encrypted_net_info.
fn load_known_group_tokens() -> Result<Vec<String>> {
    let home = dirs::home_dir().context("home dir unknown")?;
    let mrsh_path = home.join(".mrsh").join("groups.json");
    let rsh_path = home.join(".rsh").join("groups.json");
    let path = if mrsh_path.exists() {
        mrsh_path
    } else {
        rsh_path
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&data).context("parse groups.json")?;
    Ok(map.into_values().collect())
}

/// Connect to a remote host via DeviceID resolution.
///
/// Flow:
/// 0. Self-loop short-circuit: if target DeviceID == own DeviceID → 127.0.0.1 directly
/// 1. Resolve DeviceID via hbbs (rendezvous server, UDP)
/// 2. If P2P address available: race P2P (5s timeout) vs relay fallback
/// 3. If relay-only: connect directly through hbbr relay
/// 4. Authenticate over the established stream (TLS + ed25519)
pub async fn connect_via_relay(opts: &RelayConnectOptions) -> Result<TlsClient> {
    // sys-1qgww: short-circuit self-loops — if the target DeviceID is this node's
    // own ID, bypass the public rendezvous/relay entirely and bind to localhost.
    // This eliminates ~47 unnecessary auth events/30s and 22 MB/day of relay
    // audit log growth caused by workstation targeting itself via hbbr.
    if let Some(ref own_id) = opts.own_device_id {
        if !own_id.is_empty() && own_id == &opts.device_id {
            info!(
                "self-loop detected (DeviceID {} == own ID) — short-circuiting to 127.0.0.1:{}",
                opts.device_id, opts.port
            );
            return crate::client::connect(&crate::client::ConnectOptions {
                host: "127.0.0.1".to_string(),
                port: opts.port,
                key_path: opts.key_path.clone(),
                password_user: None,
            })
            .await
            .context("localhost short-circuit connect failed");
        }
    }

    debug!(
        "resolving DeviceID {} via {}",
        opts.device_id, opts.rendezvous_server
    );

    let rdv_client = mrsh_relay::rendezvous::Client {
        servers: vec![opts.rendezvous_server.clone()],
        licence_key: opts.rendezvous_key.clone(),
        local_id: String::new(),
        group_hash: String::new(),
        hostname: String::new(),
        platform: String::new(),
        service_port: 0,
        encrypted_net_info: Vec::new(),
        // sys-8z5gn: client-only connect never runs the registration refresh loop.
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

    let result = rdv_client
        .resolve_with_port(&opts.device_id, opts.target_port)
        .await
        .context("rendezvous resolve failed")?;

    // Try encrypted LAN discovery: if server sent network info, try direct LAN connect.
    // rsh-npyw 2026-05-20: when explicit enrollment_token is empty, fall back to
    // ALL known group tokens from ~/.mrsh/groups.json — many clients have
    // RendezvousKey set but no EnrollmentToken in the active config.
    // Also: race candidate IPs in parallel + use TCP probe before full TLS to
    // avoid sequential per-iface timeouts (was sequential 500ms × N ifaces).
    if !result.encrypted_net_info.is_empty() && !opts.force_relay {
        // Build candidate tokens: explicit first, then ALL groups.json entries.
        let mut tokens: Vec<String> = Vec::new();
        if !opts.enrollment_token.is_empty() {
            tokens.push(opts.enrollment_token.clone());
        }
        if let Ok(known) = load_known_group_tokens() {
            for t in known {
                if !tokens.contains(&t) {
                    tokens.push(t);
                }
            }
        }

        let mut decrypted = None;
        for token in &tokens {
            if let Ok(Some(net_info)) = mrsh_relay::net_crypto::decrypt_network_info(
                &result.encrypted_net_info,
                token,
            ) {
                debug!(
                    "LAN discovery: decrypted net_info with group token (hostname={}, {} interfaces)",
                    net_info.hostname,
                    net_info.interfaces.len()
                );
                decrypted = Some(net_info);
                break;
            }
        }

        if let Some(net_info) = decrypted {
            let lan_port = if opts.target_port != 0 {
                opts.target_port
            } else if net_info.service_port != 0 {
                net_info.service_port as u16
            } else {
                opts.port
            };

            // Collect candidate IPs: prefer same-subnet matches, fall back to all
            // peer IPs that look reachable via OUR interfaces (any private/ZT range).
            let our_ifaces = mrsh_relay::net_crypto::collect_network_info("", 0, 0);
            let mut candidates: Vec<(String, String, bool)> = Vec::new(); // (peer_ip, peer_iface_name, same_subnet)
            for server_iface in &net_info.interfaces {
                if server_iface.ip == "127.0.0.1" || server_iface.ip.is_empty() {
                    continue;
                }
                let same_subnet_match = our_ifaces.interfaces.iter().any(|our| {
                    mrsh_relay::net_crypto::same_subnet(
                        &our.ip,
                        &our.netmask,
                        &server_iface.ip,
                        &server_iface.netmask,
                    )
                });
                candidates.push((
                    server_iface.ip.clone(),
                    server_iface.name.clone(),
                    same_subnet_match,
                ));
            }

            // Sort: same-subnet first (highest probability), then others.
            candidates.sort_by(|a, b| b.2.cmp(&a.2));

            if !candidates.is_empty() {
                info!(
                    "LAN probe: racing {} candidate IPs in parallel ({} same-subnet)",
                    candidates.len(),
                    candidates.iter().filter(|c| c.2).count()
                );

                // TCP-probe each candidate in parallel (1500ms timeout — accommodates
                // ZT-over-WAN RTT 100-500ms; was 300ms too tight for cross-WAN paths).
                let mut tcp_handles = Vec::new();
                for (ip, name, same_subnet) in &candidates {
                    let ip = ip.clone();
                    let name = name.clone();
                    let same_subnet = *same_subnet;
                    tcp_handles.push(tokio::spawn(async move {
                        let t0 = std::time::Instant::now();
                        let result = tokio::time::timeout(
                            std::time::Duration::from_millis(1500),
                            tokio::net::TcpStream::connect((ip.as_str(), lan_port)),
                        )
                        .await;
                        let rtt = t0.elapsed();
                        let ok = matches!(result, Ok(Ok(_)));
                        debug!(
                            "LAN TCP probe {}:{} ({}) -> {} ({}ms{})",
                            ip,
                            lan_port,
                            name,
                            if ok { "open" } else { "closed/timeout" },
                            rtt.as_millis(),
                            if same_subnet { ", same-subnet" } else { "" }
                        );
                        (ip, name, ok, same_subnet, rtt)
                    }));
                }
                let mut reachable: Vec<(String, String, bool, std::time::Duration)> = Vec::new();
                for h in tcp_handles {
                    if let Ok((ip, name, true, same_subnet, rtt)) = h.await {
                        reachable.push((ip, name, same_subnet, rtt));
                    }
                }

                // rsh-f071 2026-05-21: latency-aware sort. Same-subnet remains the primary
                // axis (heuristic: peer on our subnet ≈ LAN path ≈ lowest RTT). Within each
                // group, sort by measured TCP-connect duration ascending — fastest wins.
                // Falls back gracefully if RTTs tie (preserves original iteration order).
                reachable.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.3.cmp(&b.3)));

                // Try full TLS connect on TCP-reachable candidates (sequential, 2s each
                // — but we already filtered to known-open ports, so fast).
                for (ip, name, same_subnet, rtt) in &reachable {
                    info!(
                        "LAN direct: TCP open on {}:{} ({}, {}ms{}), trying TLS handshake",
                        ip,
                        lan_port,
                        name,
                        rtt.as_millis(),
                        if *same_subnet { ", same-subnet" } else { "" }
                    );
                    let tls_result = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        crate::client::connect(&ConnectOptions {
                            host: ip.clone(),
                            port: lan_port,
                            key_path: opts.key_path.clone(),
                            password_user: None,
                        }),
                    )
                    .await;
                    match tls_result {
                        Ok(Ok(c)) => {
                            info!(
                                "LAN direct: connected to {} ({}) on port {}",
                                net_info.hostname, ip, lan_port
                            );
                            return Ok(c);
                        }
                        Ok(Err(e)) => debug!("LAN TLS {} failed: {}", ip, e),
                        Err(_) => debug!("LAN TLS {} timed out", ip),
                    }
                }
                debug!("LAN probe: no candidate succeeded full TLS, falling back to P2P/relay");
            } else {
                debug!("LAN probe: no usable peer interfaces, falling back to P2P/relay");
            }
        } else {
            debug!(
                "LAN probe: net_info present but no group token decrypts it (tried {} tokens), falling back to P2P/relay",
                tokens.len()
            );
        }
    }

    // Try P2P first if address available (skip if force_relay is set)
    if let Some(addr) = result.addr
        && !opts.force_relay
    {
        debug!("P2P: trying {}:{}", addr.ip(), opts.port);
        let p2p_result = tokio::time::timeout(
            std::time::Duration::from_secs(P2P_TIMEOUT_SECS),
            crate::client::connect(&ConnectOptions {
                host: addr.ip().to_string(),
                port: opts.port,
                key_path: opts.key_path.clone(),
                password_user: None,
            }),
        )
        .await;

        match p2p_result {
            Ok(Ok(c)) => {
                info!("P2P: connected to {}", addr.ip());
                return Ok(c);
            }
            _ => {
                // P2P failed, fall through to relay
                if result.relay_server.is_empty() {
                    bail!("P2P failed and no relay server available");
                }
                debug!("P2P failed, connecting via relay {}", result.relay_server);
            }
        }
    } else if result.relay_server.is_empty() {
        bail!(
            "device {} resolved but no address or relay available",
            opts.device_id
        );
    }

    // Relay path
    let relay_addr = if result.relay_server.contains(':') {
        result.relay_server.clone()
    } else {
        format!("{}:21117", result.relay_server)
    };

    let relay_stream =
        mrsh_relay::relay::connect_relay(&relay_addr, &result.uuid, &opts.rendezvous_key)
            .await
            .context("relay connect failed")?;

    debug!("relay: connected, authenticating...");
    crate::client::connect_over_stream(relay_stream, &opts.server_name, &opts.key_path).await
}

/// Build RelayConnectOptions from a HostConfig and global Config.
pub fn relay_options_from_config(
    host_config: &mrsh_core::config::HostConfig,
    config: &mrsh_core::config::Config,
    key_path: &Option<String>,
) -> Option<RelayConnectOptions> {
    let device_id = host_config.device_id.as_ref()?;
    let hostname = host_config
        .hostname
        .clone()
        .unwrap_or_else(|| host_config.pattern.clone());

    let rdv_server = config
        .rendezvous_server
        .as_deref()
        .unwrap_or("rdv.example.com:21116")
        .to_string();
    let rdv_key = config.rendezvous_key.clone().unwrap_or_default();

    Some(RelayConnectOptions {
        device_id: device_id.clone(),
        rendezvous_server: rdv_server,
        rendezvous_key: rdv_key,
        key_path: key_path.clone(),
        server_name: hostname,
        port: host_config.port,
        target_port: host_config.port,
        force_relay: false,
        enrollment_token: String::new(),
        own_device_id: config.device_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrsh_core::config::{Config, HostConfig};

    #[test]
    fn relay_options_from_config_with_device_id() {
        let host = HostConfig {
            pattern: "myserver".to_string(),
            hostname: Some("192.168.1.100".to_string()),
            port: 8822,
            device_id: Some("118855822".to_string()),
            ..Default::default()
        };
        let mut config = Config::default();
        config.rendezvous_server = Some("rdv.example.com:21116".to_string());
        config.rendezvous_key = Some("testkey".to_string());

        let opts = relay_options_from_config(&host, &config, &None).unwrap();
        assert_eq!(opts.device_id, "118855822");
        assert_eq!(opts.rendezvous_server, "rdv.example.com:21116");
        assert_eq!(opts.rendezvous_key, "testkey");
        assert_eq!(opts.server_name, "192.168.1.100");
        assert_eq!(opts.port, 8822);
        assert_eq!(opts.target_port, 8822);
        // own_device_id inherits from config.device_id (None here — not set)
        assert_eq!(opts.own_device_id, None);
    }

    /// sys-1qgww: when config sets its own DeviceID, relay_options_from_config
    /// propagates it so connect_via_relay can detect self-loops.
    #[test]
    fn relay_options_from_config_propagates_own_device_id() {
        let host = HostConfig {
            pattern: "myself".to_string(),
            hostname: Some("192.168.1.1".to_string()),
            port: 8822,
            device_id: Some("123456789".to_string()),
            ..Default::default()
        };
        let mut config = Config::default();
        config.device_id = Some("123456789".to_string()); // same machine
        config.rendezvous_server = Some("rdv.example.com:21116".to_string());

        let opts = relay_options_from_config(&host, &config, &None).unwrap();
        assert_eq!(opts.device_id, "123456789");
        assert_eq!(opts.own_device_id, Some("123456789".to_string()));
        // self-loop: device_id == own_device_id → connect_via_relay should short-circuit
    }

    /// sys-1qgww: different own_device_id → no self-loop, normal relay path.
    #[test]
    fn relay_options_from_config_different_own_device_id() {
        let host = HostConfig {
            pattern: "remotehost".to_string(),
            hostname: Some("10.0.0.2".to_string()),
            port: 8822,
            device_id: Some("987654321".to_string()),
            ..Default::default()
        };
        let mut config = Config::default();
        config.device_id = Some("111111111".to_string()); // different machine
        config.rendezvous_server = Some("rdv.example.com:21116".to_string());

        let opts = relay_options_from_config(&host, &config, &None).unwrap();
        assert_eq!(opts.device_id, "987654321");
        assert_eq!(opts.own_device_id, Some("111111111".to_string()));
        assert_ne!(opts.own_device_id.as_deref(), Some(opts.device_id.as_str()));
    }

    #[test]
    fn relay_options_none_without_device_id() {
        let host = HostConfig {
            pattern: "myserver".to_string(),
            hostname: Some("192.168.1.100".to_string()),
            port: 8822,
            device_id: None,
            ..Default::default()
        };
        let config = Config::default();

        assert!(relay_options_from_config(&host, &config, &None).is_none());
    }

    #[test]
    fn relay_options_uses_pattern_as_fallback_hostname() {
        let host = HostConfig {
            pattern: "myserver".to_string(),
            hostname: None, // no explicit hostname
            port: 9822,
            device_id: Some("999".to_string()),
            ..Default::default()
        };
        let config = Config::default();

        let opts =
            relay_options_from_config(&host, &config, &Some("/tmp/key".to_string())).unwrap();
        assert_eq!(opts.server_name, "myserver");
        assert_eq!(opts.key_path, Some("/tmp/key".to_string()));
    }

    #[test]
    fn relay_connect_options_debug() {
        let opts = RelayConnectOptions {
            device_id: "12345".to_string(),
            rendezvous_server: "rdv.example.com:21116".to_string(),
            rendezvous_key: String::new(),
            key_path: None,
            server_name: "host".to_string(),
            port: 8822,
            target_port: 8822,
            force_relay: false,
            enrollment_token: String::new(),
            own_device_id: None,
        };
        let debug = format!("{:?}", opts);
        assert!(debug.contains("12345"));
        assert!(debug.contains("rdv.example.com"));
    }

    /// rsh-f071: latency-aware sort. Same-subnet is the primary axis (desc),
    /// RTT the secondary tiebreaker within each group (asc).
    /// Vec layout: (ip, name, same_subnet, rtt).
    fn sort_reachable_by_latency(
        mut v: Vec<(String, String, bool, std::time::Duration)>,
    ) -> Vec<(String, String, bool, std::time::Duration)> {
        v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.3.cmp(&b.3)));
        v
    }

    #[test]
    fn sort_picks_lowest_rtt_within_same_subnet_group() {
        use std::time::Duration;
        let input = vec![
            ("10.0.0.2".to_string(), "lan_slow".to_string(), true, Duration::from_millis(80)),
            ("10.0.0.1".to_string(), "lan_fast".to_string(), true, Duration::from_millis(5)),
            ("10.0.0.3".to_string(), "lan_mid".to_string(), true, Duration::from_millis(30)),
        ];
        let out = sort_reachable_by_latency(input);
        assert_eq!(out[0].0, "10.0.0.1"); // fastest same-subnet wins
        assert_eq!(out[1].0, "10.0.0.3");
        assert_eq!(out[2].0, "10.0.0.2");
    }

    #[test]
    fn sort_prefers_same_subnet_over_lower_rtt_in_other_group() {
        use std::time::Duration;
        let input = vec![
            ("10.99.0.1".to_string(), "vpn_fast".to_string(), false, Duration::from_millis(1)),
            ("10.0.0.1".to_string(), "lan_slow".to_string(), true, Duration::from_millis(500)),
        ];
        let out = sort_reachable_by_latency(input);
        // Same-subnet wins even though its RTT is much higher.
        assert_eq!(out[0].2, true);
        assert_eq!(out[0].0, "10.0.0.1");
        assert_eq!(out[1].0, "10.99.0.1");
    }

    #[test]
    fn sort_orders_non_same_subnet_group_by_rtt() {
        use std::time::Duration;
        let input = vec![
            ("172.16.0.5".to_string(), "wan_slow".to_string(), false, Duration::from_millis(500)),
            ("172.16.0.3".to_string(), "wan_mid".to_string(), false, Duration::from_millis(120)),
            ("172.16.0.1".to_string(), "wan_fast".to_string(), false, Duration::from_millis(20)),
        ];
        let out = sort_reachable_by_latency(input);
        assert_eq!(out[0].0, "172.16.0.1");
        assert_eq!(out[1].0, "172.16.0.3");
        assert_eq!(out[2].0, "172.16.0.5");
    }

    #[test]
    fn sort_mixed_groups_preserves_axis_priority() {
        use std::time::Duration;
        let input = vec![
            ("10.99.0.1".to_string(), "vpn_fast".to_string(), false, Duration::from_millis(10)),
            ("192.168.1.5".to_string(), "lan_b".to_string(), true, Duration::from_millis(50)),
            ("172.16.0.1".to_string(), "wan".to_string(), false, Duration::from_millis(200)),
            ("192.168.1.3".to_string(), "lan_a".to_string(), true, Duration::from_millis(15)),
        ];
        let out = sort_reachable_by_latency(input);
        // Same-subnet group first (lan_a 15ms < lan_b 50ms), then non-same-subnet by RTT.
        assert_eq!(out[0].0, "192.168.1.3"); // same-subnet, fastest
        assert_eq!(out[1].0, "192.168.1.5"); // same-subnet, slower
        assert_eq!(out[2].0, "10.99.0.1");   // non-same, fastest
        assert_eq!(out[3].0, "172.16.0.1");  // non-same, slowest
    }

    #[test]
    fn sort_single_candidate_noop() {
        use std::time::Duration;
        let input = vec![
            ("10.0.0.1".to_string(), "iface".to_string(), true, Duration::from_millis(42)),
        ];
        let out = sort_reachable_by_latency(input.clone());
        assert_eq!(out, input);
    }

    #[test]
    fn sort_empty_noop() {
        let input: Vec<(String, String, bool, std::time::Duration)> = vec![];
        let out = sort_reachable_by_latency(input);
        assert!(out.is_empty());
    }
}
