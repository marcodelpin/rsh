//! Fleet status: probing hosts and classifying their reachability.
//!
//! Reads `~/.mrsh/config` for the host list, probes them concurrently over
//! TLS / relay / QUIC, and merges the results with peers discovered from the
//! rendezvous server (hbbs).

use std::time::{Duration, Instant};

use mrsh_core::config::{Config, HostConfig};
use tracing::{debug, warn};

use super::discover::discover_from_hbbs;

/// Classification of why a probe failed.
/// Lets the caller distinguish "host not there" from "host there but key rotated"
/// or "host there on a different port".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ProbeErrorKind {
    /// TCP connection timed out (no answer).
    Timeout,
    /// TCP connection was refused (port closed, service down, firewall RST).
    Refused,
    /// TLS handshake failed because the server presented a different key than
    /// what's stored in known_hosts (TOFU host-key rotation). The host IS
    /// reachable on TCP — someone rotated the key, or a different server
    /// answered on the same host:port.
    HostKeyChanged,
    /// TLS handshake or authentication failed for other reasons.
    AuthFailed,
    /// Catch-all for other connection errors (DNS, network, unexpected EOF, …).
    Other,
}

impl ProbeErrorKind {
    /// Short human-readable label (fits in a table cell).
    pub fn label(&self) -> &'static str {
        match self {
            ProbeErrorKind::Timeout => "timeout",
            ProbeErrorKind::Refused => "refused",
            ProbeErrorKind::HostKeyChanged => "key-rotated",
            ProbeErrorKind::AuthFailed => "auth-fail",
            ProbeErrorKind::Other => "error",
        }
    }
}

/// Classify a probe error message (best-effort string match).
///
/// TOFU key rotation shows up as a `rustls::Error::General` with a message
/// like `host key changed for X (expected ..., got ...)` — see
/// `mrsh_core::tls::TofuVerifier`.
pub fn classify_probe_error(err_msg: &str) -> ProbeErrorKind {
    let m = err_msg.to_ascii_lowercase();
    if m.contains("host key changed") {
        ProbeErrorKind::HostKeyChanged
    } else if m == "timeout" || m.contains("timed out") || m.contains("deadline") {
        ProbeErrorKind::Timeout
    } else if m.contains("refused") || m.contains("connectionrefused") {
        ProbeErrorKind::Refused
    } else if m.contains("auth") || m.contains("unauthorized") || m.contains("permission denied") {
        ProbeErrorKind::AuthFailed
    } else {
        ProbeErrorKind::Other
    }
}

/// Fleet host status after probing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostStatus {
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub online: bool,
    pub version: Option<String>,
    pub caps: Vec<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
    /// Classified error kind — None when online or when the probe was skipped.
    /// Surfaces TOFU key-rotation separately from generic "offline".
    pub error_kind: Option<ProbeErrorKind>,
    /// Device ID for relay fallback (from config).
    pub device_id: Option<String>,
    /// Rendezvous server for relay fallback.
    pub rendezvous_server: Option<String>,
    /// Rendezvous key for relay fallback.
    pub rendezvous_key: Option<String>,
    /// QUIC port for this host (None = QUIC not configured).
    pub quic_port: Option<u16>,
    /// Transport used to reach the host ("tls", "relay", "quic", "alt-port", "hbbs").
    pub transport: &'static str,
    // rsh-5264.1 heartbeat-feedback fields (sourced from rdv ListPeers).
    /// Server-reported version (from the most recent rdv heartbeat). When the
    /// peer hasn't been seen via rdv yet this is `None` and the version
    /// column falls back to the TCP-probed `version`.
    pub rdv_version: Option<String>,
    /// Server-reported last self-update outcome ("success", "failed:<reason>",
    /// "never"), or `None` when the peer is not registered with rdv.
    pub last_update_status: Option<String>,
    /// Unix timestamp of the last self-update attempt as reported via rdv,
    /// 0 when never updated, `None` when not registered with rdv.
    pub last_update_at_unix: Option<i64>,
    /// rsh-5264.5: server-reported release track ("stable", "canary", "dev").
    /// `None` when peer is on a pre-5264.5 server (column displayed as "-").
    pub track: Option<String>,
    /// rsh-5264.5: server-reported auto-upgrade opt-in. `None` when peer is on
    /// a pre-5264.5 server (treated as `false` semantically but rendered as "-").
    pub auto_upgrade: Option<bool>,
    /// rsh-x9l5: connection mode as probed during fleet status.
    /// "direct" = TLS direct (Hostname in config or mDNS-resolved IP).
    /// "rdv"    = relay / rendezvous path.
    /// "hbbs"   = seen via hbbs heartbeat only (TCP probe did not succeed).
    /// ""       = unknown / not determined.
    pub conn_mode: String,
}

/// Maximum concurrent probes.
const MAX_CONCURRENT: usize = 10;

/// Probe timeout per host.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Shorter timeout when retrying alternative ports (the host is either up or
/// not — no reason to wait long for each alt port).
const ALT_PORT_TIMEOUT: Duration = Duration::from_secs(3);

/// Max age (seconds) for hbbs registration to count as "online".
/// Peers register every 30s, so 90s = 3 missed heartbeats.
pub(super) const HBBS_ONLINE_THRESHOLD_SECS: u64 = 90;

/// Get status of all fleet hosts (current behavior, no alt-port retry).
///
/// See [`status_with_opts`] for the refresh-on-demand variant.
pub async fn status(config: &Config) -> Vec<HostStatus> {
    status_with_opts(config, StatusOpts::default()).await
}

/// Options for [`status_with_opts`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusOpts {
    /// When a host fails on its configured port, re-probe the standard
    /// mrsh auto-try ports (9822 tray / 8822 service / 22 ssh) before
    /// declaring it offline. Surfaces hosts that are up but on a different
    /// port than the one cached in the config file.
    ///
    /// This is what `mrsh fleet status --refresh` enables. Default is
    /// `false` to preserve the fast-path behavior for scripts that rely
    /// on the configured port being authoritative.
    pub refresh_alt_ports: bool,
}

/// Get status of all fleet hosts with explicit options.
///
/// Merges two sources:
/// 1. Config hosts (local `~/.mrsh/config` Host blocks) — probed via TCP, enriched with hbbs
/// 2. hbbs peers (dynamic, via `ListPeers` query) — online status from registration freshness
///
/// Config hosts take precedence: if a config host's DeviceID matches an hbbs peer,
/// the config entry is used (with its alias name and hostname override).
/// If TCP probe fails but hbbs says the peer registered recently, it's marked online via "hbbs".
/// hbbs peers not covered by config use registration freshness (no TCP probe needed).
///
/// When `opts.refresh_alt_ports` is true, hosts that fail on their configured
/// port are re-probed on the standard auto-try ports (9822/8822/22). This
/// catches cases where the host is reachable but the service has moved
/// (e.g. tray vs service port) — the common cause of stale 'offline' rows.
pub async fn status_with_opts(config: &Config, opts: StatusOpts) -> Vec<HostStatus> {
    let config_hosts: Vec<&HostConfig> = config.hosts.iter().collect();

    // Query hbbs for dynamic peers (best-effort, non-blocking)
    let hbbs_peers = discover_from_hbbs(config).await;

    // Index hbbs peers by device_id for fast lookup
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hbbs_map: std::collections::HashMap<String, &mrsh_relay::rendezvous::GroupPeerInfo> =
        hbbs_peers
            .iter()
            .map(|p| (p.device_id.clone(), p))
            .collect();

    let config_device_ids: std::collections::HashSet<String> = config_hosts
        .iter()
        .filter_map(|h| h.device_id.clone())
        .collect();

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    let mut handles = Vec::new();

    // Probe config hosts (TCP), with hbbs fallback info
    for host in &config_hosts {
        let sem = semaphore.clone();
        let name = host.pattern.clone();
        let hostname = host
            .hostname
            .clone()
            .unwrap_or_else(|| host.pattern.clone());
        let port = host.port;
        let device_id = host.device_id.clone();
        let rdv_server = config.rendezvous_server.clone();
        let rdv_key = config.rendezvous_key.clone();
        let quic_port = host.quic_port;

        // Check if hbbs knows this peer is recently active
        let hbbs_online = device_id
            .as_ref()
            .and_then(|did| hbbs_map.get(did))
            .map(|p| now_secs.saturating_sub(p.last_seen_secs) < HBBS_ONLINE_THRESHOLD_SECS)
            .unwrap_or(false);

        // rsh-5264.1: read heartbeat-feedback fields from the rdv peer record
        // (when present). They tag along into the spawned probe task and are
        // attached to the resulting HostStatus regardless of TCP probe outcome.
        // rsh-5264.5: also includes track + auto_upgrade for the staged-rollout
        // dashboard columns.
        #[allow(clippy::type_complexity)]
        let rdv_peer_data: Option<(String, String, i64, String, bool)> = device_id
            .as_ref()
            .and_then(|did| hbbs_map.get(did))
            .map(|p| {
                (
                    p.current_version.clone(),
                    p.last_update_status.clone(),
                    p.last_update_at_unix,
                    p.track.clone(),
                    p.auto_upgrade,
                )
            });

        let refresh_alt_ports = opts.refresh_alt_ports;
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let mut result = probe_host(
                &name, &hostname, port, device_id, rdv_server, rdv_key, quic_port,
            )
            .await;
            // If the direct probe failed, and the failure is not TOFU
            // key-rotation (which we want to surface separately), optionally
            // try the standard auto-try ports before giving up.
            if refresh_alt_ports
                && !result.online
                && result.error_kind != Some(ProbeErrorKind::HostKeyChanged)
            {
                if let Some(alt) = probe_alt_ports(&result).await {
                    result = alt;
                }
            }
            // If probe failed but hbbs says online, trust hbbs
            if !result.online && hbbs_online {
                result.online = true;
                result.transport = "hbbs";
                result.error = None;
                result.error_kind = None;
            }
            // rsh-5264.1: attach heartbeat-feedback fields whenever rdv knows
            // the peer (regardless of probe transport). Empty/zero values are
            // preserved as-reported by the server (older servers leave them
            // empty; the formatter renders them as "-").
            if let Some((ver, status, ts, track, auto_upgrade)) = rdv_peer_data {
                result.rdv_version = if ver.is_empty() { None } else { Some(ver) };
                result.last_update_status = if status.is_empty() {
                    None
                } else {
                    Some(status)
                };
                result.last_update_at_unix = Some(ts);
                // rsh-5264.5: surface rdv-reported track + auto_upgrade.
                // Empty track + false auto_upgrade = pre-5264.5 server (None).
                if track.is_empty() && !auto_upgrade {
                    result.track = None;
                    result.auto_upgrade = None;
                } else {
                    result.track = if track.is_empty() { None } else { Some(track) };
                    result.auto_upgrade = Some(auto_upgrade);
                }
            }
            result
        }));
    }

    // hbbs peers not in config — use registration freshness, no TCP probe
    for peer in &hbbs_peers {
        if config_device_ids.contains(&peer.device_id) {
            continue; // config host takes precedence
        }
        let name = if peer.hostname.is_empty() {
            peer.device_id.clone()
        } else {
            peer.hostname.clone()
        };
        let hostname = peer
            .addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| name.clone());
        let port = if peer.service_port > 0 {
            peer.service_port
        } else {
            8822
        };
        let online = now_secs.saturating_sub(peer.last_seen_secs) < HBBS_ONLINE_THRESHOLD_SECS;
        let device_id = Some(peer.device_id.clone());
        let rdv_server = config.rendezvous_server.clone();
        let rdv_key = config.rendezvous_key.clone();
        // rsh-5264.1 heartbeat-feedback: surface the rdv-reported values directly.
        let rdv_version = if peer.current_version.is_empty() {
            None
        } else {
            Some(peer.current_version.clone())
        };
        let last_update_status = if peer.last_update_status.is_empty() {
            None
        } else {
            Some(peer.last_update_status.clone())
        };
        let last_update_at_unix = Some(peer.last_update_at_unix);
        // rsh-5264.5: surface rdv-reported track + auto_upgrade.
        let track = if peer.track.is_empty() {
            None
        } else {
            Some(peer.track.clone())
        };
        let auto_upgrade = if peer.track.is_empty() && !peer.auto_upgrade {
            // peer is on a pre-5264.5 server (everything zero-default) →
            // distinguish from "explicit auto_upgrade=false" by emitting None.
            None
        } else {
            Some(peer.auto_upgrade)
        };
        handles.push(tokio::spawn(async move {
            HostStatus {
                name,
                hostname,
                port,
                online,
                version: None,
                caps: Vec::new(),
                latency_ms: 0,
                error: if online {
                    None
                } else {
                    Some("not registered".to_string())
                },
                error_kind: if online { None } else { Some(ProbeErrorKind::Other) },
                device_id,
                rendezvous_server: rdv_server,
                rendezvous_key: rdv_key,
                quic_port: None,
                transport: if online { "hbbs" } else { "none" },
                rdv_version,
                last_update_status,
                last_update_at_unix,
                track,
                auto_upgrade,
                conn_mode: if online { "rdv".to_string() } else { String::new() },
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(status) => results.push(status),
            Err(e) => warn!("probe task failed: {}", e),
        }
    }

    results
}

/// Probe a single host for version and capabilities.
/// Tries TLS direct first, then relay, then QUIC (if quic_port configured).
pub(super) async fn probe_host(
    name: &str,
    hostname: &str,
    port: u16,
    device_id: Option<String>,
    rdv_server: Option<String>,
    rdv_key: Option<String>,
    quic_port: Option<u16>,
) -> HostStatus {
    let start = Instant::now();
    debug!("probing {} ({}:{})", name, hostname, port);

    // Try direct TLS connection first
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let opts = crate::client::ConnectOptions {
            host: hostname.to_string(),
            port,
            key_path: None,
            password_user: None,
        };
        crate::client::connect(&opts).await
    })
    .await;

    let latency = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(client)) => HostStatus {
            name: name.to_string(),
            hostname: hostname.to_string(),
            port,
            online: true,
            version: client.server_version,
            caps: client.server_caps,
            latency_ms: latency,
            error: None,
            error_kind: None,
            device_id,
            rendezvous_server: rdv_server,
            rendezvous_key: rdv_key,
            quic_port,
            transport: "tls",
            rdv_version: None,
            last_update_status: None,
            last_update_at_unix: None,
            track: None,
            auto_upgrade: None,
            conn_mode: "direct".to_string(),
        },
        direct_err => {
            // Direct TLS failed — try relay if device_id present
            if let Some(ref dev_id) = device_id {
                let relay_start = Instant::now();
                debug!("direct failed for {}, trying relay via {}", name, dev_id);
                let relay_opts = crate::relay_connect::RelayConnectOptions {
                    device_id: dev_id.clone(),
                    rendezvous_server: rdv_server
                        .clone()
                        .unwrap_or_else(|| "rdv.example.com:21116".to_string()),
                    rendezvous_key: rdv_key.clone().unwrap_or_default(),
                    key_path: None,
                    server_name: hostname.to_string(),
                    port,
                    target_port: port,
                    force_relay: false,
                    enrollment_token: String::new(),
                    // sys-1qgww: own_device_id not available in fleet status path;
                    // fleet status probes many hosts so a self-loop is unlikely.
                    own_device_id: None,
                };
                match tokio::time::timeout(
                    Duration::from_secs(15),
                    crate::relay_connect::connect_via_relay(&relay_opts),
                )
                .await
                {
                    Ok(Ok(client)) => {
                        let relay_latency = relay_start.elapsed().as_millis() as u64;
                        return HostStatus {
                            name: name.to_string(),
                            hostname: hostname.to_string(),
                            port,
                            online: true,
                            version: client.server_version,
                            caps: client.server_caps,
                            latency_ms: relay_latency,
                            error: None,
                            error_kind: None,
                            device_id: Some(dev_id.clone()),
                            rendezvous_server: rdv_server,
                            rendezvous_key: rdv_key,
                            quic_port,
                            transport: "relay",
                            rdv_version: None,
                            last_update_status: None,
                            last_update_at_unix: None,
                            track: None,
                            auto_upgrade: None,
                            conn_mode: "rdv".to_string(),
                        };
                    }
                    Ok(Err(relay_e)) => {
                        debug!("relay also failed for {}: {}", name, relay_e);
                    }
                    Err(_) => {
                        debug!("relay timeout for {}", name);
                    }
                }
            }

            // TLS + relay failed — try QUIC if configured
            #[cfg(feature = "quic")]
            if let Some(qport) = quic_port {
                let quic_start = Instant::now();
                debug!(
                    "tls+relay failed for {}, trying QUIC on port {}",
                    name, qport
                );
                let addr_str = format!("{}:{}", hostname, qport);
                if let Ok(addr) = addr_str.parse() {
                    match tokio::time::timeout(
                        PROBE_TIMEOUT,
                        crate::quic::QuicClient::connect(addr, hostname, None),
                    )
                    .await
                    {
                        Ok(Ok(client)) => {
                            let quic_latency = quic_start.elapsed().as_millis() as u64;
                            return HostStatus {
                                name: name.to_string(),
                                hostname: hostname.to_string(),
                                port,
                                online: true,
                                version: client.server_version,
                                caps: client.server_caps,
                                latency_ms: quic_latency,
                                error: None,
                                error_kind: None,
                                device_id,
                                rendezvous_server: rdv_server,
                                rendezvous_key: rdv_key,
                                quic_port: Some(qport),
                                transport: "quic",
                                rdv_version: None,
                                last_update_status: None,
                                last_update_at_unix: None,
                                track: None,
                                auto_upgrade: None,
                                conn_mode: "direct".to_string(),
                            };
                        }
                        Ok(Err(e)) => {
                            debug!("QUIC also failed for {}: {}", name, e);
                        }
                        Err(_) => {
                            debug!("QUIC timeout for {}", name);
                        }
                    }
                }
            }

            // All transports failed
            let error_msg = match direct_err {
                Ok(Err(e)) => format!("{}", e),
                Err(_) => "timeout".to_string(),
                _ => unreachable!(),
            };
            let error_kind = classify_probe_error(&error_msg);
            HostStatus {
                name: name.to_string(),
                hostname: hostname.to_string(),
                port,
                online: false,
                version: None,
                caps: Vec::new(),
                latency_ms: latency,
                error: Some(error_msg),
                error_kind: Some(error_kind),
                device_id,
                rendezvous_server: rdv_server,
                rendezvous_key: rdv_key,
                quic_port,
                transport: "none",
                rdv_version: None,
                last_update_status: None,
                last_update_at_unix: None,
                track: None,
                auto_upgrade: None,
                conn_mode: String::new(),
            }
        }
    }
}

/// Re-probe a host on the standard auto-try ports (9822/8822/22), excluding
/// the one that was already tried in the main probe. Returns a new online
/// `HostStatus` if any alternative port answers, or `None` otherwise.
///
/// Purpose: catch hosts where the configured `HostConfig.port` is stale —
/// e.g. the tray moved from 8822 to 9822, or the service isn't installed but
/// the tray is running. Without this, fleet status reports the host as
/// offline even though `mrsh exec` (which does auto-try internally) works.
///
/// Preserves the original error + error_kind on the failed port so callers
/// can distinguish "alt-port rescue" from "clean connect".
async fn probe_alt_ports(failed: &HostStatus) -> Option<HostStatus> {
    use crate::client::{AUTO_TRY_PORTS, ConnectOptions, connect};

    for &alt_port in AUTO_TRY_PORTS {
        if alt_port == failed.port {
            continue; // already tried
        }
        let start = Instant::now();
        debug!(
            "fleet refresh: retrying {} on alt port {}",
            failed.name, alt_port
        );
        let opts = ConnectOptions {
            host: failed.hostname.clone(),
            port: alt_port,
            key_path: None,
            password_user: None,
        };
        match tokio::time::timeout(ALT_PORT_TIMEOUT, connect(&opts)).await {
            Ok(Ok(client)) => {
                let latency = start.elapsed().as_millis() as u64;
                return Some(HostStatus {
                    name: failed.name.clone(),
                    hostname: failed.hostname.clone(),
                    port: alt_port,
                    online: true,
                    version: client.server_version,
                    caps: client.server_caps,
                    latency_ms: latency,
                    // Preserve the original error so the user sees *why* the
                    // configured port didn't work (stale config signal).
                    error: failed.error.clone(),
                    error_kind: failed.error_kind,
                    device_id: failed.device_id.clone(),
                    rendezvous_server: failed.rendezvous_server.clone(),
                    rendezvous_key: failed.rendezvous_key.clone(),
                    quic_port: failed.quic_port,
                    transport: "alt-port",
                    rdv_version: None,
                    last_update_status: None,
                    last_update_at_unix: None,
                    track: None,
                    auto_upgrade: None,
                    conn_mode: "direct".to_string(),
                });
            }
            Ok(Err(e)) => debug!("alt port {} failed for {}: {}", alt_port, failed.name, e),
            Err(_) => debug!("alt port {} timeout for {}", alt_port, failed.name),
        }
    }
    None
}

/// Filter hosts that support a specific capability.
pub fn hosts_with_cap<'a>(statuses: &'a [HostStatus], cap: &str) -> Vec<&'a HostStatus> {
    statuses
        .iter()
        .filter(|s| s.online && s.caps.iter().any(|c| c == cap))
        .collect()
}
