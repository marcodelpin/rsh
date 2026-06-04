//! TCP support for the rendezvous server.
//!
//! - `tcp_notify_loop`: client-side persistent TCP connection used by NAT-ed
//!   peers to receive RelayResponse notifications reliably.
//! - `handle_tcp_relay_request`: server-side handler invoked for every
//!   inbound TCP connection on the rendezvous port.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, Instant, timeout};

use crate::codec;
use crate::proto;

use super::protocol::{RelayNotification, encode_socket_addr};
use super::server::{PeerEntry, RendezvousServer};

/// Persistent TCP notification loop: connects to hbbs, registers, and waits for
/// relay notifications over TCP. Reconnects on failure with backoff.
/// This is the NAT traversal fix: symmetric NAT blocks UDP replies from hbbs,
/// but the TCP connection initiated by us stays open through NAT.
pub(super) async fn tcp_notify_loop(
    cancel: tokio_util::sync::CancellationToken,
    relay_tx: tokio::sync::mpsc::Sender<RelayNotification>,
    // sys-8z5gn: shared with the UDP registration loop so a reconnect re-registers
    // with the freshest net-info after a local interface change.
    reg_bytes: std::sync::Arc<tokio::sync::RwLock<Vec<u8>>>,
    servers: &[String],
) {
    let mut backoff = Duration::from_secs(5);
    let max_backoff = Duration::from_secs(60);

    loop {
        if cancel.is_cancelled() {
            return;
        }

        for srv in servers {
            let stream = match timeout(Duration::from_secs(10), TcpStream::connect(srv)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!("tcp notify: connect to {} failed: {}", srv, e);
                    continue;
                }
                Err(_) => {
                    tracing::debug!("tcp notify: connect to {} timed out", srv);
                    continue;
                }
            };

            tracing::info!("tcp notify: connected to {}, registering via TCP", srv);

            // Send RegisterPeer over TCP (length-prefixed frame).
            let mut stream = stream;
            let frame = {
                let current = reg_bytes.read().await;
                codec::encode_frame(&current)
            };
            if let Err(e) = stream.write_all(&frame).await {
                tracing::warn!("tcp notify: send register to {} failed: {}", srv, e);
                continue;
            }

            // Read relay notifications until connection drops.
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    result = codec::decode_frame(&mut stream) => {
                        match result {
                            Ok(data) => {
                                if let Ok(msg) = proto::RendezvousMessage::decode(&data[..])
                                    && let Some(proto::rendezvous_message::Union::RelayResponse(rr)) = msg.union
                                        && !rr.uuid.is_empty() {
                                            tracing::info!(
                                                "tcp notify: relay notification uuid={} relay={}",
                                                rr.uuid, rr.relay_server
                                            );
                                            let _ = relay_tx.send(RelayNotification {
                                                uuid: rr.uuid,
                                                relay_server: rr.relay_server,
                                                target_port: rr.target_port as u16,
                                            }).await;
                                        }
                            }
                            Err(e) => {
                                tracing::debug!("tcp notify: read from {} failed: {}, reconnecting", srv, e);
                                break;
                            }
                        }
                    }
                }
            }

            // Reset backoff on successful connection (even if it eventually disconnected)
            backoff = Duration::from_secs(5);
        }

        // Backoff before reconnecting
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(max_backoff);
    }
}

/// Handle a TCP RequestRelay: look up target device and forward RelayResponse via UDP.
///
/// rsh-5264.6: also dispatches PublishVersion/QueryVersion/FetchBinary on the
/// same TCP listener — these messages are routed to `server.handle_message`
/// and the response is written back over the same socket via `codec::encode_frame`.
/// TCP transport is mandatory for binary blobs (>50KB) which fragment poorly
/// on UDP.
pub(super) async fn handle_tcp_relay_request(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    sock: &UdpSocket,
    relay_server: &str,
    key: &str,
    server: &RendezvousServer,
) -> Result<()> {
    let data = timeout(Duration::from_secs(10), codec::decode_frame(&mut stream))
        .await
        .context("tcp relay read timeout")?
        .context("tcp relay read")?;

    let msg = proto::RendezvousMessage::decode(&data[..]).context("decode TCP message")?;

    // rsh-5264.6: PublishVersionRequest / QueryVersionRequest / FetchBinaryRequest
    // routed via TCP. The blob payloads (publish: 7-8 MB, fetch: 7-8 MB response)
    // exceed UDP packet limits, so these MUST come through TCP.
    match &msg.union {
        Some(proto::rendezvous_message::Union::PublishVersionRequest(_))
        | Some(proto::rendezvous_message::Union::QueryVersionRequest(_))
        | Some(proto::rendezvous_message::Union::FetchBinaryRequest(_)) => {
            // Dispatch to the same handle_message logic the UDP path uses.
            // We discard the SocketAddr (handlers don't need it for these types).
            if let Some(resp) = server.handle_message(msg, peer, peers) {
                let resp_bytes = resp.encode_to_vec();
                let frame = codec::encode_frame(&resp_bytes);
                stream
                    .write_all(&frame)
                    .await
                    .context("write tcp version-rpc response")?;
            }
            return Ok(());
        }
        _ => {}
    }

    // Handle RegisterPeer via TCP: store the TCP stream for relay notifications.
    // This is the key fix for NAT-ed peers: they open a persistent TCP connection
    // to hbbs and receive relay notifications over it instead of unreliable UDP.
    if let Some(proto::rendezvous_message::Union::RegisterPeer(ref rp)) = msg.union
        && !rp.id.is_empty()
    {
        tracing::info!(
            "rdv tcp: register {} from {} (TCP notify channel)",
            rp.id,
            peer
        );
        let tcp_stream = Arc::new(tokio::sync::Mutex::new(stream));
        let mut map = peers.lock().unwrap();
        let existing = map.get(&rp.id);
        let addr = existing.map(|e| e.addr).unwrap_or(peer);
        map.insert(
            rp.id.clone(),
            PeerEntry {
                addr,
                last_seen: Instant::now(),
                group_hash: rp.group_hash.clone(),
                hostname: rp.hostname.clone(),
                platform: rp.platform.clone(),
                service_port: rp.service_port as u16,
                encrypted_net_info: rp.encrypted_net_info.clone(),
                ports: rp.ports.clone(),
                // rsh-5264.1 heartbeat-feedback
                current_version: rp.current_version.clone(),
                last_update_status: rp.last_update_status.clone(),
                last_update_at_unix: rp.last_update_at_unix,
                // rsh-5264.5 staged-rollout
                track: rp.track.clone(),
                auto_upgrade: rp.auto_upgrade,
                tcp_notify: Some(tcp_stream),
            },
        );
        // Don't return — the TCP stream is now owned by PeerEntry.
        // The connection stays open until the peer disconnects.
        return Ok(());
    }

    if let Some(proto::rendezvous_message::Union::RequestRelay(rr)) = msg.union {
        // Validate key.
        if !key.is_empty() && rr.licence_key != key {
            tracing::debug!("rdv tcp: key mismatch from {}", peer);
            return Ok(());
        }

        if rr.uuid.is_empty() {
            tracing::debug!("rdv tcp: empty UUID from {}", peer);
            return Ok(());
        }

        // Look up target device.
        let target_addr = {
            let map = peers.lock().unwrap();
            map.get(&rr.id).map(|e| e.addr)
        };

        // Look up target's TCP notify stream (for NAT-ed peers).
        let target_tcp = {
            let map = peers.lock().unwrap();
            map.get(&rr.id).and_then(|e| e.tcp_notify.clone())
        };

        if let Some(addr) = target_addr {
            let relay = if rr.relay_server.is_empty() {
                relay_server.to_string()
            } else {
                rr.relay_server
            };

            // Build RelayResponse message (forward target_port from client request).
            let response = proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::RelayResponse(
                    proto::RelayResponse {
                        uuid: rr.uuid.clone(),
                        relay_server: relay,
                        socket_addr: encode_socket_addr(&peer),
                        target_port: rr.target_port,
                        ..Default::default()
                    },
                )),
            };
            let response_bytes = response.encode_to_vec();

            // Try TCP notification first (reliable through NAT), fallback to UDP.
            let mut sent_tcp = false;
            if let Some(tcp_stream) = target_tcp {
                let frame = codec::encode_frame(&response_bytes);
                match timeout(
                    Duration::from_secs(5),
                    tcp_stream.lock().await.write_all(&frame),
                )
                .await
                {
                    Ok(Ok(())) => {
                        tracing::info!("rdv: relay {} → TCP (uuid={})", rr.id, rr.uuid);
                        sent_tcp = true;
                    }
                    _ => {
                        tracing::warn!("rdv: TCP notify to {} failed, falling back to UDP", rr.id);
                    }
                }
            }

            // Always send UDP too (belt + suspenders — dedup on receiver side).
            if !sent_tcp {
                sock.send_to(&response_bytes, addr).await?;
                tracing::info!("rdv: relay {} → {} UDP (uuid={})", rr.id, addr, rr.uuid);
            }
        } else {
            tracing::debug!("rdv: relay for {} — not registered", rr.id);
        }
    }

    Ok(())
}
