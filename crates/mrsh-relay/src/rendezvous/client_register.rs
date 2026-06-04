//! Client registration paths against hbbs.
//!
//! - `register_once`: best-effort one-shot registration on every configured server.
//! - `do_register`: low-level RegisterPeer + optional RegisterPk handshake on a UDP socket.
//! - `run_registration_loop`: persistent UDP keepalive + relay-notification listener
//!   (also spawns the TCP NAT-traversal channel from `server_tcp::tcp_notify_loop`).

use anyhow::{Context, Result, bail};
use prost::Message;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

use crate::proto;

use super::protocol::{Client, RelayNotification};
use super::server_tcp::tcp_notify_loop;

impl Client {
    /// Register with all configured rendezvous servers (best-effort).
    ///
    /// Returns Ok if at least one server accepted the registration.
    /// Suitable for calling in a periodic loop from server mode.
    pub async fn register_once(&self) -> Result<()> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }
        if self.local_id.is_empty() {
            bail!("no local_id configured for registration");
        }

        let mut any_ok = false;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if sock.connect(srv).await.is_err() {
                continue;
            }
            if let Ok(()) = self.do_register(&sock).await {
                any_ok = true
            }
        }

        if any_ok {
            Ok(())
        } else {
            bail!("registration failed on all {} servers", self.servers.len())
        }
    }

    /// Register ourselves with hbbs (RegisterPeer + optional RegisterPk).
    pub(super) async fn do_register(&self, sock: &UdpSocket) -> Result<()> {
        let our_id = if self.local_id.is_empty() {
            // Generate a transient ID from current time.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("{}", nanos % 1_000_000_000)
        } else {
            self.local_id.clone()
        };

        // Send RegisterPeer.
        let reg_msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: our_id.clone(),
                    serial: 0,
                    group_hash: self.group_hash.clone(),
                    hostname: self.hostname.clone(),
                    platform: self.platform.clone(),
                    service_port: self.service_port as i32,
                    encrypted_net_info: self.encrypted_net_info.clone(),
                    ports: self.ports.clone(),
                    // rsh-5264.1 heartbeat-feedback
                    current_version: self.current_version.clone(),
                    last_update_status: self.last_update_status.clone(),
                    last_update_at_unix: self.last_update_at_unix,
                    // rsh-5264.5 staged-rollout
                    track: self.track.clone(),
                    auto_upgrade: self.auto_upgrade,
                },
            )),
        };
        sock.send(&reg_msg.encode_to_vec())
            .await
            .context("send RegisterPeer")?;

        // Wait for RegisterPeerResponse.
        let mut buf = vec![0u8; 65535];
        let n = timeout(Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .context("RegisterPeer timeout")?
            .context("recv RegisterPeerResponse")?;

        let resp = proto::RendezvousMessage::decode(&buf[..n]).context("decode response")?;

        // If server wants our public key, send RegisterPk.
        if let Some(proto::rendezvous_message::Union::RegisterPeerResponse(pr)) = &resp.union
            && pr.request_pk
        {
            // Use a deterministic placeholder key for registration.
            let pk: Vec<u8> = (0..32u8)
                .map(|i| i.wrapping_mul(7).wrapping_add(13) % 255)
                .collect();

            let pk_msg = proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::RegisterPk(
                    proto::RegisterPk {
                        id: our_id,
                        uuid: vec![1u8; 16],
                        pk,
                        old_id: String::new(),
                        no_register_device: false,
                    },
                )),
            };
            sock.send(&pk_msg.encode_to_vec()).await?;

            // Read RegisterPkResponse.
            let n = timeout(Duration::from_secs(5), sock.recv(&mut buf))
                .await
                .context("RegisterPk timeout")?
                .context("recv RegisterPkResponse")?;
            let pk_resp = proto::RendezvousMessage::decode(&buf[..n])?;
            if let Some(proto::rendezvous_message::Union::RegisterPkResponse(r)) = pk_resp.union
                && r.result != proto::register_pk_response::Result::Ok as i32
            {
                bail!("RegisterPk rejected: {}", r.result);
            }
        }

        Ok(())
    }

    /// Build the encoded RegisterPeer message bytes for a given encrypted
    /// net-info blob. sys-8z5gn: factored out so the registration loop can
    /// rebuild it when the local interface set changes (re-announcing fresh
    /// LAN IPs to hbbs instead of the boot-time snapshot).
    fn build_register_bytes(&self, encrypted_net_info: Vec<u8>) -> Vec<u8> {
        let reg_msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: self.local_id.clone(),
                    serial: 0,
                    group_hash: self.group_hash.clone(),
                    hostname: self.hostname.clone(),
                    platform: self.platform.clone(),
                    service_port: self.service_port as i32,
                    encrypted_net_info,
                    ports: self.ports.clone(),
                    current_version: self.current_version.clone(),
                    last_update_status: self.last_update_status.clone(),
                    last_update_at_unix: self.last_update_at_unix,
                    track: self.track.clone(),
                    auto_upgrade: self.auto_upgrade,
                },
            )),
        };
        reg_msg.encode_to_vec()
    }

    /// Collect the current local interfaces off the async runtime (the Windows
    /// path shells out to PowerShell, which would block a tokio worker).
    /// Returns (debug-signature, NetworkInfo). sys-8z5gn.
    async fn collect_net_snapshot(&self) -> Option<(String, proto::NetworkInfo)> {
        let hostname = self.hostname.clone();
        let service_port = self.service_port;
        let tray_port = self.tray_port;
        let info = tokio::task::spawn_blocking(move || {
            crate::net_crypto::collect_network_info(&hostname, service_port, tray_port)
        })
        .await
        .ok()?;
        let sig = format!("{:?}", info.interfaces);
        Some((sig, info))
    }

    /// Re-encrypt the given NetworkInfo for our group. None for client-only
    /// constructions that carry no enrollment token. sys-8z5gn.
    fn encrypt_net_info(&self, info: &proto::NetworkInfo) -> Option<Vec<u8>> {
        if self.enrollment_token.is_empty() {
            return None;
        }
        let (_, group_pub) = crate::net_crypto::derive_group_keypair(&self.enrollment_token);
        crate::net_crypto::encrypt_network_info(info, &[(self.group_hash.clone(), group_pub)]).ok()
    }

    /// Run a persistent registration loop that also listens for relay notifications.
    ///
    /// Unlike `register_once()` which creates ephemeral sockets, this maintains
    /// a persistent UDP socket so hbbs can send RelayResponse notifications when
    /// a client requests relay connection to this device.
    ///
    /// Relay notifications are sent to `relay_tx`. The caller should spawn a handler
    /// that connects to hbbr with the UUID and accepts the incoming TLS connection.
    pub async fn run_registration_loop(
        &self,
        cancel: tokio_util::sync::CancellationToken,
        relay_tx: tokio::sync::mpsc::Sender<RelayNotification>,
    ) {
        if self.servers.is_empty() || self.local_id.is_empty() {
            tracing::warn!("rendezvous loop: no servers or no device_id, not starting");
            return;
        }

        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("rendezvous loop: bind failed: {}", e);
                return;
            }
        };

        // Resolve server addresses.
        let mut server_addrs = Vec::new();
        for srv in &self.servers {
            match tokio::net::lookup_host(srv).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        server_addrs.push(addr);
                    }
                }
                Err(e) => tracing::warn!("rendezvous loop: resolve {}: {}", srv, e),
            }
        }

        if server_addrs.is_empty() {
            tracing::warn!("rendezvous loop: no servers resolved");
            return;
        }

        // sys-8z5gn: the encrypted net-info is recomputed when local interfaces
        // change, so the registration bytes live behind a shared lock that both
        // this UDP loop and the spawned TCP notify loop read from.
        let reg_shared = std::sync::Arc::new(tokio::sync::RwLock::new(
            self.build_register_bytes(self.encrypted_net_info.clone()),
        ));
        // Interface signature we last advertised (for change detection).
        let mut last_iface_sig = self
            .collect_net_snapshot()
            .await
            .map(|(sig, _)| sig)
            .unwrap_or_default();
        // Re-check local interfaces periodically; re-announce on change.
        let mut net_refresh = tokio::time::interval(Duration::from_secs(60));
        net_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // 10s keepalive — must be well under typical NAT UDP timeout (30-60s)
        // to keep the UDP mapping alive for relay notifications from hbbs.
        // Aggressive keepalive is critical for NAT traversal reliability.
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        let mut buf = vec![0u8; 65535];

        if !self.group_hash.is_empty() {
            tracing::info!(
                "rendezvous loop: DeviceID {} (group enrolled), listening for relay",
                self.local_id
            );
        } else {
            tracing::info!(
                "rendezvous loop: DeviceID {}, listening for relay",
                self.local_id
            );
        }

        // Spawn TCP notification listener for NAT traversal.
        // Opens a persistent TCP connection to hbbs, sends RegisterPeer,
        // and listens for RelayResponse. This works through symmetric NAT
        // where UDP notifications from hbbs cannot reach us.
        {
            let tcp_cancel = cancel.clone();
            let tcp_relay_tx = relay_tx.clone();
            let tcp_reg_shared = reg_shared.clone();
            let tcp_servers = self.servers.clone();
            tokio::spawn(async move {
                tcp_notify_loop(tcp_cancel, tcp_relay_tx, tcp_reg_shared, &tcp_servers).await;
            });
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::debug!("rendezvous loop: cancelled");
                    return;
                }
                _ = interval.tick() => {
                    let bytes = reg_shared.read().await.clone();
                    for addr in &server_addrs {
                        let _ = sock.send_to(&bytes, addr).await;
                    }
                }
                _ = net_refresh.tick() => {
                    // sys-8z5gn: re-announce LAN IPs if the local interface set
                    // changed since the last advert (the boot-time snapshot goes
                    // stale on WiFi reconnect / dock change / VPN up-down).
                    if let Some((sig, info)) = self.collect_net_snapshot().await
                        && sig != last_iface_sig
                    {
                        last_iface_sig = sig;
                        if let Some(blob) = self.encrypt_net_info(&info) {
                            let bytes = self.build_register_bytes(blob);
                            *reg_shared.write().await = bytes.clone();
                            tracing::info!(
                                "rendezvous: local interfaces changed, re-announcing net info"
                            );
                            for addr in &server_addrs {
                                let _ = sock.send_to(&bytes, addr).await;
                            }
                        }
                    }
                }
                result = sock.recv_from(&mut buf) => {
                    if let Ok((n, _src)) = result
                        && let Ok(msg) = proto::RendezvousMessage::decode(&buf[..n]) {
                            match msg.union {
                                Some(proto::rendezvous_message::Union::RegisterPeerResponse(_)) => {
                                    tracing::debug!("rendezvous: registered");
                                }
                                Some(proto::rendezvous_message::Union::RegisterPkResponse(_)) => {
                                    tracing::debug!("rendezvous: pk registered");
                                }
                                Some(proto::rendezvous_message::Union::RelayResponse(rr)) => {
                                    if !rr.uuid.is_empty() {
                                        tracing::info!(
                                            "rendezvous: relay notification uuid={} relay={}",
                                            rr.uuid, rr.relay_server
                                        );
                                        let _ = relay_tx.send(RelayNotification {
                                            uuid: rr.uuid,
                                            relay_server: rr.relay_server,
                                            target_port: rr.target_port as u16,
                                        }).await;
                                    }
                                }
                                _ => {}
                            }
                        }
                }
            }
        }
    }
}
