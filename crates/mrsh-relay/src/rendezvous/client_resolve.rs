//! Resolve a DeviceID against hbbs and request relay routing.
//!
//! - `resolve` / `resolve_with_port`: high-level public API.
//! - `try_server` / `try_server_with_port`: per-server attempt.
//! - `do_punch_hole` + `handle_punch_hole_response`: PunchHoleRequest exchange.
//! - `request_relay_uuid` / `request_relay_uuid_with_port`: TCP RequestRelay.

use anyhow::{Context, Result, bail};
use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, timeout};

use crate::codec;
use crate::proto;

use super::protocol::{Client, ResolveResult, decode_socket_addr, make_uuid};

impl Client {
    /// Resolve a device ID by trying each configured server.
    /// Resolve a DeviceID, optionally requesting a specific target port on the device.
    /// `target_port` = 0 means default (service port 8822), 9822 = tray.
    pub async fn resolve_with_port(
        &self,
        device_id: &str,
        target_port: u16,
    ) -> Result<ResolveResult> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let mut last_err = None;
        for srv in &self.servers {
            match self.try_server_with_port(device_id, srv, target_port).await {
                Ok(r) => return Ok(r),
                Err(e) => last_err = Some(e),
            }
        }
        bail!(
            "all {} servers failed; last: {}",
            self.servers.len(),
            last_err.unwrap()
        );
    }

    pub async fn resolve(&self, device_id: &str) -> Result<ResolveResult> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let mut last_err = None;
        for srv in &self.servers {
            match self.try_server(device_id, srv).await {
                Ok(r) => return Ok(r),
                Err(e) => last_err = Some(e),
            }
        }
        bail!(
            "all {} servers failed; last: {}",
            self.servers.len(),
            last_err.unwrap()
        );
    }

    /// Full resolution against a single server.
    async fn try_server_with_port(
        &self,
        device_id: &str,
        server: &str,
        target_port: u16,
    ) -> Result<ResolveResult> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?;
        sock.connect(server).await.context("connect UDP")?;
        let _ = self.do_register(&sock).await;
        let result = self.do_punch_hole(&sock, device_id).await?;
        if !result.relay_server.is_empty() && result.uuid.is_empty() {
            let mut result = result;
            if let Ok(uuid) = self
                .request_relay_uuid_with_port(server, device_id, &result.relay_server, target_port)
                .await
            {
                result.uuid = uuid;
            }
            return Ok(result);
        }
        Ok(result)
    }

    async fn try_server(&self, device_id: &str, server: &str) -> Result<ResolveResult> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?;
        sock.connect(server).await.context("connect UDP")?;

        // Best-effort self-registration (not fatal if it fails).
        let _ = self.do_register(&sock).await;

        // Punch hole to locate the target peer.
        let result = self.do_punch_hole(&sock, device_id).await?;

        // If relay is indicated but no UUID yet, request one via TCP.
        if !result.relay_server.is_empty() && result.uuid.is_empty() {
            let mut result = result;
            if let Ok(uuid) = self
                .request_relay_uuid(server, device_id, &result.relay_server)
                .await
            {
                result.uuid = uuid;
            }
            return Ok(result);
        }

        Ok(result)
    }

    /// Send PunchHoleRequest and wait for a response (retries every 3s, 15s deadline).
    async fn do_punch_hole(&self, sock: &UdpSocket, device_id: &str) -> Result<ResolveResult> {
        let req = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(
                proto::PunchHoleRequest {
                    id: device_id.to_string(),
                    nat_type: proto::NatType::Asymmetric as i32,
                    licence_key: self.licence_key.clone(),
                    conn_type: proto::ConnType::DefaultConn as i32,
                    version: "1.2.7".to_string(),
                    ..Default::default()
                },
            )),
        };
        let req_bytes = req.encode_to_vec();

        let deadline = Instant::now() + Duration::from_secs(15);
        let interval = Duration::from_secs(3);
        let mut last_sent = Instant::now() - interval; // force immediate first send
        let mut buf = vec![0u8; 65535];

        while Instant::now() < deadline {
            if last_sent.elapsed() >= interval {
                sock.send(&req_bytes)
                    .await
                    .context("send PunchHoleRequest")?;
                last_sent = Instant::now();
            }

            let n = match timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => continue,
            };

            let msg = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(m) => m,
                Err(_) => continue,
            };

            match msg.union {
                Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                    return self.handle_punch_hole_response(phr, device_id);
                }
                Some(proto::rendezvous_message::Union::FetchLocalAddr(fla)) => {
                    // Same-LAN detection: hbbs tells us to connect directly.
                    // rsh-64x9 2026-05-21: same-NAT peers also benefit from LAN
                    // discovery — propagate encrypted_net_info from response so
                    // client can decrypt + probe direct LAN/ZT paths.
                    let relay = fla.relay_server;
                    let net_info = fla.encrypted_net_info;
                    if !fla.socket_addr.is_empty() {
                        let addr = decode_socket_addr(&fla.socket_addr)?;
                        return Ok(ResolveResult {
                            addr: Some(addr),
                            relay_server: relay,
                            uuid: String::new(),
                            encrypted_net_info: net_info,
                        });
                    }
                    if !relay.is_empty() {
                        return Ok(ResolveResult {
                            addr: None,
                            relay_server: relay,
                            uuid: String::new(),
                            encrypted_net_info: net_info,
                        });
                    }
                }
                _ => continue,
            }
        }

        bail!("device {:?}: no response after 15s", device_id);
    }

    fn handle_punch_hole_response(
        &self,
        phr: proto::PunchHoleResponse,
        device_id: &str,
    ) -> Result<ResolveResult> {
        use proto::punch_hole_response::Failure;
        let failure = Failure::try_from(phr.failure).unwrap_or(Failure::IdNotExist);

        match failure {
            Failure::Offline => bail!("device {:?} is offline", device_id),
            Failure::LicenseMismatch => bail!("licence key mismatch"),
            Failure::LicenseOveruse => bail!("licence overuse"),
            _ => {}
        }

        // Direct address available.
        if !phr.socket_addr.is_empty() {
            let addr = decode_socket_addr(&phr.socket_addr)?;
            return Ok(ResolveResult {
                addr: Some(addr),
                relay_server: phr.relay_server,
                uuid: String::new(),
                encrypted_net_info: phr.encrypted_net_info,
            });
        }

        if failure == Failure::IdNotExist {
            bail!("device {:?} not found on rendezvous server", device_id);
        }

        // Relay-only path.
        if !phr.relay_server.is_empty() {
            return Ok(ResolveResult {
                addr: None,
                relay_server: phr.relay_server,
                uuid: String::new(),
                encrypted_net_info: phr.encrypted_net_info,
            });
        }

        if !phr.other_failure.is_empty() {
            bail!("rendezvous error: {}", phr.other_failure);
        }

        bail!("device {:?}: empty response", device_id);
    }

    /// Request a relay UUID from hbbs via TCP (BytesCodec framed).
    async fn request_relay_uuid_with_port(
        &self,
        server: &str,
        device_id: &str,
        relay_server: &str,
        target_port: u16,
    ) -> Result<String> {
        let uuid = make_uuid();
        let tcp = tokio::net::TcpStream::connect(server)
            .await
            .context("TCP connect to hbbs")?;
        let mut tcp = tokio::io::BufWriter::new(tcp);
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    id: device_id.to_string(),
                    uuid: uuid.clone(),
                    relay_server: relay_server.to_string(),
                    licence_key: self.licence_key.clone(),
                    conn_type: proto::ConnType::DefaultConn as i32,
                    target_port: target_port as i32,
                    ..Default::default()
                },
            )),
        };
        codec::write_frame(&mut tcp, &msg.encode_to_vec()).await?;
        tcp.flush().await?;
        Ok(uuid)
    }

    async fn request_relay_uuid(
        &self,
        server: &str,
        device_id: &str,
        relay_server: &str,
    ) -> Result<String> {
        let uuid = make_uuid();

        let tcp = tokio::net::TcpStream::connect(server)
            .await
            .context("TCP connect to hbbs")?;
        let mut tcp = tokio::io::BufWriter::new(tcp);

        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    id: device_id.to_string(),
                    uuid: uuid.clone(),
                    relay_server: relay_server.to_string(),
                    licence_key: self.licence_key.clone(),
                    conn_type: proto::ConnType::DefaultConn as i32,
                    ..Default::default()
                },
            )),
        };

        codec::write_frame(&mut tcp, &msg.encode_to_vec()).await?;
        tcp.flush().await?;

        Ok(uuid)
    }
}
