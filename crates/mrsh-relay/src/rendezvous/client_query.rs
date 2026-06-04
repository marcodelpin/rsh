//! Client queries against hbbs that return *lists* of peers.
//!
//! - `query_group`: peers sharing an enrollment-token group_hash.
//! - `list_peers`: every peer registered at hbbs (auth'd by licence_key).

use anyhow::{Result, bail};
use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};

use crate::codec;
use crate::proto;

/// rsh-5264.6: payload size threshold at which `publish_version` switches to
/// TCP transport. UDP packets above ~32KB fragment poorly across networks; we
/// cap well below the 64KB UDP datagram theoretical max to leave headroom for
/// proto framing.
const TCP_TRANSPORT_THRESHOLD: usize = 32 * 1024;

/// rsh-5264.6: timeout for TCP publish/fetch operations. Generous because the
/// blob (~7-8 MB) needs to land before the rdv server replies.
const TCP_RPC_TIMEOUT: Duration = Duration::from_secs(60);

use super::protocol::{Client, GroupPeerInfo, decode_socket_addr};

impl Client {
    /// Query the rendezvous server for all peers in a group.
    ///
    /// `enrollment_token` is the raw token (base64). The proof is the hash of
    /// the token, which the server verifies matches the stored group_hash.
    /// (The nonce is the current unix timestamp, server rejects >300s drift.)
    pub async fn query_group(&self, enrollment_token: &str) -> Result<Vec<GroupPeerInfo>> {
        use sha2::{Digest, Sha256};

        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        // Compute group_hash = hash of token, hex-encoded.
        let group_hash = {
            let mut h = Sha256::new();
            h.update(enrollment_token.as_bytes());
            hex::encode(h.finalize())
        };

        // Nonce = current unix timestamp
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // hmac_proof = raw token bytes (server hashes it and compares to group_hash)
        let hmac_proof = enrollment_token.as_bytes().to_vec();

        let gq = proto::GroupQuery {
            group_hash,
            hmac_proof,
            nonce,
        };

        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::GroupQuery(gq)),
        };
        let msg_bytes = msg.encode_to_vec();

        let mut last_err = None;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("bind: {e}"));
                    continue;
                }
            };
            if let Err(e) = sock.connect(srv).await {
                last_err = Some(anyhow::anyhow!("connect {srv}: {e}"));
                continue;
            }
            if let Err(e) = sock.send(&msg_bytes).await {
                last_err = Some(anyhow::anyhow!("send to {srv}: {e}"));
                continue;
            }

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!("timeout from {srv}"));
                    continue;
                }
            };

            let resp = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };

            if let Some(proto::rendezvous_message::Union::GroupQueryResponse(gqr)) = resp.union {
                let peers = gqr
                    .peers
                    .into_iter()
                    .map(|p| {
                        let addr = if p.socket_addr.is_empty() {
                            None
                        } else {
                            decode_socket_addr(&p.socket_addr).ok()
                        };
                        GroupPeerInfo {
                            device_id: p.device_id,
                            hostname: p.hostname,
                            platform: p.platform,
                            addr,
                            last_seen_secs: p.last_seen_secs,
                            service_port: p.service_port as u16,
                            encrypted_net_info: p.encrypted_net_info,
                            // rsh-5264.1 heartbeat-feedback
                            current_version: p.current_version,
                            last_update_status: p.last_update_status,
                            last_update_at_unix: p.last_update_at_unix,
                            // rsh-5264.5 staged-rollout
                            track: p.track,
                            auto_upgrade: p.auto_upgrade,
                        }
                    })
                    .collect();
                return Ok(peers);
            }

            last_err = Some(anyhow::anyhow!("unexpected response from {srv}"));
        }

        bail!(
            "group query failed on all servers; last: {}",
            last_err.unwrap_or_else(|| anyhow::anyhow!("no servers"))
        );
    }

    /// List ALL peers registered at hbbs (authenticated by licence_key).
    pub async fn list_peers(&self) -> Result<Vec<GroupPeerInfo>> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let lp = proto::ListPeers {
            licence_key: self.licence_key.clone(),
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::ListPeers(lp)),
        };
        let msg_bytes = msg.encode_to_vec();

        let mut last_err = None;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("bind: {e}"));
                    continue;
                }
            };
            if let Err(e) = sock.connect(srv).await {
                last_err = Some(anyhow::anyhow!("connect {srv}: {e}"));
                continue;
            }
            if let Err(e) = sock.send(&msg_bytes).await {
                last_err = Some(anyhow::anyhow!("send to {srv}: {e}"));
                continue;
            }

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!("timeout from {srv}"));
                    continue;
                }
            };

            let resp = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };

            if let Some(proto::rendezvous_message::Union::ListPeersResponse(lpr)) = resp.union {
                let peers = lpr
                    .peers
                    .into_iter()
                    .map(|p| {
                        let addr = if p.socket_addr.is_empty() {
                            None
                        } else {
                            decode_socket_addr(&p.socket_addr).ok()
                        };
                        GroupPeerInfo {
                            device_id: p.device_id,
                            hostname: p.hostname,
                            platform: p.platform,
                            addr,
                            last_seen_secs: p.last_seen_secs,
                            service_port: p.service_port as u16,
                            encrypted_net_info: p.encrypted_net_info,
                            // rsh-5264.1 heartbeat-feedback
                            current_version: p.current_version,
                            last_update_status: p.last_update_status,
                            last_update_at_unix: p.last_update_at_unix,
                            // rsh-5264.5 staged-rollout
                            track: p.track,
                            auto_upgrade: p.auto_upgrade,
                        }
                    })
                    .collect();
                return Ok(peers);
            }

            last_err = Some(anyhow::anyhow!("unexpected response from {srv}"));
        }

        bail!(
            "list_peers failed on all servers; last: {}",
            last_err.unwrap_or_else(|| anyhow::anyhow!("no servers"))
        );
    }

    /// rsh-5264.3: publish a `VersionAdvert` to rdv (operator side).
    ///
    /// `binary_blob` is optional — pass an empty slice when the binary is
    /// distributed out-of-band (the advert just carries platform/track/version
    /// + signature). `operator_signature` is an Ed25519 signature over
    /// `advert.operator_signing_payload()` produced with the release-signing
    /// private key. While the rdv server's embedded
    /// `SIGNING_PUBLIC_KEY_PEM` is empty, the server accepts permissively;
    /// callers SHOULD still attach a real operator signature so the server
    /// can audit-log it.
    pub async fn publish_version(
        &self,
        advert: super::protocol::VersionAdvert,
        binary_blob: Vec<u8>,
        operator_signature: Vec<u8>,
    ) -> Result<()> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let req = proto::PublishVersionRequest {
            advert: Some(advert.to_proto()),
            binary_blob,
            operator_signature,
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PublishVersionRequest(
                req,
            )),
        };
        let msg_bytes = msg.encode_to_vec();

        // rsh-5264.6: payloads above TCP_TRANSPORT_THRESHOLD must use TCP.
        // Release binaries are ~7-8 MB and fragment poorly on UDP. The codec
        // (length-prefixed framing) handles up to 50 MB.
        if msg_bytes.len() > TCP_TRANSPORT_THRESHOLD {
            return publish_version_tcp(&self.servers, &msg_bytes).await;
        }

        let mut last_err = None;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("bind: {e}"));
                    continue;
                }
            };
            if let Err(e) = sock.connect(srv).await {
                last_err = Some(anyhow::anyhow!("connect {srv}: {e}"));
                continue;
            }
            if let Err(e) = sock.send(&msg_bytes).await {
                last_err = Some(anyhow::anyhow!("send to {srv}: {e}"));
                continue;
            }

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!("timeout from {srv}"));
                    continue;
                }
            };

            let resp = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };

            if let Some(proto::rendezvous_message::Union::PublishVersionResponse(pvr)) = resp.union
            {
                if pvr.accepted {
                    return Ok(());
                }
                bail!("rdv rejected publish: {}", pvr.error_message);
            }

            last_err = Some(anyhow::anyhow!("unexpected response from {srv}"));
        }

        bail!(
            "publish_version failed on all servers; last: {}",
            last_err.unwrap_or_else(|| anyhow::anyhow!("no servers"))
        );
    }

    /// rsh-5264.6: fetch the inline binary blob for a published advert from rdv.
    ///
    /// Operator-side flow `mrsh rdv publish --blob` stores the binary inline
    /// on the rdv. Server-side `self-update-from-rdv` calls this to retrieve
    /// the bytes after `query_version` returned the advert metadata.
    ///
    /// Always uses TCP — the response (binary blob, ~7-8 MB) is far above the
    /// UDP packet limit. Returns `Ok((blob, signature))` on success or
    /// `Err(...)` when rdv has no advert / version mismatch / blob is empty
    /// (publish was `--no-blob`).
    pub async fn fetch_binary(
        &self,
        platform: &str,
        track: &str,
        version: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let req = proto::FetchBinaryRequest {
            platform: platform.to_string(),
            track: track.to_string(),
            version: version.to_string(),
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::FetchBinaryRequest(req)),
        };
        let msg_bytes = msg.encode_to_vec();

        let mut last_err = None;
        for srv in &self.servers {
            match fetch_binary_one(srv, &msg_bytes).await {
                Ok(resp) => {
                    if !resp.found {
                        bail!("rdv: {}", resp.error_message);
                    }
                    return Ok((resp.binary_blob, resp.signature));
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        bail!(
            "fetch_binary failed on all servers; last: {}",
            last_err.unwrap_or_else(|| anyhow::anyhow!("no servers"))
        );
    }

    /// rsh-5264.3: query rdv for the latest version on a given (platform, track) tuple.
    ///
    /// Returns `Ok(None)` when no advert exists or the server reports
    /// `update_available=false`. Returns `Ok(Some(advert))` when an update is
    /// available.
    pub async fn query_version(
        &self,
        platform: &str,
        track: &str,
        current_version: &str,
    ) -> Result<Option<super::protocol::VersionAdvert>> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let req = proto::QueryVersionRequest {
            platform: platform.to_string(),
            track: track.to_string(),
            current_version: current_version.to_string(),
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::QueryVersionRequest(req)),
        };
        let msg_bytes = msg.encode_to_vec();

        let mut last_err = None;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("bind: {e}"));
                    continue;
                }
            };
            if let Err(e) = sock.connect(srv).await {
                last_err = Some(anyhow::anyhow!("connect {srv}: {e}"));
                continue;
            }
            if let Err(e) = sock.send(&msg_bytes).await {
                last_err = Some(anyhow::anyhow!("send to {srv}: {e}"));
                continue;
            }

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!("timeout from {srv}"));
                    continue;
                }
            };

            let resp = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };

            if let Some(proto::rendezvous_message::Union::QueryVersionResponse(qvr)) = resp.union {
                if !qvr.update_available {
                    return Ok(None);
                }
                return Ok(qvr
                    .advert
                    .as_ref()
                    .map(super::protocol::VersionAdvert::from_proto));
            }

            last_err = Some(anyhow::anyhow!("unexpected response from {srv}"));
        }

        bail!(
            "query_version failed on all servers; last: {}",
            last_err.unwrap_or_else(|| anyhow::anyhow!("no servers"))
        );
    }
}

// ── rsh-5264.6 TCP transport helpers ─────────────────────────────────────────

/// Send a `PublishVersionRequest` over TCP, framing with `codec::encode_frame`.
/// Iterates `servers` until one accepts the publish.
async fn publish_version_tcp(servers: &[String], msg_bytes: &[u8]) -> Result<()> {
    let mut last_err = None;
    for srv in servers {
        match publish_version_tcp_one(srv, msg_bytes).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!("publish_version_tcp to {} failed: {}", srv, e);
                last_err = Some(e);
            }
        }
    }
    bail!(
        "publish_version (TCP) failed on all servers; last: {}",
        last_err.unwrap_or_else(|| anyhow::anyhow!("no servers"))
    );
}

async fn publish_version_tcp_one(srv: &str, msg_bytes: &[u8]) -> Result<()> {
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(srv))
        .await
        .map_err(|_| anyhow::anyhow!("tcp connect to {} timed out", srv))?
        .map_err(|e| anyhow::anyhow!("tcp connect to {}: {}", srv, e))?;

    let frame = codec::encode_frame(msg_bytes);
    timeout(TCP_RPC_TIMEOUT, stream.write_all(&frame))
        .await
        .map_err(|_| anyhow::anyhow!("tcp publish write to {} timed out", srv))?
        .map_err(|e| anyhow::anyhow!("tcp publish write: {}", e))?;

    let resp_bytes = timeout(TCP_RPC_TIMEOUT, codec::decode_frame(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("tcp publish read from {} timed out", srv))?
        .map_err(|e| anyhow::anyhow!("tcp publish read: {}", e))?;

    let resp = proto::RendezvousMessage::decode(&resp_bytes[..])
        .map_err(|e| anyhow::anyhow!("decode tcp publish response: {}", e))?;

    if let Some(proto::rendezvous_message::Union::PublishVersionResponse(pvr)) = resp.union {
        if pvr.accepted {
            return Ok(());
        }
        bail!("rdv rejected publish: {}", pvr.error_message);
    }
    bail!("unexpected response type from {}", srv);
}

/// Send a `FetchBinaryRequest` over TCP and return the response. Always TCP
/// because the response carries the inline binary blob (megabytes).
async fn fetch_binary_one(srv: &str, msg_bytes: &[u8]) -> Result<proto::FetchBinaryResponse> {
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(srv))
        .await
        .map_err(|_| anyhow::anyhow!("tcp connect to {} timed out", srv))?
        .map_err(|e| anyhow::anyhow!("tcp connect to {}: {}", srv, e))?;

    let frame = codec::encode_frame(msg_bytes);
    timeout(TCP_RPC_TIMEOUT, stream.write_all(&frame))
        .await
        .map_err(|_| anyhow::anyhow!("tcp fetch write to {} timed out", srv))?
        .map_err(|e| anyhow::anyhow!("tcp fetch write: {}", e))?;

    let resp_bytes = timeout(TCP_RPC_TIMEOUT, codec::decode_frame(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("tcp fetch read from {} timed out", srv))?
        .map_err(|e| anyhow::anyhow!("tcp fetch read: {}", e))?;

    let resp = proto::RendezvousMessage::decode(&resp_bytes[..])
        .map_err(|e| anyhow::anyhow!("decode tcp fetch response: {}", e))?;

    match resp.union {
        Some(proto::rendezvous_message::Union::FetchBinaryResponse(fbr)) => Ok(fbr),
        _ => bail!("unexpected response type from {}", srv),
    }
}
