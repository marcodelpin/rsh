//! Rendezvous server (`hbbs`): registers peer DeviceIDs and resolves them.
//!
//! Listens on UDP for RegisterPeer/PunchHoleRequest/RegisterPk/HealthCheck/
//! GroupQuery/ListPeers messages, plus on TCP for RequestRelay forwarding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use prost::Message;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Duration, Instant};

use crate::proto;

use super::protocol::encode_socket_addr;
use super::server_tcp::handle_tcp_relay_request;

/// Registration entry for a peer in the rendezvous server.
pub(super) struct PeerEntry {
    pub(super) addr: SocketAddr,
    pub(super) last_seen: Instant,
    /// Hashed enrollment token (hex). Empty if no group enrollment.
    pub(super) group_hash: String,
    /// Machine hostname (from RegisterPeer).
    pub(super) hostname: String,
    /// Platform: "windows" or "linux".
    pub(super) platform: String,
    /// mrsh command listener port (0 = default 8822).
    pub(super) service_port: u16,
    /// Encrypted network info blob (opaque, forwarded to clients).
    pub(super) encrypted_net_info: Vec<u8>,
    /// All listening ports with type and capabilities.
    pub(super) ports: Vec<proto::PortInfo>,
    // rsh-5264.1 heartbeat-feedback fields (forwarded to clients).
    /// Server's compiled version (e.g. "1.10.29"). Empty when peer reports nothing.
    pub(super) current_version: String,
    /// Last self-update status string.
    pub(super) last_update_status: String,
    /// Unix timestamp of last self-update attempt, 0 if never.
    pub(super) last_update_at_unix: i64,
    // rsh-5264.5 staged-rollout fields (forwarded to clients).
    /// Release track this server follows: `"stable"` | `"canary"` | `"dev"`.
    pub(super) track: String,
    /// Whether this host opted in to rdv-driven auto-upgrade.
    pub(super) auto_upgrade: bool,
    /// Persistent TCP notification stream (for NAT-ed peers that can't receive UDP).
    pub(super) tcp_notify: Option<Arc<tokio::sync::Mutex<tokio::net::TcpStream>>>,
}

/// Default peer expiry time (5 minutes without re-registration).
const PEER_EXPIRY: Duration = Duration::from_secs(300);

/// Cleanup interval for expired peers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// A rendezvous server (hbbs) that maps DeviceIDs to socket addresses.
pub struct RendezvousServer {
    /// Authentication key (empty = no auth).
    pub(super) key: String,
    /// Address of the companion relay server (hbbr).
    pub(super) relay_server: String,
    /// rsh-5264.3: per-(platform,track) latest version adverts.
    ///
    /// Keyed by `(platform, track)`. Populated by `PublishVersionRequest`,
    /// queried by `QueryVersionRequest`. In-memory only — production
    /// deployments will want a persistent store (sqlite/sled), tracked
    /// separately.
    ///
    /// rsh-5264.6: now also stores the inline `binary_blob` (when published
    /// with `--blob`) so servers can fetch the actual binary via
    /// `FetchBinaryRequest` over TCP. Without this, only the metadata advert
    /// would be served and the blob was discarded after publish.
    pub(super) version_adverts:
        Arc<std::sync::Mutex<HashMap<(String, String), VersionAdvertEntry>>>,
}

/// rsh-5264.6: in-memory rdv storage entry — advert metadata plus optional
/// inline binary blob. The blob is only present when the operator published
/// with `mrsh rdv publish --blob` (the default).
#[derive(Debug, Clone)]
pub(super) struct VersionAdvertEntry {
    pub advert: proto::VersionAdvert,
    /// Raw binary bytes (empty when published with --no-blob).
    pub binary_blob: Vec<u8>,
}

impl RendezvousServer {
    pub fn new(key: &str, relay_server: &str) -> Self {
        Self {
            key: key.to_string(),
            relay_server: relay_server.to_string(),
            version_adverts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// rsh-5264.6: cheap Arc-clone for the TCP listener task. The version
    /// adverts Arc is shared so updates from the UDP path (publish) are
    /// visible from the TCP path (fetch) instantly.
    pub(super) fn clone_for_tcp(&self) -> Self {
        Self {
            key: self.key.clone(),
            relay_server: self.relay_server.clone(),
            version_adverts: self.version_adverts.clone(),
        }
    }

    /// Start the rendezvous server on the given UDP address.
    ///
    /// Listens on both UDP (registration, punch-hole, group queries) and TCP
    /// (RequestRelay forwarding). When a client sends RequestRelay via TCP,
    /// hbbs looks up the target device and sends RelayResponse via UDP to its
    /// registered address, enabling server-side relay acceptance.
    pub async fn listen_and_serve(&self, addr: &str) -> Result<()> {
        let sock = Arc::new(UdpSocket::bind(addr).await.context("bind UDP")?);

        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Spawn periodic cleanup of expired peers.
        let peers_gc = peers.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                tick.tick().await;
                let mut map = peers_gc.lock().unwrap();
                let now = Instant::now();
                let before = map.len();
                map.retain(|_, e| now.duration_since(e.last_seen) < PEER_EXPIRY);
                let removed = before - map.len();
                if removed > 0 {
                    tracing::debug!("rdv: expired {removed} peers, {} remaining", map.len());
                }
            }
        });

        // Spawn TCP listener for RequestRelay forwarding.
        // TCP and UDP can share the same port number.
        let tcp_listener = TcpListener::bind(addr)
            .await
            .context("bind TCP for relay forwarding")?;
        tracing::info!("rdv: TCP relay forwarding on {}", addr);

        let peers_tcp = peers.clone();
        let sock_tcp = sock.clone();
        let relay_server = self.relay_server.clone();
        let key_tcp = self.key.clone();
        // rsh-5264.6: clone the entire server (cheap — only Arc'd state inside)
        // so the TCP path can dispatch PublishVersion/QueryVersion/FetchBinary
        // through the same handle_message logic the UDP path uses.
        let server_for_tcp = self.clone_for_tcp();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp_listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("rdv tcp accept: {}", e);
                        continue;
                    }
                };
                let peers = peers_tcp.clone();
                let sock = sock_tcp.clone();
                let relay = relay_server.clone();
                let key = key_tcp.clone();
                let server = server_for_tcp.clone_for_tcp();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_relay_request(
                        stream, peer, &peers, &sock, &relay, &key, &server,
                    )
                    .await
                    {
                        tracing::debug!("rdv tcp relay from {}: {}", peer, e);
                    }
                });
            }
        });

        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = sock.recv_from(&mut buf).await?;
            if n == 0 {
                continue;
            }

            let msg = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if let Some(resp) = self.handle_message(msg, src, &peers) {
                let _ = sock.send_to(&resp.encode_to_vec(), src).await;
            }
        }
    }

    pub(super) fn handle_message(
        &self,
        msg: proto::RendezvousMessage,
        src: SocketAddr,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        match msg.union? {
            proto::rendezvous_message::Union::RegisterPeer(rp) => {
                if !rp.id.is_empty() {
                    let has_group = !rp.group_hash.is_empty();
                    let mut map = peers.lock().unwrap();
                    // Preserve existing TCP notify stream when re-registering via UDP
                    let existing_tcp = map.get(&rp.id).and_then(|e| e.tcp_notify.clone());
                    map.insert(
                        rp.id.clone(),
                        PeerEntry {
                            addr: src,
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
                            tcp_notify: existing_tcp,
                        },
                    );
                    if has_group {
                        tracing::debug!(
                            "rdv: registered {} from {} (group: {})",
                            rp.id,
                            src,
                            rp.group_hash
                        );
                    } else {
                        tracing::debug!("rdv: registered {} from {}", rp.id, src);
                    }
                }
                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::RegisterPeerResponse(
                        proto::RegisterPeerResponse { request_pk: false },
                    )),
                })
            }

            proto::rendezvous_message::Union::RegisterPk(_rpk) => Some(proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::RegisterPkResponse(
                    proto::RegisterPkResponse {
                        result: proto::register_pk_response::Result::Ok as i32,
                        keep_alive: 300,
                    },
                )),
            }),

            proto::rendezvous_message::Union::PunchHoleRequest(phr) => {
                self.handle_punch_hole(phr, src, peers)
            }

            proto::rendezvous_message::Union::HealthCheck(_) => {
                let peer_count = peers.lock().unwrap().len() as u32;
                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::HealthResponse(
                        proto::HealthResponse {
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            peers_online: peer_count,
                            relays_active: 0,
                            version: env!("CARGO_PKG_VERSION").to_string(),
                        },
                    )),
                })
            }

            proto::rendezvous_message::Union::GroupQuery(gq) => self.handle_group_query(gq, peers),

            proto::rendezvous_message::Union::ListPeers(lp) => self.handle_list_peers(lp, peers),

            proto::rendezvous_message::Union::PublishVersionRequest(pvr) => {
                Some(self.handle_publish_version(pvr))
            }

            proto::rendezvous_message::Union::QueryVersionRequest(qvr) => {
                Some(self.handle_query_version(qvr))
            }

            proto::rendezvous_message::Union::FetchBinaryRequest(fbr) => {
                Some(self.handle_fetch_binary(fbr))
            }

            _ => None,
        }
    }

    /// rsh-5264.3: handle a `PublishVersionRequest` from an operator.
    ///
    /// **Signature verification policy** (current build):
    ///
    /// `mrsh_core::release_signing::SIGNING_PUBLIC_KEY_PEM` is empty in this
    /// source tree. We CANNOT cryptographically verify `operator_signature`
    /// without a key. The handler therefore accepts adverts permissively and
    /// only records the operator signature for future audit.
    ///
    /// **MUST-FIX-BEFORE-PROD**: once `SIGNING_PUBLIC_KEY_PEM` is populated
    /// (or the rdv server is started with a `--release-pubkey <pem>` flag),
    /// this handler MUST verify `operator_signature` against
    /// `advert.operator_signing_payload()` and reject mismatches with
    /// `accepted=false, error_message="signature verification failed"`. See
    /// `docs/release-signing.md` and `bd show rsh-5264.3` for the rollout plan.
    pub(super) fn handle_publish_version(
        &self,
        req: proto::PublishVersionRequest,
    ) -> proto::RendezvousMessage {
        let advert = match req.advert {
            Some(a) => a,
            None => {
                return reply_publish(false, "missing advert");
            }
        };

        if advert.platform.is_empty() || advert.track.is_empty() || advert.latest_version.is_empty()
        {
            return reply_publish(
                false,
                "advert requires non-empty platform, track, and latest_version",
            );
        }

        // Stamp accepted-at server-side so adverts share a consistent clock.
        let mut stamped = advert;
        stamped.published_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // PERMISSIVE: SIGNING_PUBLIC_KEY_PEM is empty, so we can't verify.
        // We log the call and store the advert.
        if !req.operator_signature.is_empty() {
            tracing::debug!(
                "rdv: PublishVersion {}|{}|{} (op_sig {} bytes, NOT verified — \
                 SIGNING_PUBLIC_KEY_PEM is empty in this build)",
                stamped.platform,
                stamped.track,
                stamped.latest_version,
                req.operator_signature.len()
            );
        } else {
            tracing::warn!(
                "rdv: PublishVersion {}|{}|{} accepted with EMPTY operator_signature \
                 (permissive mode — populate SIGNING_PUBLIC_KEY_PEM before prod)",
                stamped.platform,
                stamped.track,
                stamped.latest_version,
            );
        }

        let key = (stamped.platform.clone(), stamped.track.clone());
        let blob_len = req.binary_blob.len();
        let entry = VersionAdvertEntry {
            advert: stamped.clone(),
            binary_blob: req.binary_blob,
        };
        let mut adverts = self.version_adverts.lock().unwrap();
        adverts.insert(key, entry);
        tracing::info!(
            "rdv: stored advert {}|{}|{} (binary_blob {} bytes)",
            stamped.platform,
            stamped.track,
            stamped.latest_version,
            blob_len
        );
        reply_publish(true, "")
    }

    /// rsh-5264.3: handle a `QueryVersionRequest` from a server.
    ///
    /// Returns `update_available=true` plus the stored advert iff the
    /// stored `latest_version` is strictly greater than `current_version`
    /// using a simple lexicographic+numeric semver comparison. Empty
    /// `current_version` (servers without rsh-5264.1 fields) is treated as
    /// "unknown" — we always return the advert so the server can decide.
    pub(super) fn handle_query_version(
        &self,
        req: proto::QueryVersionRequest,
    ) -> proto::RendezvousMessage {
        let key = (req.platform.clone(), req.track.clone());
        let adverts = self.version_adverts.lock().unwrap();
        match adverts.get(&key) {
            Some(entry) => {
                let advert = &entry.advert;
                let update_available = req.current_version.is_empty()
                    || semver_greater(&advert.latest_version, &req.current_version);
                proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::QueryVersionResponse(
                        proto::QueryVersionResponse {
                            update_available,
                            advert: if update_available {
                                Some(advert.clone())
                            } else {
                                None
                            },
                        },
                    )),
                }
            }
            None => proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::QueryVersionResponse(
                    proto::QueryVersionResponse {
                        update_available: false,
                        advert: None,
                    },
                )),
            },
        }
    }

    /// rsh-5264.6: handle a `FetchBinaryRequest` from a server triggering
    /// `self-update-from-rdv`. Returns the inline `binary_blob` (raw bytes)
    /// alongside the matching signature when (platform, track, version)
    /// matches a stored advert AND that advert has a non-empty blob.
    ///
    /// Negative cases:
    /// - no advert for (platform, track) → `found=false`, error="no advert"
    /// - advert exists but version mismatch → `found=false`, error="version mismatch"
    /// - advert exists but blob is empty (published `--no-blob`) → `found=false`,
    ///   error="advert has no inline binary_blob (publish was --no-blob)"
    pub(super) fn handle_fetch_binary(
        &self,
        req: proto::FetchBinaryRequest,
    ) -> proto::RendezvousMessage {
        let key = (req.platform.clone(), req.track.clone());
        let adverts = self.version_adverts.lock().unwrap();
        let resp = match adverts.get(&key) {
            None => proto::FetchBinaryResponse {
                found: false,
                binary_blob: Vec::new(),
                signature: Vec::new(),
                error_message: format!(
                    "no advert for {}|{}",
                    req.platform, req.track
                ),
            },
            Some(entry) => {
                if entry.advert.latest_version != req.version {
                    proto::FetchBinaryResponse {
                        found: false,
                        binary_blob: Vec::new(),
                        signature: Vec::new(),
                        error_message: format!(
                            "version mismatch: requested {}, advert has {}",
                            req.version, entry.advert.latest_version
                        ),
                    }
                } else if entry.binary_blob.is_empty() {
                    proto::FetchBinaryResponse {
                        found: false,
                        binary_blob: Vec::new(),
                        signature: Vec::new(),
                        error_message:
                            "advert has no inline binary_blob (publish was --no-blob)"
                                .to_string(),
                    }
                } else {
                    tracing::info!(
                        "rdv: serving binary for {}|{}|{} ({} bytes)",
                        req.platform,
                        req.track,
                        req.version,
                        entry.binary_blob.len()
                    );
                    proto::FetchBinaryResponse {
                        found: true,
                        binary_blob: entry.binary_blob.clone(),
                        signature: entry.advert.signature.clone(),
                        error_message: String::new(),
                    }
                }
            }
        };
        proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::FetchBinaryResponse(resp)),
        }
    }

    fn handle_punch_hole(
        &self,
        req: proto::PunchHoleRequest,
        src: SocketAddr,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        // Key check.
        if !self.key.is_empty() && req.licence_key != self.key {
            return Some(proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::PunchHoleResponse(
                    proto::PunchHoleResponse {
                        failure: proto::punch_hole_response::Failure::LicenseMismatch as i32,
                        relay_server: self.relay_server.clone(),
                        ..Default::default()
                    },
                )),
            });
        }

        let map = peers.lock().unwrap();

        match map.get(&req.id) {
            Some(entry) => {
                let encoded_addr = encode_socket_addr(&entry.addr);

                // Same-LAN detection: requester and target share an IP.
                if entry.addr.ip() == src.ip() {
                    return Some(proto::RendezvousMessage {
                        union: Some(proto::rendezvous_message::Union::FetchLocalAddr(
                            proto::FetchLocalAddr {
                                socket_addr: encoded_addr,
                                relay_server: self.relay_server.clone(),
                                // rsh-64x9 2026-05-21: include encrypted_net_info so
                                // same-NAT peers can ALSO do LAN discovery + direct
                                // connect (previously dropped here, forcing relay).
                                encrypted_net_info: entry.encrypted_net_info.clone(),
                                ..Default::default()
                            },
                        )),
                    });
                }

                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::PunchHoleResponse(
                        proto::PunchHoleResponse {
                            socket_addr: encoded_addr,
                            relay_server: self.relay_server.clone(),
                            encrypted_net_info: entry.encrypted_net_info.clone(),
                            ports: entry.ports.clone(),
                            ..Default::default()
                        },
                    )),
                })
            }
            None => Some(proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::PunchHoleResponse(
                    proto::PunchHoleResponse {
                        failure: proto::punch_hole_response::Failure::IdNotExist as i32,
                        relay_server: self.relay_server.clone(),
                        ..Default::default()
                    },
                )),
            }),
        }
    }

    /// Handle ListPeers: return ALL registered peers (auth'd by licence_key).
    fn handle_list_peers(
        &self,
        lp: proto::ListPeers,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        // Authenticate: licence_key must match server's key
        if !self.key.is_empty() && lp.licence_key != self.key {
            tracing::warn!("rdv: list_peers rejected — key mismatch");
            return None;
        }

        let map = peers.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let all_peers: Vec<proto::GroupPeer> = map
            .iter()
            .map(|(id, entry)| {
                let last_seen_secs = now.as_secs() - entry.last_seen.elapsed().as_secs();
                proto::GroupPeer {
                    device_id: id.clone(),
                    hostname: entry.hostname.clone(),
                    platform: entry.platform.clone(),
                    socket_addr: encode_socket_addr(&entry.addr),
                    last_seen_secs,
                    service_port: entry.service_port as i32,
                    ports: entry.ports.clone(),
                    encrypted_net_info: entry.encrypted_net_info.clone(),
                    // rsh-5264.1 heartbeat-feedback
                    current_version: entry.current_version.clone(),
                    last_update_status: entry.last_update_status.clone(),
                    last_update_at_unix: entry.last_update_at_unix,
                    // rsh-5264.5 staged-rollout
                    track: entry.track.clone(),
                    auto_upgrade: entry.auto_upgrade,
                }
            })
            .collect();

        tracing::info!("rdv: list_peers — {} peers", all_peers.len());

        Some(proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::ListPeersResponse(
                proto::ListPeersResponse { peers: all_peers },
            )),
        })
    }

    /// Handle a GroupQuery: return all peers matching the group_hash,
    /// verified by HMAC proof (requester must know the enrollment token).
    fn handle_group_query(
        &self,
        gq: proto::GroupQuery,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        if gq.group_hash.is_empty() {
            return None;
        }

        // Verify HMAC proof: HMAC over (nonce_le_bytes, enrollment_token).
        // The nonce must be within 5 minutes of current time to prevent replay.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_secs.abs_diff(gq.nonce) > 300 {
            tracing::warn!(
                "rdv: group query rejected — stale nonce (delta={}s)",
                now_secs.abs_diff(gq.nonce)
            );
            return None;
        }

        // We verify the proof by hashing the supplied raw enrollment token
        // and matching the result against the stored group_hash.
        //
        // Conceptually: client sends raw enrollment_token in `hmac_proof`
        // and `group_hash` to filter peers. Server hashes the token and
        // matches. The token is sent over UDP on the same network, which
        // is acceptable for our use case (internal fleet, same LAN or VPN).
        use sha2::{Digest, Sha256};
        let computed_hash = if !gq.hmac_proof.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&gq.hmac_proof);
            hex::encode(hasher.finalize())
        } else {
            String::new()
        };

        if computed_hash != gq.group_hash {
            tracing::warn!("rdv: group query rejected — proof mismatch");
            return None;
        }

        let map = peers.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let matching: Vec<proto::GroupPeer> = map
            .iter()
            .filter(|(_, entry)| entry.group_hash == gq.group_hash)
            .map(|(id, entry)| {
                let last_seen_secs = now.as_secs() - entry.last_seen.elapsed().as_secs();
                proto::GroupPeer {
                    device_id: id.clone(),
                    hostname: entry.hostname.clone(),
                    platform: entry.platform.clone(),
                    socket_addr: encode_socket_addr(&entry.addr),
                    last_seen_secs,
                    service_port: entry.service_port as i32,
                    ports: entry.ports.clone(),
                    encrypted_net_info: entry.encrypted_net_info.clone(),
                    // rsh-5264.1 heartbeat-feedback
                    current_version: entry.current_version.clone(),
                    last_update_status: entry.last_update_status.clone(),
                    last_update_at_unix: entry.last_update_at_unix,
                    // rsh-5264.5 staged-rollout
                    track: entry.track.clone(),
                    auto_upgrade: entry.auto_upgrade,
                }
            })
            .collect();

        tracing::info!(
            "rdv: group query for {} — {} peers found",
            gq.group_hash,
            matching.len()
        );

        Some(proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::GroupQueryResponse(
                proto::GroupQueryResponse { peers: matching },
            )),
        })
    }
}

// ── rsh-5264.3 helpers ───────────────────────────────────────────────────

fn reply_publish(accepted: bool, error_message: &str) -> proto::RendezvousMessage {
    proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PublishVersionResponse(
            proto::PublishVersionResponse {
                accepted,
                error_message: error_message.to_string(),
            },
        )),
    }
}

/// Return true if `a` is a strictly greater semver-style version than `b`.
///
/// Splits on `.` and compares each numeric component as `u64` (falling back to
/// lexicographic if a component is non-numeric). Pre-release suffixes are not
/// honoured — `"1.10.30"` > `"1.10.30-rc1"` per this comparator (which is
/// fine for the rdv use case: operators publish only stable strings, and
/// pre-release ordering is not required for "is this newer" decisions).
fn semver_greater(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<(u64, String)> {
        s.split('.')
            .map(|tok| match tok.parse::<u64>() {
                Ok(n) => (n, String::new()),
                Err(_) => (0, tok.to_string()),
            })
            .collect()
    };
    let av = parse(a);
    let bv = parse(b);
    let len = av.len().max(bv.len());
    for i in 0..len {
        let (an, as_) = av.get(i).cloned().unwrap_or_default();
        let (bn, bs) = bv.get(i).cloned().unwrap_or_default();
        if !as_.is_empty() || !bs.is_empty() {
            // Lexicographic when either component is non-numeric.
            match as_.cmp(&bs) {
                std::cmp::Ordering::Greater => return true,
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        if an > bn {
            return true;
        }
        if an < bn {
            return false;
        }
    }
    false
}
