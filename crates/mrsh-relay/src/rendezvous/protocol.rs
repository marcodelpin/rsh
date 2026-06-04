//! Protocol types and shared helpers for the rendezvous module.
//!
//! Contains:
//! - Public protocol-facing types (`ResolveResult`, `GroupPeerInfo`, `RelayNotification`).
//! - The `Client` struct used by the rendezvous client API.
//! - Standalone helpers shared across submodules: `is_device_id`, `decode_socket_addr`,
//!   `encode_socket_addr`, `make_uuid`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::{Result, bail};

use crate::proto;

/// Default hbbs UDP port.
pub const DEFAULT_PORT: u16 = 21116;

/// Outcome of resolving a DeviceID through hbbs.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// Direct peer address, if available (None means relay-only).
    pub addr: Option<SocketAddr>,
    /// Relay server address returned by hbbs.
    pub relay_server: String,
    /// UUID for relay pairing (empty if P2P).
    pub uuid: String,
    /// Encrypted network info blob (from server's RegisterPeer, forwarded by hbbs).
    pub encrypted_net_info: Vec<u8>,
}

/// A discovered peer from a group query.
#[derive(Debug, Clone)]
pub struct GroupPeerInfo {
    pub device_id: String,
    pub hostname: String,
    pub platform: String,
    pub addr: Option<SocketAddr>,
    pub last_seen_secs: u64,
    /// mrsh command listener port (0 means default 8822).
    pub service_port: u16,
    /// Raw encrypted network info blob (for client-side decryption).
    pub encrypted_net_info: Vec<u8>,
    // rsh-5264.1 heartbeat-feedback fields (forwarded from RegisterPeer).
    /// Server's compiled version (e.g. "1.10.29"). Empty when peer reports nothing.
    pub current_version: String,
    /// Last self-update status: "success", "failed:<reason>", or "never".
    /// Empty when peer reports nothing (older server).
    pub last_update_status: String,
    /// Unix timestamp of last self-update attempt, 0 if never.
    pub last_update_at_unix: i64,
    // rsh-5264.5 staged-rollout fields (forwarded from RegisterPeer).
    /// Release track this server follows: `"stable"` | `"canary"` | `"dev"`.
    /// Empty when the peer is on a pre-5264.5 server (treated as `"stable"`
    /// at display time).
    pub track: String,
    /// Whether this host is opted-in to rdv-driven auto-upgrade. Defaults to
    /// `false` (explicit opt-in) and stays `false` for pre-5264.5 servers.
    pub auto_upgrade: bool,
}

/// rsh-5264.3 VersionAdvert: rdv-published "latest version available" for a
/// given (platform, track) tuple.
///
/// Mirror of the protobuf [`crate::proto::VersionAdvert`] message, exposed as a
/// public Rust struct so callers don't need to depend on `prost`-generated
/// types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionAdvert {
    /// Build platform: `"windows-msvc"`, `"linux-glibc"`, `"linux-musl"`, `"macos"`.
    pub platform: String,
    /// Release track: `"stable"`, `"canary"`, `"dev"`.
    pub track: String,
    /// Semantic version of the advertised release (e.g. `"1.10.30"`).
    pub latest_version: String,
    /// Optional URL where rdv (or a CDN) hosts the binary. Empty means
    /// out-of-band distribution; the server is expected to fetch from another
    /// path it already knows.
    pub download_url: String,
    /// Ed25519 signature of the binary content (from the release-signing key).
    /// Servers verify this offline using the embedded
    /// `mrsh_core::release_signing::SIGNING_PUBLIC_KEY_PEM`.
    pub signature: Vec<u8>,
    /// Unix-seconds timestamp when rdv accepted this advert (set by rdv when
    /// `PublishVersion` is processed; the operator value is overwritten).
    pub published_at_unix: i64,
}

impl VersionAdvert {
    /// Convert from the on-the-wire protobuf type.
    pub fn from_proto(p: &crate::proto::VersionAdvert) -> Self {
        Self {
            platform: p.platform.clone(),
            track: p.track.clone(),
            latest_version: p.latest_version.clone(),
            download_url: p.download_url.clone(),
            signature: p.signature.clone(),
            published_at_unix: p.published_at_unix,
        }
    }

    /// Convert to the on-the-wire protobuf type.
    pub fn to_proto(&self) -> crate::proto::VersionAdvert {
        crate::proto::VersionAdvert {
            platform: self.platform.clone(),
            track: self.track.clone(),
            latest_version: self.latest_version.clone(),
            download_url: self.download_url.clone(),
            signature: self.signature.clone(),
            published_at_unix: self.published_at_unix,
        }
    }

    /// Canonical bytes that the operator signs for `PublishVersionRequest`.
    ///
    /// Format: `"<platform>|<track>|<version>"` — joining the fields with `|`
    /// avoids ambiguity (none of the three fields contains `|` in any
    /// supported value, and a single delimiter prevents e.g. `("a", "b", "c")`
    /// colliding with `("ab", "", "c")`).
    pub fn operator_signing_payload(&self) -> Vec<u8> {
        format!("{}|{}|{}", self.platform, self.track, self.latest_version).into_bytes()
    }
}

/// A relay notification received from hbbs: a client wants to connect via relay.
#[derive(Debug, Clone)]
pub struct RelayNotification {
    /// UUID for relay pairing (both sides connect to hbbr with this UUID).
    pub uuid: String,
    /// Relay server address (hbbr host:port).
    pub relay_server: String,
    /// Requested target port (0 = default service port, 9822 = tray).
    pub target_port: u16,
}

/// Client for hbbs rendezvous protocol.
pub struct Client {
    /// Rendezvous servers to try, in order (host:port).
    pub servers: Vec<String>,
    /// Server public key (sent as licence_key in PunchHoleRequest).
    pub licence_key: String,
    /// Our own device ID for registration.
    pub local_id: String,
    /// Hashed enrollment token (hex) — included in RegisterPeer for group discovery.
    pub group_hash: String,
    /// Machine hostname — included in RegisterPeer for group discovery.
    pub hostname: String,
    /// Platform (e.g. "windows", "linux") — included in RegisterPeer.
    pub platform: String,
    /// mrsh command listener port — included in RegisterPeer so hbbs can report it.
    pub service_port: u16,
    /// Encrypted network info blob (envelope encryption). Opaque to hbbs.
    pub encrypted_net_info: Vec<u8>,
    /// Enrollment token — kept so the registration loop can re-derive the group
    /// keypair and re-encrypt fresh network info when local interfaces change
    /// (sys-8z5gn: re-announce LAN IPs on network change, not just at startup).
    /// Empty for client-only constructions that never run the registration loop.
    pub enrollment_token: String,
    /// Tray port — included in the refreshed NetworkInfo for LAN discovery.
    /// 0 for client-only constructions.
    pub tray_port: u16,
    /// All listening ports with type and capabilities.
    pub ports: Vec<proto::PortInfo>,
    // rsh-5264.1 heartbeat-feedback fields.
    /// Server's compiled version (env!("CARGO_PKG_VERSION")) — empty for clients.
    pub current_version: String,
    /// Last self-update status: "success", "failed:<reason>", or "never".
    pub last_update_status: String,
    /// Unix timestamp of last self-update attempt, 0 if never.
    pub last_update_at_unix: i64,
    // rsh-5264.5 staged-rollout fields.
    /// Release track this server follows: `"stable"` | `"canary"` | `"dev"`.
    /// Empty for clients (only servers populate this).
    pub track: String,
    /// Whether this host is opted-in to rdv-driven auto-upgrade. `false` for
    /// clients; `true` only on servers whose config sets `AutoUpgrade true`.
    pub auto_upgrade: bool,
}

/// Check whether a string looks like a device ID rather than a hostname/IP.
///
/// Device IDs: optional leading letters followed by one or more digits.
/// Examples: "123456789", "abc123". Not: "192.168.1.1", "example.com".
pub fn is_device_id(s: &str) -> bool {
    if s.is_empty() || s.contains('.') || s.contains(':') {
        return false;
    }
    let mut has_digit = false;
    let mut past_letters = false;
    for ch in s.chars() {
        if ch.is_ascii_alphabetic() {
            if past_letters {
                return false; // letters after digits
            }
        } else if ch.is_ascii_digit() {
            has_digit = true;
            past_letters = true;
        } else {
            return false;
        }
    }
    has_digit
}

/// Decode an AddrMangle-encoded socket address (IPv4).
///
/// The encoding packs IP + port + timestamp into a 128-bit integer:
///   bits [0..24)   → port + (tm & 0xFFFF)
///   bits [17..49)  → tm (32-bit obfuscation value)
///   bits [49..81)  → ip32 + tm
///
/// We decode by extracting tm, then subtracting it from ip and port.
pub fn decode_socket_addr(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 4 || data.len() > 16 {
        bail!("invalid AddrMangle length: {}", data.len());
    }

    // Zero-pad to 16 bytes, read as two u64 LE halves.
    let mut padded = [0u8; 16];
    padded[..data.len()].copy_from_slice(data);
    let lo = u64::from_le_bytes(padded[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(padded[8..].try_into().unwrap());

    // Extract the obfuscation timestamp (bits 17..49).
    let tm = ((lo >> 17) | (hi << 47)) as u32;

    // Extract IP (bits 49..81) and subtract tm.
    let ip_raw = ((lo >> 49) | (hi << 15)) as u32;
    let ip32 = ip_raw.wrapping_sub(tm);

    // Extract port (bits 0..24, masked to 16 bits) and subtract tm.
    let port = ((lo & 0xFF_FFFF) as u16).wrapping_sub((tm & 0xFFFF) as u16);

    let octets = ip32.to_le_bytes();
    Ok(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
        port,
    )))
}

/// Encode an IPv4 socket address using AddrMangle encoding (inverse of `decode_socket_addr`).
///
/// The encoding packs IP + port + a timestamp-based obfuscation value into
/// a 128-bit integer, then returns the minimal non-zero byte slice (min 4 bytes).
pub fn encode_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let (ip, port) = match addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => return vec![0; 4], // IPv6 not supported in this encoding
    };

    let ip32 = u32::from_le_bytes(ip.octets());

    // Obfuscation timestamp — same approach as RustDesk AddrMangle.
    let tm: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let ip_enc = ip32.wrapping_add(tm);
    let port_enc = port.wrapping_add((tm & 0xFFFF) as u16);

    // Pack into 128-bit value:
    //   bits 0..16:  port_enc
    //   bits 17..48: tm
    //   bits 49..80: ip_enc
    let val: u128 = (port_enc as u128) | ((tm as u128) << 17) | ((ip_enc as u128) << 49);

    let bytes = val.to_le_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(4)
        .max(4);
    bytes[..end].to_vec()
}

/// Encode a socket address with a specific obfuscation value (for testing).
#[cfg(test)]
pub(super) fn encode_socket_addr_with_tm(addr: &SocketAddr, tm: u32) -> Vec<u8> {
    let (ip, port) = match addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => return vec![0; 4],
    };

    let ip32 = u32::from_le_bytes(ip.octets());
    let ip_enc = ip32.wrapping_add(tm);
    let port_enc = port.wrapping_add((tm & 0xFFFF) as u16);

    let val: u128 = (port_enc as u128) | ((tm as u128) << 17) | ((ip_enc as u128) << 49);

    let bytes = val.to_le_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(4)
        .max(4);
    bytes[..end].to_vec()
}

/// Generate a random UUID v4 string.
pub(super) fn make_uuid() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        u64::from_be_bytes([0, 0, b[10], b[11], b[12], b[13], b[14], b[15]]),
    )
}
