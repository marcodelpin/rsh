//! Rendezvous client and server — resolve a DeviceID to an IP:port via hbbs.
//!
//! Client protocol flow (all UDP, raw protobuf — no BytesCodec framing):
//!   1. RegisterPeer  → RegisterPeerResponse (register ourselves)
//!   2. RegisterPk    → RegisterPkResponse    (register public key if requested)
//!   3. PunchHoleRequest → PunchHoleResponse | FetchLocalAddr (resolve target)
//!   4. If relay needed: RequestRelay via TCP (BytesCodec framed)
//!
//! Server: accepts RegisterPeer/PunchHoleRequest/RegisterPk over UDP,
//!         maintains a DeviceID→SocketAddr registry with heartbeat expiry.
//!
//! Clean-room implementation. MIT licensed.
//!
//! ## Module layout
//!
//! - [`protocol`]: protocol-facing types + standalone helpers
//!   (`Client`, `ResolveResult`, `GroupPeerInfo`, `RelayNotification`,
//!   `is_device_id`, `encode_socket_addr`, `decode_socket_addr`).
//! - [`server`]: `RendezvousServer` (UDP listener + message dispatch).
//! - [`server_tcp`]: TCP relay-forwarding handler + persistent NAT-traversal
//!   notification loop used by clients.
//! - [`client_register`]: client-side `register_once`, `do_register`,
//!   `run_registration_loop`.
//! - [`client_resolve`]: client-side `resolve` / `resolve_with_port` and the
//!   PunchHoleRequest + RequestRelay machinery.
//! - [`client_query`]: client-side `query_group` and `list_peers`.

mod client_query;
mod client_register;
mod client_resolve;
mod protocol;
mod server;
mod server_tcp;

#[cfg(test)]
mod tests;

pub use protocol::{
    Client, DEFAULT_PORT, GroupPeerInfo, RelayNotification, ResolveResult, VersionAdvert,
    decode_socket_addr, encode_socket_addr, is_device_id,
};
pub use server::RendezvousServer;
