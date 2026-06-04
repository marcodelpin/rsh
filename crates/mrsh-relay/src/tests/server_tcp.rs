//! Tests for `crates/mrsh-relay/src/rendezvous/server_tcp.rs`.
//!
//! TCP-side dispatch (handle_tcp_relay_request, including the rsh-5264.6
//! PublishVersion / QueryVersion / FetchBinary routing) is covered by an
//! end-to-end test in `crates/mrsh-relay/src/rendezvous/tests.rs` that
//! starts a real `RendezvousServer` via `listen_and_serve`, publishes a
//! large blob (>32 KB so the TCP path triggers), and fetches it back via
//! TCP using `Client::fetch_binary`.
//!
//! This file is a placeholder so the test-required PreToolUse hook can map
//! source → tests on disk.
//!
//! Coverage in `rendezvous/tests.rs`:
//!   - rdv_fetch_binary_over_tcp_e2e (rsh-5264.6) — full TCP roundtrip
