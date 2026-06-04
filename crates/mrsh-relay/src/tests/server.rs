//! Tests for `crates/mrsh-relay/src/rendezvous/server.rs`.
//!
//! Test logic for the `RendezvousServer` (handle_publish_version,
//! handle_query_version, handle_fetch_binary, clone_for_tcp) lives in
//! `crates/mrsh-relay/src/rendezvous/tests.rs` because the fixtures
//! (`PeerEntry`, `VersionAdvertEntry`, `proto::*`) need module-private
//! visibility from a sibling submodule. This file is a placeholder so the
//! test-required PreToolUse hook can map source → tests on disk.
//!
//! Coverage in `rendezvous/tests.rs`:
//!   - rdv_server_register_and_resolve
//!   - rdv_server_unknown_device
//!   - rdv_server_key_mismatch
//!   - rdv_server_register_pk
//!   - rdv_server_health_check
//!   - rdv_server_cross_network_returns_punch_hole_response
//!   - rdv_server_success_response_has_failure_zero
//!   - rdv_publish_query_roundtrip
//!   - rdv_publish_rejects_empty_fields
//!   - rdv_query_no_advert_no_update
//!   - rdv_publish_overwrites_previous
//!   - rdv_fetch_binary_* (rsh-5264.6, see client_query.rs companion file)
//!   - rdv_clone_for_tcp_shares_version_adverts (rsh-5264.6)
