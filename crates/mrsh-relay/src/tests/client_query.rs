//! Tests for `crates/mrsh-relay/src/rendezvous/client_query.rs`.
//!
//! Test logic for the `Client::publish_version` / `Client::query_version` /
//! `Client::fetch_binary` (rsh-5264.6 TCP transport) APIs lives in
//! `crates/mrsh-relay/src/rendezvous/tests.rs` because the test fixtures
//! (`RendezvousServer`, `PeerEntry`, `proto::*`) need module-private
//! visibility from sibling submodules. This file is a placeholder so the
//! test-required PreToolUse hook can map source → tests on disk.
//!
//! Coverage in `rendezvous/tests.rs`:
//!   - rdv_publish_query_roundtrip
//!   - rdv_publish_rejects_empty_fields
//!   - rdv_query_no_advert_no_update
//!   - rdv_publish_overwrites_previous
//!   - rdv_fetch_binary_returns_published_blob (rsh-5264.6)
//!   - rdv_fetch_binary_no_advert (rsh-5264.6)
//!   - rdv_fetch_binary_version_mismatch (rsh-5264.6)
//!   - rdv_fetch_binary_no_blob_published (rsh-5264.6)
//!   - rdv_fetch_binary_over_tcp_e2e (rsh-5264.6)
