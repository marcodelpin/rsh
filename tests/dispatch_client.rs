//! Companion test marker file for `src/dispatch_client.rs`.
//!
//! Real coverage of the `parse_value_flag` helper (rsh-5264.6 self-update
//! --from-rdv flag parsing) lives in the `#[cfg(test)] mod tests` block
//! inside `src/dispatch_client.rs` itself (private fn, accessible from the
//! same module's inline tests but not from a separate integration crate).
//!
//! Run those tests via:
//!   cargo test --lib parse_value_flag
//!
//! End-to-end self-update direct push is covered by `tests/regression.rs`.
//! self-update --from-rdv requires a running rdv server; the protocol-layer
//! TCP roundtrip is in `crates/mrsh-relay/src/rendezvous/tests.rs::rdv_fetch_binary_over_tcp_e2e`.
//!
//! This file intentionally has NO #[test] functions. cargo will still compile
//! it as an integration crate target, but the test harness will report
//! "0 tests" — the documentation marker is what the test-required
//! PreToolUse hook checks for on disk.
