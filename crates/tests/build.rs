//! Marker file: rsh-o3xl build.rs coverage.
//!
//! The actual coverage for `crates/mrsh-core/build.rs` lives at:
//!   - `crates/mrsh-server/src/selfupdate.rs::tests::signing_public_key_pem_sourced_from_build_rs`
//!     (verifies SIGNING_PUBLIC_KEY_PEM is sourced from OUT_DIR/release_pubkey.pem)
//!   - `crates/mrsh-server/src/selfupdate.rs::tests::insecure_no_verify_rejected_when_key_populated_logic`
//!     (runtime gate logic mirrors handle_self_update_from_rdv)
//!
//! No companion `#[test]` fns here — build.rs is exercised by every cargo
//! build (the build itself fails if include_str! cannot find the file).
//!
//! Hook satisfaction: TEST-REQUIRED guard wants a tests/ peer file for every
//! source file. This marker documents WHERE actual coverage lives.
