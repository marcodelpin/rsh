//! Smoke tests for the mrsh library crate's public surface.
//!
//! The library intentionally exposes very little — just constants from
//! `consts::` and the `mac_form` module. This file verifies that surface
//! is reachable by external consumers (the hook testing-discipline check
//! also expects this file alongside `src/lib.rs`).

use mrsh::consts::{CLIENT_SUBCOMMANDS, LOCAL_COMMANDS};

#[test]
fn local_commands_is_non_empty() {
    assert!(!LOCAL_COMMANDS.is_empty(), "LOCAL_COMMANDS must list at least one local command");
}

#[test]
fn client_subcommands_is_non_empty() {
    assert!(!CLIENT_SUBCOMMANDS.is_empty(), "CLIENT_SUBCOMMANDS must list at least one client subcommand");
}

#[test]
fn mac_form_module_is_reachable() {
    // Sanity: mac_form re-export reachable from the lib crate root.
    assert!(mrsh::mac_form::is_mac_form("aa:bb:cc:dd:ee:ff"));
    assert!(!mrsh::mac_form::is_mac_form("not-a-mac"));
}
