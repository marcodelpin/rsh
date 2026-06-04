//! Regression tests for `mrsh wake` argument disambiguation (rsh-kcch).
//!
//! Before rsh-kcch the `wake` command forwarded its first arg straight to
//! `send_wol`, so `mrsh wake EXAMPLE-LAPTOP` errored with "invalid MAC address"
//! instead of resolving MacAddress from the user's config. The
//! MAC-vs-hostname classifier now lives in `mrsh::mac_form::is_mac_form`
//! and is covered here.
//!
//! Companion fix: `mrsh-core/src/config.rs` now accepts both `mac` and
//! `macaddress` keywords (parser lowercases the key first), so the form
//! `MacAddress AA-BB-CC-DD-EE-FF` that mrsh's --help documents actually
//! populates `HostConfig.mac`. The config-side check lives in
//! mrsh-core's own unit tests; here we cover only the binary's side.

use mrsh::mac_form::is_mac_form;

#[test]
fn colon_separated_mac_is_mac() {
    assert!(is_mac_form("aa:bb:cc:dd:ee:ff"));
    assert!(is_mac_form("AA:BB:CC:DD:EE:FF"));
}

#[test]
fn hyphen_separated_mac_is_mac() {
    assert!(is_mac_form("aa-bb-cc-dd-ee-ff"));
    assert!(is_mac_form("AA-BB-CC-DD-EE-FF"));
}

#[test]
fn cisco_dotted_mac_is_mac() {
    assert!(is_mac_form("aabb.ccdd.eeff"));
    assert!(is_mac_form("B808.CFFA.44CA"));
}

#[test]
fn bare_hex_mac_is_mac() {
    assert!(is_mac_form("aabbccddeeff"));
    assert!(is_mac_form("B808CFFA44CA"));
}

#[test]
fn hostname_with_hyphens_is_not_mac() {
    // This is the rsh-kcch reproduction case — must NOT be classified as MAC.
    assert!(!is_mac_form("EXAMPLE-LAPTOP"));
    assert!(!is_mac_form("example-gpu"));
    assert!(!is_mac_form("host-b"));
}

#[test]
fn ip_address_is_not_mac() {
    assert!(!is_mac_form("192.0.2.151"));
    assert!(!is_mac_form("10.0.0.1"));
}

#[test]
fn plain_hostname_is_not_mac() {
    assert!(!is_mac_form("localhost"));
    assert!(!is_mac_form("buildserver"));
}

#[test]
fn empty_and_short_strings_are_not_mac() {
    assert!(!is_mac_form(""));
    assert!(!is_mac_form("a"));
    assert!(!is_mac_form("aa:bb"));
}

#[test]
fn wrong_length_with_separators_is_not_mac() {
    // 17 chars but only 5 groups (too few separators)
    assert!(!is_mac_form("aaaaa:bb:cc:dd:ee"));
    // 14 chars but not the Cisco shape (no dots at expected positions)
    assert!(!is_mac_form("aabbccddeeff12"));
}

#[test]
fn mixed_separators_at_byte_2_anchor_only() {
    // Anchor on bytes[2] — first separator dictates which char is allowed
    // throughout. A literal that mixes ':' and '-' is rejected.
    assert!(!is_mac_form("aa:bb-cc:dd-ee:ff"));
}
