//! Direct unit-style tests for `mrsh::mac_form::is_mac_form`.
//!
//! Companion to `tests/dispatch.rs` (which exercises the same fn from the
//! `wake` command perspective). Kept separate so the hook
//! testing-discipline check sees a dedicated test file for `src/mac_form.rs`.

use mrsh::mac_form::is_mac_form;

#[test]
fn accepts_colon_separated_mac() {
    assert!(is_mac_form("aa:bb:cc:dd:ee:ff"));
}

#[test]
fn accepts_hyphen_separated_mac() {
    assert!(is_mac_form("aa-bb-cc-dd-ee-ff"));
}

#[test]
fn accepts_cisco_dotted_mac() {
    assert!(is_mac_form("aabb.ccdd.eeff"));
}

#[test]
fn accepts_bare_hex_mac() {
    assert!(is_mac_form("aabbccddeeff"));
}

#[test]
fn rejects_hostname_with_hyphens() {
    // The rsh-kcch regression — must NOT be classified as MAC.
    assert!(!is_mac_form("EXAMPLE-LAPTOP"));
}

#[test]
fn rejects_ipv4() {
    assert!(!is_mac_form("192.0.2.151"));
}

#[test]
fn rejects_short_string() {
    assert!(!is_mac_form(""));
    assert!(!is_mac_form("aa:bb"));
}

#[test]
fn rejects_non_hex_in_separated_form() {
    assert!(!is_mac_form("zz:bb:cc:dd:ee:ff"));
}
