//! MAC-address form detection used by the `wake` command to decide
//! whether the user-supplied argument is a MAC literal or a host name
//! to look up in `~/.mrsh/config`.
//!
//! Pure function, no I/O — easy to unit-test.

/// Returns true if `s` parses as a MAC literal in one of:
///   - 17 chars: 6 hex pairs separated by ':' or '-' (e.g. `aa:bb:cc:dd:ee:ff`)
///   - 14 chars: 3 groups of 4 hex separated by '.' (Cisco notation `aabb.ccdd.eeff`)
///   - 12 chars: bare hex, no separators (e.g. `aabbccddeeff`)
///
/// Any other shape (including host names that happen to contain `-` like
/// `EXAMPLE-LAPTOP`) returns false, so the caller falls back to a config lookup.
pub fn is_mac_form(s: &str) -> bool {
    let bytes = s.as_bytes();
    match s.len() {
        17 => {
            let sep = bytes[2];
            if sep != b':' && sep != b'-' {
                return false;
            }
            s.split(sep as char).count() == 6
                && s.chars().all(|c| c.is_ascii_hexdigit() || c as u8 == sep)
        }
        14 => {
            s.split('.').count() == 3 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.')
        }
        12 => s.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    }
}
