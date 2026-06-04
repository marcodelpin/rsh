//! Terminal protocol helpers — resize encoding/decoding shared between client and server.

/// Prefix byte for terminal resize messages in the shell data stream.
pub const RESIZE_PREFIX: u8 = 0x01;

/// Encode a terminal resize message: `[0x01, cols_hi, cols_lo, rows_hi, rows_lo]`.
pub fn encode_resize(cols: u16, rows: u16) -> Vec<u8> {
    vec![
        RESIZE_PREFIX,
        (cols >> 8) as u8,
        (cols & 0xff) as u8,
        (rows >> 8) as u8,
        (rows & 0xff) as u8,
    ]
}

/// Parse a terminal resize message. Returns `(cols, rows)` if valid.
pub fn parse_resize(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() >= 5 && data[0] == RESIZE_PREFIX {
        let cols = (data[1] as u16) << 8 | data[2] as u16;
        let rows = (data[3] as u16) << 8 | data[4] as u16;
        Some((cols, rows))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_roundtrip() {
        let msg = encode_resize(120, 40);
        let (cols, rows) = parse_resize(&msg).unwrap();
        assert_eq!(cols, 120);
        assert_eq!(rows, 40);
    }

    #[test]
    fn resize_too_short() {
        assert!(parse_resize(&[0x01, 0, 80]).is_none());
    }

    #[test]
    fn resize_wrong_prefix() {
        assert!(parse_resize(&[0x02, 0, 80, 0, 24]).is_none());
    }

    #[test]
    fn resize_large_values() {
        let msg = encode_resize(200, 50);
        let (cols, rows) = parse_resize(&msg).unwrap();
        assert_eq!(cols, 200);
        assert_eq!(rows, 50);
    }

    #[test]
    fn resize_max_values() {
        let msg = encode_resize(u16::MAX, u16::MAX);
        let (cols, rows) = parse_resize(&msg).unwrap();
        assert_eq!(cols, u16::MAX);
        assert_eq!(rows, u16::MAX);
    }
}
