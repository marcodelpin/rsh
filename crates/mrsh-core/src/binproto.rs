//! Binary wire protocol — replaces JSON for all messages.
//!
//! Format: [4-byte BE length][1-byte type ID][payload]
//! Framing reuses wire.rs send_message/recv_message (length-prefixed).
//! Payload is type-specific binary, no JSON, no base64.
//!
//! Strings are length-prefixed: [2-byte BE len][UTF-8 bytes]
//! Binary blobs are length-prefixed: [4-byte BE len][raw bytes]

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wire;

// ── Message type IDs ────────────────────────────────────────────

/// Message type constants.
pub mod msg {
    // Auth flow
    pub const AUTH_REQUEST: u8 = 0x01;
    pub const AUTH_CHALLENGE: u8 = 0x02;
    pub const AUTH_RESPONSE: u8 = 0x03;
    pub const AUTH_OK: u8 = 0x04;
    pub const AUTH_FAIL: u8 = 0x05;
    pub const TOTP_CHALLENGE: u8 = 0x06;
    pub const TOTP_RESPONSE: u8 = 0x07;

    // Exec (buffered)
    pub const EXEC: u8 = 0x10;
    pub const EXEC_RESULT: u8 = 0x11;

    // Exec (streaming)
    pub const EXEC_STREAM: u8 = 0x12;
    pub const EXEC_STDOUT: u8 = 0x13;
    pub const EXEC_STDERR: u8 = 0x14;
    pub const EXEC_EXIT: u8 = 0x15;
    pub const EXEC_SIGNAL: u8 = 0x16;

    // Push (chunked)
    pub const PUSH_START: u8 = 0x20;
    pub const PUSH_DATA: u8 = 0x21;
    pub const PUSH_END: u8 = 0x22;
    pub const PUSH_OK: u8 = 0x23;

    // Pull
    pub const PULL_REQ: u8 = 0x30;
    pub const PULL_DATA: u8 = 0x31;
    pub const PULL_END: u8 = 0x32;

    // Info / system
    pub const INFO_REQ: u8 = 0x40;
    pub const INFO_RESP: u8 = 0x41;

    // Ping
    pub const PING: u8 = 0x50;
    pub const PONG: u8 = 0x51;

    // Screenshot
    pub const SCREENSHOT_REQ: u8 = 0x60;
    pub const SCREENSHOT_DATA: u8 = 0x61;

    // Self-update
    pub const SELF_UPDATE: u8 = 0x70;
    pub const SELF_UPDATE_OK: u8 = 0x71;

    // Shell / session
    pub const SHELL_REQ: u8 = 0x80;
    pub const SHELL_DATA: u8 = 0x81;
    pub const SHELL_RESIZE: u8 = 0x82;

    // Sync (delta, sigs, walk)
    pub const SYNC_REQ: u8 = 0x90;
    pub const SYNC_RESP: u8 = 0x91;

    // Generic request/response (for commands not yet migrated to binary)
    pub const REQUEST: u8 = 0xF0;
    pub const RESPONSE: u8 = 0xF1;

    // Error
    pub const ERROR: u8 = 0xFF;
}

// ── Encoding helpers ────────────────────────────────────────────

/// Write a length-prefixed string (2-byte BE length + UTF-8 bytes).
pub fn encode_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Write a length-prefixed binary blob (4-byte BE length + raw bytes).
pub fn encode_blob(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Read a length-prefixed string from a byte slice at the given offset.
/// Returns (string, new_offset).
pub fn decode_str(data: &[u8], offset: usize) -> Result<(&str, usize)> {
    if offset + 2 > data.len() {
        bail!("decode_str: truncated length at offset {}", offset);
    }
    let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    let start = offset + 2;
    let end = start + len;
    if end > data.len() {
        bail!(
            "decode_str: truncated data at offset {} (need {} bytes, have {})",
            offset,
            len,
            data.len() - start
        );
    }
    let s = std::str::from_utf8(&data[start..end]).context("decode_str: invalid UTF-8")?;
    Ok((s, end))
}

/// Read a length-prefixed blob from a byte slice at the given offset.
/// Returns (slice, new_offset).
pub fn decode_blob(data: &[u8], offset: usize) -> Result<(&[u8], usize)> {
    if offset + 4 > data.len() {
        bail!("decode_blob: truncated length at offset {}", offset);
    }
    let len = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
        as usize;
    let start = offset + 4;
    let end = start + len;
    if end > data.len() {
        bail!(
            "decode_blob: truncated data at offset {} (need {} bytes, have {})",
            offset,
            len,
            data.len() - start
        );
    }
    Ok((&data[start..end], end))
}

/// Read a u32 little-endian from data at offset.
pub fn decode_u32_le(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    if offset + 4 > data.len() {
        bail!("decode_u32_le: truncated at offset {}", offset);
    }
    let v = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
    Ok((v, offset + 4))
}

/// Read a u64 little-endian from data at offset.
pub fn decode_u64_le(data: &[u8], offset: usize) -> Result<(u64, usize)> {
    if offset + 8 > data.len() {
        bail!("decode_u64_le: truncated at offset {}", offset);
    }
    let v = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    Ok((v, offset + 8))
}

// ── Send/recv typed messages ────────────────────────────────────

/// Send a binary-protocol message: [type_id][payload].
/// Framing (length prefix) handled by wire::send_message.
pub async fn send_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    type_id: u8,
    payload: &[u8],
) -> Result<()> {
    let mut msg = Vec::with_capacity(1 + payload.len());
    msg.push(type_id);
    msg.extend_from_slice(payload);
    wire::send_message(writer, &msg).await
}

/// Send a typed message with no payload (e.g., PING, PUSH_END).
pub async fn send_empty<W: AsyncWriteExt + Unpin>(writer: &mut W, type_id: u8) -> Result<()> {
    wire::send_message(writer, &[type_id]).await
}

/// Receive a binary-protocol message. Returns (type_id, payload).
pub async fn recv_msg<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    let data = wire::recv_message(reader).await?;
    if data.is_empty() {
        bail!("empty binary message");
    }
    let type_id = data[0];
    let payload = data[1..].to_vec();
    Ok((type_id, payload))
}

// ── Auth message builders ───────────────────────────────────────

/// Build AUTH_REQUEST payload:
///   pubkey_blob (4-byte len + raw) + version_str (2-byte len + utf8) + caps_count(1) + caps[]
pub fn build_auth_request(pubkey: &[u8], version: &str, caps: &[&str]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + pubkey.len() + 2 + version.len() + 1 + caps.len() * 20);
    encode_blob(&mut buf, pubkey);
    encode_str(&mut buf, version);
    buf.push(caps.len() as u8);
    for cap in caps {
        encode_str(&mut buf, cap);
    }
    buf
}

/// Parse AUTH_REQUEST payload.
pub fn parse_auth_request(data: &[u8]) -> Result<(Vec<u8>, String, Vec<String>)> {
    let (pubkey, off) = decode_blob(data, 0)?;
    let pubkey = pubkey.to_vec();
    let (version, off) = decode_str(data, off)?;
    let version = version.to_string();
    if off >= data.len() {
        return Ok((pubkey, version, vec![]));
    }
    let caps_count = data[off] as usize;
    let mut off = off + 1;
    let mut caps = Vec::with_capacity(caps_count);
    for _ in 0..caps_count {
        let (cap, new_off) = decode_str(data, off)?;
        caps.push(cap.to_string());
        off = new_off;
    }
    Ok((pubkey, version, caps))
}

/// Build AUTH_OK payload: version_str + caps_count + caps[] + banner_str (optional)
pub fn build_auth_ok(version: &str, caps: &[&str], banner: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_str(&mut buf, version);
    buf.push(caps.len() as u8);
    for cap in caps {
        encode_str(&mut buf, cap);
    }
    if let Some(b) = banner {
        buf.push(1); // has_banner flag
        encode_str(&mut buf, b);
    } else {
        buf.push(0);
    }
    buf
}

/// Parse AUTH_OK payload.
pub fn parse_auth_ok(data: &[u8]) -> Result<(String, Vec<String>, Option<String>)> {
    let (version, off) = decode_str(data, 0)?;
    let version = version.to_string();
    if off >= data.len() {
        return Ok((version, vec![], None));
    }
    let caps_count = data[off] as usize;
    let mut off = off + 1;
    let mut caps = Vec::with_capacity(caps_count);
    for _ in 0..caps_count {
        let (cap, new_off) = decode_str(data, off)?;
        caps.push(cap.to_string());
        off = new_off;
    }
    let banner = if off < data.len() && data[off] == 1 {
        let (b, _) = decode_str(data, off + 1)?;
        Some(b.to_string())
    } else {
        None
    };
    Ok((version, caps, banner))
}

// ── Exec message builders ───────────────────────────────────────

/// Build EXEC payload: command string + env_count(1) + env[]
pub fn build_exec(command: &str, env_vars: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_str(&mut buf, command);
    buf.push(env_vars.len().min(255) as u8);
    for env in env_vars.iter().take(255) {
        encode_str(&mut buf, env);
    }
    buf
}

/// Parse EXEC payload.
pub fn parse_exec(data: &[u8]) -> Result<(String, Vec<String>)> {
    let (command, off) = decode_str(data, 0)?;
    let command = command.to_string();
    if off >= data.len() {
        return Ok((command, vec![]));
    }
    let env_count = data[off] as usize;
    let mut off = off + 1;
    let mut env_vars = Vec::with_capacity(env_count);
    for _ in 0..env_count {
        let (env, new_off) = decode_str(data, off)?;
        env_vars.push(env.to_string());
        off = new_off;
    }
    Ok((command, env_vars))
}

/// Build EXEC_RESULT payload: exit_code(4 LE) + output_blob(4-byte len + raw)
pub fn build_exec_result(exit_code: u32, output: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 4 + output.len());
    buf.extend_from_slice(&exit_code.to_le_bytes());
    encode_blob(&mut buf, output);
    buf
}

/// Parse EXEC_RESULT payload.
pub fn parse_exec_result(data: &[u8]) -> Result<(u32, Vec<u8>)> {
    let (exit_code, off) = decode_u32_le(data, 0)?;
    let (output, _) = decode_blob(data, off)?;
    Ok((exit_code, output.to_vec()))
}

// ── Push message builders ───────────────────────────────────────

/// Build PUSH_START payload: file_size(8 LE) + remote_path string
pub fn build_push_start(file_size: u64, remote_path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 2 + remote_path.len());
    buf.extend_from_slice(&file_size.to_le_bytes());
    encode_str(&mut buf, remote_path);
    buf
}

/// Parse PUSH_START payload.
pub fn parse_push_start(data: &[u8]) -> Result<(u64, String)> {
    let (file_size, off) = decode_u64_le(data, 0)?;
    let (path, _) = decode_str(data, off)?;
    Ok((file_size, path.to_string()))
}

// ── Pull message builders ───────────────────────────────────────

/// Build PULL_REQ payload: remote_path string
pub fn build_pull_req(remote_path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_str(&mut buf, remote_path);
    buf
}

/// Parse PULL_REQ payload.
pub fn parse_pull_req(data: &[u8]) -> Result<String> {
    let (path, _) = decode_str(data, 0)?;
    Ok(path.to_string())
}

// ── Error message builder ───────────────────────────────────────

/// Build ERROR payload: error string
pub fn build_error(error: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_str(&mut buf, error);
    buf
}

/// Parse ERROR payload.
pub fn parse_error(data: &[u8]) -> Result<String> {
    let (error, _) = decode_str(data, 0)?;
    Ok(error.to_string())
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_roundtrip() {
        let mut buf = Vec::new();
        encode_str(&mut buf, "hello world");
        let (decoded, end) = decode_str(&buf, 0).unwrap();
        assert_eq!(decoded, "hello world");
        assert_eq!(end, buf.len());
    }

    #[test]
    fn str_empty() {
        let mut buf = Vec::new();
        encode_str(&mut buf, "");
        let (decoded, end) = decode_str(&buf, 0).unwrap();
        assert_eq!(decoded, "");
        assert_eq!(end, 2);
    }

    #[test]
    fn blob_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let mut buf = Vec::new();
        encode_blob(&mut buf, &data);
        let (decoded, end) = decode_blob(&buf, 0).unwrap();
        assert_eq!(decoded, &data);
        assert_eq!(end, buf.len());
    }

    #[test]
    fn blob_empty() {
        let mut buf = Vec::new();
        encode_blob(&mut buf, &[]);
        let (decoded, end) = decode_blob(&buf, 0).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(end, 4);
    }

    #[test]
    fn auth_request_roundtrip() {
        let pubkey = vec![0x01, 0x02, 0x03, 0x04];
        let version = "1.4.2";
        let caps = vec!["self-update", "zstd", "binary-proto"];

        let payload = build_auth_request(&pubkey, version, &caps);
        let (pk, ver, c) = parse_auth_request(&payload).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(ver, version);
        assert_eq!(c, vec!["self-update", "zstd", "binary-proto"]);
    }

    #[test]
    fn auth_ok_roundtrip() {
        let payload = build_auth_ok("1.4.2", &["self-update", "zstd"], Some("Welcome!"));
        let (ver, caps, banner) = parse_auth_ok(&payload).unwrap();
        assert_eq!(ver, "1.4.2");
        assert_eq!(caps, vec!["self-update", "zstd"]);
        assert_eq!(banner, Some("Welcome!".to_string()));
    }

    #[test]
    fn auth_ok_no_banner() {
        let payload = build_auth_ok("1.4.2", &[], None);
        let (ver, caps, banner) = parse_auth_ok(&payload).unwrap();
        assert_eq!(ver, "1.4.2");
        assert!(caps.is_empty());
        assert!(banner.is_none());
    }

    #[test]
    fn exec_roundtrip() {
        let payload = build_exec("hostname", &["FOO=bar".to_string(), "BAZ=1".to_string()]);
        let (cmd, env) = parse_exec(&payload).unwrap();
        assert_eq!(cmd, "hostname");
        assert_eq!(env, vec!["FOO=bar", "BAZ=1"]);
    }

    #[test]
    fn exec_result_roundtrip() {
        let output = b"DESKTOP-ABC\r\n";
        let payload = build_exec_result(0, output);
        let (code, data) = parse_exec_result(&payload).unwrap();
        assert_eq!(code, 0);
        assert_eq!(data, output);
    }

    #[test]
    fn exec_result_failure() {
        let payload = build_exec_result(1, b"error: not found");
        let (code, data) = parse_exec_result(&payload).unwrap();
        assert_eq!(code, 1);
        assert_eq!(data, b"error: not found");
    }

    #[test]
    fn push_start_roundtrip() {
        let payload = build_push_start(78_000_000, r"C:\Temp\data.jsonl");
        let (size, path) = parse_push_start(&payload).unwrap();
        assert_eq!(size, 78_000_000);
        assert_eq!(path, r"C:\Temp\data.jsonl");
    }

    #[test]
    fn pull_req_roundtrip() {
        let payload = build_pull_req(r"C:\ProgramData\mrsh\audit.log");
        let path = parse_pull_req(&payload).unwrap();
        assert_eq!(path, r"C:\ProgramData\mrsh\audit.log");
    }

    #[test]
    fn error_roundtrip() {
        let payload = build_error("file not found: /tmp/test.txt");
        let err = parse_error(&payload).unwrap();
        assert_eq!(err, "file not found: /tmp/test.txt");
    }

    #[tokio::test]
    async fn exec_stream_flow() {
        // Simulate server sending streaming exec output
        let (mut client, mut server) = tokio::io::duplex(8192);

        // Server sends stdout chunk
        send_msg(&mut server, msg::EXEC_STDOUT, b"hello ").await.unwrap();
        let (tid, data) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::EXEC_STDOUT);
        assert_eq!(data, b"hello ");

        // Server sends stderr chunk
        send_msg(&mut server, msg::EXEC_STDERR, b"warning\n").await.unwrap();
        let (tid, data) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::EXEC_STDERR);
        assert_eq!(data, b"warning\n");

        // Server sends more stdout
        send_msg(&mut server, msg::EXEC_STDOUT, b"world\n").await.unwrap();
        let (tid, data) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::EXEC_STDOUT);
        assert_eq!(data, b"world\n");

        // Server sends exit code
        let exit_code: u32 = 0;
        send_msg(&mut server, msg::EXEC_EXIT, &exit_code.to_le_bytes()).await.unwrap();
        let (tid, data) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::EXEC_EXIT);
        assert_eq!(data.len(), 4);
        let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn exec_stream_nonzero_exit() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        // Error output on stderr, then non-zero exit
        send_msg(&mut server, msg::EXEC_STDERR, b"not found\n").await.unwrap();
        let exit_code: u32 = 1;
        send_msg(&mut server, msg::EXEC_EXIT, &exit_code.to_le_bytes()).await.unwrap();

        let (tid, _) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::EXEC_STDERR);
        let (tid, data) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::EXEC_EXIT);
        let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(code, 1);
    }

    #[test]
    fn decode_str_truncated() {
        let buf = vec![0x00, 0x05, 0x41, 0x42]; // claims 5 bytes, only has 2
        assert!(decode_str(&buf, 0).is_err());
    }

    #[test]
    fn decode_blob_truncated() {
        let buf = vec![0x00, 0x00, 0x00, 0x10]; // claims 16 bytes, has 0
        assert!(decode_blob(&buf, 0).is_err());
    }

    #[test]
    fn multiple_strings_sequential() {
        let mut buf = Vec::new();
        encode_str(&mut buf, "first");
        encode_str(&mut buf, "second");
        encode_str(&mut buf, "third");

        let (s1, off) = decode_str(&buf, 0).unwrap();
        let (s2, off) = decode_str(&buf, off).unwrap();
        let (s3, off) = decode_str(&buf, off).unwrap();
        assert_eq!(s1, "first");
        assert_eq!(s2, "second");
        assert_eq!(s3, "third");
        assert_eq!(off, buf.len());
    }

    #[tokio::test]
    async fn send_recv_msg_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_msg(&mut client, msg::EXEC, b"hostname").await.unwrap();
        let (type_id, payload) = recv_msg(&mut server).await.unwrap();
        assert_eq!(type_id, msg::EXEC);
        assert_eq!(payload, b"hostname");
    }

    #[tokio::test]
    async fn send_recv_empty_msg() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_empty(&mut client, msg::PING).await.unwrap();
        let (type_id, payload) = recv_msg(&mut server).await.unwrap();
        assert_eq!(type_id, msg::PING);
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn full_auth_flow() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        // Client sends AUTH_REQUEST
        let pubkey = vec![0xAA; 32];
        let req = build_auth_request(&pubkey, "1.4.2", &["binary-proto", "zstd"]);
        send_msg(&mut client, msg::AUTH_REQUEST, &req).await.unwrap();

        // Server receives and parses
        let (tid, payload) = recv_msg(&mut server).await.unwrap();
        assert_eq!(tid, msg::AUTH_REQUEST);
        let (pk, ver, caps) = parse_auth_request(&payload).unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(ver, "1.4.2");
        assert!(caps.contains(&"binary-proto".to_string()));

        // Server sends challenge (32 random bytes)
        let challenge = vec![0xBB; 32];
        send_msg(&mut server, msg::AUTH_CHALLENGE, &challenge).await.unwrap();

        // Client receives challenge
        let (tid, payload) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::AUTH_CHALLENGE);
        assert_eq!(payload.len(), 32);

        // Client sends signature (64 bytes)
        let sig = vec![0xCC; 64];
        send_msg(&mut client, msg::AUTH_RESPONSE, &sig).await.unwrap();

        // Server receives, verifies, sends OK
        let (tid, payload) = recv_msg(&mut server).await.unwrap();
        assert_eq!(tid, msg::AUTH_RESPONSE);
        assert_eq!(payload.len(), 64);

        let ok = build_auth_ok("1.4.2", &["self-update", "zstd"], None);
        send_msg(&mut server, msg::AUTH_OK, &ok).await.unwrap();

        // Client receives OK
        let (tid, payload) = recv_msg(&mut client).await.unwrap();
        assert_eq!(tid, msg::AUTH_OK);
        let (ver, caps, banner) = parse_auth_ok(&payload).unwrap();
        assert_eq!(ver, "1.4.2");
        assert!(banner.is_none());
    }
}
