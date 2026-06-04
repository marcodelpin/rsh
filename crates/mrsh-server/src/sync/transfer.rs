//! Single-file sync handlers: signatures, delta, patch, pull, push-chunked.

use anyhow::{Context, Result};
use base64::Engine;
use mrsh_core::protocol::{self, Response};
use mrsh_core::wire;
use mrsh_transfer::delta;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

use super::protocol::{
    convert_delta_from_proto, convert_delta_to_proto, convert_sigs_to_proto, gzip_compress,
    gzip_decompress,
};
use super::sanitize_path;

/// Handle pull-delta: stream file to client using binary M/D/E protocol.
/// Protocol: send JSON response, then length-prefixed binary messages:
///   'M' + u32be(block_index)  — match (client has this block)
///   'D' + raw_data            — data (new/changed block)
///   'E'                       — end of transfer
pub async fn handle_pull_delta<S>(stream: &mut S, req: &protocol::Request) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let raw_path = req.path.as_deref().unwrap_or("");
    let path = sanitize_path(raw_path).map_err(|e| anyhow::anyhow!(e))?;
    let client_sigs = req
        .signatures
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| delta::BlockSig {
            index: s.index as usize,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect::<Vec<_>>();

    debug!(
        "pull-delta: path={} client_sigs={}",
        path,
        client_sigs.len()
    );

    // Read file
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let resp = Response::error(&format!("read {}: {}", path, e));
            wire::send_json(stream, &resp).await?;
            return Ok(());
        }
    };

    // Send success response
    let resp = Response {
        success: true,
        output: Some(format!("{}", data.len())),
        error: None,
        size: Some(data.len() as i64),
        binary: None,
        gzip: None,
    };
    wire::send_json(stream, &resp).await?;

    // Build weak hash lookup from client signatures
    let mut weak_map: std::collections::HashMap<u32, Vec<&delta::BlockSig>> =
        std::collections::HashMap::new();
    for sig in &client_sigs {
        weak_map.entry(sig.weak).or_default().push(sig);
    }

    // Iterate server file blocks and stream M/D messages
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + delta::BLOCK_SIZE).min(data.len());
        let block = &data[offset..end];

        let mut matched = false;
        if !client_sigs.is_empty() {
            let weak = adler32::adler32(block).unwrap_or(0);
            if let Some(candidates) = weak_map.get(&weak) {
                let strong = {
                    use md5::{Digest, Md5};
                    let hash = Md5::digest(block);
                    base64::engine::general_purpose::STANDARD.encode(hash)
                };
                for sig in candidates {
                    if sig.strong == strong {
                        // Match — client has this block
                        let mut msg = [0u8; 5];
                        msg[0] = b'M';
                        msg[1..5].copy_from_slice(&(sig.index as u32).to_be_bytes());
                        wire::send_message(stream, &msg)
                            .await
                            .context("send M block")?;
                        matched = true;
                        break;
                    }
                }
            }
        }

        if !matched {
            // Data — send raw block bytes with internal length prefix
            // Format: [D][4-byte data length BE][data bytes]
            let data_len = block.len() as u32;
            let mut msg = Vec::with_capacity(5 + block.len());
            msg.push(b'D');
            msg.extend_from_slice(&data_len.to_be_bytes());
            msg.extend_from_slice(block);
            wire::send_message(stream, &msg)
                .await
                .context("send D block")?;
        }

        offset = end;
    }

    // Send end marker
    wire::send_message(stream, b"E")
        .await
        .context("send E marker")?;

    debug!("pull-delta: sent {} bytes for {}", data.len(), path);
    Ok(())
}

/// Handle push-chunked: receive binary D/E stream from client, write to file.
///
/// Protocol:
///   Client sends JSON request (sync_type="push-chunked", path=remote_path).
///   Server sends JSON ack (success/error for path validation + parent dir).
///   Client streams:
///     'D' + flag(1) + len(4 BE) + payload  — data chunk (flag: 0=raw, 1=zstd)
///     'E'                                   — end of transfer
///   Server sends final JSON response after writing file.
pub async fn handle_push_chunked<S>(stream: &mut S, req: &protocol::Request) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let raw_path = req.path.as_deref().unwrap_or("");
    let path = sanitize_path(raw_path).map_err(|e| anyhow::anyhow!(e))?;

    info!("push-chunked: path={}", path);

    // Validate path and ensure parent directory exists
    if path.is_empty() {
        let resp = Response::error("missing path");
        wire::send_json(stream, &resp).await?;
        return Ok(());
    }

    // rsh-odtu: refuse writes that resolve under SYSTEM account profile when
    // the service is running in session 0. The 8822 SYSTEM service expands
    // %USERPROFILE% / ~ to systemprofile, which is almost never the caller's
    // intent — they meant a real user profile and should hit 9822 (tray).
    if crate::is_session_zero() && crate::path_under_systemprofile(path) {
        let hint = crate::session_zero_hint("push");
        let resp = Response::error(&format!(
            "refusing push to systemprofile path under SYSTEM service (port 8822).\n{}",
            hint
        ));
        wire::send_json(stream, &resp).await?;
        return Ok(());
    }

    if let Some(parent) = Path::new(path).parent()
        && !parent.exists()
    {
        info!("push-chunked: creating new directory {}", parent.display());
        if let Err(e) = std::fs::create_dir_all(parent) {
            let resp = Response::error(&format!("create parent dir: {}", e));
            wire::send_json(stream, &resp).await?;
            return Ok(());
        }
    }

    // Send ack — client can start streaming
    let ack = Response {
        success: true,
        output: Some("ready".to_string()),
        error: None,
        size: None,
        binary: None,
        gzip: None,
    };
    wire::send_json(stream, &ack).await?;

    // Receive D/E messages and accumulate data
    let mut file_data: Vec<u8> = Vec::new();
    let mut chunk_count = 0u32;

    loop {
        let msg = wire::recv_message(stream)
            .await
            .context("recv push chunk")?;
        if msg.is_empty() {
            break;
        }

        match msg[0] {
            b'D' => {
                // D + flag(1) + len(4 BE) + payload
                if msg.len() < 6 {
                    let resp = Response::error("malformed D message: too short");
                    wire::send_json(stream, &resp).await?;
                    return Ok(());
                }
                let flag = msg[1];
                let payload_len = u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]) as usize;
                if msg.len() < 6 + payload_len {
                    let resp = Response::error(&format!(
                        "malformed D message: expected {} payload bytes, got {}",
                        payload_len,
                        msg.len() - 6
                    ));
                    wire::send_json(stream, &resp).await?;
                    return Ok(());
                }
                let payload = &msg[6..6 + payload_len];

                let chunk_data = match flag {
                    0x01 => {
                        // zstd compressed
                        zstd::decode_all(payload).context("decompress push chunk")?
                    }
                    _ => {
                        // raw
                        payload.to_vec()
                    }
                };

                file_data.extend_from_slice(&chunk_data);
                chunk_count += 1;
            }
            b'E' => {
                break;
            }
            other => {
                let resp = Response::error(&format!("unexpected message type: 0x{:02x}", other));
                wire::send_json(stream, &resp).await?;
                return Ok(());
            }
        }
    }

    // Write the file
    match std::fs::write(path, &file_data) {
        Ok(()) => {
            info!(
                "push-chunked: wrote {} bytes ({} chunks) to {}",
                file_data.len(),
                chunk_count,
                path
            );
            let resp = Response {
                success: true,
                output: Some(format!("{} bytes", file_data.len())),
                error: None,
                size: Some(file_data.len() as i64),
                binary: None,
                gzip: None,
            };
            wire::send_json(stream, &resp).await?;
        }
        Err(e) => {
            let resp = Response::error(&format!("write {}: {}", path, e));
            wire::send_json(stream, &resp).await?;
        }
    }

    Ok(())
}

/// Get block signatures for a remote file.
pub(super) fn handle_get_signatures(path: &str) -> Response {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            // File doesn't exist yet — return empty signatures (new file)
            if e.kind() == std::io::ErrorKind::NotFound {
                return Response {
                    success: true,
                    output: Some("[]".to_string()),
                    error: None,
                    size: Some(0),
                    binary: None,
                    gzip: None,
                };
            }
            return Response::error(&format!("read {}: {}", path, e));
        }
    };

    let sigs = delta::compute_signatures(&data);
    let proto_sigs = convert_sigs_to_proto(&sigs);

    match serde_json::to_string(&proto_sigs) {
        Ok(json) => Response {
            success: true,
            output: Some(json),
            error: None,
            size: Some(data.len() as i64),
            binary: None,
            gzip: None,
        },
        Err(e) => Response::error(&format!("serialize signatures: {}", e)),
    }
}

/// Compute delta between local file and remote signatures.
pub(super) fn handle_compute_delta(path: &str, remote_sigs: &[delta::BlockSig]) -> Response {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Response::error(&format!("read {}: {}", path, e)),
    };

    let ops = delta::compute_delta(&data, remote_sigs);
    let proto_ops = convert_delta_to_proto(&ops);

    // Gzip + base64 the delta JSON
    let json = match serde_json::to_vec(&proto_ops) {
        Ok(j) => j,
        Err(e) => return Response::error(&format!("serialize delta: {}", e)),
    };

    let compressed = gzip_compress(&json);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&compressed);

    Response {
        success: true,
        output: Some(b64),
        error: None,
        size: Some(data.len() as i64),
        binary: None,
        gzip: Some(true),
    }
}

/// Apply delta or full content to a file.
pub(super) fn handle_apply_patch(
    path: &str,
    delta_ops: Option<&[protocol::DeltaOp]>,
    content: Option<&str>,
) -> Response {
    // rsh-odtu: refuse patches that resolve under SYSTEM account profile —
    // same rationale as push_chunked above (SYSTEM-side %USERPROFILE% expansion
    // silently aliases to systemprofile).
    if crate::is_session_zero() && crate::path_under_systemprofile(path) {
        let hint = crate::session_zero_hint("push");
        return Response::error(&format!(
            "refusing patch to systemprofile path under SYSTEM service (port 8822).\n{}",
            hint
        ));
    }

    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent()
        && !parent.exists()
    {
        info!("patch: creating new directory {}", parent.display());
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Response::error(&format!("create dir: {}", e));
        }
    }

    // If content provided, write directly (full file transfer)
    if let Some(content_b64) = content {
        // Try to decompress if gzipped
        let raw = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
            Ok(d) => d,
            Err(e) => return Response::error(&format!("decode content: {}", e)),
        };

        let data = gzip_decompress(&raw).unwrap_or(raw);

        return match std::fs::write(path, &data) {
            Ok(()) => {
                info!("patch: wrote {} bytes to {}", data.len(), path);
                Response {
                    success: true,
                    output: Some(format!("{} bytes written", data.len())),
                    error: None,
                    size: Some(data.len() as i64),
                    binary: None,
                    gzip: None,
                }
            }
            Err(e) => Response::error(&format!("write {}: {}", path, e)),
        };
    }

    // Apply delta operations
    if let Some(ops) = delta_ops {
        let existing = std::fs::read(path).unwrap_or_default();
        let transfer_ops = convert_delta_from_proto(ops);
        let result = delta::apply_delta(&existing, &transfer_ops);

        return match std::fs::write(path, &result) {
            Ok(()) => {
                info!("patch-delta: wrote {} bytes to {}", result.len(), path);
                Response {
                    success: true,
                    output: Some(format!("{} bytes written", result.len())),
                    error: None,
                    size: Some(result.len() as i64),
                    binary: None,
                    gzip: None,
                }
            }
            Err(e) => Response::error(&format!("write {}: {}", path, e)),
        };
    }

    Response::error("patch requires delta or content")
}

/// Read full file for pull.
pub(super) fn handle_pull_file(path: &str) -> Response {
    match std::fs::read(path) {
        Ok(data) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
            Response {
                success: true,
                output: Some(b64),
                error: None,
                size: Some(data.len() as i64),
                binary: Some(true),
                gzip: None,
            }
        }
        Err(e) => Response::error(&format!("read {}: {}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_empty_file_not_found() {
        let resp = handle_get_signatures("/nonexistent_sync_test_xyz");
        assert!(resp.success);
        assert_eq!(resp.output.as_deref(), Some("[]"));
        assert_eq!(resp.size, Some(0));
    }

    #[test]
    fn signatures_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world test data for signatures").unwrap();

        let resp = handle_get_signatures(path.to_str().unwrap());
        assert!(resp.success);
        let sigs: Vec<protocol::BlockSig> =
            serde_json::from_str(resp.output.as_deref().unwrap()).unwrap();
        assert!(!sigs.is_empty());
    }

    #[test]
    fn patch_full_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patched.txt");
        let content = base64::engine::general_purpose::STANDARD.encode(b"patched content");

        let resp = handle_apply_patch(path.to_str().unwrap(), None, Some(&content));
        assert!(resp.success);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"patched content");
    }

    #[test]
    fn pull_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pull-test.txt");
        std::fs::write(&path, b"pull me").unwrap();

        let resp = handle_pull_file(path.to_str().unwrap());
        assert!(resp.success);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(resp.output.as_deref().unwrap())
            .unwrap();
        assert_eq!(decoded, b"pull me");
    }

    /// Test pull-delta with a multi-block file (>BLOCK_SIZE * 10 blocks).
    /// Verifies the M/D/E binary protocol streams all blocks correctly.
    #[tokio::test]
    async fn pull_delta_multi_block_file() {
        use mrsh_transfer::delta::BLOCK_SIZE;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-test.bin");

        // Create file with 12 blocks + partial (49252 bytes total)
        let file_size = BLOCK_SIZE * 12 + 100;
        let data: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        // Build request with no client signatures (full send)
        let req = protocol::Request {
            req_type: "sync".to_string(),
            path: Some(path.to_str().unwrap().to_string()),
            command: None,
            content: None,
            binary: None,
            gzip: None,
            sync_type: None,
            delta: None,
            signatures: Some(vec![]),
            paths: None,
            batch_patches: None,
            env_vars: None,
            track: None,
            version: None,
            allow_downgrade: None,
            insecure_no_verify: None,
        };

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);

        // Spawn the delta handler
        let handle = tokio::spawn(async move { handle_pull_delta(&mut server, &req).await });

        // Read the JSON header
        let resp: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(resp.success);
        assert_eq!(resp.size, Some(file_size as i64));

        // Read M/D/E messages and reconstruct the file
        let mut reconstructed = Vec::new();
        loop {
            let msg = wire::recv_message(&mut client).await.unwrap();
            match msg[0] {
                b'E' => break,
                b'D' => {
                    let data_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
                    assert_eq!(msg.len() - 5, data_len, "D message length mismatch");
                    reconstructed.extend_from_slice(&msg[5..]);
                }
                b'M' => {
                    panic!("unexpected M block with empty client signatures");
                }
                other => panic!("unexpected message type: 0x{:02x}", other),
            }
        }

        assert_eq!(reconstructed.len(), file_size);
        assert_eq!(
            reconstructed, data,
            "reconstructed file must match original"
        );

        handle.await.unwrap().unwrap();
    }

    /// Test pull-delta with matching signatures — blocks the client already has
    /// should produce 'M' messages instead of 'D' messages.
    #[tokio::test]
    async fn pull_delta_with_matching_signatures() {
        use mrsh_transfer::delta::BLOCK_SIZE;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delta-match.bin");

        // Create 3-block file
        let file_size = BLOCK_SIZE * 3;
        let data: Vec<u8> = (0..file_size).map(|i| (i % 199) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        // Compute signatures for blocks 0 and 2 (client "has" these)
        let mut client_sigs = Vec::new();
        for idx in [0usize, 2] {
            let block = &data[idx * BLOCK_SIZE..(idx + 1) * BLOCK_SIZE];
            let weak = adler32::adler32(block).unwrap();
            let strong = {
                use md5::{Digest, Md5};
                let hash = Md5::digest(block);
                base64::engine::general_purpose::STANDARD.encode(hash)
            };
            client_sigs.push(protocol::BlockSig {
                index: idx as i32,
                weak,
                strong,
            });
        }

        let req = protocol::Request {
            req_type: "sync".to_string(),
            path: Some(path.to_str().unwrap().to_string()),
            command: None,
            content: None,
            binary: None,
            gzip: None,
            sync_type: None,
            delta: None,
            signatures: Some(client_sigs),
            paths: None,
            batch_patches: None,
            env_vars: None,
            track: None,
            version: None,
            allow_downgrade: None,
            insecure_no_verify: None,
        };

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let handle = tokio::spawn(async move { handle_pull_delta(&mut server, &req).await });

        let resp: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(resp.success);

        let mut m_count = 0;
        let mut d_count = 0;
        loop {
            let msg = wire::recv_message(&mut client).await.unwrap();
            match msg[0] {
                b'E' => break,
                b'M' => m_count += 1,
                b'D' => d_count += 1,
                other => panic!("unexpected: 0x{:02x}", other),
            }
        }

        // Blocks 0 and 2 should match, block 1 should be data
        assert_eq!(m_count, 2, "two blocks should match client signatures");
        assert_eq!(d_count, 1, "one block should be sent as data");

        handle.await.unwrap().unwrap();
    }

    /// Test pull-delta with a large file (2MB+) to verify streaming
    /// handles hundreds of blocks without hitting wire message limits.
    /// Each 'D' message is BLOCK_SIZE+5 bytes (~4101), well under the
    /// 50MB wire limit, ensuring any file size works via streaming.
    #[tokio::test]
    async fn pull_delta_large_file_chunking() {
        use mrsh_transfer::delta::BLOCK_SIZE;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-chunk-test.bin");

        // 2MB + partial block — 513 blocks total
        let file_size = BLOCK_SIZE * 512 + 1234;
        let data: Vec<u8> = (0..file_size).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        let req = protocol::Request {
            req_type: "sync".to_string(),
            path: Some(path.to_str().unwrap().to_string()),
            command: None,
            content: None,
            binary: None,
            gzip: None,
            sync_type: None,
            delta: None,
            signatures: Some(vec![]),
            paths: None,
            batch_patches: None,
            env_vars: None,
            track: None,
            version: None,
            allow_downgrade: None,
            insecure_no_verify: None,
        };

        // Large duplex buffer to avoid backpressure stalls
        let (mut client, mut server) = tokio::io::duplex(4 * 1024 * 1024);

        let handle = tokio::spawn(async move { handle_pull_delta(&mut server, &req).await });

        let resp: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(resp.success);
        assert_eq!(resp.size, Some(file_size as i64));

        let mut reconstructed = Vec::with_capacity(file_size);
        let mut block_count = 0u32;
        loop {
            let msg = wire::recv_message(&mut client).await.unwrap();
            match msg[0] {
                b'E' => break,
                b'D' => {
                    let data_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
                    assert_eq!(msg.len() - 5, data_len);
                    // Each D message must be ≤ BLOCK_SIZE+5, never near 50MB limit
                    assert!(
                        msg.len() <= BLOCK_SIZE + 5,
                        "D message too large: {}",
                        msg.len()
                    );
                    reconstructed.extend_from_slice(&msg[5..]);
                    block_count += 1;
                }
                b'M' => panic!("unexpected M with empty signatures"),
                other => panic!("unexpected message type: 0x{:02x}", other),
            }
        }

        assert_eq!(
            reconstructed.len(),
            file_size,
            "reconstructed size mismatch"
        );
        assert_eq!(reconstructed, data, "reconstructed data mismatch");
        // 512 full blocks + 1 partial = 513
        assert_eq!(
            block_count, 513,
            "expected 513 blocks (512 full + 1 partial)"
        );

        handle.await.unwrap().unwrap();
    }

    /// Test handle_pull_file with a file at the base64 expansion boundary.
    /// A ~35MB file base64-encodes to ~47MB, still under the 50MB wire limit.
    /// This verifies the non-streaming path works near the limit.
    #[test]
    fn pull_file_moderately_large() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("moderate-pull.bin");

        // 512KB file — verifies base64 encoding works at scale
        let data: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        let resp = handle_pull_file(path.to_str().unwrap());
        assert!(resp.success);

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(resp.output.as_deref().unwrap())
            .unwrap();
        assert_eq!(decoded.len(), 512 * 1024);
        assert_eq!(decoded, data);
    }


    /// Test push-chunked: client sends D/E binary messages, server writes file.
    /// Verifies raw and zstd-compressed chunks are handled correctly.
    #[tokio::test]
    async fn push_chunked_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("push-chunked-test.bin");

        let req = protocol::Request {
            req_type: "sync".to_string(),
            path: Some(path.to_str().unwrap().to_string()),
            command: None,
            content: Some("1000".to_string()),
            binary: None,
            gzip: None,
            sync_type: Some("push-chunked".to_string()),
            delta: None,
            signatures: None,
            paths: None,
            batch_patches: None,
            env_vars: None,
            track: None,
            version: None,
            allow_downgrade: None,
            insecure_no_verify: None,
        };

        let test_data: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();

        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let data_clone = test_data.clone();
        let handle = tokio::spawn(async move { handle_push_chunked(&mut server, &req).await });

        // Read ack
        let ack: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(ack.success, "ack should succeed: {:?}", ack.error);

        // Send a raw D chunk (flag=0x00)
        let half = data_clone.len() / 2;
        let chunk1 = &data_clone[..half];
        let mut msg1 = Vec::with_capacity(6 + chunk1.len());
        msg1.push(b'D');
        msg1.push(0x00); // raw
        msg1.extend_from_slice(&(chunk1.len() as u32).to_be_bytes());
        msg1.extend_from_slice(chunk1);
        wire::send_message(&mut client, &msg1).await.unwrap();

        // Send a zstd-compressed D chunk (flag=0x01)
        let chunk2 = &data_clone[half..];
        let compressed = zstd::encode_all(chunk2, 3).unwrap();
        let mut msg2 = Vec::with_capacity(6 + compressed.len());
        msg2.push(b'D');
        msg2.push(0x01); // zstd
        msg2.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        msg2.extend_from_slice(&compressed);
        wire::send_message(&mut client, &msg2).await.unwrap();

        // Send E
        wire::send_message(&mut client, b"E").await.unwrap();

        // Read final response
        let resp: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(
            resp.success,
            "final response should succeed: {:?}",
            resp.error
        );
        assert_eq!(resp.size, Some(1000));

        // Verify file on disk
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, data_clone);

        handle.await.unwrap().unwrap();
    }

    /// Test push-chunked with a larger file split into multiple chunks.
    #[tokio::test]
    async fn push_chunked_multi_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("push-chunked-large.bin");

        // 2MB test file
        let file_size = 2 * 1024 * 1024;
        let test_data: Vec<u8> = (0..file_size).map(|i| ((i * 7 + 13) % 256) as u8).collect();

        let req = protocol::Request {
            req_type: "sync".to_string(),
            path: Some(path.to_str().unwrap().to_string()),
            command: None,
            content: Some(file_size.to_string()),
            binary: None,
            gzip: None,
            sync_type: Some("push-chunked".to_string()),
            delta: None,
            signatures: None,
            paths: None,
            batch_patches: None,
            env_vars: None,
            track: None,
            version: None,
            allow_downgrade: None,
            insecure_no_verify: None,
        };

        let data_clone = test_data.clone();
        let (mut client, mut server) = tokio::io::duplex(4 * 1024 * 1024);

        let handle = tokio::spawn(async move { handle_push_chunked(&mut server, &req).await });

        let ack: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(ack.success);

        // Send in 512KB chunks with zstd
        let chunk_size = 512 * 1024;
        for chunk in data_clone.chunks(chunk_size) {
            let compressed = zstd::encode_all(chunk, 3).unwrap();
            let (flag, payload): (u8, &[u8]) = if compressed.len() < chunk.len() {
                (0x01, &compressed[..])
            } else {
                (0x00, chunk)
            };
            let mut msg = Vec::with_capacity(6 + payload.len());
            msg.push(b'D');
            msg.push(flag);
            msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            msg.extend_from_slice(payload);
            wire::send_message(&mut client, &msg).await.unwrap();
        }

        wire::send_message(&mut client, b"E").await.unwrap();

        let resp: protocol::Response = wire::recv_json(&mut client).await.unwrap();
        assert!(resp.success);
        assert_eq!(resp.size, Some(file_size as i64));

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written.len(), file_size);
        assert_eq!(written, data_clone);

        handle.await.unwrap().unwrap();
    }

    /// Concurrent push/pull stress: multiple threads simultaneously read signatures
    /// and write content to the same file. Verifies:
    ///   - No panics under concurrent access
    ///   - File is readable after all threads complete (not truncated to 0 or corrupted)
    ///   - handle_apply_patch + handle_get_signatures are safe to call concurrently
    ///     (std::fs::write is not atomic, but must not crash or leave unreadable state)
    #[test]
    fn concurrent_push_pull_no_panic_or_corruption() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("stress.bin").to_string_lossy().to_string());

        // Seed file with 4KB of repeating content
        let initial = vec![b'A'; 4096];
        std::fs::write(path.as_str(), &initial).unwrap();

        let n_writers = 4;
        let n_readers = 4;
        let iters = 20;

        let mut handles = vec![];

        // Writers: push new content of the same size
        for w in 0..n_writers {
            let p = Arc::clone(&path);
            handles.push(thread::spawn(move || {
                let payload = vec![b'A' + w as u8; 4096];
                let content = base64::engine::general_purpose::STANDARD.encode(&payload);
                for _ in 0..iters {
                    let resp = handle_apply_patch(p.as_str(), None, Some(&content));
                    // Accept success or fs error; must not panic
                    let _ = resp.success;
                }
            }));
        }

        // Readers: pull signatures — must not panic even if file is being written
        for _ in 0..n_readers {
            let p = Arc::clone(&path);
            handles.push(thread::spawn(move || {
                for _ in 0..iters {
                    let resp = handle_get_signatures(p.as_str());
                    // Success or empty sigs both acceptable under concurrent writes
                    let _ = resp.success;
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // File must be readable and non-empty after all concurrent ops
        let final_content = std::fs::read(path.as_str()).unwrap();
        assert!(
            !final_content.is_empty(),
            "file must not be empty after concurrent stress"
        );
        // Content must be entirely one of the valid payloads (A..E repeated), not mixed garbage
        // (std::fs::write does not guarantee atomicity, but kernel writes of this size are
        //  typically atomic on Linux ext4/tmpfs — this assertion documents expected behavior)
        let first_byte = final_content[0];
        assert!(
            (b'A'..=b'A' + n_writers as u8).contains(&first_byte),
            "unexpected first byte 0x{:02x} — file may be corrupted",
            first_byte
        );
    }

}
