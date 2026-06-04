//! Single-file push/pull — delta sync via rolling-hash + chunked streaming.
//!
//! - `push` / `push_file` — upload to remote with delta if remote has signatures,
//!   otherwise streamed full upload.
//! - `pull` — download from remote with delta-aware M/D/E binary protocol.

use anyhow::{Context, Result, bail};
use mrsh_core::protocol::Response;
use mrsh_core::wire;
use mrsh_transfer::delta;
use std::io::Read as StdRead;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

use super::PushResult;
use super::PullResult;
use super::protocol::check_response;

/// Chunk size for binary push (10 MB).
const PUSH_CHUNK_SIZE: usize = 10 * 1024 * 1024;

// ── Push ────────────────────────────────────────────────────────

/// Push data from memory to remote host.
/// Uses delta sync if remote has signatures, otherwise chunked full upload.
/// For large files, prefer `push_file()` which streams from disk.
pub async fn push<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_data: &[u8],
    remote_path: &str,
) -> Result<PushResult> {
    // Step 1: Request remote file signatures
    let mut req = simple_request("push-sigs");
    req.path = Some(remote_path.to_string());
    let resp = client.request(&req).await?;

    if !resp.success {
        return push_full(client, local_data, remote_path).await;
    }

    let sigs_json = resp.output.unwrap_or_default();
    let remote_sigs: Vec<mrsh_core::protocol::BlockSig> =
        serde_json::from_str(&sigs_json).unwrap_or_default();

    if remote_sigs.is_empty() {
        return push_full(client, local_data, remote_path).await;
    }

    push_delta(client, local_data, remote_path, &remote_sigs).await
}

/// Push a local file by path — streams from disk, never loads entire file.
/// For delta sync, reads into memory only if remote has signatures (delta needs
/// full data for rolling hash). For full upload, streams chunk-by-chunk.
pub async fn push_file<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_path: &Path,
    remote_path: &str,
) -> Result<PushResult> {
    let file_size = std::fs::metadata(local_path)
        .map(|m| m.len())
        .context("stat local file")?;

    // Step 1: Request remote file signatures
    let mut req = simple_request("push-sigs");
    req.path = Some(remote_path.to_string());
    let resp = client.request(&req).await?;

    if !resp.success {
        // Remote file doesn't exist — stream full upload from disk
        return push_full_streaming(client, local_path, file_size, remote_path).await;
    }

    // Step 2: Parse remote signatures
    let sigs_json = resp.output.unwrap_or_default();
    let remote_sigs: Vec<mrsh_core::protocol::BlockSig> =
        serde_json::from_str(&sigs_json).unwrap_or_default();

    if remote_sigs.is_empty() {
        return push_full_streaming(client, local_path, file_size, remote_path).await;
    }

    // Delta sync requires full file in memory (rolling hash comparison).
    // This is acceptable: delta is only used when remote already has a version,
    // meaning transfers are small (only changed blocks).
    let local_data = std::fs::read(local_path).context("read local file for delta")?;
    push_delta(client, &local_data, remote_path, &remote_sigs).await
}

/// Delta push — send only changed blocks (requires data in memory for rolling hash).
async fn push_delta<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_data: &[u8],
    remote_path: &str,
    remote_sigs: &[mrsh_core::protocol::BlockSig],
) -> Result<PushResult> {
    let transfer_sigs: Vec<delta::BlockSig> = remote_sigs
        .iter()
        .map(|s| delta::BlockSig {
            index: s.index as usize,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect();

    let ops = delta::compute_delta(local_data, &transfer_sigs);

    let proto_ops: Vec<mrsh_core::protocol::DeltaOp> = ops
        .iter()
        .map(|op| mrsh_core::protocol::DeltaOp {
            op_type: op.op_type.clone(),
            index: if op.op_type == "match" {
                Some(op.index as i32)
            } else {
                None
            },
            data: if op.op_type == "data" {
                Some(op.data.clone())
            } else {
                None
            },
        })
        .collect();

    let mut patch_req = simple_request("push-delta");
    patch_req.path = Some(remote_path.to_string());
    patch_req.delta = Some(proto_ops);

    let patch_resp = client.request(&patch_req).await?;
    check_response(&patch_resp)?;

    Ok(PushResult {
        path: remote_path.to_string(),
        bytes_sent: local_data.len(),
        delta: true,
    })
}

/// Full upload streaming from disk — never loads entire file into memory.
/// Reads PUSH_CHUNK_SIZE bytes at a time, compresses with zstd, sends as D message.
async fn push_full_streaming<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_path: &Path,
    file_size: u64,
    remote_path: &str,
) -> Result<PushResult> {
    // Step 1: Send sync request to initiate chunked push
    let mut req = simple_request("sync");
    req.sync_type = Some("push-chunked".to_string());
    req.path = Some(remote_path.to_string());
    req.content = Some(file_size.to_string());

    wire::send_json(client.stream_mut(), &req)
        .await
        .context("send push-chunked request")?;
    let ack: Response = wire::recv_json(client.stream_mut())
        .await
        .context("recv push-chunked ack")?;

    if !ack.success {
        bail!(
            "push-chunked rejected: {}",
            ack.error.as_deref().unwrap_or("unknown")
        );
    }

    // Step 2: Stream from disk chunk-by-chunk
    let mut file = std::fs::File::open(local_path).context("open local file")?;
    let mut buf = vec![0u8; PUSH_CHUNK_SIZE];
    let mut total_sent = 0u64;

    loop {
        let n = file.read(&mut buf).context("read chunk from disk")?;
        if n == 0 {
            break;
        }

        let chunk = &buf[..n];
        let compressed = zstd::encode_all(chunk, 3).context("zstd compress chunk")?;
        let (flag, payload): (u8, &[u8]) = if compressed.len() < chunk.len() {
            (0x01, &compressed)
        } else {
            (0x00, chunk)
        };

        let payload_len = payload.len() as u32;
        let mut msg = Vec::with_capacity(6 + payload.len());
        msg.push(b'D');
        msg.push(flag);
        msg.extend_from_slice(&payload_len.to_be_bytes());
        msg.extend_from_slice(payload);
        wire::send_message(client.stream_mut(), &msg)
            .await
            .context("send D chunk")?;

        total_sent += n as u64;
    }

    // Step 3: Send end marker
    wire::send_message(client.stream_mut(), b"E")
        .await
        .context("send E marker")?;

    // Step 4: Receive final response
    let resp: Response = wire::recv_json(client.stream_mut())
        .await
        .context("recv push-chunked result")?;
    check_response(&resp)?;

    Ok(PushResult {
        path: remote_path.to_string(),
        bytes_sent: total_sent as usize,
        delta: false,
    })
}

/// Full upload without delta — in-memory variant (for tests and small data).
/// Delegates to the streaming protocol but from a memory buffer.
async fn push_full<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    data: &[u8],
    remote_path: &str,
) -> Result<PushResult> {
    let mut req = simple_request("sync");
    req.sync_type = Some("push-chunked".to_string());
    req.path = Some(remote_path.to_string());
    req.content = Some(data.len().to_string());

    wire::send_json(client.stream_mut(), &req)
        .await
        .context("send push-chunked request")?;
    let ack: Response = wire::recv_json(client.stream_mut())
        .await
        .context("recv push-chunked ack")?;

    if !ack.success {
        bail!(
            "push-chunked rejected: {}",
            ack.error.as_deref().unwrap_or("unknown")
        );
    }

    for chunk in data.chunks(PUSH_CHUNK_SIZE) {
        let compressed = zstd::encode_all(chunk, 3).context("zstd compress chunk")?;
        let (flag, payload): (u8, &[u8]) = if compressed.len() < chunk.len() {
            (0x01, &compressed)
        } else {
            (0x00, chunk)
        };

        let payload_len = payload.len() as u32;
        let mut msg = Vec::with_capacity(6 + payload.len());
        msg.push(b'D');
        msg.push(flag);
        msg.extend_from_slice(&payload_len.to_be_bytes());
        msg.extend_from_slice(payload);
        wire::send_message(client.stream_mut(), &msg)
            .await
            .context("send D chunk")?;
    }

    wire::send_message(client.stream_mut(), b"E")
        .await
        .context("send E marker")?;

    let resp: Response = wire::recv_json(client.stream_mut())
        .await
        .context("recv push-chunked result")?;
    check_response(&resp)?;

    Ok(PushResult {
        path: remote_path.to_string(),
        bytes_sent: data.len(),
        delta: false,
    })
}

// ── Pull ────────────────────────────────────────────────────────

/// Pull a remote file to local.
/// Uses delta sync: sends sigs of local → server computes delta → applies.
pub async fn pull<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_data: Option<&[u8]>,
    remote_path: &str,
) -> Result<PullResult> {
    // Step 1: Compute local signatures (empty if no local file)
    let local_sigs = match local_data {
        Some(data) if !data.is_empty() => delta::compute_signatures(data),
        _ => Vec::new(),
    };

    // Step 2: Send pull request with local sigs
    let proto_sigs: Vec<mrsh_core::protocol::BlockSig> = local_sigs
        .iter()
        .map(|s| mrsh_core::protocol::BlockSig {
            index: s.index as i32,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect();

    let mut req = simple_request("sync");
    req.sync_type = Some("pull-delta".to_string());
    req.path = Some(remote_path.to_string());
    req.signatures = Some(proto_sigs);

    // Send request and read JSON ack (server sends success + file size)
    wire::send_json(client.stream_mut(), &req)
        .await
        .context("send pull-delta request")?;
    let resp: Response = wire::recv_json(client.stream_mut())
        .await
        .context("recv pull-delta ack")?;
    check_response(&resp)?;

    // Step 3: Read binary M/D/E stream from server
    let local_blocks: Vec<&[u8]> = match local_data {
        Some(data) if !data.is_empty() => data.chunks(delta::BLOCK_SIZE).collect(),
        _ => Vec::new(),
    };

    let mut result_data = Vec::new();

    loop {
        let msg = wire::recv_message(client.stream_mut())
            .await
            .context("recv pull-delta block")?;
        if msg.is_empty() {
            bail!("pull-delta: empty message from server");
        }
        match msg[0] {
            b'M' => {
                // Match — client has this block, copy from local data
                if msg.len() < 5 {
                    bail!("pull-delta: M message too short");
                }
                let idx = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
                if idx < local_blocks.len() {
                    result_data.extend_from_slice(local_blocks[idx]);
                } else {
                    bail!(
                        "pull-delta: M block index {} out of range (have {})",
                        idx,
                        local_blocks.len()
                    );
                }
            }
            b'D' => {
                // Data — new/changed block from server
                if msg.len() < 5 {
                    bail!("pull-delta: D message too short");
                }
                let data_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
                if msg.len() < 5 + data_len {
                    bail!(
                        "pull-delta: D message truncated (expected {} bytes, got {})",
                        data_len,
                        msg.len() - 5
                    );
                }
                result_data.extend_from_slice(&msg[5..5 + data_len]);
            }
            b'E' => {
                // End of transfer
                break;
            }
            other => {
                bail!("pull-delta: unknown message type 0x{:02x}", other);
            }
        }
    }

    let has_delta = !local_blocks.is_empty();
    Ok(PullResult {
        data: result_data,
        delta: has_delta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RshClient;
    use mrsh_core::protocol::Request;
    use mrsh_core::wire;
    use tokio::io::DuplexStream;

    fn mock_client() -> (RshClient<DuplexStream>, DuplexStream) {
        let (client_end, server_end) = tokio::io::duplex(16384);
        (RshClient::new_mock(client_end), server_end)
    }

    fn ok_response(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        }
    }

    fn err_response(error: &str) -> Response {
        Response {
            success: false,
            output: None,
            error: Some(error.to_string()),
            size: None,
            binary: None,
            gzip: None,
        }
    }

    // ── Push: full upload (no remote file) ──────────────────────────

    #[tokio::test]
    async fn push_full_upload_when_no_remote() {
        let (mut client, mut server) = mock_client();
        let data = b"new file content";

        let h = tokio::spawn(async move {
            // Step 1: push-sigs request → error (no remote file)
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-sigs");
            assert_eq!(req.path.as_deref(), Some("/tmp/test.txt"));
            wire::send_json(&mut server, &err_response("file not found"))
                .await
                .unwrap();

            // Step 2: push-chunked sync request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("push-chunked"));
            assert_eq!(req.path.as_deref(), Some("/tmp/test.txt"));
            // content carries total size
            assert_eq!(req.content.as_deref(), Some("16"));

            // Send ack
            wire::send_json(&mut server, &ok_response("ready"))
                .await
                .unwrap();

            // Read D message(s)
            let mut received_data = Vec::new();
            loop {
                let msg = wire::recv_message(&mut server).await.unwrap();
                match msg[0] {
                    b'D' => {
                        let flag = msg[1];
                        let payload_len =
                            u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]) as usize;
                        let payload = &msg[6..6 + payload_len];
                        let chunk = if flag == 0x01 {
                            zstd::decode_all(payload).unwrap()
                        } else {
                            payload.to_vec()
                        };
                        received_data.extend_from_slice(&chunk);
                    }
                    b'E' => break,
                    other => panic!("unexpected message type: 0x{:02x}", other),
                }
            }
            assert_eq!(received_data, b"new file content");

            // Send final response
            let resp = Response {
                success: true,
                output: Some("16 bytes".to_string()),
                error: None,
                size: Some(16),
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut server, &resp).await.unwrap();
        });

        let result = push(&mut client, data, "/tmp/test.txt").await.unwrap();
        assert_eq!(result.bytes_sent, data.len());
        assert!(!result.delta); // full upload, not delta
        h.await.unwrap();
    }

    /// Test push_full with a large payload (>1MB) to verify chunking works.
    #[tokio::test]
    async fn push_full_large_file_chunked() {
        // 1.5MB file — should produce 1 chunk (< 10MB threshold)
        let data: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
        let (mut client, mut server) = mock_client();

        let data_clone = data.clone();
        let h = tokio::spawn(async move {
            // push-sigs → no remote file
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            wire::send_json(&mut server, &err_response("not found"))
                .await
                .unwrap();

            // push-chunked request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.sync_type.as_deref(), Some("push-chunked"));

            // ack
            wire::send_json(&mut server, &ok_response("ready"))
                .await
                .unwrap();

            // Receive chunks
            let mut received = Vec::new();
            loop {
                let msg = wire::recv_message(&mut server).await.unwrap();
                match msg[0] {
                    b'D' => {
                        let flag = msg[1];
                        let len = u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]) as usize;
                        let payload = &msg[6..6 + len];
                        let chunk = if flag == 0x01 {
                            zstd::decode_all(payload).unwrap()
                        } else {
                            payload.to_vec()
                        };
                        received.extend_from_slice(&chunk);
                    }
                    b'E' => break,
                    other => panic!("unexpected: 0x{:02x}", other),
                }
            }
            assert_eq!(received.len(), data_clone.len());
            assert_eq!(received, data_clone);

            let resp = Response {
                success: true,
                output: Some(format!("{} bytes", data_clone.len())),
                error: None,
                size: Some(data_clone.len() as i64),
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut server, &resp).await.unwrap();
        });

        let result = push(&mut client, &data, "/tmp/large.bin").await.unwrap();
        assert_eq!(result.bytes_sent, 1_500_000);
        assert!(!result.delta);
        h.await.unwrap();
    }

    // ── Push: delta sync (remote file exists) ───────────────────────

    #[tokio::test]
    async fn push_delta_when_remote_exists() {
        let (mut client, mut server) = mock_client();
        let data = b"updated content here";

        let h = tokio::spawn(async move {
            // Step 1: push-sigs → return sigs
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-sigs");
            let sigs = vec![mrsh_core::protocol::BlockSig {
                index: 0,
                weak: 123456,
                strong: "abc123".to_string(),
            }];
            let sigs_json = serde_json::to_string(&sigs).unwrap();
            wire::send_json(&mut server, &ok_response(&sigs_json))
                .await
                .unwrap();

            // Step 2: push-delta with computed delta ops
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-delta");
            assert_eq!(req.path.as_deref(), Some("/tmp/delta.txt"));
            assert!(req.delta.is_some());
            wire::send_json(&mut server, &ok_response("ok"))
                .await
                .unwrap();
        });

        let result = push(&mut client, data, "/tmp/delta.txt").await.unwrap();
        assert_eq!(result.bytes_sent, data.len());
        assert!(result.delta);
        h.await.unwrap();
    }

    // ── Pull: full download ─────────────────────────────────────────

    #[tokio::test]
    async fn pull_full_download_no_local() {
        let (mut client, mut server) = mock_client();
        let remote_content = b"remote file data";

        let h = tokio::spawn(async move {
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("pull-delta"));
            assert_eq!(req.path.as_deref(), Some("/tmp/remote.txt"));
            // No local file → empty sigs
            assert!(req.signatures.as_ref().map_or(true, |s| s.is_empty()));
            // Send JSON ack
            wire::send_json(
                &mut server,
                &ok_response(&format!("{}", remote_content.len())),
            )
            .await
            .unwrap();
            // Send D message with file content
            let data_len = remote_content.len() as u32;
            let mut msg = Vec::with_capacity(5 + remote_content.len());
            msg.push(b'D');
            msg.extend_from_slice(&data_len.to_be_bytes());
            msg.extend_from_slice(remote_content);
            wire::send_message(&mut server, &msg).await.unwrap();
            // Send E marker
            wire::send_message(&mut server, b"E").await.unwrap();
        });

        let result = pull(&mut client, None, "/tmp/remote.txt").await.unwrap();
        assert_eq!(result.data, remote_content);
        assert!(!result.delta);
        h.await.unwrap();
    }

    // ── Pull: identical files (empty delta) ─────────────────────────

    #[tokio::test]
    async fn pull_identical_files_no_transfer() {
        let (mut client, mut server) = mock_client();
        let local_data = b"same content";

        let h = tokio::spawn(async move {
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("pull-delta"));
            // Local sigs should be present
            assert!(req.signatures.as_ref().map_or(false, |s| !s.is_empty()));
            // Send JSON ack
            wire::send_json(&mut server, &ok_response(&format!("{}", local_data.len())))
                .await
                .unwrap();
            // Files identical: send M for block 0 (matching client's block)
            let mut msg = [0u8; 5];
            msg[0] = b'M';
            msg[1..5].copy_from_slice(&0u32.to_be_bytes());
            wire::send_message(&mut server, &msg).await.unwrap();
            // Send E marker
            wire::send_message(&mut server, b"E").await.unwrap();
        });

        let result = pull(&mut client, Some(local_data), "/tmp/same.txt")
            .await
            .unwrap();
        assert_eq!(result.data, local_data);
        assert!(result.delta);
        h.await.unwrap();
    }
}
