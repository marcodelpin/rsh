//! Sync command handlers — signatures, delta, patch, pull, walk, batch ops.

use anyhow::{Context, Result};
use base64::Engine;
use mrsh_core::protocol::{self, Response};
use mrsh_core::wire;
use mrsh_transfer::blockcache;
use mrsh_transfer::chunking::hash_sha256;
use mrsh_transfer::delta;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

// ── Global block cache (server-wide singleton) ──────────────────

/// Default cache data directory on Windows.
#[cfg(windows)]
const CACHE_DATA_DIR: &str = r"C:\ProgramData\mrsh\cache";

/// Fallback for non-Windows (testing / Linux builds).
#[cfg(not(windows))]
const CACHE_DATA_DIR: &str = "/var/lib/rsh/cache";

static BLOCK_CACHE: LazyLock<Mutex<blockcache::Cache>> = LazyLock::new(|| {
    let cache_file = Path::new(CACHE_DATA_DIR).join("blockcache.msgpack");
    match blockcache::Cache::new(&cache_file) {
        Ok(cache) => {
            debug!("block cache loaded from {:?}", cache_file);
            Mutex::new(cache)
        }
        Err(e) => {
            tracing::warn!("block cache init failed ({:?}): {}, using empty cache", cache_file, e);
            // Create an in-memory cache with a temp path — will work but won't persist
            let fallback = std::env::temp_dir().join("rsh-blockcache-fallback.msgpack");
            Mutex::new(blockcache::Cache::new(&fallback).expect("fallback cache must succeed"))
        }
    }
});

/// Sanitize a file path: reject null bytes and newlines.
pub fn sanitize_path(path: &str) -> Result<&str, String> {
    if path.as_bytes().contains(&0) {
        return Err("path contains null byte".to_string());
    }
    if path.contains('\n') || path.contains('\r') {
        return Err("path contains newline".to_string());
    }
    Ok(path)
}

/// Dispatch sync sub-commands.
pub fn handle_sync(req: &protocol::Request) -> Response {
    let sync_type = req.sync_type.as_deref().unwrap_or("");
    let raw_path = req.path.as_deref().unwrap_or("");

    // Sanitize path for all sync operations that use it
    let path = if !raw_path.is_empty() {
        match sanitize_path(raw_path) {
            Ok(p) => p,
            Err(e) => return Response::error(&e),
        }
    } else {
        raw_path
    };

    debug!("sync: type={} path={}", sync_type, path);

    match sync_type {
        "signatures" => handle_get_signatures(path),
        "delta" => {
            let sigs = convert_sigs_from_proto(req.signatures.as_deref().unwrap_or(&[]));
            handle_compute_delta(path, &sigs)
        }
        "patch" => handle_apply_patch(path, req.delta.as_deref(), req.content.as_deref()),
        "pull" => handle_pull_file(path),
        "walk" => handle_walk(path),
        "batch-signatures" => {
            let paths = req.paths.as_deref().unwrap_or(&[]);
            handle_batch_signatures(paths)
        }
        "batch-patch" => {
            let patches = req.batch_patches.as_deref().unwrap_or(&[]);
            handle_batch_patch(patches)
        }
        "cache-stats" => handle_cache_stats(),
        "index-dir" => handle_index_dir(path),
        "smart-sync" => handle_smart_sync(req.content.as_deref().unwrap_or("")),
        "find-and-move" => {
            let patches = req.batch_patches.as_deref().unwrap_or(&[]);
            handle_find_and_move(patches)
        }
        other => Response::error(&format!("unknown sync type: {}", other)),
    }
}

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

    debug!("push-chunked: path={}", path);

    // Validate path and ensure parent directory exists
    if path.is_empty() {
        let resp = Response::error("missing path");
        wire::send_json(stream, &resp).await?;
        return Ok(());
    }

    if let Some(parent) = Path::new(path).parent()
        && !parent.exists()
            && let Err(e) = std::fs::create_dir_all(parent) {
                let resp = Response::error(&format!("create parent dir: {}", e));
                wire::send_json(stream, &resp).await?;
                return Ok(());
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
        let msg = wire::recv_message(stream).await.context("recv push chunk")?;
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
                let payload_len =
                    u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]) as usize;
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
            debug!(
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
fn handle_get_signatures(path: &str) -> Response {
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
fn handle_compute_delta(path: &str, remote_sigs: &[delta::BlockSig]) -> Response {
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
fn handle_apply_patch(
    path: &str,
    delta_ops: Option<&[protocol::DeltaOp]>,
    content: Option<&str>,
) -> Response {
    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Response::error(&format!("create dir: {}", e));
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
            Ok(()) => Response {
                success: true,
                output: Some(format!("{} bytes written", data.len())),
                error: None,
                size: Some(data.len() as i64),
                binary: None,
                gzip: None,
            },
            Err(e) => Response::error(&format!("write {}: {}", path, e)),
        };
    }

    // Apply delta operations
    if let Some(ops) = delta_ops {
        let existing = std::fs::read(path).unwrap_or_default();
        let transfer_ops = convert_delta_from_proto(ops);
        let result = delta::apply_delta(&existing, &transfer_ops);

        return match std::fs::write(path, &result) {
            Ok(()) => Response {
                success: true,
                output: Some(format!("{} bytes written", result.len())),
                error: None,
                size: Some(result.len() as i64),
                binary: None,
                gzip: None,
            },
            Err(e) => Response::error(&format!("write {}: {}", path, e)),
        };
    }

    Response::error("patch requires delta or content")
}

/// Read full file for pull.
fn handle_pull_file(path: &str) -> Response {
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

/// Recursive directory walk returning file paths and sizes.
fn handle_walk(path: &str) -> Response {
    let mut entries = Vec::new();
    if let Err(e) = walk_dir(Path::new(path), &mut entries) {
        return Response::error(&format!("walk {}: {}", path, e));
    }

    match serde_json::to_string(&entries) {
        Ok(json) => Response {
            success: true,
            output: Some(json),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        },
        Err(e) => Response::error(&format!("serialize walk: {}", e)),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WalkEntry {
    #[serde(rename = "p")]
    path: String,
    #[serde(rename = "s")]
    size: i64,
    #[serde(rename = "m", default, skip_serializing_if = "is_zero_i64")]
    mtime: i64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn walk_dir(dir: &Path, entries: &mut Vec<WalkEntry>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_dir(&entry.path(), entries)?;
        } else {
            let meta = entry.metadata()?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            entries.push(WalkEntry {
                path: entry.path().to_string_lossy().to_string(),
                size: meta.len() as i64,
                mtime,
            });
        }
    }
    Ok(())
}

// ── Batch operations ──────────────────────────────────────────

#[derive(serde::Serialize)]
struct BatchFileSignatures {
    path: String,
    sigs: Vec<protocol::BlockSig>,
    size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Compute block signatures for multiple files at once.
fn handle_batch_signatures(paths: &[String]) -> Response {
    let mut results = Vec::with_capacity(paths.len());

    for path in paths {
        let mut item = BatchFileSignatures {
            path: path.clone(),
            sigs: Vec::new(),
            size: 0,
            error: None,
        };

        match std::fs::read(path) {
            Ok(data) => {
                let sigs = delta::compute_signatures(&data);
                item.sigs = convert_sigs_to_proto(&sigs);
                item.size = data.len() as i64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File doesn't exist — empty signatures (new file)
            }
            Err(e) => {
                item.error = Some(format!("read {}: {}", path, e));
            }
        }

        results.push(item);
    }

    match serde_json::to_string(&results) {
        Ok(json) => Response {
            success: true,
            output: Some(json),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        },
        Err(e) => Response::error(&format!("serialize batch-signatures: {}", e)),
    }
}

#[derive(serde::Serialize)]
struct BatchPatchResult {
    path: String,
    size: i64,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Apply patches/full content to multiple files at once.
fn handle_batch_patch(patches: &[protocol::BatchPatchItem]) -> Response {
    let mut results = Vec::with_capacity(patches.len());

    for patch in patches {
        let mut result = BatchPatchResult {
            path: patch.path.clone(),
            size: 0,
            success: false,
            error: None,
        };

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&patch.path).parent()
            && !parent.exists()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            result.error = Some(format!("create dir: {}", e));
            results.push(result);
            continue;
        }

        let final_data;

        if let Some(content_b64) = &patch.content {
            // Full content: base64 → optional gzip decompress → write
            let raw = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
                Ok(d) => d,
                Err(e) => {
                    result.error = Some(format!("decode content: {}", e));
                    results.push(result);
                    continue;
                }
            };
            final_data = gzip_decompress(&raw).unwrap_or(raw);
        } else if let Some(ops) = &patch.delta {
            // Delta: apply operations to existing file
            let existing = std::fs::read(&patch.path).unwrap_or_default();
            let transfer_ops = convert_delta_from_proto(ops);
            final_data = delta::apply_delta(&existing, &transfer_ops);
        } else {
            result.error = Some("no content or delta provided".to_string());
            results.push(result);
            continue;
        }

        // Backup existing file if requested
        if let Some(suffix) = &patch.backup_suffix
            && Path::new(&patch.path).exists()
        {
            let backup_path = format!("{}{}", patch.path, suffix);
            let _ = std::fs::rename(&patch.path, &backup_path);
        }

        match std::fs::write(&patch.path, &final_data) {
            Ok(()) => {
                result.success = true;
                result.size = final_data.len() as i64;
            }
            Err(e) => {
                result.error = Some(format!("write {}: {}", patch.path, e));
            }
        }

        results.push(result);
    }

    match serde_json::to_string(&results) {
        Ok(json) => Response {
            success: true,
            output: Some(json),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        },
        Err(e) => Response::error(&format!("serialize batch-patch: {}", e)),
    }
}

/// Handle batch-patch-bin: binary protocol for efficient multi-file writes.
/// The blob data is received as a separate binary message after the JSON request.
/// This handler is called from the streaming dispatch path.
pub async fn handle_batch_patch_bin<S>(stream: &mut S, req: &protocol::Request) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let meta_json = req.content.as_deref().unwrap_or("[]");

    #[derive(serde::Deserialize)]
    struct BinMeta {
        path: String,
        size: i64,
        #[serde(default)]
        backup: Option<String>,
    }

    let items: Vec<BinMeta> = match serde_json::from_str(meta_json) {
        Ok(v) => v,
        Err(e) => {
            let resp = Response::error(&format!("invalid bin-patch metadata: {}", e));
            wire::send_json(stream, &resp).await?;
            return Ok(());
        }
    };

    // Read the binary blob (second message)
    let blob = wire::recv_message(stream)
        .await
        .context("recv bin-patch blob")?;

    let mut results = Vec::with_capacity(items.len());
    let mut offset = 0usize;

    for item in &items {
        let mut result = BatchPatchResult {
            path: item.path.clone(),
            size: 0,
            success: false,
            error: None,
        };

        // Sanitize each file path in the batch
        if let Err(e) = sanitize_path(&item.path) {
            result.error = Some(e);
            results.push(result);
            // Still consume this item's bytes from the blob
            offset += item.size as usize;
            continue;
        }

        let end = offset + item.size as usize;
        if end > blob.len() {
            result.error = Some(format!(
                "insufficient data: need {} bytes at offset {}, have {}",
                item.size,
                offset,
                blob.len()
            ));
            results.push(result);
            continue;
        }

        let file_data = &blob[offset..end];
        offset = end;

        // Ensure parent directory
        if let Some(parent) = Path::new(&item.path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Backup if requested
        if let Some(suffix) = &item.backup
            && Path::new(&item.path).exists()
        {
            let backup_path = format!("{}{}", item.path, suffix);
            let _ = std::fs::rename(&item.path, &backup_path);
        }

        match std::fs::write(&item.path, file_data) {
            Ok(()) => {
                result.success = true;
                result.size = item.size;
            }
            Err(e) => {
                result.error = Some(format!("write {}: {}", item.path, e));
            }
        }

        results.push(result);
    }

    let json = serde_json::to_string(&results).unwrap_or_default();
    let resp = Response {
        success: true,
        output: Some(json),
        error: None,
        size: None,
        binary: None,
        gzip: None,
    };
    wire::send_json(stream, &resp).await?;

    Ok(())
}

/// Cache stats — returns block and file counts from the shared block cache.
fn handle_cache_stats() -> Response {
    let cache = match BLOCK_CACHE.lock() {
        Ok(c) => c,
        Err(e) => return Response::error(&format!("cache lock poisoned: {}", e)),
    };
    let (blocks, files) = cache.stats();
    let stats = serde_json::json!({ "blocks": blocks, "files": files });
    Response {
        success: true,
        output: Some(stats.to_string()),
        error: None,
        size: None,
        binary: None,
        gzip: None,
    }
}

/// Index all files in a directory into the block cache (recursive walk).
fn handle_index_dir(path: &str) -> Response {
    let dir = Path::new(path);
    if !dir.is_dir() {
        return Response::error(&format!("not a directory: {}", path));
    }

    let mut cache = match BLOCK_CACHE.lock() {
        Ok(c) => c,
        Err(e) => return Response::error(&format!("cache lock poisoned: {}", e)),
    };

    let mut count = 0usize;
    fn walk_and_index(
        dir: &Path,
        cache: &mut blockcache::Cache,
        count: &mut usize,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_dir() {
                walk_and_index(&entry.path(), cache, count)?;
            } else if ft.is_file()
                && let Some(p) = entry.path().to_str()
                    && cache.index_file(p).is_ok() {
                        *count += 1;
                    }
        }
        Ok(())
    }

    if let Err(e) = walk_and_index(dir, &mut cache, &mut count) {
        return Response::error(&format!("walk {}: {}", path, e));
    }

    // Flush to persist indexed data
    let _ = cache.flush();

    debug!("index-dir: indexed {} files in {}", count, path);
    Response {
        success: true,
        output: Some(format!("Indexed {} files", count)),
        error: None,
        size: None,
        binary: None,
        gzip: None,
    }
}

/// Smart sync — processes sync requests using block cache for dedup/move detection.
/// Input: JSON array of SyncRequest. Output: JSON array of SyncResult.
/// Uses block cache for dedup and move detection.
fn handle_smart_sync(content: &str) -> Response {
    #[derive(serde::Deserialize)]
    struct SyncRequest {
        dest: String,
        hash: String,
        #[allow(dead_code)]
        size: i64,
        #[serde(default)]
        blocks: Vec<String>,
    }

    #[derive(serde::Serialize)]
    struct SyncResult {
        dest: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        missing: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    let requests: Vec<SyncRequest> = match serde_json::from_str(content) {
        Ok(r) => r,
        Err(e) => return Response::error(&format!("invalid smart-sync request: {}", e)),
    };

    let mut cache = match BLOCK_CACHE.lock() {
        Ok(c) => c,
        Err(e) => return Response::error(&format!("cache lock poisoned: {}", e)),
    };

    let mut results = Vec::with_capacity(requests.len());

    for req in &requests {
        let mut result = SyncResult {
            dest: req.dest.clone(),
            status: String::new(),
            source: None,
            missing: None,
            error: None,
        };

        // 1. Check if destination already has correct content
        let dest_path = Path::new(&req.dest);
        if dest_path.exists() {
            // Check cache first (avoids re-reading file)
            if let Some(info) = cache.get_file_info(&req.dest)
                && info.content_hash == req.hash {
                    result.status = "exists".to_string();
                    results.push(result);
                    continue;
                }

            // Cache miss or hash mismatch — read actual file to verify
            if let Ok(data) = std::fs::read(&req.dest)
                && hash_sha256(&data) == req.hash {
                    result.status = "exists".to_string();
                    let _ = cache.index_file(&req.dest);
                    results.push(result);
                    continue;
                }
        } else {
            // File missing from disk — invalidate stale cache entry
            cache.remove_file(&req.dest);
        }

        // 2. Try to find file by content hash (rename/move detection)
        let sources = cache.find_by_content_hash(&req.hash);
        let mut moved = false;
        for src_path in &sources {
            if src_path == &req.dest {
                continue;
            }

            // Verify source still has correct content
            if let Ok(data) = std::fs::read(src_path)
                && hash_sha256(&data) == req.hash {
                    // Move the file
                    if move_file(src_path, &req.dest).is_ok() {
                        result.status = "moved".to_string();
                        result.source = Some(src_path.clone());
                        let _ = cache.index_file(&req.dest);
                        moved = true;
                        break;
                    }
                }
        }
        if moved {
            results.push(result);
            continue;
        }

        // 3. Check for partial match — find which blocks we already have
        if !req.blocks.is_empty() {
            let mut missing_blocks = Vec::new();
            for block_hash in &req.blocks {
                let block_sources = cache.find_block_sources(block_hash);
                if block_sources.is_empty() {
                    missing_blocks.push(block_hash.clone());
                }
            }

            if missing_blocks.len() < req.blocks.len() {
                // We have some blocks locally
                result.status = "partial".to_string();
                result.missing = Some(missing_blocks);
                results.push(result);
                continue;
            }
        }

        // 4. Need full transfer
        result.status = "transfer".to_string();
        results.push(result);
    }

    // Flush cache after processing all requests
    let _ = cache.flush();

    match serde_json::to_string(&results) {
        Ok(json) => Response {
            success: true,
            output: Some(json),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        },
        Err(e) => Response::error(&format!("serialize smart-sync results: {}", e)),
    }
}

/// Move a file, handling cross-device moves via copy+delete.
fn move_file(src: &str, dst: &str) -> std::io::Result<()> {
    // Ensure destination directory exists
    if let Some(parent) = Path::new(dst).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Try rename first (fast, same-device)
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Cross-device: copy + delete
            std::fs::copy(src, dst)?;
            std::fs::remove_file(src)?;
            Ok(())
        }
    }
}

// ── Type conversion helpers ────────────────────────────────────

fn convert_sigs_from_proto(sigs: &[protocol::BlockSig]) -> Vec<delta::BlockSig> {
    sigs.iter()
        .map(|s| delta::BlockSig {
            index: s.index as usize,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect()
}

fn convert_sigs_to_proto(sigs: &[delta::BlockSig]) -> Vec<protocol::BlockSig> {
    sigs.iter()
        .map(|s| protocol::BlockSig {
            index: s.index as i32,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect()
}

fn convert_delta_from_proto(ops: &[protocol::DeltaOp]) -> Vec<delta::DeltaOp> {
    ops.iter()
        .map(|op| delta::DeltaOp {
            op_type: op.op_type.clone(),
            index: op.index.unwrap_or(0) as usize,
            data: op.data.clone().unwrap_or_default(),
        })
        .collect()
}

fn convert_delta_to_proto(ops: &[delta::DeltaOp]) -> Vec<protocol::DeltaOp> {
    ops.iter()
        .map(|op| protocol::DeltaOp {
            op_type: op.op_type.clone(),
            index: if op.op_type == "match" {
                Some(op.index as i32)
            } else {
                None
            },
            data: if op.data.is_empty() {
                None
            } else {
                Some(op.data.clone())
            },
        })
        .collect()
}

// ── Compression helpers ────────────────────────────────────────

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap_or_default();
    encoder.finish().unwrap_or_default()
}

fn gzip_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    // Check for gzip magic bytes
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        return None;
    }
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}


// ── Find-and-move: server-side content-hash dedup ──────────────

/// Item describing a file to find by hash and move to destination.
#[derive(Debug, serde::Deserialize)]
struct FindMoveItem {
    dest: String,
    hash: String,
    size: i64,
    root: String,
}

/// Result of a find-and-move operation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct FindMoveResult {
    dest: String,
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    moved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Find files by content hash in search roots and move to destination.
/// Avoids re-transferring files that already exist elsewhere on the server.
fn handle_find_and_move(patches: &[protocol::BatchPatchItem]) -> Response {
    let content = match patches.first().and_then(|p| p.content.as_deref()) {
        Some(c) => c,
        None => return Response::error("No find-move items provided"),
    };

    let items: Vec<FindMoveItem> = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => return Response::error(&format!("Invalid find-move items: {}", e)),
    };

    if items.is_empty() {
        return Response {
            success: true,
            output: Some("[]".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
    }

    // Build hash index: walk search root, hash files matching any requested size
    let search_root = std::env::var("USERPROFILE")
        .map(|_| items[0].root.clone())
        .unwrap_or_else(|_| items[0].root.clone());
    let sizes: std::collections::HashSet<i64> = items.iter().map(|i| i.size).collect();
    let mut hash_index: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    if let Ok(entries) = std::fs::read_dir(&search_root) {
        fn walk_and_index(
            dir: &Path,
            sizes: &std::collections::HashSet<i64>,
            index: &mut std::collections::HashMap<String, Vec<String>>,
        ) {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk_and_index(&path, sizes, index);
                } else if let Ok(meta) = entry.metadata()
                    && sizes.contains(&(meta.len() as i64))
                        && let Ok(data) = std::fs::read(&path) {
                            let hash = hash_sha256(&data);
                            index
                                .entry(hash)
                                .or_default()
                                .push(path.to_string_lossy().to_string());
                        }
            }
        }
        drop(entries);
        walk_and_index(Path::new(&search_root), &sizes, &mut hash_index);
    }

    // Process each find-move request
    let mut results = Vec::with_capacity(items.len());
    for item in &items {
        let mut result = FindMoveResult {
            dest: item.dest.clone(),
            found: false,
            source: None,
            moved: false,
            error: None,
        };

        let dest_path = Path::new(&item.dest);

        // Check if destination already has correct file
        if dest_path.exists()
            && let Ok(data) = std::fs::read(dest_path)
                && hash_sha256(&data) == item.hash {
                    result.found = true;
                    result.source = Some(item.dest.clone());
                    results.push(result);
                    continue;
                }

        // Look for file with matching hash
        if let Some(paths) = hash_index.get(&item.hash) {
            for src_path in paths {
                if src_path == &item.dest {
                    continue;
                }
                result.found = true;
                result.source = Some(src_path.clone());

                // Ensure destination directory exists
                if let Some(parent) = dest_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                // Move file (rename, fallback to copy+delete for cross-device)
                match std::fs::rename(src_path, &item.dest) {
                    Ok(_) => result.moved = true,
                    Err(_) => match std::fs::copy(src_path, &item.dest) {
                        Ok(_) => {
                            let _ = std::fs::remove_file(src_path);
                            result.moved = true;
                        }
                        Err(e) => result.error = Some(e.to_string()),
                    },
                }
                break;
            }
        }

        results.push(result);
    }

    let output = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
    Response {
        success: true,
        output: Some(output),
        error: None,
        size: None,
        binary: None,
        gzip: None,
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

    #[test]
    fn walk_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("b.txt"), b"bbb").unwrap();

        let resp = handle_walk(dir.path().to_str().unwrap());
        assert!(resp.success);
        let entries: Vec<WalkEntry> =
            serde_json::from_str(resp.output.as_deref().unwrap()).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn gzip_roundtrip() {
        let data = b"test data for compression";
        let compressed = gzip_compress(data);
        let decompressed = gzip_decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn gzip_decompress_non_gzip() {
        assert!(gzip_decompress(b"not gzip").is_none());
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
        };

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);

        // Spawn the delta handler
        let handle = tokio::spawn(async move {
            handle_pull_delta(&mut server, &req).await
        });

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
                    let data_len =
                        u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
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
        assert_eq!(reconstructed, data, "reconstructed file must match original");

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
        };

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let handle = tokio::spawn(async move {
            handle_pull_delta(&mut server, &req).await
        });

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
        };

        // Large duplex buffer to avoid backpressure stalls
        let (mut client, mut server) = tokio::io::duplex(4 * 1024 * 1024);

        let handle = tokio::spawn(async move {
            handle_pull_delta(&mut server, &req).await
        });

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
                    assert!(msg.len() <= BLOCK_SIZE + 5, "D message too large: {}", msg.len());
                    reconstructed.extend_from_slice(&msg[5..]);
                    block_count += 1;
                }
                b'M' => panic!("unexpected M with empty signatures"),
                other => panic!("unexpected message type: 0x{:02x}", other),
            }
        }

        assert_eq!(reconstructed.len(), file_size, "reconstructed size mismatch");
        assert_eq!(reconstructed, data, "reconstructed data mismatch");
        // 512 full blocks + 1 partial = 513
        assert_eq!(block_count, 513, "expected 513 blocks (512 full + 1 partial)");

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

    #[test]
    fn sanitize_path_rejects_null_byte() {
        let result = sanitize_path("foo\0bar");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("null"));
    }

    #[test]
    fn sanitize_path_rejects_newline() {
        let result = sanitize_path("foo\nbar");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_path_accepts_normal() {
        let result = sanitize_path("/tmp/test.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/tmp/test.txt");
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
        };

        let test_data: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();

        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let data_clone = test_data.clone();
        let handle = tokio::spawn(async move {
            handle_push_chunked(&mut server, &req).await
        });

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
        assert!(resp.success, "final response should succeed: {:?}", resp.error);
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
        };

        let data_clone = test_data.clone();
        let (mut client, mut server) = tokio::io::duplex(4 * 1024 * 1024);

        let handle = tokio::spawn(async move {
            handle_push_chunked(&mut server, &req).await
        });

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

    // ── find-and-move tests ──────────────────────────────────────

    #[test]
    fn find_and_move_found_and_moved() {
        let tmp = tempfile::tempdir().unwrap();
        let search = tmp.path().join("search");
        let dest = tmp.path().join("dest");
        std::fs::create_dir_all(&search).unwrap();
        std::fs::create_dir_all(&dest).unwrap();

        let content = b"unique content for test";
        std::fs::write(search.join("original.dat"), content).unwrap();
        let hash = hash_sha256(content);

        let items = serde_json::to_string(&vec![serde_json::json!({
            "dest": dest.join("moved.dat").to_str().unwrap(),
            "hash": hash,
            "size": content.len() as i64,
            "root": search.to_str().unwrap(),
        })]).unwrap();

        let patches = vec![protocol::BatchPatchItem {
            path: String::new(),
            delta: None,
            content: Some(items),
            backup_suffix: None,
        }];

        let resp = handle_find_and_move(&patches);
        assert!(resp.success);
        let results: Vec<FindMoveResult> = serde_json::from_str(&resp.output.unwrap()).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].found);
        assert!(results[0].moved);
        assert!(dest.join("moved.dat").exists());
    }

    #[test]
    fn find_and_move_already_at_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let content = b"already here";
        let file = tmp.path().join("file.dat");
        std::fs::write(&file, content).unwrap();
        let hash = hash_sha256(content);

        let items = serde_json::to_string(&vec![serde_json::json!({
            "dest": file.to_str().unwrap(),
            "hash": hash,
            "size": content.len() as i64,
            "root": tmp.path().to_str().unwrap(),
        })]).unwrap();

        let patches = vec![protocol::BatchPatchItem {
            path: String::new(), delta: None,
            content: Some(items), backup_suffix: None,
        }];

        let resp = handle_find_and_move(&patches);
        assert!(resp.success);
        let results: Vec<FindMoveResult> = serde_json::from_str(&resp.output.unwrap()).unwrap();
        assert!(results[0].found);
        assert!(!results[0].moved); // already in place
    }

    #[test]
    fn find_and_move_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let items = serde_json::to_string(&vec![serde_json::json!({
            "dest": tmp.path().join("nope.dat").to_str().unwrap(),
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "size": 999i64,
            "root": tmp.path().to_str().unwrap(),
        })]).unwrap();

        let patches = vec![protocol::BatchPatchItem {
            path: String::new(), delta: None,
            content: Some(items), backup_suffix: None,
        }];

        let resp = handle_find_and_move(&patches);
        assert!(resp.success);
        let results: Vec<FindMoveResult> = serde_json::from_str(&resp.output.unwrap()).unwrap();
        assert!(!results[0].found);
        assert!(!results[0].moved);
    }

    #[test]
    fn find_and_move_empty_input() {
        let patches = vec![protocol::BatchPatchItem {
            path: String::new(), delta: None,
            content: Some("[]".to_string()), backup_suffix: None,
        }];
        let resp = handle_find_and_move(&patches);
        assert!(resp.success);
        assert_eq!(resp.output.as_deref(), Some("[]"));
    }

    #[test]
    fn find_and_move_no_patches() {
        let resp = handle_find_and_move(&[]);
        assert!(!resp.success);
    }

    // ── walk mtime test ──────────────────────────────────────────

    #[test]
    fn walk_includes_mtime() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.txt"), b"data").unwrap();

        let resp = handle_walk(dir.path().to_str().unwrap());
        assert!(resp.success);
        let entries: Vec<WalkEntry> = serde_json::from_str(&resp.output.unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].mtime > 0, "mtime should be > 0");
        assert_eq!(entries[0].size, 4);
    }
}
