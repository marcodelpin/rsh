//! Batch + dedup handlers: batch-signatures, batch-patch, batch-patch-bin,
//! smart-sync, find-and-move.

use anyhow::{Context, Result};
use base64::Engine;
use mrsh_core::protocol::{self, Response};
use mrsh_core::wire;
use mrsh_transfer::chunking::hash_sha256;
use mrsh_transfer::delta;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use super::BLOCK_CACHE;
use super::protocol::{convert_delta_from_proto, convert_sigs_to_proto, gzip_decompress};
use super::sanitize_path;

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
pub(super) fn handle_batch_signatures(paths: &[String]) -> Response {
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
pub(super) fn handle_batch_patch(patches: &[protocol::BatchPatchItem]) -> Response {
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
        {
            info!("batch-patch: creating new directory {}", parent.display());
            if let Err(e) = std::fs::create_dir_all(parent) {
                result.error = Some(format!("create dir: {}", e));
                results.push(result);
                continue;
            }
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
                info!(
                    "batch-patch: wrote {} bytes to {}",
                    final_data.len(),
                    patch.path
                );
                result.success = true;
                result.size = final_data.len() as i64;
            }
            Err(e) => {
                result.error = Some(format!("write {}: {}", patch.path, e));
            }
        }

        results.push(result);
    }

    info!(
        "batch-patch: {}/{} files written",
        results.iter().filter(|r| r.success).count(),
        results.len()
    );

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
        if let Some(parent) = Path::new(&item.path).parent()
            && !parent.exists()
        {
            info!(
                "batch-patch-bin: creating new directory {}",
                parent.display()
            );
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
                info!(
                    "batch-patch-bin: wrote {} bytes to {}",
                    file_data.len(),
                    item.path
                );
                result.success = true;
                result.size = item.size;
            }
            Err(e) => {
                result.error = Some(format!("write {}: {}", item.path, e));
            }
        }

        results.push(result);
    }

    info!(
        "batch-patch-bin: {}/{} files written",
        results.iter().filter(|r| r.success).count(),
        results.len()
    );

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

/// Smart sync — processes sync requests using block cache for dedup/move detection.
/// Input: JSON array of SyncRequest. Output: JSON array of SyncResult.
/// Uses block cache for dedup and move detection.
pub(super) fn handle_smart_sync(content: &str) -> Response {
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
                && info.content_hash == req.hash
            {
                result.status = "exists".to_string();
                results.push(result);
                continue;
            }

            // Cache miss or hash mismatch — read actual file to verify
            if let Ok(data) = std::fs::read(&req.dest)
                && hash_sha256(&data) == req.hash
            {
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
                && hash_sha256(&data) == req.hash
            {
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
pub(super) fn handle_find_and_move(patches: &[protocol::BatchPatchItem]) -> Response {
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
                    && let Ok(data) = std::fs::read(&path)
                {
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
            && hash_sha256(&data) == item.hash
        {
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
        })])
        .unwrap();

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
        })])
        .unwrap();

        let patches = vec![protocol::BatchPatchItem {
            path: String::new(),
            delta: None,
            content: Some(items),
            backup_suffix: None,
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
        })])
        .unwrap();

        let patches = vec![protocol::BatchPatchItem {
            path: String::new(),
            delta: None,
            content: Some(items),
            backup_suffix: None,
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
            path: String::new(),
            delta: None,
            content: Some("[]".to_string()),
            backup_suffix: None,
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
}
