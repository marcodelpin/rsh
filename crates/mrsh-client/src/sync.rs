//! Push/pull file transfer — delta sync using rsh-transfer.
//! Sends block signatures, receives delta, applies patches.
//! Supports single files and directories (walk + per-file delta).

use anyhow::{Context, Result, bail};
use base64::Engine;
use mrsh_core::protocol::{Request, Response};
use mrsh_core::wire;
use mrsh_transfer::delta;
use std::io::Read as StdRead;
use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

// ── Transfer options ────────────────────────────────────────────

/// Options controlling directory transfer behavior.
#[derive(Debug, Clone, Default)]
pub struct TransferOptions {
    /// Show progress bar with rate and ETA.
    pub progress: bool,
    /// Dry run: list files without transferring.
    pub dry_run: bool,
    /// Backup suffix for overwritten files (e.g. ".bak").
    pub backup_suffix: Option<String>,
    /// Bandwidth limit in KB/s (0 = unlimited). Reserved for future use.
    pub bwlimit_kbps: u32,
}

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

/// Chunk size for binary push (10 MB).
const PUSH_CHUNK_SIZE: usize = 10 * 1024 * 1024;

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
    wire::send_json(client.stream_mut(), &req).await.context("send pull-delta request")?;
    let resp: Response = wire::recv_json(client.stream_mut()).await.context("recv pull-delta ack")?;
    check_response(&resp)?;

    // Step 3: Read binary M/D/E stream from server
    let local_blocks: Vec<&[u8]> = match local_data {
        Some(data) if !data.is_empty() => data.chunks(delta::BLOCK_SIZE).collect(),
        _ => Vec::new(),
    };

    let mut result_data = Vec::new();

    loop {
        let msg = wire::recv_message(client.stream_mut()).await.context("recv pull-delta block")?;
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
                    bail!("pull-delta: M block index {} out of range (have {})", idx, local_blocks.len());
                }
            }
            b'D' => {
                // Data — new/changed block from server
                if msg.len() < 5 {
                    bail!("pull-delta: D message too short");
                }
                let data_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
                if msg.len() < 5 + data_len {
                    bail!("pull-delta: D message truncated (expected {} bytes, got {})", data_len, msg.len() - 5);
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
    Ok(PullResult { data: result_data, delta: has_delta })
}

// ── Push directory ──────────────────────────────────────────────

/// Walk entry from server (wire format: `json:"p"`, `json:"s"`).
#[derive(serde::Deserialize, Debug)]
struct WalkEntry {
    #[serde(rename = "p")]
    path: String,
    #[serde(rename = "s")]
    size: i64,
    #[serde(rename = "m", default)]
    mtime: i64,
}

/// Push a local directory to the remote host recursively.
/// Walks local tree, creates remote dirs, pushes each file with delta sync.
pub async fn push_dir<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_dir: &Path,
    remote_dir: &str,
    opts: &TransferOptions,
) -> Result<DirSyncResult> {
    // Walk local directory
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    walk_local(local_dir, local_dir, remote_dir, &mut files)?;

    eprintln!("push directory: {} -> {} ({} files)", local_dir.display(), remote_dir, files.len());

    if files.is_empty() {
        return Ok(DirSyncResult { files_total: 0, files_transferred: 0, bytes_total: 0 });
    }

    if opts.dry_run {
        for (local_path, remote_path) in &files {
            let size = std::fs::metadata(local_path).map(|m| m.len()).unwrap_or(0);
            eprintln!("  [dry-run] {} ({} bytes) -> {}", local_path.display(), size, remote_path);
        }
        return Ok(DirSyncResult { files_total: files.len(), files_transferred: 0, bytes_total: 0 });
    }

    // Collect unique remote parent directories and create them
    let mut remote_parents: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, remote_path) in &files {
        if let Some(parent) = remote_path.rsplit_once('\\').map(|(p, _)| p.to_string()) {
            remote_parents.insert(parent);
        }
    }
    for dir in &remote_parents {
        let cmd = format!("cmd /c if not exist \"{}\" mkdir \"{}\"", dir, dir);
        let mut req = simple_request("exec");
        req.command = Some(cmd);
        let _ = client.request(&req).await;
    }

    // Push each file with delta sync
    let total = files.len();
    let mut transferred = 0usize;
    let mut bytes_total = 0u64;
    let start_time = Instant::now();

    for (i, (local_path, remote_path)) in files.iter().enumerate() {
        let file_size = match std::fs::metadata(local_path) {
            Ok(m) => m.len(),
            Err(e) => {
                eprintln!("  skip {}: {}", local_path.display(), e);
                continue;
            }
        };
        bytes_total += file_size;

        if opts.progress {
            print_progress(i, total, bytes_total, start_time,
                &local_path.file_name().unwrap_or_default().to_string_lossy());
        } else {
            eprintln!("  [{}/{}] {}", i + 1, total,
                local_path.file_name().unwrap_or_default().to_string_lossy());
        }

        // Backup before overwrite if requested
        if let Some(ref suffix) = opts.backup_suffix {
            backup_remote(client, remote_path, suffix).await;
        }

        push_file(client, local_path, remote_path).await?;
        transferred += 1;
    }

    if opts.progress {
        eprintln!(); // clear progress line
    }

    Ok(DirSyncResult { files_total: total, files_transferred: transferred, bytes_total })
}

/// Walk local directory tree, collecting (local_path, remote_path) pairs.
fn walk_local(
    root: &Path,
    dir: &Path,
    remote_dir: &str,
    files: &mut Vec<(std::path::PathBuf, String)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_local(root, &entry.path(), remote_dir, files)?;
        } else {
            let rel = entry.path().strip_prefix(root)
                .map_err(|e| anyhow::anyhow!("strip prefix: {}", e))?
                .to_string_lossy()
                .replace('/', "\\");
            let remote_path = format!("{}\\{}", remote_dir, rel);
            files.push((entry.path(), remote_path));
        }
    }
    Ok(())
}

// ── Pull directory ──────────────────────────────────────────────

/// Pull a remote directory to local recursively.
/// Requests walk from server, then pulls each file with delta sync.
pub async fn pull_dir<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    remote_dir: &str,
    local_dir: &Path,
    opts: &TransferOptions,
) -> Result<DirSyncResult> {
    // Request recursive file listing from server
    let mut req = simple_request("sync");
    req.sync_type = Some("walk".to_string());
    req.path = Some(remote_dir.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;

    let json = resp.output.unwrap_or_default();
    let entries: Vec<WalkEntry> = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("parse walk response: {}", e))?;

    eprintln!("pull directory: {} -> {} ({} files)", remote_dir, local_dir.display(), entries.len());

    if opts.dry_run {
        for entry in &entries {
            eprintln!("  [dry-run] {} ({} bytes)", entry.path, entry.size);
        }
        return Ok(DirSyncResult { files_total: entries.len(), files_transferred: 0, bytes_total: 0 });
    }

    std::fs::create_dir_all(local_dir)?;

    let total = entries.len();
    let mut transferred = 0usize;
    let mut bytes_total = 0u64;
    let start_time = Instant::now();

    for (i, entry) in entries.iter().enumerate() {
        // Build paths — server walk returns paths relative to remote_dir or absolute.
        // Server may return relative paths (forward slashes) or absolute.
        let rel_path = if entry.path.starts_with(remote_dir) {
            // Absolute path from server — strip the remote_dir prefix
            entry.path[remote_dir.len()..].trim_start_matches(['/', '\\']).to_string()
        } else {
            // Already relative
            entry.path.clone()
        };

        let remote_file = format!("{}\\{}", remote_dir, rel_path.replace('/', "\\"));
        let local_file = local_dir.join(rel_path.replace('\\', "/"));

        // Ensure local parent exists
        if let Some(parent) = local_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if opts.progress {
            print_progress(i, total, bytes_total, start_time, &rel_path);
        } else {
            eprintln!("  [{}/{}] {} ({} bytes)", i + 1, total, rel_path, entry.size);
        }

        // Backup local file before overwrite if requested
        if let Some(ref suffix) = opts.backup_suffix {
            if local_file.exists() {
                let backup_path = format!("{}{}", local_file.display(), suffix);
                if let Err(e) = std::fs::copy(&local_file, &backup_path) {
                    eprintln!("  backup warning: {}: {}", backup_path, e);
                }
            }
        }

        // Read existing local file for delta sync
        let local_data = std::fs::read(&local_file).ok();
        let result = pull(client, local_data.as_deref(), &remote_file).await?;
        std::fs::write(&local_file, &result.data)?;

        bytes_total += result.data.len() as u64;
        transferred += 1;
    }

    if opts.progress {
        eprintln!(); // clear progress line
    }

    Ok(DirSyncResult { files_total: total, files_transferred: transferred, bytes_total })
}

// ── Delete remote extras (--delete / mirror mode) ──────────────

/// Remove remote files not present in the local directory.
/// Uses server walk to get remote file list, compares with local tree.
pub async fn delete_remote_extras<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_dir: &Path,
    remote_dir: &str,
) -> Result<usize> {
    // Walk remote directory via server
    let mut req = simple_request("sync");
    req.sync_type = Some("walk".to_string());
    req.path = Some(remote_dir.to_string());
    let resp = client.request(&req).await?;
    if !resp.success {
        eprintln!("--delete: could not walk remote: {}", resp.error.as_deref().unwrap_or("unknown"));
        return Ok(0);
    }

    let json = resp.output.unwrap_or_default();
    let remote_entries: Vec<WalkEntry> = serde_json::from_str(&json).unwrap_or_default();

    // Build set of local relative paths (normalized with backslash for Windows remote)
    let mut local_files: Vec<(std::path::PathBuf, String)> = Vec::new();
    walk_local(local_dir, local_dir, remote_dir, &mut local_files)?;
    let local_set: std::collections::HashSet<String> =
        local_files.iter().map(|(_, remote)| remote.clone()).collect();

    // Find remote files not in local set
    let mut to_delete: Vec<String> = Vec::new();
    for entry in &remote_entries {
        let full_path = if entry.path.starts_with(remote_dir) {
            entry.path.clone()
        } else {
            format!("{}\\{}", remote_dir, entry.path.replace('/', "\\"))
        };
        if !local_set.contains(&full_path) {
            to_delete.push(full_path);
        }
    }

    if to_delete.is_empty() {
        return Ok(0);
    }

    eprintln!("--delete: {} remote files to remove", to_delete.len());

    // Delete in batches of 50 via exec (PowerShell Remove-Item)
    for chunk in to_delete.chunks(50) {
        let paths: Vec<String> = chunk.iter().map(|p| format!("'{}'", p)).collect();
        let cmd = format!("Remove-Item -Force {}", paths.join(", "));
        let mut del_req = simple_request("exec");
        del_req.command = Some(cmd);
        let _ = client.request(&del_req).await;
    }

    Ok(to_delete.len())
}

// ── Bidirectional sync ──────────────────────────────────────────

/// Default directory names excluded from sync-dir.
const SYNC_EXCLUDE_DIRS: &[&str] = &[
    ".git", ".venv", ".tmp", ".beads", ".claude", ".pytest_cache",
    ".ruff_cache", "__pycache__", "node_modules", "target",
];

/// Result of a bidirectional sync.
#[derive(Debug, Default)]
pub struct SyncDirResult {
    pub pulled: usize,
    pub pushed: usize,
    pub unchanged: usize,
    pub pull_bytes: u64,
    pub push_bytes: u64,
}

/// Bidirectional directory sync using mtime+size comparison.
///
/// 1. Walk remote (server-side) and local, collecting path+size+mtime.
/// 2. Compare: newer wins. Same mtime+size = skip.
/// 3. Pull newer-remote files, push newer-local files.
pub async fn sync_dir<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_dir: &Path,
    remote_dir: &str,
    opts: &TransferOptions,
    exclude: &[String],
) -> Result<SyncDirResult> {
    let start = Instant::now();
    let mut result = SyncDirResult::default();

    // Load .syncignore from local dir (one pattern per line, # comments, empty lines skipped)
    let syncignore_path = local_dir.join(".syncignore");
    let file_excludes: Vec<String> = if syncignore_path.is_file() {
        std::fs::read_to_string(&syncignore_path)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect()
    } else {
        Vec::new()
    };

    // Build exclude set (defaults + .syncignore + CLI --exclude)
    let all_excludes: Vec<&str> = SYNC_EXCLUDE_DIRS
        .iter()
        .copied()
        .chain(file_excludes.iter().map(|s| s.as_str()))
        .chain(exclude.iter().map(|s| s.as_str()))
        .collect();

    // Split into exact dir names and glob patterns (containing * or ?)
    let mut exclude_dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut exclude_globs: Vec<&str> = Vec::new();
    for pat in &all_excludes {
        if pat.contains('*') || pat.contains('?') {
            exclude_globs.push(pat);
        } else {
            exclude_dirs.insert(pat);
        }
    }
    let exclude_set = exclude_dirs;

    // Step 1: Walk remote
    let mut req = simple_request("sync");
    req.sync_type = Some("walk".to_string());
    req.path = Some(remote_dir.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let remote_entries: Vec<WalkEntry> =
        serde_json::from_str(&resp.output.unwrap_or_default()).unwrap_or_default();

    // Build remote map: relative_path → (size, mtime)
    // Server returns full paths (e.g. /path/to\...\docs\file.md)
    // We need to strip the remote_dir prefix to get relative paths
    let remote_prefix_fwd = remote_dir.replace('\\', "/");
    let remote_prefix_bk = remote_dir.replace('/', "\\");
    let mut remote_map: std::collections::HashMap<String, (i64, i64)> =
        std::collections::HashMap::new();
    for entry in &remote_entries {
        let normalized = entry.path.replace('/', "\\");
        let rel = if normalized.starts_with(&remote_prefix_bk) {
            normalized[remote_prefix_bk.len()..].trim_start_matches('\\').to_string()
        } else {
            let fwd = entry.path.replace('\\', "/");
            if fwd.starts_with(&remote_prefix_fwd) {
                fwd[remote_prefix_fwd.len()..].trim_start_matches('/').replace('/', "\\")
            } else {
                normalized
            }
        };
        // Check exclusion: any path component matches exclude dir, or full path matches glob
        if is_excluded(&rel, &exclude_set, &exclude_globs) {
            continue;
        }
        remote_map.insert(rel, (entry.size, entry.mtime));
    }

    // Step 2: Walk local
    let mut local_map: std::collections::HashMap<String, (i64, i64)> =
        std::collections::HashMap::new();
    walk_local_with_mtime(local_dir, local_dir, &exclude_set, &exclude_globs, &mut local_map)?;

    // Step 3: Compare and classify
    let mut to_pull: Vec<String> = Vec::new(); // relative paths, remote is newer
    let mut to_push: Vec<String> = Vec::new(); // relative paths, local is newer

    // Check all remote files
    for (rel, (rsize, rmtime)) in &remote_map {
        match local_map.get(rel) {
            Some((lsize, lmtime)) => {
                if rsize == lsize && (*rmtime == 0 || *lmtime == 0 || rmtime == lmtime) {
                    // Same size + (mtime unavailable or equal) = unchanged
                    result.unchanged += 1;
                } else if rsize == lsize && rmtime == lmtime {
                    result.unchanged += 1;
                } else if *rmtime > 0 && *lmtime > 0 && rmtime > lmtime {
                    to_pull.push(rel.clone());
                } else if *rmtime > 0 && *lmtime > 0 && lmtime > rmtime {
                    to_push.push(rel.clone());
                } else if rsize != lsize && (*rmtime == 0 || *lmtime == 0) {
                    // No mtime available, different size — pull remote (conservative)
                    to_pull.push(rel.clone());
                } else {
                    // Same mtime, different size — pull remote
                    to_pull.push(rel.clone());
                }
            }
            None => {
                // Only on remote — pull
                to_pull.push(rel.clone());
            }
        }
    }

    // Check local-only files (not on remote)
    for rel in local_map.keys() {
        if !remote_map.contains_key(rel) {
            to_push.push(rel.clone());
        }
    }

    if opts.dry_run {
        for p in &to_pull {
            eprintln!("[dry-run] would pull: {}", p);
        }
        for p in &to_push {
            eprintln!("[dry-run] would push: {}", p);
        }
        eprintln!(
            "sync-dir: {} to pull, {} to push, {} unchanged",
            to_pull.len(),
            to_push.len(),
            result.unchanged
        );
        return Ok(result);
    }

    // Step 4: Pull newer-remote files
    for rel in &to_pull {
        let remote_path = format!("{}\\{}", remote_dir, rel);
        let local_path = local_dir.join(rel.replace('\\', "/"));
        if let Some(parent) = local_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let local_data = std::fs::read(&local_path).ok();
        match pull(client, local_data.as_deref(), &remote_path).await {
            Ok(pr) => {
                result.pull_bytes += pr.data.len() as u64;
                std::fs::write(&local_path, &pr.data)?;
                result.pulled += 1;
                if opts.progress {
                    eprintln!("  ← {}", rel);
                }
            }
            Err(e) => {
                eprintln!("  pull {} failed: {}", rel, e);
            }
        }
    }

    // Step 5: Push newer-local files
    for rel in &to_push {
        let remote_path = format!("{}\\{}", remote_dir, rel);
        let local_path = local_dir.join(rel.replace('\\', "/"));
        match push_file(client, &local_path, &remote_path).await {
            Ok(pr) => {
                result.push_bytes += pr.bytes_sent as u64;
                result.pushed += 1;
                if opts.progress {
                    eprintln!("  → {}", rel);
                }
            }
            Err(e) => {
                eprintln!("  push {} failed: {}", rel, e);
            }
        }
    }

    let elapsed = start.elapsed();
    eprintln!(
        "sync-dir: {} pulled ({} bytes), {} pushed ({} bytes), {} unchanged in {:.1?}",
        result.pulled, result.pull_bytes, result.pushed, result.push_bytes, result.unchanged, elapsed
    );

    Ok(result)
}

/// Walk local directory collecting relative_path → (size, mtime_epoch).
fn walk_local_with_mtime(
    root: &Path,
    dir: &Path,
    exclude_dirs: &std::collections::HashSet<&str>,
    exclude_globs: &[&str],
    files: &mut std::collections::HashMap<String, (i64, i64)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if exclude_dirs.contains(name_str.as_ref()) {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_local_with_mtime(root, &entry.path(), exclude_dirs, exclude_globs, files)?;
        } else {
            let meta = entry.metadata()?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let rel = entry
                .path()
                .strip_prefix(root)
                .map_err(|e| anyhow::anyhow!("strip prefix: {}", e))?
                .to_string_lossy()
                .replace('/', "\\");
            if is_excluded(&rel, exclude_dirs, exclude_globs) {
                continue;
            }
            files.insert(rel, (meta.len() as i64, mtime));
        }
    }
    Ok(())
}

/// Check if a relative path should be excluded.
/// Matches any path component against exact dir names, or the filename/path against globs.
fn is_excluded(rel: &str, dirs: &std::collections::HashSet<&str>, globs: &[&str]) -> bool {
    // Check each path component against exact dir names
    for component in rel.split('\\') {
        if dirs.contains(component) {
            return true;
        }
    }
    // Check filename and full relative path against glob patterns
    let filename = rel.rsplit('\\').next().unwrap_or(rel);
    for pat in globs {
        if glob_match(pat, filename) || glob_match(pat, rel) {
            return true;
        }
    }
    false
}

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let (mut star_p, mut star_t) = (usize::MAX, 0);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_p = pi;
            star_t = ti;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

// ── Types ───────────────────────────────────────────────────────

/// Result of a push operation.
#[derive(Debug)]
pub struct PushResult {
    pub path: String,
    pub bytes_sent: usize,
    pub delta: bool,
}

/// Result of a pull operation.
#[derive(Debug)]
pub struct PullResult {
    pub data: Vec<u8>,
    pub delta: bool,
}

/// Result of a directory sync operation.
#[derive(Debug)]
pub struct DirSyncResult {
    pub files_total: usize,
    pub files_transferred: usize,
    pub bytes_total: u64,
}

// ── Progress & helpers ──────────────────────────────────────────

/// Print a progress line with percentage, rate, and ETA.
fn print_progress(current: usize, total: usize, bytes_done: u64, start: Instant, name: &str) {
    let elapsed = start.elapsed().as_secs_f64();
    let pct = if total > 0 {
        (current + 1) as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    let rate = if elapsed > 0.1 {
        bytes_done as f64 / elapsed
    } else {
        0.0
    };

    let eta = if rate > 0.0 && current < total {
        let remaining_files = total - current - 1;
        let avg_per_file = elapsed / (current + 1) as f64;
        remaining_files as f64 * avg_per_file
    } else {
        0.0
    };

    let rate_str = format_rate(rate);
    let eta_str = format_duration(eta);

    // Truncate name to fit in one line
    let display_name = if name.len() > 30 {
        format!("...{}", &name[name.len() - 27..])
    } else {
        name.to_string()
    };

    eprint!(
        "\r  [{}/{}] {:5.1}% {:>8} {:>6} {}          ",
        current + 1, total, pct, rate_str, eta_str, display_name
    );
}

/// Format bytes/sec as human-readable rate.
fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_048_576.0 {
        format!("{:.1}MB/s", bytes_per_sec / 1_048_576.0)
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.0}KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.0}B/s", bytes_per_sec)
    }
}

/// Format seconds as mm:ss or hh:mm:ss.
fn format_duration(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// Rename a remote file with a backup suffix before overwriting.
async fn backup_remote<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    remote_path: &str,
    suffix: &str,
) {
    let backup_path = format!("{}{}", remote_path, suffix);
    let cmd = format!(
        "if (Test-Path '{}') {{ Move-Item -Force '{}' '{}' }}",
        remote_path, remote_path, backup_path
    );
    let mut req = simple_request("exec");
    req.command = Some(cmd);
    let _ = client.request(&req).await;
}

// ── Helpers ─────────────────────────────────────────────────────

fn check_response(resp: &Response) -> Result<()> {
    if !resp.success {
        bail!("{}", resp.error.as_deref().unwrap_or("unknown error"));
    }
    Ok(())
}

/// Build a sync request with signatures.
pub fn build_sync_request(
    sync_type: &str,
    path: &str,
    sigs: Vec<mrsh_core::protocol::BlockSig>,
) -> Request {
    Request {
        req_type: "sync".to_string(),
        command: None,
        path: Some(path.to_string()),
        content: None,
        binary: None,
        gzip: None,
        sync_type: Some(sync_type.to_string()),
        delta: None,
        signatures: Some(sigs),
        paths: None,
        batch_patches: None,
        env_vars: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RshClient;
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


    // ── Existing tests ──────────────────────────────────────────────

    #[test]
    fn push_result_debug() {
        let r = PushResult {
            path: "/tmp/test".to_string(),
            bytes_sent: 1024,
            delta: true,
        };
        assert!(format!("{:?}", r).contains("delta: true"));
    }

    #[test]
    fn pull_result_debug() {
        let r = PullResult {
            data: vec![1, 2, 3],
            delta: false,
        };
        assert!(format!("{:?}", r).contains("delta: false"));
    }

    #[test]
    fn build_sync_request_fields() {
        let sigs = vec![mrsh_core::protocol::BlockSig {
            index: 0,
            weak: 12345,
            strong: "abc".to_string(),
        }];
        let req = build_sync_request("pull-delta", "/tmp/file", sigs);
        assert_eq!(req.req_type, "sync");
        assert_eq!(req.sync_type.as_deref(), Some("pull-delta"));
        assert_eq!(req.path.as_deref(), Some("/tmp/file"));
        assert_eq!(req.signatures.unwrap().len(), 1);
    }

    #[test]
    fn check_response_ok() {
        let resp = ok_response("ok");
        assert!(check_response(&resp).is_ok());
    }

    #[test]
    fn check_response_error() {
        let resp = err_response("file not found");
        let err = check_response(&resp).unwrap_err();
        assert!(err.to_string().contains("file not found"));
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
            wire::send_json(&mut server, &err_response("file not found")).await.unwrap();

            // Step 2: push-chunked sync request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("push-chunked"));
            assert_eq!(req.path.as_deref(), Some("/tmp/test.txt"));
            // content carries total size
            assert_eq!(req.content.as_deref(), Some("16"));

            // Send ack
            wire::send_json(&mut server, &ok_response("ready")).await.unwrap();

            // Read D message(s)
            let mut received_data = Vec::new();
            loop {
                let msg = wire::recv_message(&mut server).await.unwrap();
                match msg[0] {
                    b'D' => {
                        let flag = msg[1];
                        let payload_len = u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]) as usize;
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
            wire::send_json(&mut server, &err_response("not found")).await.unwrap();

            // push-chunked request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.sync_type.as_deref(), Some("push-chunked"));

            // ack
            wire::send_json(&mut server, &ok_response("ready")).await.unwrap();

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
            wire::send_json(&mut server, &ok_response(&sigs_json)).await.unwrap();

            // Step 2: push-delta with computed delta ops
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-delta");
            assert_eq!(req.path.as_deref(), Some("/tmp/delta.txt"));
            assert!(req.delta.is_some());
            wire::send_json(&mut server, &ok_response("ok")).await.unwrap();
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
            wire::send_json(&mut server, &ok_response(&format!("{}", remote_content.len()))).await.unwrap();
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
            wire::send_json(&mut server, &ok_response(&format!("{}", local_data.len()))).await.unwrap();
            // Files identical: send M for block 0 (matching client's block)
            let mut msg = [0u8; 5];
            msg[0] = b'M';
            msg[1..5].copy_from_slice(&0u32.to_be_bytes());
            wire::send_message(&mut server, &msg).await.unwrap();
            // Send E marker
            wire::send_message(&mut server, b"E").await.unwrap();
        });

        let result = pull(&mut client, Some(local_data), "/tmp/same.txt").await.unwrap();
        assert_eq!(result.data, local_data);
        assert!(result.delta);
        h.await.unwrap();
    }

    // ── Push dir: dry run ───────────────────────────────────────────

    #[tokio::test]
    async fn push_dir_dry_run() {
        let (mut client, _server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_push_dir");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.txt"), "aaa").unwrap();
        std::fs::write(tmp.join("b.txt"), "bbb").unwrap();

        let opts = TransferOptions { dry_run: true, ..Default::default() };
        let result = push_dir(&mut client, &tmp, "C:\\dest", &opts).await.unwrap();
        assert_eq!(result.files_total, 2);
        assert_eq!(result.files_transferred, 0); // dry run = no transfer

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Pull dir: basic ─────────────────────────────────────────────

    #[tokio::test]
    async fn pull_dir_basic() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_pull_dir");
        let _ = std::fs::remove_dir_all(&tmp);

        let file_content = b"pulled content";

        let h = tokio::spawn(async move {
            // Step 1: walk request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("walk"));
            let walk = r#"[{"p":"file.txt","s":14}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();

            // Step 2: pull-delta for file.txt (binary M/D/E protocol)
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("pull-delta"));
            // JSON ack
            wire::send_json(&mut server, &ok_response(&format!("{}", file_content.len()))).await.unwrap();
            // D message with file content
            let data_len = file_content.len() as u32;
            let mut msg = Vec::with_capacity(5 + file_content.len());
            msg.push(b'D');
            msg.extend_from_slice(&data_len.to_be_bytes());
            msg.extend_from_slice(file_content);
            wire::send_message(&mut server, &msg).await.unwrap();
            // E marker
            wire::send_message(&mut server, b"E").await.unwrap();
        });

        let opts = TransferOptions::default();
        let result = pull_dir(&mut client, "C:\\src", &tmp, &opts).await.unwrap();
        assert_eq!(result.files_total, 1);
        assert_eq!(result.files_transferred, 1);

        let pulled = std::fs::read(tmp.join("file.txt")).unwrap();
        assert_eq!(pulled, file_content);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Pull dir: dry run ───────────────────────────────────────────

    #[tokio::test]
    async fn pull_dir_dry_run() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_pull_dir_dry");
        let _ = std::fs::remove_dir_all(&tmp);

        let h = tokio::spawn(async move {
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk = r#"[{"p":"a.txt","s":100},{"p":"b.txt","s":200}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();
        });

        let opts = TransferOptions { dry_run: true, ..Default::default() };
        let result = pull_dir(&mut client, "C:\\src", &tmp, &opts).await.unwrap();
        assert_eq!(result.files_total, 2);
        assert_eq!(result.files_transferred, 0);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Delete remote extras ────────────────────────────────────────

    #[tokio::test]
    async fn delete_remote_extras_removes_missing() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_delete_extras");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("keep.txt"), "keep").unwrap();

        let h = tokio::spawn(async move {
            // Walk request
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk = r#"[{"p":"keep.txt","s":4},{"p":"delete_me.txt","s":10}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();

            // Delete exec request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "exec");
            let cmd = req.command.as_deref().unwrap();
            assert!(cmd.contains("Remove-Item"));
            assert!(cmd.contains("delete_me.txt"));
            wire::send_json(&mut server, &ok_response("")).await.unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote").await.unwrap();
        assert_eq!(count, 1);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn delete_remote_extras_nothing_to_delete() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_delete_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("same.txt"), "same").unwrap();

        let h = tokio::spawn(async move {
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk = r#"[{"p":"same.txt","s":4}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote").await.unwrap();
        assert_eq!(count, 0);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Format helpers ──────────────────────────────────────────────

    #[test]
    fn format_rate_bytes() {
        assert_eq!(format_rate(500.0), "500B/s");
    }

    #[test]
    fn format_rate_kilobytes() {
        assert_eq!(format_rate(2048.0), "2KB/s");
    }

    #[test]
    fn format_rate_megabytes() {
        assert_eq!(format_rate(5_242_880.0), "5.0MB/s");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(45.0), "0:45");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(125.0), "2:05");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(3665.0), "1:01:05");
    }

    // ── Transfer options ────────────────────────────────────────────

    #[test]
    fn transfer_options_default() {
        let opts = TransferOptions::default();
        assert!(!opts.progress);
        assert!(!opts.dry_run);
        assert!(opts.backup_suffix.is_none());
        assert_eq!(opts.bwlimit_kbps, 0);
    }

    // ── Walk entry deserialization ──────────────────────────────────

    #[test]
    fn walk_entry_parse() {
        let json = r#"{"p":"subdir/file.txt","s":1024}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.path, "subdir/file.txt");
        assert_eq!(entry.size, 1024);
    }

    // ── glob_match tests ─────────────────────────────────────────

    #[test]
    fn glob_star_matches_any() {
        assert!(glob_match("*.log", "debug.log"));
        assert!(glob_match("*.log", "a.b.log"));
        assert!(!glob_match("*.log", "debug.txt"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("test*", "test_file.rs"));
        assert!(glob_match("test*", "test"));
        assert!(!glob_match("test*", "best"));
    }

    #[test]
    fn glob_question_mark() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(glob_match("file?.txt", "fileA.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));
    }

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("readme.md", "readme.md"));
        assert!(glob_match("readme.md", "README.md")); // case-insensitive (Windows paths)
        assert!(!glob_match("readme.md", "readme.txt"));
    }

    #[test]
    fn glob_empty() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn glob_double_star() {
        assert!(glob_match("**", "any/path/here"));
    }

    // ── is_excluded tests ────────────────────────────────────────

    #[test]
    fn excluded_by_dir_name() {
        let dirs: std::collections::HashSet<&str> = [".git", "node_modules"].into_iter().collect();
        let globs: Vec<&str> = vec![];
        assert!(is_excluded(".git\\config", &dirs, &globs));
        assert!(is_excluded("src\\node_modules\\pkg", &dirs, &globs));
        assert!(!is_excluded("src\\main.rs", &dirs, &globs));
    }

    #[test]
    fn excluded_by_glob() {
        let dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let globs = vec!["*.log", "*.tmp"];
        assert!(is_excluded("debug.log", &dirs, &globs));
        assert!(is_excluded("sub\\output.tmp", &dirs, &globs));
        assert!(!is_excluded("main.rs", &dirs, &globs));
    }

    #[test]
    fn excluded_nested_dir() {
        let dirs: std::collections::HashSet<&str> = [".venv"].into_iter().collect();
        let globs: Vec<&str> = vec![];
        assert!(is_excluded("project\\.venv\\lib\\site.py", &dirs, &globs));
    }

    #[test]
    fn not_excluded_partial_match() {
        let dirs: std::collections::HashSet<&str> = [".git"].into_iter().collect();
        let globs: Vec<&str> = vec![];
        assert!(!is_excluded(".gitignore", &dirs, &globs));
        assert!(!is_excluded("src\\.github\\ci.yml", &dirs, &globs));
    }

    // ── walk_local_with_mtime tests ──────────────────────────────

    #[test]
    fn walk_local_collects_files_with_mtime() {
        let tmp = std::env::temp_dir().join("rsh_test_walk_mtime");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("a.txt"), "aaa").unwrap();
        std::fs::write(tmp.join("sub").join("b.txt"), "bbbbb").unwrap();

        let dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let globs: Vec<&str> = vec![];
        let mut files = std::collections::HashMap::new();
        walk_local_with_mtime(&tmp, &tmp, &dirs, &globs, &mut files).unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(files.get("a.txt").unwrap().0, 3); // size
        assert_eq!(files.get("sub\\b.txt").unwrap().0, 5);
        // mtime should be > 0 (recent)
        assert!(files.get("a.txt").unwrap().1 > 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn walk_local_excludes_dirs() {
        let tmp = std::env::temp_dir().join("rsh_test_walk_exclude");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(tmp.join(".git").join("HEAD"), "ref").unwrap();
        std::fs::write(tmp.join("src").join("main.rs"), "fn main(){}").unwrap();
        std::fs::write(tmp.join("readme.md"), "# hi").unwrap();

        let dirs: std::collections::HashSet<&str> = [".git"].into_iter().collect();
        let globs: Vec<&str> = vec![];
        let mut files = std::collections::HashMap::new();
        walk_local_with_mtime(&tmp, &tmp, &dirs, &globs, &mut files).unwrap();

        assert_eq!(files.len(), 2); // readme.md + src/main.rs
        assert!(files.contains_key("readme.md"));
        assert!(files.contains_key("src\\main.rs"));
        assert!(!files.contains_key(".git\\HEAD"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn walk_local_excludes_globs() {
        let tmp = std::env::temp_dir().join("rsh_test_walk_glob");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("main.rs"), "code").unwrap();
        std::fs::write(tmp.join("debug.log"), "log data").unwrap();
        std::fs::write(tmp.join("output.tmp"), "tmp").unwrap();

        let dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let globs = vec!["*.log", "*.tmp"];
        let mut files = std::collections::HashMap::new();
        walk_local_with_mtime(&tmp, &tmp, &dirs, &globs, &mut files).unwrap();

        assert_eq!(files.len(), 1);
        assert!(files.contains_key("main.rs"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── WalkEntry mtime deserialization ──────────────────────────

    #[test]
    fn walk_entry_with_mtime() {
        let json = r#"{"p":"file.txt","s":100,"m":1711200000}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.mtime, 1711200000);
    }

    #[test]
    fn walk_entry_without_mtime_defaults_zero() {
        let json = r#"{"p":"file.txt","s":100}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.mtime, 0);
    }

    // ── SYNC_EXCLUDE_DIRS ────────────────────────────────────────

    #[test]
    fn default_excludes_contain_essentials() {
        assert!(SYNC_EXCLUDE_DIRS.contains(&".git"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&".venv"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&"node_modules"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&"target"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&"__pycache__"));
    }
}
