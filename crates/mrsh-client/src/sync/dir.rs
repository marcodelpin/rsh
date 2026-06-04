//! Directory walk and recursive push/pull for the client.
//!
//! - `push_dir` — walk local tree, mkdir remote, push each file with delta.
//! - `pull_dir` — server walk + per-file pull with delta.
//! - `delete_remote_extras` — mirror mode: remove remote files not in local set.
//! - shared path-normalisation, glob, exclude, and progress helpers.

use anyhow::Result;
use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

use super::{DirSyncResult, TransferOptions};
use super::protocol::{WalkEntry, check_response};
use super::transfer::{pull, push_file};

// ── Push directory ──────────────────────────────────────────────

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

    eprintln!(
        "push directory: {} -> {} ({} files)",
        local_dir.display(),
        remote_dir,
        files.len()
    );

    if files.is_empty() {
        return Ok(DirSyncResult {
            files_total: 0,
            files_transferred: 0,
            bytes_total: 0,
        });
    }

    if opts.dry_run {
        for (local_path, remote_path) in &files {
            let size = std::fs::metadata(local_path).map(|m| m.len()).unwrap_or(0);
            eprintln!(
                "  [dry-run] {} ({} bytes) -> {}",
                local_path.display(),
                size,
                remote_path
            );
        }
        return Ok(DirSyncResult {
            files_total: files.len(),
            files_transferred: 0,
            bytes_total: 0,
        });
    }

    // Collect unique remote parent directories and create them.
    // Server-side mkdir handles both forward and backslash paths.
    let mut remote_parents: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, remote_path) in &files {
        if let Some(parent) = remote_path.rsplit_once('/').map(|(p, _)| p.to_string()) {
            remote_parents.insert(parent);
        }
    }
    for dir in &remote_parents {
        // Create remote directories. The push handler's create_dir_all handles this
        // automatically, but we pre-create for visibility in logs.
        let cmd = if dir.contains(':') || dir.starts_with("\\\\") {
            // Windows-style path (C:\... or UNC)
            format!("cmd /c if not exist \"{}\" mkdir \"{}\"", dir, dir)
        } else {
            // Unix-style path
            format!("SH:mkdir -p '{}'", dir)
        };
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
            print_progress(
                i,
                total,
                bytes_total,
                start_time,
                &local_path.file_name().unwrap_or_default().to_string_lossy(),
            );
        } else {
            eprintln!(
                "  [{}/{}] {}",
                i + 1,
                total,
                local_path.file_name().unwrap_or_default().to_string_lossy()
            );
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

    Ok(DirSyncResult {
        files_total: total,
        files_transferred: transferred,
        bytes_total,
    })
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
            let rel = entry
                .path()
                .strip_prefix(root)
                .map_err(|e| anyhow::anyhow!("strip prefix: {}", e))?
                .to_string_lossy()
                .replace('\\', "/");
            let remote_path = format!("{}/{}", remote_dir.trim_end_matches(['/', '\\']), rel);
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
    let entries: Vec<WalkEntry> =
        serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("parse walk response: {}", e))?;

    eprintln!(
        "pull directory: {} -> {} ({} files)",
        remote_dir,
        local_dir.display(),
        entries.len()
    );

    if opts.dry_run {
        for entry in &entries {
            eprintln!("  [dry-run] {} ({} bytes)", entry.path, entry.size);
        }
        return Ok(DirSyncResult {
            files_total: entries.len(),
            files_transferred: 0,
            bytes_total: 0,
        });
    }

    std::fs::create_dir_all(local_dir)?;

    let total = entries.len();
    let mut transferred = 0usize;
    let mut bytes_total = 0u64;
    let start_time = Instant::now();
    let mut failed: Vec<(String, String)> = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        // Build paths — server walk returns paths relative to remote_dir or absolute.
        // Server may return relative paths (forward slashes) or absolute.
        let rel_path = if entry.path.starts_with(remote_dir) {
            // Absolute path from server — strip the remote_dir prefix
            entry.path[remote_dir.len()..]
                .trim_start_matches(['/', '\\'])
                .to_string()
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
            eprintln!(
                "  [{}/{}] {} ({} bytes)",
                i + 1,
                total,
                rel_path,
                entry.size
            );
        }

        // Backup local file before overwrite if requested
        if let Some(ref suffix) = opts.backup_suffix
            && local_file.exists()
        {
            let backup_path = format!("{}{}", local_file.display(), suffix);
            if let Err(e) = std::fs::copy(&local_file, &backup_path) {
                eprintln!("  backup warning: {}: {}", backup_path, e);
            }
        }

        // Read existing local file for delta sync
        let local_data = std::fs::read(&local_file).ok();
        match pull(client, local_data.as_deref(), &remote_file).await {
            Ok(result) => {
                if let Err(e) = std::fs::write(&local_file, &result.data) {
                    eprintln!("  FAIL (write): {}: {}", rel_path, e);
                    failed.push((rel_path.clone(), format!("local write: {}", e)));
                } else {
                    bytes_total += result.data.len() as u64;
                    transferred += 1;
                }
            }
            Err(e) => {
                // Skip unreadable files (e.g., NTFS ACL from docker cp) and continue
                eprintln!("  SKIP: {}: {}", rel_path, e);
                failed.push((rel_path.clone(), e.to_string()));
            }
        }
    }

    if opts.progress {
        eprintln!(); // clear progress line
    }

    if !failed.is_empty() {
        eprintln!("\npull-dir: {} files skipped:", failed.len());
        for (path, err) in &failed {
            eprintln!("  - {}: {}", path, err);
        }
    }

    Ok(DirSyncResult {
        files_total: total,
        files_transferred: transferred,
        bytes_total,
    })
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
        eprintln!(
            "--delete: could not walk remote: {}",
            resp.error.as_deref().unwrap_or("unknown")
        );
        return Ok(0);
    }

    let json = resp.output.unwrap_or_default();
    let remote_entries: Vec<WalkEntry> = serde_json::from_str(&json).unwrap_or_default();

    // Build set of local relative paths. Compare relatives, not full paths, because
    // server walk returns full paths while older tests/mocks may still send relatives.
    let empty_dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let empty_globs: [&str; 0] = [];
    let mut local_map: std::collections::HashMap<String, (i64, i64)> =
        std::collections::HashMap::new();
    walk_local_with_mtime(
        local_dir,
        local_dir,
        &empty_dirs,
        &empty_globs,
        &mut local_map,
    )?;
    let local_set: std::collections::HashSet<String> = local_map.into_keys().collect();

    // Find remote files not in local set
    let mut to_delete: Vec<String> = Vec::new();
    for entry in &remote_entries {
        let rel = normalize_remote_rel_path(remote_dir, &entry.path);
        if !local_set.contains(&rel) {
            to_delete.push(join_remote_path(remote_dir, &rel));
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

// ── Walk + path helpers (shared with diff.rs) ──────────────────

/// Walk local directory collecting relative_path → (size, mtime_epoch).
pub(super) fn walk_local_with_mtime(
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

pub(super) fn normalize_remote_rel_path(remote_dir: &str, remote_path: &str) -> String {
    let remote_prefix_bk = remote_dir.replace('/', "\\");
    let remote_prefix_fwd = remote_dir.replace('\\', "/");
    normalize_remote_rel_path_with_prefixes(&remote_prefix_bk, &remote_prefix_fwd, remote_path)
}

pub(super) fn normalize_remote_rel_path_with_prefixes(
    remote_prefix_bk: &str,
    remote_prefix_fwd: &str,
    remote_path: &str,
) -> String {
    let normalized = remote_path.replace('/', "\\");
    if normalized.starts_with(remote_prefix_bk) {
        normalized[remote_prefix_bk.len()..]
            .trim_start_matches('\\')
            .to_string()
    } else {
        let fwd = remote_path.replace('\\', "/");
        if fwd.starts_with(remote_prefix_fwd) {
            fwd[remote_prefix_fwd.len()..]
                .trim_start_matches('/')
                .replace('/', "\\")
        } else {
            normalized.trim_start_matches('\\').to_string()
        }
    }
}

fn join_remote_path(remote_dir: &str, rel: &str) -> String {
    let base = remote_dir.trim_end_matches(['/', '\\']);
    let rel = rel.trim_start_matches(['/', '\\']).replace('/', "\\");
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}\\{rel}")
    }
}

/// Check if a relative path should be excluded.
/// Matches any path component against exact dir names, or the filename/path against globs.
pub(super) fn is_excluded(
    rel: &str,
    dirs: &std::collections::HashSet<&str>,
    globs: &[&str],
) -> bool {
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

// ── Progress + backup helpers ──────────────────────────────────

/// Print a progress line with percentage, rate, and ETA.
pub(super) fn print_progress(
    current: usize,
    total: usize,
    bytes_done: u64,
    start: Instant,
    name: &str,
) {
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
        current + 1,
        total,
        pct,
        rate_str,
        eta_str,
        display_name
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RshClient;
    use mrsh_core::protocol::{Request, Response};
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

    // ── Push dir: dry run ───────────────────────────────────────────

    #[tokio::test]
    async fn push_dir_dry_run() {
        let (mut client, _server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_push_dir");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.txt"), "aaa").unwrap();
        std::fs::write(tmp.join("b.txt"), "bbb").unwrap();

        let opts = TransferOptions {
            dry_run: true,
            ..Default::default()
        };
        let result = push_dir(&mut client, &tmp, "C:\\dest", &opts)
            .await
            .unwrap();
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
            wire::send_json(&mut server, &ok_response(walk))
                .await
                .unwrap();

            // Step 2: pull-delta for file.txt (binary M/D/E protocol)
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("pull-delta"));
            // JSON ack
            wire::send_json(
                &mut server,
                &ok_response(&format!("{}", file_content.len())),
            )
            .await
            .unwrap();
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
            wire::send_json(&mut server, &ok_response(walk))
                .await
                .unwrap();
        });

        let opts = TransferOptions {
            dry_run: true,
            ..Default::default()
        };
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
            wire::send_json(&mut server, &ok_response(walk))
                .await
                .unwrap();

            // Delete exec request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "exec");
            let cmd = req.command.as_deref().unwrap();
            assert!(cmd.contains("Remove-Item"));
            assert!(cmd.contains("delete_me.txt"));
            wire::send_json(&mut server, &ok_response(""))
                .await
                .unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote")
            .await
            .unwrap();
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
            wire::send_json(&mut server, &ok_response(walk))
                .await
                .unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote")
            .await
            .unwrap();
        assert_eq!(count, 0);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn delete_remote_extras_handles_full_remote_paths() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_delete_full_paths");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("sub").join("same.txt"), "same").unwrap();

        let h = tokio::spawn(async move {
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk =
                r#"[{"p":"C:/remote/sub/same.txt","s":4},{"p":"C:\\remote\\sub\\gone.txt","s":4}]"#;
            wire::send_json(&mut server, &ok_response(walk))
                .await
                .unwrap();

            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "exec");
            let cmd = req.command.as_deref().unwrap();
            assert!(cmd.contains("gone.txt"));
            assert!(!cmd.contains("same.txt"));
            wire::send_json(&mut server, &ok_response(""))
                .await
                .unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote")
            .await
            .unwrap();
        assert_eq!(count, 1);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn normalize_remote_rel_path_accepts_full_and_relative() {
        assert_eq!(
            normalize_remote_rel_path("C:\\remote", "C:\\remote\\sub\\file.txt"),
            "sub\\file.txt"
        );
        assert_eq!(
            normalize_remote_rel_path("C:\\remote", "C:/remote/sub/file.txt"),
            "sub\\file.txt"
        );
        assert_eq!(
            normalize_remote_rel_path("C:\\remote", "sub/file.txt"),
            "sub\\file.txt"
        );
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
}
