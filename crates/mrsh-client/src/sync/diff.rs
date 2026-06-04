//! Bidirectional directory sync — mtime+size comparison + push/pull diff.

use anyhow::Result;
use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

use super::SyncDirResult;
use super::TransferOptions;
use super::dir::{
    is_excluded, normalize_remote_rel_path_with_prefixes, walk_local_with_mtime,
};
use super::protocol::{WalkEntry, check_response};
use super::transfer::{pull, push_file};

/// Default directory names excluded from sync-dir.
pub(super) const SYNC_EXCLUDE_DIRS: &[&str] = &[
    ".git",
    ".venv",
    ".tmp",
    ".beads",
    ".claude",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "target",
];

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
        let rel = normalize_remote_rel_path_with_prefixes(
            &remote_prefix_bk,
            &remote_prefix_fwd,
            &entry.path,
        );
        // Check exclusion: any path component matches exclude dir, or full path matches glob
        if is_excluded(&rel, &exclude_set, &exclude_globs) {
            continue;
        }
        remote_map.insert(rel, (entry.size, entry.mtime));
    }

    // Step 2: Walk local
    let mut local_map: std::collections::HashMap<String, (i64, i64)> =
        std::collections::HashMap::new();
    walk_local_with_mtime(
        local_dir,
        local_dir,
        &exclude_set,
        &exclude_globs,
        &mut local_map,
    )?;

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
        result.pulled,
        result.pull_bytes,
        result.pushed,
        result.push_bytes,
        result.unchanged,
        elapsed
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_excludes_contain_essentials() {
        assert!(SYNC_EXCLUDE_DIRS.contains(&".git"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&".venv"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&"node_modules"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&"target"));
        assert!(SYNC_EXCLUDE_DIRS.contains(&"__pycache__"));
    }
}
