//! Sync command handlers - signatures, delta, patch, pull, walk, batch ops.
//!
//! # Module layout
//! - [`transfer`] - single-file handlers (get-signatures, compute-delta,
//!   apply-patch, pull-file, pull-delta streaming, push-chunked streaming).
//! - [`dir`] - recursive walk + block-cache index.
//! - [`diff`] - batch ops, smart-sync, find-and-move.
//! - [`protocol`] - type conversions + gzip helpers + `WalkEntry` wire shape.

mod diff;
mod dir;
mod protocol;
mod transfer;

use mrsh_core::protocol::{self as proto, Response};
use mrsh_transfer::blockcache;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use tracing::{debug, info};

pub use diff::handle_batch_patch_bin;
pub use transfer::{handle_pull_delta, handle_push_chunked};

// Global block cache (server-wide singleton)

/// Default cache data directory on Windows.
#[cfg(windows)]
const CACHE_DATA_DIR: &str = r"C:\ProgramData\mrsh\cache";

/// Fallback for non-Windows (testing / Linux builds).
#[cfg(not(windows))]
const CACHE_DATA_DIR: &str = "/var/lib/rsh/cache";

pub(super) static BLOCK_CACHE: LazyLock<Mutex<blockcache::Cache>> = LazyLock::new(|| {
    let cache_file = Path::new(CACHE_DATA_DIR).join("blockcache.msgpack");
    match blockcache::Cache::new(&cache_file) {
        Ok(cache) => {
            debug!("block cache loaded from {:?}", cache_file);
            Mutex::new(cache)
        }
        Err(e) => {
            tracing::warn!(
                "block cache init failed ({:?}): {}, using empty cache",
                cache_file,
                e
            );
            // Create an in-memory cache with a temp path - will work but won't persist
            let fallback = std::env::temp_dir().join("rsh-blockcache-fallback.msgpack");
            Mutex::new(blockcache::Cache::new(&fallback).expect("fallback cache must succeed"))
        }
    }
});

/// Sanitize a file path: reject null bytes and newlines.
pub fn sanitize_path(path: &str) -> std::result::Result<&str, String> {
    if path.as_bytes().contains(&0) {
        return Err("path contains null byte".to_string());
    }
    if path.contains('\n') || path.contains('\r') {
        return Err("path contains newline".to_string());
    }
    Ok(path)
}

/// Dispatch sync sub-commands.
pub fn handle_sync(req: &proto::Request) -> Response {
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

    info!("sync: type={} path={}", sync_type, path);

    match sync_type {
        "signatures" => transfer::handle_get_signatures(path),
        "delta" => {
            let sigs =
                protocol::convert_sigs_from_proto(req.signatures.as_deref().unwrap_or(&[]));
            transfer::handle_compute_delta(path, &sigs)
        }
        "patch" => transfer::handle_apply_patch(path, req.delta.as_deref(), req.content.as_deref()),
        "pull" => transfer::handle_pull_file(path),
        "walk" => dir::handle_walk(path),
        "batch-signatures" => {
            let paths = req.paths.as_deref().unwrap_or(&[]);
            diff::handle_batch_signatures(paths)
        }
        "batch-patch" => {
            let patches = req.batch_patches.as_deref().unwrap_or(&[]);
            diff::handle_batch_patch(patches)
        }
        "cache-stats" => dir::handle_cache_stats(),
        "index-dir" => dir::handle_index_dir(path),
        "smart-sync" => diff::handle_smart_sync(req.content.as_deref().unwrap_or("")),
        "find-and-move" => {
            let patches = req.batch_patches.as_deref().unwrap_or(&[]);
            diff::handle_find_and_move(patches)
        }
        other => Response::error(&format!("unknown sync type: {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
