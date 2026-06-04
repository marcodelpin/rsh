//! Directory operations: recursive walk, block-cache index, cache stats.

use mrsh_core::protocol::Response;
use mrsh_transfer::blockcache;
use std::path::Path;
use tracing::debug;

use super::BLOCK_CACHE;
use super::protocol::WalkEntry;

/// Recursive directory walk returning file paths and sizes.
pub(super) fn handle_walk(path: &str) -> Response {
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

/// Cache stats — returns block and file counts from the shared block cache.
pub(super) fn handle_cache_stats() -> Response {
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
pub(super) fn handle_index_dir(path: &str) -> Response {
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
                && cache.index_file(p).is_ok()
            {
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

#[cfg(test)]
mod tests {
    use super::*;

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
