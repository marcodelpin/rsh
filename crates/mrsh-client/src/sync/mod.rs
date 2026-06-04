//! Push/pull file transfer — delta sync using rsh-transfer.
//! Sends block signatures, receives delta, applies patches.
//! Supports single files and directories (walk + per-file delta).
//!
//! # Module layout
//! - [`transfer`] — single-file push/pull (delta + chunked streaming).
//! - [`dir`] — recursive push_dir / pull_dir / delete_remote_extras.
//! - [`diff`] — bidirectional `sync_dir` (mtime+size compare).
//! - [`protocol`] — wire types (`WalkEntry`, `build_sync_request`, helpers).

mod dir;
mod diff;
mod protocol;
mod transfer;

// ── Public re-exports ───────────────────────────────────────────

pub use dir::{delete_remote_extras, pull_dir, push_dir};
pub use diff::sync_dir;
pub use protocol::build_sync_request;
pub use transfer::{pull, push, push_file};

// ── Public result/option types ──────────────────────────────────

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

/// Result of a bidirectional sync.
#[derive(Debug, Default)]
pub struct SyncDirResult {
    pub pulled: usize,
    pub pushed: usize,
    pub unchanged: usize,
    pub pull_bytes: u64,
    pub push_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn transfer_options_default() {
        let opts = TransferOptions::default();
        assert!(!opts.progress);
        assert!(!opts.dry_run);
        assert!(opts.backup_suffix.is_none());
        assert_eq!(opts.bwlimit_kbps, 0);
    }
}
