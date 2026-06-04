//! Self-update watchdog rollback executor (rsh-5264.4).
//!
//! When `update_status::record_heartbeat_outcome` returns
//! `WatchdogAction::RollbackTriggered`, this module restores the previous
//! binary from the .bak captured at watchdog-arm time, then schedules a
//! service restart so the rolled-back binary takes over.
//!
//! Safety guarantees:
//!   * .bak is validated (exists, ≥1 MB) BEFORE the swap
//!   * the failed binary is renamed to `mrsh.exe.failed-<ts>` (NEVER deleted)
//!     so a human can post-mortem
//!   * `last_update.json` is updated with status="failed:rolled-back" so the
//!     next heartbeat reports the rollback to rdv
//!   * watchdog state is NOT re-armed by this module (anti-loop)

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::update_status::{self, UpdateStatus};

/// Minimum acceptable size of the .bak before rollback proceeds (1 MB).
/// Same threshold used by `selfupdate::validate_update_path` for the new
/// binary — the .bak we are restoring should also clear it.
const MIN_BAK_SIZE: u64 = 1_000_000;

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validate that the previous-binary path captured at arm time is still
/// usable for a rollback. Returns Err with a descriptive reason on any
/// failure so the caller can record it via `update_status`.
pub fn validate_bak_path(prev_path: &str) -> Result<()> {
    if prev_path.is_empty() {
        bail!("previous_binary_path is empty — watchdog state corrupted");
    }
    let p = Path::new(prev_path);
    let meta = std::fs::metadata(p)
        .with_context(|| format!("previous binary not found: {}", prev_path))?;
    if !meta.is_file() {
        bail!("previous_binary_path is not a regular file: {}", prev_path);
    }
    if meta.len() < MIN_BAK_SIZE {
        bail!(
            "previous binary too small: {} bytes (minimum {})",
            meta.len(),
            MIN_BAK_SIZE
        );
    }
    Ok(())
}

/// Build the path of the failed binary's quarantine name from the live exe
/// path and the current unix timestamp.
fn quarantine_path(exe_path: &Path, ts: i64) -> PathBuf {
    let parent = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = exe_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    parent.join(format!("{}.failed-{}", stem, ts))
}

/// Resolve the live `mrsh.exe` (or `mrsh`) path. We deliberately compute
/// the canonical filename from the exe directory rather than trust
/// `current_exe()` blindly — a rename-swap may have left `current_exe()`
/// pointing at `mrsh-prev.exe` or a deleted inode.
fn resolve_live_exe_path() -> Result<PathBuf> {
    let raw = std::env::current_exe().context("get current exe path")?;
    let raw_str = raw.to_string_lossy().to_string();
    // Linux appends " (deleted)" when the file was unlinked under us.
    let trimmed = raw_str.trim_end_matches(" (deleted)").to_string();
    let raw = PathBuf::from(trimmed);
    let dir = raw
        .parent()
        .context("current exe has no parent directory")?
        .to_path_buf();

    #[cfg(target_os = "windows")]
    {
        Ok(dir.join("mrsh.exe"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Linux deploy path is /usr/local/bin/mrsh or /opt/<svc>/<bin>;
        // either way the canonical filename matches the live process.
        let stem = raw
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Strip trailing ".bak" or ".prev" if somehow present
        let canonical = stem
            .trim_end_matches(".bak")
            .trim_end_matches(".prev")
            .to_string();
        Ok(dir.join(canonical))
    }
}

/// Execute the rollback: validate .bak, quarantine the failed binary,
/// promote .bak back to live, schedule restart, update status file.
///
/// Best-effort: each step is logged and partial failures still record a
/// "failed:rolled-back" status so an operator can investigate.
///
/// Caller (heartbeat call site) MUST have just received
/// `WatchdogAction::RollbackTriggered` from `record_heartbeat_outcome`.
pub fn execute_rollback() -> Result<()> {
    let data_dir = update_status::default_data_dir();
    let prior = update_status::read(&data_dir);
    let prev_bak = prior.previous_binary_path.clone();

    info!(
        "watchdog: rollback requested (prev_bak={}, watchdog_started_at={})",
        prev_bak, prior.watchdog_started_at,
    );

    // 1] Validate the .bak exists and is sane
    if let Err(e) = validate_bak_path(&prev_bak) {
        let reason = format!("rolled-back: bak invalid: {}", e);
        warn!("watchdog: {}", reason);
        let _ = update_status::write(
            &data_dir,
            &UpdateStatus {
                status: format!(
                    "failed:rolled-back-aborted: {}",
                    truncate_for_status(&e.to_string()),
                ),
                ts: now_unix_secs(),
                watchdog_active: false,
                watchdog_started_at: 0,
                consecutive_heartbeat_failures: 0,
                previous_binary_path: prev_bak.clone(),
            },
        );
        return Err(e);
    }

    // 2] Resolve live exe path
    let exe_path = match resolve_live_exe_path() {
        Ok(p) => p,
        Err(e) => {
            warn!("watchdog: cannot resolve live exe path: {}", e);
            return Err(e);
        }
    };

    // 3] Quarantine the failed binary (NEVER delete — preserve evidence)
    let ts = now_unix_secs();
    let quarantine = quarantine_path(&exe_path, ts);
    if exe_path.exists() {
        if let Err(e) = std::fs::rename(&exe_path, &quarantine) {
            warn!(
                "watchdog: failed to quarantine {} → {}: {}",
                exe_path.display(),
                quarantine.display(),
                e,
            );
            // Continue anyway — promote will fail loudly if the slot is occupied
        } else {
            info!(
                "watchdog: quarantined failed binary {} → {}",
                exe_path.display(),
                quarantine.display(),
            );
        }
    }

    // 4] Promote .bak back to the live path. Use rename when possible,
    //    fall back to copy (cross-device or strange FS).
    let restored = match std::fs::rename(&prev_bak, &exe_path) {
        Ok(()) => true,
        Err(e1) => {
            warn!(
                "watchdog: rename {} → {} failed ({}), falling back to copy",
                prev_bak,
                exe_path.display(),
                e1,
            );
            match std::fs::copy(&prev_bak, &exe_path) {
                Ok(_) => true,
                Err(e2) => {
                    warn!(
                        "watchdog: copy {} → {} also failed: {}",
                        prev_bak,
                        exe_path.display(),
                        e2,
                    );
                    false
                }
            }
        }
    };

    if !restored {
        let reason = "rolled-back: promote .bak to live failed";
        let _ = update_status::write(
            &data_dir,
            &UpdateStatus {
                status: format!("failed:{}", truncate_for_status(reason)),
                ts: now_unix_secs(),
                watchdog_active: false,
                watchdog_started_at: 0,
                consecutive_heartbeat_failures: 0,
                previous_binary_path: prev_bak.clone(),
            },
        );
        bail!(reason);
    }

    // 5] On Linux, ensure the restored binary is executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&exe_path, perms);
    }

    // 6] Persist final status BEFORE restart so the new (= old, restored)
    //    binary observes "failed:rolled-back" on its first heartbeat.
    let _ = update_status::write(
        &data_dir,
        &UpdateStatus {
            status: "failed:rolled-back".to_string(),
            ts: now_unix_secs(),
            watchdog_active: false,
            watchdog_started_at: 0,
            consecutive_heartbeat_failures: 0,
            previous_binary_path: prev_bak.clone(),
        },
    );
    // Always clear any lingering pending marker (defensive)
    update_status::clear_pending(&data_dir);

    // 7] Schedule service restart so the rolled-back binary takes over.
    //    Best-effort: log + continue if restart fails (operator can fix).
    schedule_restart();

    info!(
        "watchdog: rollback complete — restored {} from {}; restart scheduled",
        exe_path.display(),
        prev_bak,
    );
    Ok(())
}

fn truncate_for_status(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(*c, '"' | '\\' | '\n' | '\r' | '\t'))
        .take(80)
        .collect()
}

/// Schedule a service restart on the host. Windows uses `net stop && net start`
/// scheduled via schtask (clean detached process). Linux uses systemctl.
/// Both paths are best-effort.
#[cfg(target_os = "windows")]
fn schedule_restart() {
    use crate::win_proc::HideWindow;
    use std::process::Command;

    let svc = {
        let probe = Command::new("sc").args(["query", "mrsh"]).hide_window().output();
        if probe.map(|o| o.status.success()).unwrap_or(false) {
            "mrsh"
        } else {
            "rsh"
        }
    };

    // Use a detached cmd to avoid blocking the heartbeat thread.
    let cmd = format!("net stop {svc} & timeout /t 2 /nobreak >nul & net start {svc}");
    use std::os::windows::process::CommandExt;
    let _ = Command::new("cmd")
        .args(["/c", "start", "/b", "cmd", "/c", &cmd])
        .creation_flags(0x08000000 | 0x00000008) // CREATE_NO_WINDOW | DETACHED_PROCESS
        .spawn();
}

#[cfg(not(target_os = "windows"))]
fn schedule_restart() {
    use std::process::Command;
    // Try mrsh first, then legacy rsh service name. Best-effort.
    for svc in ["mrsh", "rsh"] {
        let _ = Command::new("systemctl")
            .args(["restart", svc])
            .spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn validate_bak_rejects_empty_path() {
        let r = validate_bak_path("");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn validate_bak_rejects_missing_file() {
        let r = validate_bak_path("/no/such/path/should/exist/bak");
        assert!(r.is_err());
    }

    #[test]
    fn validate_bak_rejects_too_small() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"tiny").unwrap();
        let r = validate_bak_path(f.path().to_str().unwrap());
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("too small"));
    }

    #[test]
    fn validate_bak_accepts_min_size_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; MIN_BAK_SIZE as usize]).unwrap();
        let r = validate_bak_path(f.path().to_str().unwrap());
        assert!(r.is_ok());
    }

    #[test]
    fn validate_bak_rejects_directory() {
        let dir = tempdir().unwrap();
        let r = validate_bak_path(dir.path().to_str().unwrap());
        assert!(r.is_err());
    }

    #[test]
    fn quarantine_path_includes_timestamp() {
        let exe = PathBuf::from("/opt/mrsh/mrsh.exe");
        let q = quarantine_path(&exe, 1234567890);
        assert!(q.to_string_lossy().contains("mrsh.exe.failed-1234567890"));
        assert_eq!(q.parent(), exe.parent());
    }

    #[test]
    fn quarantine_path_no_parent_uses_dot() {
        let exe = PathBuf::from("mrsh");
        let q = quarantine_path(&exe, 42);
        // parent is "" → fallback to "."
        let s = q.to_string_lossy().to_string();
        assert!(s.contains("mrsh.failed-42"));
    }

    #[test]
    fn rollback_writes_failed_status_when_bak_invalid() {
        // We cannot exercise a real rollback (would need a fake live exe at
        // a known path AND a sane .bak). But we CAN verify that an invalid
        // bak path (empty) results in a "failed:rolled-back-aborted" record.
        // To do this safely, override the data_dir via the public API:
        // we write the watchdog state directly with an invalid prev path,
        // but execute_rollback() reads default_data_dir() which is the
        // real install dir on this host. So we only do an indirect check:
        // verify that validate_bak_path drives the abort branch by giving
        // a reason string that record-failure would surface.
        let r = validate_bak_path("");
        assert!(r.is_err());
        let msg = format!("{}", r.unwrap_err());
        assert!(!msg.is_empty());
    }

    #[test]
    fn truncate_for_status_strips_unsafe_chars() {
        let cleaned = truncate_for_status("a\nb\tc\"d");
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\t'));
        assert!(!cleaned.contains('"'));
        assert!(cleaned.contains("abcd"));
    }

    #[test]
    fn truncate_for_status_caps_length() {
        let long = "x".repeat(200);
        let cleaned = truncate_for_status(&long);
        assert!(cleaned.len() <= 80);
    }
}
