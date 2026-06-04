//! Persisted self-update status for rsh-5264.1 heartbeat-feedback +
//! rsh-5264.4 watchdog auto-revert on N consecutive heartbeat failures.
//!
//! Stored as `<data_dir>/last_update.json` with shape:
//!   {
//!     "status": "success" | "failed:<reason>" | "never",
//!     "ts": <unix_secs>,
//!     "watchdog_active": <bool>,
//!     "watchdog_started_at": <unix_secs>,
//!     "consecutive_heartbeat_failures": <u32>,
//!     "previous_binary_path": "<string>"
//!   }
//!
//! A sibling `<data_dir>/last_update.pending` marker is written by the OLD
//! binary BEFORE invoking the self-update bat. The NEW binary, on first
//! startup, sees the marker, writes the success record, and removes the
//! marker. If the swap failed (bat error) the OLD binary writes
//! `last_update.json` with status="failed:<reason>" directly and removes
//! the pending marker — there is no new binary to do it.
//!
//! The watchdog is armed by `selfupdate` after a successful binary swap.
//! Subsequent heartbeats call `record_heartbeat_outcome` which:
//!   - on first SUCCESS while armed → clears watchdog (binary considered healthy)
//!   - on FAILURE → increments counter; on N=3 consecutive → returns RollbackTriggered
//!   - on SUCCESS after partial failures → resets counter (transient blip absorbed)

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of consecutive heartbeat failures that triggers an auto-rollback.
pub const ROLLBACK_FAILURE_THRESHOLD: u32 = 3;

/// Resolve the canonical server data directory used by mrsh.
///
/// Mirrors `crate::paths::server_data_dir()` from the binary crate but lives
/// in the library so `selfupdate::handle_self_update` (called by dispatch)
/// can find it without taking it as a parameter through every layer.
///
/// Windows: `C:\ProgramData\mrsh` then `%USERPROFILE%\.mrsh`.
/// Linux: `/etc/mrsh` for root (legacy `/etc/rsh` if not yet migrated),
/// `$HOME/.mrsh` otherwise.
pub fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let new_dir = PathBuf::from(r"C:\ProgramData\mrsh");
        if new_dir.exists() {
            return new_dir;
        }
        if let Some(home) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(home).join(".mrsh");
        }
        new_dir
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Explicit override (Android root + RO /etc, embedded targets, tests).
        if let Some(d) = std::env::var_os("MRSH_DATA_DIR") {
            return PathBuf::from(d);
        }
        // SAFETY: geteuid is safe, no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            // Canonical /etc/mrsh; legacy /etc/rsh until paths::server_data_dir()
            // performs the one-time migration at server startup (rsh-ag8t).
            let new_dir = PathBuf::from("/etc/mrsh");
            if new_dir.exists() {
                return new_dir;
            }
            let legacy_dir = PathBuf::from("/etc/rsh");
            if legacy_dir.exists() {
                return legacy_dir;
            }
            return new_dir;
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".mrsh");
        }
        PathBuf::from("/etc/mrsh")
    }
}

/// Persisted record. Default = "never" with ts=0 and watchdog disarmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    pub status: String,
    pub ts: i64,
    pub watchdog_active: bool,
    pub watchdog_started_at: i64,
    pub consecutive_heartbeat_failures: u32,
    pub previous_binary_path: String,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            status: "never".to_string(),
            ts: 0,
            watchdog_active: false,
            watchdog_started_at: 0,
            consecutive_heartbeat_failures: 0,
            previous_binary_path: String::new(),
        }
    }
}

impl UpdateStatus {
    pub fn never() -> Self {
        Self::default()
    }

    pub fn success_now() -> Self {
        Self {
            status: "success".to_string(),
            ts: now_unix_secs(),
            watchdog_active: false,
            watchdog_started_at: 0,
            consecutive_heartbeat_failures: 0,
            previous_binary_path: String::new(),
        }
    }

    pub fn failed_now(reason: &str) -> Self {
        Self {
            status: format!("failed:{}", sanitize_reason(reason)),
            ts: now_unix_secs(),
            watchdog_active: false,
            watchdog_started_at: 0,
            consecutive_heartbeat_failures: 0,
            previous_binary_path: String::new(),
        }
    }
}

/// Sanitize a status/reason: single-line, max ~80 chars, no quotes.
fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !matches!(*c, '"' | '\\' | '\n' | '\r' | '\t'))
        .take(80)
        .collect()
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Path of the persisted status file inside `data_dir`.
pub fn status_path(data_dir: &Path) -> PathBuf {
    data_dir.join("last_update.json")
}

/// Path of the pending marker inside `data_dir`.
pub fn pending_path(data_dir: &Path) -> PathBuf {
    data_dir.join("last_update.pending")
}

/// Render a status record as the canonical JSON text.
pub fn encode(status: &UpdateStatus) -> String {
    // Hand-rolled JSON to avoid a serde_json dep just for a few fields.
    // Status is sanitized in failed_now() and prev_path is sanitized below.
    let prev = sanitize_reason(&status.previous_binary_path);
    format!(
        "{{\"status\": \"{}\", \"ts\": {}, \"watchdog_active\": {}, \"watchdog_started_at\": {}, \"consecutive_heartbeat_failures\": {}, \"previous_binary_path\": \"{}\"}}",
        status.status,
        status.ts,
        status.watchdog_active,
        status.watchdog_started_at,
        status.consecutive_heartbeat_failures,
        prev,
    )
}

/// Parse the canonical JSON text back. Returns None on any error.
///
/// Accepts the format produced by `encode` and is lenient about whitespace,
/// key order, and missing watchdog fields (default to disarmed) so a v1
/// `last_update.json` written by rsh-5264.1 still loads cleanly.
pub fn parse(text: &str) -> Option<UpdateStatus> {
    let s = text.trim();
    if !s.starts_with('{') || !s.ends_with('}') {
        return None;
    }
    let inner = &s[1..s.len() - 1];

    let mut status: Option<String> = None;
    let mut ts: Option<i64> = None;
    let mut watchdog_active = false;
    let mut watchdog_started_at: i64 = 0;
    let mut consecutive_heartbeat_failures: u32 = 0;
    let mut previous_binary_path = String::new();

    for part in split_top_level_commas(inner) {
        let p = part.trim();
        let colon = p.find(':')?;
        let key = p[..colon].trim().trim_matches('"');
        let val = p[colon + 1..].trim();
        match key {
            "status" => {
                status = Some(val.trim_matches('"').to_string());
            }
            "ts" => {
                ts = val.parse::<i64>().ok();
            }
            "watchdog_active" => {
                watchdog_active = val == "true";
            }
            "watchdog_started_at" => {
                watchdog_started_at = val.parse::<i64>().unwrap_or(0);
            }
            "consecutive_heartbeat_failures" => {
                consecutive_heartbeat_failures = val.parse::<u32>().unwrap_or(0);
            }
            "previous_binary_path" => {
                previous_binary_path = val.trim_matches('"').to_string();
            }
            _ => {}
        }
    }

    Some(UpdateStatus {
        status: status?,
        ts: ts.unwrap_or(0),
        watchdog_active,
        watchdog_started_at,
        consecutive_heartbeat_failures,
        previous_binary_path,
    })
}

/// Split a JSON object body on top-level commas. Quoted values keep their commas.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            in_quotes = !in_quotes;
        } else if b == b',' && !in_quotes {
            out.push(&s[start..i]);
            start = i + 1;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Read the current persisted status. Returns `UpdateStatus::never()` when
/// the file is missing, unreadable, or unparseable (best-effort, never errors).
pub fn read(data_dir: &Path) -> UpdateStatus {
    let path = status_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).unwrap_or_default(),
        Err(_) => UpdateStatus::default(),
    }
}

/// Write the status atomically. Returns Err on I/O failure but never panics.
/// Uses tempfile + rename so a partial write never leaves a corrupted file.
pub fn write(data_dir: &Path, status: &UpdateStatus) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    let path = status_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, encode(status))?;
    // rename is atomic on the same filesystem.
    if let Err(e) = std::fs::rename(&tmp, &path) {
        // Windows can hold the destination locked; fall back to direct write.
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&path, encode(status))?;
        tracing::debug!("update_status: rename fallback used: {}", e);
    }
    Ok(())
}

/// Mark a self-update as pending. The marker file is plain text with the
/// new binary path, written by the OLD binary before invoking the bat.
pub fn write_pending(data_dir: &Path, new_binary_path: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    std::fs::write(pending_path(data_dir), new_binary_path)
}

/// Remove the pending marker (best-effort, ignore "not found").
pub fn clear_pending(data_dir: &Path) {
    let _ = std::fs::remove_file(pending_path(data_dir));
}

/// True when a pending marker exists (a self-update was in flight).
pub fn has_pending(data_dir: &Path) -> bool {
    pending_path(data_dir).exists()
}

/// On-startup reconciliation:
/// - If a pending marker exists, the OLD binary scheduled a self-update.
///   The fact that THIS code is running means either (a) the new binary
///   started successfully (most likely), or (b) it never restarted but
///   the OLD binary somehow re-entered. In both cases we record success
///   and clear the marker — partial-failure paths must call `record_failure`
///   directly before the marker is consumed here.
///
///   NOTE: reconcile records "success" but DOES NOT arm the watchdog —
///   arming is the responsibility of `selfupdate` BEFORE the swap, so the
///   .bak path is captured. This way reconcile can be called repeatedly
///   on every restart without re-arming a stale watchdog.
/// - Otherwise no-op: keep the existing record (so "never" stays "never"
///   on first boot, or "success"/"failed:..."/armed-watchdog persists).
pub fn reconcile_on_startup(data_dir: &Path) -> UpdateStatus {
    if has_pending(data_dir) {
        // Preserve any watchdog state that was armed pre-swap by selfupdate.
        let prior = read(data_dir);
        let s = UpdateStatus {
            status: "success".to_string(),
            ts: now_unix_secs(),
            watchdog_active: prior.watchdog_active,
            watchdog_started_at: prior.watchdog_started_at,
            consecutive_heartbeat_failures: 0,
            previous_binary_path: prior.previous_binary_path,
        };
        let _ = write(data_dir, &s);
        clear_pending(data_dir);
        tracing::info!(
            "update_status: pending marker found at startup → recorded success at ts={} (watchdog_active={})",
            s.ts,
            s.watchdog_active,
        );
        s
    } else {
        read(data_dir)
    }
}

/// Record a self-update failure synchronously (no marker reconciliation).
/// Used when the OLD binary detects the bat could not be invoked at all.
pub fn record_failure(data_dir: &Path, reason: &str) -> std::io::Result<()> {
    clear_pending(data_dir);
    write(data_dir, &UpdateStatus::failed_now(reason))
}

/// Arm the watchdog after a successful binary swap. Captures the path of
/// the previous binary (.bak) so a rollback can restore it on N consecutive
/// heartbeat failures.
///
/// Called by `selfupdate` AFTER scheduling the swap (Windows: bat, Linux:
/// rename + copy). Writes the watchdog state into `last_update.json` so it
/// survives the binary restart and is observed by the new binary's first
/// heartbeat.
pub fn arm_watchdog(data_dir: &Path, prev_bak_path: &str) -> std::io::Result<()> {
    let mut s = read(data_dir);
    s.watchdog_active = true;
    s.watchdog_started_at = now_unix_secs();
    s.consecutive_heartbeat_failures = 0;
    s.previous_binary_path = prev_bak_path.to_string();
    tracing::info!(
        "update_status: watchdog armed (prev_bak_path={}, threshold={})",
        prev_bak_path,
        ROLLBACK_FAILURE_THRESHOLD,
    );
    write(data_dir, &s)
}

/// Action returned by `record_heartbeat_outcome` to signal what the caller
/// should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    /// No action — watchdog inactive, OR active and counter still under threshold.
    Continue,
    /// Watchdog was active and the new binary just had its first successful
    /// heartbeat — clear watchdog state (rollback no longer possible/needed).
    ClearWatchdog,
    /// Watchdog was active and counter just hit `ROLLBACK_FAILURE_THRESHOLD`.
    /// Caller MUST invoke `watchdog::execute_rollback()` to restore the .bak.
    RollbackTriggered,
}

/// Update the watchdog state after a heartbeat attempt and return the action
/// the caller should take.
///
/// State machine (when `watchdog_active=true`):
///   - heartbeat success → clear watchdog (return ClearWatchdog)
///   - heartbeat failure → increment counter
///       - counter < N → return Continue
///       - counter == N → return RollbackTriggered (counter is RESET to 0
///         here AND watchdog is disarmed so the rollback executor can
///         re-arm only on a fresh self-update)
///
/// When `watchdog_active=false`, this function is a no-op (always returns
/// Continue) — heartbeat outcome tracking only matters during the post-update
/// observation window.
///
/// Persists the new state to `last_update.json` so it survives a server
/// restart in the middle of the observation window.
pub fn record_heartbeat_outcome(data_dir: &Path, success: bool) -> WatchdogAction {
    let mut s = read(data_dir);
    if !s.watchdog_active {
        return WatchdogAction::Continue;
    }

    if success {
        // First post-update heartbeat success → binary considered healthy.
        s.watchdog_active = false;
        s.consecutive_heartbeat_failures = 0;
        // Keep previous_binary_path on disk for forensics, do NOT clear it.
        let _ = write(data_dir, &s);
        tracing::info!("update_status: watchdog cleared after successful heartbeat");
        return WatchdogAction::ClearWatchdog;
    }

    // Failure path
    s.consecutive_heartbeat_failures = s.consecutive_heartbeat_failures.saturating_add(1);
    if s.consecutive_heartbeat_failures >= ROLLBACK_FAILURE_THRESHOLD {
        // Disarm watchdog AT THE SAME TIME as triggering rollback to avoid
        // a re-trigger loop if the rollback itself takes time to complete.
        // The rollback executor will write the final "failed:rolled-back"
        // status when it's done.
        s.watchdog_active = false;
        let prev_count = s.consecutive_heartbeat_failures;
        s.consecutive_heartbeat_failures = 0;
        let _ = write(data_dir, &s);
        tracing::warn!(
            "update_status: watchdog tripped after {} consecutive heartbeat failures — rollback triggered",
            prev_count,
        );
        return WatchdogAction::RollbackTriggered;
    }

    let _ = write(data_dir, &s);
    tracing::warn!(
        "update_status: watchdog observed heartbeat failure {}/{}",
        s.consecutive_heartbeat_failures,
        ROLLBACK_FAILURE_THRESHOLD,
    );
    WatchdogAction::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn never_is_default() {
        let s = UpdateStatus::default();
        assert_eq!(s.status, "never");
        assert_eq!(s.ts, 0);
        assert!(!s.watchdog_active);
        assert_eq!(s.watchdog_started_at, 0);
        assert_eq!(s.consecutive_heartbeat_failures, 0);
        assert_eq!(s.previous_binary_path, "");
    }

    #[test]
    fn encode_decode_roundtrip_success() {
        let s = UpdateStatus {
            status: "success".to_string(),
            ts: 1730500000,
            ..Default::default()
        };
        let text = encode(&s);
        assert!(text.contains("\"status\": \"success\""));
        assert!(text.contains("\"ts\": 1730500000"));
        let back = parse(&text).expect("parse");
        assert_eq!(back, s);
    }

    #[test]
    fn encode_decode_roundtrip_failed() {
        let s = UpdateStatus {
            status: "failed:bat exit code 1".to_string(),
            ts: 9999,
            ..Default::default()
        };
        let text = encode(&s);
        let back = parse(&text).expect("parse");
        assert_eq!(back, s);
    }

    #[test]
    fn encode_decode_roundtrip_with_watchdog() {
        let s = UpdateStatus {
            status: "success".to_string(),
            ts: 1730500000,
            watchdog_active: true,
            watchdog_started_at: 1730500001,
            consecutive_heartbeat_failures: 2,
            previous_binary_path: "/path/to/mrsh.exe.bak".to_string(),
        };
        let text = encode(&s);
        let back = parse(&text).expect("parse");
        assert_eq!(back, s);
    }

    #[test]
    fn parse_lenient_whitespace() {
        let text = "{ \"status\":\"never\" , \"ts\" : 0 }";
        let s = parse(text).expect("parse");
        assert_eq!(s.status, "never");
        assert_eq!(s.ts, 0);
        assert!(!s.watchdog_active);
    }

    #[test]
    fn parse_v1_without_watchdog_fields() {
        // Backward compat: rsh-5264.1 wrote only status+ts.
        let text = "{\"status\": \"success\", \"ts\": 1730500000}";
        let s = parse(text).expect("parse");
        assert_eq!(s.status, "success");
        assert_eq!(s.ts, 1730500000);
        assert!(!s.watchdog_active);
        assert_eq!(s.consecutive_heartbeat_failures, 0);
        assert_eq!(s.previous_binary_path, "");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse("not json").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn read_missing_returns_never() {
        let dir = tempdir().unwrap();
        let s = read(dir.path());
        assert_eq!(s.status, "never");
        assert_eq!(s.ts, 0);
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = tempdir().unwrap();
        let s = UpdateStatus {
            status: "success".to_string(),
            ts: 42,
            ..Default::default()
        };
        write(dir.path(), &s).unwrap();
        let back = read(dir.path());
        assert_eq!(back, s);
    }

    #[test]
    fn pending_marker_lifecycle() {
        let dir = tempdir().unwrap();
        assert!(!has_pending(dir.path()));
        write_pending(dir.path(), "/tmp/mrsh-new").unwrap();
        assert!(has_pending(dir.path()));
        let path = pending_path(dir.path());
        let txt = std::fs::read_to_string(&path).unwrap();
        assert_eq!(txt, "/tmp/mrsh-new");
        clear_pending(dir.path());
        assert!(!has_pending(dir.path()));
    }

    #[test]
    fn reconcile_promotes_pending_to_success() {
        let dir = tempdir().unwrap();
        write_pending(dir.path(), "/tmp/mrsh-new").unwrap();
        let s = reconcile_on_startup(dir.path());
        assert_eq!(s.status, "success");
        assert!(s.ts > 0);
        assert!(!has_pending(dir.path()));
        let back = read(dir.path());
        assert_eq!(back.status, "success");
    }

    #[test]
    fn reconcile_preserves_armed_watchdog() {
        // selfupdate arms the watchdog BEFORE writing the pending marker,
        // so reconcile must preserve watchdog_active when promoting.
        let dir = tempdir().unwrap();
        arm_watchdog(dir.path(), "/path/to/old.bak").unwrap();
        write_pending(dir.path(), "/tmp/mrsh-new").unwrap();
        let s = reconcile_on_startup(dir.path());
        assert_eq!(s.status, "success");
        assert!(s.watchdog_active);
        assert_eq!(s.previous_binary_path, "/path/to/old.bak");
        assert_eq!(s.consecutive_heartbeat_failures, 0);
    }

    #[test]
    fn reconcile_no_pending_keeps_existing() {
        let dir = tempdir().unwrap();
        let prior = UpdateStatus {
            status: "failed:test".to_string(),
            ts: 7,
            ..Default::default()
        };
        write(dir.path(), &prior).unwrap();
        let s = reconcile_on_startup(dir.path());
        assert_eq!(s, prior);
    }

    #[test]
    fn record_failure_clears_pending() {
        let dir = tempdir().unwrap();
        write_pending(dir.path(), "/tmp/mrsh-new").unwrap();
        record_failure(dir.path(), "schtask denied").unwrap();
        assert!(!has_pending(dir.path()));
        let s = read(dir.path());
        assert!(s.status.starts_with("failed:"));
        assert!(s.status.contains("schtask denied"));
        assert!(s.ts > 0);
    }

    #[test]
    fn failed_reason_sanitized() {
        let s = UpdateStatus::failed_now("line1\nline2\twith \"quotes\"");
        let text = encode(&s);
        let back = parse(&text).expect("parse");
        assert_eq!(back.status, s.status);
        assert!(!back.status.contains('\n'));
        assert!(!back.status.contains('"'));
    }

    #[test]
    fn failed_reason_truncated() {
        let long = "x".repeat(200);
        let s = UpdateStatus::failed_now(&long);
        assert!(s.status.len() <= "failed:".len() + 80);
    }

    #[test]
    fn split_top_level_commas_respects_quoted() {
        let v = split_top_level_commas("\"a,b\":\"c,d\", \"e\":1");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].trim(), "\"a,b\":\"c,d\"");
        assert_eq!(v[1].trim(), "\"e\":1");
    }

    // ── Watchdog tests (rsh-5264.4) ─────────────────────────────────────

    #[test]
    fn watchdog_arm_starts_in_active_state() {
        let dir = tempdir().unwrap();
        arm_watchdog(dir.path(), "/tmp/mrsh.exe.bak").unwrap();
        let s = read(dir.path());
        assert!(s.watchdog_active);
        assert!(s.watchdog_started_at > 0);
        assert_eq!(s.consecutive_heartbeat_failures, 0);
        assert_eq!(s.previous_binary_path, "/tmp/mrsh.exe.bak");
    }

    #[test]
    fn three_failures_triggers_rollback() {
        let dir = tempdir().unwrap();
        arm_watchdog(dir.path(), "/tmp/mrsh.exe.bak").unwrap();
        assert_eq!(
            record_heartbeat_outcome(dir.path(), false),
            WatchdogAction::Continue,
            "1st failure → continue"
        );
        assert_eq!(
            record_heartbeat_outcome(dir.path(), false),
            WatchdogAction::Continue,
            "2nd failure → continue"
        );
        assert_eq!(
            record_heartbeat_outcome(dir.path(), false),
            WatchdogAction::RollbackTriggered,
            "3rd failure → rollback"
        );
        // After rollback trigger, watchdog must be disarmed so we don't re-fire
        let s = read(dir.path());
        assert!(!s.watchdog_active);
        assert_eq!(s.consecutive_heartbeat_failures, 0);
        // previous_binary_path preserved for forensics
        assert_eq!(s.previous_binary_path, "/tmp/mrsh.exe.bak");
    }

    #[test]
    fn success_after_failures_resets_counter() {
        let dir = tempdir().unwrap();
        arm_watchdog(dir.path(), "/tmp/mrsh.exe.bak").unwrap();
        record_heartbeat_outcome(dir.path(), false);
        record_heartbeat_outcome(dir.path(), false);
        // 2nd transient failure absorbed; success resets and clears watchdog
        let action = record_heartbeat_outcome(dir.path(), true);
        assert_eq!(action, WatchdogAction::ClearWatchdog);
        let s = read(dir.path());
        assert!(!s.watchdog_active);
        assert_eq!(s.consecutive_heartbeat_failures, 0);
    }

    #[test]
    fn success_after_arm_clears_watchdog() {
        let dir = tempdir().unwrap();
        arm_watchdog(dir.path(), "/tmp/mrsh.exe.bak").unwrap();
        let action = record_heartbeat_outcome(dir.path(), true);
        assert_eq!(action, WatchdogAction::ClearWatchdog);
        let s = read(dir.path());
        assert!(!s.watchdog_active);
    }

    #[test]
    fn record_outcome_noop_when_watchdog_inactive() {
        let dir = tempdir().unwrap();
        // No arm_watchdog call → watchdog_active=false from default
        let action_fail = record_heartbeat_outcome(dir.path(), false);
        assert_eq!(action_fail, WatchdogAction::Continue);
        let action_ok = record_heartbeat_outcome(dir.path(), true);
        assert_eq!(action_ok, WatchdogAction::Continue);
        // Counter must NOT increment when watchdog is inactive
        let s = read(dir.path());
        assert_eq!(s.consecutive_heartbeat_failures, 0);
    }

    #[test]
    fn watchdog_state_persists_across_read_write() {
        let dir = tempdir().unwrap();
        arm_watchdog(dir.path(), "/path/with spaces/mrsh.bak").unwrap();
        record_heartbeat_outcome(dir.path(), false);
        // Simulate restart: read should still see watchdog_active + 1 failure
        let s = read(dir.path());
        assert!(s.watchdog_active);
        assert_eq!(s.consecutive_heartbeat_failures, 1);
    }

    #[test]
    fn rollback_threshold_constant_is_three() {
        // Rule per acceptance criteria: N=3 consecutive failures
        assert_eq!(ROLLBACK_FAILURE_THRESHOLD, 3);
    }
}
