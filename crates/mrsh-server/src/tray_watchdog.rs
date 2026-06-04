//! Background watchdog that periodically re-checks tray status and re-launches
//! it if needed. Covers the gap where the user logs in AFTER the service has
//! started — the install-time `ensure_tray_task` call only fires once at
//! service startup, so a deferred logon (RDP, post-reboot) would leave the
//! tray Down indefinitely.
//!
//! Design (rsh-3t7f / rsh-t06i fix#2):
//!   * Spawned once from the service main entry point.
//!   * Runs in a detached OS thread (no tokio dependency — the work is a
//!     single `schtasks` invocation per cycle, no async needed).
//!   * Calls `service::ensure_tray_task` every `MRSH_TRAY_WATCHDOG_SECS`
//!     seconds (default 60). That function is already idempotent + gated
//!     (checks tasklist process count before calling `/run`), so calling
//!     it repeatedly is safe.
//!   * Disable via `MRSH_NO_TRAY_WATCHDOG=1` for testing.

/// Parse the watchdog interval from an env var value.
///
/// Returns 60 by default, clamped to [10, 3600] seconds.
pub fn parse_interval(env_val: Option<&str>) -> u64 {
    env_val
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(10, 3600)
}

#[cfg(target_os = "windows")]
pub fn spawn_tray_watchdog(exe_path: String) {
    use std::thread;
    use std::time::Duration;

    if std::env::var_os("MRSH_NO_TRAY_WATCHDOG").is_some() {
        tracing::info!("tray watchdog: disabled via MRSH_NO_TRAY_WATCHDOG");
        return;
    }

    let interval_secs = parse_interval(std::env::var("MRSH_TRAY_WATCHDOG_SECS").ok().as_deref());

    let spawn_result = thread::Builder::new()
        .name("mrsh-tray-watchdog".to_string())
        .spawn(move || {
            // Initial settle delay: let the service finish startup before we
            // start polling. Also avoids racing the install-time
            // ensure_tray_task call that fires in main.rs::--service init.
            thread::sleep(Duration::from_secs(30));
            tracing::info!("tray watchdog: started (interval {}s)", interval_secs);
            loop {
                crate::service::ensure_tray_task(&exe_path);
                thread::sleep(Duration::from_secs(interval_secs));
            }
        });

    if let Err(e) = spawn_result {
        tracing::warn!("tray watchdog: failed to spawn thread: {}", e);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_tray_watchdog(_exe_path: String) {
    // No-op on non-Windows: the tray concept is Windows-specific and
    // is_session_zero() always returns false elsewhere.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interval_default_when_none() {
        assert_eq!(parse_interval(None), 60);
    }

    #[test]
    fn parse_interval_default_when_unparseable() {
        assert_eq!(parse_interval(Some("xyz")), 60);
        assert_eq!(parse_interval(Some("")), 60);
        assert_eq!(parse_interval(Some("-1")), 60);
    }

    #[test]
    fn parse_interval_accepts_valid_values() {
        assert_eq!(parse_interval(Some("30")), 30);
        assert_eq!(parse_interval(Some("60")), 60);
        assert_eq!(parse_interval(Some("120")), 120);
        assert_eq!(parse_interval(Some("3600")), 3600);
    }

    #[test]
    fn parse_interval_clamps_low_to_10() {
        assert_eq!(parse_interval(Some("0")), 10);
        assert_eq!(parse_interval(Some("1")), 10);
        assert_eq!(parse_interval(Some("9")), 10);
    }

    #[test]
    fn parse_interval_clamps_high_to_3600() {
        assert_eq!(parse_interval(Some("3601")), 3600);
        assert_eq!(parse_interval(Some("99999")), 3600);
    }

    #[test]
    fn parse_interval_edge_at_clamp_bounds() {
        // Exactly at bounds → return as-is
        assert_eq!(parse_interval(Some("10")), 10);
        assert_eq!(parse_interval(Some("3600")), 3600);
    }
}
