//! Output formatting for fleet status, update plans, and update results.
//!
//! Pure presentation — no I/O, no mutation. The tables produced here are
//! consumed by `mrsh fleet status`, `mrsh fleet update`, and the dashboard
//! TUI's status view.

use super::status::{HostStatus, ProbeErrorKind};
use super::update::{HostUpdatePlan, UpdateResult};

/// Compute the human-readable STATUS cell for a row.
///
/// - Online + configured-port: "online"
/// - Online via alt-port: "online*" (signal: configured port didn't respond)
/// - Online via hbbs freshness: "hbbs"
/// - Online via relay/quic: "online" (transport column carries the detail)
/// - Offline with TOFU rotation: "key-rotated"
/// - Offline with timeout: "timeout"
/// - Offline with refused: "refused"
/// - Offline (other): "offline"
pub(super) fn status_label(s: &HostStatus) -> &'static str {
    if s.online {
        return match s.transport {
            "alt-port" => "online*",
            "hbbs" => "hbbs",
            _ => "online",
        };
    }
    match s.error_kind {
        Some(ProbeErrorKind::HostKeyChanged) => "key-rotated",
        Some(ProbeErrorKind::Timeout) => "timeout",
        Some(ProbeErrorKind::Refused) => "refused",
        _ => "offline",
    }
}

/// Format fleet status as a table string.
pub fn format_status_table(statuses: &[HostStatus]) -> String {
    format_status_table_inner(statuses, false)
}

/// Render the relative age of a `last_update_at_unix` (seconds, 0 = never).
/// Examples: "2m ago", "3h ago", "5d ago", "never".
pub(super) fn format_update_age(now_secs: i64, ts: i64) -> String {
    if ts <= 0 {
        return "never".to_string();
    }
    let delta = now_secs.saturating_sub(ts);
    if delta < 0 {
        return "future".to_string(); // clock skew, surface but don't crash
    }
    let d = delta as u64;
    if d < 60 {
        format!("{}s ago", d)
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86400)
    }
}

/// Pick the best version cell for a HostStatus row.
/// rsh-5264.1: prefer TCP-probed `version`, then rdv-reported `rdv_version`.
pub(super) fn pick_version_label(s: &HostStatus) -> &str {
    if let Some(v) = s.version.as_deref() {
        return v;
    }
    if let Some(v) = s.rdv_version.as_deref() {
        return v;
    }
    "-"
}

/// rsh-5264.5: render the auto_upgrade cell.
/// `Some(true)` → "✓", `Some(false)` → "✗", `None` (pre-5264.5 server) → "-".
pub(super) fn format_auto_upgrade(au: Option<bool>) -> &'static str {
    match au {
        Some(true) => "yes",
        Some(false) => "no",
        None => "-",
    }
}

/// rsh-5264.5: render the track cell.
/// Empty/None → "-".
pub(super) fn format_track(track: Option<&str>) -> &str {
    match track {
        Some(t) if !t.is_empty() => t,
        _ => "-",
    }
}

/// Format fleet status table. If `show_caps` is true, include a CAPS column.
///
/// rsh-5264.1: when any host has a non-zero `last_update_at_unix` reported
/// via rdv, two extra columns are appended: LAST_UPDATE (relative age) and
/// UPD_STATUS (success / failed:... / never). When NO host reports any
/// rdv-side update info the columns are suppressed to keep the table compact.
///
/// rsh-5264.5: when any host reports a track or auto_upgrade flag (i.e. is
/// running a 5264.5+ server), TRACK and AUTO_UPG columns are appended right
/// after VERSION/LATENCY/UPD columns. Older fleets see the table unchanged.
pub fn format_status_table_inner(statuses: &[HostStatus], show_caps: bool) -> String {
    if statuses.is_empty() {
        return "No hosts configured.".to_string();
    }

    // rsh-5264.1: only show last-update columns when at least one row has
    // anything to report. This prevents new columns from polluting fleets
    // running pre-rsh-5264.1 servers (every cell would be "-").
    let show_last_update = statuses.iter().any(|s| {
        s.last_update_at_unix.is_some_and(|t| t > 0) || s.last_update_status.is_some()
    });

    // rsh-5264.5: only show staged-rollout columns when at least one host has
    // either a track or an auto_upgrade flag set (i.e. is on a 5264.5+ build).
    let show_staged_rollout = statuses
        .iter()
        .any(|s| s.track.is_some() || s.auto_upgrade.is_some());

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut lines = Vec::new();
    let mut header = format!(
        "{:<20} {:<6} {:<12} {:<12} {:<8}",
        "HOST", "PORT", "STATUS", "VERSION", "LATENCY"
    );
    if show_last_update {
        header.push_str(&format!(" {:<12} {:<14}", "LAST_UPDATE", "UPD_STATUS"));
    }
    if show_staged_rollout {
        header.push_str(&format!(" {:<8} {:<9}", "TRACK", "AUTO_UPG"));
    }
    // rsh-x9l5: show MODE column (direct/rdv) when any host has conn_mode set.
    let show_conn_mode = statuses.iter().any(|s| !s.conn_mode.is_empty());
    if show_conn_mode {
        header.push_str(&format!(" {:<8}", "MODE"));
    }
    if show_caps {
        header.push_str(" CAPS");
    }
    lines.push(header);

    let dash_len = if show_caps { 100 } else { 60 }
        + if show_last_update { 28 } else { 0 }
        + if show_staged_rollout { 19 } else { 0 }
        + if show_conn_mode { 9 } else { 0 };
    lines.push("-".repeat(dash_len));

    for s in statuses {
        let status = status_label(s);
        let version = pick_version_label(s);
        let latency = if s.online {
            format!("{}ms", s.latency_ms)
        } else {
            "-".to_string()
        };
        let mut row = format!(
            "{:<20} {:<6} {:<12} {:<12} {:<8}",
            s.name, s.port, status, version, latency
        );
        if show_last_update {
            let age = match s.last_update_at_unix {
                Some(ts) => format_update_age(now_secs, ts),
                None => "-".to_string(),
            };
            let upd_status = s.last_update_status.as_deref().unwrap_or("-");
            // Truncate UPD_STATUS for table fit; full status visible via JSON
            // export or `--verbose` future hook.
            let upd_short: String = upd_status.chars().take(14).collect();
            row.push_str(&format!(" {:<12} {:<14}", age, upd_short));
        }
        if show_staged_rollout {
            let track = format_track(s.track.as_deref()).to_string();
            let auto_upg = format_auto_upgrade(s.auto_upgrade);
            row.push_str(&format!(" {:<8} {:<9}", track, auto_upg));
        }
        if show_conn_mode {
            let mode = if s.conn_mode.is_empty() { "-" } else { &s.conn_mode };
            row.push_str(&format!(" {:<8}", mode));
        }
        if show_caps {
            let caps = if s.caps.is_empty() {
                "-".to_string()
            } else {
                s.caps.join(",")
            };
            row.push_str(&format!(" {}", caps));
        }
        lines.push(row);
    }

    lines.join("\n")
}

/// Render `plan_fleet_update` output as a table. Used by `--dry-run` and as
/// a preamble to the real update.
pub fn format_update_plan(plans: &[HostUpdatePlan]) -> String {
    if plans.is_empty() {
        return "No hosts in plan.".to_string();
    }
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<20} {:<10} {:<12} {:<12} {:<10} {}",
        "HOST", "OS", "CURRENT", "TARGET", "BYTES", "ACTION"
    ));
    lines.push("-".repeat(90));
    for p in plans {
        let current = p.current_version.as_deref().unwrap_or("-");
        let action = match &p.skip_reason {
            Some(reason) => format!("SKIP: {}", reason),
            None => "push + self-update".to_string(),
        };
        let bytes = if p.binary_bytes > 0 {
            format!("{}", p.binary_bytes)
        } else {
            "-".to_string()
        };
        lines.push(format!(
            "{:<20} {:<10} {:<12} {:<12} {:<10} {}",
            p.name,
            p.os.label(),
            current,
            p.target_version,
            bytes,
            action
        ));
    }
    lines.join("\n")
}

/// Format update results as a summary table.
pub fn format_update_results(results: &[UpdateResult]) -> String {
    if results.is_empty() {
        return String::new();
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "\n{:<20} {:<10} {:<12} {:<12} {}",
        "HOST", "RESULT", "OLD", "NEW", "ERROR"
    ));
    lines.push("-".repeat(70));

    let mut success_count = 0;
    for r in results {
        let result = if r.success {
            success_count += 1;
            "OK"
        } else {
            "FAILED"
        };
        let old = r.old_version.as_deref().unwrap_or("-");
        let new = r.new_version.as_deref().unwrap_or("-");
        let error = r.error.as_deref().unwrap_or("");
        lines.push(format!(
            "{:<20} {:<10} {:<12} {:<12} {}",
            r.name, result, old, new, error
        ));
    }

    lines.push(format!(
        "\n{}/{} hosts updated successfully.",
        success_count,
        results.len()
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::status::HostStatus;

    fn empty_status(name: &str) -> HostStatus {
        HostStatus {
            name: name.to_string(),
            hostname: format!("{}.local", name),
            port: 8822,
            online: true,
            version: Some("1.10.30".to_string()),
            caps: vec![],
            latency_ms: 5,
            error: None,
            error_kind: None,
            device_id: None,
            rendezvous_server: None,
            rendezvous_key: None,
            quic_port: None,
            transport: "tls",
            rdv_version: None,
            last_update_status: None,
            last_update_at_unix: None,
            track: None,
            auto_upgrade: None,
            conn_mode: "direct".to_string(),
        }
    }

    #[test]
    fn format_auto_upgrade_renders_yes_no_dash() {
        assert_eq!(format_auto_upgrade(Some(true)), "yes");
        assert_eq!(format_auto_upgrade(Some(false)), "no");
        assert_eq!(format_auto_upgrade(None), "-");
    }

    #[test]
    fn format_track_renders_value_or_dash() {
        assert_eq!(format_track(Some("canary")), "canary");
        assert_eq!(format_track(Some("")), "-");
        assert_eq!(format_track(None), "-");
    }

    #[test]
    fn rsh_5264_5_columns_appear_when_any_host_reports_track_or_auto_upgrade() {
        let mut canary = empty_status("canary-host");
        canary.track = Some("canary".to_string());
        canary.auto_upgrade = Some(true);

        let mut stable = empty_status("stable-host");
        stable.track = Some("stable".to_string());
        stable.auto_upgrade = Some(false);

        let table = format_status_table(&[canary, stable]);
        assert!(table.contains("TRACK"), "TRACK column missing:\n{}", table);
        assert!(
            table.contains("AUTO_UPG"),
            "AUTO_UPG column missing:\n{}",
            table
        );
        assert!(table.contains("canary"), "canary row missing:\n{}", table);
        assert!(table.contains("stable"), "stable row missing:\n{}", table);
        assert!(table.contains("yes"), "yes flag missing:\n{}", table);
        assert!(table.contains("no"), "no flag missing:\n{}", table);
    }

    #[test]
    fn rsh_5264_5_columns_suppressed_when_no_host_reports_either() {
        let h = empty_status("legacy");
        let table = format_status_table(&[h]);
        assert!(
            !table.contains("TRACK"),
            "TRACK column should be hidden when no host reports it:\n{}",
            table
        );
        assert!(
            !table.contains("AUTO_UPG"),
            "AUTO_UPG column should be hidden when no host reports it:\n{}",
            table
        );
    }

    #[test]
    fn pre_5264_5_servers_render_as_dash_alongside_5264_5_servers() {
        // Mixed fleet: one host on a new server reports track, one on an old
        // server reports nothing → the old one should show "-" not "no" so the
        // operator can tell pre-5264.5 from explicit-opt-out.
        let new = {
            let mut h = empty_status("new");
            h.track = Some("stable".to_string());
            h.auto_upgrade = Some(false);
            h
        };
        let old = empty_status("old");
        let table = format_status_table(&[new, old]);
        // The "old" row should contain a `-` token in the auto_upgrade slot.
        // We can't easily assert exact column position without re-implementing
        // the formatter, but presence of both "no" (new) and "-" (old) on
        // distinct lines is the contract.
        let lines: Vec<&str> = table.lines().collect();
        let new_row = lines.iter().find(|l| l.starts_with("new ")).unwrap();
        let old_row = lines.iter().find(|l| l.starts_with("old ")).unwrap();
        assert!(
            new_row.contains(" no "),
            "new row should show explicit no: {}",
            new_row
        );
        assert!(
            old_row.contains(" - "),
            "old row should show dash for unknown auto_upgrade: {}",
            old_row
        );
    }
}
