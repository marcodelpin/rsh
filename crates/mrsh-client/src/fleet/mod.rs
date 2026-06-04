//! Fleet management — status and update across configured hosts.
//! Reads ~/.mrsh/config for host list, probes concurrently.
//! Update: push binary + self-update to all outdated hosts.

mod discover;
mod format;
mod status;
mod update;

pub use format::{format_status_table, format_status_table_inner, format_update_plan,
    format_update_results};
pub use status::{HostStatus, ProbeErrorKind, StatusOpts, classify_probe_error, hosts_with_cap,
    status, status_with_opts};
pub use update::{FleetBinaries, HostUpdatePlan, OsKind, UpdateOpts, UpdateResult, classify_os,
    hosts_needing_update, plan_fleet_update, rdv_data_sufficient, update_fleet,
    update_fleet_multi};

#[cfg(test)]
mod tests {
    use super::*;
    use super::format::status_label;
    use super::status::HBBS_ONLINE_THRESHOLD_SECS;
    use mrsh_core::config::Config;

    fn mock_status(name: &str, online: bool, version: Option<&str>) -> HostStatus {
        HostStatus {
            name: name.to_string(),
            hostname: format!("{}.local", name),
            port: 8822,
            online,
            version: version.map(|v| v.to_string()),
            caps: vec!["self-update".to_string(), "shell".to_string()],
            latency_ms: 42,
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
    fn hosts_with_cap_filters() {
        let statuses = vec![
            mock_status("host1", true, Some("4.38.0")),
            mock_status("host2", false, None),
            mock_status("host3", true, Some("4.38.0")),
        ];
        let with_update = hosts_with_cap(&statuses, "self-update");
        assert_eq!(with_update.len(), 2); // only online hosts
    }

    #[test]
    fn hosts_needing_update_filters() {
        let statuses = vec![
            mock_status("host1", true, Some("4.38.0")),
            mock_status("host2", true, Some("4.39.0")),
            mock_status("host3", false, None),
        ];
        let need_update = hosts_needing_update(&statuses, "4.39.0");
        assert_eq!(need_update.len(), 1);
        assert_eq!(need_update[0].name, "host1");
    }

    #[test]
    fn format_status_table_empty() {
        let result = format_status_table(&[]);
        assert_eq!(result, "No hosts configured.");
    }

    #[test]
    fn format_status_table_with_hosts() {
        let statuses = vec![
            mock_status("host1", true, Some("4.38.0")),
            mock_status("host2", false, None),
        ];
        let table = format_status_table(&statuses);
        assert!(table.contains("host1"));
        assert!(table.contains("online"));
        assert!(table.contains("offline"));
        assert!(table.contains("4.38.0"));
    }

    #[test]
    fn host_status_debug() {
        let s = mock_status("test", true, Some("1.0.0"));
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
        assert!(debug.contains("1.0.0"));
    }

    #[tokio::test]
    async fn status_empty_config() {
        let config = Config::default();
        let results = status(&config).await;
        assert!(results.is_empty());
    }

    #[test]
    fn format_update_results_empty() {
        let result = format_update_results(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn format_update_results_mixed() {
        let results = vec![
            UpdateResult {
                name: "host1".to_string(),
                success: true,
                old_version: Some("0.1.0".to_string()),
                new_version: Some("0.2.0".to_string()),
                error: None,
            },
            UpdateResult {
                name: "host2".to_string(),
                success: false,
                old_version: Some("0.1.0".to_string()),
                new_version: None,
                error: Some("connect failed".to_string()),
            },
        ];
        let table = format_update_results(&results);
        assert!(table.contains("host1"));
        assert!(table.contains("OK"));
        assert!(table.contains("host2"));
        assert!(table.contains("FAILED"));
        assert!(table.contains("1/2 hosts updated"));
    }

    #[test]
    fn update_result_debug() {
        let r = UpdateResult {
            name: "test".to_string(),
            success: true,
            old_version: Some("1.0".to_string()),
            new_version: Some("2.0".to_string()),
            error: None,
        };
        let debug = format!("{:?}", r);
        assert!(debug.contains("test"));
        assert!(debug.contains("true"));
    }

    #[tokio::test]
    async fn update_fleet_empty_config() {
        let config = Config::default();
        let results = update_fleet(&config, &[0u8; 100], "1.0.0").await;
        assert!(results.is_empty());
    }

    #[test]
    fn host_status_with_relay_fields() {
        let s = HostStatus {
            name: "relay-host".to_string(),
            hostname: "relay-host.local".to_string(),
            port: 8822,
            online: false,
            version: None,
            caps: Vec::new(),
            latency_ms: 0,
            error: Some("timeout".to_string()),
            error_kind: Some(ProbeErrorKind::Timeout),
            device_id: Some("118855822".to_string()),
            rendezvous_server: Some("rdv.example.com:21116".to_string()),
            rendezvous_key: Some("testkey".to_string()),
            quic_port: None,
            transport: "none",
            rdv_version: None,
            last_update_status: None,
            last_update_at_unix: None,
            track: None,
            auto_upgrade: None,
            conn_mode: String::new(),
        };
        assert_eq!(s.device_id.as_deref(), Some("118855822"));
        assert!(s.rendezvous_server.is_some());
        let debug = format!("{:?}", s);
        assert!(debug.contains("118855822"));
    }

    #[test]
    fn mock_status_has_no_relay_fields() {
        let s = mock_status("test", true, Some("1.0.0"));
        assert!(s.device_id.is_none());
        assert!(s.rendezvous_server.is_none());
        assert!(s.rendezvous_key.is_none());
    }

    #[test]
    fn format_status_table_verbose_shows_caps() {
        let mut s = mock_status("myhost", true, Some("1.2.0"));
        s.caps = vec!["exec".to_string(), "shell".to_string(), "push".to_string()];
        let table = format_status_table_inner(&[s], true);
        assert!(
            table.contains("CAPS"),
            "verbose table must have CAPS header"
        );
        assert!(
            table.contains("exec,shell,push"),
            "caps should be comma-separated"
        );
    }

    #[test]
    fn format_status_table_verbose_empty_caps_shows_dash() {
        let mut s = mock_status("no-caps-host", true, Some("1.0.0"));
        s.caps = Vec::new();
        let table = format_status_table_inner(&[s], true);
        assert!(table.contains("CAPS"));
        let lines: Vec<&str> = table.lines().collect();
        let host_line = lines.iter().find(|l| l.contains("no-caps-host")).unwrap();
        assert!(
            host_line.trim().ends_with('-'),
            "empty caps should show '-', got: {}",
            host_line
        );
    }

    #[test]
    fn format_status_table_non_verbose_hides_caps() {
        let mut s = mock_status("myhost", true, Some("1.2.0"));
        s.caps = vec!["exec".to_string()];
        let table = format_status_table_inner(&[s], false);
        assert!(
            !table.contains("CAPS"),
            "non-verbose table must not have CAPS column"
        );
    }

    #[test]
    fn hbbs_online_threshold_fresh_peer_is_online() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Peer registered 10 seconds ago — well within 90s threshold
        let last_seen = now - 10;
        let online = now.saturating_sub(last_seen) < HBBS_ONLINE_THRESHOLD_SECS;
        assert!(online, "peer seen 10s ago should be online");
    }

    #[test]
    fn hbbs_online_threshold_stale_peer_is_offline() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Peer registered 100 seconds ago — beyond 90s threshold
        let last_seen = now - 100;
        let online = now.saturating_sub(last_seen) < HBBS_ONLINE_THRESHOLD_SECS;
        assert!(!online, "peer seen 100s ago should be offline");
    }

    #[test]
    fn classify_tofu_host_key_rotation() {
        // Real-world message shape from mrsh_core::tls::TofuVerifier.
        let msg = "host key changed for client-lab (expected <fp1>, got <fp2>)";
        assert_eq!(
            classify_probe_error(msg),
            ProbeErrorKind::HostKeyChanged,
            "TOFU rotation must be surfaced distinctly from generic offline"
        );
    }

    #[test]
    fn classify_timeout_variants() {
        assert_eq!(classify_probe_error("timeout"), ProbeErrorKind::Timeout);
        assert_eq!(
            classify_probe_error("operation timed out after 5s"),
            ProbeErrorKind::Timeout
        );
        assert_eq!(
            classify_probe_error("deadline exceeded"),
            ProbeErrorKind::Timeout
        );
    }

    #[test]
    fn classify_refused() {
        assert_eq!(
            classify_probe_error("Connection refused (os error 111)"),
            ProbeErrorKind::Refused
        );
        assert_eq!(
            classify_probe_error("ConnectionRefused"),
            ProbeErrorKind::Refused
        );
    }

    #[test]
    fn classify_auth_failure() {
        assert_eq!(
            classify_probe_error("authentication failed: bad key"),
            ProbeErrorKind::AuthFailed
        );
    }

    #[test]
    fn classify_unknown_is_other() {
        assert_eq!(
            classify_probe_error("some weird error"),
            ProbeErrorKind::Other
        );
    }

    #[test]
    fn status_label_key_rotated_not_offline() {
        // Regression for sys-poal: TOFU rotation must NOT be reported as
        // plain "offline" — that silently hides security-relevant state.
        let mut s = mock_status("client-lab", false, None);
        s.error = Some("host key changed for client-lab (...)".to_string());
        s.error_kind = Some(ProbeErrorKind::HostKeyChanged);
        assert_eq!(status_label(&s), "key-rotated");
    }

    #[test]
    fn status_label_alt_port_marks_star() {
        // Regression for sys-poal: when configured port is stale but host is
        // reachable on an auto-try port, STATUS must show "online*" so the
        // operator notices the stale config.
        let mut s = mock_status("client-lab", true, Some("1.9.3"));
        s.transport = "alt-port";
        assert_eq!(status_label(&s), "online*");
    }

    #[test]
    fn status_label_plain_online() {
        let s = mock_status("host1", true, Some("1.9.3"));
        assert_eq!(status_label(&s), "online");
    }

    #[test]
    fn status_label_timeout_vs_refused() {
        let mut s = mock_status("host1", false, None);
        s.error_kind = Some(ProbeErrorKind::Timeout);
        assert_eq!(status_label(&s), "timeout");
        s.error_kind = Some(ProbeErrorKind::Refused);
        assert_eq!(status_label(&s), "refused");
    }

    #[test]
    fn status_opts_default_preserves_old_behavior() {
        // Default opts MUST have refresh_alt_ports=false so scripts that
        // relied on "configured port is authoritative" don't break.
        let opts = StatusOpts::default();
        assert!(
            !opts.refresh_alt_ports,
            "default must not enable alt-port retry (backward-compat)"
        );
    }

    #[test]
    fn format_status_table_surfaces_key_rotation() {
        let mut s = mock_status("client-lab", false, None);
        s.error = Some("host key changed for client-lab (...)".to_string());
        s.error_kind = Some(ProbeErrorKind::HostKeyChanged);
        let table = format_status_table(&[s]);
        assert!(
            table.contains("key-rotated"),
            "table must surface key-rotated status, got: {}",
            table
        );
        assert!(
            !table.contains(" offline "),
            "must NOT be reported as plain offline when TOFU rotated"
        );
    }

    #[test]
    fn format_status_table_surfaces_alt_port() {
        let mut s = mock_status("client-lab", true, Some("1.9.3"));
        s.transport = "alt-port";
        let table = format_status_table(&[s]);
        assert!(
            table.contains("online*"),
            "alt-port rescue must show as online*, got: {}",
            table
        );
    }

    #[test]
    fn probe_error_kind_label_stable() {
        // Stability check: labels are consumed by table formatting and
        // potentially by scripts — changing them is a breaking change.
        assert_eq!(ProbeErrorKind::Timeout.label(), "timeout");
        assert_eq!(ProbeErrorKind::Refused.label(), "refused");
        assert_eq!(ProbeErrorKind::HostKeyChanged.label(), "key-rotated");
        assert_eq!(ProbeErrorKind::AuthFailed.label(), "auth-fail");
        assert_eq!(ProbeErrorKind::Other.label(), "error");
    }

    // rsh-lic: OS classification + per-host binary selection regression tests.

    #[test]
    fn os_kind_parse_accepts_aliases() {
        assert_eq!(OsKind::parse("windows"), Some(OsKind::Windows));
        assert_eq!(OsKind::parse("Win64"), Some(OsKind::Windows));
        assert_eq!(OsKind::parse("linux"), Some(OsKind::LinuxGnu));
        assert_eq!(OsKind::parse("GLIBC"), Some(OsKind::LinuxGnu));
        assert_eq!(OsKind::parse("linux-musl"), Some(OsKind::LinuxMusl));
        assert_eq!(OsKind::parse("alpine"), Some(OsKind::LinuxMusl));
        assert_eq!(OsKind::parse("beos"), None);
    }

    #[test]
    fn os_kind_defaults_match_deploy_layout() {
        assert_eq!(OsKind::Windows.default_binary_path(), "deploy/mrsh.exe");
        assert_eq!(OsKind::LinuxGnu.default_binary_path(), "deploy/mrsh-linux");
        assert_eq!(
            OsKind::LinuxMusl.default_binary_path(),
            "deploy/mrsh-linux-musl"
        );
    }

    #[test]
    fn os_kind_remote_paths_match_legacy_constants() {
        // These must not drift — selfupdate.rs and fleet.rs agree on the
        // temp landing paths. Regression for the v1.10.22 Linux breakage.
        assert_eq!(OsKind::Windows.remote_update_path(), "C:/Temp/mrsh-new.exe");
        assert_eq!(OsKind::LinuxGnu.remote_update_path(), "/tmp/mrsh-new");
        assert_eq!(OsKind::LinuxMusl.remote_update_path(), "/tmp/mrsh-new");
    }

    #[test]
    fn classify_os_prefers_config_hint() {
        let mut s = mock_status("alpine-host", true, Some("1.0.0"));
        s.caps = vec!["linux".to_string()];
        // Even though caps say linux-gnu, a config hint forces musl.
        assert_eq!(classify_os(&s, Some("linux-musl")), OsKind::LinuxMusl);
    }

    #[test]
    fn classify_os_falls_back_to_caps_when_no_hint() {
        let mut s = mock_status("linux-host", true, Some("1.0.0"));
        s.caps = vec!["linux".to_string(), "shell".to_string()];
        assert_eq!(classify_os(&s, None), OsKind::LinuxGnu);
    }

    #[test]
    fn classify_os_musl_cap_wins_over_linux_cap() {
        let mut s = mock_status("rdv", true, Some("1.0.0"));
        // Server advertises both — musl must win.
        s.caps = vec!["linux".to_string(), "linux-musl".to_string()];
        assert_eq!(classify_os(&s, None), OsKind::LinuxMusl);
    }

    #[test]
    fn classify_os_windows_from_window_cap() {
        let mut s = mock_status("win-host", true, Some("1.0.0"));
        s.caps = vec!["window".to_string(), "shell".to_string()];
        assert_eq!(classify_os(&s, None), OsKind::Windows);
    }

    #[test]
    fn classify_os_invalid_hint_falls_back() {
        let mut s = mock_status("x", true, Some("1.0.0"));
        s.caps = vec!["linux".to_string()];
        // Invalid hint must not crash — fall back to cap detection.
        assert_eq!(classify_os(&s, Some("not-an-os")), OsKind::LinuxGnu);
    }

    /// rsh-1g6g regression: pre-1.10.X Linux daemon advertises "system" cap
    /// (it's the daemon-mode marker, not Windows-only). Without an explicit
    /// "linux" cap, the legacy heuristic must still classify as Linux.
    #[test]
    fn classify_os_legacy_linux_with_system_cap_is_not_windows() {
        let mut s = mock_status("server01", true, Some("1.10.22"));
        // Pre-1.10.X Linux daemon caps: "system" without "linux".
        s.caps = vec![
            "exec".to_string(),
            "shell".to_string(),
            "push".to_string(),
            "pull".to_string(),
            "system".to_string(),
        ];
        assert_eq!(classify_os(&s, None), OsKind::LinuxGnu);
    }

    /// Companion to the rsh-1g6g regression: a real Windows daemon advertises
    /// "window" / "tray" / "mouse" / "keyboard" — those ARE Windows-only.
    #[test]
    fn classify_os_windows_daemon_with_mouse_keyboard() {
        let mut s = mock_status("win-host", true, Some("1.0.0"));
        s.caps = vec![
            "exec".to_string(),
            "system".to_string(),
            "mouse".to_string(),
            "keyboard".to_string(),
        ];
        assert_eq!(classify_os(&s, None), OsKind::Windows);
    }

    #[test]
    fn fleet_binaries_pick_routes_per_os() {
        let bins = FleetBinaries {
            windows: Some(vec![0x4du8, 0x5a]), // "MZ"
            linux_gnu: Some(vec![0x7f, b'E', b'L', b'F']),
            linux_musl: Some(vec![b'M', b'U', b'S', b'L']),
            ..FleetBinaries::default()
        };
        assert_eq!(bins.pick(OsKind::Windows), Some(&[0x4d, 0x5a][..]));
        assert_eq!(bins.pick(OsKind::LinuxGnu).map(|b| b.len()), Some(4));
        assert_eq!(bins.pick(OsKind::LinuxMusl).map(|b| b.len()), Some(4));
    }

    #[test]
    fn fleet_binaries_musl_falls_back_to_gnu() {
        let bins = FleetBinaries {
            windows: None,
            linux_gnu: Some(vec![0x7f, b'E', b'L', b'F']),
            linux_musl: None,
            ..FleetBinaries::default()
        };
        // musl request falls back to glibc — not ideal but preserves the
        // pre-rsh-lic behavior for fleets that don't ship a musl build.
        assert_eq!(bins.pick(OsKind::LinuxMusl).map(|b| b.len()), Some(4));
    }

    #[test]
    fn fleet_binaries_windows_no_linux_fallback() {
        let bins = FleetBinaries {
            windows: Some(vec![0x4d, 0x5a]),
            linux_gnu: None,
            linux_musl: None,
            ..FleetBinaries::default()
        };
        // Windows must NEVER fall back to Linux bytes (that's the bug we're
        // fixing — v1.10.22 pushed mrsh.exe to Linux hosts).
        assert!(bins.pick(OsKind::LinuxGnu).is_none());
        assert!(bins.pick(OsKind::LinuxMusl).is_none());
    }

    // rsh-6i9e: aarch64-specific tests.

    #[test]
    fn os_kind_parse_aarch64_aliases() {
        assert_eq!(OsKind::parse("linux-aarch64"), Some(OsKind::LinuxAarch64));
        assert_eq!(OsKind::parse("linux-arm64"), Some(OsKind::LinuxAarch64));
        assert_eq!(OsKind::parse("aarch64"), Some(OsKind::LinuxAarch64));
        assert_eq!(OsKind::parse("arm64"), Some(OsKind::LinuxAarch64));
        assert_eq!(OsKind::parse("ARM64"), Some(OsKind::LinuxAarch64));
    }

    #[test]
    fn os_kind_parse_x86_64_aliases() {
        assert_eq!(OsKind::parse("linux-x86_64"), Some(OsKind::LinuxGnu));
        assert_eq!(OsKind::parse("linux-amd64"), Some(OsKind::LinuxGnu));
        assert_eq!(OsKind::parse("windows-x86_64"), Some(OsKind::Windows));
        assert_eq!(OsKind::parse("windows-x64"), Some(OsKind::Windows));
    }

    #[test]
    fn os_kind_aarch64_default_path() {
        assert_eq!(
            OsKind::LinuxAarch64.default_binary_path(),
            "deploy/mrsh-linux-aarch64"
        );
        assert_eq!(OsKind::LinuxAarch64.remote_update_path(), "/tmp/mrsh-new");
        assert_eq!(OsKind::LinuxAarch64.label(), "linux-aarch64");
    }

    #[test]
    fn classify_os_aarch64_cap_wins_over_linux() {
        // Server advertises both "linux" (backward-compat) AND "linux-aarch64"
        // (new) — aarch64 must win so x86_64 binaries are not pushed.
        let mut s = mock_status("arm-headunit", true, Some("1.0.0"));
        s.caps = vec!["linux".to_string(), "linux-aarch64".to_string()];
        assert_eq!(classify_os(&s, None), OsKind::LinuxAarch64);
    }

    #[test]
    fn classify_os_aarch64_hint_overrides_caps() {
        // Config hint forces aarch64 even if caps don't advertise it.
        let mut s = mock_status("hu-k706", true, Some("1.0.0"));
        s.caps = vec!["linux".to_string()];
        assert_eq!(
            classify_os(&s, Some("linux-aarch64")),
            OsKind::LinuxAarch64
        );
    }

    #[test]
    fn fleet_binaries_aarch64_no_fallback() {
        // Loading only an x86_64 Linux binary MUST NOT serve aarch64 hosts —
        // pushing x86_64 ELF to ARM64 would brick the service.
        let bins = FleetBinaries {
            windows: None,
            linux_gnu: Some(vec![0x7f, b'E', b'L', b'F']),
            linux_musl: None,
            linux_aarch64: None,
        };
        assert!(bins.pick(OsKind::LinuxAarch64).is_none());
    }

    #[test]
    fn fleet_binaries_aarch64_picks_correct_bytes() {
        let bins = FleetBinaries {
            windows: Some(vec![0x4d, 0x5a]),
            linux_gnu: Some(vec![b'g', b'n', b'u']),
            linux_musl: Some(vec![b'm', b'u', b's', b'l']),
            linux_aarch64: Some(vec![b'a', b'r', b'm', b'6', b'4']),
        };
        assert_eq!(bins.pick(OsKind::LinuxAarch64).map(|b| b.len()), Some(5));
        // x86_64 GNU must not be affected by aarch64 presence.
        assert_eq!(bins.pick(OsKind::LinuxGnu).map(|b| b.len()), Some(3));
    }

    #[test]
    fn plan_fleet_update_aarch64_skipped_without_binary() {
        // Aarch64 host present, only x86_64 binaries loaded → must SKIP, not
        // fall back to x86_64 ELF.
        let mut arm = mock_status("hu-k706", true, Some("1.0.0"));
        arm.caps = vec![
            "linux".to_string(),
            "linux-aarch64".to_string(),
            "self-update".to_string(),
            "shell".to_string(),
        ];
        let bins = FleetBinaries {
            windows: None,
            linux_gnu: Some(vec![0u8; MIN_BINARY_SIZE_SENTINEL]),
            linux_musl: None,
            linux_aarch64: None,
        };
        let plans = plan_fleet_update(&Config::default(), &[arm], &bins, "2.0.0");
        let armp = &plans[0];
        assert_eq!(armp.os, OsKind::LinuxAarch64);
        assert!(
            armp.skip_reason
                .as_ref()
                .is_some_and(|r| r.contains("linux-aarch64")),
            "aarch64 host without aarch64 binary must be skipped, got {:?}",
            armp.skip_reason
        );
    }

    #[test]
    fn plan_fleet_update_aarch64_routed_when_loaded() {
        let mut arm = mock_status("hu-k706", true, Some("1.0.0"));
        arm.caps = vec![
            "linux".to_string(),
            "linux-aarch64".to_string(),
            "self-update".to_string(),
            "shell".to_string(),
        ];
        let bins = FleetBinaries {
            windows: None,
            linux_gnu: None,
            linux_musl: None,
            linux_aarch64: Some(vec![0u8; MIN_BINARY_SIZE_SENTINEL]),
        };
        let plans = plan_fleet_update(&Config::default(), &[arm], &bins, "2.0.0");
        let armp = &plans[0];
        assert_eq!(armp.os, OsKind::LinuxAarch64);
        assert!(armp.skip_reason.is_none(), "should NOT skip when aarch64 binary loaded, got {:?}", armp.skip_reason);
        assert_eq!(armp.binary_bytes, MIN_BINARY_SIZE_SENTINEL);
    }

    #[test]
    fn plan_fleet_update_marks_windows_skip_when_no_exe() {
        // Fleet has a Windows host + a Linux host. We loaded only the Linux
        // binary → Windows host must be SKIPPED, not misfired with ELF bytes.
        let mut win = mock_status("winbox", true, Some("1.0.0"));
        win.caps = vec![
            "window".to_string(),
            "self-update".to_string(),
            "shell".to_string(),
        ];
        let mut lin = mock_status("linbox", true, Some("1.0.0"));
        lin.caps = vec![
            "linux".to_string(),
            "self-update".to_string(),
            "shell".to_string(),
        ];

        let bins = FleetBinaries {
            windows: None,
            linux_gnu: Some(vec![0u8; MIN_BINARY_SIZE_SENTINEL]),
            linux_musl: None,
            ..FleetBinaries::default()
        };
        let cfg = Config::default();
        let plans = plan_fleet_update(&cfg, &[win, lin], &bins, "2.0.0");
        let winp = plans.iter().find(|p| p.name == "winbox").unwrap();
        let linp = plans.iter().find(|p| p.name == "linbox").unwrap();
        assert_eq!(winp.os, OsKind::Windows);
        assert!(
            winp.skip_reason
                .as_ref()
                .is_some_and(|r| r.contains("windows")),
            "winbox without windows binary must be skipped, got {:?}",
            winp.skip_reason
        );
        assert_eq!(linp.os, OsKind::LinuxGnu);
        assert!(linp.skip_reason.is_none());
        assert_eq!(linp.binary_bytes, MIN_BINARY_SIZE_SENTINEL);
    }

    #[test]
    fn plan_fleet_update_skips_offline() {
        let mut off = mock_status("offline-host", false, None);
        off.caps = Vec::new();
        let bins = FleetBinaries {
            windows: Some(vec![0u8; MIN_BINARY_SIZE_SENTINEL]),
            linux_gnu: None,
            linux_musl: None,
            ..FleetBinaries::default()
        };
        let plans = plan_fleet_update(&Config::default(), &[off], &bins, "2.0.0");
        assert!(plans[0].skip_reason.as_deref() == Some("host offline"));
    }

    #[test]
    fn plan_fleet_update_skips_current_version() {
        let mut s = mock_status("current", true, Some("2.0.0"));
        s.caps = vec!["window".to_string(), "self-update".to_string()];
        let bins = FleetBinaries {
            windows: Some(vec![0u8; MIN_BINARY_SIZE_SENTINEL]),
            linux_gnu: None,
            linux_musl: None,
            ..FleetBinaries::default()
        };
        let plans = plan_fleet_update(&Config::default(), &[s], &bins, "2.0.0");
        assert!(
            plans[0]
                .skip_reason
                .as_ref()
                .is_some_and(|r| r.contains("already v2.0.0"))
        );
    }

    #[test]
    fn format_update_plan_shows_both_oses() {
        let plan = vec![
            HostUpdatePlan {
                name: "winbox".to_string(),
                hostname: "winbox.example.local".to_string(),
                port: 8822,
                os: OsKind::Windows,
                current_version: Some("1.0.0".to_string()),
                target_version: "2.0.0".to_string(),
                skip_reason: None,
                binary_bytes: 5_000_000,
            },
            HostUpdatePlan {
                name: "rdv".to_string(),
                hostname: "rendezvous.example.com".to_string(),
                port: 8822,
                os: OsKind::LinuxMusl,
                current_version: Some("1.0.0".to_string()),
                target_version: "2.0.0".to_string(),
                skip_reason: None,
                binary_bytes: 6_000_000,
            },
        ];
        let table = format_update_plan(&plan);
        assert!(table.contains("winbox"));
        assert!(table.contains("windows"));
        assert!(table.contains("rdv"));
        assert!(table.contains("linux-musl"));
        assert!(table.contains("push + self-update"));
    }

    // Small constant used only by the plan tests — stays below the real
    // 1MB threshold because those tests don't actually push binaries.
    const MIN_BINARY_SIZE_SENTINEL: usize = 16;

    #[test]
    fn hbbs_online_threshold_boundary() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Exactly at threshold — should be offline (< not <=)
        let last_seen = now - HBBS_ONLINE_THRESHOLD_SECS;
        let online = now.saturating_sub(last_seen) < HBBS_ONLINE_THRESHOLD_SECS;
        assert!(!online, "peer seen exactly at threshold should be offline");

        // One second before threshold — should be online
        let last_seen = now - HBBS_ONLINE_THRESHOLD_SECS + 1;
        let online = now.saturating_sub(last_seen) < HBBS_ONLINE_THRESHOLD_SECS;
        assert!(online, "peer seen 1s before threshold should be online");
    }
}
