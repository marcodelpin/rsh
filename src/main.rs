//! mrsh — Remote Shell (Rust rewrite)
//! CLI entry point: client commands + server mode (Windows).
//!
//! Server mode detection:
//!   - `-install`   → register Windows service
//!   - `-uninstall` → remove Windows service
//!   - `-console`   → run server in foreground (debug)
//!   - No `-h` + no local subcommand on Windows → server mode (tray or service)

// Console subsystem: terminal waits for process, stdin/stdout work natively.
// Tray/service modes call FreeConsole() early to detach.

mod cli;
mod dispatch;
mod dispatch_client;
mod lan_detect;
mod mac_form;
#[cfg(feature = "quic")]
mod dispatch_quic;
mod fleet_cmd;
mod help;
mod keygen;
mod local_cmds;
mod path_translate;
mod paths;
mod rdv_publish;
mod release_cmd;
mod server_mode;
mod ssh_fallback;
mod streaming;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use cli::{Cli, DEFAULT_PORT, TRAY_PORT, preprocess_args};

// Re-export helpers consumed from sibling modules (fleet_cmd, keygen, server_mode)
// via `crate::<name>` paths.
pub(crate) use paths::{
    all_authorized_keys_paths, get_local_addrs, ipv4_same_lan, is_same_lan, server_data_dir,
};

fn main() -> Result<()> {
    // Console subsystem: stdin/stdout/stderr connected to parent terminal by default.
    // For tray/service: detach from console (no visible window needed).
    #[cfg(target_os = "windows")]
    {
        let needs_no_console = std::env::args().any(|a| a == "--tray" || a == "--service");
        if needs_no_console {
            unsafe {
                use windows::Win32::System::Console::FreeConsole;
                let _ = FreeConsole();
            }
        }
    }

    let cli = Cli::parse_from(preprocess_args());

    #[cfg(target_os = "windows")]
    if cli.signal_helper {
        let attach_pid = cli
            .attach_pid
            .context("--signal-helper requires --attach-pid")?;
        let event = cli
            .ctrl_event
            .as_deref()
            .context("--signal-helper requires --ctrl-event")?;
        let event = mrsh_server::shell::parse_ctrl_event_name(event)?;
        return mrsh_server::shell::run_ctrl_helper(attach_pid, event);
    }

    // Accept changed host keys if flag or env var set
    if cli.accept_host_key || std::env::var("MRSH_ACCEPT_HOST_KEY").is_ok() {
        mrsh_core::tls::set_accept_host_key(true);
    }

    // Determine if we're running in server mode (needs audit log to file)
    // desk-xqq: exclude LOCAL_COMMANDS (fleet, cfg, keygen, …) from server-mode
    // detection — they have host=None but are client-side commands that must log
    // to stderr (or suppress logs for --json), not to the audit log.
    let is_local_cmd = std::env::args()
        .nth(1)
        .map(|a| cli::LOCAL_COMMANDS.contains(&a.as_str()))
        .unwrap_or(false);
    let is_server_mode = cli.console || cli.debug || cli.install || cli.uninstall || {
        #[cfg(target_os = "windows")]
        {
            cli.service || cli.tray || (cli.host.is_none() && !is_local_cmd)
        }
        #[cfg(not(target_os = "windows"))]
        {
            cli.daemon
        }
    };

    if is_server_mode {
        // Server mode: log to audit file (+ stderr if console available)
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let data_dir = server_data_dir();
        std::fs::create_dir_all(&data_dir).ok();
        // Use different log file for tray vs service to avoid lock contention
        #[cfg(target_os = "windows")]
        let log_prefix = if cli.debug {
            "audit-debug.log"
        } else if std::env::args().any(|a| a == "--tray") {
            "audit-tray.log"
        } else {
            "audit.log"
        };
        #[cfg(not(target_os = "windows"))]
        let log_prefix = if cli.debug {
            "audit-debug.log"
        } else {
            "audit.log"
        };
        let filter = tracing_subscriber::EnvFilter::new(match (cli.debug, cli.verbose) {
            (true, _) => "debug", // -d always verbose
            (_, 0) => "info",
            (_, 1) => "info",
            _ => "debug",
        });

        // Tray/service modes have no console — skip stderr layer to avoid writing
        // to invalid handle (causes 0xC0000409 on Windows 10 IoT LTSC).
        #[cfg(target_os = "windows")]
        let has_console = !std::env::args().any(|a| a == "--tray" || a == "--service");
        #[cfg(not(target_os = "windows"))]
        let has_console = true;

        let stderr_layer = if has_console {
            Some(tracing_subscriber::fmt::layer())
        } else {
            None
        };

        // Use builder to avoid panic on permission denied (e.g. service data dir
        // not yet writable, or SYSTEM user lacking access during migration).
        let file_layer = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(log_prefix)
            .build(&data_dir)
            .ok()
            .map(|appender| {
                tracing_subscriber::fmt::layer()
                    .with_writer(appender)
                    .with_ansi(false)
            });

        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        // Client mode: logs to stderr, stdout reserved for --json output.
        // desk-xqq: we detect --json up front and redirect logs to a file when
        // the tracing-subscriber cannot reliably route to Windows HANDLE 2.
        // On non-Windows or when not in JSON mode, use normal stderr routing.
        let json_mode = std::env::args().any(|a| a == "--json");
        let filter_str = match cli.verbose {
            0 => "info",
            _ => "debug",
        };
        if json_mode {
            // JSON mode: discard all tracing output so stdout is JSON-only.
            // desk-xqq: tracing_subscriber::fmt().with_writer(stderr) does not
            // reliably route to Windows HANDLE 2 when stdout is a pipe.
            // Use an empty registry (no layers) — events are accepted and
            // dropped, nothing is written to any handle.
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            tracing_subscriber::registry().init();
        } else {
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(filter_str))
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .init();
        }
    }
    // ── Cross-platform service/install/uninstall ────────────
    if cli.install {
        let exe = std::env::current_exe()?.to_string_lossy().to_string();
        // Persist --fs-spool into the server config so the installed service
        // picks it up on startup without the CLI flag being re-supplied.
        if let Some(ref spool) = cli.fs_spool {
            let mut cfg = mrsh_core::config::Config::load();
            cfg.fs_spool = Some(spool.clone());
            if let Err(e) = cfg.save() {
                tracing::warn!("failed to persist FsSpool to config: {}", e);
            } else {
                info!("persisted FsSpool={} to config", spool);
            }
        }
        mrsh_server::service::install_service(&exe)?;
        return Ok(());
    }
    if cli.uninstall {
        mrsh_server::service::uninstall_service()?;
        return Ok(());
    }
    if cli.console {
        let rt = tokio::runtime::Runtime::new()?;
        let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
        return rt.block_on(server_mode::run_server_mode_with_fs_spool(
            cli.port.unwrap_or(DEFAULT_PORT),
            false,
            spool,
        ));
    }
    if cli.debug {
        let port = cli.port.unwrap_or(DEFAULT_PORT);
        eprintln!("=== mrsh debug server on port {} ===", port);
        eprintln!("  auth: ed25519 (authorized_keys)");
        eprintln!("  relay/rdv: disabled");
        eprintln!("  log: console + audit-debug.log");
        eprintln!("  Ctrl+C to stop");
        let rt = tokio::runtime::Runtime::new()?;
        let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
        return rt.block_on(server_mode::run_debug_mode_with_fs_spool(port, spool));
    }

    // ── Explicit tray mode (Windows) ─────────────────────────
    // Skips SCM dispatch entirely — goes straight to tray on port 9822.
    // Use when service_dispatcher::start() interferes (e.g. schtask launch).
    #[cfg(target_os = "windows")]
    if cli.tray {
        let rt = tokio::runtime::Runtime::new()?;
        let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
        return rt.block_on(server_mode::run_server_mode_with_fs_spool(
            TRAY_PORT, true, spool,
        ));
    }

    // ── Linux daemon mode ────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    if cli.daemon {
        let port = cli.port.unwrap_or(DEFAULT_PORT);
        let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
        mrsh_server::service::run_as_service(move |cancel| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
            let spool = spool.clone();
            rt.block_on(async {
                if let Err(e) = server_mode::run_server_mode_with_cancel_and_spool(
                    port, cancel, spool,
                )
                .await
                {
                    tracing::error!("server error: {}", e);
                }
            });
        })?;
        return Ok(());
    }

    // ── Windows server mode detection ────────────────────────
    // Must happen BEFORE tokio runtime, because service_dispatcher::start()
    // blocks the main thread and spawns service_main on a new thread.
    #[cfg(target_os = "windows")]
    {
        // Explicit --service flag: SCM launched us with this flag, go straight to dispatch.
        if cli.service {
            // Ensure tray task exists (self-heal if missing/deleted)
            let exe = std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if !exe.is_empty() {
                mrsh_server::service::ensure_tray_task(&exe);
                // rsh-3t7f: keep the tray alive across deferred logons by
                // re-running ensure_tray_task on a background timer. Catches
                // the case where a user logs in AFTER service start (RDP,
                // post-boot logon delay) — the install-time call above only
                // fires once.
                mrsh_server::tray_watchdog::spawn_tray_watchdog(exe.clone());
            }
            // Self-heal firewall rules to profile=any so service stays reachable
            // at Windows lock screen (NLA may downgrade to Public). rsh-5wzh.
            mrsh_server::service::ensure_firewall_rules();

            let port = cli.port.unwrap_or(DEFAULT_PORT);
            // SCM doesn't pass CLI flags through; pick fs_spool up from config
            // (installer writes FsSpool to persistent config). CLI flag still
            // honoured when present so `mrsh --service --fs-spool DIR` works.
            let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
            mrsh_server::service::run_as_service(move |cancel| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
                let spool = spool.clone();
                rt.block_on(async {
                    if let Err(e) = server_mode::run_server_mode_with_cancel_and_spool(
                        port, cancel, spool,
                    )
                    .await
                    {
                        tracing::error!("server error: {}", e);
                    }
                });
            })?;
            return Ok(());
        }

        // Default server mode: tray.
        // No -h, no local subcommand, no --service → launch as tray (port 9822).
        // SCM dispatch only happens with explicit --service flag (set by service registration).
        // This avoids the SCM probe delay and ensures schtask/double-click = tray.
        let is_local_cmd = cli.args.first().is_none_or(|a| {
            cli::LOCAL_COMMANDS.contains(&a.as_str()) || a == "help" || a == "recording"
        });
        if cli.host.is_none() && !is_local_cmd {
            // With preprocess_args(), non-command first args are already converted
            // to -h <host>. If we still get here, it's a client subcommand without
            // -h (e.g. "mrsh exec -h host") or truly no args → tray mode.
            if let Some(first_arg) = cli.args.first()
                && cli::CLIENT_SUBCOMMANDS.contains(&first_arg.as_str()) {
                    eprintln!(
                        "error: '{}' requires -h <host> BEFORE the subcommand",
                        first_arg
                    );
                    eprintln!("  correct: mrsh -h <host> {} ...", first_arg);
                    eprintln!("  hint:    mrsh <host> {} ...  (also works)", first_arg);
                    std::process::exit(1);
                }
            let rt = tokio::runtime::Runtime::new()?;
            let spool = cli.fs_spool.clone().map(std::path::PathBuf::from);
            return rt.block_on(server_mode::run_server_mode_with_fs_spool(
                TRAY_PORT, true, spool,
            ));
        }
    }

    // ── Non-service path: build tokio runtime and run async main ──
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(dispatch::async_main(cli));

    // Force process exit for client mode. Without this, the GUI subsystem binary
    // (windows_subsystem = "windows") can linger indefinitely if background tokio
    // tasks, TLS streams, or console handles aren't fully cleaned up.
    match &result {
        Ok(()) => std::process::exit(0),
        Err(_) => {
            // Let the error propagate for display, then exit
            let _ = result.as_ref().map_err(|e| eprintln!("Error: {:#}", e));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use cli::{compute_timeout_secs, unmangle_msys_remote};

    // --- compute_timeout_secs ---

    #[test]
    fn timeout_explicit_overrides_all_commands() {
        assert_eq!(compute_timeout_secs(60, "push"), 60);
        assert_eq!(compute_timeout_secs(60, "shell"), 60);
        assert_eq!(compute_timeout_secs(60, "exec"), 60);
        assert_eq!(compute_timeout_secs(1, "pull"), 1);
    }

    #[test]
    fn timeout_zero_uses_per_command_defaults() {
        // Interactive commands: no timeout
        assert_eq!(compute_timeout_secs(0, "shell"), 0);
        assert_eq!(compute_timeout_secs(0, "browse"), 0);
        assert_eq!(compute_timeout_secs(0, "sftp"), 0);
        assert_eq!(compute_timeout_secs(0, "tunnel"), 0);
        assert_eq!(compute_timeout_secs(0, "watch"), 0);
        assert_eq!(compute_timeout_secs(0, "attach"), 0);
        assert_eq!(compute_timeout_secs(0, "socks5"), 0);
        assert_eq!(compute_timeout_secs(0, "pull-via-batch"), 0);

        // Transfer commands: 300s default
        assert_eq!(compute_timeout_secs(0, "push"), 300);
        assert_eq!(compute_timeout_secs(0, "pull"), 300);

        // All other commands: 600s default
        assert_eq!(compute_timeout_secs(0, "ping"), 600);
        assert_eq!(compute_timeout_secs(0, "exec"), 600);
        assert_eq!(compute_timeout_secs(0, "ls"), 600);
        assert_eq!(compute_timeout_secs(0, "cat"), 600);
        assert_eq!(compute_timeout_secs(0, "info"), 600);
        assert_eq!(compute_timeout_secs(0, "kill"), 600);
        assert_eq!(compute_timeout_secs(0, "screenshot"), 600);
    }

    // --- CLI arg parsing ---

    #[test]
    fn cli_timeout_default_is_zero() {
        let cli = Cli::try_parse_from(["mrsh", "-h", "host", "ping"]).unwrap();
        assert_eq!(cli.timeout, 0);
    }

    #[test]
    fn cli_timeout_explicit_value_parsed() {
        let cli = Cli::try_parse_from(["mrsh", "-h", "host", "--timeout", "45", "ping"]).unwrap();
        assert_eq!(cli.timeout, 45);
    }

    #[test]
    fn cli_timeout_zero_explicit_parsed() {
        let cli =
            Cli::try_parse_from(["mrsh", "-h", "host", "--timeout", "0", "exec", "ls"]).unwrap();
        assert_eq!(cli.timeout, 0);
    }

    // --- tokio timeout wrapper behaviour ---

    #[tokio::test]
    async fn timeout_wrapper_fires_on_slow_future() {
        let slow = tokio::time::sleep(std::time::Duration::from_secs(60));
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), slow).await;
        assert!(result.is_err(), "expected timeout to fire");
    }

    #[tokio::test]
    async fn timeout_wrapper_passes_fast_future() {
        let fast = async { 42u32 };
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), fast).await;
        assert_eq!(result.unwrap(), 42);
    }

    // --- build_server_caps ---

    #[test]
    fn caps_contains_common_capabilities() {
        let caps = server_mode::build_server_caps();
        for expected in &[
            "exec",
            "stream-exec",
            "push",
            "pull",
            "self-update",
            "info",
            "ps",
            "kill",
            "ls",
            "cat",
            "tail",
            "clip",
            "screenshot",
        ] {
            assert!(
                caps.iter().any(|c| c == expected),
                "missing common cap: {}",
                expected
            );
        }
    }

    #[test]
    fn caps_contains_shell_on_all_platforms() {
        let caps = server_mode::build_server_caps();
        assert!(
            caps.contains(&"shell".to_string()),
            "shell must be in caps on all platforms"
        );
    }

    #[test]
    fn caps_contains_reboot_shutdown_on_all_platforms() {
        let caps = server_mode::build_server_caps();
        assert!(caps.contains(&"reboot".to_string()));
        assert!(caps.contains(&"shutdown".to_string()));
    }

    #[test]
    fn caps_no_duplicates() {
        let caps = server_mode::build_server_caps();
        let mut seen = std::collections::HashSet::new();
        for cap in &caps {
            assert!(seen.insert(cap), "duplicate cap: {}", cap);
        }
    }

    /// rsh-6i9e: server MUST advertise its CPU arch so `fleet update` routes
    /// the right binary to vehicle aarch64 head-units.
    #[test]
    fn caps_contains_arch_marker() {
        let caps = server_mode::build_server_caps();
        #[cfg(all(not(windows), target_arch = "x86_64"))]
        assert!(
            caps.contains(&"linux-x86_64".to_string()),
            "x86_64 Linux build must advertise linux-x86_64 cap: {:?}",
            caps
        );
        #[cfg(all(not(windows), target_arch = "aarch64"))]
        assert!(
            caps.contains(&"linux-aarch64".to_string()),
            "aarch64 Linux build must advertise linux-aarch64 cap: {:?}",
            caps
        );
        #[cfg(all(windows, target_arch = "x86_64"))]
        assert!(
            caps.contains(&"windows-x86_64".to_string()),
            "x86_64 Windows build must advertise windows-x86_64 cap: {:?}",
            caps
        );
        #[cfg(all(windows, target_arch = "aarch64"))]
        assert!(
            caps.contains(&"windows-aarch64".to_string()),
            "aarch64 Windows build must advertise windows-aarch64 cap: {:?}",
            caps
        );
    }

    /// rsh-6i9e: backward-compat. Adding arch caps MUST NOT remove the
    /// legacy "linux"/"window" markers — old clients still rely on them.
    #[test]
    fn caps_backward_compat_legacy_markers_preserved() {
        let caps = server_mode::build_server_caps();
        #[cfg(not(windows))]
        assert!(
            caps.contains(&"linux".to_string()),
            "legacy 'linux' cap must remain for old-client compat: {:?}",
            caps
        );
        #[cfg(windows)]
        assert!(
            caps.contains(&"window".to_string()),
            "legacy 'window' cap must remain for old-client compat: {:?}",
            caps
        );
    }

    // --- resolve_device_id ---

    #[test]
    fn device_id_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = mrsh_core::config::Config::default();
        config.device_id = Some("123456789".to_string());
        let id = server_mode::resolve_device_id(&config, tmp.path());
        assert_eq!(id, "123456789");
    }

    #[test]
    fn device_id_from_legacy_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("device_id"), "987654321\n").unwrap();
        let config = mrsh_core::config::Config::default(); // no device_id set
        let id = server_mode::resolve_device_id(&config, tmp.path());
        assert_eq!(id, "987654321");
    }

    #[test]
    fn device_id_generated_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let config = mrsh_core::config::Config::default();
        let id = server_mode::resolve_device_id(&config, tmp.path());
        // Should be 9 digits
        assert_eq!(id.len(), 9, "generated ID should be 9 digits: {}", id);
        assert!(
            id.chars().all(|c| c.is_ascii_digit()),
            "ID should be all digits: {}",
            id
        );
        let n: u32 = id.parse().unwrap();
        assert!((100_000_000..999_999_999).contains(&n));
    }

    #[test]
    fn device_id_config_takes_precedence_over_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("device_id"), "111111111").unwrap();
        let mut config = mrsh_core::config::Config::default();
        config.device_id = Some("222222222".to_string());
        let id = server_mode::resolve_device_id(&config, tmp.path());
        assert_eq!(id, "222222222", "config should take precedence over file");
    }

    #[test]
    #[cfg(not(windows))]
    fn caps_linux_excludes_windows_only() {
        let caps = server_mode::build_server_caps();
        for win_only in &[
            "mouse",
            "keyboard",
            "window",
            "service",
            "session",
            "recording",
            "sleep",
            "lock",
        ] {
            assert!(
                !caps.iter().any(|c| c == win_only),
                "Linux caps should not contain {}",
                win_only
            );
        }
    }

    // --- unmangle_msys_remote ---

    #[test]
    fn unmangle_scoop_git_home() {
        let mangled = "C:/Users/user/scoop/apps/git/2.53.0.2/home/user/rsh";
        assert_eq!(
            unmangle_msys_remote(mangled),
            Some("/home/user/rsh".to_string())
        );
    }

    #[test]
    fn unmangle_scoop_git_usr() {
        let mangled = "C:/Users/user/scoop/apps/git/2.53.0.2/usr/local/bin/rsh";
        assert_eq!(
            unmangle_msys_remote(mangled),
            Some("/usr/local/bin/rsh".to_string())
        );
    }

    #[test]
    fn unmangle_normal_remote_path_untouched() {
        assert_eq!(unmangle_msys_remote("/home/user/rsh"), None);
    }

    #[test]
    fn unmangle_windows_local_path_untouched() {
        assert_eq!(
            unmangle_msys_remote("C:\\ProgramData\\mrsh\\mrsh.exe"),
            None
        );
    }

    #[test]
    fn unmangle_trailing_slash() {
        let mangled = "C:/Users/user/scoop/apps/git/2.53.0.2/home/user/rsh/";
        assert_eq!(
            unmangle_msys_remote(mangled),
            Some("/home/user/rsh/".to_string())
        );
    }
}
