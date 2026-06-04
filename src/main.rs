//! mrsh — Remote Shell (Rust rewrite)
//! CLI entry point: client commands + server mode (Windows).
//!
//! Server mode detection:
//!   - `-install`   → register Windows service
//!   - `-uninstall` → remove Windows service
//!   - `-console`   → run server in foreground (debug)
//!   - No `-h` + no local subcommand on Windows → server mode (tray or service)

// Suppress console window on Windows.
// CLI output uses AttachConsole to reattach to parent's console when needed.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod fleet_cmd;
mod help;
mod keygen;
mod local_cmds;
mod server_mode;

use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Parser;
use mrsh_client::client::ConnectOptions;
use tracing::info;

/// mrsh — Remote Shell
#[derive(Parser, Debug)]
#[command(
    name = "mrsh",
    version,
    about = "Remote shell tool",
    disable_help_flag = true
)]
struct Cli {
    /// Remote host (IP, hostname, or DeviceID)
    #[arg(short = 'h', long)]
    host: Option<String>,

    /// Print help
    #[arg(long)]
    help: bool,

    /// Remote port (omit for auto-try: 8822 → 9822 → 22)
    #[arg(short, long)]
    port: Option<u16>,

    /// SSH key file
    #[arg(short = 'i', long)]
    key: Option<String>,

    /// Verbose output (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Install as system service (Windows: SCM service, Linux: systemd unit)
    #[arg(long = "install")]
    install: bool,

    /// Uninstall system service
    #[arg(long = "uninstall")]
    uninstall: bool,

    /// Run server in foreground (debug mode)
    #[arg(long = "console")]
    console: bool,

    /// Internal: launched by SCM as service (Windows only)
    #[cfg(target_os = "windows")]
    #[arg(long = "service", hide = true)]
    service: bool,

    /// Run as tray app (user session, port 9822, system tray icon)
    #[cfg(target_os = "windows")]
    #[arg(long = "tray")]
    tray: bool,

    /// Run as background daemon (Linux only)
    #[cfg(not(target_os = "windows"))]
    #[arg(long = "daemon")]
    daemon: bool,

    /// Delete remote files not present locally (mirror mode, push only)
    #[arg(long = "delete")]
    delete: bool,

    /// Username for password auth (fallback when no SSH key)
    #[arg(long = "user")]
    user: Option<String>,

    /// SOCKS5 dynamic proxy port (ssh -D equivalent)
    #[arg(short = 'D', long = "dynamic")]
    dynamic_port: Option<u16>,

    /// Show progress bar with rate and ETA during transfers
    #[arg(long = "progress")]
    progress: bool,

    /// Dry run: show what would be transferred without doing it
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Backup suffix for overwritten files (e.g. --backup=.bak)
    #[arg(long = "backup")]
    backup: Option<String>,

    /// Bandwidth limit in KB/s (0 = unlimited)
    #[arg(long = "bwlimit", default_value_t = 0)]
    bwlimit: u32,

    /// Global operation timeout in seconds (0 = per-command default)
    #[arg(long = "timeout", default_value_t = 0)]
    timeout: u64,

    /// Start control master (hold connection, serve via UDS)
    #[arg(short = 'M')]
    master: bool,

    /// Skip multiplexing, always open new connection
    #[arg(long = "no-mux")]
    no_mux: bool,

    /// Accept changed host keys (update known_hosts instead of rejecting)
    #[arg(long = "accept-host-key")]
    accept_host_key: bool,

    /// Stop running master for this host
    #[arg(long = "mux-stop")]
    mux_stop: bool,

    /// Use cmd.exe instead of PowerShell for exec (avoids $var expansion)
    #[arg(long = "cmd")]
    use_cmd: bool,

    /// Use sh/bash instead of PowerShell for exec
    #[arg(long = "sh")]
    use_sh: bool,

    /// Use QUIC transport instead of TLS/TCP (experimental, requires --features quic)
    #[cfg(feature = "quic")]
    #[arg(long = "quic")]
    use_quic: bool,

    /// Subcommand and arguments
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

/// Tray mode port (user session, secondary listener).
const TRAY_PORT: u16 = 9822;

/// Default server port. Override at compile time: MRSH_DEFAULT_PORT=9822
pub(crate) const DEFAULT_PORT: u16 = match option_env!("MRSH_DEFAULT_PORT") {
    Some(s) => {
        // const-compatible u16 parse
        let b = s.as_bytes();
        let mut n: u16 = 0;
        let mut i = 0;
        while i < b.len() {
            n = n * 10 + (b[i] - b'0') as u16;
            i += 1;
        }
        n
    }
    None => 8822,
};

/// Known local subcommands that don't require -h (used in server mode detection).
const LOCAL_COMMANDS: &[&str] = &["version", "fleet", "wake", "cfg", "config-edit", "connect", "log", "logs", "dash", "dashboard", "keygen", "keys", "totp-setup", "totp-verify", "pack", "install-pack", "relay", "rdv", "rendezvous", "discover", "nat"];

/// Returns the effective operation timeout in seconds.
/// Explicit `--timeout N` (N > 0) overrides everything.
/// Per-command defaults: push/pull → 300s, interactive cmds → 0, others → 120s.
fn compute_timeout_secs(explicit: u64, cmd: &str) -> u64 {
    if explicit > 0 {
        return explicit;
    }
    match cmd {
        "shell" | "browse" | "sftp" | "tunnel" | "watch" | "attach" | "socks5" => 0,
        "push" | "pull" => 300,
        _ => 120,
    }
}

fn main() -> Result<()> {
    // Reattach to parent console for CLI output (we're a windowsgui subsystem binary).
    // Skip for --tray and --service modes:
    //   --tray: GUI app, no console needed — AllocConsole causes 0xC0000409 on Win10 IoT LTSC
    //   --service: SCM background process, output goes to audit.log — AllocConsole + CONOUT$
    //     on LTSC can prevent service startup (v1.3.3 rollback on media-host)
    #[cfg(target_os = "windows")]
    {
        let needs_no_console = std::env::args().any(|a| a == "--tray" || a == "--service");
        // TUI commands need a visible, fully functional console
        let is_tui_cmd = std::env::args().any(|a| {
            matches!(a.as_str(), "dash" | "dashboard" | "logs" | "cfg" | "config-edit" | "browse" | "sftp" | "connect")
        });
        if !needs_no_console {
            unsafe {
                use windows::Win32::System::Console::{
                    AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS,
                    GetConsoleWindow,
                };
                use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
                if AttachConsole(ATTACH_PARENT_PROCESS).is_err()
                    && AllocConsole().is_ok() {
                        // TUI commands need a visible console; other commands hide it
                        if !is_tui_cmd {
                            let hwnd = GetConsoleWindow();
                            if !hwnd.is_invalid() {
                                let _ = ShowWindow(hwnd, SW_HIDE);
                            }
                        }
                    }
                // After attach/alloc, reopen std handles so Rust's stdin/stdout
                // point to the (re)attached console. Without this, GUI subsystem
                // binary has null stdout → print! output lost (exec from PowerShell).
                //
                // IMPORTANT: only overwrite handles that are NULL. When launched
                // with redirected output (WSL interop, PowerShell pipe, cmd >file),
                // the parent sets valid pipe handles — overwriting them with CONOUT$
                // silently discards all piped output.
                {
                    use windows::Win32::Storage::FileSystem::{
                        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
                    };
                    use windows::Win32::System::Console::{
                        GetStdHandle, SetStdHandle, STD_INPUT_HANDLE,
                        STD_OUTPUT_HANDLE, STD_ERROR_HANDLE,
                    };
                    use windows::core::w;

                    // Helper: check if a std handle is already valid (non-null,
                    // non-INVALID_HANDLE_VALUE). If so, it was set by the parent
                    // (pipe/redirect) and must NOT be overwritten.
                    let handle_valid = |which| -> bool {
                        matches!(GetStdHandle(which), Ok(h) if !h.is_invalid() && h.0 as usize != 0)
                    };

                    let stdin_ok = handle_valid(STD_INPUT_HANDLE);
                    let stdout_ok = handle_valid(STD_OUTPUT_HANDLE);
                    let stderr_ok = handle_valid(STD_ERROR_HANDLE);

                    if !stdin_ok
                        && let Ok(h) = CreateFileW(
                            w!("CONIN$"), FILE_GENERIC_READ.0,
                            FILE_SHARE_READ, None, OPEN_EXISTING, Default::default(), None,
                        ) {
                            let _ = SetStdHandle(STD_INPUT_HANDLE, h);
                        }
                    if !stdout_ok
                        && let Ok(h) = CreateFileW(
                            w!("CONOUT$"), FILE_GENERIC_WRITE.0,
                            FILE_SHARE_WRITE, None, OPEN_EXISTING, Default::default(), None,
                        ) {
                            let _ = SetStdHandle(STD_OUTPUT_HANDLE, h);
                        }
                    if !stderr_ok
                        && let Ok(h) = CreateFileW(
                            w!("CONOUT$"), FILE_GENERIC_WRITE.0,
                            FILE_SHARE_WRITE, None, OPEN_EXISTING, Default::default(), None,
                        ) {
                            let _ = SetStdHandle(STD_ERROR_HANDLE, h);
                        }
                }
            }
        }
    }

    let cli = Cli::parse();

    // Accept changed host keys if flag or env var set
    if cli.accept_host_key || std::env::var("MRSH_ACCEPT_HOST_KEY").is_ok() {
        mrsh_core::tls::set_accept_host_key(true);
    }

    // Determine if we're running in server mode (needs audit log to file)
    let is_server_mode = cli.console
        || cli.install
        || cli.uninstall
        || {
            #[cfg(target_os = "windows")]
            { cli.service || cli.tray || cli.host.is_none() }
            #[cfg(not(target_os = "windows"))]
            { cli.daemon }
        };

    if is_server_mode {
        // Server mode: log to audit file (+ stderr if console available)
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let data_dir = server_data_dir();
        std::fs::create_dir_all(&data_dir).ok();
        // Use different log file for tray vs service to avoid lock contention
        #[cfg(target_os = "windows")]
        let log_prefix = if std::env::args().any(|a| a == "--tray") { "audit-tray.log" } else { "audit.log" };
        #[cfg(not(target_os = "windows"))]
        let log_prefix = "audit.log";
        let filter = tracing_subscriber::EnvFilter::new(match cli.verbose {
            0 => "info",
            1 => "info",
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
        // Client mode: stderr only
        tracing_subscriber::fmt()
            .with_env_filter(match cli.verbose {
                0 => "warn",
                1 => "info",
                _ => "debug",
            })
            .init();
    }
    // ── Cross-platform service/install/uninstall ────────────
    if cli.install {
        let exe = std::env::current_exe()?.to_string_lossy().to_string();
        mrsh_server::service::install_service(&exe)?;
        return Ok(());
    }
    if cli.uninstall {
        mrsh_server::service::uninstall_service()?;
        return Ok(());
    }
    if cli.console {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(server_mode::run_server_mode(cli.port.unwrap_or(DEFAULT_PORT), false));
    }

    // ── Explicit tray mode (Windows) ─────────────────────────
    // Skips SCM dispatch entirely — goes straight to tray on port 9822.
    // Use when service_dispatcher::start() interferes (e.g. schtask launch).
    #[cfg(target_os = "windows")]
    if cli.tray {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(server_mode::run_server_mode(TRAY_PORT, true));
    }

    // ── Linux daemon mode ────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    if cli.daemon {
        let port = cli.port.unwrap_or(DEFAULT_PORT);
        mrsh_server::service::run_as_service(move |cancel| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
            rt.block_on(async {
                if let Err(e) = server_mode::run_server_mode_with_cancel(port, cancel).await {
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
            }

            let port = cli.port.unwrap_or(DEFAULT_PORT);
            mrsh_server::service::run_as_service(move |cancel| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
                rt.block_on(async {
                    if let Err(e) = server_mode::run_server_mode_with_cancel(port, cancel).await {
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
            LOCAL_COMMANDS.contains(&a.as_str()) || a == "help" || a == "recording"
        });
        if cli.host.is_none() && !is_local_cmd {
            let rt = tokio::runtime::Runtime::new()?;
            return rt.block_on(server_mode::run_server_mode(TRAY_PORT, true));
        }
    }

    // ── Non-service path: build tokio runtime and run async main ──
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    // Normalize path arguments (Git Bash /c/Users → C:/Users, WSL /mnt/c → C:/, etc.)
    // Only normalize args that look like paths — skip command name (args[0])
    // and content arguments (exec command text, write content).
    let cmd_peek = cli.args.first().map(|s| s.as_str()).unwrap_or("");
    let args_normalized: Vec<String> = cli
        .args
        .iter()
        .enumerate()
        .map(|(i, a)| {
            if i == 0 {
                // Command name — never normalize
                a.clone()
            } else if cmd_peek == "exec" || (cmd_peek == "write" && i >= 2) {
                // exec: arg is PowerShell command text — don't normalize
                // write: args[2+] is content — don't normalize
                a.clone()
            } else {
                mrsh_core::path::normalize(a)
            }
        })
        .collect();
    let args = &args_normalized;
    // Default: "version" without -h, "shell" with -h
    let cmd = args
        .first()
        .map(|s| s.as_str())
        .unwrap_or(if cli.host.is_some() {
            "shell"
        } else {
            "version"
        });

    // Help (--help flag or "help" subcommand)
    if cli.help || cmd == "help" {
        help::print_usage();
        return Ok(());
    }

    // ── Local commands (no -h needed) ────────────────────────
    match cmd {
        "version" => {
            let version = env!("CARGO_PKG_VERSION");
            let suffix = option_env!("MRSH_VERSION_SUFFIX").unwrap_or("");
            if suffix.is_empty() {
                println!("mrsh {}", version);
            } else {
                println!("mrsh {}-{}", version, suffix);
            }
            return Ok(());
        }
        "fleet" => {
            return fleet_cmd::run_fleet(&args[1..]).await;
        }
        "discover" => {
            let timeout_secs: u64 = args.get(1)
                .and_then(|s| s.strip_prefix("--timeout=").or(Some(s.as_str())))
                .and_then(|s| s.parse().ok())
                .unwrap_or(3);
            let config = mrsh_core::config::Config::load();
            let local_id = config.device_id.clone().unwrap_or_default();
            eprintln!("Scanning LAN for mrsh peers ({timeout_secs}s)...");
            let peers = mrsh_relay::discovery::discover_lan(
                mrsh_relay::discovery::DISCOVERY_PORT,
                std::time::Duration::from_secs(timeout_secs),
                &local_id,
            ).await;
            if peers.is_empty() {
                println!("No peers found.");
            } else {
                println!("{:<20} {:<16} {:<10} {:<6}", "HOSTNAME", "IP", "PLATFORM", "PORT");
                println!("{}", "-".repeat(54));
                for p in &peers {
                    let port = if p.service_port > 0 { p.service_port.to_string() } else { "-".to_string() };
                    println!("{:<20} {:<16} {:<10} {:<6}", p.hostname, p.addr.ip(), p.platform, port);
                }
                println!("\nFound {} peer(s)", peers.len());
            }
            return Ok(());
        }
        "nat" => {
            eprintln!("Detecting NAT type (querying STUN servers)...");
            let info = mrsh_relay::stun::detect_nat_type(
                std::time::Duration::from_secs(3),
            ).await;
            println!("NAT type: {}", info.nat_type);
            if let Some(addr) = info.external_addr {
                println!("External address: {}", addr);
            }
            return Ok(());
        }
        "wake" => {
            if args.len() < 2 {
                bail!("wake requires a MAC address (aa:bb:cc:dd:ee:ff)");
            }
            mrsh_client::shell::send_wol(&args[1])?;
            println!("WoL packet sent to {}", args[1]);
            return Ok(());
        }
        "recording" => {
            let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if sub == "export" {
                // Local-only: convert .log+.time to asciicast
                let rest = &args[2..];
                let mut width: u32 = 120;
                let mut height: u32 = 35;
                let mut log_file = String::new();
                let mut out_file = String::new();
                for a in rest {
                    if let Some(w) = a.strip_prefix("--width=") {
                        width = w.parse().unwrap_or(120);
                    } else if let Some(h) = a.strip_prefix("--height=") {
                        height = h.parse().unwrap_or(35);
                    } else if log_file.is_empty() {
                        log_file = a.clone();
                    } else {
                        out_file = a.clone();
                    }
                }
                if log_file.is_empty() {
                    bail!("Usage: mrsh recording export <file.log> [output.cast]");
                }
                if out_file.is_empty() {
                    out_file = log_file
                        .strip_suffix(".log")
                        .unwrap_or(&log_file)
                        .to_string()
                        + ".cast";
                }
                mrsh_client::recording::export_asciicast(&log_file, &out_file, width, height)?;
                println!("Exported to {}", out_file);
                return Ok(());
            }
            // "list" with no -h → fall through to client section
            if cli.host.is_none() && sub != "list" {
                bail!("Usage: mrsh recording <export|list>");
            }
            // list with -h falls through to client commands
        }
        "keygen" => {
            let output = args.get(1).map(std::path::PathBuf::from);
            return keygen::run_keygen(output.as_deref());
        }
        "keys" => {
            return keygen::run_keys(&args[1..]);
        }
        "totp-setup" => {
            let fingerprint = args.get(1).map(|s| s.as_str());
            return keygen::run_totp_setup(fingerprint);
        }
        "totp-verify" => {
            if args.len() < 3 {
                bail!("Usage: mrsh totp-verify <fingerprint> <code>");
            }
            return keygen::run_totp_verify(&args[1], &args[2]);
        }
        "cfg" | "config-edit" => {
            mrsh_client::config_tui::run_config_tui()?;
            return Ok(());
        }
        "connect" => {
            match mrsh_client::host_picker::run_host_picker()? {
                mrsh_client::host_picker::PickerResult::Selected(host) => {
                    let target = host.hostname.as_deref().unwrap_or(&host.pattern);
                    let port = if host.port > 0 { host.port } else { 8822 };
                    eprintln!("Connecting to {} ({}:{})...", host.pattern, target, port);
                    let opts = ConnectOptions {
                        host: target.to_string(),
                        port,
                        key_path: host.identity_file.clone(),
                        password_user: cli.user.clone(),
                    };
                    let mut client = mrsh_client::client::connect(&opts).await?;
                    mrsh_client::shell::run_shell(&mut client, &[]).await?;
                    return Ok(());
                }
                mrsh_client::host_picker::PickerResult::Cancelled => {
                    return Ok(());
                }
            }
        }
        "log" => {
            return local_cmds::run_log_query(&args[1..]);
        }
        "logs" => {
            mrsh_client::log_viewer::run_log_viewer()?;
            return Ok(());
        }
        "dash" | "dashboard" => {
            mrsh_client::dashboard::run_dashboard().await?;
            return Ok(());
        }
        "pack" | "install-pack" => {
            return local_cmds::run_install_pack(&args[1..]);
        }
        "relay" => {
            return fleet_cmd::run_relay_server(&args[1..]).await;
        }
        "rdv" | "rendezvous" => {
            return fleet_cmd::run_rendezvous_server(&args[1..]).await;
        }
        _ => {}
    }

    // ── --mux-stop: stop running master ─────────────────────
    if cli.mux_stop {
        let host = cli.host.as_deref().unwrap_or_else(|| {
            eprintln!("error: -h <host> required for --mux-stop");
            std::process::exit(1);
        });
        return mrsh_client::mux::stop_master(host, cli.port.unwrap_or(DEFAULT_PORT)).await;
    }

    // ── Server mode: no -h, no local command ────────────────
    if cli.host.is_none() && !LOCAL_COMMANDS.contains(&cmd) {
        #[cfg(target_os = "windows")]
        {
            // Windows: default to tray server mode (user session, port 9822)
            info!("no -h flag, launching tray server mode");
            return server_mode::run_server_mode(TRAY_PORT, true).await;
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Linux: default to foreground server mode (port 8822)
            info!("no -h flag, launching server mode");
            return server_mode::run_server_mode(DEFAULT_PORT, false).await;
        }
    }

    // ── Client commands (require -h) ─────────────────────────
    let host = cli.host.as_deref().unwrap_or_else(|| {
        eprintln!("error: -h <host> required");
        std::process::exit(1);
    });

    // Resolve from config
    let config = mrsh_core::config::Config::load();
    let host_config = config.find_host(host);
    let port_explicit = cli.port.is_some(); // user passed -p explicitly
    let (resolved_host, mut resolved_port, port_from_config) = if let Some(hc) = host_config {
        let cfg_port = hc.port;
        (
            hc.hostname.as_deref().unwrap_or(host).to_string(),
            cli.port.unwrap_or(cfg_port),
            cli.port.is_none() && cfg_port != 8822, // config specified non-default port
        )
    } else {
        (host.to_string(), cli.port.unwrap_or(DEFAULT_PORT), false)
    };
    // Auto-try ports when neither -p nor config specified a port
    let auto_try_ports = !port_explicit && !port_from_config;

    // ── Auto-mux: try UDS before opening new connection ──────
    if !cli.no_mux && !cli.master
        && let Some(mux_req) = mrsh_client::mux::build_mux_request(cmd, args)
            && let Some(resp) = mrsh_client::mux::try_request(host, resolved_port, &mux_req).await {
                if resp.success {
                    if let Some(ref output) = resp.output {
                        print!("{}", output);
                    }
                } else {
                    let msg = resp.error.as_deref().unwrap_or("unknown error");
                    eprintln!("error: {}", msg);
                    std::process::exit(1);
                }
                return Ok(());
            }
            // No master running → fall through to normal connect

    // Check for DeviceID — from config or raw host
    let device_id = host_config
        .and_then(|hc| hc.device_id.clone())
        .or_else(|| {
            if mrsh_relay::rendezvous::is_device_id(host) {
                Some(host.to_string())
            } else {
                None
            }
        });

    // ── QUIC transport (experimental, --quic flag) ───────────
    #[cfg(feature = "quic")]
    if cli.use_quic {
        use anyhow::Context as _;
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", resolved_host, resolved_port)
            .to_socket_addrs()
            .context("resolve host")?
            .next()
            .with_context(|| format!("no address for {}", resolved_host))?;

        let quic = mrsh_client::quic::QuicClient::connect(
            addr,
            &resolved_host,
            cli.key.as_deref(),
        )
        .await
        .context("QUIC connect")?;

        // ── QUIC SOCKS5 (-D flag) ─────────────────────────────
        if let Some(socks_port) = cli.dynamic_port {
            use std::sync::Arc;
            use tokio::net::TcpListener;

            eprintln!(
                "SOCKS5 proxy (QUIC): 127.0.0.1:{} → {}:{}",
                socks_port, resolved_host, resolved_port
            );

            let quic = Arc::new(quic);
            let bind_addr = format!("127.0.0.1:{}", socks_port);
            let listener = TcpListener::bind(&bind_addr)
                .await
                .with_context(|| format!("SOCKS5: bind {}", bind_addr))?;
            eprintln!("SOCKS5 proxy listening on {}", bind_addr);

            loop {
                let (client_stream, peer) = listener.accept().await?;
                client_stream.set_nodelay(true).ok();
                let quic = Arc::clone(&quic);

                tokio::spawn(async move {
                    if let Err(e) = handle_quic_socks5_conn(client_stream, &quic).await {
                        tracing::debug!("SOCKS5/QUIC: {} error: {}", peer, e);
                    }
                });
            }
        }

        match cmd {
            "ping" => {
                println!("PONG (QUIC)");
            }
            "exec" => {
                if args.len() < 2 {
                    bail!("exec requires a command");
                }
                let command = args[1..].join(" ");
                let output = quic.exec(&command).await?;
                print!("{}", output);
            }
            "push" => {
                if args.len() < 3 {
                    bail!("push requires <local> <remote>");
                }
                let data = std::fs::read(&args[1])?;
                let written = quic.push(&args[2], &data).await?;
                println!("pushed {} bytes to {}", written, args[2]);
            }
            "pull" | "cat" => {
                if args.len() < 2 {
                    bail!("{} requires <remote> [local]", cmd);
                }
                let data = quic.pull(&args[1]).await?;
                if cmd == "cat" || args.len() < 3 {
                    std::io::Write::write_all(&mut std::io::stdout(), &data)?;
                } else {
                    std::fs::write(&args[2], &data)?;
                    println!("pulled {} bytes to {}", data.len(), args[2]);
                }
            }
            "ls" => {
                let path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
                let files = quic.ls(path).await?;
                for f in &files {
                    let kind = if f.is_dir { "d" } else { "-" };
                    println!("{}{} {:>10} {} {}", kind, f.mode, f.size, f.mod_time, f.name);
                }
            }
            "tunnel" => {
                if args.len() < 3 {
                    bail!("tunnel requires: <local_bind> <remote_host:port>");
                }
                let (local_bind, remote_target) =
                    mrsh_client::tunnel::parse_tunnel_spec(&args[1], &args[2])?;
                eprintln!(
                    "tunnel (QUIC): {} → {} via {}",
                    local_bind, remote_target, resolved_host
                );
                let listener = tokio::net::TcpListener::bind(&local_bind)
                    .await
                    .with_context(|| format!("bind {}", local_bind))?;
                eprintln!("listening on {}", listener.local_addr()?);
                let (local_stream, peer) = listener.accept().await?;
                local_stream.set_nodelay(true).ok();
                eprintln!("tunnel: local connection from {}", peer);
                let (mut quic_send, mut quic_recv) = quic.open_tunnel(&remote_target).await?;
                let (mut tcp_read, mut tcp_write) = local_stream.into_split();
                tokio::select! {
                    _ = tokio::io::copy(&mut quic_recv, &mut tcp_write) => {}
                    _ = tokio::io::copy(&mut tcp_read, &mut quic_send) => {}
                }
            }
            "shell" => {
                mrsh_client::shell::run_quic_shell(&quic).await?;
            }
            // ── Fleet ops: route through exec with native-equivalent PowerShell ──
            "info" => {
                let output = quic.exec("[PSCustomObject]@{Hostname=$env:COMPUTERNAME; OS=[Environment]::OSVersion.VersionString; Arch=[Environment]::Is64BitOperatingSystem} | ConvertTo-Json").await?;
                println!("{}", output);
            }
            "ps" => {
                let output = quic.exec("Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet64 | ConvertTo-Json").await?;
                println!("{}", output);
            }
            "kill" => {
                if args.len() < 2 {
                    bail!("kill requires a PID");
                }
                let output = quic.exec(&format!("Stop-Process -Id {} -Force", args[1])).await?;
                if !output.is_empty() {
                    println!("{}", output);
                }
            }
            "tail" => {
                if args.len() < 2 {
                    bail!("tail requires <path> [lines]");
                }
                let lines: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
                let escaped = args[1].replace('\'', "''");
                let output = quic.exec(&format!("Get-Content '{}' -Tail {}", escaped, lines)).await?;
                print!("{}", output);
            }
            "filever" => {
                if args.len() < 2 {
                    bail!("filever requires <path>");
                }
                let escaped = args[1].replace('\'', "''");
                let output = quic.exec(&format!("(Get-Item '{}').VersionInfo | ConvertTo-Json", escaped)).await?;
                println!("{}", output);
            }
            "eventlog" | "evtlog" => {
                let log_name = args.get(1).map(|s| s.as_str()).unwrap_or("System");
                let count: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
                let output = quic.exec(&format!(
                    "Get-EventLog -LogName {} -Newest {} | Select-Object TimeGenerated,EntryType,Source,Message | ConvertTo-Json",
                    log_name, count
                )).await?;
                println!("{}", output);
            }
            "ss" | "screenshot" => {
                let display: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                let quality: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(75);
                // Use PowerShell .NET to capture screen and return base64
                let ps_cmd = format!(
                    "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
                     $s = [System.Windows.Forms.Screen]::AllScreens[{}]; \
                     $b = [System.Drawing.Bitmap]::new($s.Bounds.Width, $s.Bounds.Height); \
                     $g = [System.Drawing.Graphics]::FromImage($b); \
                     $g.CopyFromScreen($s.Bounds.Location, [System.Drawing.Point]::Empty, $s.Bounds.Size); \
                     $ms = [System.IO.MemoryStream]::new(); \
                     $ep = [System.Drawing.Imaging.Encoder]::Quality; \
                     $epc = [System.Drawing.Imaging.EncoderParameters]::new(1); \
                     $epc.Param[0] = [System.Drawing.Imaging.EncoderParameter]::new($ep, [long]{}); \
                     $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object {{ $_.MimeType -eq 'image/jpeg' }}; \
                     $b.Save($ms, $codec, $epc); \
                     [Convert]::ToBase64String($ms.ToArray())",
                    display, quality
                );
                let b64_output = quic.exec(&ps_cmd).await?;
                let data = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    b64_output.trim(),
                )
                .context("decode screenshot base64")?;
                let out_path = format!("screenshot_{}.jpg", display);
                std::fs::write(&out_path, &data)?;
                println!("saved {} ({} bytes)", out_path, data.len());
            }
            // ── Clipboard ────────────────────────────────────────────
            "clip" | "clipboard" => {
                let action = args.get(1).map(|s| s.as_str()).unwrap_or("get");
                match action {
                    "get" | "read" => {
                        let output = quic.exec("Get-Clipboard").await?;
                        print!("{}", output);
                    }
                    "set" | "write" | "copy" => {
                        if args.len() < 3 {
                            bail!("clip set requires text");
                        }
                        let text = args[2..].join(" ");
                        let escaped = text.replace('\'', "''");
                        quic.exec(&format!("Set-Clipboard '{}'", escaped)).await?;
                        println!("clipboard set");
                    }
                    other => bail!("unknown clip action: {} (use get|set)", other),
                }
            }
            // ── Service management ───────────────────────────────────
            "service" | "svc" => {
                if args.len() < 2 {
                    bail!("service requires: list|status|start|stop|restart [name]");
                }
                let action = args[1].as_str();
                let name = args.get(2).map(|s| s.as_str());
                let ps_cmd = match (action, name) {
                    ("list", _) => "Get-Service | Select-Object Status,Name,DisplayName | ConvertTo-Json".to_string(),
                    ("status", Some(n)) => format!("Get-Service '{}' | Select-Object Status,Name,DisplayName,StartType | ConvertTo-Json", n),
                    ("start", Some(n)) => format!("Start-Service '{}'; Get-Service '{}' | Select-Object Status,Name | ConvertTo-Json", n, n),
                    ("stop", Some(n)) => format!("Stop-Service '{}' -Force; Get-Service '{}' | Select-Object Status,Name | ConvertTo-Json", n, n),
                    ("restart", Some(n)) => format!("Restart-Service '{}'; Get-Service '{}' | Select-Object Status,Name | ConvertTo-Json", n, n),
                    (_, None) => bail!("service {} requires a service name", action),
                    (other, _) => bail!("unknown service action: {} (use list|status|start|stop|restart)", other),
                };
                let output = quic.exec(&ps_cmd).await?;
                println!("{}", output);
            }
            // ── Write file ───────────────────────────────────────────
            "write" => {
                if args.len() < 3 {
                    bail!("write requires <remote-path> <content>");
                }
                let content = args[2..].join(" ");
                let written = quic.push(&args[1], content.as_bytes()).await?;
                println!("wrote {} bytes to {}", written, args[1]);
            }
            // ── Self-update ──────────────────────────────────────────
            "self-update" => {
                if args.len() < 2 {
                    bail!("self-update requires <remote-binary-path>");
                }
                let escaped = args[1].replace('\'', "''");
                let output = quic.exec(&format!(
                    "$src = '{}'; \
                     $exe = (Get-Process -Id $PID).Path; \
                     $bak = $exe + '.old'; \
                     if (Test-Path $bak) {{ Remove-Item $bak -Force }}; \
                     Rename-Item $exe $bak; \
                     Copy-Item $src $exe; \
                     Remove-Item $src -Force; \
                     'OK: restart service to apply'",
                    escaped
                )).await?;
                println!("{}", output);
            }
            // ── GUI automation ───────────────────────────────────────
            "input" | "mouse" | "key" | "window" => {
                if args.len() < 3 {
                    bail!("{} requires <action> <args>", cmd);
                }
                // Forward as native exec — server handles via input handler
                let full_cmd = args.join(" ");
                let output = quic.exec(&full_cmd).await?;
                if !output.is_empty() {
                    println!("{}", output);
                }
            }
            // ── Power management ─────────────────────────────────────
            "reboot" => {
                let force = args.get(1).map(|s| s == "-f" || s == "--force").unwrap_or(false);
                if !force {
                    eprint!("Reboot {}:{}? [y/N] ", resolved_host, resolved_port);
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer)?;
                    let a = answer.trim().to_lowercase();
                    if a != "y" && a != "yes" && a != "si" {
                        return Ok(());
                    }
                }
                println!("Rebooting {}:{}...", resolved_host, resolved_port);
                quic.exec("Restart-Computer -Force").await.ok();
            }
            "shutdown" => {
                let force = args.get(1).map(|s| s == "-f" || s == "--force").unwrap_or(false);
                if !force {
                    eprint!("Shutdown {}:{}? [y/N] ", resolved_host, resolved_port);
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer)?;
                    let a = answer.trim().to_lowercase();
                    if a != "y" && a != "yes" && a != "si" {
                        return Ok(());
                    }
                }
                println!("Shutting down {}:{}...", resolved_host, resolved_port);
                quic.exec("Stop-Computer -Force").await.ok();
                println!("Shutdown command sent.");
            }
            "sleep" => {
                let force = args.get(1).map(|s| s == "-f" || s == "--force").unwrap_or(false);
                if !force {
                    eprint!("Sleep {}:{}? [y/N] ", resolved_host, resolved_port);
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer)?;
                    let a = answer.trim().to_lowercase();
                    if a != "y" && a != "yes" && a != "si" {
                        return Ok(());
                    }
                }
                println!("Putting {}:{} to sleep...", resolved_host, resolved_port);
                quic.exec(
                    "Add-Type -Assembly System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $true, $false)"
                ).await.ok();
                println!("Sleep command sent.");
            }
            "lock" => {
                println!("Locking workstation on {}:{}...", resolved_host, resolved_port);
                quic.exec("rundll32.exe user32.dll,LockWorkStation").await?;
                println!("Workstation locked.");
            }
            // ── Status (multi-ping with RTT stats) ───────────────────
            "status" => {
                let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
                let mut rtts = Vec::with_capacity(count);
                let mut failures = 0usize;
                println!("--- {} (QUIC) ---", resolved_host);
                for i in 0..count {
                    let start = std::time::Instant::now();
                    match quic.exec("echo PONG").await {
                        Ok(_) => {
                            let elapsed = start.elapsed();
                            eprintln!("  ping {}: {:.1?}", i + 1, elapsed);
                            rtts.push(elapsed);
                        }
                        Err(e) => {
                            failures += 1;
                            eprintln!("  ping {}: FAILED ({})", i + 1, e);
                        }
                    }
                    if i < count - 1 {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
                if !rtts.is_empty() {
                    let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                    let min = rtts.iter().min().unwrap();
                    let max = rtts.iter().max().unwrap();
                    let mut sorted = rtts.clone();
                    sorted.sort();
                    let p50 = sorted[sorted.len() / 2];
                    let loss = (failures as f64 / count as f64) * 100.0;

                    println!("--- {} (QUIC) ping statistics ---", resolved_host);
                    println!("{} transmitted, {} received, {:.0}% loss", count, rtts.len(), loss);
                    println!("rtt min/avg/max/p50 = {:.1?}/{:.1?}/{:.1?}/{:.1?}", min, avg, max, p50);

                    let jitter = if rtts.len() >= 2 {
                        let avg_ns = avg.as_nanos() as f64;
                        let sum_sq: f64 = rtts.iter().map(|d| {
                            let diff = d.as_nanos() as f64 - avg_ns;
                            diff * diff
                        }).sum();
                        std::time::Duration::from_nanos((sum_sq / rtts.len() as f64).sqrt() as u64)
                    } else {
                        std::time::Duration::ZERO
                    };
                    println!("jitter: {:.1?}", jitter);

                    let quality = if loss > 50.0 {
                        "POOR (high packet loss)"
                    } else if avg > std::time::Duration::from_millis(500) {
                        "POOR (high latency)"
                    } else if loss > 10.0
                        || avg > std::time::Duration::from_millis(200)
                        || jitter > std::time::Duration::from_millis(100)
                    {
                        "FAIR"
                    } else if avg > std::time::Duration::from_millis(50)
                        || jitter > std::time::Duration::from_millis(20)
                    {
                        "GOOD"
                    } else {
                        "EXCELLENT"
                    };
                    println!("quality: {}", quality);
                }
            }
            // ── Cache management ─────────────────────────────────────
            "cache" => {
                if args.len() < 2 {
                    bail!("cache requires: stats|index [path]");
                }
                match args[1].as_str() {
                    "stats" => {
                        let output = quic.exec("if (Test-Path 'C:\\ProgramData\\mrsh\\cache') { Get-ChildItem 'C:\\ProgramData\\mrsh\\cache' -Recurse | Measure-Object -Property Length -Sum | Select-Object Count,Sum | ConvertTo-Json } else { '{\"Count\":0,\"Sum\":0}' }").await?;
                        println!("{}", output);
                    }
                    "index" => {
                        if args.len() < 3 {
                            bail!("cache index requires <remote-path>");
                        }
                        let escaped = args[2].replace('\'', "''");
                        let output = quic.exec(&format!(
                            "Get-ChildItem '{}' -Recurse | Select-Object FullName,Length,LastWriteTime | ConvertTo-Json",
                            escaped
                        )).await?;
                        println!("{}", output);
                    }
                    other => bail!("unknown cache action: {} (use stats|index)", other),
                }
            }
            // ── Plugin management ────────────────────────────────────
            "plugin" => {
                if args.len() < 2 {
                    bail!("plugin requires <action> [args...]");
                }
                let plugin_cmd = args[1..].join(" ");
                let output = quic.exec(&format!("mrsh plugin {}", plugin_cmd)).await?;
                if !output.is_empty() {
                    println!("{}", output);
                }
            }
            // ── Recording list ───────────────────────────────────────
            "recording" => {
                let output = quic.exec("if (Test-Path 'C:\\ProgramData\\mrsh\\recordings') { Get-ChildItem 'C:\\ProgramData\\mrsh\\recordings' -Filter '*.cast' | Select-Object Name,Length,LastWriteTime | ConvertTo-Json } else { '[]' }").await?;
                println!("{}", output);
            }
            // ── Server version ───────────────────────────────────────
            "server-version" => {
                println!("{}", quic.server_version.as_deref().unwrap_or("unknown"));
            }
            // ── TUI-only commands (not applicable over QUIC) ─────────
            "sessions" | "attach" | "browse" | "sftp" => {
                bail!("command {:?} requires TUI mode (omit --quic)", cmd);
            }
            // ── Unknown → try as exec ────────────────────────────────
            _ => {
                let command = args.join(" ");
                let output = quic.exec(&command).await?;
                print!("{}", output);
            }
        }
        quic.close();
        return Ok(());
    }

    // Determine if host was specified as a bare DeviceID (numeric-only).
    // If so, relay is the ONLY path. If host is IP/hostname with DeviceID
    // from config, try direct first with relay as fallback.
    let host_is_device_id = mrsh_relay::rendezvous::is_device_id(host);

    // Helper: build relay options from config + device_id
    #[cfg(not(feature = "no-relay"))]
    let make_relay_opts = |dev_id: &str, port: u16| mrsh_client::relay_connect::RelayConnectOptions {
        device_id: dev_id.to_string(),
        rendezvous_server: config
            .rendezvous_server
            .as_deref()
            .unwrap_or("localhost:21116")
            .to_string(),
        rendezvous_key: config.rendezvous_key.clone().unwrap_or_default(),
        key_path: cli.key.clone(),
        server_name: resolved_host.clone(),
        port,
        target_port: if auto_try_ports { 0 } else { port },
        force_relay: false,
        enrollment_token: config.enrollment_token.clone().unwrap_or_default(),
    };

    let mut client = if host_is_device_id {
        // Bare DeviceID: relay is the only path
        #[cfg(feature = "no-relay")]
        bail!("relay connections disabled in this build");
        #[cfg(not(feature = "no-relay"))]
        {
            let dev_id = device_id.as_ref().unwrap();
            mrsh_client::relay_connect::connect_via_relay(&make_relay_opts(dev_id, resolved_port)).await?
        }
    } else {
        // IP/hostname: try direct first
        let direct_opts = ConnectOptions {
            host: resolved_host.clone(),
            port: resolved_port,
            key_path: cli.key.clone(),
            password_user: cli.user.clone(),
        };
        let direct_result = if auto_try_ports {
            mrsh_client::client::connect_auto_try(&direct_opts).await
                .map(|(c, p)| { resolved_port = p; c })
        } else {
            mrsh_client::client::connect(&direct_opts).await
        };

        match direct_result {
            Ok(client) => client,
            Err(direct_err) => {
                // Direct TLS failed — try relay fallback if DeviceID available
                #[cfg(not(feature = "no-relay"))]
                if let Some(ref dev_id) = device_id {
                    tracing::debug!("direct failed, trying relay via {}", dev_id);
                    match mrsh_client::relay_connect::connect_via_relay(&make_relay_opts(dev_id, resolved_port)).await {
                        Ok(client) => {
                            eprintln!("connected via relay (direct failed)");
                            client
                        }
                        Err(_) => {
                            // Relay also failed — try SSH fallback on port 22
                            if mrsh_client::ssh_client::ssh_client_available() {
                                tracing::debug!("relay failed, trying SSH on port 22");
                                return run_ssh_fallback(&resolved_host, 22, &cli.key, cmd, &args).await;
                            }
                            return Err(direct_err);
                        }
                    }
                } else {
                    // No relay — try SSH fallback on port 22
                    if mrsh_client::ssh_client::ssh_client_available() {
                        tracing::debug!("direct TLS failed, trying SSH on port 22");
                        return run_ssh_fallback(&resolved_host, 22, &cli.key, cmd, &args).await;
                    }
                    return Err(direct_err);
                }
            }
        }
    };

    // ── Save server's DeviceID + rendezvous to client config ───
    if client.server_device_id.is_some() || client.server_rendezvous.is_some() {
        let mut cfg = mrsh_core::config::Config::load();
        if cfg.update_host_relay_info(
            &host,
            client.server_device_id.as_deref(),
            client.server_rendezvous.as_deref(),
        ) {
            if let Err(e) = cfg.save() {
                tracing::debug!("failed to save relay info to config: {}", e);
            } else {
                tracing::debug!(
                    "saved relay info for {}: device_id={:?}, rdv={:?}",
                    host, client.server_device_id, client.server_rendezvous
                );
            }
        }
    }

    // ── Show server instance info ──────────────────────────────
    // Always show for interactive commands; with -v for others.
    let is_interactive_cmd = matches!(cmd, "shell" | "attach" | "browse" | "sftp" | "connect" | "dash" | "logs");
    if cli.verbose > 0 || is_interactive_cmd {
        eprintln!("{}", client.describe_instance(resolved_port));
    }

    // Warn if running desktop-dependent command on SYSTEM service
    if client.is_system() {
        let desktop_cmds = ["screenshot", "ss", "window", "clip"];
        if desktop_cmds.contains(&cmd) {
            eprintln!(
                "warning: {} may not work on SYSTEM service (no desktop).\n\
                 \x20 Use tray instead: mrsh -h {} -p 9822 {}",
                cmd, host, args.join(" ")
            );
        }
    }

    // ── Control master mode (-M) ──────────────────────────────
    if cli.master {
        return mrsh_client::mux::run_master(host, resolved_port, client).await;
    }

    // ── Session logging ────────────────────────────────────────
    let tracker = if config.is_session_log_enabled(host) {
        let cmd_args = if args.len() > 1 {
            Some(args[1..].join(" "))
        } else {
            None
        };
        // Rotate old logs on session start (cheap: just readdir)
        let log_dir = config.session_log_dir();
        mrsh_client::session_log::rotate_logs(&log_dir, config.session_log_retain);
        Some(mrsh_client::session_log::SessionTracker::start(
            host,
            resolved_port,
            cmd,
            cmd_args.as_deref(),
            &log_dir,
        ))
    } else {
        None
    };

    // ── SOCKS5 dynamic proxy (-D flag) ───────────────────────
    if let Some(socks_port) = cli.dynamic_port {
        // Drop the initial client — SOCKS5 creates new connections per request
        drop(client);

        let connect_opts = Arc::new(ConnectOptions {
            host: resolved_host.clone(),
            port: resolved_port,
            key_path: cli.key.clone(),
            password_user: cli.user.clone(),
        });

        eprintln!(
            "SOCKS5 proxy: 127.0.0.1:{} → {}:{}",
            socks_port, resolved_host, resolved_port
        );

        let connect_fn = move || {
            let opts = connect_opts.clone();
            async move {
                let client = mrsh_client::client::connect(&opts).await?;
                Ok(client.into_stream())
            }
        };

        mrsh_client::socks::run_socks5(socks_port, connect_fn).await?;
        return Ok(());
    }

    // Streaming exec runs without outer timeout — output flow keeps connection alive.
    if cmd == "exec" && client.supports_stream_exec() {
        if args.len() < 2 {
            bail!("exec requires a command");
        }
        let raw_command = args[1..].join(" ");
        // Prepend shell prefix if --cmd or --sh flag used
        let command = if cli.use_cmd {
            format!("CMD:{}", raw_command)
        } else if cli.use_sh {
            format!("SH:{}", raw_command)
        } else {
            raw_command
        };
        let exit_code = mrsh_client::commands::exec_stream(&mut client, &command, &[]).await?;
        // Finish session log
        if let Some(tracker) = tracker {
            tracker.finish(exit_code);
        }
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    // Determine operation timeout: explicit --timeout overrides per-command defaults.
    let timeout_secs = compute_timeout_secs(cli.timeout, cmd);

    let cmd_future = async {
    match cmd {
        "ping" => {
            let result = mrsh_client::commands::ping(&mut client).await?;
            println!("{}", result);
        }
        "exec" => {
            // Fallback: buffered exec for servers without stream-exec capability
            if args.len() < 2 {
                bail!("exec requires a command");
            }
            let raw_command = args[1..].join(" ");
            let command = if cli.use_cmd {
                format!("CMD:{}", raw_command)
            } else if cli.use_sh {
                format!("SH:{}", raw_command)
            } else {
                raw_command
            };
            let result = mrsh_client::commands::exec(&mut client, &command, &[]).await?;
            print!("{}", result);
        }
        "ls" => {
            let path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            let files = mrsh_client::commands::ls(&mut client, path).await?;
            for f in &files {
                let kind = if f.is_dir { "d" } else { "-" };
                println!(
                    "{}{} {:>10} {} {}",
                    kind, f.mode, f.size, f.mod_time, f.name
                );
            }
        }
        "cat" => {
            if args.len() < 2 {
                bail!("cat requires a path");
            }
            let text = mrsh_client::commands::cat_text(&mut client, &args[1]).await?;
            print!("{}", text);
        }
        "push" => {
            if args.len() < 3 {
                bail!("push requires <local> <remote>");
            }
            let local_path = std::path::Path::new(&args[1]);
            let meta = std::fs::metadata(local_path)
                .map_err(|e| anyhow::anyhow!("cannot stat {}: {}", args[1], e))?;
            let xfer_opts = mrsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            if meta.is_dir() {
                let result = mrsh_client::sync::push_dir(&mut client, local_path, &args[2], &xfer_opts).await?;
                eprintln!(
                    "pushed directory: {}/{} files, {} bytes",
                    result.files_transferred, result.files_total, result.bytes_total
                );
                if cli.delete {
                    let deleted = mrsh_client::sync::delete_remote_extras(
                        &mut client, local_path, &args[2],
                    ).await?;
                    if deleted > 0 {
                        println!("--delete: removed {} remote files", deleted);
                    }
                }
            } else {
                if cli.dry_run {
                    eprintln!("[dry-run] would push {} -> {}", args[1], args[2]);
                } else {
                    let result = mrsh_client::sync::push_file(&mut client, local_path, &args[2]).await?;
                    println!(
                        "pushed {} bytes to {} (delta: {})",
                        result.bytes_sent, result.path, result.delta
                    );
                }
            }
        }
        "pull" => {
            if args.len() < 3 {
                bail!("pull requires <remote> <local>");
            }
            let xfer_opts = mrsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            // Check if remote is a directory (ls succeeds on dirs)
            let is_dir = {
                let files = mrsh_client::commands::ls(&mut client, &args[1]).await;
                files.is_ok()
            };
            if is_dir {
                let local_path = std::path::Path::new(&args[2]);
                let result = mrsh_client::sync::pull_dir(&mut client, &args[1], local_path, &xfer_opts).await?;
                println!(
                    "pulled directory: {}/{} files, {} bytes",
                    result.files_transferred, result.files_total, result.bytes_total
                );
            } else {
                if cli.dry_run {
                    eprintln!("[dry-run] would pull {} -> {}", args[1], args[2]);
                } else {
                    let local_data = std::fs::read(&args[2]).ok();
                    let result =
                        mrsh_client::sync::pull(&mut client, local_data.as_deref(), &args[1]).await?;
                    std::fs::write(&args[2], &result.data)?;
                    println!(
                        "pulled {} bytes (delta: {})",
                        result.data.len(),
                        result.delta
                    );
                }
            }
        }
        "screenshot" => {
            let display_idx: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let quality: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(75);
            let scale: u8 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100);
            let data =
                mrsh_client::commands::screenshot(&mut client, display_idx, quality, scale).await?;
            let out_path = format!("screenshot_{}.jpg", display_idx);
            std::fs::write(&out_path, &data)?;
            println!("saved {} ({} bytes)", out_path, data.len());
        }
        "sessions" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("list");
            match action {
                "list" => {
                    let result = mrsh_client::commands::sessions_list(&mut client).await?;
                    println!("{}", result);
                }
                "kill" => {
                    if args.len() < 3 {
                        bail!("sessions kill requires <session-id>");
                    }
                    mrsh_client::commands::session_kill(&mut client, &args[2]).await?;
                    println!("session killed");
                }
                other => bail!("unknown sessions action: {}", other),
            }
        }
        "shell" => {
            let env_vars: Vec<String> = args.iter().skip(1).cloned().collect();
            mrsh_client::shell::run_shell(&mut client, &env_vars).await?;
        }
        "attach" => {
            // attach [session-id] [--ro]
            let mut session_id = "";
            let mut read_only = false;
            let mut env_vars = Vec::new();
            for arg in args.iter().skip(1) {
                match arg.as_str() {
                    "--ro" | "--read-only" | "-r" => read_only = true,
                    s if !s.starts_with('-') && session_id.is_empty() => session_id = s,
                    _ => env_vars.push(arg.clone()),
                }
            }
            mrsh_client::shell::run_attach(&mut client, session_id, read_only, &env_vars).await?;
        }
        "browse" => {
            let start_path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            // browse is synchronous TUI — bridge async client via Handle
            let handle = tokio::runtime::Handle::current();
            // RefCell borrow held across block_on is safe: closures run synchronously
            use std::cell::RefCell;
            let client_cell = RefCell::new(client);
            mrsh_client::browse::run_browser(
                start_path,
                |dir_path| {
                    let mut c = client_cell.borrow_mut();
                    let result = handle.block_on(mrsh_client::commands::ls(&mut *c, dir_path));
                    result.map_err(|e| e.to_string())
                },
                |remote_path, local_path| {
                    let mut c = client_cell.borrow_mut();
                    let result =
                        handle.block_on(mrsh_client::sync::pull(&mut *c, None, remote_path));
                    match result {
                        Ok(pr) => {
                            if let Err(e) = std::fs::write(local_path, &pr.data) {
                                eprintln!("write error: {}", e);
                            } else {
                                println!("saved {} ({} bytes)", local_path, pr.data.len());
                            }
                        }
                        Err(e) => eprintln!("pull error: {}", e),
                    }
                },
            );
            // Recover client for clean shutdown
            client = client_cell.into_inner();
            drop(client);
            return Ok(());
        }
        "sftp" => {
            let host_display = cli.host.as_deref().unwrap_or("unknown");
            mrsh_client::sftp::run_sftp(&mut client, host_display).await?;
        }
        "tunnel" => {
            // mrsh -h host tunnel <local_bind> <remote_host:remote_port>
            // mrsh -h host tunnel 127.0.0.1:5432 db-server:5432
            // mrsh -h host tunnel 5432 db-server:5432
            if args.len() < 3 {
                bail!("tunnel requires: <local_bind> <remote_host:port>");
            }
            let (local_bind, remote_target) =
                mrsh_client::tunnel::parse_tunnel_spec(&args[1], &args[2])?;
            eprintln!("tunnel: {} → {} via {}", local_bind, remote_target, resolved_host);

            // Persistent tunnel: reconnects for each accepted local connection.
            // Must use the same connection method (relay vs direct) as the original.
            let tunnel_device_id = device_id.clone();
            let tunnel_config = config.clone();
            let tunnel_host = resolved_host.clone();
            let tunnel_auto_try = auto_try_ports;
            let tunnel_port = resolved_port;
            let tunnel_key = cli.key.clone();
            mrsh_client::tunnel::run_tunnel_persistent(
                move || {
                    let dev_id = tunnel_device_id.clone();
                    let cfg = tunnel_config.clone();
                    let host = tunnel_host.clone();
                    let port = tunnel_port;
                    let key = tunnel_key.clone();
                    async move {
                        let client = if let Some(ref did) = dev_id {
                            // Relay path
                            let relay_opts = mrsh_client::relay_connect::RelayConnectOptions {
                                device_id: did.clone(),
                                rendezvous_server: cfg
                                    .rendezvous_server
                                    .as_deref()
                                    .unwrap_or("localhost:21116")
                                    .to_string(),
                                rendezvous_key: cfg.rendezvous_key.clone().unwrap_or_default(),
                                key_path: key,
                                server_name: host,
                                port,
                                target_port: if tunnel_auto_try { 0 } else { port },
                                force_relay: true, // skip 5s P2P timeout on tunnel reconnects
                                enrollment_token: cfg.enrollment_token.clone().unwrap_or_default(),
                            };
                            mrsh_client::relay_connect::connect_via_relay(&relay_opts).await?
                        } else {
                            // Direct path
                            let opts = ConnectOptions {
                                host,
                                port,
                                key_path: key,
                                password_user: None,
                            };
                            mrsh_client::client::connect(&opts).await?
                        };
                        Ok(client.into_stream())
                    }
                },
                &local_bind,
                &remote_target,
            ).await?;
        }
        "recording" => {
            // Only "list" reaches here (export handled in local section)
            let output = mrsh_client::recording::list_remote(&mut client).await?;
            print!("{}", output);
        }
        "write" => {
            if args.len() < 3 {
                bail!("write requires <remote-path> <content>");
            }
            let content = args[2..].join(" ");
            mrsh_client::commands::write_file(&mut client, &args[1], content.as_bytes()).await?;
            println!("wrote {} bytes to {}", content.len(), args[1]);
        }
        "self-update" => {
            if args.len() < 2 {
                bail!("self-update requires <remote-binary-path>");
            }
            let result = mrsh_client::commands::self_update(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "input" => {
            // mrsh -h host input mouse pos
            // mrsh -h host input mouse move 500,300
            if args.len() < 3 {
                bail!("input requires <type> <action> [args...]");
            }
            let extra = if args.len() > 3 {
                args[3..].join(" ")
            } else {
                String::new()
            };
            let result =
                mrsh_client::commands::input(&mut client, &args[1], &args[2], &extra)
                    .await?;
            println!("{}", result);
        }
        "ps" => {
            let result = mrsh_client::commands::ps(&mut client).await?;
            println!("{}", result);
        }
        "kill" => {
            if args.len() < 2 {
                bail!("kill requires a PID");
            }
            let result = mrsh_client::commands::kill_process(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "tail" => {
            if args.len() < 2 {
                bail!("tail requires <path> [lines]");
            }
            let lines: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            let result = mrsh_client::commands::tail(&mut client, &args[1], lines).await?;
            print!("{}", result);
        }
        "rlog" | "remote-log" => {
            // Remote log query: mrsh -h host rlog <path> [--grep pattern] [--tail N] [--max N] [-i]
            if args.len() < 2 {
                bail!("Usage: mrsh -h host rlog <path> [--grep pattern] [--tail N] [--max N] [-i]");
            }
            let path = &args[1];
            let mut pattern = String::new();
            let mut tail_lines: u32 = 0;
            let mut max_matches: u32 = 0;
            let mut flags: u8 = 0;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--grep" | "-g" => { i += 1; if let Some(p) = args.get(i) { pattern = p.clone(); } }
                    "--tail" | "-n" => { i += 1; if let Some(n) = args.get(i) { tail_lines = n.parse().unwrap_or(0); } }
                    "--max" | "-m" => { i += 1; if let Some(n) = args.get(i) { max_matches = n.parse().unwrap_or(0); } }
                    "-i" => flags |= mrsh_core::binproto::LOG_FLAG_CASE_INSENSITIVE,
                    "-v" => flags |= mrsh_core::binproto::LOG_FLAG_INVERT,
                    other if other.starts_with("--grep=") => pattern = other[7..].to_string(),
                    other if other.starts_with("--tail=") => tail_lines = other[7..].parse().unwrap_or(0),
                    other if other.starts_with("--max=") => max_matches = other[6..].parse().unwrap_or(0),
                    _ => {}
                }
                i += 1;
            }
            if !client.supports("log-query") {
                bail!("server does not support log-query (upgrade server to v1.7+)");
            }
            let (scanned, matched) = mrsh_client::commands::log_query(
                &mut client, path, &pattern, flags, tail_lines, max_matches
            ).await?;
            eprintln!("--- {} lines scanned, {} matched ---", scanned, matched);
        }
        "filever" => {
            if args.len() < 2 {
                bail!("filever requires <path>");
            }
            let result = mrsh_client::commands::filever(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "info" => {
            let result = mrsh_client::commands::info(&mut client).await?;
            println!("{}", result);
        }
        "eventlog" | "evtlog" => {
            let log_name = args.get(1).map(|s| s.as_str()).unwrap_or("System");
            let count: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
            let result = mrsh_client::commands::eventlog(&mut client, log_name, count).await?;
            println!("{}", result);
        }
        "clip" | "clipboard" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("get");
            match action {
                "get" | "read" => {
                    let result = mrsh_client::commands::clip_get(&mut client).await?;
                    print!("{}", result);
                }
                "set" | "write" | "copy" => {
                    if args.len() < 3 {
                        bail!("clip set requires text");
                    }
                    let text = args[2..].join(" ");
                    let result = mrsh_client::commands::clip_set(&mut client, &text).await?;
                    println!("{}", result);
                }
                "sync" => {
                    let interval_ms: u64 = args.get(2)
                        .and_then(|s| s.strip_prefix("--interval=").or(Some(s.as_str())))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(500);
                    mrsh_client::commands::clip_sync(
                        &mut client,
                        std::time::Duration::from_millis(interval_ms),
                    ).await?;
                }
                other => bail!("unknown clip action: {} (use get|set|sync)", other),
            }
        }
        "service" | "svc" => {
            if args.len() < 2 {
                bail!("service requires: list|status|start|stop|restart [name]");
            }
            let name = args.get(2).map(|s| s.as_str());
            let result = mrsh_client::commands::service(&mut client, &args[1], name).await?;
            println!("{}", result);
        }
        "plugin" => {
            if args.len() < 2 {
                bail!("plugin requires <action> [args...]");
            }
            let plugin_args = args[1..].join(" ");
            let result = mrsh_client::commands::plugin(&mut client, &plugin_args).await?;
            if !result.is_empty() {
                println!("{}", result);
            }
        }
        "reboot" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Reboot {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            println!("Rebooting {}:{}...", resolved_host, resolved_port);
            mrsh_client::commands::exec(&mut client, "Restart-Computer -Force", &[])
                .await
                .ok();
        }
        "shutdown" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Shutdown {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            println!("Shutting down {}:{}...", resolved_host, resolved_port);
            mrsh_client::commands::exec(&mut client, "Stop-Computer -Force", &[])
                .await
                .ok();
            println!("Shutdown command sent.");
        }
        "sleep" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Sleep {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            println!("Putting {}:{} to sleep...", resolved_host, resolved_port);
            mrsh_client::commands::exec(
                &mut client,
                "Add-Type -Assembly System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $true, $false)",
                &[],
            ).await.ok();
            println!("Sleep command sent.");
        }
        "lock" => {
            eprintln!(
                "Locking workstation on {}:{}...",
                resolved_host, resolved_port
            );
            mrsh_client::commands::exec(&mut client, "rundll32.exe user32.dll,LockWorkStation", &[])
                .await?;
            println!("Workstation locked.");
        }
        "mouse" | "key" | "window" => {
            // GUI automation: mrsh -h host mouse move 500 300
            if args.len() < 3 {
                bail!("{} requires <action> <args>", cmd);
            }
            let result =
                mrsh_client::commands::input(&mut client, cmd, &args[1], &args[2..].join(" "))
                    .await?;
            if !result.is_empty() {
                println!("{}", result);
            }
        }
        "cache" => {
            if args.len() < 2 {
                bail!("cache requires: stats|index [path]");
            }
            match args[1].as_str() {
                "stats" => {
                    let req = mrsh_client::commands::build_request("sync", None, None, None);
                    let mut req = req;
                    req.sync_type = Some("cache-stats".to_string());
                    let resp = client.request(&req).await?;
                    if !resp.success {
                        bail!("{}", resp.error.as_deref().unwrap_or("cache stats failed"));
                    }
                    println!("{}", resp.output.unwrap_or_default());
                }
                "index" => {
                    if args.len() < 3 {
                        bail!("cache index requires <remote-path>");
                    }
                    let mut req =
                        mrsh_client::commands::build_request("sync", None, Some(&args[2]), None);
                    req.sync_type = Some("index-dir".to_string());
                    let resp = client.request(&req).await?;
                    if !resp.success {
                        bail!("{}", resp.error.as_deref().unwrap_or("index failed"));
                    }
                    println!("{}", resp.output.unwrap_or_default());
                }
                other => bail!("unknown cache action: {} (use stats|index)", other),
            }
        }
        "status" => {
            let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let mut rtts = Vec::with_capacity(count);
            let mut failures = 0usize;

            for i in 0..count {
                let start = std::time::Instant::now();
                match mrsh_client::commands::ping(&mut client).await {
                    Ok(_) => {
                        let elapsed = start.elapsed();
                        eprintln!("  ping {}: {:.1?}", i + 1, elapsed);
                        rtts.push(elapsed);
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!("  ping {}: FAILED ({})", i + 1, e);
                    }
                }
                if i < count - 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }

            eprintln!();
            if !rtts.is_empty() {
                rtts.sort();
                let min = rtts[0];
                let max = rtts[rtts.len() - 1];
                let p50 = rtts[rtts.len() / 2];
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let loss = failures as f64 / count as f64 * 100.0;

                println!(
                    "--- {}:{} ping statistics ---",
                    resolved_host, resolved_port
                );
                println!(
                    "{} transmitted, {} received, {:.0}% loss",
                    count,
                    rtts.len(),
                    loss
                );
                println!(
                    "rtt min/avg/max/p50 = {:.1?}/{:.1?}/{:.1?}/{:.1?}",
                    min, avg, max, p50
                );

                // Jitter (standard deviation of RTTs)
                let jitter = if rtts.len() >= 2 {
                    let avg_ns = avg.as_nanos() as f64;
                    let sum_sq: f64 = rtts.iter().map(|d| {
                        let diff = d.as_nanos() as f64 - avg_ns;
                        diff * diff
                    }).sum();
                    std::time::Duration::from_nanos((sum_sq / rtts.len() as f64).sqrt() as u64)
                } else {
                    std::time::Duration::ZERO
                };
                println!("jitter: {:.1?}", jitter);

                let quality = if loss > 50.0 {
                    "POOR (high packet loss)"
                } else if avg > std::time::Duration::from_millis(500) {
                    "POOR (high latency)"
                } else if loss > 10.0
                    || avg > std::time::Duration::from_millis(200)
                    || jitter > std::time::Duration::from_millis(100)
                {
                    "FAIR"
                } else if avg > std::time::Duration::from_millis(50)
                    || jitter > std::time::Duration::from_millis(20)
                {
                    "GOOD"
                } else {
                    "EXCELLENT"
                };
                println!("quality: {}", quality);
            }

            // Remote info
            println!("\n--- remote info ---");
            if let Ok(info_json) = mrsh_client::commands::info(&mut client).await {
                println!("{}", info_json)
            }
        }
        "sync-dir" => {
            if args.len() < 3 {
                bail!("sync-dir requires <local-dir> <remote-dir>");
            }
            let xfer_opts = mrsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            let exclude: Vec<String> = args.iter()
                .filter(|a| a.starts_with("--exclude="))
                .map(|a| a.trim_start_matches("--exclude=").to_string())
                .collect();
            let local_path = std::path::Path::new(&args[1]);
            let result = mrsh_client::sync::sync_dir(
                &mut client, local_path, &args[2], &xfer_opts, &exclude,
            ).await?;
            println!(
                "sync-dir: {} pulled, {} pushed, {} unchanged",
                result.pulled, result.pushed, result.unchanged
            );
        }
        "watch" => {
            if args.len() < 3 {
                bail!("watch requires <local-dir> <remote-dir>");
            }
            run_watch(&mut client, &args[1], &args[2]).await?;
        }
        "server-version" => {
            let result = mrsh_client::commands::ping(&mut client).await?;
            println!("{}", result);
        }
        _other => {
            // Unknown command → treat as exec
            let command = args.join(" ");
            let result = mrsh_client::commands::exec(&mut client, &command, &[]).await?;
            print!("{}", result);
        }
    }
    Ok(())
    };

    let cmd_result: Result<()> = if timeout_secs > 0 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            cmd_future,
        ).await {
            Ok(result) => result,
            Err(_) => bail!("operation timed out after {}s (use --timeout to override)", timeout_secs),
        }
    } else {
        cmd_future.await
    };

    // Finish session log
    if let Some(tracker) = tracker {
        tracker.finish(if cmd_result.is_ok() { 0 } else { 1 });
    }

    cmd_result
}






// ── SSH fallback ──────────────────────────────────────────────

/// Connect via SSH and run a command when mrsh TLS is not available.
async fn run_ssh_fallback(
    host: &str,
    port: u16,
    key_path: &Option<String>,
    cmd: &str,
    args: &[String],
) -> Result<()> {
    if !mrsh_client::ssh_client::ssh_client_available() {
        bail!("SSH fallback not available (compile with --features ssh)");
    }
    #[cfg(feature = "ssh")]
    {
        use mrsh_client::ssh_client::SshSession;
        eprintln!("connecting via SSH (port {})...", port);
        let session = SshSession::connect(host, port, key_path).await?;
        let exit_code = server_mode::run_ssh_command(session, cmd, args).await?;
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        Ok(())
    }
    #[cfg(not(feature = "ssh"))]
    {
        let _ = (host, port, key_path, cmd, args);
        bail!("SSH fallback not available");
    }
}

// ── Watch mode ──────────────────────────────────────────────

/// Watch a local directory for changes and auto-push to remote.
async fn run_watch<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
    client: &mut mrsh_client::client::RshClient<S>,
    local_dir: &str,
    remote_dir: &str,
) -> Result<()> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::mpsc;

    let local_dir = std::fs::canonicalize(local_dir)?;
    if !local_dir.is_dir() {
        bail!("{} is not a directory", local_dir.display());
    }

    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&local_dir, RecursiveMode::Recursive)?;

    eprintln!(
        "Watching {} -> {} (Ctrl+C to stop)",
        local_dir.display(),
        remote_dir
    );

    // Debounce: collect changes, flush every 500ms of quiet
    let debounce = std::time::Duration::from_millis(500);
    let mut pending: HashSet<PathBuf> = HashSet::new();

    loop {
        match rx.recv_timeout(debounce) {
            Ok(Ok(event)) => {
                let dominated_by_write =
                    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                if !dominated_by_write {
                    continue;
                }

                for path in event.paths {
                    // Skip directories and hidden/ignored
                    if path.is_dir() {
                        continue;
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str())
                        && name.starts_with('.')
                    {
                        continue;
                    }
                    // Skip common ignores
                    let path_str = path.to_string_lossy();
                    if path_str.contains("node_modules")
                        || path_str.contains("__pycache__")
                        || path_str.contains(".git")
                    {
                        continue;
                    }
                    pending.insert(path);
                }
            }
            Ok(Err(e)) => {
                eprintln!("watch error: {}", e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Debounce expired — flush pending
                if pending.is_empty() {
                    continue;
                }

                let files: Vec<PathBuf> = pending.drain().collect();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 86400;
                let hh = now / 3600;
                let mm = (now % 3600) / 60;
                let ss = now % 60;
                let now = format!("{:02}:{:02}:{:02}", hh, mm, ss);
                eprintln!("\n[{}] Pushing {} file(s)...", now, files.len());

                for path in &files {
                    let rel = path
                        .strip_prefix(&local_dir)
                        .unwrap_or(path)
                        .to_string_lossy();
                    // Convert to Windows remote path
                    let remote_path = format!("{}\\{}", remote_dir, rel.replace('/', "\\"));

                    match mrsh_client::sync::push_file(client, path, &remote_path).await {
                        Ok(result) => {
                            eprintln!(
                                "  {} ({} bytes, delta: {})",
                                rel, result.bytes_sent, result.delta
                            );
                        }
                        Err(e) => {
                            eprintln!("  {} FAILED: {}", rel, e);
                            continue;
                        }
                    }
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 86400;
                let hh = now / 3600;
                let mm = (now % 3600) / 60;
                let ss = now % 60;
                let now = format!("{:02}:{:02}:{:02}", hh, mm, ss);
                eprintln!("[{}] Done.", now);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

// ── QUIC SOCKS5 helper ──────────────────────────────────────

/// Handle one SOCKS5 client connection tunnelled over QUIC.
///
/// Performs the SOCKS5 handshake, extracts the CONNECT target, opens a
/// new QUIC tunnel stream to that target, and relays traffic.
#[cfg(feature = "quic")]
async fn handle_quic_socks5_conn(
    mut client: tokio::net::TcpStream,
    quic: &mrsh_client::quic::QuicClient,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // SOCKS5 version constants
    const V5: u8 = 0x05;
    const CMD_CONNECT: u8 = 0x01;
    const ATYP_IPV4: u8 = 0x01;
    const ATYP_DOMAIN: u8 = 0x03;
    const ATYP_IPV6: u8 = 0x04;
    const REP_SUCCESS: u8 = 0x00;
    const REP_FAILURE: u8 = 0x01;
    const REP_CMD_UNSUPPORTED: u8 = 0x07;
    const REP_ADDR_UNSUPPORTED: u8 = 0x08;

    // Greeting: version + number of auth methods
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    anyhow::ensure!(buf[0] == V5, "not SOCKS5 (version={})", buf[0]);
    let n = buf[1] as usize;
    let mut methods = vec![0u8; n];
    client.read_exact(&mut methods).await?;
    // Respond: no auth required (0x00)
    client.write_all(&[V5, 0x00]).await?;

    // CONNECT request: VER CMD RSV ATYP <addr> <port>
    let mut hdr = [0u8; 4];
    client.read_exact(&mut hdr).await?;
    anyhow::ensure!(hdr[0] == V5, "bad SOCKS5 request version");
    if hdr[1] != CMD_CONNECT {
        client.write_all(&[V5, REP_CMD_UNSUPPORTED, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.ok();
        anyhow::bail!("unsupported SOCKS5 command {}", hdr[1]);
    }
    let target_host = match hdr[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        ATYP_DOMAIN => {
            let len = {
                let mut b = [0u8; 1];
                client.read_exact(&mut b).await?;
                b[0] as usize
            };
            let mut d = vec![0u8; len];
            client.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            let ip = std::net::Ipv6Addr::from(a);
            format!("[{}]", ip)
        }
        atyp => {
            client.write_all(&[V5, REP_ADDR_UNSUPPORTED, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.ok();
            anyhow::bail!("unsupported SOCKS5 address type {}", atyp);
        }
    };
    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf).await?;
    let target_port = u16::from_be_bytes(port_buf);
    let target = format!("{}:{}", target_host, target_port);

    tracing::debug!("SOCKS5/QUIC: CONNECT {}", target);

    // Open QUIC tunnel to target
    match quic.open_tunnel(&target).await {
        Ok((mut quic_send, mut quic_recv)) => {
            // Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (bound to 0.0.0.0:0)
            client.write_all(&[V5, REP_SUCCESS, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await?;
            // Relay bidirectionally
            let (mut tcp_read, mut tcp_write) = client.into_split();
            tokio::select! {
                _ = tokio::io::copy(&mut quic_recv, &mut tcp_write) => {}
                _ = tokio::io::copy(&mut tcp_read, &mut quic_send) => {}
            }
        }
        Err(e) => {
            client.write_all(&[V5, REP_FAILURE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.ok();
            anyhow::bail!("QUIC open_tunnel {}: {}", target, e);
        }
    }
    Ok(())
}


pub(crate) fn get_local_addrs() -> Vec<std::net::Ipv4Addr> {
    let mut addrs = Vec::new();
    // Read from /proc/net/fib_trie on Linux, or use getifaddrs equivalent.
    // Cross-platform: just try binding UDP to discover local IPs.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Try connecting to common LAN gateways to discover our IPs.
        for target in &["192.168.0.1:80", "192.168.1.1:80", "10.0.0.1:80", "172.16.0.1:80"] {
            if sock.connect(target).is_ok()
                && let Ok(local) = sock.local_addr()
                    && let std::net::SocketAddr::V4(v4) = local
                        && !addrs.contains(v4.ip()) {
                            addrs.push(*v4.ip());
                        }
        }
    }
    // Also try to parse from system interfaces
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                for part in s.split_whitespace() {
                    if let Ok(ip) = part.parse::<std::net::Ipv4Addr>() {
                        if !addrs.contains(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
            }
        }
    }
    addrs
}

/// Check if a remote address is on the same /24 subnet as any local address.
pub(crate) fn is_same_lan(remote: std::net::SocketAddr, local_addrs: &[std::net::Ipv4Addr]) -> bool {
    let remote_ip = match remote {
        std::net::SocketAddr::V4(v4) => *v4.ip(),
        _ => return false,
    };
    let remote_octets = remote_ip.octets();
    for local in local_addrs {
        let local_octets = local.octets();
        // Same /24 network
        if remote_octets[0] == local_octets[0]
            && remote_octets[1] == local_octets[1]
            && remote_octets[2] == local_octets[2]
        {
            return true;
        }
    }
    false
}






/// Return ALL possible authorized_keys paths (primary first, then fallbacks).
/// The server should load keys from ALL of these, merging and deduplicating.
pub(crate) fn all_authorized_keys_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // Primary: the data_dir we'd normally use
    let primary = server_data_dir();
    paths.push(primary.join("authorized_keys"));

    #[cfg(target_os = "windows")]
    {
        // System-wide location (service)
        let system_dir = std::path::PathBuf::from(r"C:\ProgramData\mrsh");
        let system_ak = system_dir.join("authorized_keys");
        if !paths.contains(&system_ak) {
            paths.push(system_ak);
        }

        // User home location (tray)
        if let Some(home) = std::env::var_os("USERPROFILE") {
            let user_ak = std::path::PathBuf::from(home).join(".mrsh").join("authorized_keys");
            if !paths.contains(&user_ak) {
                paths.push(user_ak);
            }
        }

        // Legacy location
        let legacy_ak = std::path::PathBuf::from(r"C:\ProgramData\remote-shell").join("authorized_keys");
        if !paths.contains(&legacy_ak) {
            paths.push(legacy_ak);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // System-wide
        let etc_ak = std::path::PathBuf::from("/etc/rsh/authorized_keys");
        if !paths.contains(&etc_ak) {
            paths.push(etc_ak);
        }

        // User home
        if let Some(home) = std::env::var_os("HOME") {
            let user_ak = std::path::PathBuf::from(home).join(".mrsh").join("authorized_keys");
            if !paths.contains(&user_ak) {
                paths.push(user_ak);
            }
        }
    }

    paths
}

pub(crate) fn server_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        let new_dir = std::path::PathBuf::from(r"C:\ProgramData\mrsh");
        let legacy_dir = std::path::PathBuf::from(r"C:\ProgramData\remote-shell");

        // New location exists — use it
        if new_dir.exists() {
            return new_dir;
        }

        // Legacy location exists — migrate critical files then use new dir
        if legacy_dir.exists()
            && std::fs::create_dir_all(&new_dir).is_ok() {
                for name in &[
                    "authorized_keys",
                    "id_ed25519",
                    "id_ed25519.pub",
                    "device_id",
                    "tls_cert.pem",
                    "tls_key.pem",
                    "banner.txt",
                    "revoked_keys",
                ] {
                    let src = legacy_dir.join(name);
                    let dst = new_dir.join(name);
                    if src.exists() && !dst.exists() {
                        let _ = std::fs::copy(&src, &dst);
                    }
                }
                tracing::info!(
                    "migrated data from {} to {}",
                    legacy_dir.display(),
                    new_dir.display()
                );
                return new_dir;
            }

        // Fall back to user home
        if let Some(home) = std::env::var_os("USERPROFILE") {
            return std::path::PathBuf::from(home).join(".mrsh");
        }

        new_dir
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Root/service mode: /etc/rsh/
        if unsafe { libc::geteuid() } == 0 {
            let service_dir = std::path::PathBuf::from("/etc/rsh");
            return service_dir;
        }

        // User mode: ~/.mrsh/
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(".mrsh");
        }

        std::path::PathBuf::from("/etc/rsh")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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

        // Transfer commands: 300s default
        assert_eq!(compute_timeout_secs(0, "push"), 300);
        assert_eq!(compute_timeout_secs(0, "pull"), 300);

        // All other commands: 120s default
        assert_eq!(compute_timeout_secs(0, "ping"), 120);
        assert_eq!(compute_timeout_secs(0, "exec"), 120);
        assert_eq!(compute_timeout_secs(0, "ls"), 120);
        assert_eq!(compute_timeout_secs(0, "cat"), 120);
        assert_eq!(compute_timeout_secs(0, "info"), 120);
        assert_eq!(compute_timeout_secs(0, "kill"), 120);
        assert_eq!(compute_timeout_secs(0, "screenshot"), 120);
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
        let cli = Cli::try_parse_from(["mrsh", "-h", "host", "--timeout", "0", "exec", "ls"]).unwrap();
        assert_eq!(cli.timeout, 0);
    }

    // --- tokio timeout wrapper behaviour ---

    #[tokio::test]
    async fn timeout_wrapper_fires_on_slow_future() {
        let slow = tokio::time::sleep(std::time::Duration::from_secs(60));
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            slow,
        ).await;
        assert!(result.is_err(), "expected timeout to fire");
    }

    #[tokio::test]
    async fn timeout_wrapper_passes_fast_future() {
        let fast = async { 42u32 };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fast,
        ).await;
        assert_eq!(result.unwrap(), 42);
    }

    // --- build_server_caps ---

    #[test]
    fn caps_contains_common_capabilities() {
        let caps = server_mode::build_server_caps();
        for expected in &["exec", "stream-exec", "push", "pull", "self-update", "info", "ps", "kill", "ls", "cat", "tail", "clip", "screenshot"] {
            assert!(caps.iter().any(|c| c == expected), "missing common cap: {}", expected);
        }
    }

    #[test]
    fn caps_contains_shell_on_all_platforms() {
        let caps = server_mode::build_server_caps();
        assert!(caps.contains(&"shell".to_string()), "shell must be in caps on all platforms");
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
        assert!(id.chars().all(|c| c.is_ascii_digit()), "ID should be all digits: {}", id);
        let n: u32 = id.parse().unwrap();
        assert!(n >= 100_000_000 && n < 999_999_999);
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
        for win_only in &["mouse", "keyboard", "window", "service", "session", "recording", "sleep", "lock"] {
            assert!(!caps.iter().any(|c| c == win_only), "Linux caps should not contain {}", win_only);
        }
    }
}
