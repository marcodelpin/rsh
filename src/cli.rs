//! CLI argument parsing.
//!
//! Defines the `Cli` clap struct, default ports, the lists of known local and
//! client subcommands, and the argument preprocessing helpers used by `main()`
//! before clap parsing (positional-host shorthand, MSYS path unmangling, and
//! per-command timeout selection).

use clap::Parser;

/// mrsh — Remote Shell
#[derive(Parser, Debug)]
#[command(
    name = "mrsh",
    version,
    about = "Remote shell tool",
    disable_help_flag = true
)]
pub(crate) struct Cli {
    /// Remote host (IP, hostname, or DeviceID)
    #[arg(short = 'h', long)]
    pub host: Option<String>,

    /// Print help
    #[arg(long)]
    pub help: bool,

    /// Remote port (omit for auto-try: 8822 → 9822 → 22)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// SSH key file
    #[arg(short = 'i', long)]
    pub key: Option<String>,

    /// Verbose output (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Install as system service (Windows: SCM service, Linux: systemd unit)
    #[arg(long = "install")]
    pub install: bool,

    /// Uninstall system service
    #[arg(long = "uninstall")]
    pub uninstall: bool,

    /// Run server in foreground (debug mode)
    #[arg(long = "console")]
    pub console: bool,

    /// Debug server: foreground, verbose logging to console+file, no relay/rdv registration.
    /// Listens on specified port (-p) or default 8822. Use for diagnostics and recovery.
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,

    /// Additional shared-filesystem spool dir to accept FS-transport sessions.
    /// Runs alongside the TCP listener: clients use `-h fs:///path/to/spool`
    /// and the server polls the same dir for new sessions.
    #[arg(long = "fs-spool", value_name = "DIR")]
    pub fs_spool: Option<String>,

    /// Internal: launched by SCM as service (Windows only)
    #[cfg(target_os = "windows")]
    #[arg(long = "service", hide = true)]
    pub service: bool,

    /// Internal: attach to a target console and synthesize a Ctrl event.
    #[cfg(target_os = "windows")]
    #[arg(long = "signal-helper", hide = true)]
    pub signal_helper: bool,

    /// Internal: PID whose console should receive the generated Ctrl event.
    #[cfg(target_os = "windows")]
    #[arg(long = "attach-pid", hide = true)]
    pub attach_pid: Option<u32>,

    /// Internal: ctrl-c or ctrl-break for the generated console event.
    #[cfg(target_os = "windows")]
    #[arg(long = "ctrl-event", hide = true)]
    pub ctrl_event: Option<String>,

    /// Run as tray app (user session, port 9822, system tray icon)
    #[cfg(target_os = "windows")]
    #[arg(long = "tray")]
    pub tray: bool,

    /// Run as background daemon (Linux only)
    #[cfg(not(target_os = "windows"))]
    #[arg(long = "daemon")]
    pub daemon: bool,

    /// Delete remote files not present locally (mirror mode, push only)
    #[arg(long = "delete")]
    pub delete: bool,

    /// Username for SSH fallback or password auth (like ssh -u user@host)
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    /// SOCKS5 dynamic proxy port (ssh -D equivalent)
    #[arg(short = 'D', long = "dynamic")]
    pub dynamic_port: Option<u16>,

    /// Show progress bar with rate and ETA during transfers
    #[arg(long = "progress")]
    pub progress: bool,

    /// Dry run: show what would be transferred without doing it
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Backup suffix for overwritten files (e.g. --backup=.bak)
    #[arg(long = "backup")]
    pub backup: Option<String>,

    /// Bandwidth limit in KB/s (0 = unlimited)
    #[arg(long = "bwlimit", default_value_t = 0)]
    pub bwlimit: u32,

    /// Global operation timeout in seconds (0 = per-command default)
    #[arg(long = "timeout", default_value_t = 0)]
    pub timeout: u64,

    /// Start control master (hold connection, serve via UDS)
    #[arg(short = 'M')]
    pub master: bool,

    /// Skip multiplexing, always open new connection
    #[arg(long = "no-mux")]
    pub no_mux: bool,

    /// Accept changed host keys (update known_hosts instead of rejecting)
    #[arg(long = "accept-host-key")]
    pub accept_host_key: bool,

    /// Stop running master for this host
    #[arg(long = "mux-stop")]
    pub mux_stop: bool,

    /// Use cmd.exe instead of PowerShell for exec (avoids $var expansion)
    #[arg(long = "cmd")]
    pub use_cmd: bool,

    /// Use sh/bash instead of PowerShell for exec
    #[arg(long = "sh")]
    pub use_sh: bool,

    /// Preferred shell for interactive sessions (pwsh, cmd, bash, zsh, fish, or full path)
    #[arg(long = "shell")]
    pub shell: Option<String>,

    /// Use QUIC transport instead of TLS/TCP (experimental, requires --features quic)
    #[cfg(feature = "quic")]
    #[arg(long = "quic")]
    pub use_quic: bool,

    /// Subcommand and arguments
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Tray mode port (user session, secondary listener).
pub(crate) const TRAY_PORT: u16 = 9822;

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
///
/// Public so external crates (e.g. the merged `mrsh-desk` binary's argv
/// dispatcher; see `mrsh-desk/src/mrsh_bin/dispatcher.rs`) can re-export this
/// list as the SSOT for "which argv[1] tokens belong to mrsh".
pub const LOCAL_COMMANDS: &[&str] = &[
    "version",
    "fleet",
    "wake",
    "cfg",
    "config-edit",
    "connect",
    "log",
    "logs",
    "dash",
    "dashboard",
    "keygen",
    "keys",
    "totp-setup",
    "totp-verify",
    "pack",
    "install-pack",
    "relay",
    "rdv",
    "rendezvous",
    "discover",
    "nat",
    "release",
];

/// Client subcommands that require -h <host>.
///
/// Public for the same reason as `LOCAL_COMMANDS`: SSOT for the merged-binary
/// dispatcher in `mrsh-desk`.
pub const CLIENT_SUBCOMMANDS: &[&str] = &[
    "exec",
    "dlog",
    "push",
    "pull",
    "sync-dir",
    "ping",
    "info",
    "ps",
    "kill",
    "ls",
    "cat",
    "tail",
    "clip",
    "screenshot",
    "shell",
    "attach",
    "browse",
    "sftp",
    "self-update",
    "server-version",
    "socks5",
    "push-via",
    "push-via-batch",
    "pull-via",
    "pull-via-batch",
    "tunnel",
    "watch",
    "write",
    "input",
    "mouse",
    "key",
    "window",
    "tray-start",
];

/// Pre-process CLI args: if the first positional argument is not a known command,
/// treat it as a host and insert `-h` before it.
/// This allows `mrsh myhost exec "dir"` as shorthand for `mrsh -h myhost exec "dir"`.
pub(crate) fn preprocess_args() -> Vec<String> {
    let raw: Vec<String> = std::env::args().collect();

    // If -h/--host already present, nothing to do
    let has_host_flag = raw.iter().any(|a| {
        a == "-h"
            || a == "--host"
            || a.starts_with("--host=")
            || (a.starts_with("-h") && a.len() > 2 && !a.starts_with("--"))
    });
    if has_host_flag {
        return raw;
    }

    // Short flags that consume the next argument as a value
    const VALUE_FLAGS_SHORT: &[&str] = &["-p", "-i", "-D"];
    const VALUE_FLAGS_LONG: &[&str] = &[
        "--port",
        "--key",
        "--dynamic",
        "--user",
        "--backup",
        "--bwlimit",
        "--timeout",
        "--shell",
        "--attach-pid",
        "--ctrl-event",
    ];

    // Find the first positional argument (skip flags and their values)
    let mut i = 1; // skip binary name
    while i < raw.len() {
        let arg = &raw[i];
        if arg == "--" {
            break;
        }
        if arg.starts_with("--") {
            if !arg.contains('=') && VALUE_FLAGS_LONG.contains(&arg.as_str()) {
                i += 2; // flag + value
            } else {
                i += 1;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            if VALUE_FLAGS_SHORT.contains(&arg.as_str()) {
                i += 2; // flag + value
            } else {
                i += 1;
            }
            continue;
        }
        break; // first positional
    }

    if i >= raw.len() {
        return raw; // no positional args
    }

    let first_pos = &raw[i];

    // If it's a known command (local or client subcommand), don't transform
    if LOCAL_COMMANDS.contains(&first_pos.as_str())
        || CLIENT_SUBCOMMANDS.contains(&first_pos.as_str())
        || first_pos == "help"
        || first_pos == "recording"
    {
        return raw;
    }

    // Not a known command → treat as host, insert -h before it
    let mut result = Vec::with_capacity(raw.len() + 1);
    result.extend_from_slice(&raw[..i]);
    result.push("-h".to_string());
    result.extend_from_slice(&raw[i..]);
    result
}

/// Returns the effective operation timeout in seconds.
/// Explicit `--timeout N` (N > 0) overrides everything.
/// Per-command defaults: push/pull → 300s, interactive cmds → 0, others → 600s.
pub(crate) fn compute_timeout_secs(explicit: u64, cmd: &str) -> u64 {
    if explicit > 0 {
        return explicit;
    }
    match cmd {
        "shell" | "browse" | "sftp" | "tunnel" | "watch" | "attach" | "socks5" | "push-via"
        | "push-via-batch" | "pull-via" | "pull-via-batch" => 0,
        "push" | "pull" => 300,
        _ => 600,
    }
}

/// Detect paths that MSYS likely mangled from a Linux path to a Windows path.
/// E.g. `/tmp/file` → `W:/Temp/file` or `/home/user` → `C:/Users/user/scoop/.../home/user`.
/// These patterns indicate the user meant a remote Linux path but MSYS converted it.
/// Detect and unmangle MSYS-converted remote paths.
/// MSYS converts `/home/user/path` → `C:/Users/.../scoop/apps/git/2.x.x/home/user/path`
/// before mrsh sees the argument. We detect this and restore the original Unix path.
/// Returns Some(fixed_path) if mangled, None if path is fine.
pub(crate) fn unmangle_msys_remote(path: &str) -> Option<String> {
    // Must be a drive-letter path
    if path.len() < 3 || path.as_bytes()[1] != b':' || !path.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }

    let lower = path.to_lowercase();

    // Known Unix root directories that MSYS mangles
    let unix_roots = [
        "/home/", "/usr/", "/etc/", "/opt/", "/var/", "/tmp/", "/root/",
    ];

    // Pattern 1: scoop/apps/git/<version>/<unix_path>
    // E.g. C:/Users/user/scoop/apps/git/2.53.0.2/home/user/rsh
    if let Some(git_idx) = lower.find("scoop/apps/git/") {
        let after_git = &path[git_idx + "scoop/apps/git/".len()..];
        // Skip version component (e.g. "2.53.0.2/")
        if let Some(slash_idx) = after_git.find('/') {
            let unix_path = &after_git[slash_idx..]; // "/home/user/rsh"
            return Some(unix_path.to_string());
        }
    }

    // Pattern 2: msys64/<unix_path> or mingw64/<unix_path>
    for marker in &["msys64/", "msys/", "mingw64/", "mingw/"] {
        if let Some(idx) = lower.find(marker) {
            let after = &path[idx + marker.len()..];
            for root in &unix_roots {
                let root_no_slash = &root[1..]; // "home/" without leading /
                if after.starts_with(root_no_slash) {
                    return Some(format!("/{}", after));
                }
            }
        }
    }

    // Pattern 3: drive-letter path containing a unix root dir
    // E.g. C:/some/prefix/home/user/path → /home/user/path
    for root in &unix_roots {
        if let Some(idx) = lower.find(root) {
            // Only unmangle if it looks like MSYS did it (has suspicious prefix)
            let prefix = &lower[..idx];
            if prefix.contains("scoop")
                || prefix.contains("git")
                || prefix.contains("msys")
                || prefix.contains("mingw")
                || prefix.contains("program")
            {
                return Some(path[idx..].to_string());
            }
        }
    }

    None
}
