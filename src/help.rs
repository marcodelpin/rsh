//! CLI help text and usage documentation.

pub fn print_usage() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        r#"mrsh {version} (rust) — Remote Shell Tool

USAGE:
  mrsh [options] <command> [args...]
  mrsh -h <host> [-p port] [-i key] <command> [args...]

OPTIONS:
  -h <host>     Remote host (IP, hostname, or DeviceID)
  -p <port>     Remote port (omit to auto-try: 9822 → 8822 → 22)
  -i <key>      SSH key file
  -v, -vv       Verbose output
  --cmd         Use cmd.exe for exec (avoids PowerShell $var expansion)
  --sh          Use sh/bash for exec (Git Bash on Windows, sh on Linux)

LOCAL COMMANDS (no -h needed):
  version       Show version
  fleet status  Show all configured hosts and their versions
  fleet update  Push binary to all outdated hosts
  fleet config  Check rendezvous config consistency across fleet
  fleet discover --group <name>  Discover peers enrolled in a group
                  Uses enrollment token HMAC for authentication.
                  Returns: DeviceID, hostname, platform, LAN status
  wake <host|mac>  Send Wake-on-LAN packet (MAC from config or argument)
  cfg           Interactive config editor (TUI)
  connect       Pick a known host from TUI list and connect
  log           Session log report (hours per host)
                  --host=X  --since=YYYY-MM-DD  --until=YYYY-MM-DD
                  --detail  --json
  logs          Interactive log viewer (TUI) — browse, filter, summarize
  dash          Fleet dashboard (TUI) — live host status, auto-refresh
  keygen [path] Generate ed25519 key pair
  keys list     List authorized keys from ALL locations (fingerprint, type, comment)
                  Searches: system dir, user dir, legacy dir — deduplicates
  keys show     Show local client public key and fingerprint
  keys add <k>  Add public key (string or .pub file path)
                  Added keys are recognized immediately (hot-reload on next auth)
  keys remove <fp|comment>  Remove key by fingerprint or comment
  totp-setup [fp] Generate TOTP secret + recovery codes for a key
  totp-verify <secret|fp> <code>  Verify a TOTP code
  recording export <file.log> [output.cast]  Convert session log to asciicast
  pack          Generate single-file installer for target machine
                  Linux:   self-extracting .sh (bash header + tar.gz)
                  Windows: NSIS installer .exe (requires makensis on build host)
                  --platform=windows|linux  --output=FILE  --binary=PATH
                  --key=KEY_OR_FILE  --port=PORT  --nas-auth=CMD
                  --group=NAME  --rendezvous-server=HOST:PORT
                  Group enrollment: embeds EnrollmentToken in config so the
                  installed server registers with SHA256(token) as group_hash.
  relay         Run relay server (hbbr) for connection pairing
                  --port=PORT (default: 21117)  --key=KEY
  rdv           Run rendezvous server (hbbs) for device discovery
                  --port=PORT (default: 21116)  --key=KEY  --relay=HOST:PORT
                  Stores peer group_hash for fleet group discovery.
  help          This help

SERVER MODE (run mrsh as a server):
  mrsh                  Start as tray (Windows default: port 9822, system tray icon)
  mrsh --tray           Explicit tray mode (same as default, kept for compat)
  mrsh --console        Foreground server (both platforms)
  mrsh -d [-p PORT]     Debug server: foreground, verbose, no relay/rdv, Ctrl+C to stop
                          Auth: ed25519 (authorized_keys from all locations)
                          Log: console (debug level) + audit-debug.log
                          Version reports as "X.Y.Z-debug"
  mrsh --daemon         Background daemon (Linux, systemd signal handling)
  mrsh --install        Install system service (Windows SCM / Linux systemd)
  mrsh --uninstall      Remove system service
  mrsh -p <port>        Override listening port (default: 8822)

  Windows runs TWO instances: service (port 8822, SYSTEM) + tray (port 9822, user).
  The service auto-starts the tray at boot via a scheduled task (mrsh-tray).
  Default behavior: mrsh.exe without flags = tray mode (no --tray needed).
  If the tray is not running, start it: schtasks /run /tn mrsh-tray

CLIENT COMMANDS (require -h):
  ping          Test connectivity
  exec <cmd>    Execute command (streaming output, no timeout)
  shell         Interactive shell (ConPTY on Windows, PTY on Linux)
  attach [id]   Persistent session (--ro for read-only)
  browse [path] Interactive file browser (TUI)
  sftp          SFTP-like interactive file transfer shell
  server-version  Show remote server version
  recording list  List session recordings on remote host
  push <l> <r>  Push file or directory (delta sync)
  pull <r> <l>  Pull file or directory (delta sync)
  sync-dir <l> <r>  Bidirectional sync (newer wins, mtime+size)
                  Reads .syncignore from local dir (pattern-per-line)
                  --exclude=<pattern>  Additional exclude (exact or glob)

TRANSFER OPTIONS:
  --progress    Show progress bar with rate and ETA
  --dry-run     Show what would be transferred without doing it
  --backup=.bak Rename remote files before overwriting
  --bwlimit=N   Bandwidth limit in KB/s (0 = unlimited)
  --delete      Mirror mode: remove remote files not in local (push only)
  --timeout=N   Global operation timeout in seconds (0 = per-command default)
                  Default: exec 120s, push/pull 300s, shell/tunnel/watch 0 (none)
  ls [path]     List directory
  cat <path>    Read file
  write <r> <c> Write content to file
  ss            Capture screen (alias: screenshot)
  watch <l> <r> Watch dir, auto-push changes
  status [n]    RTT statistics (n pings)
  ps            List processes
  kill <pid>    Kill process
  tail <f> [n]  Tail file (default 20 lines)
  info          System info
  eventlog      Windows Event Log
  clip get|set  Clipboard
  service       Service management
  filever       PE version info
  rlog <path>   Remote log query (server-side grep/tail, streaming)
                  --grep <pattern>  Filter lines by regex
                  --tail <N>        Show only last N lines
                  --max <N>         Limit to N matches
                  -i                Case-insensitive match
                  -v                Invert match (exclude pattern)
  sessions      List/kill persistent sessions
  self-update   Trigger remote self-update
  input         GUI automation (mouse/key/window)
  mouse         Mouse control (alias for input mouse)
  key           Keyboard control (alias for input key)
  window        Window control (alias for input window)
  plugin        Plugin management
  cache         Block cache stats/index
  tunnel <l> <r> TCP tunnel (ssh -L equivalent, persistent listener)
                  Stays open, accepts multiple connections (e.g. browser).
                  Each local connection opens a new mrsh stream to the server.
  -D <port>     SOCKS5 proxy (ssh -D equivalent)
  --user <name> Password auth (fallback when no SSH key)
  reboot [-f]   Reboot remote host
  shutdown [-f] Shutdown remote host
  sleep [-f]    Sleep remote host
  lock          Lock workstation

MUX (connection multiplexing):
  -M            Start control master (hold connection, serve via UDS)
  --no-mux      Skip multiplexing, always open new connection
  --mux-stop    Stop running master for this host

For AI agent usage guide, see docs/AI_USAGE.md in the source tree.
"#,
        version = version
    );
}
