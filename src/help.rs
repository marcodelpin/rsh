//! CLI help text and usage documentation.

pub fn print_usage() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        r#"mrsh {version} (rust) — Remote Shell Tool

QUICKSTART (Windows server hosts):
  mrsh ships TWO local listeners: service (port 8822, SYSTEM session 0) and
  tray (port 9822, user session, GUI + USERPROFILE access). Pick the right port:

    -p 8822   file ops, services, registry, processes — no desktop needed
    -p 9822   anything that touches GUI, browser, ~/, %USERPROFILE%
    (no -p)   auto-try 9822 → 8822 → 22 (recommended)

  IF THE TRAY IS NOT RUNNING (e.g. fresh logon, RDP, post-boot delay):
    mrsh -h <host> exec 'schtasks /run /tn mrsh-tray'
    # wait 3-5 s, then connect via -p 9822
  The service auto-recovers the tray within ~60 s (watchdog, rsh-3t7f),
  so manual re-launch is only needed if you can't wait.

USAGE:
  mrsh <host> [command] [args...]
  mrsh -h <host> [-p port] [-i key] [-u user] <command> [args...]
  mrsh -h user@host [-p port] <command> [args...]
  mrsh [local-command] [args...]

OPTIONS:
  -h <host>     Remote host (IP, hostname, or DeviceID)
  -p <port>     Remote port (omit to auto-try: 9822 → 8822 → 22)
  -i <key>      SSH key file
  -u <user>     Username for SSH fallback or password auth (like ssh user@host)
  -v, -vv       Verbose output
  --cmd         Use cmd.exe for exec (avoids PowerShell $var expansion)
  --sh          Use sh/bash for exec (Git Bash on Windows, sh on Linux)
  --shell <s>   Preferred shell for interactive sessions
                  Windows: pwsh (default), powershell, cmd
                  Linux: bash (default), zsh, fish, or full path

LOCAL COMMANDS (no -h needed):
  version       Show version
  fleet status  Show all configured hosts and their versions
                  -v, --verbose   Include CAPS column
                  -r, --refresh   Re-probe auto-try ports (9822/8822/22)
                                  when configured port fails. Surfaces
                                  hosts reachable on an alternate port
                                  (shown as "online*") and host-key
                                  rotations (shown as "key-rotated").
  fleet update  Push the right binary to each outdated host (auto OS detect)
                  --windows PATH         Windows binary (default: deploy/mrsh.exe)
                  --linux PATH           Linux glibc x86_64 (default: deploy/mrsh-linux)
                  --linux-musl PATH      Linux musl x86_64 (default: deploy/mrsh-linux-musl)
                  --linux-aarch64 PATH   Linux aarch64 / ARM64 (default: deploy/mrsh-linux-aarch64)
                  --dry-run, -n          Print the plan without pushing
                  --refresh, -r          Re-probe auto-try ports (stale config)
                  Per-host override via `Platform windows|linux|linux-musl|linux-aarch64`
                  in ~/.mrsh/config. Hosts without a matching binary are SKIPPED.
                  Legacy positional arg is treated as Windows binary for compat.
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
  rdv publish <binary> --platform <p> --track <t> --version <v>
                  [--key <priv.pem>] [--server <host:port>] [--no-blob]
                  Publish a VersionAdvert to rdv (rsh-5264.3, operator only).
                  Signs the binary + canonical payload with the release key.
  rdv query --platform <p> --track <t> [--current-version <v>]
                  Ask rdv whether an update is available for (platform, track).
  release sign <binary> --key <priv.pem> [--out <binary>.sig]
                  Sign a release binary (Ed25519, separate keypair from rdv).
                  See docs/release-signing.md for the operator workflow.
  release verify <binary> <sig>
                  Verify a binary against an Ed25519 signature using the
                  embedded SIGNING_PUBLIC_KEY_PEM constant. Exit 1 on mismatch.
  release pubkey  Print the embedded release-signing public key (PEM).
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

PORT SELECTION GUIDE (Windows targets — choose -p based on what you need):

  Use -p 8822 (service / SYSTEM session 0):
    file ops (push, pull, sync-dir), Get-Service / sc.exe, registry HKLM,
    Move-Item / Copy-Item / Get-Process / kill, log reading, DB query.
    No GUI / no user-context required. Works without anyone logged in.

  Use -p 9822 (tray / user session — REQUIRED for GUI):
    Start-Process <app.exe>, launch WPF / Win32 / browser, WSL commands,
    user-mapped drives, anything that needs Desktop / interactive token.
    Fails if no user is logged in OR tray task not running.

  Auto-detect (omit -p — RECOMMENDED for most cases):
    tries 9822 → 8822 → 22, picks first that responds.

  Antipattern: schtasks /Create /TR <app.exe> /RL LIMITED — wrong for GUI.
    /RL LIMITED forces a Limited Run Level token (no desktop). Use /IT
    (Interactive Token) for GUI apps, OR launch via -p 9822 directly.

  Recommended: prefer 'mrsh launch <app>' subcommand (auto-routes via 9822
    Start-Process → schtasks /IT fallback → useful error)

CLIENT COMMANDS (require -h):
  ping          Test connectivity
  exec <cmd>    Execute command (streaming output, no timeout)
  exec --detach <cmd>  Run DETACHED (survives drop) for >30min jobs [Linux]; prints a handle
  dlog <id>     Tail a detached job's log + status (RUNNING/EXITED) — companion to exec --detach
  shell         Interactive shell (ConPTY on Windows, PTY on Linux)
  attach [id]   Persistent session (--ro for read-only)
  browse [path] Interactive file browser (TUI)
  sftp          SFTP-like interactive file transfer shell
  server-version  Show remote server version
  tray-start    Launch tray instance in user session (Windows, from service port)
  launch <app> [args...]  Auto-route GUI app launch on Windows (Start-Process
                  cascade with schtasks /IT fallback). Use this instead of
                  ad-hoc 'schtasks /Create /RL LIMITED' patterns — those fail
                  in SYSTEM session 0 (no desktop).
                  Example: mrsh -h sj11 launch C:\\ProdMaster\\ProdMaster.exe
  recording list  List session recordings on remote host
  push <l> <r>  Push file or directory (delta sync)
  pull <r> <l>  Pull file or directory (delta sync)
                  Unreadable files (e.g. docker cp NTFS perms) are skipped
                  and reported at end — pull continues for remaining files.
  sync-dir <l> <r>  Bidirectional sync (newer wins, mtime+size)
                  Reads .syncignore from local dir (pattern-per-line)
                  --exclude=<pattern>  Additional exclude (exact or glob)
  NOTE on Git Bash: remote paths like /opt/foo are auto-converted by MSYS.
  mrsh detects and unmangles them silently. To disable MSYS conversion:
  MSYS_NO_PATHCONV=1 mrsh ... push local /opt/foo

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
                  <remote-binary-path>             direct push (existing binary on host)
                  --from-rdv [--track <t>]         pull latest from rdv (rsh-5264.6)
                            [--version <v>]        pin specific version
                            [--allow-downgrade]    accept rollback to older version
                            [--insecure-no-verify] skip Ed25519 verify (DEV ONLY)
  input         GUI automation (mouse/key/window)
  mouse         Mouse control (alias for input mouse)
  key           Keyboard control (alias for input key)
  window        Window control (alias for input window)
  plugin        Plugin management
  cache         Block cache stats/index
  tunnel <l> <r> TCP tunnel (ssh -L equivalent, persistent listener)
                  Stays open, accepts multiple connections (e.g. browser).
                  Each local connection opens a new mrsh stream to the server.
  push-via <l> <url>  Upload a file via SOCKS5 proxy (curl -T through relay)
  pull-via <url> <l>  Download a file via SOCKS5 proxy (curl -o through relay)
  push-via-batch <src-dir> <base-url/>  Batch upload many files via ONE proxy.
                  Reuses a single SOCKS5 for all files; spawns N parallel curl
                  workers. Designed for 10k+ file uploads to FTP/HTTP endpoints
                  reachable only from the relay host.
                  --include=PAT      Glob include (repeatable, e.g. *.tif)
                  --exclude=PAT      Glob exclude (repeatable, e.g. tmp/*)
                  --resume           Skip files with matching remote size (curl HEAD)
                  --parallel=N       Concurrent curl workers (default 4)
                  --progress         Print one progress line every 1s
                  --index=FILE       Append one JSONL record per file (status, timing, err)
                  --dry-run          Print plan without uploading
                  On Ctrl+C, drains in-flight uploads and writes index footer.
  pull-via-batch <base-url/> <dest-dir>  Batch download many files via ONE proxy.
                  Manifest-driven counterpart to push-via-batch.
                  --manifest=SRC      Local file or URL with JSONL/plain-text file list
                  --include=PAT       Glob include on manifest relative paths
                  --exclude=PAT       Glob exclude on manifest relative paths
                  --resume            Skip local files already present
                  --parallel=N        Concurrent curl workers (default 4)
                  --progress          Print one progress line every 1s
                  --index=FILE        Append one JSONL record per file (status, timing, err)
                  --dry-run           Print plan without downloading
                  Accepts push-via-batch JSONL index files as manifest input.
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

EXAMPLES:
  mrsh gpu                     Open shell to 'gpu' (same as: mrsh -h gpu)
  mrsh gpu exec "dir"          Run command on 'gpu' (same as: mrsh -h gpu exec "dir")
  mrsh 192.168.1.1 push a b    Push file (same as: mrsh -h 192.168.1.1 push a b)
  mrsh gpu -p 9822 info        With explicit port
  mrsh -p 9822 gpu info        Flags can go before or after host

  The first argument is treated as the host when it's not a known command.
  Use -h explicitly when combining with other short flags before the host.

For AI agent usage guide, see docs/AI_USAGE.md in the source tree.
"#,
        version = version
    );
}
