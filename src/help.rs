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
  -p <port>     Remote port (omit to auto-try: 8822 → 9822 → 22)
  -i <key>      SSH key file
  -v, -vv       Verbose output

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
  keys list     List authorized keys (fingerprint, type, comment)
  keys show     Show local client public key and fingerprint
  keys add <k>  Add public key (string or .pub file path)
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
  sessions      List/kill persistent sessions
  self-update   Trigger remote self-update
  input         GUI automation (mouse/key/window)
  mouse         Mouse control (alias for input mouse)
  key           Keyboard control (alias for input key)
  window        Window control (alias for input window)
  plugin        Plugin management
  cache         Block cache stats/index
  tunnel <l> <r> TCP tunnel (ssh -L equivalent)
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

AI USAGE:
  mrsh is a unified remote shell tool (client+server in one binary) for AI agents.
  It replaces SSH for Windows targets with ed25519 auth, file transfer, GUI automation.

  CONNECTIVITY:
  - CONNECTION PRIORITY: LAN direct > Tailscale > Relay (DeviceID)
  - CONFIG FILE: ~/.mrsh/config defines Host aliases with Hostname, Port, DeviceID, MAC.
    Always check config before assuming default ports.
  - AUTO-TRY PORTS: Without -p, mrsh tries 8822 → 9822 → 22 in sequence.
    Port 22 covers hosts running mrsh on the SSH port. No manual -p needed.
  - FIREWALL: On install (--install) or first startup, mrsh MUST open firewall
    for all ports it listens on. Without this, LAN clients get "connection refused".
    Windows: netsh advfirewall firewall add rule name="mrsh-inbound" dir=in action=allow protocol=TCP localport=8822 profile=private
    Linux:   ufw allow 8822/tcp  OR  firewall-cmd --add-port=8822/tcp --permanent
    If mrsh listens on multiple ports (8822, 9822), ALL must have firewall rules.
    Tailscale installs its own firewall rules but only for the Tailscale IP —
    LAN traffic (192.168.x.x) is NOT covered and will be blocked without explicit rules.
  - WSL CONNECTIVITY: WSL cannot reach Tailscale hosts (100.x.x.x) via TCP.
    For Tailscale targets, use the Windows mrsh client:
      powershell.exe -Command "& mrsh -h <host> exec '<cmd>' 2>&1 | Out-String"
    For LAN targets (192.168.x.x), WSL mrsh works directly.
    Note: success messages go to stdout, progress/errors to stderr.
  - RELAY FALLBACK: When LAN and Tailscale both fail, try DeviceID:
      mrsh -h <DeviceID> exec '<cmd>'
    DeviceIDs are in ~/.mrsh/config. Relay races P2P and hbbr in parallel.
  - ALWAYS use UNC paths for network shares, NEVER mapped drive letters.
    Prefer DNS hostnames in UNC: \\nas-server\share not \\10.0.0.1\share

  EXEC BEHAVIOR:
  - mrsh exec runs commands via PowerShell (-NoProfile -Command), NOT CMD.
    Use PowerShell syntax: Get-ChildItem (not dir), Remove-Item (not del),
    Get-Content (not type), Set-Content (not echo >), Test-Path (not if exist).
  - The destination path in push is resolved by the SERVER, not the client.
  - STREAMING: exec output is streamed in real-time (stdout/stderr chunks arrive
    as the command produces them). No timeout on streaming exec — output flow
    keeps the connection alive. Large log searches, long-running commands, and
    Select-String on big files all work without timeout.
  - LARGE FILES: For large log files, prefer server-side filtering to reduce transfer:
      mrsh exec "Select-String -Pattern 'error' -Path 'C:\ProgramData\mrsh\audit.log' | Select-Object -Last 50"
      mrsh exec "Get-Content 'C:\path\log.txt' -Tail 100"
      mrsh exec "Get-Content 'C:\path\log.txt' -Tail 1000 | Select-String 'pattern'"
    These filter on the server — only matching lines are sent to the client.
    Avoid: Get-Content of entire multi-MB file without filtering (transfers everything).
  - FALLBACK: If the server lacks stream-exec capability (old version), exec falls
    back to buffered mode (120s timeout). Use --timeout=N to override.

  TRANSFER:
  - Push/pull use CDC delta sync by default (block-level, resumable).
  - Use --raw to skip delta and transfer full files (simpler, no cache).
  - Use --log-file to write logs to file AND console simultaneously.
  - sync-dir <local> <remote>: bidirectional sync. Compares mtime+size,
    pulls newer-remote files, pushes newer-local files. Gracefully falls
    back to size-only when server lacks mtime support (pre-1.4.3).
    Reads .syncignore from local dir root (one pattern per line, # comments).
    Default excludes: .git, .venv, .tmp, .beads, .claude, __pycache__,
    node_modules, target, .pytest_cache, .ruff_cache.
  - SCP: standard `scp` command works against mrsh SSH server.
    mrsh intercepts scp -t/-f on exec channel, handles the protocol natively.

  OUTPUT FORMATS:
    ls       → JSON array: [{{"name":"f.txt","size":1234,"mode":"0644","mod":"...","isDir":false}}]
    cat      → base64-encoded content (decode with base64 -d)
    screenshot → JPEG saved locally (default: screenshot_HOST_TIMESTAMP.jpg)
    exec     → stdout as plain text, stderr on error
    ping     → "OK" or "FAILED: <reason>"
    info     → system info; use --json for structured output
    service list/status → Windows service management

  SYSTEM DISCOVERY:
    mrsh info --json          System info (hostname, OS, RAM, disk, NICs)
    mrsh service list         List Windows services
    mrsh service status <svc> Service details (state, PID, binary path)
    mrsh wake <host|MAC>      Wake-on-LAN (send magic packet, MAC from config)
    mrsh fleet status         Show version/status of all configured hosts

  DEPLOYMENT TO NEW/BROKEN MACHINE:
  - ALWAYS use `mrsh pack` to generate an installer. NEVER manually copy naked binaries.
    mrsh pack --platform windows --key ~/.ssh/id_ed25519.pub --port 8822 \
              --rendezvous-server rendezvous.example.com:21116 -o installer.exe
    The installer bundles: binary (mrsh.exe) + authorized_keys + firewall rules + service registration.
    It also: stops old rsh/mrsh services, deletes legacy rsh.exe, cleans C:\ProgramData\remote-shell\,
    registers new mrsh service with correct display name, launches tray in user session.
    User copies installer to target, runs as admin, done.
  - For fleet updates (already-running machines): use `mrsh self-update`:
      mrsh -h <host> push deploy/mrsh.exe "C:\Temp\mrsh-new.exe"
      mrsh -h <host> self-update "C:\Temp\mrsh-new.exe"
    self-update creates a schtask that stops service, swaps binary, restarts.
    Do NOT use manual bat/ps1 scripts — self-update handles stop/swap/start automatically.

  SERVICE + TRAY ARCHITECTURE (CRITICAL FOR AI AGENTS):
  - ALWAYS CONNECT TO TRAY (port 9822) FIRST. Tray is the preferred endpoint.
    Tray = user session: mapped drives, GUI, screenshots, network shares, user env.
    Tray handles 90%+ of operations better than the SYSTEM service.
  - Service (port 8822): runs as SYSTEM via SCM. Use ONLY for admin operations
    (service install, registry HKLM, launching tray when it's down).
  - CONNECTION SEQUENCE:
    1. Try tray first:  mrsh -h <host> -p 9822 exec '<cmd>'
    2. If tray down (connection refused): launch tray from service:
       mrsh -h <host> exec 'schtasks /run /tn mrsh-tray'
       Wait 3-5s, then use -p 9822
    3. If ONLY admin/SYSTEM needed: use service directly (no -p, default 8822)
  - At service startup, `ensure_tray_task` auto-heals the tray scheduled task.
  - Tray tooltip shows: version, port, and DeviceID. Click "ID: ..." to copy.

    Capability matrix:
      | Feature                    | Port 8822 (SYSTEM)   | Port 9822 (tray/user) |
      | exec, push/pull            | Yes                  | Yes                   |
      | mapped drives (Z:, etc.)   | NO (invisible)       | Yes                   |
      | network shares (UNC)       | NO (no user creds)   | Yes                   |
      | user env vars ($env:HOME)  | SYSTEM profile       | User profile          |
      | mouse/key input            | Yes (cross-session)  | Yes                   |
      | window list/find           | null (no desktop)    | Yes (JSON)            |
      | screenshot                 | fails                | Yes                   |
      | install user software      | NO                   | Yes                   |
      | service install/HKLM       | Yes (SYSTEM)         | NO (user-level)       |

    WRONG: mrsh -h host exec 'Get-ChildItem Z:\'           ← uses SYSTEM, Z: invisible
    RIGHT: mrsh -h host -p 9822 exec 'Get-ChildItem Z:\'   ← uses tray, Z: visible

  SELF-UPDATE (existing machines):
  - CRITICAL: NEVER kill/stop/restart mrsh through its own connection using /ru SYSTEM.
    SYSTEM cannot start tray-mode apps in user desktop session — locks you out.
  - SAFE UPDATE PROCEDURE:
    1. BEFORE touching the service, verify alternative access (SSH, WinRM, RDP, debug-server).
       If mrsh is the ONLY access channel, DO NOT proceed — ask for recovery path.
    2. Canonical install directory: C:\ProgramData\mrsh\ (binary: mrsh.exe, NOT rsh.exe)
    3. Push + self-update: mrsh push deploy/mrsh.exe "C:\Temp\mrsh-new.exe"
       then: mrsh self-update "C:\Temp\mrsh-new.exe"
    4. The service auto-heals the tray task on restart (ensure_tray_task).
    5. Wait 15s, verify: mrsh -h <host> exec "hostname"

  REMOTE EXECUTION — NO ORPHAN PROCESSES:
  - Use mrsh exec DIRECTLY for commands. Do NOT create intermediate .bat/.ps1 wrappers
    that leave orphan processes on the remote desktop.
      CORRECT: mrsh exec 'Get-Process | Where-Object {{ $_.Name -eq "app" }}'
      WRONG:   mrsh exec 'cmd /k "dir"'        ← leaves orphan cmd.exe window
      WRONG:   mrsh exec 'start /b script.bat'  ← leaves orphan console
  - If you need cmd.exe features (pipes, cd /d): mrsh exec 'cmd /c "..."'
    Always use /c (auto-exits after command), NEVER /k (keeps console open).
  - If you need PowerShell: mrsh exec 'powershell -NoProfile -Command "..."'

  HIDDEN SCHTASK EXECUTION (no console window on remote desktop):
  - Bare schtasks /tr "powershell ..." shows a console window to the remote user.
  - Use VBS wrapper (run-hidden.vbs) to launch PowerShell hidden (window style 0):
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "powershell ... -File """ & WScript.Arguments(0) & """", 0, True
  - Deploy once: mrsh push run-hidden.vbs 'C:/Temp/run-hidden.vbs'
  - Usage: /tr "wscript C:\Temp\run-hidden.vbs C:\Temp\script.ps1"
    instead of: /tr "powershell -ExecutionPolicy Bypass -File ..."
  - PS1 output: use *> C:\Temp\<name>.log redirect (NOT Start-Transcript).
  - NEVER use /it flag with schtasks via SSH/rsh — /it requires interactive desktop logon.
"#,
        version = version
    );
}
