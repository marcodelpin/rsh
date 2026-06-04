# mrsh — AI Agent Usage Guide

mrsh is a unified remote shell tool (client+server in one binary) for AI agents.
It replaces SSH for Windows targets with ed25519 auth, file transfer, GUI automation.

## CONNECTIVITY

- **CONNECTION PRIORITY**: LAN direct > Tailscale > Relay (DeviceID)
- **CONFIG FILE**: `~/.mrsh/config` defines Host aliases with Hostname, Port, DeviceID, MAC.
  Always check config before assuming default ports.
- **DO NOT USE `-p <port>`** unless you have a specific reason. mrsh auto-selects the
  best port: tray (9822) first, then service (8822), then SSH (22).
  The tray runs in the user session (mapped drives, GUI, screenshots, network shares).
  The service runs as SYSTEM (admin ops, no user context). Omitting -p gets you tray.
  Use -p 8822 ONLY when: (a) you need SYSTEM privileges, or (b) no user is logged in.
- **AUTO-TRY PORTS**: Without -p, mrsh tries 9822 → 8822 → 22 in sequence.
  Port 22 covers hosts running mrsh on the SSH port. No manual -p needed.
- **SSH FALLBACK**: If all TLS ports fail, mrsh automatically falls back to
  standard SSH on port 22 (via russh). This makes mrsh a drop-in ssh
  replacement for hosts that only have OpenSSH (Proxmox, generic Linux, Windows).
  Supported over SSH: exec, push, pull, ping. No GUI/fleet/screenshot.
  v1.10.18+: SSH push/pull detects remote OS — uses PowerShell on Windows,
  `cat` on Unix. All paths normalized to POSIX (forward slashes).
- **FIREWALL**: On install (--install) or first startup, mrsh MUST open firewall
  for all ports it listens on. Without this, LAN clients get "connection refused".
  - Windows: `netsh advfirewall firewall add rule name="mrsh-inbound" dir=in action=allow protocol=TCP localport=8822 profile=private`
  - Linux: `ufw allow 8822/tcp` OR `firewall-cmd --add-port=8822/tcp --permanent`
  - If mrsh listens on multiple ports (8822, 9822), ALL must have firewall rules.
  - Tailscale installs its own firewall rules but only for the Tailscale IP —
    LAN traffic (192.168.x.x) is NOT covered and will be blocked without explicit rules.
- **WSL CONNECTIVITY**: WSL cannot reach Tailscale hosts (100.x.x.x) via TCP.
  For Tailscale targets, use the Windows mrsh client:
  `powershell.exe -Command "& mrsh -h <host> exec '<cmd>' 2>&1 | Out-String"`
  For LAN targets (192.168.x.x), WSL mrsh works directly.
- **RELAY FALLBACK**: When LAN and Tailscale both fail, try DeviceID:
  `mrsh -h <DeviceID> exec '<cmd>'`
  DeviceIDs are in `~/.mrsh/config`. Relay races P2P and hbbr in parallel.
- ALWAYS use UNC paths for network shares, NEVER mapped drive letters.
  Prefer DNS hostnames in UNC: `\\nas-server\share` not `\\10.0.0.1\share`

## EXEC BEHAVIOR

- mrsh exec runs commands via **PowerShell** (`-NoProfile -Command`), NOT CMD.
  Use PowerShell syntax: `Get-ChildItem` (not dir), `Remove-Item` (not del),
  `Get-Content` (not type), `Set-Content` (not echo >), `Test-Path` (not if exist).
- **SHELL SELECTION**: Use `--cmd` for cmd.exe or `--sh` for bash:
  ```
  mrsh exec 'echo %PATH%'            ← PowerShell (default, $vars expanded)
  mrsh --cmd exec 'echo %PATH%'      ← cmd.exe (no $var expansion)
  mrsh --sh exec 'echo $PATH'        ← bash/sh (Unix syntax)
  ```
- The destination path in push is resolved by the SERVER, not the client.
- **STREAMING**: exec output is streamed in real-time. No timeout on streaming exec.
- **LARGE FILES**: Prefer server-side filtering to reduce transfer:
  ```
  mrsh exec "Select-String -Pattern 'error' -Path 'C:\ProgramData\mrsh\audit.log' | Select-Object -Last 50"
  mrsh exec "Get-Content 'C:\path\log.txt' -Tail 100"
  ```

## TRANSFER

- Push/pull use CDC delta sync by default (block-level, resumable).
- `--raw` to skip delta, `--log-file` for dual logging.
- `sync-dir <local> <remote>`: bidirectional sync (mtime+size, reads .syncignore).
- SCP: standard `scp` command works against mrsh SSH server.

## OUTPUT FORMATS

| Command | Format |
|---------|--------|
| ls | JSON array: `[{"name":"f.txt","size":1234,"mode":"0644","mod":"...","isDir":false}]` |
| cat | base64-encoded content |
| screenshot | JPEG saved locally |
| exec | stdout as plain text, stderr on error |
| ping | "OK" or "FAILED: reason" |
| info | system info; `--json` for structured output |

## SERVICE + TRAY ARCHITECTURE

- **JUST USE**: `mrsh -h <host> exec '<cmd>'` (no -p needed!)
  Auto-try connects to tray (9822) first — user session with full capabilities.
  Falls back to service (8822) if tray is down, then SSH (22).
- Service (port 8822): runs as SYSTEM via SCM. Use -p 8822 ONLY for:
  (a) admin operations, (b) unattended machines.
- Launch tray from service: `mrsh -h <host> -p 8822 tray-start`
  (replaces manual `exec 'schtasks /run /tn mrsh-tray'` — handles task creation + launch)
- `ensure_tray_task` auto-heals tray scheduled task at service startup.
- Tray icon: blue = idle, RED = active connections.
- Toast notifications: ONLY on first connection after 5+ minutes idle.

### Capability Matrix

| Feature | Port 8822 (SYSTEM) | Port 9822 (tray/user) |
|---------|-------------------|----------------------|
| exec, push/pull | Yes | Yes |
| mapped drives (Z:) | NO (invisible) | Yes |
| network shares (UNC) | NO (no user creds) | Yes |
| screenshot | fails | Yes |
| mouse/key input | Yes (cross-session) | Yes |
| window list/find | null (no desktop) | Yes (JSON) |
| install software | Yes (SYSTEM) | Yes (if admin-install) |
| HKLM registry | Yes (SYSTEM) | Yes (if admin-install) |

**WRONG**: `mrsh -h host -p 8822 exec 'Get-ChildItem Z:\'` ← forces SYSTEM, Z: invisible
**RIGHT**: `mrsh -h host exec 'Get-ChildItem Z:\'` ← auto-try finds tray, Z: visible

## DEPLOYMENT

### New machine (installer)
```bash
mrsh pack --platform windows --key ~/.ssh/id_ed25519.pub --port 8822 \
          --rendezvous-server rendezvous.example.com:21116 -o installer.exe
```
The installer bundles binary + authorized_keys + firewall rules + service registration.
**v1.9.7+**: installer MERGES keys with existing authorized_keys (never overwrites).

### Fleet update (existing machines)
```bash
mrsh -h <host> push local/mrsh.exe 'C:\ProgramData\mrsh\mrsh-new.exe'
mrsh -h <host> self-update 'C:\ProgramData\mrsh\mrsh-new.exe'
```
**v1.9.6+**: self-update uses rename-swap (no more ROLLBACK failures).

### Debug mode
```bash
mrsh -d [-p PORT]    # foreground, verbose, no relay/rdv, Ctrl+C to stop
```
Version reports as "X.Y.Z-debug". Useful for diagnostics and recovery.

## KEY MANAGEMENT

- ALWAYS use `mrsh keys add/remove/list` — NEVER edit authorized_keys manually.
- **Hot-reload** (v1.9.4+): keys added AFTER server start are recognized immediately.
- **Multi-path search** (v1.9.3+): loads keys from ALL possible locations:
  - Windows: `C:\ProgramData\mrsh\` + `%USERPROFILE%\.mrsh\` + legacy `remote-shell\`
  - Linux: `/etc/rsh/` + `~/.mrsh/`
- **Non-admin fallback** (v1.9.6+): `keys add` falls back to `~/.mrsh/` when ProgramData not writable.
- Remote key management:
  ```bash
  mrsh -h <host> keys add '<pubkey-string>'
  mrsh -h <host> keys list
  mrsh -h <host> keys remove '<fingerprint-or-comment>'
  ```

## FLEET DISCOVERY

```bash
mrsh fleet discover --group <name>
```
Shows all peers in the enrollment group with:
- DeviceID, hostname, platform, WAN address
- **Decrypted LAN IPs** (v1.9.8+): extracted from encrypted network info blob

## SELF-UPDATE

- CRITICAL: NEVER kill/stop/restart mrsh through its own connection.
- SAFE PROCEDURE:
  1. Verify alternative access BEFORE touching service.
  2. Canonical dir: `C:\ProgramData\mrsh\` (binary: `mrsh.exe`)
  3. Push + self-update (uses rename-swap internally).
  4. Wait 15s, verify: `mrsh -h <host> exec "hostname"`

## REMOTE EXECUTION — NO ORPHAN PROCESSES

```
CORRECT: mrsh exec 'Get-Process | Where-Object { $_.Name -eq "app" }'
WRONG:   mrsh exec 'cmd /k "dir"'        ← leaves orphan cmd.exe window
WRONG:   mrsh exec 'start /b script.bat'  ← leaves orphan console
```
Use `cmd /c` (auto-exits) not `/k` (keeps open).

## HIDDEN SCHTASK EXECUTION

Use VBS wrapper to launch PowerShell hidden (window style 0):
```vbs
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell ... -File """ & WScript.Arguments(0) & """", 0, True
```
Deploy: `mrsh push run-hidden.vbs 'C:/Temp/run-hidden.vbs'`
Usage: `/tr "wscript C:\Temp\run-hidden.vbs C:\Temp\script.ps1"`
NEVER use `/it` flag with schtasks via SSH/mrsh — requires interactive desktop logon.
