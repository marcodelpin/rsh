# Shell Behavior Matrix

Cross-platform interactive shell behavior for `mrsh shell` / `mrsh attach`.

## Architecture Overview

```
Client (stdin/stdout) <--TLS/QUIC--> Server (PTY/ConPTY) <--> Shell process
```

- **Client** (`mrsh-client/src/shell.rs`): raw mode, stdin relay, tilde escapes, resize
- **Server** (`mrsh-server/src/shell.rs`): PTY (Unix) or ConPTY (Windows), shell spawn
- **Wire**: length-prefixed frames via `mrsh-core::wire`, resize = `0x01` prefix + 4 bytes
- **Terminal helpers**: `mrsh-core/src/terminal.rs` — `encode_resize()` / `parse_resize()` shared
- **Dispatch**: `mrsh-server/src/dispatch.rs` routes `"shell"` / `"shell-persistent"` to `HijackAction`

### Data flow

```
                   TLS path                           QUIC path
              ┌──────────────┐                   ┌──────────────┐
  stdin ─────>│ relay_loop() │──send_message──>  │quic_relay    │──send_message──>
              │  (tokio      │                   │  _loop()     │
  stdout <────│   select!)   │<─recv_message──   │              │<─recv_message──
              └──────────────┘                   └──────────────┘
                   ^                                  ^
                   │ mpsc channel                     │ mpsc channel
              ┌──────────────┐                   ┌──────────────┐
              │ stdin reader  │                   │ stdin reader  │
              │  thread       │                   │  thread       │
              │  (blocking)   │                   │  (blocking)   │
              └──────────────┘                   └──────────────┘
```

## Client OS Behavior

### Windows Client

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| Terminal size | `crossterm::terminal::size()`, fallback 80x24 | shell.rs:21 |
| Raw mode | `crossterm::terminal::enable_raw_mode()` — graceful fallback if not a terminal | shell.rs:39-48 |
| Stdin (interactive) | Opens `CONIN$` directly — `std::io::stdin().read()` returns `Ok(0)` on some Windows PTYs (mintty, WezTerm) in raw mode because the Rust stdin handle is attached to a console screen buffer that ConPTY/mintty redirected away from the real input device | shell.rs:140-157 |
| Stdin (piped) | Detects via `GetFileType() == FILE_TYPE_PIPE` (0x0003), falls back to `std::io::stdin()` | shell.rs:135-138 |
| Pipe detection | Win32 FFI: `GetFileType` on stdin raw handle. `GetConsoleMode`/`SetConsoleMode` are declared but unused — crossterm handles all console mode changes | shell.rs:118-129 |
| VT input constants | `ENABLE_VIRTUAL_TERMINAL_INPUT` (0x0200), `ENABLE_WINDOW_INPUT` (0x0008) declared but **not applied** — crossterm raw mode handles this | shell.rs:121-123 |
| Resize sending | `send_resize()` via `encode_resize()` exists but **not wired to window size change events** | shell.rs:302-309 |
| Stdin thread | Dedicated `std::thread::spawn` with blocking reads, mpsc channel to async loop — same pattern for both TLS and QUIC paths | shell.rs:85-191, 425-484 |

### Linux Client

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| Terminal size | Same crossterm path | shell.rs:21 |
| Raw mode | `crossterm::terminal::enable_raw_mode()` — sets cflag via termios | shell.rs:39-48 |
| Stdin | `std::io::stdin().read()` — blocking in spawned thread. fd 0 always points to the real terminal on Unix | shell.rs:173-190 |
| Resize sending | Same as Windows — **not wired to SIGWINCH** | shell.rs:302-309 |

### macOS Client

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| Terminal size | Same crossterm path | shell.rs:21 |
| Raw mode | Same crossterm path (POSIX termios) | shell.rs:39-48 |
| Stdin | Same as Linux — `std::io::stdin().read()` in dedicated thread | shell.rs:173-190 |
| Resize sending | Same — **not wired to SIGWINCH** | shell.rs:302-309 |

## Server OS Behavior

### Windows Server — TLS (ConPTY)

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| PTY creation | `CreatePseudoConsole()` with initial COORD from client size | shell.rs:338-343 |
| Shell selection | `choose_shell_windows()`: MRSH_SHELL env > pwsh.exe > powershell.exe (> cmd.exe never reached) | shell.rs:598-613 |
| Process spawn | `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` attribute list | shell.rs:410-422 |
| HPCON handle | Passed as `hpc.0 as *const c_void` (handle **value** cast to pointer) | shell.rs:365 |
| I/O relay | Blocking reader thread (ConPTY output pipe) -> mpsc channel(32) -> async select | shell.rs:446-471 |
| Ctrl+C translation | Incoming `0x03` is intercepted server-side; a detached helper attaches to the shell console and calls `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)` | shell.rs |
| Resize | `ResizePseudoConsole(hpc, COORD)` on control message | shell.rs:487-491 |
| Env vars | Full environment block: `BTreeMap` merge of inherited env + extras, UTF-16 double-null terminated | shell.rs:373-390 |
| Cleanup | `ClosePseudoConsole` -> drop input pipe -> abort reader -> close process handles (from raw usize) | shell.rs:531-544 |
| Process handle Send | `HANDLE` is `!Send` (*mut c_void). Raw `usize` extracted, `HANDLE` reconstructed only in sync cleanup | shell.rs:428-432, 540-542 |

### Linux Server — TLS (openpty)

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| PTY creation | `libc::openpty()` with initial winsize from client | shell.rs:59-79 |
| Shell selection | `choose_shell_unix()`: MRSH_SHELL env > /bin/bash > /bin/sh | shell.rs:560-592 |
| Process spawn | `tokio::process::Command` with `pre_exec` (close master, setsid, TIOCSCTTY, dup2 stdio to slave) | shell.rs:97-136 |
| TIOCSCTTY cast | musl: `c_int`, glibc/macOS: `c_ulong` — cfg-gated via `#[cfg(target_env = "musl")]` | shell.rs:119-122 |
| I/O relay | `dup(master)` for separate read/write File handles, blocking reader thread -> mpsc channel(32) | shell.rs:152-194 |
| Resize | `TIOCSWINSZ` ioctl on master + explicit `kill(-child_pid, SIGWINCH)` to child process group | shell.rs:211-227 |
| EIO handling | `EIO` on master read = slave closed (child exited) — normal PTY teardown on Linux/macOS | shell.rs:185-186 |
| Env vars | `cmd.env(k, v)` for each env var entry + `TERM=xterm-256color` | shell.rs:98-104 |
| Cleanup | drop master write file -> abort reader -> send EOF to client | shell.rs:263-268 |

### macOS Server — TLS (openpty)

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| PTY creation | Same openpty path as Linux | shell.rs:59-79 |
| TIOCSCTTY cast | `c_ulong` (same as glibc) via `#[cfg(not(target_env = "musl"))]` | shell.rs:122 |
| Shell selection | Same `choose_shell_unix()` — will find /bin/zsh if present (macOS default) | shell.rs:560-592 |
| Everything else | Identical to Linux path | - |

### Windows Server — QUIC (ConPTY)

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| PTY creation | Same `CreatePseudoConsole` pattern as TLS | quic.rs:945-960 |
| Shell selection | `shell::choose_shell_windows(&env_vars)` — parsed from handshake, honors MRSH_SHELL | quic.rs:981-983 |
| HPCON handle | Passed as value cast to pointer (`hpc.0 as *const c_void`) — matches TLS style | quic.rs:972 |
| Env vars | Forwarded via handshake `env=` tokens; UTF-16 env block built via `shell::build_windows_env_block()` (shared with TLS) | quic.rs (parse_shell_target + build_windows_env_block) |
| Relay loop | Same pattern as TLS (blocking reader thread, async select) | quic.rs:1006-1056 |
| Ctrl+C translation | Same ETX interception + generated console Ctrl+C path as TLS via shared shell helper | quic.rs + shell.rs |
| OK handshake | Sends `OK\n` before relay loop (QUIC protocol requirement) | quic.rs:1004 |

### Linux Server — QUIC (openpty)

| Aspect | Detail | File:Line |
|--------|--------|-----------|
| PTY creation | Same openpty+winsize pattern | quic.rs:737-754 |
| Shell selection | `shell::choose_shell_unix(&env_vars)` — parsed from handshake, honors MRSH_SHELL | quic.rs:764-766 |
| TIOCSCTTY cast | Properly cfg-gated (musl: c_int, glibc/macOS: c_ulong) | quic.rs:782-785 |
| Env vars | Forwarded via handshake `env=` tokens; each becomes `cmd.env(k, v)` | quic.rs (parse_shell_target) |
| OK handshake | Sends `OK\n` before relay loop (QUIC protocol requirement) | quic.rs:829 |
| Everything else | Structurally same as TLS Linux handler | - |

## QUIC Shell Paths

### QUIC Client (`mrsh-client/src/shell.rs`)

- `run_quic_shell()` at shell.rs:378 (behind `#[cfg(feature = "quic")]`)
- Uses the **same dedicated stdin thread + mpsc pattern** as TLS (shell.rs:425-484)
- Platform-specific stdin handling (CONIN$ on Windows, fd 0 on Unix) is identical to TLS
- Same escape processing (`process_escapes`) and relay logic
- Opens shell via `QuicClient::open_shell()` -> `shell\0{COLSxROWS}\n` header -> `OK\n` response

### QUIC Server

- **Linux/macOS**: `handle_quic_shell()` at quic.rs:725 — same PTY pattern as TLS
- **Windows**: `handle_quic_shell()` at quic.rs:925 — same ConPTY pattern as TLS
- Channel header protocol: `shell[\0{COLSxROWS}[\0env=KEY=VAL]*]\n` -> `OK\n` or `ERROR: ...\n`
- Server parses target via `parse_shell_target()` — splits on `\0`; first token = size; subsequent `env=KEY=VAL` tokens are forwarded as env vars; unknown tokens ignored (forward-compat)
- Old servers: see "Backward compatibility" below
- Bidirectional wire-framed chunks after handshake

### Backward compatibility (handshake)

Old servers split the channel header on the **first** `\0`, so an extended
header like `shell\0120x40\0env=MRSH_SHELL=pwsh\n` becomes target
`120x40\0env=MRSH_SHELL=pwsh`. `parse_size()` then splits on `x` and parses
parts; the second part contains a `\0` so `.parse::<u16>()` fails and falls
back to `24` (cols=120 still parses). Net effect on an old server:

- env vars are silently dropped
- size cols preserved, rows defaults to 24

This is the documented degradation mode. New clients can detect old servers
via the existing `version` field returned during auth and skip env tokens
when targeting old servers if exact size preservation is needed.

## Tilde Escape Sequences

Processed client-side only. Active after `\r` or `\n` (after_newline state).

| Sequence | Action | Condition |
|----------|--------|-----------|
| `~.` | Disconnect (send empty frame, return) | after newline only |
| `~~` | Send literal `~` | after newline only |
| `~?` | Print help text, continue | after newline only |
| `~<other>` | Send both `~` and char verbatim | after newline only |

Split-across-reads is handled: `in_escape` flag persists between `process_escapes` calls (shell.rs:252-296).

## Resize Protocol

Wire format: `[0x01, cols_hi, cols_lo, rows_hi, rows_lo]` (5 bytes, big-endian).
Defined in `mrsh-core/src/terminal.rs`.

| Side | What happens |
|------|-------------|
| Client sends resize | `encode_resize()` -> `send_message()` |
| Server receives | `parse_resize()` check in relay loop before forwarding to PTY |
| Windows server | `ResizePseudoConsole(hpc, COORD)` |
| Linux/macOS server | `ioctl(TIOCSWINSZ)` + `kill(-pid, SIGWINCH)` |

**Known gap**: Client does NOT currently detect terminal resize events and send them. The `send_resize` function and `encode_resize` exist but are not wired into the relay loop. Initial size is sent at connection time only.

## Persistent Sessions (attach)

- Client: `run_attach()` at shell.rs:316
- Request type: `"shell-persistent"` dispatched via `HijackAction::ShellPersistent`
- Session ID in `req.path`, read-only flag in `req.binary` (overloaded field)
- Server creates/attaches via `SessionStore`
- Same relay loop as regular shell
- `run_attach` now uses the same best-effort raw-mode helper as `run_shell`

## Shell Selection

### Unix (Linux/macOS) — `choose_shell_unix()`

Priority: MRSH_SHELL env > /bin/bash > /bin/sh

MRSH_SHELL values supported: `bash`, `/bin/bash`, `sh`, `/bin/sh`, `zsh`, `/bin/zsh`, `/usr/bin/zsh`, `fish` (checks existence), or any absolute path that exists.

### Windows — `choose_shell_windows()`

Priority: MRSH_SHELL env > pwsh.exe (if in PATH) > powershell.exe

MRSH_SHELL values supported: `pwsh`, `pwsh.exe`, `powershell`, `powershell.exe`, `cmd`, `cmd.exe`.

### QUIC paths

Both QUIC server handlers call the same `choose_shell_*` functions but pass `&[]` for env_vars, so MRSH_SHELL from the client is not honored over QUIC.

## Known Quirks and Divergences

### 1. Windows CONIN$ vs stdin (client-side)

`std::io::stdin().read()` returns `Ok(0)` immediately on mintty/WezTerm PTYs in raw mode. The Rust stdin handle is attached to a console screen buffer that ConPTY/mintty redirected away from the real input device. Opening `CONIN$` directly bypasses this — it always refers to the actual console input device. Piped stdin is detected via `GetFileType` to avoid CONIN$ when stdin is a pipe.

**Ref**: shell.rs:96-171

### 2. Win32 constants declared but unused (client-side)

`ENABLE_VIRTUAL_TERMINAL_INPUT` and `ENABLE_WINDOW_INPUT` are defined in a `win32` module along with `GetConsoleMode`/`SetConsoleMode` FFI declarations, but only `GetFileType` is actually called. crossterm handles all console mode management. The unused declarations are annotated with `#[allow(dead_code)]`.

**Ref**: shell.rs:118-129

### 3. HPCON handle passing divergence (TLS vs QUIC server)

TLS handler passes HPCON as `hpc.0 as *const c_void` (the handle **value** reinterpreted as a pointer). QUIC handler passes it as `&hpc as *const HPCON as *const c_void` (a pointer **to** the HPCON struct). Both work because `HPCON` is `repr(transparent)` around `isize`, so `&hpc` points to the `isize` value — `UpdateProcThreadAttribute` reads `size_of::<HPCON>()` bytes from the pointer, getting the same `isize` value either way. However, the TLS approach is semantically more correct (passes value-as-pointer matching the Windows API convention). **Could be normalized.**

**Ref**: shell.rs:365 vs quic.rs:972

### 4. Process handle Send workaround (Windows server)

`HANDLE` is `!Send` because it contains `*mut c_void`. Both TLS and QUIC handlers extract raw `usize` values from `PROCESS_INFORMATION` and reconstruct `HANDLE` only in the synchronous cleanup section. This avoids holding `!Send` types across await points.

**Ref**: shell.rs:428-432, 540-542; quic.rs:995-997, 1063-1065

### 5. musl vs glibc TIOCSCTTY ioctl type (Unix server)

`ioctl` request type differs: musl = `c_int`, glibc/macOS = `c_ulong`. All three Unix shell paths (TLS, QUIC Linux, QUIC macOS) now have proper `#[cfg(target_env = "musl")]` gating.

**Ref**: shell.rs:119-122; quic.rs:782-785

### 6. No runtime resize (client)

Client detects terminal size at connection time only. Dynamic resize requires wiring `SIGWINCH` (Unix) or console buffer change events (Windows) into the relay loop. The `send_resize` / `encode_resize` functions exist but are not called during the session.

### 7. QUIC server does not forward env_vars

Both QUIC server `handle_quic_shell` implementations pass `&[]` to `choose_shell_*`, meaning MRSH_SHELL from the client is not honored. The QUIC channel protocol (`shell\0{size}\n`) has no provision for passing env vars — it would need a protocol extension. Additionally, the Windows QUIC server does not build an environment block (passes `None` to `CreateProcessW`), so extra env vars are not forwarded to the child shell.

**Ref**: quic.rs:766 (Linux), quic.rs:983, 989 (Windows)

### 8. QUIC Windows server: no env block

TLS Windows server builds a full UTF-16 environment block merging inherited env + extras. QUIC Windows server passes `None` — child inherits the server's environment unmodified. **Could be normalized.**

**Ref**: shell.rs:373-390 (TLS) vs quic.rs:989 (QUIC, no block)

### 9. Read buffer size difference

TLS server reader threads and QUIC server reader threads both use 32768-byte buffers, matching. Client stdin threads use 4096-byte buffers. This is fine — stdin produces much less data than PTY output — but is an asymmetry worth noting.

### 10. Logging verbosity difference

TLS Windows ConPTY handler uses `info!` level for relay events (every data chunk logged). TLS Unix handler and both QUIC handlers use `debug!` for relay events. The ConPTY path will produce significantly more log output. This appears to be leftover debug instrumentation.

**Ref**: shell.rs:479 (`info!` for client data), shell.rs:514-515 (`info!` for ConPTY output) vs shell.rs:206/237 (`debug!` for Unix)

## Normalization Opportunities (future work)

The following divergences are unnecessary and could be normalized without behavior changes:

| Divergence | TLS path | QUIC path | Effort |
|-----------|----------|-----------|--------|
| HPCON passing style | `hpc.0 as *const` | `&hpc as *const HPCON as *const` | Trivial — align QUIC to TLS style |
| QUIC env_vars forwarding | Full support | Passes `&[]` | Medium — needs QUIC channel protocol extension |
| QUIC Windows env block | BTreeMap merge | None (inherit) | Medium — depends on env_vars protocol |
| ConPTY logging level | `info!` | `debug!` | Trivial — change `info!` to `debug!` in TLS handler |
| `run_attach` raw mode | Best-effort fallback helper | N/A (no QUIC attach) | Done |
