//! Shell relay protocol — bidirectional terminal over length-prefixed frames.
//! On Windows: uses ConPTY. On Linux (testing): uses /bin/sh with pty.
//! Control message: 0x01 + cols(2 BE) + rows(2 BE) = resize.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

pub use mrsh_core::terminal::{RESIZE_PREFIX, encode_resize, parse_resize};
use mrsh_core::wire;

/// Parse terminal size from "COLSxROWS" string (e.g., "80x24").
pub fn parse_size(size_str: &str) -> (u16, u16) {
    let parts: Vec<&str> = size_str.split('x').collect();
    if parts.len() == 2 {
        let cols = parts[0].parse().unwrap_or(80);
        let rows = parts[1].parse().unwrap_or(24);
        (cols, rows)
    } else {
        (80, 24)
    }
}

/// Build a UTF-16 double-null-terminated environment block for `CreateProcessW`.
///
/// Merges the process-inherited environment with `env_vars` (each entry in
/// `KEY=VAL` form). `env_vars` entries override inherited values on key
/// collision.
///
/// Returns `None` when `env_vars` is empty — caller should then pass a null
/// environment pointer so the child inherits the server's env unmodified.
///
/// Shared between the TLS and QUIC Windows shell handlers to avoid divergence.
#[cfg(target_os = "windows")]
pub fn build_windows_env_block(env_vars: &[String]) -> Option<Vec<u16>> {
    if env_vars.is_empty() {
        return None;
    }
    let mut env_map: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    for e in env_vars {
        if let Some((k, v)) = e.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in &env_map {
        let entry = format!("{}={}", k, v);
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    block.push(0); // double-null terminator
    Some(block)
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsCtrlEvent {
    CtrlC,
    CtrlBreak,
}

#[cfg(target_os = "windows")]
impl WindowsCtrlEvent {
    fn as_arg(self) -> &'static str {
        match self {
            Self::CtrlC => "ctrl-c",
            Self::CtrlBreak => "ctrl-break",
        }
    }
}

#[cfg(target_os = "windows")]
fn ctrl_helper_log(message: impl AsRef<str>) {
    println!("mrsh-ctrl-helper: {}", message.as_ref());
}

#[cfg(target_os = "windows")]
fn push_console_key_event(
    records: &mut Vec<windows::Win32::System::Console::INPUT_RECORD>,
    key_down: bool,
    virtual_key: u16,
    scan_code: u16,
    unicode_char: u16,
    control_state: u32,
) {
    use windows::core::BOOL;
    use windows::Win32::System::Console::{INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD};

    let mut key_event = KEY_EVENT_RECORD {
        bKeyDown: BOOL::from(key_down),
        wRepeatCount: 1,
        wVirtualKeyCode: virtual_key,
        wVirtualScanCode: scan_code,
        uChar: Default::default(),
        dwControlKeyState: control_state,
    };
    key_event.uChar.UnicodeChar = unicode_char;

    let mut input = INPUT_RECORD {
        EventType: KEY_EVENT as u16,
        Event: Default::default(),
    };
    input.Event.KeyEvent = key_event;
    records.push(input);
}

#[cfg(target_os = "windows")]
fn write_ctrl_c_console_input() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{INPUT_RECORD, LEFT_CTRL_PRESSED, WriteConsoleInputW};

    const VK_CONTROL: u16 = 0x11;
    const VK_C: u16 = b'C' as u16;
    const SCAN_CONTROL: u16 = 0x1d;
    const SCAN_C: u16 = 0x2e;

    let console_input = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .context("open CONIN$ for WriteConsoleInputW")?;
    let handle = HANDLE(console_input.as_raw_handle() as *mut std::ffi::c_void);

    let mut records: Vec<INPUT_RECORD> = Vec::with_capacity(4);
    push_console_key_event(
        &mut records,
        true,
        VK_CONTROL,
        SCAN_CONTROL,
        0,
        LEFT_CTRL_PRESSED,
    );
    push_console_key_event(
        &mut records,
        true,
        VK_C,
        SCAN_C,
        0x03,
        LEFT_CTRL_PRESSED,
    );
    push_console_key_event(
        &mut records,
        false,
        VK_C,
        SCAN_C,
        0,
        LEFT_CTRL_PRESSED,
    );
    push_console_key_event(&mut records, false, VK_CONTROL, SCAN_CONTROL, 0, 0);

    let mut written = 0u32;
    unsafe {
        WriteConsoleInputW(handle, &records, &mut written).context("WriteConsoleInputW")?;
    }
    if written != records.len() as u32 {
        anyhow::bail!(
            "WriteConsoleInputW wrote {} records, expected {}",
            written,
            records.len()
        );
    }

    Ok(())
}

/// Parse the hidden helper flag value (`ctrl-c` / `ctrl-break`).
#[cfg(target_os = "windows")]
pub fn parse_ctrl_event_name(name: &str) -> Result<WindowsCtrlEvent> {
    match name {
        "ctrl-c" => Ok(WindowsCtrlEvent::CtrlC),
        "ctrl-break" => Ok(WindowsCtrlEvent::CtrlBreak),
        other => anyhow::bail!("unsupported ctrl event '{}'", other),
    }
}

/// One-shot helper entrypoint: attach to an existing console and synthesize Ctrl+C/Break.
///
/// This is intentionally process-local and short lived. The main server process keeps its
/// own console state untouched and spawns a detached helper when it needs to translate
/// an incoming ETX byte into a real Windows console control event.
#[cfg(target_os = "windows")]
pub fn run_ctrl_helper(attach_pid: u32, event: WindowsCtrlEvent) -> Result<()> {
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::Console::{
        AttachConsole, CTRL_BREAK_EVENT, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
        SetConsoleCtrlHandler,
    };

    let helper_pid = std::process::id();
    ctrl_helper_log(format!(
        "helper_pid={} attach_pid={} event={:?}",
        helper_pid, attach_pid, event
    ));

    unsafe {
        let _ = FreeConsole();
    }

    let attach_started = Instant::now();
    let attach_result = unsafe { AttachConsole(attach_pid) };
    let attach_last_error = unsafe { GetLastError() };
    match attach_result {
        Ok(()) => ctrl_helper_log(format!(
            "AttachConsole succeeded for attach_pid={} helper_pid={} raw_last_error={}",
            attach_pid, helper_pid, attach_last_error.0
        )),
        Err(err) => {
            ctrl_helper_log(format!(
                "AttachConsole failed for attach_pid={} helper_pid={} raw_last_error={} error={:?}",
                attach_pid, helper_pid, attach_last_error.0, err
            ));
            return Err(err).context("AttachConsole");
        }
    }

    unsafe {
        SetConsoleCtrlHandler(None, true).context("SetConsoleCtrlHandler")?;
    }

    if event == WindowsCtrlEvent::CtrlC {
        let key_inject_started = Instant::now();
        match write_ctrl_c_console_input() {
            Ok(()) => ctrl_helper_log(format!(
                "WriteConsoleInputW injected synthetic Ctrl+C after_attach_ms={} inject_ms={}",
                attach_started.elapsed().as_millis(),
                key_inject_started.elapsed().as_millis()
            )),
            Err(err) => ctrl_helper_log(format!(
                "WriteConsoleInputW failed after_attach_ms={} inject_ms={} error={:#}",
                attach_started.elapsed().as_millis(),
                key_inject_started.elapsed().as_millis(),
                err
            )),
        }
    }

    unsafe {
        let event_type = match event {
            WindowsCtrlEvent::CtrlC => CTRL_C_EVENT,
            WindowsCtrlEvent::CtrlBreak => CTRL_BREAK_EVENT,
        };
        let generate_started = Instant::now();
        let generate_result = GenerateConsoleCtrlEvent(event_type, 0);
        let generate_last_error = GetLastError();
        match generate_result {
            Ok(()) => ctrl_helper_log(format!(
                "GenerateConsoleCtrlEvent({:?}, 0) succeeded after_attach_ms={} call_ms={} raw_last_error={}",
                event_type,
                attach_started.elapsed().as_millis(),
                generate_started.elapsed().as_millis(),
                generate_last_error.0
            )),
            Err(err) => {
                ctrl_helper_log(format!(
                    "GenerateConsoleCtrlEvent({:?}, 0) failed after_attach_ms={} call_ms={} raw_last_error={} error={:?}",
                    event_type,
                    attach_started.elapsed().as_millis(),
                    generate_started.elapsed().as_millis(),
                    generate_last_error.0,
                    err
                ));
                return Err(err).context("GenerateConsoleCtrlEvent");
            }
        }
        ctrl_helper_log("sleeping 500ms before FreeConsole");
        std::thread::sleep(Duration::from_millis(500));
        let _ = FreeConsole();
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn spawn_ctrl_helper(attach_pid: u32, event: WindowsCtrlEvent) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::time::Instant;
    use windows::Win32::System::Threading::{CREATE_NO_WINDOW, DETACHED_PROCESS};

    let exe = std::env::current_exe().context("current_exe for ctrl helper")?;
    let started = Instant::now();
    let output = Command::new(exe)
        .arg("--signal-helper")
        .arg("--attach-pid")
        .arg(attach_pid.to_string())
        .arg("--ctrl-event")
        .arg(event.as_arg())
        .creation_flags(DETACHED_PROCESS.0 | CREATE_NO_WINDOW.0)
        .output()
        .context("spawn ctrl helper")?;
    let elapsed_ms = started.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    for line in stdout.lines() {
        debug!("shell: ctrl helper stdout: {}", line);
    }
    for line in stderr.lines() {
        debug!("shell: ctrl helper stderr: {}", line);
    }

    if output.status.success() {
        debug!(
            "shell: ctrl helper completed in {}ms for pid {} event {:?}",
            elapsed_ms, attach_pid, event
        );
        Ok(())
    } else {
        anyhow::bail!(
            "ctrl helper exited with status {} after {}ms (stdout={} bytes, stderr={} bytes)",
            output.status,
            elapsed_ms,
            output.stdout.len(),
            output.stderr.len()
        );
    }
}

#[cfg(target_os = "windows")]
fn shell_input_debug_bytes(data: &[u8]) -> String {
    const MAX_BYTES: usize = 64;

    let mut out = String::new();
    for (idx, byte) in data.iter().take(MAX_BYTES).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    if data.len() > MAX_BYTES {
        out.push_str(" ...");
    }
    out
}

#[cfg(target_os = "windows")]
pub(crate) fn write_windows_shell_input(
    in_file: &mut std::fs::File,
    shell_pid: u32,
    data: &[u8],
) -> Result<()> {
    use std::io::Write;

    // Normalise DEL (0x7F) → BS (0x08). Linux-style terminals (xterm, VS Code,
    // WezTerm, Windows Terminal in many configs) send 0x7F when the user
    // presses Backspace, but Windows ConPTY-hosted pwsh.exe only deletes on
    // 0x08. Without this translation the user sees their typing accumulate
    // and backspace never removes a char. We do NOT touch the real Delete
    // key (which sends ESC[3~, not 0x7F).
    let mut normalised: Vec<u8> = Vec::with_capacity(data.len());
    let mut changed = false;
    for &b in data {
        if b == 0x7F {
            normalised.push(0x08);
            changed = true;
        } else {
            normalised.push(b);
        }
    }
    let data: &[u8] = if changed { &normalised } else { data };

    if data.contains(&0x03) {
        info!(
            "shell: writing {} input bytes to ConPTY (contains_ctrl_c=true, shell_pid={}, backspace_norm={}, hex=[{}])",
            data.len(),
            shell_pid,
            changed,
            shell_input_debug_bytes(data)
        );
    } else {
        debug!(
            "shell: writing {} input bytes to ConPTY (contains_ctrl_c=false, shell_pid={}, backspace_norm={}, hex=[{}])",
            data.len(),
            shell_pid,
            changed,
            shell_input_debug_bytes(data)
        );
    }

    let mut start = 0usize;
    for (idx, byte) in data.iter().enumerate() {
        if *byte != 0x03 {
            continue;
        }

        if idx > start {
            in_file
                .write_all(&data[start..idx])
                .context("write shell input chunk")?;
        }

        // rsh-o0e: prefer CTRL_C_EVENT path exclusively when we have a shell
        // pid to attach to. Writing the raw 0x03 byte to ConPTY *in addition*
        // to dispatching CTRL_C_EVENT leaves a stray ETX in ConPTY's input
        // buffer: pwsh's native Ctrl+C handler (fired by CTRL_C_EVENT) cancels
        // the current pipeline, but the orphan 0x03 byte then gets prepended
        // to the NEXT user command, causing PSReadLine / the parser to read
        // e.g. "\x03Write-Output ..." and reject it as an unknown command
        // ("The term 'Write-Output' is not recognized ..."). CTRL_C_EVENT via
        // the attached helper is the canonical, pwsh-native interrupt path;
        // the raw-ETX write is only a fallback for when we lack the pid (the
        // shell was launched externally to our ConPTY, etc.).
        let mut raw_etx_written = false;
        if shell_pid != 0 {
            info!(
                "shell: dispatching CTRL_C_EVENT helper for pid {} at input offset {} (suppressing raw ETX into ConPTY)",
                shell_pid, idx
            );
            match spawn_ctrl_helper(shell_pid, WindowsCtrlEvent::CtrlC) {
                Ok(()) => {
                    info!(
                        "shell: CTRL_C_EVENT helper completed successfully for pid {} — raw ETX NOT written to ConPTY",
                        shell_pid
                    );
                }
                Err(err) => {
                    info!(
                        "shell: CTRL_C_EVENT helper failed for pid {}: {:#} — falling back to raw ETX write",
                        shell_pid, err
                    );
                    in_file
                        .write_all(&data[idx..idx + 1])
                        .context("fallback raw ctrl-c to conpty after helper failure")?;
                    raw_etx_written = true;
                }
            }
        } else {
            info!(
                "shell: shell pid unavailable at input offset {}, writing raw ETX as only Ctrl+C path",
                idx
            );
            in_file
                .write_all(&data[idx..idx + 1])
                .context("write raw ctrl-c to conpty (no pid)")?;
            raw_etx_written = true;
        }
        let _ = raw_etx_written; // reserved for future telemetry

        start = idx + 1;
    }

    if start < data.len() {
        in_file
            .write_all(&data[start..])
            .context("write shell input tail")?;
    }
    in_file.flush().context("flush shell input")?;
    Ok(())
}

/// Handle a shell session over the mrsh stream using a real PTY.
///
/// # Unix PTY architecture
///
/// Uses `openpty(3)` to create a pseudo-terminal pair (master/slave). The
/// child shell process gets the slave as its controlling terminal (via
/// `setsid` + `TIOCSCTTY`), while the parent (server) reads/writes the
/// master side. This gives us proper terminal emulation: line discipline,
/// signal delivery (Ctrl-C → SIGINT), and job control.
///
/// # Resize handling
///
/// Client sends resize control messages (0x01 prefix). Server translates
/// these to `TIOCSWINSZ` ioctls on the master fd, which updates the kernel
/// winsize struct. We also send `SIGWINCH` explicitly to the child process
/// group because some shells only check winsize on signal receipt.
///
/// # Platform differences
///
/// - **glibc/macOS**: `TIOCSCTTY` ioctl request type is `c_ulong`
/// - **musl/Android Bionic**: `TIOCSCTTY` ioctl request type is `c_int`
///   Both are handled via `#[cfg(target_env)]` / `#[cfg(target_os)]` gating in `pre_exec`.
#[cfg(not(target_os = "windows"))]
pub async fn handle_shell<S>(stream: &mut S, size_str: &str, env_vars: &[String]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use std::os::unix::io::{FromRawFd, RawFd};

    let (cols, rows) = parse_size(size_str);
    info!("PTY shell session: {}x{}", cols, rows);

    // Create PTY pair with initial window size.
    // openpty() allocates both master and slave fds and sets the initial
    // terminal size. We pass NULL for name/termios — defaults are fine.
    let mut master: RawFd = 0;
    let mut slave: RawFd = 0;
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const libc::winsize as *mut libc::winsize,
        )
    } != 0
    {
        anyhow::bail!("openpty failed: {}", std::io::Error::last_os_error());
    }

    // Choose shell: MRSH_SHELL env > $SHELL > /bin/bash > /bin/sh
    let shell = choose_shell_unix(env_vars);

    // Spawn child with slave PTY as controlling terminal.
    //
    // The pre_exec closure runs in the forked child BEFORE exec. It must:
    // 1. Close master fd (child doesn't need the master side)
    // 2. Create a new session (setsid) so child is session leader
    // 3. Set the slave as controlling terminal (TIOCSCTTY)
    // 4. Redirect stdin/stdout/stderr to the slave fd
    //
    // After exec, the child shell sees the slave PTY as its terminal,
    // gets proper terminal signals (SIGINT, SIGTSTP), and supports
    // job control.
    let slave_fd = slave;
    let master_fd = master;
    let mut cmd = tokio::process::Command::new(shell);
    cmd.env("TERM", "xterm-256color");
    cmd.kill_on_drop(true);
    // Match SSH behavior: launch shell with cwd = $HOME, not the daemon's
    // cwd (which is /etc/mrsh, the data dir). User-reported bug rsh-lyi4:
    // 'mrsh shell' landed users in the data dir, surprising vs SSH which lands
    // them in their home. Prefer client-forwarded HOME env, fall back to
    // server's own HOME, last resort skip (cmd inherits cwd unchanged).
    let home = env_vars
        .iter()
        .find_map(|e| e.strip_prefix("HOME=").map(str::to_string))
        .or_else(|| std::env::var("HOME").ok());
    if let Some(h) = &home {
        if !h.is_empty() && std::path::Path::new(h).exists() {
            cmd.current_dir(h);
        }
    }
    for e in env_vars {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    unsafe {
        cmd.pre_exec(move || {
            // Close master fd in child — only the parent reads/writes master
            libc::close(master_fd);
            // Create new session — makes this process the session leader,
            // required before TIOCSCTTY can set a controlling terminal
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Set controlling terminal.
            // The ioctl request type differs between C library implementations:
            // - glibc/macOS: ioctl(2) takes `unsigned long` (c_ulong) for request
            // - musl libc: ioctl(2) takes `int` (c_int) for request
            // Without this cfg gate, musl builds fail with a type mismatch.
            // Android Bionic libc also takes c_int for ioctl request, like musl.
            #[cfg(any(target_env = "musl", target_os = "android"))]
            let tiocsctty = libc::TIOCSCTTY as libc::c_int;
            #[cfg(not(any(target_env = "musl", target_os = "android")))]
            let tiocsctty = libc::TIOCSCTTY as libc::c_ulong;
            if libc::ioctl(slave_fd, tiocsctty, 0 as libc::c_int) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Redirect stdio to slave PTY — the child's stdin/stdout/stderr
            // become the slave side of the PTY pair
            libc::dup2(slave_fd, 0);
            libc::dup2(slave_fd, 1);
            libc::dup2(slave_fd, 2);
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            Ok(())
        });
    }

    let child = cmd.spawn().context("spawn shell")?;
    let child_pid = child.id().unwrap_or(0) as libc::pid_t;
    // Keep child alive (kill_on_drop fires when dropped at end of scope)
    let _child = child;

    // Close slave in parent (child has its own copy after fork)
    unsafe {
        libc::close(slave);
    }

    // Duplicate master fd so we can have separate File handles for reading
    // and writing. File::from_raw_fd takes ownership and closes the fd on
    // drop — without dup, the reader thread's File would close the same fd
    // that the writer needs.
    let master_write_fd = unsafe { libc::dup(master) };
    if master_write_fd < 0 {
        anyhow::bail!("dup(master) failed: {}", std::io::Error::last_os_error());
    }

    // Spawn blocking reader thread: PTY master output → mpsc channel.
    //
    // Same pattern as Windows ConPTY reader thread below. We use a blocking
    // thread + mpsc channel rather than tokio::io::AsyncFd because:
    // 1. PTY master fds can block indefinitely — spawn_blocking is correct
    // 2. The channel bridges blocking I/O and the async select loop cleanly
    // 3. EIO on read is the normal way Unix PTYs signal child exit
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(master) };
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    // EIO = slave side closed (child exited) — this is the
                    // normal PTY teardown signal on Linux/macOS. The kernel
                    // returns EIO on the master when no process has the slave
                    // open anymore.
                    if e.raw_os_error() == Some(libc::EIO) {
                        break;
                    }
                    debug!("PTY read error: {}", e);
                    break;
                }
            }
        }
        // f dropped here → closes the master read fd
    });

    // Write handle for master PTY
    let mut master_file = unsafe { std::fs::File::from_raw_fd(master_write_fd) };

    // Bidirectional relay loop
    loop {
        tokio::select! {
            // Client → PTY
            result = wire::recv_message(stream) => {
                match result {
                    Ok(data) if data.is_empty() => {
                        debug!("shell: client EOF");
                        break;
                    }
                    Ok(data) => {
                        // Check for resize control message
                        if let Some((c, r)) = parse_resize(&data) {
                            let new_ws = libc::winsize {
                                ws_row: r,
                                ws_col: c,
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            unsafe {
                                libc::ioctl(master_write_fd, libc::TIOCSWINSZ, &new_ws);
                                // TIOCSWINSZ on master sends SIGWINCH to foreground pgrp,
                                // but also signal child process group explicitly
                                if child_pid > 0 {
                                    libc::kill(-child_pid, libc::SIGWINCH);
                                }
                            }
                            continue;
                        }
                        // Forward data to PTY
                        use std::io::Write;
                        if master_file.write_all(&data).is_err()
                            || master_file.flush().is_err()
                        {
                            debug!("shell: PTY write failed");
                            break;
                        }
                    }
                    Err(_) => {
                        debug!("shell: client disconnected");
                        break;
                    }
                }
            }
            // PTY → Client
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(stream, &data).await.is_err() {
                            debug!("shell: send to client failed");
                            break;
                        }
                    }
                    None => {
                        // Reader thread exited — child process ended
                        debug!("shell: process exited");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup: close master write → reader thread gets EIO → exits
    drop(master_file);
    reader_task.abort();
    // Send EOF to client
    wire::send_message(stream, &[]).await.ok();
    info!("PTY shell session ended");
    Ok(())
}

/// Windows ConPTY shell handler — real pseudo-console implementation.
///
/// # ConPTY architecture
///
/// Windows pseudo-console (ConPTY, added in Windows 10 1809) provides a
/// POSIX-PTY-like abstraction. The data flow is:
///
/// ```text
/// mrsh client <--wire--> [input pipe] --> ConPTY --> [output pipe] --> reader thread
///                              ^                          |
///                              |                          v
///                         write_all()              channel → send_message()
/// ```
///
/// Two anonymous pipes connect to the ConPTY:
/// - **Input pipe** (pty_in_write): we write client keystrokes here
/// - **Output pipe** (pty_out_read): ConPTY's rendered output comes out here
///
/// The ConPTY owns copies of the other ends (pty_in_read, pty_out_write),
/// so we close our copies immediately after CreatePseudoConsole.
///
/// # HPCON handle
///
/// `HPCON` is an opaque `isize` (pseudo-console handle), NOT a kernel
/// HANDLE. It is passed to `UpdateProcThreadAttribute` as a pointer-to-value
/// (`hpc.0 as *const c_void`), not dereferenced as a pointer.
///
/// # Process handle Send safety
///
/// `HANDLE` contains `*mut c_void` which is `!Send`. We extract raw `usize`
/// values from `PROCESS_INFORMATION` and reconstruct `HANDLE` only in the
/// synchronous cleanup section at the end.
///
/// # Resize
///
/// Resize control messages (0x01 prefix) are translated to
/// `ResizePseudoConsole()` calls — the ConPTY equivalent of TIOCSWINSZ.
#[cfg(target_os = "windows")]
pub async fn handle_shell<S>(stream: &mut S, size_str: &str, env_vars: &[String]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use windows::core::BOOL;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
        STARTF_USESTDHANDLES,
    };

    let (cols, rows) = parse_size(size_str);
    info!("ConPTY shell session: {}x{}", cols, rows);

    // --- Create anonymous pipes for ConPTY ---
    let (pty_in_write, pty_out_read, hpc, shell_pid, proc_raw, thread_raw) = unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: BOOL::from(true),
        };
        let mut pty_in_read = HANDLE::default();
        let mut pty_in_write = HANDLE::default();
        let mut pty_out_read = HANDLE::default();
        let mut pty_out_write = HANDLE::default();

        CreatePipe(&mut pty_in_read, &mut pty_in_write, Some(&sa as *const _), 0)
            .context("CreatePipe input")?;
        CreatePipe(&mut pty_out_read, &mut pty_out_write, Some(&sa as *const _), 0)
            .context("CreatePipe output")?;

        // --- Create pseudo console ---
        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };
        let hpc = CreatePseudoConsole(size, pty_in_read, pty_out_write, 0)
            .context("CreatePseudoConsole")?;

        // --- Prepare process attribute list ---
        let mut attr_size: usize = 0;
        // First call: get required buffer size (returns error by design)
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attr_size);

        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as _);
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_size)
            .context("InitializeProcThreadAttributeList")?;

        // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
        const PSEUDOCONSOLE_ATTR: usize = 0x00020016;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PSEUDOCONSOLE_ATTR,
            Some(hpc.0 as *const std::ffi::c_void),
            std::mem::size_of::<HPCON>(),
            None,
            None,
        )
        .context("UpdateProcThreadAttribute")?;

        // --- Build environment block (inherit + extras) ---
        let env_block = build_windows_env_block(env_vars);

        // --- Create child process (preferred shell) ---
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // Some shells write via console APIs while others still use inherited
        // stdio handles. Point both at the ConPTY pipes so all output stays in-band.
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = pty_in_read;
        si.StartupInfo.hStdOutput = pty_out_write;
        si.StartupInfo.hStdError = pty_out_write;
        si.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION::default();
        let shell_exe = choose_shell_windows(env_vars);
        info!("shell: {}", shell_exe);
        let mut cmd: Vec<u16> = format!("{}\0", shell_exe).encode_utf16().collect();

        let env_ptr = env_block
            .as_ref()
            .map(|b| b.as_ptr() as *const std::ffi::c_void);
        let create_flags = EXTENDED_STARTUPINFO_PRESENT
            | CREATE_NO_WINDOW
            | if env_ptr.is_some() {
                windows::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT
            } else {
                windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0)
            };

        CreateProcessW(
            windows::core::PCWSTR::null(),
            Some(windows::core::PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            true,
            create_flags,
            env_ptr,
            windows::core::PCWSTR::null(),
            &si.StartupInfo,
            &mut pi,
        )
        .context("CreateProcessW")?;

        info!("shell: process created, pid={}", pi.dwProcessId);
        // Parent no longer needs the child-side ends after the process starts.
        let _ = CloseHandle(pty_in_read);
        let _ = CloseHandle(pty_out_write);
        DeleteProcThreadAttributeList(attr_list);
        // attr_buf dropped here — safe, attribute list no longer needed

        // Extract raw handle values from PROCESS_INFORMATION.
        // HANDLE(*mut c_void) is !Send, but the raw values (usize) are Send.
        // We reconstruct HANDLE only in the non-async cleanup section.
        let shell_pid = pi.dwProcessId;
        let proc_raw = pi.hProcess.0 as usize;
        let thread_raw = pi.hThread.0 as usize;
        (pty_in_write, pty_out_read, hpc, shell_pid, proc_raw, thread_raw)
    };

    // --- Convert pipe handles to File for blocking I/O ---
    // HANDLE(pub *mut c_void) — .0 is already RawHandle
    use std::os::windows::io::FromRawHandle;
    let out_file = unsafe { std::fs::File::from_raw_handle(pty_out_read.0) };
    let mut in_file = Some(unsafe { std::fs::File::from_raw_handle(pty_in_write.0) });

    // --- Spawn blocking reader thread (ConPTY output → channel) ---
    info!("shell: starting ConPTY reader thread");
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = out_file;
        let mut buf = [0u8; 32768];
        tracing::info!("shell reader: thread started, attempting first read...");
        loop {
            match f.read(&mut buf) {
                Ok(0) => {
                    tracing::info!("shell reader: EOF (0 bytes)");
                    break;
                }
                Ok(n) => {
                    tracing::info!("shell reader: got {} bytes", n);
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        tracing::info!("shell reader: channel send failed (receiver dropped)");
                        break;
                    }
                }
                Err(e) => {
                    tracing::info!("shell reader: read error: {}", e);
                    break;
                }
            }
        }
        tracing::info!("shell reader: thread exiting");
    });

    let (proc_exit_tx, mut proc_exit_rx) = tokio::sync::mpsc::channel::<()>(1);
    let proc_wait_task = tokio::task::spawn_blocking(move || {
        let proc_handle = HANDLE(proc_raw as *mut std::ffi::c_void);
        let _ = unsafe { WaitForSingleObject(proc_handle, u32::MAX) };
        let _ = proc_exit_tx.blocking_send(());
    });

    // --- Bidirectional relay loop ---
    //
    // CANCELLATION-SAFETY: earlier versions called `wire::recv_message(stream)`
    // directly inside `tokio::select!`. When the ConPTY-output branch fired
    // mid-read, the recv future was dropped and any partial-frame bytes it
    // had consumed from the TLS stream vanished with it — the next recv then
    // read a garbage length header and errored out. Now the header/body read
    // state lives OUTSIDE any future; a single `stream.read(target)` call
    // fills the external buffer, which survives cancellation.
    //
    // Writes to the stream (ConPTY output → client) happen at the TOP of
    // each loop iteration from a pending slot, after the previous `select!`
    // released the stream borrow.
    debug!("shell: entering relay loop");
    let mut conpty_closed = false;
    let mut header_buf = [0u8; 4];
    let mut header_filled: usize = 0;
    let mut body_buf: Vec<u8> = Vec::new();
    let mut body_filled: usize = 0;
    let mut reading_header = true;
    let mut pending_out: Option<Vec<u8>> = None;
    let mut rx_closed = false;
    loop {
        // Flush any queued ConPTY output bytes to the client before the next
        // read cycle. Stream isn't borrowed by anything else at this point.
        if let Some(data) = pending_out.take() {
            debug!("shell: ConPTY output {} bytes, sending to client", data.len());
            if wire::send_message(stream, &data).await.is_err() {
                debug!("shell: send to client FAILED");
                break;
            }
            info!("shell: sent to client OK");
        }

        let read_len_needed = if reading_header {
            4 - header_filled
        } else {
            body_buf.len() - body_filled
        };

        tokio::select! {
            read_result = async {
                use tokio::io::AsyncReadExt;
                if reading_header {
                    stream.read(&mut header_buf[header_filled..]).await
                } else {
                    stream.read(&mut body_buf[body_filled..]).await
                }
            }, if read_len_needed > 0 => {
                match read_result {
                    Ok(0) => {
                        debug!("shell: client disconnected (read 0)");
                        break;
                    }
                    Ok(n) => {
                        if reading_header {
                            header_filled += n;
                            if header_filled == 4 {
                                let length = u32::from_be_bytes(header_buf) as usize;
                                const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;
                                if length > MAX_MESSAGE_SIZE {
                                    debug!("shell: client frame too large ({} bytes), disconnecting", length);
                                    break;
                                }
                                if length == 0 {
                                    info!("shell: client EOF");
                                    break;
                                }
                                body_buf = vec![0u8; length];
                                body_filled = 0;
                                reading_header = false;
                            }
                        } else {
                            body_filled += n;
                            if body_filled == body_buf.len() {
                                let data = std::mem::take(&mut body_buf);
                                header_filled = 0;
                                body_filled = 0;
                                reading_header = true;
                                debug!("shell: client data event ({} bytes)", data.len());
                                // Check for resize control message
                                if let Some((c, r)) = parse_resize(&data) {
                                    unsafe {
                                        let sz = COORD { X: c as i16, Y: r as i16 };
                                        let _ = ResizePseudoConsole(hpc, sz);
                                    }
                                } else {
                                    // Forward data to ConPTY input
                                    let Some(inf) = in_file.as_mut() else {
                                        debug!("shell: input pipe already closed");
                                        break;
                                    };
                                    if let Err(err) = write_windows_shell_input(inf, shell_pid, &data) {
                                        debug!("shell: input pipe broken: {:#}", err);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        debug!("shell: client disconnected (read err)");
                        break;
                    }
                }
            }
            proc_exit = proc_exit_rx.recv(), if !conpty_closed => {
                if proc_exit.is_some() {
                    info!("shell: child process exited");
                    unsafe {
                        ClosePseudoConsole(hpc);
                    }
                    conpty_closed = true;
                    let _ = in_file.take();
                }
            }
            // ConPTY output → queue for next iteration's flush
            msg = rx.recv(), if !rx_closed && pending_out.is_none() => {
                match msg {
                    Some(data) => {
                        pending_out = Some(data);
                    }
                    None => {
                        info!("shell: ConPTY reader exited (process ended)");
                        rx_closed = true;
                        // If ConPTY is closed and no output is pending, we're done.
                        if pending_out.is_none() { break; }
                    }
                }
            }
        }
    }

    // --- Cleanup ---
    // Close ConPTY first — this breaks the pipe and unblocks the reader thread
    if !conpty_closed {
        unsafe {
            ClosePseudoConsole(hpc);
        }
    }
    // Drop input pipe to signal EOF to ConPTY
    let _ = in_file.take();
    // Wait for reader thread to finish (it should exit once pipe breaks)
    reader_task.abort();
    proc_wait_task.abort();
    // Close process handles (reconstruct HANDLE from raw usize values)
    unsafe {
        let _ = CloseHandle(HANDLE(proc_raw as *mut std::ffi::c_void));
        let _ = CloseHandle(HANDLE(thread_raw as *mut std::ffi::c_void));
    }
    // Signal EOF to client
    wire::send_message(stream, &[]).await.ok();
    info!("ConPTY shell session ended");
    Ok(())
}

/// Extract MRSH_SHELL from env_vars (format: "MRSH_SHELL=pwsh").
fn requested_shell(env_vars: &[String]) -> Option<String> {
    env_vars
        .iter()
        .find_map(|e| e.strip_prefix("MRSH_SHELL=").map(|s| s.to_string()))
}

/// Choose shell for Linux/macOS: MRSH_SHELL env > $SHELL > /bin/bash > /bin/sh.
///
/// Public so the QUIC shell handler can reuse the same logic instead of
/// duplicating shell selection with potential divergence.
#[cfg(not(target_os = "windows"))]
pub fn choose_shell_unix(env_vars: &[String]) -> &'static str {
    if let Some(req) = requested_shell(env_vars) {
        // Leak to get 'static — only called once per session
        match req.as_str() {
            "bash" | "/bin/bash" => return "/bin/bash",
            "sh" | "/bin/sh" => return "/bin/sh",
            "zsh" | "/bin/zsh" | "/usr/bin/zsh" => {
                if std::path::Path::new("/usr/bin/zsh").exists() {
                    return "/usr/bin/zsh";
                } else if std::path::Path::new("/bin/zsh").exists() {
                    // leak the string since we need 'static
                    return "/bin/zsh";
                }
            }
            "fish" => {
                if std::path::Path::new("/usr/bin/fish").exists() {
                    return "/usr/bin/fish";
                }
            }
            other => {
                let p = std::path::Path::new(other);
                if p.is_absolute() && p.exists() {
                    return Box::leak(other.to_string().into_boxed_str());
                }
            }
        }
    }
    if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    }
}

/// Choose shell for Windows: MRSH_SHELL env > pwsh.exe > powershell.exe > cmd.exe.
///
/// Public so the QUIC shell handler can reuse the same logic.
#[cfg(target_os = "windows")]
pub fn choose_shell_windows(env_vars: &[String]) -> &'static str {
    if let Some(req) = requested_shell(env_vars) {
        match req.to_lowercase().as_str() {
            "pwsh" | "pwsh.exe" => return "pwsh.exe",
            "powershell" | "powershell.exe" => return "powershell.exe",
            "cmd" | "cmd.exe" => return "cmd.exe",
            _ => {}
        }
    }
    // Default: prefer pwsh (7+) over powershell (5.1) over cmd
    if which_exists("pwsh.exe") {
        "pwsh.exe"
    } else {
        "powershell.exe"
    }
}

/// Check if an executable exists on PATH (Windows).
#[cfg(target_os = "windows")]
pub fn which_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).exists()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn init_test_tracing() {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_test_writer()
                .with_target(true)
                .try_init();
        });
    }

    #[test]
    fn parse_size_valid() {
        assert_eq!(parse_size("80x24"), (80, 24));
        assert_eq!(parse_size("120x40"), (120, 40));
    }

    #[test]
    fn parse_size_invalid_defaults() {
        assert_eq!(parse_size("invalid"), (80, 24));
        assert_eq!(parse_size(""), (80, 24));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_ctrl_event_names() {
        assert_eq!(
            parse_ctrl_event_name("ctrl-c").unwrap(),
            WindowsCtrlEvent::CtrlC
        );
        assert_eq!(
            parse_ctrl_event_name("ctrl-break").unwrap(),
            WindowsCtrlEvent::CtrlBreak
        );
        assert!(parse_ctrl_event_name("bogus").is_err());
    }

    // resize encode/decode tests moved to mrsh-core::terminal

    #[tokio::test]
    async fn shell_echo_test() {
        init_test_tracing();
        let (mut client, mut server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(async move { handle_shell(&mut server, "80x24", &[]).await });

        // Send a command
        wire::send_message(&mut client, b"echo hello\n")
            .await
            .unwrap();

        // Read output (may get prompt + echo)
        let output = wire::recv_message(&mut client).await.unwrap();
        assert!(!output.is_empty());

        // Send EOF
        wire::send_message(&mut client, &[]).await.unwrap();

        // Wait for shell to exit
        let _ = handle.await;
    }

    #[tokio::test]
    async fn shell_resize_is_filtered() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(async move { handle_shell(&mut server, "80x24", &[]).await });

        // Send resize control message — should not be forwarded to shell
        let resize = encode_resize(120, 40);
        wire::send_message(&mut client, &resize).await.unwrap();

        // Send actual command after resize
        wire::send_message(&mut client, b"echo resized\n")
            .await
            .unwrap();

        // Should get output (resize was silently consumed)
        let output = wire::recv_message(&mut client).await.unwrap();
        assert!(!output.is_empty());

        wire::send_message(&mut client, &[]).await.unwrap();
        let _ = handle.await;
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn shell_exit_command_ends_session_without_client_eof() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(async move { handle_shell(&mut server, "80x24", &[]).await });

        wire::send_message(&mut client, b"exit\n").await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let output = wire::recv_message(&mut client).await.unwrap();
                if output.is_empty() {
                    break;
                }
            }
        })
        .await
        .expect("shell session should end after exit command");

        handle.await.unwrap().unwrap();
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn shell_command_output_reaches_client() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let handle = tokio::spawn(async move { handle_shell(&mut server, "80x24", &[]).await });

        wire::send_message(&mut client, b"Write-Output MRSH_TEST_OUTPUT\r\n")
            .await
            .unwrap();
        wire::send_message(&mut client, b"exit\r\n").await.unwrap();

        let collected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut buf = Vec::new();
            loop {
                let output = wire::recv_message(&mut client).await.unwrap();
                if output.is_empty() {
                    break;
                }
                buf.extend_from_slice(&output);
            }
            buf
        })
        .await
        .expect("shell session should produce output and end");

        let text = String::from_utf8_lossy(&collected);
        assert!(
            text.contains("MRSH_TEST_OUTPUT"),
            "expected output marker in shell stream, got: {:?}",
            text
        );

        handle.await.unwrap().unwrap();
    }

}
