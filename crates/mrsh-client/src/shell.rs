//! Interactive shell relay — bidirectional terminal over wire protocol.
//! Client-side counterpart to rsh-server's ConPTY shell handler.
//! SSH-like tilde escape sequences: ~. disconnect, ~~ literal ~, ~? help.

use anyhow::{Context, Result, bail};
use crossterm::terminal;
use mrsh_core::wire;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
#[cfg(not(unix))]
use tokio::time::{Interval, MissedTickBehavior};
use tracing::{debug, info};

use crate::client::{RshClient, simple_request};

/// Run an interactive shell session.
/// Puts the terminal into raw mode, relays I/O between stdin/stdout and
/// the server's ConPTY, handles resize and tilde escapes.
pub async fn run_shell<S: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut RshClient<S>,
    env_vars: &[String],
) -> Result<()> {
    // Get terminal size
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let size_str = format!("{}x{}", cols, rows);

    // Send shell request
    let mut req = simple_request("shell");
    req.command = Some(size_str);
    if !env_vars.is_empty() {
        req.env_vars = Some(env_vars.to_vec());
    }
    let resp = client.request(&req).await?;
    if !resp.success {
        bail!(
            "shell failed: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        );
    }

    // Enter raw mode
    let raw_mode = enable_raw_mode_best_effort("interactive shell");
    let normalize_windows_newlines = remote_shell_prefers_windows_newlines(&client.server_caps);

    // Run the relay, ensuring we restore terminal on any exit path
    let stdin_rx = spawn_stdin_reader();
    let mut stdout = tokio::io::stdout();
    let result = relay_loop_with_io(
        client.stream_mut(),
        stdin_rx,
        &mut stdout,
        normalize_windows_newlines,
    )
    .await;

    // Always restore terminal
    disable_raw_mode_if_enabled(raw_mode);

    match result {
        Ok(exit) => {
            debug!("shell client: interactive relay finished with {:?}", exit);
            match exit {
                ShellExit::Disconnect => {
                    eprintln!("\r\nConnection closed.\r");
                    Ok(())
                }
                ShellExit::ServerEof => {
                    eprintln!("\r\nShell session ended.\r");
                    Ok(())
                }
            }
        }
        Err(e) => {
            debug!("shell client: interactive relay returned error: {e:#}");
            eprintln!("\r\nShell error: {}\r", e);
            Err(e)
        }
    }
}

#[derive(Debug)]
pub(crate) enum ShellExit {
    Disconnect,
    ServerEof,
}

const WINDOWS_FILE_TYPE_CHAR: u32 = 0x0002;
const WINDOWS_FILE_TYPE_PIPE: u32 = 0x0003;

fn should_use_conin_for_windows_stdin(stdin_file_type: u32, has_console_mode: bool) -> bool {
    stdin_file_type == WINDOWS_FILE_TYPE_CHAR && has_console_mode
}

fn shell_debug_bytes(data: &[u8]) -> String {
    const MAX_BYTES: usize = 32;

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

fn forward_stdin_reader<R>(
    mut reader: R,
    stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    source: &'static str,
)
where
    R: std::io::Read,
{
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                debug!("shell client: stdin reader {source} returned 0 bytes; stopping");
                break;
            }
            Ok(n) => {
                debug!(
                    "shell client: stdin reader {source} got {n} bytes hex=[{}]",
                    shell_debug_bytes(&buf[..n])
                );
                if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                    debug!("shell client: stdin reader {source} stopping because receiver dropped");
                    break;
                }
            }
            Err(err) => {
                debug!("shell client: stdin reader {source} error: {err}");
                break;
            }
        }
    }
}

/// Bidirectional relay between local terminal and remote shell.
/// Uses dedicated stdin thread + biased select to avoid cancellation issues.
/// Resize detection is platform-specific: SIGWINCH on Unix, polling elsewhere.
async fn relay_loop<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    normalize_windows_newlines: bool,
) -> Result<ShellExit> {
    let stdin_rx = spawn_stdin_reader();
    let mut stdout = tokio::io::stdout();
    relay_loop_with_io(stream, stdin_rx, &mut stdout, normalize_windows_newlines).await
}

/// Cancellation-safe relay loop.
///
/// The earlier implementation called `wire::recv_message(stream)` inside
/// `tokio::select!`. When stdin/resize branches fired while recv was mid-read,
/// the recv future was dropped and any partial-frame bytes it had already
/// consumed from the TLS stream vanished with it — next recv restarted from a
/// stale offset, read garbage as the length header, and blew up with
/// "message too large" errors. To fix it:
///
/// * The header/body read state lives OUTSIDE any future (arrays + counters
///   in the loop scope). A single `stream.read(target)` call fills the next
///   bytes into the external buffer; if the future is cancelled, no bytes are
///   lost because the buffer we wrote into survives.
/// * stdin + resize branches never call `stream.write` themselves — they only
///   stage pending work. Writes happen BEFORE the next `select!`, when no
///   read future is holding the stream. This keeps the borrow checker happy
///   and guarantees writes don't race with in-flight reads.
async fn relay_loop_with_io<S, W>(
    stream: &mut S,
    mut stdin_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    stdout: &mut W,
    normalize_windows_newlines: bool,
) -> Result<ShellExit>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;

    let (mut after_newline, mut in_escape) = (true, false);
    let mut last_size = terminal::size().ok();
    let mut stdin_closed = false;

    // Frame reader state — persists across select iterations so cancellation
    // of an in-flight read never loses partial-frame bytes.
    let mut header_buf = [0u8; 4];
    let mut header_filled: usize = 0;
    let mut body_buf: Vec<u8> = Vec::new();
    let mut body_filled: usize = 0;
    let mut reading_header = true;

    // Outbound work queued by stdin/resize branches. Drained at the top of
    // every iteration before the next `select!`.
    let mut pending_outbound: Option<Vec<u8>> = None;
    let mut pending_resize: Option<(u16, u16)> = None;
    let mut pending_disconnect = false;

    #[cfg(unix)]
    let mut resize_events =
        signal(SignalKind::window_change()).context("listen for terminal resize")?;

    #[cfg(not(unix))]
    let mut resize_events = make_resize_interval();

    loop {
        // Drain pending work synchronously — stream is not borrowed by any
        // in-flight future here, so we can freely write.
        if let Some(data) = pending_outbound.take() {
            debug!(
                "shell client: sending {} stdin bytes to server hex=[{}]",
                data.len(),
                shell_debug_bytes(&data)
            );
            wire::send_message(stream, &data)
                .await
                .context("send to server")?;
        }
        if let Some((cols, rows)) = pending_resize.take() {
            send_resize(stream, cols, rows)
                .await
                .context("send resize to server")?;
        }
        if pending_disconnect {
            info!("shell client: ~. escape detected, closing session");
            wire::send_message(stream, &[]).await.ok();
            return Ok(ShellExit::Disconnect);
        }

        // Select target slice for the next read. MUST be computed before the
        // `select!` because we pass a mutable borrow into `stream.read`.
        let read_len_needed = if reading_header {
            4 - header_filled
        } else {
            body_buf.len() - body_filled
        };
        // Guard: only poll stdin/resize when we aren't sitting on pending
        // outbound work (otherwise we'd overwrite unsent bytes).
        let can_accept_stdin =
            !stdin_closed && pending_outbound.is_none() && !pending_disconnect;
        let can_accept_resize = pending_resize.is_none();

        tokio::select! {
            biased;
            // Read branch: write directly into the external buffer.
            read_result = async {
                if reading_header {
                    stream.read(&mut header_buf[header_filled..]).await
                } else {
                    stream.read(&mut body_buf[body_filled..]).await
                }
            }, if read_len_needed > 0 => {
                match read_result {
                    Ok(0) => {
                        info!("shell client: stream closed by peer (read 0)");
                        return Ok(ShellExit::ServerEof);
                    }
                    Ok(n) => {
                        if reading_header {
                            header_filled += n;
                            if header_filled == 4 {
                                let length = u32::from_be_bytes(header_buf) as usize;
                                const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;
                                if length > MAX_MESSAGE_SIZE {
                                    info!(
                                        "shell client: message too large ({length} bytes), treating as server EOF"
                                    );
                                    return Ok(ShellExit::ServerEof);
                                }
                                if length == 0 {
                                    info!("shell client: server sent EOF frame — closing session");
                                    return Ok(ShellExit::ServerEof);
                                }
                                body_buf = vec![0u8; length];
                                body_filled = 0;
                                reading_header = false;
                            }
                        } else {
                            body_filled += n;
                            if body_filled == body_buf.len() {
                                let frame = std::mem::take(&mut body_buf);
                                stdout
                                    .write_all(&frame)
                                    .await
                                    .context("write to stdout")?;
                                stdout.flush().await.ok();
                                header_filled = 0;
                                body_filled = 0;
                                reading_header = true;
                            }
                        }
                    }
                    Err(err) => {
                        info!("shell client: read error, treating as server EOF: {err:#}");
                        return Ok(ShellExit::ServerEof);
                    }
                }
            }
            result = stdin_rx.recv(), if can_accept_stdin => {
                match result {
                    None => {
                        info!("shell client: stdin reader closed; continuing to drain remote output");
                        stdin_closed = true;
                    }
                    Some(input) => {
                        debug!(
                            "shell client: received stdin chunk {} bytes hex=[{}]",
                            input.len(),
                            shell_debug_bytes(&input)
                        );
                        let (out, action) =
                            process_escapes(&input, &mut after_newline, &mut in_escape);
                        let out = normalize_shell_input_for_remote(out, normalize_windows_newlines);
                        match action {
                            EscapeAction::Continue => {
                                if !out.is_empty() {
                                    pending_outbound = Some(out);
                                } else {
                                    debug!("shell client: stdin chunk consumed locally without outbound frame");
                                }
                            }
                            EscapeAction::Disconnect => {
                                pending_disconnect = true;
                            }
                            EscapeAction::Help => {
                                debug!("shell client: showing local escape help");
                                let help = b"\r\nEscape sequences: ~. disconnect, ~~ literal ~, ~? help\r\n";
                                stdout.write_all(help).await.ok();
                                stdout.flush().await.ok();
                                if !out.is_empty() {
                                    pending_outbound = Some(out);
                                }
                            }
                        }
                    }
                }
            }
            resize = next_resize(&mut resize_events, &mut last_size), if can_accept_resize => {
                if let Some((cols, rows)) = resize {
                    pending_resize = Some((cols, rows));
                }
            }
        }
    }
}

pub(crate) fn spawn_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        // Dedicated blocking thread for stdin reading.
        //
        // We cannot use tokio::io::stdin() because its async read can be
        // cancelled by tokio::select!, which on some platforms leaves the
        // stdin file descriptor in an inconsistent state. A dedicated thread
        // with blocking reads is cancel-safe: the thread owns the read call
        // and the channel sender cleanly breaks the loop when the receiver
        // (async relay loop) is dropped.
        //
        // Platform-specific stdin handling below:
        //
        // WINDOWS: std::io::stdin().read() returns Ok(0) immediately on
        //   PTY-hosted terminals (mintty, WezTerm, Windows Terminal with
        //   certain configurations) when the console is in raw mode. This
        //   happens because the Rust stdin handle is attached to a console
        //   screen buffer that ConPTY/mintty redirected away from the real
        //   input device. Opening CONIN$ directly bypasses this — it always
        //   refers to the actual console input device regardless of PTY
        //   redirection. We detect piped stdin via GetFileType to avoid
        //   using CONIN$ when stdin is a pipe (e.g. `echo cmd | mrsh shell`).
        //
        // UNIX (Linux/macOS): std::io::stdin().read() works reliably with
        //   raw mode set by crossterm (which configures termios). No special
        //   handling needed — the fd 0 always points to the real terminal.
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            // Win32 FFI for stdin classification + VT input enable.
            //
            // ENABLE_VIRTUAL_TERMINAL_INPUT (0x0200) is REQUIRED on Windows
            // for arrow keys / function keys / mc / curses apps to work.
            // Without it, raw console reads return binary KEY_EVENT_RECORD
            // structs (16+ bytes per key event) instead of ANSI escape
            // sequences (3 bytes for arrows: ESC [ A/B/C/D). The remote
            // bash + readline + ncurses expect ANSI bytes, so VT input
            // must be turned on before we start reading.
            //
            // crossterm::enable_raw_mode() disables echo/line/processed
            // input but does NOT enable VT input — we set it explicitly
            // here on whichever handle we read from (CONIN$ or stdin).
            #[allow(non_snake_case)]
            mod win32 {
                pub const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
                pub const FILE_TYPE_CHAR: u32 = 0x0002; // character device (console)

                unsafe extern "system" {
                    pub fn GetConsoleMode(h: *mut std::ffi::c_void, mode: *mut u32) -> i32;
                    pub fn SetConsoleMode(h: *mut std::ffi::c_void, mode: u32) -> i32;
                    pub fn GetFileType(h: *mut std::ffi::c_void) -> u32;
                }
            }

            // Enable ENABLE_VIRTUAL_TERMINAL_INPUT on the given handle
            // (best-effort: ignore failures — most Windows hosts since
            // build 10586 support it; older builds will degrade silently).
            fn enable_vt_input(handle: *mut std::ffi::c_void, who: &str) {
                unsafe {
                    let mut mode: u32 = 0;
                    if win32::GetConsoleMode(handle, &mut mode) == 0 {
                        debug!("shell client: GetConsoleMode({who}) failed — skip VT input");
                        return;
                    }
                    let new_mode = mode | win32::ENABLE_VIRTUAL_TERMINAL_INPUT;
                    if mode == new_mode {
                        debug!("shell client: VT input already enabled on {who}");
                        return;
                    }
                    if win32::SetConsoleMode(handle, new_mode) == 0 {
                        debug!("shell client: SetConsoleMode({who}, +VT_INPUT) failed");
                    } else {
                        debug!("shell client: enabled ENABLE_VIRTUAL_TERMINAL_INPUT on {who} (was 0x{mode:04x}, now 0x{new_mode:04x})");
                    }
                }
            }

            let stdin_handle = std::io::stdin().as_raw_handle();
            let stdin_file_type = unsafe { win32::GetFileType(stdin_handle) };
            let stdin_has_console_mode = unsafe {
                let mut mode: u32 = 0;
                win32::GetConsoleMode(stdin_handle, &mut mode) != 0
            };
            let use_conin =
                should_use_conin_for_windows_stdin(stdin_file_type, stdin_has_console_mode);

            debug!(
                "shell client: windows stdin classified as file_type=0x{stdin_file_type:04x} has_console_mode={stdin_has_console_mode} use_conin={use_conin}"
            );

            if use_conin {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("CONIN$")
                {
                    Ok(f) => {
                        // CONIN$ is a fresh handle distinct from std::io::stdin()
                        // — set VT input on this specific handle so raw reads
                        // emit ANSI sequences (arrow keys, function keys, mc).
                        enable_vt_input(f.as_raw_handle(), "CONIN$");
                        forward_stdin_reader(f, stdin_tx, "CONIN$");
                    }
                    Err(err) => {
                        debug!(
                            "shell client: open CONIN$ failed ({err}); falling back to stdin handle"
                        );
                        // Fallback: ensure VT input on the stdin handle too.
                        enable_vt_input(stdin_handle, "stdin-fallback");
                        forward_stdin_reader(std::io::stdin(), stdin_tx, "stdin-fallback");
                    }
                }
            } else {
                let stdin_kind = if stdin_file_type == WINDOWS_FILE_TYPE_PIPE {
                    "pipe"
                } else if stdin_file_type == win32::FILE_TYPE_CHAR {
                    "char-without-console-mode"
                } else {
                    "redirected-non-console"
                };
                debug!("shell client: reading input from stdin handle ({stdin_kind})");
                // Only attempt VT input on actual console char devices.
                if stdin_has_console_mode {
                    enable_vt_input(stdin_handle, "stdin");
                }
                forward_stdin_reader(std::io::stdin(), stdin_tx, "stdin");
            }
        }
        #[cfg(not(windows))]
        {
            // Unix (Linux/macOS): stdin fd 0 always points to the real terminal
            // device or a redirected stream; plain blocking reads are correct.
            forward_stdin_reader(std::io::stdin(), stdin_tx, "stdin");
        }
    });
    stdin_rx
}

fn try_enable_raw_mode_with<E, F>(context: &str, enable: F) -> bool
where
    E: std::fmt::Display,
    F: FnOnce() -> std::result::Result<(), E>,
{
    match enable() {
        Ok(()) => {
            debug!("raw mode enabled for {}", context);
            true
        }
        Err(e) => {
            debug!(
                "raw mode unavailable for {}: {} — stdin may not be a terminal",
                context, e
            );
            false
        }
    }
}

pub(crate) fn enable_raw_mode_best_effort(context: &str) -> bool {
    try_enable_raw_mode_with(context, terminal::enable_raw_mode)
}

pub(crate) fn disable_raw_mode_if_enabled(raw_mode: bool) {
    if raw_mode {
        terminal::disable_raw_mode().ok();
    }
}

#[cfg(unix)]
pub(crate) async fn next_resize(
    resize_events: &mut Signal,
    last_size: &mut Option<(u16, u16)>,
) -> Option<(u16, u16)> {
    loop {
        resize_events.recv().await?;
        let size = terminal::size().ok();
        if size.is_some() && size != *last_size {
            *last_size = size;
            return size;
        }
    }
}

#[cfg(not(unix))]
pub(crate) async fn next_resize(
    resize_events: &mut Interval,
    last_size: &mut Option<(u16, u16)>,
) -> Option<(u16, u16)> {
    loop {
        resize_events.tick().await;
        let size = terminal::size().ok();
        if size.is_some() && size != *last_size {
            *last_size = size;
            return size;
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn make_resize_interval() -> Interval {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
}

pub(crate) enum EscapeAction {
    Continue,
    Disconnect,
    Help,
}

fn remote_shell_prefers_windows_newlines(caps: &[String]) -> bool {
    caps.iter().any(|cap| {
        matches!(
            cap.as_str(),
            "window"
                | "session"
                | "keyboard"
                | "mouse"
                | "recording"
                | "service"
                | "lock"
                | "sleep"
                | "tray"
                | "system"
        )
    })
}

fn normalize_shell_input_for_remote(input: Vec<u8>, normalize_windows_newlines: bool) -> Vec<u8> {
    if !normalize_windows_newlines || (!input.contains(&b'\n') && !input.contains(&b'\r')) {
        return input;
    }

    let mut normalized = Vec::with_capacity(input.len());
    let mut prev_was_cr = false;
    for byte in input {
        match byte {
            b'\r' => {
                normalized.push(b'\n');
                prev_was_cr = true;
            }
            b'\n' => {
                if !prev_was_cr {
                    normalized.push(b'\n');
                }
                prev_was_cr = false;
            }
            _ => {
                normalized.push(byte);
                prev_was_cr = false;
            }
        }
    }
    normalized
}

/// Process SSH-like tilde escape sequences.
/// Returns (output_bytes, action).
pub(crate) fn process_escapes(
    input: &[u8],
    after_newline: &mut bool,
    in_escape: &mut bool,
) -> (Vec<u8>, EscapeAction) {
    let mut out = Vec::with_capacity(input.len());
    let mut action = EscapeAction::Continue;

    for &b in input {
        if *in_escape {
            *in_escape = false;
            match b {
                b'.' => {
                    debug!("shell client: matched tilde escape disconnect (~.)");
                    action = EscapeAction::Disconnect;
                    return (out, action);
                }
                b'~' => {
                    out.push(b'~');
                    *after_newline = false;
                }
                b'?' => {
                    action = EscapeAction::Help;
                    *after_newline = true;
                }
                _ => {
                    // Not an escape — send both ~ and the char
                    out.push(b'~');
                    out.push(b);
                    *after_newline = b == b'\r' || b == b'\n';
                }
            }
            continue;
        }

        if *after_newline && b == b'~' {
            *in_escape = true;
            continue;
        }

        *after_newline = b == b'\r' || b == b'\n';
        out.push(b);
    }

    (out, action)
}

/// Re-export from mrsh-core for backward compatibility.
pub use mrsh_core::terminal::encode_resize;

/// Send a terminal resize control message.
pub async fn send_resize<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cols: u16,
    rows: u16,
) -> Result<()> {
    let msg = encode_resize(cols, rows);
    wire::send_message(stream, &msg).await
}

// ── Persistent session (attach) ──────────────────────────────

/// Attach to a persistent shell session.
/// If `session_id` is empty, creates a new persistent session.
/// If `read_only` is true, attaches in read-only mode.
pub async fn run_attach<S: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut RshClient<S>,
    session_id: &str,
    read_only: bool,
    env_vars: &[String],
) -> Result<()> {
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let size_str = format!("{}x{}", cols, rows);

    let mut req = simple_request("shell-persistent");
    req.command = Some(size_str);
    if !session_id.is_empty() {
        req.path = Some(session_id.to_string());
    }
    if read_only {
        req.binary = Some(true);
    }
    if !env_vars.is_empty() {
        req.env_vars = Some(env_vars.to_vec());
    }
    let resp = client.request(&req).await?;
    if !resp.success {
        bail!(
            "attach failed: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        );
    }

    // Print session info if server returned it
    if let Some(ref output) = resp.output
        && !output.is_empty()
    {
        eprintln!("session: {}", output);
    }

    let raw_mode = enable_raw_mode_best_effort("persistent shell attach");
    let normalize_windows_newlines = remote_shell_prefers_windows_newlines(&client.server_caps);
    let result = relay_loop(client.stream_mut(), normalize_windows_newlines).await;
    disable_raw_mode_if_enabled(raw_mode);

    match result {
        Ok(ShellExit::Disconnect) => {
            eprintln!("\r\nDetached from session.\r");
            Ok(())
        }
        Ok(ShellExit::ServerEof) => {
            eprintln!("\r\nSession ended.\r");
            Ok(())
        }
        Err(e) => {
            eprintln!("\r\nSession error: {}\r", e);
            Err(e)
        }
    }
}

// ── QUIC interactive shell ──────────────────────────────────

/// Run an interactive shell session over a QUIC connection.
///
/// Puts the terminal into raw mode, relays I/O between stdin/stdout and
/// the server's ConPTY, handles resize and tilde escapes.
///
/// `env_vars` are forwarded to the remote shell via the QUIC handshake
/// (e.g. `MRSH_SHELL=pwsh`). Matches the TLS path's env-vars forwarding.
#[cfg(feature = "quic")]
pub async fn run_quic_shell(quic: &crate::quic::QuicClient, env_vars: &[String]) -> Result<()> {
    use tokio::io::BufReader;

    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let size_str = format!("{}x{}", cols, rows);

    let (mut send, recv) = quic.open_shell(&size_str, env_vars).await?;
    let mut reader = BufReader::new(recv);

    let raw_mode = enable_raw_mode_best_effort("QUIC shell");
    let normalize_windows_newlines = remote_shell_prefers_windows_newlines(&quic.server_caps);
    let result = quic_relay_loop(&mut send, &mut reader, normalize_windows_newlines).await;
    disable_raw_mode_if_enabled(raw_mode);

    match result {
        Ok(ShellExit::Disconnect) => {
            eprintln!("\r\nConnection closed.\r");
            Ok(())
        }
        Ok(ShellExit::ServerEof) => {
            eprintln!("\r\nShell session ended.\r");
            Ok(())
        }
        Err(e) => {
            eprintln!("\r\nShell error: {}\r", e);
            Err(e)
        }
    }
}

/// QUIC relay loop — same structure as the TLS relay_loop but uses
/// quinn streams directly instead of a generic AsyncRead+AsyncWrite.
///
/// Uses the same dedicated stdin thread pattern as the TLS path for
/// cancel-safety (see relay_loop above for rationale). The previous
/// implementation used tokio::io::stdin() directly with an undeclared
/// `stdin_buf` variable — that was a compile error behind the feature gate.
#[cfg(feature = "quic")]
async fn quic_relay_loop(
    send: &mut quinn::SendStream,
    reader: &mut tokio::io::BufReader<quinn::RecvStream>,
    normalize_windows_newlines: bool,
) -> Result<ShellExit> {
    let mut after_newline = true;
    let mut in_escape = false;
    let mut stdin_closed = false;

    // Spawn dedicated blocking stdin reader thread — same pattern as TLS relay_loop.
    // See relay_loop() for platform-specific stdin handling rationale.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        // Windows stdin: CONIN$ for interactive, std::io::stdin() for piped.
        // Same logic as TLS relay_loop() — see that function for full rationale.
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::io::AsRawHandle;

            #[allow(non_snake_case)]
            mod win32 {
                unsafe extern "system" {
                    pub fn GetFileType(h: *mut std::ffi::c_void) -> u32;
                }
            }

            let stdin_is_pipe = unsafe {
                let h = std::io::stdin().as_raw_handle();
                win32::GetFileType(h) == 0x0003
            };

            if !stdin_is_pipe {
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("CONIN$")
                    .expect("open CONIN$");
                let mut buf = [0u8; 4096];
                loop {
                    match f.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            } else {
                let mut buf = [0u8; 4096];
                loop {
                    match std::io::stdin().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // Unix (Linux/macOS): fd 0 is always the real terminal — no CONIN$ needed.
        #[cfg(not(windows))]
        {
            use std::io::Read;
            let mut buf = vec![0u8; 4096];
            loop {
                match std::io::stdin().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            biased;
            result = wire::recv_message(reader) => {
                match result {
                    Ok(data) if data.is_empty() => return Ok(ShellExit::ServerEof),
                    Ok(data) => {
                        stdout.write_all(&data).await.context("write stdout")?;
                        stdout.flush().await.ok();
                    }
                    Err(_) => return Ok(ShellExit::ServerEof),
                }
            }
            result = stdin_rx.recv(), if !stdin_closed => {
                match result {
                    None => {
                        stdin_closed = true;
                    }
                    Some(input) => {
                        let (out, action) = process_escapes(&input, &mut after_newline, &mut in_escape);
                        let out = normalize_shell_input_for_remote(out, normalize_windows_newlines);
                        match action {
                            EscapeAction::Continue => {
                                if !out.is_empty() {
                                    wire::send_message(send, &out)
                                        .await
                                        .context("send to server")?;
                                }
                            }
                            EscapeAction::Disconnect => {
                                wire::send_message(send, &[]).await.ok();
                                return Ok(ShellExit::Disconnect);
                            }
                            EscapeAction::Help => {
                                let help = b"\r\nEscape sequences: ~. disconnect, ~~ literal ~, ~? help\r\n";
                                stdout.write_all(help).await.ok();
                                stdout.flush().await.ok();
                                if !out.is_empty() {
                                    wire::send_message(send, &out)
                                        .await
                                        .context("send to server")?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Wake on LAN ──────────────────────────────────────────────

/// Send a Wake-on-LAN magic packet.
pub fn send_wol(mac: &str) -> Result<()> {
    let mac_bytes = parse_mac(mac)?;
    let mut packet = vec![0xFF; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac_bytes);
    }

    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind UDP")?;
    socket.set_broadcast(true).context("set broadcast")?;
    socket
        .send_to(&packet, "255.255.255.255:9")
        .context("send WoL packet")?;
    Ok(())
}

fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 {
        bail!("invalid MAC address: {}", mac);
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] =
            u8::from_str_radix(part, 16).with_context(|| format!("invalid MAC byte: {}", part))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_disconnect() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~.", &mut after_nl, &mut in_esc);
        assert!(out.is_empty());
        assert!(matches!(action, EscapeAction::Disconnect));
    }

    #[test]
    fn escape_literal_tilde() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~~", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"~");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn escape_help() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, _action) = process_escapes(b"~?", &mut after_nl, &mut in_esc);
        assert!(out.is_empty());
    }

    #[test]
    fn escape_not_after_newline() {
        let mut after_nl = false;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~.", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"~.");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn escape_after_cr() {
        let mut after_nl = false;
        let mut in_esc = false;
        let (out, _) = process_escapes(b"\r", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"\r");
        assert!(after_nl);
    }

    #[test]
    fn normal_text_passthrough() {
        let mut after_nl = false;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"hello world", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"hello world");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn encode_resize_format() {
        let msg = encode_resize(120, 40);
        assert_eq!(msg.len(), 5);
        assert_eq!(msg[0], 0x01);
        assert_eq!((msg[1] as u16) << 8 | msg[2] as u16, 120);
        assert_eq!((msg[3] as u16) << 8 | msg[4] as u16, 40);
    }

    #[test]
    fn parse_mac_valid() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_mac_dashes() {
        let mac = parse_mac("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_mac_invalid() {
        assert!(parse_mac("invalid").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:gg").is_err());
    }

    #[test]
    fn wol_packet_structure() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut packet = vec![0xFF; 6];
        for _ in 0..16 {
            packet.extend_from_slice(&mac);
        }
        assert_eq!(packet.len(), 6 + 16 * 6); // 102 bytes
        assert!(packet[0..6].iter().all(|&b| b == 0xFF));
        assert_eq!(&packet[6..12], &mac);
    }

    #[test]
    fn escape_unknown_sequence() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~x", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"~x");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn escape_split_across_reads() {
        let mut after_nl = true;
        let mut in_esc = false;
        // First read: just the tilde
        let (out1, _) = process_escapes(b"~", &mut after_nl, &mut in_esc);
        assert!(out1.is_empty());
        assert!(in_esc);
        // Second read: the command char
        let (out2, action) = process_escapes(b".", &mut after_nl, &mut in_esc);
        assert!(out2.is_empty());
        assert!(matches!(action, EscapeAction::Disconnect));
    }

    #[test]
    fn raw_mode_helper_returns_true_on_success() {
        let enabled = try_enable_raw_mode_with::<std::io::Error, _>("test shell", || Ok(()));
        assert!(enabled);
    }

    #[test]
    fn raw_mode_helper_returns_false_on_error() {
        let enabled = try_enable_raw_mode_with::<std::io::Error, _>("test shell", || {
            Err(std::io::Error::other("no tty"))
        });
        assert!(!enabled);
    }

    #[test]
    fn normalize_shell_input_for_windows_collapses_crlf_and_cr_to_lf() {
        let normalized =
            normalize_shell_input_for_remote(b"alpha\nbeta\r\ngamma\rdelta".to_vec(), true);
        assert_eq!(normalized, b"alpha\nbeta\ngamma\ndelta");
    }

    #[test]
    fn windows_conin_selection_requires_real_console_mode() {
        assert!(should_use_conin_for_windows_stdin(WINDOWS_FILE_TYPE_CHAR, true));
        assert!(!should_use_conin_for_windows_stdin(WINDOWS_FILE_TYPE_CHAR, false));
        assert!(!should_use_conin_for_windows_stdin(WINDOWS_FILE_TYPE_PIPE, true));
        assert!(!should_use_conin_for_windows_stdin(0, false));
    }

    #[tokio::test]
    async fn relay_loop_waits_for_remote_eof_after_local_stdin_closes() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(4096);
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);

        stdin_tx
            .send(b"hostname\r\nexit\r\n".to_vec())
            .await
            .unwrap();
        drop(stdin_tx);

        let server = tokio::spawn(async move {
            let input = wire::recv_message(&mut server_stream).await.unwrap();
            assert_eq!(input, b"hostname\r\nexit\r\n");

            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            wire::send_message(&mut server_stream, b"REMOTE-OUTPUT\r\n")
                .await
                .unwrap();
            wire::send_message(&mut server_stream, &[]).await.unwrap();
        });

        let mut stdout = tokio::io::sink();
        let exit = relay_loop_with_io(&mut client_stream, stdin_rx, &mut stdout, false)
            .await
            .unwrap();

        assert!(matches!(exit, ShellExit::ServerEof));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn relay_loop_normalizes_line_endings_to_lf_for_windows_shells() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(4096);
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);

        stdin_tx
            .send(b"hostname\nexit\r\n".to_vec())
            .await
            .unwrap();
        drop(stdin_tx);

        let server = tokio::spawn(async move {
            let input = wire::recv_message(&mut server_stream).await.unwrap();
            assert_eq!(input, b"hostname\nexit\n");
            wire::send_message(&mut server_stream, &[]).await.unwrap();
        });

        let mut stdout = tokio::io::sink();
        let exit = relay_loop_with_io(&mut client_stream, stdin_rx, &mut stdout, true)
            .await
            .unwrap();

        assert!(matches!(exit, ShellExit::ServerEof));
        server.await.unwrap();
    }
}
