//! Client commands — ping, exec, ls, cat, screenshot, etc.
//! Each command builds a request, sends it, and formats the response.

use anyhow::{Result, bail};
use base64::Engine;
use mrsh_core::protocol::{FileInfo, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

// ── Ping ─────────────────────────────────────────────────────────

/// Ping the server, returns "pong" on success.
pub async fn ping<S: AsyncRead + AsyncWrite + Unpin>(client: &mut RshClient<S>) -> Result<String> {
    if client.supports_binary_proto() {
        client.ping_binary().await?;
        return Ok("pong".to_string());
    }
    let resp = client.request(&simple_request("ping")).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// Return the server version captured during authentication.
pub fn server_version<S>(client: &RshClient<S>) -> Result<String> {
    client
        .server_version
        .clone()
        .ok_or_else(|| anyhow::anyhow!("server version unavailable"))
}

// ── Exec ─────────────────────────────────────────────────────────

/// Execute a command on the remote host (buffered — waits for completion).
pub async fn exec<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
    env_vars: &[String],
) -> Result<String> {
    if client.supports_binary_proto() {
        let (exit_code, output) = client.exec_binary(command, env_vars).await?;
        let output_str = String::from_utf8_lossy(&output).to_string();
        if exit_code != 0 && output_str.is_empty() {
            // rsh-v17v 2026-05-21: server may have an error diagnostic that the
            // binary protocol didn't transport (older server <1.10.48 OR a path
            // that returned empty output AND no error). Hint user to try -p 8822
            // if they were on -p 9822 (tray exec exit-code bug rsh-yoic).
            bail!(
                "command failed with exit code {} (empty output — server didn't include diagnostic; if using -p 9822 tray, try -p 8822 service)",
                exit_code
            );
        }
        return Ok(output_str);
    }

    let mut req = simple_request("exec");
    req.command = Some(command.to_string());
    if !env_vars.is_empty() {
        req.env_vars = Some(env_vars.to_vec());
    }
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// Execute a command with streaming output — prints to stdout/stderr as chunks arrive.
/// Returns the exit code. No timeout issues: output flows continuously.
pub async fn exec_stream<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
    env_vars: &[String],
) -> Result<i32> {
    client.exec_stream(command, env_vars).await
}

/// Like [`exec`] but ALSO returns the remote exit code (rsh-1cp1).
///
/// The plain `exec` discards the binary-protocol exit code unless output was
/// empty — `mrsh exec 'cmd; exit 3'` returned local exit 0 (the "exit 0 lie",
/// buffered-native variant). JSON-protocol servers don't transport an exit
/// code: they report 0 on success (failure surfaces as Err via check_response).
pub async fn exec_with_code<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
    env_vars: &[String],
) -> Result<(u32, String)> {
    if client.supports_binary_proto() {
        let (exit_code, output) = client.exec_binary(command, env_vars).await?;
        return Ok((exit_code, String::from_utf8_lossy(&output).to_string()));
    }
    let out = exec(client, command, env_vars).await?;
    Ok((0, out))
}

// ── Exec --detach (rsh-oom9) ─────────────────────────────────────

/// rsh-oom9: build the detached-runner wrapper for a user command. Shared by the
/// mrsh-TLS path ([`exec_detach`]) AND the SSH-fallback path
/// (`server_mode::run_ssh_command`) so `--detach` behaves identically on both
/// transports.
///
/// Linux-only (`setsid`/`sh`/`base64`/`mktemp`); a non-Linux host returns a clean
/// "setsid not found" error. The user command is base64-encoded (quote-safe on the
/// wire), decoded + run inside a detached `setsid` session whose stdout+stderr go
/// to `<dir>/out.log` (`<dir>` = `mktemp -d`); an exit marker
/// `__mrsh_detach_exit__:<code>` is appended on completion. The outer shell
/// backgrounds the setsid session and returns at once, echoing
/// `MRSH_DETACH_DIR=<dir>`.
///
/// SECURITY: the scratch dir is created with `mktemp -d` (atomic, mode 0700,
/// UNGUESSABLE random name) under `umask 077`, NOT a predictable `/tmp/<nanos>`
/// path — this defeats the symlink/race + predictable-name temp attacks that
/// matter because the runner often executes as **root** (the mrsh daemon's uid).
pub fn build_detach_wrapper(command: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(command);
    // {b64} is single-quoted (base64 alphabet is shell-safe). $DIR is created by
    // mktemp (0700, random) and exported so the inner single-quoted `setsid sh -c
    // '…'` inherits it; $? is expanded by that inner sh at runtime (the script's
    // exit code). The outer sh expands the non-quoted $DIR refs and backgrounds
    // the setsid session.
    format!(
        "command -v setsid >/dev/null 2>&1 || {{ echo 'mrsh detach: setsid not found (Linux-only)' >&2; exit 1; }}\n\
         umask 077\n\
         DIR=$(mktemp -d \"${{TMPDIR:-/tmp}}/mrsh-detach.XXXXXXXX\") || {{ echo 'mrsh detach: mktemp failed' >&2; exit 1; }}\n\
         export DIR\n\
         printf %s '{b64}' | base64 -d > \"$DIR/cmd.sh\" || {{ echo 'mrsh detach: base64 decode failed' >&2; exit 1; }}\n\
         setsid sh -c 'sh \"$DIR/cmd.sh\" > \"$DIR/out.log\" 2>&1; echo \"__mrsh_detach_exit__:$?\" >> \"$DIR/out.log\"' </dev/null >/dev/null 2>&1 &\n\
         echo \"MRSH_DETACH_DIR=$DIR\""
    )
}

/// rsh-oom9: parse the `MRSH_DETACH_DIR=<dir>` handle out of a detach wrapper's
/// stdout. Shared by both transports.
pub fn parse_detach_handle(output: &str) -> Result<String> {
    match output
        .lines()
        .find_map(|l| l.trim().strip_prefix("MRSH_DETACH_DIR="))
        .map(|s| s.trim().to_string())
    {
        Some(dir) if !dir.is_empty() => Ok(dir),
        _ => bail!("exec --detach failed: {}", output.trim()),
    }
}

/// rsh-oom9: the MSYS-safe display token for a detach handle — the basename of the
/// scratch dir (`mrsh-detach.XXXXXXXX`). A bare token has NO leading slash, so Git
/// Bash / MSYS does NOT path-translate it when the user copy-pastes the printed
/// `dlog <token>` follow-line (a full `/tmp/...` arg gets rewritten to `W:/Temp/...`
/// → "no such detach"). [`build_dlog_query`] accepts BOTH the token and a full path.
pub fn detach_token(dir: &str) -> &str {
    dir.trim_end_matches('/').rsplit('/').next().unwrap_or(dir)
}

/// rsh-oom9: build the read-only poll query for a detached job's log + liveness.
/// Accepts EITHER a bare token (`mrsh-detach.X`, MSYS-safe — reconstructed under
/// `${TMPDIR:-/tmp}` server-side, matching the dir mktemp created in
/// [`build_detach_wrapper`]) OR a full path (`/tmp/mrsh-detach.X`, as emitted on
/// Linux/cmd/PowerShell clients that don't path-translate). Validates the handle
/// (must contain `mrsh-detach.`, no `..` traversal, no shell metachar) so a
/// hand-typed handle can't be abused. Shared by both transports.
pub fn build_dlog_query(handle: &str) -> Result<String> {
    if handle.is_empty()
        || !handle.contains("mrsh-detach.")
        || handle.contains("..")
        || handle.contains('\'')
        || handle.contains('\n')
        || handle.contains('$')
        || handle.contains('`')
    {
        bail!("invalid detach handle {handle:?} (expected the token/dir from `exec --detach`)");
    }
    // A full path (starts with `/`) is used verbatim; a bare token is rebuilt under
    // ${TMPDIR:-/tmp} (the SAME expression build_detach_wrapper used for mktemp, so
    // it resolves to the identical dir for the same remote user/host).
    Ok(format!(
        "H='{handle}'; case \"$H\" in /*) D=\"$H\";; *) D=\"${{TMPDIR:-/tmp}}/$H\";; esac; \
         LOG=\"$D/out.log\"; \
         if [ -f \"$LOG\" ]; then cat \"$LOG\"; if grep -q __mrsh_detach_exit__: \"$LOG\"; then echo '[EXITED]'; else echo '[RUNNING]'; fi; else echo \"no such detach: $H\" >&2; exit 1; fi"
    ))
}

/// rsh-oom9: launch a remote command DETACHED so it survives any client/channel
/// drop — for >30min jobs (builds, scrapes). Returns the opaque handle (the
/// scratch dir); follow with [`exec_dlog`]. mrsh-TLS transport.
pub async fn exec_detach<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
) -> Result<String> {
    let wrapper = build_detach_wrapper(command);
    let (_code, output) = exec_with_code(client, &wrapper, &[]).await?;
    parse_detach_handle(&output)
}

/// rsh-oom9: poll a detached job's log + liveness (companion to [`exec_detach`]).
/// `handle` is the opaque scratch-dir returned by [`exec_detach`]. Returns the
/// full captured log followed by a `[RUNNING]` / `[EXITED]` marker. mrsh-TLS.
pub async fn exec_dlog<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    handle: &str,
) -> Result<String> {
    let q = build_dlog_query(handle)?;
    let (_c, out) = exec_with_code(client, &q, &[]).await?;
    Ok(out)
}

// ── Ls ───────────────────────────────────────────────────────────

/// List a remote directory, returns parsed file entries.
pub async fn ls<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<Vec<FileInfo>> {
    let mut req = simple_request("ls");
    req.path = Some(path.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let json = resp.output.unwrap_or_default();
    let files: Vec<FileInfo> =
        serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("parse ls response: {}", e))?;
    Ok(files)
}

// ── Cat (read file) ──────────────────────────────────────────────

/// Read a remote file, returns raw bytes (decoded from base64).
pub async fn cat<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<Vec<u8>> {
    let mut req = simple_request("cat");
    req.path = Some(path.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let b64 = resp.output.unwrap_or_default();
    if resp.binary.unwrap_or(false) {
        let data = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| anyhow::anyhow!("decode base64: {}", e))?;
        Ok(data)
    } else {
        Ok(b64.into_bytes())
    }
}

/// Read a remote file as text.
pub async fn cat_text<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<String> {
    let data = cat(client, path).await?;
    String::from_utf8(data).map_err(|e| anyhow::anyhow!("file is not valid UTF-8: {}", e))
}

// ── Write ────────────────────────────────────────────────────────

/// Write content to a remote file (base64-encoded).
pub async fn write_file<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
    content: &[u8],
) -> Result<()> {
    let mut req = simple_request("write");
    req.path = Some(path.to_string());
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(content));
    req.binary = Some(true);
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(())
}

// ── Screenshot ───────────────────────────────────────────────────

/// Capture a screenshot from the remote host.
/// Returns raw image bytes (JPEG or raw RGBA).
pub async fn screenshot<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    display: u32,
    quality: u8,
    scale: u8,
) -> Result<Vec<u8>> {
    let mut req = simple_request("screenshot");
    req.command = Some(display.to_string());
    req.content = Some(quality.to_string());
    req.path = Some(scale.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let b64 = resp.output.unwrap_or_default();
    let data = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| anyhow::anyhow!("decode screenshot: {}", e))?;
    Ok(data)
}

// ── Session management ───────────────────────────────────────────

/// List persistent shell sessions.
pub async fn sessions_list<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
) -> Result<String> {
    let mut req = simple_request("session");
    req.command = Some("list".to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// Kill a persistent session by ID.
pub async fn session_kill<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    session_id: &str,
) -> Result<()> {
    let mut req = simple_request("session");
    req.command = Some("kill".to_string());
    req.path = Some(session_id.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(())
}

// ── Self-update ──────────────────────────────────────────────────

/// Trigger self-update on the remote server.
pub async fn self_update<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    binary_path: &str,
) -> Result<String> {
    let mut req = simple_request("self-update");
    req.path = Some(binary_path.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// rsh-5264.6: trigger self-update via rdv pull. Server fetches the latest
/// signed binary from rdv (operator pre-published via `mrsh rdv publish`),
/// verifies the Ed25519 signature, and runs the swap flow.
///
/// - `track`: release track on rdv (`stable` | `canary` | `dev`); empty/None
///   => server uses "stable" default
/// - `version`: pin a specific version (e.g. `1.10.32`); None => accept the
///   advert's `latest_version`
/// - `allow_downgrade`: when true, server accepts a pinned version older
///   than the running binary (rollback); default false
/// - `insecure_no_verify`: skip Ed25519 verify (DEV ONLY — required while
///   `SIGNING_PUBLIC_KEY_PEM` is empty in the source)
pub async fn self_update_from_rdv<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    track: Option<String>,
    version: Option<String>,
    allow_downgrade: bool,
    insecure_no_verify: bool,
) -> Result<String> {
    let mut req = simple_request("self-update-from-rdv");
    req.track = track;
    req.version = version;
    if allow_downgrade {
        req.allow_downgrade = Some(true);
    }
    if insecure_no_verify {
        req.insecure_no_verify = Some(true);
    }
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── GUI input ────────────────────────────────────────────────────

/// Send a GUI input command (mouse/key/window).
pub async fn input<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
    action: &str,
    args: &str,
) -> Result<String> {
    let mut req = simple_request("input");
    // Server expects Command="mouse pos 500,300" as single space-separated string
    let cmd = if args.is_empty() {
        format!("{} {}", command, action)
    } else {
        format!("{} {} {}", command, action, args)
    };
    req.command = Some(cmd);
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── Native commands ──────────────────────────────────────────────

/// Send a "native" command to the server.
/// Most system commands (ps, clip, eventlog, info, service, etc.)
/// use `Request { type: "native", command: "<subcmd> <args>" }`.
pub async fn native<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
) -> Result<String> {
    let mut req = simple_request("native");
    req.command = Some(command.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// List remote processes.
pub async fn ps<S: AsyncRead + AsyncWrite + Unpin>(client: &mut RshClient<S>) -> Result<String> {
    native(client, "ps").await
}

/// Kill a remote process by PID.
pub async fn kill_process<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    pid: &str,
) -> Result<String> {
    native(client, &format!("kill {}", pid)).await
}

/// Tail a remote file.
pub async fn tail<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
    lines: u32,
) -> Result<String> {
    native(client, &format!("tail {} {}", path, lines)).await
}

/// Get file version info (Windows PE).
pub async fn filever<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<String> {
    native(client, &format!("filever {}", path)).await
}

/// Get system info.
pub async fn info<S: AsyncRead + AsyncWrite + Unpin>(client: &mut RshClient<S>) -> Result<String> {
    native(client, "info").await
}

/// Query Windows Event Log.
pub async fn eventlog<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    log_name: &str,
    count: u32,
) -> Result<String> {
    native(client, &format!("eventlog {} {}", log_name, count)).await
}

/// Clipboard get.
pub async fn clip_get<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
) -> Result<String> {
    native(client, "clip-get").await
}

/// Clipboard set.
pub async fn clip_set<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    text: &str,
) -> Result<String> {
    native(client, &format!("clip-set {}", text)).await
}

/// Bidirectional clipboard sync — polls local and remote, syncs changes.
///
/// Runs until cancelled (Ctrl+C). Uses `clip-get`/`clip-set` commands
/// under the hood, polling every `interval`.
pub async fn clip_sync<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    interval: std::time::Duration,
) -> Result<()> {
    use std::io::Write;

    let mut last_local = get_local_clipboard().unwrap_or_default();
    let mut last_remote = native(client, "clip-get").await.unwrap_or_default();

    eprintln!(
        "Clipboard sync active (poll {}ms). Ctrl+C to stop.",
        interval.as_millis()
    );

    loop {
        tokio::time::sleep(interval).await;

        // Check local clipboard
        let local = get_local_clipboard().unwrap_or_default();
        if !local.is_empty() && local != last_local {
            // Local changed → push to remote
            if native(client, &format!("clip-set {}", local)).await.is_ok() {
                eprint!("→ ");
                std::io::stderr().flush().ok();
                last_local = local.clone();
                last_remote = local;
            }
            continue;
        }

        // Check remote clipboard
        match native(client, "clip-get").await {
            Ok(remote) if !remote.is_empty() && remote != last_remote => {
                // Remote changed → pull to local
                if set_local_clipboard(&remote).is_ok() {
                    eprint!("← ");
                    std::io::stderr().flush().ok();
                    last_remote = remote.clone();
                    last_local = remote;
                }
            }
            _ => {}
        }
    }
}

/// Get local clipboard text (cross-platform via PowerShell on Windows, xclip/xsel on Linux).
fn get_local_clipboard() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-Clipboard"])
            .output()?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Try xclip first, then xsel
        let out = std::process::Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output()
            .or_else(|_| {
                std::process::Command::new("xsel")
                    .args(["--clipboard", "--output"])
                    .output()
            });
        match out {
            Ok(o) => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
            Err(e) => bail!("clipboard read failed (install xclip or xsel): {}", e),
        }
    }
}

/// Set local clipboard text.
fn set_local_clipboard(text: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Set-Clipboard -Value '{}'", text.replace('\'', "''")),
            ])
            .output()?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::io::Write;
        let mut child = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .or_else(|_| {
                std::process::Command::new("xsel")
                    .args(["--clipboard", "--input"])
                    .stdin(std::process::Stdio::piped())
                    .spawn()
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    }
}

/// Service management (list, status, start, stop, restart).
pub async fn service<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    action: &str,
    name: Option<&str>,
) -> Result<String> {
    let cmd = match name {
        Some(n) => format!("service {} {}", action, n),
        None => format!("service {}", action),
    };
    native(client, &cmd).await
}

/// Plugin management.
pub async fn plugin<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    args: &str,
) -> Result<String> {
    let mut req = simple_request("plugin");
    req.command = Some(args.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── Log query ──────────────────────────────────────────────────

/// Remote log query: stream matching lines from a file on the server.
/// Uses binary protocol LOG_QUERY/LOG_DATA/LOG_END.
pub async fn log_query<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
    pattern: &str,
    flags: u8,
    tail_lines: u32,
    max_matches: u32,
) -> Result<(u64, u64)> {
    use mrsh_core::binproto::{self, msg};

    let payload = binproto::build_log_query(path, pattern, flags, tail_lines, 0, max_matches);
    binproto::send_msg(client.stream_mut(), msg::LOG_QUERY, &payload).await?;

    loop {
        let (type_id, data) = binproto::recv_msg(client.stream_mut()).await?;
        match type_id {
            msg::LOG_DATA => {
                let line = String::from_utf8_lossy(&data);
                println!("{}", line);
            }
            msg::LOG_END => {
                let (lines_scanned, lines_matched, _offset) = binproto::parse_log_end(&data)?;
                return Ok((lines_scanned, lines_matched));
            }
            msg::ERROR => {
                let err = binproto::parse_error(&data)?;
                bail!("server: {}", err);
            }
            other => bail!("unexpected message type 0x{:02x}", other),
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

fn check_response(resp: &Response) -> Result<()> {
    if !resp.success {
        bail!("{}", resp.error.as_deref().unwrap_or("unknown error"));
    }
    Ok(())
}

/// Build a request with arbitrary fields.
pub fn build_request(
    req_type: &str,
    command: Option<&str>,
    path: Option<&str>,
    content: Option<&str>,
) -> Request {
    Request {
        req_type: req_type.to_string(),
        command: command.map(|s| s.to_string()),
        path: path.map(|s| s.to_string()),
        content: content.map(|s| s.to_string()),
        binary: None,
        gzip: None,
        sync_type: None,
        delta: None,
        signatures: None,
        paths: None,
        batch_patches: None,
        env_vars: None,
        track: None,
        version: None,
        allow_downgrade: None,
        insecure_no_verify: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RshClient;
    use mrsh_core::wire;
    use tokio::io::DuplexStream;

    #[test]
    fn check_response_ok() {
        let resp = Response {
            success: true,
            output: Some("ok".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        assert!(check_response(&resp).is_ok());
    }

    #[test]
    fn check_response_error() {
        let resp = Response {
            success: false,
            output: None,
            error: Some("test error".to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
        let err = check_response(&resp).unwrap_err();
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn build_request_fields() {
        let req = build_request("exec", Some("hostname"), None, None);
        assert_eq!(req.req_type, "exec");
        assert_eq!(req.command.as_deref(), Some("hostname"));
        assert!(req.path.is_none());
    }

    #[test]
    fn build_request_all_fields() {
        let req = build_request("write", None, Some("/tmp/test"), Some("content"));
        assert_eq!(req.req_type, "write");
        assert_eq!(req.path.as_deref(), Some("/tmp/test"));
        assert_eq!(req.content.as_deref(), Some("content"));
    }

    // ── Mock infrastructure ─────────────────────────────────────────

    /// Create a mock client + server stream pair.
    fn mock_client() -> (RshClient<DuplexStream>, DuplexStream) {
        let (client_end, server_end) = tokio::io::duplex(8192);
        (RshClient::new_mock(client_end), server_end)
    }

    /// Spawn a mock server that reads a Request, validates it, then sends a canned Response.
    fn spawn_mock_server(
        mut server: DuplexStream,
        validate: impl FnOnce(&Request) + Send + 'static,
        response: Response,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            validate(&req);
            wire::send_json(&mut server, &response).await.unwrap();
        })
    }

    fn ok_response(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        }
    }

    fn ok_response_binary(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: Some(true),
            gzip: None,
        }
    }

    fn err_response(error: &str) -> Response {
        Response {
            success: false,
            output: None,
            error: Some(error.to_string()),
            size: None,
            binary: None,
            gzip: None,
        }
    }

    // ── Ping ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ping_sends_request_returns_pong() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "ping");
            },
            ok_response("pong"),
        );

        let result = ping(&mut client).await.unwrap();
        assert_eq!(result, "pong");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ping_propagates_error() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("server busy"));

        let err = ping(&mut client).await.unwrap_err();
        assert!(err.to_string().contains("server busy"));
        h.await.unwrap();
    }

    #[test]
    fn server_version_returns_authenticated_version() {
        let (mut client, _server) = mock_client();
        client.server_version = Some("1.10.20".to_string());

        let result = super::server_version(&client).unwrap();
        assert_eq!(result, "1.10.20");
    }

    #[test]
    fn server_version_errors_when_missing() {
        let (mut client, _server) = mock_client();
        client.server_version = None;

        let err = super::server_version(&client).unwrap_err();
        assert!(err.to_string().contains("server version unavailable"));
    }

    // ── Exec ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_sends_command() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "exec");
                assert_eq!(req.command.as_deref(), Some("hostname"));
                assert!(req.env_vars.is_none());
            },
            ok_response("myhost"),
        );

        let result = exec(&mut client, "hostname", &[]).await.unwrap();
        assert_eq!(result, "myhost");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn exec_sends_env_vars() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "exec");
                let env = req.env_vars.as_ref().unwrap();
                assert_eq!(env, &["FOO=bar".to_string()]);
            },
            ok_response("ok"),
        );

        let result = exec(&mut client, "echo $FOO", &["FOO=bar".to_string()])
            .await
            .unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    // ── Ls ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ls_parses_file_info() {
        let (mut client, server) = mock_client();
        let json = r#"[{"name":"file.txt","size":42,"mode":"-rw-r--r--","is_dir":false,"mod_time":"2026-01-01T00:00:00Z"}]"#;
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "ls");
                assert_eq!(req.path.as_deref(), Some("/tmp"));
            },
            ok_response(json),
        );

        let files = ls(&mut client, "/tmp").await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "file.txt");
        assert_eq!(files[0].size, 42);
        assert!(!files[0].is_dir);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ls_empty_dir() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, ok_response("[]"));

        let files = ls(&mut client, "/empty").await.unwrap();
        assert!(files.is_empty());
        h.await.unwrap();
    }

    // ── Cat ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn cat_binary_decodes_base64() {
        let (mut client, server) = mock_client();
        let content = b"hello binary";
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "cat");
                assert_eq!(req.path.as_deref(), Some("/bin/test"));
            },
            ok_response_binary(&b64),
        );

        let data = cat(&mut client, "/bin/test").await.unwrap();
        assert_eq!(data, content);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn cat_text_returns_string() {
        let (mut client, server) = mock_client();
        // Non-binary response: output is returned as-is (bytes of the string)
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "cat");
            },
            ok_response("hello text"),
        );

        let data = cat(&mut client, "/etc/hostname").await.unwrap();
        assert_eq!(data, b"hello text");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn cat_text_fn_returns_string() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, ok_response("line1\nline2"));

        let text = cat_text(&mut client, "/etc/hosts").await.unwrap();
        assert_eq!(text, "line1\nline2");
        h.await.unwrap();
    }

    // ── Write ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn write_file_encodes_base64() {
        let (mut client, server) = mock_client();
        let content = b"file content";
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(content);
        let h = spawn_mock_server(
            server,
            move |req| {
                assert_eq!(req.req_type, "write");
                assert_eq!(req.path.as_deref(), Some("/tmp/out.txt"));
                assert_eq!(req.content.as_deref(), Some(expected_b64.as_str()));
                assert_eq!(req.binary, Some(true));
            },
            ok_response(""),
        );

        write_file(&mut client, "/tmp/out.txt", content)
            .await
            .unwrap();
        h.await.unwrap();
    }

    // ── Screenshot ───────────────────────────────────────────────────

    #[tokio::test]
    async fn screenshot_decodes_base64() {
        let (mut client, server) = mock_client();
        let fake_jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG magic
        let b64 = base64::engine::general_purpose::STANDARD.encode(&fake_jpeg);
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "screenshot");
                assert_eq!(req.command.as_deref(), Some("0")); // display
                assert_eq!(req.content.as_deref(), Some("80")); // quality
                assert_eq!(req.path.as_deref(), Some("50")); // scale
            },
            ok_response(&b64),
        );

        let data = screenshot(&mut client, 0, 80, 50).await.unwrap();
        assert_eq!(data, fake_jpeg);
        h.await.unwrap();
    }

    // ── Sessions ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn sessions_list_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "session");
                assert_eq!(req.command.as_deref(), Some("list"));
            },
            ok_response("sess1\nsess2"),
        );

        let result = sessions_list(&mut client).await.unwrap();
        assert!(result.contains("sess1"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn session_kill_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "session");
                assert_eq!(req.command.as_deref(), Some("kill"));
                assert_eq!(req.path.as_deref(), Some("abc123"));
            },
            ok_response(""),
        );

        session_kill(&mut client, "abc123").await.unwrap();
        h.await.unwrap();
    }

    // ── Self-update ──────────────────────────────────────────────────

    #[tokio::test]
    async fn self_update_sends_path() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "self-update");
                assert_eq!(req.path.as_deref(), Some("/opt/rsh/rsh-new"));
            },
            ok_response("updated to v5.5.0"),
        );

        let result = self_update(&mut client, "/opt/rsh/rsh-new").await.unwrap();
        assert!(result.contains("5.5.0"));
        h.await.unwrap();
    }

    /// rsh-5264.6: self_update_from_rdv emits the new request type and
    /// includes track/version/allow_downgrade/insecure_no_verify when set.
    #[tokio::test]
    async fn self_update_from_rdv_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "self-update-from-rdv");
                assert_eq!(req.track.as_deref(), Some("canary"));
                assert_eq!(req.version.as_deref(), Some("1.10.32"));
                assert_eq!(req.allow_downgrade, Some(true));
                assert_eq!(req.insecure_no_verify, Some(true));
                // path must NOT be set (no positional binary path)
                assert!(req.path.is_none());
            },
            ok_response("update scheduled via rdv"),
        );

        let result = self_update_from_rdv(
            &mut client,
            Some("canary".to_string()),
            Some("1.10.32".to_string()),
            true,
            true,
        )
        .await
        .unwrap();
        assert!(result.contains("scheduled"));
        h.await.unwrap();
    }

    /// rsh-5264.6: defaults — None track/version + false flags emit a minimal
    /// request (only req_type set, optional flags omitted via skip_if_none).
    #[tokio::test]
    async fn self_update_from_rdv_omits_optional_fields_when_default() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "self-update-from-rdv");
                assert!(req.track.is_none());
                assert!(req.version.is_none());
                assert!(req.allow_downgrade.is_none());
                assert!(req.insecure_no_verify.is_none());
            },
            ok_response(""),
        );

        let _ = self_update_from_rdv(&mut client, None, None, false, false)
            .await
            .unwrap();
        h.await.unwrap();
    }

    // ── Input ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn input_formats_command() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "input");
                assert_eq!(req.command.as_deref(), Some("mouse pos 500,300"));
            },
            ok_response("ok"),
        );

        let result = input(&mut client, "mouse", "pos", "500,300").await.unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn input_no_args() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("key enter"));
            },
            ok_response(""),
        );

        input(&mut client, "key", "enter", "").await.unwrap();
        h.await.unwrap();
    }

    // ── Native + wrappers ────────────────────────────────────────────

    #[tokio::test]
    async fn native_sends_command() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "native");
                assert_eq!(req.command.as_deref(), Some("info"));
            },
            ok_response("Windows 11"),
        );

        let result = native(&mut client, "info").await.unwrap();
        assert_eq!(result, "Windows 11");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ps_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "native");
                assert_eq!(req.command.as_deref(), Some("ps"));
            },
            ok_response("PID 1234 explorer.exe"),
        );

        let result = ps(&mut client).await.unwrap();
        assert!(result.contains("explorer.exe"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn kill_process_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("kill 1234"));
            },
            ok_response("killed"),
        );

        let result = kill_process(&mut client, "1234").await.unwrap();
        assert_eq!(result, "killed");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn tail_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("tail /var/log/syslog 20"));
            },
            ok_response("last line"),
        );

        let result = tail(&mut client, "/var/log/syslog", 20).await.unwrap();
        assert_eq!(result, "last line");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn filever_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("filever C:\\app.exe"));
            },
            ok_response("1.0.0.0"),
        );

        let result = filever(&mut client, "C:\\app.exe").await.unwrap();
        assert_eq!(result, "1.0.0.0");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn info_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("info"));
            },
            ok_response("hostname: test"),
        );

        let result = info(&mut client).await.unwrap();
        assert!(result.contains("hostname"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn eventlog_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("eventlog System 10"));
            },
            ok_response("event data"),
        );

        let result = eventlog(&mut client, "System", 10).await.unwrap();
        assert_eq!(result, "event data");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn clip_get_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("clip-get"));
            },
            ok_response("clipboard content"),
        );

        let result = clip_get(&mut client).await.unwrap();
        assert_eq!(result, "clipboard content");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn clip_set_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("clip-set hello world"));
            },
            ok_response("ok"),
        );

        let result = clip_set(&mut client, "hello world").await.unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn service_with_name() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("service status nginx"));
            },
            ok_response("running"),
        );

        let result = service(&mut client, "status", Some("nginx")).await.unwrap();
        assert_eq!(result, "running");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn service_without_name() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.command.as_deref(), Some("service list"));
            },
            ok_response("svc1\nsvc2"),
        );

        let result = service(&mut client, "list", None).await.unwrap();
        assert!(result.contains("svc1"));
        h.await.unwrap();
    }

    // ── Plugin ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn plugin_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "plugin");
                assert_eq!(req.command.as_deref(), Some("list"));
            },
            ok_response("plugin1 v1.0"),
        );

        let result = plugin(&mut client, "list").await.unwrap();
        assert!(result.contains("plugin1"));
        h.await.unwrap();
    }

    // ── Error propagation ────────────────────────────────────────────

    #[tokio::test]
    async fn exec_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("command not found"));

        let err = exec(&mut client, "nosuchcmd", &[]).await.unwrap_err();
        assert!(err.to_string().contains("command not found"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ls_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("access denied"));

        let err = ls(&mut client, "/root").await.unwrap_err();
        assert!(err.to_string().contains("access denied"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn write_file_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("disk full"));

        let err = write_file(&mut client, "/tmp/big", b"data")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disk full"));
        h.await.unwrap();
    }

    // ── Additional check_response tests ─────────────────────────────

    #[test]
    fn check_response_error_no_message() {
        // When error field is None, should report "unknown error"
        let resp = Response {
            success: false,
            output: None,
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        let err = check_response(&resp).unwrap_err();
        assert!(err.to_string().contains("unknown error"));
    }

    #[test]
    fn check_response_success_with_no_output() {
        let resp = Response {
            success: true,
            output: None,
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        assert!(check_response(&resp).is_ok());
    }

    #[test]
    fn check_response_error_with_empty_string() {
        let resp = Response {
            success: false,
            output: None,
            error: Some("".to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
        // Even an empty error string should still fail
        let err = check_response(&resp);
        assert!(err.is_err());
    }

    // ── Additional build_request tests ──────────────────────────────

    #[test]
    fn build_request_all_none() {
        let req = build_request("ping", None, None, None);
        assert_eq!(req.req_type, "ping");
        assert!(req.command.is_none());
        assert!(req.path.is_none());
        assert!(req.content.is_none());
        assert!(req.binary.is_none());
        assert!(req.gzip.is_none());
        assert!(req.sync_type.is_none());
        assert!(req.delta.is_none());
        assert!(req.signatures.is_none());
        assert!(req.paths.is_none());
        assert!(req.batch_patches.is_none());
        assert!(req.env_vars.is_none());
    }

    #[test]
    fn simple_request_format() {
        let req = simple_request("exec");
        assert_eq!(req.req_type, "exec");
        assert!(req.command.is_none());
        assert!(req.path.is_none());
        assert!(req.content.is_none());
        assert!(req.binary.is_none());
        assert!(req.env_vars.is_none());
    }

    #[test]
    fn simple_request_preserves_type_string() {
        let req = simple_request("self-update");
        assert_eq!(req.req_type, "self-update");
    }

    // ── Additional error propagation tests ──────────────────────────

    #[tokio::test]
    async fn cat_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("no such file"));

        let err = cat(&mut client, "/nonexistent").await.unwrap_err();
        assert!(err.to_string().contains("no such file"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn screenshot_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("display not found"));

        let err = screenshot(&mut client, 5, 80, 50).await.unwrap_err();
        assert!(err.to_string().contains("display not found"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn session_kill_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("session not found"));

        let err = session_kill(&mut client, "nosuchid").await.unwrap_err();
        assert!(err.to_string().contains("session not found"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn self_update_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("binary not found"));

        let err = self_update(&mut client, "/bad/path").await.unwrap_err();
        assert!(err.to_string().contains("binary not found"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn input_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("input not supported"));

        let err = input(&mut client, "mouse", "click", "100,200")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("input not supported"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn native_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("not available"));

        let err = native(&mut client, "info").await.unwrap_err();
        assert!(err.to_string().contains("not available"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn plugin_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("plugin not loaded"));

        let err = plugin(&mut client, "status foo").await.unwrap_err();
        assert!(err.to_string().contains("plugin not loaded"));
        h.await.unwrap();
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[tokio::test]
    async fn ls_invalid_json_returns_parse_error() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, ok_response("not valid json"));

        let err = ls(&mut client, "/tmp").await.unwrap_err();
        assert!(err.to_string().contains("parse ls response"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn cat_binary_invalid_base64_returns_error() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, ok_response_binary("!!!not-base64!!!"));

        let err = cat(&mut client, "/bin/bad").await.unwrap_err();
        assert!(err.to_string().contains("decode base64"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn exec_success_with_empty_output() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "exec");
            },
            ok_response(""),
        );

        let result = exec(&mut client, "true", &[]).await.unwrap();
        assert_eq!(result, "");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn exec_success_output_none_defaults_empty() {
        let (mut client, server) = mock_client();
        let resp = Response {
            success: true,
            output: None,
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        let h = spawn_mock_server(server, |_| {}, resp);

        let result = exec(&mut client, "true", &[]).await.unwrap();
        assert_eq!(result, "");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn cat_non_binary_returns_raw_bytes() {
        // When binary flag is false/None, output is returned as raw UTF-8 bytes
        let (mut client, server) = mock_client();
        let resp = Response {
            success: true,
            output: Some("plain text content".to_string()),
            error: None,
            size: None,
            binary: Some(false),
            gzip: None,
        };
        let h = spawn_mock_server(server, |_| {}, resp);

        let data = cat(&mut client, "/etc/hostname").await.unwrap();
        assert_eq!(data, b"plain text content");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn write_file_empty_content() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            move |req| {
                assert_eq!(req.req_type, "write");
                assert_eq!(req.path.as_deref(), Some("/tmp/empty"));
                // base64 of empty slice is ""
                assert_eq!(req.content.as_deref(), Some(""));
                assert_eq!(req.binary, Some(true));
            },
            ok_response(""),
        );

        write_file(&mut client, "/tmp/empty", b"").await.unwrap();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn screenshot_parameters_encoded_correctly() {
        let (mut client, server) = mock_client();
        let fake_data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic
        let b64 = base64::engine::general_purpose::STANDARD.encode(&fake_data);
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "screenshot");
                assert_eq!(req.command.as_deref(), Some("2")); // display 2
                assert_eq!(req.content.as_deref(), Some("100")); // quality 100
                assert_eq!(req.path.as_deref(), Some("75")); // scale 75
            },
            ok_response(&b64),
        );

        let data = screenshot(&mut client, 2, 100, 75).await.unwrap();
        assert_eq!(data, fake_data);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn input_with_multi_word_args() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "input");
                // "key type Hello World" — command=key, action=type, args="Hello World"
                assert_eq!(req.command.as_deref(), Some("key type Hello World"));
            },
            ok_response("ok"),
        );

        let result = input(&mut client, "key", "type", "Hello World")
            .await
            .unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn service_action_formats() {
        // Test various service actions format correctly
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                assert_eq!(req.req_type, "native");
                assert_eq!(req.command.as_deref(), Some("service restart sshd"));
            },
            ok_response("restarted"),
        );

        let result = service(&mut client, "restart", Some("sshd")).await.unwrap();
        assert_eq!(result, "restarted");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn exec_multiple_env_vars() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(
            server,
            |req| {
                let env = req.env_vars.as_ref().unwrap();
                assert_eq!(env.len(), 3);
                assert_eq!(env[0], "A=1");
                assert_eq!(env[1], "B=2");
                assert_eq!(env[2], "C=3");
            },
            ok_response("ok"),
        );

        let envs = vec!["A=1".to_string(), "B=2".to_string(), "C=3".to_string()];
        exec(&mut client, "env", &envs).await.unwrap();
        h.await.unwrap();
    }

    // ── Log query (binary protocol) ─────────────────────────────────

    /// Spawn a mock binary-protocol server for log_query tests.
    /// Reads the LOG_QUERY message, validates it, then sends the provided messages.
    fn spawn_log_query_server(
        mut server: DuplexStream,
        validate: impl FnOnce(&[u8]) + Send + 'static,
        responses: Vec<(u8, Vec<u8>)>,
    ) -> tokio::task::JoinHandle<()> {
        use mrsh_core::binproto;
        tokio::spawn(async move {
            // Read the LOG_QUERY message
            let (type_id, payload) = binproto::recv_msg(&mut server).await.unwrap();
            assert_eq!(type_id, binproto::msg::LOG_QUERY);
            validate(&payload);
            // Send each response message
            for (msg_type, data) in responses {
                binproto::send_msg(&mut server, msg_type, &data)
                    .await
                    .unwrap();
            }
        })
    }

    #[tokio::test]
    async fn log_query_data_then_end() {
        use mrsh_core::binproto::{self, msg};

        let (mut client, server) = mock_client();

        let line1 = b"2026-03-25 error: something failed";
        let line2 = b"2026-03-25 error: another failure";
        let log_end = binproto::build_log_end(1000, 2, 5000);

        let h = spawn_log_query_server(
            server,
            |payload| {
                let (path, pattern, flags, tail, _offset, max) =
                    binproto::parse_log_query(payload).unwrap();
                assert_eq!(path, "/var/log/app.log");
                assert_eq!(pattern, "error");
                assert_eq!(flags, 0);
                assert_eq!(tail, 100);
                assert_eq!(max, 50);
            },
            vec![
                (msg::LOG_DATA, line1.to_vec()),
                (msg::LOG_DATA, line2.to_vec()),
                (msg::LOG_END, log_end),
            ],
        );

        let (scanned, matched) = log_query(&mut client, "/var/log/app.log", "error", 0, 100, 50)
            .await
            .unwrap();
        assert_eq!(scanned, 1000);
        assert_eq!(matched, 2);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn log_query_no_matches() {
        use mrsh_core::binproto::{self, msg};

        let (mut client, server) = mock_client();
        let log_end = binproto::build_log_end(500, 0, 2000);

        let h = spawn_log_query_server(server, |_| {}, vec![(msg::LOG_END, log_end)]);

        let (scanned, matched) =
            log_query(&mut client, "/var/log/app.log", "nonexistent", 0, 50, 10)
                .await
                .unwrap();
        assert_eq!(scanned, 500);
        assert_eq!(matched, 0);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn log_query_server_error() {
        use mrsh_core::binproto::{self, msg};

        let (mut client, server) = mock_client();
        let error_payload = binproto::build_error("file not found");

        let h = spawn_log_query_server(server, |_| {}, vec![(msg::ERROR, error_payload)]);

        let err = log_query(&mut client, "/nonexistent.log", "pattern", 0, 100, 50)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("file not found"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn log_query_unexpected_message_type() {
        use mrsh_core::binproto::msg;

        let (mut client, server) = mock_client();

        let h = spawn_log_query_server(
            server,
            |_| {},
            vec![
                (msg::PING, vec![]), // unexpected message type for log_query
            ],
        );

        let err = log_query(&mut client, "/var/log/test.log", "x", 0, 10, 5)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unexpected message type"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn log_query_with_flags() {
        use mrsh_core::binproto::{self, msg};

        let (mut client, server) = mock_client();
        let flags = binproto::LOG_FLAG_CASE_INSENSITIVE | binproto::LOG_FLAG_INVERT;
        let log_end = binproto::build_log_end(200, 5, 1000);

        let h = spawn_log_query_server(
            server,
            move |payload| {
                let (_path, _pattern, f, _tail, _offset, _max) =
                    binproto::parse_log_query(payload).unwrap();
                assert_eq!(f, flags);
            },
            vec![(msg::LOG_END, log_end)],
        );

        let (scanned, matched) =
            log_query(&mut client, "/var/log/test.log", "debug", flags, 0, 100)
                .await
                .unwrap();
        assert_eq!(scanned, 200);
        assert_eq!(matched, 5);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn log_query_data_lines_printed_before_end() {
        use mrsh_core::binproto::{self, msg};

        let (mut client, server) = mock_client();
        // Server sends 3 LOG_DATA lines, then LOG_END with matched=3
        let log_end = binproto::build_log_end(100, 3, 500);

        let h = spawn_log_query_server(
            server,
            |_| {},
            vec![
                (msg::LOG_DATA, b"line one".to_vec()),
                (msg::LOG_DATA, b"line two".to_vec()),
                (msg::LOG_DATA, b"line three".to_vec()),
                (msg::LOG_END, log_end),
            ],
        );

        let (scanned, matched) = log_query(&mut client, "/log", "pattern", 0, 50, 100)
            .await
            .unwrap();
        // LOG_END matched count is authoritative (overwrites incremental counter)
        assert_eq!(scanned, 100);
        assert_eq!(matched, 3);
        h.await.unwrap();
    }
}
