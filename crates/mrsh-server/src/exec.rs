//! Command execution — runs commands via PowerShell (Windows) or sh (Linux).
//!
//! Two modes:
//! - Buffered (`handle_exec`): waits for process to complete, returns full output.
//! - Streaming (`handle_exec_stream`): sends stdout/stderr chunks as they arrive.

use anyhow::{Result, bail};
use mrsh_core::binproto::{self, msg};
use mrsh_core::protocol::Response;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::safety;

/// Execute a command and return the response.
/// On Windows: `powershell -NoProfile -Command <cmd>`
/// On Linux: `sh -c <cmd>` (for testing)
pub async fn handle_exec(command: &str, env_vars: &[String]) -> Response {
    debug!("exec: {}", command);

    if command.is_empty() {
        return Response {
            success: false,
            output: None,
            error: Some("empty command".to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    // Safety guard: block commands that would kill/stop this mrsh process.
    if let safety::SafetyVerdict::Block { reason } = safety::check_exec(command) {
        return Response {
            success: false,
            output: None,
            error: Some(reason),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    let result = run_command(command, env_vars).await;

    match result {
        Ok((output, success)) => Response {
            success,
            output: Some(output),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        },
        Err(e) => Response {
            success: false,
            output: None,
            error: Some(e.to_string()),
            size: None,
            binary: None,
            gzip: None,
        },
    }
}

/// Run a command, returning (output, success).
async fn run_command(command: &str, env_vars: &[String]) -> anyhow::Result<(String, bool)> {
    let mut cmd = build_command(command);

    // Add environment variables (with sanitization)
    if !env_vars.is_empty() {
        for ev in env_vars {
            if let Some((k, v)) = ev.split_once('=') {
                if is_dangerous_env_var(k) {
                    debug!("blocked dangerous env var: {}", k);
                    continue;
                }
                cmd.env(k, v);
            }
        }
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawn failed: {}", e))?;

    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    Ok((combined, output.status.success()))
}

#[cfg(target_os = "windows")]
fn build_command(command: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-Command", command]);
    // HideWindow equivalent via creation flags
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd
}

#[cfg(not(target_os = "windows"))]
fn build_command(command: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.args(["-c", command]);
    cmd
}

/// Check if an environment variable name is dangerous and should be blocked.
/// Prevents privilege escalation and code injection via env vars.
fn is_dangerous_env_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    matches!(
        upper.as_str(),
        // Path/library injection
        "PATH"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            // Shell/interpreter override
            | "SHELL"
            | "COMSPEC"
            | "IFS"
            // PowerShell profile injection
            | "PSMODULEPATH"
            | "PSModulePath"
            // Proxy hijacking
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
            | "http_proxy"
            | "https_proxy"
            // User/auth spoofing
            | "HOME"
            | "USERPROFILE"
            | "USER"
            | "USERNAME"
            | "LOGNAME"
    )
}

/// Execute a command with streaming output — sends stdout/stderr chunks as they arrive.
/// Sends EXEC_STDOUT, EXEC_STDERR, and finally EXEC_EXIT messages.
pub async fn handle_exec_stream<W: AsyncWriteExt + Unpin>(
    command: &str,
    env_vars: &[String],
    writer: &mut W,
) -> Result<()> {
    debug!("exec_stream: {}", command);

    if command.is_empty() {
        let err = binproto::build_error("empty command");
        binproto::send_msg(writer, msg::ERROR, &err).await?;
        return Ok(());
    }

    // Safety guard
    if let safety::SafetyVerdict::Block { reason } = safety::check_exec(command) {
        let err = binproto::build_error(&reason);
        binproto::send_msg(writer, msg::ERROR, &err).await?;
        return Ok(());
    }

    let mut cmd = build_command(command);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    // Add environment variables
    for ev in env_vars {
        if let Some((k, v)) = ev.split_once('=') {
            if is_dangerous_env_var(k) {
                debug!("blocked dangerous env var: {}", k);
                continue;
            }
            cmd.env(k, v);
        }
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = binproto::build_error(&format!("spawn failed: {}", e));
            binproto::send_msg(writer, msg::ERROR, &err).await?;
            return Ok(());
        }
    };

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    let mut stdout_buf = vec![0u8; 32768];
    let mut stderr_buf = vec![0u8; 8192];
    let mut stdout_done = false;
    let mut stderr_done = false;

    // Stream chunks as they arrive
    loop {
        tokio::select! {
            biased; // prefer stdout over stderr when both ready

            result = stdout.read(&mut stdout_buf), if !stdout_done => {
                match result {
                    Ok(0) => stdout_done = true,
                    Ok(n) => {
                        binproto::send_msg(writer, msg::EXEC_STDOUT, &stdout_buf[..n]).await?;
                    }
                    Err(e) => {
                        debug!("stdout read error: {}", e);
                        stdout_done = true;
                    }
                }
            }

            result = stderr.read(&mut stderr_buf), if !stderr_done => {
                match result {
                    Ok(0) => stderr_done = true,
                    Ok(n) => {
                        binproto::send_msg(writer, msg::EXEC_STDERR, &stderr_buf[..n]).await?;
                    }
                    Err(e) => {
                        debug!("stderr read error: {}", e);
                        stderr_done = true;
                    }
                }
            }
        }

        if stdout_done && stderr_done {
            break;
        }
    }

    // Wait for process exit and send exit code
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(1) as u32;
    binproto::send_msg(writer, msg::EXEC_EXIT, &exit_code.to_le_bytes()).await?;

    debug!("exec_stream done, exit_code={}", exit_code);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_echo() {
        let resp = handle_exec("echo hello", &[]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("hello"));
    }

    #[tokio::test]
    async fn exec_empty_command() {
        let resp = handle_exec("", &[]).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("empty command"));
    }

    #[tokio::test]
    async fn exec_failing_command() {
        let resp = handle_exec("false", &[]).await;
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn exec_with_env_vars() {
        let resp = handle_exec("echo $TEST_VAR", &["TEST_VAR=hello123".to_string()]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("hello123"));
    }

    #[test]
    fn blocks_dangerous_env_vars() {
        assert!(is_dangerous_env_var("PATH"));
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("LD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
        assert!(is_dangerous_env_var("SHELL"));
        assert!(is_dangerous_env_var("COMSPEC"));
        assert!(is_dangerous_env_var("IFS"));
        assert!(is_dangerous_env_var("HTTP_PROXY"));
        assert!(is_dangerous_env_var("HOME"));
        assert!(is_dangerous_env_var("USERPROFILE"));
    }

    #[test]
    fn allows_safe_env_vars() {
        assert!(!is_dangerous_env_var("TEST_VAR"));
        assert!(!is_dangerous_env_var("MY_APP_CONFIG"));
        assert!(!is_dangerous_env_var("RUST_LOG"));
        assert!(!is_dangerous_env_var("LANG"));
    }

    #[tokio::test]
    async fn exec_stream_echo() {
        use mrsh_core::binproto;

        let (mut reader, writer) = tokio::io::duplex(65536);

        // Run the streaming handler in a task
        let handle = tokio::spawn(async move {
            handle_exec_stream("echo streaming_test", &[], &mut tokio::io::BufWriter::new(writer)).await
        });

        // Read chunks from the pipe
        let mut got_stdout = false;
        let mut exit_code = None;
        loop {
            let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
            match type_id {
                msg::EXEC_STDOUT => {
                    let s = String::from_utf8_lossy(&data);
                    if s.contains("streaming_test") {
                        got_stdout = true;
                    }
                }
                msg::EXEC_EXIT => {
                    exit_code = Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
                    break;
                }
                msg::EXEC_STDERR => {} // ignore stderr
                _ => panic!("unexpected msg type 0x{:02x}", type_id),
            }
        }
        assert!(got_stdout, "should have received stdout with 'streaming_test'");
        assert_eq!(exit_code, Some(0));
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exec_stream_empty_command() {
        use mrsh_core::binproto;

        let (mut reader, writer) = tokio::io::duplex(4096);
        let handle = tokio::spawn(async move {
            handle_exec_stream("", &[], &mut tokio::io::BufWriter::new(writer)).await
        });

        let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
        assert_eq!(type_id, msg::ERROR);
        let err = binproto::parse_error(&data).unwrap();
        assert!(err.contains("empty command"));
        handle.await.unwrap().unwrap();
    }
}
