//! Command execution — runs commands via PowerShell (Windows) or sh (Linux).
//!
//! Two modes:
//! - Buffered (`handle_exec`): waits for process to complete, returns full output.
//! - Streaming (`handle_exec_stream`): sends stdout/stderr chunks as they arrive.

use anyhow::Result;
use mrsh_core::binproto::{self, msg};
use mrsh_core::protocol::Response;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::safety;

#[cfg(target_os = "windows")]
use std::sync::OnceLock;

/// On Windows: probes once at first exec whether direct `powershell.exe` spawning works.
/// Some systems (AppLocker / software restriction policies) block direct pwsh spawning
/// by SYSTEM services but allow `cmd.exe → powershell.exe` via indirection. When the probe
/// fails we wrap PS commands via `cmd /c powershell -NoProfile -Command <cmd>`.
#[cfg(target_os = "windows")]
static POWERSHELL_DIRECT_WORKS: OnceLock<bool> = OnceLock::new();

#[cfg(target_os = "windows")]
fn probe_powershell_direct() -> bool {
    // Synchronous probe — called once at lazy init time. Short timeout.
    use std::os::windows::process::CommandExt;
    let result = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "exit 0"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .output();
    match result {
        Ok(o) if o.status.success() => {
            info!("exec: direct powershell spawn probe PASSED — using direct pwsh");
            true
        }
        Ok(o) => {
            warn!(
                "exec: direct powershell probe returned exit={:?} — routing via cmd /c fallback",
                o.status.code()
            );
            false
        }
        Err(e) => {
            warn!(
                "exec: direct powershell spawn failed ({}) — routing via cmd /c fallback",
                e
            );
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn powershell_direct_works() -> bool {
    *POWERSHELL_DIRECT_WORKS.get_or_init(probe_powershell_direct)
}

/// Execute a command and return the response.
/// On Windows: `powershell -NoProfile -Command <cmd>` (default)
///             `cmd /c <cmd>` (shell="cmd")
/// On Linux: `sh -c <cmd>`
pub async fn handle_exec(command: &str, env_vars: &[String]) -> Response {
    handle_exec_with_shell(command, env_vars, None).await
}

/// Execute with explicit shell selection.
/// Shell can be specified via `shell` param or command prefix:
///   `CMD:dir /b`  → cmd.exe
///   `SH:ls -la`   → sh/bash
///   `echo hello`  → default (PowerShell on Windows, sh on Linux)
pub async fn handle_exec_with_shell(
    command: &str,
    env_vars: &[String],
    shell: Option<&str>,
) -> Response {
    // Auto-detect shell from command prefix
    let (effective_shell, effective_command) = if let Some(rest) = command.strip_prefix("CMD:") {
        (Some("cmd"), rest)
    } else if let Some(rest) = command.strip_prefix("SH:") {
        (Some("sh"), rest)
    } else {
        (shell, command)
    };
    let command = effective_command;
    let shell = effective_shell;
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

    let result = run_command_with_shell(command, env_vars, shell).await;

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

/// Run with explicit shell.
async fn run_command_with_shell(
    command: &str,
    env_vars: &[String],
    shell: Option<&str>,
) -> anyhow::Result<(String, bool)> {
    let mut cmd = build_command_with_shell(command, shell);

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
pub fn build_command(command: &str) -> tokio::process::Command {
    build_command_with_shell(command, None)
}

#[cfg(target_os = "windows")]
pub fn build_command_with_shell(command: &str, shell: Option<&str>) -> tokio::process::Command {
    let mut cmd = match shell {
        Some("cmd") => {
            let mut c = tokio::process::Command::new("cmd");
            c.args(["/c", command]);
            c
        }
        Some("sh") | Some("bash") => {
            // Use Git Bash if available, otherwise fall back to PowerShell
            let bash = if std::path::Path::new("C:\\Program Files\\Git\\bin\\bash.exe").exists() {
                "C:\\Program Files\\Git\\bin\\bash.exe"
            } else {
                "bash"
            };
            let mut c = tokio::process::Command::new(bash);
            c.args(["-c", command]);
            c
        }
        _ => {
            // Default: PowerShell — probe once whether direct spawn works on this host.
            // If AppLocker / policy blocks pwsh.exe as a SYSTEM-service child, fall back
            // to `cmd /c powershell -NoProfile -Command <cmd>` which routes via cmd.exe.
            if powershell_direct_works() {
                let mut c = tokio::process::Command::new("powershell");
                c.args(["-NoProfile", "-Command", command]);
                c
            } else {
                let mut c = tokio::process::Command::new("cmd");
                // /d disables AutoRun; /c runs the following command and terminates.
                // powershell is resolved from PATH inside the cmd child, which on
                // AppLocker-constrained systems is the path that the policy allows.
                c.args(["/d", "/c", "powershell", "-NoProfile", "-Command", command]);
                c
            }
        }
    };
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd
}

#[cfg(not(target_os = "windows"))]
pub fn build_command(command: &str) -> tokio::process::Command {
    build_command_with_shell(command, None)
}

#[cfg(not(target_os = "windows"))]
pub fn build_command_with_shell(command: &str, shell: Option<&str>) -> tokio::process::Command {
    let shell_bin = match shell {
        Some("bash") => "bash",
        Some("sh") => "sh",
        _ => "sh",
    };
    let mut cmd = tokio::process::Command::new(shell_bin);
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

    fn read_env_command(name: &str) -> String {
        #[cfg(target_os = "windows")]
        {
            format!("Write-Output $env:{name}")
        }
        #[cfg(not(target_os = "windows"))]
        {
            format!("printenv {name}")
        }
    }

    fn require_env_command(name: &str) -> String {
        #[cfg(target_os = "windows")]
        {
            format!("if ($env:{name}) {{ Write-Output $env:{name} }} else {{ exit 1 }}")
        }
        #[cfg(not(target_os = "windows"))]
        {
            format!("printenv {name}")
        }
    }

    fn join_env_command(left: &str, right: &str) -> String {
        #[cfg(target_os = "windows")]
        {
            format!("Write-Output ($env:{left} + '_' + $env:{right})")
        }
        #[cfg(not(target_os = "windows"))]
        {
            format!("echo ${{{left}}}_${{{right}}}")
        }
    }

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
        let resp = handle_exec(
            &read_env_command("TEST_VAR"),
            &["TEST_VAR=hello123".to_string()],
        )
        .await;
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
            handle_exec_stream(
                "echo streaming_test",
                &[],
                &mut tokio::io::BufWriter::new(writer),
            )
            .await
        });

        // Read chunks from the pipe
        let mut got_stdout = false;
        let exit_code = loop {
            let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
            match type_id {
                msg::EXEC_STDOUT => {
                    let s = String::from_utf8_lossy(&data);
                    if s.contains("streaming_test") {
                        got_stdout = true;
                    }
                }
                msg::EXEC_EXIT => {
                    break Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
                }
                msg::EXEC_STDERR => {} // ignore stderr
                _ => panic!("unexpected msg type 0x{:02x}", type_id),
            }
        };
        assert!(
            got_stdout,
            "should have received stdout with 'streaming_test'"
        );
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

    // ── build_command tests ─────────────────────────────────────

    #[test]
    fn build_command_uses_expected_shell() {
        let cmd = build_command("echo test");
        let std_cmd = cmd.as_std();
        let args: Vec<&std::ffi::OsStr> = std_cmd.get_args().collect();
        #[cfg(target_os = "windows")]
        {
            // Default PS path may be direct (`powershell -NoProfile -Command echo test`)
            // or fallback via cmd (`cmd /d /c powershell -NoProfile -Command echo test`).
            // The probe decides at first call; both are valid — assert the final PS
            // invocation args match, regardless of wrapper.
            let program = std_cmd.get_program().to_str().unwrap_or("");
            if program == "powershell" {
                assert_eq!(args, vec!["-NoProfile", "-Command", "echo test"]);
            } else {
                assert_eq!(program, "cmd");
                assert_eq!(
                    args,
                    vec!["/d", "/c", "powershell", "-NoProfile", "-Command", "echo test"]
                );
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(std_cmd.get_program(), "sh");
            assert_eq!(args, vec!["-c", "echo test"]);
        }
    }

    #[test]
    fn build_command_preserves_complex_command() {
        let complex = "ls -la /tmp && echo done | grep done";
        let cmd = build_command(complex);
        let std_cmd = cmd.as_std();
        let args: Vec<&std::ffi::OsStr> = std_cmd.get_args().collect();
        #[cfg(target_os = "windows")]
        {
            // Accept either direct powershell invocation or cmd-wrapped fallback
            // (depending on whether the one-shot probe decided pwsh is spawnable).
            let program = std_cmd.get_program().to_str().unwrap_or("");
            if program == "powershell" {
                assert_eq!(args[0], "-NoProfile");
                assert_eq!(args[1], "-Command");
                assert_eq!(args[2], complex);
            } else {
                assert_eq!(program, "cmd");
                assert_eq!(args[0], "/d");
                assert_eq!(args[1], "/c");
                assert_eq!(args[2], "powershell");
                assert_eq!(args[3], "-NoProfile");
                assert_eq!(args[4], "-Command");
                assert_eq!(args[5], complex);
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(args[0], "-c");
            assert_eq!(args[1], complex);
        }
    }

    #[test]
    fn build_command_with_empty_string() {
        // build_command itself does not validate — that's handle_exec's job.
        // Verify it still produces a valid Command structure.
        let cmd = build_command("");
        let std_cmd = cmd.as_std();
        let args: Vec<&std::ffi::OsStr> = std_cmd.get_args().collect();
        #[cfg(target_os = "windows")]
        {
            let program = std_cmd.get_program().to_str().unwrap_or("");
            if program == "powershell" {
                assert_eq!(args, vec!["-NoProfile", "-Command", ""]);
            } else {
                assert_eq!(program, "cmd");
                assert_eq!(args, vec!["/d", "/c", "powershell", "-NoProfile", "-Command", ""]);
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(std_cmd.get_program(), "sh");
            assert_eq!(args, vec!["-c", ""]);
        }
    }

    // ── is_dangerous_env_var exhaustive coverage ────────────────

    #[test]
    fn blocks_all_documented_dangerous_vars() {
        // Every single entry in the matches! block
        let dangerous = [
            "PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "SHELL",
            "COMSPEC",
            "IFS",
            "PSMODULEPATH",
            "PSModulePath",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "HOME",
            "USERPROFILE",
            "USER",
            "USERNAME",
            "LOGNAME",
        ];
        for var in &dangerous {
            assert!(is_dangerous_env_var(var), "{} should be blocked", var);
        }
    }

    #[test]
    fn dangerous_vars_case_insensitive() {
        // The function does .to_uppercase() so lowercase/mixed should also block
        assert!(is_dangerous_env_var("path"));
        assert!(is_dangerous_env_var("Path"));
        assert!(is_dangerous_env_var("ld_preload"));
        assert!(is_dangerous_env_var("Ld_Preload"));
        assert!(is_dangerous_env_var("shell"));
        assert!(is_dangerous_env_var("Shell"));
        assert!(is_dangerous_env_var("comspec"));
        assert!(is_dangerous_env_var("ifs"));
        assert!(is_dangerous_env_var("home"));
        assert!(is_dangerous_env_var("Home"));
        assert!(is_dangerous_env_var("username"));
        assert!(is_dangerous_env_var("logname"));
        assert!(is_dangerous_env_var("all_proxy"));
        assert!(is_dangerous_env_var("no_proxy"));
        assert!(is_dangerous_env_var("userprofile"));
    }

    #[test]
    fn allows_vars_with_dangerous_substring() {
        // Vars that contain a dangerous name as substring should NOT be blocked
        assert!(!is_dangerous_env_var("MY_PATH"));
        assert!(!is_dangerous_env_var("PATH_EXTRA"));
        assert!(!is_dangerous_env_var("MY_HOME_DIR"));
        assert!(!is_dangerous_env_var("CUSTOM_USER"));
        assert!(!is_dangerous_env_var("NEW_SHELL_VAR"));
        assert!(!is_dangerous_env_var("NOT_HTTP_PROXY_REALLY"));
    }

    #[test]
    fn allows_common_safe_env_vars() {
        let safe = [
            "RUST_LOG",
            "RUST_BACKTRACE",
            "LANG",
            "LC_ALL",
            "TZ",
            "TERM",
            "DISPLAY",
            "EDITOR",
            "VISUAL",
            "CARGO_HOME",
            "GOPATH",
            "NODE_ENV",
            "APP_CONFIG",
            "DATABASE_URL",
            "PORT",
            "DEBUG",
            "VERBOSE",
        ];
        for var in &safe {
            assert!(!is_dangerous_env_var(var), "{} should be allowed", var);
        }
    }

    #[test]
    fn dangerous_var_empty_name() {
        assert!(!is_dangerous_env_var(""));
    }

    // ── handle_exec response format tests ───────────────────────

    #[tokio::test]
    async fn exec_empty_command_response_fields() {
        let resp = handle_exec("", &[]).await;
        assert!(!resp.success);
        assert!(resp.output.is_none());
        assert_eq!(resp.error, Some("empty command".to_string()));
        assert!(resp.size.is_none());
        assert!(resp.binary.is_none());
        assert!(resp.gzip.is_none());
    }

    #[tokio::test]
    async fn exec_success_response_fields() {
        let resp = handle_exec("echo ok", &[]).await;
        assert!(resp.success);
        assert!(resp.output.is_some());
        assert!(resp.error.is_none());
        assert!(resp.size.is_none());
        assert!(resp.binary.is_none());
        assert!(resp.gzip.is_none());
    }

    #[tokio::test]
    async fn exec_failure_response_has_output_not_error() {
        // A command that runs but exits non-zero still has output, not error
        let resp = handle_exec("echo fail_msg >&2; false", &[]).await;
        assert!(!resp.success);
        assert!(resp.output.is_some()); // combined stdout+stderr
        assert!(resp.error.is_none()); // error is only for spawn failures
    }

    // ── handle_exec safety guard integration ────────────────────

    #[tokio::test]
    async fn exec_blocks_taskkill_rsh() {
        let resp = handle_exec("taskkill /im rsh.exe /f", &[]).await;
        assert!(!resp.success);
        assert!(resp.output.is_none());
        let err = resp.error.unwrap();
        assert!(err.contains("BLOCKED"), "expected BLOCKED, got: {}", err);
        assert!(err.contains("safety guard"));
    }

    #[tokio::test]
    async fn exec_blocks_stop_service_mrsh() {
        let resp = handle_exec("Stop-Service mrsh", &[]).await;
        assert!(!resp.success);
        let err = resp.error.unwrap();
        assert!(err.contains("BLOCKED"));
    }

    #[tokio::test]
    async fn exec_blocks_net_stop_rsh() {
        let resp = handle_exec("net stop rsh", &[]).await;
        assert!(!resp.success);
        let err = resp.error.unwrap();
        assert!(err.contains("BLOCKED"));
    }

    #[tokio::test]
    async fn exec_blocks_sc_delete_mrsh() {
        let resp = handle_exec("sc delete mrsh", &[]).await;
        assert!(!resp.success);
        let err = resp.error.unwrap();
        assert!(err.contains("BLOCKED"));
    }

    #[tokio::test]
    async fn exec_blocks_remove_item_rsh_exe() {
        let resp = handle_exec("Remove-Item C:\\ProgramData\\mrsh\\rsh.exe", &[]).await;
        assert!(!resp.success);
        let err = resp.error.unwrap();
        assert!(err.contains("BLOCKED"));
    }

    #[tokio::test]
    async fn exec_allows_safe_commands() {
        // Verify safety guard does NOT block normal commands
        let resp = handle_exec("echo hello_world", &[]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("hello_world"));
    }

    // ── handle_exec env var filtering ───────────────────────────

    #[tokio::test]
    async fn exec_dangerous_env_var_silently_dropped() {
        // PATH is dangerous; command should still succeed but not see the override
        // so the inherited PATH is used instead of the injected value.
        let resp = handle_exec(&read_env_command("PATH"), &["PATH=/evil/path".to_string()]).await;
        assert!(resp.success);
        let output = resp.output.unwrap();
        assert!(
            !output.contains("/evil/path"),
            "PATH override should have been blocked, got: {}",
            output
        );
    }

    #[tokio::test]
    async fn exec_safe_env_var_passed_through() {
        let resp = handle_exec(
            &read_env_command("MY_CUSTOM_VAR"),
            &["MY_CUSTOM_VAR=secret42".to_string()],
        )
        .await;
        assert!(resp.success);
        assert!(
            resp.output.unwrap().contains("secret42"),
            "safe env var should be passed to command"
        );
    }

    #[tokio::test]
    async fn exec_malformed_env_var_ignored() {
        // Entries without '=' should be silently ignored
        let resp = handle_exec("echo works", &["NO_EQUALS_SIGN".to_string()]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("works"));
    }

    #[tokio::test]
    async fn exec_multiple_env_vars_mixed() {
        // Mix of safe, dangerous, and malformed env vars
        let env_vars = vec![
            "SAFE_ONE=alpha".to_string(),
            "PATH=/bad".to_string(), // dangerous, dropped
            "MALFORMED".to_string(), // no '=', ignored
            "SAFE_TWO=beta".to_string(),
            "LD_PRELOAD=/evil.so".to_string(), // dangerous, dropped
        ];
        let resp = handle_exec(&join_env_command("SAFE_ONE", "SAFE_TWO"), &env_vars).await;
        assert!(resp.success);
        let output = resp.output.unwrap();
        assert!(output.contains("alpha"), "SAFE_ONE should be set");
        assert!(output.contains("beta"), "SAFE_TWO should be set");
    }

    #[tokio::test]
    async fn exec_env_var_with_equals_in_value() {
        // Value itself contains '=' — split_once should handle this
        let resp = handle_exec(
            &read_env_command("CONN_STR"),
            &["CONN_STR=host=localhost;port=5432".to_string()],
        )
        .await;
        assert!(resp.success);
        assert!(
            resp.output.unwrap().contains("host=localhost;port=5432"),
            "value with embedded '=' should be preserved"
        );
    }

    // ── handle_exec_stream safety guard integration ─────────────

    #[tokio::test]
    async fn exec_stream_blocks_dangerous_command() {
        use mrsh_core::binproto;

        let (mut reader, writer) = tokio::io::duplex(4096);
        let handle = tokio::spawn(async move {
            handle_exec_stream(
                "taskkill /im rsh.exe /f",
                &[],
                &mut tokio::io::BufWriter::new(writer),
            )
            .await
        });

        let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
        assert_eq!(type_id, msg::ERROR);
        let err = binproto::parse_error(&data).unwrap();
        assert!(err.contains("BLOCKED"), "expected BLOCKED, got: {}", err);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exec_stream_failing_command() {
        use mrsh_core::binproto;

        let (mut reader, writer) = tokio::io::duplex(65536);
        let handle = tokio::spawn(async move {
            handle_exec_stream("false", &[], &mut tokio::io::BufWriter::new(writer)).await
        });

        // Read all messages until EXEC_EXIT
        let exit_code = loop {
            let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
            match type_id {
                msg::EXEC_STDOUT | msg::EXEC_STDERR => {}
                msg::EXEC_EXIT => {
                    break u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                }
                _ => panic!("unexpected msg type 0x{:02x}", type_id),
            }
        };
        assert_eq!(exit_code, 1, "false should exit with code 1");
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exec_stream_with_env_vars() {
        use mrsh_core::binproto;

        let (mut reader, writer) = tokio::io::duplex(65536);
        let env = vec!["STREAM_TEST_VAR=streamed123".to_string()];
        let cmd = read_env_command("STREAM_TEST_VAR");
        let handle = tokio::spawn(async move {
            handle_exec_stream(&cmd, &env, &mut tokio::io::BufWriter::new(writer)).await
        });

        let mut got_value = false;
        loop {
            let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
            match type_id {
                msg::EXEC_STDOUT => {
                    let s = String::from_utf8_lossy(&data);
                    if s.contains("streamed123") {
                        got_value = true;
                    }
                }
                msg::EXEC_STDERR => {}
                msg::EXEC_EXIT => break,
                _ => panic!("unexpected msg type 0x{:02x}", type_id),
            }
        }
        assert!(got_value, "env var should appear in stream output");
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exec_stream_dangerous_env_var_blocked() {
        use mrsh_core::binproto;

        let (mut reader, writer) = tokio::io::duplex(65536);
        let env = vec!["LD_PRELOAD=/evil.so".to_string()];
        let cmd = require_env_command("LD_PRELOAD");
        let handle = tokio::spawn(async move {
            handle_exec_stream(&cmd, &env, &mut tokio::io::BufWriter::new(writer)).await
        });

        let mut saw_evil = false;
        let exit_code = loop {
            let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
            match type_id {
                msg::EXEC_STDOUT => {
                    let s = String::from_utf8_lossy(&data);
                    if s.contains("/evil.so") {
                        saw_evil = true;
                    }
                }
                msg::EXEC_STDERR => {}
                msg::EXEC_EXIT => {
                    break u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                }
                _ => panic!("unexpected msg type 0x{:02x}", type_id),
            }
        };
        assert!(!saw_evil, "LD_PRELOAD should have been blocked");
        // printenv for unset var exits non-zero
        assert_eq!(exit_code, 1);
        handle.await.unwrap().unwrap();
    }

    // ── handle_exec stderr capture ──────────────────────────────

    #[tokio::test]
    async fn exec_captures_stderr_in_output() {
        let resp = handle_exec("echo stderr_test >&2", &[]).await;
        // stderr is combined into output
        assert!(resp.output.unwrap().contains("stderr_test"));
    }

    #[tokio::test]
    async fn exec_combines_stdout_and_stderr() {
        let resp = handle_exec("echo OUT_PART && echo ERR_PART >&2", &[]).await;
        let output = resp.output.unwrap();
        assert!(output.contains("OUT_PART"), "should contain stdout");
        assert!(output.contains("ERR_PART"), "should contain stderr");
    }
}
