//! SSH fallback when mrsh TLS handshake is not available.
//!
//! When direct TLS to mrsh ports (8822/9822) fails AND no relay is configured,
//! we attempt to honour the connection via the system's `ssh` client on port 22.
//! For interactive shell sessions we prefer execve'ing into native `ssh` so the
//! user keeps their existing key-agent + ControlMaster + tty handling.

use anyhow::{Result, bail};
#[cfg(feature = "ssh")]
use anyhow::Context;

use crate::server_mode;

/// Connect via SSH and run a command when mrsh TLS is not available.
pub(crate) async fn run_ssh_fallback(
    host: &str,
    port: u16,
    key_path: &Option<String>,
    user: Option<&str>,
    preferred_shell: Option<&str>,
    cmd: &str,
    args: &[String],
) -> Result<()> {
    if !mrsh_client::ssh_client::ssh_client_available() {
        bail!("SSH fallback not available (compile with --features ssh)");
    }
    #[cfg(feature = "ssh")]
    {
        use mrsh_client::ssh_client::SshSession;

        if cmd == "shell"
            && let Some(exit_code) =
                try_run_native_ssh_shell(host, port, key_path, user, preferred_shell).await?
        {
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            return Ok(());
        }

        // Noise reduction: print to stderr only when verbose, or log to tracing
        tracing::debug!("SSH fallback: connecting to {}:{}", host, port);
        let session = SshSession::connect(host, port, key_path, user).await?;
        let mut shell_env_vars = Vec::new();
        if cmd == "shell" {
            shell_env_vars.extend(args.iter().skip(1).cloned());
            if let Some(shell) = preferred_shell {
                shell_env_vars.push(format!("MRSH_SHELL={shell}"));
            }
        }
        // rsh-1cp1: once the command has been DISPATCHED over SSH, errors are
        // TERMINAL — propagating Err would let the caller's fallback chain
        // re-execute the command on another transport (observed double-exec of
        // non-idempotent commands). Connect/auth errors above still propagate
        // (nothing ran remotely yet, fallback is safe).
        let exit_code = match server_mode::run_ssh_command(session, host, cmd, args, &shell_env_vars)
            .await
        {
            Ok(code) => code,
            Err(e) => {
                eprintln!("mrsh ssh: {e}");
                std::process::exit(1);
            }
        };
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        Ok(())
    }
    #[cfg(not(feature = "ssh"))]
    {
        let _ = (host, port, key_path, user, preferred_shell, cmd, args);
        bail!("SSH fallback not available");
    }
}

#[cfg(feature = "ssh")]
async fn try_run_native_ssh_shell(
    host: &str,
    port: u16,
    key_path: &Option<String>,
    user: Option<&str>,
    preferred_shell: Option<&str>,
) -> Result<Option<i32>> {
    use std::process::Stdio;

    let Some(ssh_program) = find_native_ssh_program() else {
        return Ok(None);
    };

    let mut cmd = tokio::process::Command::new(&ssh_program);
    cmd.arg("-tt");
    if port != 22 {
        cmd.arg("-p").arg(port.to_string());
    }
    if let Some(user) = user.filter(|s| !s.is_empty()) {
        cmd.arg("-l").arg(user);
    }
    if let Some(path) = key_path.as_ref().filter(|s| !s.is_empty()) {
        cmd.arg("-i").arg(path);
    }
    cmd.arg(host);
    if let Some(shell) = preferred_shell.filter(|s| !s.is_empty()) {
        cmd.arg(shell);
    }
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    tracing::debug!("SSH fallback shell: delegating to native ssh client");
    match cmd.status().await {
        Ok(status) => Ok(Some(status.code().unwrap_or(1))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("run native ssh shell"),
    }
}

#[cfg(feature = "ssh")]
fn command_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let base = dir.join(name);
                if base.exists() {
                    return true;
                }
                #[cfg(windows)]
                {
                    dir.join(format!("{name}.exe")).exists()
                }
                #[cfg(not(windows))]
                {
                    false
                }
            })
        })
        .unwrap_or(false)
}

#[cfg(feature = "ssh")]
fn find_native_ssh_program() -> Option<String> {
    if command_on_path("ssh") {
        return Some("ssh".to_string());
    }
    #[cfg(windows)]
    {
        let win_ssh = std::path::PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe");
        if win_ssh.exists() {
            return Some(win_ssh.to_string_lossy().to_string());
        }
    }
    None
}
