//! Self-update mechanism — replace running binary via scheduled task.
//! Windows-only in production; cross-platform validation logic.

use anyhow::{Context, Result};
use mrsh_core::protocol::Response;
use tracing::info;

/// Minimum acceptable binary size (1 MB).
const MIN_BINARY_SIZE: u64 = 1_000_000;

/// Validate that the new binary exists and meets size requirements.
pub fn validate_update_path(path: &str) -> Result<()> {
    let metadata = std::fs::metadata(path).context(format!("new binary not found: {}", path))?;

    if metadata.len() < MIN_BINARY_SIZE {
        anyhow::bail!(
            "new binary too small: {} bytes (minimum {} bytes)",
            metadata.len(),
            MIN_BINARY_SIZE
        );
    }

    Ok(())
}

/// Handle self-update request. Validates the new binary path, then
/// schedules replacement (Windows service mode only in production).
pub fn handle_self_update(path: &str) -> Response {
    // Validate
    if let Err(e) = validate_update_path(path) {
        return Response {
            success: false,
            output: None,
            error: Some(e.to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    info!("self-update requested: {}", path);

    // On Windows service mode, this would:
    // 1. Write a .bat script to stop service, replace binary, restart
    // 2. Schedule via schtasks /create /tn rsh-self-update /ru SYSTEM
    // 3. Run via schtasks /run /tn rsh-self-update
    // 4. Return success (actual update happens asynchronously)
    //
    // For now, return success with the path validated.
    // Full implementation requires Windows service detection.

    #[cfg(target_os = "windows")]
    {
        match schedule_update_windows(path) {
            Ok(msg) => Response {
                success: true,
                output: Some(msg),
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

    #[cfg(not(target_os = "windows"))]
    {
        match replace_binary_linux(path) {
            Ok(msg) => Response {
                success: true,
                output: Some(msg),
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
}

/// Replace the binary on Linux: backup current → copy new → optionally restart systemd.
#[cfg(not(target_os = "windows"))]
fn replace_binary_linux(new_binary: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let exe_path = std::env::current_exe()
        .context("get current exe path")?
        .to_string_lossy()
        .to_string();

    let backup_path = format!("{}.bak", exe_path);

    // Backup current binary
    std::fs::copy(&exe_path, &backup_path)
        .context(format!("backup {} → {}", exe_path, backup_path))?;
    info!("backed up {} → {}", exe_path, backup_path);

    // Copy new binary over current
    std::fs::copy(new_binary, &exe_path)
        .context(format!("copy {} → {}", new_binary, exe_path))?;

    // Ensure executable permission
    let perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&exe_path, perms).context("set executable permission")?;

    // Clean up new binary
    let _ = std::fs::remove_file(new_binary);

    // Try to restart via systemd (non-blocking, best effort)
    // Try mrsh first, then legacy rsh service name
    let restarted = ["mrsh", "rsh"].iter().any(|svc| {
        std::process::Command::new("systemctl")
            .args(["restart", svc])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    });

    if restarted {
        Ok(format!("updated {} and restarted via systemd", exe_path))
    } else {
        Ok(format!(
            "updated {} (manual restart required — not running as systemd service)",
            exe_path
        ))
    }
}

/// Schedule the actual binary replacement on Windows.
/// Strategy: try schtask first (clean, isolated process). If schtask fails
/// (non-admin, Group Policy), fall back to direct spawn from SYSTEM process.
#[cfg(target_os = "windows")]
fn schedule_update_windows(new_binary: &str) -> Result<String> {
    use std::process::Command;

    let exe_path = std::env::current_exe()
        .context("get current exe path")?
        .to_string_lossy()
        .to_string();

    let backup_path = format!("{}.bak", exe_path);
    let bat_path = format!("{}\\mrsh-update.bat", std::env::temp_dir().to_string_lossy());

    // Detect actual service name (mrsh or legacy rsh)
    let svc_name = {
        let check = Command::new("sc").args(["query", "mrsh"]).output();
        if check.map(|o| o.status.success()).unwrap_or(false) {
            "mrsh"
        } else {
            "rsh"
        }
    };

    let exe_name = std::path::Path::new(&exe_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Write update bat script
    let bat_content = format!(
        r#"@echo off
net stop {svc}
timeout /t 5 /nobreak >nul
taskkill /F /IM {exe_name} 2>nul
timeout /t 3 /nobreak >nul
copy /y "{exe}" "{backup}"
copy /y "{new}" "{exe}"
IF ERRORLEVEL 1 (
    timeout /t 5 /nobreak >nul
    copy /y "{new}" "{exe}"
    IF ERRORLEVEL 1 (
        copy /y "{backup}" "{exe}"
        echo ROLLBACK: restored from backup >> "{exe}.update.log"
        net start {svc}
        exit /b 1
    )
)
net start {svc}
del "{new}"
del "{bat}" 2>nul
"#,
        svc = svc_name,
        exe_name = exe_name,
        exe = exe_path,
        backup = backup_path,
        new = new_binary,
        bat = bat_path,
    );

    std::fs::write(&bat_path, &bat_content).context("write update bat")?;

    // Try schtask first (cleanest approach)
    if try_schtask_update(&bat_path) {
        return Ok("update scheduled via schtask, service will restart in ~10 seconds".to_string());
    }

    // Schtask failed (non-admin, Group Policy). Fall back to direct spawn.
    // We're running as SYSTEM — spawn detached cmd.exe to run the bat.
    info!("schtask failed, using direct spawn for self-update");
    use std::os::windows::process::CommandExt;
    let child = Command::new("cmd")
        .args(["/c", "start", "/b", "cmd", "/c", &bat_path])
        .creation_flags(0x08000000 | 0x00000008) // CREATE_NO_WINDOW | DETACHED_PROCESS
        .spawn();

    match child {
        Ok(_) => Ok("update spawned directly, service will restart in ~10 seconds".to_string()),
        Err(e) => anyhow::bail!("direct spawn failed: {}", e),
    }
}

/// Try to create and run a schtask for the update. Returns true on success.
#[cfg(target_os = "windows")]
fn try_schtask_update(bat_path: &str) -> bool {
    use std::process::Command;

    let _ = Command::new("schtasks")
        .args(["/delete", "/tn", "mrsh-self-update", "/f"])
        .output();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let future = now + 120;
    let secs_of_day = future % 86400;
    let st = format!("{:02}:{:02}", secs_of_day / 3600, (secs_of_day % 3600) / 60);

    let create = Command::new("schtasks")
        .args([
            "/create", "/tn", "mrsh-self-update",
            "/tr", &format!("cmd /c \"{}\"", bat_path),
            "/sc", "once", "/st", &st, "/f", "/ru", "SYSTEM",
        ])
        .output();

    if !create.map(|o| o.status.success()).unwrap_or(false) {
        return false;
    }

    let run = Command::new("schtasks")
        .args(["/run", "/tn", "mrsh-self-update"])
        .output();

    run.map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validate_nonexistent_path() {
        let result = validate_update_path("/nonexistent/binary");
        assert!(result.is_err());
    }

    #[test]
    fn validate_too_small() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"tiny").unwrap();
        let result = validate_update_path(f.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too small"));
    }

    #[test]
    fn handle_self_update_nonexistent() {
        let resp = handle_self_update("/nonexistent/rsh-new.exe");
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("not found"));
    }

    #[test]
    fn handle_self_update_too_small() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        let resp = handle_self_update(f.path().to_str().unwrap());
        assert!(!resp.success);
    }

    #[test]
    fn validate_exactly_at_min_size() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; MIN_BINARY_SIZE as usize]).unwrap();
        let result = validate_update_path(f.path().to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn validate_just_under_min_size() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; (MIN_BINARY_SIZE - 1) as usize]).unwrap();
        let result = validate_update_path(f.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too small"));
    }

    #[test]
    fn validate_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let result = validate_update_path(f.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn validate_directory_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_update_path(dir.path().to_str().unwrap());
        // Directory exists but metadata.len() == 0 or is not a regular file
        // Either way it should fail (too small)
        assert!(result.is_err());
    }
}
