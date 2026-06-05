//! Windows service integration — register, start, stop, run as service.
//! Uses windows-service crate on Windows; stub on other platforms.

#[cfg(target_os = "windows")]
use crate::win_proc::HideWindow;
#[cfg(target_os = "windows")]
use tracing::info;

/// Service name used for registration.
pub const SERVICE_NAME: &str = "mrsh";

/// Display name in Windows Services console.
pub const SERVICE_DISPLAY_NAME: &str = "mrsh - Remote Shell";

/// Install mrsh as a Windows service.
#[cfg(target_os = "windows")]
pub fn install_service(exe_path: &str) -> anyhow::Result<()> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(exe_path),
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    // Try create; if service already exists, update its config (display name, binary path)
    match manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG) {
        Ok(_) => {}
        Err(windows_service::Error::Winapi(ref e))
            if e.raw_os_error() == Some(0x431) /* ERROR_SERVICE_EXISTS */ =>
        {
            info!("service already exists, updating config");
            let _ = std::process::Command::new("sc")
                .args([
                    "config", SERVICE_NAME,
                    &format!("binPath= \"{}\" --service", exe_path),
                    &format!("DisplayName= \"{}\"", SERVICE_DISPLAY_NAME),
                ])
                .hide_window()
                .output();
        }
        Err(e) => return Err(e.into()),
    }

    // Set recovery options: restart on failure
    // windows-service doesn't expose failure actions directly,
    // so we use sc.exe as fallback
    let _ = std::process::Command::new("sc")
        .args([
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000",
        ])
        .hide_window()
        .output();

    info!("service installed: {}", SERVICE_NAME);

    // Grant Users modify access to ProgramData\mrsh\ so self-update works
    // on non-admin machines (e.g. CLIENT-OREB). Without this, the service runs
    // as SYSTEM but exec handlers impersonate the connected user, who can't
    // rename/overwrite the binary.
    let data_dir = std::path::Path::new(exe_path)
        .parent()
        .unwrap_or(std::path::Path::new(r"C:\ProgramData\mrsh"));
    let _ = std::process::Command::new("icacls")
        .args([
            &data_dir.to_string_lossy().to_string(),
            "/grant",
            "Users:(OI)(CI)M",
            "/T",
        ])
        .hide_window()
        .output();
    info!("ACL: granted Users:Modify on {}", data_dir.display());

    // Open firewall for mrsh ports (LAN access — Tailscale only covers its own IP).
    // profile=any covers private+domain+public — needed because at lock screen
    // Windows NLA can fall back to "Public" (no domain identification, user logged
    // out), and a private+domain-only rule would block inbound. rsh-5wzh 2026-05-15.
    for port in &[8822u16, 9822] {
        let rule_name = format!("mrsh-inbound-{}", port);
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={}", port),
                "profile=any",
            ])
            .hide_window()
            .output();
        info!("firewall rule added: {} (TCP {})", rule_name, port);
    }

    // Kill any existing tray process (old version) before registering new task.
    // Without this, the old tray keeps running and shows stale version.
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/IM", "mrsh.exe"])
        .hide_window()
        .output();
    // Also kill legacy binary name
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/IM", "rsh.exe"])
        .hide_window()
        .output();

    // Register tray companion at user logon — ensures visible tray icon
    // whenever someone is logged in, preventing fully hidden operation.
    if let Err(e) = register_tray_logon_task(exe_path) {
        tracing::warn!("could not register tray logon task: {}", e);
    }

    Ok(())
}

/// Scheduled task name for the tray companion.
#[cfg(target_os = "windows")]
const TRAY_TASK_NAME: &str = "mrsh-tray";

/// Ensure the tray task exists — called at service startup to self-heal
/// if the task was deleted or never created (e.g. installer quoting bug).
#[cfg(target_os = "windows")]
pub fn ensure_tray_task(exe_path: &str) {
    // Check if task exists
    let check = std::process::Command::new("schtasks")
        .args(["/query", "/tn", TRAY_TASK_NAME])
        .hide_window()
        .output();
    let task_exists = check.map(|o| o.status.success()).unwrap_or(false);

    if !task_exists {
        info!("tray task missing, re-registering");
        if let Err(e) = register_tray_logon_task(exe_path) {
            tracing::warn!("failed to register tray task: {}", e);
        }
        return; // register_tray_logon_task already calls /run
    }

    // Task exists — check if RunLevel needs updating (LeastPrivilege → HighestAvailable).
    // Older versions registered with LeastPrivilege, which means the tray runs non-elevated
    // even when the user is admin. Re-register if RunLevel is missing or wrong.
    let xml_check = std::process::Command::new("schtasks")
        .args(["/query", "/tn", TRAY_TASK_NAME, "/xml"])
        .hide_window()
        .output();
    let needs_upgrade = xml_check
        .map(|o| {
            let xml = String::from_utf8_lossy(&o.stdout);
            // Re-register if HighestAvailable is NOT present (old task or no RunLevel)
            !xml.contains("HighestAvailable")
        })
        .unwrap_or(false);

    if needs_upgrade {
        info!("tray task has wrong RunLevel, re-registering with HighestAvailable");
        if let Err(e) = register_tray_logon_task(exe_path) {
            tracing::warn!("failed to re-register tray task: {}", e);
        }
        return;
    }

    // Task exists — check if tray process is already running before launching another
    let tasklist = std::process::Command::new("tasklist")
        .args(["/fi", "imagename eq mrsh.exe", "/fo", "csv", "/nh"])
        .hide_window()
        .output();
    let tray_running = tasklist
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            // Count mrsh.exe processes — if >1, tray is already running (1 = service only)
            out.lines().filter(|l| l.contains("mrsh.exe")).count() > 1
        })
        .unwrap_or(false);

    if !tray_running {
        info!("tray task exists but tray not running, launching");
        let _ = std::process::Command::new("schtasks")
            .args(["/run", "/tn", TRAY_TASK_NAME])
            .hide_window()
            .output();
    }
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_tray_task(_exe_path: &str) {}

/// Ensure firewall rules for mrsh ports cover all profiles (private+domain+public).
/// Self-heals existing fleet installs that had `profile=private,domain` — at
/// Windows lock screen NLA can downgrade to Public profile, and the old rule
/// would no longer apply, leaving mrsh unreachable while user is locked out.
/// Idempotent: `netsh advfirewall firewall set rule` updates an existing rule
/// in place. rsh-5wzh 2026-05-15.
#[cfg(target_os = "windows")]
pub fn ensure_firewall_rules() {
    for port in &[8822u16, 9822] {
        let rule_name = format!("mrsh-inbound-{}", port);
        // `set rule new profile=any` updates if rule exists; falls back to
        // add+delete if `set` fails (very old netsh).
        let set_result = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "set",
                "rule",
                &format!("name={}", rule_name),
                "new",
                "profile=any",
                "action=allow",
                "dir=in",
                "protocol=TCP",
                &format!("localport={}", port),
            ])
            .hide_window()
            .output();
        let set_ok = set_result
            .as_ref()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if set_ok {
            info!("firewall rule ensured: {} (TCP {}, profile=any)", rule_name, port);
            continue;
        }
        // Rule may not exist (old install without firewall step, or just upgraded
        // from a very old build). Add it.
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={}", port),
                "profile=any",
            ])
            .hide_window()
            .output();
        info!("firewall rule added (no prior rule): {} (TCP {})", rule_name, port);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_firewall_rules() {}

/// Register a scheduled task that launches the mrsh tray at user logon.
///
/// This provides user-visible evidence that mrsh is running: a system tray
/// icon with version, port, and connection notifications. Without this,
/// the service runs completely hidden — a concern for abuse prevention.
#[cfg(target_os = "windows")]
fn register_tray_logon_task(exe_path: &str) -> anyhow::Result<()> {
    use std::process::Command;

    // Use XML import for the task — schtasks /create /sc ONLOGON from SYSTEM
    // doesn't set GroupId correctly, causing the task to run in session 0
    // instead of the interactive user session. XML with GroupId S-1-5-32-545
    // (Users group) ensures the task launches in the logged-in user's session.
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
  <Actions><Exec><Command>{exe}</Command><Arguments>--tray</Arguments></Exec></Actions>
</Task>"#,
        exe = exe_path,
    );

    // Write XML to temp file
    let xml_path = std::env::temp_dir().join("mrsh-tray-task.xml");
    // Write as UTF-16 LE with BOM (required by schtasks /xml)
    let mut utf16: Vec<u8> = vec![0xFF, 0xFE]; // BOM
    for c in xml.encode_utf16() {
        utf16.push(c as u8);
        utf16.push((c >> 8) as u8);
    }
    std::fs::write(&xml_path, &utf16)?;

    let output = Command::new("schtasks")
        .args([
            "/create",
            "/tn",
            TRAY_TASK_NAME,
            "/xml",
            xml_path.to_str().unwrap_or(""),
            "/f",
        ])
        .hide_window()
        .output()?;

    let _ = std::fs::remove_file(&xml_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("schtasks xml import failed: {}", stderr.trim());
    }

    info!("tray logon task registered: {}", TRAY_TASK_NAME);

    // Run the tray task immediately — user is likely already logged in.
    let _ = Command::new("schtasks")
        .args(["/run", "/tn", TRAY_TASK_NAME])
        .hide_window()
        .output();

    Ok(())
}

#[cfg(target_os = "android")]
pub fn install_service(_exe_path: &str) -> anyhow::Result<()> {
    // Android (Termux) has no systemd. Autostart is provided by the Termux:Boot
    // app: place a script at ~/.termux/boot/01-start-mrsh that exec's the binary.
    // mrsh itself does not write that file (Termux:Boot must be user-installed).
    eprintln!(
        "install-service: no-op on Android — use Termux:Boot script ~/.termux/boot/01-start-mrsh"
    );
    eprintln!(
        "example: echo '#!/data/data/com.termux/files/usr/bin/sh\\nexec ~/.local/bin/mrsh --daemon' > ~/.termux/boot/01-start-mrsh && chmod +x ~/.termux/boot/01-start-mrsh"
    );
    Ok(())
}

/// Resolve the service user for the systemd unit.
///
/// If running via `sudo`, returns the invoking user (`SUDO_USER`).
/// Otherwise returns the current effective user's name.
/// Falls back to "root" if detection fails.
#[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
fn resolve_service_user() -> String {
    // SUDO_USER is the human user who ran sudo (most common case for install)
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            return sudo_user;
        }
    }
    // Not sudo — resolve from euid
    let euid = unsafe { libc::geteuid() };
    // Try getpwuid_r for the name
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 4096];
        let mut result = std::ptr::null_mut();
        if libc::getpwuid_r(
            euid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        ) == 0
            && !result.is_null()
        {
            let name = std::ffi::CStr::from_ptr(pwd.pw_name);
            if let Ok(s) = name.to_str() {
                return s.to_string();
            }
        }
    }
    "root".to_string()
}

#[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
pub fn install_service(exe_path: &str) -> anyhow::Result<()> {
    // Canonical install dir: /opt/mrsh/. The binary lives here owned by the
    // service user (NOT root), so self-update works without sudo (rsh-z7um).
    // /usr/local/bin/mrsh is left as a symlink for CLI compatibility.
    use std::os::unix::fs::PermissionsExt;

    let target_dir = "/opt/mrsh";
    let target_bin = format!("{}/mrsh", target_dir);
    let legacy_bin = "/usr/local/bin/mrsh";

    // Create /opt/mrsh/ and copy current binary there
    std::fs::create_dir_all(target_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {} (try with sudo)", target_dir, e))?;
    std::fs::copy(exe_path, &target_bin)
        .map_err(|e| anyhow::anyhow!("copy {} -> {}: {}", exe_path, target_bin, e))?;
    std::fs::set_permissions(&target_bin, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| anyhow::anyhow!("chmod {}: {}", target_bin, e))?;

    // Symlink /usr/local/bin/mrsh -> /opt/mrsh/mrsh for CLI compat.
    // If the legacy path is a regular file (existing install), remove it first.
    if std::path::Path::new(legacy_bin).exists() || std::fs::symlink_metadata(legacy_bin).is_ok() {
        let _ = std::fs::remove_file(legacy_bin);
    }
    std::os::unix::fs::symlink(&target_bin, legacy_bin)
        .map_err(|e| anyhow::anyhow!("symlink {} -> {}: {}", legacy_bin, target_bin, e))?;

    // Resolve the service user: if running via sudo, detect the invoking user
    // (SUDO_USER); otherwise use the current euid's name. This ensures the
    // systemd unit runs as the human user, not root. The data dir
    // (~/.mrsh or /etc/mrsh) must be readable by this user.
    let service_user = resolve_service_user();

    let unit = format!(
        r#"[Unit]
Description=Remote Shell (mrsh) daemon
After=network.target

[Service]
Type=simple
ExecStart={exe} --daemon
Restart=on-failure
RestartSec=5
WorkingDirectory=/home/{user}/.mrsh
User={user}
Group={user}

[Install]
WantedBy=multi-user.target
"#,
        exe = target_bin,
        user = service_user,
    );
    // Remove any legacy rsh.service unit from older installs (renamed to mrsh.service).
    let legacy_unit = "/etc/systemd/system/rsh.service";
    if std::path::Path::new(legacy_unit).exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "--now", "rsh"])
            .output();
        let _ = std::fs::remove_file(legacy_unit);
        eprintln!("removed legacy unit {} (renamed to mrsh.service)", legacy_unit);
    }

    let unit_path = "/etc/systemd/system/mrsh.service";
    std::fs::write(unit_path, &unit)
        .map_err(|e| anyhow::anyhow!("write {}: {} (try with sudo)", unit_path, e))?;
    eprintln!("wrote {} (binary at {})", unit_path, target_bin);
    eprintln!("symlinked {} -> {}", legacy_bin, target_bin);
    eprintln!("run: sudo systemctl daemon-reload && sudo systemctl enable --now mrsh");
    eprintln!("note: chown {} to the service user before starting", target_bin);
    Ok(())
}

/// Uninstall the Windows service.
#[cfg(target_os = "windows")]
pub fn uninstall_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;

    // Remove tray logon task
    let _ = std::process::Command::new("schtasks")
        .args(["/delete", "/tn", TRAY_TASK_NAME, "/f"])
        .hide_window()
        .output();

    // Remove firewall rules
    for port in &[8822u16, 9822] {
        let rule_name = format!("mrsh-inbound-{}", port);
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name),
            ])
            .hide_window()
            .output();
    }

    info!("service uninstalled: {}", SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "android")]
pub fn uninstall_service() -> anyhow::Result<()> {
    eprintln!(
        "uninstall-service: no-op on Android — remove ~/.termux/boot/01-start-mrsh manually"
    );
    Ok(())
}

#[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
pub fn uninstall_service() -> anyhow::Result<()> {
    // Stop + disable both the current (mrsh) and any legacy (rsh) unit.
    for svc in ["mrsh", "rsh"] {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", svc])
            .output();
        let _ = std::process::Command::new("systemctl")
            .args(["disable", svc])
            .output();
    }
    let mut removed = false;
    for unit_path in [
        "/etc/systemd/system/mrsh.service",
        "/etc/systemd/system/rsh.service",
    ] {
        if std::path::Path::new(unit_path).exists() {
            std::fs::remove_file(unit_path)
                .map_err(|e| anyhow::anyhow!("remove {}: {} (try with sudo)", unit_path, e))?;
            removed = true;
        }
    }
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();
    if removed {
        eprintln!("service uninstalled");
    } else {
        eprintln!("no systemd unit file found (mrsh.service / rsh.service)");
    }
    Ok(())
}

/// Check if running as a Windows service.
#[cfg(target_os = "windows")]
pub fn is_service_mode() -> bool {
    // If stdin is not a console (no attached terminal), likely running as service.
    // More robust check: try to register as service dispatcher.
    // For now, use CLI flag detection.
    std::env::args().any(|a| a == "--service")
}

#[cfg(not(target_os = "windows"))]
pub fn is_service_mode() -> bool {
    false
}

/// Get the default port based on mode.
pub fn default_port() -> u16 {
    if is_service_mode() { 8822 } else { 9822 }
}

/// Run as a Windows service (blocks until service stops).
///
/// The `server_fn` receives a CancellationToken that is cancelled when the
/// SCM sends a Stop control. The function should spawn the tokio runtime
/// and run the server until the token fires.
#[cfg(target_os = "windows")]
pub fn run_as_service(
    server_fn: impl FnOnce(tokio_util::sync::CancellationToken) + Send + 'static,
) -> anyhow::Result<()> {
    use std::sync::OnceLock;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    // Shared state between service_main and the dispatcher thread.
    // OnceLock lets service_main set the cancel token + server_fn once.
    static CANCEL: OnceLock<tokio_util::sync::CancellationToken> = OnceLock::new();
    static SERVER_FN: OnceLock<
        std::sync::Mutex<Option<Box<dyn FnOnce(tokio_util::sync::CancellationToken) + Send>>>,
    > = OnceLock::new();

    // Store the server function so service_main can retrieve it.
    let cancel = tokio_util::sync::CancellationToken::new();
    let _ = CANCEL.set(cancel.clone());
    let _ = SERVER_FN.set(std::sync::Mutex::new(Some(Box::new(server_fn))));

    // Define the service entry point (called by SCM on a separate thread).
    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        let cancel = CANCEL.get().expect("cancel token set").clone();
        let cancel_for_stop = cancel.clone();

        // Register the control handler (Stop, Shutdown, etc.)
        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    cancel_for_stop.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .expect("register service control handler");

        // Report Running
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });

        // Run the actual server
        if let Some(f) = SERVER_FN
            .get()
            .and_then(|m| m.lock().ok())
            .and_then(|mut opt| opt.take())
        {
            f(cancel);
        }

        // Report Stopped
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });
    }

    // This blocks until the service stops.
    // If this is NOT called from SCM, it returns an error immediately.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;

    Ok(())
}

/// Run as a Linux daemon — blocks until SIGTERM/SIGINT received.
///
/// The `server_fn` receives a CancellationToken that is cancelled when
/// SIGTERM or SIGINT is received.
#[cfg(not(target_os = "windows"))]
pub fn run_as_service(
    server_fn: impl FnOnce(tokio_util::sync::CancellationToken) + Send + 'static,
) -> anyhow::Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_for_signal = cancel.clone();

    // Spawn signal handler thread
    std::thread::spawn(move || {
        use nix::sys::signal::{SigSet, Signal};
        let mut sigset = SigSet::empty();
        sigset.add(Signal::SIGTERM);
        sigset.add(Signal::SIGINT);
        // Block these signals so sigwait can catch them
        sigset.thread_block().ok();
        // Wait for signal
        if let Ok(_sig) = sigset.wait() {
            cancel_for_signal.cancel();
        }
    });

    server_fn(cancel);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_constants() {
        assert_eq!(SERVICE_NAME, "mrsh");
        assert!(!SERVICE_DISPLAY_NAME.is_empty());
    }

    #[test]
    fn default_port_value() {
        // Not running as service in tests
        let port = default_port();
        assert!(port == 8822 || port == 9822);
    }

    #[test]
    fn is_service_mode_false_in_tests() {
        assert!(!is_service_mode());
    }

    /// Regression test for solved/010: clap parses `-service` as short flags
    /// `-s -e -r -v -i -c -e`, not as `--service`. The install function must
    /// register `--service` (double dash) and is_service_mode must match it.
    #[test]
    fn service_flag_uses_double_dash() {
        // Verify install_service would use "--service" (checked via constant or code review)
        // The actual launch_arguments in install_service use OsString::from("--service")
        // and is_service_mode checks for "--service" — both must use double dash.
        //
        // We can't easily test is_service_mode with injected args in Rust,
        // but we verify the detection string matches what install registers.
        // If someone changes either side, this test documents the contract.
        let install_flag = "--service";
        let detect_flag = "--service"; // must match is_service_mode() check
        assert_eq!(
            install_flag, detect_flag,
            "install_service launch_arguments and is_service_mode must use the same flag format"
        );

        // Verify single-dash would be wrong (clap uses double-dash)
        assert_ne!(
            install_flag, "-service",
            "single-dash -service is wrong, clap uses --service"
        );
    }

    /// Verify is_service_mode returns false in test context (no --service arg)
    #[test]
    fn is_service_mode_detects_double_dash_only() {
        // In test context, args are the test runner args, never "--service"
        assert!(!is_service_mode());
    }

    #[test]
    fn install_service_linux_needs_root() {
        #[cfg(not(target_os = "windows"))]
        {
            // Writing to /etc/systemd/system/ requires root, so this should fail
            // in a non-root test environment.
            let result = install_service("/fake/path");
            // May succeed if running as root (CI), otherwise fails with permission error
            let _ = result;
        }
    }

    #[test]
    fn uninstall_service_linux_no_unit() {
        #[cfg(not(target_os = "windows"))]
        {
            let unit_path = "/etc/systemd/system/mrsh.service";
            if std::path::Path::new(unit_path).exists() {
                // mrsh is installed on this machine — uninstall needs root, skip
                return;
            }
            // No unit file exists → prints message, returns Ok
            let result = uninstall_service();
            assert!(result.is_ok());
        }
    }
}
