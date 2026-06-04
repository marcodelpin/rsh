//! mrsh server — TLS listener, auth dispatch, command execution.
//! Core modules work cross-platform; Windows-specific modules use cfg(windows).

pub mod dispatch;
pub mod exec;
pub mod exec_user;
pub mod fileops;
pub mod fs_listener;
pub mod gui;
pub mod handler;
pub mod listener;
pub mod log_query;
pub mod mux;
pub mod notify;
pub mod plugin;
pub mod ratelimit;
pub mod safety;
pub mod scp;
pub mod screenshot;
pub mod selfupdate;
pub mod service;
pub mod tray_watchdog;
pub mod update_status;
pub mod watchdog;
pub mod session;
pub mod shell;
pub mod sync;
pub mod tray;
pub mod tunnel;
pub mod win_proc;
pub mod zombie;

#[cfg(feature = "quic")]
pub mod quic;

pub mod ssh;

/// Check if the current process is running in Windows session 0 (SYSTEM service).
/// Session 0 has no interactive desktop — screenshot, window enumeration, and
/// clipboard operations will fail or return empty results.
#[cfg(target_os = "windows")]
pub fn is_session_zero() -> bool {
    unsafe {
        let pid = windows::Win32::System::Threading::GetCurrentProcessId();
        let mut sid = 0u32;
        let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut sid);
        sid == 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_session_zero() -> bool {
    false
}

/// Build a user-friendly error message for commands that need an interactive desktop session.
pub fn session_zero_hint(feature: &str) -> String {
    format!(
        "{feature} failed: this is the SYSTEM service (session 0, port 8822) which has no desktop.\n\
         \n\
         Connect to the TRAY instance instead (port 9822, user session):\n\
         \n\
         \x20 mrsh -h <host> -p 9822 {feature}\n\
         \n\
         If the tray is not running:\n\
         \n\
         \x20 mrsh -h <host> exec 'schtasks /run /tn mrsh-tray'\n\
         \x20 # wait 3-5 seconds, then use -p 9822"
    )
}

/// True when `path` resolves under the Windows SYSTEM account profile
/// (`C:\Windows\System32\config\systemprofile\...`).
///
/// Used to refuse writes on the 8822 SYSTEM service when the caller meant a
/// user profile path — the SYSTEM-side expansion of `~` / `%USERPROFILE%`
/// silently aliases to `systemprofile`, which is almost never the intent.
/// rsh-odtu / rsh-t06i 2026-05-19.
pub fn path_under_systemprofile(path: &str) -> bool {
    // Case-insensitive substring match; accept both backslash and forward-slash
    // path separators. Normalize once, then test both literal sentinels.
    let lower = path.to_lowercase();
    let normalized = lower.replace('\\', "/");
    normalized.contains("/config/systemprofile/")
        || normalized.ends_with("/config/systemprofile")
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn systemprofile_detected_backslash_lowercase() {
        assert!(path_under_systemprofile(
            r"C:\Windows\System32\config\systemprofile\.claude\active.txt"
        ));
    }

    #[test]
    fn systemprofile_detected_forwardslash() {
        assert!(path_under_systemprofile(
            "C:/Windows/System32/config/systemprofile/.claude/active.txt"
        ));
    }

    #[test]
    fn systemprofile_detected_mixed_case() {
        assert!(path_under_systemprofile(
            r"C:\WINDOWS\System32\CONFIG\SystemProfile\foo"
        ));
    }

    #[test]
    fn systemprofile_detected_bare_dir() {
        assert!(path_under_systemprofile(
            r"C:\Windows\System32\config\systemprofile"
        ));
    }

    #[test]
    fn user_profile_not_detected() {
        assert!(!path_under_systemprofile(
            r"C:\Users\Marco\.claude\active.txt"
        ));
        assert!(!path_under_systemprofile("/home/user/.claude/active.txt"));
        assert!(!path_under_systemprofile("/tmp/test.txt"));
    }

    #[test]
    fn similar_name_not_detected() {
        // No false positive on look-alike paths
        assert!(!path_under_systemprofile(r"C:\systemprofile\foo"));
        assert!(!path_under_systemprofile(r"C:\config\notsystemprofile\foo"));
    }
}
