//! mrsh server — TLS listener, auth dispatch, command execution.
//! Core modules work cross-platform; Windows-specific modules use cfg(windows).

pub mod dispatch;
pub mod exec;
pub mod exec_user;
pub mod fileops;
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
pub mod session;
pub mod shell;
pub mod sync;
pub mod tray;
pub mod tunnel;

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
