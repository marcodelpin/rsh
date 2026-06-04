//! Cross-platform helper: hide console window on Windows when spawning child
//! processes. No-op on Linux/macOS.
//!
//! Why: when the mrsh server runs as a Windows tray (interactive user session),
//! every `Command::new(...)` of a console-subsystem child (powershell, schtasks,
//! sc, taskkill, netsh, tasklist, etc.) flashes a console window visible to the
//! logged-in user. Setting CREATE_NO_WINDOW (0x08000000) at process creation
//! prevents Windows from allocating that console window.
//!
//! The tray flashes were the root cause of bd rsh-np7e (user report 2026-05-08:
//! "in remoti apre shell visibile, dovrebbe essere nascosta").
//!
//! Use:
//!   use crate::win_proc::HideWindow;
//!   let out = std::process::Command::new("schtasks").args(["/Run","/TN","x"]).hide_window().output()?;
//!   let mut c = tokio::process::Command::new("powershell"); c.hide_window(); c.spawn()?;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Apply CREATE_NO_WINDOW to any Command type on Windows; no-op elsewhere.
///
/// Implemented for both `std::process::Command` and `tokio::process::Command`
/// so callers don't need to know which variant they're holding.
pub trait HideWindow {
    fn hide_window(&mut self) -> &mut Self;
}

#[cfg(target_os = "windows")]
impl HideWindow for std::process::Command {
    fn hide_window(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(target_os = "windows")]
impl HideWindow for tokio::process::Command {
    fn hide_window(&mut self) -> &mut Self {
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(target_os = "windows"))]
impl HideWindow for std::process::Command {
    fn hide_window(&mut self) -> &mut Self {
        self
    }
}

#[cfg(not(target_os = "windows"))]
impl HideWindow for tokio::process::Command {
    fn hide_window(&mut self) -> &mut Self {
        self
    }
}
