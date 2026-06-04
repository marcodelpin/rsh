//! System tray icon — shows status and provides context menu.
//! Uses raw Win32 API (Shell_NotifyIconW) on Windows; stub on other platforms.

/// Tray menu actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    ShowStatus,
    OpenLog,
    Quit,
}

// Menu command IDs for WM_COMMAND
#[cfg(target_os = "windows")]
const IDM_STATUS: u32 = 1001;
#[cfg(target_os = "windows")]
const IDM_OPEN_LOG: u32 = 1002;
#[cfg(target_os = "windows")]
const IDM_COPY_ID: u32 = 1004;
#[cfg(target_os = "windows")]
const IDM_QUIT: u32 = 1003;

// Custom message for tray icon callbacks
#[cfg(target_os = "windows")]
const WM_TRAYICON: u32 = 0x0400 + 1; // WM_USER + 1

#[cfg(target_os = "windows")]
mod win32_tray {
    use super::*;
    use std::sync::Mutex;
    use windows::core::{PCWSTR, w};
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Shell::{
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::*;
    #[allow(unused_imports)]
    use windows::Win32::Graphics::Gdi::*;

    /// Idle threshold (seconds). Toast only when first connection arrives after
    /// this many seconds of no active connections.
    const IDLE_THRESHOLD_SECS: u64 = 300; // 5 minutes

    /// Global state accessible from the window procedure.
    struct TrayState {
        cancel: tokio_util::sync::CancellationToken,
        port: u16,
        device_id: String,
        notify_rx: Option<tokio::sync::broadcast::Receiver<crate::notify::ConnectionEvent>>,
        /// Number of currently active connections.
        active_connections: u32,
        /// When the last connection closed (for idle detection).
        last_disconnect: std::time::Instant,
        /// HWND for tray icon updates (stored as isize for Send safety).
        hwnd_raw: isize,
        /// Normal icon handle (stored as isize for Send safety).
        icon_normal_raw: isize,
        /// Active (red) icon handle (stored as isize for Send safety).
        icon_active_raw: isize,
    }

    static TRAY_STATE: Mutex<Option<TrayState>> = Mutex::new(None);

    /// Encode a Rust string as a null-terminated wide string into a fixed buffer.
    fn str_to_wide_buf<const N: usize>(s: &str) -> [u16; N] {
        let mut buf = [0u16; N];
        for (i, c) in s.encode_utf16().take(N - 1).enumerate() {
            buf[i] = c;
        }
        buf
    }

    /// Window procedure for our hidden tray window.
    unsafe extern "system" fn tray_wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        unsafe {
            match msg {
                WM_TRAYICON => {
                    let event = lparam.0 as u32;
                    if event == WM_RBUTTONUP || event == WM_LBUTTONUP {
                        let mut pt = windows::Win32::Foundation::POINT::default();
                        let _ = GetCursorPos(&mut pt);

                        let hmenu = CreatePopupMenu().unwrap_or_default();

                        let version = env!("CARGO_PKG_VERSION");
                        let (port, device_id) = TRAY_STATE
                            .lock()
                            .ok()
                            .and_then(|s| s.as_ref().map(|ts| (ts.port, ts.device_id.clone())))
                            .unwrap_or((9822, String::new()));
                        let status_text: Vec<u16> =
                            format!("mrsh v{version} (port {port})")
                                .encode_utf16()
                                .chain(std::iter::once(0))
                                .collect();
                        let _ = AppendMenuW(
                            hmenu,
                            MF_STRING | MF_GRAYED,
                            IDM_STATUS as usize,
                            PCWSTR(status_text.as_ptr()),
                        );
                        // Show DeviceID (clickable → copies to clipboard)
                        if !device_id.is_empty() {
                            let id_text: Vec<u16> =
                                format!("ID: {} (click to copy)", device_id)
                                    .encode_utf16()
                                    .chain(std::iter::once(0))
                                    .collect();
                            let _ = AppendMenuW(
                                hmenu,
                                MF_STRING,
                                IDM_COPY_ID as usize,
                                PCWSTR(id_text.as_ptr()),
                            );
                        }
                        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
                        let _ = AppendMenuW(
                            hmenu,
                            MF_STRING,
                            IDM_OPEN_LOG as usize,
                            w!("Open Log"),
                        );
                        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
                        let _ = AppendMenuW(
                            hmenu,
                            MF_STRING,
                            IDM_QUIT as usize,
                            w!("Quit"),
                        );

                        let _ = SetForegroundWindow(hwnd);
                        let _ = TrackPopupMenu(
                            hmenu,
                            TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                            pt.x,
                            pt.y,
                            Some(0),
                            hwnd,
                            None,
                        );
                        let _ = DestroyMenu(hmenu);
                    }
                    LRESULT(0)
                }
                WM_COMMAND => {
                    let cmd = (wparam.0 & 0xFFFF) as u32;
                    match cmd {
                        IDM_COPY_ID => {
                            if let Ok(state) = TRAY_STATE.lock()
                                && let Some(ts) = state.as_ref()
                                    && !ts.device_id.is_empty() {
                                        copy_to_clipboard(&ts.device_id);
                                    }
                        }
                        IDM_OPEN_LOG => super::open_log_file(),
                        IDM_QUIT => {
                            tracing::info!("tray quit requested");
                            if let Ok(state) = TRAY_STATE.lock()
                                && let Some(ts) = state.as_ref() {
                                    ts.cancel.cancel();
                                }
                            PostQuitMessage(0);
                        }
                        _ => {}
                    }
                    LRESULT(0)
                }
                WM_TIMER => {
                    // Process connection events: track active count, toast on 0→1 after idle,
                    // swap icon color based on active connections.
                    let (toast_msg, icon_change) = {
                        if let Ok(mut state) = TRAY_STATE.lock() {
                            if let Some(ts) = state.as_mut() {
                                let was_active = ts.active_connections > 0;
                                let mut first_connect_after_idle = false;

                                if let Some(ref mut rx) = ts.notify_rx {
                                    while let Ok(ev) = rx.try_recv() {
                                        match ev.kind {
                                            crate::notify::EventKind::Connected => {
                                                if ts.active_connections == 0 {
                                                    // 0→1 transition: check idle threshold
                                                    let idle_secs = ts.last_disconnect.elapsed().as_secs();
                                                    if idle_secs >= IDLE_THRESHOLD_SECS {
                                                        first_connect_after_idle = true;
                                                    }
                                                }
                                                ts.active_connections = ts.active_connections.saturating_add(1);
                                                tracing::info!(
                                                    "connection from {} ({}) [active: {}]",
                                                    ev.peer.ip(),
                                                    ev.key_comment.as_deref().unwrap_or("unknown"),
                                                    ts.active_connections,
                                                );
                                            }
                                            crate::notify::EventKind::Disconnected => {
                                                ts.active_connections = ts.active_connections.saturating_sub(1);
                                                if ts.active_connections == 0 {
                                                    ts.last_disconnect = std::time::Instant::now();
                                                }
                                                tracing::debug!(
                                                    "disconnect {} [active: {}]",
                                                    ev.peer.ip(), ts.active_connections
                                                );
                                            }
                                        }
                                    }
                                }

                                let is_active = ts.active_connections > 0;
                                let icon_changed = was_active != is_active;
                                let icon = if icon_changed && ts.hwnd_raw != 0 {
                                    Some(if is_active {
                                        (ts.hwnd_raw, ts.icon_active_raw)
                                    } else {
                                        (ts.hwnd_raw, ts.icon_normal_raw)
                                    })
                                } else {
                                    None
                                };

                                let toast = if first_connect_after_idle {
                                    Some("Remote connection established".to_string())
                                } else {
                                    None
                                };

                                (toast, icon)
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        }
                    };

                    if let Some(msg) = toast_msg {
                        super::show_balloon(&msg);
                    }
                    if let Some((h, icon)) = icon_change {
                        update_tray_icon(HWND(h as *mut _), HICON(icon as *mut _));
                    }

                    let cancelled = TRAY_STATE
                        .lock()
                        .ok()
                        .and_then(|s| {
                            s.as_ref().map(|ts| ts.cancel.is_cancelled())
                        })
                        .unwrap_or(false);
                    if cancelled {
                        PostQuitMessage(0);
                    }
                    LRESULT(0)
                }
                WM_DESTROY => {
                    PostQuitMessage(0);
                    LRESULT(0)
                }
                _ => DefWindowProcW(hwnd, msg, wparam, lparam),
            }
        }
    }

    /// Create a simple colored 16×16 HICON (for tray status indication).
    fn create_color_icon(r: u8, g: u8, b: u8) -> HICON {
        let size: i32 = 16;
        let num_pixels = (size * size) as usize;
        let and_mask = vec![0u8; num_pixels / 8];
        let mut xor_mask = vec![0u8; num_pixels * 4];
        for pixel in xor_mask.chunks_exact_mut(4) {
            pixel[0] = b; // B
            pixel[1] = g; // G
            pixel[2] = r; // R
            pixel[3] = 0;
        }
        unsafe {
            let hinstance = GetModuleHandleW(None).unwrap_or_default();
            CreateIcon(
                Some(hinstance.into()),
                size,
                size,
                1,
                32,
                and_mask.as_ptr(),
                xor_mask.as_ptr(),
            )
            .unwrap_or_default()
        }
    }

    /// Update the tray icon (swap between normal and active).
    fn update_tray_icon(hwnd: HWND, icon: HICON) {
        unsafe {
            let mut nid = NOTIFYICONDATAW::default();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON;
            nid.hIcon = icon;
            let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    }

    /// Copy text to the Windows clipboard.
    fn copy_to_clipboard(text: &str) {
        use windows::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
        };
        use windows::Win32::System::Memory::{
            GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        unsafe {
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes = wide.len() * 2;

            if OpenClipboard(None).is_ok() {
                let _ = EmptyClipboard();
                if let Ok(hmem) = GlobalAlloc(GMEM_MOVEABLE, bytes) {
                    let ptr = GlobalLock(hmem);
                    if !ptr.is_null() {
                        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, ptr as *mut u8, bytes);
                        let _ = GlobalUnlock(hmem);
                        let _ = SetClipboardData(CF_UNICODETEXT.0 as u32, Some(windows::Win32::Foundation::HANDLE(hmem.0 as _)));
                    }
                }
                let _ = CloseClipboard();
            }
        }
    }

    /// Run the tray — creates hidden window, registers tray icon, message loop.
    pub fn run(
        cancel: tokio_util::sync::CancellationToken,
        port: u16,
        device_id: String,
    ) -> anyhow::Result<()> {
        tracing::info!("tray: starting Win32 tray on port {} (id: {})", port, device_id);

        // Set up notification channel for connection events
        let notify_rx = crate::notify::subscribe();

        // Store state for wndproc
        // Create colored icon for active connections indication
        let icon_active = create_color_icon(0xCC, 0x33, 0x33); // Red = active connections

        *TRAY_STATE.lock().unwrap() = Some(TrayState {
            cancel: cancel.clone(),
            port,
            device_id: device_id.clone(),
            notify_rx,
            active_connections: 0,
            last_disconnect: std::time::Instant::now() - std::time::Duration::from_secs(IDLE_THRESHOLD_SECS + 1),
            hwnd_raw: 0,
            icon_normal_raw: 0, // set after icon is loaded
            icon_active_raw: icon_active.0 as isize,
        });

        unsafe {
            let hinstance = GetModuleHandleW(None)?;

            // Register window class
            let class_name = w!("rsh_tray_class");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(tray_wndproc),
                hInstance: hinstance.into(),
                lpszClassName: class_name,
                ..Default::default()
            };
            RegisterClassW(&wc);

            // Create hidden message window
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name,
                w!("rsh tray"),
                WINDOW_STYLE::default(),
                0, 0, 0, 0,
                Some(HWND_MESSAGE),
                None,
                Some(hinstance.into()),
                None,
            )?;

            // Create tray icon — load embedded icon from exe resource (winres),
            // fall back to generic application icon if not embedded.
            let hicon = {
                use windows::Win32::UI::WindowsAndMessaging::LoadImageW;
                use windows::Win32::Foundation::HINSTANCE;
                // winres embeds icon as MAKEINTRESOURCE(1) — integer ID, not string.
                // MAKEINTRESOURCE(1) = pointer with value 1 (low word = resource ID).
                let res_id = windows::core::PCWSTR(1 as *const u16);
                let exe_icon = LoadImageW(
                    Some(HINSTANCE(hinstance.0)),
                    res_id,
                    windows::Win32::UI::WindowsAndMessaging::IMAGE_ICON,
                    0, 0,
                    windows::Win32::UI::WindowsAndMessaging::LR_DEFAULTSIZE,
                );
                match exe_icon {
                    Ok(h) if !h.is_invalid() => HICON(h.0),
                    _ => LoadIconW(None, IDI_APPLICATION)?,
                }
            };
            let tip_text = if device_id.is_empty() {
                format!("mrsh v{} (port {})", env!("CARGO_PKG_VERSION"), port)
            } else {
                format!("mrsh v{} (port {}) ID:{}", env!("CARGO_PKG_VERSION"), port, device_id)
            };
            let tooltip = str_to_wide_buf::<128>(&tip_text);

            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = hicon;
            nid.szTip = tooltip;
            let _ = Shell_NotifyIconW(NIM_ADD, &nid);

            // Store hwnd and icon for runtime icon swapping
            if let Ok(mut state) = TRAY_STATE.lock() {
                if let Some(ts) = state.as_mut() {
                    ts.hwnd_raw = hwnd.0 as isize;
                    ts.icon_normal_raw = hicon.0 as isize;
                }
            }

            // Timer for checking notifications and cancel token (every 1 second)
            SetTimer(Some(hwnd), 1, 1000, None);

            tracing::info!("tray: message loop starting");

            // Message loop
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Cleanup
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
            tracing::info!("tray: exiting");
        }

        Ok(())
    }
}

/// Run the system tray icon (blocks the current thread).
#[cfg(target_os = "windows")]
pub fn run_tray(cancel: tokio_util::sync::CancellationToken, port: u16, device_id: String) -> anyhow::Result<()> {
    win32_tray::run(cancel, port, device_id)
}

/// Show a Windows balloon/toast notification for a connection event.
#[cfg(target_os = "windows")]
fn show_balloon(message: &str) {
    let script = format!(
        r#"
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $n = New-Object System.Windows.Forms.NotifyIcon
        $n.Icon = [System.Drawing.SystemIcons]::Information
        $n.BalloonTipTitle = "rsh"
        $n.BalloonTipText = "{}"
        $n.Visible = $true
        $n.ShowBalloonTip(5000)
        Start-Sleep -Milliseconds 5500
        $n.Dispose()
        "#,
        message.replace('"', "'")
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .spawn();
}

/// Open the mrsh log file (rsh.log) in the default text editor.
#[cfg(target_os = "windows")]
fn open_log_file() {
    let data_dir = find_data_dir();
    let log_path = data_dir.join("rsh.log");
    let target = if log_path.exists() {
        log_path
    } else {
        data_dir
    };
    let _ = std::process::Command::new("explorer")
        .arg(target)
        .spawn();
}

/// Locate the mrsh data directory.
#[cfg(target_os = "windows")]
fn find_data_dir() -> std::path::PathBuf {
    let service_dir = std::path::PathBuf::from(r"C:\ProgramData\mrsh");
    if service_dir.exists() {
        return service_dir;
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return std::path::PathBuf::from(home).join(".rsh");
    }
    service_dir
}

#[cfg(not(target_os = "windows"))]
pub fn run_tray(_cancel: tokio_util::sync::CancellationToken, _port: u16, _device_id: String) -> anyhow::Result<()> {
    anyhow::bail!("system tray not available on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_action_eq() {
        assert_eq!(TrayAction::Quit, TrayAction::Quit);
        assert_ne!(TrayAction::Quit, TrayAction::ShowStatus);
    }

    #[test]
    fn tray_stub_non_windows() {
        #[cfg(not(target_os = "windows"))]
        {
            let cancel = tokio_util::sync::CancellationToken::new();
            let result = run_tray(cancel, 8822, String::new());
            assert!(result.is_err());
        }
    }

    #[test]
    fn tray_stub_non_windows_error_message() {
        #[cfg(not(target_os = "windows"))]
        {
            let cancel = tokio_util::sync::CancellationToken::new();
            let result = run_tray(cancel, 9822, String::new());
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("not available"),
                "error should indicate platform unsupported: {err}"
            );
        }
    }

    #[test]
    fn tray_action_debug_format() {
        let action = TrayAction::ShowStatus;
        let debug = format!("{:?}", action);
        assert!(debug.contains("ShowStatus"));
    }

    #[test]
    fn tray_action_clone() {
        let original = TrayAction::OpenLog;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    /// Verify that run_tray with cancelled token on non-Windows returns error
    /// (not hang or panic). Tests the graceful failure path.
    #[test]
    fn tray_cancelled_token_returns_error() {
        #[cfg(not(target_os = "windows"))]
        {
            let cancel = tokio_util::sync::CancellationToken::new();
            cancel.cancel(); // Pre-cancel
            let result = run_tray(cancel, 8822, String::new());
            assert!(result.is_err());
        }
    }

    /// Test with various port values — stub should fail regardless.
    #[test]
    fn tray_stub_various_ports() {
        #[cfg(not(target_os = "windows"))]
        {
            for port in [0, 1, 8822, 9822, 65535] {
                let cancel = tokio_util::sync::CancellationToken::new();
                let result = run_tray(cancel, port, String::new());
                assert!(result.is_err(), "port {} should fail on non-Windows", port);
            }
        }
    }

    #[test]
    fn tray_action_all_variants() {
        let actions = [TrayAction::ShowStatus, TrayAction::OpenLog, TrayAction::Quit];
        // All variants are distinct
        assert_ne!(actions[0], actions[1]);
        assert_ne!(actions[1], actions[2]);
        assert_ne!(actions[0], actions[2]);
    }
}
