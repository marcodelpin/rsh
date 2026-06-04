//! GUI automation — mouse, keyboard, and window management.
//! Windows-only in production; cross-platform types and stub handlers.

use mrsh_core::protocol::Response;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Window information returned by window list/find.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub hwnd: u64,
    pub title: String,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub visible: bool,
}

/// Handle an input/GUI command.
/// Format: command is "mouse|key|window", path holds the sub-action,
/// content holds arguments (JSON or space-separated).
pub fn handle_input(command: &str, action: &str, args: &str) -> Response {
    debug!("input: cmd={} action={} args={}", command, action, args);

    match command {
        "mouse" => handle_mouse(action, args),
        "key" => handle_key(action, args),
        "window" => handle_window(action, args),
        other => Response::error(&format!("unknown input command: {}", other)),
    }
}

// ── Mouse ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_mouse(action: &str, args: &str) -> Response {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    match action {
        "pos" => {
            let mut pt = POINT::default();
            unsafe { windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut pt).ok() };
            ok_response(&format!("{},{}", pt.x, pt.y))
        }
        "move" => {
            let (x, y) = parse_xy(args);
            unsafe { windows::Win32::UI::WindowsAndMessaging::SetCursorPos(x, y).ok() };
            ok_response("ok")
        }
        "click" => {
            let inputs = [
                INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dwFlags: MOUSEEVENTF_LEFTDOWN,
                            ..Default::default()
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dwFlags: MOUSEEVENTF_LEFTUP,
                            ..Default::default()
                        },
                    },
                },
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        // click_at/down_at/up_at: atomic move+button in a SINGLE SendInput batch
        // using MOUSEEVENTF_ABSOLUTE. The coord-less "click" above fires at the
        // current cursor position, racing a separate "move" RPC — on WPF custom
        // WindowChrome the kernel hit-tests an off-by-a-pixel down event as
        // HTCAPTION/HTSYSMENU and opens the system menu instead of activating the
        // toolbar button. Binding move+down+up to the target coords atomically
        // removes the race and the NC-boundary misfire (rsh-oz4i).
        "click_at" => {
            let (x, y) = parse_xy(args);
            let inputs = [
                mouse_abs_input(x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE),
                mouse_abs_input(x, y, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE),
                mouse_abs_input(x, y, MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE),
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        "down_at" => {
            let (x, y) = parse_xy(args);
            let inputs = [
                mouse_abs_input(x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE),
                mouse_abs_input(x, y, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE),
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        "up_at" => {
            let (x, y) = parse_xy(args);
            let inputs = [
                mouse_abs_input(x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE),
                mouse_abs_input(x, y, MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE),
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        "scroll" => {
            let delta: i32 = args.trim().parse().unwrap_or(120);
            let inputs = [INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        mouseData: delta as u32,
                        dwFlags: MOUSEEVENTF_WHEEL,
                        ..Default::default()
                    },
                },
            }];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        other => Response::error(&format!("unknown mouse action: {}", other)),
    }
}

#[cfg(not(target_os = "windows"))]
fn handle_mouse(action: &str, _args: &str) -> Response {
    Response::error(&format!(
        "mouse {action} not available on Linux. GUI automation requires a Windows host with mrsh tray (port 9822)"
    ))
}

// ── Keyboard ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_key(action: &str, args: &str) -> Response {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    match action {
        "type" => {
            // Type unicode string
            for ch in args.chars() {
                let scan = ch as u16;
                let inputs = [
                    INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wScan: scan,
                                dwFlags: KEYEVENTF_UNICODE,
                                ..Default::default()
                            },
                        },
                    },
                    INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wScan: scan,
                                dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                                ..Default::default()
                            },
                        },
                    },
                ];
                unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            }
            ok_response("ok")
        }
        "tap" => {
            let vk = named_key_to_vk(args.trim());
            let inputs = [
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(vk),
                            ..Default::default()
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(vk),
                            dwFlags: KEYEVENTF_KEYUP,
                            ..Default::default()
                        },
                    },
                },
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        other => Response::error(&format!("unknown key action: {}", other)),
    }
}

#[cfg(not(target_os = "windows"))]
fn handle_key(action: &str, _args: &str) -> Response {
    Response::error(&format!(
        "key {action} not available on Linux. GUI automation requires a Windows host with mrsh tray (port 9822)"
    ))
}

// ── Window management ──────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_window(action: &str, args: &str) -> Response {
    use windows::Win32::Foundation::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    // Window enumeration and management require an interactive desktop
    if matches!(action, "list" | "find") && crate::is_session_zero() {
        return Response::error(&crate::session_zero_hint(&format!("window {action}")));
    }

    match action {
        "list" => {
            let mut windows = Vec::new();
            unsafe {
                EnumWindows(
                    Some(enum_windows_callback),
                    LPARAM(&mut windows as *mut Vec<WindowInfo> as isize),
                )
                .ok();
            }
            let json = serde_json::to_string(&windows).unwrap_or_default();
            ok_response(&json)
        }
        "find" => {
            let title_pattern = args.trim().to_lowercase();
            let mut windows: Vec<WindowInfo> = Vec::new();
            unsafe {
                EnumWindows(
                    Some(enum_windows_callback),
                    LPARAM(&mut windows as *mut Vec<WindowInfo> as isize),
                )
                .ok();
            }
            let matched: Vec<&WindowInfo> = windows
                .iter()
                .filter(|w| w.title.to_lowercase().contains(&title_pattern))
                .collect();
            let json = serde_json::to_string(&matched).unwrap_or_default();
            ok_response(&json)
        }
        "activate" => {
            let hwnd_val: u64 = args.trim().parse().unwrap_or(0);
            let hwnd = HWND(hwnd_val as *mut _);
            unsafe {
                let _ = SetForegroundWindow(hwnd);
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            ok_response("ok")
        }
        "close" => {
            let hwnd_val: u64 = args.trim().parse().unwrap_or(0);
            let hwnd = HWND(hwnd_val as *mut _);
            unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)).ok() };
            ok_response("ok")
        }
        other => Response::error(&format!("unknown window action: {}", other)),
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn enum_windows_callback(
    hwnd: windows::Win32::Foundation::HWND,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::core::BOOL {
    use windows::Win32::Foundation::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    unsafe {
        if !IsWindowVisible(hwnd).as_bool() {
            return windows::core::BOOL(1); // TRUE
        }

        let mut title_buf = [0u16; 512];
        let len = GetWindowTextW(hwnd, &mut title_buf);
        if len == 0 {
            return windows::core::BOOL(1); // TRUE
        }
        let title = String::from_utf16_lossy(&title_buf[..len as usize]);

        let mut rect = RECT::default();
        let _ = GetWindowRect(hwnd, &mut rect);

        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));

        let windows = &mut *(lparam.0 as *mut Vec<WindowInfo>);
        windows.push(WindowInfo {
            hwnd: hwnd.0 as u64,
            title,
            pid,
            x: rect.left,
            y: rect.top,
            width: rect.right - rect.left,
            height: rect.bottom - rect.top,
            visible: true,
        });

        windows::core::BOOL(1) // TRUE
    }
}

#[cfg(not(target_os = "windows"))]
fn handle_window(action: &str, _args: &str) -> Response {
    Response::error(&format!(
        "window {action} not available on Linux. Window management requires a Windows host with mrsh tray (port 9822)"
    ))
}

// ── Helpers ────────────────────────────────────────────────────────

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_xy(args: &str) -> (i32, i32) {
    let parts: Vec<&str> = args.split(',').collect();
    if parts.len() >= 2 {
        let x = parts[0].trim().parse().unwrap_or(0);
        let y = parts[1].trim().parse().unwrap_or(0);
        (x, y)
    } else {
        (0, 0)
    }
}

/// Normalize a pixel coordinate to the 0..=65535 range SendInput expects for
/// MOUSEEVENTF_ABSOLUTE. Maps pixel [0, dim-1] linearly onto [0, 65535] so the
/// target pixel is hit exactly (no off-by-one into an adjacent NC region).
/// `dim` is the primary-screen extent in pixels (SM_CXSCREEN / SM_CYSCREEN).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn normalize_abs(coord: i32, dim: i32) -> i32 {
    if dim <= 1 {
        return 0;
    }
    let c = coord.clamp(0, dim - 1) as i64;
    ((c * 65535) / (dim as i64 - 1)) as i32
}

/// Build a MOUSEEVENTF_ABSOLUTE MOUSEINPUT for the given pixel coords + flags.
/// Coords are normalized against the primary screen extents.
#[cfg(target_os = "windows")]
fn mouse_abs_input(
    x: i32,
    y: i32,
    flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
) -> windows::Win32::UI::Input::KeyboardAndMouse::INPUT {
    use windows::Win32::UI::Input::KeyboardAndMouse::{INPUT, INPUT_0, INPUT_MOUSE, MOUSEINPUT};
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    let (sw, sh) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: normalize_abs(x, sw),
                dy: normalize_abs(y, sh),
                dwFlags: flags,
                ..Default::default()
            },
        },
    }
}

/// Map named key to Windows virtual key code.
#[cfg(target_os = "windows")]
fn named_key_to_vk(name: &str) -> u16 {
    match name.to_lowercase().as_str() {
        "enter" | "return" => 0x0D,
        "tab" => 0x09,
        "escape" | "esc" => 0x1B,
        "backspace" => 0x08,
        "delete" | "del" => 0x2E,
        "space" => 0x20,
        "up" => 0x26,
        "down" => 0x28,
        "left" => 0x25,
        "right" => 0x27,
        "home" => 0x24,
        "end" => 0x23,
        "pageup" => 0x21,
        "pagedown" => 0x22,
        "insert" => 0x2D,
        "ctrl" | "control" => 0x11,
        "alt" => 0x12,
        "shift" => 0x10,
        "win" | "windows" | "super" => 0x5B,
        "f1" => 0x70,
        "f2" => 0x71,
        "f3" => 0x72,
        "f4" => 0x73,
        "f5" => 0x74,
        "f6" => 0x75,
        "f7" => 0x76,
        "f8" => 0x77,
        "f9" => 0x78,
        "f10" => 0x79,
        "f11" => 0x7A,
        "f12" => 0x7B,
        _ => {
            // Single character → ASCII VK
            if let Some(c) = name.chars().next() {
                c.to_ascii_uppercase() as u16
            } else {
                0
            }
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xy_valid() {
        assert_eq!(parse_xy("100,200"), (100, 200));
        assert_eq!(parse_xy(" 50 , 75 "), (50, 75));
    }

    #[test]
    fn parse_xy_invalid() {
        assert_eq!(parse_xy("invalid"), (0, 0));
        assert_eq!(parse_xy(""), (0, 0));
    }

    #[test]
    fn normalize_abs_endpoints() {
        // pixel 0 → 0, last pixel → 65535 (exact endpoints)
        assert_eq!(normalize_abs(0, 1920), 0);
        assert_eq!(normalize_abs(1919, 1920), 65535);
        assert_eq!(normalize_abs(0, 1080), 0);
        assert_eq!(normalize_abs(1079, 1080), 65535);
    }

    #[test]
    fn normalize_abs_midpoint() {
        // ~middle pixel maps to ~middle of the normalized range
        let mid = normalize_abs(960, 1920);
        assert!((32000..=33000).contains(&mid), "mid was {mid}");
    }

    #[test]
    fn normalize_abs_toolbar_band() {
        // rsh-oz4i target: toolbar Configurazione at (1759,130) on 1920x1080.
        // Must land at a stable normalized coord, NOT clamp to 0/65535.
        let nx = normalize_abs(1759, 1920);
        let ny = normalize_abs(130, 1080);
        assert!((59000..61000).contains(&nx), "nx was {nx}");
        assert!((7000..9000).contains(&ny), "ny was {ny}");
    }

    #[test]
    fn normalize_abs_clamps_out_of_range() {
        // negative + over-extent clamp into valid range, never panic / wrap
        assert_eq!(normalize_abs(-50, 1920), 0);
        assert_eq!(normalize_abs(5000, 1920), 65535);
    }

    #[test]
    fn normalize_abs_degenerate_dim() {
        // dim <= 1 is degenerate (no real screen) → 0, no divide-by-zero
        assert_eq!(normalize_abs(100, 1), 0);
        assert_eq!(normalize_abs(100, 0), 0);
    }

    #[test]
    fn window_info_serializes() {
        let info = WindowInfo {
            hwnd: 12345,
            title: "Test Window".to_string(),
            pid: 100,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            visible: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Test Window"));
        assert!(json.contains("12345"));
    }

    #[test]
    fn handle_input_unknown_command() {
        let resp = handle_input("unknown", "action", "args");
        assert!(!resp.success);
    }

    #[test]
    fn handle_input_mouse_stub() {
        // On non-Windows, all mouse actions return platform error
        #[cfg(not(target_os = "windows"))]
        {
            let resp = handle_input("mouse", "pos", "");
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }

    #[test]
    fn handle_input_window_stub() {
        #[cfg(not(target_os = "windows"))]
        {
            let resp = handle_input("window", "list", "");
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }
}
