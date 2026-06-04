//! Cross-platform remote path translation for push/pull.
//!
//! Problem: when invoking mrsh from Git Bash on Windows, common shell behaviors
//! mangle the remote-side path BEFORE mrsh.exe sees it:
//!
//! 1. `~/dest.txt` is expanded by the shell to `/c/Users/<user>/dest.txt` —
//!    that's the SENDER's HOME, not the receiver's. Pushing to a Linux receiver
//!    silently lands the file at `/c/Users/<user>/dest.txt` on the Linux box
//!    (a literal path under `/c`), not `~user/dest.txt`.
//!
//! 2. MSYS path conversion rewrites `/tmp/x` → `W:/Temp/x` for arguments that
//!    look like POSIX absolute paths. Bypassed via `MSYS_NO_PATHCONV=1`, but
//!    that's easy to forget.
//!
//! 3. A literal `~/foo` (single-quoted) survives the shell; mrsh historically
//!    sent it verbatim and the server-side write failed (sh does NOT expand `~`
//!    when it appears mid-argument from a write syscall — only at command
//!    parsing time inside a shell).
//!
//! Fix strategy (this module): inspect the REMOTE path argument client-side,
//! detect the suspicious patterns, query the receiver's `$HOME` over an existing
//! exec session, and rewrite the path to the correct receiver-side form. Cache
//! the receiver HOME per-invocation so we don't re-query for each push/pull.
//!
//! Triggers (any one fires translation):
//!   - leading `~/` or bare `~`
//!   - leading `/c/Users/<user>/...` (Git Bash mount-point form of `~/`)
//!   - leading `C:/Users/<user>/...` or `C:\Users\<user>\...` (MSYS-converted)
//!   - any of the above where `<user>` matches the SENDER's USERNAME
//!   - leading `<drive>:[/\]Temp[/\]...` when receiver is Linux (MSYS-converted
//!     `/tmp/...` — the most common spuri-creation path). Rewrites to `/tmp/...`.
//!     Fix landed 2026-05-09 after fleet audit found ~50M of `W:/Temp/*` literal
//!     dirs across multiple build hosts.
//!
//! When the receiver is detected as Windows we leave Windows-style paths alone.
//! When the receiver is Linux/macOS we rewrite to `<receiver-home>/<rest>`.

use anyhow::Result;
use mrsh_client::client::RshClient;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

/// Result of translating a remote path.
#[derive(Debug, Clone)]
pub struct TranslatedPath {
    /// The path to actually send to the server.
    pub remote: String,
    /// True if we rewrote the input.
    pub rewritten: bool,
    /// Original input (for logging).
    pub original: String,
}

/// Detected receiver platform family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverOs {
    Linux,
    Windows,
    Unknown,
}

/// Probe receiver $HOME and OS family by issuing a single `exec` over the open
/// client. The probe is intentionally portable:
///   - On a sh-like server (Linux/macOS): `echo $HOME` prints `/home/<user>`.
///   - On a PowerShell server (Windows): `echo $HOME` prints `C:\Users\<user>`.
///
/// We classify the OS from the shape of the output.
pub async fn probe_receiver_home<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
) -> Result<(String, ReceiverOs)> {
    let raw = mrsh_client::commands::exec(client, "echo $HOME", &[]).await?;
    let home = raw.trim().trim_end_matches(['\r', '\n']).to_string();
    let os = classify_os(&home);
    debug!("path_translate: receiver HOME={} OS={:?}", home, os);
    Ok((home, os))
}

fn classify_os(home: &str) -> ReceiverOs {
    let bytes = home.as_bytes();
    if bytes.len() >= 2 && (bytes[0] as char).is_ascii_alphabetic() && bytes[1] == b':' {
        ReceiverOs::Windows
    } else if home.starts_with('/') {
        ReceiverOs::Linux
    } else if home.contains('\\') {
        ReceiverOs::Windows
    } else {
        ReceiverOs::Unknown
    }
}

/// Inspect the remote path and rewrite it if it matches a known
/// shell-mangled-on-sender pattern that would land on the wrong receiver path.
///
/// `home` and `os` come from [`probe_receiver_home`].
///
/// Translation rules (only applied when receiver is non-Windows):
///   1. leading `~/` or bare `~` → `<home>/<rest>` (or `<home>`)
///   2. `/c/Users/<sender>/...` → `<home>/<rest>` (Git Bash mount-point case)
///   3. `C:/Users/<sender>/...` or `C:\Users\<sender>\...` → `<home>/<rest>`
///      (MSYS-converted case)
///
/// When receiver IS Windows: leave Windows-style paths alone, but still expand
/// a leading `~/` since PowerShell write syscalls don't expand it.
pub fn translate_remote_path(input: &str, home: &str, os: ReceiverOs) -> TranslatedPath {
    let original = input.to_string();
    let trimmed = input.trim_end_matches(['\r', '\n']);

    // Rule 1: literal `~/` or bare `~` — always rewrite (both OSes).
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return TranslatedPath {
            remote: join_home(home, rest),
            rewritten: true,
            original,
        };
    }
    if trimmed == "~" {
        return TranslatedPath {
            remote: home.to_string(),
            rewritten: true,
            original,
        };
    }

    // For the next rules we only act on non-Windows receivers; on a Windows
    // receiver `C:/Users/...` is a legitimate path.
    if os == ReceiverOs::Windows {
        return TranslatedPath {
            remote: trimmed.to_string(),
            rewritten: false,
            original,
        };
    }

    let sender_user = current_sender_username();

    // Rule 2: Git Bash mount-point form `/c/Users/<user>/...` (any drive letter
    // /<x>/Users/<user>/...). Heuristic: 3-letter prefix `/<a>/` then `Users`.
    if let Some(rest) = strip_gitbash_user_prefix(trimmed, sender_user.as_deref()) {
        warn!(
            "path_translate: rewrote sender-side mount path {:?} -> receiver {:?}",
            trimmed,
            join_home(home, rest)
        );
        return TranslatedPath {
            remote: join_home(home, rest),
            rewritten: true,
            original,
        };
    }

    // Rule 3: MSYS-converted form `C:/Users/<user>/...` or `C:\Users\<user>\...`.
    if let Some(rest) = strip_windows_user_prefix(trimmed, sender_user.as_deref()) {
        warn!(
            "path_translate: rewrote sender-side Windows path {:?} -> receiver {:?}",
            trimmed,
            join_home(home, rest)
        );
        return TranslatedPath {
            remote: join_home(home, rest),
            rewritten: true,
            original,
        };
    }

    // Rule 4: MSYS-converted `/tmp/...` form `<drive>:[/\]Temp[/\]...`.
    // MSYS rewrites POSIX `/tmp/foo` to the configured Windows TMP directory
    // (commonly `W:/Temp/foo` or `C:\Temp\foo`). Receiver is Linux here, so
    // the original intent was `/tmp/foo`. Rewrite back.
    if let Some(rest) = strip_msys_temp_prefix(trimmed) {
        let rewritten = if rest.is_empty() {
            "/tmp".to_string()
        } else {
            format!("/tmp/{}", rest.replace('\\', "/"))
        };
        warn!(
            "path_translate: rewrote MSYS-converted Temp path {:?} -> receiver {:?}",
            trimmed, rewritten
        );
        return TranslatedPath {
            remote: rewritten,
            rewritten: true,
            original,
        };
    }

    TranslatedPath {
        remote: trimmed.to_string(),
        rewritten: false,
        original,
    }
}

fn join_home(home: &str, rest: &str) -> String {
    let base = home.trim_end_matches(['/', '\\']);
    let suffix = rest.trim_start_matches(['/', '\\']);
    if suffix.is_empty() {
        base.to_string()
    } else if base.contains('\\') && !base.contains('/') {
        format!("{}\\{}", base, suffix.replace('/', "\\"))
    } else {
        format!("{}/{}", base, suffix.replace('\\', "/"))
    }
}

fn current_sender_username() -> Option<String> {
    std::env::var("USERNAME") // Windows
        .or_else(|_| std::env::var("USER")) // Unix
        .ok()
        .filter(|s| !s.is_empty())
}

/// Strip a leading `/<drive>/Users/<sender>/` from `path` (Git Bash
/// mount-point form) and return the remainder. Drive letter is any single
/// ASCII letter; user must match `sender_user` if provided.
fn strip_gitbash_user_prefix<'a>(path: &'a str, sender_user: Option<&str>) -> Option<&'a str> {
    let bytes = path.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'/' {
        return None;
    }
    if !(bytes[1] as char).is_ascii_alphabetic() {
        return None;
    }
    if bytes[2] != b'/' {
        return None;
    }
    let after_drive = &path[3..];
    let rest = after_drive.strip_prefix("Users/")?;
    let (user, after_user) = rest.split_once('/').unwrap_or((rest, ""));
    if let Some(expected) = sender_user {
        if !user.eq_ignore_ascii_case(expected) {
            return None;
        }
    }
    Some(after_user)
}

/// Strip a leading `<Drive>:[/\\]Temp[/\\]` from `path` (MSYS-converted form
/// of POSIX `/tmp/`). Returns the remainder. Drive letter is any single ASCII
/// letter (MSYS picks based on user's mount config — commonly W: or C:).
/// Match on `Temp` is case-insensitive (Win FS is case-insensitive, MSYS may
/// emit either case).
fn strip_msys_temp_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    if !(bytes[0] as char).is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    if bytes[2] != b'/' && bytes[2] != b'\\' {
        return None;
    }
    let after_drive = &path[3..];
    // Match "Temp/" or "Temp\" or bare "Temp" (case-insensitive).
    let lower = after_drive.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("temp/") {
        Some(&after_drive[5..5 + rest.len()])
    } else if let Some(rest) = lower.strip_prefix("temp\\") {
        Some(&after_drive[5..5 + rest.len()])
    } else if lower == "temp" {
        Some("")
    } else {
        None
    }
}

/// Strip a leading `<Drive>:[/\\]Users[/\\]<sender>[/\\]` from `path`
/// (MSYS-converted form). Returns the remainder.
fn strip_windows_user_prefix<'a>(path: &'a str, sender_user: Option<&str>) -> Option<&'a str> {
    let bytes = path.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    if !(bytes[0] as char).is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    if bytes[2] != b'/' && bytes[2] != b'\\' {
        return None;
    }
    let after_drive = &path[3..];
    // Match "Users/" or "Users\"
    let rest = if let Some(r) = after_drive.strip_prefix("Users/") {
        r
    } else if let Some(r) = after_drive.strip_prefix("Users\\") {
        r
    } else {
        return None;
    };
    let split_idx = rest.find(['/', '\\']);
    let (user, after_user) = match split_idx {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if let Some(expected) = sender_user {
        if !user.eq_ignore_ascii_case(expected) {
            return None;
        }
    }
    Some(after_user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_linux_home() {
        assert_eq!(classify_os("/home/user"), ReceiverOs::Linux);
        assert_eq!(classify_os("/root"), ReceiverOs::Linux);
        assert_eq!(
            classify_os("/data/data/com.termux/files/home"),
            ReceiverOs::Linux
        );
    }

    #[test]
    fn classify_windows_home() {
        assert_eq!(classify_os("C:\\Users\\user"), ReceiverOs::Windows);
        assert_eq!(classify_os("C:/Users/user"), ReceiverOs::Windows);
        assert_eq!(classify_os("D:\\Users\\admin"), ReceiverOs::Windows);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify_os(""), ReceiverOs::Unknown);
        assert_eq!(classify_os("relative/path"), ReceiverOs::Unknown);
    }

    #[test]
    fn translate_tilde_slash_linux() {
        let r = translate_remote_path("~/kb-build/dest.txt", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "/home/user/kb-build/dest.txt");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_bare_tilde() {
        let r = translate_remote_path("~", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "/home/user");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_tilde_windows_receiver() {
        let r = translate_remote_path("~/Documents/x.txt", "C:\\Users\\admin", ReceiverOs::Windows);
        assert_eq!(r.remote, "C:\\Users\\admin\\Documents\\x.txt");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_gitbash_mount_form() {
        // Simulate USERNAME=user
        unsafe {
            std::env::set_var("USERNAME", "user");
        }
        let r = translate_remote_path(
            "/c/Users/user/kb-build/dest.txt",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "/home/user/kb-build/dest.txt");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_msys_windows_form() {
        unsafe {
            std::env::set_var("USERNAME", "user");
        }
        let r = translate_remote_path(
            "C:/Users/user/kb-build/dest.txt",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "/home/user/kb-build/dest.txt");
        assert!(r.rewritten);

        let r = translate_remote_path(
            "C:\\Users\\user\\kb-build\\dest.txt",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "/home/user/kb-build/dest.txt");
        assert!(r.rewritten);
    }

    #[test]
    fn passthrough_other_user() {
        // USERNAME=user, but path mentions another user → leave alone
        unsafe {
            std::env::set_var("USERNAME", "user");
        }
        let r = translate_remote_path(
            "/c/Users/admin/test.txt",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "/c/Users/admin/test.txt");
        assert!(!r.rewritten);
    }

    #[test]
    fn passthrough_absolute_linux_path() {
        let r = translate_remote_path("/tmp/test.txt", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "/tmp/test.txt");
        assert!(!r.rewritten);
    }

    #[test]
    fn passthrough_relative_path() {
        let r = translate_remote_path("relative/path.txt", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "relative/path.txt");
        assert!(!r.rewritten);
    }

    #[test]
    fn passthrough_windows_to_windows() {
        // Windows receiver, Windows path → leave alone (legitimate)
        let r = translate_remote_path(
            "C:/ProgramData/mrsh/foo.txt",
            "C:\\Users\\admin",
            ReceiverOs::Windows,
        );
        assert_eq!(r.remote, "C:/ProgramData/mrsh/foo.txt");
        assert!(!r.rewritten);
    }

    #[test]
    fn translate_msys_temp_w_drive_to_linux() {
        // The classic case: `/tmp/foo` mangled to `W:/Temp/foo` on the sender
        // because MSYS_NO_PATHCONV was unset. Receiver is Linux → rewrite.
        let r = translate_remote_path("W:/Temp/foo.txt", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "/tmp/foo.txt");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_msys_temp_c_drive_backslash_to_linux() {
        let r = translate_remote_path(
            "C:\\Temp\\gyro_2048-debug.apk",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "/tmp/gyro_2048-debug.apk");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_msys_temp_lowercase_to_linux() {
        // MSYS sometimes emits lowercase `temp`.
        let r = translate_remote_path("W:/temp/x.bin", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "/tmp/x.bin");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_msys_temp_nested_path() {
        let r = translate_remote_path(
            "W:/Temp/build-out/release/foo.bin",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "/tmp/build-out/release/foo.bin");
        assert!(r.rewritten);
    }

    #[test]
    fn translate_msys_temp_bare() {
        // Bare `W:/Temp` with no trailing path — rewrite to `/tmp`.
        let r = translate_remote_path("W:/Temp", "/home/user", ReceiverOs::Linux);
        assert_eq!(r.remote, "/tmp");
        assert!(r.rewritten);
    }

    #[test]
    fn passthrough_msys_temp_to_windows_receiver() {
        // Windows receiver: `W:/Temp/foo` is a legitimate path, leave alone.
        let r = translate_remote_path("W:/Temp/foo.txt", "C:\\Users\\admin", ReceiverOs::Windows);
        assert_eq!(r.remote, "W:/Temp/foo.txt");
        assert!(!r.rewritten);
    }

    #[test]
    fn passthrough_non_temp_drive_path() {
        // `C:/ProgramData/...` to Linux receiver — no Temp prefix, leave alone.
        // (We don't auto-rewrite arbitrary `<drive>:/...` because the user might
        // have a legitimate intent.)
        let r = translate_remote_path(
            "C:/ProgramData/mrsh/foo.exe",
            "/home/user",
            ReceiverOs::Linux,
        );
        assert_eq!(r.remote, "C:/ProgramData/mrsh/foo.exe");
        assert!(!r.rewritten);
    }

    #[test]
    fn join_home_linux() {
        assert_eq!(join_home("/home/user", "kb/x.txt"), "/home/user/kb/x.txt");
        assert_eq!(join_home("/home/user/", "/kb/x.txt"), "/home/user/kb/x.txt");
        assert_eq!(join_home("/home/user", ""), "/home/user");
    }

    #[test]
    fn join_home_windows() {
        assert_eq!(
            join_home("C:\\Users\\admin", "Documents/x.txt"),
            "C:\\Users\\admin\\Documents\\x.txt"
        );
    }
}
