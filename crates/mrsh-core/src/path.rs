//! Path normalization for Git Bash, MINGW64, and WSL paths.
//!
//! Converts non-native path formats to Windows-native:
//! - MSYS/Git Bash: `/c/Users` → `C:/Users`
//! - WSL: `/mnt/c/Users` → `C:/Users`
//! - Bare drive: `/c` → `C:/`
//! - Backslash normalization: `C:\Users` → `C:/Users`
//! - Double-slash cleanup (preserves UNC `//server/share`)

/// Normalize a path from Git Bash / MINGW64 / WSL to Windows-native format.
///
/// Returns the path unchanged if it's already in native format or empty.
pub fn normalize(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let mut p = path.to_string();

    // 1. WSL style: /mnt/c/Users → C:/Users
    if p.starts_with("/mnt/") && p.len() >= 6 {
        let drive = p.as_bytes()[5];
        if drive.is_ascii_alphabetic() && (p.len() == 6 || p.as_bytes()[6] == b'/') {
            p = format!("{}:{}", (drive as char).to_ascii_uppercase(), &p[6..]);
            if p.len() == 2 {
                p.push('/');
            }
        }
    }

    // 2. MSYS/Git Bash style: /c/Users → C:/Users
    if p.len() >= 3
        && p.as_bytes()[0] == b'/'
        && p.as_bytes()[1].is_ascii_alphabetic()
        && p.as_bytes()[2] == b'/'
    {
        p = format!(
            "{}:{}",
            (p.as_bytes()[1] as char).to_ascii_uppercase(),
            &p[2..]
        );
    }

    // 3. Bare drive: /c → C:/
    if p.len() == 2 && p.as_bytes()[0] == b'/' && p.as_bytes()[1].is_ascii_alphabetic() {
        p = format!("{}:/", (p.as_bytes()[1] as char).to_ascii_uppercase());
    }

    // 4. Backslash → forward slash
    p = p.replace('\\', "/");

    // 5. Clean double slashes (preserve UNC //server/share)
    if !p.starts_with("//") {
        while p.contains("//") {
            p = p.replace("//", "/");
        }
    }

    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msys_drive_path() {
        assert_eq!(normalize("/c/Users/user"), "C:/Users/user");
        assert_eq!(normalize("/d/Data"), "D:/Data");
        assert_eq!(normalize("/s/Projects"), "/path/to");
    }

    #[test]
    fn msys_uppercase() {
        assert_eq!(normalize("/C/Users"), "C:/Users");
    }

    #[test]
    fn bare_drive() {
        assert_eq!(normalize("/c"), "C:/");
        assert_eq!(normalize("/s"), "S:/");
    }

    #[test]
    fn wsl_mnt_path() {
        assert_eq!(normalize("/mnt/c/Users/user"), "C:/Users/user");
        assert_eq!(normalize("/path/to"), "/path/to");
    }

    #[test]
    fn wsl_bare_drive() {
        assert_eq!(normalize("/mnt/c"), "C:/");
    }

    #[test]
    fn backslash_to_forward() {
        assert_eq!(normalize("C:\\Users\\user"), "C:/Users/user");
    }

    #[test]
    fn double_slash_cleanup() {
        assert_eq!(normalize("C://Users//user"), "C:/Users/user");
    }

    #[test]
    fn unc_preserved() {
        assert_eq!(normalize("//server/share/file"), "//server/share/file");
    }

    #[test]
    fn already_native() {
        assert_eq!(normalize("C:/Users/user"), "C:/Users/user");
        assert_eq!(normalize("/path/to/file.txt"), "/path/to/file.txt");
    }

    #[test]
    fn empty_string() {
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn relative_path_unchanged() {
        assert_eq!(normalize("src/main.rs"), "src/main.rs");
        assert_eq!(normalize("./file.txt"), "./file.txt");
    }

    #[test]
    fn linux_absolute_non_drive() {
        // /usr/bin should NOT be converted (not a drive letter pattern)
        assert_eq!(normalize("/usr/bin"), "/usr/bin");
        assert_eq!(normalize("/home/user"), "/home/user");
    }
}
