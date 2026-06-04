//! NSIS .nsi script generation + makensis discovery.

use std::path::PathBuf;

use anyhow::{Result, bail};

/// Generate the NSIS .nsi installer script.
pub(super) fn generate_nsi_script(
    version: &str,
    port: u16,
    has_startup: bool,
    has_config: bool,
) -> String {
    let mut s = String::new();

    // Header
    s.push_str("!include \"MUI2.nsh\"\n\n");
    s.push_str(&format!("Name \"mrsh {}\"\n", version));
    s.push_str("OutFile \"${OUTFILE}\"\n");
    s.push_str("InstallDir \"C:\\ProgramData\\mrsh\"\n");
    s.push_str("RequestExecutionLevel admin\n");
    s.push_str("SetCompressor /SOLID lzma\n\n");

    // Branding
    s.push_str(&format!("!define VERSION \"{}\"\n", version));
    s.push_str(&format!("!define PORT \"{}\"\n", port));
    s.push_str("BrandingText \"mrsh ${VERSION}\"\n\n");

    // Pages
    s.push_str("!insertmacro MUI_PAGE_INSTFILES\n");
    s.push_str("!insertmacro MUI_LANGUAGE \"English\"\n\n");

    // Install section
    s.push_str("Section \"Install\"\n");
    s.push_str("    SetOutPath $INSTDIR\n\n");

    // Stop existing services and kill all processes (ignore errors)
    s.push_str("    DetailPrint \"Stopping existing services...\"\n");
    s.push_str("    nsExec::ExecToStack 'net stop mrsh'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'net stop rsh'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'sc delete rsh'\n"); // delete legacy service registration
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'sc delete mrsh'\n"); // delete to re-register with correct binary path
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'taskkill /F /IM mrsh.exe'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'taskkill /F /IM rsh.exe'\n");
    s.push_str("    Pop $0\n");
    // Remove old rsh.exe from mrsh dir (legacy rename artifact)
    s.push_str("    Delete \"$INSTDIR\\rsh.exe\"\n");
    s.push_str("    Delete \"$INSTDIR\\rsh.exe.bak\"\n\n");

    // Extract files
    s.push_str("    DetailPrint \"Extracting files...\"\n");
    s.push_str("    File \"${SRCDIR}\\mrsh.exe\"\n");
    s.push_str("    File \"${SRCDIR}\\authorized_keys\"\n");
    s.push_str("    File \"${SRCDIR}\\AI_USAGE.md\"\n");
    s.push_str("    File \"${SRCDIR}\\install.bat\"\n");
    if has_startup {
        s.push_str("    File \"${SRCDIR}\\startup.bat\"\n");
    }
    if has_config {
        s.push_str("    File \"${SRCDIR}\\config\"\n");
        // Also copy enrollment config to SYSTEM user profile (server reads from there)
        s.push_str("    CreateDirectory \"$PROFILE\\.mrsh\"\n");
        s.push_str("    CopyFiles /SILENT \"$INSTDIR\\config\" \"$PROFILE\\.mrsh\\config\"\n");
        // SYSTEM profile for service mode
        s.push_str("    CreateDirectory \"C:\\Windows\\System32\\config\\systemprofile\\.mrsh\"\n");
        s.push_str("    CopyFiles /SILENT \"$INSTDIR\\config\" \"C:\\Windows\\System32\\config\\systemprofile\\.mrsh\\config\"\n");
        // Also copy to ProgramData (service data dir — belt + suspenders)
        s.push_str("    CopyFiles /SILENT \"$INSTDIR\\config\" \"$INSTDIR\\config.enrollment\"\n");
    }
    s.push('\n');

    // Install service
    s.push_str("    DetailPrint \"Installing mrsh service...\"\n");
    s.push_str("    nsExec::ExecToStack '\"$INSTDIR\\mrsh.exe\" --install'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    StrCmp $0 \"0\" +2 0\n");
    s.push_str("    DetailPrint \"Warning: service install returned $0\"\n\n");

    // Start service
    s.push_str("    DetailPrint \"Starting mrsh service...\"\n");
    s.push_str("    nsExec::ExecToStack 'net start mrsh'\n");
    s.push_str("    Pop $0\n\n");

    // Firewall rule
    s.push_str("    DetailPrint \"Adding firewall rules...\"\n");
    s.push_str("    nsExec::ExecToStack 'netsh advfirewall firewall add rule name=\"mrsh\" dir=in action=allow program=\"$INSTDIR\\mrsh.exe\" enable=yes'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'netsh advfirewall firewall add rule name=\"mrsh-ports\" dir=in action=allow protocol=TCP localport=8822,9822 profile=any'\n");
    s.push_str("    Pop $0\n\n");

    // Legacy cleanup: migrate data from C:\ProgramData\remote-shell\ → mrsh\, then delete
    s.push_str("    ; --- Legacy cleanup ---\n");
    s.push_str("    IfFileExists \"C:\\ProgramData\\remote-shell\\*.*\" 0 +11\n");
    s.push_str("    DetailPrint \"Migrating data from legacy remote-shell directory...\"\n");
    s.push_str("    nsExec::ExecToStack 'xcopy /E /I /Y \"C:\\ProgramData\\remote-shell\\cache\" \"$INSTDIR\\cache\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'xcopy /E /I /Y \"C:\\ProgramData\\remote-shell\\sessions\" \"$INSTDIR\\sessions\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'cmd /c copy /y \"C:\\ProgramData\\remote-shell\\banner.txt\" \"$INSTDIR\\banner.txt\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'cmd /c copy /y \"C:\\ProgramData\\remote-shell\\screen-token\" \"$INSTDIR\\screen-token\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'sc delete rsh'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'cmd /c rmdir /s /q \"C:\\ProgramData\\remote-shell\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    DetailPrint \"Legacy directory cleaned up.\"\n\n");

    // Launch tray in user session via scheduled task (ONLOGON task registered by --install).
    // Cannot use Exec — NSIS runs elevated (SYSTEM), Exec inherits that session.
    // schtasks /run launches the ONLOGON task in the interactive user session.
    s.push_str("    DetailPrint \"Starting tray icon...\"\n");
    s.push_str("    nsExec::ExecToStack 'schtasks /run /tn mrsh-tray'\n");
    s.push_str("    Pop $0\n\n");

    // Done
    s.push_str(&format!(
        "    DetailPrint \"Installation complete. mrsh listening on port {}.\"\n",
        port
    ));
    s.push_str("SectionEnd\n");

    s
}

/// Find the makensis executable.
pub(super) fn find_makensis() -> Result<PathBuf> {
    // On Windows: use `where` (native) only — `which` from Git Bash/MSYS returns
    // POSIX paths like `/c/ProgramData/Scoop/shims/makensis` which CreateProcess
    // cannot parse, causing "The system cannot find the path specified" (rsh-2am).
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("where")
            .arg("makensis.exe")
            .output()
            && output.status.success()
        {
            let path = String::from_utf8_lossy(&output.stdout)
                .trim()
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    // On Unix: use `which`
    #[cfg(not(target_os = "windows"))]
    {
        for name in ["makensis", "makensis.exe"] {
            if let Ok(output) = std::process::Command::new("which").arg(name).output()
                && output.status.success()
            {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }

    // Common locations
    for candidate in [
        "/usr/bin/makensis",
        "/usr/local/bin/makensis",
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    bail!(
        "makensis not found. Install NSIS:\n\
         \x20 Ubuntu/Debian: sudo apt install nsis\n\
         \x20 Windows: winget install NSIS.NSIS\n\
         \x20 macOS: brew install makensis"
    )
}
