//! Generate a ready-to-deploy installer package for a target machine.
//!
//! - **Linux**: Self-extracting `.sh` (bash header + tar.gz payload).
//! - **Windows**: NSIS-based installer `.exe` (requires `makensis` on build host).
//!
//! Both produce a **single executable file** for easy deployment.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

mod keys;
mod linux;
mod nsis;
mod windows;

pub use keys::get_group_token;

/// Options for generating an install pack.
pub struct InstallPackOptions {
    /// Target platform: "windows" or "linux".
    pub platform: String,
    /// Output file path. If None, auto-named based on version+platform.
    pub output: Option<PathBuf>,
    /// Path to the mrsh binary to include.
    pub binary: Option<PathBuf>,
    /// Extra public keys to add to authorized_keys.
    pub extra_keys: Vec<String>,
    /// Port the target server will listen on (default 8822).
    pub port: u16,
    /// Optional NAS auth command for startup.bat.
    pub nas_auth: Option<String>,
    /// Fleet enrollment group name.
    pub group: Option<String>,
    /// Rendezvous server address for fleet enrollment.
    pub rendezvous_server: Option<String>,
}

/// Generate the install pack — returns the path to the single output file.
pub fn generate(opts: &InstallPackOptions) -> Result<PathBuf> {
    let version = env!("CARGO_PKG_VERSION");
    let is_windows = opts.platform == "windows";

    // Collect all pack contents in memory
    let binary_src = find_binary(&opts.binary, is_windows)?;
    let binary_name = if is_windows { "mrsh.exe" } else { "mrsh" };
    let binary_data = std::fs::read(&binary_src)
        .with_context(|| format!("read binary: {}", binary_src.display()))?;
    println!("  binary: {} ({} bytes)", binary_name, binary_data.len());

    let auth_keys_content = keys::build_authorized_keys(&opts.extra_keys)?;
    let key_count = auth_keys_content.lines().count();
    println!("  authorized_keys: {} key(s)", key_count);

    // Load AI usage guide from disk (next to binary, or data dir, or docs/)
    let ai_usage = find_ai_usage_md();

    let install_script = if is_windows {
        windows::generate_windows_script(opts.port, &opts.nas_auth)
    } else {
        linux::generate_linux_script(opts.port)
    };
    let script_name = if is_windows {
        "install.bat"
    } else {
        "install.sh"
    };
    println!("  {}: service install", script_name);

    // Optional files
    let startup_bat = if is_windows {
        opts.nas_auth.as_ref().map(|nas| {
            println!("  startup.bat: NAS auth at service start");
            format!("@echo off\r\n{}\r\n", nas)
        })
    } else {
        None
    };

    let config_content = if let Some(ref group_name) = opts.group {
        let rdv_server = opts
            .rendezvous_server
            .as_deref()
            .unwrap_or("localhost:21116");
        let token = keys::load_or_create_group_token(group_name)?;

        use sha2::{Digest, Sha256};
        let group_hash = {
            let mut h = Sha256::new();
            h.update(token.as_bytes());
            hex::encode(h.finalize())
        };

        // Include RendezvousKey from local config (needed for relay auth)
        let local_config = mrsh_core::config::Config::load();
        let rdv_key_line = if let Some(ref key) = local_config.rendezvous_key {
            format!("RendezvousKey {key}\n")
        } else {
            String::new()
        };

        let content = format!(
            "# mrsh fleet enrollment config (auto-generated)\n\
             RendezvousServer {rdv_server}\n\
             {rdv_key_line}\
             EnrollmentToken {token}\n\
             GroupHash {group_hash}\n",
        );
        keys::save_group_mapping(group_name, &token)?;
        println!("  config: group={}, rendezvous={}", group_name, rdv_server);
        Some(content)
    } else {
        None
    };

    // Generate single output file
    let out_path = if is_windows {
        windows::generate_nsis_installer(
            opts,
            version,
            &binary_data,
            &auth_keys_content,
            &install_script,
            startup_bat.as_deref(),
            config_content.as_deref(),
            &ai_usage,
        )?
    } else {
        linux::generate_self_extracting_sh(
            opts,
            version,
            &binary_data,
            &auth_keys_content,
            &install_script,
            config_content.as_deref(),
            &ai_usage,
        )?
    };

    let file_size = std::fs::metadata(&out_path)?.len();
    let size_mb = file_size as f64 / 1_048_576.0;
    println!(
        "\nInstall pack ready: {} ({:.1} MB)",
        out_path.display(),
        size_mb
    );

    if is_windows {
        println!("Deploy: copy to target and run as Administrator.");
        println!("The installer extracts, installs the service, and configures the firewall.");
    } else {
        println!("Deploy: copy to target and run:");
        println!(
            "  chmod +x {} && sudo ./{}",
            out_path.display(),
            out_path.display()
        );
    }

    if let Some(ref g) = opts.group {
        println!(
            "Discover enrolled machines with: mrsh fleet discover --group {}",
            g
        );
    }

    Ok(out_path)
}

/// Find the mrsh binary to bundle.
/// Default: use the running binary itself (current_exe). This ensures the
/// installer always bundles the exact version that generated it.
pub(super) fn find_binary(explicit: &Option<PathBuf>, _is_windows: bool) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p.clone());
        }
        bail!("specified binary not found: {}", p.display());
    }

    // Use the running binary — the installer should bundle the same version
    let self_exe = std::env::current_exe().context("get current executable path")?;
    if self_exe.exists() {
        return Ok(self_exe);
    }

    bail!("cannot find mrsh binary. Specify with --binary=PATH");
}

/// Find AI_USAGE.md on disk. Searches: CWD/docs/, exe dir/../docs/, data dirs.
/// Returns content if found, empty string if not (non-fatal — installer works without it).
pub(super) fn find_ai_usage_md() -> String {
    let mut candidates = vec![
        PathBuf::from("docs/AI_USAGE.md"),
        PathBuf::from("AI_USAGE.md"),
    ];

    // Relative to exe (source tree layout: exe in target/release/, docs/ at root)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("../docs/AI_USAGE.md"));
            candidates.push(dir.join("../../docs/AI_USAGE.md"));
            candidates.push(dir.join("AI_USAGE.md"));
        }
    }

    // Platform data directories (where installer puts AI_USAGE.md)
    #[cfg(target_os = "windows")]
    {
        candidates.push(PathBuf::from("C:/ProgramData/mrsh/AI_USAGE.md"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        candidates.push(PathBuf::from("/etc/mrsh/AI_USAGE.md"));
    }
    // User mrsh dir
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".mrsh/AI_USAGE.md"));
    }

    for path in &candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            println!(
                "  AI_USAGE.md: {} bytes (from {})",
                content.len(),
                path.display()
            );
            return content;
        }
    }

    eprintln!("  AI_USAGE.md: not found (installer will skip it)");
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::keys::build_authorized_keys;
    use super::linux::{generate_linux_script, generate_sfx_header};
    use super::nsis::{find_makensis, generate_nsi_script};
    use super::windows::generate_windows_script;

    #[test]
    fn build_authorized_keys_with_extras() {
        let keys = vec!["ssh-ed25519 AAAA testkey".to_string()];
        let result = build_authorized_keys(&keys).unwrap();
        assert!(result.contains("ssh-ed25519 AAAA testkey"));
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn build_authorized_keys_deduplicates() {
        let keys = vec![
            "ssh-ed25519 AAAA key1".to_string(),
            "ssh-ed25519 AAAA key1".to_string(),
        ];
        let result = build_authorized_keys(&keys).unwrap();
        assert_eq!(result.matches("key1").count(), 1);
    }

    #[test]
    fn windows_script_contains_essentials() {
        let script = generate_windows_script(8822, &None);
        assert!(script.contains("net session"));
        assert!(script.contains("mrsh.exe"));
        assert!(script.contains("--install"));
        assert!(script.contains("net start mrsh"));
        assert!(script.contains("netsh advfirewall"));
        assert!(script.contains("ProgramData"));
    }

    /// Fresh-Windows guard: install.bat MUST detect missing VC++ runtime
    /// and silent-install vc_redist.x64.exe BEFORE invoking mrsh.exe.
    /// (rsh-q13 lesson — STATUS_DLL_NOT_FOUND on freshly-imaged hosts.)
    #[test]
    fn windows_script_has_vcrt_check() {
        let script = generate_windows_script(8822, &None);
        assert!(script.contains("vcruntime140.dll"), "must check vcruntime140.dll");
        assert!(script.contains("msvcp140.dll"), "must check msvcp140.dll");
        assert!(script.contains("vc_redist.x64.exe"), "must download vc_redist.x64.exe");
        assert!(
            script.contains("aka.ms/vs/17/release/vc_redist.x64.exe"),
            "must reference canonical Microsoft URL"
        );
        assert!(
            script.contains("/install /quiet /norestart"),
            "must use silent install flags"
        );
        // VC++ check must precede the mrsh.exe copy/install
        let vcrt_pos = script.find("vcruntime140.dll").unwrap();
        let install_pos = script.find("--install").unwrap();
        assert!(
            vcrt_pos < install_pos,
            "VC++ check must run BEFORE mrsh.exe --install"
        );
    }

    /// Tolerance: install.bat MUST NOT abort if `mrsh.exe --install` returns
    /// non-zero exit code AS LONG AS `sc query mrsh` confirms the service is
    /// registered. The truth source is service-state, not exit-code.
    #[test]
    fn windows_script_tolerates_install_nonzero_when_service_registered() {
        let script = generate_windows_script(8822, &None);
        assert!(
            script.contains("INSTALL_EXIT"),
            "must capture --install exit code into a variable"
        );
        assert!(
            script.contains("TOLERATED"),
            "must log 'TOLERATED' when --install exit non-zero but service registered"
        );
        // After --install, sc query must run BEFORE deciding to abort
        let install_pos = script.find("--install >> ").unwrap();
        let sc_query_pos = script[install_pos..]
            .find("sc query mrsh")
            .map(|p| install_pos + p)
            .expect("sc query mrsh must appear after --install");
        let abort_pos = script[install_pos..]
            .find("exit /b 1")
            .map(|p| install_pos + p);
        if let Some(abort) = abort_pos {
            assert!(
                sc_query_pos < abort,
                "sc query mrsh must run before any 'exit /b 1' after --install"
            );
        }
    }

    /// Robust start: install.bat MUST fall back to `sc start mrsh` when
    /// `net start mrsh` doesn't reach RUNNING (handles NEVER_STARTED, 1077),
    /// then poll until RUNNING (or timeout).
    #[test]
    fn windows_script_has_sc_start_fallback_and_poll() {
        let script = generate_windows_script(8822, &None);
        assert!(script.contains("sc start mrsh"), "must include sc start fallback");
        assert!(
            script.contains(":wait_running"),
            "must include polling loop label :wait_running"
        );
        assert!(
            script.contains(":running"),
            "must include success label :running"
        );
        assert!(
            script.contains(":not_running"),
            "must include timeout label :not_running"
        );
        // sc start fallback must appear AFTER net start
        let net_start_pos = script.find("net start mrsh >> ").unwrap();
        let sc_start_pos = script.find("sc start mrsh").unwrap();
        assert!(
            sc_start_pos > net_start_pos,
            "sc start mrsh must be a fallback AFTER net start"
        );
    }

    #[test]
    fn windows_script_includes_startup_bat() {
        let script = generate_windows_script(8822, &Some("net use \\\\nas\\share".to_string()));
        assert!(script.contains("startup.bat"));
    }

    #[test]
    fn linux_script_contains_essentials() {
        let script = generate_linux_script(8822);
        assert!(script.contains("id -u"));
        assert!(script.contains("install -m 755"));
        assert!(script.contains("--install"));
        assert!(script.contains("systemctl enable"));
        assert!(script.contains("/etc/mrsh"));
    }

    #[test]
    fn sfx_header_has_archive_marker() {
        let header = generate_sfx_header("5.13.0", 8822);
        assert!(header.contains("__ARCHIVE_BELOW__"));
        assert!(header.starts_with("#!/bin/bash"));
        assert!(header.contains("tar xzf"));
    }

    #[test]
    fn generate_linux_sfx() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("test-install.sh");
        let fake_bin = dir.path().join("mrsh");
        std::fs::write(&fake_bin, b"fake-binary-content").unwrap();

        let opts = InstallPackOptions {
            platform: "linux".to_string(),
            output: Some(out.clone()),
            binary: Some(fake_bin),
            extra_keys: vec!["ssh-ed25519 AAAA testkey".to_string()],
            port: 8822,
            nas_auth: None,
            group: None,
            rendezvous_server: None,
        };

        let result = generate(&opts).unwrap();
        assert_eq!(result, out);
        assert!(out.exists());

        // Verify it starts with shebang
        let content = std::fs::read(&out).unwrap();
        assert!(content.starts_with(b"#!/bin/bash"));
        // Verify it contains the archive marker
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("__ARCHIVE_BELOW__"));
    }

    #[test]
    fn nsi_script_has_required_sections() {
        let script = generate_nsi_script("5.15.0", 8822, false, false);
        assert!(script.contains("MUI2.nsh"));
        assert!(script.contains("mrsh 5.15.0"));
        assert!(script.contains("RequestExecutionLevel admin"));
        assert!(script.contains("ProgramData\\mrsh"));
        assert!(script.contains("mrsh.exe"));
        assert!(script.contains("authorized_keys"));
        assert!(script.contains("--install"));
        assert!(script.contains("net start mrsh"));
        assert!(script.contains("netsh advfirewall"));
        assert!(script.contains("8822"));
    }

    #[test]
    fn nsi_script_includes_optional_files() {
        let script = generate_nsi_script("5.15.0", 9822, true, true);
        assert!(script.contains("startup.bat"));
        assert!(script.contains("config"));
        assert!(script.contains("9822"));
    }

    #[test]
    fn nsi_script_excludes_optional_files_when_absent() {
        let script = generate_nsi_script("5.15.0", 8822, false, false);
        assert!(!script.contains("startup.bat"));
        // "config" appears in other contexts (like "Installing"), check File directive
        assert!(!script.contains("File \"${SRCDIR}\\config\""));
    }

    #[test]
    fn nsis_installer_e2e() {
        // Skip if makensis not available
        if find_makensis().is_err() {
            eprintln!("skipping nsis_installer_e2e: makensis not found");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("test-install.exe");
        let fake_bin = dir.path().join("mrsh.exe");
        std::fs::write(&fake_bin, b"fake-windows-binary").unwrap();

        let opts = InstallPackOptions {
            platform: "windows".to_string(),
            output: Some(out.clone()),
            binary: Some(fake_bin),
            extra_keys: vec!["ssh-ed25519 AAAA winkey".to_string()],
            port: 9822,
            nas_auth: Some("net use \\\\nas\\share /user:dom\\usr pass".to_string()),
            group: None,
            rendezvous_server: None,
        };

        let result = generate(&opts).unwrap();
        assert_eq!(result, out);
        assert!(out.exists());

        // NSIS installer should be a valid PE (starts with MZ)
        let data = std::fs::read(&out).unwrap();
        assert!(
            data.len() > 100,
            "installer too small: {} bytes",
            data.len()
        );
        assert_eq!(&data[0..2], b"MZ", "not a valid PE executable");
    }
}
