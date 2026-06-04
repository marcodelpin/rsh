//! Windows installer generation: NSIS .exe + install.bat script.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use super::InstallPackOptions;
use super::nsis::{find_makensis, generate_nsi_script};

/// Generate an NSIS-based Windows installer (.exe).
///
/// Requires `makensis` (NSIS compiler) on the build host.
/// Install on Ubuntu: `apt install nsis`
pub(super) fn generate_nsis_installer(
    opts: &InstallPackOptions,
    version: &str,
    binary_data: &[u8],
    auth_keys: &str,
    install_script: &str,
    startup_bat: Option<&str>,
    config: Option<&str>,
    ai_usage: &str,
) -> Result<PathBuf> {
    let out_path = match &opts.output {
        Some(p) => p.clone(),
        None => PathBuf::from(format!("mrsh-{}-windows-install.exe", version)),
    };

    // Verify makensis is available
    let makensis = find_makensis()?;

    // Create temp directory with all files to embed
    let tmp = tempfile::tempdir().context("create temp dir for NSIS")?;
    let src_dir = tmp.path();

    std::fs::write(src_dir.join("mrsh.exe"), binary_data).context("write mrsh.exe to temp")?;
    std::fs::write(src_dir.join("authorized_keys"), auth_keys.as_bytes())
        .context("write authorized_keys to temp")?;
    if !ai_usage.is_empty() {
        std::fs::write(src_dir.join("AI_USAGE.md"), ai_usage.as_bytes())
            .context("write AI_USAGE.md to temp")?;
    }
    std::fs::write(src_dir.join("install.bat"), install_script.as_bytes())
        .context("write install.bat to temp")?;

    if let Some(startup) = startup_bat {
        std::fs::write(src_dir.join("startup.bat"), startup.as_bytes())
            .context("write startup.bat to temp")?;
    }
    if let Some(cfg) = config {
        std::fs::write(src_dir.join("config"), cfg.as_bytes()).context("write config to temp")?;
    }

    // Generate .nsi script
    let has_startup = startup_bat.is_some();
    let has_config = config.is_some();
    let nsi_script = generate_nsi_script(version, opts.port, has_startup, has_config);
    let nsi_path = src_dir.join("installer.nsi");
    std::fs::write(&nsi_path, &nsi_script).context("write installer.nsi")?;

    // Resolve absolute output path before invoking makensis
    let abs_out = if out_path.is_absolute() {
        out_path.clone()
    } else {
        std::env::current_dir()?.join(&out_path)
    };

    // Run makensis
    println!("  nsis: compiling installer...");
    let status = std::process::Command::new(&makensis)
        .arg("-V2")
        .arg(format!("-DOUTFILE={}", abs_out.display()))
        .arg(format!("-DSRCDIR={}", src_dir.display()))
        .arg(&nsi_path)
        .status()
        .with_context(|| format!("run {}", makensis.display()))?;

    if !status.success() {
        bail!("makensis failed with exit code: {:?}", status.code());
    }

    if !abs_out.exists() {
        bail!(
            "makensis succeeded but output not found: {}",
            abs_out.display()
        );
    }

    Ok(out_path)
}

/// Generate Windows install.bat script.
pub(super) fn generate_windows_script(port: u16, nas_auth: &Option<String>) -> String {
    let mut script = String::from("@echo off\r\n");
    script.push_str("setlocal enabledelayedexpansion\r\n");
    // Log every step to a file alongside the console — enables postmortem when
    // the operator closes the window before reading errors (rsh-q13).
    script.push_str("set \"LOGFILE=%~dp0install.log\"\r\n");
    script.push_str("> \"%LOGFILE%\" echo === mrsh install.bat ===\r\n");
    script.push_str(&format!(
        ">> \"%LOGFILE%\" echo Version: {}\r\n",
        env!("CARGO_PKG_VERSION")
    ));
    script.push_str(&format!(">> \"%LOGFILE%\" echo Port: {}\r\n", port));
    script.push_str(">> \"%LOGFILE%\" echo Started: %date% %time%\r\n");
    script.push_str(">> \"%LOGFILE%\" echo CWD: %~dp0\r\n");
    script.push_str(">> \"%LOGFILE%\" echo User: %USERNAME%@%COMPUTERNAME%\r\n");
    script.push_str(">> \"%LOGFILE%\" echo.\r\n\r\n");

    script.push_str("echo === mrsh Installer ===\r\n");
    script.push_str("echo.\r\n");
    script.push_str(&format!("echo Version: {}\r\n", env!("CARGO_PKG_VERSION")));
    script.push_str(&format!("echo Port: {}\r\n", port));
    script.push_str("echo Log: %LOGFILE%\r\n");
    script.push_str("echo.\r\n\r\n");

    // Auto-elevate via UAC if not already admin.
    // This avoids the silent-failure mode where the operator double-clicks
    // install.bat (running unprivileged), the script exits with "ERROR: Run
    // as administrator", and they close the window thinking it's done.
    script.push_str("net session >nul 2>&1\r\n");
    script.push_str("if %errorlevel% neq 0 (\r\n");
    script.push_str("    echo Not running as administrator — relaunching with UAC prompt...\r\n");
    script.push_str(">> \"%LOGFILE%\" echo NOT-ADMIN: requesting UAC elevation\r\n");
    // PowerShell Start-Process -Verb RunAs triggers UAC; the new cmd window
    // receives the same arguments and the same CWD via /d.
    script.push_str(
        "    powershell -NoProfile -Command \"Start-Process -FilePath '%COMSPEC%' \
         -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs\" 2>>\"%LOGFILE%\"\r\n",
    );
    script.push_str("    if errorlevel 1 (\r\n");
    script.push_str("        echo ERROR: UAC elevation refused or PowerShell unavailable.\r\n");
    script.push_str("        echo Run install.bat manually as Administrator.\r\n");
    script.push_str(">>     \"%LOGFILE%\" echo UAC-FAIL: elevation denied or PowerShell missing\r\n");
    script.push_str("        pause\r\n");
    script.push_str("        exit /b 1\r\n");
    script.push_str("    )\r\n");
    script.push_str("    exit /b 0\r\n");
    script.push_str(")\r\n");
    script.push_str(">> \"%LOGFILE%\" echo OK: running as Administrator\r\n");
    script.push_str("echo Running as Administrator.\r\n\r\n");

    // ── VC++ runtime check (fresh-Windows guard) ───────────────
    // Rust MSVC builds depend on vcruntime140.dll + msvcp140.dll. On freshly-
    // imaged Windows hosts these are absent and mrsh.exe fails to load with
    // STATUS_DLL_NOT_FOUND (0xC0000135) before any code runs. Detect missing
    // CRT and silent-install the redistributable (rsh-q13 lesson).
    script.push_str("echo Checking VC++ runtime...\r\n");
    script.push_str(">> \"%LOGFILE%\" echo Step: VC++ runtime check\r\n");
    script.push_str("set VCRT_OK=1\r\n");
    script.push_str("if not exist \"%SystemRoot%\\System32\\vcruntime140.dll\" set VCRT_OK=0\r\n");
    script.push_str("if not exist \"%SystemRoot%\\System32\\msvcp140.dll\" set VCRT_OK=0\r\n");
    script.push_str("if \"%VCRT_OK%\"==\"0\" (\r\n");
    script.push_str("    echo VC++ runtime missing - downloading and installing redist...\r\n");
    script.push_str(">> \"%LOGFILE%\" echo VCRT-MISSING: downloading vc_redist.x64.exe\r\n");
    script.push_str("    set \"VCREDIST=%TEMP%\\vc_redist.x64.exe\"\r\n");
    script.push_str(
        "    powershell -NoProfile -Command \"\
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' \
-OutFile $env:VCREDIST -UseBasicParsing\" 2>>\"%LOGFILE%\"\r\n",
    );
    script.push_str("    if not exist \"%VCREDIST%\" (\r\n");
    script.push_str("        echo ERROR: VC++ redist download failed.\r\n");
    script.push_str("        echo Download manually: https://aka.ms/vs/17/release/vc_redist.x64.exe\r\n");
    script.push_str(">>     \"%LOGFILE%\" echo VCRT-DL-FAIL: download failed\r\n");
    script.push_str("        pause\r\n");
    script.push_str("        exit /b 1\r\n");
    script.push_str("    )\r\n");
    script.push_str(">> \"%LOGFILE%\" echo OK: redist downloaded, installing silent\r\n");
    script.push_str("    \"%VCREDIST%\" /install /quiet /norestart >> \"%LOGFILE%\" 2>&1\r\n");
    script.push_str("    set VC_EXIT=!errorlevel!\r\n");
    script.push_str(">> \"%LOGFILE%\" echo VCRT-INSTALL: exit !VC_EXIT!\r\n");
    // 0 = success, 3010 = success but reboot required (still proceed)
    script.push_str("    if !VC_EXIT! neq 0 if !VC_EXIT! neq 3010 (\r\n");
    script.push_str("        echo ERROR: VC++ redist install failed (exit !VC_EXIT!).\r\n");
    script.push_str(">>     \"%LOGFILE%\" echo VCRT-INSTALL-FAIL: exit !VC_EXIT!\r\n");
    script.push_str("        pause\r\n");
    script.push_str("        exit /b 1\r\n");
    script.push_str("    )\r\n");
    script.push_str("    if not exist \"%SystemRoot%\\System32\\vcruntime140.dll\" (\r\n");
    script.push_str("        echo ERROR: vcruntime140.dll still missing after redist install.\r\n");
    script.push_str(">>     \"%LOGFILE%\" echo VCRT-VERIFY-FAIL: dll absent post-install\r\n");
    script.push_str("        pause\r\n");
    script.push_str("        exit /b 1\r\n");
    script.push_str("    )\r\n");
    script.push_str(">> \"%LOGFILE%\" echo OK: VC++ runtime now present\r\n");
    script.push_str("    echo VC++ runtime installed.\r\n");
    script.push_str(") else (\r\n");
    script.push_str(">> \"%LOGFILE%\" echo OK: VC++ runtime already present\r\n");
    script.push_str("    echo VC++ runtime present.\r\n");
    script.push_str(")\r\n\r\n");

    let data_dir = r"C:\ProgramData\mrsh";
    // Stop everything and clean up before installing
    script.push_str("echo Stopping all services...\r\n");
    script.push_str("net stop mrsh >nul 2>&1\r\n");
    script.push_str("net stop rsh >nul 2>&1\r\n");
    script.push_str("sc delete rsh >nul 2>&1\r\n");
    script.push_str("sc delete mrsh >nul 2>&1\r\n");
    script.push_str("taskkill /F /IM mrsh.exe >nul 2>&1\r\n");
    script.push_str("taskkill /F /IM rsh.exe >nul 2>&1\r\n");
    script.push_str("timeout /t 3 /nobreak >nul\r\n\r\n");

    script.push_str(&format!(
        "if not exist \"{}\" mkdir \"{}\"\r\n",
        data_dir, data_dir
    ));

    // Remove old rsh.exe from mrsh dir (legacy rename artifact)
    script.push_str(&format!("del /q \"{}\\rsh.exe\" >nul 2>&1\r\n", data_dir));
    script.push_str(&format!(
        "del /q \"{}\\rsh.exe.bak\" >nul 2>&1\r\n\r\n",
        data_dir
    ));

    script.push_str(&format!(
        "copy /Y \"%~dp0mrsh.exe\" \"{}\\mrsh.exe\"\r\n",
        data_dir
    ));
    // Merge new keys with existing authorized_keys (never overwrite/lose existing keys)
    script.push_str(&format!(
        "if exist \"{}\\authorized_keys\" (\r\n\
         \x20   echo Merging authorized_keys...\r\n\
         \x20   for /f \"usebackq delims=\" %%L in (\"%~dp0authorized_keys\") do (\r\n\
         \x20       findstr /x /c:\"%%L\" \"{}\\authorized_keys\" >nul 2>&1 || echo %%L>>\"{}\\authorized_keys\"\r\n\
         \x20   )\r\n\
         ) else (\r\n\
         \x20   copy /Y \"%~dp0authorized_keys\" \"{}\\authorized_keys\"\r\n\
         )\r\n",
        data_dir, data_dir, data_dir, data_dir
    ));

    // Copy AI usage guide
    script.push_str(&format!(
        "if exist \"%~dp0AI_USAGE.md\" copy /Y \"%~dp0AI_USAGE.md\" \"{}\\AI_USAGE.md\"\r\n",
        data_dir
    ));

    if nas_auth.is_some() {
        script.push_str(&format!(
            "if exist \"%~dp0startup.bat\" copy /Y \"%~dp0startup.bat\" \"{}\\startup.bat\"\r\n",
            data_dir
        ));
    }

    script.push_str(&format!(
        "if exist \"%~dp0config\" copy /Y \"%~dp0config\" \"{}\\config\"\r\n",
        data_dir
    ));

    script.push_str("echo.\r\n");
    script.push_str("echo Files copied.\r\n\r\n");

    script.push_str(">> \"%LOGFILE%\" echo Step: register service via mrsh.exe --install\r\n");
    script.push_str(&format!(
        "\"{}\\mrsh.exe\" --install >> \"%LOGFILE%\" 2>&1\r\n",
        data_dir
    ));
    script.push_str("set INSTALL_EXIT=%errorlevel%\r\n");
    script.push_str(">> \"%LOGFILE%\" echo --install exit code: %INSTALL_EXIT%\r\n");
    // Tolerate non-zero exit from --install IF the service is actually registered
    // (the install_service code path occasionally returns non-zero from a
    // post-success step like icacls/firewall on freshly-provisioned hosts; the
    // service is still correctly registered. Truth source = `sc query mrsh`).
    script.push_str("sc query mrsh >nul 2>&1\r\n");
    script.push_str("if %errorlevel% neq 0 (\r\n");
    script.push_str("    echo ERROR: Service 'mrsh' not registered (mrsh.exe --install exit %INSTALL_EXIT%).\r\n");
    script.push_str("    echo See %LOGFILE% for details.\r\n");
    script.push_str(">> \"%LOGFILE%\" echo FAIL: sc query mrsh after --install returned non-zero\r\n");
    script.push_str("    pause\r\n");
    script.push_str("    exit /b 1\r\n");
    script.push_str(")\r\n");
    script.push_str("if %INSTALL_EXIT% neq 0 (\r\n");
    script.push_str(">> \"%LOGFILE%\" echo TOLERATED: --install exit %INSTALL_EXIT% but service IS registered\r\n");
    script.push_str("    echo Service registered (mrsh.exe --install returned %INSTALL_EXIT%, but sc query confirms registration).\r\n");
    script.push_str(") else (\r\n");
    script.push_str(">> \"%LOGFILE%\" echo OK: --install completed cleanly\r\n");
    script.push_str(")\r\n\r\n");

    // Start service: try `net start` first, fall back to `sc start` (handles
    // the NEVER_STARTED state, Win32 1077 / 0x435, that occurs when a previous
    // install left the service registered but never started).
    script.push_str(">> \"%LOGFILE%\" echo Step: start service\r\n");
    script.push_str("net start mrsh >> \"%LOGFILE%\" 2>&1\r\n");
    script.push_str("set NETSTART_EXIT=%errorlevel%\r\n");
    script.push_str(">> \"%LOGFILE%\" echo net start mrsh exit: %NETSTART_EXIT%\r\n");
    script.push_str("sc query mrsh | findstr /c:\"RUNNING\" >nul\r\n");
    script.push_str("if errorlevel 1 (\r\n");
    script.push_str(">> \"%LOGFILE%\" echo NET-START-NO-RUNNING: trying sc start mrsh fallback\r\n");
    script.push_str("    echo Trying sc start fallback...\r\n");
    script.push_str("    sc start mrsh >> \"%LOGFILE%\" 2>&1\r\n");
    script.push_str(">> \"%LOGFILE%\" echo sc start mrsh exit: !errorlevel!\r\n");
    script.push_str(")\r\n");
    // Poll for RUNNING up to 15s
    script.push_str("set RUN_TRIES=0\r\n");
    script.push_str(":wait_running\r\n");
    script.push_str("sc query mrsh | findstr /c:\"RUNNING\" >nul\r\n");
    script.push_str("if not errorlevel 1 goto :running\r\n");
    script.push_str("set /a RUN_TRIES=RUN_TRIES+1\r\n");
    script.push_str("if %RUN_TRIES% geq 15 goto :not_running\r\n");
    script.push_str("timeout /t 1 /nobreak >nul 2>&1\r\n");
    script.push_str("goto :wait_running\r\n");
    script.push_str(":not_running\r\n");
    script.push_str("    echo WARN: service not RUNNING after 15s (see %LOGFILE%).\r\n");
    script.push_str(">> \"%LOGFILE%\" echo WARN: service not RUNNING after 15s poll\r\n");
    script.push_str("    sc query mrsh >> \"%LOGFILE%\" 2>&1\r\n");
    script.push_str("    goto :start_done\r\n");
    script.push_str(":running\r\n");
    script.push_str(">> \"%LOGFILE%\" echo OK: service RUNNING\r\n");
    script.push_str("    echo Service mrsh RUNNING.\r\n");
    script.push_str(":start_done\r\n");
    script.push_str("echo.\r\n\r\n");

    script.push_str(&format!(
        "netsh advfirewall firewall add rule name=\"mrsh\" dir=in action=allow \
         program=\"{}\\mrsh.exe\" enable=yes >nul 2>&1\r\n",
        data_dir
    ));
    script.push_str(
        "netsh advfirewall firewall add rule name=\"mrsh-ports\" dir=in action=allow \
         protocol=TCP localport=8822,9822 profile=any >nul 2>&1\r\n",
    );
    script.push_str("echo Firewall rules added.\r\n\r\n");

    // Legacy cleanup
    script.push_str("if exist C:\\ProgramData\\remote-shell (\r\n");
    script.push_str("    echo Cleaning up legacy directory...\r\n");
    script.push_str(&format!(
        "    xcopy /E /I /Y C:\\ProgramData\\remote-shell\\cache \"{}\\cache\" >nul 2>&1\r\n",
        data_dir
    ));
    script.push_str(&format!(
        "    xcopy /E /I /Y C:\\ProgramData\\remote-shell\\sessions \"{}\\sessions\" >nul 2>&1\r\n",
        data_dir
    ));
    script.push_str(&format!(
        "    copy /Y C:\\ProgramData\\remote-shell\\banner.txt \"{}\\banner.txt\" >nul 2>&1\r\n",
        data_dir
    ));
    script.push_str(&format!(
        "    copy /Y C:\\ProgramData\\remote-shell\\screen-token \"{}\\screen-token\" >nul 2>&1\r\n", data_dir));
    script.push_str("    sc delete rsh >nul 2>&1\r\n");
    script.push_str("    rmdir /s /q C:\\ProgramData\\remote-shell\r\n");
    script.push_str("    echo Legacy directory removed.\r\n");
    script.push_str(")\r\n\r\n");

    // Launch tray in user session (start /b = background, no new window)
    script.push_str(&format!(
        "start \"\" \"{}\\mrsh.exe\" --tray\r\n\r\n",
        data_dir
    ));

    // rsh-yc9: post-install smoke test (wait for listener + verify connectivity)
    script.push_str("echo === Smoke test ===\r\n");
    script.push_str(&format!(
        "powershell -NoProfile -Command \"$ok = $false; for ($i=0; $i -lt 10; $i++) {{ if (Get-NetTCPConnection -LocalPort {} -State Listen -ErrorAction SilentlyContinue) {{ $ok = $true; break }}; Start-Sleep 1 }}; if ($ok) {{ Write-Host 'OK: listener bound on port {}' }} else {{ Write-Host 'FAIL: no listener on port {} after 10s'; exit 1 }}\"\r\n",
        port, port, port
    ));
    script.push_str(&format!(
        "powershell -NoProfile -Command \"$conns = Get-NetTCPConnection -LocalPort {} -State Listen -ErrorAction SilentlyContinue; $addrs = $conns | Select-Object -ExpandProperty LocalAddress -Unique; Write-Host ('Listening on: ' + ($addrs -join ', '))\"\r\n",
        port
    ));
    script.push_str(&format!(
        "powershell -NoProfile -Command \"$r = Test-NetConnection -ComputerName 127.0.0.1 -Port {} -WarningAction SilentlyContinue; if ($r.TcpTestSucceeded) {{ Write-Host 'OK: 127.0.0.1:{} reachable' }} else {{ Write-Host 'FAIL: 127.0.0.1:{} not reachable' }}\"\r\n",
        port, port, port
    ));
    script.push_str("echo.\r\n");

    script.push_str("echo === Installation complete ===\r\n");
    script.push_str(&format!("echo mrsh is now listening on port {}.\r\n", port));
    script.push_str("echo You can connect from the source machine with:\r\n");
    script.push_str("echo   mrsh -h <this-machine-ip> ping\r\n");
    script.push_str("echo.\r\n");
    script.push_str("pause\r\n");

    script
}
