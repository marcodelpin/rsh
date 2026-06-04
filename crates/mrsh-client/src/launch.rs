//! `mrsh launch <app> [args...]` — auto-route GUI app launch on Windows targets.
//!
//! Encapsulates the pattern documented in skill `/prodmaster-trace-error` Step 0
//! and `mrsh --help` PORT SELECTION GUIDE: WPF/Win32 GUI apps cannot render in
//! SYSTEM session 0 (port 8822 service). They need an Interactive Token in the
//! logged-in user's session.
//!
//! The cascade runs SERVER-SIDE in a single shell call, so we only need one
//! connection (whatever port the user passed via -p, or auto-detected):
//!
//!   1] try `Start-Process -PassThru` — fastest path
//!   2] fallback `schtasks /Create /TN <name> /TR <app> /SC ONCE /ST <t> /IT /F`
//!      then `schtasks /Run /TN <name>` — Interactive Token forces user session
//!   3] verify a process matching `[io.path]::GetFileNameWithoutExtension(app)`
//!      is running, return PID; else error
//!
//! Replaces ad-hoc `schtasks /Create /RL LIMITED` patterns that fail silently
//! in session 0 (Steeljobs incident 2026-05-08 session a592c97c — agent burned
//! 8 minutes before realizing /RL LIMITED has no desktop access).

use anyhow::{anyhow, Result};

/// Validate the server stdout from running the launch cascade. Returns the
/// trimmed line on success (e.g. `method=start-process pid=12345`).
pub fn parse_launch_output(output: &str) -> Result<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("mrsh launch: server returned empty output"));
    }
    if !trimmed.contains("method=") {
        return Err(anyhow!("mrsh launch failed: {}", trimmed));
    }
    Ok(trimmed.to_string())
}

/// Build the PowerShell script that runs the launch cascade on the remote.
///
/// The `app` is passed as-is (caller is responsible for path-form: full path or
/// PATH-resolvable basename). `app_args` is the argument list — each element is
/// PowerShell-quoted with single quotes (internal `'` doubled per PS rules).
///
/// The script writes one line on success: `method=<start-process|schtasks-IT> pid=<n>[ task=<name>]`.
/// On failure it returns non-zero exit and prints the failure reasons to stderr.
pub fn build_launch_script(app: &str, app_args: &[String]) -> String {
    // PowerShell single-quote escape: ' -> ''
    let q = |s: &str| format!("'{}'", s.replace('\'', "''"));

    // Build $args array literal: @('a','b','c') or @() if empty
    let args_array = if app_args.is_empty() {
        "@()".to_string()
    } else {
        let parts: Vec<String> = app_args.iter().map(|a| q(a)).collect();
        format!("@({})", parts.join(","))
    };

    // For schtasks /TR we build a single command-line string. The PS variable
    // $Tr will be assigned via SINGLE-quoted PS string (so " is literal, no
    // PS escaping needed). Single-quote in source (rare in paths) is escaped
    // by doubling per PS rules.
    let mut tr_parts: Vec<String> = Vec::with_capacity(1 + app_args.len());
    tr_parts.push(format!("\"{}\"", app));
    for a in app_args {
        if a.contains(' ') || a.contains('\t') {
            tr_parts.push(format!("\"{}\"", a));
        } else {
            tr_parts.push(a.clone());
        }
    }
    let tr_inner = tr_parts.join(" ");
    let tr_value = tr_inner.replace('\'', "''");

    format!(
        r#"$ErrorActionPreference = 'Stop'
$App = {app_q}
$AppArgs = {args_array}
try {{
    $proc = if ($AppArgs.Count -gt 0) {{
        Start-Process -FilePath $App -ArgumentList $AppArgs -PassThru
    }} else {{
        Start-Process -FilePath $App -PassThru
    }}
    Write-Output "method=start-process pid=$($proc.Id)"
    exit 0
}} catch {{
    Write-Warning "Start-Process failed: $_"
}}
$T = "MrshLaunch_$(Get-Random -Maximum 99999)"
$S = (Get-Date).AddSeconds(2).ToString("HH:mm")
$Tr = '{tr_value}'
$null = schtasks /Create /TN $T /TR $Tr /SC ONCE /ST $S /IT /F 2>&1
$rc1 = $LASTEXITCODE
if ($rc1 -ne 0) {{ Write-Error "schtasks /Create failed (exit $rc1)"; exit 1 }}
$null = schtasks /Run /TN $T 2>&1
$rc2 = $LASTEXITCODE
Start-Sleep -Seconds 3
$exe = [io.path]::GetFileNameWithoutExtension($App)
$proc = Get-Process -Name $exe -ErrorAction SilentlyContinue | Select-Object -First 1
$null = schtasks /Delete /TN $T /F 2>&1
if ($proc) {{
    Write-Output "method=schtasks-IT pid=$($proc.Id) task=$T"
    exit 0
}} else {{
    Write-Error "schtasks /Run completed (exit $rc2) but no process matching '$exe' found after 3s"
    exit 1
}}
"#,
        app_q = q(app),
        args_array = args_array,
        tr_value = tr_value,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_script_no_args() {
        let s = build_launch_script("C:\\ProdMaster\\ProdMaster.exe", &[]);
        assert!(s.contains("$App = 'C:\\ProdMaster\\ProdMaster.exe'"));
        assert!(s.contains("$AppArgs = @()"));
        assert!(s.contains("Start-Process -FilePath $App -PassThru"));
        assert!(s.contains("schtasks /Create /TN $T /TR $Tr /SC ONCE /ST $S /IT /F"));
    }

    #[test]
    fn build_script_with_args() {
        let s = build_launch_script(
            "notepad.exe",
            &["readme.txt".to_string(), "-encoding".to_string(), "utf8".to_string()],
        );
        assert!(s.contains("$AppArgs = @('readme.txt','-encoding','utf8')"));
    }

    #[test]
    fn build_script_escapes_single_quote() {
        let s = build_launch_script("C:\\app's\\thing.exe", &["it's me".to_string()]);
        assert!(s.contains("$App = 'C:\\app''s\\thing.exe'"));
        assert!(s.contains("$AppArgs = @('it''s me')"));
    }

    #[test]
    fn build_script_arg_with_spaces_quoted_in_tr() {
        let s = build_launch_script("app.exe", &["arg with spaces".to_string()]);
        assert!(s.contains("\"arg with spaces\""));
    }

    #[test]
    fn parse_output_success_start_process() {
        let r = parse_launch_output("method=start-process pid=12345\n").unwrap();
        assert_eq!(r, "method=start-process pid=12345");
    }

    #[test]
    fn parse_output_success_schtasks() {
        let r = parse_launch_output("method=schtasks-IT pid=999 task=MrshLaunch_42").unwrap();
        assert!(r.contains("method=schtasks-IT"));
    }

    #[test]
    fn parse_output_empty_fails() {
        assert!(parse_launch_output("").is_err());
        assert!(parse_launch_output("   \n").is_err());
    }

    #[test]
    fn parse_output_no_method_fails() {
        let e = parse_launch_output("WARN: tray down").unwrap_err();
        assert!(format!("{}", e).contains("mrsh launch failed"));
    }
}
