//! QUIC transport dispatch (experimental, requires `--features quic`).
//!
//! Mirrors the TLS path in `dispatch_client` but routes every command through
//! a `QuicClient` instead of `AnyClient`. PowerShell-equivalent commands are
//! synthesised inline (info, ps, kill, screenshot, ...) because the QUIC
//! protocol layer is intentionally thin and only exposes exec/push/pull/ls.

#![cfg(feature = "quic")]

use anyhow::{Context, Result, bail};

use crate::cli::Cli;
use crate::streaming::handle_quic_socks5_conn;

pub(crate) async fn run(
    cli: &Cli,
    args: &[String],
    cmd: &str,
    resolved_host: &str,
    resolved_port: u16,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:{}", resolved_host, resolved_port)
        .to_socket_addrs()
        .context("resolve host")?
        .next()
        .with_context(|| format!("no address for {}", resolved_host))?;

    let quic = mrsh_client::quic::QuicClient::connect(addr, resolved_host, cli.key.as_deref())
        .await
        .context("QUIC connect")?;

    // ── QUIC SOCKS5 (-D flag) ─────────────────────────────
    if let Some(socks_port) = cli.dynamic_port {
        use std::sync::Arc;
        use tokio::net::TcpListener;

        eprintln!(
            "SOCKS5 proxy (QUIC): 127.0.0.1:{} → {}:{}",
            socks_port, resolved_host, resolved_port
        );

        let quic = Arc::new(quic);
        let bind_addr = format!("127.0.0.1:{}", socks_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("SOCKS5: bind {}", bind_addr))?;
        eprintln!("SOCKS5 proxy listening on {}", bind_addr);

        loop {
            let (client_stream, peer) = listener.accept().await?;
            client_stream.set_nodelay(true).ok();
            let quic = Arc::clone(&quic);

            tokio::spawn(async move {
                if let Err(e) = handle_quic_socks5_conn(client_stream, &quic).await {
                    tracing::debug!("SOCKS5/QUIC: {} error: {}", peer, e);
                }
            });
        }
    }

    match cmd {
        "ping" => {
            println!("PONG (QUIC)");
        }
        "exec" => {
            if args.len() < 2 {
                bail!("exec requires a command");
            }
            let command = args[1..].join(" ");
            let output = quic.exec(&command).await?;
            print!("{}", output);
        }
        "push" => {
            if args.len() < 3 {
                bail!("push requires <local> <remote>");
            }
            let data = std::fs::read(&args[1])?;
            let written = quic.push(&args[2], &data).await?;
            println!("pushed {} bytes to {}", written, args[2]);
        }
        "pull" | "cat" => {
            if args.len() < 2 {
                bail!("{} requires <remote> [local]", cmd);
            }
            let data = quic.pull(&args[1]).await?;
            if cmd == "cat" || args.len() < 3 {
                std::io::Write::write_all(&mut std::io::stdout(), &data)?;
            } else {
                std::fs::write(&args[2], &data)?;
                println!("pulled {} bytes to {}", data.len(), args[2]);
            }
        }
        "ls" => {
            let path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            let files = quic.ls(path).await?;
            for f in &files {
                let kind = if f.is_dir { "d" } else { "-" };
                println!(
                    "{}{} {:>10} {} {}",
                    kind, f.mode, f.size, f.mod_time, f.name
                );
            }
        }
        "tunnel" => {
            if args.len() < 3 {
                bail!("tunnel requires: <local_bind> <remote_host:port>");
            }
            let (local_bind, remote_target) =
                mrsh_client::tunnel::parse_tunnel_spec(&args[1], &args[2])?;
            eprintln!(
                "tunnel (QUIC): {} → {} via {}",
                local_bind, remote_target, resolved_host
            );
            let listener = tokio::net::TcpListener::bind(&local_bind)
                .await
                .with_context(|| format!("bind {}", local_bind))?;
            eprintln!("listening on {}", listener.local_addr()?);
            let (local_stream, peer) = listener.accept().await?;
            local_stream.set_nodelay(true).ok();
            eprintln!("tunnel: local connection from {}", peer);
            let (mut quic_send, mut quic_recv) = quic.open_tunnel(&remote_target).await?;
            let (mut tcp_read, mut tcp_write) = local_stream.into_split();
            tokio::select! {
                _ = tokio::io::copy(&mut quic_recv, &mut tcp_write) => {}
                _ = tokio::io::copy(&mut tcp_read, &mut quic_send) => {}
            }
        }
        "shell" => {
            // Mirror the TLS path: extra args become env vars, --shell adds
            // MRSH_SHELL so the server honors the shell selection.
            let mut env_vars: Vec<String> = args.iter().skip(1).cloned().collect();
            if let Some(ref shell) = cli.shell {
                env_vars.push(format!("MRSH_SHELL={}", shell));
            }
            mrsh_client::shell::run_quic_shell(&quic, &env_vars).await?;
        }
        // ── Fleet ops: route through exec with native-equivalent PowerShell ──
        "info" => {
            let output = quic.exec("[PSCustomObject]@{Hostname=$env:COMPUTERNAME; OS=[Environment]::OSVersion.VersionString; Arch=[Environment]::Is64BitOperatingSystem} | ConvertTo-Json").await?;
            println!("{}", output);
        }
        "ps" => {
            let output = quic.exec("Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet64 | ConvertTo-Json").await?;
            println!("{}", output);
        }
        "kill" => {
            if args.len() < 2 {
                bail!("kill requires a PID");
            }
            let output = quic
                .exec(&format!("Stop-Process -Id {} -Force", args[1]))
                .await?;
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        "tail" => {
            if args.len() < 2 {
                bail!("tail requires <path> [lines]");
            }
            let lines: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            let escaped = args[1].replace('\'', "''");
            let output = quic
                .exec(&format!("Get-Content '{}' -Tail {}", escaped, lines))
                .await?;
            print!("{}", output);
        }
        "filever" => {
            if args.len() < 2 {
                bail!("filever requires <path>");
            }
            let escaped = args[1].replace('\'', "''");
            let output = quic
                .exec(&format!(
                    "(Get-Item '{}').VersionInfo | ConvertTo-Json",
                    escaped
                ))
                .await?;
            println!("{}", output);
        }
        "eventlog" | "evtlog" => {
            let log_name = args.get(1).map(|s| s.as_str()).unwrap_or("System");
            let count: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
            let output = quic.exec(&format!(
                "Get-EventLog -LogName {} -Newest {} | Select-Object TimeGenerated,EntryType,Source,Message | ConvertTo-Json",
                log_name, count
            )).await?;
            println!("{}", output);
        }
        "ss" | "screenshot" => {
            let display: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let quality: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(75);
            // Use PowerShell .NET to capture screen and return base64
            let ps_cmd = format!(
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
                 $s = [System.Windows.Forms.Screen]::AllScreens[{}]; \
                 $b = [System.Drawing.Bitmap]::new($s.Bounds.Width, $s.Bounds.Height); \
                 $g = [System.Drawing.Graphics]::FromImage($b); \
                 $g.CopyFromScreen($s.Bounds.Location, [System.Drawing.Point]::Empty, $s.Bounds.Size); \
                 $ms = [System.IO.MemoryStream]::new(); \
                 $ep = [System.Drawing.Imaging.Encoder]::Quality; \
                 $epc = [System.Drawing.Imaging.EncoderParameters]::new(1); \
                 $epc.Param[0] = [System.Drawing.Imaging.EncoderParameter]::new($ep, [long]{}); \
                 $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object {{ $_.MimeType -eq 'image/jpeg' }}; \
                 $b.Save($ms, $codec, $epc); \
                 [Convert]::ToBase64String($ms.ToArray())",
                display, quality
            );
            let b64_output = quic.exec(&ps_cmd).await?;
            let data = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                b64_output.trim(),
            )
            .context("decode screenshot base64")?;
            let out_path = format!("screenshot_{}.jpg", display);
            std::fs::write(&out_path, &data)?;
            println!("saved {} ({} bytes)", out_path, data.len());
        }
        // ── Clipboard ────────────────────────────────────────────
        "clip" | "clipboard" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("get");
            match action {
                "get" | "read" => {
                    let output = quic.exec("Get-Clipboard").await?;
                    print!("{}", output);
                }
                "set" | "write" | "copy" => {
                    if args.len() < 3 {
                        bail!("clip set requires text");
                    }
                    let text = args[2..].join(" ");
                    let escaped = text.replace('\'', "''");
                    quic.exec(&format!("Set-Clipboard '{}'", escaped)).await?;
                    println!("clipboard set");
                }
                other => bail!("unknown clip action: {} (use get|set)", other),
            }
        }
        // ── Service management ───────────────────────────────────
        "service" | "svc" => {
            if args.len() < 2 {
                bail!("service requires: list|status|start|stop|restart [name]");
            }
            let action = args[1].as_str();
            let name = args.get(2).map(|s| s.as_str());
            let ps_cmd = match (action, name) {
                ("list", _) => {
                    "Get-Service | Select-Object Status,Name,DisplayName | ConvertTo-Json"
                        .to_string()
                }
                ("status", Some(n)) => format!(
                    "Get-Service '{}' | Select-Object Status,Name,DisplayName,StartType | ConvertTo-Json",
                    n
                ),
                ("start", Some(n)) => format!(
                    "Start-Service '{}'; Get-Service '{}' | Select-Object Status,Name | ConvertTo-Json",
                    n, n
                ),
                ("stop", Some(n)) => format!(
                    "Stop-Service '{}' -Force; Get-Service '{}' | Select-Object Status,Name | ConvertTo-Json",
                    n, n
                ),
                ("restart", Some(n)) => format!(
                    "Restart-Service '{}'; Get-Service '{}' | Select-Object Status,Name | ConvertTo-Json",
                    n, n
                ),
                (_, None) => bail!("service {} requires a service name", action),
                (other, _) => bail!(
                    "unknown service action: {} (use list|status|start|stop|restart)",
                    other
                ),
            };
            let output = quic.exec(&ps_cmd).await?;
            println!("{}", output);
        }
        // ── Write file ───────────────────────────────────────────
        "write" => {
            if args.len() < 3 {
                bail!("write requires <remote-path> <content>");
            }
            let content = args[2..].join(" ");
            let written = quic.push(&args[1], content.as_bytes()).await?;
            println!("wrote {} bytes to {}", written, args[1]);
        }
        // ── Self-update ──────────────────────────────────────────
        "self-update" => {
            if args.len() < 2 {
                bail!("self-update requires <remote-binary-path>");
            }
            let escaped = args[1].replace('\'', "''");
            let output = quic
                .exec(&format!(
                    "$src = '{}'; \
                 $exe = (Get-Process -Id $PID).Path; \
                 $bak = $exe + '.old'; \
                 if (Test-Path $bak) {{ Remove-Item $bak -Force }}; \
                 Rename-Item $exe $bak; \
                 Copy-Item $src $exe; \
                 Remove-Item $src -Force; \
                 'OK: restart service to apply'",
                    escaped
                ))
                .await?;
            println!("{}", output);
        }
        // ── GUI automation ───────────────────────────────────────
        "input" | "mouse" | "key" | "window" => {
            if args.len() < 3 {
                bail!("{} requires <action> <args>", cmd);
            }
            // Forward as native exec — server handles via input handler
            let full_cmd = args.join(" ");
            let output = quic.exec(&full_cmd).await?;
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        // ── Power management ─────────────────────────────────────
        "reboot" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Reboot {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            println!("Rebooting {}:{}...", resolved_host, resolved_port);
            quic.exec("Restart-Computer -Force").await.ok();
        }
        "shutdown" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Shutdown {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            println!("Shutting down {}:{}...", resolved_host, resolved_port);
            quic.exec("Stop-Computer -Force").await.ok();
            println!("Shutdown command sent.");
        }
        "sleep" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Sleep {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            println!("Putting {}:{} to sleep...", resolved_host, resolved_port);
            quic.exec(
                "Add-Type -Assembly System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $true, $false)"
            ).await.ok();
            println!("Sleep command sent.");
        }
        "lock" => {
            println!(
                "Locking workstation on {}:{}...",
                resolved_host, resolved_port
            );
            quic.exec("rundll32.exe user32.dll,LockWorkStation").await?;
            println!("Workstation locked.");
        }
        // ── Status (multi-ping with RTT stats) ───────────────────
        "status" => {
            let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let mut rtts = Vec::with_capacity(count);
            let mut failures = 0usize;
            println!("--- {} (QUIC) ---", resolved_host);
            for i in 0..count {
                let start = std::time::Instant::now();
                match quic.exec("echo PONG").await {
                    Ok(_) => {
                        let elapsed = start.elapsed();
                        eprintln!("  ping {}: {:.1?}", i + 1, elapsed);
                        rtts.push(elapsed);
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!("  ping {}: FAILED ({})", i + 1, e);
                    }
                }
                if i < count - 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
            if !rtts.is_empty() {
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let min = rtts.iter().min().unwrap();
                let max = rtts.iter().max().unwrap();
                let mut sorted = rtts.clone();
                sorted.sort();
                let p50 = sorted[sorted.len() / 2];
                let loss = (failures as f64 / count as f64) * 100.0;

                println!("--- {} (QUIC) ping statistics ---", resolved_host);
                println!(
                    "{} transmitted, {} received, {:.0}% loss",
                    count,
                    rtts.len(),
                    loss
                );
                println!(
                    "rtt min/avg/max/p50 = {:.1?}/{:.1?}/{:.1?}/{:.1?}",
                    min, avg, max, p50
                );

                let jitter = if rtts.len() >= 2 {
                    let avg_ns = avg.as_nanos() as f64;
                    let sum_sq: f64 = rtts
                        .iter()
                        .map(|d| {
                            let diff = d.as_nanos() as f64 - avg_ns;
                            diff * diff
                        })
                        .sum();
                    std::time::Duration::from_nanos((sum_sq / rtts.len() as f64).sqrt() as u64)
                } else {
                    std::time::Duration::ZERO
                };
                println!("jitter: {:.1?}", jitter);

                let quality = if loss > 50.0 {
                    "POOR (high packet loss)"
                } else if avg > std::time::Duration::from_millis(500) {
                    "POOR (high latency)"
                } else if loss > 10.0
                    || avg > std::time::Duration::from_millis(200)
                    || jitter > std::time::Duration::from_millis(100)
                {
                    "FAIR"
                } else if avg > std::time::Duration::from_millis(50)
                    || jitter > std::time::Duration::from_millis(20)
                {
                    "GOOD"
                } else {
                    "EXCELLENT"
                };
                println!("quality: {}", quality);
            }
        }
        // ── Cache management ─────────────────────────────────────
        "cache" => {
            if args.len() < 2 {
                bail!("cache requires: stats|index [path]");
            }
            match args[1].as_str() {
                "stats" => {
                    let output = quic.exec("if (Test-Path 'C:\\ProgramData\\mrsh\\cache') { Get-ChildItem 'C:\\ProgramData\\mrsh\\cache' -Recurse | Measure-Object -Property Length -Sum | Select-Object Count,Sum | ConvertTo-Json } else { '{\"Count\":0,\"Sum\":0}' }").await?;
                    println!("{}", output);
                }
                "index" => {
                    if args.len() < 3 {
                        bail!("cache index requires <remote-path>");
                    }
                    let escaped = args[2].replace('\'', "''");
                    let output = quic.exec(&format!(
                        "Get-ChildItem '{}' -Recurse | Select-Object FullName,Length,LastWriteTime | ConvertTo-Json",
                        escaped
                    )).await?;
                    println!("{}", output);
                }
                other => bail!("unknown cache action: {} (use stats|index)", other),
            }
        }
        // ── Plugin management ────────────────────────────────────
        "plugin" => {
            if args.len() < 2 {
                bail!("plugin requires <action> [args...]");
            }
            let plugin_cmd = args[1..].join(" ");
            let output = quic.exec(&format!("mrsh plugin {}", plugin_cmd)).await?;
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        // ── Recording list ───────────────────────────────────────
        "recording" => {
            let output = quic.exec("if (Test-Path 'C:\\ProgramData\\mrsh\\recordings') { Get-ChildItem 'C:\\ProgramData\\mrsh\\recordings' -Filter '*.cast' | Select-Object Name,Length,LastWriteTime | ConvertTo-Json } else { '[]' }").await?;
            println!("{}", output);
        }
        // ── Server version ───────────────────────────────────────
        "server-version" => {
            println!("{}", quic.server_version.as_deref().unwrap_or("unknown"));
        }
        // ── TUI-only commands (not applicable over QUIC) ─────────
        "sessions" | "attach" | "browse" | "sftp" => {
            bail!("command {:?} requires TUI mode (omit --quic)", cmd);
        }
        // ── Unknown → try as exec ────────────────────────────────
        _ => {
            let command = args.join(" ");
            let output = quic.exec(&command).await?;
            print!("{}", output);
        }
    }
    quic.close();
    Ok(())
}
