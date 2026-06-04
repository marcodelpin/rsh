//! Local CLI commands that don't need a remote connection.
//! Extracted from main.rs to reduce its size.

use anyhow::{Context, Result, bail};

/// Query and display session logs.
pub fn run_log_query(args: &[String]) -> Result<()> {
    let config = mrsh_core::config::Config::load();
    let log_dir = config.session_log_dir();

    let mut host_filter = None;
    let mut since = None;
    let mut until = None;
    let mut show_detail = false;
    let mut json_output = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host_filter = args.get(i).map(|s| s.to_string());
            }
            "--since" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    since = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
                }
            }
            "--until" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    until = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
                }
            }
            "--detail" | "-d" => show_detail = true,
            "--json" => json_output = true,
            other if other.starts_with("--host=") => {
                host_filter = Some(other.strip_prefix("--host=").unwrap().to_string());
            }
            other if other.starts_with("--since=") => {
                since = chrono::NaiveDate::parse_from_str(
                    other.strip_prefix("--since=").unwrap(),
                    "%Y-%m-%d",
                )
                .ok();
            }
            other if other.starts_with("--until=") => {
                until = chrono::NaiveDate::parse_from_str(
                    other.strip_prefix("--until=").unwrap(),
                    "%Y-%m-%d",
                )
                .ok();
            }
            _ => {}
        }
        i += 1;
    }

    let filter = mrsh_client::session_log::LogFilter {
        host: host_filter,
        since,
        until,
    };

    let entries = mrsh_client::session_log::query_logs(&log_dir, &filter);

    if entries.is_empty() {
        eprintln!("No session log entries found in {}", log_dir.display());
        if !config.session_log {
            eprintln!("Hint: session logging is disabled. Remove 'SessionLog false' from ~/.mrsh/config to re-enable.");
        }
        return Ok(());
    }

    if json_output {
        for entry in &entries {
            println!("{}", serde_json::to_string(entry)?);
        }
        return Ok(());
    }

    if show_detail {
        println!(
            "{:<20} {:>5} {:<8} {:<30} {:>10} {:>4}",
            "HOST", "PORT", "CMD", "ARGS", "DURATION", "EXIT"
        );
        println!("{}", "-".repeat(80));
        for entry in &entries {
            println!(
                "{:<20} {:>5} {:<8} {:<30} {:>10} {:>4}",
                entry.host,
                entry.port,
                entry.cmd,
                entry
                    .args
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(30)
                    .collect::<String>(),
                mrsh_client::session_log::format_duration(entry.duration_s),
                entry.exit,
            );
        }
        println!("{}", "-".repeat(80));
    }

    // Summary by host
    let summaries = mrsh_client::session_log::summarize_by_host(&entries);

    println!(
        "\n{:<25} {:>10} {:>8} {:>12} {:>12}",
        "HOST", "COMMANDS", "HOURS", "FIRST", "LAST"
    );
    println!("{}", "=".repeat(70));

    let mut total_seconds = 0.0;
    let mut total_commands = 0u64;

    for s in &summaries {
        total_seconds += s.total_seconds;
        total_commands += s.command_count;
        let hours = s.total_seconds / 3600.0;
        let first = s
            .first_seen
            .as_ref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        let last = s
            .last_seen
            .as_ref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        println!(
            "{:<25} {:>10} {:>8.1} {:>12} {:>12}",
            s.host, s.command_count, hours, first, last,
        );
    }

    println!("{}", "-".repeat(70));
    println!(
        "{:<25} {:>10} {:>8.1}",
        "TOTAL",
        total_commands,
        total_seconds / 3600.0,
    );

    Ok(())
}

/// Generate an install pack for deploying mrsh to a new machine.
pub fn run_install_pack(args: &[String]) -> Result<()> {
    let mut platform = if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "linux".to_string()
    };
    let mut output = None;
    let mut binary = None;
    let mut extra_keys = Vec::new();
    let mut port = crate::DEFAULT_PORT;
    let mut nas_auth = None;
    let mut group = None;
    let mut rendezvous_server = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--platform" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    platform = p.clone();
                }
            }
            "--output" | "-o" => {
                i += 1;
                if let Some(o) = args.get(i) {
                    output = Some(std::path::PathBuf::from(o));
                }
            }
            "--binary" => {
                i += 1;
                if let Some(b) = args.get(i) {
                    binary = Some(std::path::PathBuf::from(b));
                }
            }
            "--key" => {
                i += 1;
                if let Some(k) = args.get(i) {
                    // Could be a key string or a path to a file
                    let path = std::path::Path::new(k);
                    if path.exists() {
                        let content =
                            std::fs::read_to_string(path).with_context(|| format!("read key file: {}", k))?;
                        extra_keys.push(content.trim().to_string());
                    } else {
                        extra_keys.push(k.clone());
                    }
                }
            }
            "--port" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    port = p.parse().unwrap_or(crate::DEFAULT_PORT);
                }
            }
            "--nas-auth" => {
                i += 1;
                if let Some(n) = args.get(i) {
                    nas_auth = Some(n.clone());
                }
            }
            "--group" => {
                i += 1;
                if let Some(g) = args.get(i) {
                    group = Some(g.clone());
                }
            }
            "--rendezvous-server" => {
                i += 1;
                if let Some(r) = args.get(i) {
                    rendezvous_server = Some(r.clone());
                }
            }
            other if other.starts_with("--platform=") => {
                platform = other.strip_prefix("--platform=").unwrap().to_string();
            }
            other if other.starts_with("--output=") || other.starts_with("-o=") => {
                let val = other.split_once('=').unwrap().1;
                output = Some(std::path::PathBuf::from(val));
            }
            other if other.starts_with("--binary=") => {
                binary = Some(std::path::PathBuf::from(
                    other.strip_prefix("--binary=").unwrap(),
                ));
            }
            other if other.starts_with("--port=") => {
                port = other
                    .strip_prefix("--port=")
                    .unwrap()
                    .parse()
                    .unwrap_or(crate::DEFAULT_PORT);
            }
            other if other.starts_with("--nas-auth=") => {
                nas_auth = Some(other.strip_prefix("--nas-auth=").unwrap().to_string());
            }
            other if other.starts_with("--group=") => {
                group = Some(other.strip_prefix("--group=").unwrap().to_string());
            }
            other if other.starts_with("--rendezvous-server=") => {
                rendezvous_server = Some(other.strip_prefix("--rendezvous-server=").unwrap().to_string());
            }
            _ => {
                bail!(
                    "Unknown install-pack option: {other}\n\
                     Usage: mrsh install-pack [--platform windows|linux] [--output FILE] [--binary PATH]\n\
                     \x20      [--key KEY_OR_FILE] [--port PORT] [--nas-auth CMD]\n\
                     \x20      [--group NAME] [--rendezvous-server HOST:PORT]\n\
                     \x20      Linux: produces self-extracting .sh (bash + tar.gz)\n\
                     \x20      Windows: produces NSIS installer .exe (requires makensis)",
                    other = args[i]
                );
            }
        }
        i += 1;
    }

    let opts = mrsh_client::install_pack::InstallPackOptions {
        platform,
        output,
        binary,
        extra_keys,
        port,
        nas_auth,
        group,
        rendezvous_server,
    };

    println!("Generating install pack...");
    let out_file = mrsh_client::install_pack::generate(&opts)?;
    println!("\nDone: {}", out_file.display());
    Ok(())
}
