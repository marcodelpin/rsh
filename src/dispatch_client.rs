//! Remote command dispatch (TLS/relay path).
//!
//! `run_command` is the giant client-command match block factored out of
//! `dispatch::async_main`. It takes ownership of `AnyClient` so the `browse`
//! arm can move the client into a `RefCell` for the synchronous TUI.
//!
//! Adding new commands: extend the match below with a new arm. Keep arms
//! self-contained — shared helpers belong in `mrsh-client` crate, not here.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mrsh_client::client::{AnyClient, ConnectOptions};

use crate::cli::Cli;
use crate::path_translate::{probe_receiver_home, translate_remote_path};
use crate::streaming::run_watch;

/// rsh-5264.6: parse a `--name value` or `--name=value` flag pair from argv.
/// Returns `Some(value)` when the flag is present, `None` otherwise.
fn parse_value_flag(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{}=", flag);
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            return args.get(i + 1).cloned();
        }
        if let Some(v) = a.strip_prefix(&prefix) {
            return Some(v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_value_flag;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_value_flag_space_form() {
        let args = s(&["--from-rdv", "--track", "canary", "--version", "1.10.32"]);
        assert_eq!(parse_value_flag(&args, "--track"), Some("canary".into()));
        assert_eq!(parse_value_flag(&args, "--version"), Some("1.10.32".into()));
    }

    #[test]
    fn parse_value_flag_equals_form() {
        let args = s(&["--from-rdv", "--track=canary", "--version=1.10.32"]);
        assert_eq!(parse_value_flag(&args, "--track"), Some("canary".into()));
        assert_eq!(parse_value_flag(&args, "--version"), Some("1.10.32".into()));
    }

    #[test]
    fn parse_value_flag_absent_returns_none() {
        let args = s(&["--from-rdv"]);
        assert_eq!(parse_value_flag(&args, "--track"), None);
        assert_eq!(parse_value_flag(&args, "--version"), None);
    }

    #[test]
    fn parse_value_flag_at_end_without_value_returns_none() {
        let args = s(&["--from-rdv", "--track"]); // no following arg
        assert_eq!(parse_value_flag(&args, "--track"), None);
    }

    #[test]
    fn parse_value_flag_does_not_match_partial_prefix() {
        let args = s(&["--track-foo", "x", "--track", "real"]);
        // First match wins per scan order — "--track-foo" doesn't equal "--track"
        // and "--track-foo=" prefix doesn't match because "--track-foo" lacks
        // an "=" suffix. The real "--track real" pair matches.
        assert_eq!(parse_value_flag(&args, "--track"), Some("real".into()));
    }
}

/// Probe receiver HOME+OS, translate `remote_path`, log+warn the user when
/// the path is rewritten so they understand what mrsh substituted.
/// Falls back to the original path if the probe fails.
async fn translate_or_passthrough(
    client: &mut AnyClient,
    remote_path: &str,
    op: &str,
) -> String {
    match probe_receiver_home(client).await {
        Ok((home, os)) => {
            let t = translate_remote_path(remote_path, &home, os);
            if t.rewritten {
                eprintln!(
                    "mrsh {}: rewrote remote path {:?} -> {:?} (receiver HOME={}, OS={:?})",
                    op, t.original, t.remote, home, os
                );
            }
            t.remote
        }
        Err(e) => {
            tracing::debug!("path_translate: probe failed ({}), using path as-is", e);
            remote_path.to_string()
        }
    }
}

/// Decide whether the given remote path arg is a candidate for translation.
/// Cheap pre-filter to avoid the probe round-trip for clearly-safe paths.
fn needs_path_probe(remote_path: &str) -> bool {
    let t = remote_path.trim_end_matches(['\r', '\n']);
    if t.starts_with("~/") || t == "~" {
        return true;
    }
    // /<a>/Users/... (Git Bash mount form)
    let bytes = t.as_bytes();
    if bytes.len() >= 4
        && bytes[0] == b'/'
        && (bytes[1] as char).is_ascii_alphabetic()
        && bytes[2] == b'/'
        && t[3..].starts_with("Users/")
    {
        return true;
    }
    // <Drive>:[/\\]Users[/\\]... (MSYS-converted form)
    if bytes.len() >= 4
        && (bytes[0] as char).is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
        && (t[3..].starts_with("Users/") || t[3..].starts_with("Users\\"))
    {
        return true;
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_command(
    mut client: AnyClient,
    cli: &Cli,
    cmd: &str,
    args: &[String],
    host: &str,
    resolved_host: &str,
    resolved_port: u16,
    device_id: Option<&str>,
    config: &mrsh_core::config::Config,
    auto_try_ports: bool,
) -> Result<()> {
    // rsh-le15: -i flag wins, else the resolved Host block's IdentityFile (the
    // TLS/transfer paths here previously ignored config IdentityFile).
    let effective_key = config.resolve_identity_file(host, &cli.key);
    match cmd {
        "ping" => {
            let result = mrsh_client::commands::ping(&mut client).await?;
            println!("{}", result);
        }
        "exec" => {
            // Fallback: buffered exec for servers without stream-exec capability
            if args.len() < 2 {
                bail!("exec requires a command");
            }
            // rsh-oom9: `exec --detach <cmd>` launches the command in a detached
            // runner that survives the channel drop (for >30min jobs), printing a
            // handle to follow with `mrsh -h <host> dlog <id>`. The flag is
            // stripped before assembling the command.
            let detach = args[1..].iter().any(|a| a == "--detach");
            let cmd_words: Vec<&str> = args[1..]
                .iter()
                .map(|s| s.as_str())
                .filter(|a| *a != "--detach")
                .collect();
            if cmd_words.is_empty() {
                bail!("exec requires a command");
            }
            let raw_command = cmd_words.join(" ");
            if detach {
                let dir =
                    mrsh_client::commands::exec_detach(&mut client, &raw_command).await?;
                let token = mrsh_client::commands::detach_token(&dir);
                println!("mrsh-detach started  handle={token}  (dir: {dir})");
                println!("follow: mrsh -h {host} dlog {token}");
            } else {
                let command = if cli.use_cmd {
                    format!("CMD:{}", raw_command)
                } else if cli.use_sh {
                    format!("SH:{}", raw_command)
                } else {
                    raw_command
                };
                // rsh-1cp1: propagate the REMOTE exit code (was discarded — a remote
                // `exit 3` returned local exit 0).
                let (exit_code, result) =
                    mrsh_client::commands::exec_with_code(&mut client, &command, &[]).await?;
                print!("{}", result);
                if exit_code != 0 {
                    std::process::exit(exit_code as i32);
                }
            }
        }
        "dlog" => {
            // rsh-oom9: poll a detached job (companion to `exec --detach`).
            let id = match args.get(1) {
                Some(s) => s.as_str(),
                None => bail!("dlog requires a detach id (the handle from `exec --detach`)"),
            };
            let out = mrsh_client::commands::exec_dlog(&mut client, id).await?;
            print!("{}", out);
        }
        "ls" => {
            let path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            let files = mrsh_client::commands::ls(&mut client, path).await?;
            for f in &files {
                let kind = if f.is_dir { "d" } else { "-" };
                println!(
                    "{}{} {:>10} {} {}",
                    kind, f.mode, f.size, f.mod_time, f.name
                );
            }
        }
        "cat" => {
            if args.len() < 2 {
                bail!("cat requires a path");
            }
            let text = mrsh_client::commands::cat_text(&mut client, &args[1]).await?;
            print!("{}", text);
        }
        "push" => {
            if args.len() < 3 {
                bail!("push requires <local> <remote>");
            }
            let local_path = std::path::Path::new(&args[1]);
            let meta = std::fs::metadata(local_path)
                .map_err(|e| anyhow::anyhow!("cannot stat {}: {}", args[1], e))?;
            let xfer_opts = mrsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            // Translate sender-mangled `~/` and `/c/Users/<sender>/...` paths
            // into the receiver-side absolute path.
            let remote_arg: String = if needs_path_probe(&args[2]) {
                translate_or_passthrough(&mut client, &args[2], "push").await
            } else {
                args[2].clone()
            };
            if meta.is_dir() {
                let result =
                    mrsh_client::sync::push_dir(&mut client, local_path, &remote_arg, &xfer_opts)
                        .await?;
                eprintln!(
                    "pushed directory: {}/{} files, {} bytes",
                    result.files_transferred, result.files_total, result.bytes_total
                );
                if cli.delete {
                    let deleted = mrsh_client::sync::delete_remote_extras(
                        &mut client,
                        local_path,
                        &remote_arg,
                    )
                    .await?;
                    if deleted > 0 {
                        println!("--delete: removed {} remote files", deleted);
                    }
                }
            } else {
                if cli.dry_run {
                    eprintln!("[dry-run] would push {} -> {}", args[1], remote_arg);
                } else {
                    let result =
                        mrsh_client::sync::push_file(&mut client, local_path, &remote_arg).await?;
                    // Verify remote file exists and size matches.
                    // ls() works on directories — for single files, ls the parent and filter.
                    let local_size = meta.len() as i64;
                    let remote_path = std::path::Path::new(&remote_arg);
                    let parent = remote_path
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| ".".to_string());
                    let file_name = remote_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string());
                    let remote_files = mrsh_client::commands::ls(&mut client, &parent).await;
                    // rsh-9mpb: classify verification result and translate failures
                    // into NON-ZERO exit so callers can detect silent breakage
                    // (previously verification failures were buried in a
                    // (verified: false) suffix on an exit-0 success message).
                    enum VerifyOutcome {
                        Verified,
                        SizeMismatch { local: i64, remote: i64 },
                        NotFound,
                        Unverifiable(String), // ls() failed — can't tell either way
                    }
                    let outcome = match (remote_files, file_name) {
                        (Ok(files), Some(name)) => {
                            if let Some(f) = files.iter().find(|f| f.name == name) {
                                if f.size == local_size {
                                    VerifyOutcome::Verified
                                } else {
                                    VerifyOutcome::SizeMismatch {
                                        local: local_size,
                                        remote: f.size,
                                    }
                                }
                            } else {
                                VerifyOutcome::NotFound
                            }
                        }
                        (Err(e), _) => VerifyOutcome::Unverifiable(e.to_string()),
                        (_, None) => VerifyOutcome::Unverifiable(
                            "remote path has no file component".to_string(),
                        ),
                    };
                    match &outcome {
                        VerifyOutcome::Verified => {
                            println!(
                                "pushed {} bytes to {} (delta: {}, verified: true)",
                                result.bytes_sent, result.path, result.delta
                            );
                        }
                        VerifyOutcome::SizeMismatch { local, remote } => {
                            // Local bytes left the client but remote landed wrong-sized.
                            // Distinct from NotFound — file IS present but corrupt/truncated.
                            bail!(
                                "push to {} reported {} bytes BUT remote size mismatch: local={} remote={} \
                                 (suggests transport corruption or partial write)",
                                result.path, result.bytes_sent, local, remote
                            );
                        }
                        VerifyOutcome::NotFound => {
                            // The dangerous one — bytes claimed sent but file doesn't exist.
                            // This is the rsh-9mpb silent-failure pattern: auth may have
                            // succeeded at the wire layer but server rejected the write,
                            // or the destination path was rewritten silently.
                            bail!(
                                "push to {} reported {} bytes BUT remote file NOT FOUND. \
                                 Likely silent server-side rejection (check audit.log for \
                                 'auth failed' or 'unknown key'). Re-run with --debug or check \
                                 server-side mrsh audit log under /etc/mrsh (legacy \
                                 /etc/rsh) audit.log.YYYY-MM-DD",
                                result.path, result.bytes_sent
                            );
                        }
                        VerifyOutcome::Unverifiable(reason) => {
                            // We can't prove either way. Surface warning but exit 0 — this is
                            // a transient ls failure, not a definitive push failure. Operators
                            // running pushes in pipelines should add their own post-check.
                            eprintln!(
                                "WARNING: could not verify remote file after push ({}). \
                                 Bytes sent: {}, remote: {} — manual verification advised.",
                                reason, result.bytes_sent, result.path
                            );
                            println!(
                                "pushed {} bytes to {} (delta: {}, verified: unknown)",
                                result.bytes_sent, result.path, result.delta
                            );
                        }
                    }
                }
            }
        }
        "pull" => {
            if args.len() < 3 {
                bail!("pull requires <remote> <local>");
            }
            let xfer_opts = mrsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            // Translate sender-mangled `~/` and `/c/Users/<sender>/...` paths
            // into the receiver-side absolute path.
            let remote_arg: String = if needs_path_probe(&args[1]) {
                translate_or_passthrough(&mut client, &args[1], "pull").await
            } else {
                args[1].clone()
            };
            // Check if remote is a directory (ls succeeds on dirs)
            let is_dir = {
                let files = mrsh_client::commands::ls(&mut client, &remote_arg).await;
                files.is_ok()
            };
            if is_dir {
                let local_path = std::path::Path::new(&args[2]);
                let result =
                    mrsh_client::sync::pull_dir(&mut client, &remote_arg, local_path, &xfer_opts)
                        .await?;
                println!(
                    "pulled directory: {}/{} files, {} bytes",
                    result.files_transferred, result.files_total, result.bytes_total
                );
            } else {
                if cli.dry_run {
                    eprintln!("[dry-run] would pull {} -> {}", remote_arg, args[2]);
                } else {
                    let local_data = std::fs::read(&args[2]).ok();
                    let result =
                        mrsh_client::sync::pull(&mut client, local_data.as_deref(), &remote_arg)
                            .await?;
                    std::fs::write(&args[2], &result.data)?;
                    println!(
                        "pulled {} bytes (delta: {})",
                        result.data.len(),
                        result.delta
                    );
                }
            }
        }
        // rsh-j7yf: `ss` is an alias for `screenshot`. Previously `ss` fell
        // through to the default exec arm and was sent as a PowerShell
        // command — `ss : The term 'ss' is not recognized`. The hard-block in
        // src/dispatch.rs already refuses `ss` on 8822 SYSTEM, so this arm
        // only fires for 9822 (tray) where the screenshot dispatch is valid.
        "screenshot" | "ss" => {
            let display_idx: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let quality: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(75);
            let scale: u8 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100);
            let data =
                mrsh_client::commands::screenshot(&mut client, display_idx, quality, scale)
                    .await?;
            let out_path = format!("screenshot_{}.jpg", display_idx);
            std::fs::write(&out_path, &data)?;
            println!("saved {} ({} bytes)", out_path, data.len());
        }
        "sessions" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("list");
            match action {
                "list" => {
                    let result = mrsh_client::commands::sessions_list(&mut client).await?;
                    println!("{}", result);
                }
                "kill" => {
                    if args.len() < 3 {
                        bail!("sessions kill requires <session-id>");
                    }
                    mrsh_client::commands::session_kill(&mut client, &args[2]).await?;
                    println!("session killed");
                }
                other => bail!("unknown sessions action: {}", other),
            }
        }
        "shell" => {
            let mut env_vars: Vec<String> = args.iter().skip(1).cloned().collect();
            if let Some(ref shell) = cli.shell {
                env_vars.push(format!("MRSH_SHELL={}", shell));
            }
            mrsh_client::shell::run_shell(&mut client, &env_vars).await?;
        }
        "attach" => {
            // attach [session-id] [--ro]
            let mut session_id = "";
            let mut read_only = false;
            let mut env_vars = Vec::new();
            for arg in args.iter().skip(1) {
                match arg.as_str() {
                    "--ro" | "--read-only" | "-r" => read_only = true,
                    s if !s.starts_with('-') && session_id.is_empty() => session_id = s,
                    _ => env_vars.push(arg.clone()),
                }
            }
            mrsh_client::shell::run_attach(&mut client, session_id, read_only, &env_vars)
                .await?;
        }
        "browse" => {
            let start_path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            // browse is synchronous TUI — bridge async client via Handle
            let handle = tokio::runtime::Handle::current();
            // RefCell borrow held across block_on is safe: closures run synchronously
            use std::cell::RefCell;
            let client_cell = RefCell::new(client);
            mrsh_client::browse::run_browser(
                start_path,
                |dir_path| {
                    let mut c = client_cell.borrow_mut();
                    let result = handle.block_on(mrsh_client::commands::ls(&mut *c, dir_path));
                    result.map_err(|e| e.to_string())
                },
                |remote_path, local_path| {
                    let mut c = client_cell.borrow_mut();
                    let result =
                        handle.block_on(mrsh_client::sync::pull(&mut *c, None, remote_path));
                    match result {
                        Ok(pr) => {
                            if let Err(e) = std::fs::write(local_path, &pr.data) {
                                eprintln!("write error: {}", e);
                            } else {
                                println!("saved {} ({} bytes)", local_path, pr.data.len());
                            }
                        }
                        Err(e) => eprintln!("pull error: {}", e),
                    }
                },
            );
            // Recover client for clean shutdown
            let client = client_cell.into_inner();
            drop(client);
            return Ok(());
        }
        "sftp" => {
            let host_display = cli.host.as_deref().unwrap_or("unknown");
            mrsh_client::sftp::run_sftp(&mut client, host_display).await?;
        }
        "push-via" | "pull-via" => {
            // Upload (push-via) or download (pull-via) via SOCKS5 proxy
            // through the relay host. Wraps: mrsh -D + curl -x socks5h://.
            // push-via: <local> <url>  → curl -T <local> <url>
            // pull-via: <url> <local>  → curl -o <local> <url>
            let is_pull = cmd == "pull-via";
            if args.len() < 3 {
                if is_pull {
                    bail!(
                        "pull-via requires <url> <local> (ftp://, sftp://, http://, https://)"
                    );
                } else {
                    bail!(
                        "push-via requires <local> <url> (ftp://, sftp://, http://, https://)"
                    );
                }
            }
            let (local, url) = if is_pull {
                (&args[2], &args[1])
            } else {
                (&args[1], &args[2])
            };

            // Verify curl exists
            if std::process::Command::new("curl")
                .arg("--version")
                .output()
                .is_err()
            {
                bail!("{} requires 'curl' in PATH", cmd);
            }

            // For push: verify local file exists
            if !is_pull && !std::path::Path::new(local).exists() {
                bail!("local file not found: {}", local);
            }

            // Find available local port
            let socks_port = {
                let l =
                    std::net::TcpListener::bind("127.0.0.1:0").context("bind local port")?;
                let p = l.local_addr()?.port();
                drop(l);
                p
            };

            // Drop the initial client — SOCKS5 creates fresh connections per request
            drop(client);

            let connect_opts = Arc::new(ConnectOptions {
                host: resolved_host.to_string(),
                port: resolved_port,
                key_path: effective_key.clone(),
                password_user: cli.user.clone(),
            });
            let connect_fn = move || {
                let opts = connect_opts.clone();
                async move {
                    // connect_any dispatches fs:// → fs-transport, else TCP.
                    let client = mrsh_client::client::connect_any(&opts).await?;
                    Ok(client.into_stream())
                }
            };

            eprintln!(
                "{}: SOCKS5 127.0.0.1:{} → {}:{}, {} {}",
                cmd,
                socks_port,
                resolved_host,
                resolved_port,
                if is_pull { "downloading" } else { "uploading" },
                url
            );

            // Run SOCKS5 in background, then curl
            let socks_handle = tokio::spawn(async move {
                mrsh_client::socks::run_socks5(socks_port, connect_fn).await
            });

            // Brief startup delay
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

            let mut curl_cmd = std::process::Command::new("curl");
            curl_cmd
                .arg("-x")
                .arg(format!("socks5h://127.0.0.1:{}", socks_port))
                .arg("--fail")
                .arg("--show-error");
            if is_pull {
                curl_cmd.arg("-o").arg(local).arg(url);
            } else {
                curl_cmd.arg("-T").arg(local).arg(url);
            }
            let status = curl_cmd.status()?;

            socks_handle.abort();

            if !status.success() {
                bail!("curl exited with code {:?}", status.code());
            }
            eprintln!("{}: completed successfully", cmd);
            return Ok(());
        }
        "push-via-batch" => {
            // Batch upload: reuses ONE SOCKS5 proxy for N parallel curl workers.
            // mrsh -h <relay> push-via-batch <src-dir> <base-url/>
            //   [--include=PAT]... [--exclude=PAT]... [--resume]
            //   [--parallel=N] [--progress] [--index=FILE] [--dry-run]
            if args.len() < 3 {
                bail!(
                    "push-via-batch requires <src-dir> <base-url/> (base URL must end with '/')"
                );
            }
            let src_dir = std::path::PathBuf::from(&args[1]);
            let base_url = args[2].clone();
            if !base_url.ends_with('/') {
                bail!("base URL must end with '/': {}", base_url);
            }

            // Parse batch-specific flags from trailing args (sync-dir style).
            let mut include: Vec<String> = Vec::new();
            let mut exclude: Vec<String> = Vec::new();
            let mut resume = false;
            let mut parallel: usize = 4;
            let mut show_progress = cli.progress;
            let mut index_path: Option<std::path::PathBuf> = None;
            let mut dry_run = cli.dry_run;

            let mut it = args[3..].iter();
            while let Some(a) = it.next() {
                if let Some(v) = a.strip_prefix("--include=") {
                    include.push(v.to_string());
                } else if a == "--include" {
                    if let Some(v) = it.next() {
                        include.push(v.clone());
                    }
                } else if let Some(v) = a.strip_prefix("--exclude=") {
                    exclude.push(v.to_string());
                } else if a == "--exclude" {
                    if let Some(v) = it.next() {
                        exclude.push(v.clone());
                    }
                } else if a == "--resume" {
                    resume = true;
                } else if let Some(v) = a.strip_prefix("--parallel=") {
                    parallel = v.parse::<usize>().context("--parallel needs a number")?;
                } else if a == "--parallel" {
                    if let Some(v) = it.next() {
                        parallel = v.parse::<usize>().context("--parallel needs a number")?;
                    }
                } else if a == "--progress" {
                    show_progress = true;
                } else if let Some(v) = a.strip_prefix("--index=") {
                    index_path = Some(std::path::PathBuf::from(v));
                } else if a == "--index" {
                    if let Some(v) = it.next() {
                        index_path = Some(std::path::PathBuf::from(v));
                    }
                } else if a == "--dry-run" {
                    dry_run = true;
                } else {
                    bail!("push-via-batch: unknown flag {}", a);
                }
            }

            // Drop the initial client — SOCKS5 creates fresh connections per request.
            drop(client);

            let connect_opts = Arc::new(ConnectOptions {
                host: resolved_host.to_string(),
                port: resolved_port,
                key_path: effective_key.clone(),
                password_user: cli.user.clone(),
            });
            let connect_fn = move || {
                let opts = connect_opts.clone();
                async move {
                    // connect_any dispatches fs:// → fs-transport, else TCP.
                    let client = mrsh_client::client::connect_any(&opts).await?;
                    Ok(client.into_stream())
                }
            };

            let opts = mrsh_client::push_via_batch::BatchOptions {
                src_dir,
                base_url,
                include,
                exclude,
                resume,
                parallel,
                progress: show_progress,
                index_path,
                dry_run,
            };
            let result = mrsh_client::push_via_batch::run(opts, connect_fn).await?;
            eprintln!(
                "push-via-batch: done — total={} uploaded={} skipped={} failed={} \
                 bytes={} elapsed={:.1}s",
                result.total,
                result.uploaded,
                result.skipped,
                result.failed,
                result.bytes_sent,
                result.elapsed_secs,
            );
            if result.failed > 0 {
                bail!("push-via-batch: {} file(s) failed", result.failed);
            }
            return Ok(());
        }
        "pull-via-batch" => {
            // Batch download: one shared SOCKS5 proxy + N parallel curl workers.
            // mrsh -h <relay> pull-via-batch <base-url/> <dest-dir>
            //   --manifest <file|url> [--include=PAT]... [--exclude=PAT]...
            //   [--resume] [--parallel=N] [--progress] [--index=FILE] [--dry-run]
            if args.len() < 3 {
                bail!("pull-via-batch requires <base-url/> <dest-dir> --manifest <file|url>");
            }
            let base_url = args[1].clone();
            let dest_dir = std::path::PathBuf::from(&args[2]);
            if !base_url.ends_with('/') {
                bail!("base URL must end with '/': {}", base_url);
            }

            let mut manifest: Option<String> = None;
            let mut include: Vec<String> = Vec::new();
            let mut exclude: Vec<String> = Vec::new();
            let mut resume = false;
            let mut parallel: usize = 4;
            let mut show_progress = cli.progress;
            let mut index_path: Option<std::path::PathBuf> = None;
            let mut dry_run = cli.dry_run;

            let mut it = args[3..].iter();
            while let Some(a) = it.next() {
                if let Some(v) = a.strip_prefix("--manifest=") {
                    manifest = Some(v.to_string());
                } else if a == "--manifest" {
                    if let Some(v) = it.next() {
                        manifest = Some(v.clone());
                    }
                } else if let Some(v) = a.strip_prefix("--include=") {
                    include.push(v.to_string());
                } else if a == "--include" {
                    if let Some(v) = it.next() {
                        include.push(v.clone());
                    }
                } else if let Some(v) = a.strip_prefix("--exclude=") {
                    exclude.push(v.to_string());
                } else if a == "--exclude" {
                    if let Some(v) = it.next() {
                        exclude.push(v.clone());
                    }
                } else if a == "--resume" {
                    resume = true;
                } else if let Some(v) = a.strip_prefix("--parallel=") {
                    parallel = v.parse::<usize>().context("--parallel needs a number")?;
                } else if a == "--parallel" {
                    if let Some(v) = it.next() {
                        parallel = v.parse::<usize>().context("--parallel needs a number")?;
                    }
                } else if a == "--progress" {
                    show_progress = true;
                } else if let Some(v) = a.strip_prefix("--index=") {
                    index_path = Some(std::path::PathBuf::from(v));
                } else if a == "--index" {
                    if let Some(v) = it.next() {
                        index_path = Some(std::path::PathBuf::from(v));
                    }
                } else if a == "--dry-run" {
                    dry_run = true;
                } else {
                    bail!("pull-via-batch: unknown flag {}", a);
                }
            }

            let manifest = manifest.context(
                "pull-via-batch requires --manifest <file|url> (local file or remote manifest URL)"
            )?;

            drop(client);

            let connect_opts = Arc::new(ConnectOptions {
                host: resolved_host.to_string(),
                port: resolved_port,
                key_path: effective_key.clone(),
                password_user: cli.user.clone(),
            });
            let connect_fn = move || {
                let opts = connect_opts.clone();
                async move {
                    // connect_any dispatches fs:// → fs-transport, else TCP.
                    let client = mrsh_client::client::connect_any(&opts).await?;
                    Ok(client.into_stream())
                }
            };

            let opts = mrsh_client::pull_via_batch::BatchOptions {
                base_url,
                dest_dir,
                manifest,
                include,
                exclude,
                resume,
                parallel,
                progress: show_progress,
                index_path,
                dry_run,
            };
            let result = mrsh_client::pull_via_batch::run(opts, connect_fn).await?;
            eprintln!(
                "pull-via-batch: done — total={} downloaded={} skipped={} failed={} \
                 bytes={} elapsed={:.1}s",
                result.total,
                result.downloaded,
                result.skipped,
                result.failed,
                result.bytes_received,
                result.elapsed_secs,
            );
            if result.failed > 0 {
                bail!("pull-via-batch: {} file(s) failed", result.failed);
            }
            return Ok(());
        }
        "tunnel" => {
            // mrsh -h host tunnel <local_bind> <remote_host:remote_port>
            // mrsh -h host tunnel 127.0.0.1:5432 db-server:5432
            // mrsh -h host tunnel 5432 db-server:5432
            if args.len() < 3 {
                bail!("tunnel requires: <local_bind> <remote_host:port>");
            }
            let (local_bind, remote_target) =
                mrsh_client::tunnel::parse_tunnel_spec(&args[1], &args[2])?;
            eprintln!(
                "tunnel: {} → {} via {}",
                local_bind, remote_target, resolved_host
            );

            // Persistent tunnel: reconnects for each accepted local connection.
            // Must use the same connection method (relay vs direct) as the original.
            let tunnel_device_id = device_id.map(|s| s.to_string());
            let tunnel_config = config.clone();
            let tunnel_host = resolved_host.to_string();
            let tunnel_auto_try = auto_try_ports;
            let tunnel_port = resolved_port;
            let tunnel_key = effective_key.clone(); // rsh-le15: honor config IdentityFile
            mrsh_client::tunnel::run_tunnel_persistent(
                move || {
                    let dev_id = tunnel_device_id.clone();
                    let cfg = tunnel_config.clone();
                    let host = tunnel_host.clone();
                    let port = tunnel_port;
                    let key = tunnel_key.clone();
                    async move {
                        let client = if let Some(ref did) = dev_id {
                            // Relay path
                            let relay_opts = mrsh_client::relay_connect::RelayConnectOptions {
                                device_id: did.clone(),
                                rendezvous_server: cfg
                                    .rendezvous_server
                                    .as_deref()
                                    .unwrap_or("localhost:21116")
                                    .to_string(),
                                rendezvous_key: cfg.rendezvous_key.clone().unwrap_or_default(),
                                key_path: key,
                                server_name: host,
                                port,
                                target_port: if tunnel_auto_try { 0 } else { port },
                                force_relay: true, // skip 5s P2P timeout on tunnel reconnects
                                enrollment_token: cfg
                                    .enrollment_token
                                    .clone()
                                    .unwrap_or_default(),
                                // sys-1qgww: propagate own DeviceID for self-loop detection
                                own_device_id: cfg.device_id.clone(),
                            };
                            mrsh_client::relay_connect::connect_via_relay(&relay_opts)
                                .await?
                                .erase_stream()
                        } else {
                            // Direct path — connect_any covers fs:// as well.
                            let opts = ConnectOptions {
                                host,
                                port,
                                key_path: key,
                                password_user: None,
                            };
                            mrsh_client::client::connect_any(&opts).await?
                        };
                        Ok(client.into_stream())
                    }
                },
                &local_bind,
                &remote_target,
            )
            .await?;
        }
        "recording" => {
            // Only "list" reaches here (export handled in local section)
            let output = mrsh_client::recording::list_remote(&mut client).await?;
            print!("{}", output);
        }
        "write" => {
            if args.len() < 3 {
                bail!("write requires <remote-path> <content>");
            }
            let content = args[2..].join(" ");
            mrsh_client::commands::write_file(&mut client, &args[1], content.as_bytes())
                .await?;
            println!("wrote {} bytes to {}", content.len(), args[1]);
        }
        "self-update" => {
            // rsh-5264.6: dual-mode arm.
            //   Direct push:  self-update <remote-binary-path>
            //   rdv pull:     self-update --from-rdv [--track <t>] [--version <v>]
            //                 [--allow-downgrade] [--insecure-no-verify]
            let from_rdv = args.iter().any(|a| a == "--from-rdv");
            if from_rdv {
                let track = parse_value_flag(&args[1..], "--track");
                let version = parse_value_flag(&args[1..], "--version");
                let allow_downgrade =
                    args.iter().any(|a| a == "--allow-downgrade");
                let insecure_no_verify =
                    args.iter().any(|a| a == "--insecure-no-verify");
                let result = mrsh_client::commands::self_update_from_rdv(
                    &mut client,
                    track,
                    version,
                    allow_downgrade,
                    insecure_no_verify,
                )
                .await?;
                println!("{}", result);
            } else {
                if args.len() < 2 {
                    bail!(
                        "self-update requires <remote-binary-path> OR --from-rdv \
                         [--track <t>] [--version <v>] [--allow-downgrade] \
                         [--insecure-no-verify]"
                    );
                }
                let result =
                    mrsh_client::commands::self_update(&mut client, &args[1]).await?;
                println!("{}", result);
            }
        }
        "input" => {
            // mrsh -h host input mouse pos
            // mrsh -h host input mouse move 500,300
            if args.len() < 3 {
                bail!("input requires <type> <action> [args...]");
            }
            let extra = if args.len() > 3 {
                args[3..].join(" ")
            } else {
                String::new()
            };
            let result =
                mrsh_client::commands::input(&mut client, &args[1], &args[2], &extra).await?;
            println!("{}", result);
        }
        "ps" => {
            let result = mrsh_client::commands::ps(&mut client).await?;
            println!("{}", result);
        }
        "kill" => {
            if args.len() < 2 {
                bail!("kill requires a PID");
            }
            let result = mrsh_client::commands::kill_process(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "tail" => {
            if args.len() < 2 {
                bail!("tail requires <path> [lines]");
            }
            let lines: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            let result = mrsh_client::commands::tail(&mut client, &args[1], lines).await?;
            print!("{}", result);
        }
        "rlog" | "remote-log" => {
            // Remote log query: mrsh -h host rlog <path> [--grep pattern] [--tail N] [--max N] [-i]
            if args.len() < 2 {
                bail!(
                    "Usage: mrsh -h host rlog <path> [--grep pattern] [--tail N] [--max N] [-i]"
                );
            }
            let path = &args[1];
            let mut pattern = String::new();
            let mut tail_lines: u32 = 0;
            let mut max_matches: u32 = 0;
            let mut flags: u8 = 0;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--grep" | "-g" => {
                        i += 1;
                        if let Some(p) = args.get(i) {
                            pattern = p.clone();
                        }
                    }
                    "--tail" | "-n" => {
                        i += 1;
                        if let Some(n) = args.get(i) {
                            tail_lines = n.parse().unwrap_or(0);
                        }
                    }
                    "--max" | "-m" => {
                        i += 1;
                        if let Some(n) = args.get(i) {
                            max_matches = n.parse().unwrap_or(0);
                        }
                    }
                    "-i" => flags |= mrsh_core::binproto::LOG_FLAG_CASE_INSENSITIVE,
                    "-v" => flags |= mrsh_core::binproto::LOG_FLAG_INVERT,
                    other if other.starts_with("--grep=") => pattern = other[7..].to_string(),
                    other if other.starts_with("--tail=") => {
                        tail_lines = other[7..].parse().unwrap_or(0)
                    }
                    other if other.starts_with("--max=") => {
                        max_matches = other[6..].parse().unwrap_or(0)
                    }
                    _ => {}
                }
                i += 1;
            }
            if !client.supports("log-query") {
                bail!("server does not support log-query (upgrade server to v1.7+)");
            }
            let (scanned, matched) = mrsh_client::commands::log_query(
                &mut client,
                path,
                &pattern,
                flags,
                tail_lines,
                max_matches,
            )
            .await?;
            eprintln!("--- {} lines scanned, {} matched ---", scanned, matched);
        }
        "filever" => {
            if args.len() < 2 {
                bail!("filever requires <path>");
            }
            let result = mrsh_client::commands::filever(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "info" => {
            let result = mrsh_client::commands::info(&mut client).await?;
            println!("{}", result);
        }
        "eventlog" | "evtlog" => {
            let log_name = args.get(1).map(|s| s.as_str()).unwrap_or("System");
            let count: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
            let result = mrsh_client::commands::eventlog(&mut client, log_name, count).await?;
            println!("{}", result);
        }
        "clip" | "clipboard" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("get");
            match action {
                "get" | "read" => {
                    let result = mrsh_client::commands::clip_get(&mut client).await?;
                    print!("{}", result);
                }
                "set" | "write" | "copy" => {
                    if args.len() < 3 {
                        bail!("clip set requires text");
                    }
                    let text = args[2..].join(" ");
                    let result = mrsh_client::commands::clip_set(&mut client, &text).await?;
                    println!("{}", result);
                }
                "sync" => {
                    let interval_ms: u64 = args
                        .get(2)
                        .and_then(|s| s.strip_prefix("--interval=").or(Some(s.as_str())))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(500);
                    mrsh_client::commands::clip_sync(
                        &mut client,
                        std::time::Duration::from_millis(interval_ms),
                    )
                    .await?;
                }
                other => bail!("unknown clip action: {} (use get|set|sync)", other),
            }
        }
        "service" | "svc" => {
            if args.len() < 2 {
                bail!("service requires: list|status|start|stop|restart [name]");
            }
            let name = args.get(2).map(|s| s.as_str());
            let result = mrsh_client::commands::service(&mut client, &args[1], name).await?;
            println!("{}", result);
        }
        "plugin" => {
            if args.len() < 2 {
                bail!("plugin requires <action> [args...]");
            }
            let plugin_args = args[1..].join(" ");
            let result = mrsh_client::commands::plugin(&mut client, &plugin_args).await?;
            if !result.is_empty() {
                println!("{}", result);
            }
        }
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
            mrsh_client::commands::exec(&mut client, "Restart-Computer -Force", &[])
                .await
                .ok();
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
            mrsh_client::commands::exec(&mut client, "Stop-Computer -Force", &[])
                .await
                .ok();
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
            mrsh_client::commands::exec(
                &mut client,
                "Add-Type -Assembly System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $true, $false)",
                &[],
            ).await.ok();
            println!("Sleep command sent.");
        }
        "lock" => {
            eprintln!(
                "Locking workstation on {}:{}...",
                resolved_host, resolved_port
            );
            mrsh_client::commands::exec(
                &mut client,
                "rundll32.exe user32.dll,LockWorkStation",
                &[],
            )
            .await?;
            println!("Workstation locked.");
        }
        "mouse" | "key" | "window" => {
            // GUI automation: mrsh -h host mouse move 500 300
            if args.len() < 3 {
                bail!("{} requires <action> <args>", cmd);
            }
            let result =
                mrsh_client::commands::input(&mut client, cmd, &args[1], &args[2..].join(" "))
                    .await?;
            if !result.is_empty() {
                println!("{}", result);
            }
        }
        "cache" => {
            if args.len() < 2 {
                bail!("cache requires: stats|index [path]");
            }
            match args[1].as_str() {
                "stats" => {
                    let req = mrsh_client::commands::build_request("sync", None, None, None);
                    let mut req = req;
                    req.sync_type = Some("cache-stats".to_string());
                    let resp = client.request(&req).await?;
                    if !resp.success {
                        bail!("{}", resp.error.as_deref().unwrap_or("cache stats failed"));
                    }
                    println!("{}", resp.output.unwrap_or_default());
                }
                "index" => {
                    if args.len() < 3 {
                        bail!("cache index requires <remote-path>");
                    }
                    let mut req = mrsh_client::commands::build_request(
                        "sync",
                        None,
                        Some(&args[2]),
                        None,
                    );
                    req.sync_type = Some("index-dir".to_string());
                    let resp = client.request(&req).await?;
                    if !resp.success {
                        bail!("{}", resp.error.as_deref().unwrap_or("index failed"));
                    }
                    println!("{}", resp.output.unwrap_or_default());
                }
                other => bail!("unknown cache action: {} (use stats|index)", other),
            }
        }
        "status" => {
            let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let mut rtts = Vec::with_capacity(count);
            let mut failures = 0usize;

            for i in 0..count {
                let start = std::time::Instant::now();
                match mrsh_client::commands::ping(&mut client).await {
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

            eprintln!();
            if !rtts.is_empty() {
                rtts.sort();
                let min = rtts[0];
                let max = rtts[rtts.len() - 1];
                let p50 = rtts[rtts.len() / 2];
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let loss = failures as f64 / count as f64 * 100.0;

                println!(
                    "--- {}:{} ping statistics ---",
                    resolved_host, resolved_port
                );
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

                // Jitter (standard deviation of RTTs)
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

            // Remote info
            println!("\n--- remote info ---");
            if let Ok(info_json) = mrsh_client::commands::info(&mut client).await {
                println!("{}", info_json)
            }
        }
        "sync-dir" => {
            if args.len() < 3 {
                bail!("sync-dir requires <local-dir> <remote-dir>");
            }
            let xfer_opts = mrsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            let exclude: Vec<String> = args
                .iter()
                .filter(|a| a.starts_with("--exclude="))
                .map(|a| a.trim_start_matches("--exclude=").to_string())
                .collect();
            let local_path = std::path::Path::new(&args[1]);
            let result = mrsh_client::sync::sync_dir(
                &mut client,
                local_path,
                &args[2],
                &xfer_opts,
                &exclude,
            )
            .await?;
            println!(
                "sync-dir: {} pulled, {} pushed, {} unchanged",
                result.pulled, result.pushed, result.unchanged
            );
        }
        "watch" => {
            if args.len() < 3 {
                bail!("watch requires <local-dir> <remote-dir>");
            }
            run_watch(&mut client, &args[1], &args[2]).await?;
        }
        "server-version" => {
            let result = mrsh_client::commands::server_version(&client)?;
            println!("{}", result);
        }
        "tray-start" => {
            let req = mrsh_client::client::simple_request("tray-start");
            let resp = client.request(&req).await?;
            if resp.success {
                println!("tray started: {}", resp.output.as_deref().unwrap_or("ok"));
            } else {
                bail!(
                    "tray-start failed: {}",
                    resp.error.as_deref().unwrap_or("unknown")
                );
            }
        }
        "launch" => {
            // mrsh -h <host> launch <app> [args...]
            // Cascade Start-Process -> schtasks /IT for GUI app launch in user session.
            // See crates/mrsh-client/src/launch.rs for full cascade pattern.
            if args.len() < 2 {
                bail!("launch requires <app> [args...]");
            }
            let app = &args[1];
            let app_args: Vec<String> = args[2..].to_vec();
            let script = mrsh_client::launch::build_launch_script(app, &app_args);
            use mrsh_client::commands::exec as run_remote_cmd;
            let raw = run_remote_cmd(&mut client, &script, &[]).await?;
            let line = mrsh_client::launch::parse_launch_output(&raw)?;
            println!("{}", line);
        }
        _other => {
            // Unknown command → treat as exec
            let command = args.join(" ");
            let result = mrsh_client::commands::exec(&mut client, &command, &[]).await?;
            print!("{}", result);
        }
    }
    Ok(())
}
