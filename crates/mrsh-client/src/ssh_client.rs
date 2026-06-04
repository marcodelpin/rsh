//! SSH client fallback — connects to hosts with only SSH (no mrsh service).
//!
//! When mrsh TLS handshake fails but SSH is available, this module
//! provides exec/push/pull/shell over standard SSH protocol via russh.
//!
//! # Feature gate
//!
//! Compiled only with `--features ssh-client`.

#[cfg(feature = "ssh-client")]
mod impl_ssh_client {
    use anyhow::{Context, Result, bail};
    use crossterm::terminal;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    #[cfg(unix)]
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::Mutex;
    use tracing::{debug, info, warn};

    /// SSH client session handle.
    pub struct SshSession {
        handle: russh::client::Handle<SshClientHandler>,
        /// Cached remote OS detection: true = Windows, false = Unix.
        remote_is_windows: std::sync::Mutex<Option<bool>>,
    }

    /// Per-connection handler for russh client events.
    struct SshClientHandler {
        /// Server host key fingerprint (for TOFU verification).
        server_fingerprint: Mutex<Option<String>>,
    }

    impl russh::client::Handler for SshClientHandler {
        type Error = anyhow::Error;

        /// Called when server presents its host key. Accept all for now.
        /// TODO: TOFU verification against known_hosts.
        async fn check_server_key(
            &mut self,
            server_public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            let fp = server_public_key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
            info!("SSH server key: {}", fp);
            *self.server_fingerprint.lock().await = Some(fp.to_string());
            Ok(true) // Accept (TODO: TOFU check)
        }
    }

    /// Parsed SSH config entry for a host.
    struct SshConfigEntry {
        user: Option<String>,
        identity_file: Option<String>,
        port: Option<u16>,
        hostname: Option<String>,
    }

    /// Resolve effective SSH username using the sys-tn4 priority chain:
    ///
    /// 1. `user_override`      — CLI `--user`/`-u` flag
    /// 2. `config_user`        — `User` from `~/.ssh/config` Host block
    /// 3. `env_user`           — `$USER` (Unix) or `$USERNAME` (Windows)
    /// 4. `"root"`             — last-resort fallback
    ///
    /// Pure function — takes resolved env so it is fully testable.
    pub(crate) fn resolve_ssh_user(
        user_override: Option<&str>,
        config_user: Option<&str>,
        env_user: Option<&str>,
    ) -> String {
        if let Some(u) = user_override.filter(|s| !s.is_empty()) {
            return u.to_string();
        }
        if let Some(u) = config_user.filter(|s| !s.is_empty()) {
            return u.to_string();
        }
        if let Some(u) = env_user.filter(|s| !s.is_empty()) {
            return u.to_string();
        }
        "root".to_string()
    }

    /// Read `$USER` (Unix) or `$USERNAME` (Windows) — helper for `resolve_ssh_user`.
    fn current_env_user() -> Option<String> {
        std::env::var("USER")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("USERNAME").ok().filter(|s| !s.is_empty()))
    }

    /// Parse ~/.ssh/config and find matching Host entry.
    /// Supports multi-pattern Host lines (e.g. "Host foo bar baz.mdp").
    fn parse_ssh_config(host: &str) -> SshConfigEntry {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => {
                return SshConfigEntry {
                    user: None,
                    identity_file: None,
                    port: None,
                    hostname: None,
                };
            }
        };
        let config_path = home.join(".ssh").join("config");
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => {
                return SshConfigEntry {
                    user: None,
                    identity_file: None,
                    port: None,
                    hostname: None,
                };
            }
        };

        let mut in_matching_block = false;
        let mut user = None;
        let mut identity_file = None;
        let mut port = None;
        let mut hostname = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check for Host directive (new block)
            if let Some(patterns) = trimmed
                .strip_prefix("Host ")
                .or_else(|| trimmed.strip_prefix("Host\t"))
            {
                in_matching_block = patterns.split_whitespace().any(|pat| {
                    if pat.contains('*') {
                        // Simple glob: convert * to regex-like match
                        let re = pat.replace('*', "");
                        host.contains(&re) || pat == "*"
                    } else {
                        pat.eq_ignore_ascii_case(host)
                    }
                });
                continue;
            }

            if !in_matching_block {
                continue;
            }

            // Parse key-value in matching block
            let (key, value) = if let Some((k, v)) = trimmed.split_once(char::is_whitespace) {
                (k.trim(), v.trim())
            } else {
                continue;
            };

            match key {
                "User" => {
                    user = Some(value.to_string());
                }
                "Port" => {
                    port = value.parse().ok();
                }
                "HostName" => {
                    hostname = Some(value.to_string());
                }
                "IdentityFile" => {
                    // Expand ~ to home dir
                    let expanded = if let Some(rest) = value.strip_prefix("~/") {
                        home.join(rest).to_string_lossy().to_string()
                    } else {
                        value.to_string()
                    };
                    identity_file = Some(expanded);
                }
                _ => {}
            }
        }

        SshConfigEntry {
            user,
            identity_file,
            port,
            hostname,
        }
    }

    /// Collect mrsh-specific key paths: ~/.mrsh/id_ed25519 and platform data dir.
    ///
    /// These are tried as a last-resort fallback after standard SSH keys.
    /// Used when the remote host has the mrsh public key in authorized_keys
    /// (e.g. auto-enrolled via `mrsh keys add`) but the standard SSH keys
    /// have been rejected.
    pub(crate) fn mrsh_key_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();

        // User mrsh key: ~/.mrsh/id_ed25519
        if let Some(home) = dirs::home_dir() {
            let user_key = home.join(".mrsh").join("id_ed25519");
            if user_key.exists() {
                candidates.push(user_key);
            }
        }

        // Platform data dir key
        #[cfg(target_os = "windows")]
        {
            let system_key = PathBuf::from(r"C:\ProgramData\mrsh\id_ed25519");
            if system_key.exists() {
                candidates.push(system_key);
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let system_key = PathBuf::from("/etc/mrsh/id_ed25519");
            if system_key.exists() {
                candidates.push(system_key);
            }
        }

        candidates
    }

    /// Try to load a key file using russh's loader, with fallback for raw
    /// 32-byte or 64-byte ed25519 binary keys (convert to OpenSSH PEM in-memory).
    ///
    /// mrsh's own server key at `C:\ProgramData\mrsh\id_ed25519` is stored as a
    /// raw 32-byte seed, NOT an OpenSSH PEM. `russh::keys::load_secret_key`
    /// refuses such files. This function transparently converts the raw bytes
    /// to an in-memory `ssh_key::PrivateKey` so we can use the mrsh key as an
    /// SSH fallback credential.
    pub(crate) fn load_secret_key_with_fallback(
        path: &std::path::Path,
    ) -> Result<russh::keys::ssh_key::PrivateKey, String> {
        // Try standard OpenSSH PEM format first
        match russh::keys::load_secret_key(path, None) {
            Ok(k) => return Ok(k),
            Err(e) => {
                debug!("SSH: standard load failed for {}: {}", path.display(), e);
            }
        }

        // Fallback: try raw binary ed25519 key (32-byte seed or 64-byte expanded)
        let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

        let seed: [u8; 32] = match data.len() {
            32 => {
                debug!(
                    "SSH: {} looks like raw 32-byte ed25519 seed",
                    path.display()
                );
                data.try_into().unwrap()
            }
            64 => {
                // 64-byte expanded key: first 32 bytes are the seed
                debug!(
                    "SSH: {} looks like raw 64-byte ed25519 key, using seed half",
                    path.display()
                );
                data[..32].try_into().unwrap()
            }
            _ => {
                return Err(format!(
                    "load {} failed: not OpenSSH PEM and not raw ed25519 ({} bytes)",
                    path.display(),
                    data.len()
                ));
            }
        };

        // Convert raw seed to OpenSSH format via ssh_key crate
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed_kp = russh::keys::ssh_key::private::Ed25519Keypair {
            public: russh::keys::ssh_key::public::Ed25519PublicKey(
                signing_key.verifying_key().to_bytes(),
            ),
            private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(
                &signing_key.to_bytes(),
            ),
        };
        let private_key = russh::keys::ssh_key::PrivateKey::new(
            russh::keys::ssh_key::private::KeypairData::Ed25519(ed_kp),
            "mrsh-raw-converted",
        )
        .map_err(|e| format!("convert raw key from {}: {}", path.display(), e))?;

        warn!(
            "SSH: loaded raw binary ed25519 key from {} (converted to OpenSSH format in-memory)",
            path.display()
        );
        Ok(private_key)
    }

    impl SshSession {
        /// Connect to an SSH server and authenticate with available keys.
        ///
        /// Reads `~/.ssh/config` for User and IdentityFile, then tries keys in
        /// this priority order:
        ///
        /// 1. CLI `--key` path (if provided)
        /// 2. `IdentityFile` from ssh_config (if set)
        /// 3. `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa` (OpenSSH order)
        /// 4. `~/.mrsh/id_ed25519` (mrsh user key — raw binary format supported)
        /// 5. `C:\ProgramData\mrsh\id_ed25519` (Windows) or `/etc/mrsh/id_ed25519` (Unix)
        ///
        /// Keys are loaded via `load_secret_key_with_fallback` which handles
        /// both standard OpenSSH PEM and raw 32/64-byte ed25519 binary formats.
        ///
        /// TODO (sys-fg7 follow-up): add ssh-agent support via `$SSH_AUTH_SOCK`.
        pub async fn connect(
            host: &str,
            port: u16,
            key_path: &Option<String>,
            user_override: Option<&str>,
        ) -> Result<Self> {
            // rsh-1cp1: russh defaults have NO keepalive — a long-running exec
            // with silent output (script that prints only at the end) leaves the
            // TCP connection idle; NAT/conntrack middleboxes drop the mapping
            // after ~20-30min, the channel dies, the remote process gets SIGHUP
            // and buffered output is lost. SSH-level keepalive every 30s keeps
            // the mapping alive; after 6 missed replies (~3min) the connection
            // is declared dead (which then surfaces as an honest exec error).
            let config = russh::client::Config {
                keepalive_interval: Some(std::time::Duration::from_secs(30)),
                keepalive_max: 6,
                ..Default::default()
            };

            let handler = SshClientHandler {
                server_fingerprint: Mutex::new(None),
            };

            // Read ~/.ssh/config for User, IdentityFile, Port, HostName
            let ssh_cfg = parse_ssh_config(host);

            // Use HostName from config if available (alias resolution)
            let effective_host = ssh_cfg.hostname.as_deref().unwrap_or(host);
            // Use Port from config if caller passed default (22)
            let effective_port = if port == 22 {
                ssh_cfg.port.unwrap_or(port)
            } else {
                port
            };

            let addr = format!("{}:{}", effective_host, effective_port);
            debug!("SSH client connecting to {}", addr);

            let mut handle = russh::client::connect(Arc::new(config), &addr, handler)
                .await
                .context("SSH connect")?;

            // Priority (sys-tn4): CLI override > ~/.ssh/config User > $USER/$USERNAME > root
            let env_user = current_env_user();
            let ssh_user =
                resolve_ssh_user(user_override, ssh_cfg.user.as_deref(), env_user.as_deref());
            debug!("SSH user: {}", ssh_user);

            // Collect candidate key paths in priority order (sys-fg7):
            //   1. CLI --key (if provided)
            //   2. SSH config IdentityFile (if set and exists)
            //   3. Standard ~/.ssh/ keys: ed25519, ecdsa, rsa (OpenSSH order)
            //   4. mrsh user key: ~/.mrsh/id_ed25519
            //   5. mrsh system key: C:\ProgramData\mrsh\id_ed25519 / /etc/mrsh/id_ed25519
            let key_candidates: Vec<PathBuf> = if let Some(path) = key_path {
                vec![PathBuf::from(path)]
            } else {
                let home = dirs::home_dir().context("no home dir")?;
                let ssh_dir = home.join(".ssh");
                let mut candidates: Vec<PathBuf> = Vec::new();

                // SSH config IdentityFile gets highest priority (after --key flag)
                if let Some(ref id_file) = ssh_cfg.identity_file {
                    let id_path = PathBuf::from(id_file);
                    if id_path.exists() {
                        candidates.push(id_path);
                    }
                }

                // Standard SSH keys in OpenSSH order: ed25519, ecdsa, rsa
                for name in &["id_ed25519", "id_ecdsa", "id_rsa"] {
                    let p = ssh_dir.join(name);
                    if p.exists() && !candidates.contains(&p) {
                        candidates.push(p);
                    }
                }

                // mrsh-specific keys (user + system) — last resort fallback
                for mrsh_key in mrsh_key_candidates() {
                    if !candidates.contains(&mrsh_key) {
                        candidates.push(mrsh_key);
                    }
                }

                candidates
            };

            if key_candidates.is_empty() {
                bail!("no SSH keys found (tried ~/.ssh/ and ~/.mrsh/)");
            }

            // Try each key until one succeeds
            let mut last_err = String::new();
            for key_path in &key_candidates {
                // Load key with fallback for raw binary ed25519 format
                // (mrsh's native key at ProgramData is a raw 32-byte seed,
                // not OpenSSH PEM — load_secret_key_with_fallback handles it)
                let loaded_key = match load_secret_key_with_fallback(key_path) {
                    Ok(k) => k,
                    Err(e) => {
                        debug!("SSH: skip {}: {}", key_path.display(), e);
                        last_err = e;
                        continue;
                    }
                };

                // Determine hash algorithms to try for this key type
                let hash_variants: Vec<Option<russh::keys::HashAlg>> = match loaded_key.algorithm()
                {
                    russh::keys::ssh_key::Algorithm::Rsa { .. } => {
                        // rsa-sha2-256 is the modern default (OpenSSH 8.8+)
                        vec![Some(russh::keys::HashAlg::Sha256)]
                    }
                    _ => vec![None],
                };
                drop(loaded_key); // Used only for algorithm detection; re-loaded per attempt

                for hash_alg in &hash_variants {
                    let russh_key = match load_secret_key_with_fallback(key_path) {
                        Ok(k) => k,
                        Err(_) => break,
                    };
                    debug!(
                        "SSH: trying {} ({:?}, hash={:?}) as {}",
                        key_path.display(),
                        russh_key.algorithm(),
                        hash_alg,
                        ssh_user
                    );
                    let key_with_hash =
                        russh::keys::PrivateKeyWithHashAlg::new(Arc::new(russh_key), *hash_alg);

                    match handle
                        .authenticate_publickey(&ssh_user, key_with_hash)
                        .await
                    {
                        Ok(russh::client::AuthResult::Success) => {
                            info!(
                                "SSH authenticated to {} with {} hash={:?}",
                                addr,
                                key_path.display(),
                                hash_alg
                            );
                            return Ok(SshSession {
                                handle,
                                remote_is_windows: std::sync::Mutex::new(None),
                            });
                        }
                        Ok(russh::client::AuthResult::Failure {
                            remaining_methods, ..
                        }) => {
                            debug!(
                                "SSH: {} hash={:?} rejected (remaining: {:?})",
                                key_path.display(),
                                hash_alg,
                                remaining_methods
                            );
                            last_err = format!("key {} rejected", key_path.display());
                            if remaining_methods.is_empty() {
                                break;
                            }
                        }
                        Err(e) => {
                            last_err = format!("{}: {}", key_path.display(), e);
                            break;
                        }
                    }
                }
            }

            bail!(
                "SSH authentication rejected (tried {} keys: {})",
                key_candidates.len(),
                last_err
            );
        }

        /// Detect if remote host runs Windows. Cached after first probe.
        /// Uses `uname -s`: succeeds on Unix, fails on Windows.
        async fn is_remote_windows(&self) -> bool {
            {
                let cached = self.remote_is_windows.lock().unwrap();
                if let Some(val) = *cached {
                    return val;
                }
            }
            let is_win = match self.exec("uname -s").await {
                Ok((0, _)) => false,
                _ => true,
            };
            *self.remote_is_windows.lock().unwrap() = Some(is_win);
            debug!("SSH remote OS: {}", if is_win { "Windows" } else { "Unix" });
            is_win
        }

        /// Execute a command on the remote host, return output (buffered).
        ///
        /// rsh-1cp1: a connection drop mid-command used to silently return
        /// `Ok((0, partial))` — the local exit code LIED about success while the
        /// remote process was SIGHUP-killed. Now: channel ending WITHOUT an
        /// ExitStatus is an error.
        pub async fn exec(&self, command: &str) -> Result<(u32, String)> {
            let channel = self
                .handle
                .channel_open_session()
                .await
                .context("open session channel")?;

            channel.exec(true, command).await.context("send exec")?;

            let mut output = Vec::new();
            let mut exit_code = 0u32;
            let mut saw_exit = false;
            let mut channel = channel;

            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => {
                        output.extend_from_slice(&data);
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        output.extend_from_slice(&data);
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = exit_status;
                        saw_exit = true;
                    }
                    // rsh-1cp1: OpenSSH frequently sends exit-status AFTER the
                    // channel EOF — breaking on Eof discarded it (silent exit 0).
                    // Keep reading until the channel actually closes.
                    Some(russh::ChannelMsg::Eof) => {}
                    Some(russh::ChannelMsg::Close) | None => break,
                    _ => {} // ignore other messages
                }
            }

            if !saw_exit {
                bail!(
                    "SSH channel closed before the command completed — connection \
                     dropped ({} bytes of output received; the remote process was \
                     likely SIGHUP-killed). For long-running commands prefer a \
                     remote-durable wrapper (systemd-run / nohup + log file).",
                    output.len()
                );
            }

            Ok((exit_code, String::from_utf8_lossy(&output).to_string()))
        }

        /// Execute a command with LIVE streaming output (rsh-1cp1): stdout/stderr
        /// chunks are written to the local stdout/stderr AS THEY ARRIVE instead of
        /// buffered-at-end — a connection drop mid-command loses only the not-yet-
        /// produced tail, not everything. Returns the remote exit code; a channel
        /// drop without ExitStatus is an error (never a silent exit 0).
        pub async fn exec_streamed(&self, command: &str) -> Result<u32> {
            use std::io::Write;

            let channel = self
                .handle
                .channel_open_session()
                .await
                .context("open session channel")?;

            channel.exec(true, command).await.context("send exec")?;

            let mut stdout = std::io::stdout();
            let mut stderr = std::io::stderr();
            let mut bytes_streamed = 0usize;
            let mut exit_code = 0u32;
            let mut saw_exit = false;
            let mut channel = channel;

            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => {
                        bytes_streamed += data.len();
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        bytes_streamed += data.len();
                        stderr.write_all(&data)?;
                        stderr.flush()?;
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = exit_status;
                        saw_exit = true;
                    }
                    // rsh-1cp1: exit-status often arrives AFTER Eof — keep
                    // reading until the channel closes (see exec() above).
                    Some(russh::ChannelMsg::Eof) => {}
                    Some(russh::ChannelMsg::Close) | None => break,
                    _ => {} // ignore other messages
                }
            }

            if !saw_exit {
                bail!(
                    "SSH channel closed before the command completed — connection \
                     dropped ({} bytes were streamed before the drop; the remote \
                     process was likely SIGHUP-killed). For long-running commands \
                     prefer a remote-durable wrapper (systemd-run / nohup + log).",
                    bytes_streamed
                );
            }

            Ok(exit_code)
        }

        /// Open an interactive shell over the SSH fallback transport.
        pub async fn shell(&self, env_vars: &[String]) -> Result<u32> {
            let (cols, rows) = terminal::size().unwrap_or((80, 24));
            let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .context("open session channel")?;

            channel
                .request_pty(true, &term, cols as u32, rows as u32, 0, 0, &[])
                .await
                .context("request PTY")?;

            for (key, value) in forwarded_env_vars(env_vars) {
                // Standard SSH servers may ignore env requests; avoid making shell startup fail.
                let _ = channel.set_env(false, key, value).await;
            }

            if let Some(shell) = requested_shell(env_vars) {
                channel
                    .exec(true, shell.as_bytes())
                    .await
                    .context("start interactive shell")?;
            } else {
                channel
                    .request_shell(true)
                    .await
                    .context("request interactive shell")?;
            }

            let raw_mode = crate::shell::enable_raw_mode_best_effort("SSH fallback shell");

            let result = relay_shell_channel(&mut channel).await;

            crate::shell::disable_raw_mode_if_enabled(raw_mode);

            match result {
                Ok((crate::shell::ShellExit::Disconnect, exit_code)) => {
                    eprintln!("\r\nConnection closed.\r");
                    Ok(exit_code)
                }
                Ok((crate::shell::ShellExit::ServerEof, exit_code)) => {
                    eprintln!("\r\nShell session ended.\r");
                    Ok(exit_code)
                }
                Err(e) => {
                    eprintln!("\r\nShell error: {}\r", e);
                    Err(e)
                }
            }
        }

        /// Push a local file to remote via SSH stdin pipe.
        /// Detects remote OS: Unix uses `cat > path`, Windows uses PowerShell.
        pub async fn push(&self, local_path: &std::path::Path, remote_path: &str) -> Result<u64> {
            // Directory push: list files and push each one
            if local_path.is_dir() {
                return self.push_dir(local_path, remote_path).await;
            }

            let data = std::fs::read(local_path).context("read local file")?;
            let size = data.len() as u64;

            let is_win = self.is_remote_windows().await;
            let channel = self.handle.channel_open_session().await?;

            if is_win {
                // Windows OpenSSH: use PowerShell to read stdin bytes and write to file.
                // Works with both cmd.exe and PowerShell as the default SSH shell.
                // Always normalize to POSIX paths — PowerShell and .NET accept forward slashes.
                let posix_path = remote_path.replace('\\', "/").replace('\'', "''");
                let parent_cmd = if let Some(parent) = std::path::Path::new(remote_path).parent() {
                    let ps = parent
                        .to_string_lossy()
                        .replace('\\', "/")
                        .replace('\'', "''");
                    format!(
                        "if (-not (Test-Path '{}')) {{ New-Item -ItemType Directory -Path '{}' -Force | Out-Null }}; ",
                        ps, ps
                    )
                } else {
                    String::new()
                };
                let cmd = format!(
                    "powershell.exe -NoProfile -Command \"{}$ms = [IO.MemoryStream]::new(); [Console]::OpenStandardInput().CopyTo($ms); [IO.File]::WriteAllBytes('{}', $ms.ToArray())\"",
                    parent_cmd, posix_path
                );
                channel.exec(true, cmd).await?;
            } else {
                // Unix: cat+stdin pipe (base64 via echo fails for >100KB, ARG_MAX limit)
                let mkdir_parent = if let Some(parent) = std::path::Path::new(remote_path).parent()
                {
                    format!("mkdir -p '{}' && ", parent.display())
                } else {
                    String::new()
                };
                channel
                    .exec(
                        true,
                        format!(
                            "{}cat > '{}'",
                            mkdir_parent,
                            remote_path.replace('\'', "'\\''")
                        ),
                    )
                    .await?;
            }

            // Send data in chunks (SSH channel may have message size limits)
            let chunk_size = 32768;
            let mut offset = 0;
            while offset < data.len() {
                let end = (offset + chunk_size).min(data.len());
                channel.data(&data[offset..end]).await?;
                offset = end;
            }
            channel.eof().await?;

            let mut channel = channel;
            let mut exit_code = 0u32;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => exit_code = exit_status,
                    Some(russh::ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }
            if exit_code != 0 {
                bail!("push failed with exit code {}", exit_code);
            }

            Ok(size)
        }

        /// Push a directory recursively via SSH.
        async fn push_dir(&self, local_dir: &std::path::Path, remote_dir: &str) -> Result<u64> {
            let mut total_bytes = 0u64;
            let mut files = Vec::new();
            Self::collect_files_recursive(local_dir, &mut files)?;

            for file_path in &files {
                let rel = file_path.strip_prefix(local_dir).unwrap_or(file_path);
                let remote_path = format!(
                    "{}/{}",
                    remote_dir.trim_end_matches('/'),
                    rel.to_string_lossy().replace('\\', "/")
                );

                match Box::pin(self.push(file_path, &remote_path)).await {
                    Ok(bytes) => total_bytes += bytes,
                    Err(e) => {
                        eprintln!("  SKIP: {}: {}", rel.display(), e);
                    }
                }
            }
            Ok(total_bytes)
        }

        /// Recursively collect files from a directory.
        fn collect_files_recursive(
            dir: &std::path::Path,
            out: &mut Vec<std::path::PathBuf>,
        ) -> Result<()> {
            for entry in std::fs::read_dir(dir).context(format!("read dir {}", dir.display()))? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    Self::collect_files_recursive(&path, out)?;
                } else if path.is_file() {
                    out.push(path);
                }
            }
            Ok(())
        }

        /// Pull a remote file. Unix uses `cat`, Windows uses PowerShell raw byte output.
        pub async fn pull(&self, remote_path: &str) -> Result<Vec<u8>> {
            let is_win = self.is_remote_windows().await;
            let cmd = if is_win {
                // POSIX paths — PowerShell and .NET accept forward slashes
                let posix_path = remote_path.replace('\\', "/").replace('\'', "''");
                format!(
                    "powershell.exe -NoProfile -Command \"$b = [IO.File]::ReadAllBytes('{}'); [Console]::OpenStandardOutput().Write($b, 0, $b.Length)\"",
                    posix_path
                )
            } else {
                format!("cat '{}'", remote_path.replace('\'', "'\\''"))
            };
            let channel = self.handle.channel_open_session().await?;
            channel.exec(true, cmd).await?;

            let mut data = Vec::new();
            let mut channel = channel;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data: chunk }) => {
                        data.extend_from_slice(&chunk);
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        if exit_status != 0 {
                            bail!("pull failed with exit code {}", exit_status);
                        }
                    }
                    Some(russh::ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }

            Ok(data)
        }

        /// Close the SSH session.
        pub async fn disconnect(self) -> Result<()> {
            self.handle
                .disconnect(russh::Disconnect::ByApplication, "bye", "en")
                .await?;
            Ok(())
        }
    }

    pub(crate) fn requested_shell(env_vars: &[String]) -> Option<&str> {
        env_vars
            .iter()
            .find_map(|e| e.strip_prefix("MRSH_SHELL="))
            .filter(|s| !s.is_empty())
    }

    pub(crate) fn forwarded_env_vars(env_vars: &[String]) -> impl Iterator<Item = (&str, &str)> {
        env_vars
            .iter()
            .filter_map(|e| e.split_once('='))
            .filter(|(key, _)| !key.is_empty() && *key != "MRSH_SHELL")
    }

    async fn relay_shell_channel(
        channel: &mut russh::Channel<russh::client::Msg>,
    ) -> Result<(crate::shell::ShellExit, u32)> {
        let mut stdin_rx = crate::shell::spawn_stdin_reader();
        let mut stdout = tokio::io::stdout();
        let mut after_newline = true;
        let mut in_escape = false;
        let mut last_size = terminal::size().ok();
        let mut exit_code = 0u32;
        let mut stdin_closed = false;

        #[cfg(unix)]
        let mut resize_events =
            signal(SignalKind::window_change()).context("listen for terminal resize")?;

        #[cfg(not(unix))]
        let mut resize_events = crate::shell::make_resize_interval();

        loop {
            tokio::select! {
                result = stdin_rx.recv(), if !stdin_closed => {
                    match result {
                        None => {
                            stdin_closed = true;
                            channel.eof().await.ok();
                        }
                        Some(input) => {
                            let (out, action) =
                                crate::shell::process_escapes(&input, &mut after_newline, &mut in_escape);
                            match action {
                                crate::shell::EscapeAction::Continue => {
                                    if !out.is_empty() {
                                        channel.data(&out[..]).await.context("send SSH shell input")?;
                                    }
                                }
                                crate::shell::EscapeAction::Disconnect => {
                                    channel.eof().await.ok();
                                    channel.close().await.ok();
                                    return Ok((crate::shell::ShellExit::Disconnect, exit_code));
                                }
                                crate::shell::EscapeAction::Help => {
                                    let help = b"\r\nEscape sequences: ~. disconnect, ~~ literal ~, ~? help\r\n";
                                    stdout.write_all(help).await.ok();
                                    stdout.flush().await.ok();
                                    if !out.is_empty() {
                                        channel.data(&out[..]).await.context("send SSH shell input")?;
                                    }
                                }
                            }
                        }
                    }
                }
                msg = channel.wait() => {
                    match msg {
                        Some(russh::ChannelMsg::Data { data }) => {
                            stdout.write_all(&data).await.context("write SSH shell stdout")?;
                            stdout.flush().await.ok();
                        }
                        Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                            stdout.write_all(&data).await.context("write SSH shell stderr")?;
                            stdout.flush().await.ok();
                        }
                        Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                            exit_code = exit_status;
                        }
                        Some(russh::ChannelMsg::Eof)
                        | Some(russh::ChannelMsg::Close)
                        | None => {
                            return Ok((crate::shell::ShellExit::ServerEof, exit_code));
                        }
                        _ => {}
                    }
                }
                resize = crate::shell::next_resize(&mut resize_events, &mut last_size) => {
                    if let Some((cols, rows)) = resize {
                        channel
                            .window_change(cols as u32, rows as u32, 0, 0)
                            .await
                            .context("send SSH window resize")?;
                    }
                }
            }
        }
    }
}

// Re-export
#[cfg(feature = "ssh-client")]
pub use impl_ssh_client::SshSession;

/// Check if SSH client feature is available.
pub fn ssh_client_available() -> bool {
    cfg!(feature = "ssh-client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_client_feature_detection() {
        // Just verifies the function compiles and returns a bool
        let _ = ssh_client_available();
    }

    #[cfg(feature = "ssh-client")]
    mod ssh_config_tests {
        /// Parse the SAME ssh_config content that `parse_ssh_config` would read.
        /// This is a pure in-memory mirror of the production parser — no I/O,
        /// so tests are parallel-safe (fixes pre-existing race on shared temp dir).
        fn parse_config_str(content: &str, host: &str) -> (Option<String>, Option<String>) {
            let mut in_matching_block = false;
            let mut user = None;
            let mut identity_file = None;

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some(patterns) = trimmed
                    .strip_prefix("Host ")
                    .or_else(|| trimmed.strip_prefix("Host\t"))
                {
                    in_matching_block = patterns.split_whitespace().any(|pat| {
                        if pat.contains('*') {
                            let re = pat.replace('*', "");
                            host.contains(&re) || pat == "*"
                        } else {
                            pat.eq_ignore_ascii_case(host)
                        }
                    });
                    continue;
                }
                if !in_matching_block {
                    continue;
                }
                let (key, value) = if let Some((k, v)) = trimmed.split_once(char::is_whitespace) {
                    (k.trim(), v.trim())
                } else {
                    continue;
                };
                match key {
                    "User" => {
                        user = Some(value.to_string());
                    }
                    "IdentityFile" => {
                        identity_file = Some(value.to_string());
                    }
                    _ => {}
                }
            }
            (user, identity_file)
        }

        #[test]
        fn matches_exact_host() {
            let cfg = "Host pve.example.local\n    User root\n    IdentityFile ~/.ssh/id_ed25519\n";
            let (user, id) = parse_config_str(cfg, "pve.example.local");
            assert_eq!(user, Some("root".to_string()));
            assert_eq!(id, Some("~/.ssh/id_ed25519".to_string()));
        }

        #[test]
        fn matches_multi_pattern_host() {
            let cfg = "Host proxmox pve.example.local pve2 pve.example.local\n    User root\n    IdentityFile ~/.ssh/id_ed25519\n";
            let (user, _) = parse_config_str(cfg, "pve.example.local");
            assert_eq!(user, Some("root".to_string()));
            let (user, _) = parse_config_str(cfg, "proxmox");
            assert_eq!(user, Some("root".to_string()));
        }

        #[test]
        fn no_match_returns_none() {
            let cfg = "Host pve.example.local\n    User root\n";
            let (user, id) = parse_config_str(cfg, "other-host");
            assert_eq!(user, None);
            assert_eq!(id, None);
        }

        #[test]
        fn stops_at_next_host_block() {
            let cfg = "Host foo\n    User alice\n\nHost bar\n    User bob\n";
            let (user, _) = parse_config_str(cfg, "foo");
            assert_eq!(user, Some("alice".to_string()));
            let (user, _) = parse_config_str(cfg, "bar");
            assert_eq!(user, Some("bob".to_string()));
        }

        #[test]
        fn case_insensitive_host_match() {
            let cfg = "Host pve.example.local\n    User root\n";
            let (user, _) = parse_config_str(cfg, "pve.example.local");
            assert_eq!(user, Some("root".to_string()));
        }
    }

    /// Priority-chain tests for `resolve_ssh_user` (sys-tn4).
    /// Order: --user CLI flag > SSH config User > $USER/$USERNAME > "root".
    #[cfg(feature = "ssh-client")]
    mod resolve_ssh_user_tests {
        use super::super::impl_ssh_client::resolve_ssh_user;

        #[test]
        fn cli_override_wins_over_everything() {
            let got = resolve_ssh_user(Some("alice"), Some("bob"), Some("carol"));
            assert_eq!(got, "alice", "CLI --user must win over config and env");
        }

        #[test]
        fn config_user_when_no_cli_override() {
            let got = resolve_ssh_user(None, Some("claude"), Some("user"));
            assert_eq!(
                got, "claude",
                "SSH config User must win over env when no CLI flag"
            );
        }

        #[test]
        fn env_user_when_no_cli_or_config() {
            let got = resolve_ssh_user(None, None, Some("user"));
            assert_eq!(
                got, "user",
                "env $USER must be used when no CLI and no config"
            );
        }

        #[test]
        fn root_as_last_resort_only() {
            let got = resolve_ssh_user(None, None, None);
            assert_eq!(got, "root", "fallback to root only when no other source");
        }

        #[test]
        fn empty_cli_override_skipped() {
            // Clap gives us None for absent flag, but defend against empty string anyway
            let got = resolve_ssh_user(Some(""), Some("claude"), Some("user"));
            assert_eq!(got, "claude", "empty --user string must fall through");
        }

        #[test]
        fn empty_config_user_skipped() {
            let got = resolve_ssh_user(None, Some(""), Some("user"));
            assert_eq!(got, "user", "empty config User must fall through");
        }

        #[test]
        fn empty_env_user_skipped() {
            let got = resolve_ssh_user(None, None, Some(""));
            assert_eq!(got, "root", "empty env user must fall through to root");
        }

        /// Regression test for the exact sys-tn4 scenario:
        /// automation.example.local requires User=claude (no root).
        /// Before fix: mrsh fell back to SSH as root → rejected.
        /// After fix: SSH config User=claude is picked up, auth succeeds.
        #[test]
        fn claude_automation_scenario() {
            // No --user flag, SSH config says User=claude, env is user
            let got = resolve_ssh_user(None, Some("claude"), Some("user"));
            assert_eq!(
                got, "claude",
                "sys-tn4: automation.example.local must use 'claude' from ssh config, not 'root' or 'user'"
            );
        }
    }

    #[cfg(feature = "ssh-client")]
    mod shell_env_tests {
        use super::super::impl_ssh_client::{forwarded_env_vars, requested_shell};

        #[test]
        fn requested_shell_reads_mrsh_shell() {
            let env_vars = vec![
                "FOO=bar".to_string(),
                "MRSH_SHELL=pwsh.exe".to_string(),
                "BAZ=qux".to_string(),
            ];
            assert_eq!(requested_shell(&env_vars), Some("pwsh.exe"));
        }

        #[test]
        fn forwarded_env_vars_skip_mrsh_shell_and_invalid_entries() {
            let env_vars = vec![
                "FOO=bar".to_string(),
                "MRSH_SHELL=bash".to_string(),
                "INVALID".to_string(),
                "=oops".to_string(),
                "BAZ=qux".to_string(),
            ];
            let got: Vec<(&str, &str)> = forwarded_env_vars(&env_vars).collect();
            assert_eq!(got, vec![("FOO", "bar"), ("BAZ", "qux")]);
        }
    }

    /// Key-loading fallback tests for sys-fg7.
    /// Covers OpenSSH PEM loading (existing behavior) and raw ed25519
    /// binary fallback (new behavior for mrsh native keys).
    #[cfg(feature = "ssh-client")]
    mod ssh_key_fallback_tests {
        use super::super::impl_ssh_client::*;

        #[test]
        fn load_openssh_pem_ed25519_key() {
            let dir = tempfile::tempdir().unwrap();

            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let ed_kp = russh::keys::ssh_key::private::Ed25519Keypair {
                public: russh::keys::ssh_key::public::Ed25519PublicKey(
                    signing_key.verifying_key().to_bytes(),
                ),
                private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(
                    &signing_key.to_bytes(),
                ),
            };
            let private_key = russh::keys::ssh_key::PrivateKey::new(
                russh::keys::ssh_key::private::KeypairData::Ed25519(ed_kp),
                "test",
            )
            .unwrap();
            let openssh_str = private_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .to_string();

            let key_path = dir.path().join("id_ed25519_openssh");
            std::fs::write(&key_path, &openssh_str).unwrap();

            let result = load_secret_key_with_fallback(&key_path);
            assert!(
                result.is_ok(),
                "should load OpenSSH PEM ed25519 key: {:?}",
                result.err()
            );
            let key = result.unwrap();
            assert_eq!(
                key.algorithm(),
                russh::keys::ssh_key::Algorithm::Ed25519,
                "loaded key should be ed25519"
            );
        }

        #[test]
        fn load_raw_32byte_ed25519_seed() {
            let dir = tempfile::tempdir().unwrap();

            // Generate a 32-byte random seed (mimics mrsh native key format)
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let seed = signing_key.to_bytes();
            assert_eq!(seed.len(), 32);

            let key_path = dir.path().join("id_ed25519_raw32");
            std::fs::write(&key_path, &seed).unwrap();

            let result = load_secret_key_with_fallback(&key_path);
            assert!(
                result.is_ok(),
                "should load raw 32-byte ed25519 seed: {:?}",
                result.err()
            );
            let key = result.unwrap();
            assert_eq!(
                key.algorithm(),
                russh::keys::ssh_key::Algorithm::Ed25519,
                "converted key should be ed25519"
            );
        }

        #[test]
        fn load_raw_64byte_ed25519_expanded() {
            let dir = tempfile::tempdir().unwrap();

            // 64-byte key = seed (32B) + public key (32B)
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut expanded = Vec::with_capacity(64);
            expanded.extend_from_slice(&signing_key.to_bytes());
            expanded.extend_from_slice(&signing_key.verifying_key().to_bytes());
            assert_eq!(expanded.len(), 64);

            let key_path = dir.path().join("id_ed25519_raw64");
            std::fs::write(&key_path, &expanded).unwrap();

            let result = load_secret_key_with_fallback(&key_path);
            assert!(
                result.is_ok(),
                "should load raw 64-byte ed25519 key: {:?}",
                result.err()
            );
            let key = result.unwrap();
            assert_eq!(
                key.algorithm(),
                russh::keys::ssh_key::Algorithm::Ed25519,
                "converted key should be ed25519"
            );
        }

        #[test]
        fn raw_32byte_key_produces_correct_pubkey() {
            let dir = tempfile::tempdir().unwrap();

            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let expected_pubkey = signing_key.verifying_key().to_bytes();
            let key_path = dir.path().join("id_ed25519_raw32_pub");
            std::fs::write(&key_path, &signing_key.to_bytes()).unwrap();

            let key = load_secret_key_with_fallback(&key_path).unwrap();

            // Build the equivalent OpenSSH PEM from the same seed
            let dir2 = tempfile::tempdir().unwrap();
            let ed_kp = russh::keys::ssh_key::private::Ed25519Keypair {
                public: russh::keys::ssh_key::public::Ed25519PublicKey(expected_pubkey),
                private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(
                    &signing_key.to_bytes(),
                ),
            };
            let pem_key = russh::keys::ssh_key::PrivateKey::new(
                russh::keys::ssh_key::private::KeypairData::Ed25519(ed_kp),
                "",
            )
            .unwrap();
            let pem_path = dir2.path().join("id_ed25519_pem");
            std::fs::write(
                &pem_path,
                pem_key
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .unwrap()
                    .to_string(),
            )
            .unwrap();
            let pem_loaded = russh::keys::load_secret_key(&pem_path, None).unwrap();

            // Raw-converted and PEM-loaded keys must produce identical public keys
            assert_eq!(
                key.public_key().to_bytes().unwrap(),
                pem_loaded.public_key().to_bytes().unwrap(),
                "raw-converted and PEM-loaded keys should have same public key"
            );
        }

        #[test]
        fn reject_invalid_size_raw_key() {
            let dir = tempfile::tempdir().unwrap();

            // 48 bytes — not a valid raw ed25519 key size
            let key_path = dir.path().join("id_ed25519_bad");
            std::fs::write(&key_path, [0xABu8; 48]).unwrap();

            let result = load_secret_key_with_fallback(&key_path);
            assert!(result.is_err(), "should reject 48-byte file");
            let err = result.unwrap_err();
            assert!(
                err.contains("not OpenSSH PEM and not raw ed25519"),
                "error should mention format mismatch: {}",
                err
            );
        }

        #[test]
        fn mrsh_key_candidates_returns_vec() {
            // Just verify the function doesn't panic and returns a Vec
            let candidates = mrsh_key_candidates();
            // Can't assert specific paths exist in CI, but should not panic
            assert!(
                candidates.len() <= 2,
                "at most 2 mrsh key paths (user + system)"
            );
        }
    }
}
