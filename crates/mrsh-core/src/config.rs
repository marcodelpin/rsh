//! ~/.mrsh/config parser — SSH-style config with Host blocks.

use std::path::PathBuf;

/// LAN-first resolution policy for a host (rsh-x9l5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LanFirst {
    /// Try mDNS `<host>.local` first; fall back to rdv on failure.
    #[default]
    Auto,
    /// LAN path only — return an error if not reachable via mDNS/direct.
    Yes,
    /// Skip LAN probe entirely; use rdv directly (old behaviour).
    No,
}

impl LanFirst {
    /// Parse from config value string. Unknown values default to `Auto`.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => LanFirst::Yes,
            "no" | "false" | "0" => LanFirst::No,
            _ => LanFirst::Auto, // "auto" or anything unrecognised
        }
    }
}

/// A single host entry from the config file.
#[derive(Debug, Clone, Default)]
pub struct HostConfig {
    pub pattern: String,
    pub hostname: Option<String>,
    pub port: u16,
    pub identity_file: Option<String>,
    pub user: Option<String>,
    pub mac: Option<String>,
    pub device_id: Option<String>,
    /// Human-friendly description (e.g., "Development GPU workstation").
    pub description: Option<String>,
    /// Secondary/Tailscale IP address.
    pub tailscale_ip: Option<String>,
    pub rendezvous_server: Option<String>,
    pub rendezvous_servers: Vec<String>,
    pub rendezvous_key: Option<String>,
    /// Per-host session logging override (true/false). None = inherit global.
    pub session_log: Option<bool>,
    /// QUIC port for this host (if QUIC transport is enabled on the server).
    pub quic_port: Option<u16>,
    /// Target OS override for fleet update binary selection.
    /// Accepted values (case-insensitive): "windows", "linux", "linux-musl",
    /// "linux-aarch64" (also accepts "linux-arm64", "aarch64", "arm64").
    /// When None, auto-detected from server capabilities at probe time.
    /// Useful for hosts that are offline during `fleet update` or that run
    /// a different libc/arch than the probed cap suggests.
    pub platform: Option<String>,
    /// Per-host release track override (e.g., "stable", "canary", "beta").
    /// Used by VersionAdvert protocol for staged rollouts (rsh-5264.3).
    pub track: Option<String>,
    /// Per-host opt-in for auto-upgrade flow (rsh-5264 epic).
    pub auto_upgrade: Option<bool>,
    /// LAN-first resolution policy (rsh-x9l5).
    ///
    /// `Auto` (default): try mDNS `<host>.local` before falling back to rdv.
    /// `Yes`: LAN path only — error if unreachable.
    /// `No`: skip LAN probe, go straight to rdv (preserves old behaviour).
    pub lan_first: LanFirst,
}

impl HostConfig {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            hostname: None,
            port: 8822,
            identity_file: None,
            user: None,
            mac: None,
            device_id: None,
            description: None,
            tailscale_ip: None,
            rendezvous_server: None,
            rendezvous_servers: Vec::new(),
            rendezvous_key: None,
            session_log: None,
            quic_port: None,
            platform: None,
            track: None,
            auto_upgrade: None,
            lan_first: LanFirst::Auto,
        }
    }

    /// Returns merged list of rendezvous servers (single + list).
    pub fn get_rendezvous_servers(&self) -> Vec<String> {
        let mut servers = Vec::new();
        if let Some(ref s) = self.rendezvous_server {
            servers.push(s.clone());
        }
        servers.extend(self.rendezvous_servers.iter().cloned());
        servers
    }
}

/// Parsed config file.
#[derive(Debug, Clone)]
pub struct Config {
    pub hosts: Vec<HostConfig>,
    pub device_id: Option<String>,
    pub rendezvous_server: Option<String>,
    pub rendezvous_servers: Vec<String>,
    pub rendezvous_key: Option<String>,
    /// Fleet enrollment token (base64). Server includes SHA256(token) in heartbeat.
    pub enrollment_token: Option<String>,
    /// Global session logging (default: true).
    pub session_log: bool,
    /// Directory for session log files (default: ~/.mrsh/logs).
    pub session_log_dir: Option<String>,
    /// Days to retain session logs (default: 90).
    pub session_log_retain: u32,
    /// Optional shared-filesystem spool dir. When set, the server also polls
    /// this directory for FS-transport sessions (see `mrsh_core::fs_transport`).
    /// Clients connect with `-h fs:///<path>`. None = TCP only.
    pub fs_spool: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            device_id: None,
            rendezvous_server: None,
            rendezvous_servers: Vec::new(),
            rendezvous_key: None,
            enrollment_token: None,
            session_log: true,
            session_log_dir: None,
            session_log_retain: 90,
            fs_spool: None,
        }
    }
}

impl Config {
    /// Returns the default config file path (~/.mrsh/config).
    pub fn default_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".mrsh").join("config"))
    }

    /// Returns the per-host release track, if a `Host <name>` block defines one.
    /// rsh-5264.3 staged rollouts.
    pub fn track_for(&self, hostname: &str) -> Option<String> {
        for h in &self.hosts {
            if h.pattern == hostname {
                return h.track.clone();
            }
        }
        None
    }

    /// Returns the per-host auto-upgrade flag, if defined. rsh-5264.5.
    pub fn auto_upgrade_for(&self, hostname: &str) -> Option<bool> {
        for h in &self.hosts {
            if h.pattern == hostname {
                return h.auto_upgrade;
            }
        }
        None
    }

    /// Load config with fallback chain:
    /// 1. ~/.mrsh/config (user config)
    /// 2. C:\ProgramData\mrsh\config.enrollment (installer enrollment config)
    /// 3. ~/.rsh/config (legacy)
    /// If user config exists but lacks rendezvous fields, merges from enrollment config.
    pub fn load() -> Self {
        // Primary: user config
        let user_cfg = Self::default_path()
            .and_then(|p| std::fs::read_to_string(&p).ok())
            .map(|c| Self::parse(&c));

        // Enrollment config from data dir (installer writes here)
        let enrollment_cfg = Self::load_enrollment();

        match (user_cfg, enrollment_cfg) {
            (Some(mut u), Some(e)) => {
                // Merge: user config wins, but fill missing rendezvous fields from enrollment
                if u.rendezvous_server.is_none() {
                    u.rendezvous_server = e.rendezvous_server;
                }
                if u.rendezvous_key.is_none() {
                    u.rendezvous_key = e.rendezvous_key;
                }
                if u.enrollment_token.is_none() {
                    u.enrollment_token = e.enrollment_token;
                }
                u
            }
            (Some(u), None) => u,
            (None, Some(e)) => e,
            (None, None) => {
                // Legacy: ~/.rsh/config
                dirs::home_dir()
                    .map(|h| h.join(".rsh").join("config"))
                    .and_then(|p| std::fs::read_to_string(&p).ok())
                    .map(|c| Self::parse(&c))
                    .unwrap_or_default()
            }
        }
    }

    /// Load enrollment config from the service data directory.
    /// Windows: C:\ProgramData\mrsh\config.enrollment
    /// Linux: /etc/mrsh/config.enrollment (legacy fallback /etc/rsh, rsh-ag8t)
    fn load_enrollment() -> Option<Self> {
        #[cfg(target_os = "windows")]
        let candidates = vec![std::path::PathBuf::from(r"C:\ProgramData\mrsh")];
        #[cfg(target_os = "android")]
        // Termux: HOME is /data/data/com.termux/files/home; no /etc writable to user.
        let candidates = vec![
            dirs::home_dir()
                .map(|h| h.join(".config").join("mrsh"))
                .unwrap_or_else(|| std::path::PathBuf::from("/data/local/tmp/mrsh")),
        ];
        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        // Canonical /etc/mrsh first, legacy /etc/rsh fallback (rsh-ag8t).
        let candidates = vec![
            std::path::PathBuf::from("/etc/mrsh"),
            std::path::PathBuf::from("/etc/rsh"),
        ];

        candidates
            .iter()
            .find_map(|d| std::fs::read_to_string(d.join("config.enrollment")).ok())
            .map(|c| Self::parse(&c))
    }

    /// Parse config from string content.
    pub fn parse(content: &str) -> Self {
        let mut cfg = Config::default();
        let mut current_host: Option<HostConfig> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key-value (space or = separated)
            let (key, value) = match line.split_once(char::is_whitespace) {
                Some((k, v)) => (k.trim(), v.trim()),
                None => match line.split_once('=') {
                    Some((k, v)) => (k.trim(), v.trim()),
                    None => continue,
                },
            };

            // Strip surrounding quotes
            let value = value.trim_matches(|c| c == '"' || c == '\'');

            match key.to_lowercase().as_str() {
                "host" => {
                    if let Some(host) = current_host.take() {
                        cfg.hosts.push(host);
                    }
                    current_host = Some(HostConfig::new(value));
                }
                "hostname" => {
                    if let Some(ref mut host) = current_host {
                        host.hostname = Some(value.to_string());
                    }
                }
                "port" => {
                    if let Some(ref mut host) = current_host
                        && let Ok(p) = value.parse::<u16>()
                    {
                        host.port = p;
                    }
                }
                "identityfile" => {
                    if let Some(ref mut host) = current_host {
                        let expanded = if value.starts_with("~/") {
                            dirs::home_dir()
                                .map(|h| h.join(&value[2..]).to_string_lossy().to_string())
                                .unwrap_or_else(|| value.to_string())
                        } else {
                            value.to_string()
                        };
                        host.identity_file = Some(expanded);
                    }
                }
                "user" => {
                    if let Some(ref mut host) = current_host {
                        host.user = Some(value.to_string());
                    }
                }
                "mac" | "macaddress" => {
                    if let Some(ref mut host) = current_host {
                        host.mac = Some(value.to_string());
                    }
                }
                "description" => {
                    if let Some(ref mut host) = current_host {
                        host.description = Some(value.to_string());
                    }
                }
                "tailscaleip" => {
                    if let Some(ref mut host) = current_host {
                        host.tailscale_ip = Some(value.to_string());
                    }
                }
                "deviceid" => {
                    if let Some(ref mut host) = current_host {
                        host.device_id = Some(value.to_string());
                    } else {
                        cfg.device_id = Some(value.to_string());
                    }
                }
                "rendezvousserver" | "rendezvous" => {
                    if let Some(ref mut host) = current_host {
                        host.rendezvous_server = Some(value.to_string());
                    } else {
                        cfg.rendezvous_server = Some(value.to_string());
                    }
                }
                "rendezvousservers" => {
                    let servers = parse_server_list(value);
                    if let Some(ref mut host) = current_host {
                        host.rendezvous_servers = servers;
                    } else {
                        cfg.rendezvous_servers = servers;
                    }
                }
                "rendezvouskey" => {
                    if let Some(ref mut host) = current_host {
                        host.rendezvous_key = Some(value.to_string());
                    } else {
                        cfg.rendezvous_key = Some(value.to_string());
                    }
                }
                "quicport" => {
                    if let Some(ref mut host) = current_host
                        && let Ok(p) = value.parse::<u16>()
                    {
                        host.quic_port = Some(p);
                    }
                }
                "platform" => {
                    // rsh-lic: per-host OS hint for fleet-update binary pick.
                    if let Some(ref mut host) = current_host {
                        host.platform = Some(value.to_lowercase());
                    }
                }
                "lanfirst" => {
                    if let Some(ref mut host) = current_host {
                        host.lan_first = LanFirst::from_str(value);
                    }
                }
                "enrollmenttoken" => {
                    if current_host.is_none() {
                        cfg.enrollment_token = Some(value.to_string());
                    }
                }
                "sessionlog" => {
                    let enabled = matches!(value.to_lowercase().as_str(), "true" | "yes" | "1");
                    if let Some(ref mut host) = current_host {
                        host.session_log = Some(enabled);
                    } else {
                        cfg.session_log = enabled;
                    }
                }
                "sessionlogdir" => {
                    if current_host.is_none() {
                        let expanded = if value.starts_with("~/") {
                            dirs::home_dir()
                                .map(|h| h.join(&value[2..]).to_string_lossy().to_string())
                                .unwrap_or_else(|| value.to_string())
                        } else {
                            value.to_string()
                        };
                        cfg.session_log_dir = Some(expanded);
                    }
                }
                "sessionlogretain" => {
                    if current_host.is_none()
                        && let Ok(days) = value.parse::<u32>()
                    {
                        cfg.session_log_retain = days;
                    }
                }
                "fsspool" => {
                    // FS-transport spool dir (server side). Global-only.
                    if current_host.is_none() {
                        let expanded = if value.starts_with("~/") {
                            dirs::home_dir()
                                .map(|h| h.join(&value[2..]).to_string_lossy().to_string())
                                .unwrap_or_else(|| value.to_string())
                        } else {
                            value.to_string()
                        };
                        cfg.fs_spool = Some(expanded);
                    }
                }
                _ => {} // Ignore unknown keys
            }
        }

        if let Some(host) = current_host {
            cfg.hosts.push(host);
        }

        cfg
    }

    /// Find the best matching host configuration.
    pub fn find_host(&self, name: &str) -> Option<&HostConfig> {
        self.hosts.iter().find(|h| match_pattern(&h.pattern, name))
    }

    /// rsh-le15: resolve the effective client key path for connecting to `name`.
    ///
    /// Precedence (matches SSH semantics):
    ///   1. explicit `-i` flag (`cli_key`)
    ///   2. the matching Host block's `IdentityFile`
    ///   3. `None` — caller falls back to default `~/.ssh/id_ed25519` discovery
    ///
    /// The TLS/relay/transfer paths previously used only the `-i` flag and
    /// silently ignored a config-only `IdentityFile` (only the SSH transport
    /// honored it), so config-only auth failed the TLS handshake until the key
    /// was copied to the default path.
    pub fn resolve_identity_file(&self, name: &str, cli_key: &Option<String>) -> Option<String> {
        cli_key
            .clone()
            .or_else(|| self.find_host(name).and_then(|h| h.identity_file.clone()))
    }

    /// Returns merged list of global rendezvous servers (single + list).
    pub fn get_rendezvous_servers(&self) -> Vec<String> {
        let mut servers = Vec::new();
        if let Some(ref s) = self.rendezvous_server {
            servers.push(s.clone());
        }
        servers.extend(self.rendezvous_servers.iter().cloned());
        servers
    }

    /// Check if session logging is enabled for a given host.
    /// Per-host setting overrides global.
    pub fn is_session_log_enabled(&self, host: &str) -> bool {
        if let Some(hc) = self.find_host(host)
            && let Some(enabled) = hc.session_log
        {
            return enabled;
        }
        self.session_log
    }

    /// Returns the session log directory path (creates if needed).
    pub fn session_log_dir(&self) -> PathBuf {
        if let Some(ref dir) = self.session_log_dir {
            PathBuf::from(dir)
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".mrsh")
                .join("logs")
        }
    }

    /// Serialize config back to SSH-style text.
    pub fn to_string(&self) -> String {
        let mut sb = String::new();

        // Global settings
        if let Some(ref id) = self.device_id {
            sb.push_str(&format!("DeviceID {}\n", id));
        }
        if let Some(ref s) = self.rendezvous_server {
            sb.push_str(&format!("RendezvousServer {}\n", s));
        }
        if !self.rendezvous_servers.is_empty() {
            sb.push_str(&format!(
                "RendezvousServers {}\n",
                self.rendezvous_servers.join(", ")
            ));
        }
        if let Some(ref k) = self.rendezvous_key {
            sb.push_str(&format!("RendezvousKey {}\n", k));
        }
        if let Some(ref t) = self.enrollment_token {
            sb.push_str(&format!("EnrollmentToken {}\n", t));
        }
        if !self.session_log {
            sb.push_str("SessionLog false\n");
        }
        if let Some(ref dir) = self.session_log_dir {
            sb.push_str(&format!("SessionLogDir {}\n", dir));
        }
        if self.session_log_retain != 90 {
            sb.push_str(&format!("SessionLogRetain {}\n", self.session_log_retain));
        }
        if let Some(ref p) = self.fs_spool {
            sb.push_str(&format!("FsSpool {}\n", p));
        }

        let has_global = self.device_id.is_some()
            || self.rendezvous_server.is_some()
            || !self.rendezvous_servers.is_empty()
            || self.rendezvous_key.is_some()
            || self.enrollment_token.is_some()
            || !self.session_log
            || self.fs_spool.is_some();

        if has_global && !self.hosts.is_empty() {
            sb.push('\n');
        }

        for (i, h) in self.hosts.iter().enumerate() {
            if i > 0 {
                sb.push('\n');
            }
            sb.push_str(&format!("Host {}\n", h.pattern));
            if let Some(ref v) = h.hostname {
                sb.push_str(&format!("    Hostname {}\n", v));
            }
            if h.port > 0 {
                sb.push_str(&format!("    Port {}\n", h.port));
            }
            if let Some(ref v) = h.identity_file {
                sb.push_str(&format!("    IdentityFile {}\n", v));
            }
            if let Some(ref v) = h.user {
                sb.push_str(&format!("    User {}\n", v));
            }
            if let Some(ref v) = h.mac {
                sb.push_str(&format!("    MAC {}\n", v));
            }
            if let Some(ref v) = h.device_id {
                sb.push_str(&format!("    DeviceID {}\n", v));
            }
            if let Some(ref v) = h.description {
                sb.push_str(&format!("    Description {}\n", v));
            }
            if let Some(ref v) = h.tailscale_ip {
                sb.push_str(&format!("    TailscaleIP {}\n", v));
            }
            if let Some(ref v) = h.rendezvous_server {
                sb.push_str(&format!("    RendezvousServer {}\n", v));
            }
            if !h.rendezvous_servers.is_empty() {
                sb.push_str(&format!(
                    "    RendezvousServers {}\n",
                    h.rendezvous_servers.join(", ")
                ));
            }
            if let Some(ref v) = h.rendezvous_key {
                sb.push_str(&format!("    RendezvousKey {}\n", v));
            }
            if let Some(enabled) = h.session_log {
                sb.push_str(&format!(
                    "    SessionLog {}\n",
                    if enabled { "true" } else { "false" }
                ));
            }
            // Only serialise when explicitly set (auto is the default, no need to write it)
            match h.lan_first {
                LanFirst::Yes => sb.push_str("    LanFirst yes\n"),
                LanFirst::No => sb.push_str("    LanFirst no\n"),
                LanFirst::Auto => {} // default — omit
            }
        }

        sb
    }

    /// Save config to the default path (~/.mrsh/config).
    /// Update a host's DeviceID and rendezvous server from auth response.
    /// Creates a new Host block if none exists for this hostname.
    /// Returns true if the config was modified.
    pub fn update_host_relay_info(
        &mut self,
        hostname: &str,
        device_id: Option<&str>,
        rendezvous_server: Option<&str>,
    ) -> bool {
        if device_id.is_none() && rendezvous_server.is_none() {
            return false;
        }

        // Find existing host by pattern or hostname
        let existing = self.hosts.iter_mut().find(|h| {
            h.pattern.eq_ignore_ascii_case(hostname)
                || h.hostname
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(hostname))
                    .unwrap_or(false)
        });

        if let Some(host) = existing {
            let mut changed = false;
            if let Some(id) = device_id {
                if host.device_id.as_deref() != Some(id) {
                    host.device_id = Some(id.to_string());
                    changed = true;
                }
            }
            if let Some(rdv) = rendezvous_server {
                if host.rendezvous_server.as_deref() != Some(rdv) {
                    host.rendezvous_server = Some(rdv.to_string());
                    changed = true;
                }
            }
            changed
        } else {
            // Create new Host block
            let mut host = HostConfig {
                pattern: hostname.to_string(),
                ..Default::default()
            };
            if let Some(id) = device_id {
                host.device_id = Some(id.to_string());
            }
            if let Some(rdv) = rendezvous_server {
                host.rendezvous_server = Some(rdv.to_string());
            }
            self.hosts.push(host);
            true
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::default_path().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "cannot determine config path")
        })?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, self.to_string())
    }
}

/// Split comma/space-separated server list.
fn parse_server_list(value: &str) -> Vec<String> {
    value
        .replace(',', " ")
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Match a glob pattern against a name (* and ? wildcards).
fn match_pattern(pattern: &str, name: &str) -> bool {
    // Convert glob to regex
    let mut regex = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }
    regex.push('$');

    regex::Regex::new(&regex)
        .map(|re| re.is_match(name))
        .unwrap_or(pattern == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONFIG: &str = r#"# Global settings
RendezvousServer rdv.example.com:21116
RendezvousKey dGVzdGtleUV4YW1wbGVLZXkxMjM0NTY3ODkwYWJjZGVm

Host server-a
    Hostname server-a.local
    Port 8822

Host server-b
    Hostname server-b.local
    Port 22
    DeviceID 123456789

Host web-*
    Hostname 192.168.1.130
    Port 8822

Host laptop-1
    Hostname laptop-1.local
    Port 8822
    DeviceID 987654321
"#;

    #[test]
    fn parse_global_settings() {
        let cfg = Config::parse(TEST_CONFIG);
        assert_eq!(
            cfg.rendezvous_server.as_deref(),
            Some("rdv.example.com:21116")
        );
        assert_eq!(
            cfg.rendezvous_key.as_deref(),
            Some("dGVzdGtleUV4YW1wbGVLZXkxMjM0NTY3ODkwYWJjZGVm")
        );
    }

    #[test]
    fn resolve_identity_file_precedence() {
        // rsh-le15 regression: TLS/relay path must honor a config-only IdentityFile.
        // Precedence: -i flag > Host block IdentityFile > None (default discovery).
        let cfg = Config::parse(
            "Host with-key\n    Hostname with-key.local\n    Port 8822\n    \
             IdentityFile /home/user/.ssh/id_ed25519_gitlab\n",
        );

        // 1. explicit -i flag wins over the config IdentityFile
        let flag = Some("/explicit/flag/key".to_string());
        assert_eq!(
            cfg.resolve_identity_file("with-key", &flag).as_deref(),
            Some("/explicit/flag/key"),
            "-i flag must take precedence over config IdentityFile"
        );

        // 2. no -i flag → config IdentityFile is honored (the bug: TLS path ignored it)
        assert_eq!(
            cfg.resolve_identity_file("with-key", &None).as_deref(),
            Some("/home/user/.ssh/id_ed25519_gitlab"),
            "config IdentityFile must be honored when -i is absent"
        );

        // 3. host without IdentityFile + no -i → None (caller falls back to discovery)
        let plain = Config::parse("Host plain\n    Hostname plain.local\n    Port 8822\n");
        assert_eq!(plain.resolve_identity_file("plain", &None), None);

        // 4. unknown host + no -i → None
        assert_eq!(cfg.resolve_identity_file("nonexistent", &None), None);
    }

    #[test]
    fn parse_hosts() {
        let cfg = Config::parse(TEST_CONFIG);
        assert_eq!(cfg.hosts.len(), 4);
        assert_eq!(cfg.hosts[0].pattern, "server-a");
        assert_eq!(cfg.hosts[0].hostname.as_deref(), Some("server-a.local"));
        assert_eq!(cfg.hosts[0].port, 8822);
    }

    #[test]
    fn parse_device_id() {
        let cfg = Config::parse(TEST_CONFIG);
        let hp = cfg.find_host("server-b").unwrap();
        assert_eq!(hp.device_id.as_deref(), Some("123456789"));
        assert_eq!(hp.port, 22);
    }

    #[test]
    fn glob_pattern_match() {
        let cfg = Config::parse(TEST_CONFIG);
        // Exact match
        assert!(cfg.find_host("server-a").is_some());
        // Wildcard match
        assert!(cfg.find_host("web-frontend").is_some());
        assert!(cfg.find_host("web-api01").is_some());
        // No match
        assert!(cfg.find_host("unknown-host").is_none());
    }

    #[test]
    fn get_rendezvous_servers_merged() {
        let cfg = Config::parse(
            "RendezvousServer primary.com:21116\nRendezvousServers backup1.com:21116, backup2.com:21116\n",
        );
        let servers = cfg.get_rendezvous_servers();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "primary.com:21116");
        assert_eq!(servers[1], "backup1.com:21116");
        assert_eq!(servers[2], "backup2.com:21116");
    }

    #[test]
    fn empty_config() {
        let cfg = Config::parse("");
        assert!(cfg.hosts.is_empty());
        assert!(cfg.rendezvous_server.is_none());
        assert!(cfg.enrollment_token.is_none());
    }

    #[test]
    fn parse_enrollment_token() {
        let cfg = Config::parse("EnrollmentToken abc123base64token==\n");
        assert_eq!(cfg.enrollment_token.as_deref(), Some("abc123base64token=="));
    }

    #[test]
    fn enrollment_token_round_trip() {
        let cfg = Config::parse("EnrollmentToken mytoken123\nDeviceID 999\n");
        let output = cfg.to_string();
        let cfg2 = Config::parse(&output);
        assert_eq!(cfg2.enrollment_token.as_deref(), Some("mytoken123"));
        assert_eq!(cfg2.device_id.as_deref(), Some("999"));
    }

    #[test]
    fn parse_server_list_commas_and_spaces() {
        assert_eq!(
            parse_server_list("a:21116, b:21116 c:21116"),
            vec!["a:21116", "b:21116", "c:21116"]
        );
    }

    #[test]
    fn session_log_dir_default() {
        let cfg = Config::parse("");
        let dir = cfg.session_log_dir();
        assert!(
            dir.ends_with(".mrsh/logs")
                || dir.ends_with(".mrsh\\logs")
                || dir.ends_with(".rsh/logs")
        );
    }

    #[test]
    fn session_log_dir_custom() {
        let cfg = Config::parse("SessionLogDir /custom/logs\n");
        assert_eq!(
            cfg.session_log_dir(),
            std::path::PathBuf::from("/custom/logs")
        );
    }

    #[test]
    fn session_log_enabled_global_default() {
        let cfg = Config::parse("");
        // Default is true
        assert!(cfg.is_session_log_enabled("any-host"));
    }

    #[test]
    fn session_log_disabled_global() {
        let cfg = Config::parse("SessionLog false\n");
        assert!(!cfg.is_session_log_enabled("any-host"));
    }

    #[test]
    fn session_log_per_host_override() {
        let cfg = Config::parse(
            "SessionLog true\n\nHost nolog\n    Hostname nolog.local\n    SessionLog false\n",
        );
        assert!(cfg.is_session_log_enabled("other"));
        assert!(!cfg.is_session_log_enabled("nolog"));
    }

    #[test]
    fn parse_description_and_tailscale_ip() {
        let cfg = Config::parse(
            "Host gpu\n    Hostname gpu-server.local\n    Description Development GPU workstation\n    TailscaleIP 100.64.0.1\n",
        );
        let h = cfg.find_host("gpu").unwrap();
        assert_eq!(
            h.description.as_deref(),
            Some("Development GPU workstation")
        );
        assert_eq!(h.tailscale_ip.as_deref(), Some("100.64.0.1"));
    }

    #[test]
    fn description_tailscale_round_trip() {
        let input = "Host gpu\n    Hostname gpu-server.local\n    Port 8822\n    Description Dev GPU\n    TailscaleIP 100.1.2.3\n";
        let cfg = Config::parse(input);
        let output = cfg.to_string();
        let cfg2 = Config::parse(&output);
        let h = cfg2.find_host("gpu").unwrap();
        assert_eq!(h.description.as_deref(), Some("Dev GPU"));
        assert_eq!(h.tailscale_ip.as_deref(), Some("100.1.2.3"));
    }

    #[test]
    fn default_path_returns_some() {
        // Should return Some on any system with HOME set
        let path = Config::default_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(
            p.ends_with(".mrsh/config")
                || p.ends_with(".mrsh\\config")
                || p.ends_with(".rsh/config")
        );
    }
}
