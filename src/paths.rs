//! Path helpers: server data dir, authorized_keys lookup, local network discovery.

/// Discover local IPv4 addresses by binding UDP to common LAN gateways.
pub(crate) fn get_local_addrs() -> Vec<std::net::Ipv4Addr> {
    let mut addrs = Vec::new();
    // Read from /proc/net/fib_trie on Linux, or use getifaddrs equivalent.
    // Cross-platform: just try binding UDP to discover local IPs.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Try connecting to common LAN gateways to discover our IPs.
        for target in &[
            "192.168.0.1:80",
            "192.168.1.1:80",
            "10.0.0.1:80",
            "172.16.0.1:80",
        ] {
            if sock.connect(target).is_ok()
                && let Ok(local) = sock.local_addr()
                && let std::net::SocketAddr::V4(v4) = local
                && !addrs.contains(v4.ip())
            {
                addrs.push(*v4.ip());
            }
        }
    }
    // Also try to parse from system interfaces
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                for part in s.split_whitespace() {
                    if let Ok(ip) = part.parse::<std::net::Ipv4Addr>() {
                        if !addrs.contains(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
            }
        }
    }
    addrs
}

/// Check if an IPv4 address is on the same /24 subnet as any local address.
pub(crate) fn ipv4_same_lan(
    remote_ip: std::net::Ipv4Addr,
    local_addrs: &[std::net::Ipv4Addr],
) -> bool {
    let remote_octets = remote_ip.octets();
    local_addrs.iter().any(|local| {
        let l = local.octets();
        remote_octets[0] == l[0] && remote_octets[1] == l[1] && remote_octets[2] == l[2]
    })
}

/// Check if a remote socket address is on the same /24 subnet as any local address.
pub(crate) fn is_same_lan(
    remote: std::net::SocketAddr,
    local_addrs: &[std::net::Ipv4Addr],
) -> bool {
    match remote {
        std::net::SocketAddr::V4(v4) => ipv4_same_lan(*v4.ip(), local_addrs),
        _ => false,
    }
}

/// Return ALL possible authorized_keys paths (primary first, then fallbacks).
/// The server should load keys from ALL of these, merging and deduplicating.
pub(crate) fn all_authorized_keys_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // Primary: the data_dir we'd normally use
    let primary = server_data_dir();
    paths.push(primary.join("authorized_keys"));

    #[cfg(target_os = "windows")]
    {
        // System-wide location (service)
        let system_dir = std::path::PathBuf::from(r"C:\ProgramData\mrsh");
        let system_ak = system_dir.join("authorized_keys");
        if !paths.contains(&system_ak) {
            paths.push(system_ak);
        }

        // User home location (tray)
        if let Some(home) = std::env::var_os("USERPROFILE") {
            let user_ak = std::path::PathBuf::from(home)
                .join(".mrsh")
                .join("authorized_keys");
            if !paths.contains(&user_ak) {
                paths.push(user_ak);
            }
        }

        // Legacy location
        let legacy_ak =
            std::path::PathBuf::from(r"C:\ProgramData\remote-shell").join("authorized_keys");
        if !paths.contains(&legacy_ak) {
            paths.push(legacy_ak);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // System-wide: canonical /etc/mrsh first, legacy /etc/rsh fallback (rsh-ag8t)
        for dir in ["/etc/mrsh", "/etc/rsh"] {
            let etc_ak = std::path::PathBuf::from(dir).join("authorized_keys");
            if !paths.contains(&etc_ak) {
                paths.push(etc_ak);
            }
        }

        // User home
        if let Some(home) = std::env::var_os("HOME") {
            let user_ak = std::path::PathBuf::from(home)
                .join(".mrsh")
                .join("authorized_keys");
            if !paths.contains(&user_ak) {
                paths.push(user_ak);
            }
        }
    }

    paths
}

/// Resolve the canonical server data directory.
///
/// `MRSH_DATA_DIR` env var overrides on all platforms (custom-path installs).
/// Windows: `C:\ProgramData\mrsh` (migrating from legacy `C:\ProgramData\remote-shell`),
/// or `%USERPROFILE%\.mrsh` as fallback.
/// Linux: `/etc/mrsh` (root/service, migrating from legacy `/etc/rsh`), `~/.mrsh` (user mode).
pub(crate) fn server_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        // Explicit override (custom-path installs, e.g. C:\ProgramData\mrsh-id8000).
        // Mirrors the Linux branch so non-standard installs keep a persistent
        // host-key/TLS cert/authorized_keys instead of falling back to ephemeral.
        if let Some(d) = std::env::var_os("MRSH_DATA_DIR") {
            return std::path::PathBuf::from(d);
        }

        let new_dir = std::path::PathBuf::from(r"C:\ProgramData\mrsh");
        let legacy_dir = std::path::PathBuf::from(r"C:\ProgramData\remote-shell");

        // New location exists — use it
        if new_dir.exists() {
            return new_dir;
        }

        // Legacy location exists — migrate critical files then use new dir
        if legacy_dir.exists() && std::fs::create_dir_all(&new_dir).is_ok() {
            for name in &[
                "authorized_keys",
                "id_ed25519",
                "id_ed25519.pub",
                "device_id",
                "tls_cert.pem",
                "tls_key.pem",
                "banner.txt",
                "revoked_keys",
            ] {
                let src = legacy_dir.join(name);
                let dst = new_dir.join(name);
                if src.exists() && !dst.exists() {
                    let _ = std::fs::copy(&src, &dst);
                }
            }
            tracing::info!(
                "migrated data from {} to {}",
                legacy_dir.display(),
                new_dir.display()
            );
            return new_dir;
        }

        // Fall back to user home
        if let Some(home) = std::env::var_os("USERPROFILE") {
            return std::path::PathBuf::from(home).join(".mrsh");
        }

        new_dir
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Explicit override (Android root + RO /etc, embedded targets, tests).
        if let Some(d) = std::env::var_os("MRSH_DATA_DIR") {
            return std::path::PathBuf::from(d);
        }

        // Root/service mode: /etc/mrsh (canonical), migrating from legacy /etc/rsh.
        // Mirrors the Windows ProgramData\mrsh <- ProgramData\remote-shell pattern (rsh-ag8t).
        if unsafe { libc::geteuid() } == 0 {
            let new_dir = std::path::PathBuf::from("/etc/mrsh");
            let legacy_dir = std::path::PathBuf::from("/etc/rsh");

            // New location exists — use it
            if new_dir.exists() {
                return new_dir;
            }

            // Legacy location exists — migrate critical files then use new dir
            if legacy_dir.exists() && std::fs::create_dir_all(&new_dir).is_ok() {
                for name in &[
                    "authorized_keys",
                    "id_ed25519",
                    "id_ed25519.pub",
                    "device_id",
                    "tls_cert.pem",
                    "tls_key.pem",
                    "banner.txt",
                    "revoked_keys",
                    "config",
                    "config.enrollment",
                    "screen-token",
                ] {
                    let src = legacy_dir.join(name);
                    let dst = new_dir.join(name);
                    if src.exists() && !dst.exists() {
                        let _ = std::fs::copy(&src, &dst);
                    }
                }
                tracing::info!(
                    "migrated data from {} to {}",
                    legacy_dir.display(),
                    new_dir.display()
                );
                return new_dir;
            }

            // Legacy exists but new dir can't be created (RO /etc?) — keep legacy
            if legacy_dir.exists() {
                return legacy_dir;
            }

            return new_dir;
        }

        // User mode: ~/.mrsh/
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(".mrsh");
        }

        std::path::PathBuf::from("/etc/mrsh")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression rsh-ag8t: on Unix the system-wide authorized_keys lookup
    /// must include BOTH the canonical /etc/mrsh AND the legacy /etc/rsh,
    /// with the canonical path searched first.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn authorized_keys_paths_include_canonical_then_legacy() {
        let paths = all_authorized_keys_paths();
        let mrsh_idx = paths
            .iter()
            .position(|p| p == std::path::Path::new("/etc/mrsh/authorized_keys"))
            .expect("/etc/mrsh/authorized_keys missing from lookup list");
        let rsh_idx = paths
            .iter()
            .position(|p| p == std::path::Path::new("/etc/rsh/authorized_keys"))
            .expect("/etc/rsh/authorized_keys (legacy) missing from lookup list");
        assert!(
            mrsh_idx < rsh_idx,
            "canonical /etc/mrsh must precede legacy /etc/rsh"
        );
    }

    /// `MRSH_DATA_DIR` must override the platform default on every OS
    /// (Linux parity for Windows custom-path installs — desk-ryp).
    #[test]
    fn server_data_dir_honors_mrsh_data_dir_override() {
        // Env mutation is process-global; keep this test self-contained.
        let prev = std::env::var_os("MRSH_DATA_DIR");
        let custom = if cfg!(target_os = "windows") {
            r"C:\ProgramData\mrsh-test-override"
        } else {
            "/tmp/mrsh-test-override"
        };
        // SAFETY: single-threaded test; env restored before returning.
        unsafe { std::env::set_var("MRSH_DATA_DIR", custom) };

        assert_eq!(server_data_dir(), std::path::PathBuf::from(custom));

        // Restore prior environment.
        // SAFETY: single-threaded test cleanup.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("MRSH_DATA_DIR", v),
                None => std::env::remove_var("MRSH_DATA_DIR"),
            }
        }
    }
}
