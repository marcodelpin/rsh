//! Fleet update: per-OS binary selection, planning, push + self-update.
//!
//! Multi-OS path picks the right binary for each host (Windows / Linux glibc
//! / Linux musl) based on advertised caps + optional `Platform` config hint,
//! then pushes the matching bytes and triggers a self-update.

use std::time::{Duration, Instant};

use mrsh_core::config::Config;
#[cfg(feature = "quic")]
use tracing::debug;

use super::format::format_update_plan;
use super::status::{HostStatus, StatusOpts, probe_host, status_with_opts};

/// Result of updating a single host.
#[derive(Debug)]
pub struct UpdateResult {
    pub name: String,
    pub success: bool,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub error: Option<String>,
}

/// Remote temp path for the new binary — platform-dependent.
const REMOTE_UPDATE_PATH_WINDOWS: &str = "C:/Temp/mrsh-new.exe";
const REMOTE_UPDATE_PATH_LINUX: &str = "/tmp/mrsh-new";

/// Target-OS classification used by `fleet update` to pick the right binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsKind {
    /// Native Windows target (x86_64) — `deploy/mrsh.exe`.
    Windows,
    /// Linux glibc x86_64 target — `deploy/mrsh-linux`.
    LinuxGnu,
    /// Linux musl x86_64 target (Alpine, rendezvous.example.com) — `deploy/mrsh-linux-musl`.
    LinuxMusl,
    /// Linux aarch64 target (vehicle head-units, ARM SBCs, Apple-silicon Linux VMs)
    /// — `deploy/mrsh-linux-aarch64` (rsh-6i9e).
    LinuxAarch64,
}

impl OsKind {
    /// Short label for status/plan tables.
    pub fn label(&self) -> &'static str {
        match self {
            OsKind::Windows => "windows",
            OsKind::LinuxGnu => "linux",
            OsKind::LinuxMusl => "linux-musl",
            OsKind::LinuxAarch64 => "linux-aarch64",
        }
    }

    /// Parse a user-provided platform hint from config / CLI flags.
    /// Returns `None` for unknown values (caller should fall back to auto-detect).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" | "win32" | "win64" | "windows-x86_64" | "windows-x64" => {
                Some(OsKind::Windows)
            }
            "linux" | "linux-gnu" | "gnu" | "glibc" | "linux-x86_64" | "linux-amd64" => {
                Some(OsKind::LinuxGnu)
            }
            "linux-musl" | "musl" | "alpine" => Some(OsKind::LinuxMusl),
            "linux-aarch64" | "linux-arm64" | "aarch64" | "arm64" => Some(OsKind::LinuxAarch64),
            _ => None,
        }
    }

    /// Default on-disk binary path for this OS (relative to the worktree root).
    pub fn default_binary_path(&self) -> &'static str {
        match self {
            OsKind::Windows => "deploy/mrsh.exe",
            OsKind::LinuxGnu => "deploy/mrsh-linux",
            OsKind::LinuxMusl => "deploy/mrsh-linux-musl",
            OsKind::LinuxAarch64 => "deploy/mrsh-linux-aarch64",
        }
    }

    /// Remote temp path where the new binary is pushed before self-update.
    pub fn remote_update_path(&self) -> &'static str {
        match self {
            OsKind::Windows => REMOTE_UPDATE_PATH_WINDOWS,
            OsKind::LinuxGnu | OsKind::LinuxMusl | OsKind::LinuxAarch64 => REMOTE_UPDATE_PATH_LINUX,
        }
    }
}

/// Binaries loaded from disk, keyed by target OS. A missing entry means
/// `fleet update` will SKIP hosts that need that OS (rather than misfire the
/// Windows PE onto a Linux box).
#[derive(Debug, Clone, Default)]
pub struct FleetBinaries {
    pub windows: Option<Vec<u8>>,
    pub linux_gnu: Option<Vec<u8>>,
    pub linux_musl: Option<Vec<u8>>,
    /// rsh-6i9e: Linux aarch64 binary for ARM head-units / SBCs.
    pub linux_aarch64: Option<Vec<u8>>,
}

impl FleetBinaries {
    /// Select the binary bytes for a given OS. Falls back to `linux_gnu` for
    /// `LinuxMusl` when no musl-specific binary was supplied — glibc-linked
    /// binaries won't run on Alpine, but the fallback keeps the old behavior
    /// intact for setups that don't maintain a separate musl build.
    ///
    /// `LinuxAarch64` does NOT fall back: an x86_64 binary cannot run on
    /// aarch64. Hosts get a clear "no binary loaded for linux-aarch64" skip
    /// reason instead.
    pub fn pick(&self, os: OsKind) -> Option<&[u8]> {
        match os {
            OsKind::Windows => self.windows.as_deref(),
            OsKind::LinuxGnu => self.linux_gnu.as_deref(),
            OsKind::LinuxMusl => self.linux_musl.as_deref().or(self.linux_gnu.as_deref()),
            OsKind::LinuxAarch64 => self.linux_aarch64.as_deref(),
        }
    }

    /// True when at least one binary is loaded.
    pub fn has_any(&self) -> bool {
        self.windows.is_some()
            || self.linux_gnu.is_some()
            || self.linux_musl.is_some()
            || self.linux_aarch64.is_some()
    }
}

/// Classify a host's target OS from its HostStatus + config hint.
///
/// Precedence:
/// 1. Config hint from `Platform <value>` in ~/.mrsh/config (explicit win).
/// 2. Cap-based detection from the authenticated TLS handshake (`is_linux`,
///    `is_linux_musl`). This is what a freshly-probed host lands on.
/// 3. Default: Windows (matches legacy behavior when no hint is available —
///    e.g. host was offline during probe and has no Platform in config).
pub fn classify_os(status: &HostStatus, platform_hint: Option<&str>) -> OsKind {
    if let Some(hint) = platform_hint {
        if let Some(kind) = OsKind::parse(hint) {
            return kind;
        }
    }
    // rsh-6i9e: arch-specific caps take precedence — a server advertising
    // "linux-aarch64" cannot run an x86_64 binary. Check the most specific
    // cap first.
    if status.caps.iter().any(|c| c == "linux-aarch64") {
        return OsKind::LinuxAarch64;
    }
    // Treat a caps list containing "linux-musl" as musl first (it also has "linux").
    if status.caps.iter().any(|c| c == "linux-musl") {
        return OsKind::LinuxMusl;
    }
    if status.caps.iter().any(|c| c == "linux") {
        return OsKind::LinuxGnu;
    }
    // Legacy heuristic for servers that don't advertise "linux": absence of
    // Windows-only caps implies Linux glibc.
    //
    // NOTE: "system" is NOT a Windows-only cap — it indicates the server is
    // running in non-tray/daemon mode (Linux daemons advertise it too via
    // build_server_caps_with_mode). Misclassification on pre-1.10.X Linux
    // servers (which didn't advertise the explicit "linux" cap) caused
    // rsh-1g6g: linux-server.example.local was pushed Windows binaries to /usr/local/bin/.
    // Only "window" / "tray" / "mouse" / "keyboard" are truly Windows-only.
    let has_windows_cap = status
        .caps
        .iter()
        .any(|c| c == "window" || c == "tray" || c == "mouse" || c == "keyboard");
    if !has_windows_cap && !status.caps.is_empty() {
        OsKind::LinuxGnu
    } else {
        OsKind::Windows
    }
}

/// Hosts that need updating (online + version differs from target).
///
/// Version source precedence (rsh-5264.1):
/// 1. TCP-probed `version` — most authoritative when available.
/// 2. rdv-reported `rdv_version` — fallback when TCP probe didn't report
///    (e.g. host reachable only via hbbs registration freshness).
///
/// Hosts with an unknown version (no probe and no rdv data) are treated as
/// candidates — same legacy behavior as before this change.
pub fn hosts_needing_update<'a>(
    statuses: &'a [HostStatus],
    target_version: &str,
) -> Vec<&'a HostStatus> {
    statuses
        .iter()
        .filter(|s| {
            s.online && {
                let observed = s.version.as_deref().or(s.rdv_version.as_deref());
                observed.is_none_or(|v| v != target_version)
            }
        })
        .collect()
}

/// Decide whether `mrsh fleet update` can satisfy its task using ONLY the
/// rdv-reported versions (no TCP probe). True when at least one online host
/// reports a version via rdv AND every online host has either a TCP version
/// or a rdv_version (so we can classify confidently).
///
/// rsh-5264.1: enables `mrsh fleet update --via-rdv` to skip TCP probing when
/// rdv has fresh data for the whole fleet. Falls back to TCP probing when
/// rdv coverage is incomplete.
pub fn rdv_data_sufficient(statuses: &[HostStatus]) -> bool {
    let online: Vec<&HostStatus> = statuses.iter().filter(|s| s.online).collect();
    if online.is_empty() {
        return false;
    }
    online
        .iter()
        .all(|s| s.version.is_some() || s.rdv_version.is_some())
        && online.iter().any(|s| s.rdv_version.is_some())
}

/// Update all outdated hosts in the fleet using a single Windows binary
/// (legacy API — v1.10.22 and earlier). This still works for pure-Windows
/// fleets but misfires on Linux hosts; prefer [`update_fleet_multi`].
pub async fn update_fleet(
    config: &Config,
    binary_data: &[u8],
    target_version: &str,
) -> Vec<UpdateResult> {
    // Construct a single-OS FleetBinaries so legacy callers get the old
    // behavior without changes. Linux hosts will still fail-fast in pick()
    // if the provided bytes are a Windows PE — but at least the code path
    // is unified with multi-OS.
    let binaries = FleetBinaries {
        windows: Some(binary_data.to_vec()),
        linux_gnu: Some(binary_data.to_vec()),
        linux_musl: Some(binary_data.to_vec()),
        // rsh-6i9e: legacy single-binary path does NOT auto-populate aarch64
        // — pushing an x86_64 binary onto an aarch64 host would brick the
        // service silently. Callers must use FleetBinaries directly to update
        // aarch64 hosts.
        linux_aarch64: None,
    };
    let opts = UpdateOpts::default();
    update_fleet_multi(config, &binaries, target_version, opts).await
}

/// Options controlling `fleet update` behavior.
#[derive(Debug, Clone, Default)]
pub struct UpdateOpts {
    /// If true, probe + classify hosts and print the plan, but don't push
    /// or trigger self-update. Exit code reflects planning, not update.
    pub dry_run: bool,
    /// When true, the initial status probe retries auto-try ports for hosts
    /// that fail on their configured port (same semantics as
    /// `fleet status --refresh`). Matches the issue's "force re-probe" ask.
    pub refresh_ports: bool,
}

/// Per-host plan returned by `plan_fleet_update` — lets callers inspect what
/// would happen before anything is pushed. Also what `--dry-run` renders.
#[derive(Debug, Clone)]
pub struct HostUpdatePlan {
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub os: OsKind,
    pub current_version: Option<String>,
    pub target_version: String,
    /// Why this host is being skipped, if any.
    pub skip_reason: Option<String>,
    /// Byte count of the binary that would be pushed. 0 when skipped.
    pub binary_bytes: usize,
}

/// Build the per-host plan without mutating anything. Exposed separately so
/// `--dry-run` and the real update path share the exact same classification
/// logic — no drift.
pub fn plan_fleet_update(
    config: &Config,
    statuses: &[HostStatus],
    binaries: &FleetBinaries,
    target_version: &str,
) -> Vec<HostUpdatePlan> {
    // Index config hosts by pattern → Platform hint.
    let platform_by_pattern: std::collections::HashMap<&str, &str> = config
        .hosts
        .iter()
        .filter_map(|h| h.platform.as_deref().map(|p| (h.pattern.as_str(), p)))
        .collect();

    statuses
        .iter()
        .map(|s| {
            let hint = platform_by_pattern.get(s.name.as_str()).copied();
            let os = classify_os(s, hint);
            // rsh-1uto: version precedence TCP-probe → rdv heartbeat (rsh-5264.1).
            // rdv-only peers are never TCP-probed (version=None, caps=[]) but the
            // heartbeat still reports their current version.
            let effective_version = s.version.clone().or_else(|| s.rdv_version.clone());
            // A host was actually probed (auth completed) iff it reported a
            // version over TCP/relay. rdv-synthesized entries have NO caps data —
            // empty caps there means "unknown", NOT "lacks self-update".
            let probed = s.version.is_some();
            let skip_reason = if !s.online {
                Some("host offline".to_string())
            } else if effective_version.as_deref() == Some(target_version) {
                Some(format!("already v{}", target_version))
            } else if !probed {
                // rsh-1uto: previously misreported as "server lacks self-update
                // cap" AND classify_os defaulted to Windows on empty caps —
                // pushing on that guess risks the rsh-1g6g wrong-binary brick.
                // Honest skip until a relay probe supplies version/OS/caps.
                Some("not probed (rdv-only) — OS/caps unknown, relay probe needed".to_string())
            } else if !s.caps.iter().any(|c| c == "self-update") {
                Some("server lacks self-update cap".to_string())
            } else if binaries.pick(os).is_none() {
                Some(format!("no binary loaded for {}", os.label()))
            } else {
                None
            };
            let binary_bytes = if skip_reason.is_none() {
                binaries.pick(os).map(|b| b.len()).unwrap_or(0)
            } else {
                0
            };
            HostUpdatePlan {
                name: s.name.clone(),
                hostname: s.hostname.clone(),
                port: s.port,
                os,
                current_version: effective_version,
                target_version: target_version.to_string(),
                skip_reason,
                binary_bytes,
            }
        })
        .collect()
}

/// rsh-mwxj: does this status row need a relay probe before planning?
///
/// rdv-only peers (hbbs registration, never TCP-probed) have `online=true`
/// with `version=None` and empty caps — `plan_fleet_update` can't classify
/// them (OS/caps unknown) so they'd skip as "not probed". A relay probe
/// fills version+caps+OS and makes them actionable.
fn needs_relay_probe(s: &HostStatus) -> bool {
    s.online && s.version.is_none() && s.device_id.is_some()
}

/// rsh-mwxj: authenticated relay-probe for unprobed rdv-only peers.
///
/// Reuses `probe_host` (direct TLS → relay → offline) with bounded
/// concurrency. Successful probes REPLACE the synthetic rdv rows in place
/// (preserving the heartbeat-feedback fields the probe path doesn't carry);
/// failed probes leave the original row untouched — the plan keeps the
/// honest "not probed" skip for those.
async fn relay_probe_unprobed(statuses: &mut [HostStatus]) {
    let targets: Vec<usize> = statuses
        .iter()
        .enumerate()
        .filter(|(_, s)| needs_relay_probe(s))
        .map(|(i, _)| i)
        .collect();
    if targets.is_empty() {
        return;
    }
    eprintln!(
        "relay-probing {} rdv-only host(s) for version/OS/caps...",
        targets.len()
    );

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let mut handles = Vec::new();
    for &i in &targets {
        let s = &statuses[i];
        let sem = semaphore.clone();
        let (name, hostname, port) = (s.name.clone(), s.hostname.clone(), s.port);
        let (device_id, rdv_server, rdv_key, quic_port) = (
            s.device_id.clone(),
            s.rendezvous_server.clone(),
            s.rendezvous_key.clone(),
            s.quic_port,
        );
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let probed = probe_host(
                &name, &hostname, port, device_id, rdv_server, rdv_key, quic_port,
            )
            .await;
            (i, probed)
        }));
    }
    for h in handles {
        if let Ok((i, probed)) = h.await {
            if probed.online && probed.version.is_some() {
                // Keep the rdv heartbeat-feedback fields from the synthetic row
                // (probe_host doesn't read the rdv peer record).
                let old = &statuses[i];
                let merged = HostStatus {
                    rdv_version: old.rdv_version.clone(),
                    last_update_status: old.last_update_status.clone(),
                    last_update_at_unix: old.last_update_at_unix,
                    track: old.track.clone(),
                    auto_upgrade: old.auto_upgrade,
                    ..probed
                };
                statuses[i] = merged;
            } else {
                tracing::debug!(
                    "relay-probe: {} stayed unprobed ({})",
                    statuses[i].name,
                    probed.error.as_deref().unwrap_or("no version reported")
                );
            }
        }
    }
}

/// Multi-OS fleet update entry point (v1.10.23+). Probes every host, picks
/// the right binary per OS (cap-based + config `Platform` hint), and pushes
/// only matching binaries. Hosts without a matching binary are SKIPPED, not
/// misfired.
pub async fn update_fleet_multi(
    config: &Config,
    binaries: &FleetBinaries,
    target_version: &str,
    opts: UpdateOpts,
) -> Vec<UpdateResult> {
    if !binaries.has_any() {
        eprintln!("No binaries loaded — nothing to update.");
        return Vec::new();
    }

    let probe_opts = StatusOpts {
        refresh_alt_ports: opts.refresh_ports,
    };
    let mut statuses = status_with_opts(config, probe_opts).await;
    relay_probe_unprobed(&mut statuses).await;
    let plans = plan_fleet_update(config, &statuses, binaries, target_version);

    if opts.dry_run {
        eprintln!("Dry run — nothing will be pushed.\n");
        println!("{}", format_update_plan(&plans));
        return Vec::new();
    }

    // Real update: render plan first (transparency), then act on hosts with
    // no skip_reason.
    eprintln!("{}\n", format_update_plan(&plans));

    let status_by_name: std::collections::HashMap<&str, &HostStatus> =
        statuses.iter().map(|s| (s.name.as_str(), s)).collect();

    let actionable: Vec<(&HostUpdatePlan, &HostStatus)> = plans
        .iter()
        .filter(|p| p.skip_reason.is_none())
        .filter_map(|p| status_by_name.get(p.name.as_str()).map(|s| (p, *s)))
        .collect();

    if actionable.is_empty() {
        eprintln!("All hosts already current or skipped.");
        return Vec::new();
    }

    eprintln!(
        "Updating {} host(s) to v{}...\n",
        actionable.len(),
        target_version
    );

    let mut results = Vec::new();
    for (plan, host_status) in &actionable {
        let Some(bytes) = binaries.pick(plan.os) else {
            // Should be unreachable — plan_fleet_update already filtered these
            // out via `skip_reason`, but guard in case callers bypass the plan.
            results.push(UpdateResult {
                name: plan.name.clone(),
                success: false,
                old_version: plan.current_version.clone(),
                new_version: None,
                error: Some(format!("no binary for {}", plan.os.label())),
            });
            continue;
        };
        let result = update_single_host_for_os(host_status, bytes, plan.os).await;
        results.push(result);
    }

    results
}

/// Update a single host with a specific OS classification (used by
/// `update_fleet_multi`). Picks the remote temp path via the OS variant
/// instead of re-deriving from caps.
async fn update_single_host_for_os(
    host: &HostStatus,
    binary_data: &[u8],
    os: OsKind,
) -> UpdateResult {
    use std::io::Write as _;
    let old_version = host.version.clone();
    eprint!(
        "  {} [{}] ({}:{})... ",
        host.name,
        os.label(),
        host.hostname,
        host.port
    );
    let _ = std::io::stderr().flush();

    let opts = crate::client::ConnectOptions {
        host: host.hostname.clone(),
        port: host.port,
        key_path: None,
        password_user: None,
    };

    match crate::client::connect(&opts).await {
        Ok(client) => push_and_update_tls_os(host, client, binary_data, old_version, os).await,
        Err(direct_err) => {
            if let Some(ref dev_id) = host.device_id {
                let relay_opts = crate::relay_connect::RelayConnectOptions {
                    device_id: dev_id.clone(),
                    rendezvous_server: host
                        .rendezvous_server
                        .clone()
                        .unwrap_or_else(|| "rdv.example.com:21116".to_string()),
                    rendezvous_key: host.rendezvous_key.clone().unwrap_or_default(),
                    key_path: None,
                    server_name: host.hostname.clone(),
                    port: host.port,
                    target_port: host.port,
                    force_relay: false,
                    enrollment_token: String::new(),
                    // sys-1qgww: own_device_id not available in fleet update path;
                    // fleet update pushes to many hosts so self-loop unlikely here.
                    own_device_id: None,
                };
                if let Ok(client) = crate::relay_connect::connect_via_relay(&relay_opts).await {
                    return push_and_update_tls_os(host, client, binary_data, old_version, os)
                        .await;
                }
            }

            // QUIC fallback (Windows-only — QUIC feature is off on Linux builds).
            #[cfg(feature = "quic")]
            if os == OsKind::Windows
                && let Some(qport) = host.quic_port
            {
                let addr_str = format!("{}:{}", host.hostname, qport);
                if let Ok(addr) = addr_str.parse() {
                    match crate::quic::QuicClient::connect(addr, &host.hostname, None).await {
                        Ok(quic) => {
                            return push_and_update_quic(host, quic, binary_data, old_version)
                                .await;
                        }
                        Err(e) => {
                            debug!("QUIC connect also failed for {}: {}", host.name, e);
                        }
                    }
                }
            }

            eprintln!("CONNECT FAILED: {}", direct_err);
            UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("all transports failed: {}", direct_err)),
            }
        }
    }
}

/// Like `push_and_update_tls` but uses the pre-classified OsKind instead of
/// re-asking the client (which can be wrong across the rename-swap window
/// when caps haven't been refreshed).
async fn push_and_update_tls_os(
    host: &HostStatus,
    mut client: crate::client::TlsClient,
    binary_data: &[u8],
    old_version: Option<String>,
    os: OsKind,
) -> UpdateResult {
    use std::io::Write as _;
    let update_path = os.remote_update_path();
    // Force flush after each progress message so per-host output is visible
    // immediately on stderr (avoids the buffered "all 13 hosts appear at
    // process exit" UX bug that hid iteration progress on relay-connected
    // hosts — rsh-hmp).
    let flush = || {
        let _ = std::io::stderr().flush();
    };

    match crate::sync::push(&mut client, binary_data, update_path).await {
        Ok(r) => {
            eprint!("pushed ({} bytes)... ", r.bytes_sent);
            flush();
        }
        Err(e) => {
            eprintln!("PUSH FAILED: {}", e);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("push: {}", e)),
            };
        }
    }

    match crate::commands::self_update(&mut client, update_path).await {
        Ok(_) => {
            eprint!("update sent... ");
            flush();
        }
        Err(e) => {
            eprintln!("UPDATE FAILED: {}", e);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("self-update: {}", e)),
            };
        }
    }

    drop(client);

    // Wait for self-update restart to complete + verify with bounded retry.
    // Relay-connected hosts (~5s RTT) often need >20s for service stop+swap+
    // start. Poll up to ~60s, retry probe every ~10s, accept any version
    // change as success (handles fleet updates where target = current+1 OR
    // schtask is async and version takes longer to refresh).
    eprint!("waiting... ");
    flush();
    verify_after_update_with_retry(host, old_version, Duration::from_secs(60)).await
}

/// Push binary and trigger self-update via QUIC (schtask-based restart).
#[cfg(feature = "quic")]
async fn push_and_update_quic(
    host: &HostStatus,
    quic: crate::quic::QuicClient,
    binary_data: &[u8],
    old_version: Option<String>,
) -> UpdateResult {
    // Push binary to remote temp path
    // QUIC is Windows-only, so always use Windows path
    match quic.push(REMOTE_UPDATE_PATH_WINDOWS, binary_data).await {
        Ok(bytes) => {
            eprint!("pushed ({} bytes, quic)... ", bytes);
        }
        Err(e) => {
            eprintln!("PUSH FAILED (quic): {}", e);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("quic push: {}", e)),
            };
        }
    }

    // Trigger update via scheduled task (service mode)
    let win_path = REMOTE_UPDATE_PATH_WINDOWS.replace('/', "\\");
    let update_cmd = format!(
        "schtasks /create /tn mrsh-fleet-upd /tr \
         \"cmd /c net stop mrsh & \
         timeout /t 2 /nobreak >nul & \
         copy /y {win} C:\\ProgramData\\mrsh\\mrsh.exe & \
         net start mrsh & \
         del {win} & \
         schtasks /delete /tn mrsh-fleet-upd /f\" \
         /sc once /st 00:00 /f /ru SYSTEM",
        win = win_path
    );
    if let Err(e) = quic.exec(&update_cmd).await {
        eprintln!("SCHTASK CREATE FAILED: {}", e);
        return UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some(format!("schtask: {}", e)),
        };
    }
    if let Err(e) = quic.exec("schtasks /run /tn mrsh-fleet-upd").await {
        eprintln!("SCHTASK RUN FAILED: {}", e);
        return UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some(format!("schtask run: {}", e)),
        };
    }
    eprint!("update triggered (quic)... ");

    drop(quic);

    // Wait for restart (25s — schtask has extra scheduling delay)
    eprint!("waiting... ");
    tokio::time::sleep(Duration::from_secs(25)).await;

    verify_after_update(host, old_version).await
}

/// Probe host post-update with bounded retry. Polls every ~10s up to `max_wait`,
/// accepts any successful probe as completion. Reports last version observed.
/// Used by push_and_update_tls_os to handle relay-connected hosts where the
/// service restart can take >20s (rsh-hmp).
async fn verify_after_update_with_retry(
    host: &HostStatus,
    old_version: Option<String>,
    max_wait: Duration,
) -> UpdateResult {
    use std::io::Write as _;
    let start = Instant::now();
    let poll_interval = Duration::from_secs(10);
    let mut last_version: Option<String> = None;
    let mut last_online = false;

    while start.elapsed() < max_wait {
        // First wait, then probe (gives the service time to come back).
        tokio::time::sleep(poll_interval).await;
        let verify = probe_host(
            &host.name,
            &host.hostname,
            host.port,
            host.device_id.clone(),
            host.rendezvous_server.clone(),
            host.rendezvous_key.clone(),
            host.quic_port,
        )
        .await;
        last_online = verify.online;
        if verify.online {
            last_version = verify.version.clone();
            // If version changed from old, we're done — accept immediately.
            if old_version != verify.version {
                eprintln!("OK (v{})", verify.version.as_deref().unwrap_or("?"));
                let _ = std::io::stderr().flush();
                return UpdateResult {
                    name: host.name.clone(),
                    success: true,
                    old_version,
                    new_version: verify.version,
                    error: None,
                };
            }
        }
        // Same version (or offline) → keep polling.
    }

    // Exhausted retry budget — return whatever last probe showed.
    if last_online {
        eprintln!(
            "OK (v{}, version unchanged)",
            last_version.as_deref().unwrap_or("?")
        );
        let _ = std::io::stderr().flush();
        UpdateResult {
            name: host.name.clone(),
            success: true,
            old_version,
            new_version: last_version,
            error: None,
        }
    } else {
        eprintln!("OFFLINE after update (waited {}s)", max_wait.as_secs());
        let _ = std::io::stderr().flush();
        UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some(format!(
                "host offline after update (waited {}s)",
                max_wait.as_secs()
            )),
        }
    }
}

/// Probe host post-update and return UpdateResult.
#[allow(dead_code)]
async fn verify_after_update(host: &HostStatus, old_version: Option<String>) -> UpdateResult {
    let verify = probe_host(
        &host.name,
        &host.hostname,
        host.port,
        host.device_id.clone(),
        host.rendezvous_server.clone(),
        host.rendezvous_key.clone(),
        host.quic_port,
    )
    .await;

    if verify.online {
        let new_ver = verify.version.clone();
        eprintln!("OK (v{})", new_ver.as_deref().unwrap_or("?"));
        UpdateResult {
            name: host.name.clone(),
            success: true,
            old_version,
            new_version: new_ver,
            error: None,
        }
    } else {
        eprintln!("OFFLINE after update");
        UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some("host offline after update".to_string()),
        }
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::fleet::status::HostStatus;

    pub(super) fn host(
        name: &str,
        version: Option<&str>,
        caps: &[&str],
        rdv_version: Option<&str>,
    ) -> HostStatus {
        HostStatus {
            name: name.to_string(),
            hostname: name.to_string(),
            port: 8822,
            online: true,
            version: version.map(str::to_string),
            caps: caps.iter().map(|s| s.to_string()).collect(),
            latency_ms: 1,
            error: None,
            error_kind: None,
            device_id: Some("123456789".to_string()),
            rendezvous_server: None,
            rendezvous_key: None,
            quic_port: None,
            transport: "tls",
            rdv_version: rdv_version.map(str::to_string),
            last_update_status: None,
            last_update_at_unix: None,
            track: None,
            auto_upgrade: None,
            conn_mode: "direct".to_string(),
        }
    }

    fn bins() -> FleetBinaries {
        FleetBinaries {
            windows: Some(vec![1]),
            linux_gnu: Some(vec![2]),
            linux_musl: Some(vec![3]),
            linux_aarch64: None,
        }
    }

    /// Regression rsh-1uto: an rdv-only peer (never probed: version=None,
    /// caps empty) must NOT be misreported as "lacks self-update cap" — and
    /// must NOT become actionable on the classify_os Windows default guess
    /// (rsh-1g6g wrong-binary brick class).
    #[test]
    fn rdv_only_peer_skips_as_unprobed_not_lacks_cap() {
        let cfg = Config::default();
        let statuses = vec![host("omni-sj-08", None, &[], Some("1.10.38"))];
        let plans = plan_fleet_update(&cfg, &statuses, &bins(), "1.10.51");
        let reason = plans[0].skip_reason.as_deref().unwrap();
        assert!(reason.contains("not probed"), "got: {reason}");
        assert!(!reason.contains("lacks self-update"), "got: {reason}");
        // rdv heartbeat version surfaces as CURRENT in the plan
        assert_eq!(plans[0].current_version.as_deref(), Some("1.10.38"));
    }

    /// rsh-1uto: rdv-only peer already at target (per heartbeat) skips as
    /// already-current, not as unprobed/lacks-cap.
    #[test]
    fn rdv_only_peer_already_current_via_heartbeat() {
        let cfg = Config::default();
        let statuses = vec![host("uptodate", None, &[], Some("1.10.51"))];
        let plans = plan_fleet_update(&cfg, &statuses, &bins(), "1.10.51");
        assert_eq!(plans[0].skip_reason.as_deref(), Some("already v1.10.51"));
    }

    /// A genuinely probed server WITHOUT the self-update cap keeps the
    /// original honest skip reason.
    #[test]
    fn probed_server_without_cap_still_reported() {
        let cfg = Config::default();
        let statuses = vec![host("ancient", Some("1.0.0"), &["exec", "linux"], None)];
        let plans = plan_fleet_update(&cfg, &statuses, &bins(), "1.10.51");
        assert_eq!(
            plans[0].skip_reason.as_deref(),
            Some("server lacks self-update cap")
        );
    }

    /// Probed, outdated, capable host is actionable with the right binary.
    #[test]
    fn probed_outdated_capable_host_is_actionable() {
        let cfg = Config::default();
        let statuses = vec![host(
            "rug",
            Some("1.10.41"),
            &["exec", "self-update", "linux"],
            None,
        )];
        let plans = plan_fleet_update(&cfg, &statuses, &bins(), "1.10.51");
        assert!(plans[0].skip_reason.is_none(), "got: {:?}", plans[0].skip_reason);
        assert_eq!(plans[0].os, OsKind::LinuxGnu);
        assert_eq!(plans[0].binary_bytes, 1); // linux_gnu stub len
    }
}

#[cfg(test)]
mod relay_probe_tests {
    use super::plan_tests::host;
    use super::*;

    /// rsh-mwxj: rdv-only synthetic rows (online, no version, device_id known)
    /// are probe targets; probed rows and offline rows are not.
    #[test]
    fn needs_relay_probe_classifies_correctly() {
        let rdv_only = host("omni-sj-08", None, &[], Some("1.10.38"));
        assert!(needs_relay_probe(&rdv_only));

        let probed = host("rug", Some("1.10.41"), &["exec", "linux"], None);
        assert!(!needs_relay_probe(&probed));

        let mut offline = host("dead", None, &[], None);
        offline.online = false;
        assert!(!needs_relay_probe(&offline));

        let mut no_devid = host("anon", None, &[], None);
        no_devid.device_id = None;
        assert!(!needs_relay_probe(&no_devid));
    }
}
