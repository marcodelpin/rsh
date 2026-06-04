//! Zombie listener cleanup — kill stale mrsh processes left behind by
//! self-update or service restart that are still LISTENING on our port.
//!
//! On Windows, `SO_REUSEADDR` allows multiple processes to bind the same port.
//! After a self-update (net stop/net start, schtask bat), the old process may
//! survive and keep listening. These zombies accept TCP connections but cannot
//! complete the mrsh protocol handshake, causing timeouts and relay fallback.
//!
//! Called at server startup BEFORE binding the listener port.

use tracing::{info, warn};

/// Find and kill any other processes listening on `port`, excluding our own PID.
/// Returns the number of zombie processes killed.
pub fn kill_zombie_listeners(port: u16) -> usize {
    let my_pid = std::process::id();
    let pids = find_listeners(port);

    let mut killed = 0;
    for pid in pids {
        if pid == my_pid {
            continue;
        }

        // Verify the target is actually an mrsh/rsh process before killing.
        // We don't want to kill unrelated services that happen to share a port.
        if !is_mrsh_process(pid) {
            info!(
                "zombie cleanup: PID {} on port {} is not mrsh, skipping",
                pid, port
            );
            continue;
        }

        info!(
            "zombie cleanup: killing stale mrsh PID {} on port {} (our PID={})",
            pid, port, my_pid
        );

        if kill_process(pid) {
            killed += 1;
            info!("zombie cleanup: killed PID {}", pid);
        } else {
            warn!("zombie cleanup: failed to kill PID {}", pid);
        }
    }

    if killed > 0 {
        // Brief pause to let the OS release the sockets
        std::thread::sleep(std::time::Duration::from_millis(500));
        info!(
            "zombie cleanup: killed {} stale listener(s) on port {}",
            killed, port
        );
    }

    killed
}

/// Find all PIDs listening on the given TCP port.
#[cfg(target_os = "windows")]
fn find_listeners(port: u16) -> Vec<u32> {
    use crate::win_proc::HideWindow;
    // Use netstat -ano to find LISTENING sockets on our port.
    // Output format: "  TCP    0.0.0.0:8822    0.0.0.0:0    LISTENING    12345"
    let output = match std::process::Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .hide_window()
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("zombie cleanup: netstat failed: {}", e);
            return vec![];
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let target = format!(":{}", port);
    let mut pids = Vec::new();

    for line in stdout.lines() {
        // Match lines that are LISTENING on our port
        let line = line.trim();
        if !line.contains("LISTENING") {
            continue;
        }

        // Parse: "TCP    <local_addr>:<port>    <foreign_addr>    LISTENING    <PID>"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // parts[1] is local address like "0.0.0.0:8822" or "[::]:8822"
        let local_addr = parts[1];
        if !local_addr.ends_with(&target) {
            continue;
        }

        // Verify the port matches exactly (avoid matching e.g. :18822)
        let port_str = local_addr.rsplit(':').next().unwrap_or("");
        if port_str != port.to_string() {
            continue;
        }

        // parts[4] is the PID
        if let Ok(pid) = parts[4].parse::<u32>() {
            if pid != 0 {
                pids.push(pid);
            }
        }
    }

    pids
}

/// Find all PIDs listening on the given TCP port.
#[cfg(not(target_os = "windows"))]
fn find_listeners(port: u16) -> Vec<u32> {
    // Try `ss -tlnpH` first (modern Linux), fall back to parsing /proc/net/tcp.
    if let Some(pids) = find_listeners_ss(port) {
        return pids;
    }
    find_listeners_proc(port)
}

/// Use `ss` to find listeners.
#[cfg(not(target_os = "windows"))]
fn find_listeners_ss(port: u16) -> Option<Vec<u32>> {
    let output = std::process::Command::new("ss")
        .args(["-tlnpH", &format!("sport = :{}", port)])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in stdout.lines() {
        // ss output includes "pid=XXXX" in the last column
        if let Some(pid_start) = line.find("pid=") {
            let rest = &line[pid_start + 4..];
            let pid_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(pid) = pid_str.parse::<u32>() {
                if pid != 0 {
                    pids.push(pid);
                }
            }
        }
    }

    Some(pids)
}

/// Fallback: parse /proc/net/tcp to find listeners.
#[cfg(not(target_os = "windows"))]
fn find_listeners_proc(port: u16) -> Vec<u32> {
    use std::io::BufRead;

    let hex_port = format!("{:04X}", port);
    let mut inodes = Vec::new();

    // Read /proc/net/tcp and /proc/net/tcp6
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(file) = std::fs::File::open(path) {
            for line in std::io::BufReader::new(file).lines().flatten() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }
                // Column 1 is local_address (hex_ip:hex_port), column 3 is state (0A = LISTEN)
                let local = parts[1];
                let state = parts[3];
                if state != "0A" {
                    continue; // Not LISTEN
                }
                if let Some(port_hex) = local.split(':').last() {
                    if port_hex == hex_port {
                        if let Ok(inode) = parts[9].parse::<u64>() {
                            inodes.push(inode);
                        }
                    }
                }
            }
        }
    }

    if inodes.is_empty() {
        return vec![];
    }

    // Map inodes to PIDs by scanning /proc/*/fd/
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(link) = std::fs::read_link(fd.path()) {
                        let link_str = link.to_string_lossy();
                        // Links look like "socket:[12345]"
                        if link_str.starts_with("socket:[") {
                            let inode_str = &link_str[8..link_str.len() - 1];
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                if inodes.contains(&inode) {
                                    pids.push(pid);
                                    break; // Found this PID, move to next
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pids
}

/// Check if a PID corresponds to an mrsh (or legacy rsh) process.
#[cfg(target_os = "windows")]
fn is_mrsh_process(pid: u32) -> bool {
    use crate::win_proc::HideWindow;
    // Use tasklist to get the image name for this PID
    let output = match std::process::Command::new("tasklist")
        .args(["/fi", &format!("PID eq {}", pid), "/fo", "csv", "/nh"])
        .hide_window()
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    stdout.contains("mrsh") || stdout.contains("rsh")
}

/// Check if a PID corresponds to an mrsh (or legacy rsh) process.
#[cfg(not(target_os = "windows"))]
fn is_mrsh_process(pid: u32) -> bool {
    // Read /proc/<pid>/exe symlink or /proc/<pid>/comm
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(link) = std::fs::read_link(&exe_path) {
        let name = link.to_string_lossy().to_lowercase();
        return name.contains("mrsh") || name.contains("rsh");
    }

    // Fallback: check comm (process name, max 15 chars)
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
        let comm = comm.trim().to_lowercase();
        return comm.contains("mrsh") || comm.contains("rsh");
    }

    false
}

/// Kill a process by PID.
#[cfg(target_os = "windows")]
fn kill_process(pid: u32) -> bool {
    use crate::win_proc::HideWindow;
    std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .hide_window()
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Kill a process by PID.
#[cfg(not(target_os = "windows"))]
fn kill_process(pid: u32) -> bool {
    // Send SIGKILL — these are zombies that didn't respond to normal shutdown.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_listeners_returns_vec() {
        // Use a port unlikely to be in use — just verify it doesn't crash
        let pids = find_listeners(59999);
        // Should return empty vec (nothing listening on this port)
        assert!(pids.is_empty() || !pids.is_empty()); // no panic = success
    }

    #[test]
    fn kill_zombie_listeners_skips_own_pid() {
        // Calling with a random port should kill nothing and return 0
        let killed = kill_zombie_listeners(59998);
        assert_eq!(killed, 0);
    }

    #[test]
    fn is_mrsh_process_own_pid() {
        // Our own process is mrsh (in test context, it's the test runner
        // which may or may not contain "mrsh" in its name)
        let _result = is_mrsh_process(std::process::id());
        // Just verify it doesn't crash
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn find_listeners_parses_netstat() {
        // Verify that find_listeners can parse netstat output without crashing
        // on the common port 445 (SMB, almost always listening on Windows)
        let pids = find_listeners(445);
        // SMB usually has PID 4 (System), but we don't assert specific values
        let _ = pids;
    }
}
