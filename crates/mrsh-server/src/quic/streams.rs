//! Per-stream channel handlers: dispatch by `chanType` then run the matching
//! handler (tunnel / udp-tunnel / exec / push / pull / ls / shell).

use anyhow::{Context, Result};
use mrsh_core::auth;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::exec;
use crate::sync;
use crate::tunnel;

use super::send_quic_json;
use super::shell::handle_quic_shell;
use super::{
    CHAN_TYPE_EXEC, CHAN_TYPE_LS, CHAN_TYPE_PULL, CHAN_TYPE_PUSH, CHAN_TYPE_SHELL,
    CHAN_TYPE_TUNNEL, CHAN_TYPE_UDP_TUNNEL,
};

/// Parse the shell channel target into (size_str, env_vars).
///
/// Target format (null-separated tokens, backward compatible):
///   `""` or `"{COLSxROWS}"` — legacy, no env vars
///   `"{COLSxROWS}\0env=KEY=VAL\0env=KEY=VAL\0..."` — extended
///
/// Unknown tokens (future directives) are silently ignored for forward
/// compatibility. `env=` payload is one `KEY=VAL` pair per token.
pub(super) fn parse_shell_target(target: &str) -> (String, Vec<String>) {
    if target.is_empty() {
        return (String::new(), Vec::new());
    }
    let mut iter = target.split('\0');
    let size = iter.next().unwrap_or("").to_string();
    let mut env_vars = Vec::new();
    for tok in iter {
        if let Some(kv) = tok.strip_prefix("env=") {
            if !kv.is_empty() {
                env_vars.push(kv.to_string());
            }
        }
        // unknown tokens: ignore (forward compat)
    }
    (size, env_vars)
}

/// Handle a single QUIC channel stream with permission checks.
/// Header format: `chanType[\0target]\n` — null byte separates type from target.
pub(super) async fn handle_quic_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    remote: &str,
    perms: &auth::KeyPermissions,
    allowed_tunnels: &[String],
) -> Result<()> {
    let mut reader = BufReader::new(recv);

    // Read header line
    let mut header = String::new();
    reader
        .read_line(&mut header)
        .await
        .context("read channel header")?;

    // Strip trailing newline
    let header = header.trim_end_matches('\n');

    // Parse: chanType + optional \0 + target
    let (chan_type, target) = if let Some(idx) = header.find('\0') {
        (&header[..idx], &header[idx + 1..])
    } else {
        (header, "")
    };

    info!(
        "[QUIC] stream opened: type={} target={} from {}",
        chan_type, target, remote
    );

    match chan_type {
        CHAN_TYPE_TUNNEL | CHAN_TYPE_UDP_TUNNEL => {
            if !perms.allow_tunnel {
                send.write_all(b"ERROR: tunnel not permitted for this key\n")
                    .await
                    .ok();
                return Ok(());
            }
            if !tunnel::is_tunnel_allowed(target, allowed_tunnels) {
                let msg = format!("ERROR: tunnel to {} not allowed by server policy\n", target);
                send.write_all(msg.as_bytes()).await.ok();
                return Ok(());
            }
            if chan_type == CHAN_TYPE_TUNNEL {
                handle_quic_tunnel(&mut send, &mut reader, target).await
            } else {
                handle_quic_udp_tunnel(&mut send, &mut reader, target).await
            }
        }
        CHAN_TYPE_EXEC => {
            if !perms.allow_exec {
                send.write_all(b"ERROR: exec not permitted for this key\n")
                    .await
                    .ok();
                return Ok(());
            }
            handle_quic_exec(&mut send, &mut reader).await
        }
        CHAN_TYPE_PUSH => {
            if !perms.allow_push {
                send.write_all(b"ERROR: push not permitted for this key\n")
                    .await
                    .ok();
                return Ok(());
            }
            handle_quic_push(&mut send, &mut reader, target).await
        }
        CHAN_TYPE_PULL => {
            if !perms.allow_pull {
                send.write_all(b"ERROR: pull not permitted for this key\n")
                    .await
                    .ok();
                return Ok(());
            }
            handle_quic_pull(&mut send, &mut reader, target).await
        }
        CHAN_TYPE_LS => {
            if !perms.allow_pull {
                send.write_all(b"ERROR: ls not permitted for this key\n")
                    .await
                    .ok();
                return Ok(());
            }
            handle_quic_ls(&mut send, &mut reader, target).await
        }
        CHAN_TYPE_SHELL => {
            if !perms.allow_shell {
                send.write_all(b"ERROR: shell not permitted for this key\n")
                    .await
                    .ok();
                return Ok(());
            }
            handle_quic_shell(&mut send, &mut reader, target).await
        }
        _ => {
            send.write_all(b"ERROR: unknown channel type\n").await.ok();
            Ok(())
        }
    }
}

/// TCP tunnel over QUIC stream: connect to target, bidirectional relay.
async fn handle_quic_tunnel(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Connect to target
    let target_stream = match TcpStream::connect(target).await {
        Ok(s) => {
            send.write_all(b"OK\n").await.context("send OK")?;
            s
        }
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            anyhow::bail!("connect to {}: {}", target, e);
        }
    };
    target_stream.set_nodelay(true).ok();

    let (mut target_read, mut target_write) = target_stream.into_split();

    // Bidirectional relay: QUIC stream <-> TCP target (raw bytes)
    let mut buf_quic = vec![0u8; 32768];
    let mut buf_tcp = vec![0u8; 32768];

    loop {
        tokio::select! {
            // QUIC -> TCP
            result = reader.read(&mut buf_quic) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("[QUIC] tunnel: client stream ended");
                        break;
                    }
                    Ok(n) => {
                        target_write.write_all(&buf_quic[..n]).await
                            .context("write to target")?;
                    }
                }
            }
            // TCP -> QUIC
            result = target_read.read(&mut buf_tcp) => {
                match result {
                    Ok(0) => {
                        debug!("[QUIC] tunnel: target closed");
                        break;
                    }
                    Ok(n) => {
                        send.write_all(&buf_tcp[..n]).await
                            .context("write to QUIC stream")?;
                    }
                    Err(e) => {
                        debug!("[QUIC] tunnel: target read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    info!("[QUIC] tunnel closed");
    Ok(())
}

/// UDP tunnel over QUIC stream: relay datagrams between QUIC and UDP target.
async fn handle_quic_udp_tunnel(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Connect UDP to target
    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            anyhow::bail!("bind UDP: {}", e);
        }
    };

    if let Err(e) = udp.connect(target).await {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        anyhow::bail!("connect UDP to {}: {}", target, e);
    }

    send.write_all(b"OK\n").await.context("send OK")?;
    info!("[QUIC] UDP tunnel to {} established", target);

    let mut buf_quic = vec![0u8; 65535];
    let mut buf_udp = vec![0u8; 65535];

    loop {
        tokio::select! {
            // QUIC stream -> UDP
            result = reader.read(&mut buf_quic) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("[QUIC] UDP tunnel: QUIC stream ended");
                        break;
                    }
                    Ok(n) => {
                        udp.send(&buf_quic[..n]).await.ok();
                    }
                }
            }
            // UDP -> QUIC stream
            result = udp.recv(&mut buf_udp) => {
                match result {
                    Ok(n) => {
                        if send.write_all(&buf_udp[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("[QUIC] UDP tunnel: recv error: {}", e);
                        // Non-fatal for UDP (timeouts, etc.)
                        continue;
                    }
                }
            }
        }
    }

    info!("[QUIC] UDP tunnel closed");
    Ok(())
}

/// Execute a command over QUIC stream: read command line, run, send result.
async fn handle_quic_exec(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
) -> Result<()> {
    // Read command line
    let mut cmd_line = String::new();
    reader
        .read_line(&mut cmd_line)
        .await
        .context("read command")?;
    let cmd = cmd_line.trim();

    if cmd.is_empty() {
        send.write_all(b"ERROR: empty command\n").await.ok();
        return Ok(());
    }

    // Execute
    let resp = exec::handle_exec(cmd, &[]).await;

    // Send OK then result
    send.write_all(b"OK\n").await.context("send OK")?;
    if resp.success {
        if let Some(output) = &resp.output {
            send.write_all(output.as_bytes()).await.ok();
        }
    } else {
        let err_msg = resp.error.as_deref().unwrap_or("unknown error");
        let msg = format!("ERROR: {}", err_msg);
        send.write_all(msg.as_bytes()).await.ok();
    }

    Ok(())
}

/// Push a file over QUIC: read 8-byte BE size + raw data, write to `path`.
///
/// Header already parsed: `push\0<path>\n`. `target` is the remote path.
/// Protocol: client sends 8-byte BE u64 size, then `size` bytes of raw data.
/// Response: `OK\n<bytes_written>\n` or `ERROR: <msg>\n`.
async fn handle_quic_push(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Validate path
    if let Err(e) = sync::sanitize_path(target) {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    if target.is_empty() {
        send.write_all(b"ERROR: empty path\n").await.ok();
        return Ok(());
    }

    // Read 8-byte BE size
    let mut size_buf = [0u8; 8];
    if let Err(e) = reader.read_exact(&mut size_buf).await {
        let msg = format!("ERROR: failed to read size: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }
    let size = u64::from_be_bytes(size_buf);

    // Read raw data
    let mut data = vec![0u8; size as usize];
    if let Err(e) = reader.read_exact(&mut data).await {
        let msg = format!("ERROR: failed to read data: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    // Create parent directories
    let path = std::path::Path::new(target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            info!("[QUIC] push: creating new directory {}", parent.display());
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                let msg = format!("ERROR: create dirs: {}\n", e);
                send.write_all(msg.as_bytes()).await.ok();
                return Ok(());
            }
        }
    }

    // Write file
    match tokio::fs::write(path, &data).await {
        Ok(()) => {
            let resp = format!("OK\n{}\n", size);
            send.write_all(resp.as_bytes()).await.ok();
            info!("[QUIC] push: wrote {} bytes to {}", size, target);
        }
        Err(e) => {
            let msg = format!("ERROR: write file: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
        }
    }

    Ok(())
}

/// Pull a file over QUIC: read path from header, send file data.
///
/// Header already parsed: `pull\0<path>\n`. `target` is the remote path.
/// Response: `OK\n` + 8-byte BE u64 size + raw data, or `ERROR: <msg>\n`.
async fn handle_quic_pull(
    send: &mut quinn::SendStream,
    _reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Validate path
    if let Err(e) = sync::sanitize_path(target) {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    if target.is_empty() {
        send.write_all(b"ERROR: empty path\n").await.ok();
        return Ok(());
    }

    // Read file
    let data = match tokio::fs::read(target).await {
        Ok(d) => d,
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };

    let size = data.len() as u64;

    // Send OK + size + data
    send.write_all(b"OK\n").await.context("send OK")?;
    send.write_all(&size.to_be_bytes())
        .await
        .context("send size")?;
    send.write_all(&data).await.context("send data")?;

    info!("[QUIC] pull: sent {} bytes from {}", size, target);
    Ok(())
}

/// List a remote directory over QUIC.
///
/// Header: `ls\0<path>\n`. Response: newline-delimited JSON array of FileInfo,
/// or `ERROR: <msg>\n`.
async fn handle_quic_ls(
    send: &mut quinn::SendStream,
    _reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    use mrsh_core::protocol::FileInfo;

    let path = if target.is_empty() { "." } else { target };

    // Validate path
    if let Err(e) = sync::sanitize_path(path) {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(e) => e,
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };

    let mut files: Vec<FileInfo> = Vec::new();
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                warn!("[QUIC] ls: read_dir entry error: {}", e);
                continue;
            }
        };
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mod_time = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default();
        let name = entry.file_name().to_string_lossy().to_string();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            format!("{:o}", meta.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let mode = String::from("---");
        files.push(FileInfo {
            name,
            size: meta.len() as i64,
            mode,
            mod_time,
            is_dir: meta.is_dir(),
        });
    }

    send_quic_json(send, &files).await?;
    info!("[QUIC] ls: {} entries from {}", files.len(), path);
    Ok(())
}

