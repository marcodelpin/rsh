//! Streaming-style mrsh client commands.
//!
//! - `run_watch`: filesystem watcher that auto-pushes changed files.
//! - `handle_quic_socks5_conn`: per-connection SOCKS5 over QUIC bridge.

use anyhow::{Result, bail};

/// Watch a local directory for changes and auto-push to remote.
pub(crate) async fn run_watch<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
    client: &mut mrsh_client::client::RshClient<S>,
    local_dir: &str,
    remote_dir: &str,
) -> Result<()> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::mpsc;

    let local_dir = std::fs::canonicalize(local_dir)?;
    if !local_dir.is_dir() {
        bail!("{} is not a directory", local_dir.display());
    }

    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&local_dir, RecursiveMode::Recursive)?;

    eprintln!(
        "Watching {} -> {} (Ctrl+C to stop)",
        local_dir.display(),
        remote_dir
    );

    // Debounce: collect changes, flush every 500ms of quiet
    let debounce = std::time::Duration::from_millis(500);
    let mut pending: HashSet<PathBuf> = HashSet::new();

    loop {
        match rx.recv_timeout(debounce) {
            Ok(Ok(event)) => {
                let dominated_by_write =
                    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                if !dominated_by_write {
                    continue;
                }

                for path in event.paths {
                    // Skip directories and hidden/ignored
                    if path.is_dir() {
                        continue;
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str())
                        && name.starts_with('.')
                    {
                        continue;
                    }
                    // Skip common ignores
                    let path_str = path.to_string_lossy();
                    if path_str.contains("node_modules")
                        || path_str.contains("__pycache__")
                        || path_str.contains(".git")
                    {
                        continue;
                    }
                    pending.insert(path);
                }
            }
            Ok(Err(e)) => {
                eprintln!("watch error: {}", e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Debounce expired — flush pending
                if pending.is_empty() {
                    continue;
                }

                let files: Vec<PathBuf> = pending.drain().collect();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 86400;
                let hh = now / 3600;
                let mm = (now % 3600) / 60;
                let ss = now % 60;
                let now = format!("{:02}:{:02}:{:02}", hh, mm, ss);
                eprintln!("\n[{}] Pushing {} file(s)...", now, files.len());

                for path in &files {
                    let rel = path
                        .strip_prefix(&local_dir)
                        .unwrap_or(path)
                        .to_string_lossy();
                    // Convert to Windows remote path
                    let remote_path = format!("{}\\{}", remote_dir, rel.replace('/', "\\"));

                    match mrsh_client::sync::push_file(client, path, &remote_path).await {
                        Ok(result) => {
                            eprintln!(
                                "  {} ({} bytes, delta: {})",
                                rel, result.bytes_sent, result.delta
                            );
                        }
                        Err(e) => {
                            eprintln!("  {} FAILED: {}", rel, e);
                            continue;
                        }
                    }
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 86400;
                let hh = now / 3600;
                let mm = (now % 3600) / 60;
                let ss = now % 60;
                let now = format!("{:02}:{:02}:{:02}", hh, mm, ss);
                eprintln!("[{}] Done.", now);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

/// Handle one SOCKS5 client connection tunnelled over QUIC.
///
/// Performs the SOCKS5 handshake, extracts the CONNECT target, opens a
/// new QUIC tunnel stream to that target, and relays traffic.
#[cfg(feature = "quic")]
pub(crate) async fn handle_quic_socks5_conn(
    mut client: tokio::net::TcpStream,
    quic: &mrsh_client::quic::QuicClient,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // SOCKS5 version constants
    const V5: u8 = 0x05;
    const CMD_CONNECT: u8 = 0x01;
    const ATYP_IPV4: u8 = 0x01;
    const ATYP_DOMAIN: u8 = 0x03;
    const ATYP_IPV6: u8 = 0x04;
    const REP_SUCCESS: u8 = 0x00;
    const REP_FAILURE: u8 = 0x01;
    const REP_CMD_UNSUPPORTED: u8 = 0x07;
    const REP_ADDR_UNSUPPORTED: u8 = 0x08;

    // Greeting: version + number of auth methods
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    anyhow::ensure!(buf[0] == V5, "not SOCKS5 (version={})", buf[0]);
    let n = buf[1] as usize;
    let mut methods = vec![0u8; n];
    client.read_exact(&mut methods).await?;
    // Respond: no auth required (0x00)
    client.write_all(&[V5, 0x00]).await?;

    // CONNECT request: VER CMD RSV ATYP <addr> <port>
    let mut hdr = [0u8; 4];
    client.read_exact(&mut hdr).await?;
    anyhow::ensure!(hdr[0] == V5, "bad SOCKS5 request version");
    if hdr[1] != CMD_CONNECT {
        client
            .write_all(&[V5, REP_CMD_UNSUPPORTED, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        anyhow::bail!("unsupported SOCKS5 command {}", hdr[1]);
    }
    let target_host = match hdr[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        ATYP_DOMAIN => {
            let len = {
                let mut b = [0u8; 1];
                client.read_exact(&mut b).await?;
                b[0] as usize
            };
            let mut d = vec![0u8; len];
            client.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            let ip = std::net::Ipv6Addr::from(a);
            format!("[{}]", ip)
        }
        atyp => {
            client
                .write_all(&[V5, REP_ADDR_UNSUPPORTED, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .ok();
            anyhow::bail!("unsupported SOCKS5 address type {}", atyp);
        }
    };
    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf).await?;
    let target_port = u16::from_be_bytes(port_buf);
    let target = format!("{}:{}", target_host, target_port);

    tracing::debug!("SOCKS5/QUIC: CONNECT {}", target);

    // Open QUIC tunnel to target
    match quic.open_tunnel(&target).await {
        Ok((mut quic_send, mut quic_recv)) => {
            // Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (bound to 0.0.0.0:0)
            client
                .write_all(&[V5, REP_SUCCESS, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await?;
            // Relay bidirectionally
            let (mut tcp_read, mut tcp_write) = client.into_split();
            tokio::select! {
                _ = tokio::io::copy(&mut quic_recv, &mut tcp_write) => {}
                _ = tokio::io::copy(&mut tcp_read, &mut quic_send) => {}
            }
        }
        Err(e) => {
            client
                .write_all(&[V5, REP_FAILURE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .ok();
            anyhow::bail!("QUIC open_tunnel {}: {}", target, e);
        }
    }
    Ok(())
}
