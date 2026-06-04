//! SCP protocol handler for mrsh SSH server.
//!
//! Intercepts `scp -t <path>` (sink/upload) and `scp -f <path>` (source/download)
//! exec commands, implementing the SCP wire protocol. No external scp binary required.

use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};

/// Check if a command is an SCP invocation.
pub fn is_scp_command(cmd: &str) -> bool {
    cmd.starts_with("scp ") || cmd == "scp"
}

/// Handle SCP protocol on a bidirectional stream. Returns exit code.
pub async fn handle_scp<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    command: &str,
    remote_addr: &str,
) -> u32 {
    let args: Vec<&str> = command.split_whitespace().collect();
    if args.len() < 2 {
        let _ = scp_error(stream, "scp: missing arguments").await;
        return 1;
    }

    let mut is_sink = false;
    let mut is_source = false;
    let mut recursive = false;
    let mut target_path = String::new();

    for &arg in &args[1..] {
        match arg {
            "-t" => is_sink = true,
            "-f" => is_source = true,
            "-r" => recursive = true,
            "-d" | "-v" | "-p" => {} // ignored flags
            _ => target_path = arg.to_string(),
        }
    }

    if target_path.is_empty() {
        let _ = scp_error(stream, "scp: missing path").await;
        return 1;
    }

    if is_sink {
        info!("SCP sink (upload) → {} (recursive={}), from {}", target_path, recursive, remote_addr);
        scp_sink(stream, &target_path, remote_addr).await
    } else if is_source {
        info!("SCP source (download) ← {} (recursive={}), from {}", target_path, recursive, remote_addr);
        scp_source(stream, &target_path, recursive, remote_addr).await
    } else {
        let _ = scp_error(stream, "scp: must specify -t or -f").await;
        1
    }
}

/// SCP sink: receive files from client (-t).
async fn scp_sink<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    target_path: &str,
    remote_addr: &str,
) -> u32 {
    // Send initial OK
    if stream.write_all(&[0]).await.is_err() {
        return 1;
    }

    let mut current_dir = PathBuf::from(target_path);

    loop {
        let line = match read_line(stream).await {
            Ok(l) => l,
            Err(_) => return 0, // EOF = done
        };

        if line.is_empty() {
            continue;
        }

        match line[0] {
            b'C' => {
                // C<mode> <size> <name>
                if let Err(e) = receive_file(stream, &line, &current_dir, remote_addr).await {
                    let _ = scp_error(stream, &format!("scp: {}", e)).await;
                    return 1;
                }
            }
            b'D' => {
                // D<mode> 0 <name> — enter directory
                let text = String::from_utf8_lossy(&line[1..]);
                let parts: Vec<&str> = text.splitn(3, ' ').collect();
                if parts.len() < 3 {
                    let _ = scp_error(stream, "scp: invalid directory header").await;
                    return 1;
                }
                let dir_name = parts[2].trim();
                current_dir = current_dir.join(dir_name);
                if let Err(e) = std::fs::create_dir_all(&current_dir) {
                    let _ = scp_error(stream, &format!("scp: mkdir {}: {}", current_dir.display(), e)).await;
                    return 1;
                }
                info!("SCP mkdir {} (from {})", current_dir.display(), remote_addr);
                let _ = stream.write_all(&[0]).await;
            }
            b'E' => {
                // E — leave directory
                if let Some(parent) = current_dir.parent() {
                    current_dir = parent.to_path_buf();
                }
                let _ = stream.write_all(&[0]).await;
            }
            b'T' => {
                // T<mtime> 0 <atime> 0 — timestamps (ack and ignore)
                let _ = stream.write_all(&[0]).await;
            }
            _ => {
                let _ = scp_error(stream, &format!("scp: unknown command {:?}", line[0] as char)).await;
                return 1;
            }
        }
    }
}

/// Receive a single file from the SCP client.
async fn receive_file<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    header: &[u8],
    target_dir: &Path,
    remote_addr: &str,
) -> Result<(), String> {
    // Parse: C<mode> <size> <name>
    let text = String::from_utf8_lossy(&header[1..]);
    let parts: Vec<&str> = text.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err("invalid file header".to_string());
    }

    let size: u64 = parts[1]
        .parse()
        .map_err(|_| format!("invalid size: {}", parts[1]))?;
    let name = parts[2].trim();

    // Determine target path
    let file_path = if target_dir.is_dir() {
        target_dir.join(name)
    } else {
        target_dir.to_path_buf()
    };

    // Ensure parent exists
    if let Some(parent) = file_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Ack the header
    stream
        .write_all(&[0])
        .await
        .map_err(|e| format!("ack header: {}", e))?;

    // Receive file data
    let mut file = std::fs::File::create(&file_path)
        .map_err(|e| format!("create {}: {}", file_path.display(), e))?;

    let mut remaining = size;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = stream
            .read(&mut buf[..to_read])
            .await
            .map_err(|e| format!("read data: {}", e))?;
        if n == 0 {
            return Err(format!("unexpected EOF at {}/{} bytes", size - remaining, size));
        }
        std::io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| format!("write {}: {}", file_path.display(), e))?;
        remaining -= n as u64;
    }

    // Read trailing \0
    let mut trail = [0u8; 1];
    let _ = stream.read_exact(&mut trail).await;

    info!(
        "SCP received {} ({} bytes) from {}",
        file_path.display(),
        size,
        remote_addr
    );

    // Ack file complete
    stream
        .write_all(&[0])
        .await
        .map_err(|e| format!("ack complete: {}", e))?;
    Ok(())
}

/// SCP source: send files to client (-f).
async fn scp_source<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    path: &str,
    recursive: bool,
    remote_addr: &str,
) -> u32 {
    // Wait for initial client ack
    let mut ack = [0u8; 1];
    if stream.read_exact(&mut ack).await.is_err() {
        return 1;
    }

    let p = Path::new(path);
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) => {
            let _ = scp_error(stream, &format!("scp: {}", e)).await;
            return 1;
        }
    };

    if meta.is_dir() {
        if !recursive {
            let _ = scp_error(stream, &format!("scp: {}: is a directory (use -r)", path)).await;
            return 1;
        }
        send_dir(stream, p, remote_addr).await
    } else {
        send_file(stream, p, meta.len(), remote_addr).await
    }
}

/// Send a single file to the SCP client.
async fn send_file<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    path: &Path,
    size: u64,
    remote_addr: &str,
) -> u32 {
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    // Send header: C0644 <size> <name>\n
    let header = format!("C0644 {} {}\n", size, name);
    if stream.write_all(header.as_bytes()).await.is_err() {
        return 1;
    }

    // Wait for ack
    let mut ack = [0u8; 1];
    if stream.read_exact(&mut ack).await.is_err() || ack[0] != 0 {
        return 1;
    }

    // Send file data
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let _ = scp_error(stream, &format!("scp: open {}: {}", path.display(), e)).await;
            return 1;
        }
    };

    if stream.write_all(&data).await.is_err() {
        return 1;
    }

    // Send trailing \0
    if stream.write_all(&[0]).await.is_err() {
        return 1;
    }

    // Wait for ack
    if stream.read_exact(&mut ack).await.is_err() || ack[0] != 0 {
        return 1;
    }

    info!("SCP sent {} ({} bytes) to {}", path.display(), size, remote_addr);
    0
}

/// Recursively send a directory to the SCP client.
fn send_dir<'a, S: AsyncRead + AsyncWrite + Unpin + 'a>(
    stream: &'a mut S,
    dir: &'a Path,
    remote_addr: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = u32> + Send + 'a>>
where S: Send {
    Box::pin(async move {
    let name = dir.file_name().unwrap_or_default().to_string_lossy();

    // Send directory header: D0755 0 <name>\n
    let header = format!("D0755 0 {}\n", name);
    if stream.write_all(header.as_bytes()).await.is_err() {
        return 1;
    }

    let mut ack = [0u8; 1];
    if stream.read_exact(&mut ack).await.is_err() || ack[0] != 0 {
        return 1;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            let _ = scp_error(stream, &format!("scp: readdir {}: {}", dir.display(), e)).await;
            return 1;
        }
    };

    let mut sorted: Vec<_> = entries.flatten().collect();
    sorted.sort_by_key(|e| e.file_name());

    for entry in sorted {
        let path = entry.path();
        if path.is_dir() {
            if send_dir(stream, &path, remote_addr).await != 0 {
                return 1;
            }
        } else if let Ok(meta) = entry.metadata() {
            if send_file(stream, &path, meta.len(), remote_addr).await != 0 {
                return 1;
            }
        }
    }

    // End directory: E\n
    if stream.write_all(b"E\n").await.is_err() {
        return 1;
    }
    if stream.read_exact(&mut ack).await.is_err() || ack[0] != 0 {
        return 1;
    }

    0
    })
}

/// Read a line from the stream (up to \n).
async fn read_line<S: AsyncRead + Unpin + Send>(stream: &mut S) -> Result<Vec<u8>, std::io::Error> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF"));
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        line.push(byte[0]);
    }
}

/// Send an SCP error message.
async fn scp_error<S: AsyncWrite + Unpin + Send>(stream: &mut S, msg: &str) -> Result<(), std::io::Error> {
    warn!("SCP error: {}", msg);
    stream.write_all(&[1]).await?;
    stream.write_all(msg.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    #[test]
    fn is_scp_detects_commands() {
        assert!(is_scp_command("scp -t /tmp/file.txt"));
        assert!(is_scp_command("scp -f /tmp/file.txt"));
        assert!(is_scp_command("scp -r -t /tmp/dir"));
        assert!(is_scp_command("scp"));
        assert!(!is_scp_command("ls"));
        assert!(!is_scp_command("scpfoo"));
        assert!(!is_scp_command("echo scp"));
    }

    fn duplex() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(65536)
    }

    #[tokio::test]
    async fn scp_sink_single_file() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_sink(&mut server, &target, "test").await
        });

        // Read initial OK
        let mut ack = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut ack).await.unwrap();
        assert_eq!(ack[0], 0);

        // Send file header: C0644 5 hello.txt\n
        tokio::io::AsyncWriteExt::write_all(&mut client, b"C0644 5 hello.txt\n").await.unwrap();
        // Read ack
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut ack).await.unwrap();
        assert_eq!(ack[0], 0);
        // Send file data + trailing \0
        tokio::io::AsyncWriteExt::write_all(&mut client, b"hello\0").await.unwrap();
        // Read ack
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut ack).await.unwrap();
        assert_eq!(ack[0], 0);

        // Close client side → EOF → sink returns
        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(tmp.join("hello.txt")).unwrap();
        assert_eq!(content, "hello");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_single_file() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_source");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("data.bin"), b"ABCDE").unwrap();

        let (mut client, mut server) = duplex();
        let file_path = tmp.join("data.bin").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &file_path, false, "test").await
        });

        // Send initial ack
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0]).await.unwrap();

        // Read file header: C0644 5 data.bin\n
        let header = read_line(&mut client).await.unwrap();
        let header_str = String::from_utf8_lossy(&header);
        assert!(header_str.starts_with("C0644 5 data.bin"));

        // Send ack
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0]).await.unwrap();

        // Read 5 bytes of file data
        let mut data = vec![0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut data).await.unwrap();
        assert_eq!(&data, b"ABCDE");

        // Read trailing \0
        let mut trail = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut trail).await.unwrap();
        assert_eq!(trail[0], 0);

        // Send final ack
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0]).await.unwrap();

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_not_found() {
        let (mut client, mut server) = duplex();

        let h = tokio::spawn(async move {
            scp_source(&mut server, "/nonexistent/file.txt", false, "test").await
        });

        // Send initial ack
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0]).await.unwrap();

        // Read error (byte 1 + message)
        let mut err_byte = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut err_byte).await.unwrap();
        assert_eq!(err_byte[0], 1); // error indicator

        let code = h.await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn scp_source_dir_without_recursive() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_norecurse");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let dir_path = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &dir_path, false, "test").await
        });

        // Send initial ack
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0]).await.unwrap();

        // Should get error — dir without -r
        let mut err_byte = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut err_byte).await.unwrap();
        assert_eq!(err_byte[0], 1);

        let code = h.await.unwrap();
        assert_eq!(code, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_handle_parses_flags() {
        let (mut client, mut server) = duplex();
        let tmp = std::env::temp_dir().join("rsh_test_scp_flags");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let target = tmp.to_str().unwrap().to_string();
        let cmd = format!("scp -v -p -t {}", target);

        let h = tokio::spawn(async move {
            handle_scp(&mut server, &cmd, "test").await
        });

        // Read initial OK (sink mode)
        let mut ack = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut ack).await.unwrap();
        assert_eq!(ack[0], 0);

        // Close → EOF → returns 0
        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
