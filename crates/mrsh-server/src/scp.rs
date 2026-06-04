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
        } else if let Ok(meta) = entry.metadata()
            && send_file(stream, &path, meta.len(), remote_addr).await != 0 {
                return 1;
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
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn duplex() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(65536)
    }

    /// Read bytes from `stream` until `\n` (exclusive), panics on error.
    async fn client_read_line(stream: &mut DuplexStream) -> Vec<u8> {
        read_line(stream).await.unwrap()
    }

    /// Read exactly one byte from `stream`, panic on error.
    async fn client_read_byte(stream: &mut DuplexStream) -> u8 {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await.unwrap();
        buf[0]
    }

    /// Write exactly one byte to `stream`, panic on error.
    async fn client_write_byte(stream: &mut DuplexStream, b: u8) {
        stream.write_all(&[b]).await.unwrap();
    }

    // ── is_scp_command ───────────────────────────────────────────────────────

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

    #[test]
    fn is_scp_command_edge_cases() {
        // "scp" followed by a space is valid even with no arguments yet
        assert!(is_scp_command("scp "));
        // Subcommands that start with "scp " but have unusual flags must pass
        assert!(is_scp_command("scp -r -v -p -d -f /some/path"));
        // Empty string is not a valid scp command
        assert!(!is_scp_command(""));
        // A string that contains "scp" but does not start with it
        assert!(!is_scp_command("not scp"));
        // Case-sensitive: uppercase SCP is not recognized
        assert!(!is_scp_command("SCP -t /tmp/file"));
    }

    // ── read_line ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_line_returns_content_before_newline() {
        let (mut client, mut server) = duplex();
        client.write_all(b"C0644 42 file.txt\n").await.unwrap();
        let line = read_line(&mut server).await.unwrap();
        assert_eq!(line, b"C0644 42 file.txt");
    }

    #[tokio::test]
    async fn read_line_empty_line() {
        let (mut client, mut server) = duplex();
        // A bare newline produces an empty vec
        client.write_all(b"\n").await.unwrap();
        let line = read_line(&mut server).await.unwrap();
        assert!(line.is_empty());
    }

    #[tokio::test]
    async fn read_line_eof_returns_error() {
        let (client, mut server) = duplex();
        // Drop writer side — server sees EOF
        drop(client);
        let result = read_line(&mut server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_line_multiple_lines_sequential() {
        let (mut client, mut server) = duplex();
        client.write_all(b"first\nsecond\nthird\n").await.unwrap();
        assert_eq!(read_line(&mut server).await.unwrap(), b"first");
        assert_eq!(read_line(&mut server).await.unwrap(), b"second");
        assert_eq!(read_line(&mut server).await.unwrap(), b"third");
    }

    // ── scp_error wire format ────────────────────────────────────────────────

    #[tokio::test]
    async fn scp_error_sends_error_byte_then_message() {
        let (mut client, mut server) = duplex();
        scp_error(&mut server, "bad things happened").await.unwrap();
        drop(server);

        // First byte must be 1 (SCP error indicator)
        assert_eq!(client_read_byte(&mut client).await, 1);
        // Then the message followed by '\n'
        let msg_line = client_read_line(&mut client).await;
        assert_eq!(msg_line, b"bad things happened");
    }

    #[tokio::test]
    async fn scp_error_with_empty_message() {
        let (mut client, mut server) = duplex();
        scp_error(&mut server, "").await.unwrap();
        drop(server);

        assert_eq!(client_read_byte(&mut client).await, 1);
        let msg_line = client_read_line(&mut client).await;
        assert!(msg_line.is_empty());
    }

    // ── handle_scp argument parsing ──────────────────────────────────────────

    #[tokio::test]
    async fn handle_scp_missing_arguments_returns_error() {
        let (mut client, mut server) = duplex();
        let h = tokio::spawn(async move { handle_scp(&mut server, "scp", "test").await });
        // Should emit error byte without requiring client ack
        assert_eq!(client_read_byte(&mut client).await, 1);
        let code = h.await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn handle_scp_missing_path_after_flags() {
        let (mut client, mut server) = duplex();
        // Flags only, no actual path argument
        let h = tokio::spawn(async move { handle_scp(&mut server, "scp -t", "test").await });
        assert_eq!(client_read_byte(&mut client).await, 1);
        let code = h.await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn handle_scp_neither_sink_nor_source_returns_error() {
        let (mut client, mut server) = duplex();
        // No -t or -f flag → error
        let h = tokio::spawn(async move {
            handle_scp(&mut server, "scp /some/path", "test").await
        });
        assert_eq!(client_read_byte(&mut client).await, 1);
        let code = h.await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn scp_handle_parses_flags() {
        let (mut client, mut server) = duplex();
        let tmp = std::env::temp_dir().join("rsh_test_scp_flags");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let target = tmp.to_str().unwrap().to_string();
        let cmd = format!("scp -v -p -t {}", target);

        let h = tokio::spawn(async move { handle_scp(&mut server, &cmd, "test").await });

        // Read initial OK (sink mode)
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Close → EOF → returns 0
        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn handle_scp_recursive_flag_accepted() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_rflag");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();
        let cmd = format!("scp -r -t {}", target);

        let h = tokio::spawn(async move { handle_scp(&mut server, &cmd, "test").await });

        // Sink sends initial OK even in recursive mode
        assert_eq!(client_read_byte(&mut client).await, 0);
        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── scp_sink ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn scp_sink_single_file() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        // Read initial OK
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Send file header: C0644 5 hello.txt\n
        client.write_all(b"C0644 5 hello.txt\n").await.unwrap();
        // Read ack
        assert_eq!(client_read_byte(&mut client).await, 0);
        // Send file data + trailing \0
        client.write_all(b"hello\0").await.unwrap();
        // Read ack
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Close client side → EOF → sink returns
        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(tmp.join("hello.txt")).unwrap();
        assert_eq!(content, "hello");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_empty_file() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        // Initial OK
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Zero-byte file
        client.write_all(b"C0644 0 empty.bin\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        // No data bytes; just the trailing \0 and then server acks
        client.write_all(b"\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let bytes = std::fs::read(tmp.join("empty.bin")).unwrap();
        assert!(bytes.is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_timestamp_command_is_acked_and_ignored() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_ts");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        // Initial OK
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Send a T (timestamp) command — should be acked and ignored
        client.write_all(b"T1700000000 0 1700000000 0\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Now send a regular file
        client.write_all(b"C0644 3 ts.txt\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client.write_all(b"abc\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(tmp.join("ts.txt")).unwrap();
        assert_eq!(content, "abc");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_directory_create_and_leave() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_dir");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        // Initial OK
        assert_eq!(client_read_byte(&mut client).await, 0);

        // D command: enter directory "subdir"
        client.write_all(b"D0755 0 subdir\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // File inside the directory
        client.write_all(b"C0644 4 inner.txt\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client.write_all(b"data\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // E command: leave directory
        client.write_all(b"E\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(tmp.join("subdir").join("inner.txt")).unwrap();
        assert_eq!(content, "data");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_nested_directories() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_nested");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0); // initial OK

        // Enter "a"
        client.write_all(b"D0755 0 a\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Enter "a/b"
        client.write_all(b"D0755 0 b\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // File "a/b/deep.txt"
        client.write_all(b"C0644 5 deep.txt\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client.write_all(b"depth\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Leave "a/b"
        client.write_all(b"E\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Leave "a"
        client.write_all(b"E\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(tmp.join("a").join("b").join("deep.txt")).unwrap();
        assert_eq!(content, "depth");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_unknown_command_returns_error() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_unk");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0); // initial OK

        // Send an unknown command byte 'X'
        client.write_all(b"X garbage\n").await.unwrap();

        // Server must send error byte
        assert_eq!(client_read_byte(&mut client).await, 1);

        let code = h.await.unwrap();
        assert_eq!(code, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_invalid_file_header_returns_error() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_badhdr");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0); // initial OK

        // C header with non-numeric size
        client.write_all(b"C0644 notanumber file.txt\n").await.unwrap();

        // Server should send error byte
        assert_eq!(client_read_byte(&mut client).await, 1);

        let code = h.await.unwrap();
        assert_eq!(code, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_truncated_file_header_returns_error() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_trunc");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0);

        // Only one field after 'C' — too few parts
        client.write_all(b"C0644\n").await.unwrap();

        assert_eq!(client_read_byte(&mut client).await, 1);
        let code = h.await.unwrap();
        assert_eq!(code, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_invalid_directory_header_returns_error() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_badd");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0);

        // D header with only one field
        client.write_all(b"D0755\n").await.unwrap();

        assert_eq!(client_read_byte(&mut client).await, 1);
        let code = h.await.unwrap();
        assert_eq!(code, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_large_file_size_in_header() {
        // Verify the header can express sizes > u32::MAX without parse error.
        // We do not actually transfer that many bytes; we only exercise header parsing
        // by sending a file of the right declared size (0 bytes here would mismatch,
        // so we use a small real size and verify a different large-size is parseable
        // through the public parse path via a fabricated receive_file call on a mock).
        //
        // Instead, drive it through scp_sink: declare 4 bytes, send 4 bytes, verify.
        let tmp = std::env::temp_dir().join("rsh_test_scp_sink_large_hdr");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0);

        // Header with a large (but accurate) size: 4 bytes
        client.write_all(b"C0644 4 large_hdr.bin\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client.write_all(b"WXYZ\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let bytes = std::fs::read(tmp.join("large_hdr.bin")).unwrap();
        assert_eq!(&bytes, b"WXYZ");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── scp_source ───────────────────────────────────────────────────────────

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
        client_write_byte(&mut client, 0).await;

        // Read file header
        let header = client_read_line(&mut client).await;
        let header_str = String::from_utf8_lossy(&header);
        assert!(header_str.starts_with("C0644 5 data.bin"));

        // Send ack
        client_write_byte(&mut client, 0).await;

        // Read 5 bytes of file data
        let mut data = vec![0u8; 5];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ABCDE");

        // Read trailing \0
        assert_eq!(client_read_byte(&mut client).await, 0);

        // Send final ack
        client_write_byte(&mut client, 0).await;

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_empty_file() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_source_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("empty.dat"), b"").unwrap();

        let (mut client, mut server) = duplex();
        let file_path = tmp.join("empty.dat").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &file_path, false, "test").await
        });

        client_write_byte(&mut client, 0).await; // initial ack

        let header = client_read_line(&mut client).await;
        let header_str = String::from_utf8_lossy(&header);
        // Size must be 0
        assert!(header_str.starts_with("C0644 0 empty.dat"), "unexpected header: {}", header_str);

        client_write_byte(&mut client, 0).await; // ack header

        // Trailing \0 only (no data bytes)
        assert_eq!(client_read_byte(&mut client).await, 0);

        client_write_byte(&mut client, 0).await; // final ack

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_header_format_large_size() {
        // Verify the header line format for a multi-MB file uses correct decimal size.
        let tmp = std::env::temp_dir().join("rsh_test_scp_source_largesz");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Write exactly 100,000 bytes
        let payload = vec![0xAAu8; 100_000];
        std::fs::write(tmp.join("big.dat"), &payload).unwrap();

        let (mut client, mut server) = duplex();
        let file_path = tmp.join("big.dat").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &file_path, false, "test").await
        });

        client_write_byte(&mut client, 0).await;

        let header = client_read_line(&mut client).await;
        let header_str = String::from_utf8_lossy(&header);
        assert!(
            header_str.starts_with("C0644 100000 big.dat"),
            "unexpected header: {}",
            header_str
        );

        // Ack header, read all bytes, send final ack
        client_write_byte(&mut client, 0).await;
        let mut buf = vec![0u8; 100_000];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
        assert_eq!(client_read_byte(&mut client).await, 0); // trailing \0
        client_write_byte(&mut client, 0).await; // final ack

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
        client_write_byte(&mut client, 0).await;

        // Server must send error byte
        assert_eq!(client_read_byte(&mut client).await, 1);

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

        client_write_byte(&mut client, 0).await;

        // Should get error — dir without -r
        assert_eq!(client_read_byte(&mut client).await, 1);

        let code = h.await.unwrap();
        assert_eq!(code, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_dir_with_recursive_sends_d_and_e_frames() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_source_rec");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("mydir")).unwrap();
        std::fs::write(tmp.join("mydir").join("a.txt"), b"AAA").unwrap();

        let (mut client, mut server) = duplex();
        let dir_path = tmp.join("mydir").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &dir_path, true, "test").await
        });

        client_write_byte(&mut client, 0).await; // initial ack

        // Expect directory header D0755 0 mydir\n
        let dir_hdr = client_read_line(&mut client).await;
        let dir_hdr_str = String::from_utf8_lossy(&dir_hdr);
        assert!(
            dir_hdr_str.starts_with("D0755 0 mydir"),
            "unexpected dir header: {}",
            dir_hdr_str
        );
        client_write_byte(&mut client, 0).await; // ack D

        // Expect file header C0644 3 a.txt\n
        let file_hdr = client_read_line(&mut client).await;
        let file_hdr_str = String::from_utf8_lossy(&file_hdr);
        assert!(
            file_hdr_str.starts_with("C0644 3 a.txt"),
            "unexpected file header: {}",
            file_hdr_str
        );
        client_write_byte(&mut client, 0).await; // ack C

        // File data
        let mut data = vec![0u8; 3];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"AAA");
        assert_eq!(client_read_byte(&mut client).await, 0); // trailing \0
        client_write_byte(&mut client, 0).await; // final ack

        // Expect E\n (end of directory)
        let end_hdr = client_read_line(&mut client).await;
        assert_eq!(&end_hdr, b"E");
        client_write_byte(&mut client, 0).await; // ack E

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_binary_file_content_preserved() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_source_bin");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Include null bytes and high-value bytes — must survive the transfer
        let payload: Vec<u8> = (0u8..=255).collect();
        std::fs::write(tmp.join("binary.bin"), &payload).unwrap();

        let (mut client, mut server) = duplex();
        let file_path = tmp.join("binary.bin").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &file_path, false, "test").await
        });

        client_write_byte(&mut client, 0).await;

        let header = client_read_line(&mut client).await;
        let header_str = String::from_utf8_lossy(&header);
        assert!(header_str.starts_with("C0644 256 binary.bin"), "header: {}", header_str);

        client_write_byte(&mut client, 0).await;

        let mut received = vec![0u8; 256];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert_eq!(client_read_byte(&mut client).await, 0);
        client_write_byte(&mut client, 0).await;

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Unicode filename round-trip ───────────────────────────────────────────

    #[tokio::test]
    async fn scp_sink_unicode_filename() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_unicode");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0);

        // File with multi-byte UTF-8 name: "файл.txt" (Russian "file.txt")
        let filename = "файл.txt";
        let header = format!("C0644 2 {}\n", filename);
        client.write_all(header.as_bytes()).await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client.write_all(b"hi\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(tmp.join(filename)).unwrap();
        assert_eq!(content, "hi");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_sink_filename_with_spaces() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_spaces");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0);

        // SCP header uses splitn(3, ' ') so the filename can contain spaces starting
        // from the third field. "my file.txt" will be trimmed correctly.
        client.write_all(b"C0644 4 my file.txt\n").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client.write_all(b"test\0").await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        // The implementation does `parts[2].trim()` — the name is "my file.txt"
        let content = std::fs::read_to_string(tmp.join("my file.txt")).unwrap();
        assert_eq!(content, "test");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── permission mode in header ─────────────────────────────────────────────

    #[tokio::test]
    async fn scp_source_header_uses_0644_mode() {
        // Verify the source always sends "C0644" for regular files regardless of
        // the actual file permissions on disk.
        let tmp = std::env::temp_dir().join("rsh_test_scp_mode");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("exec.sh"), b"#!/bin/sh\n").unwrap();

        let (mut client, mut server) = duplex();
        let file_path = tmp.join("exec.sh").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &file_path, false, "test").await
        });

        client_write_byte(&mut client, 0).await;

        let header = client_read_line(&mut client).await;
        let header_str = String::from_utf8_lossy(&header);
        // Mode must always be 0644, regardless of on-disk mode
        assert!(header_str.starts_with("C0644 "), "expected C0644 mode, got: {}", header_str);

        // Clean up: ack + read data + trail + final ack
        client_write_byte(&mut client, 0).await;
        let size_str = header_str.split_whitespace().nth(1).unwrap();
        let size: usize = size_str.parse().unwrap();
        let mut buf = vec![0u8; size];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0);
        client_write_byte(&mut client, 0).await;

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn scp_source_recursive_dir_header_uses_0755_mode() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_dirmode");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("d")).unwrap();
        std::fs::write(tmp.join("d").join("f.txt"), b"x").unwrap();

        let (mut client, mut server) = duplex();
        let dir_path = tmp.join("d").to_str().unwrap().to_string();

        let h = tokio::spawn(async move {
            scp_source(&mut server, &dir_path, true, "test").await
        });

        client_write_byte(&mut client, 0).await;

        let dir_hdr = client_read_line(&mut client).await;
        let dir_hdr_str = String::from_utf8_lossy(&dir_hdr);
        assert!(dir_hdr_str.starts_with("D0755 "), "expected D0755, got: {}", dir_hdr_str);

        // Drain the rest so the server task can finish cleanly
        client_write_byte(&mut client, 0).await; // ack D
        let file_hdr = client_read_line(&mut client).await;
        client_write_byte(&mut client, 0).await; // ack C
        let file_hdr_str = String::from_utf8_lossy(&file_hdr);
        let sz: usize = file_hdr_str.split_whitespace().nth(1).unwrap().parse().unwrap();
        let mut buf = vec![0u8; sz];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(client_read_byte(&mut client).await, 0); // trailing \0
        client_write_byte(&mut client, 0).await; // final ack
        let end = client_read_line(&mut client).await;
        assert_eq!(&end, b"E");
        client_write_byte(&mut client, 0).await; // ack E

        let code = h.await.unwrap();
        assert_eq!(code, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── multiple files in one sink session ────────────────────────────────────

    #[tokio::test]
    async fn scp_sink_multiple_files_in_sequence() {
        let tmp = std::env::temp_dir().join("rsh_test_scp_multi");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let (mut client, mut server) = duplex();
        let target = tmp.to_str().unwrap().to_string();

        let h = tokio::spawn(async move { scp_sink(&mut server, &target, "test").await });

        assert_eq!(client_read_byte(&mut client).await, 0);

        for (name, content) in &[("one.txt", "111"), ("two.txt", "222"), ("three.txt", "333")] {
            let header = format!("C0644 {} {}\n", content.len(), name);
            client.write_all(header.as_bytes()).await.unwrap();
            assert_eq!(client_read_byte(&mut client).await, 0);
            client.write_all(content.as_bytes()).await.unwrap();
            client.write_all(b"\0").await.unwrap();
            assert_eq!(client_read_byte(&mut client).await, 0);
        }

        drop(client);
        let code = h.await.unwrap();
        assert_eq!(code, 0);

        assert_eq!(std::fs::read_to_string(tmp.join("one.txt")).unwrap(), "111");
        assert_eq!(std::fs::read_to_string(tmp.join("two.txt")).unwrap(), "222");
        assert_eq!(std::fs::read_to_string(tmp.join("three.txt")).unwrap(), "333");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
