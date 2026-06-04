//! Shared-filesystem transport for mrsh.
//!
//! An `FsStream` implements `AsyncRead + AsyncWrite` over a shared spool directory,
//! exchanging binary chunks as files. One session = one pair of monotonic sequences,
//! one per direction. Transport works over any filesystem the two peers can both
//! read/write — local disk, CIFS/SMB, NFS, sshfs, Resilio-synced dirs — without
//! needing TCP/TLS between the peers.
//!
//! # Layout
//!
//! ```text
//! <spool>/<session-id>/c2s/00000001.bin   client→server chunk 1
//! <spool>/<session-id>/c2s/00000002.bin   client→server chunk 2
//! <spool>/<session-id>/s2c/00000001.bin   server→client chunk 1
//! <spool>/<session-id>/closed.c2s         sentinel — client has nothing more to send
//! <spool>/<session-id>/closed.s2c         sentinel — server has nothing more to send
//! ```
//!
//! # Semantics
//!
//! - Writes are atomic: chunk written to `NNNNNNNN.bin.tmp` then renamed.
//! - Reads poll for the next expected sequence file, sleep `poll_interval` on miss.
//! - Each peer removes files it has consumed (best-effort).
//! - A peer signals EOF by creating an empty sentinel file in its own direction.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Default polling interval when watching for new chunk files.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Role inside a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Writes to c2s/, reads from s2c/.
    Client,
    /// Writes to s2c/, reads from c2s/.
    Server,
}

impl Role {
    fn send_dir(&self) -> &'static str {
        match self {
            Role::Client => "c2s",
            Role::Server => "s2c",
        }
    }

    fn recv_dir(&self) -> &'static str {
        match self {
            Role::Client => "s2c",
            Role::Server => "c2s",
        }
    }

    fn send_sentinel(&self) -> &'static str {
        match self {
            Role::Client => "closed.c2s",
            Role::Server => "closed.s2c",
        }
    }

    fn recv_sentinel(&self) -> &'static str {
        match self {
            Role::Client => "closed.s2c",
            Role::Server => "closed.c2s",
        }
    }
}

/// Prepare the session directory layout. Safe to call concurrently from both peers.
pub fn ensure_session_dirs(spool: &Path, session_id: &str) -> Result<PathBuf> {
    let session = spool.join(session_id);
    std::fs::create_dir_all(session.join("c2s")).context("create c2s dir")?;
    std::fs::create_dir_all(session.join("s2c")).context("create s2c dir")?;
    Ok(session)
}

/// Generate a fresh 16-hex-char session id backed by a CSPRNG.
pub fn generate_session_id() -> String {
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(16);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

type PinnedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Duplex stream over a shared filesystem.
///
/// `poll_read` / `poll_write` drive their own per-call futures stored inside
/// the stream — no detached `tokio::spawn` background tasks. That keeps ordering
/// tight enough for TLS wrapping (which is sensitive to any byte reordering).
pub struct FsStream {
    session_dir: PathBuf,
    role: Role,
    poll_interval: Duration,
    read_seq: u64,
    read_eof: bool,
    read_buffer: Vec<u8>,
    read_cursor: usize,
    read_fut: Option<PinnedFuture<io::Result<Option<Vec<u8>>>>>,
    write_seq: u64,
    write_fut: Option<PinnedFuture<io::Result<()>>>,
    shutdown_fut: Option<PinnedFuture<io::Result<()>>>,
    shutdown_done: bool,
}

impl FsStream {
    /// Open a session endpoint. Creates the spool layout if missing. Idempotent.
    pub fn open(spool: &Path, session_id: &str, role: Role) -> Result<Self> {
        let session_dir = ensure_session_dirs(spool, session_id)?;
        Ok(Self {
            session_dir,
            role,
            poll_interval: DEFAULT_POLL_INTERVAL,
            read_seq: 1,
            read_eof: false,
            read_buffer: Vec::new(),
            read_cursor: 0,
            read_fut: None,
            write_seq: 1,
            write_fut: None,
            shutdown_fut: None,
            shutdown_done: false,
        })
    }

    /// Override the polling cadence (default `DEFAULT_POLL_INTERVAL`).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Directory holding this session's spool files.
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }
}

async fn write_chunk_fut(
    session_dir: PathBuf,
    send_dir: &'static str,
    seq: u64,
    data: Vec<u8>,
) -> io::Result<()> {
    let dir = session_dir.join(send_dir);
    let final_path = dir.join(format!("{:08}.bin", seq));
    let tmp_path = dir.join(format!("{:08}.bin.tmp", seq));
    tokio::fs::write(&tmp_path, &data).await?;
    tokio::fs::rename(&tmp_path, &final_path).await?;
    Ok(())
}

async fn read_chunk_fut(
    session_dir: PathBuf,
    recv_dir: &'static str,
    recv_sentinel: &'static str,
    seq: u64,
    poll_interval: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let file = session_dir.join(recv_dir).join(format!("{:08}.bin", seq));
    let sentinel = session_dir.join(recv_sentinel);
    loop {
        match tokio::fs::read(&file).await {
            Ok(buf) => {
                let _ = tokio::fs::remove_file(&file).await;
                return Ok(Some(buf));
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if tokio::fs::try_exists(&sentinel).await.unwrap_or(false) {
            // Sentinel carries the highest seq the peer wrote. If our expected
            // seq is beyond that, it's a real EOF. Otherwise keep polling —
            // the chunk is in flight (relevant for eventually-consistent FS
            // like Resilio/SMB where the sentinel may sync before the chunk).
            let final_seq = read_sentinel_final_seq(&sentinel).await;
            // Race check: chunk may have landed just before/after our last miss.
            if let Ok(buf) = tokio::fs::read(&file).await {
                let _ = tokio::fs::remove_file(&file).await;
                return Ok(Some(buf));
            }
            if let Some(max) = final_seq
                && seq > max
            {
                return Ok(None);
            }
            // else: keep polling; chunk hasn't arrived yet.
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn read_sentinel_final_seq(path: &Path) -> Option<u64> {
    let bytes = tokio::fs::read(path).await.ok()?;
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    text.parse().ok()
}

async fn signal_eof_fut(
    session_dir: PathBuf,
    sentinel_name: &'static str,
    final_seq: u64,
) -> io::Result<()> {
    let path = session_dir.join(sentinel_name);
    let payload = final_seq.to_string();
    tokio::fs::write(&path, payload.as_bytes()).await
}

impl AsyncRead for FsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve from buffered chunk first.
        if self.read_cursor < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_cursor..];
            let n = remaining.len().min(buf.remaining());
            let copy: Vec<u8> = remaining[..n].to_vec();
            buf.put_slice(&copy);
            self.read_cursor += n;
            if self.read_cursor == self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_cursor = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }

        // Ensure there's an in-flight read future for the next sequence.
        if self.read_fut.is_none() {
            let session_dir = self.session_dir.clone();
            let recv_dir = self.role.recv_dir();
            let recv_sentinel = self.role.recv_sentinel();
            let seq = self.read_seq;
            let poll_interval = self.poll_interval;
            self.read_fut = Some(Box::pin(read_chunk_fut(
                session_dir,
                recv_dir,
                recv_sentinel,
                seq,
                poll_interval,
            )));
        }

        let fut = self.read_fut.as_mut().expect("read_fut set above");
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(chunk))) => {
                self.read_fut = None;
                self.read_seq += 1;
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.read_buffer = chunk;
                    self.read_cursor = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => {
                self.read_fut = None;
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.read_fut = None;
                self.read_eof = true;
                Poll::Ready(Err(e))
            }
        }
    }
}

impl AsyncWrite for FsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Flush pending write (if any) before accepting more — preserves ordering.
        if let Some(fut) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    self.write_fut = None;
                }
            }
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let session_dir = self.session_dir.clone();
        let send_dir = self.role.send_dir();
        let seq = self.write_seq;
        self.write_seq += 1;
        let owned = data.to_vec();
        let n = owned.len();
        let mut fut: PinnedFuture<io::Result<()>> =
            Box::pin(write_chunk_fut(session_dir, send_dir, seq, owned));

        // Kick the future once so it makes progress; common path writes are
        // very fast and this avoids an unnecessary reschedule.
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.write_fut = Some(fut);
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(fut) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    self.write_fut = None;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        // Drain any pending write first so bytes don't get lost before EOF.
        if let Some(fut) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    self.write_fut = None;
                }
            }
        }
        if self.shutdown_fut.is_none() {
            let session_dir = self.session_dir.clone();
            let sentinel = self.role.send_sentinel();
            // write_seq is "next seq to use" — highest written = write_seq - 1.
            let final_seq = self.write_seq.saturating_sub(1);
            self.shutdown_fut = Some(Box::pin(signal_eof_fut(
                session_dir,
                sentinel,
                final_seq,
            )));
        }
        let fut = self.shutdown_fut.as_mut().expect("shutdown_fut set above");
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.shutdown_fut = None;
                self.shutdown_done = true;
                Poll::Ready(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{recv_message, send_message};
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    fn spool() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[tokio::test]
    async fn roundtrip_single_message() {
        let dir = spool();
        let session = generate_session_id();
        let mut client = FsStream::open(dir.path(), &session, Role::Client)
            .expect("client")
            .with_poll_interval(Duration::from_millis(10));
        let mut server = FsStream::open(dir.path(), &session, Role::Server)
            .expect("server")
            .with_poll_interval(Duration::from_millis(10));

        let payload = b"hello fs transport".to_vec();
        send_message(&mut client, &payload).await.expect("send");

        let got = recv_message(&mut server).await.expect("recv");
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn roundtrip_multiple_messages() {
        let dir = spool();
        let session = generate_session_id();
        let mut client = FsStream::open(dir.path(), &session, Role::Client)
            .expect("client")
            .with_poll_interval(Duration::from_millis(10));
        let mut server = FsStream::open(dir.path(), &session, Role::Server)
            .expect("server")
            .with_poll_interval(Duration::from_millis(10));

        for i in 0..5u32 {
            let payload = format!("chunk-{}", i).into_bytes();
            send_message(&mut client, &payload).await.expect("send");
        }
        for i in 0..5u32 {
            let got = recv_message(&mut server).await.expect("recv");
            assert_eq!(got, format!("chunk-{}", i).into_bytes());
        }
    }

    #[tokio::test]
    async fn bidirectional_exchange() {
        let dir = spool();
        let session = generate_session_id();
        let mut client = FsStream::open(dir.path(), &session, Role::Client)
            .expect("client")
            .with_poll_interval(Duration::from_millis(10));
        let mut server = FsStream::open(dir.path(), &session, Role::Server)
            .expect("server")
            .with_poll_interval(Duration::from_millis(10));

        send_message(&mut client, b"ping").await.expect("send ping");
        let got = recv_message(&mut server).await.expect("recv ping");
        assert_eq!(got, b"ping");

        send_message(&mut server, b"pong").await.expect("send pong");
        let got = recv_message(&mut client).await.expect("recv pong");
        assert_eq!(got, b"pong");
    }

    #[tokio::test]
    async fn shutdown_signals_eof() {
        let dir = spool();
        let session = generate_session_id();
        let mut client = FsStream::open(dir.path(), &session, Role::Client)
            .expect("client")
            .with_poll_interval(Duration::from_millis(10));
        let mut server = FsStream::open(dir.path(), &session, Role::Server)
            .expect("server")
            .with_poll_interval(Duration::from_millis(10));

        send_message(&mut client, b"last").await.expect("send");
        client.shutdown().await.expect("shutdown client");

        let got = recv_message(&mut server).await.expect("recv");
        assert_eq!(got, b"last");

        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 16];
        let n = server.read(&mut buf).await.expect("read eof");
        assert_eq!(n, 0);
    }

    #[test]
    fn session_id_is_16_hex() {
        let id = generate_session_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
