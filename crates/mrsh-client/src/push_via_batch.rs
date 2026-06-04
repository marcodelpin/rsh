//! Batch upload via SOCKS5 proxy — parallel curl workers reuse a single proxy.
//!
//! Use case: uploading thousands of files (10k+) to an external FTP/HTTP endpoint
//! that is reachable only from the relay host. The single-file `push-via` command
//! pays the SOCKS5 startup cost per file; this batch variant starts the SOCKS5
//! proxy once and drives N parallel `curl -T` workers against it.
//!
//! Features:
//! - Walk a source directory with optional include/exclude glob filters
//! - Reuse a single SOCKS5 proxy for the entire batch
//! - Parallel curl invocations (default 4, configurable)
//! - Resume mode: skip files whose remote size matches local size (curl HEAD)
//! - Progress reporting every 1s (files done/total, bytes, rate, ETA)
//! - JSONL index file — one record per file (status, elapsed, error)
//! - Graceful Ctrl+C: drain in-flight uploads, write index footer

use std::future::Future;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

use crate::via_batch_common::{
    AbortOnDrop, BatchFileStatus, append_index, build_url, format_bytes, format_duration,
    open_index_writer, path_from_rel, walk_and_filter,
};

// ── Options ──────────────────────────────────────────────────────

/// Options for a batch upload via SOCKS5 proxy.
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Source directory to walk.
    pub src_dir: PathBuf,
    /// Base URL with trailing slash, e.g. `ftp://user:pass@host/path/`.
    pub base_url: String,
    /// Include glob patterns (applied to relative path, OR-combined). Empty → all.
    pub include: Vec<String>,
    /// Exclude glob patterns (applied to relative path, OR-combined).
    pub exclude: Vec<String>,
    /// Skip files whose remote size matches local size (HEAD request first).
    pub resume: bool,
    /// Number of concurrent curl invocations.
    pub parallel: usize,
    /// Print progress line every 1s.
    pub progress: bool,
    /// Optional JSONL index file path. One record per file.
    pub index_path: Option<PathBuf>,
    /// Dry run: walk + filter + print plan, skip uploads.
    pub dry_run: bool,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            src_dir: PathBuf::new(),
            base_url: String::new(),
            include: Vec::new(),
            exclude: Vec::new(),
            resume: false,
            parallel: 4,
            progress: false,
            index_path: None,
            dry_run: false,
        }
    }
}

/// Final batch summary.
#[derive(Debug, Default, Clone)]
pub struct BatchResult {
    pub total: usize,
    pub uploaded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub bytes_sent: u64,
    pub elapsed_secs: f64,
}

// ── Entry point ──────────────────────────────────────────────────

/// Run the batch upload. Starts a SOCKS5 proxy via `connect_fn`, walks `opts.src_dir`,
/// then drives `opts.parallel` concurrent curl workers against the shared proxy.
///
/// Returns a `BatchResult` summary. Writes one JSONL record per processed file to
/// `opts.index_path` if set. Honors Ctrl+C: drains in-flight workers before returning.
pub async fn run<F, Fut, S>(opts: BatchOptions, connect_fn: F) -> Result<BatchResult>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !opts.src_dir.is_dir() {
        bail!("source is not a directory: {}", opts.src_dir.display());
    }
    if !opts.base_url.ends_with('/') {
        bail!("base URL must end with '/': {}", opts.base_url);
    }
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        bail!("push-via-batch requires 'curl' in PATH");
    }
    let parallel = opts.parallel.max(1);

    // Walk source directory and apply include/exclude filters.
    let files = walk_and_filter(&opts.src_dir, &opts.include, &opts.exclude)?;
    let total = files.len();
    eprintln!(
        "push-via-batch: {} files matched in {} (parallel={}, resume={}, progress={})",
        total,
        opts.src_dir.display(),
        parallel,
        opts.resume,
        opts.progress,
    );
    if total == 0 {
        return Ok(BatchResult::default());
    }

    if opts.dry_run {
        for (rel, size) in &files {
            println!("DRY {}  {} bytes", rel, size);
        }
        return Ok(BatchResult {
            total,
            ..Default::default()
        });
    }

    // Allocate a local SOCKS5 port.
    let socks_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").context("bind local port")?;
        let p = l.local_addr()?.port();
        drop(l);
        p
    };

    // Start SOCKS5 proxy in the background — single instance for the entire batch.
    let _socks_handle = AbortOnDrop::new(tokio::spawn(async move {
        crate::socks::run_socks5(socks_port, connect_fn).await
    }));

    // Short startup delay so the listener is ready before the first curl fires.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Optional JSONL index file.
    let index_writer = open_index_writer(&opts.index_path)?;

    // Shared state.
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    let uploaded = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let bytes_sent = Arc::new(AtomicU64::new(0));

    // Ctrl+C handler: set cancel flag, let in-flight workers drain.
    let cancel_sig = cancel.clone();
    let ctrlc_handle = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\npush-via-batch: Ctrl+C received, draining in-flight uploads...");
            cancel_sig.store(true, Ordering::SeqCst);
        }
    });

    // Progress printer: prints one line every 1s with counters.
    let progress_handle = if opts.progress {
        let done = done.clone();
        let uploaded = uploaded.clone();
        let skipped = skipped.clone();
        let failed = failed.clone();
        let bytes_sent = bytes_sent.clone();
        let cancel = cancel.clone();
        let start = Instant::now();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let d = done.load(Ordering::Relaxed);
                if d >= total || cancel.load(Ordering::Relaxed) {
                    break;
                }
                let u = uploaded.load(Ordering::Relaxed);
                let s = skipped.load(Ordering::Relaxed);
                let f = failed.load(Ordering::Relaxed);
                let bs = bytes_sent.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64().max(0.001);
                let rate = bs as f64 / elapsed;
                let eta = if d > 0 {
                    (total - d) as f64 * (elapsed / d as f64)
                } else {
                    0.0
                };
                eprintln!(
                    "  [{:5}/{}] up={} skip={} fail={} {} {}/s ETA {}",
                    d,
                    total,
                    u,
                    s,
                    f,
                    format_bytes(bs),
                    format_bytes(rate as u64),
                    format_duration(eta),
                );
            }
        }))
    } else {
        None
    };

    let batch_start = Instant::now();
    let sem = Arc::new(Semaphore::new(parallel));
    let base_url = Arc::new(opts.base_url.clone());
    let src_dir = Arc::new(opts.src_dir.clone());
    let mut handles = Vec::with_capacity(total);

    for (rel, size) in files {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let permit_sem = sem.clone();
        let base = base_url.clone();
        let src = src_dir.clone();
        let cancel = cancel.clone();
        let done_c = done.clone();
        let uploaded_c = uploaded.clone();
        let skipped_c = skipped.clone();
        let failed_c = failed.clone();
        let bytes_c = bytes_sent.clone();
        let index = index_writer.clone();
        let resume = opts.resume;

        handles.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire_owned().await.ok();
            if cancel.load(Ordering::SeqCst) {
                // Drain fast — still record as skipped so the index is complete.
                done_c.fetch_add(1, Ordering::SeqCst);
                skipped_c.fetch_add(1, Ordering::SeqCst);
                append_index(
                    index.as_ref(),
                    &rel,
                    Some(size),
                    BatchFileStatus::Skipped,
                    0.0,
                    Some("cancelled"),
                )
                .await;
                return;
            }

            let local = src.join(path_from_rel(&rel));
            let url = build_url(&base, &rel);
            let t0 = Instant::now();

            // Resume check: HEAD the remote URL, compare Content-Length to local size.
            if resume {
                match remote_size(socks_port, &url).await {
                    Ok(Some(remote_sz)) if remote_sz == size => {
                        let elapsed = t0.elapsed().as_secs_f64();
                        done_c.fetch_add(1, Ordering::SeqCst);
                        skipped_c.fetch_add(1, Ordering::SeqCst);
                        append_index(
                            index.as_ref(),
                            &rel,
                            Some(size),
                            BatchFileStatus::Skipped,
                            elapsed,
                            Some("resume-size-match"),
                        )
                        .await;
                        return;
                    }
                    Ok(_) => {} // size mismatch or not present → upload
                    Err(e) => {
                        // HEAD failed: attempt upload anyway, capture warning in index.
                        tracing::debug!("HEAD failed for {}: {}", rel, e);
                    }
                }
            }

            // Upload via curl -T through the shared SOCKS5 proxy.
            match run_curl_upload(socks_port, &local, &url).await {
                Ok(()) => {
                    let elapsed = t0.elapsed().as_secs_f64();
                    done_c.fetch_add(1, Ordering::SeqCst);
                    uploaded_c.fetch_add(1, Ordering::SeqCst);
                    bytes_c.fetch_add(size, Ordering::SeqCst);
                    append_index(
                        index.as_ref(),
                        &rel,
                        Some(size),
                        BatchFileStatus::Uploaded,
                        elapsed,
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    let elapsed = t0.elapsed().as_secs_f64();
                    done_c.fetch_add(1, Ordering::SeqCst);
                    failed_c.fetch_add(1, Ordering::SeqCst);
                    let msg = e.to_string();
                    eprintln!("FAIL {} : {}", rel, msg);
                    append_index(
                        index.as_ref(),
                        &rel,
                        Some(size),
                        BatchFileStatus::Failed,
                        elapsed,
                        Some(&msg),
                    )
                    .await;
                }
            }
        }));
    }

    // Wait for all workers (including any queued after cancel — they short-circuit).
    for h in handles {
        let _ = h.await;
    }

    // Shut down the SOCKS5 proxy and helper tasks.
    ctrlc_handle.abort();
    if let Some(p) = progress_handle {
        p.abort();
    }

    // Index footer.
    if let Some(w) = &index_writer {
        let mut f = w.lock().await;
        let footer = serde_json::json!({
            "event": "batch-end",
            "total": total,
            "uploaded": uploaded.load(Ordering::SeqCst),
            "skipped": skipped.load(Ordering::SeqCst),
            "failed": failed.load(Ordering::SeqCst),
            "bytes_sent": bytes_sent.load(Ordering::SeqCst),
            "elapsed_secs": batch_start.elapsed().as_secs_f64(),
            "cancelled": cancel.load(Ordering::SeqCst),
        });
        let _ = writeln!(&mut *f, "{}", footer);
        let _ = f.flush();
    }

    let result = BatchResult {
        total,
        uploaded: uploaded.load(Ordering::SeqCst),
        skipped: skipped.load(Ordering::SeqCst),
        failed: failed.load(Ordering::SeqCst),
        bytes_sent: bytes_sent.load(Ordering::SeqCst),
        elapsed_secs: batch_start.elapsed().as_secs_f64(),
    };
    Ok(result)
}

// ── curl invocation ─────────────────────────────────────────────

/// Invoke `curl -T <local> <url>` through the shared SOCKS5 proxy.
async fn run_curl_upload(socks_port: u16, local: &Path, url: &str) -> Result<()> {
    let mut cmd = tokio::process::Command::new("curl");
    cmd.arg("-x")
        .arg(format!("socks5h://127.0.0.1:{}", socks_port))
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("-T")
        .arg(local)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn curl")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!(
            "curl exited {:?}: {}",
            out.status.code(),
            if stderr.is_empty() {
                "no stderr".into()
            } else {
                stderr
            }
        );
    }
    Ok(())
}

/// Query remote file size via `curl -I` (HEAD for HTTP, SIZE for FTP).
/// Returns `Ok(None)` if the remote file is absent or no size was reported.
async fn remote_size(socks_port: u16, url: &str) -> Result<Option<u64>> {
    let mut cmd = tokio::process::Command::new("curl");
    cmd.arg("-x")
        .arg(format!("socks5h://127.0.0.1:{}", socks_port))
        .arg("-sI")
        .arg("--fail")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn curl HEAD")?;
    if !out.status.success() {
        // Not an error: remote file may not exist yet.
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            if let Ok(n) = rest.trim().parse::<u64>() {
                return Ok(Some(n));
            }
        }
    }
    Ok(None)
}

// ── Tests ───────────────────────────────────────────────────────
