//! Batch download via SOCKS5 proxy — parallel curl workers reuse a single proxy.
//!
//! Unlike upload batching, download batching cannot assume a portable remote
//! directory listing across HTTP/FTP/SFTP, so the MVP is manifest-driven.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

use crate::socks;
use crate::via_batch_common::{
    AbortOnDrop, BatchFileStatus, append_index, build_url, format_bytes, format_duration,
    looks_like_url, matches_filters, open_index_writer, path_from_rel, replace_file,
    sanitize_rel_path, temp_download_path,
};

/// Options for a batch download via SOCKS5 proxy.
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Base URL with trailing slash, e.g. `ftp://user:pass@host/path/`.
    pub base_url: String,
    /// Destination directory for downloaded files.
    pub dest_dir: PathBuf,
    /// Manifest path or URL.
    pub manifest: String,
    /// Include glob patterns applied to relative manifest paths.
    pub include: Vec<String>,
    /// Exclude glob patterns applied to relative manifest paths.
    pub exclude: Vec<String>,
    /// Skip local files already present.
    pub resume: bool,
    /// Number of concurrent curl invocations.
    pub parallel: usize,
    /// Print progress line every 1s.
    pub progress: bool,
    /// Optional JSONL index file path. One record per file.
    pub index_path: Option<PathBuf>,
    /// Dry run: print plan, skip downloads.
    pub dry_run: bool,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            dest_dir: PathBuf::new(),
            manifest: String::new(),
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
    pub downloaded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub bytes_received: u64,
    pub elapsed_secs: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestEntry {
    path: String,
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ManifestLine {
    path: Option<String>,
    size: Option<u64>,
}

/// Run the batch download. Starts a SOCKS5 proxy via `connect_fn`, loads the
/// manifest (local file or URL), then drives `opts.parallel` concurrent curl
/// workers against the shared proxy.
pub async fn run<F, Fut, S>(opts: BatchOptions, connect_fn: F) -> Result<BatchResult>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !opts.base_url.ends_with('/') {
        bail!("base URL must end with '/': {}", opts.base_url);
    }
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        bail!("pull-via-batch requires 'curl' in PATH");
    }

    let manifest_is_url = looks_like_url(&opts.manifest);
    let socks_port = if manifest_is_url || !opts.dry_run {
        Some(bind_local_port()?)
    } else {
        None
    };
    let _socks_handle = if let Some(port) = socks_port {
        let handle = tokio::spawn(async move { socks::run_socks5(port, connect_fn).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        Some(AbortOnDrop::new(handle))
    } else {
        None
    };

    let manifest_content = if manifest_is_url {
        fetch_manifest_via_curl(socks_port.expect("socks_port"), &opts.manifest).await?
    } else {
        std::fs::read_to_string(&opts.manifest)
            .with_context(|| format!("read manifest {}", opts.manifest))?
    };

    let entries = parse_manifest(&manifest_content, &opts.include, &opts.exclude)?;
    let total = entries.len();
    eprintln!(
        "pull-via-batch: {} files matched from manifest {} (parallel={}, resume={}, progress={})",
        total,
        opts.manifest,
        opts.parallel.max(1),
        opts.resume,
        opts.progress,
    );

    if total == 0 {
        return Ok(BatchResult::default());
    }

    if opts.dry_run {
        for entry in &entries {
            match entry.size {
                Some(size) => println!("DRY {}  {} bytes", entry.path, size),
                None => println!("DRY {}  size=unknown", entry.path),
            }
        }
        return Ok(BatchResult {
            total,
            ..Default::default()
        });
    }

    std::fs::create_dir_all(&opts.dest_dir)
        .with_context(|| format!("create destination {}", opts.dest_dir.display()))?;

    let index_writer = open_index_writer(&opts.index_path)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    let downloaded = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let cancel_sig = cancel.clone();
    let ctrlc_handle = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\npull-via-batch: Ctrl+C received, draining in-flight downloads...");
            cancel_sig.store(true, Ordering::SeqCst);
        }
    });

    let progress_handle = if opts.progress {
        let done = done.clone();
        let downloaded = downloaded.clone();
        let skipped = skipped.clone();
        let failed = failed.clone();
        let bytes_received = bytes_received.clone();
        let cancel = cancel.clone();
        let start = Instant::now();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let d = done.load(Ordering::Relaxed);
                if d >= total || cancel.load(Ordering::Relaxed) {
                    break;
                }
                let ok = downloaded.load(Ordering::Relaxed);
                let sk = skipped.load(Ordering::Relaxed);
                let fl = failed.load(Ordering::Relaxed);
                let br = bytes_received.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64().max(0.001);
                let rate = br as f64 / elapsed;
                let eta = if d > 0 {
                    (total - d) as f64 * (elapsed / d as f64)
                } else {
                    0.0
                };
                eprintln!(
                    "  [{:5}/{}] dl={} skip={} fail={} {} {}/s ETA {}",
                    d,
                    total,
                    ok,
                    sk,
                    fl,
                    format_bytes(br),
                    format_bytes(rate as u64),
                    format_duration(eta),
                );
            }
        }))
    } else {
        None
    };

    let batch_start = Instant::now();
    let sem = Arc::new(Semaphore::new(opts.parallel.max(1)));
    let base_url = Arc::new(opts.base_url.clone());
    let dest_dir = Arc::new(opts.dest_dir.clone());
    let socks_port = socks_port.expect("socks_port");
    let mut handles = Vec::with_capacity(total);

    for entry in entries {
        if cancel.load(Ordering::SeqCst) {
            break;
        }

        let permit_sem = sem.clone();
        let base = base_url.clone();
        let dest_root = dest_dir.clone();
        let cancel = cancel.clone();
        let done_c = done.clone();
        let downloaded_c = downloaded.clone();
        let skipped_c = skipped.clone();
        let failed_c = failed.clone();
        let bytes_c = bytes_received.clone();
        let index = index_writer.clone();
        let resume = opts.resume;

        handles.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire_owned().await.ok();
            if cancel.load(Ordering::SeqCst) {
                done_c.fetch_add(1, Ordering::SeqCst);
                skipped_c.fetch_add(1, Ordering::SeqCst);
                append_index(
                    index.as_ref(),
                    &entry.path,
                    entry.size,
                    BatchFileStatus::Skipped,
                    0.0,
                    Some("cancelled"),
                )
                .await;
                return;
            }

            let local = dest_root.join(path_from_rel(&entry.path));
            let url = build_url(&base, &entry.path);
            let t0 = Instant::now();

            if resume && should_skip_existing(&local, entry.size) {
                let elapsed = t0.elapsed().as_secs_f64();
                done_c.fetch_add(1, Ordering::SeqCst);
                skipped_c.fetch_add(1, Ordering::SeqCst);
                append_index(
                    index.as_ref(),
                    &entry.path,
                    entry.size,
                    BatchFileStatus::Skipped,
                    elapsed,
                    Some("resume-local-match"),
                )
                .await;
                return;
            }

            if let Some(parent) = local.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                let elapsed = t0.elapsed().as_secs_f64();
                let msg = format!("create {}: {}", parent.display(), e);
                done_c.fetch_add(1, Ordering::SeqCst);
                failed_c.fetch_add(1, Ordering::SeqCst);
                append_index(
                    index.as_ref(),
                    &entry.path,
                    entry.size,
                    BatchFileStatus::Failed,
                    elapsed,
                    Some(&msg),
                )
                .await;
                return;
            }

            match run_curl_download(socks_port, &url, &local, entry.size).await {
                Ok(written) => {
                    let elapsed = t0.elapsed().as_secs_f64();
                    done_c.fetch_add(1, Ordering::SeqCst);
                    downloaded_c.fetch_add(1, Ordering::SeqCst);
                    bytes_c.fetch_add(written, Ordering::SeqCst);
                    append_index(
                        index.as_ref(),
                        &entry.path,
                        entry.size.or(Some(written)),
                        BatchFileStatus::Downloaded,
                        elapsed,
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    let elapsed = t0.elapsed().as_secs_f64();
                    let msg = e.to_string();
                    eprintln!("FAIL {} : {}", entry.path, msg);
                    done_c.fetch_add(1, Ordering::SeqCst);
                    failed_c.fetch_add(1, Ordering::SeqCst);
                    append_index(
                        index.as_ref(),
                        &entry.path,
                        entry.size,
                        BatchFileStatus::Failed,
                        elapsed,
                        Some(&msg),
                    )
                    .await;
                }
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    ctrlc_handle.abort();
    if let Some(handle) = progress_handle {
        handle.abort();
    }

    if let Some(writer) = &index_writer {
        let mut f = writer.lock().await;
        let footer = serde_json::json!({
            "event": "batch-end",
            "total": total,
            "downloaded": downloaded.load(Ordering::SeqCst),
            "skipped": skipped.load(Ordering::SeqCst),
            "failed": failed.load(Ordering::SeqCst),
            "bytes_received": bytes_received.load(Ordering::SeqCst),
            "elapsed_secs": batch_start.elapsed().as_secs_f64(),
            "cancelled": cancel.load(Ordering::SeqCst),
        });
        let _ = writeln!(&mut *f, "{}", footer);
        let _ = f.flush();
    }

    Ok(BatchResult {
        total,
        downloaded: downloaded.load(Ordering::SeqCst),
        skipped: skipped.load(Ordering::SeqCst),
        failed: failed.load(Ordering::SeqCst),
        bytes_received: bytes_received.load(Ordering::SeqCst),
        elapsed_secs: batch_start.elapsed().as_secs_f64(),
    })
}

fn parse_manifest(
    content: &str,
    include: &[String],
    exclude: &[String],
) -> Result<Vec<ManifestEntry>> {
    let mut by_path: BTreeMap<String, ManifestEntry> = BTreeMap::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let record = if line.starts_with('{') {
            let parsed: ManifestLine = serde_json::from_str(line)
                .with_context(|| format!("parse JSONL manifest line {}", idx + 1))?;
            match parsed.path {
                Some(path) => Some((path, parsed.size)),
                None => None,
            }
        } else {
            Some((line.to_string(), None))
        };

        let Some((path, size)) = record else {
            continue;
        };
        let path = sanitize_rel_path(&path)?;
        if !matches_filters(&path, include, exclude) {
            continue;
        }
        by_path.insert(path.clone(), ManifestEntry { path, size });
    }
    Ok(by_path.into_values().collect())
}

fn should_skip_existing(local: &Path, expected_size: Option<u64>) -> bool {
    let Ok(meta) = std::fs::metadata(local) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    match expected_size {
        Some(size) => meta.len() == size,
        None => true,
    }
}

async fn fetch_manifest_via_curl(socks_port: u16, url: &str) -> Result<String> {
    let mut cmd = tokio::process::Command::new("curl");
    cmd.arg("-x")
        .arg(format!("socks5h://127.0.0.1:{}", socks_port))
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn curl manifest fetch")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!(
            "curl manifest fetch exited {:?}: {}",
            out.status.code(),
            if stderr.is_empty() {
                "no stderr".into()
            } else {
                stderr
            }
        );
    }
    String::from_utf8(out.stdout).context("manifest is not valid UTF-8")
}

async fn run_curl_download(
    socks_port: u16,
    url: &str,
    dest: &Path,
    expected_size: Option<u64>,
) -> Result<u64> {
    let tmp = temp_download_path(dest);
    let _ = std::fs::remove_file(&tmp);

    let mut cmd = tokio::process::Command::new("curl");
    cmd.arg("-x")
        .arg(format!("socks5h://127.0.0.1:{}", socks_port))
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("-o")
        .arg(&tmp)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn curl download")?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
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

    let written = std::fs::metadata(&tmp)
        .with_context(|| format!("stat {}", tmp.display()))?
        .len();
    if let Some(expected) = expected_size
        && written != expected
    {
        let _ = std::fs::remove_file(&tmp);
        bail!(
            "download size mismatch for {}: got {} bytes, expected {}",
            dest.display(),
            written,
            expected
        );
    }

    replace_file(&tmp, dest)?;
    Ok(written)
}

fn bind_local_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind local port")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_manifest() {
        let manifest = "a/file1.txt\nb/file2.txt\n";
        let got = parse_manifest(manifest, &[], &[]).unwrap();
        assert_eq!(
            got,
            vec![
                ManifestEntry {
                    path: "a/file1.txt".to_string(),
                    size: None,
                },
                ManifestEntry {
                    path: "b/file2.txt".to_string(),
                    size: None,
                },
            ]
        );
    }

    #[test]
    fn parse_push_index_jsonl_as_manifest() {
        let manifest = r#"{"path":"a/file1.txt","size":12,"status":"uploaded"}
{"event":"batch-end","total":1}"#;
        let got = parse_manifest(manifest, &[], &[]).unwrap();
        assert_eq!(
            got,
            vec![ManifestEntry {
                path: "a/file1.txt".to_string(),
                size: Some(12),
            }]
        );
    }

    #[test]
    fn parse_manifest_applies_filters_and_dedupes() {
        let manifest = "a/keep.tif\na/keep.tif\na/skip.jpg\ntmp/nope.tif\n";
        let got = parse_manifest(manifest, &["*.tif".to_string()], &["tmp/*".to_string()]).unwrap();
        assert_eq!(
            got,
            vec![ManifestEntry {
                path: "a/keep.tif".to_string(),
                size: None,
            }]
        );
    }

    #[test]
    fn parse_manifest_rejects_escape_path() {
        let err = parse_manifest("../secret.txt\n", &[], &[]).unwrap_err();
        assert!(err.to_string().contains("escapes destination"));
    }

    #[test]
    fn resume_skip_matches_size_or_existence() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a.bin");
        std::fs::write(&file, b"abcd").unwrap();
        assert!(should_skip_existing(&file, Some(4)));
        assert!(!should_skip_existing(&file, Some(5)));
        assert!(should_skip_existing(&file, None));
    }

    #[test]
    fn temp_download_path_keeps_same_directory() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let dest = tmp_dir.path().join("file.bin");
        let tmp = temp_download_path(&dest);
        assert_eq!(tmp.file_name().and_then(|n| n.to_str()), Some("file.bin.mrsh-part"));
        assert_eq!(tmp.parent(), dest.parent());
    }
}
