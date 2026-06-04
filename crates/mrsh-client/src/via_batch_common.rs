//! Shared helpers for relay-backed batch transfer commands.

use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Abort a background Tokio task when this guard goes out of scope.
pub struct AbortOnDrop<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> AbortOnDrop<T> {
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Status of a single file processed by a batch transfer command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchFileStatus {
    Uploaded,
    Downloaded,
    Skipped,
    Failed,
}

impl BatchFileStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            BatchFileStatus::Uploaded => "uploaded",
            BatchFileStatus::Downloaded => "downloaded",
            BatchFileStatus::Skipped => "skipped",
            BatchFileStatus::Failed => "failed",
        }
    }
}

/// Walk `root` and return (relative_path, size) for every regular file matching
/// include/exclude rules. Relative paths use forward slashes.
pub fn walk_and_filter(
    root: &Path,
    include: &[String],
    exclude: &[String],
) -> Result<Vec<(String, u64)>> {
    let mut out: Vec<(String, u64)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("read_dir {}: {}", dir.display(), e);
                continue;
            }
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let ft = match entry.file_type() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let rel = match p.strip_prefix(root) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            if !matches_filters(&rel, include, exclude) {
                continue;
            }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((rel, size));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Apply include + exclude globs to a relative path.
/// Empty include -> match all (only exclude is consulted).
pub fn matches_filters(rel: &str, include: &[String], exclude: &[String]) -> bool {
    let filename = rel.rsplit('/').next().unwrap_or(rel);
    if !include.is_empty() {
        let mut matched = false;
        for pat in include {
            if glob_match(pat, rel) || glob_match(pat, filename) {
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    for pat in exclude {
        if glob_match(pat, rel) || glob_match(pat, filename) {
            return false;
        }
    }
    true
}

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
/// Case-insensitive (matches the existing sync.rs helper behavior).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let (mut star_p, mut star_t) = (usize::MAX, 0);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_p = pi;
            star_t = ti;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Convert a forward-slash relative path into native separators.
pub fn path_from_rel(rel: &str) -> PathBuf {
    let mut p = PathBuf::new();
    for comp in rel.split('/') {
        p.push(comp);
    }
    p
}

/// Validate and normalize a manifest-provided relative path.
/// Rejects absolute paths, prefixes, and parent traversal.
pub fn sanitize_rel_path(rel: &str) -> Result<String> {
    let normalized = rel.trim().replace('\\', "/");
    // Reject drive-letter prefix (C:, D:, etc.) explicitly: on Linux the Path
    // parser treats "C:" as a Normal segment, on Windows as a Prefix. Manifest
    // paths from clients must never contain a drive letter regardless of host.
    if let Some(first) = normalized.split('/').find(|s| !s.is_empty()) {
        let bytes = first.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            bail!("manifest path must be relative: {}", rel);
        }
    }
    let mut clean = Vec::new();
    for comp in Path::new(&normalized).components() {
        match comp {
            std::path::Component::Normal(seg) => clean.push(seg.to_string_lossy().into_owned()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => bail!("manifest path escapes destination: {}", rel),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                bail!("manifest path must be relative: {}", rel)
            }
        }
    }
    if clean.is_empty() {
        bail!("manifest path is empty");
    }
    Ok(clean.join("/"))
}

/// Build a URL by joining `base` (with trailing `/`) and a relative path.
/// Each path segment is URL-encoded for safety (spaces, unicode, etc.).
pub fn build_url(base: &str, rel: &str) -> String {
    let mut out = String::with_capacity(base.len() + rel.len() + 8);
    out.push_str(base);
    let mut first = true;
    for seg in rel.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        url_encode_segment(seg, &mut out);
    }
    out
}

/// RFC 3986 unreserved + safe segment encoding.
pub fn url_encode_segment(s: &str, out: &mut String) {
    for b in s.as_bytes() {
        let c = *b;
        let safe = c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' || c == b'~';
        if safe {
            out.push(c as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", c));
        }
    }
}

/// Open an optional JSONL index file.
pub fn open_index_writer(path: &Option<PathBuf>) -> Result<Option<Arc<Mutex<std::fs::File>>>> {
    match path {
        Some(p) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .with_context(|| format!("open index file {}", p.display()))?;
            Ok(Some(Arc::new(Mutex::new(f))))
        }
        None => Ok(None),
    }
}

/// Append one JSONL record to an index file.
pub async fn append_index(
    writer: Option<&Arc<Mutex<std::fs::File>>>,
    rel: &str,
    size: Option<u64>,
    status: BatchFileStatus,
    elapsed_secs: f64,
    err: Option<&str>,
) {
    let Some(w) = writer else {
        return;
    };
    let record = serde_json::json!({
        "path": rel,
        "size": size,
        "status": status.as_str(),
        "elapsed_secs": elapsed_secs,
        "error": err,
        "ts": chrono::Utc::now().to_rfc3339(),
    });
    let mut f = w.lock().await;
    let _ = writeln!(&mut *f, "{}", record);
    let _ = f.flush();
}

pub fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{:.2}GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.2}MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1}KB", n as f64 / KB as f64)
    } else {
        format!("{}B", n)
    }
}

pub fn format_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--".to_string();
    }
    let s = secs as u64;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let ss = s % 60;
    if h > 0 {
        format!("{}h{:02}m", h, m)
    } else if m > 0 {
        format!("{}m{:02}s", m, ss)
    } else {
        format!("{}s", ss)
    }
}

pub fn looks_like_url(value: &str) -> bool {
    value
        .split_once("://")
        .map(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("http")
                || scheme.eq_ignore_ascii_case("https")
                || scheme.eq_ignore_ascii_case("ftp")
                || scheme.eq_ignore_ascii_case("sftp")
        })
        .unwrap_or(false)
}

pub fn temp_download_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "download".into());
    name.push(".mrsh-part");
    dest.with_file_name(name)
}

pub fn replace_file(tmp: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        std::fs::remove_file(dest)
            .with_context(|| format!("remove existing destination {}", dest.display()))?;
    }
    std::fs::rename(tmp, dest)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basic() {
        assert!(glob_match("*.tif", "image.tif"));
        assert!(glob_match("*.tif", "IMAGE.TIF"));
        assert!(!glob_match("*.tif", "image.jpg"));
        assert!(glob_match("tmp/*", "tmp/foo.txt"));
        assert!(!glob_match("tmp/*", "other/foo.txt"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn filters_include_exclude() {
        let incl = vec!["*.tif".to_string()];
        let excl = vec!["tmp/*".to_string()];
        assert!(matches_filters("a/b/c.tif", &incl, &excl));
        assert!(!matches_filters("tmp/c.tif", &incl, &excl));
        assert!(!matches_filters("a/b.jpg", &incl, &excl));
        assert!(matches_filters("a/b.jpg", &[], &excl));
        assert!(!matches_filters("tmp/x.jpg", &[], &excl));
    }

    #[test]
    fn url_build_encodes_segments() {
        let url = build_url("ftp://host/path/", "sub dir/file name.tif");
        assert_eq!(url, "ftp://host/path/sub%20dir/file%20name.tif");
        let url2 = build_url("ftp://host/path/", "plain/file.bin");
        assert_eq!(url2, "ftp://host/path/plain/file.bin");
    }

    #[test]
    fn walk_filters_are_applied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::fs::write(root.join("a/1.tif"), b"1").unwrap();
        std::fs::write(root.join("a/2.jpg"), b"22").unwrap();
        std::fs::write(root.join("tmp/skip.tif"), b"skip").unwrap();

        let got = walk_and_filter(root, &["*.tif".to_string()], &["tmp/*".to_string()]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "a/1.tif");
        assert_eq!(got[0].1, 1);
    }

    #[test]
    fn path_from_rel_roundtrip() {
        let p = path_from_rel("a/b/c.txt");
        let parts: Vec<_> = p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(parts, vec!["a", "b", "c.txt"]);
    }

    #[test]
    fn format_helpers() {
        assert_eq!(format_bytes(500), "500B");
        assert!(format_bytes(2048).starts_with("2.0"));
        assert_eq!(format_duration(30.0), "30s");
        assert_eq!(format_duration(90.0), "1m30s");
        assert_eq!(format_duration(3700.0), "1h01m");
        assert_eq!(format_duration(f64::NAN), "--");
    }

    #[test]
    fn sanitize_rejects_escape() {
        assert!(sanitize_rel_path("../x").is_err());
        assert!(sanitize_rel_path("C:/x").is_err());
        assert_eq!(sanitize_rel_path("./a\\b.txt").unwrap(), "a/b.txt");
    }

    #[test]
    fn looks_like_url_detects_supported_schemes() {
        assert!(looks_like_url("https://example.com/list.jsonl"));
        assert!(looks_like_url("HTTPS://example.com/list.jsonl"));
        assert!(looks_like_url("ftp://host/path"));
        assert!(!looks_like_url("manifest.jsonl"));
    }
}
