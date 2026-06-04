//! Remote log query — server-side grep/tail with streaming results.
//!
//! Handles LOG_QUERY messages: reads a file, optionally filters with regex,
//! streams matching lines as LOG_DATA, ends with LOG_END stats.

use anyhow::{Context, Result, bail};
use mrsh_core::binproto::{self, msg};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

/// Handle a LOG_QUERY request: read file, filter, stream results.
pub async fn handle_log_query<S: AsyncRead + AsyncWrite + Unpin>(
    payload: &[u8],
    stream: &mut S,
) -> Result<()> {
    let (path, pattern, flags, tail_lines, byte_offset, max_matches) =
        binproto::parse_log_query(payload).context("parse LOG_QUERY")?;

    let follow = flags & binproto::LOG_FLAG_FOLLOW != 0;
    let case_insensitive = flags & binproto::LOG_FLAG_CASE_INSENSITIVE != 0;
    let invert = flags & binproto::LOG_FLAG_INVERT != 0;

    info!("log query: path={} pattern={:?} tail={} offset={} follow={}",
        path, pattern, tail_lines, byte_offset, follow);

    // Validate path exists
    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let err = format!("file not found: {} ({})", path, e);
            binproto::send_msg(stream, msg::ERROR, &binproto::build_error(&err)).await?;
            return Ok(());
        }
    };

    if !metadata.is_file() {
        let err = format!("not a file: {}", path);
        binproto::send_msg(stream, msg::ERROR, &binproto::build_error(&err)).await?;
        return Ok(());
    }

    // Compile regex if pattern is non-empty
    let regex = if !pattern.is_empty() {
        let re = if case_insensitive {
            regex::RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .build()
        } else {
            regex::Regex::new(&pattern).map_err(Into::into)
        };
        match re {
            Ok(r) => Some(r),
            Err(e) => {
                let err = format!("invalid regex: {}", e);
                binproto::send_msg(stream, msg::ERROR, &binproto::build_error(&err)).await?;
                return Ok(());
            }
        }
    } else {
        None
    };

    // Read file
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path))?;

    let all_lines: Vec<&str> = content.lines().collect();
    let total_lines = all_lines.len() as u64;

    // Determine which lines to process
    let lines_to_scan: Vec<&str> = if tail_lines > 0 && tail_lines < all_lines.len() as u32 {
        // Tail mode: scan only the last N lines
        all_lines[all_lines.len() - tail_lines as usize..].to_vec()
    } else {
        all_lines
    };

    let mut lines_scanned: u64 = 0;
    let mut matches_found: u64 = 0;
    let max = if max_matches == 0 { u64::MAX } else { max_matches as u64 };

    for line in &lines_to_scan {
        lines_scanned += 1;

        let matches = match &regex {
            Some(re) => {
                let m = re.is_match(line);
                if invert { !m } else { m }
            }
            None => true, // No pattern = all lines match
        };

        if matches {
            matches_found += 1;
            // Send matching line as LOG_DATA (raw UTF-8 bytes)
            binproto::send_msg(stream, msg::LOG_DATA, line.as_bytes()).await?;

            if matches_found >= max {
                break;
            }
        }
    }

    // Send LOG_END with stats
    let final_offset = content.len() as u64;
    let end_payload = binproto::build_log_end(lines_scanned, matches_found, final_offset);
    binproto::send_msg(stream, msg::LOG_END, &end_payload).await?;

    debug!("log query complete: scanned={} matched={}", lines_scanned, matches_found);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create temp file, run log_query, collect results from a mock stream.
    async fn run_query(
        content: &str,
        pattern: &str,
        flags: u8,
        tail: u32,
        max_matches: u32,
    ) -> Result<(Vec<String>, u64, u64)> {
        let mut f = tempfile::NamedTempFile::new()?;
        f.write_all(content.as_bytes())?;
        let path = f.path().to_str().unwrap().to_string();

        let payload = binproto::build_log_query(&path, pattern, flags, tail, 0, max_matches);

        // Use duplex stream as mock
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let handle = tokio::spawn(async move {
            handle_log_query(&payload, &mut server).await
        });

        // Read responses
        let mut lines = Vec::new();
        let mut scanned = 0u64;
        let mut matched = 0u64;

        loop {
            let (type_id, data) = binproto::recv_msg(&mut client).await?;
            match type_id {
                msg::LOG_DATA => {
                    lines.push(String::from_utf8_lossy(&data).to_string());
                }
                msg::LOG_END => {
                    let (s, m, _) = binproto::parse_log_end(&data)?;
                    scanned = s;
                    matched = m;
                    break;
                }
                msg::ERROR => {
                    let err = binproto::parse_error(&data)?;
                    bail!("server error: {}", err);
                }
                other => bail!("unexpected message type: 0x{:02x}", other),
            }
        }

        handle.await??;
        Ok((lines, scanned, matched))
    }

    #[tokio::test]
    async fn query_all_lines() {
        let (lines, scanned, matched) = run_query(
            "line1\nline2\nline3\n", "", 0, 0, 0
        ).await.unwrap();
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
        assert_eq!(scanned, 3);
        assert_eq!(matched, 3);
    }

    #[tokio::test]
    async fn query_with_pattern() {
        let (lines, _, matched) = run_query(
            "error: disk full\ninfo: ok\nerror: timeout\n", "error", 0, 0, 0
        ).await.unwrap();
        assert_eq!(lines, vec!["error: disk full", "error: timeout"]);
        assert_eq!(matched, 2);
    }

    #[tokio::test]
    async fn query_case_insensitive() {
        let (lines, _, _) = run_query(
            "ERROR: one\nerror: two\nInfo: three\n",
            "error",
            binproto::LOG_FLAG_CASE_INSENSITIVE,
            0, 0
        ).await.unwrap();
        assert_eq!(lines, vec!["ERROR: one", "error: two"]);
    }

    #[tokio::test]
    async fn query_invert() {
        let (lines, _, _) = run_query(
            "keep\nskip\nkeep2\n",
            "skip",
            binproto::LOG_FLAG_INVERT,
            0, 0
        ).await.unwrap();
        assert_eq!(lines, vec!["keep", "keep2"]);
    }

    #[tokio::test]
    async fn query_tail() {
        let (lines, scanned, _) = run_query(
            "a\nb\nc\nd\ne\n", "", 0, 2, 0
        ).await.unwrap();
        assert_eq!(lines, vec!["d", "e"]);
        assert_eq!(scanned, 2);
    }

    #[tokio::test]
    async fn query_max_matches() {
        let (lines, _, matched) = run_query(
            "a\nb\nc\nd\ne\n", "", 0, 0, 3
        ).await.unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(matched, 3);
    }

    #[tokio::test]
    async fn query_tail_with_pattern() {
        let (lines, _, matched) = run_query(
            "error: 1\ninfo: 2\nerror: 3\ninfo: 4\nerror: 5\n",
            "error",
            0, 3, 0  // tail 3 lines, then grep
        ).await.unwrap();
        // Last 3 lines: "info: 4", "error: 5" — wait, that's only matching "error: 5"
        // Actually last 3 lines of 5: "error: 3", "info: 4", "error: 5"
        assert_eq!(lines, vec!["error: 3", "error: 5"]);
        assert_eq!(matched, 2);
    }

    #[tokio::test]
    async fn query_nonexistent_file() {
        let result = run_query(
            "", "", 0, 0, 0  // This creates a file, but let's test missing path
        ).await;
        // This test uses a valid temp file, so it works.
        // Test actual missing file separately:
        let payload = binproto::build_log_query("/nonexistent/file.log", "", 0, 0, 0, 0);
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            handle_log_query(&payload, &mut server).await.unwrap();
        });
        let (type_id, data) = binproto::recv_msg(&mut client).await.unwrap();
        assert_eq!(type_id, msg::ERROR);
        let err = binproto::parse_error(&data).unwrap();
        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn query_invalid_regex() {
        // Create a real temp file so we get past the file check to the regex check
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"test\n").unwrap();
        let payload = binproto::build_log_query(f.path().to_str().unwrap(), "[invalid", 0, 0, 0, 0);
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            handle_log_query(&payload, &mut server).await.unwrap();
        });
        let (type_id, data) = binproto::recv_msg(&mut client).await.unwrap();
        assert_eq!(type_id, msg::ERROR);
        let err = binproto::parse_error(&data).unwrap();
        assert!(err.contains("regex"));
    }
}
