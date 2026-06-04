//! Wire-protocol types and helpers for client sync operations.
//!
//! Shared across `transfer`, `dir`, and `diff` submodules:
//!   - `WalkEntry` — server walk response shape.
//!   - `build_sync_request` — convenience constructor for sync requests with sigs.
//!   - `check_response` — error-mapping helper for `Response`.

use anyhow::{Result, bail};
use mrsh_core::protocol::{Request, Response};

/// Walk entry from server (wire format: `json:"p"`, `json:"s"`, `json:"m"`).
#[derive(serde::Deserialize, Debug)]
pub(super) struct WalkEntry {
    #[serde(rename = "p")]
    pub(super) path: String,
    #[serde(rename = "s")]
    pub(super) size: i64,
    #[serde(rename = "m", default)]
    pub(super) mtime: i64,
}

/// Map a non-success `Response` to an error.
pub(super) fn check_response(resp: &Response) -> Result<()> {
    if !resp.success {
        bail!("{}", resp.error.as_deref().unwrap_or("unknown error"));
    }
    Ok(())
}

/// Build a sync request with signatures.
pub fn build_sync_request(
    sync_type: &str,
    path: &str,
    sigs: Vec<mrsh_core::protocol::BlockSig>,
) -> Request {
    Request {
        req_type: "sync".to_string(),
        command: None,
        path: Some(path.to_string()),
        content: None,
        binary: None,
        gzip: None,
        sync_type: Some(sync_type.to_string()),
        delta: None,
        signatures: Some(sigs),
        paths: None,
        batch_patches: None,
        env_vars: None,
        track: None,
        version: None,
        allow_downgrade: None,
        insecure_no_verify: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_response(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        }
    }

    fn err_response(error: &str) -> Response {
        Response {
            success: false,
            output: None,
            error: Some(error.to_string()),
            size: None,
            binary: None,
            gzip: None,
        }
    }

    #[test]
    fn build_sync_request_fields() {
        let sigs = vec![mrsh_core::protocol::BlockSig {
            index: 0,
            weak: 12345,
            strong: "abc".to_string(),
        }];
        let req = build_sync_request("pull-delta", "/tmp/file", sigs);
        assert_eq!(req.req_type, "sync");
        assert_eq!(req.sync_type.as_deref(), Some("pull-delta"));
        assert_eq!(req.path.as_deref(), Some("/tmp/file"));
        assert_eq!(req.signatures.unwrap().len(), 1);
    }

    #[test]
    fn check_response_ok() {
        let resp = ok_response("ok");
        assert!(check_response(&resp).is_ok());
    }

    #[test]
    fn check_response_error() {
        let resp = err_response("file not found");
        let err = check_response(&resp).unwrap_err();
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn walk_entry_parse() {
        let json = r#"{"p":"subdir/file.txt","s":1024}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.path, "subdir/file.txt");
        assert_eq!(entry.size, 1024);
    }

    #[test]
    fn walk_entry_with_mtime() {
        let json = r#"{"p":"file.txt","s":100,"m":1711200000}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.mtime, 1711200000);
    }

    #[test]
    fn walk_entry_without_mtime_defaults_zero() {
        let json = r#"{"p":"file.txt","s":100}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.mtime, 0);
    }
}
