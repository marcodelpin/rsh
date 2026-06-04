//! Shared-filesystem session listener.
//!
//! Instead of accepting TCP connections, the fs listener polls a spool directory
//! for new session subdirectories. Each subdirectory pairs one client with the
//! server via an [`FsStream`](mrsh_core::fs_transport::FsStream). The session id
//! is the subdirectory name (16 hex chars by convention, but any name works).
//!
//! A session is considered "new" when its directory contains a marker file
//! named `ready.server` (written atomically by the client after the session
//! layout is set up). That keeps us from racing with the client while it's
//! still creating `c2s/` and `s2c/`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mrsh_core::fs_transport::{FsStream, Role};
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::handler::{self, ServerContext};

/// Default polling cadence when watching the spool root for new sessions.
pub const DEFAULT_SCAN_INTERVAL: Duration = Duration::from_millis(500);

/// Marker filename that signals the session layout is ready to be picked up.
pub const READY_MARKER: &str = "ready.server";

/// Marker filename that signals the server accepted the session (avoids double-pickup).
pub const CLAIMED_MARKER: &str = "claimed.server";

/// Watch `spool_dir` for new sessions and dispatch each to `handler::handle_connection`.
///
/// Layout expected:
/// - `spool_dir/<session>/c2s/`
/// - `spool_dir/<session>/s2c/`
/// - `spool_dir/<session>/ready.server` (triggers pickup)
///
/// After claiming a session the listener writes `claimed.server` so concurrent
/// listeners (e.g. if the same spool is shared across hosts) don't race.
pub async fn run_fs_listener(
    spool_dir: PathBuf,
    tls_acceptor: TlsAcceptor,
    ctx: Arc<ServerContext>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    tokio::fs::create_dir_all(&spool_dir)
        .await
        .context("create fs-listener spool dir")?;
    info!("fs listener on {}", spool_dir.display());

    let mut seen: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("fs listener shutting down");
                return Ok(());
            }
            _ = tokio::time::sleep(DEFAULT_SCAN_INTERVAL) => {}
        }

        let entries = match scan_ready_sessions(&spool_dir).await {
            Ok(v) => v,
            Err(e) => {
                warn!("fs listener scan error: {:#}", e);
                continue;
            }
        };

        for session in entries {
            if !seen.insert(session.clone()) {
                continue;
            }
            let session_dir = spool_dir.join(&session);
            match claim_session(&session_dir).await {
                Ok(true) => {}
                Ok(false) => {
                    // Already claimed by another listener or claim failed silently.
                    continue;
                }
                Err(e) => {
                    warn!("fs listener claim {} failed: {:#}", session, e);
                    continue;
                }
            }

            let ctx_clone = ctx.clone();
            let spool_clone = spool_dir.clone();
            let session_clone = session.clone();
            let acceptor_clone = tls_acceptor.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_fs_session(&spool_clone, &session_clone, acceptor_clone, ctx_clone)
                        .await
                {
                    debug!("fs session {} ended: {:#}", session_clone, e);
                }
            });
        }
    }
}

async fn scan_ready_sessions(spool_dir: &Path) -> Result<Vec<String>> {
    let mut entries = tokio::fs::read_dir(spool_dir)
        .await
        .context("read_dir spool")?;
    let mut result = Vec::new();
    while let Some(entry) = entries.next_entry().await.context("next_entry")? {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let ready = path.join(READY_MARKER);
        let claimed = path.join(CLAIMED_MARKER);
        if tokio::fs::try_exists(&ready).await.unwrap_or(false)
            && !tokio::fs::try_exists(&claimed).await.unwrap_or(false)
        {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                result.push(name.to_string());
            }
        }
    }
    Ok(result)
}

async fn claim_session(session_dir: &Path) -> Result<bool> {
    let claimed = session_dir.join(CLAIMED_MARKER);
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&claimed)
        .await
    {
        Ok(mut f) => {
            f.write_all(b"claimed").await.context("write claim marker")?;
            f.flush().await.ok();
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(anyhow::Error::from(e).context("create claim marker")),
    }
}

async fn handle_fs_session(
    spool_dir: &Path,
    session_id: &str,
    tls_acceptor: TlsAcceptor,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    debug!("fs listener claimed session {}", session_id);
    let stream =
        FsStream::open(spool_dir, session_id, Role::Server).context("open FsStream(server)")?;
    let tls_stream = tls_acceptor
        .accept(stream)
        .await
        .context("TLS handshake over fs-transport")?;
    handler::handle_connection(tls_stream, &ctx, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ratelimit, session};
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use mrsh_core::fs_transport::ensure_session_dirs;
    use mrsh_core::{auth, protocol, tls as core_tls, wire};
    use tempfile::tempdir;
    use tokio_rustls::TlsConnector;

    fn test_tls_pair(cert_dir: &Path) -> (TlsAcceptor, TlsConnector) {
        let (certs, key) = core_tls::load_or_generate_cert(cert_dir).expect("cert");
        let server_cfg = core_tls::server_config(certs, key).expect("server cfg");
        let acceptor = TlsAcceptor::from(server_cfg);
        let client_cfg = core_tls::client_config();
        let connector = TlsConnector::from(client_cfg);
        (acceptor, connector)
    }

    fn make_ctx(signing_key: &SigningKey) -> ServerContext {
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: auth::KeyPermissions::default(),
        };
        ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "fs-listener-test".to_string(),
            banner: None,
            caps: vec!["shell".to_string()],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
            server_key_path: None,
            device_id: Some("fs-dev".to_string()),
            rendezvous_server: None,
            authorized_keys_paths: vec![],
        }
    }

    #[tokio::test]
    async fn listener_picks_up_session_and_completes_auth() {
        use tokio_rustls::rustls::pki_types::ServerName;

        let spool = tempdir().expect("tempdir");
        let spool_dir = spool.path().to_path_buf();
        let cert_dir = tempdir().expect("cert tempdir");
        let (acceptor, connector) = test_tls_pair(cert_dir.path());

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = Arc::new(make_ctx(&signing_key));
        let cancel = tokio_util::sync::CancellationToken::new();

        let spool_for_server = spool_dir.clone();
        let ctx_for_server = ctx.clone();
        let cancel_for_server = cancel.clone();
        let acceptor_for_server = acceptor.clone();
        let listener = tokio::spawn(async move {
            let _ = run_fs_listener(
                spool_for_server,
                acceptor_for_server,
                ctx_for_server,
                cancel_for_server,
            )
            .await;
        });

        // Client-side: lay out the session, publish ready.server, TLS wrap, then drive auth.
        let session = mrsh_core::fs_transport::generate_session_id();
        let session_dir = ensure_session_dirs(&spool_dir, &session).expect("ensure_session_dirs");
        let fs_stream = FsStream::open(&spool_dir, &session, Role::Client)
            .expect("open FsStream(client)")
            .with_poll_interval(std::time::Duration::from_millis(20));

        let ready_tmp = session_dir.join("ready.server.tmp");
        let ready_final = session_dir.join("ready.server");
        {
            use tokio::io::AsyncWriteExt as _;
            let mut f = tokio::fs::File::create(&ready_tmp).await.expect("ready tmp");
            f.write_all(b"ready").await.expect("write ready");
            f.flush().await.ok();
        }
        tokio::fs::rename(&ready_tmp, &ready_final)
            .await
            .expect("rename ready");

        let server_name = ServerName::try_from("fs-test").expect("server name");
        let mut client = connector
            .connect(server_name, fs_stream)
            .await
            .expect("tls handshake");

        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let auth_req = protocol::AuthRequest {
            auth_type: "auth".to_string(),
            public_key: Some(b64.encode(pub_bytes)),
            key_type: Some("ssh-ed25519".to_string()),
            username: None,
            password: None,
            version: Some("0.1.0".to_string()),
            want_mux: None,
            caps: Some(vec!["shell".to_string()]),
        };
        wire::send_json(&mut client, &auth_req).await.expect("send auth request");

        let challenge: protocol::AuthChallenge =
            wire::recv_json(&mut client).await.expect("recv challenge");
        let challenge_bytes = b64.decode(&challenge.challenge).expect("decode challenge");

        let kp = auth::SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: std::path::PathBuf::from("/dev/null"),
        };
        let sig = kp.sign_challenge(&challenge_bytes);
        let auth_resp = protocol::AuthResponse {
            signature: b64.encode(&sig),
        };
        wire::send_json(&mut client, &auth_resp)
            .await
            .expect("send auth response");

        let result: protocol::AuthResult = wire::recv_json(&mut client).await.expect("recv result");
        assert!(result.success, "auth failed: {:?}", result.error);
        assert_eq!(result.version.as_deref(), Some("fs-listener-test"));

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;

        // Confirm the claim marker was written so re-scans wouldn't double-pickup.
        assert!(tokio::fs::try_exists(session_dir.join(CLAIMED_MARKER)).await.unwrap());

        // Confirm the auth payloads on disk are NOT plaintext (no ssh-ed25519 marker).
        // The raw pubkey is sent as JSON inside the AuthRequest; if TLS is working,
        // we should NOT find "ssh-ed25519" in any raw chunk written to the spool.
        // NOTE: after-the-fact verification — files were deleted by reader, this is a
        // smoke assertion that no leftover plaintext is present.
        let mut dir = tokio::fs::read_dir(session_dir.join("c2s")).await.unwrap();
        while let Some(entry) = dir.next_entry().await.unwrap() {
            let bytes = tokio::fs::read(entry.path()).await.unwrap_or_default();
            assert!(
                !bytes.windows(11).any(|w| w == b"ssh-ed25519"),
                "leftover plaintext in {}", entry.path().display()
            );
        }
    }

    #[tokio::test]
    async fn scan_ignores_claimed_sessions() {
        let spool = tempdir().expect("tempdir");
        let spool_dir = spool.path().to_path_buf();
        let session_dir = spool_dir.join("abcd");
        ensure_session_dirs(&spool_dir, "abcd").expect("ensure dirs");
        tokio::fs::write(session_dir.join(READY_MARKER), b"ready")
            .await
            .unwrap();
        tokio::fs::write(session_dir.join(CLAIMED_MARKER), b"claimed")
            .await
            .unwrap();

        let found = scan_ready_sessions(&spool_dir).await.expect("scan");
        assert!(found.is_empty(), "already-claimed sessions must be ignored");
    }

    #[tokio::test]
    async fn claim_is_single_shot() {
        let spool = tempdir().expect("tempdir");
        let spool_dir = spool.path().to_path_buf();
        ensure_session_dirs(&spool_dir, "zzz").expect("ensure dirs");
        let session_dir = spool_dir.join("zzz");

        let first = claim_session(&session_dir).await.expect("first claim");
        assert!(first);
        let second = claim_session(&session_dir).await.expect("second claim");
        assert!(!second, "second claim must return false");
    }
}
