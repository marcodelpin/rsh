//! QUIC transport — multiplexed streams over UDP with same auth as TLS.
//! Auth on first stream, channels on subsequent streams.
//!
//! Protocol: ALPN "rsh-quic", newline-delimited JSON for auth,
//! channel header = `chanType\0target\n`, then raw I/O per channel type.
//!
//! Module layout:
//!   - `server`  — top-level QUIC listener (`start_quic_listener`)
//!   - `session` — per-connection lifecycle (`handle_quic_connection`)
//!   - `streams` — per-stream channel handlers (tunnel/exec/push/pull/ls/shell)
//!   - `auth`    — ed25519 challenge-response auth + key extractors

#![cfg(feature = "quic")]

use anyhow::{Context, Result};
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;

mod auth;
mod server;
mod session;
mod shell;
mod streams;

pub use server::start_quic_listener;

/// Channel type constants (shared between dispatcher and tests).
pub(super) const CHAN_TYPE_TUNNEL: &str = "tunnel";
pub(super) const CHAN_TYPE_UDP_TUNNEL: &str = "udp-tunnel";
pub(super) const CHAN_TYPE_EXEC: &str = "exec";
pub(super) const CHAN_TYPE_PUSH: &str = "push";
pub(super) const CHAN_TYPE_PULL: &str = "pull";
pub(super) const CHAN_TYPE_LS: &str = "ls";
pub(super) const CHAN_TYPE_SHELL: &str = "shell";

/// Send newline-delimited JSON on a QUIC send stream.
pub(super) async fn send_quic_json<T: serde::Serialize>(
    send: &mut quinn::SendStream,
    value: &T,
) -> Result<()> {
    let mut data = serde_json::to_vec(value).context("serialize JSON")?;
    data.push(b'\n');
    send.write_all(&data).await.context("write JSON")?;
    Ok(())
}

/// Read a newline-delimited JSON message from a QUIC recv stream.
pub(super) async fn recv_quic_json<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<quinn::RecvStream>,
) -> Result<T> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("read JSON line")?;
    serde_json::from_str(&line).context("parse JSON")
}

#[cfg(test)]
mod tests {
    use super::auth::{extract_ed25519_raw, extract_ed25519_sig};
    use super::session::handle_quic_connection;
    use super::streams::parse_shell_target;
    use super::{recv_quic_json, send_quic_json};

    use std::sync::Arc;

    use anyhow::{Context, Result};
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use mrsh_core::{auth, protocol, tls};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    use crate::handler::ServerContext;
    use crate::ratelimit;
    use crate::session;

    // ── parse_shell_target ───────────────────────────────────────

    #[test]
    fn parse_shell_target_empty() {
        let (size, env) = parse_shell_target("");
        assert_eq!(size, "");
        assert!(env.is_empty());
    }

    #[test]
    fn parse_shell_target_size_only_legacy() {
        let (size, env) = parse_shell_target("120x40");
        assert_eq!(size, "120x40");
        assert!(env.is_empty());
    }

    #[test]
    fn parse_shell_target_size_plus_env() {
        let (size, env) = parse_shell_target("80x24\0env=MRSH_SHELL=pwsh");
        assert_eq!(size, "80x24");
        assert_eq!(env, vec!["MRSH_SHELL=pwsh".to_string()]);
    }

    #[test]
    fn parse_shell_target_multiple_env() {
        let (size, env) =
            parse_shell_target("80x24\0env=MRSH_SHELL=bash\0env=FOO=bar\0env=BAZ=qux");
        assert_eq!(size, "80x24");
        assert_eq!(
            env,
            vec![
                "MRSH_SHELL=bash".to_string(),
                "FOO=bar".to_string(),
                "BAZ=qux".to_string(),
            ]
        );
    }

    #[test]
    fn parse_shell_target_unknown_tokens_ignored() {
        let (size, env) =
            parse_shell_target("80x24\0future=ignored\0env=MRSH_SHELL=zsh\0other=nope");
        assert_eq!(size, "80x24");
        assert_eq!(env, vec!["MRSH_SHELL=zsh".to_string()]);
    }

    #[test]
    fn parse_shell_target_empty_env_skipped() {
        let (size, env) = parse_shell_target("80x24\0env=\0env=FOO=bar");
        assert_eq!(size, "80x24");
        assert_eq!(env, vec!["FOO=bar".to_string()]);
    }

    #[test]
    fn parse_shell_target_env_without_size() {
        let (size, env) = parse_shell_target("\0env=MRSH_SHELL=pwsh");
        assert_eq!(size, "");
        assert_eq!(env, vec!["MRSH_SHELL=pwsh".to_string()]);
    }

    fn make_test_context(signing_key: &SigningKey) -> Arc<ServerContext> {
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: auth::KeyPermissions::default(),
        };

        Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec!["shell".to_string()],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
            server_key_path: None,
            device_id: None,
            rendezvous_server: None,
            authorized_keys_paths: vec![],
        })
    }

    fn make_quic_endpoint_pair() -> Result<(quinn::Endpoint, quinn::Endpoint, std::net::SocketAddr)>
    {
        // Generate TLS cert/key in a unique temp dir per test run
        let tmp = tempfile::tempdir()?;
        let (certs, key) = tls::load_or_generate_cert(tmp.path())?;

        // Server config
        let mut server_tls = (*tls::server_config(certs.clone(), key)?).clone();
        server_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];
        let server_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_tls))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

        let server_ep = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())?;
        let server_addr = server_ep.local_addr()?;

        // Client config
        let mut client_tls = (*tls::client_config()).clone();
        client_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];
        let client_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
        ));
        client_config.transport_config(Arc::new(transport));

        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        client_ep.set_default_client_config(client_config);

        Ok((server_ep, client_ep, server_addr))
    }

    /// Helper: perform client-side auth on a QUIC connection.
    async fn client_authenticate(
        conn: &quinn::Connection,
        signing_key: &SigningKey,
    ) -> Result<protocol::AuthResult> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let (mut send, recv) = conn.open_bi().await.context("open auth stream")?;

        // Send AuthRequest
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
        send_quic_json(&mut send, &auth_req).await?;

        let mut reader = BufReader::new(recv);

        // Receive challenge
        let challenge: protocol::AuthChallenge = recv_quic_json(&mut reader)
            .await
            .context("recv challenge")?;
        let challenge_bytes = b64.decode(&challenge.challenge)?;

        // Sign
        let kp = auth::SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: std::path::PathBuf::from("/dev/null"),
        };
        let sig = kp.sign_challenge(&challenge_bytes);

        let auth_resp = protocol::AuthResponse {
            signature: b64.encode(&sig),
        };
        send_quic_json(&mut send, &auth_resp).await?;
        send.finish().context("finish auth send")?;

        // Receive result
        let result: protocol::AuthResult = recv_quic_json(&mut reader).await?;
        Ok(result)
    }

    #[tokio::test]
    async fn quic_auth_success() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        // Server: accept one connection, auth the first stream
        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        // Client: connect and authenticate
        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success, "auth should succeed");
        assert_eq!(result.version.as_deref(), Some("0.1.0-test"));
        assert!(result.mux_enabled.unwrap_or(false));

        // Close connection (server loop will exit)
        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_auth_wrong_key() {
        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&server_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Use a different key (not authorized)
        let wrong_key = SigningKey::generate(&mut rand::thread_rng());
        let result = client_authenticate(&conn, &wrong_key).await;

        // Should get failure result or connection closed
        match result {
            Ok(r) => assert!(!r.success, "auth should fail with wrong key"),
            Err(_) => {} // Connection closed by server is also acceptable
        }

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_exec_channel() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Authenticate first
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open exec channel
        let (mut send, recv) = conn.open_bi().await.unwrap();

        // Send header: "exec\n"
        send.write_all(b"exec\n").await.unwrap();
        // Send command: "echo hello_quic\n"
        send.write_all(b"echo hello_quic\n").await.unwrap();
        send.finish().unwrap();

        // Read response
        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();

        assert!(
            response.starts_with("OK\n"),
            "expected OK prefix, got: {:?}",
            response
        );
        assert!(
            response.contains("hello_quic"),
            "expected echo output, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_tunnel_echo() {
        use tokio::net::TcpListener;

        // Start TCP echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Auth
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open tunnel channel
        let (mut send, recv) = conn.open_bi().await.unwrap();

        // Header: tunnel\0target\n
        let header = format!("tunnel\0{}\n", echo_addr);
        send.write_all(header.as_bytes()).await.unwrap();

        // Read OK response
        let mut reader = BufReader::new(recv);
        let mut ok_line = String::new();
        reader.read_line(&mut ok_line).await.unwrap();
        assert_eq!(ok_line.trim(), "OK");

        // Send data through tunnel
        send.write_all(b"hello tunnel").await.unwrap();

        // Read echoed data — give the echo server some time
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Close and cleanup
        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_unknown_channel_type() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Auth
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open unknown channel type
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"foobar\n").await.unwrap();
        send.finish().unwrap();

        // Should get error response
        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR"),
            "expected error for unknown channel, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[test]
    fn extract_ed25519_raw_32_bytes() {
        let raw = vec![0x42u8; 32];
        assert_eq!(extract_ed25519_raw(&raw).unwrap(), raw);
    }

    #[test]
    fn extract_ed25519_raw_ssh_wire() {
        let key_type = b"ssh-ed25519";
        let raw_key = vec![0x42u8; 32];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(raw_key.len() as u32).to_be_bytes());
        wire.extend_from_slice(&raw_key);

        let extracted = extract_ed25519_raw(&wire).unwrap();
        assert_eq!(extracted, raw_key);
    }

    #[test]
    fn extract_ed25519_sig_64_bytes() {
        let sig = vec![0x42u8; 64];
        assert_eq!(extract_ed25519_sig(&sig).unwrap(), sig);
    }

    #[test]
    fn extract_invalid_key_fails() {
        let short = vec![0x42u8; 10];
        assert!(extract_ed25519_raw(&short).is_err());
    }

    #[test]
    fn extract_invalid_sig_fails() {
        let short = vec![0x42u8; 10];
        assert!(extract_ed25519_sig(&short).is_err());
    }

    #[tokio::test]
    async fn quic_push_pull_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Authenticate
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Create temp file path
        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("test_push.dat");
        let file_path_str = file_path.to_str().unwrap();

        // === PUSH ===
        let test_data = b"hello QUIC push/pull!";
        {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let header = format!("push\0{}\n", file_path_str);
            send.write_all(header.as_bytes()).await.unwrap();

            let size = test_data.len() as u64;
            send.write_all(&size.to_be_bytes()).await.unwrap();
            send.write_all(test_data).await.unwrap();
            send.finish().unwrap();

            let mut response = String::new();
            let mut reader = BufReader::new(recv);
            reader.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with("OK\n"),
                "push should succeed, got: {:?}",
                response
            );
        }

        // Verify file was written
        let written = tokio::fs::read(&file_path).await.unwrap();
        assert_eq!(written, test_data);

        // === PULL ===
        {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let header = format!("pull\0{}\n", file_path_str);
            send.write_all(header.as_bytes()).await.unwrap();
            send.finish().unwrap();

            let mut reader = BufReader::new(recv);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await.unwrap();
            assert_eq!(status_line.trim(), "OK");

            let mut size_buf = [0u8; 8];
            reader.read_exact(&mut size_buf).await.unwrap();
            let size = u64::from_be_bytes(size_buf);
            assert_eq!(size, test_data.len() as u64);

            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data).await.unwrap();
            assert_eq!(data, test_data);
        }

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_push_permission_denied() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        // Create context with push disabled
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let mut perms = auth::KeyPermissions::default();
        perms.allow_push = false;
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: perms,
        };
        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec![],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
            server_key_path: None,
            device_id: None,
            rendezvous_server: None,
            authorized_keys_paths: vec![],
        });

        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Try push — should be denied
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"push\0/tmp/denied.dat\n").await.unwrap();
        send.write_all(&8u64.to_be_bytes()).await.unwrap();
        send.write_all(b"testdata").await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR") && response.contains("not permitted"),
            "expected permission denied, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_pull_nonexistent_file() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Pull nonexistent file
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"pull\0/tmp/nonexistent_quic_test_xyz.dat\n")
            .await
            .unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR"),
            "expected error for missing file, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_push_creates_parent_dirs() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Push to nested path that doesn't exist yet
        let tmp_dir = tempfile::tempdir().unwrap();
        let nested = tmp_dir
            .path()
            .join("a")
            .join("b")
            .join("c")
            .join("test.txt");
        let nested_str = nested.to_str().unwrap();

        let (mut send, recv) = conn.open_bi().await.unwrap();
        let header = format!("push\0{}\n", nested_str);
        send.write_all(header.as_bytes()).await.unwrap();

        let data = b"nested data";
        send.write_all(&(data.len() as u64).to_be_bytes())
            .await
            .unwrap();
        send.write_all(data).await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("OK\n"), "got: {:?}", response);

        // Verify
        let content = tokio::fs::read(&nested).await.unwrap();
        assert_eq!(content, data);

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_push_empty_file() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("empty.dat");
        let file_path_str = file_path.to_str().unwrap();

        // Push empty file
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let header = format!("push\0{}\n", file_path_str);
        send.write_all(header.as_bytes()).await.unwrap();
        send.write_all(&0u64.to_be_bytes()).await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("OK\n"), "got: {:?}", response);

        // Verify empty file
        let content = tokio::fs::read(&file_path).await.unwrap();
        assert!(content.is_empty());

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_ls_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Create a temp dir with a known file
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("hello.txt"), b"hi").unwrap();

        // List the temp dir
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let header = format!("ls\0{}\n", tmp_dir.path().to_str().unwrap());
        send.write_all(header.as_bytes()).await.unwrap();
        send.finish().unwrap();

        let mut reader = BufReader::new(recv);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        // Should be valid JSON array containing "hello.txt"
        let files: Vec<mrsh_core::protocol::FileInfo> = serde_json::from_str(&line)
            .unwrap_or_else(|_| panic!("expected JSON array, got: {:?}", line));
        assert!(
            files.iter().any(|f| f.name == "hello.txt"),
            "hello.txt not found in listing"
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_ls_nonexistent_dir() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ls\0/tmp/nonexistent_quic_ls_test_xyz\n")
            .await
            .unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR"),
            "expected error for missing dir, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn quic_shell_handshake() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open shell channel: "shell\0{COLSxROWS}\n"
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"shell\080x24\n").await.unwrap();

        // Server should respond with "OK\n"
        let mut reader = BufReader::new(recv);
        let mut ok_line = String::new();
        reader.read_line(&mut ok_line).await.unwrap();
        assert_eq!(ok_line.trim(), "OK", "expected OK, got: {:?}", ok_line);

        // Disconnect — server relay loop should exit cleanly
        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_shell_permission_denied() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        // Create context with shell disabled
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let mut perms = auth::KeyPermissions::default();
        perms.allow_shell = false;
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: perms,
        };
        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec![],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
            server_key_path: None,
            device_id: None,
            rendezvous_server: None,
            authorized_keys_paths: vec![],
        });

        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Try shell — should be denied
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"shell\n").await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR") && response.contains("not permitted"),
            "expected permission denied, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }
}
