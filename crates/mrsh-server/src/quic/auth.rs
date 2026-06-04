//! QUIC authentication: ed25519 challenge-response on the first stream,
//! plus helpers to extract raw 32-byte keys / 64-byte signatures from
//! either SSH wire format or already-raw bytes.

use anyhow::{Context, Result};
use base64::Engine;
use mrsh_core::{auth, protocol};
use tokio::io::BufReader;
use tracing::{debug, info, warn};

use crate::handler::ServerContext;

use super::{recv_quic_json, send_quic_json};

/// Perform ed25519 challenge-response authentication on the first QUIC stream.
/// Returns `Some(permissions)` on success, `None` on failure.
pub(super) async fn authenticate_quic_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    ctx: &ServerContext,
    remote: std::net::SocketAddr,
) -> Option<auth::KeyPermissions> {
    match authenticate_quic_inner(&mut send, recv, ctx).await {
        Ok(info) => {
            info!(
                "[QUIC] authenticated: {} (v{}) from {}",
                info.0.as_deref().unwrap_or("unknown"),
                info.1.as_deref().unwrap_or("?"),
                remote
            );
            Some(info.2)
        }
        Err(e) => {
            warn!("[QUIC] auth failed from {}: {}", remote, e);
            // Try to send failure result (best effort)
            let _ = send_quic_json(
                &mut send,
                &protocol::AuthResult {
                    success: false,
                    error: Some(e.to_string()),
                    version: Some(ctx.server_version.clone()),
                    ..Default::default()
                },
            )
            .await;
            let _ = send.finish();
            None
        }
    }
}

/// Inner auth logic, returns (comment, version, permissions) on success.
async fn authenticate_quic_inner(
    send: &mut quinn::SendStream,
    recv: quinn::RecvStream,
    ctx: &ServerContext,
) -> Result<(Option<String>, Option<String>, auth::KeyPermissions)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut reader = BufReader::new(recv);

    // 1. Receive AuthRequest (newline-delimited JSON)
    let auth_req: protocol::AuthRequest = recv_quic_json(&mut reader)
        .await
        .context("recv AuthRequest")?;

    debug!(
        "[QUIC] auth request: type={} version={:?}",
        auth_req.auth_type, auth_req.version
    );

    if auth_req.auth_type != "auth" && auth_req.auth_type != "pubkey" {
        anyhow::bail!("unsupported auth type: {}", auth_req.auth_type);
    }

    // 2. Look up client's public key
    let client_pubkey_b64 = auth_req.public_key.as_ref().context("missing public_key")?;
    let client_pubkey_wire = b64
        .decode(client_pubkey_b64)
        .context("decode public_key base64")?;

    // Extract raw 32-byte ed25519 key
    let raw_key = extract_ed25519_raw(&client_pubkey_wire)?;

    // Find matching authorized key
    let matched_key = ctx
        .authorized_keys
        .iter()
        .find(|k| k.key_data == raw_key)
        .context("public key not authorized")?;

    // 3. Send challenge
    let challenge = auth::generate_challenge();
    let challenge_msg = protocol::AuthChallenge {
        challenge: b64.encode(&challenge),
    };
    send_quic_json(send, &challenge_msg).await?;

    // 4. Receive signed response
    let auth_resp: protocol::AuthResponse = recv_quic_json(&mut reader)
        .await
        .context("recv AuthResponse")?;

    let signature = b64
        .decode(&auth_resp.signature)
        .context("decode signature base64")?;

    let raw_sig = extract_ed25519_sig(&signature)?;

    // 5. Verify signature
    let valid = auth::verify_ed25519_signature(&raw_key, &challenge, &raw_sig)
        .context("verify signature")?;

    if !valid {
        anyhow::bail!("signature verification failed");
    }

    // 6. Send success
    let result = protocol::AuthResult {
        success: true,
        error: None,
        version: Some(ctx.server_version.clone()),
        mux_enabled: Some(true),
        caps: Some(ctx.caps.clone()),
        banner: ctx.banner.clone(),
        device_id: ctx.device_id.clone(),
        rendezvous_server: ctx.rendezvous_server.clone(),
    };
    send_quic_json(send, &result).await?;
    send.finish().context("finish auth send stream")?;

    Ok((
        matched_key.comment.clone(),
        auth_req.version,
        matched_key.permissions.clone(),
    ))
}

/// Extract raw 32-byte ed25519 public key from SSH wire format or raw bytes.
pub(super) fn extract_ed25519_raw(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() == 32 {
        return Ok(data.to_vec());
    }
    if data.len() > 32 {
        if data.len() >= 51 {
            let type_len = u32::from_be_bytes(data[0..4].try_into()?) as usize;
            if type_len == 11 && &data[4..15] == b"ssh-ed25519" {
                return Ok(data[data.len() - 32..].to_vec());
            }
        }
        return Ok(data[data.len() - 32..].to_vec());
    }
    anyhow::bail!("invalid ed25519 public key: {} bytes", data.len());
}

/// Extract raw 64-byte ed25519 signature from SSH wire format or raw bytes.
pub(super) fn extract_ed25519_sig(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() == 64 {
        return Ok(data.to_vec());
    }
    if data.len() > 64 {
        return Ok(data[data.len() - 64..].to_vec());
    }
    anyhow::bail!("invalid ed25519 signature: {} bytes", data.len());
}
