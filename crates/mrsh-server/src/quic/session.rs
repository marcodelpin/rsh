//! Per-connection lifecycle: authenticate the first stream, then accept and
//! dispatch subsequent channel streams until the connection closes.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::handler::ServerContext;

use super::auth::authenticate_quic_stream;
use super::streams::handle_quic_stream;

/// Handle a single QUIC connection: auth on first stream, channels on rest.
pub(super) async fn handle_quic_connection(
    conn: quinn::Connection,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    let remote = conn.remote_address();
    info!("[QUIC] new connection from {}", remote);

    // First stream = authentication
    let (send, recv) = conn.accept_bi().await.context("accept auth stream")?;

    let perms = match authenticate_quic_stream(send, recv, &ctx, remote).await {
        Some(p) => p,
        None => {
            conn.close(quinn::VarInt::from_u32(1), b"auth failed");
            return Ok(());
        }
    };

    info!("[QUIC] client authenticated from {}", remote);
    let perms = Arc::new(perms);

    // Handle subsequent streams
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                debug!("[QUIC] connection closed: {}", e);
                return Ok(());
            }
        };

        let remote_str = remote.to_string();
        let perms = perms.clone();
        let allowed_tunnels = ctx.allowed_tunnels.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_quic_stream(send, recv, &remote_str, &perms, &allowed_tunnels).await
            {
                debug!("[QUIC] stream error: {}", e);
            }
        });
    }
}
