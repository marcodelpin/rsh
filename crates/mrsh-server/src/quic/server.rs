//! QUIC listener: bind UDP endpoint with rustls + ALPN, dispatch each
//! incoming connection to `session::handle_quic_connection`.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::Endpoint;
use tracing::{debug, info};

use crate::handler::ServerContext;

use super::session::handle_quic_connection;

/// Start the QUIC listener on the same port as TLS (UDP).
///
/// Uses the provided rustls `ServerConfig` with ALPN set to `rsh-quic`.
/// QUIC config: MaxIdle=60s, KeepAlive=15s, MaxIncoming=1000.
pub async fn start_quic_listener(
    port: u16,
    tls_config: Arc<rustls::ServerConfig>,
    ctx: Arc<ServerContext>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    // Clone and set ALPN for QUIC
    let mut quic_tls = (*tls_config).clone();
    quic_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(quic_tls))
            .context("build QUIC server crypto config")?,
    ));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let endpoint = Endpoint::server(server_config, addr).context("bind QUIC endpoint")?;

    info!("[QUIC] listening on {}", addr);

    loop {
        let incoming = tokio::select! {
            inc = endpoint.accept() => {
                match inc {
                    Some(i) => i,
                    None => {
                        info!("[QUIC] endpoint closed");
                        return Ok(());
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("[QUIC] shutting down");
                endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
                return Ok(());
            }
        };

        let ctx = ctx.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_quic_connection(conn, ctx).await {
                        debug!("[QUIC] connection error: {}", e);
                    }
                }
                Err(e) => {
                    debug!("[QUIC] accept error: {}", e);
                }
            }
        });
    }
}
