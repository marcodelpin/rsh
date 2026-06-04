//! Discovery of fleet peers via the rendezvous (hbbs) server.
//!
//! Used by `status` to enrich the locally-configured host list with peers
//! that are registered on the rendezvous server but not in `~/.mrsh/config`.

use mrsh_core::config::Config;
use tracing::debug;

/// Query hbbs for all registered peers (best-effort).
pub(super) async fn discover_from_hbbs(
    config: &Config,
) -> Vec<mrsh_relay::rendezvous::GroupPeerInfo> {
    let rdv_server = match &config.rendezvous_server {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return Vec::new(),
    };
    let rdv_key = config.rendezvous_key.clone().unwrap_or_default();

    let client = mrsh_relay::rendezvous::Client {
        servers: vec![rdv_server],
        licence_key: rdv_key,
        local_id: String::new(),
        group_hash: String::new(),
        hostname: String::new(),
        platform: String::new(),
        service_port: 0,
        encrypted_net_info: Vec::new(),
        // sys-8z5gn: client-only query never runs the registration refresh loop.
        enrollment_token: String::new(),
        tray_port: 0,
        ports: Vec::new(),
        // rsh-5264.1: client-side queries don't report a server version.
        current_version: String::new(),
        last_update_status: String::new(),
        last_update_at_unix: 0,
        // rsh-5264.5: client doesn't have a track / auto_upgrade setting.
        track: String::new(),
        auto_upgrade: false,
    };

    match client.list_peers().await {
        Ok(peers) => {
            debug!("hbbs: discovered {} peers", peers.len());
            peers
        }
        Err(e) => {
            debug!("hbbs: list_peers failed (non-fatal): {}", e);
            Vec::new()
        }
    }
}
