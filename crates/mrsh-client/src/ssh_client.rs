//! SSH client fallback — connects to hosts with only SSH (no mrsh service).
//!
//! When mrsh TLS handshake fails but SSH is available, this module
//! provides exec/push/pull/shell over standard SSH protocol via russh.
//!
//! # Feature gate
//!
//! Compiled only with `--features ssh-client`.

#[cfg(feature = "ssh-client")]
mod impl_ssh_client {
    use anyhow::{Context, Result, bail};
    use base64::Engine;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tracing::{debug, info};

    /// SSH client session handle.
    pub struct SshSession {
        handle: russh::client::Handle<SshClientHandler>,
    }

    /// Per-connection handler for russh client events.
    struct SshClientHandler {
        /// Server host key fingerprint (for TOFU verification).
        server_fingerprint: Mutex<Option<String>>,
    }

    impl russh::client::Handler for SshClientHandler {
        type Error = anyhow::Error;

        /// Called when server presents its host key. Accept all for now.
        /// TODO: TOFU verification against known_hosts.
        async fn check_server_key(
            &mut self,
            server_public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            let fp = server_public_key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
            info!("SSH server key: {}", fp);
            *self.server_fingerprint.lock().await = Some(fp.to_string());
            Ok(true) // Accept (TODO: TOFU check)
        }
    }

    impl SshSession {
        /// Connect to an SSH server and authenticate with ed25519 key.
        pub async fn connect(
            host: &str,
            port: u16,
            key_path: &Option<String>,
        ) -> Result<Self> {
            let config = russh::client::Config {
                ..Default::default()
            };

            let handler = SshClientHandler {
                server_fingerprint: Mutex::new(None),
            };

            let addr = format!("{}:{}", host, port);
            debug!("SSH client connecting to {}", addr);

            let mut handle = russh::client::connect(Arc::new(config), &addr, handler)
                .await
                .context("SSH connect")?;

            // Authenticate
            let key_pair = if let Some(path) = key_path {
                mrsh_core::auth::load_ssh_key(std::path::Path::new(path))
                    .context("load SSH key")?
            } else {
                mrsh_core::auth::discover_key()
                    .context("no SSH key found")?
            };

            // Load key as russh PrivateKey and wrap with hash algorithm
            let key_file = key_pair.path.clone();
            let russh_key = russh::keys::load_secret_key(&key_file, None)
                .context("load key for SSH auth")?;

            let key_with_hash = russh::keys::PrivateKeyWithHashAlg::new(
                Arc::new(russh_key),
                None, // ed25519 doesn't need hash algorithm selection
            );

            let auth_result = handle
                .authenticate_publickey(
                    std::env::var("USER").unwrap_or_else(|_| "root".into()),
                    key_with_hash,
                )
                .await
                .context("SSH pubkey auth")?;

            match auth_result {
                russh::client::AuthResult::Success => {}
                russh::client::AuthResult::Failure { .. } => {
                    bail!("SSH authentication rejected");
                }
                other => {
                    bail!("SSH auth unexpected result: {:?}", other);
                }
            }

            info!("SSH client authenticated to {}", addr);
            Ok(SshSession { handle })
        }

        /// Execute a command on the remote host, return output.
        pub async fn exec(&self, command: &str) -> Result<(u32, String)> {
            let channel = self.handle.channel_open_session().await
                .context("open session channel")?;

            channel.exec(true, command).await
                .context("send exec")?;

            let mut output = Vec::new();
            let mut exit_code = 0u32;
            let mut channel = channel;

            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => {
                        output.extend_from_slice(&data);
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        output.extend_from_slice(&data);
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = exit_status;
                    }
                    Some(russh::ChannelMsg::Eof) | None => break,
                    _ => {} // ignore other messages
                }
            }

            Ok((exit_code, String::from_utf8_lossy(&output).to_string()))
        }

        /// Push a local file to remote via SCP-like exec + stdin.
        /// Uses `cat > remote_path` on the remote side.
        pub async fn push(&self, local_path: &std::path::Path, remote_path: &str) -> Result<u64> {
            let data = std::fs::read(local_path).context("read local file")?;
            let size = data.len() as u64;

            // Use base64 encoding via exec to avoid binary stdin issues
            // Alternative: use SFTP subsystem when available
            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
            let cmd = format!(
                "echo '{}' | base64 -d > '{}'",
                b64,
                remote_path.replace('\'', "'\\''")
            );

            // For large files, use dd with stdin
            if size > 1_000_000 {
                // Large file: use cat with stdin pipe
                let channel = self.handle.channel_open_session().await?;
                let mkdir_parent = if let Some(parent) = std::path::Path::new(remote_path).parent() {
                    format!("mkdir -p '{}' && ", parent.display())
                } else {
                    String::new()
                };
                channel.exec(true, format!("{}cat > '{}'", mkdir_parent, remote_path.replace('\'', "'\\''"))).await?;
                channel.data(&data[..]).await?;
                channel.eof().await?;

                let mut channel = channel;
                let mut exit_code = 0u32;
                loop {
                    match channel.wait().await {
                        Some(russh::ChannelMsg::ExitStatus { exit_status }) => exit_code = exit_status,
                        Some(russh::ChannelMsg::Eof) | None => break,
                        _ => {}
                    }
                }
                if exit_code != 0 {
                    bail!("push failed with exit code {}", exit_code);
                }
            } else {
                // Small file: base64 via exec
                let (exit_code, output) = self.exec(&cmd).await?;
                if exit_code != 0 {
                    bail!("push failed: {}", output);
                }
            }

            Ok(size)
        }

        /// Pull a remote file via cat.
        pub async fn pull(&self, remote_path: &str) -> Result<Vec<u8>> {
            let cmd = format!("cat '{}'", remote_path.replace('\'', "'\\''"));
            let channel = self.handle.channel_open_session().await?;
            channel.exec(true, cmd).await?;

            let mut data = Vec::new();
            let mut channel = channel;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data: chunk }) => {
                        data.extend_from_slice(&chunk);
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        if exit_status != 0 {
                            bail!("pull failed with exit code {}", exit_status);
                        }
                    }
                    Some(russh::ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }

            Ok(data)
        }

        /// Close the SSH session.
        pub async fn disconnect(self) -> Result<()> {
            self.handle
                .disconnect(russh::Disconnect::ByApplication, "bye", "en")
                .await?;
            Ok(())
        }
    }
}

// Re-export
#[cfg(feature = "ssh-client")]
pub use impl_ssh_client::SshSession;

/// Check if SSH client feature is available.
pub fn ssh_client_available() -> bool {
    cfg!(feature = "ssh-client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_client_feature_detection() {
        // Just verifies the function compiles and returns a bool
        let _ = ssh_client_available();
    }
}
