//! `mrsh rdv publish` and `mrsh rdv query` operator subcommands (rsh-5264.3).
//!
//! `publish`: send a `PublishVersionRequest` over UDP to the configured
//! rendezvous server, advertising a new (platform, track, version) tuple
//! signed by the operator's release-signing private key.
//!
//! `query`: send a `QueryVersionRequest` and print the advert (or "no
//! update available"). Useful for operators verifying a publish actually
//! landed.
//!
//! Phase 3 of the rdv-driven auto-upgrade pipeline (parent rsh-5264).
//! The actual self-update execution on receiving servers is OUT OF SCOPE for
//! this PR — it is a separate child issue (see rsh-5264.4 / rsh-5264.5).

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use mrsh_relay::rendezvous::{Client as RdvClient, VersionAdvert};

/// `mrsh rdv publish <binary> --platform <p> --track <t> --version <v>
///   [--key <priv.pem>] [--server <host:port>] [--rdv-key <licence>]
///   [--download-url <url>] [--no-blob]`
pub async fn run_publish(args: &[String]) -> Result<()> {
    let mut binary: Option<PathBuf> = None;
    let mut platform: Option<String> = None;
    let mut track: Option<String> = None;
    let mut version: Option<String> = None;
    let mut priv_key: Option<PathBuf> = None;
    let mut server: Option<String> = None;
    let mut licence: Option<String> = None;
    let mut download_url = String::new();
    let mut send_blob = true;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--platform" => {
                i += 1;
                platform = args.get(i).cloned();
            }
            "--track" => {
                i += 1;
                track = args.get(i).cloned();
            }
            "--version" => {
                i += 1;
                version = args.get(i).cloned();
            }
            "--key" => {
                i += 1;
                priv_key = args.get(i).map(PathBuf::from);
            }
            "--server" => {
                i += 1;
                server = args.get(i).cloned();
            }
            "--rdv-key" => {
                i += 1;
                licence = args.get(i).cloned();
            }
            "--download-url" => {
                i += 1;
                download_url = args.get(i).cloned().unwrap_or_default();
            }
            "--no-blob" => {
                send_blob = false;
            }
            "--help" | "-h" => {
                print_publish_usage();
                return Ok(());
            }
            s if s.starts_with("--platform=") => {
                platform = Some(s.strip_prefix("--platform=").unwrap().to_string());
            }
            s if s.starts_with("--track=") => {
                track = Some(s.strip_prefix("--track=").unwrap().to_string());
            }
            s if s.starts_with("--version=") => {
                version = Some(s.strip_prefix("--version=").unwrap().to_string());
            }
            s if s.starts_with("--key=") => {
                priv_key = Some(PathBuf::from(s.strip_prefix("--key=").unwrap()));
            }
            s if s.starts_with("--server=") => {
                server = Some(s.strip_prefix("--server=").unwrap().to_string());
            }
            s if s.starts_with("--rdv-key=") => {
                licence = Some(s.strip_prefix("--rdv-key=").unwrap().to_string());
            }
            s if s.starts_with("--download-url=") => {
                download_url = s.strip_prefix("--download-url=").unwrap().to_string();
            }
            _ => {
                if binary.is_none() {
                    binary = Some(PathBuf::from(a));
                } else {
                    bail!("unexpected positional argument: {a}");
                }
            }
        }
        i += 1;
    }

    let binary = binary.ok_or_else(|| anyhow::anyhow!("missing <binary>"))?;
    let platform = platform.ok_or_else(|| anyhow::anyhow!("--platform is required"))?;
    let track = track.ok_or_else(|| anyhow::anyhow!("--track is required"))?;
    let version = version.ok_or_else(|| anyhow::anyhow!("--version is required"))?;

    // Sign the binary content with the release-signing key. If --key is
    // omitted we still produce an advert with empty signatures (server is in
    // permissive mode while SIGNING_PUBLIC_KEY_PEM is empty), but we warn —
    // the operator should normally always sign.
    let (binary_signature, operator_signature) = if let Some(key) = priv_key.as_ref() {
        let priv_pem = std::fs::read_to_string(key)
            .with_context(|| format!("read private key: {}", key.display()))?;
        let bsig = mrsh_core::release_signing::sign_binary(&binary, &priv_pem)
            .with_context(|| format!("sign binary: {}", binary.display()))?;
        // Operator signature covers the canonical platform|track|version
        // payload — see VersionAdvert::operator_signing_payload.
        let payload = format!("{platform}|{track}|{version}");
        let opsig = sign_payload_bytes(payload.as_bytes(), &priv_pem)
            .context("sign operator payload")?;
        (bsig, opsig)
    } else {
        eprintln!(
            "WARNING: --key omitted; publishing UNSIGNED advert. \
             Server is currently permissive (SIGNING_PUBLIC_KEY_PEM is empty in this build), \
             but production rdv WILL reject unsigned publishes."
        );
        (Vec::new(), Vec::new())
    };

    let binary_blob = if send_blob {
        std::fs::read(&binary)
            .with_context(|| format!("read binary: {}", binary.display()))?
    } else {
        Vec::new()
    };

    let advert = VersionAdvert {
        platform: platform.clone(),
        track: track.clone(),
        latest_version: version.clone(),
        download_url,
        signature: binary_signature,
        published_at_unix: 0, // server stamps this
    };

    let client = build_client(server, licence)?;
    let server_str = client
        .servers
        .first()
        .cloned()
        .unwrap_or_else(|| "<unknown>".into());

    eprintln!(
        "publishing {}|{}|{} → {} ({} blob bytes, {} op_sig bytes)",
        platform,
        track,
        version,
        server_str,
        binary_blob.len(),
        operator_signature.len()
    );

    client
        .publish_version(advert, binary_blob, operator_signature)
        .await?;

    eprintln!("OK: rdv accepted advert");
    Ok(())
}

/// `mrsh rdv query --platform <p> --track <t> [--current-version <v>]
///   [--server <host:port>] [--rdv-key <licence>]`
pub async fn run_query(args: &[String]) -> Result<()> {
    let mut platform: Option<String> = None;
    let mut track: Option<String> = None;
    let mut current_version = String::new();
    let mut server: Option<String> = None;
    let mut licence: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--platform" => {
                i += 1;
                platform = args.get(i).cloned();
            }
            "--track" => {
                i += 1;
                track = args.get(i).cloned();
            }
            "--current-version" => {
                i += 1;
                current_version = args.get(i).cloned().unwrap_or_default();
            }
            "--server" => {
                i += 1;
                server = args.get(i).cloned();
            }
            "--rdv-key" => {
                i += 1;
                licence = args.get(i).cloned();
            }
            "--help" | "-h" => {
                eprintln!("Usage: mrsh rdv query --platform <p> --track <t> [--current-version <v>] [--server <host:port>]");
                return Ok(());
            }
            s if s.starts_with("--platform=") => {
                platform = Some(s.strip_prefix("--platform=").unwrap().to_string());
            }
            s if s.starts_with("--track=") => {
                track = Some(s.strip_prefix("--track=").unwrap().to_string());
            }
            s if s.starts_with("--current-version=") => {
                current_version = s.strip_prefix("--current-version=").unwrap().to_string();
            }
            s if s.starts_with("--server=") => {
                server = Some(s.strip_prefix("--server=").unwrap().to_string());
            }
            s if s.starts_with("--rdv-key=") => {
                licence = Some(s.strip_prefix("--rdv-key=").unwrap().to_string());
            }
            _ => bail!("unexpected argument: {a}"),
        }
        i += 1;
    }

    let platform = platform.ok_or_else(|| anyhow::anyhow!("--platform is required"))?;
    let track = track.ok_or_else(|| anyhow::anyhow!("--track is required"))?;

    let client = build_client(server, licence)?;
    match client
        .query_version(&platform, &track, &current_version)
        .await?
    {
        None => {
            println!(
                "no update available for {}|{} (current: {})",
                platform,
                track,
                if current_version.is_empty() {
                    "<unspecified>"
                } else {
                    &current_version
                }
            );
        }
        Some(advert) => {
            println!(
                "update available: {}|{} latest={} (published {} unix; {} sig bytes; download_url={})",
                advert.platform,
                advert.track,
                advert.latest_version,
                advert.published_at_unix,
                advert.signature.len(),
                if advert.download_url.is_empty() {
                    "<none>"
                } else {
                    &advert.download_url
                }
            );
        }
    }
    Ok(())
}

fn print_publish_usage() {
    eprintln!(
        "Usage: mrsh rdv publish <binary> \\\n  \
         --platform <windows-msvc|linux-glibc|linux-musl|macos> \\\n  \
         --track <stable|canary|dev> \\\n  \
         --version <semver, e.g. 1.10.30> \\\n  \
         [--key <release-private-key.pem>]    sign binary + operator payload\n  \
         [--server <host:port>]               override config rendezvous_server\n  \
         [--rdv-key <licence>]                rdv licence_key (currently advisory)\n  \
         [--download-url <url>]               where servers fetch the binary later\n  \
         [--no-blob]                          don't ship the binary inline"
    );
}

fn build_client(
    server_override: Option<String>,
    licence_override: Option<String>,
) -> Result<RdvClient> {
    let config = mrsh_core::config::Config::load();
    let server = server_override
        .or_else(|| config.rendezvous_server.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no rendezvous server configured \
                 (set rendezvous_server in config or pass --server <host:port>)"
            )
        })?;
    let licence = licence_override
        .or_else(|| config.rendezvous_key.clone())
        .unwrap_or_default();
    Ok(RdvClient {
        servers: vec![server],
        licence_key: licence,
        local_id: String::new(),
        group_hash: String::new(),
        hostname: String::new(),
        platform: String::new(),
        service_port: 0,
        encrypted_net_info: Vec::new(),
        // sys-8z5gn: operator-side publish/query client, no refresh loop.
        enrollment_token: String::new(),
        tray_port: 0,
        ports: Vec::new(),
        current_version: String::new(),
        last_update_status: String::new(),
        last_update_at_unix: 0,
        // rsh-5264.5: operator-side client (publish/query), no server track to report.
        track: String::new(),
        auto_upgrade: false,
    })
}

/// Sign an arbitrary byte payload (e.g. the canonical "<plat>|<track>|<ver>" string)
/// with the release-signing private key.
fn sign_payload_bytes(payload: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem.trim())
        .context("parse Ed25519 private key (expected PKCS#8 PEM)")?;
    let sig = signing_key.sign(payload);
    Ok(sig.to_bytes().to_vec())
}
