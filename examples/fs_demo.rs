//! Cross-machine fs-transport demo / perf harness.
//!
//! Exercises `FsStream` + TLS over a shared spool directory (e.g. Resilio/SMB).
//!
//! Two modes:
//!
//! ```bash
//! # on target machine (listener, loops until killed)
//! mrsh-fs-demo --dir /path/to/shared/spool --role server
//!
//! # on this machine (client, one session then exit)
//! mrsh-fs-demo --dir /path/to/shared/spool --role client --size-kb 64
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mrsh_core::fs_transport::{FsStream, Role, ensure_session_dirs, generate_session_id};
use mrsh_core::tls as core_tls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(clap::Parser, Debug)]
struct Args {
    /// Shared spool directory (must be accessible from both peers).
    #[arg(long)]
    dir: PathBuf,

    /// Role: "server" or "client".
    #[arg(long)]
    role: String,

    /// Payload string (default: "ping"). Overridden when --size-kb is set.
    #[arg(long, default_value = "ping")]
    payload: String,

    /// Generate a payload of this many KiB (random bytes). Overrides --payload.
    #[arg(long, default_value_t = 0)]
    size_kb: usize,

    /// Maximum wait for a session or a message (seconds).
    #[arg(long, default_value_t = 1200)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = <Args as clap::Parser>::parse();
    tokio::fs::create_dir_all(&args.dir).await.context("ensure dir")?;

    let cert_dir = args.dir.join(".tls");
    tokio::fs::create_dir_all(&cert_dir).await.context("ensure tls dir")?;
    let (certs, key) = core_tls::load_or_generate_cert(&cert_dir).context("cert")?;

    match args.role.as_str() {
        "server" => run_server(&args, certs, key).await,
        "client" => run_client(&args).await,
        other => bail!("unknown role {}", other),
    }
}

async fn run_server(
    args: &Args,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<()> {
    println!("fs-demo server: watching {}", args.dir.display());
    let server_cfg = core_tls::server_config(certs, key)?;
    let acceptor = TlsAcceptor::from(server_cfg);

    loop {
        let session = match wait_for_session(&args.dir, args.timeout).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("fs-demo server: session wait error: {:#}", e);
                continue;
            }
        };
        println!("fs-demo server: picked up session {}", session);
        let _ = tokio::fs::write(
            args.dir.join(&session).join("claimed.server"),
            b"claimed",
        )
        .await;

        let acceptor = acceptor.clone();
        let dir = args.dir.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_one_session(&dir, &session, &acceptor).await {
                eprintln!("fs-demo server: session {} error: {:#}", session, e);
            }
        });
    }
}

async fn wait_for_session(dir: &Path, timeout_s: u64) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    loop {
        if Instant::now() > deadline {
            bail!("no session appeared within {}s", timeout_s);
        }
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(e) = entries.next_entry().await? {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let ready = p.join("ready.server");
            let claimed = p.join("claimed.server");
            if tokio::fs::try_exists(&ready).await.unwrap_or(false)
                && !tokio::fs::try_exists(&claimed).await.unwrap_or(false)
                && let Some(name) = p.file_name().and_then(|n| n.to_str())
            {
                return Ok(name.to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn handle_one_session(dir: &Path, session: &str, acceptor: &TlsAcceptor) -> Result<()> {
    let fs = FsStream::open(dir, session, Role::Server).context("open FsStream(server)")?;
    let mut tls = acceptor.accept(fs).await.context("TLS accept")?;
    println!("fs-demo server: TLS handshake OK ({})", session);

    let mut lenbuf = [0u8; 8];
    tls.read_exact(&mut lenbuf).await.context("read length")?;
    let len = u64::from_be_bytes(lenbuf) as usize;
    let mut data = vec![0u8; len];
    tls.read_exact(&mut data).await.context("read payload")?;
    let hash = hash_short(&data);
    println!(
        "fs-demo server: received {} bytes (b3/16: {})",
        len, hash
    );

    let reply_body = hash.as_bytes();
    let reply_len = (reply_body.len() as u64).to_be_bytes();
    tls.write_all(&reply_len).await.context("write reply length")?;
    tls.write_all(reply_body).await.context("write reply body")?;
    tls.flush().await.ok();
    tls.shutdown().await.ok();
    println!("fs-demo server: replied with b3/16 {}", hash);
    Ok(())
}

async fn run_client(args: &Args) -> Result<()> {
    println!("fs-demo client: using {}", args.dir.display());

    let payload: Vec<u8> = if args.size_kb > 0 {
        use rand::RngCore;
        use rand::rngs::OsRng;
        let mut buf = vec![0u8; args.size_kb * 1024];
        OsRng.fill_bytes(&mut buf);
        buf
    } else {
        args.payload.as_bytes().to_vec()
    };
    let payload_hash = hash_short(&payload);
    let payload_len = payload.len();

    let t_start = Instant::now();

    let session = generate_session_id();
    let session_dir = ensure_session_dirs(&args.dir, &session).context("ensure session dirs")?;
    let fs = FsStream::open(&args.dir, &session, Role::Client).context("open FsStream(client)")?;

    let ready_tmp = session_dir.join("ready.server.tmp");
    let ready_final = session_dir.join("ready.server");
    tokio::fs::write(&ready_tmp, b"ready").await.context("write ready tmp")?;
    tokio::fs::rename(&ready_tmp, &ready_final)
        .await
        .context("publish ready marker")?;
    println!("fs-demo client: published session {}", session);

    let client_cfg = core_tls::client_config();
    let connector = TlsConnector::from(client_cfg);
    let name = ServerName::try_from("fs-demo").unwrap();
    let mut tls = tokio::time::timeout(
        Duration::from_secs(args.timeout),
        connector.connect(name, fs),
    )
    .await
    .context("TLS handshake timeout")?
    .context("TLS handshake failed")?;
    let t_handshake = t_start.elapsed();
    println!(
        "fs-demo client: TLS handshake OK ({:.2}s)",
        t_handshake.as_secs_f64()
    );

    let t_send = Instant::now();
    let len_hdr = (payload_len as u64).to_be_bytes();
    tls.write_all(&len_hdr).await.context("write len")?;
    tls.write_all(&payload).await.context("write payload")?;
    tls.flush().await.ok();
    let t_sent = t_send.elapsed();
    println!(
        "fs-demo client: sent {} bytes in {:.2}s ({:.2} KiB/s, b3/16: {})",
        payload_len,
        t_sent.as_secs_f64(),
        (payload_len as f64) / 1024.0 / t_sent.as_secs_f64().max(0.001),
        payload_hash
    );

    let t_recv = Instant::now();
    let mut lenbuf = [0u8; 8];
    tokio::time::timeout(
        Duration::from_secs(args.timeout),
        tls.read_exact(&mut lenbuf),
    )
    .await
    .context("read reply length timeout")?
    .context("read reply length")?;
    let rlen = u64::from_be_bytes(lenbuf) as usize;
    let mut reply = vec![0u8; rlen];
    tls.read_exact(&mut reply).await.context("read reply body")?;
    let t_received = t_recv.elapsed();

    let reply_str = String::from_utf8_lossy(&reply);
    let ok = reply_str == payload_hash;
    println!(
        "fs-demo client: received {} bytes in {:.2}s (reply b3/16: {})",
        rlen,
        t_received.as_secs_f64(),
        reply_str
    );

    let total = t_start.elapsed();
    println!(
        "fs-demo client: total {:.2}s (handshake {:.2}s + send {:.2}s + recv {:.2}s), match={}",
        total.as_secs_f64(),
        t_handshake.as_secs_f64(),
        t_sent.as_secs_f64(),
        t_received.as_secs_f64(),
        ok
    );

    if !ok {
        bail!("hash mismatch: expected {}, got {}", payload_hash, reply_str);
    }
    println!("fs-demo client: OK");
    Ok(())
}

fn hash_short(data: &[u8]) -> String {
    let h = blake3::hash(data);
    // 8 bytes = 16 hex chars.
    h.as_bytes()
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}
