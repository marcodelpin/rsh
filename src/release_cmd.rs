//! `mrsh release` subcommand: sign / verify / pubkey for release binaries.
//!
//! Backed by `mrsh_core::release_signing` (Ed25519, separate keypair from rdv
//! enrollment). See `docs/release-signing.md` for operator workflow and
//! `crates/mrsh-core/src/release_signing.rs` for the cryptographic core.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Entry point dispatched from `dispatch::async_main` for the `release`
/// subcommand. `args` is the slice AFTER the leading `release` token.
pub fn run(args: &[String]) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "sign" => cmd_sign(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "pubkey" => cmd_pubkey(&args[1..]),
        "" | "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            bail!("unknown `mrsh release` subcommand: {other}");
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         mrsh release sign   <binary> --key <private-key.pem> [--out <binary>.sig]\n  \
         mrsh release verify <binary> <signature.sig>\n  \
         mrsh release pubkey\n\
         \n\
         Signs / verifies release binaries with the embedded Ed25519\n\
         release-signing key (separate from the rdv enrollment key).\n\
         See docs/release-signing.md."
    );
}

// ── sign ────────────────────────────────────────────────────────────────

fn cmd_sign(args: &[String]) -> Result<()> {
    let mut binary: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--key" => {
                i += 1;
                key = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            s if s.starts_with("--key=") => {
                key = Some(PathBuf::from(s.strip_prefix("--key=").unwrap()));
            }
            s if s.starts_with("--out=") => {
                out = Some(PathBuf::from(s.strip_prefix("--out=").unwrap()));
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
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

    let binary = binary.ok_or_else(|| {
        anyhow::anyhow!("missing <binary> (usage: mrsh release sign <binary> --key <priv.pem>)")
    })?;
    let key = key.ok_or_else(|| {
        anyhow::anyhow!(
            "missing --key <private-key.pem> (Ed25519 PKCS#8 PEM, see docs/release-signing.md)"
        )
    })?;
    let out = out.unwrap_or_else(|| default_sig_path(&binary));

    let priv_pem = std::fs::read_to_string(&key)
        .with_context(|| format!("read private key: {}", key.display()))?;
    let sig = mrsh_core::release_signing::sign_binary(&binary, &priv_pem)
        .with_context(|| format!("sign binary: {}", binary.display()))?;
    std::fs::write(&out, &sig)
        .with_context(|| format!("write signature: {}", out.display()))?;

    eprintln!("Signed {} → {} ({} bytes)", binary.display(), out.display(), sig.len());
    Ok(())
}

fn default_sig_path(binary: &Path) -> PathBuf {
    let mut s = binary.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

// ── verify ──────────────────────────────────────────────────────────────

fn cmd_verify(args: &[String]) -> Result<()> {
    let mut positional: Vec<&String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            _ => positional.push(a),
        }
    }
    if positional.len() != 2 {
        bail!("usage: mrsh release verify <binary> <signature.sig>");
    }
    let binary = PathBuf::from(positional[0]);
    let sig_path = PathBuf::from(positional[1]);

    let sig = std::fs::read(&sig_path)
        .with_context(|| format!("read signature: {}", sig_path.display()))?;
    let ok = mrsh_core::release_signing::verify_binary(&binary, &sig)
        .with_context(|| format!("verify {}", binary.display()))?;

    if ok {
        eprintln!("OK: {} verified against {}", binary.display(), sig_path.display());
        Ok(())
    } else {
        eprintln!(
            "FAIL: signature {} does NOT verify against {}",
            sig_path.display(),
            binary.display()
        );
        std::process::exit(1);
    }
}

// ── pubkey ──────────────────────────────────────────────────────────────

fn cmd_pubkey(_args: &[String]) -> Result<()> {
    let pem = mrsh_core::release_signing::embedded_public_key_pem();
    if pem.trim().is_empty() {
        bail!(
            "no embedded SIGNING_PUBLIC_KEY_PEM in this build — see docs/release-signing.md \
             for the operator-side procedure"
        );
    }
    print!("{pem}");
    if !pem.ends_with('\n') {
        println!();
    }
    Ok(())
}
