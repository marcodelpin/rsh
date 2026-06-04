//! Build-time injection of the release-signing public key (rsh-o3xl).
//!
//! `release_signing::SIGNING_PUBLIC_KEY_PEM` is populated at compile time from
//! one of (in priority order):
//!   1. `MRSH_RELEASE_PUBKEY` env var — raw PEM contents (CI/release builds)
//!   2. `MRSH_RELEASE_PUBKEY_FILE` env var — path to `.pem` file
//!   3. Canonical workstation operator key (auto-detected on developer workstations):
//!      `/path/to/release-pubkey.pub.pem`
//!   4. Committed `release-pubkey.pub.pem` next to this crate (rsh-c1fm) — public
//!      key checked into the repo so ANY build host (Linux CI / build-host that
//!      lacks the workstation `S:/` path) still embeds it. The key is public, so
//!      committing it is safe.
//!   5. Empty string — fallback when none of the above apply (truly keyless build)
//!
//! Output: `$OUT_DIR/release_pubkey.pem` consumed via `include_str!` in
//! `release_signing.rs`.
//!
//! Rerun triggered by changes to either env var or the canonical key file.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=MRSH_RELEASE_PUBKEY");
    println!("cargo:rerun-if-env-changed=MRSH_RELEASE_PUBKEY_FILE");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let dest = PathBuf::from(&out_dir).join("release_pubkey.pem");

    let pubkey = if let Ok(raw) = env::var("MRSH_RELEASE_PUBKEY") {
        let raw = raw.trim();
        if raw.is_empty() {
            println!("cargo:warning=MRSH_RELEASE_PUBKEY is set but empty — embedding empty key");
            String::new()
        } else if !raw.contains("BEGIN PUBLIC KEY") {
            println!(
                "cargo:warning=MRSH_RELEASE_PUBKEY does not contain a PEM envelope — \
                 expected '-----BEGIN PUBLIC KEY-----' header. Embedding raw value as-is."
            );
            raw.to_string()
        } else {
            raw.to_string()
        }
    } else if let Ok(path) = env::var("MRSH_RELEASE_PUBKEY_FILE") {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                println!("cargo:rerun-if-changed={}", path);
                contents
            }
            Err(e) => {
                println!(
                    "cargo:warning=MRSH_RELEASE_PUBKEY_FILE={} unreadable ({}) — embedding empty",
                    path, e
                );
                String::new()
            }
        }
    } else {
        // Fallback 3: auto-detect canonical workstation operator key path.
        // Allows developer builds on the operator workstation to embed the
        // release key automatically without setting any env var.
        let canonical = std::path::Path::new(
            "/path/to/release-pubkey.pub.pem",
        );
        if canonical.exists() {
            println!(
                "cargo:rerun-if-changed={}",
                canonical.display()
            );
            println!(
                "cargo:warning=MRSH_RELEASE_PUBKEY_FILE not set — \
                 auto-detected canonical operator key at {}",
                canonical.display()
            );
            fs::read_to_string(canonical).unwrap_or_else(|e| {
                println!(
                    "cargo:warning=canonical key at {} unreadable ({}) — embedding empty",
                    canonical.display(),
                    e
                );
                String::new()
            })
        } else {
            // Fallback 4 (rsh-c1fm): public key committed next to this crate.
            // Works on ANY build host (Linux build-host / CI) that lacks the
            // workstation S:/ path. Public key → safe to commit to the (private) repo.
            let committed = std::path::Path::new(
                &env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
            )
            .join("release-pubkey.pub.pem");
            if committed.exists() {
                println!("cargo:rerun-if-changed={}", committed.display());
                println!(
                    "cargo:warning=embedding committed release pubkey at {}",
                    committed.display()
                );
                fs::read_to_string(&committed).unwrap_or_else(|e| {
                    println!(
                        "cargo:warning=committed key at {} unreadable ({}) — embedding empty",
                        committed.display(),
                        e
                    );
                    String::new()
                })
            } else {
                // Fallback 5: no key available (truly keyless build).
                // `mrsh release pubkey` will error loudly at runtime.
                String::new()
            }
        }
    };

    fs::write(&dest, pubkey).expect("write release_pubkey.pem to OUT_DIR");
}
