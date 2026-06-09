//! Release binary signing using a dedicated Ed25519 keypair.
//!
//! This is intentionally separate from the rdv enrollment key (used by peers
//! to authenticate to the rendezvous server). The release-signing key is
//! intended to live in a hardware-protected location (or at minimum the
//! operator's encrypted dotfiles store) and is touched only at release time.
//!
//! Phase 3 prerequisite for rdv-driven auto-upgrade (rsh-5264.3 VersionAdvert
//! protocol): once a binary advertised by rdv carries an Ed25519 signature
//! over its content, peers can fetch + verify the upgrade payload offline
//! using only the embedded `SIGNING_PUBLIC_KEY_PEM` constant below.
//!
//! # Workflow
//!
//! 1. Operator generates the keypair ONCE, out of band (see
//!    `docs/release-signing.md`).
//! 2. Operator pastes the resulting public-key PEM into
//!    `SIGNING_PUBLIC_KEY_PEM`.
//! 3. At release time: `mrsh release sign <binary> --key <priv.pem> --out <binary>.sig`.
//! 4. Peers verify with `mrsh release verify <binary> <binary>.sig` (which
//!    uses the embedded `SIGNING_PUBLIC_KEY_PEM`).
//!
//! # Constants
//!
//! `SIGNING_PUBLIC_KEY_PEM` is empty in the source tree — it MUST be replaced
//! by the operator before any production release. `verify_binary` returns an
//! explicit error if the constant is empty so a misconfigured build cannot
//! silently accept anything.

use std::path::Path;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};

/// Ed25519 release-signing public key in PEM (SPKI) form.
///
/// rsh-o3xl: populated at compile time by `build.rs` from one of:
///   1. `MRSH_RELEASE_PUBKEY` env var — raw PEM contents (CI/release builds)
///   2. `MRSH_RELEASE_PUBKEY_FILE` env var — path to `.pem` file
///      canonical: `/path/to/release-pubkey.pub.pem`
///   3. Empty string — local/dev builds (verify path requires
///      `--insecure-no-verify` until populated; see selfupdate.rs runtime gate)
///
/// The matching private key is generated once with openssl (below) and kept
/// offline by the operator; it is never committed to this repository.
/// Public key raw hex: 26a9ba143f71cd1056c0535e3935a4e1ef2fe7b8ca183f92555ccf10cb3c2c6e
///
/// Generation (operator, out of band — already done; key in secret repo):
/// ```text
/// openssl genpkey -algorithm Ed25519 -out release-private.pem
/// openssl pkey -in release-private.pem -pubout -out release-public.pem
/// ```
///
/// See `docs/release-signing.md` and `docs/adr/0007-self-update-from-rdv.md`.
pub const SIGNING_PUBLIC_KEY_PEM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/release_pubkey.pem"));

/// Maximum binary size accepted by sign/verify (defensive bound — a release
/// binary in this workspace is well under 100 MB; the cap prevents accidental
/// signing of, e.g., a directory tarball mistaken for a binary).
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// Sign `binary_path` using the Ed25519 private key in `private_key_pem`.
///
/// `private_key_pem` is a PKCS#8 PEM string (the format produced by
/// `openssl genpkey -algorithm Ed25519`). Returns the raw 64-byte Ed25519
/// signature.
pub fn sign_binary(binary_path: &Path, private_key_pem: &str) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem.trim())
        .context("parse Ed25519 private key (expected PKCS#8 PEM)")?;
    let bytes = read_binary(binary_path)?;
    let sig: Signature = signing_key.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

/// Verify `signature` against `binary_path` using the embedded
/// `SIGNING_PUBLIC_KEY_PEM` constant.
///
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on a cryptographic
/// mismatch, and `Err` for structural problems (missing public key,
/// truncated signature, unreadable binary).
pub fn verify_binary(binary_path: &Path, signature: &[u8]) -> Result<bool> {
    if SIGNING_PUBLIC_KEY_PEM.trim().is_empty() {
        bail!(
            "SIGNING_PUBLIC_KEY_PEM is empty — this build was not configured \
             with a release-signing public key. See docs/release-signing.md."
        );
    }
    let verifying_key = parse_public_key_pem(SIGNING_PUBLIC_KEY_PEM)
        .context("parse embedded SIGNING_PUBLIC_KEY_PEM")?;
    verify_with_key(binary_path, signature, &verifying_key)
}

/// Same as [`verify_binary`] but with a caller-supplied public key (used by
/// tests and by tooling that wants to verify with a non-embedded key).
pub fn verify_binary_with_key_pem(
    binary_path: &Path,
    signature: &[u8],
    public_key_pem: &str,
) -> Result<bool> {
    let verifying_key =
        parse_public_key_pem(public_key_pem).context("parse provided public key PEM")?;
    verify_with_key(binary_path, signature, &verifying_key)
}

/// Return the embedded public key PEM (for `mrsh release pubkey`).
pub fn embedded_public_key_pem() -> &'static str {
    SIGNING_PUBLIC_KEY_PEM
}

// ── internals ────────────────────────────────────────────────────────────

fn parse_public_key_pem(pem: &str) -> Result<VerifyingKey> {
    // ed25519-dalek's VerifyingKey implements DecodePublicKey via the spki
    // crate; that path expects the standard SPKI PEM label `PUBLIC KEY`.
    VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|e| anyhow::anyhow!("invalid Ed25519 SPKI PEM: {e}"))
}

fn verify_with_key(
    binary_path: &Path,
    signature: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<bool> {
    if signature.len() != Signature::BYTE_SIZE {
        bail!(
            "signature length is {} bytes, expected {} (Ed25519)",
            signature.len(),
            Signature::BYTE_SIZE
        );
    }
    let sig_array: [u8; Signature::BYTE_SIZE] = signature
        .try_into()
        .expect("length checked above");
    let sig = Signature::from_bytes(&sig_array);
    let bytes = read_binary(binary_path)?;
    Ok(verifying_key.verify(&bytes, &sig).is_ok())
}

fn read_binary(binary_path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(binary_path)
        .with_context(|| format!("stat binary: {}", binary_path.display()))?;
    if meta.len() > MAX_BINARY_BYTES {
        bail!(
            "binary {} is {} bytes, exceeds release-signing cap of {} bytes",
            binary_path.display(),
            meta.len(),
            MAX_BINARY_BYTES
        );
    }
    std::fs::read(binary_path)
        .with_context(|| format!("read binary: {}", binary_path.display()))
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};

    /// Deterministic helper: build a fresh keypair and return PEMs.
    fn fresh_keypair_pems() -> (String, String) {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let priv_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private pkcs8 pem")
            .to_string();
        let pub_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public spki pem");
        (priv_pem, pub_pem)
    }

    fn write_tmp_binary(content: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().expect("tmp");
        std::fs::write(f.path(), content).expect("write tmp binary");
        f
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (priv_pem, pub_pem) = fresh_keypair_pems();
        let binary = write_tmp_binary(b"hello mrsh release payload");
        let sig = sign_binary(binary.path(), &priv_pem).expect("sign");
        assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");
        let ok = verify_binary_with_key_pem(binary.path(), &sig, &pub_pem)
            .expect("verify ok path");
        assert!(ok, "round-trip signature must verify");
    }

    #[test]
    fn verify_rejects_tampered_binary() {
        let (priv_pem, pub_pem) = fresh_keypair_pems();
        let binary = write_tmp_binary(b"original content");
        let sig = sign_binary(binary.path(), &priv_pem).expect("sign");
        // Tamper after signing.
        std::fs::write(binary.path(), b"tampered content").expect("rewrite");
        let ok = verify_binary_with_key_pem(binary.path(), &sig, &pub_pem)
            .expect("verify call ok");
        assert!(!ok, "verify must return false for tampered binary");
    }

    #[test]
    fn verify_rejects_wrong_signature() {
        // Sign with key A, verify with public key B.
        let (priv_a, _pub_a) = fresh_keypair_pems();
        let (_priv_b, pub_b) = fresh_keypair_pems();
        let binary = write_tmp_binary(b"payload");
        let sig = sign_binary(binary.path(), &priv_a).expect("sign with A");
        let ok = verify_binary_with_key_pem(binary.path(), &sig, &pub_b)
            .expect("verify call ok");
        assert!(!ok, "verify must reject signature from wrong key");
    }

    #[test]
    fn sign_rejects_missing_binary() {
        let (priv_pem, _pub_pem) = fresh_keypair_pems();
        let missing = std::path::Path::new("does-not-exist-mrsh-release-test.bin");
        let err = sign_binary(missing, &priv_pem)
            .expect_err("signing a missing file must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("stat binary") || msg.contains("does-not-exist"),
            "error should reference the missing path: {msg}"
        );
    }

    #[test]
    fn sign_rejects_invalid_private_key() {
        let binary = write_tmp_binary(b"payload");
        let err = sign_binary(binary.path(), "not a valid PEM")
            .expect_err("invalid private key PEM must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.to_lowercase().contains("private key"),
            "error should reference private key parsing: {msg}"
        );
    }

    #[test]
    fn verify_rejects_truncated_signature() {
        let (priv_pem, pub_pem) = fresh_keypair_pems();
        let binary = write_tmp_binary(b"payload");
        let sig = sign_binary(binary.path(), &priv_pem).expect("sign");
        let truncated = &sig[..32];
        let err = verify_binary_with_key_pem(binary.path(), truncated, &pub_pem)
            .expect_err("truncated signature must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("signature length"),
            "error should mention signature length: {msg}"
        );
    }

    #[test]
    fn verify_with_empty_embedded_constant_fails_loudly() {
        // SIGNING_PUBLIC_KEY_PEM is empty in source — verify_binary (which
        // uses the constant) must refuse to run rather than silently
        // accepting anything. On release/CI builds the pubkey IS embedded
        // (build.rs fallback), so this empty-key premise doesn't hold — skip.
        if !SIGNING_PUBLIC_KEY_PEM.trim().is_empty() {
            return;
        }
        let binary = write_tmp_binary(b"payload");
        let dummy_sig = vec![0u8; 64];
        let err = verify_binary(binary.path(), &dummy_sig)
            .expect_err("empty embedded key must produce an explicit error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SIGNING_PUBLIC_KEY_PEM is empty"),
            "error must explain misconfiguration: {msg}"
        );
    }
}
