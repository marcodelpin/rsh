# Release Binary Signing (Ed25519)

mrsh release binaries can be signed with a dedicated Ed25519 keypair. This is
**separate** from the rdv enrollment key used by peers to authenticate to the
rendezvous server. Mixing the two would conflate two different security
boundaries: enrollment-key compromise lets an attacker impersonate one peer,
while release-key compromise lets an attacker push a malicious binary to the
entire fleet.

This document is the operator-side procedure. The cryptographic core lives in
`crates/mrsh-core/src/release_signing.rs` and the CLI in
`src/release_cmd.rs`.

## Why a separate key

| Key | Purpose | Storage | Touched |
| --- | --- | --- | --- |
| rdv enrollment-key | per-peer auth to rendezvous | `~/.mrsh/` on each peer | every connection |
| release-signing-key | sign release artifacts (mrsh.exe, mrsh) | hardware-protected, single operator host | only at release time |

Compromising the enrollment-key on one peer must NOT let an attacker forge a
signed upgrade. Hence the keys must be different and the release-signing key
must live on as few hosts as possible.

## Generating the keypair (ONCE, out of band)

Do this on a trusted operator machine, OUTSIDE this repository, with no
secrets-tracking tools watching the working directory.

```bash
# Private key (PKCS#8 PEM). Keep this OFF the repo.
openssl genpkey -algorithm Ed25519 -out release-private.pem

# Derive public key (SubjectPublicKeyInfo PEM).
openssl pkey -in release-private.pem -pubout -out release-public.pem

# Sanity check.
openssl pkey -in release-private.pem -text -noout | head -3
```

## Storing the private key

Pick the most-protected slot you have:

1. **Best**: hardware token (YubiKey, smartcard) holding an Ed25519 key, with
   PKCS#11 export of the matching public key for embedding.
2. **Acceptable**: encrypted dotfiles (`/path/to/release-private.pem`),
   accessed only on the release host.
3. **Floor**: encrypted password manager attachment.

In all cases:

- NEVER commit the private key to ANY repo.
- NEVER paste it into chat, KB, or session logs.
- NEVER copy it to fleet machines — only the release host needs it.

The path passed to `mrsh release sign --key <path>` is read at release time;
set it via env var (`RELEASE_KEY_PATH`) so the literal path is not in command
history.

## Embedding the public key

Open `crates/mrsh-core/src/release_signing.rs` and replace:

```rust
pub const SIGNING_PUBLIC_KEY_PEM: &str = "";
```

with the contents of `release-public.pem` (preserving the
`-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----` envelope), e.g.:

```rust
pub const SIGNING_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA<base64-of-32-byte-verifying-key>
-----END PUBLIC KEY-----
";
```

Commit that change — the public key in source IS the trust anchor for every
peer running this build. The `verify_binary` function refuses to run when
the constant is empty, so a misconfigured build cannot silently accept any
signature.

## CLI usage

```bash
# Sign (release host, requires the private key file)
mrsh release sign deploy/mrsh.exe --key "$RELEASE_KEY_PATH" --out deploy/mrsh.exe.sig

# Verify (any host, uses embedded public key)
mrsh release verify deploy/mrsh.exe deploy/mrsh.exe.sig

# Print the embedded public key (for operator audit)
mrsh release pubkey
```

`mrsh release verify` exits 0 on a valid signature and 1 on mismatch.

## bbd integration (documented, not enforced this PR)

The `/bbd` workflow (Bump-Build-Deploy) should add a signing step BEFORE the
`mrsh push` to fleet machines. Sketch:

```bash
# After cargo build --release
mrsh release sign deploy/mrsh.exe --key "$RELEASE_KEY_PATH" --out deploy/mrsh.exe.sig
# Push both files
mrsh -h <host> push deploy/mrsh.exe     C:/ProgramData/mrsh/mrsh-new.exe
mrsh -h <host> push deploy/mrsh.exe.sig C:/ProgramData/mrsh/mrsh-new.exe.sig
# (Phase 4) peer self-update verifies the .sig before swapping the binary in.
```

Phase 3 (`rsh-5264.3` VersionAdvert protocol) is the next step: rdv broadcasts
the latest signed binary's URL + signature, peers fetch + verify offline using
only the embedded public key, and only then trigger the rename-swap deploy
pattern (see `safe-remote-update.md`).

## Threat model recap

- A peer with a stolen enrollment-key can impersonate that one peer to rdv.
- An attacker with the release-signing-private-key can forge an upgrade for
  the entire fleet.
- An attacker with neither cannot forge an upgrade because every peer
  verifies signatures using the embedded public key before swapping the
  binary.

Keep the private key off-net, ideally on hardware. Treat it like a CA key.
