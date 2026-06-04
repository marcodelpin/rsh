//! Key generation, TOTP setup/verification, and key management.

use anyhow::{Context, Result, bail};

/// Generate ed25519 keypair in OpenSSH format.
pub fn run_keygen(output: Option<&std::path::Path>) -> Result<()> {
    use mrsh_core::auth;

    let default_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".mrsh");
    let default_key = default_dir.join("id_ed25519");
    let key_path = output.unwrap_or(&default_key);

    if key_path.exists() {
        bail!(
            "key file already exists: {}\nUse a different path or remove the existing key first.",
            key_path.display()
        );
    }

    // Generate using the same logic as server key generation
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let ed_kp = ssh_key::private::Ed25519Keypair {
        public: ssh_key::public::Ed25519PublicKey(signing_key.verifying_key().to_bytes()),
        private: ssh_key::private::Ed25519PrivateKey::from_bytes(&signing_key.to_bytes()),
    };
    let comment = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "mrsh".to_string());
    let private_key =
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(ed_kp), &comment)
            .context("create ed25519 private key")?;

    let openssh_str = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("serialize key to OpenSSH format")?
        .to_string();

    // Ensure parent directory exists
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create directory: {}", parent.display()))?;
    }

    // Write private key
    std::fs::write(key_path, &openssh_str)
        .with_context(|| format!("write key: {}", key_path.display()))?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Write public key (.pub) — SSH wire format: [4-byte len]["ssh-ed25519"][4-byte len][32-byte key]
    let pub_key_path = std::path::PathBuf::from(format!("{}.pub", key_path.display()));
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let key_type_bytes = b"ssh-ed25519";
    let mut wire = Vec::new();
    wire.extend_from_slice(&(key_type_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type_bytes);
    wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&pub_bytes);
    let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wire);
    let pub_key_str = format!("ssh-ed25519 {} {}\n", pub_b64, comment);

    std::fs::write(&pub_key_path, &pub_key_str)
        .with_context(|| format!("write public key: {}", pub_key_path.display()))?;

    let fingerprint = auth::key_fingerprint(&pub_bytes);
    eprintln!("Generated ed25519 key pair:");
    eprintln!("  Private: {}", key_path.display());
    eprintln!("  Public:  {}", pub_key_path.display());
    eprintln!("  Fingerprint: {}", fingerprint);
    eprintln!();
    eprintln!("Add to server's authorized_keys:");
    eprintln!("  {}", pub_key_str.trim());

    Ok(())
}

/// Generate TOTP secret for a key fingerprint.
///
/// Creates a random base32 secret and outputs:
/// - The secret (for adding to server's totp_secrets file)
/// - An otpauth:// URI (for QR code / authenticator app import)
/// - Recovery codes (for adding to server's totp_recovery file)
pub fn run_totp_setup(fingerprint: Option<&str>) -> Result<()> {
    use mrsh_core::auth;
    use sha2::{Digest, Sha256};

    let fp = if let Some(fp) = fingerprint {
        fp.to_string()
    } else {
        // Try to read the default key and compute its fingerprint
        let key_pair = auth::discover_key().context(
            "no fingerprint provided and no default key found.\n\
             Usage: mrsh totp-setup [fingerprint]\n\
             Or ensure ~/.ssh/id_ed25519 exists.",
        )?;
        let raw_pub = key_pair.public_key_bytes();
        auth::key_fingerprint(&raw_pub)
    };

    let secret = auth::generate_totp_secret();

    // Generate recovery codes (10 random 8-char hex codes)
    let mut recovery_codes = Vec::new();
    let mut recovery_hashes = Vec::new();
    for _ in 0..10 {
        let mut buf = [0u8; 4];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut buf);
        let code = buf.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let digest = Sha256::digest(code.as_bytes());
        let hash = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        recovery_codes.push(code);
        recovery_hashes.push(hash);
    }

    let uri = format!(
        "otpauth://totp/rsh:{}?secret={}&issuer=rsh&algorithm=SHA1&digits=6&period=30",
        fp, secret
    );

    eprintln!("TOTP setup for key: {}", fp);
    eprintln!();
    eprintln!("Secret (base32): {}", secret);
    eprintln!();
    eprintln!("otpauth URI (for authenticator app):");
    eprintln!("  {}", uri);
    eprintln!();
    eprintln!("Add to server's totp_secrets file:");
    eprintln!("  {} {}", fp, secret);
    eprintln!();
    eprintln!("Recovery codes (save these! each can be used once):");
    for code in &recovery_codes {
        eprintln!("  {}", code);
    }
    eprintln!();
    eprintln!("Add to server's totp_recovery file:");
    eprintln!("  {} {}", fp, recovery_hashes.join(" "));
    eprintln!();
    eprintln!("Add 'totp' option to the key in authorized_keys:");
    eprintln!("  totp ssh-ed25519 AAAA... comment");

    Ok(())
}

/// Verify a TOTP code against a secret (for testing setup).
pub fn run_totp_verify(secret_or_fingerprint: &str, code: &str) -> Result<()> {
    use mrsh_core::auth;

    // If it looks like a base32 secret (all uppercase + digits, length 32+), use directly.
    // Otherwise treat as fingerprint and look up in totp_secrets file.
    let secret = if secret_or_fingerprint.len() >= 16
        && secret_or_fingerprint
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '=')
    {
        secret_or_fingerprint.to_string()
    } else {
        // Look up fingerprint in server data dir
        let data_dir = crate::server_data_dir();
        let totp_path = data_dir.join("totp_secrets");
        if !totp_path.exists() {
            bail!(
                "totp_secrets file not found at {}\nProvide a base32 secret directly, or create the file.",
                totp_path.display()
            );
        }
        let secrets = auth::load_totp_secrets(&totp_path)?;
        let found = auth::find_totp_secret(secret_or_fingerprint, &secrets);
        match found {
            Some(s) => s.secret_base32.clone(),
            None => bail!(
                "no TOTP secret found for fingerprint: {}",
                secret_or_fingerprint
            ),
        }
    };

    match auth::verify_totp(&secret, code)? {
        true => {
            eprintln!("TOTP code is valid.");
            Ok(())
        }
        false => {
            bail!("TOTP code is invalid.");
        }
    }
}

/// Handle `mrsh keys <action>` subcommand.
pub fn run_keys(args: &[String]) -> Result<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("list");

    match action {
        "list" => keys_list(),
        "show" => keys_show(),
        "add" => {
            if args.len() < 2 {
                bail!("Usage: mrsh keys add <pubkey-string-or-file>\n\
                       Example: mrsh keys add ~/.ssh/id_ed25519.pub\n\
                       Example: mrsh keys add 'ssh-ed25519 AAAA... comment'");
            }
            keys_add(&args[1..].join(" "))
        }
        "remove" | "rm" => {
            if args.len() < 2 {
                bail!("Usage: mrsh keys remove <fingerprint-or-comment>\n\
                       Example: mrsh keys remove SHA256:abc...\n\
                       Example: mrsh keys remove mykey");
            }
            keys_remove(&args[1])
        }
        other => bail!("Unknown keys action: {other}\nUsage: mrsh keys [list|show|add|remove]"),
    }
}

/// List all authorized keys with fingerprint, type, and comment.
/// Searches ALL possible authorized_keys locations.
fn keys_list() -> Result<()> {
    use mrsh_core::auth;
    use std::collections::HashSet;

    let ak_paths = crate::all_authorized_keys_paths();
    let mut total_keys = 0;
    let mut seen_key_data: HashSet<Vec<u8>> = HashSet::new();
    let mut found_any_file = false;

    println!("{:<12} {:<50} COMMENT", "TYPE", "FINGERPRINT");
    println!("{}", "-".repeat(80));

    for ak_path in &ak_paths {
        if !ak_path.exists() {
            continue;
        }
        found_any_file = true;

        let keys = match auth::load_authorized_keys(ak_path, false) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("  (error reading {}: {})", ak_path.display(), e);
                continue;
            }
        };

        let mut path_count = 0;
        for key in &keys {
            if !seen_key_data.insert(key.key_data.clone()) {
                continue; // deduplicate across files
            }
            let fp = auth::key_fingerprint(&key.key_data);
            let comment = key.comment.as_deref().unwrap_or("");
            let perms = format_permissions(&key.permissions);
            println!("{:<12} {:<50} {}", key.key_type, fp, comment);
            if !perms.is_empty() {
                println!("             options: {}", perms);
            }
            path_count += 1;
        }

        if path_count > 0 {
            println!("  ({} from {})", path_count, ak_path.display());
            total_keys += path_count;
        }
    }

    if !found_any_file {
        eprintln!("No authorized_keys file found in any location:");
        for p in &ak_paths {
            eprintln!("  - {}", p.display());
        }
        eprintln!("Generate a key with: mrsh keygen");
        return Ok(());
    }

    if total_keys == 0 {
        eprintln!("All authorized_keys files are empty.");
    } else {
        println!("\n{} unique key(s) total", total_keys);
    }

    Ok(())
}

/// Show the local client's public key and fingerprint.
fn keys_show() -> Result<()> {
    use mrsh_core::auth;

    let key_pair = auth::discover_key().context(
        "no SSH key found.\n\
         Generate one with: mrsh keygen\n\
         Or create one with: ssh-keygen -t ed25519",
    )?;

    let pub_bytes = key_pair.public_key_bytes();
    let fp = auth::key_fingerprint(&pub_bytes);

    // Build the SSH public key line
    let key_type_bytes = key_pair.key_type.as_bytes();
    let mut wire = Vec::new();
    wire.extend_from_slice(&(key_type_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type_bytes);
    wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&pub_bytes);
    let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wire);

    println!("Key:         {}", key_pair.path.display());
    println!("Type:        {}", key_pair.key_type);
    println!("Fingerprint: {}", fp);
    println!();
    println!("Public key (add to remote authorized_keys):");
    println!("  {} {} mrsh-client", key_pair.key_type, pub_b64);

    Ok(())
}

/// Find a writable authorized_keys path.
/// Tries the primary data_dir first; if not writable (non-admin user on ProgramData),
/// falls back to user-level ~/.mrsh/authorized_keys.
fn writable_authorized_keys_path() -> Result<std::path::PathBuf> {
    let primary = crate::server_data_dir().join("authorized_keys");

    // Try to open primary for append to test writability
    if let Ok(_) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&primary)
    {
        return Ok(primary);
    }

    // Fallback: user home dir
    let home_dir = dirs::home_dir()
        .context("cannot determine home directory")?
        .join(".mrsh");
    std::fs::create_dir_all(&home_dir)?;
    let user_path = home_dir.join("authorized_keys");
    eprintln!(
        "note: {} not writable, using {}",
        primary.display(),
        user_path.display()
    );
    Ok(user_path)
}

/// Add a public key to the server's authorized_keys.
fn keys_add(key_input: &str) -> Result<()> {
    let ak_path = writable_authorized_keys_path()?;

    // Determine if input is a file path or a key string
    let key_line = if std::path::Path::new(key_input.trim()).exists() {
        std::fs::read_to_string(key_input.trim())
            .with_context(|| format!("read key file: {}", key_input.trim()))?
            .trim()
            .to_string()
    } else {
        key_input.trim().to_string()
    };

    // Validate: must start with a recognized key type
    if !key_line.starts_with("ssh-") && !key_line.starts_with("ecdsa-") {
        bail!("Invalid key format. Expected: ssh-ed25519 AAAA... [comment]\n\
               Or provide a path to a .pub file.");
    }

    // Check for duplicates across ALL authorized_keys paths
    let new_parts: Vec<&str> = key_line.splitn(3, char::is_whitespace).collect();
    if new_parts.len() >= 2 {
        for path in &crate::all_authorized_keys_paths() {
            if let Ok(existing) = std::fs::read_to_string(path) {
                for line in existing.lines() {
                    let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
                    if parts.len() >= 2 && parts[1] == new_parts[1] {
                        bail!("Key already exists in {}", path.display());
                    }
                }
            }
        }
    }

    // Append to file
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ak_path)
        .with_context(|| format!("open {}", ak_path.display()))?;
    writeln!(file, "{}", key_line)?;

    // Parse to show fingerprint
    use mrsh_core::auth;
    if let Ok(keys) = auth::load_authorized_keys(&ak_path, false)
        && let Some(last) = keys.last() {
            let fp = auth::key_fingerprint(&last.key_data);
            eprintln!("Added key: {} ({})", fp, last.comment.as_deref().unwrap_or("no comment"));
        }
    eprintln!("Written to: {}", ak_path.display());

    Ok(())
}

/// Remove a key from authorized_keys by fingerprint or comment match.
/// Searches ALL authorized_keys paths and removes from whichever contains the key.
fn keys_remove(query: &str) -> Result<()> {
    use mrsh_core::auth;

    // Search all paths for the matching key
    for ak_path in &crate::all_authorized_keys_paths() {
        if !ak_path.exists() {
            continue;
        }

        let keys = match auth::load_authorized_keys(ak_path, false) {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Find matching key in this file
        let mut found_idx = None;
        for (i, key) in keys.iter().enumerate() {
            let fp = auth::key_fingerprint(&key.key_data);
            let comment = key.comment.as_deref().unwrap_or("");
            if fp == query || fp.ends_with(query) || comment == query {
                found_idx = Some(i);
                break;
            }
        }

        let Some(idx) = found_idx else { continue };

        let removed = &keys[idx];
        let removed_fp = auth::key_fingerprint(&removed.key_data);
        let removed_comment = removed.comment.as_deref().unwrap_or("no comment");

        // Try to write — may fail if file is not writable
        let content = std::fs::read_to_string(ak_path)?;
        let mut non_blank_idx = 0;
        let mut new_lines = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                new_lines.push(line.to_string());
                continue;
            }
            if non_blank_idx == idx {
                non_blank_idx += 1;
                continue; // skip this line
            }
            non_blank_idx += 1;
            new_lines.push(line.to_string());
        }

        std::fs::write(ak_path, new_lines.join("\n") + "\n")
            .with_context(|| format!("write {}", ak_path.display()))?;

        eprintln!("Removed: {} ({})", removed_fp, removed_comment);
        eprintln!("From: {}", ak_path.display());
        eprintln!("{} key(s) remaining.", keys.len() - 1);
        return Ok(());
    }

    bail!(
        "No key matching '{}' found in any authorized_keys.\n\
         Use 'mrsh keys list' to see available keys.",
        query
    );
}

/// Format key permissions for display.
fn format_permissions(perms: &mrsh_core::auth::KeyPermissions) -> String {
    let mut opts: Vec<String> = Vec::new();
    if !perms.allow_exec { opts.push("no-exec".into()); }
    if !perms.allow_push { opts.push("no-push".into()); }
    if !perms.allow_pull { opts.push("no-pull".into()); }
    if !perms.allow_shell { opts.push("no-shell".into()); }
    if !perms.allow_tunnel { opts.push("no-tunnel".into()); }
    if !perms.allow_gui { opts.push("no-gui".into()); }
    if !perms.allow_clipboard { opts.push("no-clipboard".into()); }
    if !perms.allow_reboot { opts.push("no-reboot".into()); }
    if !perms.allow_screenshot { opts.push("no-screenshot".into()); }
    if !perms.allow_self_update { opts.push("no-self-update".into()); }
    if let Some(ref cmd) = perms.forced_command {
        opts.push(format!("command=\"{}\"", cmd));
    }
    opts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrsh_core::auth::{self, KeyPermissions};

    // ── format_permissions ──────────────────────────────────────────

    #[test]
    fn format_permissions_default_all_allowed() {
        let perms = KeyPermissions::default();
        let out = format_permissions(&perms);
        assert!(out.is_empty(), "default permissions should produce empty string, got: {out}");
    }

    #[test]
    fn format_permissions_no_exec() {
        let perms = KeyPermissions {
            allow_exec: false,
            ..Default::default()
        };
        assert_eq!(format_permissions(&perms), "no-exec");
    }

    #[test]
    fn format_permissions_multiple_denied() {
        let perms = KeyPermissions {
            allow_exec: false,
            allow_push: false,
            allow_pull: false,
            ..Default::default()
        };
        let out = format_permissions(&perms);
        assert!(out.contains("no-exec"), "missing no-exec: {out}");
        assert!(out.contains("no-push"), "missing no-push: {out}");
        assert!(out.contains("no-pull"), "missing no-pull: {out}");
    }

    #[test]
    fn format_permissions_all_denied() {
        let perms = KeyPermissions {
            allow_exec: false,
            allow_push: false,
            allow_pull: false,
            allow_shell: false,
            allow_tunnel: false,
            allow_gui: false,
            allow_clipboard: false,
            allow_reboot: false,
            allow_screenshot: false,
            allow_self_update: false,
            forced_command: None,
            require_totp: false,
        };
        let out = format_permissions(&perms);
        // Should have all no-* entries
        for tag in &[
            "no-exec", "no-push", "no-pull", "no-shell", "no-tunnel",
            "no-gui", "no-clipboard", "no-reboot", "no-screenshot", "no-self-update",
        ] {
            assert!(out.contains(tag), "missing {tag} in: {out}");
        }
    }

    #[test]
    fn format_permissions_forced_command() {
        let perms = KeyPermissions {
            forced_command: Some("whoami".to_string()),
            ..Default::default()
        };
        let out = format_permissions(&perms);
        assert_eq!(out, r#"command="whoami""#);
    }

    #[test]
    fn format_permissions_mixed_deny_with_forced_command() {
        let perms = KeyPermissions {
            allow_shell: false,
            forced_command: Some("/bin/date".to_string()),
            ..Default::default()
        };
        let out = format_permissions(&perms);
        assert!(out.contains("no-shell"), "missing no-shell: {out}");
        assert!(out.contains(r#"command="/bin/date""#), "missing forced command: {out}");
    }

    // ── run_keygen ──────────────────────────────────────────────────

    #[test]
    fn keygen_creates_valid_key_pair() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test_key");

        run_keygen(Some(&key_path)).expect("keygen should succeed");

        // Private key file exists
        assert!(key_path.exists(), "private key file should exist");
        let priv_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            priv_content.contains("BEGIN OPENSSH PRIVATE KEY"),
            "private key should be in OpenSSH format"
        );
        assert!(
            priv_content.contains("END OPENSSH PRIVATE KEY"),
            "private key should have end marker"
        );

        // Public key file exists
        let pub_path = dir.path().join("test_key.pub");
        assert!(pub_path.exists(), "public key file should exist");
        let pub_content = std::fs::read_to_string(&pub_path).unwrap();
        assert!(
            pub_content.starts_with("ssh-ed25519 "),
            "public key should start with ssh-ed25519"
        );
    }

    #[test]
    fn keygen_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("existing_key");

        // Create the file first
        std::fs::write(&key_path, "existing content").unwrap();

        let result = run_keygen(Some(&key_path));
        assert!(result.is_err(), "keygen should refuse to overwrite existing file");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already exists"),
            "error should mention file already exists: {err_msg}"
        );

        // Original content preserved
        let content = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(content, "existing content", "original file should not be modified");
    }

    #[test]
    fn keygen_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("deep").join("nested").join("key");

        run_keygen(Some(&key_path)).expect("keygen should create parent dirs");
        assert!(key_path.exists(), "key file should exist in nested path");
    }

    #[test]
    fn keygen_public_key_is_parseable() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("parse_test");

        run_keygen(Some(&key_path)).unwrap();

        // Write the pubkey into a temp authorized_keys and load it via mrsh_core
        let pub_path = dir.path().join("parse_test.pub");
        let pub_content = std::fs::read_to_string(&pub_path).unwrap();

        let ak_path = dir.path().join("authorized_keys");
        std::fs::write(&ak_path, &pub_content).unwrap();

        let keys = auth::load_authorized_keys(&ak_path, false)
            .expect("generated pubkey should be parseable as authorized_key");
        assert_eq!(keys.len(), 1, "should parse exactly one key");
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].key_data.len(), 32, "ed25519 public key is 32 bytes");
    }

    #[test]
    fn keygen_fingerprint_matches() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("fp_test");

        run_keygen(Some(&key_path)).unwrap();

        // Parse the public key to get key_data, compute fingerprint
        let pub_path = dir.path().join("fp_test.pub");
        let pub_content = std::fs::read_to_string(&pub_path).unwrap();

        let ak_path = dir.path().join("authorized_keys");
        std::fs::write(&ak_path, &pub_content).unwrap();

        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        let fp = auth::key_fingerprint(&keys[0].key_data);
        assert!(fp.starts_with("SHA256:"), "fingerprint should start with SHA256: got {fp}");
    }

    // ── keys_add logic (tested via file manipulation) ───────────────

    /// Helper: generate a valid ssh-ed25519 pubkey line
    fn gen_pubkey_line(comment: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("k");
        run_keygen(Some(&key_path)).unwrap();
        let pub_path = dir.path().join("k.pub");
        let mut content = std::fs::read_to_string(&pub_path).unwrap().trim().to_string();
        // Replace comment (last field after second space)
        if let Some(pos) = content.rfind(' ') {
            content.truncate(pos);
            content.push(' ');
            content.push_str(comment);
        }
        content
    }

    #[test]
    fn keys_add_writes_to_authorized_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key_line = gen_pubkey_line("test-add");

        // Simulate keys_add logic: validate, check duplicates, append
        assert!(key_line.starts_with("ssh-"), "test key should start with ssh-");
        std::fs::create_dir_all(dir.path()).unwrap();

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ak_path)
            .unwrap();
        writeln!(file, "{}", key_line).unwrap();
        drop(file);

        // Verify via mrsh_core parser
        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].comment.as_deref(), Some("test-add"));
    }

    #[test]
    fn keys_add_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key_line = gen_pubkey_line("dup-test");
        std::fs::write(&ak_path, format!("{}\n", key_line)).unwrap();

        // Duplicate detection logic from keys_add
        let existing = std::fs::read_to_string(&ak_path).unwrap();
        let new_parts: Vec<&str> = key_line.splitn(3, char::is_whitespace).collect();
        let mut is_duplicate = false;
        if new_parts.len() >= 2 {
            for line in existing.lines() {
                let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
                if parts.len() >= 2 && parts[1] == new_parts[1] {
                    is_duplicate = true;
                    break;
                }
            }
        }
        assert!(is_duplicate, "same key should be detected as duplicate");
    }

    #[test]
    fn keys_add_allows_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key1 = gen_pubkey_line("key-one");
        let key2 = gen_pubkey_line("key-two");
        assert_ne!(key1, key2, "two generated keys should differ");

        std::fs::write(&ak_path, format!("{}\n", key1)).unwrap();

        // Duplicate check for key2 against key1
        let existing = std::fs::read_to_string(&ak_path).unwrap();
        let new_parts: Vec<&str> = key2.splitn(3, char::is_whitespace).collect();
        let mut is_duplicate = false;
        if new_parts.len() >= 2 {
            for line in existing.lines() {
                let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
                if parts.len() >= 2 && parts[1] == new_parts[1] {
                    is_duplicate = true;
                    break;
                }
            }
        }
        assert!(!is_duplicate, "different keys should not be flagged as duplicate");

        // Append key2
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&ak_path).unwrap();
        writeln!(file, "{}", key2).unwrap();
        drop(file);

        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 2, "should have 2 keys after adding second");
    }

    // ── keys_remove logic (tested via file manipulation) ─────────────

    #[test]
    fn keys_remove_by_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key1 = gen_pubkey_line("stay");
        let key2 = gen_pubkey_line("remove-me");
        std::fs::write(&ak_path, format!("{}\n{}\n", key1, key2)).unwrap();

        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 2);

        // Find fingerprint of key to remove (the one with comment "remove-me")
        let target_idx = keys
            .iter()
            .position(|k| k.comment.as_deref() == Some("remove-me"))
            .expect("should find key with comment remove-me");
        let target_fp = auth::key_fingerprint(&keys[target_idx].key_data);

        // Simulate keys_remove: rebuild file without matched line
        let content = std::fs::read_to_string(&ak_path).unwrap();
        let mut found_idx = None;
        for (i, key) in keys.iter().enumerate() {
            let fp = auth::key_fingerprint(&key.key_data);
            if fp == target_fp {
                found_idx = Some(i);
                break;
            }
        }
        let idx = found_idx.expect("should find key by fingerprint");

        let mut non_blank_idx = 0;
        let mut new_lines = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                new_lines.push(line.to_string());
                continue;
            }
            if non_blank_idx == idx {
                non_blank_idx += 1;
                continue;
            }
            non_blank_idx += 1;
            new_lines.push(line.to_string());
        }
        std::fs::write(&ak_path, new_lines.join("\n") + "\n").unwrap();

        // Verify
        let remaining = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(remaining.len(), 1, "should have 1 key after removal");
        assert_eq!(remaining[0].comment.as_deref(), Some("stay"));
    }

    #[test]
    fn keys_remove_by_comment() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key1 = gen_pubkey_line("alpha");
        let key2 = gen_pubkey_line("beta");
        let key3 = gen_pubkey_line("gamma");
        std::fs::write(&ak_path, format!("{}\n{}\n{}\n", key1, key2, key3)).unwrap();

        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 3);

        // Search by comment
        let query = "beta";
        let mut found_idx = None;
        for (i, key) in keys.iter().enumerate() {
            let fp = auth::key_fingerprint(&key.key_data);
            let comment = key.comment.as_deref().unwrap_or("");
            if fp == query || fp.ends_with(query) || comment == query {
                found_idx = Some(i);
                break;
            }
        }
        let idx = found_idx.expect("should find key by comment 'beta'");

        // Rebuild without matched line
        let content = std::fs::read_to_string(&ak_path).unwrap();
        let mut non_blank_idx = 0;
        let mut new_lines = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                new_lines.push(line.to_string());
                continue;
            }
            if non_blank_idx == idx {
                non_blank_idx += 1;
                continue;
            }
            non_blank_idx += 1;
            new_lines.push(line.to_string());
        }
        std::fs::write(&ak_path, new_lines.join("\n") + "\n").unwrap();

        let remaining = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(remaining.len(), 2);
        let comments: Vec<_> = remaining.iter().map(|k| k.comment.as_deref().unwrap_or("")).collect();
        assert!(comments.contains(&"alpha"));
        assert!(comments.contains(&"gamma"));
        assert!(!comments.contains(&"beta"));
    }

    #[test]
    fn keys_remove_preserves_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key1 = gen_pubkey_line("keeper");
        let key2 = gen_pubkey_line("victim");
        let content = format!("# Header comment\n\n{}\n# Middle comment\n{}\n", key1, key2);
        std::fs::write(&ak_path, &content).unwrap();

        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 2);

        // Remove index 1 (victim)
        let idx = 1;
        let mut non_blank_idx = 0;
        let mut new_lines = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                new_lines.push(line.to_string());
                continue;
            }
            if non_blank_idx == idx {
                non_blank_idx += 1;
                continue;
            }
            non_blank_idx += 1;
            new_lines.push(line.to_string());
        }
        let rebuilt = new_lines.join("\n") + "\n";
        std::fs::write(&ak_path, &rebuilt).unwrap();

        // Comments and blank lines preserved
        assert!(rebuilt.contains("# Header comment"), "header comment preserved");
        assert!(rebuilt.contains("# Middle comment"), "middle comment preserved");

        let remaining = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].comment.as_deref(), Some("keeper"));
    }

    // ── keys_list formatting (smoke test via load + format) ─────────

    #[test]
    fn keys_list_formatting_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");

        let key1 = gen_pubkey_line("admin-key");
        // Add a key line with options (restrict prefix)
        let key2_raw = gen_pubkey_line("restricted");
        let key2 = format!("restrict,permit-exec {}", key2_raw);
        std::fs::write(&ak_path, format!("{}\n{}\n", key1, key2)).unwrap();

        let keys = auth::load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 2);

        // First key: default permissions → format_permissions empty
        let perms0 = format_permissions(&keys[0].permissions);
        assert!(perms0.is_empty(), "unrestricted key should have empty options: {perms0}");

        // Second key: restrict + permit-exec → all denied except exec
        let perms1 = format_permissions(&keys[1].permissions);
        assert!(!perms1.contains("no-exec"), "exec should be allowed (permit-exec): {perms1}");
        assert!(perms1.contains("no-push"), "push should be denied (restrict): {perms1}");
        assert!(perms1.contains("no-shell"), "shell should be denied (restrict): {perms1}");
    }

    // ── key validation (keys_add input validation logic) ────────────

    #[test]
    fn key_validation_rejects_invalid_format() {
        let invalid_inputs = [
            "not-a-key at all",
            "rsa-something AAAA...",
            "",
            "just-base64-AAAA",
        ];
        for input in &invalid_inputs {
            let starts_ok = input.starts_with("ssh-") || input.starts_with("ecdsa-");
            assert!(
                !starts_ok,
                "input '{input}' should fail validation"
            );
        }
    }

    #[test]
    fn key_validation_accepts_valid_prefixes() {
        let valid_prefixes = ["ssh-ed25519 AAAA...", "ssh-rsa AAAA...", "ecdsa-sha2 AAAA..."];
        for input in &valid_prefixes {
            let starts_ok = input.starts_with("ssh-") || input.starts_with("ecdsa-");
            assert!(starts_ok, "input '{input}' should pass validation");
        }
    }
}
