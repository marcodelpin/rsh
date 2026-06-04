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
fn keys_list() -> Result<()> {
    use mrsh_core::auth;

    let data_dir = crate::server_data_dir();
    let ak_path = data_dir.join("authorized_keys");

    if !ak_path.exists() {
        eprintln!("No authorized_keys file at {}", ak_path.display());
        eprintln!("Generate a key with: mrsh keygen");
        return Ok(());
    }

    let keys = auth::load_authorized_keys(&ak_path, false)?;

    if keys.is_empty() {
        eprintln!("authorized_keys is empty.");
        return Ok(());
    }

    println!("{:<12} {:<50} COMMENT", "TYPE", "FINGERPRINT");
    println!("{}", "-".repeat(80));

    for key in &keys {
        let fp = auth::key_fingerprint(&key.key_data);
        let comment = key.comment.as_deref().unwrap_or("");
        let perms = format_permissions(&key.permissions);
        println!("{:<12} {:<50} {}", key.key_type, fp, comment);
        if !perms.is_empty() {
            println!("             options: {}", perms);
        }
    }

    println!("\n{} key(s) in {}", keys.len(), ak_path.display());
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

/// Add a public key to the server's authorized_keys.
fn keys_add(key_input: &str) -> Result<()> {
    let data_dir = crate::server_data_dir();
    let ak_path = data_dir.join("authorized_keys");

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

    // Ensure data dir exists
    std::fs::create_dir_all(&data_dir)?;

    // Check for duplicates
    if ak_path.exists() {
        let existing = std::fs::read_to_string(&ak_path)?;
        // Compare key data (second field)
        let new_parts: Vec<&str> = key_line.splitn(3, char::is_whitespace).collect();
        if new_parts.len() >= 2 {
            for line in existing.lines() {
                let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
                if parts.len() >= 2 && parts[1] == new_parts[1] {
                    bail!("Key already exists in authorized_keys.");
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
fn keys_remove(query: &str) -> Result<()> {
    use mrsh_core::auth;

    let data_dir = crate::server_data_dir();
    let ak_path = data_dir.join("authorized_keys");

    if !ak_path.exists() {
        bail!("No authorized_keys file at {}", ak_path.display());
    }

    let content = std::fs::read_to_string(&ak_path)?;
    let keys = auth::load_authorized_keys(&ak_path, false)?;

    // Find matching key
    let mut found_idx = None;
    for (i, key) in keys.iter().enumerate() {
        let fp = auth::key_fingerprint(&key.key_data);
        let comment = key.comment.as_deref().unwrap_or("");
        if fp == query || fp.ends_with(query) || comment == query {
            found_idx = Some(i);
            break;
        }
    }

    let idx = found_idx.ok_or_else(|| anyhow::anyhow!(
        "No key matching '{}' found in authorized_keys.\n\
         Use 'mrsh keys list' to see available keys.",
        query
    ))?;

    let removed = &keys[idx];
    let removed_fp = auth::key_fingerprint(&removed.key_data);
    let removed_comment = removed.comment.as_deref().unwrap_or("no comment");

    // Rebuild the file without the matched line
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

    std::fs::write(&ak_path, new_lines.join("\n") + "\n")?;

    eprintln!("Removed: {} ({})", removed_fp, removed_comment);
    eprintln!("{} key(s) remaining.", keys.len() - 1);

    Ok(())
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
