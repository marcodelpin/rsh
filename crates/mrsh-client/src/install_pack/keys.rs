//! Authorized keys + group token management for the install pack.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Build authorized_keys content from the user's SSH public keys.
pub(super) fn build_authorized_keys(extra_keys: &[String]) -> Result<String> {
    let mut lines = Vec::new();

    let home = dirs::home_dir().context("cannot determine home directory")?;
    let ssh_dir = home.join(".ssh");
    let mrsh_dir = home.join(".mrsh");
    let rsh_dir = home.join(".rsh"); // legacy compat

    let candidates = [
        ssh_dir.join("id_ed25519.pub"),
        mrsh_dir.join("id_ed25519.pub"),
        rsh_dir.join("id_ed25519.pub"),
        ssh_dir.join("id_rsa.pub"),
    ];

    for path in &candidates {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("read public key: {}", path.display()))?;
            let key_line = content.trim().to_string();
            if !key_line.is_empty() && !lines.contains(&key_line) {
                lines.push(key_line);
            }
        }
    }

    for key in extra_keys {
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() && !lines.contains(&trimmed) {
            lines.push(trimmed);
        }
    }

    if lines.is_empty() {
        bail!(
            "no public keys found. Generate one with: mrsh keygen\n\
             Or specify with: --key <path-to-public-key>"
        );
    }

    Ok(lines.join("\n") + "\n")
}

/// Path to the local groups registry file (~/.mrsh/groups.json).
fn groups_file() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let mrsh_path = home.join(".mrsh").join("groups.json");
    let rsh_path = home.join(".rsh").join("groups.json");
    // Prefer new location, fall back to legacy
    Ok(if mrsh_path.exists() {
        mrsh_path
    } else {
        rsh_path
    })
}

fn load_groups() -> Result<std::collections::HashMap<String, String>> {
    let path = groups_file()?;
    if !path.exists() {
        return Ok(std::collections::HashMap::new());
    }
    let data =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&data).context("parse groups.json")
}

fn save_groups(groups: &std::collections::HashMap<String, String>) -> Result<()> {
    let path = groups_file()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(groups)?;
    std::fs::write(&path, data).with_context(|| format!("write {}", path.display()))
}

pub(super) fn load_or_create_group_token(group_name: &str) -> Result<String> {
    let mut groups = load_groups()?;
    if let Some(token) = groups.get(group_name) {
        return Ok(token.clone());
    }
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(bytes);
    groups.insert(group_name.to_string(), token.clone());
    save_groups(&groups)?;
    Ok(token)
}

pub(super) fn save_group_mapping(group_name: &str, token: &str) -> Result<()> {
    let mut groups = load_groups()?;
    groups.insert(group_name.to_string(), token.to_string());
    save_groups(&groups)
}

/// Look up the enrollment token for a named group.
pub fn get_group_token(group_name: &str) -> Result<String> {
    let groups = load_groups()?;
    groups.get(group_name).cloned()
        .with_context(|| format!("group '{}' not found in ~/.mrsh/groups.json — create it with: mrsh install-pack --group {}", group_name, group_name))
}
