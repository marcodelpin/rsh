//! Linux installer generation: self-extracting `.sh` (bash header + tar.gz payload).

use std::io::Write as IoWrite;
use std::path::PathBuf;

use anyhow::{Context, Result};

use super::InstallPackOptions;

/// Generate a self-extracting .sh file (bash header + tar.gz payload).
pub(super) fn generate_self_extracting_sh(
    opts: &InstallPackOptions,
    version: &str,
    binary_data: &[u8],
    auth_keys: &str,
    install_script: &str,
    config: Option<&str>,
    ai_usage: &str,
) -> Result<PathBuf> {
    let out_path = match &opts.output {
        Some(p) => p.clone(),
        None => PathBuf::from(format!("mrsh-{}-linux-install.sh", version)),
    };

    // Build tar.gz in memory
    let tar_gz_data = {
        let mut tar_gz = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_gz, flate2::Compression::best());
            let mut ar = tar::Builder::new(gz);

            // Add binary
            add_tar_entry(&mut ar, "mrsh", binary_data, 0o755)?;

            // Add authorized_keys
            add_tar_entry(&mut ar, "authorized_keys", auth_keys.as_bytes(), 0o600)?;

            // Add AI usage guide (if found)
            if !ai_usage.is_empty() {
                add_tar_entry(&mut ar, "AI_USAGE.md", ai_usage.as_bytes(), 0o644)?;
            }

            // Add install.sh (the inner installer, used by the wrapper)
            add_tar_entry(&mut ar, "install.sh", install_script.as_bytes(), 0o755)?;

            // Add config if present
            if let Some(cfg) = config {
                add_tar_entry(&mut ar, "config", cfg.as_bytes(), 0o600)?;
            }

            ar.into_inner()?.finish()?;
        }
        tar_gz
    };

    // Write self-extracting script
    let mut f = std::fs::File::create(&out_path)
        .with_context(|| format!("create {}", out_path.display()))?;

    // Bash header that extracts and runs
    write!(f, "{}", generate_sfx_header(version, opts.port))?;

    // Append tar.gz payload
    f.write_all(&tar_gz_data)?;
    f.flush()?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(out_path)
}

/// Add a file entry to a tar archive.
fn add_tar_entry<W: IoWrite>(
    ar: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    header.set_cksum();
    ar.append_data(&mut header, name, data)?;
    Ok(())
}

/// Generate the bash header for the self-extracting script.
pub(super) fn generate_sfx_header(version: &str, port: u16) -> String {
    format!(
        r#"#!/bin/bash
# mrsh v{version} — Self-extracting installer
# Run: chmod +x <this-file> && sudo ./<this-file>
set -e

echo "=== mrsh v{version} Installer ==="
echo "Port: {port}"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root: sudo $0"
    exit 1
fi

# Extract payload to temp dir
TMPDIR=$(mktemp -d /tmp/rsh-install.XXXXXX)
trap "rm -rf '$TMPDIR'" EXIT

ARCHIVE=$(awk '/^__ARCHIVE_BELOW__$/ {{print NR + 1; exit 0;}}' "$0")
tail -n+"$ARCHIVE" "$0" | tar xzf - -C "$TMPDIR"

# Run inner installer
cd "$TMPDIR"
chmod +x install.sh
./install.sh

exit 0
__ARCHIVE_BELOW__
"#
    )
}

/// Generate Linux install.sh script.
pub(super) fn generate_linux_script(port: u16) -> String {
    let mut script = String::from("#!/bin/bash\n");
    script.push_str("set -e\n\n");
    script.push_str(&format!(
        "echo \"=== mrsh Installer (v{}) ===\"\n",
        env!("CARGO_PKG_VERSION")
    ));
    script.push_str(&format!("echo \"Port: {}\"\n", port));
    script.push_str("echo\n\n");

    script.push_str("if [ \"$(id -u)\" -ne 0 ]; then\n");
    script.push_str("    echo \"ERROR: Run as root: sudo $0\"\n");
    script.push_str("    exit 1\n");
    script.push_str("fi\n\n");

    let bin_dir = "/usr/local/bin";
    let conf_dir = "/etc/mrsh";

    script.push_str(&format!(
        "install -m 755 \"$(dirname \"$0\")/mrsh\" \"{}/mrsh\"\n",
        bin_dir
    ));
    script.push_str(&format!(
        "ln -sf \"{0}/mrsh\" \"{0}/rsh\" 2>/dev/null\n",
        bin_dir
    )); // compat symlink
    script.push_str(&format!("echo \"Binary installed: {}/mrsh\"\n\n", bin_dir));

    script.push_str(&format!("mkdir -p \"{}\"\n", conf_dir));
    // Merge new keys with existing authorized_keys (never overwrite/lose existing keys)
    script.push_str(&format!(
        "if [ -f \"{conf}/authorized_keys\" ]; then\n\
         \x20   echo \"Merging authorized_keys...\"\n\
         \x20   while IFS= read -r line; do\n\
         \x20       [ -z \"$line\" ] && continue\n\
         \x20       grep -qxF \"$line\" \"{conf}/authorized_keys\" || echo \"$line\" >> \"{conf}/authorized_keys\"\n\
         \x20   done < \"$(dirname \"$0\")/authorized_keys\"\n\
         \x20   chmod 600 \"{conf}/authorized_keys\"\n\
         else\n\
         \x20   install -m 600 \"$(dirname \"$0\")/authorized_keys\" \"{conf}/authorized_keys\"\n\
         fi\n",
        conf = conf_dir
    ));
    script.push_str(&format!(
        "if [ -f \"$(dirname \"$0\")/config\" ]; then\n\
         \x20   install -m 600 \"$(dirname \"$0\")/config\" \"{conf}/config\"\n\
         \x20   # Also copy to root user config (server reads from user home)\n\
         \x20   mkdir -p /root/.mrsh\n\
         \x20   cp \"{conf}/config\" /root/.mrsh/config\n\
         \x20   chmod 600 /root/.mrsh/config\n\
         \x20   echo \"Fleet enrollment config installed.\"\n\
         fi\n",
        conf = conf_dir
    ));

    // Copy AI usage guide
    script.push_str(&format!(
        "if [ -f \"$(dirname \"$0\")/AI_USAGE.md\" ]; then\n\
         \x20   install -m 644 \"$(dirname \"$0\")/AI_USAGE.md\" \"{conf}/AI_USAGE.md\"\n\
         fi\n",
        conf = conf_dir
    ));

    script.push_str(&format!("echo \"Config directory: {}\"\n\n", conf_dir));

    script.push_str(&format!("{}/mrsh --install\n", bin_dir));
    script.push_str("echo \"Systemd service installed.\"\n\n");

    script.push_str("systemctl daemon-reload\n");
    script.push_str("systemctl enable --now mrsh\n");
    script.push_str("echo \"Service started.\"\n\n");

    script.push_str("echo\n");
    script.push_str("echo \"=== Installation complete ===\"\n");
    script.push_str(&format!("echo \"mrsh listening on port {}\"\n", port));
    script.push_str("echo \"Connect with: mrsh -h <this-machine-ip> ping\"\n");

    script
}
