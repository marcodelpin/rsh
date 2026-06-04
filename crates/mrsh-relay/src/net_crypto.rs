//! Envelope encryption for network info — ECIES (X25519 + AES-256-GCM).
//!
//! Server encrypts its LAN info so only authorized group members can see it.
//! hbbs stores and forwards the blob opaque.
//!
//! Key derivation: group keypair derived from enrollment_token via HKDF-like
//! construction: SHA256(enrollment_token || "mrsh-group-x25519") → X25519 secret.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use prost::Message;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::proto;

/// Derive an X25519 keypair from an enrollment token.
/// Deterministic: same token → same keypair across all group members.
pub fn derive_group_keypair(enrollment_token: &str) -> (StaticSecret, PublicKey) {
    let mut hasher = Sha256::new();
    hasher.update(enrollment_token.as_bytes());
    hasher.update(b"mrsh-group-x25519");
    let hash = hasher.finalize();

    let secret = StaticSecret::from(<[u8; 32]>::from(hash));
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Collect network interfaces on this machine.
pub fn collect_network_info(hostname: &str, service_port: u16, tray_port: u16) -> proto::NetworkInfo {
    let interfaces = collect_interfaces();
    proto::NetworkInfo {
        interfaces,
        hostname: hostname.to_string(),
        service_port: service_port as u32,
        tray_port: tray_port as u32,
    }
}

/// Envelope-encrypt NetworkInfo for one or more groups.
///
/// - Generates a random AES-256-GCM key
/// - Encrypts the serialized NetworkInfo with it
/// - For each group: ECIES-encrypts the AES key with the group's public key
pub fn encrypt_network_info(
    info: &proto::NetworkInfo,
    groups: &[(String, PublicKey)], // (group_hash, group_public_key)
) -> Result<Vec<u8>> {
    if groups.is_empty() {
        return Ok(Vec::new());
    }

    // Serialize payload
    let payload = info.encode_to_vec();

    // Generate random AES key + nonce
    let sym_key: [u8; 32] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    // Encrypt payload with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&sym_key).context("create AES cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_data = cipher
        .encrypt(nonce, payload.as_ref())
        .map_err(|e| anyhow::anyhow!("AES encrypt: {}", e))?;

    // Encrypt the AES key for each group (ECIES)
    let mut keys = Vec::with_capacity(groups.len());
    for (group_hash, group_pub) in groups {
        let entry = ecies_encrypt_key(&sym_key, group_pub, group_hash)?;
        keys.push(entry);
    }

    let envelope = proto::EncryptedNetworkInfo {
        encrypted_data,
        nonce: nonce_bytes.to_vec(),
        keys,
    };

    Ok(envelope.encode_to_vec())
}

/// Decrypt NetworkInfo from an envelope blob.
///
/// Tries each GroupKeyEntry to find one matching the caller's group.
/// Returns None if no matching group key found (not an error — just not authorized).
pub fn decrypt_network_info(
    blob: &[u8],
    enrollment_token: &str,
) -> Result<Option<proto::NetworkInfo>> {
    if blob.is_empty() {
        return Ok(None);
    }

    let envelope =
        proto::EncryptedNetworkInfo::decode(blob).context("decode EncryptedNetworkInfo")?;

    let (group_secret, _group_pub) = derive_group_keypair(enrollment_token);

    // Compute our group_hash to find matching key entry
    let mut hasher = Sha256::new();
    hasher.update(enrollment_token.as_bytes());
    let our_hash = hex::encode(hasher.finalize());

    // Find our key entry
    let entry = match envelope.keys.iter().find(|k| k.group_hash == our_hash) {
        Some(e) => e,
        None => return Ok(None), // not our group
    };

    // ECIES decrypt: DH(group_secret, ephemeral_pub) → shared_secret → decrypt AES key
    let sym_key = ecies_decrypt_key(entry, &group_secret)?;

    // Decrypt payload with recovered AES key
    let cipher = Aes256Gcm::new_from_slice(&sym_key).context("create AES cipher")?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher
        .decrypt(nonce, envelope.encrypted_data.as_ref())
        .map_err(|e| anyhow::anyhow!("AES decrypt: {}", e))?;

    let info = proto::NetworkInfo::decode(plaintext.as_slice()).context("decode NetworkInfo")?;
    Ok(Some(info))
}

/// ECIES encrypt: wrap a 32-byte key for a recipient's X25519 public key.
fn ecies_encrypt_key(
    sym_key: &[u8; 32],
    recipient_pub: &PublicKey,
    group_hash: &str,
) -> Result<proto::GroupKeyEntry> {
    // Generate ephemeral X25519 keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);

    // DH → shared secret
    let shared = ephemeral_secret.diffie_hellman(recipient_pub);

    // Derive AES key from shared secret (hash to ensure uniformity)
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(b"mrsh-ecies-key-wrap");
    let derived = hasher.finalize();

    // Encrypt sym_key with derived key
    let cipher = Aes256Gcm::new_from_slice(&derived).context("ECIES AES")?;
    let key_nonce_bytes: [u8; 12] = rand::random();
    let key_nonce = Nonce::from_slice(&key_nonce_bytes);
    let encrypted_key = cipher
        .encrypt(key_nonce, sym_key.as_ref())
        .map_err(|e| anyhow::anyhow!("ECIES encrypt: {}", e))?;

    Ok(proto::GroupKeyEntry {
        group_hash: group_hash.to_string(),
        ephemeral_pubkey: ephemeral_pub.as_bytes().to_vec(),
        encrypted_key,
        key_nonce: key_nonce_bytes.to_vec(),
    })
}

/// ECIES decrypt: unwrap a 32-byte key using our X25519 static secret.
fn ecies_decrypt_key(
    entry: &proto::GroupKeyEntry,
    our_secret: &StaticSecret,
) -> Result<[u8; 32]> {
    // Reconstruct ephemeral public key
    let ephemeral_pub_bytes: [u8; 32] = entry
        .ephemeral_pubkey
        .as_slice()
        .try_into()
        .context("ephemeral pubkey must be 32 bytes")?;
    let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);

    // DH → same shared secret
    let shared = our_secret.diffie_hellman(&ephemeral_pub);

    // Derive same AES key
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(b"mrsh-ecies-key-wrap");
    let derived = hasher.finalize();

    // Decrypt sym_key
    let cipher = Aes256Gcm::new_from_slice(&derived).context("ECIES AES")?;
    let key_nonce = Nonce::from_slice(&entry.key_nonce);
    let sym_key_bytes = cipher
        .decrypt(key_nonce, entry.encrypted_key.as_ref())
        .map_err(|e| anyhow::anyhow!("ECIES decrypt: {}", e))?;

    let sym_key: [u8; 32] = sym_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted key not 32 bytes"))?;

    Ok(sym_key)
}

/// Collect network interfaces (cross-platform).
fn collect_interfaces() -> Vec<proto::NetInterface> {
    let mut result = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to get interfaces (most reliable on Windows)
        if let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress",
            ])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                parse_windows_interfaces(&text, &mut result);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Parse /proc/net or ip command on Linux
        if let Ok(output) = std::process::Command::new("ip")
            .args(["-j", "-4", "addr", "show"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                parse_linux_interfaces(&text, &mut result);
            }
        }
    }

    result
}

#[cfg(target_os = "windows")]
fn parse_windows_interfaces(json: &str, result: &mut Vec<proto::NetInterface>) {
    // PowerShell outputs array or single object
    let json = json.trim();
    if json.is_empty() {
        return;
    }

    // Simple JSON parsing without serde (avoid adding dependency)
    // Format: [{"InterfaceAlias":"Ethernet","IPAddress":"192.0.2.50","PrefixLength":24}]
    for line in json.split('{') {
        let extract = |key: &str| -> Option<String> {
            let needle = format!("\"{}\":\"", key);
            let start = line.find(&needle)? + needle.len();
            let end = line[start..].find('"')? + start;
            Some(line[start..end].to_string())
        };
        let extract_num = |key: &str| -> Option<u32> {
            let needle = format!("\"{}\":", key);
            let start = line.find(&needle)? + needle.len();
            let num_str: String = line[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
            num_str.parse().ok()
        };

        if let (Some(name), Some(ip)) = (extract("InterfaceAlias"), extract("IPAddress")) {
            let prefix = extract_num("PrefixLength").unwrap_or(24);
            let netmask = prefix_to_netmask(prefix);
            result.push(proto::NetInterface {
                name,
                ip,
                netmask,
                gateway: String::new(), // gateway added separately if needed
            });
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn parse_linux_interfaces(json: &str, result: &mut Vec<proto::NetInterface>) {
    // ip -j -4 addr show outputs JSON array
    // [{"ifname":"eth0","addr_info":[{"local":"192.0.2.50","prefixlen":24}]}]
    let json = json.trim();
    if json.is_empty() {
        return;
    }

    // Simple extraction without serde
    for iface_block in json.split("\"ifname\"") {
        let extract_str = |block: &str, key: &str| -> Option<String> {
            let needle = format!("\"{}\":\"", key);
            let start = block.find(&needle)? + needle.len();
            let end = block[start..].find('"')? + start;
            Some(block[start..end].to_string())
        };
        let extract_num = |block: &str, key: &str| -> Option<u32> {
            let needle = format!("\"{}\":", key);
            let start = block.find(&needle)? + needle.len();
            let num_str: String = block[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
            num_str.parse().ok()
        };

        if let Some(name) = extract_str(iface_block, "") {
            // Skip — ifname was the split point, need to re-extract
        }

        // Extract ifname from the value after split
        let ifname = {
            let s = iface_block.trim_start_matches(|c: char| c != '"');
            if s.starts_with(":\"") {
                let start = 2;
                let end = s[start..].find('"').unwrap_or(0) + start;
                &s[start..end]
            } else {
                continue;
            }
        };

        if ifname == "lo" {
            continue;
        }

        if let Some(ip) = extract_str(iface_block, "local") {
            let prefix = extract_num(iface_block, "prefixlen").unwrap_or(24);
            let netmask = prefix_to_netmask(prefix);
            result.push(proto::NetInterface {
                name: ifname.to_string(),
                ip,
                netmask,
                gateway: String::new(),
            });
        }
    }
}

/// Convert CIDR prefix length to dotted netmask string.
fn prefix_to_netmask(prefix: u32) -> String {
    if prefix > 32 {
        return "255.255.255.255".to_string();
    }
    let mask: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF,
    )
}

/// Check if two IPs are on the same subnet.
pub fn same_subnet(ip1: &str, mask1: &str, ip2: &str, mask2: &str) -> bool {
    let parse_ip = |s: &str| -> Option<u32> {
        let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() == 4 {
            Some(u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]]))
        } else {
            None
        }
    };

    if let (Some(a), Some(b), Some(m1), Some(m2)) =
        (parse_ip(ip1), parse_ip(ip2), parse_ip(mask1), parse_ip(mask2))
    {
        // Use the more restrictive mask
        let mask = m1 & m2;
        (a & mask) == (b & mask)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let token = "test-enrollment-token-12345";
        let (_, group_pub) = derive_group_keypair(token);

        let info = proto::NetworkInfo {
            interfaces: vec![proto::NetInterface {
                name: "eth0".into(),
                ip: "192.0.2.50".into(),
                netmask: "255.255.255.0".into(),
                gateway: "192.0.2.1".into(),
            }],
            hostname: "test-host".into(),
            service_port: 8822,
            tray_port: 9822,
        };

        let group_hash = {
            let mut h = Sha256::new();
            h.update(token.as_bytes());
            hex::encode(h.finalize())
        };

        let blob =
            encrypt_network_info(&info, &[(group_hash, group_pub)]).expect("encrypt");
        assert!(!blob.is_empty());

        let decrypted = decrypt_network_info(&blob, token)
            .expect("decrypt")
            .expect("should find our group");
        assert_eq!(decrypted.hostname, "test-host");
        assert_eq!(decrypted.service_port, 8822);
        assert_eq!(decrypted.interfaces.len(), 1);
        assert_eq!(decrypted.interfaces[0].ip, "192.0.2.50");
    }

    #[test]
    fn wrong_token_returns_none() {
        let token = "real-token";
        let (_, group_pub) = derive_group_keypair(token);
        let group_hash = {
            let mut h = Sha256::new();
            h.update(token.as_bytes());
            hex::encode(h.finalize())
        };

        let info = proto::NetworkInfo {
            hostname: "test".into(),
            ..Default::default()
        };

        let blob = encrypt_network_info(&info, &[(group_hash, group_pub)]).unwrap();
        let result = decrypt_network_info(&blob, "wrong-token").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn multi_group_encryption() {
        let token1 = "group-alpha";
        let token2 = "group-beta";
        let (_, pub1) = derive_group_keypair(token1);
        let (_, pub2) = derive_group_keypair(token2);

        let hash1 = hex::encode(Sha256::digest(token1.as_bytes()));
        let hash2 = hex::encode(Sha256::digest(token2.as_bytes()));

        let info = proto::NetworkInfo {
            hostname: "multi-group-host".into(),
            service_port: 8822,
            ..Default::default()
        };

        let blob = encrypt_network_info(
            &info,
            &[(hash1, pub1), (hash2, pub2)],
        )
        .unwrap();

        // Both tokens can decrypt
        let d1 = decrypt_network_info(&blob, token1).unwrap().unwrap();
        assert_eq!(d1.hostname, "multi-group-host");

        let d2 = decrypt_network_info(&blob, token2).unwrap().unwrap();
        assert_eq!(d2.hostname, "multi-group-host");

        // Wrong token gets None
        let d3 = decrypt_network_info(&blob, "group-gamma").unwrap();
        assert!(d3.is_none());
    }

    #[test]
    fn empty_groups_returns_empty_blob() {
        let info = proto::NetworkInfo::default();
        let blob = encrypt_network_info(&info, &[]).unwrap();
        assert!(blob.is_empty());
    }

    #[test]
    fn empty_blob_returns_none() {
        let result = decrypt_network_info(&[], "token").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn prefix_to_netmask_common() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
    }

    #[test]
    fn same_subnet_basic() {
        assert!(same_subnet(
            "192.0.2.50", "255.255.255.0",
            "192.0.2.100", "255.255.255.0"
        ));
        assert!(!same_subnet(
            "192.0.2.50", "255.255.255.0",
            "192.168.72.50", "255.255.255.0"
        ));
        assert!(same_subnet(
            "10.0.0.1", "255.0.0.0",
            "10.255.255.254", "255.0.0.0"
        ));
    }

    #[test]
    fn deterministic_keypair() {
        let (s1, p1) = derive_group_keypair("same-token");
        let (s2, p2) = derive_group_keypair("same-token");
        assert_eq!(p1.as_bytes(), p2.as_bytes());
        // StaticSecret doesn't expose bytes directly, but same input → same DH results
        let test_pub = PublicKey::from([1u8; 32]);
        assert_eq!(
            s1.diffie_hellman(&test_pub).as_bytes(),
            s2.diffie_hellman(&test_pub).as_bytes()
        );
    }
}
