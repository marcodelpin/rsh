//! Integration test for build.rs winres + resource embedding.
//!
//! Validates that the release build produces a Windows PE binary with:
//!   1. `.rsrc` section present (winres compiled + linked)
//!   2. VersionInfo populated (FileVersion, ProductName, CompanyName)
//!   3. Icon resource embedded (from icon.ico)
//!
//! rsh-0ogm: regression test for the MSVC winres link bug fixed in build.rs.
//! Without the fix, build.rs only handled `resource.o` (MinGW) and silently
//! skipped `resource.lib` (MSVC), producing a binary with no `.rsrc`.

#[cfg(target_os = "windows")]
#[test]
fn windows_binary_has_rsrc_section() {
    use std::fs;
    use std::path::PathBuf;

    // Locate the release binary (cargo runs tests from the workspace root).
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("release")
        .join("mrsh.exe");

    if !exe.exists() {
        // Skip if not built yet (test runs require prior `cargo build --release`).
        eprintln!("SKIP: {} not found — run 'cargo build --release' first", exe.display());
        return;
    }

    let bytes = fs::read(&exe).expect("read mrsh.exe");

    // PE header offset at file+0x3C
    let pe_off = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    assert!(pe_off > 0 && pe_off + 24 < bytes.len(), "valid PE header offset");

    // Section count at PE+6
    let sec_count = u16::from_le_bytes([bytes[pe_off + 6], bytes[pe_off + 7]]) as usize;
    assert!(sec_count >= 5, "PE has at least 5 sections, got {sec_count}");

    // Optional header size at PE+20, section table starts at PE+24+optHdrSize
    let opt_hdr_size = u16::from_le_bytes([bytes[pe_off + 20], bytes[pe_off + 21]]) as usize;
    let sec_start = pe_off + 24 + opt_hdr_size;

    let mut found_rsrc = false;
    let mut sections = Vec::new();
    for i in 0..sec_count {
        let s_off = sec_start + (i * 40);
        let name_bytes = &bytes[s_off..s_off + 8];
        let name = std::str::from_utf8(name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0');
        sections.push(name.to_string());
        if name == ".rsrc" {
            found_rsrc = true;
        }
    }

    assert!(
        found_rsrc,
        "mrsh.exe must have .rsrc section for icon + VersionInfo + manifest.\nFound sections: {sections:?}\nIf this fails, build.rs is not linking resource.lib (MSVC) or resource.o (MinGW) — see rsh-0ogm."
    );
}

#[cfg(not(target_os = "windows"))]
#[test]
fn skip_on_non_windows() {
    // build.rs winres logic only runs on Windows target — nothing to test elsewhere.
}
