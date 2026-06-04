//! Build script — embed-resource for Windows icon/manifest/version.
//!
//! Uses embed-resource which emits `cargo:rustc-link-arg-bins=` (not -link-arg),
//! so the resource is linked into binaries only — test targets are excluded.
//! This avoids the CVT1100 duplicate VERSION resource that winres 0.1 caused when
//! its `-l dylib=resource` AND an explicit positional resource.lib were both passed
//! to the lib-test link line.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("resource.rc", embed_resource::NONE)
            .manifest_required()
            .unwrap_or_else(|e| eprintln!("cargo:warning=embed-resource: {e}"));
    }
}
