# Cross-Compile mrsh for Android (aarch64-linux-android)

Status: Phase 0 (cross-compile) shipped under bd `rsh-9qrk`. Phase 1 (HU deploy + Termux:Boot autostart) is user-side and tracked separately.

## Target

- Triple: `aarch64-linux-android`
- Min API level: **33** (Android 13). Chosen because most modern automotive HUs ship API >= 31; API 33 gives us ndk-side TLS 1.3, modern libc, and matches Termux's published min API.
- Toolchain: **Android NDK r27** (the official `android-ndk-r27-linux.zip`). As of 2026-06-05 it lives on **builder** (LXC280, = `build.example.local` after the consolidation) at `~/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/` — a **home-dir install (no sudo)**, NOT the old `/opt/android-sdk/ndk/...` path. The original `/opt` NDK was lost when the old LXC103 build-host was decommissioned into builder (rsh-7xny); re-provisioned via `curl https://dl.google.com/android/repository/android-ndk-r27-linux.zip` + unzip to `~/`.

## Cargo target setup (build-host)

```bash
PATH=$HOME/.cargo/bin:$PATH rustup target add aarch64-linux-android
```

## Build environment

Required env vars before `cargo build`:

```bash
export PATH=$HOME/.cargo/bin:$HOME/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
export CC_aarch64_linux_android=aarch64-linux-android33-clang
export CXX_aarch64_linux_android=aarch64-linux-android33-clang++
export AR_aarch64_linux_android=llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android33-clang
```

## Build command

```bash
cd /home/user/mrsh
cargo build --release --target aarch64-linux-android
```

Builds the full root `mrsh` binary (client + server). For server-only:

```bash
cargo build --release --target aarch64-linux-android --no-default-features --features ssh -p mrsh-server
```

Output: `target/aarch64-linux-android/release/mrsh`

Verify:

```bash
file target/aarch64-linux-android/release/mrsh
# ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked,
# interpreter /system/bin/linker64, stripped
```

Size: ~6.7 MiB stripped (release profile uses `lto = true`, `opt-level = "z"`, `panic = "abort"` per workspace `Cargo.toml`).

## Source code platform diffs (added under rsh-9qrk)

All four edits are minimal `cfg(target_os = "android")` gates layered on top of the existing Linux/musl support:

1. **`crates/mrsh-server/src/screenshot.rs`** — added `capture_screen_android()` that shells out to `/system/bin/screencap -p` (PNG to stdout) and re-encodes to JPEG via the `image` crate. The X11/Wayland `grim`/`scrot`/`import` path is now scoped to `cfg(all(not(target_os = "windows"), not(target_os = "android")))` so Android won't try unavailable tools.

2. **`crates/mrsh-server/src/service.rs`** — `install_service` and `uninstall_service` get an Android no-op branch that prints a hint pointing the user at `~/.termux/boot/01-start-mrsh`. Termux has no systemd; the existing systemd path is now scoped to `cfg(all(not(target_os = "windows"), not(target_os = "android")))`. The other `cfg(not(target_os = "windows"))` blocks (`is_service_mode`, `run_as_service`, `ensure_tray_task` stub) work unchanged on Android — they are platform-agnostic POSIX code via `nix`.

3. **`crates/mrsh-server/src/shell.rs`** — `TIOCSCTTY` ioctl request type. Bionic libc takes `c_int` like musl (glibc/macOS take `c_ulong`). The existing `cfg(target_env = "musl")` gate was widened to `cfg(any(target_env = "musl", target_os = "android"))`.

4. **`crates/mrsh-core/src/config.rs`** — `load_enrollment` data dir. Termux has no writable `/etc`; on Android we use `dirs::home_dir().join(".config/mrsh")` (resolves to `/data/data/com.termux/files/home/.config/mrsh` under Termux). Falls back to `/data/local/tmp/mrsh` if HOME not set.

`crates/mrsh-server/src/exec.rs::build_command_with_shell` is unchanged — it spawns `"sh"` resolved via PATH, which under Termux finds `/data/data/com.termux/files/usr/bin/sh`.

The build-script `build.rs` already gated the Windows winres step on `CARGO_CFG_TARGET_OS == "windows"`, so it skips on Android automatically.

## Smoke-test plan (Phase 1, out of scope for rsh-9qrk Phase 0)

1. `mrsh push <built-binary> <hu>:~/.local/bin/mrsh` (via Termux SSH or adb push then `cp`).
2. `chmod +x ~/.local/bin/mrsh && ~/.local/bin/mrsh --version` (expect `1.10.29` or current).
3. `~/.local/bin/mrsh --daemon --port 8822` — start server on HU.
4. From workstation: `mrsh -h <hu-tailscale-ip> -p 8822 exec 'getprop ro.build.version.release'`.
5. `mrsh -h <hu> -p 8822 ss` — capture a screencap-based screenshot.
6. Install Termux:Boot APK on HU; create `~/.termux/boot/01-start-mrsh` per `install_service` Android no-op hint.
7. Reboot HU; verify mrsh listens on 8822 within ~30s of boot.
8. Enroll device on rdv: `~/.local/bin/mrsh enroll --rdv rendezvous.example.com --device-id <hu-id>`.

## Known platform diffs / caveats

- **No tray UI on Android** — `--tray` mode is Windows-only; the tray task scheduling code is gated by `cfg(target_os = "windows")` and won't compile in. The Android binary is server-only-with-CLI-tools.
- **No SCM** — Android has no Service Control Manager; `is_service_mode` returns `false`. mrsh on Android always runs as a "user daemon" via Termux:Boot.
- **No fleet `--install`** — `install_service` is a no-op + hint, not a real installer. Termux:Boot script is the canonical autostart.
- **screencap may need user permission** — On most automotive HUs `/system/bin/screencap` works for the user's own surface without root. If SELinux denies, screenshot returns "screencap produced empty output" with a clear error; user must enable a permissive context or run mrsh under shell uid via adb.
- **dynamic linker** — Binary is dynamically linked against Bionic (`/system/bin/linker64`), so it MUST run on real Android, not a stock Linux ARM box. For Linux ARM we'd build `aarch64-unknown-linux-musl` instead.

## Build host

- **builder** (LXC280 on pve-host, = `build.example.local` after the LXC103→builder consolidation, rsh-7xny). The old LXC103 (with its `/opt/android-sdk/ndk/...`) no longer exists.
- Cargo: `/home/user/.cargo/bin/cargo` (rustup-managed); `CARGO_TARGET_DIR=/path/to/build-cache/cargo-target` → android binary at `$CARGO_TARGET_DIR/aarch64-linux-android/release/mrsh`.
- NDK root: `~/android-ndk-r27/` (home-dir, no sudo). Re-provision if missing: `curl -fSL https://dl.google.com/android/repository/android-ndk-r27-linux.zip -o /tmp/ndk.zip && unzip -q /tmp/ndk.zip -d /tmp && mv /tmp/android-ndk-r27 ~/`.
- Source: `/home/user/mrsh/` (Forgejo `git fetch origin` works here, unlike the Mac).
- Build script reference: `.tmp/android-build.sh` in the remote-tools worktree (rsh-9qrk / 2026-06-05 v1.10.53 build).

## Tracking

- bd issue: `rsh-9qrk`
- Commit: see `git log --grep=rsh-9qrk` in this repo.
