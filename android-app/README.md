# mrsh-android.apk

Self-contained Android wrapper for the `mrsh` server. Lets a phone (M20, HU,
future fleet phones) autostart `mrsh` at boot with **zero runtime dependency**
on Termux or mdp-updater.

bd parent: `rsh-b3ir`.

## What it does

- BootReceiver intercepts `BOOT_COMPLETED` and starts a foreground service.
- The foreground service spawns the embedded `libmrsh.so` (the same Rust mrsh
  binary, cross-compiled `aarch64-linux-android`, renamed to `lib*.so` and
  shipped in `jniLibs/arm64-v8a/`).
- The service supervises the child: on exit it restarts with exponential
  backoff (1s, 2s, 4s, 8s, cap 60s) — see C2 (`rsh-10qh`).
- Persistent low-priority notification keeps the OOM killer off our back.

mdp-updater is **only an initial install channel** — once the APK is on the
device, mrsh-android runs on its own. No Termux, no `~/.termux/boot/`, no
workstation-side scheduled keepalive.

## Capabilities (0.1.9+, the "absorption" wave)

After the absorb-A/B/C arc of `rsh-gz0z` (epic: "mrsh as single port to the
phone") the APK is self-sufficient for most fleet ops. The Termux SSH 8022
path is **LEGACY** — kept only as transitional fallback on devices that
predate 0.1.5 storage perms.

| Endpoint | Trigger | What it does | bd |
|----------|---------|--------------|----|
| Shell exec | `mrsh exec '<cmd>'` | Run command as `untrusted_app` uid | core |
| File transfer | `mrsh push /local /sdcard/<path>` + `mrsh pull` | Read/write /sdcard with MANAGE_EXTERNAL_STORAGE grant (one-time user grant on first launch) | rsh-viro (0.1.5) |
| Info UI | tap launcher icon | Show version, libmrsh.so, DeviceID, network, storage grant status, capability summary | rsh-w52b (0.1.6) |
| APK install | `mrsh exec 'am start --user 0 -a it.mdp.mrsh.INSTALL_APK --es apk /sdcard/Download/x.apk'` | PackageInstaller.Session → system Install dialog → user taps Install | rsh-ol1u (0.1.6) |
| Screencap | `mrsh exec 'am start --user 0 -a it.mdp.mrsh.SCREENCAP --es out /sdcard/Download/x.png'` | First call: MediaProjection consent dialog. Subsequent: silent capture via persistent ScreencapService. PNG saved at `out` path. | rsh-swxg (0.1.9) |

**No external programs.** All endpoints are pure Android framework calls
(MediaProjection / PackageInstaller / standard exec) — no Shizuku, no root,
no Termux, no ADB, no scrcpy, no third-party APKs.

### Self-update flow (Termux-free)

```bash
# Build + cross-compile produces app/build/outputs/apk/release/app-release.apk
# Then on operator side:
mrsh -h <phone-ip> push mrsh-android-x.y.z-release.apk /sdcard/Download/mrsh-android-x.y.z.apk
mrsh -h <phone-ip> exec 'am start --user 0 -a it.mdp.mrsh.INSTALL_APK --es apk /sdcard/Download/mrsh-android-x.y.z.apk'
# user taps Install on system PackageInstaller dialog
```

Dogfooded end-to-end on 2026-05-14 (M20): 0.1.6 → 0.1.7 → 0.1.8 → 0.1.9 all
self-installed via this flow, zero mdp-updater pushes after the 0.1.6
bootstrap.

### Limitations (still need Shizuku/root/MediaProjection-only)

| Need | Native to mrsh-android? | Why not |
|------|------------------------|---------|
| Silent APK install (no user tap) | NO | Android security requires user consent for non-system apps |
| dumpsys of other packages | NO | Needs `DUMP` permission (signature\|privileged) |
| input tap/swipe simulation | NO | Needs shell uid (Shizuku) or AccessibilityService (separate bd) |
| Force-stop other apps | NO | Needs `FORCE_STOP_PACKAGES` (signature\|privileged) |
| Read other apps' /data/data | NO | Needs root |

For those: see `rsh-a88j` (optional Shizuku SDK integration) — opt-in,
applicable only on phones where Shizuku service is bootstrappable (Android
11+ with Wireless Debugging, or pre-root device).

## Why `lib*.so` packaging

Starting with Android Q (API 29) anything inside `/data/data/<pkg>/files` is
non-executable by the runtime (W^X enforcement). The only path the system
keeps executable for an app is `nativeLibraryDir`, populated by the APK
installer from `jniLibs/<abi>/lib*.so`. Hence we ship the mrsh binary as
`libmrsh.so` even though it is a stand-alone ELF, not a JNI lib — the
installer treats it the same way.

## Layout

```
android-app/
├── build.gradle              ← AGP 8.1, root project
├── settings.gradle           ← include ':app'
├── gradle.properties         ← AndroidX, Xmx2g
└── app/
    ├── build.gradle          ← Java 8, minSdk 26 / target 29, arm64-v8a only
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/it/mdp/mrsh/
        │   ├── BootReceiver.java
        │   └── MrshService.java
        ├── res/
        │   ├── values/strings.xml
        │   └── drawable/ic_notification.xml
        └── jniLibs/arm64-v8a/
            └── (libmrsh.so — produced by C3, NOT committed)
```

## Build (C3 — `rsh-1ovl`)

The build is a two-step pipeline executed on `build.example.local` (LXC 103):

1. Cross-compile Rust mrsh for `aarch64-linux-android` (Phase 0 of `rsh-9qrk`,
   already shipped — see `docs/cross-compile-android.md`).
2. Copy the resulting binary to
   `android-app/app/src/main/jniLibs/arm64-v8a/libmrsh.so`, then
   `gradle assembleRelease`.

The wrapper script `scripts/build-android-apk.sh` lands in C3 and does both.

## Install

Pick whichever channel fits the target:

- `mdp-updater /api/push type=apk` — canonical fleet channel
- direct HTTP download + tap (e.g. via `/files/` static serve on
  `nexus.example.local:8443`)
- `adb install` if USB works on the target (M20 USB is broken, so no-go there)

After install, open the app once on the device to grant
`POST_NOTIFICATIONS` (Android 13+) and to exempt the app from battery
optimisation (one tap each in Settings).

## Verify

From any fleet host:

```bash
mrsh -h <target>.mdp server-version
```

Should return the embedded mrsh version (currently 1.10.29 — bumps with the
upstream binary).

## Config

`libmrsh.so` is launched with `--console -p 8822`. The configuration that mrsh
expects in `~/.mrsh/` (DeviceID, RendezvousServer, authorized_keys) lives in
the per-user dir under the Android app's data:
`/data/data/it.mdp.mrsh/files/.mrsh/`. A first-boot bootstrap will
auto-generate `id_ed25519` and seed `config` with a per-device DeviceID derived
from `Settings.Secure.ANDROID_ID` — lands in C2.

To inject authorized keys at install time (e.g. workstation pubkey), either:

- pre-seed the file via `mdp-updater /api/push type=command` post-install, or
- bake it into the APK at build time via `BuildConfig` (future
  enhancement, NOT in scope for v0.1.0).

## Cross-links

- Parent feature: `rsh-b3ir`
- Children: `rsh-he1b` (C1 — this), `rsh-10qh` (C2 — supervise loop),
  `rsh-1ovl` (C3 — build script), `rsh-8a8h` (C4 — M20 deploy test),
  `rsh-eiyr` (C5 — HU migration), `rsh-wbku` (C6 — Termux cleanup)
- Related solved: `2026-05-04-002` (HU Runtime.exec daemonize impossibility —
  this APK is the proper fix)
