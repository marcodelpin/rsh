#!/usr/bin/env bash
#
# build-android-apk.sh — build mrsh-android.apk on build.example.local
#
# Cross-compiles the Rust mrsh server for aarch64-linux-android, drops the
# binary into android-app/.../jniLibs/arm64-v8a/libmrsh.so, then runs
# gradle assembleRelease (or assembleDebug) to produce the final APK.
#
# Designed to run ON build.example.local (LXC 103) where Android SDK + NDK +
# Rust toolchain are already installed. Calling it from workstation:
#
#     ssh user@build.example.local 'cd ~/mrsh && git pull && scripts/build-android-apk.sh'
#
# bd: rsh-1ovl (parent rsh-b3ir).

set -euo pipefail

MODE="release"
SKIP_RUST=0
OUTPUT_DIR="${PWD}/deploy"

usage() {
  cat <<EOF
Usage: $0 [--debug|--release] [--skip-rust] [--output DIR]

Options:
  --debug         build debug APK (default: release)
  --release       build release APK (default)
  --skip-rust     reuse existing target/aarch64-linux-android/release/mrsh
                  (useful when only the Java code changed)
  --output DIR    where to copy the final APK (default: ./deploy)
  -h, --help      this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug) MODE=debug; shift ;;
    --release) MODE=release; shift ;;
    --skip-rust) SKIP_RUST=1; shift ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ANDROID_APP_DIR="$REPO_ROOT/android-app"
JNI_OUT="$ANDROID_APP_DIR/app/src/main/jniLibs/arm64-v8a/libmrsh.so"
RUST_OUT="$REPO_ROOT/target/aarch64-linux-android/release/mrsh"
# 32-bit ARM target — for older devices like Galaxy Note 3 (hlte) on
# LineageOS 18.1 (rsh-a88j F3 enable). Builds in parallel with arm64.
JNI_OUT_V7="$ANDROID_APP_DIR/app/src/main/jniLibs/armeabi-v7a/libmrsh.so"
RUST_OUT_V7="$REPO_ROOT/target/armv7-linux-androideabi/release/mrsh"

# Android SDK + NDK (auto-discover latest NDK)
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
NDK_BASE="$ANDROID_HOME/ndk"
NDK_VER="$(ls -1 "$NDK_BASE" 2>/dev/null | sort -V | tail -1 || true)"
if [[ -z "$NDK_VER" ]]; then
  echo "ERROR: no Android NDK found under $NDK_BASE" >&2
  exit 1
fi
NDK_TOOLCHAIN="$NDK_BASE/$NDK_VER/toolchains/llvm/prebuilt/linux-x86_64/bin"
export ANDROID_NDK_HOME="$NDK_BASE/$NDK_VER"

echo "==> ANDROID_HOME: $ANDROID_HOME"
echo "==> NDK: $NDK_VER"
echo "==> Repo: $REPO_ROOT"
echo "==> Mode: $MODE"

# ── Phase 1: cross-compile mrsh for both Android ABIs ───────────────────────
if [[ "$SKIP_RUST" -eq 0 ]]; then
  echo "==> Phase 1a: cargo build --release --target aarch64-linux-android"

  export PATH="$HOME/.cargo/bin:$NDK_TOOLCHAIN:$PATH"
  export CC_aarch64_linux_android="aarch64-linux-android33-clang"
  export CXX_aarch64_linux_android="aarch64-linux-android33-clang++"
  export AR_aarch64_linux_android="llvm-ar"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="aarch64-linux-android33-clang"

  rustup target add aarch64-linux-android >/dev/null 2>&1 || true
  cargo build --release --target aarch64-linux-android

  if [[ ! -f "$RUST_OUT" ]]; then
    echo "ERROR: cargo did not produce $RUST_OUT" >&2
    exit 1
  fi

  echo "==> Phase 1b: cargo build --release --target armv7-linux-androideabi (rsh-a88j F3)"
  # 32-bit ARM target. NDK convention uses prefix armv7a-... (note the 'a').
  export CC_armv7_linux_androideabi="armv7a-linux-androideabi33-clang"
  export CXX_armv7_linux_androideabi="armv7a-linux-androideabi33-clang++"
  export AR_armv7_linux_androideabi="llvm-ar"
  export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="armv7a-linux-androideabi33-clang"

  rustup target add armv7-linux-androideabi >/dev/null 2>&1 || true
  cargo build --release --target armv7-linux-androideabi

  if [[ ! -f "$RUST_OUT_V7" ]]; then
    echo "ERROR: cargo did not produce $RUST_OUT_V7" >&2
    exit 1
  fi
else
  echo "==> Phase 1: SKIPPED (--skip-rust)"
  if [[ ! -f "$RUST_OUT" ]]; then
    echo "ERROR: --skip-rust set but no prior build at $RUST_OUT" >&2
    exit 1
  fi
  if [[ ! -f "$RUST_OUT_V7" ]]; then
    echo "ERROR: --skip-rust set but no prior build at $RUST_OUT_V7" >&2
    exit 1
  fi
fi

# ── Phase 2: place libmrsh.so in jniLibs/ ────────────────────────────────────
echo "==> Phase 2a: stage libmrsh.so arm64-v8a ($(du -h "$RUST_OUT" | cut -f1))"
mkdir -p "$(dirname "$JNI_OUT")"
cp -f "$RUST_OUT" "$JNI_OUT"
chmod 0755 "$JNI_OUT"
b3sum "$JNI_OUT" 2>/dev/null || sha256sum "$JNI_OUT"

echo "==> Phase 2b: stage libmrsh.so armeabi-v7a ($(du -h "$RUST_OUT_V7" | cut -f1))"
mkdir -p "$(dirname "$JNI_OUT_V7")"
cp -f "$RUST_OUT_V7" "$JNI_OUT_V7"
chmod 0755 "$JNI_OUT_V7"
b3sum "$JNI_OUT_V7" 2>/dev/null || sha256sum "$JNI_OUT_V7"

# ── Phase 3: gradle build ────────────────────────────────────────────────────
echo "==> Phase 3: gradle assemble$([ "$MODE" = release ] && echo Release || echo Debug)"
cd "$ANDROID_APP_DIR"

# First run: generate wrapper if absent
if [[ ! -x ./gradlew ]]; then
  gradle wrapper --gradle-version 8.10.2 >/dev/null 2>&1 || true
fi

if [[ -x ./gradlew ]]; then
  ./gradlew "assemble${MODE^}" --no-daemon
else
  gradle "assemble${MODE^}" --no-daemon
fi

# ── Phase 4: copy APK out ────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
APK_SRC="$ANDROID_APP_DIR/app/build/outputs/apk/$MODE/app-$MODE.apk"
if [[ ! -f "$APK_SRC" ]]; then
  echo "ERROR: gradle did not produce $APK_SRC" >&2
  exit 1
fi
VERSION_NAME="$(awk -F'"' '/versionName/ {print $2; exit}' app/build.gradle)"
OUT="$OUTPUT_DIR/mrsh-android-${VERSION_NAME}-${MODE}.apk"
cp -f "$APK_SRC" "$OUT"
echo "==> APK ready: $OUT"
b3sum "$OUT" 2>/dev/null || sha256sum "$OUT"
du -h "$OUT" | cut -f1
