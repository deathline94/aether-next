#!/usr/bin/env bash
# Cross-compile aether engine for Android (arm64 + armv7) and stage into the APK jniLibs.
# Requires: Rust, Android NDK, cargo-ndk (optional) or rustup android targets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ENGINE="$ROOT/aether"
OUT_ARM64="$ROOT/apps/android/android/app/src/main/jniLibs/arm64-v8a"
OUT_ARM="$ROOT/apps/android/android/app/src/main/jniLibs/armeabi-v7a"
ASSETS="$ROOT/apps/android/android/app/src/main/assets/engine"

: "${ANDROID_NDK_HOME:=${NDK_HOME:-}}"
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
  echo "Set ANDROID_NDK_HOME to your NDK path"
  exit 1
fi

rustup target add aarch64-linux-android armv7-linux-androideabi 2>/dev/null || true

export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
# macOS host
if [[ "$(uname)" == "Darwin" ]]; then
  export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
fi
# Windows host (Git Bash)
if [[ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin" ]]; then
  export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin:$PATH"
fi

API=24
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android${API}-clang
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=armv7a-linux-androideabi${API}-clang
export CC_aarch64_linux_android=aarch64-linux-android${API}-clang
export CC_armv7_linux_androideabi=armv7a-linux-androideabi${API}-clang

cd "$ENGINE"

echo "==> building aarch64-linux-android"
cargo build --release --target aarch64-linux-android

echo "==> building armv7-linux-androideabi"
cargo build --release --target armv7-linux-androideabi || echo "armv7 build failed (optional)"

mkdir -p "$OUT_ARM64" "$OUT_ARM" "$ASSETS"
# jniLibs only packages lib*.so — ship as libaether.so + assets/engine/aether.
cp -f "$ENGINE/target/aarch64-linux-android/release/aether" "$OUT_ARM64/libaether.so"
cp -f "$ENGINE/target/aarch64-linux-android/release/aether" "$ASSETS/aether"
if [[ -f "$ENGINE/target/armv7-linux-androideabi/release/aether" ]]; then
  cp -f "$ENGINE/target/armv7-linux-androideabi/release/aether" "$OUT_ARM/libaether.so"
fi

chmod +x "$OUT_ARM64/libaether.so" "$ASSETS/aether" 2>/dev/null || true
echo "Staged engine binaries:"
ls -la "$OUT_ARM64" "$ASSETS"
