#!/usr/bin/env bash
# Cross-compile aether engine for all advertised Android ABIs and stage into jniLibs.
# Requires: Rust, Android NDK. Fails if any ABI build is missing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ENGINE="$ROOT/aether"
JNI_ROOT="$ROOT/apps/android/android/app/src/main/jniLibs"
ASSETS="$ROOT/apps/android/android/app/src/main/assets/engine"

: "${ANDROID_NDK_HOME:=${NDK_HOME:-}}"
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
  echo "Set ANDROID_NDK_HOME to your NDK path"
  exit 1
fi

export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
if [[ "$(uname)" == "Darwin" ]]; then
  export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
fi
if [[ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin" ]]; then
  export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin:$PATH"
fi

API=26
declare -a TRIPLES=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android)
declare -a ABIS=(arm64-v8a armeabi-v7a x86_64)
declare -a LINKERS=(
  "aarch64-linux-android${API}-clang"
  "armv7a-linux-androideabi${API}-clang"
  "x86_64-linux-android${API}-clang"
)

for t in "${TRIPLES[@]}"; do
  rustup target add "$t" 2>/dev/null || true
done

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${LINKERS[0]}"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${LINKERS[1]}"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${LINKERS[2]}"
export CC_aarch64_linux_android="${LINKERS[0]}"
export CC_armv7_linux_androideabi="${LINKERS[1]}"
export CC_x86_64_linux_android="${LINKERS[2]}"

cd "$ENGINE"
mkdir -p "$ASSETS"

for i in "${!TRIPLES[@]}"; do
  triple="${TRIPLES[$i]}"
  abi="${ABIS[$i]}"
  echo "==> building $triple ($abi)"
  cargo build --release --target "$triple"
  src="$ENGINE/target/$triple/release/aether"
  if [[ ! -f "$src" ]]; then
    echo "missing binary for $triple"
    exit 1
  fi
  out="$JNI_ROOT/$abi"
  mkdir -p "$out"
  cp -f "$src" "$out/libaether.so"
  if [[ "$abi" == "arm64-v8a" ]]; then
    cp -f "$src" "$ASSETS/aether"
  fi
done

for abi in "${ABIS[@]}"; do
  so="$JNI_ROOT/$abi/libaether.so"
  if [[ ! -s "$so" ]]; then
    echo "missing payload: $so"
    exit 1
  fi
done

chmod +x "$ASSETS/aether" 2>/dev/null || true
echo "Staged all Android engine ABIs:"
find "$JNI_ROOT" -name 'libaether.so' -printf '%p %s\n'
