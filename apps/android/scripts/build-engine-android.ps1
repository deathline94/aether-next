# Cross-compile aether for Android and stage into the APK.
# Requires: Rust, Android NDK, CMake, Ninja, Go, Git.
# Set $env:ANDROID_NDK_HOME (e.g. C:\Android\android-sdk\ndk\27.3.13750724)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Engine = Join-Path $Root "aether"
$OutArm64 = Join-Path $Root "apps\android\android\app\src\main\jniLibs\arm64-v8a"
$Assets = Join-Path $Root "apps\android\android\app\src\main\assets\engine"

if (-not $env:ANDROID_NDK_HOME) {
  Write-Error "Set ANDROID_NDK_HOME to your NDK root"
}

$prebuilt = Join-Path $env:ANDROID_NDK_HOME "toolchains\llvm\prebuilt\windows-x86_64\bin"
if (-not (Test-Path $prebuilt)) {
  Write-Error "NDK prebuilt bin not found: $prebuilt"
}
$env:Path = "$prebuilt;$env:Path"
$api = 26
$linker = "aarch64-linux-android$api-clang.cmd"
if (-not (Test-Path (Join-Path $prebuilt $linker))) {
  $linker = "aarch64-linux-android$api-clang"
}
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $linker

# BoringSSL / cmake-rs on Windows: use Ninja + skip broken host try-compile links.
if (-not $env:CMAKE_GENERATOR) { $env:CMAKE_GENERATOR = "Ninja" }
$env:ANDROID_ABI = "arm64-v8a"
$env:ANDROID_PLATFORM = "android-$api"
$env:ANDROID_NATIVE_API_LEVEL = "$api"

# Project-local cargo config for the Android target
$cargoDir = Join-Path $Engine ".cargo"
New-Item -ItemType Directory -Force -Path $cargoDir | Out-Null
$ndkEsc = $env:ANDROID_NDK_HOME -replace '\\', '\\'
@"
[target.aarch64-linux-android]
linker = "$linker"
ar = "llvm-ar.exe"

[env]
ANDROID_NDK_HOME = { value = "$ndkEsc", force = true }
CMAKE_GENERATOR = { value = "Ninja", force = true }
ANDROID_ABI = { value = "arm64-v8a", force = true }
ANDROID_PLATFORM = { value = "android-$api", force = true }
ANDROID_NATIVE_API_LEVEL = { value = "$api", force = true }
"@ | Set-Content (Join-Path $cargoDir "config.toml") -Encoding UTF8

rustup target add aarch64-linux-android | Out-Null
Push-Location $Engine
cargo build --release --target aarch64-linux-android
Pop-Location

New-Item -ItemType Directory -Force -Path $OutArm64, $Assets | Out-Null
$bin = Join-Path $Engine "target\aarch64-linux-android\release\aether"
if (-not (Test-Path $bin)) { $bin = "$bin.exe" }
if (-not (Test-Path $bin)) {
  Write-Error "Built binary not found under $Engine\target\aarch64-linux-android\release\"
}
# jniLibs only packages lib*.so — ship as libaether.so and also as assets/engine/aether.
Copy-Item -Force $bin (Join-Path $OutArm64 "libaether.so")
Copy-Item -Force $bin (Join-Path $Assets "aether")
Write-Host "Staged: $OutArm64\libaether.so and $Assets\aether"
Get-Item (Join-Path $OutArm64 "libaether.so"), (Join-Path $Assets "aether") | Format-Table Name, Length
