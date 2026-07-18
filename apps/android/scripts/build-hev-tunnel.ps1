# Build hev-socks5-tunnel shared libraries for Android ABIs and install into jniLibs.
# Requires: git, Android NDK (ANDROID_NDK_HOME or default under %LOCALAPPDATA%\Android\Sdk\ndk).
# Usage: powershell -File apps/android/scripts/build-hev-tunnel.ps1

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$src = Join-Path $root "third_party\hev-socks5-tunnel"
$jni = Join-Path $root "apps\android\android\app\src\main\jniLibs"
$tag = if ($env:HEV_TAG) { $env:HEV_TAG } else { "2.16.0" }

$ndk = $env:ANDROID_NDK_HOME
if (-not $ndk -or -not (Test-Path $ndk)) {
    $candidates = @(
        "$env:LOCALAPPDATA\Android\Sdk\ndk",
        "C:\Android\android-sdk\ndk",
        "$env:ANDROID_HOME\ndk"
    ) | Where-Object { $_ -and (Test-Path $_) }
    foreach ($c in $candidates) {
        $latest = Get-ChildItem $c -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) { $ndk = $latest.FullName; break }
    }
}
if (-not $ndk -or -not (Test-Path (Join-Path $ndk "ndk-build.cmd"))) {
    throw "Android NDK not found. Set ANDROID_NDK_HOME."
}

if (-not (Test-Path $src)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $src) | Out-Null
    git clone --recursive --branch $tag "https://github.com/heiher/hev-socks5-tunnel.git" $src
} else {
    Push-Location $src
    git fetch --tags
    git checkout $tag
    git submodule update --init --recursive
    Pop-Location
}

@"
APP_OPTIM := release
APP_PLATFORM := android-26
APP_ABI := armeabi-v7a arm64-v8a x86_64
APP_CFLAGS := -O3 -DPKGNAME=app/aethernext -DCLSNAME=AetherVpnService
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
NDK_TOOLCHAIN_VERSION := clang
"@ | Set-Content -Path (Join-Path $src "Application.mk") -Encoding ASCII

Write-Host "Building hev-socks5-tunnel with NDK: $ndk"
& (Join-Path $ndk "ndk-build.cmd") `
    "NDK_PROJECT_PATH=$src" `
    "APP_BUILD_SCRIPT=$src\Android.mk" `
    "NDK_APPLICATION_MK=$src\Application.mk" `
    "NDK_LIBS_OUT=$src\libs" `
    "NDK_OUT=$src\obj" `
    -j4

foreach ($abi in @("arm64-v8a", "armeabi-v7a", "x86_64")) {
    $from = Join-Path $src "libs\$abi\libhev-socks5-tunnel.so"
    $toDir = Join-Path $jni $abi
    New-Item -ItemType Directory -Force -Path $toDir | Out-Null
    Copy-Item $from (Join-Path $toDir "libhev-socks5-tunnel.so") -Force
    Write-Host "Installed $abi libhev-socks5-tunnel.so"
}

Write-Host "Done."
