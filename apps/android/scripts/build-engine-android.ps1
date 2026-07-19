# Cross-compile aether for all advertised Android ABIs and stage into the APK.
# Requires: Rust, Android NDK, CMake, Ninja, Go, Git.
# Set $env:ANDROID_NDK_HOME (e.g. C:\Android\android-sdk\ndk\27.3.13750724)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Engine = Join-Path $Root "aether"
$JniRoot = Join-Path $Root "apps\android\android\app\src\main\jniLibs"
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

$targets = @(
  @{ Triple = "aarch64-linux-android"; Abi = "arm64-v8a"; Linker = "aarch64-linux-android$api-clang" },
  @{ Triple = "armv7-linux-androideabi"; Abi = "armeabi-v7a"; Linker = "armv7a-linux-androideabi$api-clang" },
  @{ Triple = "x86_64-linux-android"; Abi = "x86_64"; Linker = "x86_64-linux-android$api-clang" }
)

function Resolve-Linker([string]$base) {
  $cmd = Join-Path $prebuilt "$base.cmd"
  if (Test-Path $cmd) { return "$base.cmd" }
  $plain = Join-Path $prebuilt $base
  if (Test-Path $plain) { return $base }
  throw "Linker not found: $base"
}

if (-not $env:CMAKE_GENERATOR) { $env:CMAKE_GENERATOR = "Ninja" }
$cargoDir = Join-Path $Engine ".cargo"
New-Item -ItemType Directory -Force -Path $cargoDir | Out-Null
$ndkEsc = $env:ANDROID_NDK_HOME -replace '\\', '\\'

$cargoConfig = @()
foreach ($t in $targets) {
  $linker = Resolve-Linker $t.Linker
  $envName = ("CARGO_TARGET_{0}_LINKER" -f ($t.Triple.ToUpper().Replace('-', '_')))
  Set-Item -Path "Env:$envName" -Value $linker
  rustup target add $t.Triple | Out-Null
  $cargoConfig += @"
[target.$($t.Triple)]
linker = "$linker"
ar = "llvm-ar.exe"
"@
}
$cargoConfig += @"

[env]
ANDROID_NDK_HOME = { value = "$ndkEsc", force = true }
CMAKE_GENERATOR = { value = "Ninja", force = true }
ANDROID_PLATFORM = { value = "android-$api", force = true }
ANDROID_NATIVE_API_LEVEL = { value = "$api", force = true }
"@
$cargoConfig -join "`n" | Set-Content (Join-Path $cargoDir "config.toml") -Encoding UTF8

New-Item -ItemType Directory -Force -Path $Assets | Out-Null
$primary = $null
foreach ($t in $targets) {
  $env:ANDROID_ABI = $t.Abi
  Write-Host "==> building $($t.Triple) ($($t.Abi))"
  Push-Location $Engine
  cargo build --release --target $t.Triple
  if ($LASTEXITCODE -ne 0) {
    Pop-Location
    throw "Build failed for $($t.Triple)"
  }
  Pop-Location

  $bin = Join-Path $Engine "target\$($t.Triple)\release\aether"
  if (-not (Test-Path $bin)) { $bin = "$bin.exe" }
  if (-not (Test-Path $bin)) {
    throw "Built binary missing for $($t.Triple)"
  }
  $outDir = Join-Path $JniRoot $t.Abi
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
  Copy-Item -Force $bin (Join-Path $outDir "libaether.so")
  if ($t.Abi -eq "arm64-v8a") {
    Copy-Item -Force $bin (Join-Path $Assets "aether")
    $primary = Join-Path $outDir "libaether.so"
  }
  Write-Host "Staged $($t.Abi)/libaether.so"
}

# Fail closed if any advertised ABI payload is missing.
foreach ($t in $targets) {
  $so = Join-Path $JniRoot "$($t.Abi)\libaether.so"
  if (-not (Test-Path $so) -or (Get-Item $so).Length -le 0) {
    throw "Missing payload: $so"
  }
}
if (-not $primary -or -not (Test-Path $primary)) {
  throw "arm64 primary engine missing"
}
Write-Host "All Android engine ABIs staged."
Get-ChildItem -Recurse $JniRoot -Filter libaether.so | Format-Table FullName, Length
