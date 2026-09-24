$ErrorActionPreference = "Stop"
# scripts -> desktop -> apps -> Aether
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$res = Join-Path $PSScriptRoot "..\src-tauri\resources"
New-Item -ItemType Directory -Force -Path $res | Out-Null

$stagedEngine = Join-Path $res "aether.exe"
$witnessedEngine = Join-Path $root "witnessed-engine\aether.exe"
$builtEngine = Join-Path $root "aether\target\release\aether.exe"

$wintun = Join-Path $root "packaging\wintun.dll"
$stagedWintun = Join-Path $res "wintun.dll"

# Resolve engine binary:
# 1. Witnessed engine (from CI witness download)
# 2. Locally built release engine (development build)
# 3. Already staged engine (pre-staged / verified in resources)
$engine = if (Test-Path -LiteralPath $witnessedEngine -PathType Leaf) {
  $witnessedEngine
} elseif (Test-Path -LiteralPath $builtEngine -PathType Leaf) {
  $builtEngine
} elseif (Test-Path -LiteralPath $stagedEngine -PathType Leaf) {
  $stagedEngine
} else {
  $null
}

if (-not $engine) {
  throw "Missing aether.exe. Run cargo build --release in aether/"
}

# Guard: engine must not be same size as a mistaken GUI copy (sanity)
$engineSize = (Get-Item -LiteralPath $engine).Length
if ($engineSize -lt 1MB) { throw "aether.exe looks too small: $engineSize bytes" }

$resolvedEngine = (Resolve-Path -LiteralPath $engine).Path
$resolvedStagedEngine = (Resolve-Path -LiteralPath $stagedEngine -ErrorAction SilentlyContinue).Path

if ($resolvedEngine -ne $resolvedStagedEngine) {
  Copy-Item -LiteralPath $engine -Destination $stagedEngine -Force
  Write-Host "Staged $(Split-Path -Leaf $engine) -> src-tauri/resources/aether.exe ($([math]::Round($engineSize/1MB,1)) MB)"
} else {
  Write-Host "Using already staged src-tauri/resources/aether.exe ($([math]::Round($engineSize/1MB,1)) MB)"
}

if (Test-Path -LiteralPath $wintun -PathType Leaf) {
  $resolvedWintun = (Resolve-Path -LiteralPath $wintun).Path
  $resolvedStagedWintun = (Resolve-Path -LiteralPath $stagedWintun -ErrorAction SilentlyContinue).Path
  if ($resolvedWintun -ne $resolvedStagedWintun) {
    Copy-Item -LiteralPath $wintun -Destination $stagedWintun -Force
    Write-Host "Staged packaging/wintun.dll -> src-tauri/resources/wintun.dll"
  } else {
    Write-Host "Using already staged src-tauri/resources/wintun.dll"
  }
} elseif (Test-Path -LiteralPath $stagedWintun -PathType Leaf) {
  Write-Host "Using already staged src-tauri/resources/wintun.dll"
} else {
  throw "Missing packaging\wintun.dll"
}
