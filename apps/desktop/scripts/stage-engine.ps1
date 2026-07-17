$ErrorActionPreference = "Stop"
# scripts -> desktop -> apps -> Aether
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$res = Join-Path $PSScriptRoot "..\src-tauri\resources"
New-Item -ItemType Directory -Force -Path $res | Out-Null

$engine = Join-Path $root "aether\target\release\aether.exe"
$wintun = Join-Path $root "packaging\wintun.dll"
if (-not (Test-Path $engine)) {
  throw "Missing aether.exe. Run cargo build --release in aether/"
}
if (-not (Test-Path $wintun)) {
  throw "Missing packaging\wintun.dll"
}
# Guard: engine must not be same size as a mistaken GUI copy (sanity)
$engineSize = (Get-Item $engine).Length
if ($engineSize -lt 1MB) { throw "aether.exe looks too small: $engineSize bytes" }
Copy-Item $engine -Destination (Join-Path $res "aether.exe") -Force
Copy-Item $wintun -Destination (Join-Path $res "wintun.dll") -Force
Write-Host "Staged aether.exe ($([math]::Round($engineSize/1MB,1)) MB) + wintun.dll into src-tauri/resources"
