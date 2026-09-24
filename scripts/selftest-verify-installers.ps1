<#
.SYNOPSIS
    Prove that scripts/verify-installers.ps1 can actually fail.
.DESCRIPTION
    A gate that cannot fail is worse than no gate, and this one's whole job is to
    stop a green check meaning nothing. Two fixtures:

      1. a package that contains no PE at all - the old "verify all packaged
         Windows binaries" step would have had nothing to check and passed;
      2. a package whose engine digest matches nothing.

    Each must exit non-zero. A third case asserts the positive control is
    reachable, so a script that always returns 1 (a broken call, a thrown
    exception) is not mistaken for a working gate: the real, signed wintun.dll
    that ships in this repository must verify cleanly on its own terms.
#>
[CmdletBinding()]
param(
    # Empty means "the repository this script lives in"; resolved below because
    # $PSScriptRoot is not available while parameter defaults are being evaluated.
    [string]$Root = ""
)

$ErrorActionPreference = "Stop"
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath) }
$verifier = Join-Path $Root "scripts\verify-installers.ps1"
$anchor = Join-Path $Root "packaging\trust\engine-trust.json"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("aether-verifier-selftest-" + [Guid]::NewGuid().ToString("N"))
$problems = 0

function Invoke-Verifier([string]$dir) {
    & $verifier -Directory $dir -Anchor $anchor 2>&1 | Out-String | Write-Host
    return $LASTEXITCODE
}

try {
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    # Fixture 1: nothing extractable.
    $empty = Join-Path $tmp "empty"
    New-Item -ItemType Directory -Force -Path $empty | Out-Null
    if ((Invoke-Verifier $empty) -eq 0) {
        Write-Host "FAIL  an empty package was reported as verified"
        $problems += 1
    } else {
        Write-Host "ok    an empty package is refused"
    }

    # Fixture 2: an unrecorded engine.
    $bad = Join-Path $tmp "unrecorded"
    New-Item -ItemType Directory -Force -Path $bad | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $bad "aether.exe"),
        (@(0x4D, 0x5A) + (1..4096 | ForEach-Object { [byte](($_ * 7) -band 0xFF) })))
    if ((Invoke-Verifier $bad) -eq 0) {
        Write-Host "FAIL  an unrecorded engine was reported as verified"
        $problems += 1
    } else {
        Write-Host "ok    an unrecorded engine is refused"
    }

    # Positive control: an unsigned engine with a reviewed digest, a desktop
    # executable, and the vendor-signed driver must pass together.
    $good = Join-Path $tmp "complete"
    New-Item -ItemType Directory -Force -Path $good | Out-Null
    Copy-Item (Join-Path $bad "aether.exe") (Join-Path $good "aether.exe")
    Copy-Item (Join-Path $bad "aether.exe") (Join-Path $good "AetherNext-Desktop.exe")
    Copy-Item (Join-Path $Root "packaging\wintun.dll") (Join-Path $good "wintun.dll")
    $fixtureAnchor = Join-Path $tmp "engine-trust.json"
    $fixture = Get-Content $anchor -Raw | ConvertFrom-Json
    ($fixture.files | Where-Object { $_.name -eq 'aether.exe' }).file_sha256 =
      (Get-FileHash (Join-Path $good 'aether.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture | ConvertTo-Json -Depth 10 | Set-Content $fixtureAnchor
    & $verifier -Directory $good -Anchor $fixtureAnchor 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL  a complete unsigned package was refused"
        $problems += 1
    } else {
        Write-Host "ok    a complete unsigned package verifies"
    }

    # The real driver certificate still has to verify on the host.
    $sig = Get-AuthenticodeSignature (Join-Path $good "wintun.dll")
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "WireGuard LLC") {
        Write-Host "FAIL  the committed wintun.dll no longer verifies: $($sig.Status) / $($sig.StatusMessage)"
        $problems += 1
    } else {
        Write-Host "ok    the committed wintun.dll verifies as the positive control"
    }

    if ($problems -gt 0) {
        Write-Host "verify-installers self-test: $problems problem(s)"
        exit 1
    }
    Write-Host "verify-installers self-test passed"
    exit 0
} finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
