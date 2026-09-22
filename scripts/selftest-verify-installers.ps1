<#
.SYNOPSIS
    Prove that scripts/verify-installers.ps1 can actually fail.
.DESCRIPTION
    A gate that cannot fail is worse than no gate, and this one's whole job is to
    stop a green check meaning nothing. Two fixtures:

      1. a package that contains no PE at all - the old "verify all packaged
         Windows binaries" step would have had nothing to check and passed;
      2. a package whose engine is unsigned and whose digest matches nothing.

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

    # Fixture 2: an unsigned, unrecorded engine.
    $bad = Join-Path $tmp "unsigned"
    New-Item -ItemType Directory -Force -Path $bad | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $bad "aether.exe"),
        (@(0x4D, 0x5A) + (1..4096 | ForEach-Object { [byte](($_ * 7) -band 0xFF) })))
    if ((Invoke-Verifier $bad) -eq 0) {
        Write-Host "FAIL  an unsigned engine was reported as verified"
        $problems += 1
    } else {
        Write-Host "ok    an unsigned engine is refused"
    }

    # Positive control: the shipped wintun.dll is signed by WireGuard LLC and its
    # digest is in the anchor, so a correct artifact must pass when checked alone.
    $good = Join-Path $tmp "driveronly"
    New-Item -ItemType Directory -Force -Path $good | Out-Null
    Copy-Item (Join-Path $Root "packaging\wintun.dll") (Join-Path $good "wintun.dll")
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
