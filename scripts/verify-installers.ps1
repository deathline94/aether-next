<#
.SYNOPSIS
    Verify every Windows binary that actually reaches a user, not just the outer
    installer.
.DESCRIPTION
    The step this replaces checked `Get-AuthenticodeSignature` on
    `AetherNext-windows-x64-setup.exe` alone and called that "all packaged Windows
    binaries verified". An outer signature says the file was signed when it was
    built; it says nothing about what the installer drops, because NSIS containers
    are not hash-sealed: `aether.exe`, `wintun.dll`, the GUI exe, the uninstaller
    and every plugin can be swapped afterwards while the outer signature still
    covers only its own bytes.

    So: extract, then check each binary on its own terms.
      - the unsigned engine must match the digest in packaging/trust/engine-trust.json,
        the same witness the running shell compares against;
      - wintun.dll must still carry its WireGuard LLC signature and pinned digest,
        which is also the proof that bundling did not strip or re-sign it;
      - the GUI exe must actually be present;
      - zero extractable binaries is a failure, not a pass. A gate that finds
        nothing to check has to say so, or it goes green on an empty set forever.
.EXAMPLE
    .\scripts\verify-installers.ps1 -Installer dist-windows\AetherNext-windows-x64-setup.exe `
        -Portable dist-windows\AetherNext-portable-windows-x64.zip `
        -Anchor packaging\trust\engine-trust.json
#>
[CmdletBinding()]
param(
    [string]$Installer,
    [string]$Portable,
    [string]$Anchor = "packaging/trust/engine-trust.json",
    # Validate an already-extracted tree. Used by the CI fixtures test and by anyone
    # reproducing a failure locally.
    [string]$Directory,
    [switch]$Development,
    [string]$DevEngineSha256 = "",
    [string]$EngineName = "aether.exe",
    [string]$DriverName = "wintun.dll",
    [string]$GuiNamePattern = "Aether*.exe"
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

function Get-AnchorDigest([string]$name) {
    if (-not (Test-Path $Anchor)) { throw "trust anchor $Anchor is missing" }
    $doc = Get-Content $Anchor -Raw | ConvertFrom-Json
    $entry = $doc.files | Where-Object { $_.name -eq $name }
    if (-not $entry) { throw "trust anchor has no entry for $name" }
    return $entry.file_sha256.ToLower()
}

function Find-Portable7z {
    foreach ($c in @("7z", "7za")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    foreach ($p in @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe")) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Expand-To([string]$package, [string]$dest) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    if ($package -like "*.zip") {
        Expand-Archive -Path $package -DestinationPath $dest -Force
        return
    }
    $seven = Find-Portable7z
    if (-not $seven) { throw "no 7-Zip found to extract $package; refusing to report success without inspecting it" }
    & $seven "x" "-y" "-o$dest" $package | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z failed ($LASTEXITCODE) on $package" }
}

function Get-PEFiles([string]$root) {
    # A PE is anything with the MZ header, not anything named .exe: the NSIS
    # payload hides the uninstaller and plugins under other extensions.
    Get-ChildItem -Path $root -Recurse -File | Where-Object {
        $_.Length -gt 2 -and $(
            $fs = [System.IO.File]::OpenRead($_.FullName)
            try { $b = New-Object byte[] 2; $fs.Read($b, 0, 2) | Out-Null; ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) }
            finally { $fs.Dispose() }
        )
    }
}

function Test-Signature([string]$path, [string]$expectCN) {
    $helper = Join-Path (Split-Path -Parent $PSCommandPath) "..\.github\scripts\sign-windows.ps1"
    try {
        & $helper -VerifyOnly -Path $path -ExpectedPublisherCN $expectCN | Out-Null
        return $null
    } catch {
        return $_.Exception.Message
    }
}

$targets = @()
$staging = $null
if ($Directory) {
    $targets += [pscustomobject]@{ Name = "directory"; Root = $Directory }
} else {
    if (-not $Installer -and -not $Portable) { throw "pass -Installer and/or -Portable, or -Directory" }
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) ("aether-verify-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $staging | Out-Null
    if ($Installer) {
        $d = Join-Path $staging "installer"
        Expand-To $Installer $d
        $targets += [pscustomobject]@{ Name = "installer"; Root = $d }
    }
    if ($Portable) {
        $d = Join-Path $staging "portable"
        Expand-To $Portable $d
        $targets += [pscustomobject]@{ Name = "portable"; Root = $d }
    }
}

try {
    if (-not $Development -and $DevEngineSha256) { throw "development verification inputs may not reach a release" }
    $anchorDoc = Get-Content $Anchor -Raw | ConvertFrom-Json
    $engineEntry = $anchorDoc.files | Where-Object { $_.name -eq $EngineName } | Select-Object -First 1
    if (-not $engineEntry) { throw "trust anchor has no entry for $EngineName" }
    $engineDigest = Get-AnchorDigest $EngineName
    $driverDigest = Get-AnchorDigest $DriverName
    $placeholder = "0" * 64
    $checkedAny = $false

    foreach ($t in $targets) {
        $pes = @(Get-PEFiles $t.Root)
        if ($pes.Count -eq 0) {
            $failures.Add("$($t.Name): extracted zero PE files from $($t.Root) - nothing was verified")
            continue
        }
        $checkedAny = $true
        Write-Host "$($t.Name): $($pes.Count) PE file(s) to verify"

        $engine = $pes | Where-Object { $_.Name -ieq $EngineName } | Select-Object -First 1
        if (-not $engine) {
            $failures.Add("$($t.Name): no $EngineName inside; the installer would launch an engine that was never packaged")
        } else {
            $hash = (Get-FileHash $engine.FullName -Algorithm SHA256).Hash.ToLower()
            if ($engineDigest -eq $placeholder -and -not $Development) {
                $failures.Add("$($t.Name): the anchor still carries a placeholder digest for $EngineName, so nothing can vouch for it (publish it first)")
            } elseif ($engineDigest -eq $placeholder) {
                if ($DevEngineSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $hash -ne $DevEngineSha256.ToLowerInvariant()) {
                    $failures.Add("$($t.Name): development engine digest $hash does not match the run's staged digest $DevEngineSha256")
                }
            } elseif ($hash -ne $engineDigest) {
                $failures.Add("$($t.Name): $EngineName is $hash but $Anchor says $engineDigest")
            }
        }

        $driver = $pes | Where-Object { $_.Name -ieq $DriverName } | Select-Object -First 1
        if (-not $driver) {
            $failures.Add("$($t.Name): no $DriverName inside")
        } else {
            $hash = (Get-FileHash $driver.FullName -Algorithm SHA256).Hash.ToLower()
            if ($hash -ne $driverDigest) {
                $failures.Add("$($t.Name): wintun.dll is $hash but $Anchor says $driverDigest")
            }
            # WireGuard's own signature must survive bundling: a re-signed or stripped
            # driver is a different trust story than the one the anchor describes.
            $problem = Test-Signature $driver.FullName "WireGuard LLC"
            if ($problem) { $failures.Add("$($t.Name): $problem") }
        }

        $guis = @($pes | Where-Object { $_.Name -like $GuiNamePattern -and $_.Name -ne $EngineName })
        if ($guis.Count -eq 0) { $failures.Add("$($t.Name): no desktop executable inside") }
    }

    if (-not $checkedAny) {
        $failures.Add("no package produced any files at all")
    }

    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Error -Message $f -ErrorAction Continue }
        Write-Host "verify-installers: $($failures.Count) problem(s)"
        exit 1
    }
    Write-Host "verify-installers: engine and driver digests match the anchor; driver signature is valid"
    exit 0
} finally {
    if ($staging -and (Test-Path $staging)) { Remove-Item -Recurse -Force $staging }
}
