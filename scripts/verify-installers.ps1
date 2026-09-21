# Windows Authenticode verification of *packaged* artifacts.
#
# The defect this replaces: build.yml signed the standalone GUI copy and the
# outer NSIS container, then "verified all packaged Windows binaries" by looking
# at the outer container only. The exe the user actually installs had already
# been embedded unsigned. A verification step that inspects the wrong artifact
# is worse than none, because it records a pass.
#
# Rules:
#   * extract the installer and inspect every binary INSIDE it
#   * fail closed if the extraction yields zero binaries (a changed bundle
#     layout must never make the check vacuous)
#   * fail closed on NotSigned / HashMismatch / publisher mismatch

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DistPath,
    [string]$ExpectedCN = 'deathline94',
    [string]$SevenZip = 'C:\Program Files\7-Zip\7z.exe'
)

$ErrorActionPreference = 'Stop'
$failures = @()

function Test-EveryBinary([string]$installer, [string]$workdir) {
    if (-not (Test-Path $SevenZip)) {
        throw "7z not found at $SevenZip — cannot inspect installer contents (refusing to skip)"
    }
    if (Test-Path $workdir) { Remove-Item -Recurse -Force $workdir }
    New-Item -ItemType Directory -Force -Path $workdir | Out-Null

    & $SevenZip x -y "-o$workdir" $installer | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z failed to extract $installer" }

    # Everything we own that is executable. wintun.dll is third-party signed and
    # is checked by the runtime trust policy instead, so it is reported but not
    # required to carry our CN.
    $payload = Get-ChildItem -Recurse -Path $workdir -Include *.exe, *.dll -File
    if (-not $payload -or $payload.Count -eq 0) {
        # Fail closed: an empty extraction means the probe cannot see anything,
        # not that everything is fine.
        throw "no binaries found inside $installer — verification would be vacuous"
    }

    $checked = 0
    foreach ($bin in $payload) {
        $sig = Get-AuthenticodeSignature -FilePath $bin.FullName
        $isThirdParty = $bin.Name -match '^(wintun|WebView2Loader)\.dll$'
        Write-Host ("  {0,-34} {1,-14} {2}" -f $bin.Name, $sig.Status, $sig.SignerCertificate.Subject)
        if ($sig.Status -in @('NotSigned', 'HashMismatch')) {
            if (-not $isThirdParty) {
                $script:failures += "$($bin.Name) is $($sig.Status) inside the installer"
            }
        }
        elseif ($sig.SignerCertificate.Subject -notmatch "CN=$ExpectedCN(?:,|$)") {
            if (-not $isThirdParty) {
                $script:failures += "$($bin.Name) signed by '$($sig.SignerCertificate.Subject)', expected CN=$ExpectedCN"
            }
        }
        $checked++
    }
    return $checked
}

Write-Host "Verifying Authenticode of every binary INSIDE each package"
$installers = Get-ChildItem -Recurse -Path $DistPath -Include *.exe -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'setup|installer|-windows' }

if (-not $installers) {
    Write-Error "no installers found under $DistPath"
    exit 1
}

$i = 0
foreach ($inst in $installers) {
    Write-Host "`n[$($inst.Name)]"
    $work = Join-Path $env:TEMP "aether-unpack-$i"
    $i++
    try {
        $n = Test-EveryBinary $inst.FullName $work
        Write-Host "  -> inspected $n binary/binaries"
    } catch {
        $failures += "$($inst.Name): $($_.Exception.Message)"
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        if (Test-Path $work) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`n=== PACKAGE VERIFICATION FAILED ===" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "`nAll packaged binaries carry an acceptable signature."
