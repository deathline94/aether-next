# Tests for .github/scripts/sign-windows.ps1 - the one rule every Windows
# artifact passes through on its way out of this repository.
#
# What is actually being proved here, on a machine with no code-signing
# certificate: a self-signed certificate is a *development* affordance, so it has
# to be named as one (-DevEphemeral). Before this, the helper accepted a
# `NotTrusted` verdict whenever the signer was the certificate the same run had
# minted - which is how a package no clean machine can verify ended up published
# as a download. These cases fail if that leniency comes back through any door:
#
#   1  signing without -DevEphemeral is refused for a self-signed certificate
#   2  signing with -DevEphemeral works, and says so
#   3  -VerifyOnly accepts the dev-signed file only with -DevEphemeral + thumbprint
#   4  -VerifyOnly refuses the same file without it (the distributable rule)
#   5  a wrong -ExpectedCertSha256 pin is refused
#   6  the right pin is accepted
#   7  a publisher CN that is not the anchor's is refused
#
# The remaining property - a certificate that chains to a trusted root yields
# `Valid` and needs no licence - cannot be exercised without such a certificate,
# and is stated as unverified rather than assumed.
#
# Run:  powershell -NoProfile -File .github/scripts/test-sign-windows.ps1
[CmdletBinding()]
param(
    [string]$HelperPath,
    # A PE to sign. Defaults to a small system binary, copied to a temp directory:
    # nothing in the repository is touched, and the signature lands on the copy.
    [string]$SubjectPath
)

$ErrorActionPreference = 'Stop'
$pass = 0
$fail = 0

function Ok([string]$m) { $script:pass++; Write-Host "  ok   $m" }
function No([string]$m) { $script:fail++; Write-Host "  FAIL $m" }

# A refusal is only the expected one if it names the rule under test: a helper
# that throws for an unrelated reason (a missing file, a bad parameter) would
# otherwise make the case look proved.
function Assert-Refused {
    param($Result, [string]$Because, [string]$WhenOk)
    if (-not $Result.Refused) { No "$WhenOk - it did not refuse, and that is the defect: $($Result.Text)" }
    elseif ($Result.Text -match $Because) { Ok $WhenOk }
    else { No "refused, but for a reason that is not the rule under test ($Because): $($Result.Text)" }
}

# Run the helper and report both its prose and whether it refused, so a `throw`
# inside it is data for an expectation instead of an accident that ends the test.
function Invoke-Helper {
    param([hashtable]$Parameters)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = ''
        $refused = $false
        try {
            # 2>&1 and 6>&1 so the helper's Write-Host prose is data here too; a
            # refusal is still detected by the catch, not by parsing that prose.
            $text = (& $script:HelperPath @Parameters 2>&1 6>&1 | Out-String)
        } catch {
            $refused = $true
            $text += $_.Exception.Message
        }
        # sign-windows.ps1 signals refusal by throwing, never by `exit N`, so
        # $LASTEXITCODE is not consulted: a stale value from an earlier command
        # would report a refusal that did not happen.
        [pscustomobject]@{ Text = $text.Trim(); Refused = $refused }
    } finally {
        $ErrorActionPreference = $saved
    }
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $HelperPath) { $HelperPath = Join-Path $here 'sign-windows.ps1' }
if (-not (Test-Path -LiteralPath $HelperPath)) { throw "no helper at $HelperPath" }
$cn = 'aether-sign-windows-selftest'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('aether-sign-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$certPath = $null

try {
    $root = Resolve-Path (Join-Path $here '..\..')
    if (-not $SubjectPath) {
        # An *unsigned* PE. A system binary is no use: it already carries a
        # vendor signature, and re-signing a protected file leaves the original
        # signer in place, which tests nothing about this helper.
        $SubjectPath = @(
            (Join-Path $root 'aether/target/release/aether.exe'),
            (Join-Path $root 'apps/desktop/src-tauri/target/release/aether.exe')
        ) + @(Get-ChildItem (Join-Path $root 'apps/desktop/src-tauri/target/debug/deps/*.exe') `
            -ErrorAction SilentlyContinue | ForEach-Object FullName) |
          Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if (-not $SubjectPath) {
        # CI runs this rule before the engine build. Compile a tiny unsigned
        # managed PE here so the test has no dependency on build order. A
        # library PE with an .exe name is sufficient for Authenticode checks.
        $fixture = Join-Path $tmp 'unsigned-fixture.exe'
        Add-Type -TypeDefinition 'public static class AetherSigningFixture { public static void Marker() {} }' `
            -OutputAssembly $fixture -OutputType Library
        $SubjectPath = $fixture
    }
    $subject = Join-Path $tmp 'subject.exe'
    Copy-Item -LiteralPath $SubjectPath -Destination $subject -Force
    $before = Get-AuthenticodeSignature -LiteralPath $subject
    if ($before.Status -ne 'NotSigned') {
        throw "fixture subject $SubjectPath is already signed by $($before.SignerCertificate.Subject); this test must start from an unsigned PE"
    }

    $cert = New-SelfSignedCertificate -Subject "CN=$cn" -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Type Custom -KeyUsage DigitalSignature `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') `
        -NotAfter (Get-Date).AddDays(1)
    $certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
    Write-Host "fixture certificate: $($cert.Subject) [$($cert.Thumbprint)] (self-signed, removed at exit)"

    $leaf = ([BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
    ) -replace '-', '').ToLowerInvariant()

    # ── 1: a run-local certificate is not a signing identity by itself ───────
    $r = Invoke-Helper @{ Thumbprint = $cert.Thumbprint; Path = $subject; ExpectedPublisherCN = $cn }
    Assert-Refused -Result $r -Because 'self-signed' `
        -WhenOk 'refuses to sign a distributable artifact with a self-signed certificate'

    # ── 2: it does sign when told, and the result stays unverifiable elsewhere ─
    $r = Invoke-Helper @{
        Thumbprint = $cert.Thumbprint; Path = $subject; ExpectedPublisherCN = $cn; DevEphemeral = $true
    }
    if ($r.Refused) { No "-DevEphemeral signing failed: $($r.Text)" }
    else { Ok '-DevEphemeral signs the file, and only when it is named' }

    $sig = Get-AuthenticodeSignature -LiteralPath $subject
    if ($sig.Status -ne 'Valid' -and $sig.SignerCertificate.Thumbprint -eq $cert.Thumbprint) {
        Ok "the result is '$($sig.Status)', not 'Valid' - which is what a clean machine reports for the same bytes"
    } else {
        No "the development signature reports '$($sig.Status)' from $($sig.SignerCertificate.Subject)"
    }

    # ── 3/4: the development verify is not the distributable verify ─────────
    $r = Invoke-Helper @{
        VerifyOnly = $true; Path = $subject; Thumbprint = $cert.Thumbprint; DevEphemeral = $true;
        ExpectedPublisherCN = $cn
    }
    if ($r.Refused) { No "the development artifact was refused by its own verify path: $($r.Text)" }
    else { Ok '-VerifyOnly -DevEphemeral accepts the development artifact' }

    $r = Invoke-Helper @{ VerifyOnly = $true; Path = $subject; ExpectedPublisherCN = $cn }
    Assert-Refused -Result $r -Because "not 'Valid'" `
        -WhenOk '-VerifyOnly alone refuses it: nothing signed this way can satisfy the release rule'

    # The invocation build.yml's "Verify all packaged Windows binaries" step used to
    # make: -VerifyOnly *with* the run's thumbprint, no -DevEphemeral anywhere.
    # That is the exact shape that let a self-signed package be "verified" green on
    # the runner and refused on a user's machine, so it has to be a refusal now.
    $r = Invoke-Helper @{
        VerifyOnly = $true; Path = $subject; Thumbprint = $cert.Thumbprint; ExpectedPublisherCN = $cn
    }
    Assert-Refused -Result $r -Because "not 'Valid'" `
        -WhenOk '-VerifyOnly -Thumbprint without -DevEphemeral refuses (the old CI invocation)'

    # ── 5/6: the pinned leaf digest is checked ───────────────────────────────
    $r = Invoke-Helper @{
        VerifyOnly = $true; Path = $subject; Thumbprint = $cert.Thumbprint; DevEphemeral = $true;
        ExpectedPublisherCN = $cn; ExpectedCertSha256 = ('0' * 64)
    }
    Assert-Refused -Result $r -Because 'pin mismatch' -WhenOk 'a wrong leaf-digest pin is refused'

    $r = Invoke-Helper @{
        VerifyOnly = $true; Path = $subject; Thumbprint = $cert.Thumbprint; DevEphemeral = $true;
        ExpectedPublisherCN = $cn; ExpectedCertSha256 = $leaf
    }
    if ($r.Refused) { No "the correct cert pin was refused: $($r.Text)" }
    else { Ok 'the pinned leaf digest is accepted' }

    # ── 7: the publisher name comes from the anchor, not from the signer ────
    $r = Invoke-Helper @{
        VerifyOnly = $true; Path = $subject; Thumbprint = $cert.Thumbprint; DevEphemeral = $true;
        ExpectedPublisherCN = 'deathline94'
    }
    Assert-Refused -Result $r -Because 'publisher mismatch' -WhenOk 'a different publisher CN is refused'

    # The installer verifier must accept this signed engine only in an explicit
    # development run and only at the exact digest staged by that run.
    $package = Join-Path $tmp 'package'
    New-Item -ItemType Directory -Force -Path $package | Out-Null
    Copy-Item -LiteralPath $subject -Destination (Join-Path $package 'aether.exe')
    $digest = (Get-FileHash -LiteralPath $subject -Algorithm SHA256).Hash.ToLowerInvariant()
    $verifier = Join-Path $root 'scripts/verify-installers.ps1'
    $anchor = Join-Path $root 'packaging/trust/engine-trust.json'
    $result = & pwsh -NoProfile -File $verifier -Directory $package -Anchor $anchor `
        -ExpectedPublisherCN $cn -Development -DevThumbprint $cert.Thumbprint `
        -DevEngineSha256 $digest 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Ok 'an exact development engine passes package extraction verification' }
    else { No "the exact development package was refused: $result" }
    $result = & pwsh -NoProfile -File $verifier -Directory $package -Anchor $anchor `
        -ExpectedPublisherCN $cn -Development -DevThumbprint $cert.Thumbprint `
        -DevEngineSha256 ('0' * 64) 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and $result -match 'digest') { Ok 'a changed development engine digest is refused' }
    else { No "a changed development engine digest passed or failed for the wrong reason: $result" }
} finally {
    if ($certPath) { Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host ''
if ($fail) {
    Write-Host "# test-sign-windows: $fail of $($pass + $fail) check(s) failed"
    exit 1
}
Write-Host "# test-sign-windows: $pass check(s) passed"
exit 0
