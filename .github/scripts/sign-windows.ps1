param(
  # Mandatory for signing, ignored in -VerifyOnly mode. Declaring it optional and
  # checking below is deliberate: making it Mandatory would stop the stronger
  # verifier from being reused on already-signed artifacts.
  [string]$Thumbprint,

  [Parameter(Mandatory = $true)]
  [string]$Path,

  # Verify an existing signature without re-signing. build.yml's "Verify all
  # packaged Windows binaries" step used to re-implement this check inline and
  # weaker, which is how the two gates drifted apart.
  [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
  throw "Signing target does not exist: $Path"
}

# ── One rule, enforced everywhere ─────────────────────────────────────────────
# Accepting "any status except NotSigned/HashMismatch" is how a signature that
# Windows reports as NotTrusted - revoked, expired chain, name constraint failure,
# untrusted root - passed the signing helper while prepare-anchor.yml's witness step
# demanded exactly "Valid". The two gates disagreed, and the weaker one was the one
# that actually signed the shipped binaries.
#
# The rule is now: the verdict must be `Valid`. The single exception is a bounded,
# provable one, because CI has no Authenticode trust chain: `build.yml` and
# `prepare-anchor.yml` mint an *ephemeral self-signed* certificate per run, so the
# only possible non-Valid verdict for a correctly-signed artifact is "the root is
# not in the machine's store". That is accepted only when the signer is byte-for-byte
# the certificate this very run created (thumbprint match) - which is strictly
# narrower than the old rule, since a NotTrusted signature from ANY other
# certificate, and TimestampMismatch / HashMismatch / NotSigned / UnknownError from
# any, still fail.
#
# `-VerifyOnly` has no run-local certificate to defer to, so there it is `Valid`
# or nothing.
function Assert-AetherSignature {
  param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Thumbprint = "",
    [string]$Context = "signature"
  )
  $sig = Get-AuthenticodeSignature -LiteralPath $Target
  if ($null -eq $sig.SignerCertificate) {
    throw "${Context} invalid for ${Target}: no signer certificate present"
  }
  if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    $selfIssuedRunCert = (
      $Thumbprint -ne "" -and
      $sig.Status -eq [System.Management.Automation.SignatureStatus]::NotTrusted -and
      $sig.SignerCertificate.Thumbprint -eq $Thumbprint.ToUpper()
    )
    if (-not $selfIssuedRunCert) {
      throw "${Context} invalid for ${Target}: Windows reports '$($sig.Status)' (not 'Valid') - $($sig.StatusMessage)"
    }
    Write-Host "::notice::${Context} on ${Target} is NotTrusted only because this run minted its own certificate; signer matches the run's thumbprint $Thumbprint"
  }
  if ($sig.SignerCertificate.Subject -notmatch "CN=deathline94(?:,|$)") {
    throw "${Context} publisher mismatch for ${Target}: $($sig.SignerCertificate.Subject)"
  }
  return $sig
}

if ($VerifyOnly) {
  # A thumbprint may still be supplied: the packaged binaries are signed by this
  # run's own ephemeral certificate, so the run-local exception has to be available
  # on the verify path too. Without one, this is `Valid` or nothing.
  $verified = Assert-AetherSignature -Target $Path -Thumbprint $Thumbprint -Context "Packaged artifact signature"
  Write-Host "Verified ${Path}: $($verified.SignerCertificate.Subject) [$($verified.Status)]"
  return
}

if (-not $Thumbprint) { throw "Thumbprint is required unless -VerifyOnly is set" }

$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint"
if (-not $cert.HasPrivateKey) {
  throw "Code-signing certificate does not have a private key"
}

Set-AuthenticodeSignature `
  -LiteralPath $Path `
  -Certificate $cert `
  -HashAlgorithm SHA256 `
  -TimestampServer "http://timestamp.digicert.com" | Out-Null

# Re-read through the same function the release job uses: the bytes this script just
# signed must satisfy the strongest assertion in the repository, here and now.
$signature = Assert-AetherSignature -Target $Path -Thumbprint $Thumbprint -Context "Signature"

Write-Host "Signed ${Path}: $($signature.SignerCertificate.Subject)"
