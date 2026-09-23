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
  [switch]$VerifyOnly,

  # The one licence to tolerate a signature Windows cannot chain to a trusted root.
  # It exists for development builds only, and it is not implied by anything else:
  # passing -Thumbprint, or omitting -VerifyOnly, does not enable it.
  #
  # The rule this replaces: this script used to accept a `NotTrusted` verdict
  # whenever the signer was the certificate the same run had just minted, which is
  # how a self-signed engine got into the zip and the installer that were then
  # published as downloads. A clean user machine never trusts that certificate - the
  # runtime calls WinVerifyTrust (apps/desktop/src-tauri/src/trust.rs) and refuses
  # any nonzero result - so the package was unusable by design and the CI green was
  # a property of the runner, not of the artifact.
  [switch]$DevEphemeral,

  # sha256 over the signing leaf's DER - the same value the trust anchor pins as
  # `cert_sha256` and the same value the runtime compares at launch. Without it,
  # "signed" only means "signed by somebody".
  [string]$ExpectedCertSha256,

  [Parameter(Mandatory = $true)]
  [string]$ExpectedPublisherCN
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
# The rule is: the verdict must be `Valid`, the publisher CN must be the whole CN
# RDN, and - when a pin was supplied - the leaf's DER digest must equal it. The one
# exception is a `NotTrusted` verdict on a certificate this run created, and it is
# only available to a caller that says out loud that this is a development build
# (-DevEphemeral). Such an artifact is not distributable: nothing outside the run
# that made the certificate can verify it.
function Assert-AetherSignature {
  param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Thumbprint = "",
    [string]$ExpectedCertSha256 = "",
    [Parameter(Mandatory = $true)][string]$ExpectedPublisherCN,
    [bool]$AllowEphemeral = $false,
    [string]$Context = "signature"
  )
  $sig = Get-AuthenticodeSignature -LiteralPath $Target
  if ($null -eq $sig.SignerCertificate) {
    throw "${Context} invalid for ${Target}: no signer certificate present"
  }
  if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    # An untrusted root reaches us as `NotTrusted` on some Windows versions and as
    # `UnknownError` ("a certificate chain ... terminated in a root certificate
    # which is not trusted") on others - both are the same fact about the chain, and
    # both are excused only here, only for this run's own certificate, and only when
    # the caller said this is a development artifact.
    $runLocalVerdict = @(
      [System.Management.Automation.SignatureStatus]::NotTrusted,
      [System.Management.Automation.SignatureStatus]::UnknownError
    )
    $selfIssuedRunCert = (
      $AllowEphemeral -and
      $Thumbprint -ne "" -and
      ($runLocalVerdict -contains $sig.Status) -and
      $sig.SignerCertificate.Thumbprint -eq $Thumbprint.ToUpper()
    )
    if (-not $selfIssuedRunCert) {
      throw "${Context} invalid for ${Target}: Windows reports '$($sig.Status)' (not 'Valid') - $($sig.StatusMessage)"
    }
    Write-Host "::warning::${Context} on ${Target} is only verifiable inside this run: -DevEphemeral accepted '$($sig.Status)' because the signer is this run's own certificate ($Thumbprint). This artifact must not be published as a release download."
  }
  $subject = $sig.SignerCertificate.Subject
  if ($ExpectedPublisherCN -and $subject -notmatch ('CN=' + [regex]::Escape($ExpectedPublisherCN) + '(,|$)')) {
    throw "${Context} publisher mismatch for ${Target}: expected CN '$ExpectedPublisherCN', got '$subject'"
  }
  if ($ExpectedCertSha256) {
    $leaf = ([System.BitConverter]::ToString(
      [System.Security.Cryptography.SHA256]::Create().ComputeHash($sig.SignerCertificate.RawData)
    ) -replace '-', '').ToLowerInvariant()
    if ($leaf -ne $ExpectedCertSha256.ToLowerInvariant()) {
      throw "${Context} signer pin mismatch for ${Target}: leaf sha256 is $leaf, the trust anchor pins $ExpectedCertSha256 ($subject)"
    }
  }
  return $sig
}

if ($VerifyOnly) {
  # The packaged binaries are checked by the same rule the release job demands. A
  # run-local thumbprint alone is not a licence: -DevEphemeral has to be explicit,
  # so a development verify and a distributable verify cannot be confused.
  $verified = Assert-AetherSignature -Target $Path -Thumbprint $Thumbprint `
    -ExpectedCertSha256 $ExpectedCertSha256 -ExpectedPublisherCN $ExpectedPublisherCN `
    -AllowEphemeral ([bool]$DevEphemeral) -Context "Packaged artifact signature"
  Write-Host "Verified ${Path}: $($verified.SignerCertificate.Subject) [$($verified.Status)]"
  return
}

if (-not $Thumbprint) { throw "Thumbprint is required unless -VerifyOnly is set" }

$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint"
if (-not $cert.HasPrivateKey) {
  throw "Code-signing certificate does not have a private key"
}

# A self-signed certificate can only ever produce a signature another machine
# reports as NotTrusted. Refuse to attach one to an artifact nobody declared to be
# a development build, rather than signing it and letting the release job publish a
# package the shipped shell will not run.
if (-not $DevEphemeral) {
  if ($cert.Subject -eq $cert.Issuer) {
    throw "refusing to sign a distributable artifact ($Path) with the self-signed certificate $($cert.Thumbprint); supply a code-signing certificate Windows chains to a trusted root, or pass -DevEphemeral for a development build"
  }
  if (-not $ExpectedCertSha256) {
    Write-Host "::notice::signing $Path without -ExpectedCertSha256: the runtime pins the leaf digest, so an unpinned signature will be refused at launch even though Windows trusts the chain."
  }
}

Set-AuthenticodeSignature `
  -LiteralPath $Path `
  -Certificate $cert `
  -HashAlgorithm SHA256 `
  -TimestampServer "http://timestamp.digicert.com" | Out-Null

# Re-read through the same function the release job uses: the bytes this script just
# signed must satisfy the strongest assertion in the repository, here and now.
$signature = Assert-AetherSignature -Target $Path -Thumbprint $Thumbprint `
  -ExpectedCertSha256 $ExpectedCertSha256 -ExpectedPublisherCN $ExpectedPublisherCN `
  -AllowEphemeral ([bool]$DevEphemeral) -Context "Signature"

Write-Host "Signed ${Path}: $($signature.SignerCertificate.Subject)"
