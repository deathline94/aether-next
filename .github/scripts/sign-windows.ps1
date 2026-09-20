param(
  [Parameter(Mandatory = $true)]
  [string]$Path
)

$ErrorActionPreference = "Stop"

if (-not $env:WINDOWS_CERT_THUMBPRINT) {
  throw "WINDOWS_CERT_THUMBPRINT is not set"
}
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
  throw "Signing target does not exist: $Path"
}

$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$env:WINDOWS_CERT_THUMBPRINT"
if (-not $cert.HasPrivateKey) {
  throw "Code-signing certificate does not have a private key"
}

Set-AuthenticodeSignature `
  -LiteralPath $Path `
  -Certificate $cert `
  -HashAlgorithm SHA256 `
  -TimestampServer "http://timestamp.digicert.com" | Out-Null

$signature = Get-AuthenticodeSignature -LiteralPath $Path
if (-not $signature.SignerCertificate -or $signature.Status -in @("NotSigned", "HashMismatch")) {
  throw "Signature invalid for ${Path}: $($signature.StatusMessage)"
}
if ($signature.SignerCertificate.Subject -notmatch "CN=deathline94(?:,|$)") {
  throw "Publisher CN mismatch for ${Path}: $($signature.SignerCertificate.Subject)"
}

Write-Host "Signed ${Path}: $($signature.SignerCertificate.Subject)"
