param (
    [string]$Protocol = "masque",
    [string]$Noize = "firewall",
    [string]$Scan = "balanced"
)

$env:AETHER_PROTOCOL = $Protocol
$env:AETHER_NOIZE = $Noize
$env:AETHER_SCAN = $Scan
$env:AETHER_SOCKS = "127.0.0.1:1819"
$env:AETHER_HTTP = "127.0.0.1:1820"
$env:AETHER_MASQUE_HTTP2 = "1"
$env:AETHER_DANGEROUS_DISABLE_TLS_VERIFY = "1"
$env:RUST_LOG = "debug"

Write-Host "Building aether..." -ForegroundColor Cyan
cargo build --manifest-path ./aether/Cargo.toml
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

$logFile = "test_engine.log"
if (Test-Path $logFile) { Remove-Item $logFile }

Write-Host "Starting aether ($Protocol, $Noize, $Scan)..." -ForegroundColor Cyan
$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `".\aether\target\debug\aether.exe > $logFile 2>&1`"" -PassThru -NoNewWindow

$timeout = 120
$ready = $false

for ($i = 0; $i -lt $timeout; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $logFile) {
        $logs = Get-Content $logFile -Raw
        if ($logs -match "socks5 server listening") {
            $ready = $true
            break
        }
    }
}

if (-not $ready) {
    Write-Host "Engine failed to start within $timeout seconds." -ForegroundColor Red
    Write-Host "Tail of log:" -ForegroundColor Yellow
    Get-Content $logFile -Tail 20
    Stop-Process -Id $process.Id -Force
    exit 1
}

Write-Host "SOCKS proxy is up. Testing connection to google.com..." -ForegroundColor Cyan
$curlOutput = curl.exe -s -x socks5h://127.0.0.1:1819 -I https://www.google.com

if ($curlOutput -match "HTTP/.* 200") {
    Write-Host "Test Passed: Connection successful!" -ForegroundColor Green
} else {
    Write-Host "Test Failed: Could not connect to Google." -ForegroundColor Red
    Write-Host "Curl Output: $curlOutput" -ForegroundColor Red
}

Write-Host "Shutting down engine..." -ForegroundColor Cyan
Stop-Process -Id $process.Id -Force
