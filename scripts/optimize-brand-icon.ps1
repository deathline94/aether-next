# Reproducible generation of optimized aether.png web/favicon from canonical master
param(
    [int]$Dimension = 192
)

Add-Type -AssemblyName System.Drawing

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$srcPath = Join-Path $repoRoot "packages/ui/brand/aether-icon.png"
if (-not (Test-Path $srcPath)) {
    Write-Error "Master icon not found at $srcPath"
    exit 1
}

$src = [System.Drawing.Image]::FromFile($srcPath)
$dest = New-Object System.Drawing.Bitmap($Dimension, $Dimension, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($dest)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
$g.Clear([System.Drawing.Color]::Transparent)
$g.DrawImage($src, 0, 0, $Dimension, $Dimension)
$g.Dispose()
$src.Dispose()

$targets = @(
    (Join-Path $repoRoot "apps/android/public/aether.png"),
    (Join-Path $repoRoot "apps/desktop/public/aether.png"),
    (Join-Path $repoRoot "apps/android/android/app/src/main/assets/www/aether.png")
)

foreach ($target in $targets) {
    $parent = Split-Path -Parent $target
    if (Test-Path $parent) {
        $dest.Save($target, [System.Drawing.Imaging.ImageFormat]::Png)
        $len = (Get-Item $target).Length
        $kb = [math]::Round($len / 1024, 2)
        Write-Host "Wrote $target ($len bytes, $kb KB)"
    }
}

$dest.Dispose()
