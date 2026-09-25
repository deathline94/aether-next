# Generates circular aether-mark.svg embedding high-resolution circular prism emblem
Add-Type -AssemblyName System.Drawing

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$srcPath = Join-Path $repoRoot "packages/ui/brand/aether-icon.png"
$destPath = Join-Path $repoRoot "packages/ui/brand/aether-mark.svg"

$src = [System.Drawing.Image]::FromFile($srcPath)
$size = 512
$bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
$g.Clear([System.Drawing.Color]::Transparent)
$g.DrawImage($src, 0, 0, $size, $size)
$g.Dispose()
$src.Dispose()

$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
$b64 = [Convert]::ToBase64String($ms.ToArray())
$ms.Dispose()

$header = '<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 256 256" role="img" aria-label="Aether">' + "`n"
$defs = '  <defs>' + "`n" + '    <clipPath id="aether-circle-clip">' + "`n" + '      <circle cx="128" cy="128" r="128"/>' + "`n" + '    </clipPath>' + "`n" + '  </defs>' + "`n"
$body = '  <g clip-path="url(#aether-circle-clip)">' + "`n" + '    <image width="256" height="256" href="data:image/png;base64,' + $b64 + '"/>' + "`n" + '  </g>' + "`n"
$footer = '</svg>' + "`n"

$content = $header + $defs + $body + $footer
[System.IO.File]::WriteAllText($destPath, $content, [System.Text.Encoding]::UTF8)

Write-Host "Generated $destPath ($($content.Length) bytes)"
