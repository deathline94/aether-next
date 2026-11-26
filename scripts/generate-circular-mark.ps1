# Generates the circular aether-mark.svg that the README renders.
#
# The mark is a raster, so the SVG embeds it — as an 8-bit indexed PNG. The
# previous version embedded a 32-bit 1024^2 PNG, which produced a ~427 KB "SVG"
# for an 80 px logo; the palette version at 256^2 is far smaller and
# indistinguishable at any size this file is actually used at.
Add-Type -AssemblyName System.Drawing

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$srcPath = Join-Path $repoRoot "packages/ui/brand/aether-icon.png"
$destPath = Join-Path $repoRoot "packages/ui/brand/aether-mark.svg"

$src = [System.Drawing.Image]::FromFile($srcPath)
$size = 256
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

# An 8-bit indexed copy: a logo uses far fewer than 256 colours, so the palette
# is lossless in practice and a fraction of the 32-bit size.
$indexed = $bmp.Clone([System.Drawing.Rectangle]::new(0, 0, $size, $size), [System.Drawing.Imaging.PixelFormat]::Format8bppIndexed)
$bmp.Dispose()

$ms = New-Object System.IO.MemoryStream
$indexed.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$indexed.Dispose()
$b64 = [Convert]::ToBase64String($ms.ToArray())
$ms.Dispose()

$header = '<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256" role="img" aria-label="Aether">' + "`n"
$defs = '  <defs>' + "`n" + '    <clipPath id="aether-circle-clip">' + "`n" + '      <circle cx="128" cy="128" r="128"/>' + "`n" + '    </clipPath>' + "`n" + '  </defs>' + "`n"
$body = '  <g clip-path="url(#aether-circle-clip)">' + "`n" + '    <image width="256" height="256" href="data:image/png;base64,' + $b64 + '"/>' + "`n" + '  </g>' + "`n"
$footer = '</svg>' + "`n"

$content = $header + $defs + $body + $footer
[System.IO.File]::WriteAllText($destPath, $content, [System.Text.Encoding]::UTF8)

Write-Host "Generated $destPath ($($content.Length) bytes)"
