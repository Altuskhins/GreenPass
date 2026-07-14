param(
    [string]$AndroidNdk = "D:\sdkandroidstudio\android-ndk-r29",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $projectRoot
$pluginPath = Join-Path $repoRoot "GreenPass.plugin"
$buildScript = Join-Path $PSScriptRoot "build-cabi-android.ps1"

$targets = @(
    @{ Abi = "arm64-v8a"; Bundle = "libgreenpass.so.xz" },
    @{ Abi = "armeabi-v7a"; Bundle = "libgreenpass-armeabi-v7a.so.xz" }
)

Push-Location $projectRoot
try {
    go test -tags with_clash_api ./mobilebridge ./unifiedbridge
    if ($LASTEXITCODE -ne 0) { throw "mobilebridge tests failed" }

    if (-not $SkipBuild) {
        foreach ($target in $targets) {
            & $buildScript -AndroidNdk $AndroidNdk -Abi $target.Abi
        }
    }
} finally {
    Pop-Location
}

$compress = @'
import lzma, pathlib, sys
src, dst = map(pathlib.Path, sys.argv[1:3])
with src.open("rb") as source, lzma.open(dst, "wb", format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME) as target:
    while chunk := source.read(1024 * 1024):
        target.write(chunk)
'@

$manifest = Get-Content -Raw -LiteralPath $pluginPath
foreach ($target in $targets) {
    $rawPath = Join-Path $projectRoot "build\cabi\$($target.Abi)\libgreenpass.so"
    $bundlePath = Join-Path $repoRoot $target.Bundle
    python -c $compress $rawPath $bundlePath
    if ($LASTEXITCODE -ne 0) { throw "XZ compression failed for $($target.Abi)" }

    $raw = Get-Item -LiteralPath $rawPath
    $bundle = Get-Item -LiteralPath $bundlePath
    $rawHash = (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $bundleHash = (Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash.ToLowerInvariant()

    $blockPattern = '(?ms)(^\s{4}"' + [regex]::Escape($target.Abi) + '":\s*\{)(.*?)(^\s{4}\},)'
    $blockMatch = [regex]::Match($manifest, $blockPattern)
    if (-not $blockMatch.Success) { throw "SINGBOX_BUNDLES block not found: $($target.Abi)" }
    $body = $blockMatch.Groups[2].Value
    $values = @{
        so_size = $raw.Length
        so_sha256 = '"' + $rawHash + '"'
        bundle_size = $bundle.Length
        bundle_sha256 = '"' + $bundleHash + '"'
    }
    foreach ($field in $values.Keys) {
        $pattern = '(?m)(^\s*"' + $field + '":\s*)(?:"[^"]*"|\d+)(,\s*$)'
        if ([regex]::Matches($body, $pattern).Count -ne 1) { throw "Manifest field not found: $($target.Abi).$field" }
        $value = [string]$values[$field]
        $body = [regex]::Replace($body, $pattern, [System.Text.RegularExpressions.MatchEvaluator]{
            param($match)
            $match.Groups[1].Value + $value + $match.Groups[2].Value
        })
    }
    $replacement = $blockMatch.Groups[1].Value + $body + $blockMatch.Groups[3].Value
    $manifest = $manifest.Substring(0, $blockMatch.Index) + $replacement + $manifest.Substring($blockMatch.Index + $blockMatch.Length)

    Write-Host "$($target.Abi): $($bundle.Name) $($bundle.Length) bytes SHA256=$bundleHash"
}

[System.IO.File]::WriteAllText($pluginPath, $manifest, [System.Text.UTF8Encoding]::new($false))
python -m py_compile $pluginPath
if ($LASTEXITCODE -ne 0) { throw "GreenPass.plugin py_compile failed" }

Write-Host "Release libraries and GreenPass manifest are ready."
