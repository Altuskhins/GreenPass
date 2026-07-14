param(
    [string]$SourceDir = ""
)

$ErrorActionPreference = "Stop"

$coreRoot = Split-Path -Parent $PSScriptRoot
if (-not $SourceDir) {
    $workspaceRoot = Split-Path -Parent $coreRoot
    $SourceDir = Join-Path $workspaceRoot "proxy-turn-vk-android\go_client"
}

if (-not (Test-Path -LiteralPath $SourceDir)) {
    throw "qWDTT source directory not found: $SourceDir"
}

$destination = Join-Path $coreRoot "qwdttbridge"
New-Item -ItemType Directory -Force -Path $destination | Out-Null

Get-ChildItem -LiteralPath $SourceDir -Filter "*.go" -File |
    Where-Object { $_.Name -notin @("main.go", "listen.go") -and -not $_.Name.EndsWith("_test.go") } |
    ForEach-Object {
        $text = [System.IO.File]::ReadAllText($_.FullName)
        $text = [regex]::Replace($text, "(?m)^package\s+main\s*$", "package qwdttbridge")
        $target = Join-Path $destination ("upstream_" + $_.Name)
        [System.IO.File]::WriteAllText($target, $text, [System.Text.UTF8Encoding]::new($false))
    }
