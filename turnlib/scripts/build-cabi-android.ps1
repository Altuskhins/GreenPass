param(
    [string]$AndroidNdk = $env:ANDROID_NDK_HOME,
    [string]$Abi = "arm64-v8a",
    [string]$OutputDir = "build/cabi/arm64-v8a"
)

$ErrorActionPreference = "Stop"

if (-not $AndroidNdk) {
    throw "ANDROID_NDK_HOME is not set. Pass -AndroidNdk or export the variable."
}
if ($Abi -ne "arm64-v8a") {
    throw "This lib targets arm64-v8a only (got: $Abi)."
}

$toolchain = Join-Path $AndroidNdk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$cc = Join-Path $toolchain "aarch64-linux-android24-clang.cmd"
if (-not (Test-Path $cc)) {
    throw "Compiler not found: $cc"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$outFile = Join-Path $OutputDir "libzvonki.so"

$env:GOTOOLCHAIN = "auto"
$env:CGO_ENABLED = "1"
$env:GOOS = "android"
$env:GOARCH = "arm64"
$env:CC = $cc

go build -buildmode=c-shared -trimpath -ldflags="-s -w" -o $outFile ./cbridge
Write-Output $outFile
