param(
    [string]$AndroidNdk = $env:ANDROID_NDK_HOME,
    [string]$Abi = "arm64-v8a",
    [string]$OutputDir = "",
    [string]$GoCacheRoot = "D:\tmp\singbox-go",
    [string]$LibName = "libgreenpass.so"
)

# Builds the unified GreenPass C-ABI shared library for Android.
#
# Mirrors turnlib/scripts/build-cabi-android.ps1: cross-compile ./cbridge as a
# c-shared .so via the NDK clang toolchain, producing a drop-in core for the
# GreenPass plugin with the same exports GreenPass expects from VlessCore
# (StartCore/StopCore/FreeCString/LastLog/LastError/GetStatusJSON/GetLogsJSON).
#
# Usage:
#   .\scripts\build-cabi-android.ps1
#   .\scripts\build-cabi-android.ps1 -AndroidNdk "D:\sdkandroidstudio\android-ndk-r29"

$ErrorActionPreference = "Stop"

if (-not $AndroidNdk) {
    foreach ($candidate in @("D:\sdkandroidstudio\android-ndk-r29", "D:\sdkandroidstudio\android-ndk-r27d")) {
        if (Test-Path $candidate) {
            $AndroidNdk = $candidate
            break
        }
    }
}
if (-not $AndroidNdk) {
    throw "ANDROID_NDK_HOME is not set. Pass -AndroidNdk or export the variable."
}
$toolchain = Join-Path $AndroidNdk "toolchains\llvm\prebuilt\windows-x86_64\bin"
if ($Abi -eq "arm64-v8a") {
    $goArch = "arm64"
    $goArm = ""
    $cc = Join-Path $toolchain "aarch64-linux-android24-clang.cmd"
} elseif ($Abi -eq "armeabi-v7a") {
    $goArch = "arm"
    $goArm = "7"
    $cc = Join-Path $toolchain "armv7a-linux-androideabi24-clang.cmd"
} else {
    throw "Unsupported ABI: $Abi"
}
if (-not (Test-Path $cc)) {
    throw "Compiler not found: $cc"
}
if (-not $OutputDir) {
    $OutputDir = "build/cabi/$Abi"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$outFile = Join-Path $OutputDir $LibName

# Isolated Go cache so a shared GOCACHE never collides with a desktop build.
New-Item -ItemType Directory -Force $GoCacheRoot | Out-Null
$env:GOCACHE = Join-Path $GoCacheRoot "gocache"
$env:GOMODCACHE = Join-Path $GoCacheRoot "gomodcache"
$env:GOPATH = Join-Path $GoCacheRoot "gopath"
$env:TMP = Join-Path $GoCacheRoot "tmp"
$env:TEMP = $env:TMP
New-Item -ItemType Directory -Force $env:GOCACHE, $env:GOMODCACHE, $env:GOPATH, $env:TMP | Out-Null
$env:GOMAXPROCS = "2"
$env:GOFLAGS = "-p=1"

$env:GOTOOLCHAIN = "auto"
$env:CGO_ENABLED = "1"
$env:GOOS = "android"
$env:GOARCH = $goArch
$env:GOARM = $goArm
$env:CC = $cc

Write-Host "Building $LibName ($Abi) -> $outFile"
& (Join-Path $PSScriptRoot "sync-qwdtt-source.ps1")
go build -buildmode=c-shared -trimpath -tags "with_gvisor,with_utls,with_quic,with_wireguard,with_dhcp,with_clash_api,with_naive_outbound,with_masque,with_sudoku" -ldflags="-s -w -X singboxextended/mobilebridge.version=$(git rev-parse --short HEAD 2>$null)" -o $outFile ./cbridge
if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

Write-Output $outFile
