param(
    [string]$AndroidSdk = $env:ANDROID_HOME,
    [string]$AndroidNdk = $env:ANDROID_NDK_HOME,
    [string]$GoCacheRoot = "D:\tmp\turnlib-go"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AndroidSdk)) {
    $AndroidSdk = "D:\sdkandroidstudio"
}
if ([string]::IsNullOrWhiteSpace($AndroidNdk)) {
    $candidate = Join-Path $AndroidSdk "android-ndk-r27d"
    if (Test-Path $candidate) {
        $AndroidNdk = $candidate
    }
}

$env:ANDROID_HOME = $AndroidSdk
$env:ANDROID_SDK_ROOT = $AndroidSdk
if (-not [string]::IsNullOrWhiteSpace($AndroidNdk)) {
    $env:ANDROID_NDK_HOME = $AndroidNdk
}

New-Item -ItemType Directory -Force $GoCacheRoot | Out-Null
$env:GOCACHE = Join-Path $GoCacheRoot "gocache"
$env:GOMODCACHE = Join-Path $GoCacheRoot "gomodcache"
$env:GOBIN = Join-Path (Get-Location) "build\gobin"
$env:GOMAXPROCS = "2"
$env:GOFLAGS = "-p=1"
New-Item -ItemType Directory -Force $env:GOBIN | Out-Null
$env:Path = "$env:GOBIN;$env:Path"

go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260520154334-0e4426e1883d
if ($LASTEXITCODE -ne 0) { throw "go install gomobile failed with exit code $LASTEXITCODE" }
go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260520154334-0e4426e1883d
if ($LASTEXITCODE -ne 0) { throw "go install gobind failed with exit code $LASTEXITCODE" }
$gomobile = Join-Path $env:GOBIN "gomobile.exe"
if (-not (Test-Path $gomobile)) {
    $gomobile = "gomobile"
}

& $gomobile init
if ($LASTEXITCODE -ne 0) { throw "gomobile init failed with exit code $LASTEXITCODE" }
New-Item -ItemType Directory -Force build | Out-Null
& $gomobile bind -target=android -androidapi 23 -o build/combined-tunnel.aar ./mobilebridge
if ($LASTEXITCODE -ne 0) { throw "gomobile bind failed with exit code $LASTEXITCODE" }
