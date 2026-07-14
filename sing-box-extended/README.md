# sing-box-extended

Unified Android C-ABI core for GreenPass. It builds one `libgreenpass.so`
(arm64-v8a) containing [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended)
with AmneziaWG 2.0 support and the local `turnlib` olcRTC engine. All modes share
one Go runtime and can switch in-process through the existing `VlessCore` ABI.

## Layout

```
sing-box-extended/
├── go.mod / go.sum        # pins sing-box-extended v1.13.14-extended-2.5.0
├── cbridge/main.go        # C-ABI exports (//export StartCore / StopCore / ...)
├── mobilebridge/          # single-session wrapper around box.Box
├── unifiedbridge/         # routes olcRTC configs; all others use sing-box
├── scripts/
│   └── build-cabi-android.ps1  # NDK cross-compile (mirrors turnlib)
└── build/cabi/arm64-v8a/  # output: libgreenpass.so + libgreenpass.h
```

## C ABI

Mirrors the GreenPass `VlessCore` contract (empty return string == success;
caller frees every returned string with `FreeCString`):

| Export          | Signature                                   | GreenPass use |
|-----------------|---------------------------------------------|---------------|
| `StartCore`     | `char* StartCore(char* configJSON)`         | `core.start(json)` |
| `StopCore`      | `void StopCore()`                           | `core.stop()` |
| `FreeCString`   | `void FreeCString(char* ptr)`               | free returned strings |
| `LastLog`       | `char* LastLog()`                           | `core.last_log()` |
| `LastError`     | `char* LastError()`                         | `core.last_error()` |
| `GetStatusJSON` | `char* GetStatusJSON()`                     | `core.status_json()` |
| `GetLogsJSON`   | `char* GetLogsJSON()`                       | `core.logs_json()` |
| `IsRunning`     | `int IsRunning()`                           | extra (not required by VlessCore) |
| `Version`       | `char* Version()`                           | extra |
| `ValidateConfig`| `char* ValidateConfig(char* configJSON)`    | extra |

`StartCore` routes configs with top-level `"engine":"olcrtc"` to turnlib and
all other configs to sing-box. It stops the current engine before starting the
next one, preserving a single active session in the shared Go runtime.

## Build

Requires Go 1.26.4+ and Android NDK r29. Naive's bundled Cronet archive uses
ARM64 relocations unsupported by the older r27d linker.

```powershell
# Env (defaults shown; override via params/env)
$env:ANDROID_NDK_HOME = "D:\sdkandroidstudio\android-ndk-r29"

# Cross-compile libgreenpass.so for arm64-v8a
.\scripts\build-cabi-android.ps1
```

Output: `build/cabi/arm64-v8a/libgreenpass.so` (+ `libgreenpass.h`).

The script uses `go build -buildmode=c-shared` with the NDK clang toolchain
(`aarch64-linux-android24-clang`), exactly like `turnlib/scripts/build-cabi-android.ps1`.
No `gomobile` needed — gomobile is only required for AAR packaging, which this
library does not use.

## Packaging (LZMA/XZ)

The `.so` is LZMA-compressed for distribution. GreenPass downloads
`libgreenpass.so.xz` and decompresses it with the stdlib `lzma` module (FORMAT_XZ),
verifying both the `.xz` bundle SHA256 and the decompressed `.so` SHA256.
Produce the distributable bundle:

```powershell
python -c "import lzma; data=open('build/cabi/arm64-v8a/libgreenpass.so','rb').read(); lzma.open('build/cabi/arm64-v8a/libgreenpass.so.xz','wb',format=lzma.FORMAT_XZ,preset=9|lzma.PRESET_EXTREME).write(data)"
```

Then compute the four constants GreenPass pins (in `GreenPass.plugin`):

```powershell
python -c "import hashlib,os; so='build/cabi/arm64-v8a/libgreenpass.so'; xz=so+'.xz'; print(os.path.getsize(so),hashlib.sha256(open(so,'rb').read()).hexdigest()); print(os.path.getsize(xz),hashlib.sha256(open(xz,'rb').read()).hexdigest())"
```

Upload `libgreenpass.so.xz` to the GreenPass repo root; the plugin's
`SINGBOX_BUNDLE_URLS` point at `raw.githubusercontent.com/.../libgreenpass.so.xz`
with a jsDelivr CDN fallback.

## Test

```powershell
go test -tags with_clash_api ./mobilebridge ./unifiedbridge
```

Exercises the real sing-box lifecycle: config parse -> `box.New` -> `Start` ->
`Close`, single-session replacement, idempotent stop, and the diagnostics ring.
The release script separately cross-compiles the complete Android tag set,
including the Android-only Naive/Cronet implementation.

## GreenPass integration notes

- Drop `libgreenpass.so` into the GreenPass modules folder. VLESS, AWG and
  olcRTC all load that same path through the exported `VlessCore` contract.
- Config is **sing-box JSON**, not xray JSON. GreenPass's `_build_*_config`
  helpers already emit xray-shaped JSON; a sing-box config builder lives in
  `mobilebridge`-adjacent code if you want to reuse the same URI parsers.
  The config schema differs (e.g. `"type": "mixed"` inbound vs xray's
  `"protocol": "socks"`), so feed sing-box-shaped configs only.
- `StartCore` returns `""` on success and `"error: ..."` on failure, matching
  the `VlessCore.start()` convention where non-empty means error.

## License

This bridge links sing-box. Check sing-box's LICENSE before distributing the
built `.so`.
