# sing-box-extended

Unified Android C-ABI core for GreenPass. It builds one `libgreenpass.so` per
supported ABI (arm64-v8a and armeabi-v7a) containing [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended)
with AmneziaWG 2.0 support and the local `turnlib` olcRTC engine. All modes share
one Go runtime and can switch in-process through the existing `VlessCore` ABI.
Mihomo is built into that same library, so selecting it never loads a second Go
runtime into ExteraGram.

## Layout

```
sing-box-extended/
├── go.mod / go.sum        # pins sing-box-extended v1.13.14-extended-2.5.0
├── cbridge/main.go        # C-ABI exports (//export StartCore / StopCore / ...)
├── mobilebridge/          # single-session wrapper around box.Box
├── mihomobridge/          # sanitized Mihomo local-proxy lifecycle
├── unifiedbridge/         # routes sing-box, Mihomo, olcRTC and qWDTT configs
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
| `CurrentEngine` | `char* CurrentEngine()`                     | active engine diagnostics |
| `IsRunning`     | `int IsRunning()`                           | extra (not required by VlessCore) |
| `Version`       | `char* Version()`                           | extra |
| `ValidateConfig`| `char* ValidateConfig(char* configJSON)`    | extra |

`StartCore` routes configs by the top-level `engine` field. Mihomo receives a
small JSON envelope containing either its YAML config or proxy links. The bridge
forces one authenticated loopback mixed listener and disables imported TUN,
LAN, controller and server listeners before applying the config.

## Build

Requires Go 1.26.4+ and Android NDK r29. Naive's bundled Cronet archive uses
ARM64 relocations unsupported by the older r27d linker.

```powershell
# Env (defaults shown; override via params/env)
$env:ANDROID_NDK_HOME = "D:\sdkandroidstudio\android-ndk-r29"

# Cross-compile libgreenpass.so for arm64-v8a
.\scripts\build-cabi-android.ps1
```

Output: `build/cabi/<abi>/libgreenpass.so` (+ `libgreenpass.h`). Use
`build-release.ps1` to build and package both ABIs and update GreenPass hashes.

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
go test -tags with_clash_api ./mihomobridge ./mobilebridge ./unifiedbridge
```

Exercises the real sing-box lifecycle plus Mihomo envelope/link conversion and
unified engine dispatch.
The release script separately cross-compiles the complete Android tag set,
including the Android-only Naive/Cronet implementation.

## GreenPass integration notes

- Drop `libgreenpass.so` into the GreenPass modules folder. VLESS, AWG and
  olcRTC all load that same path through the exported `VlessCore` contract.
- GreenPass can send sing-box JSON, a Mihomo envelope containing proxy links,
  or a raw Mihomo YAML/JSON config imported as `.mihomo`. The bridge selects the
  engine from the envelope and keeps one authenticated loopback listener.
- `StartCore` returns `""` on success and `"error: ..."` on failure, matching
  the `VlessCore.start()` convention where non-empty means error.

## License

This bridge links sing-box and GPL-3.0-licensed Mihomo. Distributions of the
built `.so` must satisfy both upstream licenses; Mihomo's license text is kept
in `licenses/Mihomo-GPL-3.0.txt`.
