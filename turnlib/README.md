# olcRTC Android Bridge

This workspace builds a gomobile Android AAR exposing a stable Kotlin/Java and
C ABI over the current `github.com/openlibrecommunity/olcrtc/mobile` runtime.

`turnable` is no longer linked or supported by this library.

## Architecture

- `olcrtc/` is a local checkout of `https://github.com/openlibrecommunity/olcrtc.git`.
- `mobilebridge/` is the gomobile bind package. It manages session IDs, lifecycle state, callbacks, logging, config validation, and idempotent stop handling.
- `cbridge/` exposes the clean C ABI used by GreenPass: `StartCore`, `StopCore`, `GetStatusJSON`, `GetLogsJSON`, and `FreeCString`.

## Go API

```go
Start(configJson string) (sessionId string, err error)
StartOlcRTC(roomId string, keyHex string, socksPort int, socksUser string, socksPass string) (sessionId string, err error)
StartOlcRTCWithClient(carrier string, transport string, roomId string, clientId string, keyHex string, socksPort int, socksUser string, socksPass string) (sessionId string, err error)
StartFromUrl(configUrl string) (sessionId string, err error) // always returns an unsupported error
Stop(sessionId string) error
StopAll() error
IsRunning(sessionId string) bool
Version() string
ValidateConfig(configJson string) error
SetLogLevel(level string)
SetListener(listener Listener)
SetSocketProtector(protector SocketProtector)
```

`Listener` is gomobile-compatible:

```go
type Listener interface {
    OnLog(sessionId string, level string, message string)
    OnState(sessionId string, state string, message string)
}
```

Supported states: `starting`, `running`, `stopping`, `stopped`, `error`.

## C ABI

`cbridge` follows the GreenPass/VlessCore convention:

- `StartCore(configJson)` returns an empty string on success or `error: ...`.
- `StopCore()` stops the active singleton session.
- `StartCore` accepts only olcRTC JSON. `engine` may be omitted or set to `"olcrtc"`.
- `GetStatusJSON()` returns the current lifecycle state: `starting`, `handshake`, `ready`, `stopping`, `stopped`, or `error`.
- `GetLogsJSON()` returns the latest 100 structured log entries.
- Release every returned C string with `FreeCString()`.

## Config JSON

Minimal config:

```json
{
  "engine": "olcrtc",
  "carrier": "jitsi",
  "transport": "datachannel",
  "room_id": "room-or-room-url",
  "client_id": "client-id-matching-server",
  "key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "socks_port": 10808,
  "socks_user": "",
  "socks_pass": "",
  "wait_ready_timeout_millis": 30000
}
```

Important fields:

- `carrier`: `telemost`, `jitsi`, or `wbstream`; defaults to `telemost`.
- `provider`: accepted as a legacy alias for `carrier`.
- `transport`: `vp8channel` by default in upstream olcRTC; `datachannel` is also supported.
- `client_id`: required by current olcRTC and must match the server-side client id.
- `socks_listen_host`: optional bind host, for example `0.0.0.0`.
- `dns_server`: optional DNS server, for example `8.8.8.8:53`.
- `vp8_fps`, `vp8_batch_size`: optional VP8 transport tuning.
- `liveness_interval_millis`, `liveness_timeout_millis`, `liveness_failures`: optional control-stream liveness tuning.
- `wait_ready_timeout_millis`: when positive, `Start` waits until olcRTC reports the SOCKS listener and transport ready.

## Build

From the workspace root:

```powershell
.\tools\update-libzvonki.ps1 -AndroidNdk "D:\sdkandroidstudio\android-ndk-r27d"
```

This updates `turnlib\olcrtc`, runs bridge tests, builds `libzvonki.so`, writes
`libzvonki.so.gz`, updates `greenpass_modules\libzvonki\manifest.json`, and
syncs `GreenPass.plugin` checksum constants.

Manual AAR build:

```powershell
$env:ANDROID_HOME = "D:\sdkandroidstudio"
$env:ANDROID_SDK_ROOT = "D:\sdkandroidstudio"
$env:ANDROID_NDK_HOME = "D:\sdkandroidstudio\android-ndk-r27d"
.\scripts\build-android.ps1
```

The script runs `gomobile bind -target=android -androidapi 23 -o build/combined-tunnel.aar ./mobilebridge`.

## Android/Kotlin Usage

See `examples/android` for a Gradle/Kotlin snippet. Minimal usage:

```kotlin
Mobilebridge.setListener(object : Mobilebridge.Listener {
    override fun onLog(sessionId: String, level: String, message: String) {
        android.util.Log.d("OlcRTC", "[$sessionId][$level] $message")
    }

    override fun onState(sessionId: String, state: String, message: String) {
        android.util.Log.i("OlcRTC", "[$sessionId] $state $message")
    }
})

val sessionId = Mobilebridge.start(configJson)
Mobilebridge.stop(sessionId)
```

## Troubleshooting

- `client_id is required`: add the client id expected by the olcRTC server.
- `invalid socks_port`: use a TCP port in the `1..65535` range.
- `turnable engine is no longer supported`: replace old Turnable config with olcRTC JSON.
- Android VPN self-routing: call `SetSocketProtector` from a `VpnService` before starting olcRTC.

## License

This bridge links only olcRTC. Check the current `olcrtc/LICENSE` before distributing binaries.
