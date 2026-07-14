# Android-библиотека olcRTC

Документация для `combined-tunnel.aar`, собранной через `gomobile bind` из
`mobilebridge`.

Turnable из библиотеки удалён. Поддерживается только olcRTC.

## Что внутри

- `olcrtc/` — локальный checkout `github.com/openlibrecommunity/olcrtc`.
- `mobilebridge/` — gomobile API для Kotlin/Java.
- `cbridge/` — C ABI для GreenPass: `StartCore`, `StopCore`, `GetStatusJSON`, `GetLogsJSON`, `FreeCString`.

## Основной API

```kotlin
Mobilebridge.validateConfig(configJson)
val sessionId = Mobilebridge.start(configJson)
Mobilebridge.stop(sessionId)
Mobilebridge.stopAll()
Mobilebridge.isRunning(sessionId)
Mobilebridge.setLogLevel("info")
```

Состояния в listener: `starting`, `running`, `stopping`, `stopped`, `error`.

## JSON-конфиг

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

Поля:

- `engine` можно опустить; если указано, допустимо только `olcrtc`.
- `carrier`: `telemost`, `jitsi`, `wbstream`; по умолчанию `telemost`.
- `provider`: legacy-алиас для `carrier`.
- `transport`: `vp8channel` по умолчанию в olcRTC, также есть `datachannel`.
- `room_id`: идентификатор или URL комнаты для выбранного carrier.
- `client_id`: обязателен и должен совпадать с server-side client id.
- `key_hex`: общий 64-символьный hex-ключ.
- `socks_port`: локальный SOCKS5 порт.
- `socks_listen_host`: опционально, например `0.0.0.0`.
- `dns_server`: опционально, например `8.8.8.8:53`.
- `wait_ready_timeout_millis`: если больше нуля, старт ждёт готовности transport + SOCKS.

## C ABI для GreenPass

`StartCore(configJson)` возвращает:

- пустую строку при успехе;
- строку `error: ...` при ошибке.

`StopCore()` безопасен при повторном вызове и при отсутствии активной сессии.

`GetStatusJSON()` возвращает состояние `starting`, `handshake`, `ready`, `stopping`, `stopped` или `error`.

`GetLogsJSON()` возвращает последние 100 записей. Строки из C ABI необходимо освобождать через `FreeCString()`.

## Android VPN protect

Если библиотека используется внутри `VpnService`, перед стартом установите protector:

```kotlin
Mobilebridge.setSocketProtector(object : Mobilebridge.SocketProtector {
    override fun protect(fd: Int): Boolean {
        return vpnService.protect(fd)
    }
})
```

## Сборка

```powershell
cd /d D:\downwloads\proxybesplatno\turnlib
.\scripts\build-android.ps1
```

Результат: `build/combined-tunnel.aar`.

## Частые ошибки

- `client_id is required` — добавьте `client_id`, совпадающий с сервером.
- `invalid socks_port` — порт должен быть в диапазоне `1..65535`.
- `turnable engine is no longer supported` — старый Turnable-конфиг больше не подходит.
- `olcRTC already running` — upstream mobile runtime singleton; сначала остановите старую сессию.
