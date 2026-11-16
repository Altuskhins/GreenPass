"""olcRTC profiles: parse olcrtc:// links, call URLs and subscriptions; build links back."""

import hashlib
import json
import os
import re
import urllib.parse

from .android import prefs

CARRIERS = ("telemost", "jitsi", "wbstream")
CARRIER_LABELS = ("Яндекс Телемост", "Jitsi Meet", "WB Stream")
TRANSPORTS = ("datachannel", "vp8channel", "videochannel", "seichannel")
TRANSPORT_LABELS = ("Data-канал", "VP8-канал", "Видео-канал", "SEI-канал")
MAX_PROFILES = 64

_device_id = ""


def device_id():
    """Per-install client id sent to olcRTC servers, kept in prefs."""
    global _device_id
    if _device_id:
        return _device_id
    try:
        store = prefs()
        value = str(store.getString("olcrtc_device_id", "") or "").strip()
        if not re.fullmatch(r"install-[0-9a-f]{32}", value):
            value = "install-" + os.urandom(16).hex()
            store.edit().putString("olcrtc_device_id", value).commit()
        _device_id = value
    except Exception:
        _device_id = "install-" + os.urandom(16).hex()
    return _device_id


def carrier_alias(value):
    v = str(value or "").strip().lower()
    for name, aliases in (("wbstream", ("wb", "wildberries", "wbstream", "wb-stream")),
                          ("telemost", ("ya", "yandex", "yamost", "telemost", "yandex_telemost")),
                          ("jitsi", ("meet", "jitsi", "jitsi-meet", "jitsi_meet"))):
        if v in aliases:
            return name
    return ""


def transport_alias(value):
    v = str(value or "").strip().lower().replace("_", "-")
    for name, aliases in (("datachannel", ("data", "dc", "data-channel")), ("vp8channel", ("vp8", "vp8-channel")),
                          ("seichannel", ("sei", "sei-channel")), ("videochannel", ("video", "video-channel"))):
        if v in aliases:
            return name
    return v if v in TRANSPORTS else ""


def supported_transports(carrier):
    return {"jitsi": ("datachannel",), "telemost": ("vp8channel", "seichannel"),
            "wbstream": ("datachannel", "vp8channel", "seichannel")}.get(carrier_alias(carrier), ("vp8channel",))


def default_transport(carrier):
    return "datachannel" if carrier_alias(carrier) == "jitsi" else "vp8channel"


def _qs_get(qs, *names):
    for name in names:
        values = qs.get(name)
        if values and str(values[0] or "").strip():
            return urllib.parse.unquote(str(values[0]).strip())
    return ""


def _qs_int(qs, *names):
    try:
        value = int(_qs_get(qs, *names) or 0)
    except ValueError:
        return 0
    return value if value > 0 else 0


def _kv_blob(value):
    blob = str(value or "").strip().strip("<>").replace(";", "&")
    return urllib.parse.parse_qs(blob) if "=" in blob else {}


def _room_from_call_url(text, parsed):
    """(carrier, room) from a Telemost / WB Stream / Jitsi call URL."""
    host = parsed.netloc.strip().lower()
    path = urllib.parse.unquote(parsed.path).strip("/")
    if not host:
        return "", ""
    qs = urllib.parse.parse_qs(parsed.query)
    if host == "telemost.yandex.ru" or host.endswith(".telemost.yandex.ru"):
        room = _qs_get(qs, "room_id", "room", "roomId", "meeting_id", "meetingId")
        return "telemost", room or (path.rstrip("/").split("/")[-1] if path else "")
    if host == "stream.wb.ru" or host.endswith(".stream.wb.ru"):
        room = _qs_get(qs, "room_id", "room", "roomId")
        return "wbstream", room or (path.rstrip("/").split("/")[-1] if path else "")
    if host.startswith("meet.") or "jitsi" in host:
        return "jitsi", text.strip()
    return "", ""


def parse_link(raw, client_id=""):
    """(profile data, "") for an olcrtc:// link or a call URL; (None, error) otherwise."""
    text = str(raw or "").strip()
    if not text:
        return None, "Буфер обмена пуст"
    try:
        parsed = urllib.parse.urlparse(text)
        scheme = parsed.scheme.lower()
        if scheme in ("http", "https"):
            carrier, room = _room_from_call_url(text, parsed)
            if carrier and room:
                return {"carrier": carrier, "transport": default_transport(carrier), "room_id": room,
                        "client_id": str(client_id or "").strip(), "key_hex": ""}, ""
            return None, "В буфере нет olcRTC конфига"
        if scheme != "olcrtc":
            return None, "В буфере нет olcRTC конфига"

        qs = urllib.parse.parse_qs(parsed.query)
        carrier = carrier_alias(_qs_get(qs, "carrier", "provider"))
        transport = transport_alias(_qs_get(qs, "transport", "t"))
        room = _qs_get(qs, "room_id", "room")
        client = _qs_get(qs, "client_id", "device_id", "client", "id") or str(client_id or "").strip()
        key = _qs_get(qs, "key_hex", "key")

        # Compact form: olcrtc://carrier?transport<opts>@room#key$name
        compact = urllib.parse.unquote(parsed.query).strip()
        payload_qs = {}
        if "@" in compact:
            left, compact_room = compact.split("@", 1)
            transport_part = left.strip()
            if "<" in transport_part and ">" in transport_part:
                transport_part, payload = transport_part.split("<", 1)
                payload_qs = _kv_blob(payload.rsplit(">", 1)[0])
            compact_transport = transport_alias(transport_part)
            if compact_transport:
                transport = transport or compact_transport
                room = room or compact_room.strip()
                client = client or _qs_get(payload_qs, "client_id", "device_id", "client", "id")
                key = key or _qs_get(payload_qs, "key_hex", "key")

        name = ""
        fragment = parsed.fragment.strip()
        if fragment:
            key_part, _, meta = fragment.partition("$")
            if meta and "=" not in meta:
                name = meta.strip()
            if "%" in key_part:
                key_part, compact_client = key_part.split("%", 1)
                client = client or urllib.parse.unquote(compact_client).strip()
            key = key or urllib.parse.unquote(key_part).strip()
            client = client or _qs_get(_kv_blob(urllib.parse.unquote(meta)), "client_id", "device_id", "client", "id")

        netloc = urllib.parse.unquote(parsed.netloc).strip()
        path = urllib.parse.unquote(parsed.path)
        path = (path[1:] if path.startswith("/") else path).strip()
        if not carrier and carrier_alias(netloc):
            carrier = carrier_alias(netloc)
            room = room or path
        elif not room:
            room = (netloc + ("/" + path if path else "")).strip()

        carrier = carrier or "wbstream"
        data = {"carrier": carrier, "transport": transport or default_transport(carrier), "room_id": room,
                "client_id": client, "key_hex": key}
        if name:
            data["name"] = name[:64]
        fps = _qs_int(payload_qs, "vp8-fps", "vp8_fps", "fps") or _qs_int(qs, "vp8-fps", "vp8_fps")
        batch = _qs_int(payload_qs, "vp8-batch", "vp8_batch", "vp8_batch_size", "batch") or _qs_int(qs, "vp8-batch", "vp8_batch", "vp8_batch_size")
        if fps:
            data["vp8_fps"] = fps
        if batch:
            data["vp8_batch_size"] = batch
        return data, ""
    except Exception as exc:
        return None, str(exc)


def _profile_from_json(value, client_id=""):
    if not isinstance(value, dict):
        return None
    endpoint = value.get("endpoint") if isinstance(value.get("endpoint"), dict) else {}
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    transport_data = value.get("transport") if isinstance(value.get("transport"), dict) else {}
    vp8 = transport_data.get("vp8") if isinstance(transport_data.get("vp8"), dict) else {}
    carrier = carrier_alias(value.get("auth_provider") or value.get("carrier") or value.get("bypass_provider")
                            or value.get("bypassProvider") or value.get("provider")) or "wbstream"
    transport = transport_alias(transport_data.get("type") or value.get("transport")) or default_transport(carrier)
    room = str(endpoint.get("room_id") or value.get("room_id") or value.get("id") or value.get("server") or "").strip()
    client = str(endpoint.get("client_id") or value.get("client_id") or value.get("clientId") or value.get("device_id")
                 or value.get("deviceId") or client_id or "").strip()
    key = str(endpoint.get("key") or value.get("key_hex") or value.get("key") or value.get("password") or "").strip()
    if not room or not client or not key:
        return None
    data = {"carrier": carrier, "transport": transport, "room_id": room, "client_id": client, "key_hex": key,
            "name": str(value.get("name") or metadata.get("name") or "").strip()[:64]}
    for target, raw in (("vp8_fps", vp8.get("fps") or value.get("vp8_fps") or value.get("vp8Fps")),
                        ("vp8_batch_size", vp8.get("batch") or value.get("vp8_batch") or value.get("vp8Batch"))):
        try:
            if int(raw or 0) > 0:
                data[target] = int(raw)
        except (TypeError, ValueError):
            pass
    return data


def _json_profiles(text, client_id=""):
    try:
        root = json.loads(str(text or "").strip())
    except ValueError:
        return []
    if isinstance(root, dict) and isinstance(root.get("olcrtc"), dict):
        root = root["olcrtc"]
    if isinstance(root, dict):
        items = root.get("locations") if isinstance(root.get("locations"), list) else [root]
    elif isinstance(root, list):
        items = root
    else:
        return []
    return [p for p in (_profile_from_json(item, client_id) for item in items) if p]


def subscription_profiles(text, client_id=""):
    """Profiles in a subscription: olcrtc:// lines (with "##name:" lines) or JSON."""
    profiles, current = [], None
    for raw_line in str(text or "").lstrip("﻿").splitlines():
        line = raw_line.strip()
        if line.lower().startswith("olcrtc://"):
            data, error = parse_link(line, client_id)
            if data and not error:
                profiles.append(data)
                current = data
        elif current is not None and line.startswith("##") and ":" in line:
            key, value = line[2:].split(":", 1)
            if key.strip().lower() == "name":
                current["name"] = value.strip()[:64]
    return profiles or _json_profiles(text, client_id)


def fetch_subscription(url, timeout_sec=15.0):
    """Subscription text, trying the olcbox client headers first, then a browser's."""
    from . import subscriptions
    accept = "text/plain, text/markdown, application/octet-stream, */*"
    for headers in ({"Accept": accept, "User-Agent": "olcbox/1.0.0", "x-hwid": device_id()},
                    {"Accept": accept, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                                     "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}):
        text = subscriptions.fetch_text(url, timeout_sec, headers=headers)
        if subscription_profiles(text, device_id()):
            return text
    return ""


# --- stored profiles ---

def profile_id(carrier, transport, room_id, client_id, key_hex):
    raw = "|".join([str(carrier or "").strip().lower(), str(transport or "").strip().lower(),
                    str(room_id or "").strip(), str(client_id or "").strip(), str(key_hex or "").strip().lower()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def profile_name(profile):
    name = str(profile.get("name", "") or "").strip()
    if name:
        return name[:48]
    room = str(profile.get("room_id", "") or "").strip()
    client = str(profile.get("client_id", "") or "").strip()
    base = (room.rstrip("/").split("/")[-1] if room else "") or room or client or "olcRTC"
    if client and client not in base:
        base = "%s • %s" % (base, client)
    return base[:48] or "olcRTC"


def build_link(profile):
    carrier = str(profile.get("carrier", "") or "").strip().lower() or "wbstream"
    transport = str(profile.get("transport", "") or "").strip().lower()
    token = transport
    if transport == "vp8channel":
        token += "<vp8-fps=%d&vp8-batch=%d>" % (int(profile.get("vp8_fps", 60) or 60),
                                                int(profile.get("vp8_batch_size", 64) or 64))
    name = str(profile.get("name", "") or "").strip()
    return "olcrtc://%s?%s@%s#%s%s" % (carrier, token, str(profile.get("room_id", "") or "").strip(),
                                       str(profile.get("key_hex", "") or "").strip(), ("$" + name) if name else "")


def normalize_profile(data, default_carrier="telemost"):
    """Stored profile, or None when the room or 64-hex key is missing.

    The client id is always this install's device id.
    """
    if not isinstance(data, dict):
        return None
    carrier = carrier_alias(data.get("carrier")) or default_carrier
    room = str(data.get("room_id", "") or "").strip()
    key = str(data.get("key_hex", "") or "").strip()
    if not room or not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        return None
    transport = str(data.get("transport", "") or "").strip().lower()
    if transport not in supported_transports(carrier):
        transport = supported_transports(carrier)[0]
    client = device_id()
    profile = {"id": profile_id(carrier, transport, room, client, key), "name": str(data.get("name", "") or "").strip()[:64],
               "carrier": carrier, "transport": transport, "room_id": room, "client_id": client, "key_hex": key}
    for field, aliases in (("vp8_fps", ("vp8_fps",)), ("vp8_batch_size", ("vp8_batch_size", "vp8_batch"))):
        try:
            value = int(next((data[a] for a in aliases if data.get(a)), 0) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            profile[field] = value
    profile["link"] = build_link(profile)
    sub_url = str(data.get("subscription_url", "") or "").strip()
    if sub_url.lower().startswith(("http://", "https://")):
        profile["subscription_url"] = sub_url
        try:
            profile["subscription_updated_at"] = int(data.get("subscription_updated_at", 0) or 0)
        except (TypeError, ValueError):
            profile["subscription_updated_at"] = 0
    if not profile["name"]:
        profile["name"] = profile_name(profile)
    return profile


def clean_profiles(items):
    result, seen = [], set()
    for item in list(items or []):
        profile = normalize_profile(item)
        if profile and profile["id"] not in seen:
            seen.add(profile["id"])
            result.append(profile)
        if len(result) >= MAX_PROFILES:
            break
    return result
