"""Moving GreenPass data in and out: the .greenpass export, config files people send
in chats (.singconf, .mihomo, .qwdtt), and olcRTC text imports."""

import gzip
import json
import os
import time

from . import olcrtc_links
from .meta import PLUGIN_ID, VERSION

EXPORT_FILE_NAME = "export.greenpass"
EXPORT_FORMAT = "greenpass_export_v1"
MAX_IMPORT_BYTES = 8 * 1024 * 1024

# Plugin settings that travel with the export (the rest of the state is config.json).
SETTINGS_KEYS = (
    "use_proxy", "proxy_calls_via_proxy", "tgws_voip_relay_enabled", "tgws_voip_relay_ip",
    "tgws_voip_relay_port", "tgws_voip_relay_hmac", "dont_use_with_vpn", "proxy_plugins_via_greenpass",
    "subscription_hwid_custom", "vless_browser_page_size", "vless_auto_check_minutes",
    "vless_failover_enabled", "vless_browser_hidden_sources", "ipv6_enabled", "tgws_cfproxy_priority",
    "awg_warp_port", "local_port_vless", "local_port_tgws", "local_port_awg", "local_port_olcrtc",
)
_BOOL_KEYS = {"use_proxy", "proxy_calls_via_proxy", "tgws_voip_relay_enabled", "dont_use_with_vpn",
              "proxy_plugins_via_greenpass", "vless_failover_enabled", "ipv6_enabled", "tgws_cfproxy_priority"}
_INT_KEYS = {"vless_browser_page_size", "vless_auto_check_minutes"}

FILE_KINDS = {".greenpass": "greenpass", ".singconf": "singbox", ".mihomo": "mihomo", ".qwdtt": "qwdtt"}


def clean_setting(key, value):
    if key in _BOOL_KEYS:
        if isinstance(value, str):
            return value.strip().lower() not in ("", "0", "false", "off", "no")
        return bool(value)
    if key in _INT_KEYS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if key == "vless_browser_hidden_sources":
        try:
            values = value if isinstance(value, (list, tuple, set)) else json.loads(str(value or "[]"))
        except ValueError:
            values = []
        return json.dumps(sorted({str(v).strip() for v in values if str(v or "").strip()}),
                          ensure_ascii=False, separators=(",", ":"))
    return str(value if value is not None else "")


def export_bytes(store, settings):
    """gzip'd JSON with config.json and the plugin settings."""
    payload = {"format": EXPORT_FORMAT, "plugin_id": PLUGIN_ID, "plugin_version": VERSION,
               "exported_at": int(time.time()), "config": store.to_dict(), "settings": settings}
    return gzip.compress(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def decode_export(raw):
    payload = json.loads(gzip.decompress(bytes(raw)).decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("format") != EXPORT_FORMAT:
        raise ValueError("не файл экспорта GreenPass")
    if not isinstance(payload.get("config"), dict):
        raise ValueError("в файле нет настроек")
    if payload.get("settings") is not None and not isinstance(payload.get("settings"), dict):
        raise ValueError("повреждённые настройки")
    return payload


def file_kind(name):
    name = str(name or "").strip().lower()
    return next((kind for ext, kind in FILE_KINDS.items() if name.endswith(ext)), "")


def read_text(path, limit=MAX_IMPORT_BYTES):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read(limit + 1)[:limit + 1]


def parse_olcrtc_text(text):
    """(profile data, "") from JSON, a link or a call URL; (None, error) otherwise."""
    raw = str(text or "").strip()
    if not raw:
        return None, "Буфер обмена пуст"
    data = None
    for candidate in (raw, raw[raw.find("{"):raw.rfind("}") + 1] if "{" in raw and "}" in raw else ""):
        try:
            data = json.loads(candidate) if candidate else None
            break
        except ValueError:
            continue
    if isinstance(data, dict):
        if isinstance(data.get("olcrtc"), dict):
            data = data["olcrtc"]
        profile = olcrtc_links._profile_from_json(data, olcrtc_links.device_id())
        if profile:
            return profile, ""
        carrier = data.get("carrier", data.get("provider", ""))
        return {
            "carrier": olcrtc_links.carrier_alias(carrier) or str(carrier or "").strip(),
            "transport": olcrtc_links.transport_alias(data.get("transport")) or str(data.get("transport", "") or "").strip(),
            "room_id": str(data.get("room_id", data.get("room", "")) or "").strip(),
            "client_id": str(data.get("client_id", data.get("device_id", "")) or "").strip() or olcrtc_links.device_id(),
            "key_hex": str(data.get("key_hex", data.get("key", "")) or "").strip(),
        }, ""
    return olcrtc_links.parse_link(raw, olcrtc_links.device_id())


# --- Android side: files from chats and the system picker ---

def document_name(message):
    try:
        name = message.getDocumentName()
        if name:
            return str(name)
    except Exception:
        pass
    try:
        for attribute in list(getattr(message.getDocument(), "attributes", None) or []):
            name = str(getattr(attribute, "file_name", "") or "")
            if name:
                return name
    except Exception:
        pass
    return ""


def document_path(message):
    """Local path of a downloaded chat document, or ""."""
    from hook_utils import find_class
    attempts = (
        lambda: find_class("com.exteragram.messenger.utils.chats.ChatUtils").getInstance().getPathToMessage(message),
        lambda: message.messageOwner.media.document.localPath,
        lambda: message.getDocument().getPathName(),
        lambda: find_class("org.telegram.messenger.FileLoader").getInstance(int(message.currentAccount))
        .getPathToAttach(message.getDocument(), True).getAbsolutePath(),
    )
    for attempt in attempts:
        try:
            path = str(attempt() or "")
            if path and os.path.exists(path):
                return path
        except Exception:
            continue
    return ""


def read_content_uri(activity, uri, limit=MAX_IMPORT_BYTES):
    """Bytes behind a content:// URI from the file picker."""
    from java import jarray, jbyte
    stream = activity.getContentResolver().openInputStream(uri)
    if stream is None:
        raise OSError("не удалось открыть файл")
    buffer = jarray(jbyte)(65536)
    chunks, total = [], 0
    try:
        while True:
            count = int(stream.read(buffer))
            if count < 0:
                break
            total += count
            if total > limit:
                raise OSError("файл слишком большой")
            chunks.append(bytes(buffer)[:count])
    finally:
        stream.close()
    return b"".join(chunks)
