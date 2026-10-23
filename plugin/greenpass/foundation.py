__id__ = "GreenPass"
__name__ = "GreenPass"
__description__ = "Практически универсальный прокси плагин, поддержка протоколов vless/vmess/hysteria2/etc., встроенные tg-ws-proxy, AmneziaWG и olcrtc, а также полноценнымм проксированием звонков"
__author__ = "@Altyplugins / Claude"
__version__ = "2.6.5"
__icon__ = "bratpass/0"
__app_version__ = ">=12.5.1"
__sdk_version__ = ">=1.4.5.3"


import base64
import ctypes
import io
import json
import threading
import urllib.request
import urllib.error
import urllib.parse
import time
import ssl
import random
import re
import os
import gzip
import lzma
import hashlib
import hmac
import socket
import struct
import sys
import types
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from base_plugin import BasePlugin, AppEvent, MethodHook, MenuItemData, MenuItemType
from ui.bulletin import BulletinHelper as _BulletinHelper
from ui.alert import AlertDialogBuilder as _AlertDialogBuilder
from ui.settings import Header as _Header, Text as _Text, Divider, Selector as _Selector, Switch as _Switch, EditText as _EditText
from ui.settings import Custom as _Custom
from android_utils import run_on_ui_thread
from client_utils import get_last_fragment, send_document
from hook_utils import find_class
try:
    # SDK 1.4.5.0+: explicit account targeting for client_utils helpers.
    from client_utils import get_selected_account
except:
    get_selected_account = None
try:
    from elyx import get_environment as _elyx_get_environment
except:
    _elyx_get_environment = None
try:
    from java import jclass, dynamic_proxy
except:
    jclass = None
    dynamic_proxy = None
try:
    from java.lang import Integer
except:
    Integer = None
from java.util import Locale
from org.telegram.messenger import NotificationCenter, SharedConfig, MessagesController, UserConfig, ApplicationLoader, LocaleController, AndroidUtilities
from org.telegram.messenger.browser import Browser
from org.telegram.tgnet import ConnectionsManager
from org.telegram.ui.ActionBar import Theme
from org.telegram.ui.Components import LineProgressView
from android.graphics.drawable import GradientDrawable
from android.util import TypedValue
from android.view import View, ViewGroup, Gravity
from android.widget import FrameLayout, ImageView, LinearLayout, TextView
try:
    from javax.crypto import Cipher as JavaCipher
    from javax.crypto.spec import SecretKeySpec, IvParameterSpec
except:
    JavaCipher = None
    SecretKeySpec = None


def _is_elyx_runtime():
    if _elyx_get_environment is not None:
        try:
            _elyx_get_environment()
            return True
        except:
            pass
    try:
        path = os.path.abspath(str(__file__ or ""))
        normalized = path.replace("\\", "/").lower()
        if "/elyxplugins/" in normalized:
            return True
        parent = os.path.dirname(path)
        for _ in range(4):
            if any(os.path.isfile(os.path.join(parent, name)) for name in ("refmap.yml", "refmap.yaml", "refmap.json")):
                return True
            parent = os.path.dirname(parent)
    except:
        pass
    return False


def _selected_account():
    if get_selected_account is not None:
        try:
            return int(get_selected_account())
        except:
            pass
    try:
        return int(UserConfig.selectedAccount)
    except:
        return 0


def _send_document_as(account, peer, path, **kwargs):
    # Older SDKs have no account= and always send from the selected account.
    if get_selected_account is not None:
        return send_document(peer, path, account=account, **kwargs)
    return send_document(peer, path, **kwargs)

from .i18n_catalogs import *


def _is_ru_token(value):
    try:
        text = str(value or "").strip().lower()
    except Exception:
        return False
    return bool(text and (text.startswith("ru") or text.startswith("рус") or "ru_" in text or "ru-" in text or "рус" in text))


def _is_ru_language():
    try:
        info = LocaleController.getInstance().getCurrentLocaleInfo()
        if info is not None:
            return any(_is_ru_token(getattr(info, attr, None)) for attr in ("shortName", "pluralLangCode", "name", "nameEnglish"))
    except Exception:
        pass
    try:
        return _is_ru_token(Locale.getDefault().getLanguage()) or _is_ru_token(Locale.getDefault().toString())
    except Exception:
        return False


def _is_zh_token(value):
    try:
        text = str(value or "").strip().lower()
    except Exception:
        return False
    return bool(text and (text.startswith("zh") or text.startswith("chi") or "zh_" in text or "zh-" in text or "chinese" in text))


def _is_zh_language():
    try:
        info = LocaleController.getInstance().getCurrentLocaleInfo()
        if info is not None:
            return any(_is_zh_token(getattr(info, attr, None)) for attr in ("shortName", "pluralLangCode", "name", "nameEnglish"))
    except Exception:
        pass
    try:
        return _is_zh_token(Locale.getDefault().getLanguage()) or _is_zh_token(Locale.getDefault().toString())
    except Exception:
        return False


def Z(value):
    text = str(value or "")
    if _is_ru_language():
        return text
    if _is_zh_language():
        translated = TRANSLATIONS_ZH.get(text)
        if translated is not None:
            return translated
        for source, target in TRANSLATION_PARTS_ZH:
            text = text.replace(source, target)
        for source, target in TRANSLATION_FRAGMENTS_ZH:
            text = text.replace(source, target)
        return text
    translated = TRANSLATIONS_EN.get(text)
    if translated is not None:
        return translated
    for source, target in TRANSLATION_PARTS_EN:
        text = text.replace(source, target)
    for source, target in TRANSLATION_FRAGMENTS_EN:
        text = text.replace(source, target)
    return text


__description__ = Z(__description__)


def _localized_setting(factory, args, kwargs):
    args = list(args)
    if args and isinstance(args[0], str):
        args[0] = Z(args[0])
    for key in ("text", "subtext", "hint"):
        if key in kwargs and kwargs[key] is not None:
            kwargs[key] = Z(kwargs[key])
    if "items" in kwargs:
        kwargs["items"] = [Z(item) if isinstance(item, str) else item for item in list(kwargs["items"] or [])]
    return factory(*args, **kwargs)


def Header(*args, **kwargs): return _localized_setting(_Header, args, kwargs)
def Text(*args, **kwargs): return _localized_setting(_Text, args, kwargs)
def Selector(*args, **kwargs): return _localized_setting(_Selector, args, kwargs)
def Switch(*args, **kwargs): return _localized_setting(_Switch, args, kwargs)
def EditText(*args, **kwargs): return _localized_setting(_EditText, args, kwargs)


class BulletinHelper:
    @staticmethod
    def show_info(text, *args, **kwargs): return _BulletinHelper.show_info(Z(text), *args, **kwargs)
    @staticmethod
    def show_error(text, *args, **kwargs): return _BulletinHelper.show_error(Z(text), *args, **kwargs)
    @staticmethod
    def show_success(text, *args, **kwargs): return _BulletinHelper.show_success(Z(text), *args, **kwargs)


class AlertDialogBuilder:
    def __init__(self, *args, **kwargs):
        self._builder = _AlertDialogBuilder(*args, **kwargs)

    def set_title(self, text, *args): return self._builder.set_title(Z(text), *args)
    def set_message(self, text, *args): return self._builder.set_message(Z(text), *args)
    def set_positive_button(self, text, *args): return self._builder.set_positive_button(Z(text), *args)
    def set_negative_button(self, text, *args): return self._builder.set_negative_button(Z(text), *args)
    def set_items(self, items, *args): return self._builder.set_items([Z(item) if isinstance(item, str) else item for item in list(items or [])], *args)
    def __getattr__(self, name): return getattr(self._builder, name)

def _greenpass_native_abi(machine=None, pointer_size=None):
    if machine is None:
        try:
            machine = os.uname().machine
        except:
            machine = ""
    if pointer_size is None:
        pointer_size = struct.calcsize("P")
    machine = str(machine or "").strip().lower()
    if "arm" not in machine and "aarch" not in machine:
        return ""
    return "arm64-v8a" if int(pointer_size) >= 8 else "armeabi-v7a"


SINGBOX_BUNDLES = {
    "arm64-v8a": {
        "file": "libgreenpass.so.xz",
        "so_size": 126646176,
        "so_sha256": "da0db309d4d118d03b4797c8a097c8bdb7dbf3ce168d91f4a0af6248af7b389a",
        "bundle_size": 25513204,
        "bundle_sha256": "b43ef0257bf3a53fe984ceee284d2a1893d4a3bc2fd7876c6b39c90819db9ca4",
    },
    "armeabi-v7a": {
        "file": "libgreenpass-armeabi-v7a.so.xz",
        "so_size": 115947844,
        "so_sha256": "3cef15595ec068aad8b777c8cb8b01d3efbb1fff52b9168734209a574970c349",
        "bundle_size": 26078408,
        "bundle_sha256": "d58d9c8fe7834d9f780ee3cee9b47ca4c3503e6ccd525f8018726341bef9fe2b",
    },
}
SINGBOX_ABI = _greenpass_native_abi()
SINGBOX_BUNDLE = SINGBOX_BUNDLES.get(SINGBOX_ABI, {})
SINGBOX_BUNDLE_FILE = str(SINGBOX_BUNDLE.get("file", "") or "")
SINGBOX_BUNDLE_URLS = tuple(
    template % SINGBOX_BUNDLE_FILE
    for template in (
        # The newer core in ядро/build/cabi needs a public host first: the
        # plugin cannot download from a private repository.
        "https://gitflic.ru/project/plgnss/grnpsslib/blob/raw?file=%s&branch=main",
    )
    if SINGBOX_BUNDLE_FILE
)
SINGBOX_SO_FILE = "libgreenpass.so"
SINGBOX_SO_SIZE = int(SINGBOX_BUNDLE.get("so_size", 0) or 0)
SINGBOX_SO_SHA256 = str(SINGBOX_BUNDLE.get("so_sha256", "") or "")
SINGBOX_BUNDLE_SIZE = int(SINGBOX_BUNDLE.get("bundle_size", 0) or 0)
SINGBOX_BUNDLE_SHA256 = str(SINGBOX_BUNDLE.get("bundle_sha256", "") or "")
GREENPASS_RELEASES_LATEST_URL = "https://api.github.com/repos/Altuskhins/GreenPass/releases/latest"
VLESS_IMPORT_CLIPBOARD_MAX = 8192
VLESS_LOCAL_HOST = "127.0.0.1"
VLESS_LOCAL_PORT = 10804
VLESS_LOCAL_READY_TIMEOUT_SEC = 12.0
VLESS_RESUME_LOCAL_GRACE_SEC = 6.0
VLESS_RESUME_AUTO_READY_TIMEOUT_SEC = 30.0
VLESS_RESUME_AUTO_RECOVERY_DELAY_SEC = 20.0
VLESS_REMOTE_CHECK_TIMEOUT_SEC = 3.0
VLESS_NODE_PING_TIMEOUT_SEC = 1.5
VLESS_NODE_PING_REFRESH_SEC = 45.0
VLESS_NODE_PING_STALE_SEC = 90.0
VLESS_BALANCER_MAX_NODES = 32
VLESS_AUTO_SUBSCRIPTIONS_URI = "greenpass-auto://subscriptions"
VLESS_RETRY_BASE_SEC = 30.0
VLESS_RETRY_MAX_SEC = 300.0
VLESS_KIND = "vless"
VLESS_ENGINE_SINGBOX = "singbox"
VLESS_ENGINE_MIHOMO = "mihomo"
VLESS_ENGINE_ITEMS = ("sing-box", "Mihomo")
MIHOMO_CONFIG_MAX_BYTES = 1024 * 1024
PROXY_PROTOCOL_REGISTRY = {
    "vless": {"parser": "_parse_vless_uri_details", "builder": "_build_singbox_config", "label": "VLESS"},
    "vmess": {"parser": "_parse_vmess_uri_details", "builder": "_build_singbox_config", "label": "VMess"},
    "trojan": {"parser": "_parse_trojan_uri_details", "builder": "_build_singbox_config", "label": "Trojan"},
    "ss": {"parser": "_parse_ss_uri_details", "builder": "_build_singbox_config", "label": "Shadowsocks"},
    "hy2": {"parser": "_parse_hysteria2_uri_details", "builder": "_build_singbox_config", "label": "Hysteria2"},
    "hysteria2": {"parser": "_parse_hysteria2_uri_details", "builder": "_build_singbox_config", "label": "Hysteria2"},
    "tuic": {"parser": "_parse_tuic_uri_details", "builder": "_build_singbox_config", "label": "TUIC"},
    "anytls": {"parser": "_parse_anytls_uri_details", "builder": "_build_singbox_config", "label": "AnyTLS"},
    "ssh": {"parser": "_parse_ssh_uri_details", "builder": "_build_singbox_config", "label": "SSH"},
    "shadowtls": {"parser": "_parse_shadowtls_uri_details", "builder": "_build_singbox_config", "label": "ShadowTLS"},
    "hy": {"parser": "_parse_hysteria_uri_details", "builder": "_build_singbox_config", "label": "Hysteria"},
    "hysteria": {"parser": "_parse_hysteria_uri_details", "builder": "_build_singbox_config", "label": "Hysteria"},
    "naive": {"parser": "_parse_naive_uri_details", "builder": "_build_singbox_config", "label": "Naive"},
    "mieru": {"parser": "_parse_mieru_uri_details", "builder": "_build_singbox_config", "label": "Mieru"},
    "sudoku": {"parser": "_parse_sudoku_uri_details", "builder": "_build_singbox_config", "label": "Sudoku"},
}
PROXY_URI_SCHEMES = tuple(PROXY_PROTOCOL_REGISTRY)
QWDTT_KIND = "qwdtt"
QWDTT_URI_SCHEMES = ("wdtt", "qwdtt")
TGWS_KIND = "tgws"
AWG_KIND = "awg"
OLCRTC_KIND = "olcrtc"
TGWS_LOCAL_PORT = 10805
AWG_LOCAL_PORT = 2337
OLCRTC_LOCAL_PORT = 11808
PROXY_PORT = AWG_LOCAL_PORT
TGWS_LOCAL_READY_TIMEOUT_SEC = 6.0
OLCRTC_LOCAL_READY_TIMEOUT_SEC = 22.0
OLCRTC_TUNNEL_CHECK_TIMEOUT_SEC = 1.2
TGWS_CONNECT_CONFIRM_TIMEOUT_SEC = 12.0
TGWS_HEAL_COOLDOWN_SEC = 8.0
TGWS_BRIDGE_IDLE_TIMEOUT_SEC = 3600.0
TGWS_WS_CONNECT_TIMEOUT_SEC = 5.0
# After a WS failure the DC is still tried over WS, only with a shorter timeout.
TGWS_WS_FAIL_TIMEOUT_SEC = 2.0
TGWS_WS_FAIL_COOLDOWN_SEC = 60.0
TGWS_IP_FAIL_COOLDOWN_SEC = 3600.0
TGWS_WS_BLACKLIST_TTL_SEC = 420.0
TGWS_CFPROXY_CONNECT_TIMEOUT_SEC = 8.0
TGWS_CFPROXY_429_COOLDOWN_SEC = 45.0
TGWS_WS_POOL_SIZE = 4
TGWS_WS_POOL_CONNECT_TIMEOUT_SEC = 8.0
TGWS_WS_POOL_MAX_AGE_SEC = 120.0
TGWS_WS_POOL_CHECK_INTERVAL_SEC = 5.0
TGWS_WS_POOL_REFILL_BACKOFF_INITIAL_SEC = 1.0
TGWS_WS_POOL_REFILL_BACKOFF_MAX_SEC = 3600.0
TGWS_LISTENER_RESTART_DELAY_SEC = 1.0
TGWS_FRONTING_SNI = "sprinthost.ru"
TGWS_PROXY_SECRET_HEX = "00000000000000000000000000000000"
TGWS_SOCKET_BUFFER_SIZE = 256 * 1024
TGWS_RESERVED_PORTS = {VLESS_LOCAL_PORT, OLCRTC_LOCAL_PORT, AWG_LOCAL_PORT}
TGWS_VOIP_RELAY_HOST = ""
TGWS_VOIP_RELAY_CONTROL_PORT = 8765
TGWS_VOIP_RELAY_SECRET = b""
TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC = 1.5
TGWS_VOIP_REFLECTOR_CIDRS = (
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "91.108.58.0/23",
    "91.105.192.0/23",
    "95.161.64.0/20",
    "149.154.160.0/20",
    "185.76.151.0/24",
)
GREENPASS_PROXY_API_MODULE = "greenpass_proxy_api"
GREENPASS_PLUGIN_PROXY_FRIDA_ID = "GreenPassPluginProxy"
GREENPASS_PLUGIN_PROXY_NAME = "greenpass-java-url-proxy"
PLUGIN_PROXY_UI_HANDSHAKE_TIMEOUT_SEC = 2.5
OLCRTC_CARRIER_ITEMS = ("telemost", "jitsi", "wbstream")
OLCRTC_TRANSPORT_ITEMS = ("datachannel", "vp8channel", "videochannel", "seichannel")
OLCRTC_CARRIER_LABELS = ("Яндекс Телемост", "Jitsi Meet", "WB Stream")
OLCRTC_TRANSPORT_LABELS = ("Data-канал", "VP8-канал", "Видео-канал", "SEI-канал")
AWG_FILE_PICKER_REQ = 13371
GREENPASS_IMPORT_FILE_PICKER_REQ = 13372
GREENPASS_EXPORT_FILE_NAME = "export.greenpass"
GREENPASS_EXPORT_FORMAT = "greenpass_export_v1"
VLESS_EGRESS_TEST_TARGETS = [
    ("1.1.1.1", 80),
    ("1.0.0.1", 80),
]
OLCRTC_TEST_TARGETS = [
    ("149.154.167.51", 443),
]
TGWS_DEFAULT_DC_IP = {
    "2": "149.154.167.220",
    "4": "149.154.167.220",
}
TGWS_WS_PATH = "/apiws"
TGWS_WS_PATH_TEST = "/apiws_test"
# Telegram test environment: MTProto DC ids >= 10000 (DC id - 10000).
TGWS_TEST_DC_OFFSET = 10000
TGWS_TEST_DC_IP = {
    "1": "149.154.175.10",
    "2": "149.154.167.40",
    "3": "149.154.175.117",
}
TGWS_DIRECT_FALLBACK_IP = {
    "1": "149.154.175.50",
    "2": "149.154.167.51",
    "3": "149.154.175.100",
    "4": "149.154.167.91",
    "5": "149.154.171.5",
    "203": "91.105.192.100",
}
TGWS_CFPROXY_ENABLED = True
TGWS_CFPROXY_PRIORITY = False
# Plain ws:// (port 80) instead of wss:// for CF proxy / CF worker connections.
TGWS_CFPROXY_DISABLE_SECURE = False

TGWS_CFPROXY_WORKER_DOMAIN = ""

TGWS_CFPROXY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main"
    "/.github/cfproxy-domains.txt"
)
TGWS_CFPROXY_MIN_VALID_DOMAINS = 3
TGWS_CFPROXY_REFRESH_INTERVAL_SEC = 12 * 3600.0
_TGWS_CFPROXY_ENC = [
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
]
_TGWS_CFPROXY_SUFFIX = "".join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _tgws_dd(s):
    try:
        s = str(s or "")
        if s[-4:] != ".com":
            return s
        prefix = s[:-4]
        n = sum(1 for c in prefix if c.isalpha())
        out = []
        for c in prefix:
            if c.isalpha():
                base = 97 if c > "`" else 65
                out.append(chr((ord(c) - base - n) % 26 + base))
            else:
                out.append(c)
        return "".join(out) + _TGWS_CFPROXY_SUFFIX
    except:
        return str(s or "")


def _tgws_is_valid_domain(domain):
    try:
        domain = str(domain or "")
        if not domain or len(domain) > 253:
            return False
        if domain.startswith(".") or domain.endswith("."):
            return False
        labels = domain.split(".")
        if len(labels) < 2:
            return False
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label[0] == "-" or label[-1] == "-":
                return False
            if not all(ch.isalnum() or ch == "-" for ch in label):
                return False
        tld = labels[-1]
        if len(tld) < 2 or not any(ch.isalpha() for ch in tld):
            return False
        return True
    except:
        return False


def _tgws_normalize_domain_pool(domains):
    seen = set()
    normalized = []
    try:
        for domain in list(domains or []):
            item = str(domain or "").strip().lower()
            if not _tgws_is_valid_domain(item):
                continue
            if item in seen:
                continue
            seen.add(item)
            normalized.append(item)
    except:
        pass
    return normalized


def _tgws_fetch_cfproxy_domains(timeout=10.0):
    try:
        bust = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(7))
        url = TGWS_CFPROXY_DOMAINS_URL + "?" + bust
        req = urllib.request.Request(url, headers={"User-Agent": "tg-ws-proxy"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=float(timeout), context=ctx) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        encoded = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return [_tgws_dd(d) for d in encoded]
    except Exception:
        return []


TGWS_CFPROXY_DEFAULT_DOMAINS = _tgws_normalize_domain_pool([_tgws_dd(d) for d in _TGWS_CFPROXY_ENC])
if not TGWS_CFPROXY_DEFAULT_DOMAINS:
    TGWS_CFPROXY_DEFAULT_DOMAINS = [
        "pclead.co.uk",
        "offshor.co.uk",
        "cakeisalie.co.uk",
        "noskomnadzor.co.uk",
        "lovetrue.co.uk",
    ]


def _ipv4_to_int(ip):
    parts = str(ip or "").split(".")
    if len(parts) != 4:
        return -1
    try:
        values = [int(part) for part in parts]
        if any(value < 0 or value > 255 for value in values):
            return -1
        return sum(value << (24 - index * 8) for index, value in enumerate(values))
    except:
        return -1


def _cidr_contains(ip, cidr):
    try:
        base, prefix = str(cidr).split("/", 1)
        address = _ipv4_to_int(ip)
        network = _ipv4_to_int(base)
        prefix = int(prefix)
        if address < 0 or network < 0 or prefix < 0 or prefix > 32:
            return False
        mask = 0 if prefix == 0 else (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return address & mask == network & mask
    except:
        return False


def _is_telegram_reflector_ip(ip):
    return any(_cidr_contains(ip, cidr) for cidr in TGWS_VOIP_REFLECTOR_CIDRS)


def _validate_tgws_voip_relay(ip, port, secret):
    ip = str(ip or "").strip()
    try:
        port = int(str(port).strip())
    except:
        return None, "Порт Relay должен быть числом"
    try:
        if isinstance(secret, bytes):
            secret = secret.decode("utf-8")
    except:
        pass
    secret = str(secret or "")
    if _ipv4_to_int(ip) < 0:
        return None, "Неверный IPv4 Relay"
    if port < 1 or port > 65535:
        return None, "Порт Relay вне диапазона"
    secret_len = len(secret.encode("utf-8"))
    if secret_len < 16 or secret_len > 512:
        return None, "HMAC-ключ: от 16 до 512 байт"
    return (ip, port, secret), ""


def _parse_tgws_voip_relay_link(uri):
    text = str(uri or "").strip().replace("$h=", "&h=")
    try:
        parsed = urllib.parse.urlsplit(text)
        if parsed.scheme.lower() != "tg" or parsed.netloc.lower() != "relay":
            return None, "Неверная ссылка Relay"
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        return _validate_tgws_voip_relay(
            query.get("ip", [""])[-1],
            query.get("port", [""])[-1],
            query.get("h", [""])[-1],
        )
    except:
        return None, "Неверная ссылка Relay"


def _ping_tgws_voip_relay(config):
    relay_ip, relay_port, secret = config
    try:
        nonce = os.urandom(16)
        body = bytearray((2, 1))
        body.extend(struct.pack(">Q", int(time.time())))
        body.extend(nonce)
        body.extend(struct.pack(">IHH", _ipv4_to_int("149.154.167.50"), 443, 0))
        secret = secret.encode("utf-8")
        body.extend(hmac.new(secret, bytes(body), hashlib.sha256).digest())
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(float(TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC))
            sock.connect((relay_ip, relay_port))
            sock.send(bytes(body))
            response = sock.recv(128)
        if (
            len(response) != 48
            or response[0] != 2
            or response[1] != 9
            or not hmac.compare_digest(
                response[16:],
                hmac.new(secret, response[:16], hashlib.sha256).digest(),
            )
        ):
            return None
        return max(1, int(round((time.monotonic() - started) * 1000)))
    except:
        return None


VLESS_PROVIDER_ITEMS = [
    "Текущий",
    "Shrimp",
    "Akres",
    "Elix",
    "Sworkle",
]

HITVPN_LINK_PREFIX = "https://hvpn.io/"
HITRAY_LINK_PREFIX = "https://hitray.io/"
HITVPN_SCHEME_PREFIX = "hitvpn://"
HITVPN_WRAP_TAG = 1
HITVPN_WRAP_HASH_KEY = b"IIkYdtWtkU"
HITVPN_PROTO_VLESS = 2

VLESS_PROVIDER_SUBS = {
    1: [],
    2: [],
    3: [],
    4: [],
}
_LAST_VLESS_FETCH_DIAG = {}


PROXY_TRANSITION_KILLSWITCH_RESUME_DELAY_SEC = 0.12
PROXY_TRANSITION_KILLSWITCH_FAILSAFE_SEC = 2.5
PLUGIN_AUTOUPDATE_CHECK_INTERVAL_SEC = 3 * 60 * 60


def _is_tg_proxy_enabled():
    try:
        return bool(MessagesController.getGlobalMainSettings().getBoolean("proxy_enabled", False))
    except:
        return False


def _make_native_proxy_settings(address, port, username="", password="", secret="", proxy_type="SOCKS5"):
    """Create ProxySettings on newer Telegram forks; return None on legacy builds."""
    for settings_path in ("org.telegram.utils.proxy.ProxySettings", "org.telegram.proxy.ProxySettings"):
        try:
            settings_class = find_class(settings_path)
            builder = settings_class.builder()
            builder.setAddress(str(address or ""))
            builder.setPort(int(port or 0))
            builder.setUser(str(username or ""))
            builder.setPassword(str(password or ""))
            builder.setSecret(str(secret or ""))
            try:
                type_class = find_class(settings_path + "$Type")
                builder.setType(getattr(type_class, str(proxy_type or "SOCKS5")))
            except:
                pass
            return builder.build()
        except:
            continue
    return None


def _set_native_proxy_settings(enabled, address="", port=0, username="", password="", secret="", proxy=None, proxy_type="SOCKS5"):
    """Support the old six-argument and new ProxySettings overloads."""
    if not bool(enabled):
        try:
            ConnectionsManager.setProxySettings(False, None)
            return True
        except:
            try:
                ConnectionsManager.setProxySettings(False, "", 0, "", "", "")
                return True
            except:
                return False

    try:
        settings = getattr(proxy, "settings", None) if proxy is not None else None
        if settings is not None:
            ConnectionsManager.setProxySettings(True, settings)
            return True
    except:
        pass

    values = {
        "address": address,
        "port": port,
        "username": username,
        "password": password,
        "secret": secret,
    }
    if proxy is not None:
        for key, names in (
            ("address", ("address", "getAddress")),
            ("port", ("port", "getPort")),
            ("username", ("username", "user", "getUser")),
            ("password", ("password", "getPassword")),
            ("secret", ("secret", "getSecret")),
        ):
            for name in names:
                try:
                    value = getattr(proxy, name)
                    if callable(value):
                        value = value()
                    values[key] = value
                    break
                except:
                    continue

    try:
        settings = _make_native_proxy_settings(
            values.get("address", address), values.get("port", port),
            values.get("username", username), values.get("password", password),
            values.get("secret", secret), proxy_type=proxy_type,
        )
        if settings is not None:
            ConnectionsManager.setProxySettings(True, settings)
            return True
    except:
        pass

    try:
        ConnectionsManager.setProxySettings(
            True,
            str(values.get("address", address) or address),
            int(values.get("port", port) or port),
            str(values.get("username", username) or username),
            str(values.get("password", password) or password),
            str(values.get("secret", secret) or secret),
        )
        return True
    except:
        return False


def _set_tg_proxy_enabled(enabled):
    try:
        val = bool(enabled)
    except:
        val = False

    try:
        prefs = MessagesController.getGlobalMainSettings()
        ed = prefs.edit()
        ed.putBoolean("proxy_enabled", val)
        ed.commit()
    except:
        pass

    try:
        SharedConfig.proxyEnabled = val
        if hasattr(SharedConfig, "saveConfig"):
            SharedConfig.saveConfig()
    except:
        pass

    try:
        if val and SharedConfig.currentProxy is not None:
            p = SharedConfig.currentProxy
            _set_native_proxy_settings(True, proxy=p)
        else:
            _set_native_proxy_settings(False)
    except:
        pass

    try:
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
    except:
        pass

__all__ = [name for name in globals() if not name.startswith("__")]
