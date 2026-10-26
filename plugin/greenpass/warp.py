"""Cloudflare WARP config generator (pure stdlib).

Registers a fresh anonymous WARP device and renders a WireGuard/AmneziaWG .conf for it.
Only the private key, the peer data and the interface addresses end up in the config;
the registration id and token are deliberately dropped and never stored.
"""
import base64
import binascii
import datetime as _warp_dt
import ipaddress
import json
import os
import re
import ssl
import urllib.request

WARP_API_URL = "https://api.cloudflareclient.com/v0a737/reg"
WARP_USER_AGENT = "okhttp/3.12.1"
WARP_TIMEOUT = 15
WARP_MAX_RESPONSE = 256 * 1024
WARP_DEFAULT_ENDPOINT = "engage.cloudflareclient.com:2408"
WARP_CONF_NAME = "Cloudflare_WARP.conf"
# UDP ports the WARP edge accepts WireGuard on. DPI often blocks one port but not the
# others, so every generated config picks one at random.
WARP_PORTS = (2408, 500, 1701, 4500)
WARP_DNS = "1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001"
WARP_MTU = 1280
# Junk packets only: a plain WireGuard server ignores them. S1/S2/H1-H4 must stay at the
# WireGuard defaults or the WARP server drops the handshake.
WARP_OBFUSCATION = (("Jc", 4), ("Jmin", 40), ("Jmax", 70))

_WARP_P = 2 ** 255 - 19
_WARP_A24 = 121665
_WARP_BASEPOINT = (9).to_bytes(32, "little")
_WARP_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class WarpError(Exception):
    pass


def _warp_x25519(k, u):
    """RFC 7748 X25519 via the Montgomery ladder; k and u are 32-byte strings."""
    if len(k) != 32 or len(u) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    p = _WARP_P
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    scalar = int.from_bytes(bytes(kb), "little")
    ub = bytearray(u)
    ub[31] &= 127
    x1 = int.from_bytes(bytes(ub), "little") % p
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + _WARP_A24 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def warp_generate_keypair():
    """Return (private_b64, public_b64): a clamped X25519 key from os.urandom, base64-encoded."""
    priv = bytearray(os.urandom(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    priv = bytes(priv)
    pub = _warp_x25519(priv, _WARP_BASEPOINT)
    return base64.b64encode(priv).decode("ascii"), base64.b64encode(pub).decode("ascii")


def _warp_valid_key(value):
    try:
        return len(base64.b64decode(str(value), validate=True)) == 32
    except (binascii.Error, ValueError, TypeError):
        return False


def _warp_valid_endpoint(value):
    text = str(value or "").strip()
    if text.startswith("["):
        if "]:" not in text:
            return False
        host, port = text[1:].rsplit("]:", 1)
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
    else:
        if text.count(":") != 1:
            return False
        host, port = text.split(":", 1)
        if not _WARP_HOST_RE.match(host):
            return False
    return port.isdigit() and 1 <= int(port) <= 65535


def _warp_valid_ip(value, version):
    try:
        return ipaddress.ip_address(str(value).strip()).version == version
    except ValueError:
        return False


def _warp_dig(obj, *path):
    for key in path:
        if isinstance(key, int):
            if not isinstance(obj, list) or key >= len(obj):
                return None
            obj = obj[key]
        else:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(key)
    return obj


def _warp_parse_response(raw):
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WarpError("ответ WARP не похож на JSON")
    if not isinstance(data, dict):
        raise WarpError("ответ WARP не похож на JSON-объект")
    if data.get("success") is False:
        msg = _warp_dig(data, "errors", 0, "message") or _warp_dig(data, "error", "message") or "отказ API"
        raise WarpError("WARP отклонил регистрацию: %s" % str(msg)[:120])
    peer_key = _warp_dig(data, "config", "peers", 0, "public_key")
    if not isinstance(peer_key, str) or not _warp_valid_key(peer_key):
        raise WarpError("в ответе WARP нет корректного public_key пира")
    endpoint = _warp_dig(data, "config", "peers", 0, "endpoint", "host")
    if endpoint is None or endpoint == "":
        endpoint = WARP_DEFAULT_ENDPOINT
    if not isinstance(endpoint, str) or not _warp_valid_endpoint(endpoint):
        raise WarpError("в ответе WARP некорректный endpoint")
    v4 = _warp_dig(data, "config", "interface", "addresses", "v4")
    v6 = _warp_dig(data, "config", "interface", "addresses", "v6")
    if not isinstance(v4, str) or not _warp_valid_ip(v4, 4):
        raise WarpError("в ответе WARP нет корректного IPv4-адреса")
    if not isinstance(v6, str) or not _warp_valid_ip(v6, 6):
        raise WarpError("в ответе WARP нет корректного IPv6-адреса")
    return {"public_key": peer_key.strip(), "endpoint": endpoint.strip(), "v4": v4.strip(), "v6": v6.strip()}


def register_warp(timeout=WARP_TIMEOUT):
    """Register a new anonymous WARP device. Returns a dict with the private key and the
    peer/interface data needed by build_warp_conf. Raises WarpError on any failure."""
    priv, pub = warp_generate_keypair()
    now = _warp_dt.datetime.now(_warp_dt.timezone.utc)
    tos = now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000)
    body = json.dumps({
        "key": pub,
        "install_id": "",
        "fcm_token": "",
        "warp_enabled": True,
        "tos": tos,
        "type": "Android",
        "locale": "en_US",
    }).encode("utf-8")
    req = urllib.request.Request(
        WARP_API_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": WARP_USER_AGENT},
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(WARP_MAX_RESPONSE + 1)
    except ssl.SSLCertVerificationError:
        raise
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise reason
        if isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError) or "timed out" in str(exc):
            raise WarpError("таймаут запроса к Cloudflare")
        raise WarpError(str(reason or exc) or exc.__class__.__name__)
    if len(raw) > WARP_MAX_RESPONSE:
        raise WarpError("слишком большой ответ WARP")
    parsed = _warp_parse_response(raw)
    parsed["private_key"] = priv
    return parsed


def build_warp_conf(private_key, peer_public_key, endpoint, v4, v6, obfuscation=True):
    """Render the .conf text. Reg id / token are not part of it."""
    lines = [
        "[Interface]",
        "PrivateKey = %s" % private_key,
        "Address = %s/32, %s/128" % (v4, v6),
        "DNS = %s" % WARP_DNS,
        "MTU = %d" % WARP_MTU,
    ]
    if obfuscation:
        lines.extend("%s = %d" % item for item in WARP_OBFUSCATION)
    lines += [
        "",
        "[Peer]",
        "PublicKey = %s" % peer_public_key,
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "Endpoint = %s" % endpoint,
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


def _warp_endpoint_with_random_port(endpoint):
    value = str(endpoint or "").strip()
    if value.startswith("[") and "]" in value:
        host = value[: value.index("]") + 1]
    elif value.count(":") == 1:
        host = value.split(":", 1)[0]
    else:
        host = value
    if not host:
        host = WARP_DEFAULT_ENDPOINT.split(":", 1)[0]
    port = WARP_PORTS[int.from_bytes(os.urandom(2), "big") % len(WARP_PORTS)]
    return "%s:%d" % (host, port)


def generate_warp_conf(timeout=WARP_TIMEOUT):
    """Register and return the finished .conf text."""
    reg = register_warp(timeout)
    endpoint = _warp_endpoint_with_random_port(reg["endpoint"])
    return build_warp_conf(reg["private_key"], reg["public_key"], endpoint, reg["v4"], reg["v6"])
