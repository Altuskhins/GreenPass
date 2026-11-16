"""Decode HitVPN / HitRay share links (hvpn.io, hitray.io, hitvpn://) into vless:// links."""

import base64
import hashlib
import socket
import struct
import urllib.parse

PREFIXES = ("https://hvpn.io/", "https://hitray.io/", "hitvpn://")
_WRAP_TAG = 1
_HASH_KEY = b"IIkYdtWtkU"
_PROTO_VLESS = 2


def is_hitvpn_link(value):
    return str(value or "").strip().lower().startswith(PREFIXES)


class _Cbor:
    """Just enough CBOR for the HitVPN payload."""

    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def read(self):
        head = self._take(1)[0]
        major, extra = head >> 5, head & 0x1F
        if major == 0:
            return self._uint(extra)
        if major == 1:
            return -1 - self._uint(extra)
        if major == 2:
            return self._take(self._uint(extra))
        if major == 3:
            return self._take(self._uint(extra)).decode("utf-8", errors="ignore")
        if major == 4:
            return [self.read() for _ in range(self._uint(extra))]
        if major == 5:
            return {self.read(): self.read() for _ in range(self._uint(extra))}
        if major == 6:
            self._uint(extra)
            return self.read()
        if major == 7 and extra in (20, 21, 22):
            return {20: False, 21: True, 22: None}[extra]
        raise ValueError("unsupported CBOR")

    def _uint(self, extra):
        if extra < 24:
            return extra
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if extra not in sizes:
            raise ValueError("unsupported CBOR length")
        return int.from_bytes(self._take(sizes[extra]), "big")

    def _take(self, size):
        if self.pos + size > len(self.data):
            raise ValueError("truncated CBOR")
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        return chunk


def _b64url(text):
    text = str(text).replace("-", "+").replace("_", "/")
    return base64.b64decode(text + "=" * (-len(text) % 4))


def _unxor(salt, payload):
    base = hashlib.sha256(_HASH_KEY + salt)
    block = base.copy().digest()
    index = 0
    for i in range(len(payload)):
        if index >= len(block):
            base.update(block[:8])
            block = base.copy().digest()
            index = 0
        payload[i] ^= block[index]
        index += 1


def _unwrap(encoded):
    raw = _b64url(encoded)
    if len(raw) < 32 or raw[0] != _WRAP_TAG:
        raise ValueError("not a HitVPN link")
    salt, digest_prefix, payload = raw[1:5], raw[5:9], bytearray(raw[9:])
    if int.from_bytes(salt, "little"):
        _unxor(salt, payload)
    if hashlib.sha256(payload).digest()[:4] != digest_prefix:
        raise ValueError("HitVPN hash mismatch")
    root = _Cbor(payload).read()
    if not isinstance(root, dict):
        raise ValueError("HitVPN root is not a map")
    return root


def _vless_link(cfg):
    uuid_hex = bytes(cfg.get(1, b"") or b"").hex()
    if len(uuid_hex) != 32:
        return ""
    uuid = "-".join((uuid_hex[0:8], uuid_hex[8:12], uuid_hex[12:16], uuid_hex[16:20], uuid_hex[20:32]))
    try:
        address = socket.inet_ntoa(struct.pack("!I", int(cfg.get(3, 0) or 0)))
    except (struct.error, OSError, ValueError):
        return ""
    port = int(cfg.get(4, 0) or 0)
    if port <= 0:
        return ""
    query = urllib.parse.urlencode({
        "type": "udp" if int(cfg.get(5, 0) or 0) == 1 else "tcp",
        "security": "reality" if int(cfg.get(6, 0) or 0) else "none",
        "pbk": base64.urlsafe_b64encode(bytes(cfg.get(2, b"") or b"")).decode("ascii").rstrip("="),
        "sni": str(cfg.get(7, "") or ""),
        "fp": "random",
        "sid": "42",
        "spx": "/",
        "flow": "xtls-rprx-vision",
    })
    return "vless://%s@%s:%d?%s" % (uuid, address, port, query)


def decode(link):
    """vless:// links in a HitVPN share link; [] when it is not one or is broken."""
    text = str(link or "").strip()
    for prefix in PREFIXES:
        if text.lower().startswith(prefix):
            encoded = text[len(prefix):]
            break
    else:
        return []
    try:
        root = _unwrap(encoded)
    except (ValueError, TypeError):
        return []
    links = []
    for item in list(root.get(4, []) or []):
        if not isinstance(item, dict) or int(item.get(1, 0) or 0) != _PROTO_VLESS:
            continue
        try:
            cfg = _Cbor(bytes(item.get(2, b"") or b"")).read()
            link = _vless_link(cfg) if isinstance(cfg, dict) else ""
        except (ValueError, TypeError):
            link = ""
        if link and link not in links:
            links.append(link)
    return links
