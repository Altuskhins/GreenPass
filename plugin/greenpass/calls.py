"""Voice Relay: send Telegram call traffic through the user's UDP relay server.

Telegram's call endpoints (reflectors) are rewritten to ports the relay
allocates for them. Protocol: HMAC-SHA256-signed UDP requests to the relay's
control port; a challenge round, then an allocation.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import struct
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

ENABLED_SETTING = "tgws_voip_relay_enabled"
IP_SETTING = "tgws_voip_relay_ip"
PORT_SETTING = "tgws_voip_relay_port"
SECRET_SETTING = "tgws_voip_relay_hmac"
DEFAULT_CONTROL_PORT = 8765
ALLOCATE_TIMEOUT_SEC = 1.5
RETRY_AFTER_FAIL_SEC = 20.0

_REFLECTOR_NETS = [ipaddress.ip_network(cidr) for cidr in (
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
    "91.108.56.0/22", "91.108.58.0/23", "91.105.192.0/23", "95.161.64.0/20", "149.154.160.0/20",
    "185.76.151.0/24")]

_OP_CHALLENGE = 1
_OP_ALLOCATE = 2
_REPLY_CHALLENGE = 9


def is_reflector(ip):
    try:
        address = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    return address.version == 4 and any(address in net for net in _REFLECTOR_NETS)


def validate(ip, port, secret):
    """((ip, port, secret), "") or (None, error)."""
    ip = str(ip or "").strip()
    try:
        port = int(str(port).strip())
    except ValueError:
        return None, "Порт Relay должен быть числом"
    if isinstance(secret, bytes):
        secret = secret.decode("utf-8", errors="ignore")
    secret = str(secret or "")
    try:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError
    except ValueError:
        return None, "Неверный IPv4 Relay"
    if not 1 <= port <= 65535:
        return None, "Порт Relay вне диапазона"
    if not 16 <= len(secret.encode("utf-8")) <= 512:
        return None, "HMAC-ключ: от 16 до 512 байт"
    return (ip, port, secret), ""


def parse_link(uri):
    """tg://relay?ip=..&port=..&h=.. -> validate() result."""
    text = str(uri or "").strip().replace("$h=", "&h=")
    try:
        parts = urllib.parse.urlsplit(text)
        if parts.scheme.lower() != "tg" or parts.netloc.lower() != "relay":
            return None, "Неверная ссылка Relay"
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    except ValueError:
        return None, "Неверная ссылка Relay"
    return validate(query.get("ip", [""])[-1], query.get("port", [""])[-1], query.get("h", [""])[-1])


def build_link(config):
    ip, port, secret = config
    return "tg://relay?" + urllib.parse.urlencode({"ip": ip, "port": port, "h": secret})


def _request(secret, operation, nonce, target_ip, target_port):
    body = bytearray((2, operation))
    body += struct.pack(">Q", int(time.time()))
    body += nonce
    body += struct.pack(">IHH", int(ipaddress.ip_address(target_ip)), int(target_port), 0)
    body += hmac.new(secret, bytes(body), hashlib.sha256).digest()
    return bytes(body)


def _valid(secret, data):
    return (len(data) == 48 and data[0] == 2
            and hmac.compare_digest(data[16:], hmac.new(secret, data[:16], hashlib.sha256).digest()))


def ping(config):
    """Round-trip ms to the relay's challenge, or None when it does not answer correctly."""
    ip, port, secret = config
    key = secret.encode("utf-8")
    try:
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(ALLOCATE_TIMEOUT_SEC)
            sock.connect((ip, port))
            sock.send(_request(key, _OP_CHALLENGE, os.urandom(16), "149.154.167.50", 443))
            reply = sock.recv(128)
        if not _valid(key, reply) or reply[1] != _REPLY_CHALLENGE:
            return None
        return max(1, int(round((time.monotonic() - started) * 1000)))
    except OSError:
        return None


class VoiceRelay:
    def __init__(self, app):
        self.app = app
        self._retry_after = 0.0

    def enabled(self):
        return bool(self.app.setting(ENABLED_SETTING, True)) and not self.app.suspended_reason

    def config(self):
        return validate(self.app.setting(IP_SETTING, ""), self.app.setting(PORT_SETTING, str(DEFAULT_CONTROL_PORT)),
                        self.app.setting(SECRET_SETTING, ""))

    def save(self, config):
        ip, port, secret = config
        self._retry_after = 0.0
        self.app.set_setting(IP_SETTING, ip)
        self.app.set_setting(PORT_SETTING, str(port))
        self.app.set_setting(SECRET_SETTING, secret)
        self.app.set_setting(ENABLED_SETTING, True)

    def _allocate(self, config, target_ip, target_port, deadline):
        """(relay_ip, relay_port) for one reflector, or None."""
        ip, port, secret = config
        key = secret.encode("utf-8")
        nonce = os.urandom(16)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((ip, port))
                sock.send(_request(key, _OP_CHALLENGE, nonce, target_ip, target_port))
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                challenge = sock.recv(128)
                if not _valid(key, challenge) or challenge[1] != _REPLY_CHALLENGE:
                    return None
                sock.send(_request(key, _OP_ALLOCATE, nonce[:8] + challenge[8:16], target_ip, target_port))
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                reply = sock.recv(128)
        except (OSError, ValueError):
            return None
        if not _valid(key, reply) or reply[8:16] != nonce[:8] or reply[1] != 0:
            return None
        relay_port = struct.unpack(">H", reply[2:4])[0]
        return (ip, relay_port) if relay_port > 0 else None

    def allocate_all(self, targets):
        """Relay addresses for [(ip, port)] reflectors, None where allocation failed."""
        targets = list(targets)
        config, _ = self.config()
        if not targets or config is None or time.monotonic() < self._retry_after:
            return [None] * len(targets)
        deadline = time.monotonic() + ALLOCATE_TIMEOUT_SEC
        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
            relays = list(pool.map(lambda t: self._allocate(config, t[0], t[1], deadline), targets))
        self._retry_after = 0.0 if any(relays) else time.monotonic() + RETRY_AFTER_FAIL_SEC
        return relays

    def rewrite_group_call_join(self, payload):
        """Group call join response JSON with reflector candidates moved to the relay."""
        if not self.enabled():
            return payload
        try:
            data = json.loads(str(payload))
            candidates = data.get("transport", {}).get("candidates", [])
            picked = [c for c in candidates if isinstance(c, dict) and is_reflector(c.get("ip"))]
        except (ValueError, AttributeError):
            return payload
        relays = self.allocate_all([(c["ip"], int(c.get("port", 0))) for c in picked])
        fallback = next((r for r in relays if r), None)
        if fallback is None:
            return payload
        for candidate, relay in zip(picked, relays):
            relay = relay or fallback
            candidate["ip"], candidate["port"] = str(relay[0]), str(int(relay[1]))
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def rewrite_endpoints(self, endpoints, endpoint_class):
        """Replace UDP reflector endpoints of a private call in place. Returns how many."""
        if not self.enabled():
            return 0
        picked = [(i, e) for i, e in enumerate(list(endpoints))
                  if is_reflector(getattr(e, "ipv4", "")) and not bool(getattr(e, "tcp", False))]
        relays = self.allocate_all([(str(e.ipv4), int(e.port)) for _, e in picked])
        fallback = next((r for r in relays if r), None)
        if fallback is None:
            return 0
        done = []
        try:
            for (index, endpoint), relay in zip(picked, relays):
                relay = relay or fallback
                replacement = endpoint_class(
                    bool(endpoint.isRtc), int(endpoint.id), str(relay[0]), "", int(relay[1]), int(endpoint.type),
                    endpoint.peerTag, bool(endpoint.turn), bool(endpoint.stun),
                    getattr(endpoint, "username", None), getattr(endpoint, "password", None), False)
                try:
                    replacement.reflectorId = int(endpoint.reflectorId)
                except Exception:
                    pass
                endpoints[index] = replacement
                done.append((index, endpoint))
        except Exception:
            for index, original in done:
                endpoints[index] = original
            return 0
        return len(done)
