"""Local port and SOCKS5 checks used to tell whether a mode really works."""

import socket
import time

LOCAL_HOST = "127.0.0.1"

# Reached through the tunnel to prove traffic gets out.
EGRESS_TARGETS = (("1.1.1.1", 80), ("1.0.0.1", 80))
TELEGRAM_TARGETS = (("149.154.167.50", 443), ("149.154.175.50", 443))
_TRACE_PROBE = b"HEAD /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"


def port_open(port, timeout=0.2):
    try:
        with socket.create_connection((LOCAL_HOST, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def wait_port_closed(port, timeout_sec=1.5, step_sec=0.1):
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if not port_open(port):
            return True
        time.sleep(step_sec)
    return not port_open(port)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOCAL_HOST, 0))
        return int(sock.getsockname()[1])


def pick_port(preferred=0, exclude=()):
    """preferred when it is free, else a random free port not in exclude."""
    exclude = {int(p) for p in exclude if p}
    preferred = int(preferred or 0)
    if preferred > 0 and preferred not in exclude and not port_open(preferred, timeout=0.05):
        return preferred
    for _ in range(32):
        port = free_port()
        if port not in exclude:
            return port
    return 0


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def _socks_auth(sock, username, password):
    method = b"\x02" if username and password else b"\x00"
    sock.sendall(b"\x05\x01" + method)
    if _recv_exact(sock, 2) != b"\x05" + method:
        return False
    if method == b"\x02":
        user = username.encode("utf-8")[:255]
        secret = password.encode("utf-8")[:255]
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
        reply = _recv_exact(sock, 2)
        return len(reply) == 2 and reply[1] == 0
    return True


def socks_ready(port, timeout=0.5, username="", password=""):
    """The local SOCKS5 server answers the greeting (and accepts the login)."""
    try:
        with socket.create_connection((LOCAL_HOST, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return _socks_auth(sock, str(username or ""), str(password or ""))
    except (OSError, ValueError):
        return False


def socks_connect(port, host, target_port, timeout=1.5, username="", password="", probe=b""):
    """CONNECT host:target_port through the local SOCKS5; with probe, wait for a reply byte."""
    try:
        with socket.create_connection((LOCAL_HOST, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if not _socks_auth(sock, str(username or ""), str(password or "")):
                return False
            try:
                address = b"\x01" + socket.inet_aton(str(host))
            except OSError:
                name = str(host).encode("idna")
                address = b"\x03" + bytes([len(name)]) + name
            sock.sendall(b"\x05\x01\x00" + address + int(target_port).to_bytes(2, "big"))
            head = _recv_exact(sock, 4)
            if len(head) < 4 or head[1] != 0:
                return False
            if head[3] == 1:
                rest = 6
            elif head[3] == 4:
                rest = 18
            elif head[3] == 3:
                size = _recv_exact(sock, 1)
                if not size:
                    return False
                rest = size[0] + 2
            else:
                return False
            if len(_recv_exact(sock, rest)) != rest:
                return False
            if probe:
                sock.sendall(probe)
                return bool(sock.recv(1))
            return True
    except (OSError, ValueError):
        return False


def tunnel_works(port, timeout=1.5, username="", password=""):
    """Traffic gets out through the local SOCKS5 tunnel."""
    return any(socks_connect(port, host, target, timeout, username, password, _TRACE_PROBE)
               for host, target in EGRESS_TARGETS)


def telegram_reachable(port, timeout=3.0, username="", password=""):
    """A Telegram DC answers a TCP CONNECT through the local SOCKS5."""
    return any(socks_connect(port, host, target, timeout, username, password)
               for host, target in TELEGRAM_TARGETS)


def tcp_latency_ms(host, port, timeout=1.5):
    started = time.monotonic()
    try:
        with socket.create_connection((str(host), int(port)), timeout=timeout):
            return max(1, int((time.monotonic() - started) * 1000))
    except (OSError, ValueError):
        return None
