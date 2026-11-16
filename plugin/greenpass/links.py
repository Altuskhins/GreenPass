"""Proxy share links: detect, clean, parse into node details, find them in text."""

import base64
import hashlib
import html
import json
import re
import urllib.parse

from . import hitvpn

# scheme -> (protocol kind, label)
SCHEMES = {
    "vless": ("vless", "VLESS"),
    "vmess": ("vmess", "VMess"),
    "trojan": ("trojan", "Trojan"),
    "ss": ("ss", "Shadowsocks"),
    "hy2": ("hysteria2", "Hysteria2"),
    "hysteria2": ("hysteria2", "Hysteria2"),
    "tuic": ("tuic", "TUIC"),
    "anytls": ("anytls", "AnyTLS"),
    "ssh": ("ssh", "SSH"),
    "shadowtls": ("shadowtls", "ShadowTLS"),
    "hy": ("hysteria", "Hysteria"),
    "hysteria": ("hysteria", "Hysteria"),
    "naive": ("naive", "Naive"),
    "mieru": ("mieru", "Mieru"),
    "sudoku": ("sudoku", "Sudoku"),
}
KIND_SINGBOX_CONFIG = "singbox-config"
KIND_MIHOMO_CONFIG = "mihomo-config"
KIND_QWDTT = "qwdtt"

# Other links GreenPass imports, handled outside this module.
OTHER_PREFIXES = ("wdtt://", "qwdtt://", "qwdtt:config?", "olcrtc://", "tg://ws", "tg://relay?")

_GENERIC_NAMES = {
    "узел", "server", "proxy", "сервер", "конфиг", "config", "sing-box узел",
} | {"%s узел" % kind for kind in ("vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "tuic",
                                    "anytls", "ssh", "shadowtls", "naive", "mieru", "sudoku")}


def scheme_of(value):
    """Proxy scheme of a link ("" when it is not a proxy link)."""
    low = str(value or "").strip().lower()
    for scheme in SCHEMES:
        if low.startswith(scheme + "://"):
            return scheme
    return ""


def is_proxy_link(value):
    return bool(scheme_of(value))


def label(node_or_link):
    """Human protocol name for a node dict or a link."""
    if isinstance(node_or_link, dict):
        kind = str(node_or_link.get("kind", "") or "").lower() or SCHEMES.get(scheme_of(node_or_link.get("uri")), ("",))[0]
    else:
        kind = SCHEMES.get(scheme_of(node_or_link), ("",))[0] or str(node_or_link or "").lower()
    for scheme_kind, name in SCHEMES.values():
        if scheme_kind == kind:
            return name
    return {KIND_SINGBOX_CONFIG: "sing-box config", KIND_MIHOMO_CONFIG: "Mihomo config",
            KIND_QWDTT: "qWDTT"}.get(kind, "Серверы")


# --- names ---

def clean_name(raw, fallback="Узел"):
    text = urllib.parse.unquote(html.unescape(str(raw or "")))
    text = re.split(r"[?&](?:serverDescription|server_description)(?:=|$)", text, maxsplit=1, flags=re.I)[0]
    text = re.sub(r"\s{2,}", " ", text).strip()
    return text or fallback


def is_generic_name(raw):
    name = clean_name(raw).lower()
    return name in _GENERIC_NAMES or bool(re.fullmatch(r"(?:proxy|server|узел|конфиг)[-_ ]*\d+", name))


def name_from_link(link):
    """A meaningful name from the fragment or a name-like query param; "" if none."""
    try:
        parts = urllib.parse.urlsplit(str(link or ""))
        query = urllib.parse.parse_qs(parts.query)
    except ValueError:
        return ""
    candidates = [parts.fragment]
    for key in ("name", "ps", "remark", "remarks", "title"):
        candidates.extend(query.get(key, []))
    for candidate in candidates:
        name = clean_name(candidate)
        if not is_generic_name(name):
            return name
    return ""


def address_name(server, port=0):
    host = str(server or "").strip()
    if not host:
        return "Узел"
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    return "%s:%d" % (host, int(port)) if int(port or 0) > 0 else host


# --- cleaning and dedup ---

def _b64(text):
    text = str(text or "").strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(text + "=" * (-len(text) % 4))


def sanitize(raw):
    """Trim junk around a link and normalise its #fragment."""
    text = html.unescape(str(raw or "")).replace("\n", "").replace("\r", "").strip()
    if not text:
        return ""
    low = text.lower()
    if not scheme_of(text):
        starts = [low.find(s + "://") for s in SCHEMES if low.find(s + "://") > 0]
        if starts:
            text = text[min(starts):]
    text = re.sub(r"[\s)\]>,.;]+$", "", text)
    if "#" in text and not text.lower().startswith("vmess://"):
        base, fragment = text.split("#", 1)
        text = base + "#" + urllib.parse.quote(urllib.parse.unquote(fragment), safe="")
    return text


def _split_host_port(host_port):
    """("host", "port") from host:port or [v6]:port; port may be ""."""
    if host_port.startswith("["):
        end = host_port.find("]")
        if end > 0:
            rest = host_port[end + 1:]
            return host_port[:end + 1], rest[1:] if rest.startswith(":") else ""
        return host_port, ""
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        return host, port
    return host_port, ""


def dedup_key(raw):
    """Same key for links that point at the same server with the same settings."""
    uri = sanitize(raw).split("#", 1)[0].strip()
    if not uri:
        return ""
    low = uri.lower()
    if low.startswith("vmess://"):
        try:
            obj = json.loads(_b64(uri[8:]).decode("utf-8", errors="ignore"))
            if isinstance(obj, dict):
                canon = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                return "vmess://" + hashlib.sha256(canon.encode("utf-8")).hexdigest()
        except (ValueError, TypeError):
            pass
        return uri
    if low.startswith("ss://"):
        try:
            body = uri[5:]
            if "@" in body:
                creds, server = body.split("@", 1)
            else:
                decoded = _b64(body.split("?", 1)[0]).decode("utf-8", errors="ignore")
                creds, server = decoded.split("@", 1) if "@" in decoded else (decoded, "")
            host, port = _split_host_port(server.split("?", 1)[0].strip().rstrip("/"))
            if creds.strip() and host and port:
                return "ss://%s@%s:%s" % (creds.strip(), host.lower().strip(), port.strip())
        except (ValueError, TypeError):
            pass
        return uri
    try:
        parts = urllib.parse.urlsplit(uri)
    except ValueError:
        return uri
    if not parts.scheme:
        return uri
    userinfo, _, host_port = parts.netloc.rpartition("@")
    host, port = _split_host_port(host_port)
    host = host.lower().strip()
    if userinfo:
        userinfo = urllib.parse.unquote(userinfo)
        if parts.scheme.lower() == "vless":
            userinfo = userinfo.strip("{}").lower()
        userinfo = urllib.parse.quote(userinfo, safe=":")
    query = parts.query
    items = sorted(urllib.parse.parse_qsl(query, keep_blank_values=True))
    if items:
        query = "&".join("%s=%s" % (urllib.parse.quote(k, safe=""), urllib.parse.quote(v, safe="/:@"))
                         for k, v in items)
    netloc = "%s:%s" % (host, port.strip()) if port.strip() else host
    if userinfo:
        netloc = userinfo + "@" + netloc
    return urllib.parse.urlunsplit((parts.scheme.lower(), netloc, parts.path.rstrip("/"), query, ""))


# --- parsing ---

def _standard(uri, fallback_name):
    """scheme://user@host:port/path?query#name -> dict, or None."""
    if "://" not in uri:
        return None
    scheme, body = uri.split("://", 1)
    name = fallback_name
    if "#" in body:
        body, fragment = body.split("#", 1)
        name = clean_name(fragment, fallback_name)
    body, _, query = body.partition("?")
    if "@" not in body:
        return None
    user, host_port = body.rsplit("@", 1)
    host_port = host_port.strip().rstrip("/")
    path = ""
    if "/" in host_port:
        host_port, path = host_port.split("/", 1)
        path = "/" + path if path else ""
    host, port = _split_host_port(host_port)
    host = host.strip("[]").strip()
    try:
        port = int(port.strip())
    except ValueError:
        return None
    if not host or port <= 0:
        return None
    params = {k: v for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True)}
    if path and "path" not in params:
        params["path"] = path
    return {"scheme": scheme.lower(), "user": user.strip(), "host": host, "port": port,
            "params": params, "name": name, "uri": uri}


def _node(r, kind, network, security, **fields):
    node = {"uri": r["uri"], "kind": kind, "name": r["name"], "server": r["host"], "port": r["port"],
            "network": network, "security": security, "params": r["params"]}
    node.update(fields)
    return node


def _with_sni(r):
    r["params"].setdefault("sni", r["host"])
    if not r["params"]["sni"]:
        r["params"]["sni"] = r["host"]


def _split_user(r):
    user = urllib.parse.unquote(r["user"]).strip()
    first, _, second = user.partition(":")
    return user, first.strip(), second.strip()


def _parse_vless(uri):
    r = _standard(uri, "sing-box узел")
    if not r:
        return None
    uuid = urllib.parse.unquote(r["user"]).strip()
    if not uuid:
        return None
    p = r["params"]
    return _node(r, "vless", p.get("type") or "tcp", p.get("security") or "none", uuid=uuid)


def _parse_ss(uri):
    body = uri[5:]
    name = "SS узел"
    if "#" in body:
        body, fragment = body.split("#", 1)
        name = clean_name(fragment, name)
    params = {}
    if "?" in body:
        body, query = body.split("?", 1)
        for pair in query.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key.strip()] = urllib.parse.unquote(value)
    body = body.strip().rstrip("/")
    if "@" in body:
        user, server = body.split("@", 1)
        try:
            creds = _b64(user).decode("utf-8", errors="ignore")
        except (ValueError, TypeError):
            creds = ""
        if ":" not in creds:
            creds = urllib.parse.unquote(user)
        server = server.split("?", 1)[0].strip().rstrip("/")
    else:
        try:
            decoded = _b64(body).decode("utf-8", errors="ignore")
        except (ValueError, TypeError):
            return None
        if "@" not in decoded:
            return None
        creds, server = decoded.split("@", 1)
    if ":" not in creds or ":" not in server:
        return None
    method, password = creds.split(":", 1)
    host, port = _split_host_port(server)
    try:
        port = int(port.strip())
    except ValueError:
        return None
    host = host.strip("[]").strip()
    if not method.strip() or not host or port <= 0:
        return None
    return {"uri": uri, "kind": "ss", "name": name, "method": method.strip(),
            "password": urllib.parse.unquote(password), "server": host, "port": port,
            "network": "tcp", "security": "shadowsocks", "params": params}


def _parse_vmess(uri):
    try:
        obj = json.loads(_b64(uri[8:].split("#", 1)[0]).decode("utf-8", errors="ignore"))
        host = str(obj.get("add", "") or "").strip()
        port = int(obj.get("port", 0) or 0)
    except (ValueError, TypeError, AttributeError):
        return None
    if not host or port <= 0:
        return None
    try:
        alter_id = int(obj.get("aid", 0) or 0)
    except (TypeError, ValueError):
        alter_id = 0
    network = str(obj.get("net", "") or "").strip() or "tcp"
    tls = str(obj.get("tls", "") or "").strip().lower()
    security = tls or "none"
    path = str(obj.get("path", "") or "")
    host_header = str(obj.get("host", "") or "")
    sni = str(obj.get("sni", "") or "")
    params = {
        "type": network, "security": security, "sni": sni or host_header,
        "fp": str(obj.get("fp", "") or "chrome"), "alpn": str(obj.get("alpn", "") or ""),
        "path": path or "/", "host": host_header or sni,
        "headerType": str(obj.get("type", "") or "none"), "serviceName": path, "seed": path,
    }
    return {"uri": uri, "kind": "vmess", "name": clean_name(obj.get("ps", ""), "VMess узел"),
            "uuid": str(obj.get("id", "") or "").strip(), "alter_id": alter_id,
            "cipher": str(obj.get("scy", "") or "auto"), "server": host, "port": port,
            "network": network, "security": security, "params": params}


def _parse_trojan(uri):
    r = _standard(uri, "Trojan узел")
    if not r:
        return None
    p = r["params"]
    p["security"] = p.get("security") or "tls"
    p["sni"] = p.get("sni") or r["host"]
    return _node(r, "trojan", p.get("type") or "tcp", p["security"],
                 password=urllib.parse.unquote(r["user"]))


def _parse_hysteria2(uri):
    r = _standard(uri, "Hysteria2 узел")
    if not r:
        return None
    user, _, second = _split_user(r)
    password = (second if ":" in user else user).strip()
    if not password:
        return None
    _with_sni(r)
    return _node(r, "hysteria2", "udp", "tls", password=password)


def _parse_tuic(uri):
    r = _standard(uri, "TUIC узел")
    if not r:
        return None
    _, uuid, password = _split_user(r)
    if not uuid:
        return None
    _with_sni(r)
    return _node(r, "tuic", "udp", "tls", uuid=uuid, password=password)


def _parse_anytls(uri):
    r = _standard(uri, "AnyTLS узел")
    password = urllib.parse.unquote(r["user"]).strip() if r else ""
    if not password:
        return None
    _with_sni(r)
    return _node(r, "anytls", "tcp", "tls", password=password)


def _parse_ssh(uri):
    r = _standard(uri, "SSH узел")
    if not r:
        return None
    _, user, password = _split_user(r)
    if not user:
        return None
    return _node(r, "ssh", "tcp", "none", user=user, password=password)


def _parse_shadowtls(uri):
    r = _standard(uri, "ShadowTLS узел")
    password = urllib.parse.unquote(r["user"]).strip() if r else ""
    if not password:
        return None
    _with_sni(r)
    version = str(r["params"].get("version", "3"))
    return _node(r, "shadowtls", "tcp", "tls", password=password,
                 version=int(version) if version.isdigit() else 3)


def _parse_hysteria(uri):
    r = _standard(uri, "Hysteria узел")
    auth = urllib.parse.unquote(r["user"]).strip() if r else ""
    if not auth:
        return None
    _with_sni(r)
    return _node(r, "hysteria", "udp", "tls", auth=auth)


def _parse_naive(uri):
    r = _standard(uri, "Naive узел")
    if not r:
        return None
    _, user, password = _split_user(r)
    if not user:
        return None
    _with_sni(r)
    return _node(r, "naive", "tcp", "tls", user=user, password=password)


def _parse_mieru(uri):
    r = _standard(uri, "Mieru узел")
    if not r:
        return None
    user, name, password = _split_user(r)
    if ":" not in user or not name or not password:
        return None
    return _node(r, "mieru", str(r["params"].get("transport", "TCP") or "TCP").lower(), "mieru",
                 user=name, password=password)


def _parse_sudoku(uri):
    try:
        payload = json.loads(_b64(uri[len("sudoku://"):]).decode("utf-8"))
        server = str(payload.get("h", "") or "").strip()
        port = int(payload.get("p", 0) or 0)
        key = str(payload.get("k", "") or "").strip()
    except (ValueError, TypeError, AttributeError):
        return None
    if not server or not 1 <= port <= 65535 or not key:
        return None
    tables = payload.get("ts", [])
    tables = [str(t).strip() for t in tables if str(t or "").strip()] if isinstance(tables, list) else []
    return {
        "uri": uri, "kind": "sudoku", "name": "Sudoku узел", "server": server, "port": port, "key": key,
        "aead_method": str(payload.get("e", "") or "none").strip(),
        "table_type": str(payload.get("a", "") or "prefer_entropy").strip(),
        "padding_min": 5, "padding_max": 15,
        "enable_pure_downlink": not bool(payload.get("x", False)),
        "custom_table": str(payload.get("t", "") or "").strip(), "custom_tables": tables,
        "http_mask_disabled": bool(payload.get("hd", False)),
        "http_mask_mode": str(payload.get("hm", "") or "").strip(),
        "http_mask_tls": bool(payload.get("ht", False)),
        "http_mask_host": str(payload.get("hh", "") or "").strip(),
        "http_mask_multiplex": str(payload.get("hx", "") or "").strip(),
        "http_mask_path": str(payload.get("hy", "") or "").strip(),
        "network": "tcp", "security": "sudoku",
    }


_PARSERS = {
    "vless": _parse_vless, "vmess": _parse_vmess, "trojan": _parse_trojan, "ss": _parse_ss,
    "hysteria2": _parse_hysteria2, "tuic": _parse_tuic, "anytls": _parse_anytls, "ssh": _parse_ssh,
    "shadowtls": _parse_shadowtls, "hysteria": _parse_hysteria, "naive": _parse_naive,
    "mieru": _parse_mieru, "sudoku": _parse_sudoku,
}


def parse(link):
    """Node details of a proxy link (HitVPN links resolve to their first VLESS), or None."""
    text = str(link or "").strip()
    if hitvpn.is_hitvpn_link(text):
        decoded = hitvpn.decode(text)
        text = decoded[0] if decoded else ""
    scheme = scheme_of(text)
    if not scheme:
        return None
    uri = text if scheme == "sudoku" else sanitize(text)
    try:
        return _PARSERS[SCHEMES[scheme][0]](uri)
    except Exception:
        return None


def node_from_link(link):
    """A stored node for a link: the parsed details plus id and a readable name."""
    details = parse(link)
    if not details:
        return None
    uri = details["uri"]
    name = clean_name(details.get("name"))
    if is_generic_name(name):
        name = name_from_link(uri) or address_name(details.get("server"), details.get("port"))
    return {
        "id": uri, "uri": uri, "kind": details.get("kind", ""), "name": name,
        "server": details.get("server", ""), "port": int(details.get("port", 0) or 0),
        "network": details.get("network") or "tcp", "security": details.get("security") or "none",
        "method": details.get("method", ""),
    }


# --- finding links in text ---

_SCHEME_ALT = "|".join(re.escape(s) for s in SCHEMES)
_LINK_RE = re.compile(
    r"(?:%s)://[^\s\"'<>]+|(?:wdtt|qwdtt)://[^\s\"'<>]+|qwdtt:config\?[^\s\"'<>]+|olcrtc://[^\s\"']+"
    r"|tg://ws(?:\b|[^\s\"'<>]*)|tg://relay\?[^\s\"'<>]+|https://(?:hvpn|hitray)\.io/[^\s\"'<>]+"
    r"|hitvpn://[^\s\"'<>]+" % _SCHEME_ALT, re.IGNORECASE)


def contains_link(text):
    low = str(text or "").lower()
    return any(s + "://" in low for s in SCHEMES) or any(p in low for p in OTHER_PREFIXES) \
        or any(p in low for p in hitvpn.PREFIXES)


def find_links(text):
    """[(start, end, link)] for every importable link in text."""
    text = str(text or "")
    if not contains_link(text):
        return []
    found = []
    for match in _LINK_RE.finditer(text):
        link = match.group(0).rstrip(".,!?;:)]}>")
        scheme = scheme_of(link)
        if scheme and len(link) <= len(scheme) + 3:
            continue
        if not scheme and not link.lower().startswith(OTHER_PREFIXES) and not hitvpn.is_hitvpn_link(link):
            continue
        if hitvpn.is_hitvpn_link(link) and len(link) <= len("hitvpn://"):
            continue
        found.append((match.start(), match.start() + len(link), link))
    return found


def first_import_link(text):
    """The first link in text GreenPass can import (HitVPN resolved to VLESS)."""
    for _, _, link in find_links(text):
        if link.lower().startswith(OTHER_PREFIXES) or scheme_of(link):
            return link
        decoded = hitvpn.decode(link)
        if decoded:
            return decoded[0]
    return ""
