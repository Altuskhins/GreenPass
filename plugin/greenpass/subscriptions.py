"""Download subscriptions and turn them into nodes."""

import base64
import gzip
import json
import os
import re
import ssl
import urllib.parse
import urllib.request

from . import hitvpn, links, xray_json
from .android import prefs

_HWID_RE = re.compile(r"[0-9a-f]{16}")
_hwid = ""
# url -> what happened on the last fetch, shown when a subscription gives no nodes.
LAST_FETCH = {}


def hwid():
    """Device id sent as X-HWID: the user's own value, else a random one kept in prefs."""
    global _hwid
    store = prefs()
    try:
        custom = str(store.getString("subscription_hwid_custom", "") or "").strip().lower()
        if _HWID_RE.fullmatch(custom):
            return custom
        if _hwid:
            return _hwid
        value = str(store.getString("subscription_hwid", "") or "").strip().lower()
        if not _HWID_RE.fullmatch(value):
            value = os.urandom(8).hex()
            store.edit().putString("subscription_hwid", value).commit()
        _hwid = value
    except Exception:
        _hwid = _hwid or os.urandom(8).hex()
    return _hwid


def set_custom_hwid(value):
    """Set the user's HWID (16 hex chars, or "" to use the random one)."""
    global _hwid
    custom = str(value or "").strip().lower()
    if custom and not _HWID_RE.fullmatch(custom):
        return False
    try:
        prefs().edit().putString("subscription_hwid_custom", custom).commit()
        _hwid = ""
        return True
    except Exception:
        return False


def custom_hwid():
    try:
        return str(prefs().getString("subscription_hwid_custom", "") or "")
    except Exception:
        return ""


def request_headers(url):
    # Panels serve full configs only to known client apps, so look like Happ.
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "close",
        "User-agent": "Happ/3.13.0",
        "X-Device-Locale": "en",
        "X-Device-model": "Pixel 9",
        "X-Device-OS": "Android",
        "X-HWID": hwid(),
        "X-Ver-OS": "16",
    }
    host = urllib.parse.urlparse(str(url or "")).netloc
    if host:
        headers["Host"] = host
    return headers


def normalize_url(value):
    """http(s) URL, adding https:// when the scheme is missing; "" when invalid."""
    target = str(value or "").strip()
    if not target or any(c.isspace() for c in target):
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", target, re.I):
        target = "https://" + target.lstrip("/")
    try:
        parsed = urllib.parse.urlparse(target)
        parsed.port
    except ValueError:
        return ""
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return ""
    return target


def candidate_urls(url):
    """The URL plus mirrors: raw.githubusercontent refs/heads paths also via jsDelivr."""
    target = normalize_url(url)
    if not target:
        return []
    urls = [target]
    parsed = urllib.parse.urlparse(target)
    parts = [p for p in parsed.path.split("/") if p]
    if parsed.netloc.lower() == "raw.githubusercontent.com" and len(parts) >= 5 and parts[2:4] == ["refs", "heads"]:
        owner, repo, branch, tail = parts[0], parts[1], parts[4], parts[5:]
        urls.append(urllib.parse.urlunparse((parsed.scheme or "https", parsed.netloc,
                                             "/" + "/".join([owner, repo, branch] + tail), "", parsed.query, "")))
        path = "/gh/" + "/".join([owner, repo + "@" + branch] + tail)
        for host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net", "fastly.jsdelivr.net"):
            urls.append(urllib.parse.urlunparse(("https", host, path, "", parsed.query, "")))
    return list(dict.fromkeys(urls))


def _decode_body(raw, encoding=""):
    data = bytes(raw or b"")
    if data[:2] == b"\x1f\x8b" or "gzip" in str(encoding or "").lower():
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            pass
    return data.decode("utf-8", errors="ignore")


def fetch_text(url, timeout_sec=15.0, headers=None):
    """Body of a subscription URL, trying mirrors and longer timeouts; "" on failure."""
    # Many panels use self-signed or mismatched certificates.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    timeouts = sorted({max(float(timeout_sec), 15.0), max(float(timeout_sec), 30.0), max(float(timeout_sec), 45.0)})
    urls = candidate_urls(url)
    errors = []
    for candidate in urls:
        request_head = dict(headers) if isinstance(headers, dict) else request_headers(candidate)
        host = urllib.parse.urlparse(candidate).netloc or "?"
        for timeout in timeouts:
            try:
                request = urllib.request.Request(candidate, headers=request_head)
                with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                    text = _decode_body(response.read(), response.headers.get("Content-Encoding", ""))
                if text:
                    LAST_FETCH[url] = {"stage": "fetched", "fetched_url": candidate, "errors": " | ".join(errors[:4])}
                    return text
            except Exception as exc:
                error = "%s:%s" % (host, type(exc).__name__)
                if error not in errors:
                    errors.append(error)
    LAST_FETCH[url] = {"stage": "fetch_failed", "tried": len(urls), "errors": " | ".join(errors[:4])}
    return ""


def _maybe_base64(body):
    """Decode a base64 subscription body; the text itself when it is not one."""
    if links.contains_link(body) or body.lstrip().startswith(("{", "[")):
        return body
    blob = re.sub(r"[^A-Za-z0-9+/=]", "", body.replace("-", "+").replace("_", "/"))
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", errors="ignore")
    except (ValueError, TypeError):
        return body


_LINE_LINK = re.compile(r"(?:%s)://[^\s\"'<>]+|https://(?:hvpn|hitray)\.io/[^\s\"'<>]+|hitvpn://[^\s\"'<>]+"
                        % "|".join(re.escape(s) for s in links.SCHEMES), re.I)


def _is_link_line(line):
    return links.is_proxy_link(line) or hitvpn.is_hitvpn_link(line)


def _skip_link(link):
    """Placeholder entries panels add for unsupported clients."""
    low = urllib.parse.unquote(link).lower()
    return "@0.0.0.0:1" in link.lower() or ("приложение" in low and "не поддерж" in low)


def nodes_from_text(text, url=""):
    """Nodes in a subscription body: link lists (plain or base64) or Xray JSON."""
    original = str(text or "").strip()
    if not original:
        LAST_FETCH[url] = {"stage": "empty_text"}
        return []
    body = _maybe_base64(original)

    found = []
    if "\n" in body or "\r" in body:
        found = [line.strip().rstrip(".,!?;:)]}>") for line in body.splitlines() if _is_link_line(line.strip())]
    if not found:
        found = _LINE_LINK.findall(body)

    prebuilt = []
    if not found:
        for candidate in (body, original):
            if candidate.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(candidate)
                except ValueError:
                    continue
                for config in parsed if isinstance(parsed, list) else [parsed]:
                    prebuilt.extend(xray_json.config_nodes(config))
                break

    expanded = []
    for link in found:
        expanded.extend(hitvpn.decode(link) if hitvpn.is_hitvpn_link(link) else [link])

    nodes, seen = [], set()

    def add(node):
        key = links.dedup_key(node.get("uri", "")) or node.get("uri", "")
        if key and key not in seen:
            seen.add(key)
            nodes.append(node)

    for node in prebuilt:
        add(node)
    for link in expanded:
        if links.is_proxy_link(link) and not _skip_link(link):
            node = links.node_from_link(link)
            if node:
                add(node)

    # Panels often repeat one name for every server; number the repeats.
    counts = {}
    for node in nodes:
        base = links.clean_name(node.get("name"))
        counts[base] = counts.get(base, 0) + 1
        if counts[base] > 1:
            node["name"] = "%s (%d)" % (base, counts[base])
    LAST_FETCH[url] = {"stage": "done", "text_len": len(body), "link_count": len(expanded), "node_count": len(nodes)}
    return nodes


def fetch_nodes(url, text=None):
    if text is None:
        text = fetch_text(url)
    return nodes_from_text(text, url)
