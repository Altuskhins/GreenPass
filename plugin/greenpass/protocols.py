from .foundation import *

def _is_vless_uri(value):
    try:
        return str(value or "").strip().lower().startswith("vless://")
    except:
        return False


def _is_vmess_uri(value):
    try:
        return str(value or "").strip().lower().startswith("vmess://")
    except:
        return False


def _is_trojan_uri(value):
    try:
        return str(value or "").strip().lower().startswith("trojan://")
    except:
        return False


def _is_ss_uri(value):
    try:
        return str(value or "").strip().lower().startswith("ss://")
    except:
        return False


def _is_hysteria2_uri(value):
    try:
        raw = str(value or "").strip().lower()
    except:
        raw = ""
    return raw.startswith("hy2://") or raw.startswith("hysteria2://")

def _is_tuic_uri(value):
    try:
        return str(value or "").strip().lower().startswith("tuic://")
    except:
        return False


def _is_anytls_uri(value):
    try:
        return str(value or "").strip().lower().startswith("anytls://")
    except:
        return False


def _is_ssh_uri(value):
    try:
        return str(value or "").strip().lower().startswith("ssh://")
    except:
        return False


def _is_shadowtls_uri(value):
    try:
        return str(value or "").strip().lower().startswith("shadowtls://")
    except:
        return False


def _is_hysteria_uri(value):
    try:
        raw = str(value or "").strip().lower()
    except:
        raw = ""
    return raw.startswith("hy://") or raw.startswith("hysteria://")

def _is_naive_uri(value):
    try:
        return str(value or "").strip().lower().startswith("naive://")
    except:
        return False


def _is_mieru_uri(value):
    try:
        return str(value or "").strip().lower().startswith("mieru://")
    except:
        return False


def _is_sudoku_uri(value):
    try:
        return str(value or "").strip().lower().startswith("sudoku://")
    except:
        return False


def _is_proxy_uri(value):
    try:
        raw = str(value or "").strip().lower()
    except:
        raw = ""
    for scheme in PROXY_URI_SCHEMES:
        if raw.startswith(scheme + "://"):
            return True
    return False


def _is_hitvpn_uri(value):
    try:
        raw = str(value or "").strip().lower()
    except:
        raw = ""
    return bool(
        raw.startswith(HITVPN_LINK_PREFIX)
        or raw.startswith(HITRAY_LINK_PREFIX)
        or raw.startswith(HITVPN_SCHEME_PREFIX)
    )


def _contains_import_uri_text(value):
    try:
        low = str(value or "").lower()
    except:
        low = ""
    has_proxy_scheme = False
    try:
        for scheme in PROXY_URI_SCHEMES:
            if (scheme + "://") in low:
                has_proxy_scheme = True
                break
    except:
        has_proxy_scheme = False
    return bool(
        has_proxy_scheme
        or ("wdtt://" in low)
        or ("qwdtt://" in low)
        or ("qwdtt:config" in low)
        or ("olcrtc://" in low)
        or ("tg://ws" in low)
        or ("tg://relay?" in low)
        or (HITVPN_LINK_PREFIX in low)
        or (HITRAY_LINK_PREFIX in low)
        or ("hitvpn://" in low)
    )


class _MiniCborReader:
    def __init__(self, data):
        self.data = bytes(data or b"")
        self.pos = 0

    def read(self):
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if major == 0:
            return self._read_uint(additional)
        if major == 1:
            return -1 - self._read_uint(additional)
        if major == 2:
            return self._take(self._read_uint(additional))
        if major == 3:
            return self._take(self._read_uint(additional)).decode("utf-8", errors="ignore")
        if major == 4:
            return [self.read() for _ in range(self._read_uint(additional))]
        if major == 5:
            size = self._read_uint(additional)
            out = {}
            for _ in range(size):
                key = self.read()
                out[key] = self.read()
            return out
        if major == 6:
            self._read_uint(additional)
            return self.read()
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
        raise ValueError("unsupported cbor")

    def _read_uint(self, additional):
        if additional < 24:
            return additional
        if additional == 24:
            return self._take(1)[0]
        if additional == 25:
            return int.from_bytes(self._take(2), "big")
        if additional == 26:
            return int.from_bytes(self._take(4), "big")
        if additional == 27:
            return int.from_bytes(self._take(8), "big")
        raise ValueError("unsupported cbor uint")

    def _take(self, size):
        if self.pos + int(size) > len(self.data):
            raise ValueError("unexpected end of cbor")
        chunk = self.data[self.pos:self.pos + int(size)]
        self.pos += int(size)
        return chunk


def _decode_base64_urlsafe_no_padding(data):
    normalized = str(data or "").replace("-", "+").replace("_", "/")
    padding = (-len(normalized)) % 4
    if padding:
        normalized += "=" * padding
    return base64.b64decode(normalized)


def _little_endian_int(data):
    return int.from_bytes(bytes(data or b""), "little")


def _hitvpn_xor_payload(salt, payload):
    base = hashlib.sha256()
    base.update(HITVPN_WRAP_HASH_KEY)
    base.update(bytes(salt or b""))
    current = base.copy().digest()
    index = 0
    for i in range(len(payload)):
        if index >= len(current):
            base.update(current[:8])
            current = base.copy().digest()
            index = 0
        payload[i] ^= current[index]
        index += 1


def _decode_hitvpn_wrapped_payload(encoded):
    decoded = _decode_base64_urlsafe_no_padding(encoded)
    if len(decoded) < 32:
        raise ValueError("too short hitvpn link")
    if decoded[0] != HITVPN_WRAP_TAG:
        raise ValueError("invalid hitvpn tag")

    salt = decoded[1:5]
    hash_prefix = decoded[5:9]
    payload = bytearray(decoded[9:])

    if _little_endian_int(salt) != 0:
        _hitvpn_xor_payload(salt, payload)

    digest = hashlib.sha256(payload).digest()
    if digest[:4] != hash_prefix:
        raise ValueError("hitvpn hash mismatch")

    root = _MiniCborReader(payload).read()
    if not isinstance(root, dict):
        raise ValueError("hitvpn root is not a map")

    configs = []
    for item in list(root.get(4, []) or []):
        if not isinstance(item, dict):
            continue
        try:
            proto = int(item.get(1, 0))
        except:
            proto = 0
        cfg_data = item.get(2, b"")
        if not isinstance(cfg_data, (bytes, bytearray)):
            continue
        configs.append({"proto": proto, "cfg_data": bytes(cfg_data)})

    return {
        "vid": int(root.get(1, 0) or 0),
        "configs": configs,
    }


def _decode_hitvpn_vless_cfg(cfg_data, vid):
    root = _MiniCborReader(cfg_data).read()
    if not isinstance(root, dict):
        raise ValueError("hitvpn vless cfg is not a map")
    return {
        "vid": int(vid or 0),
        "uuid": bytes(root.get(1, b"") or b""),
        "server_pub_key": bytes(root.get(2, b"") or b""),
        "server_ip4": int(root.get(3, 0) or 0),
        "server_port": int(root.get(4, 0) or 0),
        "type": int(root.get(5, 0) or 0),
        "security": int(root.get(6, 0) or 0),
        "sni": str(root.get(7, "") or ""),
    }


def _hitvpn_ip4_to_string(value):
    try:
        return str(socket.inet_ntoa(struct.pack("!I", int(value or 0))))
    except:
        return ""


def _hitvpn_uuid_bytes_to_string(value):
    try:
        hexed = bytes(value or b"").hex()
    except:
        hexed = ""
    if len(hexed) != 32:
        return hexed
    return "%s-%s-%s-%s-%s" % (hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32])


def _hitvpn_to_client_vless_uri(data):
    uuid_text = _hitvpn_uuid_bytes_to_string(data.get("uuid"))
    address = _hitvpn_ip4_to_string(data.get("server_ip4"))
    try:
        port = int(data.get("server_port", 0) or 0)
    except:
        port = 0
    if not uuid_text or not address or port <= 0:
        return ""

    network = "udp" if int(data.get("type", 0) or 0) == 1 else "tcp"
    security = "reality" if int(data.get("security", 0) or 0) != 0 else "none"
    try:
        pbk = base64.urlsafe_b64encode(bytes(data.get("server_pub_key", b"") or b"")).decode("ascii").rstrip("=")
    except:
        pbk = ""
    return (
        "vless://%s@%s:%s?type=%s&security=%s&pbk=%s&sni=%s&fp=random&sid=42&spx=%%2F&flow=xtls-rprx-vision"
        % (
            uuid_text,
            address,
            str(port),
            urllib.parse.quote(str(network), safe=""),
            urllib.parse.quote(str(security), safe=""),
            urllib.parse.quote(str(pbk), safe=""),
            urllib.parse.quote(str(data.get("sni", "") or ""), safe=""),
        )
    )


def _decode_hitvpn_link_to_vless_uris(value):
    try:
        cleaned = str(value or "").strip()
    except:
        cleaned = ""
    low = cleaned.lower()
    if not cleaned:
        return []
    if low.startswith("vless://"):
        return [cleaned]
    if low.startswith(HITVPN_LINK_PREFIX):
        encoded = cleaned[len(HITVPN_LINK_PREFIX):]
    elif low.startswith(HITRAY_LINK_PREFIX):
        encoded = cleaned[len(HITRAY_LINK_PREFIX):]
    elif low.startswith(HITVPN_SCHEME_PREFIX):
        encoded = cleaned[len(HITVPN_SCHEME_PREFIX):]
    else:
        return []

    wrapped = _decode_hitvpn_wrapped_payload(encoded)
    results = []
    seen = set()
    for cfg in list(wrapped.get("configs", []) or []):
        try:
            if int(cfg.get("proto", 0) or 0) != HITVPN_PROTO_VLESS:
                continue
            generated = _hitvpn_to_client_vless_uri(_decode_hitvpn_vless_cfg(cfg.get("cfg_data", b""), wrapped.get("vid", 0)))
        except:
            generated = ""
        if not generated or generated in seen:
            continue
        seen.add(generated)
        results.append(generated)
    return results


def _proxy_uri_scheme(value):
    try:
        raw = str(value or "").strip().lower()
    except:
        raw = ""
    for scheme in PROXY_URI_SCHEMES:
        if raw.startswith(scheme + "://"):
            return scheme
    if raw.startswith(HITVPN_SCHEME_PREFIX):
        return "hitvpn"
    if raw.startswith(HITVPN_LINK_PREFIX):
        return "hvpn"
    if raw.startswith(HITRAY_LINK_PREFIX):
        return "hitray"
    return ""


def _proxy_protocol_label(value=None):
    try:
        if isinstance(value, dict):
            kind = str(value.get("kind", "") or "").strip().lower()
            if not kind:
                kind = _proxy_uri_scheme(value.get("uri", ""))
        else:
            kind = _proxy_uri_scheme(value)
            if not kind:
                kind = str(value or "").strip().lower()
    except:
        kind = ""
    spec = PROXY_PROTOCOL_REGISTRY.get(kind)
    if spec:
        return str(spec.get("label", kind) or kind)
    if kind == "singbox-config":
        return "sing-box config"
    if kind == "mihomo-config":
        return "Mihomo config"
    if kind == QWDTT_KIND:
        return "qWDTT"
    return "Серверы"


def _iter_vless_uri_matches(value):
    try:
        text = str(value or "")
    except:
        text = ""
    if not text or (not _contains_import_uri_text(text)):
        return []

    matches = []
    try:
        proxy_schemes = "|".join(re.escape(scheme) for scheme in PROXY_URI_SCHEMES)
        pattern = rf"(?:{proxy_schemes})://[^\s\"'<>]+|(?:wdtt|qwdtt)://[^\s\"'<>]+|qwdtt:config\?[^\s\"'<>]+|olcrtc://[^\s\"']+|tg://ws(?:\b|[^\s\"'<>]*)|tg://relay\?[^\s\"'<>]+|https://(?:hvpn|hitray)\.io/[^\s\"'<>]+|hitvpn://[^\s\"'<>]+"
        for match in re.finditer(pattern, text, re.IGNORECASE):
            raw = str(match.group(0) or "")
            trimmed = raw.rstrip(".,!?;:)]}>")
            scheme = _proxy_uri_scheme(trimmed)
            if not scheme and not trimmed.lower().startswith(("wdtt://", "qwdtt://", "qwdtt:config?", "olcrtc://", "tg://ws", "tg://relay?")):
                continue
            if scheme in tuple(PROXY_URI_SCHEMES) + ("hitvpn",) and len(trimmed) <= len(scheme + "://"):
                continue
            start = int(match.start())
            end = int(start + len(trimmed))
            matches.append((start, end, trimmed))
    except:
        return []
    return matches


def _extract_import_uri(value):
    for _, _, uri in _iter_vless_uri_matches(value):
        text = str(uri or "").strip()
        low = text.lower()
        if low.startswith(("wdtt://", "qwdtt://", "qwdtt:config?", "olcrtc://", "tg://ws", "tg://relay?")):
            return text
        try:
            scheme = _proxy_uri_scheme(text)
        except:
            scheme = ""
        if scheme in PROXY_URI_SCHEMES:
            return text
        try:
            decoded = _decode_hitvpn_link_to_vless_uris(text)
        except:
            decoded = []
        if decoded:
            return str(decoded[0] or "").strip()
    return ""


def _ensure_vless_url_spans(spannable, raw_text=None):
    if spannable is None:
        return 0

    try:
        text = str(raw_text if raw_text is not None else spannable)
    except:
        text = ""
    if not text:
        return 0

    try:
        if not (hasattr(spannable, "getSpans") and hasattr(spannable, "setSpan")):
            return 0
    except:
        return 0

    try:
        from android.text import Spanned
        span_flags = int(Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    except:
        span_flags = 33

    try:
        from android.text.style import URLSpan
    except:
        return 0

    applied = 0
    for start, end, uri in _iter_vless_uri_matches(text):
        try:
            existing = spannable.getSpans(int(start), int(end), URLSpan)
        except:
            existing = []

        scheme = _proxy_uri_scheme(uri)
        has_vless_span = False
        for span in list(existing or []):
            try:
                span_start = int(spannable.getSpanStart(span))
                span_end = int(spannable.getSpanEnd(span))
            except:
                span_start = -1
                span_end = -1
            try:
                span_url = str(span.getURL() or "")
            except:
                span_url = ""
            if span_start == int(start) and span_end == int(end) and span_url == uri:
                has_vless_span = True
                break
            if scheme and span_start <= int(start) and span_end >= int(end) and span_url.lower().startswith(scheme + "://"):
                has_vless_span = True
                break
            if span_start <= int(start) and span_end >= int(end) and span_url.lower().startswith(("olcrtc://", "tg://ws", "tg://relay?")):
                has_vless_span = True
                break

        if has_vless_span:
            continue

        try:
            spannable.setSpan(URLSpan(uri), int(start), int(end), int(span_flags))
            applied += 1
        except:
            pass

    return applied


def _clean_proxy_name(raw_name, fallback="Узел"):
    try:
        text = str(raw_name or "")
    except:
        text = ""
    try:
        text = unescape(text)
    except:
        pass
    try:
        text = urllib.parse.unquote(text)
    except:
        pass
    try:
        text = re.split(r"[?&](?:serverDescription|server_description)(?:=|$)", text, maxsplit=1, flags=re.I)[0]
    except:
        pass
    try:
        text = re.sub(r"\s{2,}", " ", text)
    except:
        pass
    text = str(text or "").strip()
    return text or str(fallback or "Узел")


def _is_generic_proxy_name(raw_name):
    name = _clean_proxy_name(raw_name).strip().lower()
    if name in {
        "узел", "server", "proxy", "сервер", "конфиг", "config",
        "vless узел", "vmess узел", "trojan узел", "ss узел",
        "hysteria узел", "hysteria2 узел", "tuic узел", "anytls узел",
        "ssh узел", "shadowtls узел", "naive узел", "mieru узел",
        "sudoku узел", "sing-box узел",
    }:
        return True
    return bool(re.fullmatch(r"(?:proxy|server|узел|конфиг)[-_ ]*\d+", name))


def _proxy_name_from_uri(uri):
    try:
        parsed = urllib.parse.urlsplit(str(uri or ""))
    except:
        return ""
    candidates = [parsed.fragment]
    try:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        for key in ("name", "ps", "remark", "remarks", "title"):
            candidates.extend(query.get(key, []))
    except:
        pass
    for candidate in candidates:
        name = _clean_proxy_name(candidate)
        if not _is_generic_proxy_name(name):
            return name
    return ""


def _proxy_address_name(server, port=0):
    host = str(server or "").strip()
    try:
        port = int(port or 0)
    except:
        port = 0
    if not host:
        return "Узел"
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return "%s:%d" % (host, port) if port > 0 else host


def _sanitize_proxy_uri(raw_uri):
    try:
        text = str(raw_uri or "")
    except:
        return ""
    try:
        text = unescape(text)
    except:
        pass
    text = text.replace("\n", "").replace("\r", "").strip()
    if not text:
        return ""
    try:
        low_text = text.lower()
        has_scheme_prefix = False
        for scheme in PROXY_URI_SCHEMES:
            if low_text.startswith(scheme + "://"):
                has_scheme_prefix = True
                break
        if not has_scheme_prefix:
            first_idx = -1
            for scheme in PROXY_URI_SCHEMES:
                idx = low_text.find(scheme + "://")
                if idx > 0 and (first_idx < 0 or idx < first_idx):
                    first_idx = idx
            if first_idx > 0:
                text = text[first_idx:]
    except:
        pass
    try:
        text = re.sub(r"[\s\)\]>,\.;]+$", "", text)
    except:
        pass
    if "#" in text and not text.lower().startswith("vmess://"):
        try:
            base, frag = text.split("#", 1)
            frag = urllib.parse.quote(urllib.parse.unquote(frag), safe="")
            text = base + "#" + frag
        except:
            pass
    return text


def _proxy_uri_dedup_key(raw_uri):
    uri = _sanitize_proxy_uri(raw_uri)
    if not uri:
        return ""
    if "#" in uri:
        uri = uri.split("#", 1)[0]
    uri = uri.strip()
    if not uri:
        return ""
    low = uri.lower()
    if low.startswith("vmess://"):
        try:
            body = uri[8:]
            if "#" in body:
                body = body.split("#", 1)[0]
            body = body.strip().replace("-", "+").replace("_", "/")
            missing = len(body) % 4
            if missing:
                body += "=" * (4 - missing)
            obj = json.loads(base64.b64decode(body, validate=False).decode("utf-8", errors="ignore"))
            if isinstance(obj, dict):
                canon = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                return "vmess://" + hashlib.sha256(canon.encode("utf-8")).hexdigest()
        except:
            pass
        return uri.strip()
    if low.startswith("ss://"):
        try:
            body = uri[5:].split("#", 1)[0].strip()
            if "@" in body:
                creds, server_part = body.split("@", 1)
            else:
                blob = body.split("?", 1)[0].replace("-", "+").replace("_", "/")
                miss = len(blob) % 4
                if miss:
                    blob += "=" * (4 - miss)
                decoded = base64.b64decode(blob, validate=False).decode("utf-8", errors="ignore")
                if "@" in decoded:
                    creds, server_part = decoded.split("@", 1)
                else:
                    creds, server_part = decoded, ""
            server_part = server_part.split("?", 1)[0].strip().rstrip("/")
            host = ""
            port = ""
            if server_part.startswith("["):
                rb = server_part.find("]")
                if rb > 0:
                    host = server_part[: rb + 1].lower()
                    rest = server_part[rb + 1:]
                    if rest.startswith(":"):
                        port = rest[1:]
            elif ":" in server_part:
                host, port = server_part.rsplit(":", 1)
                host = host.lower().strip()
                port = str(port or "").strip()
            creds = str(creds or "").strip()
            if creds and host and port:
                return "ss://%s@%s:%s" % (creds, host, port)
        except:
            pass
        return uri.strip()
    try:
        parsed = urllib.parse.urlsplit(uri)
    except:
        parsed = None
    if not parsed or not parsed.scheme:
        return uri
    try:
        scheme = str(parsed.scheme or "").lower()
        netloc = str(parsed.netloc or "")
        path = str(parsed.path or "")
        query = str(parsed.query or "")
        if netloc and "@" in netloc:
            userinfo, hostport = netloc.rsplit("@", 1)
        else:
            userinfo, hostport = "", netloc
        host = hostport
        port = ""
        if hostport.startswith("["):
            rb = hostport.find("]")
            if rb > 0:
                host = hostport[: rb + 1]
                rest = hostport[rb + 1:]
                if rest.startswith(":"):
                    port = rest[1:]
        elif ":" in hostport:
            host, port = hostport.rsplit(":", 1)
        host = str(host or "").lower().strip()
        port = str(port or "").strip()
        if userinfo:
            try:
                userinfo = urllib.parse.quote(urllib.parse.unquote(str(userinfo or "")), safe=":")
            except:
                userinfo = str(userinfo or "").strip()
            if scheme == "vless":
                try:
                    userinfo = urllib.parse.quote(urllib.parse.unquote(userinfo).strip("{}").lower(), safe=":")
                except:
                    pass
        if path:
            path = str(path).rstrip("/")
        q_items = []
        if query:
            try:
                q_items = urllib.parse.parse_qsl(query, keep_blank_values=True)
            except:
                q_items = []
        if q_items:
            try:
                q_items.sort(key=lambda item: (str(item[0]), str(item[1])))
                query = "&".join(
                    "%s=%s" % (
                        urllib.parse.quote(str(k or ""), safe=""),
                        urllib.parse.quote(str(v or ""), safe="/:@"),
                    )
                    for k, v in q_items
                )
            except:
                pass
        netloc2 = host
        if port:
            netloc2 = "%s:%s" % (host, port)
        if userinfo:
            netloc2 = "%s@%s" % (userinfo, netloc2)
        return urllib.parse.urlunsplit((scheme, netloc2, path, query, ""))
    except:
        return uri


def _parse_standard_proxy_uri(uri_str, fallback_name="Узел"):
    uri = _sanitize_proxy_uri(uri_str)
    if not uri or "://" not in uri:
        return None
    try:
        scheme = uri.split("://", 1)[0].lower()
        name = fallback_name
        body = uri.split("://", 1)[1]
        if "#" in body:
            body, frag = body.split("#", 1)
            name = _clean_proxy_name(frag, fallback_name)
        if "?" in body:
            before_query, params_raw = body.split("?", 1)
        else:
            before_query, params_raw = body, ""
        if "@" not in before_query:
            return None
        user_info, host_port = before_query.rsplit("@", 1)
        host_port = str(host_port or "").strip().rstrip("/")
        path = ""
        if "/" in host_port:
            host_port, path = host_port.split("/", 1)
            if path:
                path = "/" + path
        host = ""
        port = 0
        if host_port.startswith("["):
            rb = host_port.find("]")
            if rb <= 0:
                return None
            host = host_port[1:rb]
            rest = host_port[rb + 1:]
            if not rest.startswith(":"):
                return None
            port = int(str(rest[1:] or "0").strip())
        else:
            if ":" not in host_port:
                return None
            host, port_s = host_port.rsplit(":", 1)
            port = int(str(port_s or "0").strip())
        params = {}
        if params_raw:
            for key, value in urllib.parse.parse_qsl(params_raw, keep_blank_values=True):
                params[str(key or "")] = str(value or "")
        if path and "path" not in params:
            params["path"] = path
        host = str(host or "").strip()
        if not host or int(port or 0) <= 0:
            return None
        return {
            "scheme": scheme,
            "user": str(user_info or "").strip(),
            "host": host,
            "port": int(port),
            "params": params,
            "name": name,
            "uri": uri,
        }
    except:
        return None


def _parse_vless_uri_details(uri_str):
    try:
        uri = _sanitize_proxy_uri(uri_str)
    except:
        uri = ""
    if not _is_vless_uri(uri):
        return None

    try:
        r = _parse_standard_proxy_uri(uri, "sing-box узел")
        if not r:
            return None
        params = dict(r.get("params", {}) or {})
        uuid_str = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
        host = str(r.get("host", "") or "").strip()
        port = int(r.get("port", 0) or 0)
        if not uuid_str or not host or port <= 0:
            return None

        return {
            "uri": uri,
            "kind": "vless",
            "name": str(r.get("name", "sing-box узел") or "sing-box узел"),
            "uuid": str(uuid_str or "").strip(),
            "server": host,
            "port": int(port),
            "network": str(params.get("type", "tcp") or "tcp"),
            "security": str(params.get("security", "none") or "none"),
            "params": params,
        }
    except:
        return None


def _parse_ss_uri_details(uri_str):
    try:
        uri = _sanitize_proxy_uri(uri_str)
    except:
        uri = ""
    if not _is_ss_uri(uri):
        return None

    try:
        body = uri[5:]
        name = "SS узел"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = _clean_proxy_name(frag, "SS узел")

        params = {}
        if "?" in body:
            body, params_raw = body.split("?", 1)
            try:
                for pair in str(params_raw or "").split("&"):
                    if "=" not in pair:
                        continue
                    k, v = pair.split("=", 1)
                    params[str(k or "").strip()] = urllib.parse.unquote(str(v or ""))
            except:
                pass

        body = str(body or "").strip().rstrip("/")
        method = ""
        password = ""
        host = ""
        port = 0

        if "@" in body:
            user_part, server_part = body.split("@", 1)
            server_part = str(server_part or "").split("?", 1)[0].strip().rstrip("/")
            try:
                user_b64 = str(user_part or "").replace("-", "+").replace("_", "/")
                miss = len(user_b64) % 4
                if miss:
                    user_b64 += "=" * (4 - miss)
                decoded = base64.b64decode(user_b64, validate=False).decode("utf-8", errors="ignore")
            except:
                decoded = urllib.parse.unquote(str(user_part or ""))
            if ":" not in decoded or ":" not in server_part:
                return None
            method, password = decoded.split(":", 1)
            host, port_str = server_part.rsplit(":", 1)
            port = int(str(port_str or "").strip())
        else:
            try:
                blob = str(body or "").replace("-", "+").replace("_", "/")
                miss = len(blob) % 4
                if miss:
                    blob += "=" * (4 - miss)
                decoded = base64.b64decode(blob, validate=False).decode("utf-8", errors="ignore")
            except:
                return None
            if "@" not in decoded or ":" not in decoded:
                return None
            user_part, server_part = decoded.split("@", 1)
            if ":" not in user_part or ":" not in server_part:
                return None
            method, password = user_part.split(":", 1)
            host, port_str = server_part.rsplit(":", 1)
            port = int(str(port_str or "").strip())

        method = str(method or "").strip()
        password = urllib.parse.unquote(str(password or ""))
        host = str(host or "").strip()
        if not method or not host or int(port or 0) <= 0:
            return None

        return {
            "uri": uri,
            "kind": "ss",
            "name": str(name or "SS узел"),
            "method": method,
            "password": password,
            "server": host,
            "port": int(port),
            "network": "tcp",
            "security": "shadowsocks",
            "params": params,
        }
    except:
        return None


def _parse_vmess_uri_details(uri_str):
    uri = _sanitize_proxy_uri(uri_str)
    if not _is_vmess_uri(uri):
        return None
    try:
        body = uri[8:]
        if "#" in body:
            body = body.split("#", 1)[0]
        body = body.strip().replace("-", "+").replace("_", "/")
        missing = len(body) % 4
        if missing:
            body += "=" * (4 - missing)
        obj = json.loads(base64.b64decode(body, validate=False).decode("utf-8", errors="ignore"))
        if not isinstance(obj, dict):
            return None
    except:
        return None
    try:
        host = str(obj.get("add", "") or "").strip()
        port = int(obj.get("port", 0) or 0)
    except:
        return None
    if not host or port <= 0:
        return None
    try:
        alter_id = int(obj.get("aid", 0) or 0)
    except:
        alter_id = 0
    network = str(obj.get("net", "tcp") or "tcp").strip() or "tcp"
    tls_value = str(obj.get("tls", "") or "").strip().lower()
    security = "tls" if tls_value == "tls" else (tls_value if tls_value else "none")
    params = {
        "type": network,
        "security": security,
        "sni": str(obj.get("sni", "") or obj.get("host", "") or ""),
        "fp": str(obj.get("fp", "chrome") or "chrome"),
        "alpn": str(obj.get("alpn", "") or ""),
        "path": str(obj.get("path", "/") or "/"),
        "host": str(obj.get("host", "") or obj.get("sni", "") or ""),
        "headerType": str(obj.get("type", "none") or "none"),
        "serviceName": str(obj.get("path", "") or ""),
        "seed": str(obj.get("path", "") or ""),
    }
    return {
        "uri": uri,
        "kind": "vmess",
        "name": _clean_proxy_name(obj.get("ps", ""), "VMess узел"),
        "uuid": str(obj.get("id", "") or "").strip(),
        "alter_id": int(alter_id),
        "cipher": str(obj.get("scy", "auto") or "auto"),
        "server": host,
        "port": int(port),
        "network": network,
        "security": security,
        "params": params,
    }


def _parse_trojan_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "Trojan узел")
    if not r or str(r.get("scheme", "") or "") != "trojan":
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("security"):
        params["security"] = "tls"
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    network = str(params.get("type", "tcp") or "tcp")
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "trojan",
        "name": str(r.get("name", "Trojan узел") or "Trojan узел"),
        "password": urllib.parse.unquote(str(r.get("user", "") or "")),
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": network,
        "security": str(params.get("security", "tls") or "tls"),
        "params": params,
    }


def _parse_hysteria2_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "Hysteria2 узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme not in ("hy2", "hysteria2"):
        return None
    user = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    password = user.split(":", 1)[1] if ":" in user else user
    password = str(password or "").strip()
    if not password:
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "hysteria2",
        "name": str(r.get("name", "Hysteria2 узел") or "Hysteria2 узел"),
        "password": password,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "udp",
        "security": "tls",
        "params": params,
    }

def _parse_tuic_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "TUIC узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme != "tuic":
        return None
    user = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    uuid = ""
    password = ""
    if ":" in user:
        uuid, password = user.split(":", 1)
    else:
        uuid = user
    uuid = str(uuid or "").strip()
    password = str(password or "").strip()
    if not uuid:
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "tuic",
        "name": str(r.get("name", "TUIC узел") or "TUIC узел"),
        "uuid": uuid,
        "password": password,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "udp",
        "security": "tls",
        "params": params,
    }


def _parse_anytls_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "AnyTLS узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme != "anytls":
        return None
    password = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    if not password:
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "anytls",
        "name": str(r.get("name", "AnyTLS узел") or "AnyTLS узел"),
        "password": password,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "tcp",
        "security": "tls",
        "params": params,
    }


def _parse_ssh_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "SSH узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme != "ssh":
        return None
    user = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    username = user
    password = ""
    if ":" in user:
        username, password = user.split(":", 1)
    username = str(username or "").strip()
    password = str(password or "").strip()
    if not username:
        return None
    params = dict(r.get("params", {}) or {})
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "ssh",
        "name": str(r.get("name", "SSH узел") or "SSH узел"),
        "user": username,
        "password": password,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "tcp",
        "security": "none",
        "params": params,
    }


def _parse_shadowtls_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "ShadowTLS узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme != "shadowtls":
        return None
    password = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    if not password:
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    version = int(params.get("version", "3") or "3") if str(params.get("version", "3")).isdigit() else 3
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "shadowtls",
        "name": str(r.get("name", "ShadowTLS узел") or "ShadowTLS узел"),
        "password": password,
        "version": version,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "tcp",
        "security": "tls",
        "params": params,
    }


def _parse_hysteria_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "Hysteria узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme not in ("hy", "hysteria"):
        return None
    user = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    auth = user
    if not auth:
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "hysteria",
        "name": str(r.get("name", "Hysteria узел") or "Hysteria узел"),
        "auth": auth,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "udp",
        "security": "tls",
        "params": params,
    }


def _parse_naive_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "Naive узел")
    scheme = str((r or {}).get("scheme", "") or "")
    if not r or scheme != "naive":
        return None
    user = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    username = user
    password = ""
    if ":" in user:
        username, password = user.split(":", 1)
    username = str(username or "").strip()
    password = str(password or "").strip()
    if not username:
        return None
    params = dict(r.get("params", {}) or {})
    if not params.get("sni"):
        params["sni"] = str(r.get("host", "") or "")
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "naive",
        "name": str(r.get("name", "Naive узел") or "Naive узел"),
        "user": username,
        "password": password,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": "tcp",
        "security": "tls",
        "params": params,
    }


def _parse_mieru_uri_details(uri_str):
    r = _parse_standard_proxy_uri(uri_str, "Mieru узел")
    if not r or str(r.get("scheme", "") or "") != "mieru":
        return None
    user = urllib.parse.unquote(str(r.get("user", "") or "")).strip()
    if ":" not in user:
        return None
    username, password = (part.strip() for part in user.split(":", 1))
    if not username or not password:
        return None
    params = dict(r.get("params", {}) or {})
    return {
        "uri": str(r.get("uri", "") or ""),
        "kind": "mieru",
        "name": str(r.get("name", "Mieru узел") or "Mieru узел"),
        "user": username,
        "password": password,
        "server": str(r.get("host", "") or ""),
        "port": int(r.get("port", 0) or 0),
        "network": str(params.get("transport", "TCP") or "TCP").lower(),
        "security": "mieru",
        "params": params,
    }


def _parse_sudoku_uri_details(uri_str):
    try:
        uri = str(uri_str or "").strip()
        if not _is_sudoku_uri(uri):
            return None
        payload = json.loads(_decode_base64_urlsafe_no_padding(uri[len("sudoku://"):]).decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        server = str(payload.get("h", "") or "").strip()
        port = int(payload.get("p", 0) or 0)
        key = str(payload.get("k", "") or "").strip()
        if not server or not (1 <= port <= 65535) or not key:
            return None
        custom_tables = payload.get("ts", [])
        if not isinstance(custom_tables, list):
            custom_tables = []
        custom_tables = [str(item or "").strip() for item in custom_tables if str(item or "").strip()]
        return {
            "uri": uri,
            "kind": "sudoku",
            "name": "Sudoku узел",
            "server": server,
            "port": port,
            "key": key,
            "aead_method": str(payload.get("e", "") or "none").strip(),
            "table_type": str(payload.get("a", "") or "prefer_entropy").strip(),
            "padding_min": 5,
            "padding_max": 15,
            "enable_pure_downlink": not bool(payload.get("x", False)),
            "custom_table": str(payload.get("t", "") or "").strip(),
            "custom_tables": custom_tables,
            "http_mask_disabled": bool(payload.get("hd", False)),
            "http_mask_mode": str(payload.get("hm", "") or "").strip(),
            "http_mask_tls": bool(payload.get("ht", False)),
            "http_mask_host": str(payload.get("hh", "") or "").strip(),
            "http_mask_multiplex": str(payload.get("hx", "") or "").strip(),
            "http_mask_path": str(payload.get("hy", "") or "").strip(),
            "network": "tcp",
            "security": "sudoku",
        }
    except:
        return None


def _parse_proxy_uri_details(uri_str):
    spec = PROXY_PROTOCOL_REGISTRY.get(_proxy_uri_scheme(uri_str), {})
    parser = globals().get(str(spec.get("parser", "") or ""))
    if callable(parser):
        return parser(uri_str)
    if _is_hitvpn_uri(uri_str):
        try:
            decoded = _decode_hitvpn_link_to_vless_uris(uri_str)
        except:
            decoded = []
        if decoded:
            return _parse_vless_uri_details(decoded[0])
    return None


def _local_socks_settings(username="", password=""):
    user = str(username or "")
    secret = str(password or "")
    if user and secret:
        return {
            "auth": "password",
            "accounts": [{"user": user, "pass": secret}],
            "udp": True,
            "ip": VLESS_LOCAL_HOST,
        }
    return {"auth": "noauth", "udp": True, "ip": VLESS_LOCAL_HOST}


def _base_xray_socks_config(local_port, socks_username="", socks_password=""):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks-in",
            "port": int(local_port),
            "listen": VLESS_LOCAL_HOST,
            "protocol": "socks",
            "settings": _local_socks_settings(socks_username, socks_password),
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": False},
        }],
        "outbounds": [{"tag": "proxy"}],
    }


def _build_proxy_stream_settings(params, server="", port=0):
    params = dict(params or {})
    network = str(params.get("type", "tcp") or "tcp").lower()
    security = str(params.get("security", "none") or "none").lower()
    fp = str(params.get("fp", "chrome") or "chrome")
    stream = {
        "network": str(network or "tcp"),
        "security": str(security or "none"),
    }
    packet_encoding = str(params.get("packetEncoding", "") or "").strip()
    if packet_encoding:
        stream["packetEncoding"] = packet_encoding

    if security == "reality":
        stream["realitySettings"] = {
            "show": False,
            "fingerprint": fp,
            "serverName": str(params.get("sni", "") or ""),
            "publicKey": str(params.get("pbk", "") or ""),
            "shortId": str(params.get("sid", "") or ""),
            "spiderX": str(params.get("spx", "") or ""),
        }
    elif security == "tls":
        tls = {
            "serverName": str(params.get("sni", "") or ""),
            "allowInsecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
            "fingerprint": fp,
        }
        alpn = str(params.get("alpn", "") or "")
        if alpn:
            tls["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
        stream["tlsSettings"] = tls

    if network == "ws":
        stream["wsSettings"] = {
            "path": str(params.get("path", "/") or "/"),
            "headers": {
                "Host": str(params.get("host", params.get("sni", "")) or ""),
            },
        }
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": str(params.get("serviceName", "") or ""),
            "multiMode": str(params.get("mode", "multi") or "multi") == "multi",
        }
    elif network in ("h2", "http"):
        host = str(params.get("host", params.get("sni", "")) or "")
        stream["httpSettings"] = {
            "path": str(params.get("path", "/") or "/"),
            "host": [host] if host else [],
        }
    elif network in ("kcp", "mkcp"):
        stream["kcpSettings"] = {
            "header": {"type": str(params.get("headerType", "none") or "none")},
            "seed": str(params.get("seed", "") or ""),
        }
    elif network in ("xhttp", "splithttp"):
        xhttp_settings = {
            "path": str(params.get("path", "/") or "/"),
            "mode": str(params.get("mode", "auto") or "auto"),
        }
        explicit_host = str(params.get("host", "") or "")
        if explicit_host:
            xhttp_settings["host"] = explicit_host
        try:
            raw_extra = params.get("extra")
            extra = json.loads(str(raw_extra)) if raw_extra not in (None, "") else None
        except:
            extra = None
        stream_mode = str(xhttp_settings.get("mode", "auto") or "auto")
        if security == "reality" and stream_mode == "stream-one" and not (isinstance(extra, dict) and "downloadSettings" in extra):
            if not isinstance(extra, dict):
                extra = {}
            download_stream = {
                "address": str(server or ""),
                "port": int(port or 0),
                "network": "xhttp",
                "security": security,
                "realitySettings": dict(stream.get("realitySettings", {}) or {}),
                "xhttpSettings": {
                    "path": str(params.get("path", "/") or "/"),
                    "mode": "auto",
                },
            }
            if explicit_host:
                download_stream["xhttpSettings"]["host"] = explicit_host
            extra["downloadSettings"] = download_stream
            xhttp_settings["mode"] = "auto"
        if isinstance(extra, dict) and extra:
            xhttp_settings["extra"] = extra
        stream["xhttpSettings"] = xhttp_settings
        stream["network"] = "xhttp"
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "host": str(params.get("host", params.get("sni", "")) or ""),
            "path": str(params.get("path", "/") or "/"),
        }
    return stream


def _build_vless_config(uri_str, local_port, socks_username="", socks_password=""):
    if _is_ss_uri(uri_str):
        details = _parse_ss_uri_details(uri_str)
        if not details:
            return None, None
        try:
            config = {
                "log": {"loglevel": "none"},
                "inbounds": [{
                    "tag": "socks-in",
                    "port": int(local_port),
                    "listen": VLESS_LOCAL_HOST,
                    "protocol": "socks",
                    "settings": _local_socks_settings(socks_username, socks_password),
                }],
                "outbounds": [{
                    "tag": "proxy",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": str(details.get("server", "") or ""),
                            "port": int(details.get("port", 0) or 0),
                            "method": str(details.get("method", "") or ""),
                            "password": str(details.get("password", "") or ""),
                        }],
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none",
                    },
                }],
            }
            return json.dumps(config), str(details.get("name", "SS узел") or "SS узел")
        except:
            return None, None

    if _is_vmess_uri(uri_str):
        details = _parse_vmess_uri_details(uri_str)
        if not details:
            return None, None
        try:
            config = _base_xray_socks_config(local_port, socks_username, socks_password)
            config["outbounds"][0].update({
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": str(details.get("server", "") or ""),
                        "port": int(details.get("port", 0) or 0),
                        "users": [{
                            "id": str(details.get("uuid", "") or ""),
                            "alterId": int(details.get("alter_id", 0) or 0),
                            "security": str(details.get("cipher", "auto") or "auto"),
                        }],
                    }],
                },
                "streamSettings": _build_proxy_stream_settings(details.get("params", {}), details.get("server", ""), details.get("port", 0)),
            })
            return json.dumps(config), str(details.get("name", "VMess узел") or "VMess узел")
        except:
            return None, None

    if _is_trojan_uri(uri_str):
        details = _parse_trojan_uri_details(uri_str)
        if not details:
            return None, None
        try:
            config = _base_xray_socks_config(local_port, socks_username, socks_password)
            config["outbounds"][0].update({
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": str(details.get("server", "") or ""),
                        "port": int(details.get("port", 0) or 0),
                        "password": str(details.get("password", "") or ""),
                    }],
                },
                "streamSettings": _build_proxy_stream_settings(details.get("params", {}), details.get("server", ""), details.get("port", 0)),
            })
            return json.dumps(config), str(details.get("name", "Trojan узел") or "Trojan узел")
        except:
            return None, None

    if _is_hysteria2_uri(uri_str):
        details = _parse_hysteria2_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            tls = {
                "allowInsecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                "serverName": str(params.get("sni", details.get("server", "")) or ""),
            }
            alpn = str(params.get("alpn", "") or "")
            if alpn:
                tls["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
            config = _base_xray_socks_config(local_port, socks_username, socks_password)
            config["outbounds"][0].update({
                "protocol": "hysteria2",
                "settings": {
                    "servers": [{
                        "address": str(details.get("server", "") or ""),
                        "port": int(details.get("port", 0) or 0),
                        "password": str(details.get("password", "") or ""),
                    }],
                },
                "streamSettings": {
                    "network": "udp",
                    "security": "tls",
                    "tlsSettings": tls,
                },
            })
            return json.dumps(config), str(details.get("name", "Hysteria2 узел") or "Hysteria2 узел")
        except:
            return None, None

    details = _parse_vless_uri_details(uri_str)
    if not details:
        return None, None

    try:
        params = dict(details.get("params", {}) or {})
        xhttp_extra = None
        try:
            raw_extra = params.get("extra")
            if raw_extra not in (None, ""):
                xhttp_extra = json.loads(str(raw_extra))
        except:
            xhttp_extra = None
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "tag": "socks-in",
                "port": int(local_port),
                "listen": VLESS_LOCAL_HOST,
                "protocol": "socks",
                "settings": _local_socks_settings(socks_username, socks_password),
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": details["server"],
                        "port": int(details["port"]),
                        "users": [{
                            "id": details["uuid"],
                            "encryption": "none",
                            "flow": str(params.get("flow", "") or ""),
                        }],
                    }],
                },
                "streamSettings": {
                    "network": str(params.get("type", "tcp") or "tcp"),
                    "security": str(params.get("security", "none") or "none"),
                },
            }],
        }
        stream = config["outbounds"][0]["streamSettings"]
        fp = str(params.get("fp", "chrome") or "chrome")
        packet_encoding = str(params.get("packetEncoding", "") or "").strip()
        if packet_encoding:
            stream["packetEncoding"] = packet_encoding

        if str(params.get("security", "") or "") == "reality":
            stream["realitySettings"] = {
                "show": False,
                "fingerprint": fp,
                "serverName": str(params.get("sni", "") or ""),
                "publicKey": str(params.get("pbk", "") or ""),
                "shortId": str(params.get("sid", "") or ""),
                "spiderX": str(params.get("spx", "") or ""),
            }
        elif str(params.get("security", "") or "") == "tls":
            tls_settings = {
                "serverName": str(params.get("sni", "") or ""),
                "allowInsecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                "fingerprint": fp,
            }
            alpn = str(params.get("alpn", "") or "")
            if alpn:
                tls_settings["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
            stream["tlsSettings"] = tls_settings

        network = str(params.get("type", "tcp") or "tcp").lower()
        stream["network"] = str(network or "tcp")
        if network == "ws":
            stream["wsSettings"] = {
                "path": str(params.get("path", "/") or "/"),
                "headers": {
                    "Host": str(params.get("host", params.get("sni", "")) or ""),
                },
            }
        elif network == "grpc":
            stream["grpcSettings"] = {
                "serviceName": str(params.get("serviceName", "") or ""),
                "multiMode": str(params.get("mode", "multi") or "multi") == "multi",
            }
        elif network in ("h2", "http"):
            host = str(params.get("host", params.get("sni", "")) or "")
            stream["httpSettings"] = {
                "path": str(params.get("path", "/") or "/"),
                "host": [host] if host else [],
            }
        elif network in ("kcp", "mkcp"):
            stream["kcpSettings"] = {
                "header": {"type": str(params.get("headerType", "none") or "none")},
                "seed": str(params.get("seed", "") or ""),
            }
        elif network in ("xhttp", "splithttp"):
            xhttp_settings = {
                "path": str(params.get("path", "/") or "/"),
                "mode": str(params.get("mode", "auto") or "auto"),
            }
            explicit_host = str(params.get("host", "") or "")
            if explicit_host:
                xhttp_settings["host"] = explicit_host
            extra = dict(xhttp_extra or {}) if isinstance(xhttp_extra, dict) else {}
            stream_mode = str(xhttp_settings.get("mode", "auto") or "auto")
            security_mode = str(params.get("security", "none") or "none")
            if security_mode == "reality" and stream_mode == "stream-one" and "downloadSettings" not in extra:
                download_stream = {
                    "address": details["server"],
                    "port": int(details["port"]),
                    "network": "xhttp",
                    "security": security_mode,
                    "realitySettings": {
                        "show": False,
                        "fingerprint": fp,
                        "serverName": str(params.get("sni", "") or ""),
                        "publicKey": str(params.get("pbk", "") or ""),
                        "shortId": str(params.get("sid", "") or ""),
                        "spiderX": str(params.get("spx", "") or ""),
                    },
                    "xhttpSettings": {
                        "path": str(params.get("path", "/") or "/"),
                        "mode": "auto",
                    },
                }
                if explicit_host:
                    download_stream["xhttpSettings"]["host"] = explicit_host
                extra["downloadSettings"] = download_stream
                xhttp_settings["mode"] = "auto"
            if extra:
                xhttp_settings["extra"] = extra
            stream["xhttpSettings"] = xhttp_settings
            stream["network"] = "xhttp"
        elif network == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "host": str(params.get("host", params.get("sni", "")) or ""),
                "path": str(params.get("path", "/") or "/"),
            }

        return json.dumps(config), str(details.get("name", "sing-box узел") or "sing-box узел")
    except:
        return None, None


def _sb_base_config(local_port, socks_username="", socks_password=""):
    inbound = {
        "type": "mixed",
        "tag": "mixed-in",
        "listen": VLESS_LOCAL_HOST,
        "listen_port": int(local_port or 0),
    }
    user = str(socks_username or "").strip()
    pwd = str(socks_password or "").strip()
    if user and pwd:
        inbound["users"] = [{"username": user, "password": pwd}]
    return {
        "log": {"disabled": False, "level": "info"},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "dns-cloudflare", "server": "1.1.1.1"},
                {"type": "udp", "tag": "dns-google", "server": "8.8.8.8"},
                {"type": "udp", "tag": "dns-yandex-1", "server": "77.88.8.8"},
                {"type": "udp", "tag": "dns-yandex-2", "server": "77.88.8.1"},
                {
                    "type": "fallback",
                    "tag": "greenpass-dns",
                    "servers": ["dns-cloudflare", "dns-google", "dns-yandex-1", "dns-yandex-2"],
                    "strategy": "parallel",
                },
            ],
            "final": "greenpass-dns",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"action": "sniff"}],
            "final": "proxy",
            "default_domain_resolver": "greenpass-dns",
        },
    }


def _build_singbox_awg_config(conf_text, local_port):
    def _prefix(value):
        value = str(value or "").strip()
        return value if "/" in value else value + ("/128" if ":" in value else "/32")

    interface = {}
    peers = []
    current = None
    for raw in str(conf_text or "").splitlines():
        line = str(raw or "").strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                current = {}
                peers.append(current)
            else:
                current = interface if section == "interface" else None
            continue
        if current is None or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        current[key.lower()] = value

    private_key = str(interface.get("privatekey", "") or "").strip()
    addresses = [_prefix(item) for item in str(interface.get("address", "") or "").split(",") if item.strip()]
    if not private_key or not addresses or not peers:
        raise ValueError("AWG config requires PrivateKey, Address and Peer")

    awg = {}
    for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime"):
        value = str(interface.get(key, "") or "").strip()
        if value:
            awg[key] = int(value)
    for key in ("h1", "h2", "h3", "h4"):
        value = str(interface.get(key, "") or "").strip()
        if value:
            awg[key] = int(value) if value.isdigit() else value.replace(" ", "")
    for key in ("i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"):
        value = str(interface.get(key, "") or "").strip()
        if value:
            awg[key] = value

    sb_peers = []
    for peer in peers:
        endpoint = str(peer.get("endpoint", "") or "").strip()
        if endpoint.startswith("[") and "]:" in endpoint:
            host, port_text = endpoint[1:].rsplit("]:", 1)
        elif ":" in endpoint:
            host, port_text = endpoint.rsplit(":", 1)
        else:
            raise ValueError("AWG peer Endpoint must include a port")
        port = int(port_text)
        public_key = str(peer.get("publickey", "") or "").strip()
        allowed = [_prefix(item) for item in str(peer.get("allowedips", "") or "").split(",") if item.strip()]
        if not host or not (1 <= port <= 65535) or not public_key or not allowed:
            raise ValueError("AWG peer requires Endpoint, PublicKey and AllowedIPs")
        item = {
            "address": host,
            "port": port,
            "public_key": public_key,
            "allowed_ips": allowed,
        }
        psk = str(peer.get("presharedkey", "") or "").strip()
        if psk:
            item["pre_shared_key"] = psk
        keepalive = str(peer.get("persistentkeepalive", "") or "").strip()
        # Keep the NAT mapping alive by default; an idle tunnel otherwise dies silently.
        item["persistent_keepalive_interval"] = int(keepalive) if keepalive else 25
        sb_peers.append(item)

    endpoint = {
        "type": "wireguard",
        "tag": "awg-out",
        "address": addresses,
        "private_key": private_key,
        "peers": sb_peers,
    }
    listen_port = str(interface.get("listenport", "") or "").strip()
    mtu = str(interface.get("mtu", "") or "").strip()
    if listen_port:
        endpoint["listen_port"] = int(listen_port)
    if mtu:
        endpoint["mtu"] = int(mtu)
    if awg:
        endpoint["amnezia"] = awg

    config = _sb_base_config(local_port)
    config["endpoints"] = [endpoint]
    config["route"]["final"] = "awg-out"
    if not any(":" in item for item in addresses):
        # IPv4-only tunnel: refuse IPv6 targets at once instead of failing each one
        # with "missing IPv6 local address".
        config["route"]["rules"].append({"ip_version": 6, "action": "reject"})
    dns = [item.strip() for item in str(interface.get("dns", "") or "").split(",") if item.strip()]
    if dns:
        config["dns"] = {"servers": [{"type": "udp", "tag": "awg-dns", "server": dns[0]}]}
        config["route"]["default_domain_resolver"] = "awg-dns"
    return json.dumps(config)


def _sb_tls(params, server=""):
    security = str((params or {}).get("security", "none") or "none").lower()
    if security == "none":
        return None
    fp = str((params or {}).get("fp", "chrome") or "chrome")
    if not fp:
        fp = "chrome"
    tls = {
        "enabled": True,
        "server_name": str((params or {}).get("sni", "") or server or ""),
        "insecure": str((params or {}).get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
    }
    alpn = str((params or {}).get("alpn", "") or "")
    if alpn:
        tls["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
    if fp or security == "reality":
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": str((params or {}).get("pbk", "") or ""),
            "short_id": str((params or {}).get("sid", "") or ""),
        }
    return tls


def _sb_transport(params):
    network = str((params or {}).get("type", "tcp") or "tcp").lower()
    if network in ("tcp", "udp", ""):
        return None
    if network == "ws":
        t = {"type": "ws", "path": str((params or {}).get("path", "/") or "/")}
        host = str((params or {}).get("host", (params or {}).get("sni", "")) or "")
        if host:
            t["headers"] = {"Host": host}
        return t
    if network == "grpc":
        return {
            "type": "grpc",
            "service_name": str((params or {}).get("serviceName", "") or ""),
        }
    if network in ("xhttp", "splithttp"):
        extra = {}
        try:
            raw_extra = (params or {}).get("extra", "")
            parsed = json.loads(raw_extra) if isinstance(raw_extra, str) and raw_extra.strip() else {}
            if isinstance(parsed, dict):
                extra = parsed.get("xhttpSettings", parsed)
                if not isinstance(extra, dict):
                    extra = {}
        except:
            extra = {}
        host = (params or {}).get("host", extra.get("host", (params or {}).get("sni", "")))
        if isinstance(host, (list, tuple)):
            host = host[0] if host else ""
        transport = {
            "type": "xhttp",
            "mode": str((params or {}).get("mode", extra.get("mode", "auto")) or "auto"),
            "path": str((params or {}).get("path", extra.get("path", "/")) or "/"),
            "x_padding_bytes": (params or {}).get("xPaddingBytes", extra.get("xPaddingBytes", extra.get("x_padding_bytes", "100-1000"))),
        }
        if host:
            transport["host"] = str(host)
        headers = extra.get("headers")
        if isinstance(headers, dict):
            transport["headers"] = {str(k): str(v) for k, v in headers.items() if str(k).lower() != "host"}
        return transport
    if network in ("kcp", "mkcp"):
        transport = {"type": "mkcp"}
        fields = {
            "mtu": ("mtu",), "tti": ("tti",),
            "uplink_capacity": ("uplinkCapacity", "uplink_capacity"),
            "downlink_capacity": ("downlinkCapacity", "downlink_capacity"),
            "read_buffer_size": ("readBufferSize", "read_buffer_size"),
            "write_buffer_size": ("writeBufferSize", "write_buffer_size"),
        }
        for target, sources in fields.items():
            value = next((str((params or {}).get(key, "") or "").strip() for key in sources if str((params or {}).get(key, "") or "").strip()), "")
            if value.isdigit():
                transport[target] = int(value)
        header = str((params or {}).get("headerType", (params or {}).get("header_type", "")) or "").strip()
        seed = str((params or {}).get("seed", (params or {}).get("kcpseed", "")) or "").strip()
        if header:
            transport["header_type"] = header
        if seed:
            transport["seed"] = seed
        if str((params or {}).get("congestion", "") or "").lower() in ("1", "true", "yes"):
            transport["congestion"] = True
        return transport
    if network in ("h2", "http"):
        host = str((params or {}).get("host", (params or {}).get("sni", "")) or "")
        t = {"type": "http", "path": str((params or {}).get("path", "/") or "/")}
        if host:
            t["host"] = [host]
        method = str((params or {}).get("method", "") or "").strip()
        if method:
            t["method"] = method
        try:
            raw_headers = (params or {}).get("headers")
            if isinstance(raw_headers, dict) and raw_headers:
                t["headers"] = {str(k): str(v) for k, v in raw_headers.items()}
        except:
            pass
        return t
    if network == "httpupgrade":
        return {
            "type": "httpupgrade",
            "host": str((params or {}).get("host", (params or {}).get("sni", "")) or ""),
            "path": str((params or {}).get("path", "/") or "/"),
        }
    if network == "quic":
        return {"type": "quic"}
    return None


def _sb_ensure_tls_for_transport(tls, tr, params, server=""):
    if not tr or str(tr.get("type", "") or "").lower() != "quic":
        return tls
    if tls:
        return tls
    p = dict(params or {})
    sni = str(p.get("sni", "") or server or "")
    return {
        "enabled": True,
        "server_name": sni,
        "insecure": str(p.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
    }


def _build_singbox_config(uri_str, local_port, socks_username="", socks_password=""):
    if _is_sudoku_uri(uri_str):
        details = _parse_sudoku_uri_details(uri_str)
        if not details:
            return None, None
        try:
            outbound = {
                "type": "sudoku",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "key": str(details.get("key", "") or ""),
                "aead_method": str(details.get("aead_method", "none") or "none"),
                "padding_min": int(details.get("padding_min", 5) or 5),
                "padding_max": int(details.get("padding_max", 15) or 15),
                "table_type": str(details.get("table_type", "prefer_entropy") or "prefer_entropy"),
                "enable_pure_downlink": bool(details.get("enable_pure_downlink", True)),
            }
            custom_table = str(details.get("custom_table", "") or "").strip()
            custom_tables = list(details.get("custom_tables", []) or [])
            if custom_table:
                outbound["custom_table"] = custom_table
            if custom_tables:
                outbound["custom_tables"] = custom_tables

            mask_mode = str(details.get("http_mask_mode", "") or "").strip()
            mask_host = str(details.get("http_mask_host", "") or "").strip()
            mask_mux = str(details.get("http_mask_multiplex", "") or "").strip()
            mask_path = str(details.get("http_mask_path", "") or "").strip()
            mask_tls = bool(details.get("http_mask_tls", False))
            mask_disabled = bool(details.get("http_mask_disabled", False))
            if mask_disabled or mask_mode or mask_host or mask_mux or mask_path or mask_tls:
                http_mask = {"enabled": not mask_disabled}
                if mask_mode:
                    http_mask["mode"] = mask_mode
                if mask_host:
                    http_mask["host"] = mask_host
                if mask_mux:
                    http_mask["multiplex"] = mask_mux
                if mask_path:
                    http_mask["path_root"] = mask_path
                if mask_tls:
                    http_mask["tls"] = {
                        "enabled": True,
                        "server_name": mask_host or str(details.get("server", "") or ""),
                    }
                outbound["http_mask"] = http_mask

            config = _sb_base_config(local_port, socks_username, socks_password)
            config["outbounds"] = [outbound]
            return json.dumps(config), str(details.get("name", "Sudoku узел") or "Sudoku узел")
        except:
            return None, None

    if _is_mieru_uri(uri_str):
        details = _parse_mieru_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            outbound = {
                "type": "mieru",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "transport": str(params.get("transport", "TCP") or "TCP").upper(),
                "username": str(details.get("user", "") or ""),
                "password": str(details.get("password", "") or ""),
            }
            ports = [item.strip() for item in str(params.get("server_ports", "") or "").split(",") if item.strip()]
            if ports:
                outbound["server_ports"] = ports
            for key in ("multiplexing", "traffic_pattern"):
                value = str(params.get(key, "") or "").strip()
                if value:
                    outbound[key] = value
            config = _sb_base_config(local_port, socks_username, socks_password)
            config["outbounds"] = [outbound]
            return json.dumps(config), str(details.get("name", "Mieru узел") or "Mieru узел")
        except:
            return None, None

    if _is_ss_uri(uri_str):
        details = _parse_ss_uri_details(uri_str)
        if not details:
            return None, None
        try:
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            cfg["outbounds"] = [{
                "type": "shadowsocks",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "method": str(details.get("method", "") or ""),
                "password": str(details.get("password", "") or ""),
            }]
            return json.dumps(cfg), str(details.get("name", "SS узел") or "SS узел")
        except:
            return None, None

    if _is_vmess_uri(uri_str):
        details = _parse_vmess_uri_details(uri_str)
        if not details:
            return None, None
        try:
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "vmess",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "uuid": str(details.get("uuid", "") or ""),
                "security": str(details.get("cipher", "auto") or "auto"),
                "alter_id": int(details.get("alter_id", 0) or 0),
            }
            tr = _sb_transport(details.get("params", {}))
            tls = _sb_ensure_tls_for_transport(_sb_tls(details.get("params", {}), details.get("server", "")), tr, details.get("params", {}), details.get("server", ""))
            if tls:
                ob["tls"] = tls
            if tr:
                ob["transport"] = tr
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "VMess узел") or "VMess узел")
        except:
            return None, None

    if _is_trojan_uri(uri_str):
        details = _parse_trojan_uri_details(uri_str)
        if not details:
            return None, None
        try:
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "trojan",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "password": str(details.get("password", "") or ""),
            }
            tr = _sb_transport(details.get("params", {}))
            tls = _sb_ensure_tls_for_transport(_sb_tls(details.get("params", {}), details.get("server", "")), tr, details.get("params", {}), details.get("server", ""))
            if tls:
                ob["tls"] = tls
            if tr:
                ob["transport"] = tr
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "Trojan узел") or "Trojan узел")
        except:
            return None, None

    if _is_hysteria2_uri(uri_str):
        details = _parse_hysteria2_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "hysteria2",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "password": str(details.get("password", "") or ""),
                "tls": {
                    "enabled": True,
                    "server_name": str(params.get("sni", details.get("server", "")) or ""),
                    "insecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                },
            }
            alpn = str(params.get("alpn", "") or "")
            if alpn:
                ob["tls"]["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
            obfps = str(params.get("fp", "") or "")
            if obfps:
                ob["tls"]["utls"] = {"enabled": True, "fingerprint": obfps}
            obfs_type = str(params.get("obfs", "") or "").strip()
            obfs_password = str(params.get("obfs-password", params.get("obfs_password", "")) or "")
            if obfs_type:
                ob["obfs"] = {"type": obfs_type}
                if obfs_password:
                    ob["obfs"]["password"] = obfs_password
            up = str(params.get("up", "") or "").strip()
            down = str(params.get("down", "") or "").strip()
            if up:
                try:
                    ob["up_mbps"] = int(up)
                except:
                    pass
            if down:
                try:
                    ob["down_mbps"] = int(down)
                except:
                    pass
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "Hysteria2 узел") or "Hysteria2 узел")
        except:
            return None, None

    if _is_tuic_uri(uri_str):
        details = _parse_tuic_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "tuic",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "uuid": str(details.get("uuid", "") or ""),
                "password": str(details.get("password", "") or ""),
                "tls": {
                    "enabled": True,
                    "server_name": str(params.get("sni", details.get("server", "")) or ""),
                    "insecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                },
            }
            alpn = str(params.get("alpn", "") or "")
            if alpn:
                ob["tls"]["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
            cc = str(params.get("congestion_control", params.get("cc", "")) or "").strip()
            if cc:
                ob["congestion_control"] = cc
            udpm = str(params.get("udp_relay_mode", "") or "").strip()
            if udpm:
                ob["udp_relay_mode"] = udpm
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "TUIC узел") or "TUIC узел")
        except:
            return None, None

    if _is_anytls_uri(uri_str):
        details = _parse_anytls_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "anytls",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "password": str(details.get("password", "") or ""),
                "tls": {
                    "enabled": True,
                    "server_name": str(params.get("sni", details.get("server", "")) or ""),
                    "insecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                },
            }
            alpn = str(params.get("alpn", "") or "")
            if alpn:
                ob["tls"]["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
            fpsb = str(params.get("fp", "") or "")
            if fpsb:
                ob["tls"]["utls"] = {"enabled": True, "fingerprint": fpsb}
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "AnyTLS узел") or "AnyTLS узел")
        except:
            return None, None

    if _is_ssh_uri(uri_str):
        details = _parse_ssh_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "ssh",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "user": str(details.get("user", "") or ""),
                "password": str(details.get("password", "") or ""),
            }
            pk = str(params.get("private_key", params.get("privateKey", "")) or "").strip()
            if pk:
                ob["private_key"] = [pk]
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "SSH узел") or "SSH узел")
        except:
            return None, None

    if _is_shadowtls_uri(uri_str):
        details = _parse_shadowtls_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "shadowtls",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "password": str(details.get("password", "") or ""),
                "version": int(details.get("version", 3) or 3),
                "tls": {
                    "enabled": True,
                    "server_name": str(params.get("sni", details.get("server", "")) or ""),
                    "insecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                },
            }
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "ShadowTLS узел") or "ShadowTLS узел")
        except:
            return None, None

    if _is_hysteria_uri(uri_str):
        details = _parse_hysteria_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "hysteria",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "auth_str": str(details.get("auth", "") or ""),
                "tls": {
                    "enabled": True,
                    "server_name": str(params.get("sni", details.get("server", "")) or ""),
                    "insecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                },
            }
            alpn = str(params.get("alpn", "") or "")
            if alpn:
                ob["tls"]["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
            up = str(params.get("up", "") or "").strip()
            down = str(params.get("down", "") or "").strip()
            if up:
                try:
                    ob["up_mbps"] = int(up)
                except:
                    pass
            if down:
                try:
                    ob["down_mbps"] = int(down)
                except:
                    pass
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "Hysteria узел") or "Hysteria узел")
        except:
            return None, None

    if _is_naive_uri(uri_str):
        details = _parse_naive_uri_details(uri_str)
        if not details:
            return None, None
        try:
            params = dict(details.get("params", {}) or {})
            cfg = _sb_base_config(local_port, socks_username, socks_password)
            ob = {
                "type": "naive",
                "tag": "proxy",
                "server": str(details.get("server", "") or ""),
                "server_port": int(details.get("port", 0) or 0),
                "username": str(details.get("user", "") or ""),
                "password": str(details.get("password", "") or ""),
                "tls": {
                    "enabled": True,
                    "server_name": str(params.get("sni", details.get("server", "")) or ""),
                    "insecure": str(params.get("insecure", "0") or "0").lower() in ("1", "true", "yes"),
                },
            }
            quic_flag = str(params.get("quic", "") or "").strip().lower() in ("1", "true", "yes")
            if quic_flag:
                ob["quic"] = True
            cfg["outbounds"] = [ob]
            return json.dumps(cfg), str(details.get("name", "Naive узел") or "Naive узел")
        except:
            return None, None

    details = _parse_vless_uri_details(uri_str)
    if not details:
        return None, None
    try:
        params = dict(details.get("params", {}) or {})
        cfg = _sb_base_config(local_port, socks_username, socks_password)
        ob = {
            "type": "vless",
            "tag": "proxy",
            "server": str(details.get("server", "") or ""),
            "server_port": int(details.get("port", 0) or 0),
            "uuid": str(details.get("uuid", "") or ""),
            "flow": str(params.get("flow", "") or ""),
        }
        pe = str(params.get("packetEncoding", "") or "").strip()
        if pe:
            ob["packet_encoding"] = pe
        tr = _sb_transport(params)
        tls = _sb_ensure_tls_for_transport(_sb_tls(params, details.get("server", "")), tr, params, details.get("server", ""))
        if tls:
            ob["tls"] = tls
        if tr:
            ob["transport"] = tr
        cfg["outbounds"] = [ob]
        return json.dumps(cfg), str(details.get("name", "sing-box узел") or "sing-box узел")
    except:
        return None, None


def _build_registered_proxy_config(uri_str, local_port, socks_username="", socks_password=""):
    spec = PROXY_PROTOCOL_REGISTRY.get(_proxy_uri_scheme(uri_str), {})
    builder = globals().get(str(spec.get("builder", "") or ""))
    if not callable(builder):
        return None, None
    return builder(uri_str, local_port, socks_username=socks_username, socks_password=socks_password)


def _build_singbox_balanced_config(nodes, local_port, socks_username="", socks_password=""):
    outbounds = []
    for node in list(nodes or [])[:VLESS_BALANCER_MAX_NODES]:
        try:
            uri = str(node.get("uri", "") if isinstance(node, dict) else node or "")
            raw, _ = _build_registered_proxy_config(uri, local_port, socks_username=socks_username, socks_password=socks_password)
            if not raw:
                continue
            obs = json.loads(raw).get("outbounds") or []
            ob = next((o for o in obs if o.get("tag") == "proxy"), None)
            if not ob:
                continue
            tag = "sb-route-%d" % (len(outbounds) + 1)
            ob["tag"] = tag
            outbounds.append(ob)
        except:
            continue
    if not outbounds:
        return None
    cfg = _sb_base_config(local_port, socks_username, socks_password)
    if len(outbounds) == 1:
        outbounds[0]["tag"] = "proxy"
        cfg["outbounds"] = outbounds + [{"type": "direct", "tag": "direct"}]
        return json.dumps(cfg)
    selector_tags = [o["tag"] for o in outbounds]
    outbounds.append({
        "type": "urltest",
        "tag": "proxy",
        "outbounds": selector_tags,
        "url": "https://cp.cloudflare.com/generate_204",
        "interval": "3m",
        "tolerance": 50,
    })
    outbounds.append({"type": "direct", "tag": "direct"})
    cfg["outbounds"] = outbounds
    cfg["route"]["final"] = "proxy"
    return json.dumps(cfg)


def _prepare_singbox_file_config(config_text, local_port, socks_username="", socks_password=""):
    cfg = json.loads(str(config_text or ""))
    if not isinstance(cfg, dict):
        raise ValueError("sing-box config must be an object")
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("sing-box config requires outbounds")
    cfg = dict(cfg)
    base = _sb_base_config(local_port, socks_username, socks_password)
    cfg["inbounds"] = base["inbounds"]
    dns = cfg.get("dns")
    inherited_dns = not isinstance(dns, dict) or not isinstance(dns.get("servers"), list) or not dns.get("servers")
    if inherited_dns:
        cfg["dns"] = base["dns"]
    route = cfg.get("route")
    route = dict(route) if isinstance(route, dict) else {}
    if inherited_dns and not str(route.get("default_domain_resolver", "") or "").strip():
        route["default_domain_resolver"] = base["route"]["default_domain_resolver"]
    if not str(route.get("final", "") or "").strip():
        first = outbounds[0]
        tag = str(first.get("tag", "") or "").strip() if isinstance(first, dict) else ""
        if not tag and isinstance(first, dict):
            outbounds = list(outbounds)
            first = dict(first)
            first["tag"] = "proxy"
            outbounds[0] = first
            cfg["outbounds"] = outbounds
            tag = "proxy"
        route["final"] = tag or "proxy"
    cfg["route"] = route
    return json.dumps(cfg)


def _singbox_node_from_config_text(config_text, name=""):
    cfg = json.loads(str(config_text or ""))
    if not isinstance(cfg, dict):
        raise ValueError("sing-box config must be an object")
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("sing-box config requires outbounds")
    raw = json.dumps(cfg, ensure_ascii=False, separators=(",", ":"))
    node_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    label = str(name or cfg.get("name", "") or cfg.get("remarks", "") or "sing-box config").strip()
    first = outbounds[0] if isinstance(outbounds[0], dict) else {}
    try:
        port = int(first.get("server_port", first.get("port", 0)) or 0)
    except:
        port = 0
    return {
        "id": "singconf://" + node_id,
        "uri": "singconf://" + node_id,
        "kind": "singbox-config",
        "name": label[:48] if label else "sing-box config",
        "server": str(first.get("server", first.get("server_address", first.get("address", ""))) or ""),
        "port": port,
        "network": "sing-box",
        "security": "config",
        "raw_config": raw,
    }


def _normalize_vless_engine(value):
    return VLESS_ENGINE_MIHOMO if str(value or "").strip().lower() == VLESS_ENGINE_MIHOMO else VLESS_ENGINE_SINGBOX


def _build_mihomo_core_config(config_text="", links=None, local_port=0, work_dir="", socks_username="", socks_password=""):
    raw = str(config_text or "")
    if len(raw.encode("utf-8", errors="ignore")) > MIHOMO_CONFIG_MAX_BYTES:
        raise ValueError("Mihomo config is too large")
    clean_links = [str(item or "").strip() for item in list(links or []) if str(item or "").strip()]
    if not raw.strip() and not clean_links:
        raise ValueError("Mihomo config is empty")
    return json.dumps({
        "engine": VLESS_ENGINE_MIHOMO,
        "config": raw,
        "links": clean_links,
        "work_dir": str(work_dir or ""),
        "mixed_port": int(local_port or 0),
        "username": str(socks_username or ""),
        "password": str(socks_password or ""),
    }, ensure_ascii=False)


def _mihomo_node_from_config_text(config_text, name=""):
    raw = str(config_text or "")
    size = len(raw.encode("utf-8", errors="ignore"))
    if size <= 0 or size > MIHOMO_CONFIG_MAX_BYTES:
        raise ValueError("Mihomo config size is invalid")
    node_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    label = str(name or "Mihomo config").strip()
    return {
        "id": "mihomo://" + node_id,
        "uri": "mihomo://" + node_id,
        "kind": "mihomo-config",
        "name": label[:48] if label else "Mihomo config",
        "server": "",
        "port": 0,
        "network": "Mihomo",
        "security": "config",
        "raw_config": raw,
    }


def _is_singbox_core(core):
    try:
        if str(getattr(core, "mode", "") or "").lower() == "singbox":
            return True
    except:
        pass
    try:
        so_path = str(getattr(core, "_so_path", "") or "")
        base = os.path.basename(so_path).lower()
        if "greenpass" in base or "singbox" in base or "sing-box" in base or "sing_box" in base:
            return True
    except:
        pass
    return False


def _generic_proxy_node_from_details(details):
    if not details:
        return None
    uri = str(details.get("uri", "") or "")
    server = str(details.get("server", "") or "")
    port = int(details.get("port", 0) or 0)
    name = _clean_proxy_name(details.get("name", "Узел"))
    if _is_generic_proxy_name(name):
        name = _proxy_name_from_uri(uri) or _proxy_address_name(server, port)
    return {
        "id": uri,
        "uri": uri,
        "kind": str(details.get("kind", _proxy_uri_scheme(uri)) or ""),
        "name": name,
        "server": server,
        "port": port,
        "network": str(details.get("network", "tcp") or "tcp"),
        "security": str(details.get("security", "none") or "none"),
        "method": str(details.get("method", "") or ""),
    }


def _proxy_node_from_uri(uri_str):
    return _generic_proxy_node_from_details(_parse_proxy_uri_details(uri_str))

_TGWS_TG_RANGES = [
    (struct.unpack("!I", socket.inet_aton("185.76.151.0"))[0], struct.unpack("!I", socket.inet_aton("185.76.151.255"))[0]),
    (struct.unpack("!I", socket.inet_aton("149.154.160.0"))[0], struct.unpack("!I", socket.inet_aton("149.154.175.255"))[0]),
    (struct.unpack("!I", socket.inet_aton("91.105.192.0"))[0], struct.unpack("!I", socket.inet_aton("91.105.193.255"))[0]),
    (struct.unpack("!I", socket.inet_aton("91.108.0.0"))[0], struct.unpack("!I", socket.inet_aton("91.108.255.255"))[0]),
]

_TGWS_IP_TO_DC = {
    "149.154.175.50": (1, False),
    "149.154.175.51": (1, False),
    "149.154.175.53": (1, False),
    "149.154.175.54": (1, False),
    "149.154.175.52": (1, True),
    "149.154.167.41": (2, False),
    "149.154.167.50": (2, False),
    "149.154.167.51": (2, False),
    "149.154.167.220": (2, False),
    "95.161.76.100": (2, False),
    "149.154.167.151": (2, True),
    "149.154.167.222": (2, True),
    "149.154.167.223": (2, True),
    "149.154.162.123": (2, True),
    "149.154.175.100": (3, False),
    "149.154.175.101": (3, False),
    "149.154.175.102": (3, True),
    "149.154.167.91": (4, False),
    "149.154.167.92": (4, False),
    "149.154.164.250": (4, True),
    "149.154.166.120": (4, True),
    "149.154.166.121": (4, True),
    "149.154.167.118": (4, True),
    "149.154.165.111": (4, True),
    "91.108.56.100": (5, False),
    "91.108.56.101": (5, False),
    "91.108.56.116": (5, False),
    "91.108.56.126": (5, False),
    "149.154.171.5": (5, False),
    "91.108.56.102": (5, True),
    "91.108.56.128": (5, True),
    "91.108.56.151": (5, True),
    "91.105.192.100": (203, False),
}

__all__ = [name for name in globals() if not name.startswith("__")]
