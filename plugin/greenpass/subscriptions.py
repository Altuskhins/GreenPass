from .foundation import *
from .protocols import *
from .native import *

_SUBSCRIPTION_HWID = ""
_OLCRTC_DEVICE_ID = ""


def _get_or_create_subscription_hwid():
    global _SUBSCRIPTION_HWID
    try:
        prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
        custom = str(prefs.getString("subscription_hwid_custom", "") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{16}", custom):
            return custom
        if _SUBSCRIPTION_HWID:
            return _SUBSCRIPTION_HWID
        value = str(prefs.getString("subscription_hwid", "") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            value = os.urandom(8).hex()
            prefs.edit().putString("subscription_hwid", value).commit()
        _SUBSCRIPTION_HWID = value
    except:
        _SUBSCRIPTION_HWID = os.urandom(8).hex()
    return _SUBSCRIPTION_HWID


def _get_or_create_olcrtc_device_id():
    global _OLCRTC_DEVICE_ID
    if _OLCRTC_DEVICE_ID:
        return _OLCRTC_DEVICE_ID
    try:
        prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
        value = str(prefs.getString("olcrtc_device_id", "") or "").strip()
        if not re.fullmatch(r"install-[0-9a-f]{32}", value):
            value = "install-" + os.urandom(16).hex()
            prefs.edit().putString("olcrtc_device_id", value).commit()
        _OLCRTC_DEVICE_ID = value
    except:
        _OLCRTC_DEVICE_ID = "install-" + os.urandom(16).hex()
    return _OLCRTC_DEVICE_ID


def _set_subscription_hwid_custom(value):
    global _SUBSCRIPTION_HWID
    custom = str(value or "").strip().lower()
    if custom and not re.fullmatch(r"[0-9a-f]{16}", custom):
        return False
    try:
        prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
        prefs.edit().putString("subscription_hwid_custom", custom).commit()
        _SUBSCRIPTION_HWID = ""
        return True
    except:
        return False


def _vless_retry_delay(failures):
    try:
        count = max(1, int(failures))
    except:
        count = 1
    return min(float(VLESS_RETRY_MAX_SEC), float(VLESS_RETRY_BASE_SEC) * (2 ** min(count - 1, 4)))


def _subscription_request_headers(url):
    try:
        host = str(urllib.parse.urlparse(str(url or "")).netloc or "").strip()
    except:
        host = ""
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "close",
        "User-agent": "Happ/3.13.0",
        "X-Device-Locale": "en",
        "X-Device-model": "Pixel 9",
        "X-Device-OS": "Android",
        "X-HWID": _get_or_create_subscription_hwid(),
        "X-Ver-OS": "16",
    }
    if host:
        headers["Host"] = host
    return headers


def _normalize_subscription_url(value):
    target = str(value or "").strip()
    if not target or any(char.isspace() for char in target):
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", target, re.IGNORECASE):
        target = "https://" + target.lstrip("/")
    try:
        parsed = urllib.parse.urlparse(target)
        if str(parsed.scheme or "").lower() not in ("http", "https") or not parsed.hostname:
            return ""
        parsed.port
    except:
        return ""
    return target


def _subscription_candidate_urls(url):
    target = _normalize_subscription_url(url)
    if not target:
        return []

    urls = [target]
    try:
        parsed = urllib.parse.urlparse(target)
        host = str(parsed.netloc or "").strip().lower()
        parts = [part for part in str(parsed.path or "").split("/") if part]
        if host == "raw.githubusercontent.com" and len(parts) >= 5 and parts[2] == "refs" and parts[3] == "heads":
            repo_owner = str(parts[0] or "").strip()
            repo_name = str(parts[1] or "").strip()
            branch_name = str(parts[4] or "").strip()
            tail_parts = list(parts[5:])
            canonical_path = "/" + "/".join([parts[0], parts[1], parts[4]] + parts[5:])
            canonical = urllib.parse.urlunparse((
                parsed.scheme or "https",
                parsed.netloc,
                canonical_path,
                "",
                parsed.query or "",
                "",
            ))
            if canonical and canonical not in urls:
                urls.append(canonical)
            if repo_owner and repo_name and branch_name:
                jsd_path = "/gh/" + "/".join([repo_owner, repo_name + "@" + branch_name] + tail_parts)
                for jsd_host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net", "fastly.jsdelivr.net"):
                    jsd = urllib.parse.urlunparse((
                        "https",
                        jsd_host,
                        jsd_path,
                        "",
                        parsed.query or "",
                        "",
                    ))
                    if jsd and jsd not in urls:
                        urls.append(jsd)
    except:
        pass
    return urls


SUBSCRIPTION_MAX_BYTES = 8 * 1024 * 1024
SUBSCRIPTION_FETCH_DEADLINE_SEC = 40.0


class _SubscriptionLimitError(Exception):
    pass


def _gunzip_limited(data, limit):
    """Incrementally gunzip `data`; raise _SubscriptionLimitError past `limit` output bytes."""
    import zlib
    out = []
    total = 0
    rest = bytes(data)
    while rest:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        chunk = dec.decompress(rest, limit - total + 1)
        total += len(chunk)
        if total > limit:
            raise _SubscriptionLimitError("gzip body too large")
        out.append(chunk)
        while dec.unconsumed_tail:
            chunk = dec.decompress(dec.unconsumed_tail, limit - total + 1)
            total += len(chunk)
            if total > limit:
                raise _SubscriptionLimitError("gzip body too large")
            out.append(chunk)
            if not chunk:
                break
        rest = dec.unused_data
        if not dec.eof:
            break
        if rest[:2] != b"\x1f\x8b":
            break
    return b"".join(out)


def _decode_subscription_body(raw, encoding="", max_bytes=None):
    limit = int(max_bytes or SUBSCRIPTION_MAX_BYTES)
    data = bytes(raw or b"")
    if len(data) > limit:
        raise _SubscriptionLimitError("body too large")
    enc = str(encoding or "").lower().strip()
    if data[:2] == b"\x1f\x8b" or "gzip" in enc:
        try:
            data = _gunzip_limited(data, limit)
        except _SubscriptionLimitError:
            raise
        except Exception:
            pass
    try:
        return data.decode("utf-8")
    except:
        return data.decode("utf-8", errors="ignore")


def _read_limited(resp, limit, deadline):
    chunks = []
    total = 0
    # read1 returns after a single recv, so a slow-drip server cannot hold us past the deadline
    reader = getattr(resp, "read1", None) or resp.read
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("subscription fetch deadline exceeded")
        chunk = reader(min(65536, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise _SubscriptionLimitError("body too large")
        chunks.append(chunk)
    return b"".join(chunks)


class _DeadlineRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, deadline):
        self._deadline = deadline

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if time.monotonic() > self._deadline:
            raise TimeoutError("subscription fetch deadline exceeded")
        return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


def _fetch_text_url(url, timeout_sec=15.0, request_headers=None):
    try:
        base_timeout = max(float(timeout_sec), 15.0)
    except:
        base_timeout = 15.0
    timeouts = []
    for item in (base_timeout, max(base_timeout, 30.0), max(base_timeout, 45.0)):
        try:
            value = float(item)
        except:
            continue
        if value not in timeouts:
            timeouts.append(value)

    errors = []
    candidate_urls = _subscription_candidate_urls(url)
    limit = int(SUBSCRIPTION_MAX_BYTES)
    deadline = time.monotonic() + float(SUBSCRIPTION_FETCH_DEADLINE_SEC)

    def _diag_ok(candidate_url, current_timeout):
        _set_vless_fetch_diag(
            url,
            stage="fetched",
            fetched_url=str(candidate_url or ""),
            timeout=float(current_timeout),
            tried=len(candidate_urls),
            errors=" | ".join(list(errors or [])[:4]),
        )

    def _note_error(prefix, candidate_url, e):
        try:
            host = str(urllib.parse.urlparse(str(candidate_url or "")).netloc or "").strip()
        except:
            host = ""
        err = "%s@%s:%s" % (prefix, host or "?", str(type(e).__name__))
        if err not in errors:
            errors.append(err)

    stop = False
    for candidate_url in candidate_urls:
        if stop:
            break
        headers = dict(request_headers) if isinstance(request_headers, dict) else _subscription_request_headers(candidate_url)

        for current_timeout in list(timeouts or [15.0]):
            remaining = deadline - time.monotonic()
            if remaining <= 0.5:
                if "deadline" not in errors:
                    errors.append("deadline")
                stop = True
                break
            current_timeout = min(float(current_timeout), remaining)
            urllib_timed_out = False
            try:
                req = urllib.request.Request(str(candidate_url or ""), headers=headers)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx),
                    _DeadlineRedirectHandler(deadline),
                )
                with opener.open(req, timeout=float(current_timeout)) as resp:
                    raw = _read_limited(resp, limit, deadline)
                    try:
                        encoding = str(resp.headers.get("Content-Encoding", "") or "")
                    except:
                        encoding = ""
                    text = _decode_subscription_body(raw, encoding=encoding, max_bytes=limit)
                    if text:
                        _diag_ok(candidate_url, current_timeout)
                        return text
            except _SubscriptionLimitError as e:
                _note_error("toolarge", candidate_url, e)
                stop = True
                break
            except Exception as e:
                _note_error("urllib", candidate_url, e)
                urllib_timed_out = isinstance(e, (socket.timeout, TimeoutError))

            if urllib_timed_out or time.monotonic() >= deadline:
                # a timeout would almost certainly repeat with requests; move on
                continue
            try:
                import requests
                r = requests.get(str(candidate_url or ""), timeout=float(current_timeout), verify=False, headers=headers, stream=True)
                try:
                    if int(getattr(r, "status_code", 0) or 0) == 200:
                        buf = []
                        total = 0
                        for piece in r.iter_content(65536):
                            if time.monotonic() > deadline:
                                raise TimeoutError("subscription fetch deadline exceeded")
                            if not piece:
                                continue
                            total += len(piece)
                            if total > limit:
                                raise _SubscriptionLimitError("body too large")
                            buf.append(piece)
                        raw = b"".join(buf)
                        encoding = str(getattr(getattr(r, "headers", {}), "get", lambda *a, **k: "")("Content-Encoding", "") or "")
                        text = _decode_subscription_body(raw, encoding=encoding, max_bytes=limit)
                        if text:
                            _diag_ok(candidate_url, current_timeout)
                            return text
                finally:
                    try:
                        r.close()
                    except:
                        pass
            except _SubscriptionLimitError as e:
                _note_error("toolarge", candidate_url, e)
                stop = True
                break
            except Exception as e:
                _note_error("requests", candidate_url, e)
    _set_vless_fetch_diag(
        url,
        stage="fetch_failed",
        fetched_url="",
        timeout=float(timeouts[-1] if timeouts else 0.0),
        tried=len(candidate_urls),
        errors=" | ".join(list(errors or [])[:4]),
    )
    return ""


def _qwdtt_int(value, default=0):
    try:
        return int(value)
    except:
        return int(default)


def _qwdtt_profile_from_mapping(value, source_uri=""):
    if not isinstance(value, dict):
        return None
    peer = str(value.get("peer", "") or "").strip()
    if not peer:
        host = str(value.get("server", value.get("dtls_host", "")) or "").strip()
        port = _qwdtt_int(value.get("dtls_port", value.get("server_port", 56000)), 56000)
        if host:
            peer = "%s:%d" % (host, port)
    elif value.get("dtls_port", value.get("server_port", "")) not in (None, ""):
        port = _qwdtt_int(value.get("dtls_port", value.get("server_port", 56000)), 56000)
        if peer.startswith("["):
            if "]:" not in peer:
                peer = "%s:%d" % (peer, port)
        elif ":" not in peer:
            peer = "%s:%d" % (peer, port)
    raw_hashes = value.get("hashes", value.get("vkHashes", value.get("vk_hashes", value.get("vk_hash", ""))))
    if isinstance(raw_hashes, (list, tuple)):
        hashes = [str(item or "").strip() for item in raw_hashes if str(item or "").strip()]
    else:
        hashes = [item.strip() for item in str(raw_hashes or "").replace("\n", ",").split(",") if item.strip()]
    password = str(value.get("password", value.get("pass", "")) or "").strip()
    if not peer or not hashes or not password:
        return None
    workers = _qwdtt_int(value.get("workers", value.get("workersPerHash", 16)), 16)
    workers = max(9, min(108, workers))
    local_port = _qwdtt_int(value.get("local_port", value.get("port", value.get("listenPort", 9000))), 9000)
    if local_port < 0 or local_port > 65535:
        local_port = 9000
    name = str(value.get("name", value.get("label", "")) or "").strip() or (peer.split(":", 1)[0] if peer else "qWDTT")
    canonical = json.dumps({
        "peer": peer,
        "hashes": hashes,
        "password": password,
        "workers": workers,
        "local_port": local_port,
        "turn_host": str(value.get("turn_host", "") or "").strip(),
        "turn_port": str(value.get("turn_port", "") or "").strip(),
        "vk_anon_path": str(value.get("vk_anon_path", "") or "").strip(),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "id": hashlib.sha256(canonical.encode("utf-8", errors="ignore")).hexdigest()[:24],
        "name": name[:80],
        "peer": peer,
        "hashes": hashes,
        "password": password,
        "workers": workers,
        "local_port": local_port,
        "turn_host": str(value.get("turn_host", "") or "").strip(),
        "turn_port": str(value.get("turn_port", "") or "").strip(),
        "vk_anon_path": str(value.get("vk_anon_path", "") or "").strip(),
        "wait_ready_timeout_millis": max(15000, min(120000, _qwdtt_int(value.get("wait_ready_timeout_millis", 60000), 60000))),
        "source_uri": str(source_uri or "").strip(),
    }


def _parse_qwdtt_uri(value):
    text = str(value or "").strip().rstrip(".,!?)]}>")
    low = text.lower()
    if low.startswith("wdtt://"):
        parts = text[7:].split(":")
        if len(parts) < 6:
            return None
        return _qwdtt_profile_from_mapping({
            "name": parts[0],
            "peer": "%s:%s" % (parts[0], parts[1]),
            "wg_port": parts[2],
            "local_port": parts[3],
            "password": parts[4],
            "hashes": ":".join(parts[5:]),
            "workers": 16,
        }, source_uri=text)
    if low.startswith("qwdtt:config?"):
        text = "qwdtt://config?" + text.split("?", 1)[1]
        low = text.lower()
    if not low.startswith("qwdtt://"):
        return None
    try:
        parsed = urllib.parse.urlsplit(text)
        values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        def first(*names):
            for name in names:
                items = values.get(name, [])
                if items:
                    return items[0]
            return ""
        return _qwdtt_profile_from_mapping({
            "name": first("name", "label"),
            "peer": first("peer", "server"),
            "dtls_port": first("dtls_port", "server_port"),
            "hashes": first("hashes", "vkHashes", "vk_hash"),
            "workers": first("workers", "workersPerHash"),
            "local_port": first("local_port", "port", "listenPort"),
            "password": first("password", "pass"),
            "turn_host": first("turn_host"),
            "turn_port": first("turn_port"),
            "vk_anon_path": first("vk_anon_path"),
            "wait_ready_timeout_millis": first("wait_ready_timeout_millis"),
        }, source_uri=text)
    except:
        return None


def _parse_qwdtt_payload(value):
    text = str(value or "").strip()
    result = {"name": "", "description": "", "profiles": []}
    if not text:
        return result
    direct = _parse_qwdtt_uri(text)
    if direct:
        result["name"] = str(direct.get("name", "") or "")
        result["profiles"] = [direct]
        return result
    raw = text
    if not raw.startswith(("{", "[")):
        try:
            blob = raw.replace("-", "+").replace("_", "/")
            blob += "=" * ((4 - len(blob) % 4) % 4)
            decoded = base64.b64decode(blob.encode("ascii", errors="ignore"), validate=False).decode("utf-8", errors="ignore").strip()
            if decoded.startswith(("{", "[", "wdtt://", "qwdtt:")):
                return _parse_qwdtt_payload(decoded)
        except:
            pass
        return result
    try:
        data = json.loads(raw)
    except:
        return result
    entries = []
    if isinstance(data, dict):
        result["name"] = str(data.get("subscriptionName", data.get("groupName", data.get("name", ""))) or "").strip()
        result["description"] = str(data.get("description", data.get("info", "")) or "").strip()
        nested = data.get("profiles", data.get("servers", None))
        entries = nested if isinstance(nested, list) else [data]
    elif isinstance(data, list):
        entries = data
    for item in entries:
        profile = _qwdtt_profile_from_mapping(item)
        if profile and not any(str(old.get("id", "")) == str(profile.get("id", "")) for old in result["profiles"]):
            result["profiles"].append(profile)
    return result


def _qwdtt_core_config(profile, socks_port):
    if not isinstance(profile, dict):
        return ""
    payload = {
        "engine": QWDTT_KIND,
        "peer": str(profile.get("peer", "") or ""),
        "hashes": list(profile.get("hashes", []) or []),
        "password": str(profile.get("password", "") or ""),
        "workers": _qwdtt_int(profile.get("workers", 16), 16),
        "local_port": _qwdtt_int(profile.get("local_port", 9000), 9000),
        "device_id": _get_or_create_subscription_hwid(),
        "socks_listen_host": VLESS_LOCAL_HOST,
        "socks_port": int(socks_port or 0),
        "wait_ready_timeout_millis": 60000,
    }
    for key in ("turn_host", "turn_port", "vk_anon_path"):
        value = str(profile.get(key, "") or "").strip()
        if value:
            payload[key] = value
    payload["wait_ready_timeout_millis"] = max(15000, min(120000, _qwdtt_int(profile.get("wait_ready_timeout_millis", 60000), 60000)))
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _olcrtc_carrier_alias(value):
    try:
        v = str(value or "").strip().lower()
    except:
        v = ""
    if v in ("wb", "wildberries", "wbstream", "wb-stream"):
        return "wbstream"
    if v in ("ya", "yandex", "yamost", "telemost", "yandex_telemost"):
        return "telemost"
    if v in ("meet", "jitsi", "jitsi-meet", "jitsi_meet"):
        return "jitsi"
    if v in OLCRTC_CARRIER_ITEMS:
        return v
    return ""


def _olcrtc_transport_alias(value):
    try:
        v = str(value or "").strip().lower().replace("_", "-")
    except:
        v = ""
    if v in ("data", "dc", "data-channel"):
        return "datachannel"
    if v in ("vp8", "vp8-channel"):
        return "vp8channel"
    if v in ("sei", "sei-channel"):
        return "seichannel"
    if v in ("video", "video-channel"):
        return "videochannel"
    if v in OLCRTC_TRANSPORT_ITEMS:
        return v
    return ""


def _olcrtc_default_transport_for_carrier(carrier):
    return "datachannel" if _olcrtc_carrier_alias(carrier) == "jitsi" else "vp8channel"


def _olcrtc_supported_transports(carrier):
    carrier = _olcrtc_carrier_alias(carrier)
    if carrier == "jitsi":
        return ("datachannel",)
    if carrier == "telemost":
        return ("vp8channel", "seichannel")
    if carrier == "wbstream":
        return ("datachannel", "vp8channel", "seichannel")
    return ("vp8channel",)


def _olcrtc_qs_get(qs, *names):
    for name in names:
        try:
            values = qs.get(name)
        except:
            values = None
        if values:
            value = str(values[0] or "").strip()
            if value:
                return urllib.parse.unquote(value)
    return ""


def _olcrtc_qs_int(qs, *names):
    try:
        value = int(_olcrtc_qs_get(qs, *names) or 0)
        return value if value > 0 else 0
    except:
        return 0


def _olcrtc_parse_kv_blob(value):
    try:
        blob = str(value or "").strip().strip("<>").replace(";", "&")
    except:
        blob = ""
    if not blob or "=" not in blob:
        return {}
    try:
        return urllib.parse.parse_qs(blob, keep_blank_values=False)
    except:
        return {}


def _olcrtc_room_from_http_url(raw, parsed=None):
    try:
        p = parsed or urllib.parse.urlparse(str(raw or "").strip())
        host = str(p.netloc or "").strip().lower()
        path = urllib.parse.unquote(str(p.path or "")).strip("/")
        full = str(raw or "").strip()
    except:
        return "", ""
    if not host:
        return "", ""
    if host == "telemost.yandex.ru" or host.endswith(".telemost.yandex.ru"):
        room = ""
        try:
            qs = urllib.parse.parse_qs(str(p.query or ""))
            room = _olcrtc_qs_get(qs, "room_id", "room", "roomId", "meeting_id", "meetingId")
        except:
            room = ""
        if not room and path:
            room = path.rstrip("/").split("/")[-1]
        return "telemost", room
    if host == "stream.wb.ru" or host.endswith(".stream.wb.ru"):
        room = ""
        try:
            qs = urllib.parse.parse_qs(str(p.query or ""))
            room = _olcrtc_qs_get(qs, "room_id", "room", "roomId")
        except:
            room = ""
        if not room and path:
            room = path.rstrip("/").split("/")[-1]
        return "wbstream", room
    if host.startswith("meet.") or "jitsi" in host:
        return "jitsi", full
    return "", ""


def _olcrtc_profile_from_json(value, default_client_id=""):
    if not isinstance(value, dict):
        return None
    try:
        endpoint = value.get("endpoint")
        endpoint = endpoint if isinstance(endpoint, dict) else {}
        metadata = value.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        transport_data = value.get("transport")
        transport_data = transport_data if isinstance(transport_data, dict) else {}
        vp8 = transport_data.get("vp8")
        vp8 = vp8 if isinstance(vp8, dict) else {}

        carrier = _olcrtc_carrier_alias(
            value.get("auth_provider")
            or value.get("carrier")
            or value.get("bypass_provider")
            or value.get("bypassProvider")
            or value.get("provider")
        ) or "wbstream"
        transport = _olcrtc_transport_alias(
            transport_data.get("type") or value.get("transport")
        ) or _olcrtc_default_transport_for_carrier(carrier)
        room_id = str(
            endpoint.get("room_id")
            or value.get("room_id")
            or value.get("id")
            or value.get("server")
            or ""
        ).strip()
        client_id = str(
            endpoint.get("client_id")
            or value.get("client_id")
            or value.get("clientId")
            or value.get("device_id")
            or value.get("deviceId")
            or default_client_id
            or ""
        ).strip()
        key_hex = str(
            endpoint.get("key")
            or value.get("key_hex")
            or value.get("key")
            or value.get("password")
            or ""
        ).strip()
        if not room_id or not client_id or not key_hex:
            return None
        out = {
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
            "name": str(value.get("name") or metadata.get("name") or "").strip()[:64],
        }
        for target, raw in (("vp8_fps", vp8.get("fps") or value.get("vp8_fps") or value.get("vp8Fps")), ("vp8_batch_size", vp8.get("batch") or value.get("vp8_batch") or value.get("vp8Batch"))):
            try:
                parsed = int(raw or 0)
                if parsed > 0:
                    out[target] = parsed
            except:
                pass
        return out
    except:
        return None


def _extract_olcrtc_json_profiles(text, default_client_id=""):
    try:
        root = json.loads(str(text or "").strip())
    except:
        return []
    if isinstance(root, dict) and isinstance(root.get("olcrtc"), dict):
        root = root.get("olcrtc")
    if isinstance(root, dict):
        items = root.get("locations")
        items = items if isinstance(items, list) else [root]
    elif isinstance(root, list):
        items = root
    else:
        return []
    profiles = []
    for item in items:
        profile = _olcrtc_profile_from_json(item, default_client_id=default_client_id)
        if profile:
            profiles.append(profile)
    return profiles


def _parse_olcrtc_uri_to_data(raw, default_client_id=""):
    try:
        text = str(raw or "").strip()
    except:
        text = ""
    if not text:
        return None, "Буфер обмена пуст"

    try:
        parsed = urllib.parse.urlparse(text)
        scheme = str(parsed.scheme or "").lower()
        if scheme in ("http", "https"):
            carrier, room_id = _olcrtc_room_from_http_url(text, parsed)
            if carrier and room_id:
                return {
                    "carrier": carrier,
                    "transport": _olcrtc_default_transport_for_carrier(carrier),
                    "room_id": room_id,
                    "client_id": str(default_client_id or "").strip(),
                    "key_hex": "",
                }, ""
            return None, "В буфере нет olcRTC конфига"
        if scheme != OLCRTC_KIND:
            return None, "В буфере нет olcRTC конфига"

        qs = urllib.parse.parse_qs(parsed.query)
        carrier = _olcrtc_carrier_alias(_olcrtc_qs_get(qs, "carrier", "provider"))
        transport = _olcrtc_transport_alias(_olcrtc_qs_get(qs, "transport", "t"))
        room_id = _olcrtc_qs_get(qs, "room_id", "room")
        client_id = _olcrtc_qs_get(qs, "client_id", "device_id", "client", "id") or str(default_client_id or "").strip()
        key_hex = _olcrtc_qs_get(qs, "key_hex", "key")

        compact_query = urllib.parse.unquote(str(parsed.query or "")).strip()
        payload_qs = {}
        if "@" in compact_query:
            left, compact_room = compact_query.split("@", 1)
            payload = ""
            transport_part = left.strip()
            if "<" in transport_part and ">" in transport_part:
                transport_part, payload = transport_part.split("<", 1)
                payload = payload.rsplit(">", 1)[0]
                payload_qs = _olcrtc_parse_kv_blob(payload)
            compact_transport = _olcrtc_transport_alias(transport_part)
            if compact_transport:
                transport = transport or compact_transport
                room_id = room_id or compact_room.strip()
                client_id = client_id or _olcrtc_qs_get(payload_qs, "client_id", "device_id", "client", "id")
                key_hex = key_hex or _olcrtc_qs_get(payload_qs, "key_hex", "key")

        fragment = str(parsed.fragment or "").strip()
        compact_name = ""
        if fragment:
            key_part = fragment
            meta_part = ""
            if "$" in fragment:
                key_part, meta_part = fragment.split("$", 1)
                if meta_part and "=" not in meta_part:
                    compact_name = str(meta_part or "").strip()
            if "%" in key_part:
                key_part, compact_client_id = key_part.split("%", 1)
                client_id = client_id or urllib.parse.unquote(str(compact_client_id or "")).strip()
            key_hex = key_hex or urllib.parse.unquote(str(key_part or "")).strip()
            meta_part = urllib.parse.unquote(str(meta_part or ""))
            meta_qs = _olcrtc_parse_kv_blob(meta_part)
            client_id = client_id or _olcrtc_qs_get(meta_qs, "client_id", "device_id", "client", "id")

        netloc = urllib.parse.unquote(str(parsed.netloc or "")).strip()
        path = urllib.parse.unquote(str(parsed.path or ""))
        if path.startswith("/"):
            path = path[1:]
        path = path.strip()
        if not carrier and _olcrtc_carrier_alias(netloc):
            carrier = _olcrtc_carrier_alias(netloc)
            room_id = room_id or path
        elif not room_id:
            room_id = (netloc + ("/" + path if path else "")).strip()

        carrier = carrier or "wbstream"
        transport = transport or _olcrtc_default_transport_for_carrier(carrier)
        out = {
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
        }
        if compact_name:
            out["name"] = compact_name[:64]
        vp8_fps = _olcrtc_qs_int(payload_qs, "vp8-fps", "vp8_fps", "fps") or _olcrtc_qs_int(qs, "vp8-fps", "vp8_fps")
        vp8_batch = _olcrtc_qs_int(payload_qs, "vp8-batch", "vp8_batch", "vp8_batch_size", "batch") or _olcrtc_qs_int(qs, "vp8-batch", "vp8_batch", "vp8_batch_size")
        if vp8_fps > 0:
            out["vp8_fps"] = int(vp8_fps)
        if vp8_batch > 0:
            out["vp8_batch_size"] = int(vp8_batch)
        return out, ""
    except Exception as exc:
        return None, str(exc)


def _extract_olcrtc_subscription_profiles(text, default_client_id=""):
    profiles = []
    current = None
    try:
        lines = str(text or "").lstrip("\ufeff").splitlines()
    except:
        lines = []
    for raw_line in lines:
        try:
            line = str(raw_line or "").strip()
        except:
            line = ""
        if not line:
            continue
        if line.lower().startswith("olcrtc://"):
            data, err = _parse_olcrtc_uri_to_data(line, default_client_id=default_client_id)
            if data and not err:
                profiles.append(data)
                current = data
            continue
        if current is not None and line.startswith("##") and ":" in line:
            key, value = line[2:].split(":", 1)
            if key.strip().lower() == "name":
                current["name"] = value.strip()[:64]
    return profiles or _extract_olcrtc_json_profiles(text, default_client_id=default_client_id)


def _fetch_olcrtc_subscription_text(url, timeout_sec=15.0):
    accept = "text/plain, text/markdown, application/octet-stream, */*"
    for headers in (
        {"Accept": accept, "User-Agent": "olcbox/1.0.0", "x-hwid": _get_or_create_olcrtc_device_id()},
        {"Accept": accept, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"},
    ):
        text = _fetch_text_url(url, timeout_sec=timeout_sec, request_headers=headers)
        if _extract_olcrtc_subscription_profiles(text, default_client_id=_get_or_create_olcrtc_device_id()):
            return text
    return ""


def _extract_declared_plugin_version(text):
    try:
        match = re.search(r'(?m)^__version__\s*=\s*["\']([^"\']+)["\']', str(text or ""))
    except:
        match = None
    if not match:
        return ""
    try:
        return str(match.group(1) or "").strip()
    except:
        return ""


def _version_tuple(value):
    try:
        parts = re.findall(r"\d+", str(value or ""))
    except:
        parts = []
    if not parts:
        return (0,)
    return tuple(int(x) for x in parts[:8])


def _is_version_newer(remote_version, local_version):
    remote = list(_version_tuple(remote_version))
    local = list(_version_tuple(local_version))
    size = max(len(remote), len(local))
    remote.extend([0] * (size - len(remote)))
    local.extend([0] * (size - len(local)))
    return tuple(remote) > tuple(local)


def _set_vless_fetch_diag(url, **kwargs):
    global _LAST_VLESS_FETCH_DIAG
    try:
        key = str(url or "").strip()
    except:
        key = ""
    if not key:
        return
    try:
        payload = dict(kwargs or {})
    except:
        payload = {}
    payload["url"] = key
    _LAST_VLESS_FETCH_DIAG[key] = payload


def _get_vless_fetch_diag(url):
    global _LAST_VLESS_FETCH_DIAG
    try:
        key = str(url or "").strip()
    except:
        key = ""
    if not key:
        return {}
    try:
        value = _LAST_VLESS_FETCH_DIAG.get(key, {})
        return dict(value or {}) if isinstance(value, dict) else {}
    except:
        return {}


def _vless_json_name(obj, server="", sni=""):
    try:
        name = str(
            obj.get("name")
            or obj.get("remark")
            or obj.get("ps")
            or obj.get("tag")
            or ""
        ).strip()
    except:
        name = ""

    low = str(name or "").strip().lower()
    if not name or low in ("proxy", "vless", "node", "out", "outbound", "default"):
        try:
            sni_text = str(sni or "").strip()
        except:
            sni_text = ""
        if sni_text:
            return sni_text
        try:
            server_text = str(server or "").strip()
        except:
            server_text = ""
        if server_text:
            return server_text
        return "sing-box узел"
    return name


def _collect_vless_json_params(obj, user_obj=None):
    params = {}

    try:
        network = obj.get("network") or obj.get("type")
    except:
        network = ""
    try:
        security = obj.get("security")
    except:
        security = ""
    try:
        sni = obj.get("sni") or obj.get("serverName")
    except:
        sni = ""
    try:
        flow = obj.get("flow")
    except:
        flow = ""
    try:
        path = obj.get("path")
    except:
        path = ""
    try:
        host = obj.get("host")
    except:
        host = ""
    try:
        fp = obj.get("fp") or obj.get("fingerprint")
    except:
        fp = ""
    try:
        pbk = obj.get("pbk") or obj.get("publicKey")
    except:
        pbk = ""
    try:
        sid = obj.get("sid") or obj.get("shortId")
    except:
        sid = ""
    try:
        spx = obj.get("spx") or obj.get("spiderX")
    except:
        spx = ""
    try:
        packet_encoding = obj.get("packetEncoding")
    except:
        packet_encoding = ""

    if isinstance(user_obj, dict):
        try:
            flow = flow or user_obj.get("flow")
        except:
            pass

    try:
        tls = obj.get("tls")
    except:
        tls = None
    if isinstance(tls, dict):
        try:
            enabled = tls.get("enabled")
            if enabled is True or str(enabled).lower() == "true":
                security = security or "tls"
        except:
            pass
        try:
            sni = sni or tls.get("server_name") or tls.get("serverName") or tls.get("sni")
        except:
            pass
        try:
            fp = fp or tls.get("fingerprint")
        except:
            pass

    try:
        transport = obj.get("transport")
    except:
        transport = None
    if isinstance(transport, dict):
        try:
            network = network or transport.get("type") or transport.get("network")
        except:
            pass
        try:
            path = path or transport.get("path")
        except:
            pass
        try:
            headers2 = transport.get("headers") or {}
        except:
            headers2 = {}
        if isinstance(headers2, dict):
            try:
                host = host or headers2.get("Host") or headers2.get("host")
            except:
                pass

    try:
        stream = obj.get("streamSettings")
    except:
        stream = None
    if isinstance(stream, dict):
        try:
            network = stream.get("network") or network
        except:
            pass
        try:
            security = stream.get("security") or security
        except:
            pass
        try:
            packet_encoding = packet_encoding or stream.get("packetEncoding")
        except:
            pass

        try:
            reality = stream.get("realitySettings")
        except:
            reality = None
        if isinstance(reality, dict):
            try:
                sni = reality.get("serverName") or reality.get("server_name") or reality.get("sni") or sni
            except:
                pass
            try:
                fp = reality.get("fingerprint") or fp
            except:
                pass
            try:
                pbk = reality.get("publicKey") or reality.get("public_key") or pbk
            except:
                pass
            try:
                sid = reality.get("shortId") or reality.get("short_id") or sid
            except:
                pass
            try:
                spx = reality.get("spiderX") or reality.get("spider_x") or spx
            except:
                pass

        try:
            tls_settings = stream.get("tlsSettings")
        except:
            tls_settings = None
        if isinstance(tls_settings, dict):
            try:
                sni = tls_settings.get("serverName") or tls_settings.get("server_name") or sni
            except:
                pass
            try:
                fp = tls_settings.get("fingerprint") or fp
            except:
                pass

        try:
            ws_settings = stream.get("wsSettings")
        except:
            ws_settings = None
        if isinstance(ws_settings, dict):
            try:
                path = ws_settings.get("path") or path
            except:
                pass
            try:
                headers2 = ws_settings.get("headers") or {}
            except:
                headers2 = {}
            if isinstance(headers2, dict):
                try:
                    host = headers2.get("Host") or headers2.get("host") or host
                except:
                    pass

        try:
            grpc_settings = stream.get("grpcSettings")
        except:
            grpc_settings = None
        if isinstance(grpc_settings, dict):
            try:
                service_name = grpc_settings.get("serviceName") or grpc_settings.get("service_name")
            except:
                service_name = ""
            try:
                multi_mode = grpc_settings.get("multiMode")
            except:
                multi_mode = None
            if service_name:
                params["serviceName"] = str(service_name)
            if multi_mode is not None:
                params["mode"] = "multi" if bool(multi_mode) else "gun"

        try:
            xhttp_settings = stream.get("xhttpSettings")
        except:
            xhttp_settings = None
        if isinstance(xhttp_settings, dict):
            try:
                path = xhttp_settings.get("path") or path
            except:
                pass
            try:
                host = xhttp_settings.get("host") or host
            except:
                pass
            try:
                mode = xhttp_settings.get("mode")
            except:
                mode = ""
            if mode:
                params["mode"] = str(mode)
            try:
                extra = xhttp_settings.get("extra")
            except:
                extra = None
            if isinstance(extra, (dict, list)):
                try:
                    params["extra"] = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
                except:
                    pass

        try:
            httpupgrade_settings = stream.get("httpupgradeSettings")
        except:
            httpupgrade_settings = None
        if isinstance(httpupgrade_settings, dict):
            try:
                host = httpupgrade_settings.get("host") or host
            except:
                pass
            try:
                path = httpupgrade_settings.get("path") or path
            except:
                pass

    if network:
        params["type"] = str(network)
    if security:
        params["security"] = str(security)
    if sni:
        params["sni"] = str(sni)
    if flow:
        params["flow"] = str(flow)
    if path:
        params["path"] = str(path)
    if host:
        params["host"] = str(host)
    if fp:
        params["fp"] = str(fp)
    if pbk:
        params["pbk"] = str(pbk)
    if sid:
        params["sid"] = str(sid)
    if spx:
        params["spx"] = str(spx)
    if packet_encoding:
        params["packetEncoding"] = str(packet_encoding)
    return params


def _build_vless_uri_from_json_obj(obj, uuid_str, server, port, user_obj=None):
    try:
        server_text = str(server or "").strip()
    except:
        server_text = ""
    try:
        uuid_text = str(uuid_str or "").strip()
    except:
        uuid_text = ""
    try:
        port_num = int(port)
    except:
        port_num = 0
    if not uuid_text or not server_text or port_num <= 0:
        return ""

    params = _collect_vless_json_params(obj, user_obj=user_obj)
    sni = str(params.get("sni", "") or "")
    name = _vless_json_name(obj, server=server_text, sni=sni)

    query_parts = []
    for key in ("type", "security", "sni", "flow", "path", "host", "serviceName", "mode", "fp", "pbk", "sid", "spx", "packetEncoding", "extra"):
        try:
            value = params.get(key)
        except:
            value = None
        if value in (None, ""):
            continue
        safe = "/" if key == "path" else ""
        query_parts.append(
            "%s=%s" % (
                urllib.parse.quote(str(key), safe=""),
                urllib.parse.quote(str(value), safe=safe),
            )
        )

    query = ("?" + "&".join(query_parts)) if query_parts else ""
    return "vless://%s@%s:%s%s#%s" % (
        urllib.parse.quote(uuid_text, safe=""),
        server_text,
        str(port_num),
        query,
        urllib.parse.quote(str(name or "sing-box узел"), safe=""),
    )


def _xray_hysteria2_link(outbound, profile_name=""):
    if not isinstance(outbound, dict):
        return ""
    protocol = str(outbound.get("protocol", "") or "").strip().lower()
    if protocol not in ("hysteria", "hysteria2"):
        return ""
    settings = outbound.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    stream = outbound.get("streamSettings")
    stream = stream if isinstance(stream, dict) else {}
    hysteria = stream.get("hysteriaSettings")
    hysteria = hysteria if isinstance(hysteria, dict) else {}
    try:
        version = int(settings.get("version") or hysteria.get("version") or (2 if protocol == "hysteria2" else 0))
        port = int(settings.get("port") or settings.get("server_port") or 0)
    except:
        return ""
    server = str(settings.get("address") or settings.get("server") or "").strip()
    auth = str(hysteria.get("auth") or settings.get("password") or "")
    if version != 2 or not server or port <= 0 or not auth:
        return ""

    tls = stream.get("tlsSettings")
    tls = tls if isinstance(tls, dict) else {}
    params = {}
    if tls.get("serverName"):
        params["sni"] = str(tls.get("serverName"))
    if tls.get("fingerprint"):
        params["fp"] = str(tls.get("fingerprint"))
    alpn = tls.get("alpn")
    if isinstance(alpn, list):
        alpn = ",".join(str(value or "").strip() for value in alpn if str(value or "").strip())
    if alpn:
        params["alpn"] = str(alpn)
    if bool(tls.get("allowInsecure", False)):
        params["insecure"] = "1"

    finalmask = stream.get("finalmask")
    finalmask = finalmask if isinstance(finalmask, dict) else {}
    mask = next((item for item in list(finalmask.get("udp", []) or []) if isinstance(item, dict)), None)
    if mask:
        mask_settings = mask.get("settings")
        mask_settings = mask_settings if isinstance(mask_settings, dict) else {}
        if mask.get("type"):
            params["obfs"] = str(mask.get("type"))
        if mask_settings.get("password"):
            params["obfs-password"] = str(mask_settings.get("password"))

    host = "[" + server + "]" if ":" in server and not server.startswith("[") else server
    name = str(profile_name or outbound.get("tag") or _proxy_address_name(server, port) or "Hysteria2 узел").strip()
    query = urllib.parse.urlencode(params)
    return "hy2://%s@%s:%d%s#%s" % (
        urllib.parse.quote(auth, safe=""),
        host,
        port,
        ("?" + query) if query else "",
        urllib.parse.quote(name, safe=""),
    )


def _xray_vless_links(outbound, profile_name=""):
    if not isinstance(outbound, dict):
        return []
    protocol = str(outbound.get("protocol", "") or "").lower()
    if protocol in ("hysteria", "hysteria2"):
        link = _xray_hysteria2_link(outbound, profile_name=profile_name)
        return [link] if link else []
    if protocol != "vless":
        return []
    settings = outbound.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    prefix = str(profile_name or "").strip()
    tag = str(outbound.get("tag", "") or "").strip()
    links = []

    def _build(uuid_str, server, port, user=None):
        named = dict(outbound)
        child_name = "" if _is_generic_proxy_name(tag) else tag
        named["name"] = (prefix + (" " + child_name if child_name else "")).strip() if prefix else (child_name or _proxy_address_name(server, port))
        link = _build_vless_uri_from_json_obj(named, uuid_str, server, port, user_obj=user)
        if link:
            links.append(link)

    vnext = settings.get("vnext")
    if isinstance(vnext, list):
        for target in vnext:
            if not isinstance(target, dict):
                continue
            users = target.get("users")
            users = users if isinstance(users, list) else []
            for user in users:
                if isinstance(user, dict):
                    _build(user.get("id") or user.get("uuid"), target.get("address") or target.get("server"), target.get("port"), user)
        return links

    users = settings.get("users")
    users = users if isinstance(users, list) else []
    user = users[0] if users and isinstance(users[0], dict) else None
    _build(
        settings.get("uuid") or settings.get("id") or settings.get("user") or ((user or {}).get("id") if user else ""),
        settings.get("address") or settings.get("server"),
        settings.get("port") or settings.get("server_port"),
        user,
    )
    return links


_SB_SUBSCRIPTION_OUTBOUND_TYPES = (
    "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "anytls", "naive",
)


def _singbox_json_nodes(config):
    """Nodes from a sing-box style config ({"outbounds": [{"type": "vless", ...}]}).

    Each supported leaf outbound becomes a "singbox-config" node holding a
    one-outbound config, the same node type that .singconf imports use.
    """
    if not isinstance(config, dict):
        return []
    raw_items = config.get("outbounds")
    if isinstance(raw_items, list):
        items = raw_items
    elif str(config.get("type", "") or "").strip().lower() in _SB_SUBSCRIPTION_OUTBOUND_TYPES and not config.get("protocol"):
        items = [config]
    else:
        return []
    profile_name = str(config.get("remarks") or config.get("remark") or config.get("name") or "").strip()
    nodes = []
    for ob in items:
        if not isinstance(ob, dict) or ob.get("protocol"):
            continue
        kind = str(ob.get("type", "") or "").strip().lower()
        if kind not in _SB_SUBSCRIPTION_OUTBOUND_TYPES:
            continue
        server = str(ob.get("server", "") or "").strip()
        try:
            port = int(ob.get("server_port", 0) or 0)
        except:
            port = 0
        if not port and ob.get("server_ports"):
            port = 1
        if not server or port <= 0 or ob.get("detour"):
            continue
        tag = str(ob.get("tag", "") or "").strip()
        child = "" if (not tag or _is_generic_proxy_name(tag)) else tag
        label = (profile_name + " " + child).strip() if (profile_name and child) else (child or profile_name or _proxy_address_name(server, port))
        try:
            single = dict(ob)
            single["tag"] = "proxy"
            node = _singbox_node_from_config_text(json.dumps({"outbounds": [single]}, ensure_ascii=False), name=label)
        except Exception:
            continue
        node["kind"] = "singbox-config"
        nodes.append(node)
    return nodes


def _xray_config_vless_nodes(config):
    if not isinstance(config, dict):
        return []
    sb_nodes = _singbox_json_nodes(config)
    if sb_nodes:
        return sb_nodes
    profile_name = str(config.get("remarks") or config.get("remark") or config.get("name") or "").strip()
    if str(config.get("protocol", "") or ""):
        outbounds = [config]
    else:
        outbounds = [item for item in list(config.get("outbounds", []) or []) if isinstance(item, dict)]

    routing = config.get("routing")
    routing = routing if isinstance(routing, dict) else {}
    balancers = [item for item in list(routing.get("balancers", []) or []) if isinstance(item, dict)]

    def _nodes_for(items):
        nodes = []
        for outbound in items:
            for link in _xray_vless_links(outbound, profile_name=profile_name):
                node = _proxy_node_from_uri(link)
                if node:
                    nodes.append(node)
        return nodes

    groups = []
    for balancer in balancers:
        balancer_tag = str(balancer.get("tag", "") or "").strip()
        selectors = [str(value or "") for value in list(balancer.get("selector", []) or []) if str(value or "")]
        selected = [
            outbound for outbound in outbounds
            if any(str(outbound.get("tag", "") or "").startswith(selector) for selector in selectors)
        ]
        children = _nodes_for(selected)
        if not children:
            continue
        group_name = profile_name or "VLESS Auto"
        if len(balancers) > 1 and balancer_tag:
            group_name += " • " + balancer_tag
        identity = group_name + "|" + balancer_tag + "|" + ",".join(selectors)
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        first = children[0]
        groups.append({
            "id": "greenpass-balancer://" + digest,
            "uri": "greenpass-balancer://" + digest,
            "kind": "vless",
            "name": group_name,
            "server": str(first.get("server", "") or ""),
            "port": int(first.get("port", 0) or 0),
            "network": "auto",
            "security": str(first.get("security", "") or ""),
            "balance_nodes": children,
        })
    return groups or _nodes_for(outbounds)


def _fetch_vless_nodes(url, text=None):
    if text is None:
        text = _fetch_text_url(url, timeout_sec=15.0)
    if not text:
        _set_vless_fetch_diag(url, stage="empty_text", text_len=0, vless_count=0, ss_count=0, proxy_count=0, link_count=0, node_count=0)
        return []

    body = str(text or "").strip()
    original_body = body
    low_body = body.lower()
    vless_count = int(low_body.count("vless://")) if low_body else 0
    ss_count = int(low_body.count("ss://")) if low_body else 0
    proxy_scheme_count = sum(int(low_body.count(scheme + "://")) for scheme in PROXY_URI_SCHEMES) if low_body else 0
    hitvpn_count = (
        int(low_body.count(HITVPN_LINK_PREFIX))
        + int(low_body.count(HITRAY_LINK_PREFIX))
        + int(low_body.count("hitvpn://"))
    ) if low_body else 0
    raw_starts_json = bool(str(original_body or "").lstrip().startswith("{") or str(original_body or "").lstrip().startswith("["))
    if (not _contains_import_uri_text(low_body)) and (not raw_starts_json):
        try:
            b64 = body.replace("\n", "").replace("\r", "").replace("-", "+").replace("_", "/")
            b64 = "".join(ch for ch in b64 if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            missing = len(b64) % 4
            if missing:
                b64 += "=" * (4 - missing)
            decoded = base64.b64decode(b64.encode("ascii", errors="ignore"), validate=False)
            body = decoded.decode("utf-8", errors="ignore")
            low_body = body.lower()
            vless_count = int(low_body.count("vless://")) if low_body else 0
            ss_count = int(low_body.count("ss://")) if low_body else 0
            proxy_scheme_count = sum(int(low_body.count(scheme + "://")) for scheme in PROXY_URI_SCHEMES) if low_body else 0
            hitvpn_count = (
                int(low_body.count(HITVPN_LINK_PREFIX))
                + int(low_body.count(HITRAY_LINK_PREFIX))
                + int(low_body.count("hitvpn://"))
            ) if low_body else hitvpn_count
        except:
            pass

    links = []
    prebuilt_nodes = []
    if ("\n" in body or "\r" in body) and (proxy_scheme_count > 0 or hitvpn_count > 0):
        try:
            for line in str(body or "").splitlines():
                line = str(line or "").strip()
                if not line:
                    continue
                low = line.lower()
                if (
                    _is_proxy_uri(low)
                    or low.startswith(HITVPN_LINK_PREFIX)
                    or low.startswith(HITRAY_LINK_PREFIX)
                    or low.startswith(HITVPN_SCHEME_PREFIX)
                ):
                    links.append(line.rstrip(".,!?;:)]}>"))
        except:
            links = []
    try:
        if not links:
            scheme_alt = "|".join(re.escape(item) for item in sorted(PROXY_URI_SCHEMES, key=len, reverse=True))
            links = re.findall(
                r"(?:" + scheme_alt + r")://[^\s\"'<>]+|https://(?:hvpn|hitray)\.io/[^\s\"'<>]+|hitvpn://[^\s\"'<>]+",
                str(body or ""),
                re.IGNORECASE,
            )
    except:
        links = []

    if not links:
        try:
            raw = str(body or "").lstrip()
            if raw.startswith("{") or raw.startswith("["):
                parsed = json.loads(raw)
            else:
                parsed = None
        except:
            parsed = None

        if parsed is None:
            try:
                raw = str(original_body or "").lstrip()
                if raw.startswith("{") or raw.startswith("["):
                    parsed = json.loads(raw)
                    body = original_body
                    low_body = body.lower()
                    vless_count = int(low_body.count("vless://")) if low_body else vless_count
                    ss_count = int(low_body.count("ss://")) if low_body else ss_count
                    proxy_scheme_count = sum(int(low_body.count(scheme + "://")) for scheme in PROXY_URI_SCHEMES) if low_body else proxy_scheme_count
                    hitvpn_count = (
                        int(low_body.count(HITVPN_LINK_PREFIX))
                        + int(low_body.count(HITRAY_LINK_PREFIX))
                        + int(low_body.count("hitvpn://"))
                    ) if low_body else hitvpn_count
            except:
                parsed = parsed

        if parsed is not None:
            configs = parsed if isinstance(parsed, list) else [parsed]
            for config in configs:
                prebuilt_nodes.extend(_xray_config_vless_nodes(config))

    if not links:
        try:
            for line in str(body or "").splitlines():
                line = str(line or "").strip()
                low = line.lower()
                if (
                    _is_proxy_uri(low)
                    or low.startswith(HITVPN_LINK_PREFIX)
                    or low.startswith(HITRAY_LINK_PREFIX)
                    or low.startswith(HITVPN_SCHEME_PREFIX)
                ):
                    links.append(line)
        except:
            pass

    expanded_links = []
    for link in list(links or []):
        try:
            low = str(link or "").strip().lower()
        except:
            low = ""
        if low.startswith(HITVPN_LINK_PREFIX) or low.startswith(HITRAY_LINK_PREFIX) or low.startswith(HITVPN_SCHEME_PREFIX):
            try:
                expanded_links.extend(_decode_hitvpn_link_to_vless_uris(link))
            except:
                pass
        else:
            expanded_links.append(link)

    nodes = []
    seen = set()
    for node in prebuilt_nodes:
        key = _proxy_uri_dedup_key(node.get("uri", "")) or str(node.get("uri", "") or "")
        if key and key not in seen:
            seen.add(key)
            nodes.append(node)
    for link in list(expanded_links or []):
        try:
            low = str(link or "").strip().lower()
        except:
            low = ""
        if not _is_proxy_uri(low):
            continue
        try:
            decoded = urllib.parse.unquote(str(link or ""))
            decoded_low = decoded.lower()
        except:
            decoded_low = low
        if "@0.0.0.0:1" in low:
            continue
        if "приложение" in decoded_low and "не поддерж" in decoded_low:
            continue
        node = _proxy_node_from_uri(link)
        if not node:
            continue
        key = _proxy_uri_dedup_key(node.get("uri", "")) or str(node.get("uri", "") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        nodes.append(node)
    name_counts = {}
    for node in nodes:
        base_name = _clean_proxy_name(node.get("name", "Узел"))
        count = int(name_counts.get(base_name, 0)) + 1
        name_counts[base_name] = count
        if count > 1:
            node["name"] = "%s (%d)" % (base_name, count)
    _set_vless_fetch_diag(
        url,
        stage="done",
        text_len=len(body),
        vless_count=vless_count,
        ss_count=ss_count,
        proxy_count=proxy_scheme_count,
        link_count=len(expanded_links or links),
        node_count=len(nodes),
    )
    return nodes

__all__ = [name for name in globals() if not name.startswith("__")]
