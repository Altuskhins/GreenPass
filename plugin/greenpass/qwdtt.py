"""qWDTT (WireGuard over VK TURN) profiles: links, JSON payloads, nodes, core config."""

import base64
import hashlib
import json
import urllib.parse

from . import subscriptions

KIND = "qwdtt"
PREFIXES = ("wdtt://", "qwdtt://", "qwdtt:config?")


def is_qwdtt_link(value):
    return str(value or "").strip().lower().startswith(PREFIXES)


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def profile_from_mapping(value, source_uri=""):
    """Clean profile dict from loose input, or None when peer/hashes/password are missing."""
    if not isinstance(value, dict):
        return None
    port_value = value.get("dtls_port", value.get("server_port", ""))
    peer = str(value.get("peer", "") or "").strip()
    if not peer:
        host = str(value.get("server", value.get("dtls_host", "")) or "").strip()
        if host:
            peer = "%s:%d" % (host, _int(value.get("dtls_port", value.get("server_port", 56000)), 56000))
    elif port_value not in (None, ""):
        port = _int(port_value, 56000)
        if (peer.startswith("[") and "]:" not in peer) or (not peer.startswith("[") and ":" not in peer):
            peer = "%s:%d" % (peer, port)
    raw_hashes = value.get("hashes", value.get("vkHashes", value.get("vk_hashes", value.get("vk_hash", ""))))
    if isinstance(raw_hashes, (list, tuple)):
        hashes = [str(h).strip() for h in raw_hashes if str(h or "").strip()]
    else:
        hashes = [h.strip() for h in str(raw_hashes or "").replace("\n", ",").split(",") if h.strip()]
    password = str(value.get("password", value.get("pass", "")) or "").strip()
    if not peer or not hashes or not password:
        return None
    workers = max(9, min(108, _int(value.get("workers", value.get("workersPerHash", 16)), 16)))
    local_port = _int(value.get("local_port", value.get("port", value.get("listenPort", 9000))), 9000)
    if not 0 <= local_port <= 65535:
        local_port = 9000
    extra = {key: str(value.get(key, "") or "").strip() for key in ("turn_host", "turn_port", "vk_anon_path")}
    canonical = json.dumps(dict(peer=peer, hashes=hashes, password=password, workers=workers,
                                local_port=local_port, **extra),
                           ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    name = str(value.get("name", value.get("label", "")) or "").strip() or peer.split(":", 1)[0] or "qWDTT"
    profile = {
        "id": hashlib.sha256(canonical.encode("utf-8", errors="ignore")).hexdigest()[:24],
        "name": name[:80], "peer": peer, "hashes": hashes, "password": password,
        "workers": workers, "local_port": local_port,
    }
    profile.update(extra)
    profile["wait_ready_timeout_millis"] = max(15000, min(120000, _int(value.get("wait_ready_timeout_millis", 60000), 60000)))
    profile["source_uri"] = str(source_uri or "").strip()
    return profile


def parse_link(value):
    text = str(value or "").strip().rstrip(".,!?)]}>")
    low = text.lower()
    if low.startswith("wdtt://"):
        parts = text[7:].split(":")
        if len(parts) < 6:
            return None
        return profile_from_mapping({"name": parts[0], "peer": "%s:%s" % (parts[0], parts[1]), "wg_port": parts[2],
                                     "local_port": parts[3], "password": parts[4], "hashes": ":".join(parts[5:]),
                                     "workers": 16}, source_uri=text)
    if low.startswith("qwdtt:config?"):
        text = "qwdtt://config?" + text.split("?", 1)[1]
    elif not low.startswith("qwdtt://"):
        return None
    try:
        values = urllib.parse.parse_qs(urllib.parse.urlsplit(text).query, keep_blank_values=True)
    except ValueError:
        return None

    def first(*names):
        for name in names:
            if values.get(name):
                return values[name][0]
        return ""

    return profile_from_mapping({
        "name": first("name", "label"), "peer": first("peer", "server"),
        "dtls_port": first("dtls_port", "server_port"), "hashes": first("hashes", "vkHashes", "vk_hash"),
        "workers": first("workers", "workersPerHash"), "local_port": first("local_port", "port", "listenPort"),
        "password": first("password", "pass"), "turn_host": first("turn_host"), "turn_port": first("turn_port"),
        "vk_anon_path": first("vk_anon_path"), "wait_ready_timeout_millis": first("wait_ready_timeout_millis"),
    }, source_uri=text)


def parse_payload(value):
    """{"name", "description", "profiles"} from a link, JSON, or base64 of either."""
    text = str(value or "").strip()
    result = {"name": "", "description": "", "profiles": []}
    if not text:
        return result
    direct = parse_link(text)
    if direct:
        return {"name": direct["name"], "description": "", "profiles": [direct]}
    if not text.startswith(("{", "[")):
        try:
            blob = text.replace("-", "+").replace("_", "/")
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", errors="ignore").strip()
        except (ValueError, TypeError):
            return result
        return parse_payload(decoded) if decoded.startswith(("{", "[", "wdtt://", "qwdtt:")) else result
    try:
        data = json.loads(text)
    except ValueError:
        return result
    entries = []
    if isinstance(data, dict):
        result["name"] = str(data.get("subscriptionName", data.get("groupName", data.get("name", ""))) or "").strip()
        result["description"] = str(data.get("description", data.get("info", "")) or "").strip()
        nested = data.get("profiles", data.get("servers"))
        entries = nested if isinstance(nested, list) else [data]
    elif isinstance(data, list):
        entries = data
    for item in entries:
        profile = profile_from_mapping(item)
        if profile and all(p["id"] != profile["id"] for p in result["profiles"]):
            result["profiles"].append(profile)
    return result


def node_from_profile(profile):
    clean = profile_from_mapping(profile, source_uri=(profile or {}).get("source_uri", "") if isinstance(profile, dict) else "")
    if not clean:
        return None
    uri = "qwdtt://" + clean["id"]
    return {"id": uri, "uri": uri, "kind": KIND, "name": clean.get("name") or "qWDTT", "server": clean["peer"],
            "port": int(clean.get("local_port", 9000) or 9000), "network": "turn", "security": "wireguard",
            "qwdtt": clean}


def migrate_legacy(data):
    """Nodes for the profiles kept under the old config's "qwdtt_data"."""
    if not isinstance(data, dict):
        return []
    profiles = list(data.get("profiles", []) or [])
    for sub in list(data.get("subs", []) or []):
        if isinstance(sub, dict):
            profiles.extend(list(sub.get("profiles", []) or []))
    nodes, seen = [], set()
    for profile in profiles:
        node = node_from_profile(profile)
        if node and node["uri"] not in seen:
            seen.add(node["uri"])
            nodes.append(node)
    return nodes[:64]


def core_config(profile, socks_port, local_host="127.0.0.1"):
    if not isinstance(profile, dict):
        return None
    config = {
        "engine": KIND, "peer": str(profile.get("peer", "") or ""), "hashes": list(profile.get("hashes", []) or []),
        "password": str(profile.get("password", "") or ""), "workers": _int(profile.get("workers", 16), 16),
        "local_port": _int(profile.get("local_port", 9000), 9000), "device_id": subscriptions.hwid(),
        "socks_listen_host": local_host, "socks_port": int(socks_port or 0),
    }
    for key in ("turn_host", "turn_port", "vk_anon_path"):
        if str(profile.get(key, "") or "").strip():
            config[key] = str(profile[key]).strip()
    config["wait_ready_timeout_millis"] = max(15000, min(120000, _int(profile.get("wait_ready_timeout_millis", 60000), 60000)))
    return config
