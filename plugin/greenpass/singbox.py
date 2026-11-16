"""Build the JSON configs the core starts: sing-box for links, AWG and config files,
and the mihomo wrapper."""

import hashlib
import json

from . import links

LOCAL_HOST = "127.0.0.1"
BALANCER_MAX_NODES = 32
MIHOMO_CONFIG_MAX_BYTES = 1024 * 1024
URLTEST_URL = "https://cp.cloudflare.com/generate_204"


def _flag(value):
    return str(value or "0").lower() in ("1", "true", "yes")


def _csv(value):
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def base_config(local_port, username="", password=""):
    """Mixed (SOCKS/HTTP) inbound on 127.0.0.1, DNS with fallbacks, everything to "proxy"."""
    inbound = {"type": "mixed", "tag": "mixed-in", "listen": LOCAL_HOST, "listen_port": int(local_port or 0)}
    if str(username or "").strip() and str(password or "").strip():
        inbound["users"] = [{"username": str(username).strip(), "password": str(password).strip()}]
    return {
        "log": {"disabled": False, "level": "info"},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "dns-cloudflare", "server": "1.1.1.1"},
                {"type": "udp", "tag": "dns-google", "server": "8.8.8.8"},
                {"type": "udp", "tag": "dns-yandex-1", "server": "77.88.8.8"},
                {"type": "udp", "tag": "dns-yandex-2", "server": "77.88.8.1"},
                {"type": "fallback", "tag": "greenpass-dns",
                 "servers": ["dns-cloudflare", "dns-google", "dns-yandex-1", "dns-yandex-2"],
                 "strategy": "parallel"},
            ],
            "final": "greenpass-dns",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"action": "sniff"}], "final": "proxy", "default_domain_resolver": "greenpass-dns"},
    }


# --- TLS and transports for v2ray-style links (vless, vmess, trojan) ---

def _tls(params, server):
    security = str(params.get("security", "none") or "none").lower()
    if security == "none":
        return None
    fingerprint = str(params.get("fp", "") or "chrome")
    tls = {"enabled": True, "server_name": str(params.get("sni", "") or server or ""),
           "insecure": _flag(params.get("insecure"))}
    alpn = _csv(params.get("alpn"))
    if alpn:
        tls["alpn"] = alpn
    tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        tls["reality"] = {"enabled": True, "public_key": str(params.get("pbk", "") or ""),
                          "short_id": str(params.get("sid", "") or "")}
    return tls


def _host_header(params):
    return str(params.get("host", params.get("sni", "")) or "")


def _xhttp(params):
    extra = {}
    raw = params.get("extra", "")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            extra = parsed.get("xhttpSettings", parsed) if isinstance(parsed, dict) else {}
            extra = extra if isinstance(extra, dict) else {}
        except ValueError:
            extra = {}
    host = params.get("host", extra.get("host", params.get("sni", "")))
    if isinstance(host, (list, tuple)):
        host = host[0] if host else ""
    transport = {
        "type": "xhttp",
        "mode": str(params.get("mode", extra.get("mode", "auto")) or "auto"),
        "path": str(params.get("path", extra.get("path", "/")) or "/"),
        "x_padding_bytes": params.get("xPaddingBytes", extra.get("xPaddingBytes", extra.get("x_padding_bytes", "100-1000"))),
    }
    if host:
        transport["host"] = str(host)
    headers = extra.get("headers")
    if isinstance(headers, dict):
        transport["headers"] = {str(k): str(v) for k, v in headers.items() if str(k).lower() != "host"}
    return transport


def _mkcp(params):
    transport = {"type": "mkcp"}
    fields = {"mtu": ("mtu",), "tti": ("tti",),
              "uplink_capacity": ("uplinkCapacity", "uplink_capacity"),
              "downlink_capacity": ("downlinkCapacity", "downlink_capacity"),
              "read_buffer_size": ("readBufferSize", "read_buffer_size"),
              "write_buffer_size": ("writeBufferSize", "write_buffer_size")}
    for target, sources in fields.items():
        value = next((str(params.get(k, "") or "").strip() for k in sources if str(params.get(k, "") or "").strip()), "")
        if value.isdigit():
            transport[target] = int(value)
    header = str(params.get("headerType", params.get("header_type", "")) or "").strip()
    seed = str(params.get("seed", params.get("kcpseed", "")) or "").strip()
    if header:
        transport["header_type"] = header
    if seed:
        transport["seed"] = seed
    if _flag(params.get("congestion")):
        transport["congestion"] = True
    return transport


def _transport(params):
    network = str(params.get("type", "tcp") or "tcp").lower()
    if network in ("tcp", "udp", ""):
        return None
    if network == "ws":
        transport = {"type": "ws", "path": str(params.get("path", "/") or "/")}
        if _host_header(params):
            transport["headers"] = {"Host": _host_header(params)}
        return transport
    if network == "grpc":
        return {"type": "grpc", "service_name": str(params.get("serviceName", "") or "")}
    if network in ("xhttp", "splithttp"):
        return _xhttp(params)
    if network in ("kcp", "mkcp"):
        return _mkcp(params)
    if network in ("h2", "http"):
        transport = {"type": "http", "path": str(params.get("path", "/") or "/")}
        if _host_header(params):
            transport["host"] = [_host_header(params)]
        if str(params.get("method", "") or "").strip():
            transport["method"] = str(params["method"]).strip()
        if isinstance(params.get("headers"), dict) and params["headers"]:
            transport["headers"] = {str(k): str(v) for k, v in params["headers"].items()}
        return transport
    if network == "httpupgrade":
        return {"type": "httpupgrade", "host": _host_header(params), "path": str(params.get("path", "/") or "/")}
    if network == "quic":
        return {"type": "quic"}
    return None


def _add_tls_and_transport(outbound, params, server):
    transport = _transport(params)
    tls = _tls(params, server)
    if transport and transport["type"] == "quic" and not tls:
        # QUIC always runs over TLS.
        tls = {"enabled": True, "server_name": str(params.get("sni", "") or server or ""),
               "insecure": _flag(params.get("insecure"))}
    if tls:
        outbound["tls"] = tls
    if transport:
        outbound["transport"] = transport


def _plain_tls(params, server, alpn=False, fingerprint=False):
    tls = {"enabled": True, "server_name": str(params.get("sni", server) or ""), "insecure": _flag(params.get("insecure"))}
    if alpn and _csv(params.get("alpn")):
        tls["alpn"] = _csv(params.get("alpn"))
    if fingerprint and str(params.get("fp", "") or ""):
        tls["utls"] = {"enabled": True, "fingerprint": str(params["fp"])}
    return tls


def _mbps(outbound, params):
    for key, target in (("up", "up_mbps"), ("down", "down_mbps")):
        value = str(params.get(key, "") or "").strip()
        if value.isdigit():
            outbound[target] = int(value)


# --- outbound per protocol ---

def outbound(details, tag="proxy"):
    """sing-box outbound for parsed link details (see links.parse)."""
    kind = details["kind"]
    params = dict(details.get("params") or {})
    server = str(details.get("server", "") or "")
    out = {"type": kind, "tag": tag, "server": server, "server_port": int(details.get("port", 0) or 0)}

    if kind == "vless":
        out.update(uuid=details["uuid"], flow=str(params.get("flow", "") or ""))
        if str(params.get("packetEncoding", "") or "").strip():
            out["packet_encoding"] = str(params["packetEncoding"]).strip()
        _add_tls_and_transport(out, params, server)
    elif kind == "vmess":
        out.update(uuid=details["uuid"], security=details.get("cipher") or "auto",
                   alter_id=int(details.get("alter_id", 0) or 0))
        _add_tls_and_transport(out, params, server)
    elif kind == "trojan":
        out["password"] = details["password"]
        _add_tls_and_transport(out, params, server)
    elif kind == "ss":
        out.update(type="shadowsocks", method=details["method"], password=details["password"])
    elif kind == "hysteria2":
        out.update(password=details["password"], tls=_plain_tls(params, server, alpn=True, fingerprint=True))
        if str(params.get("obfs", "") or "").strip():
            out["obfs"] = {"type": str(params["obfs"]).strip()}
            obfs_password = str(params.get("obfs-password", params.get("obfs_password", "")) or "")
            if obfs_password:
                out["obfs"]["password"] = obfs_password
        _mbps(out, params)
    elif kind == "tuic":
        out.update(uuid=details["uuid"], password=details.get("password", ""),
                   tls=_plain_tls(params, server, alpn=True))
        congestion = str(params.get("congestion_control", params.get("cc", "")) or "").strip()
        if congestion:
            out["congestion_control"] = congestion
        if str(params.get("udp_relay_mode", "") or "").strip():
            out["udp_relay_mode"] = str(params["udp_relay_mode"]).strip()
    elif kind == "anytls":
        out.update(password=details["password"], tls=_plain_tls(params, server, alpn=True, fingerprint=True))
    elif kind == "ssh":
        out.update(user=details["user"], password=details.get("password", ""))
        key = str(params.get("private_key", params.get("privateKey", "")) or "").strip()
        if key:
            out["private_key"] = [key]
    elif kind == "shadowtls":
        out.update(password=details["password"], version=int(details.get("version", 3) or 3),
                   tls=_plain_tls(params, server))
    elif kind == "hysteria":
        out.update(auth_str=details["auth"], tls=_plain_tls(params, server, alpn=True))
        _mbps(out, params)
    elif kind == "naive":
        out.update(username=details["user"], password=details.get("password", ""), tls=_plain_tls(params, server))
        if _flag(params.get("quic")):
            out["quic"] = True
    elif kind == "mieru":
        out.update(transport=str(params.get("transport", "TCP") or "TCP").upper(),
                   username=details["user"], password=details["password"])
        if _csv(params.get("server_ports")):
            out["server_ports"] = _csv(params.get("server_ports"))
        for key in ("multiplexing", "traffic_pattern"):
            if str(params.get(key, "") or "").strip():
                out[key] = str(params[key]).strip()
    elif kind == "sudoku":
        out.update(key=details["key"], aead_method=details.get("aead_method") or "none",
                   padding_min=int(details.get("padding_min", 5) or 5),
                   padding_max=int(details.get("padding_max", 15) or 15),
                   table_type=details.get("table_type") or "prefer_entropy",
                   enable_pure_downlink=bool(details.get("enable_pure_downlink", True)))
        if details.get("custom_table"):
            out["custom_table"] = details["custom_table"]
        if details.get("custom_tables"):
            out["custom_tables"] = list(details["custom_tables"])
        mask = {k: details.get("http_mask_" + k) for k in ("mode", "host", "multiplex", "path")}
        if details.get("http_mask_disabled") or details.get("http_mask_tls") or any(mask.values()):
            http_mask = {"enabled": not details.get("http_mask_disabled")}
            for key, target in (("mode", "mode"), ("host", "host"), ("multiplex", "multiplex"), ("path", "path_root")):
                if mask[key]:
                    http_mask[target] = mask[key]
            if details.get("http_mask_tls"):
                http_mask["tls"] = {"enabled": True, "server_name": mask["host"] or server}
            out["http_mask"] = http_mask
    else:
        return None
    return out


def link_config(link, local_port, username="", password=""):
    """Config for one proxy link, or None when the link does not parse."""
    details = links.parse(link)
    proxy = outbound(details) if details else None
    if not proxy:
        return None
    config = base_config(local_port, username, password)
    config["outbounds"] = [proxy]
    return config


def balanced_config(nodes, local_port, username="", password=""):
    """Several nodes behind a urltest selector that picks the fastest working one."""
    outbounds = []
    for node in list(nodes or [])[:BALANCER_MAX_NODES]:
        link = node.get("uri", "") if isinstance(node, dict) else node
        details = links.parse(link)
        proxy = outbound(details, tag="sb-route-%d" % (len(outbounds) + 1)) if details else None
        if proxy:
            outbounds.append(proxy)
    if not outbounds:
        return None
    config = base_config(local_port, username, password)
    if len(outbounds) == 1:
        outbounds[0]["tag"] = "proxy"
    else:
        outbounds.append({"type": "urltest", "tag": "proxy", "outbounds": [o["tag"] for o in outbounds],
                          "url": URLTEST_URL, "interval": "3m", "tolerance": 50})
    config["outbounds"] = outbounds + [{"type": "direct", "tag": "direct"}]
    return config


def file_config(text, local_port, username="", password=""):
    """A user's sing-box config with our local inbound (and our DNS if it has none)."""
    config = json.loads(str(text or ""))
    if not isinstance(config, dict):
        raise ValueError("sing-box config must be an object")
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("sing-box config requires outbounds")
    config = dict(config)
    base = base_config(local_port, username, password)
    config["inbounds"] = base["inbounds"]
    dns = config.get("dns")
    own_dns = isinstance(dns, dict) and isinstance(dns.get("servers"), list) and dns.get("servers")
    if not own_dns:
        config["dns"] = base["dns"]
    route = dict(config["route"]) if isinstance(config.get("route"), dict) else {}
    if not own_dns and not str(route.get("default_domain_resolver", "") or "").strip():
        route["default_domain_resolver"] = base["route"]["default_domain_resolver"]
    if not str(route.get("final", "") or "").strip():
        first = outbounds[0]
        tag = str(first.get("tag", "") or "").strip() if isinstance(first, dict) else ""
        if not tag and isinstance(first, dict):
            config["outbounds"] = [dict(first, tag="proxy")] + list(outbounds[1:])
            tag = "proxy"
        route["final"] = tag or "proxy"
    config["route"] = route
    return config


def file_node(text, name=""):
    """Stored node for an imported sing-box config file."""
    config = json.loads(str(text or ""))
    if not isinstance(config, dict) or not isinstance(config.get("outbounds"), list) or not config["outbounds"]:
        raise ValueError("sing-box config requires outbounds")
    raw = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    node_id = "singconf://" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    first = config["outbounds"][0] if isinstance(config["outbounds"][0], dict) else {}
    try:
        port = int(first.get("server_port", first.get("port", 0)) or 0)
    except (TypeError, ValueError):
        port = 0
    title = str(name or config.get("name", "") or config.get("remarks", "") or "").strip()
    return {"id": node_id, "uri": node_id, "kind": links.KIND_SINGBOX_CONFIG,
            "name": title[:48] or "sing-box config",
            "server": str(first.get("server", first.get("server_address", first.get("address", ""))) or ""),
            "port": port, "network": "sing-box", "security": "config", "raw_config": raw}


def mihomo_config(config_text="", link_list=None, local_port=0, work_dir="", username="", password=""):
    """Start request for the mihomo engine inside the core."""
    raw = str(config_text or "")
    if len(raw.encode("utf-8", errors="ignore")) > MIHOMO_CONFIG_MAX_BYTES:
        raise ValueError("Mihomo config is too large")
    clean = [str(link).strip() for link in list(link_list or []) if str(link or "").strip()]
    if not raw.strip() and not clean:
        raise ValueError("Mihomo config is empty")
    return {"engine": "mihomo", "config": raw, "links": clean, "work_dir": str(work_dir or ""),
            "mixed_port": int(local_port or 0), "username": str(username or ""), "password": str(password or "")}


def mihomo_node(text, name=""):
    raw = str(text or "")
    size = len(raw.encode("utf-8", errors="ignore"))
    if size <= 0 or size > MIHOMO_CONFIG_MAX_BYTES:
        raise ValueError("Mihomo config size is invalid")
    node_id = "mihomo://" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    title = str(name or "").strip()
    return {"id": node_id, "uri": node_id, "kind": links.KIND_MIHOMO_CONFIG, "name": title[:48] or "Mihomo config",
            "server": "", "port": 0, "network": "Mihomo", "security": "config", "raw_config": raw}


# --- AmneziaWG ---

def _prefix(value):
    value = str(value or "").strip()
    return value if "/" in value else value + ("/128" if ":" in value else "/32")


def parse_wg_conf(text):
    """(interface, peers) of a WireGuard/AmneziaWG .conf, keys lower-cased."""
    interface, peers, current = {}, [], None
    for raw in str(text or "").splitlines():
        line = raw.strip()
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
        if current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key.strip().lower()] = value.strip()
    return interface, peers


def awg_config(conf_text, local_port):
    interface, peers = parse_wg_conf(conf_text)
    private_key = str(interface.get("privatekey", "") or "").strip()
    addresses = [_prefix(a) for a in _csv(interface.get("address"))]
    if not private_key or not addresses or not peers:
        raise ValueError("AWG config requires PrivateKey, Address and Peer")

    amnezia = {}
    for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime"):
        if str(interface.get(key, "") or "").strip():
            amnezia[key] = int(interface[key])
    for key in ("h1", "h2", "h3", "h4"):
        value = str(interface.get(key, "") or "").strip()
        if value:
            amnezia[key] = int(value) if value.isdigit() else value.replace(" ", "")
    for key in ("i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"):
        if str(interface.get(key, "") or "").strip():
            amnezia[key] = str(interface[key]).strip()

    wg_peers = []
    for peer in peers:
        endpoint = str(peer.get("endpoint", "") or "").strip()
        if endpoint.startswith("[") and "]:" in endpoint:
            host, port = endpoint[1:].rsplit("]:", 1)
        elif ":" in endpoint:
            host, port = endpoint.rsplit(":", 1)
        else:
            raise ValueError("AWG peer Endpoint must include a port")
        port = int(port)
        public_key = str(peer.get("publickey", "") or "").strip()
        allowed = [_prefix(a) for a in _csv(peer.get("allowedips"))]
        if not host or not 1 <= port <= 65535 or not public_key or not allowed:
            raise ValueError("AWG peer requires Endpoint, PublicKey and AllowedIPs")
        item = {"address": host, "port": port, "public_key": public_key, "allowed_ips": allowed}
        if str(peer.get("presharedkey", "") or "").strip():
            item["pre_shared_key"] = str(peer["presharedkey"]).strip()
        keepalive = str(peer.get("persistentkeepalive", "") or "").strip()
        # Keep the NAT mapping alive by default; an idle tunnel otherwise dies silently.
        item["persistent_keepalive_interval"] = int(keepalive) if keepalive else 25
        wg_peers.append(item)

    endpoint = {"type": "wireguard", "tag": "awg-out", "address": addresses, "private_key": private_key,
                "peers": wg_peers}
    if str(interface.get("listenport", "") or "").strip():
        endpoint["listen_port"] = int(interface["listenport"])
    if str(interface.get("mtu", "") or "").strip():
        endpoint["mtu"] = int(interface["mtu"])
    if amnezia:
        endpoint["amnezia"] = amnezia

    config = base_config(local_port)
    config["endpoints"] = [endpoint]
    config["route"]["final"] = "awg-out"
    if not any(":" in a for a in addresses):
        # IPv4-only tunnel: refuse IPv6 targets at once instead of failing each one.
        config["route"]["rules"].append({"ip_version": 6, "action": "reject"})
    dns = _csv(interface.get("dns"))
    if dns:
        config["dns"] = {"servers": [{"type": "udp", "tag": "awg-dns", "server": dns[0]}]}
        config["route"]["default_domain_resolver"] = "awg-dns"
    return config
