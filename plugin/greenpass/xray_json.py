"""Turn Xray JSON configs (as some subscriptions serve them) into share links."""

import hashlib
import json
import urllib.parse

from . import links

_GENERIC_TAGS = ("proxy", "vless", "node", "out", "outbound", "default")
_QUERY_KEYS = ("type", "security", "sni", "flow", "path", "host", "serviceName", "mode", "fp", "pbk", "sid",
               "spx", "packetEncoding", "extra")


def _dict(value):
    return value if isinstance(value, dict) else {}


def _first(*values):
    for value in values:
        if value:
            return value
    return None


def _name(obj, server, sni):
    name = str(obj.get("name") or obj.get("remark") or obj.get("ps") or obj.get("tag") or "").strip()
    if not name or name.lower() in _GENERIC_TAGS:
        return str(sni or "").strip() or str(server or "").strip() or "sing-box узел"
    return name


def _vless_params(obj, user=None):
    """Share-link query params from an outbound in Xray or sing-box JSON style."""
    p = {}
    network = obj.get("network") or obj.get("type")
    security = obj.get("security")
    sni = obj.get("sni") or obj.get("serverName")
    flow = obj.get("flow") or (_dict(user).get("flow") if user else None)
    path = obj.get("path")
    host = obj.get("host")
    fp = obj.get("fp") or obj.get("fingerprint")
    pbk = obj.get("pbk") or obj.get("publicKey")
    sid = obj.get("sid") or obj.get("shortId")
    spx = obj.get("spx") or obj.get("spiderX")
    packet_encoding = obj.get("packetEncoding")

    tls = obj.get("tls")
    if isinstance(tls, dict):
        if tls.get("enabled") is True or str(tls.get("enabled")).lower() == "true":
            security = security or "tls"
        sni = sni or tls.get("server_name") or tls.get("serverName") or tls.get("sni")
        fp = fp or tls.get("fingerprint")
    transport = obj.get("transport")
    if isinstance(transport, dict):
        network = network or transport.get("type") or transport.get("network")
        path = path or transport.get("path")
        headers = _dict(transport.get("headers"))
        host = host or headers.get("Host") or headers.get("host")

    stream = obj.get("streamSettings")
    if isinstance(stream, dict):
        network = stream.get("network") or network
        security = stream.get("security") or security
        packet_encoding = packet_encoding or stream.get("packetEncoding")
        reality = stream.get("realitySettings")
        if isinstance(reality, dict):
            sni = _first(reality.get("serverName"), reality.get("server_name"), reality.get("sni"), sni)
            fp = reality.get("fingerprint") or fp
            pbk = _first(reality.get("publicKey"), reality.get("public_key"), pbk)
            sid = _first(reality.get("shortId"), reality.get("short_id"), sid)
            spx = _first(reality.get("spiderX"), reality.get("spider_x"), spx)
        tls_settings = stream.get("tlsSettings")
        if isinstance(tls_settings, dict):
            sni = _first(tls_settings.get("serverName"), tls_settings.get("server_name"), sni)
            fp = tls_settings.get("fingerprint") or fp
        ws = stream.get("wsSettings")
        if isinstance(ws, dict):
            path = ws.get("path") or path
            headers = _dict(ws.get("headers"))
            host = headers.get("Host") or headers.get("host") or host
        grpc = stream.get("grpcSettings")
        if isinstance(grpc, dict):
            service = grpc.get("serviceName") or grpc.get("service_name")
            if service:
                p["serviceName"] = str(service)
            if grpc.get("multiMode") is not None:
                p["mode"] = "multi" if bool(grpc.get("multiMode")) else "gun"
        xhttp = stream.get("xhttpSettings")
        if isinstance(xhttp, dict):
            path = xhttp.get("path") or path
            host = xhttp.get("host") or host
            if xhttp.get("mode"):
                p["mode"] = str(xhttp["mode"])
            if isinstance(xhttp.get("extra"), (dict, list)):
                p["extra"] = json.dumps(xhttp["extra"], ensure_ascii=False, separators=(",", ":"))
        upgrade = stream.get("httpupgradeSettings")
        if isinstance(upgrade, dict):
            host = upgrade.get("host") or host
            path = upgrade.get("path") or path

    for key, value in (("type", network), ("security", security), ("sni", sni), ("flow", flow), ("path", path),
                       ("host", host), ("fp", fp), ("pbk", pbk), ("sid", sid), ("spx", spx),
                       ("packetEncoding", packet_encoding)):
        if value:
            p[key] = str(value)
    return p


def _vless_link(obj, uuid, server, port, user=None):
    uuid, server = str(uuid or "").strip(), str(server or "").strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ""
    if not uuid or not server or port <= 0:
        return ""
    params = _vless_params(obj, user)
    name = _name(obj, server, params.get("sni", ""))
    query = "&".join("%s=%s" % (urllib.parse.quote(key, safe=""),
                                urllib.parse.quote(params[key], safe="/" if key == "path" else ""))
                     for key in _QUERY_KEYS if params.get(key) not in (None, ""))
    return "vless://%s@%s:%d%s#%s" % (urllib.parse.quote(uuid, safe=""), server, port,
                                      "?" + query if query else "", urllib.parse.quote(name or "sing-box узел", safe=""))


def _hysteria2_link(outbound, profile_name=""):
    protocol = str(outbound.get("protocol", "") or "").strip().lower()
    settings = _dict(outbound.get("settings"))
    stream = _dict(outbound.get("streamSettings"))
    hysteria = _dict(stream.get("hysteriaSettings"))
    try:
        version = int(settings.get("version") or hysteria.get("version") or (2 if protocol == "hysteria2" else 0))
        port = int(settings.get("port") or settings.get("server_port") or 0)
    except (TypeError, ValueError):
        return ""
    server = str(settings.get("address") or settings.get("server") or "").strip()
    auth = str(hysteria.get("auth") or settings.get("password") or "")
    if version != 2 or not server or port <= 0 or not auth:
        return ""
    tls = _dict(stream.get("tlsSettings"))
    params = {}
    if tls.get("serverName"):
        params["sni"] = str(tls["serverName"])
    if tls.get("fingerprint"):
        params["fp"] = str(tls["fingerprint"])
    alpn = tls.get("alpn")
    if isinstance(alpn, list):
        alpn = ",".join(str(v).strip() for v in alpn if str(v or "").strip())
    if alpn:
        params["alpn"] = str(alpn)
    if bool(tls.get("allowInsecure", False)):
        params["insecure"] = "1"
    mask = next((m for m in list(_dict(stream.get("finalmask")).get("udp", []) or []) if isinstance(m, dict)), None)
    if mask:
        if mask.get("type"):
            params["obfs"] = str(mask["type"])
        if _dict(mask.get("settings")).get("password"):
            params["obfs-password"] = str(mask["settings"]["password"])
    host = "[%s]" % server if ":" in server and not server.startswith("[") else server
    name = str(profile_name or outbound.get("tag") or links.address_name(server, port) or "Hysteria2 узел").strip()
    query = urllib.parse.urlencode(params)
    return "hy2://%s@%s:%d%s#%s" % (urllib.parse.quote(auth, safe=""), host, port,
                                    "?" + query if query else "", urllib.parse.quote(name, safe=""))


def outbound_links(outbound, profile_name=""):
    """Share links for one Xray outbound (VLESS and Hysteria2 are supported)."""
    if not isinstance(outbound, dict):
        return []
    protocol = str(outbound.get("protocol", "") or "").lower()
    if protocol in ("hysteria", "hysteria2"):
        link = _hysteria2_link(outbound, profile_name)
        return [link] if link else []
    if protocol != "vless":
        return []
    settings = _dict(outbound.get("settings"))
    prefix = str(profile_name or "").strip()
    tag = str(outbound.get("tag", "") or "").strip()
    child = "" if links.is_generic_name(tag) else tag
    result = []

    def add(uuid, server, port, user=None):
        named = dict(outbound)
        named["name"] = (prefix + (" " + child if child else "")).strip() if prefix else (child or links.address_name(server, port))
        link = _vless_link(named, uuid, server, port, user)
        if link:
            result.append(link)

    vnext = settings.get("vnext")
    if isinstance(vnext, list):
        for target in vnext:
            if isinstance(target, dict):
                for user in target.get("users") if isinstance(target.get("users"), list) else []:
                    if isinstance(user, dict):
                        add(user.get("id") or user.get("uuid"), target.get("address") or target.get("server"),
                            target.get("port"), user)
        return result
    users = settings.get("users") if isinstance(settings.get("users"), list) else []
    user = users[0] if users and isinstance(users[0], dict) else None
    add(settings.get("uuid") or settings.get("id") or settings.get("user") or (user or {}).get("id", ""),
        settings.get("address") or settings.get("server"), settings.get("port") or settings.get("server_port"), user)
    return result


def config_nodes(config):
    """Nodes from one Xray config. Balancers become one auto node with its members."""
    if not isinstance(config, dict):
        return []
    profile = str(config.get("remarks") or config.get("remark") or config.get("name") or "").strip()
    outbounds = [config] if config.get("protocol") else [o for o in list(config.get("outbounds", []) or []) if isinstance(o, dict)]
    balancers = [b for b in list(_dict(config.get("routing")).get("balancers", []) or []) if isinstance(b, dict)]

    def nodes_for(items):
        nodes = []
        for item in items:
            for link in outbound_links(item, profile):
                node = links.node_from_link(link)
                if node:
                    nodes.append(node)
        return nodes

    groups = []
    for balancer in balancers:
        tag = str(balancer.get("tag", "") or "").strip()
        selectors = [str(s) for s in list(balancer.get("selector", []) or []) if str(s or "")]
        members = nodes_for([o for o in outbounds if any(str(o.get("tag", "") or "").startswith(s) for s in selectors)])
        if not members:
            continue
        name = (profile or "VLESS Auto") + (" • " + tag if len(balancers) > 1 and tag else "")
        node_id = "greenpass-balancer://" + hashlib.sha256((name + "|" + tag + "|" + ",".join(selectors)).encode("utf-8")).hexdigest()
        groups.append({"id": node_id, "uri": node_id, "kind": "vless", "name": name,
                       "server": members[0].get("server", ""), "port": int(members[0].get("port", 0) or 0),
                       "network": "auto", "security": members[0].get("security", ""), "balance_nodes": members})
    return groups or nodes_for(outbounds)
