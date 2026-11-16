"""The user's proxy nodes: own links plus subscriptions, the auto node, pings."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import links, net

AUTO_URI = "greenpass-auto://subscriptions"
MANUAL_SOURCE = "__manual__"
MAX_MANUAL = 64
MAX_SUBS = 64
BALANCER_MAX_NODES = 32
PING_TIMEOUT_SEC = 1.5
PING_REFRESH_SEC = 45.0
PING_STALE_SEC = 90.0
PING_DEAD = 9999


def ping_of(node):
    try:
        return int(node.get("ping", -1) or 0)
    except (TypeError, ValueError):
        return -1


def ping_fresh(node):
    try:
        checked = float(node.get("ping_checked_at", 0) or 0)
    except (TypeError, ValueError):
        return False
    return checked > 0 and time.time() - checked <= PING_STALE_SEC


def ping_badge(node):
    """"123 ms", "нет" for unreachable, "" when not checked recently."""
    if not ping_fresh(node):
        return ""
    ping = ping_of(node)
    return "нет" if ping <= 0 or ping >= PING_DEAD else "%d ms" % ping


def sort_key(node):
    """Fresh reachable nodes by ping, then unreachable, then unchecked; ties by name."""
    ping = ping_of(node)
    if not ping_fresh(node) or ping < 0:
        rank, score = 2, 999999
    elif ping <= 0 or ping >= PING_DEAD:
        rank, score = 1, 999998
    else:
        rank, score = 0, ping
    return rank, score, str(node.get("name", "") or "").strip().lower()


def leaves(node):
    """Endpoint nodes: the node itself, or the members of a balancer node."""
    members = [n for n in list(node.get("balance_nodes", []) or []) if isinstance(n, dict)] if isinstance(node, dict) else []
    if not members:
        if isinstance(node, dict):
            yield node
        return
    for member in members:
        yield from leaves(member)


class Nodes:
    """View over store.vless_manual / vless_subs / vless_active_uri."""

    def __init__(self, store, hidden_sources):
        self.store = store
        self._hidden = hidden_sources          # callable -> set of source keys the user hid
        self._index = (None, {})

    # --- lookup ---

    def all(self):
        for node in self.store.vless_manual:
            if isinstance(node, dict):
                yield node
        for sub in self.store.vless_subs:
            for node in list(sub.get("nodes", []) or []):
                if isinstance(node, dict):
                    yield node

    def find(self, uri):
        uri = str(uri or "")
        if not uri:
            return None
        if uri == AUTO_URI:
            return self.auto_node()
        return next((n for n in self.all() if n.get("uri") == uri), None)

    def active(self):
        node = self.find(self.store.vless_active_uri)
        if node is None and self.repair_active():
            self.store.save()
            node = self.find(self.store.vless_active_uri)
        return node

    def set_active(self, uri):
        self.store.vless_active_uri = str(uri or "")

    def counts(self):
        return {"nodes": sum(1 for _ in self.all()), "subs": len(self.store.vless_subs),
                "manual": len(self.store.vless_manual)}

    # --- sources (subscriptions) and the user's hidden list ---

    def source_of(self, node):
        """{"key", "name", "url", "manual"} of the subscription a node came from."""
        index = self._source_index()
        uri = str((node or {}).get("uri", "") or "")
        if uri in index:
            return dict(index[uri])
        for member in list((node or {}).get("balance_nodes", []) or []):
            source = self.source_of(member)
            if not source["manual"]:
                return source
        return {"key": MANUAL_SOURCE, "name": "Свои узлы", "url": "", "manual": True}

    def _source_index(self):
        subs = self.store.vless_subs
        if self._index[0] is subs:
            return self._index[1]
        index = {}

        def walk(node, source):
            if isinstance(node, dict):
                index.setdefault(str(node.get("uri", "") or ""), source)
                for member in list(node.get("balance_nodes", []) or []):
                    walk(member, source)

        for sub in subs:
            url = str(sub.get("url", "") or "").strip()
            if url:
                source = {"key": url, "name": str(sub.get("name", "") or "").strip() or url, "url": url, "manual": False}
                for node in list(sub.get("nodes", []) or []):
                    walk(node, source)
        index.pop("", None)
        self._index = (subs, index)
        return index

    def invalidate(self):
        self._index = (None, {})

    def visible(self, node):
        return self.source_of(node)["key"] not in self._hidden()

    # --- the auto node: nodes from every visible subscription, round-robin ---

    def balancer_nodes(self, failover=True):
        hidden = self._hidden()
        groups = []
        for sub in self.store.vless_subs:
            if str(sub.get("url", "") or "").strip() in hidden:
                continue
            group = [leaf for node in list(sub.get("nodes", []) or []) if isinstance(node, dict)
                     for leaf in (list(node.get("balance_nodes", []) or []) or [node])
                     if self.source_of(leaf)["key"] not in hidden]
            if failover:
                group = sorted(group, key=sort_key)
            if group:
                groups.append(group)
        selected, seen = [], set()
        while groups and len(selected) < BALANCER_MAX_NODES:
            remaining = []
            for group in groups:
                node = group.pop(0)
                if group:
                    remaining.append(group)
                uri = str(node.get("uri", "") or "")
                key = links.dedup_key(uri) or uri
                if links.is_proxy_link(uri) and key and key not in seen:
                    seen.add(key)
                    selected.append(node)
                    if len(selected) >= BALANCER_MAX_NODES:
                        break
            groups = remaining
        return selected

    def auto_node(self, failover=True):
        members = self.balancer_nodes(failover)
        if len(members) < 2:
            return None
        return {"uri": AUTO_URI, "kind": "vless", "name": "Автовыбор", "server": members[0].get("server", ""),
                "port": int(members[0].get("port", 0) or 0), "network": "auto", "balance_nodes": members}

    def route_members(self, node, failover=True):
        """Nodes a balancer node really routes through (visible ones; only the first without failover)."""
        hidden = self._hidden()
        members = [n for n in list((node or {}).get("balance_nodes", []) or [])
                   if isinstance(n, dict) and self.source_of(n)["key"] not in hidden]
        return members if failover or not members else members[:1]

    # --- editing ---

    def add_manual(self, node, activate=True):
        uri = node["uri"]
        key = links.dedup_key(uri) or uri
        self.store.vless_manual = [node] + [n for n in self.store.vless_manual
                                            if (links.dedup_key(n.get("uri", "")) or n.get("uri")) != key][:MAX_MANUAL - 1]
        if activate:
            self.set_active(uri)
        self.invalidate()

    def remove(self, uri):
        """Remove a node (own or from a subscription). Returns True if found."""
        found = False
        before = len(self.store.vless_manual)
        self.store.vless_manual = [n for n in self.store.vless_manual if n.get("uri") != uri]
        found = len(self.store.vless_manual) != before
        for sub in self.store.vless_subs:
            nodes = list(sub.get("nodes", []) or [])
            kept = [n for n in nodes if n.get("uri") != uri]
            if len(kept) != len(nodes):
                sub["nodes"] = kept
                found = True
        if self.store.vless_active_uri == uri:
            self.store.vless_active_uri = ""
            self.repair_active()
        self.invalidate()
        return found

    def find_subscription(self, url):
        return next((s for s in self.store.vless_subs if s.get("url") == url), None)

    def put_subscription(self, url, nodes, name=""):
        """Add or refresh a subscription's nodes. Returns True when it already existed."""
        sub = self.find_subscription(url)
        if sub is not None:
            sub["nodes"] = list(nodes)
            if name:
                sub["name"] = name
        else:
            import urllib.parse
            self.store.vless_subs = (self.store.vless_subs + [{
                "id": url, "url": url, "name": name or urllib.parse.urlparse(url).netloc or url, "nodes": list(nodes),
            }])[-MAX_SUBS:]
        self.invalidate()
        return sub is not None

    def remove_subscription(self, url):
        self.store.vless_subs = [s for s in self.store.vless_subs if s.get("url") != url]
        self.invalidate()
        if not self.find(self.store.vless_active_uri):
            self.store.vless_active_uri = ""
            self.repair_active()

    def clear(self):
        self.store.vless_manual, self.store.vless_subs, self.store.vless_active_uri = [], [], ""
        self.invalidate()

    def repair_active(self):
        """After a subscription refresh the active link may be gone: pick its
        equivalent (same dedup key) or the first subscription node. True if changed."""
        active = self.store.vless_active_uri
        if active == AUTO_URI and self.auto_node():
            return False
        active_key = links.dedup_key(active) or active
        if not active_key:
            return False
        if any((links.dedup_key(n.get("uri", "")) or n.get("uri")) == active_key for n in self.store.vless_manual):
            return False
        first = ""
        for sub in self.store.vless_subs:
            for node in list(sub.get("nodes", []) or []):
                uri = str(node.get("uri", "") or "")
                key = links.dedup_key(uri) or uri
                if key == active_key:
                    if uri != active:
                        self.store.vless_active_uri = uri
                        return True
                    return False
                first = first or uri
        if first and first != active:
            self.store.vless_active_uri = first
            return True
        return False

    # --- pings ---

    def refresh_pings(self, targets=None, force=False, on_progress=None):
        """TCP-connect latency to each node's server. Returns (checked, alive)."""
        candidates = [n for n in (list(targets) if targets is not None else list(self.all()))
                      if n.get("kind") != "qwdtt" and n.get("server") and int(n.get("port", 0) or 0) > 0]
        now = time.time()
        due = [n for n in candidates
               if force or now - float(n.get("ping_checked_at", 0) or 0) >= PING_REFRESH_SEC]
        alive = 0
        if due:
            with ThreadPoolExecutor(max_workers=min(12, len(due))) as pool:
                futures = {pool.submit(net.tcp_latency_ms, n["server"], n["port"], PING_TIMEOUT_SEC): n for n in due}
                for future in as_completed(futures):
                    node = futures[future]
                    try:
                        latency = future.result()
                    except Exception:
                        latency = None
                    node["ping"] = latency if latency else PING_DEAD
                    node["ping_checked_at"] = time.time()
                    alive += 1 if latency else 0
                    if on_progress is not None:
                        on_progress()
        self.store.vless_manual = sorted(self.store.vless_manual, key=sort_key)
        return len(due), alive

    def fastest(self, candidates=None):
        best = None
        for node in (list(candidates) if candidates is not None else self.all()):
            ping = ping_of(node)
            if node.get("kind") == "qwdtt" or not ping_fresh(node) or ping <= 0 or ping >= PING_DEAD:
                continue
            if best is None or ping < ping_of(best):
                best = node
        return best
