"""Proxy links and configs (VLESS, VMess, Trojan, SS, Hysteria2, ...) run by sing-box or
mihomo inside the core; qWDTT profiles run by the core's qwdtt engine."""

import os
import time

from .. import links, net, qwdtt, singbox
from ..store import ENGINE_MIHOMO
from .base import CONNECTED, CONNECTING, FAILED, Mode

READY_TIMEOUT_SEC = 12.0
SOCKS_USER = "greenpass"


class VlessMode(Mode):
    kind = "vless"
    title = "Прокси"
    default_port = 10804

    def __init__(self, app):
        super().__init__(app)
        self._running_key = ""
        self._auth = ("", "")
        self.title_detail = ""

    def has_config(self):
        return self.app.nodes.active() is not None

    def proxy_credentials(self):
        return self._auth[0], self._auth[1], ""

    def is_alive(self):
        return self.port > 0 and net.socks_ready(self.port, 0.35, *self._auth)

    def engine_for(self, node):
        kind = str((node or {}).get("kind", "") or "").lower()
        if kind == links.KIND_MIHOMO_CONFIG:
            return ENGINE_MIHOMO
        if kind in (links.KIND_SINGBOX_CONFIG, qwdtt.KIND):
            return "singbox"
        return self.app.store.engine

    def _build(self, node, port, username, password):
        """(config dict, title) for the node, or (None, error)."""
        kind = str(node.get("kind", "") or "").lower()
        work_dir = os.path.join(self.app.core.dir, "mihomo")
        if kind == qwdtt.KIND:
            return qwdtt.core_config(node.get("qwdtt", {}), port), "qWDTT"
        if kind == links.KIND_MIHOMO_CONFIG:
            return singbox.mihomo_config(config_text=node.get("raw_config", ""), local_port=port, work_dir=work_dir,
                                         username=username, password=password), "Mihomo"
        if kind == links.KIND_SINGBOX_CONFIG:
            return singbox.file_config(node.get("raw_config", ""), port, username, password), "sing-box"
        members = self.app.nodes.route_members(node, self.app.failover_enabled()) if node.get("balance_nodes") else []
        if self.engine_for(node) == ENGINE_MIHOMO:
            uris = [n.get("uri", "") for n in (members or [node]) if links.is_proxy_link(n.get("uri", ""))]
            return (singbox.mihomo_config(link_list=uris, local_port=port, work_dir=work_dir, username=username,
                                          password=password), "Mihomo Auto" if len(uris) > 1 else "Mihomo")
        if len(members) > 1:
            return singbox.balanced_config(members, port, username, password), "VLESS Auto"
        target = members[0] if members else node
        return singbox.link_config(target.get("uri", ""), port, username, password), "sing-box"

    def _runtime_key(self, node, members_uris):
        return "|".join([self.app.store.engine, node.get("uri", ""), ",".join(members_uris)])

    def connect(self):
        node = self.app.nodes.active()
        if node is None:
            self.set_state(FAILED, "Нет выбранного узла")
            return False
        is_qwdtt = node.get("kind") == qwdtt.KIND
        username, password = ("", "") if is_qwdtt else (SOCKS_USER, self.app.store.socks_password)
        members = [n.get("uri", "") for n in self.app.nodes.route_members(node, self.app.failover_enabled())] \
            if node.get("balance_nodes") else []
        key = self._runtime_key(node, members)

        # Nothing changed and the proxy still answers: keep it.
        if key == self._running_key and self.port > 0 and net.socks_ready(self.port, 0.35, username, password):
            if self.proxy_applied() or self.apply_proxy(self.port):
                self.set_state(CONNECTED)
                return True

        self.set_state(CONNECTING)
        self.app.stop_core()
        self._running_key = ""
        port = net.pick_port(self.local_port())
        if port <= 0:
            self.set_state(FAILED, "Нет свободного локального порта")
            return False
        try:
            config, title = self._build(node, port, username, password)
        except Exception as exc:
            config, title = None, str(exc)
        if not config:
            self.set_state(FAILED, "Не удалось разобрать ссылку" if not title else "Ошибка конфига: %s" % title)
            return False
        self.title_detail = title
        if not is_qwdtt and config.get("engine") != ENGINE_MIHOMO:
            config["log"] = dict(config.get("log") or {}, disabled=False, level="info")
            experimental = dict(config.get("experimental") or {})
            experimental["cache_file"] = dict(experimental.get("cache_file") or {},
                                              path=os.path.join(self.app.core.dir, "singbox-cache.db"))
            config["experimental"] = experimental
            error = self.app.core.validate(config)
            if error:
                self.set_state(FAILED, "Конфиг %s не принят ядром: %s" % (title, error))
                return False

        error = self.app.start_core(config)
        if error and ("address already in use" in error.lower() or "eaddrinuse" in error.lower()):
            port = net.pick_port(0, exclude=(port,))
            config_retry, _ = self._build(node, port, username, password)
            if config_retry and config.get("experimental"):
                config_retry["experimental"] = config["experimental"]
            error = self.app.start_core(config_retry) if config_retry else error
        if error:
            self.set_state(FAILED, "Ошибка ядра прокси: %s" % error)
            return False

        self.port, self._auth = port, (username, password)
        deadline = time.monotonic() + READY_TIMEOUT_SEC
        local_ready = False
        while time.monotonic() < deadline:
            if not self.app.is_current(self):
                return False
            if net.socks_ready(port, 0.5, username, password):
                local_ready = True
                # qWDTT has no egress probe; the others must pass traffic.
                if is_qwdtt or net.tunnel_works(port, 1.5, username, password):
                    break
            time.sleep(0.3)
        else:
            if local_ready and self.engine_for(node) == ENGINE_MIHOMO:
                self.set_state(FAILED, "Прокси не работает. Попробуйте переключиться на ядро sing-box")
            else:
                self.set_state(FAILED, "%s не запустился" % title)
            self.app.stop_core()
            return False

        if not self.apply_proxy(port):
            self.set_state(FAILED, "Локальный прокси не применился")
            return False
        self._running_key = key
        self.set_state(CONNECTED)
        return True

    def stop_runtime(self):
        self._running_key = ""
        self.app.stop_core()

    def health_check(self):
        """The core died (e.g. killed in background): start it again."""
        if self.state == CONNECTED and not self.is_alive():
            self._running_key = ""
            self.app.reconnect()
