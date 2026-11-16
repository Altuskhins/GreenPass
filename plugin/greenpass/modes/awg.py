"""AmneziaWG: a WireGuard/AWG .conf run by sing-box, or a generated Cloudflare WARP config."""

import re
import time

from .. import net, singbox
from ..android import toast_error, toast_info, toast_success
from ..warp import WARP_CONF_NAME, generate_warp_conf
from .base import CONNECTED, CONNECTING, FAILED, Mode

WARP_PORT_SETTING = "awg_warp_port"


class AwgMode(Mode):
    kind = "awg"
    title = "AmneziaWG"
    default_port = 2337

    def __init__(self, app):
        super().__init__(app)
        self._started_conf = ""
        self._failures = 0
        self._last_fix = 0.0

    def has_config(self):
        return bool(self.app.store.awg_conf_content.strip())

    def is_warp(self):
        return self.app.store.awg_conf_name == WARP_CONF_NAME

    def warp_port(self):
        """User's WARP endpoint port (1-65535), or None for a random one."""
        try:
            port = int(str(self.app.setting(WARP_PORT_SETTING, "") or "").strip())
        except ValueError:
            return None
        return port if 1 <= port <= 65535 else None

    def is_alive(self):
        return self.port > 0 and net.socks_ready(self.port, timeout=0.35)

    def connect(self):
        store = self.app.store
        if not self.has_config() and not self.generate_warp():
            self.set_state(FAILED, "Нет конфига AWG")
            return False
        self._fix_old_warp_mtu()
        conf = store.awg_conf_content.strip()
        port = self.local_port()

        # Same config already running: just make sure Telegram uses it.
        if self._started_conf == conf and net.socks_ready(port, timeout=0.35):
            self.port = port
            if self.proxy_applied() or self.apply_proxy(port):
                self.set_state(CONNECTED)
                return True

        self.set_state(CONNECTING)
        try:
            config = singbox.awg_config(conf, port)
        except (ValueError, TypeError) as exc:
            self.set_state(FAILED, "Ошибка конфига AWG: %s" % exc)
            return False
        error = self.app.start_core(config)
        if error:
            self._started_conf = ""
            self.set_state(FAILED, "Ошибка AWG: %s" % error)
            toast_error("Ошибка AWG: %s", error)
            return False
        self._started_conf = conf
        self.port = port
        if not self.apply_proxy(port):
            self.set_state(FAILED, "Не удалось применить прокси")
            return False
        self._failures = 0
        self.set_state(CONNECTED)
        toast_success("AmneziaWG подключен")
        return True

    def stop_runtime(self):
        if self._started_conf:
            self._started_conf = ""
            self.app.stop_core()

    def generate_warp(self):
        """Replace the config with a fresh Cloudflare WARP one. Returns True on success."""
        try:
            text = generate_warp_conf(port=self.warp_port())
        except Exception as exc:
            toast_error("Не удалось получить WARP конфиг: %s", exc)
            return False
        store = self.app.store
        store.awg_conf_name, store.awg_conf_content = WARP_CONF_NAME, text
        store.save()
        return True

    def _fix_old_warp_mtu(self):
        # WARP configs made before build 12 use MTU 1280, too big on IPv6 mobile networks.
        store = self.app.store
        if self.is_warp():
            fixed = re.sub(r"(?mi)^(\s*MTU\s*=\s*)1280\s*$", r"\g<1>1200", store.awg_conf_content)
            if fixed != store.awg_conf_content:
                store.awg_conf_content = fixed
                store.save()

    def health_check(self):
        """A dead free config keeps the core running while Telegram hangs on
        "Соединение...". After 2 failed Telegram probes in a row (at most once per
        3 minutes) regenerate WARP, or reconnect a user config."""
        if self.state != CONNECTED:
            self._failures = 0
            return
        if net.telegram_reachable(self.port, timeout=10.0):
            self._failures = 0
            return
        self._failures += 1
        if self._failures < 2 or time.monotonic() - self._last_fix < 180:
            return
        self._failures = 0
        self._last_fix = time.monotonic()
        if self.is_warp():
            if self.generate_warp():
                toast_info("AWG не отвечал — создан новый WARP конфиг")
        else:
            toast_info("AWG не отвечал — переподключаю")
        self._started_conf = ""
        self.app.reconnect()
