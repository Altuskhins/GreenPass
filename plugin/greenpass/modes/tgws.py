"""TG WS: Telegram over WebSocket through a local MTProto proxy (no core needed)."""

import json
import time

from .. import net, tgws_engine
from .base import CONNECTED, CONNECTING, FAILED, Mode

READY_TIMEOUT_SEC = 6.0
CF_PRIORITY_SETTING = "tgws_cfproxy_priority"


class TgWsMode(Mode):
    kind = "tgws"
    title = "TG WS"
    default_port = 10805
    uses_core = False

    def __init__(self, app):
        super().__init__(app)
        self.engine = tgws_engine.TgWsCore()

    def proxy_credentials(self):
        return "", "", tgws_engine._tgws_proxy_secret_for_telegram()

    def is_alive(self):
        return self.port > 0 and net.port_open(self.port)

    def cf_priority(self):
        return bool(self.app.setting(CF_PRIORITY_SETTING, tgws_engine.TGWS_CFPROXY_PRIORITY))

    def connect(self):
        if not self.engine.is_available():
            self.set_state(FAILED, "Java crypto недоступно")
            return False
        self.set_state(CONNECTING)
        self.engine.stop()
        reserved = (self.app.local_port("vless", 10804), self.app.local_port("awg", 2337),
                    self.app.local_port("olcrtc", 11808))
        port = net.pick_port(self.local_port(), exclude=reserved)
        if port <= 0:
            self.set_state(FAILED, "Нет свободного локального порта")
            return False
        error = self.engine.start(json.dumps({"port": port, "verbose": False,
                                              "dc_ip": dict(tgws_engine.TGWS_DEFAULT_DC_IP),
                                              "cfproxy_priority": self.cf_priority()}))
        if error:
            self.set_state(FAILED, "Ошибка TG WS: %s" % error)
            return False
        deadline = time.monotonic() + READY_TIMEOUT_SEC
        while not net.port_open(port):
            if time.monotonic() > deadline or not self.app.is_current(self):
                self.engine.stop()
                if self.app.is_current(self):
                    self.set_state(FAILED, "TG WS не запустился")
                return False
            time.sleep(0.1)
        self.port = port
        if not self.apply_proxy(port):
            self.engine.stop()
            self.set_state(FAILED, "Локальный прокси не применился")
            return False
        self.set_state(CONNECTED)
        return True

    def stop_runtime(self):
        self.engine.stop()

    def refresh_domains(self):
        """Fetch the Cloudflare fallback domain list again (part of the daily update check)."""
        if self.state == CONNECTED:
            self.engine._refresh_cfproxy_domains()

    def health_check(self):
        if self.state != CONNECTED:
            return
        if not self.is_alive():
            self.app.reconnect()
        elif not self.proxy_applied():
            self.apply_proxy(self.port)

    def on_resume(self):
        """Back from background: sockets may be dead, let the engine rebuild its pool."""
        if self.state == CONNECTED:
            self.engine.self_heal()
