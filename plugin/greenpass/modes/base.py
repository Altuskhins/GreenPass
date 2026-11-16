"""What every connection mode shares.

A mode runs one local proxy (a SOCKS5 or MTProto port on 127.0.0.1) and points
Telegram at it. The controller runs at most one mode at a time and calls
connect()/disconnect() from its worker thread, never from the UI thread.
"""

import threading

OFF = "off"
CONNECTING = "connecting"
CONNECTED = "connected"
FAILED = "failed"


class Mode:
    kind = ""
    title = ""
    default_port = 0
    uses_core = True            # runs inside libgreenpass (everything but TG WS)

    def __init__(self, app):
        self.app = app
        self.state = OFF
        self.error = ""
        self.port = 0
        self._lock = threading.RLock()

    # --- to implement ---

    def connect(self):
        """Start the local proxy and apply it. Returns True on success."""
        raise NotImplementedError

    def stop_runtime(self):
        """Stop whatever connect() started (core instance, listener)."""

    def is_alive(self):
        """The local proxy answers right now."""
        return False

    def proxy_credentials(self):
        """(username, password, secret) Telegram uses for the local proxy."""
        return "", "", ""

    def health_check(self):
        """Called every 30 s while connected; may reconnect. Default: nothing."""

    def has_config(self):
        """There is something to connect to (a node, a conf, a profile)."""
        return True

    # --- shared ---

    def local_port(self):
        return self.app.local_port(self.kind, self.default_port)

    def set_state(self, state, error=""):
        changed = state != self.state or error != self.error
        self.state, self.error = state, str(error or "")
        if changed:
            self.app.refresh_ui()

    def apply_proxy(self, port):
        username, password, secret = self.proxy_credentials()
        return self.app.local_proxy.apply(self.kind, port, username, password, secret,
                                          calls=self.app.calls_via_proxy())

    def proxy_applied(self):
        if self.port <= 0:
            return False
        username, password, secret = self.proxy_credentials()
        return self.app.local_proxy.is_applied(self.kind, self.port, username, password, secret)

    def disconnect(self, stop=True):
        """Clear the Telegram proxy and stop the runtime."""
        with self._lock:
            port, self.port = self.port, 0
            if port > 0:
                self.app.local_proxy.clear(owner=self.kind, port=port)
            if stop:
                try:
                    self.stop_runtime()
                except Exception:
                    pass
            self.set_state(OFF)

    def status_text(self):
        if self.state == CONNECTED:
            return "Подключено"
        if self.state == CONNECTING:
            return "Подключение..."
        if self.state == FAILED:
            return self.error or "Ошибка"
        return "Отключено"
