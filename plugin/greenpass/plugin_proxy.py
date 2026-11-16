"""Send other plugins' network traffic through GreenPass's local SOCKS5.

Three layers, all switched by the "proxy_plugins_via_greenpass" setting:
- the greenpass_proxy_api module other plugins can import (endpoint, requests proxies);
- a patch of socket.create_connection / urllib3 for Python plugins;
- a Frida script that gives java.net.URL connections a SOCKS proxy (when the
  client has frida_gadget_api).
GreenPass's own calls are never proxied (the stack is checked for our files).
"""

import json
import os
import socket
import struct
import sys
import threading
import types
import urllib.parse

SETTING = "proxy_plugins_via_greenpass"
API_MODULE = "greenpass_proxy_api"
FRIDA_ID = "GreenPassPluginProxy"
FRIDA_NAME = "greenpass-java-url-proxy"
UI_HANDSHAKE_TIMEOUT_SEC = 2.5
_SKIP_FRAMES = {"_is_own_call", "patched_create_connection", "patched_urllib3_create_connection",
                "_socks_connect", "_recv_exact"}

_FRIDA_SCRIPT = """
Java.perform(function () {
  var HOST = %s;
  var PORT = %s;
  var URL = Java.use('java.net.URL');
  var Proxy = Java.use('java.net.Proxy');
  var ProxyType = Java.use('java.net.Proxy$Type');
  var InetSocketAddress = Java.use('java.net.InetSocketAddress');
  var System = Java.use('java.lang.System');
  var proxy = Proxy.$new(ProxyType.valueOf('SOCKS'), InetSocketAddress.$new(HOST, PORT));

  function bypass(host) {
    host = String(host || '').toLowerCase();
    return !host || host === 'localhost' || host === '127.0.0.1' || host === '::1' ||
      host.indexOf('127.') === 0 || host === String(HOST).toLowerCase();
  }

  System.setProperty('socksProxyHost', HOST);
  System.setProperty('socksProxyPort', String(PORT));

  var openNoProxy = URL.openConnection.overload();
  var openWithProxy = URL.openConnection.overload('java.net.Proxy');
  openNoProxy.implementation = function () {
    var host = '';
    try { host = String(this.getHost() || ''); } catch (_) {}
    if (bypass(host)) {
      return openNoProxy.call(this);
    }
    return openWithProxy.call(this, proxy);
  };

  fridaGadget.onDispose(function () {
    try {
      System.clearProperty('socksProxyHost');
      System.clearProperty('socksProxyPort');
    } catch (_) {}
  });
});
"""


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS proxy closed")
        data += chunk
    return data


def _on_ui_thread():
    try:
        from android.os import Looper
        return Looper.myLooper() == Looper.getMainLooper()
    except Exception:
        return threading.current_thread() is threading.main_thread()


class PluginProxy:
    def __init__(self, app, own_file):
        self.app = app
        own = os.path.abspath(str(own_file or "")).replace("\\", "/").lower()
        # The .elyx build is a package dir; the .plugin build is one file.
        self._own_root = os.path.dirname(own) + "/" if own and app.plugin_is_package else ""
        self._own_file = own
        self._originals = {}
        self._frida_key = ""
        self.last_error = ""

    # --- what to expose ---

    def enabled(self):
        return bool(self.app.setting(SETTING, False))

    def endpoint(self):
        """{"host", "port", "username", "password", "source"} or None."""
        if not self.enabled():
            self.last_error = ""
            return None
        app = self.app
        if not app.wants_running():
            self.last_error = "GreenPass proxy is off" if not app.store.enabled else "GreenPass proxy is suspended by network policy"
            return None
        mode = app.mode
        if mode.kind == "tgws":
            self.last_error = "TGWS is Telegram-only"
            return None
        if mode.state != "connected" or mode.port <= 0:
            self.last_error = "SOCKS is not ready"
            return None
        username, password, _ = mode.proxy_credentials()
        self.last_error = ""
        return {"host": "127.0.0.1", "port": mode.port, "username": username, "password": password, "source": mode.kind}

    @staticmethod
    def url(endpoint):
        if not endpoint:
            return ""
        auth = ""
        if endpoint["username"] or endpoint["password"]:
            auth = "%s:%s@" % (urllib.parse.quote(endpoint["username"], safe=""),
                               urllib.parse.quote(endpoint["password"], safe=""))
        return "socks5h://%s%s:%d" % (auth, endpoint["host"], endpoint["port"])

    def sync(self):
        """Apply or remove the patches to match the current endpoint."""
        self._install_api()
        endpoint = self.endpoint()
        if endpoint:
            self._patch_python()
            self._register_frida(endpoint)
        else:
            self._unpatch_python()
            self._deactivate_frida()

    def remove(self):
        self._unpatch_python()
        self._deactivate_frida()
        module = sys.modules.get(API_MODULE)
        if module is not None:
            module._proxy = None

    # --- API module for other plugins ---

    def _install_api(self):
        module = sys.modules.get(API_MODULE)
        if module is None:
            module = types.ModuleType(API_MODULE)
            sys.modules[API_MODULE] = module
        module._proxy = self

        def current():
            proxy = getattr(module, "_proxy", None)
            if proxy is None:
                raise RuntimeError("GreenPass plugin is not loaded")
            return proxy

        def endpoint():
            return dict(current().endpoint() or {})

        def requests_proxies():
            url = PluginProxy.url(current().endpoint())
            return {"http": url, "https": url} if url else {}

        def status():
            proxy = current()
            ep = proxy.endpoint()
            return {"enabled": proxy.enabled(), "available": bool(ep), "endpoint": dict(ep or {}),
                    "proxy_url": PluginProxy.url(ep), "error": proxy.last_error}

        module.endpoint = endpoint
        module.is_available = lambda: bool(current().endpoint())
        module.requests_proxies = requests_proxies
        module.status = status
        module.API_VERSION = 1

    # --- Python socket patch ---

    def _is_own_call(self):
        frame = sys._getframe(1)
        for _ in range(48):
            if frame is None:
                return False
            name = frame.f_code.co_name
            path = os.path.abspath(frame.f_code.co_filename).replace("\\", "/").lower()
            if name not in _SKIP_FRAMES and (path == self._own_file or (self._own_root and path.startswith(self._own_root))):
                return True
            frame = frame.f_back
        return False

    @staticmethod
    def _bypass(host, endpoint):
        h = str(host or "").strip().strip("[]").lower()
        return not h or h in ("localhost", "::1", "0.0.0.0") or h.startswith("127.") or h == endpoint["host"]

    def _socks_connect(self, endpoint, address, timeout=None, source_address=None):
        host, port = address
        sock = self._originals["socket"]((endpoint["host"], endpoint["port"]), timeout, source_address)
        try:
            caller_timeout = sock.gettimeout()
            on_ui = _on_ui_thread()
            if on_ui and (caller_timeout is None or caller_timeout > UI_HANDSHAKE_TIMEOUT_SEC):
                sock.settimeout(UI_HANDSHAKE_TIMEOUT_SEC)
            user, password = endpoint["username"], endpoint["password"]
            if user or password:
                sock.sendall(b"\x05\x01\x02")
                if _recv_exact(sock, 2) != b"\x05\x02":
                    raise OSError("SOCKS auth method rejected")
                ub, pb = user.encode("utf-8")[:255], password.encode("utf-8")[:255]
                sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
                if _recv_exact(sock, 2)[1] != 0:
                    raise OSError("SOCKS auth rejected")
            else:
                sock.sendall(b"\x05\x01\x00")
                if _recv_exact(sock, 2) != b"\x05\x00":
                    raise OSError("SOCKS no-auth rejected")
            for family, atyp in ((socket.AF_INET, b"\x01"), (socket.AF_INET6, b"\x04")):
                try:
                    target = atyp + socket.inet_pton(family, str(host))
                    break
                except OSError:
                    continue
            else:
                name = str(host).encode("idna")[:255]
                target = b"\x03" + bytes([len(name)]) + name
            sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", int(port) & 0xFFFF))
            head = _recv_exact(sock, 4)
            if head[1] != 0:
                raise OSError("SOCKS connect failed: 0x%02x" % head[1])
            rest = {1: 4, 4: 16}.get(head[3])
            if head[3] == 3:
                rest = _recv_exact(sock, 1)[0]
            if rest is None:
                raise OSError("SOCKS reply has invalid address type")
            _recv_exact(sock, rest + 2)
            if on_ui:
                sock.settimeout(caller_timeout)
            return sock
        except BaseException:
            sock.close()
            raise

    def _patch_python(self):
        if "socket" in self._originals:
            return
        proxy = self
        original_socket = socket.create_connection
        self._originals["socket"] = original_socket

        def patched_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *args, **kwargs):
            endpoint = proxy.endpoint()
            if endpoint and not proxy._is_own_call() and not proxy._bypass(address[0], endpoint):
                try:
                    return proxy._socks_connect(endpoint, address, timeout, source_address)
                except OSError:
                    pass
            return original_socket(address, timeout, source_address, *args, **kwargs)

        socket.create_connection = patched_create_connection
        try:
            import urllib3.util.connection as urllib3_connection
        except Exception:
            return
        original_urllib3 = urllib3_connection.create_connection
        self._originals["urllib3"] = original_urllib3

        def patched_urllib3_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
            endpoint = proxy.endpoint()
            if endpoint and not proxy._is_own_call() and not proxy._bypass(address[0], endpoint):
                try:
                    conn = proxy._socks_connect(endpoint, address, timeout, source_address)
                    for option in socket_options or []:
                        conn.setsockopt(*option)
                    return conn
                except OSError:
                    pass
            return original_urllib3(address, timeout, source_address, socket_options)

        urllib3_connection.create_connection = patched_urllib3_create_connection

    def _unpatch_python(self):
        original = self._originals.pop("socket", None)
        if original is not None:
            socket.create_connection = original
        original = self._originals.pop("urllib3", None)
        if original is not None:
            import urllib3.util.connection as urllib3_connection
            urllib3_connection.create_connection = original

    # --- Frida (Java URL connections) ---

    def _register_frida(self, endpoint):
        key = "%s:%s:%d" % (endpoint["source"], endpoint["host"], endpoint["port"])
        try:
            import frida_gadget_api
        except Exception:
            return False
        try:
            if self._frida_key == key:
                if hasattr(frida_gadget_api, "set_plugin_active"):
                    frida_gadget_api.set_plugin_active(FRIDA_ID, True, reason="greenpass_proxy", autoload=True)
                return True
            result = frida_gadget_api.register_script(
                FRIDA_ID, _FRIDA_SCRIPT % (json.dumps(endpoint["host"]), endpoint["port"]),
                name=FRIDA_NAME, replace=True, autoload=True)
            self._frida_key = key if bool((result or {}).get("ok", True)) else ""
            return bool(self._frida_key)
        except Exception as exc:
            self._frida_key = ""
            self.last_error = str(exc)[:180]
            return False

    def _deactivate_frida(self):
        if not self._frida_key:
            return
        self._frida_key = ""
        try:
            import frida_gadget_api
            if hasattr(frida_gadget_api, "set_plugin_active"):
                frida_gadget_api.set_plugin_active(FRIDA_ID, False, reason="greenpass_proxy_off", autoload=True)
        except Exception:
            pass
