"""Point Telegram at the local proxy GreenPass runs, and read what it uses now.

Telegram forks differ: older ones have ProxyInfo(host, port, user, pass, secret)
and a six-argument ConnectionsManager.setProxySettings; newer ones wrap the fields
in ProxySettings. Every call here tries both.
"""

import threading
import time

from .android import on_ui

LOCAL_HOST = "127.0.0.1"
_SETTINGS_CLASSES = ("org.telegram.utils.proxy.ProxySettings", "org.telegram.proxy.ProxySettings")

try:
    from hook_utils import find_class
except Exception:
    find_class = None

try:
    from org.telegram.messenger import MessagesController, NotificationCenter, SharedConfig, UserConfig
    from org.telegram.tgnet import ConnectionsManager
except Exception:                       # outside the app (tests)
    MessagesController = NotificationCenter = SharedConfig = UserConfig = ConnectionsManager = None


def _cls(name):
    if find_class is None:
        return None
    try:
        return find_class(name)
    except Exception:
        return None


def _read(sources, names, default):
    for source in sources:
        for name in names:
            try:
                value = getattr(source, name)
                if callable(value):
                    value = value()
                if value is not None:
                    return value
            except Exception:
                continue
    return default


def proxy_settings_of(proxy):
    """The ProxySettings wrapped by a ProxyInfo on newer forks, else None."""
    if proxy is None:
        return None
    for getter in (lambda: proxy.settings, lambda: proxy.getSettings(),
                   lambda: proxy.getClass().getField("settings").get(proxy)):
        try:
            settings = getter()
            if settings is not None:
                return settings
        except Exception:
            continue
    return None


def proxy_values(proxy):
    """{"address", "port", "username", "password", "secret"} of a ProxyInfo."""
    sources = [s for s in (proxy, proxy_settings_of(proxy)) if s is not None]
    try:
        port = int(_read(sources, ("port", "getPort"), 0) or 0)
    except (TypeError, ValueError):
        port = 0
    return {
        "address": str(_read(sources, ("address", "getAddress"), "") or ""),
        "port": port,
        "username": str(_read(sources, ("username", "user", "getUser"), "") or ""),
        "password": str(_read(sources, ("password", "getPassword"), "") or ""),
        "secret": str(_read(sources, ("secret", "getSecret"), "") or ""),
    }


def _build_settings(host, port, username, password, secret, proxy_type="SOCKS5"):
    for path in _SETTINGS_CLASSES:
        settings_class = _cls(path)
        if settings_class is None:
            continue
        try:
            builder = settings_class.builder()
            builder.setAddress(str(host))
            builder.setPort(int(port))
            builder.setUser(str(username or ""))
            builder.setPassword(str(password or ""))
            builder.setSecret(str(secret or ""))
            type_class = _cls(path + "$Type")
            if type_class is not None:
                try:
                    # The local GreenPass proxy is always set as SOCKS5, MTProto
                    # included, as the old plugin did and testers confirmed working.
                    builder.setType(getattr(type_class, proxy_type))
                except Exception:
                    pass
            return builder.build()
        except Exception:
            continue
    return None


def new_proxy_info(host, port, username="", password="", secret=""):
    info_class = _cls("org.telegram.messenger.SharedConfig$ProxyInfo")
    if info_class is None and SharedConfig is not None:
        info_class = getattr(SharedConfig, "ProxyInfo", None)
    if info_class is None:
        return None
    try:
        return info_class(str(host), int(port), str(username or ""), str(password or ""), str(secret or ""))
    except Exception:
        pass
    settings = _build_settings(host, port, username, password, secret)
    if settings is None:
        return None
    try:
        return info_class(settings)
    except Exception:
        return None


def set_connection_proxy(enabled, proxy=None):
    """Hand the proxy to the native connection layer."""
    if ConnectionsManager is None:
        return False
    if not enabled:
        for args in ((False, None), (False, "", 0, "", "", "")):
            try:
                ConnectionsManager.setProxySettings(*args)
                return True
            except Exception:
                continue
        return False
    settings = proxy_settings_of(proxy)
    if settings is not None:
        try:
            ConnectionsManager.setProxySettings(True, settings)
            return True
        except Exception:
            pass
    v = proxy_values(proxy)
    try:
        ConnectionsManager.setProxySettings(True, v["address"], int(v["port"]), v["username"], v["password"], v["secret"])
        return True
    except Exception:
        return False


def set_native_proxy(enabled, address="", port=0, secret="", proxy_type="SOCKS5"):
    """Native connection proxy without touching the saved proxy list (used by WEB Proxy)."""
    if not enabled:
        return set_connection_proxy(False)
    settings = _build_settings(address, port, "", "", secret, proxy_type)
    if settings is not None:
        try:
            ConnectionsManager.setProxySettings(True, settings)
            return True
        except Exception:
            pass
    try:
        ConnectionsManager.setProxySettings(True, str(address), int(port), "", "", str(secret or ""))
        return True
    except Exception:
        return False


def _proxy_list():
    try:
        proxies = SharedConfig.proxyList
        return [proxies.get(i) for i in range(int(proxies.size()))]
    except Exception:
        try:
            return list(SharedConfig.proxyList or [])
        except Exception:
            return []


def current_proxy():
    try:
        return SharedConfig.currentProxy
    except Exception:
        return None


def is_proxy_enabled():
    try:
        return bool(MessagesController.getGlobalMainSettings().getBoolean("proxy_enabled", False))
    except Exception:
        return False


def logged_in_accounts():
    """Selected account first, then every other activated slot."""
    try:
        accounts = [int(UserConfig.selectedAccount)]
    except Exception:
        accounts = [0]
    try:
        count = int(UserConfig.MAX_ACCOUNT_COUNT)
    except Exception:
        count = 0
    for slot in range(count):
        if slot in accounts:
            continue
        try:
            if UserConfig.getInstance(slot).isClientActivated():
                accounts.append(slot)
        except Exception:
            continue
    return accounts


def notify_proxy_changed():
    def post():
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
    if NotificationCenter is not None:
        on_ui(post, 300)


class LocalProxy:
    """The one local proxy entry GreenPass keeps in Telegram, and which mode owns it."""

    def __init__(self, on_change=None):
        self._lock = threading.RLock()
        self.owner = ""
        self.port = 0
        self._on_change = on_change

    def apply(self, owner, port, username="", password="", secret="", calls=False):
        """Make 127.0.0.1:port the active Telegram proxy for owner. Returns True on success."""
        port = int(port or 0)
        if port <= 0 or not owner:
            return False
        with self._lock:
            ok = self._write(True, port, str(username or ""), str(password or ""), str(secret or ""),
                             bool(calls and not secret))
            if ok:
                self.owner, self.port = owner, port
            self._changed()
            return ok

    def clear(self, owner=None, port=None):
        """Turn the local proxy off, unless another mode owns it now."""
        with self._lock:
            if owner and self.owner and self.owner != owner:
                return False
            if port and self.port and self.port != int(port):
                return False
            ok = self._write(False, 0, "", "", "", False)
            if ok:
                self.owner, self.port = "", 0
            self._changed()
            return ok

    def is_applied(self, owner, port, username=None, password=None, secret=None):
        """True when Telegram uses 127.0.0.1:port right now and owner holds it."""
        port = int(port or 0)
        if port <= 0:
            return False
        with self._lock:
            if self.owner and self.owner != owner:
                return False
        v = proxy_values(current_proxy())
        if v["address"] != LOCAL_HOST or v["port"] != port:
            return False
        for key, expected in (("username", username), ("password", password), ("secret", secret)):
            if expected is not None and v[key] != str(expected):
                return False
        try:
            prefs = MessagesController.getGlobalMainSettings()
            return (prefs.getBoolean("proxy_enabled", False)
                    and str(prefs.getString("proxy_ip", "") or "") == LOCAL_HOST
                    and int(prefs.getInt("proxy_port", 0) or 0) == port)
        except Exception:
            return False

    def _changed(self):
        if self._on_change is not None:
            try:
                self._on_change()
            except Exception:
                pass

    def _write(self, enable, port, username, password, secret, calls):
        if SharedConfig is None:
            return False
        try:
            SharedConfig.loadProxyList()
        except Exception:
            pass
        try:
            editor = MessagesController.getGlobalMainSettings().edit()
        except Exception:
            editor = None

        proxy = None
        if enable:
            wanted = {"address": LOCAL_HOST, "port": port, "username": username,
                      "password": password, "secret": secret}
            # Keep one matching local row and drop stale ones left by other modes.
            for item in _proxy_list():
                values = proxy_values(item)
                if values["address"] != LOCAL_HOST:
                    continue
                if values == wanted and proxy is None:
                    proxy = item
                else:
                    try:
                        SharedConfig.deleteProxy(item)
                    except Exception:
                        pass
            if proxy is None:
                proxy = self._add_row(new_proxy_info(LOCAL_HOST, port, username, password, secret), wanted)
            if proxy is None:
                return False
            try:
                SharedConfig.currentProxy = proxy
                SharedConfig.proxyEnabled = True
            except Exception:
                pass
            if editor is not None:
                saved = False
                settings = proxy_settings_of(proxy)
                if settings is not None:
                    try:
                        settings.toSharedPreferences(editor)
                        saved = True
                    except Exception:
                        pass
                if not saved:
                    editor.putString("proxy_ip", LOCAL_HOST)
                    editor.putInt("proxy_port", port)
                    editor.putString("proxy_user", username)
                    editor.putString("proxy_pass", password)
                    editor.putString("proxy_secret", secret)
                    editor.putInt("proxy_type", 0)
        else:
            try:
                SharedConfig.proxyEnabled = False
            except Exception:
                pass

        if editor is not None:
            editor.putBoolean("proxy_enabled", bool(enable))
            for key in ("proxy_enabled_calls", "proxy_calls_enabled", "calls_use_proxy"):
                editor.putBoolean(key, bool(calls))
            try:
                editor.commit()
            except Exception:
                try:
                    editor.apply()
                except Exception:
                    pass
        for save in ("saveProxyList", "saveConfig"):
            try:
                getattr(SharedConfig, save)()
            except Exception:
                pass
        ok = set_connection_proxy(enable, proxy)
        notify_proxy_changed()
        return ok

    def _add_row(self, proxy, wanted):
        if proxy is None:
            return None
        try:
            added = SharedConfig.addProxy(proxy)
            if added is not None and proxy_values(added) == wanted:
                return added
        except Exception:
            pass
        # Forks differ on what addProxy returns and when proxyList is replaced.
        for item in _proxy_list():
            if proxy_values(item) == wanted:
                return item
        try:
            SharedConfig.proxyList.add(proxy)
        except Exception:
            pass
        return proxy


class NetworkPause:
    """Pauses every account's connection while the proxy switches, so no request
    leaks outside the proxy. Each pause() returns a lease; the network resumes
    when the last lease is released, or after a failsafe timeout."""

    FAILSAFE_SEC = 2.5

    def __init__(self):
        self._lock = threading.Lock()
        self._leases = set()
        self._next = 1
        self._paused_accounts = []

    def pause(self):
        with self._lock:
            lease = self._next
            self._next += 1
            first = not self._leases
            self._leases.add(lease)
        if first:
            self._set_paused(True)
        threading.Timer(self.FAILSAFE_SEC, self.release, args=(lease,)).start()
        return lease

    def release(self, lease, delay_sec=0.0):
        if lease is None:
            return
        if delay_sec > 0:
            threading.Timer(delay_sec, self.release, args=(lease,)).start()
            return
        with self._lock:
            if lease not in self._leases:
                return
            self._leases.discard(lease)
            last = not self._leases
        if last:
            self._set_paused(False)

    def release_all(self):
        with self._lock:
            had = bool(self._leases)
            self._leases.clear()
        if had:
            self._set_paused(False)

    def _set_paused(self, paused):
        if ConnectionsManager is None:
            return
        if paused:
            accounts = logged_in_accounts()
            self._paused_accounts = list(accounts)
        else:
            accounts, self._paused_accounts = self._paused_accounts, []
            # In background the app pauses its own connections and resumes them
            # itself on return; resuming here would override that.
            from .android import is_app_paused
            if is_app_paused():
                return
        for account in accounts:
            try:
                ConnectionsManager.getInstance(account).setAppPaused(bool(paused), False)
            except Exception:
                continue


def wait_until(check, timeout_sec, step_sec=0.1):
    deadline = time.monotonic() + float(timeout_sec)
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(step_sec)
    return bool(check())
