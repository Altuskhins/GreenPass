import base64
import re
import threading
import zlib

from base_plugin import BasePlugin, MethodHook
from java import jclass
from org.telegram.messenger import ApplicationLoader
from .foundation import _set_native_proxy_settings, _set_tg_proxy_enabled
from .webproxy_payload import DEX_PAYLOAD_ZLIB_B64


def raw_class(name):
    # forName raises ClassNotFoundException on clients without the class; callers
    # expect None ("class absent") rather than an exception.
    try:
        return jclass("java.lang.Class").forName(name)
    except Exception:
        return None


def _client_supports_webproxy():
    try:
        version = str(jclass("org.telegram.messenger.BuildVars").BUILD_VERSION_STRING)
        parts = [int(x) for x in re.findall(r"\d+", version)[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts) >= (12, 9, 0)
    except Exception:
        return True


CharSequence = jclass("java.lang.CharSequence")


def _methods_by_name(cls, *names):
    """Declared methods of cls grouped by the wanted names, or None without cls."""
    if cls is None:
        return None
    found = {name: [] for name in names}
    for method in cls.getDeclaredMethods():
        bucket = found.get(str(method.getName()))
        if bucket is not None:
            bucket.append(method)
    return found


__id__ = "wp"
__name__ = "WEB Proxy"
__description__ = "Ээээ короч диплинки там локал протик ещё какая-то хуйня типа крутяк ок"
__author__ = "@la_cringe | @dmkrjplug"
__version__ = "2.1b"
__icon__ = "akresloh/0"
__app_version__ = ">=12.9.0"
__sdk_version__ = ">=1.4.5.3"

ENTRY_CLASS = "com.extera.webproxy.NativeWebProxyCore"
BuildVersion = jclass("android.os.Build$VERSION")

LINK_PATTERN = re.compile(
    r"^(?:tg://webproxy\?|tg:webproxy\?"
    r"|https?://(?:t\.me|telegram\.me|telegram\.dog)/webproxy\?)(.+)$",
    re.IGNORECASE,
)


class Dex:
    def __init__(self, entry_class):
        self.entry_class = entry_class
        self.clazz = None
        self.loaded = False

    def load(self):
        if self.loaded:
            return
        if self.clazz is None:
            context = ApplicationLoader.applicationContext
            if context is None:
                raise RuntimeError("application context is not ready")
            if BuildVersion.SDK_INT < 26:
                raise RuntimeError("embedded DEX requires Android API 26+")
            ByteBuffer = jclass("java.nio.ByteBuffer")
            Loader = jclass("dalvik.system.InMemoryDexClassLoader")
            loader = Loader(ByteBuffer.wrap(self._read_payload()), context.getClassLoader())
            self.clazz = loader.loadClass(self.entry_class)
        try:
            self.invoke("load")
            self.loaded = True
        except Exception:
            try:
                self.invoke("unload")
            except Exception:
                pass
            self.loaded = False
            raise

    def unload(self):
        try:
            if self.loaded and self.clazz is not None:
                self.invoke("unload")
        finally:
            self.loaded = False

    def invoke(self, name, *args):
        if self.clazz is None:
            raise RuntimeError("embedded DEX is not loaded")
        matches = []
        for method in self.clazz.getDeclaredMethods():
            if str(method.getName()) == name and len(method.getParameterTypes()) == len(args):
                method.setAccessible(True)
                matches.append(method)
        if len(matches) != 1:
            raise RuntimeError("DEX method unavailable: %s/%s" % (name, len(args)))
        try:
            return matches[0].invoke(None, *args)
        except Exception as error:
            cause = None
            try:
                cause = error.getCause()
            except Exception:
                pass
            raise RuntimeError(str(cause) if cause is not None else str(error))

    def _read_payload(self):
        try:
            raw = zlib.decompress(base64.b64decode(DEX_PAYLOAD_ZLIB_B64))
        except Exception as error:
            raise RuntimeError("embedded DEX decode failed: %s" % error)
        if raw[:4] != b"dex\n":
            raise RuntimeError("embedded DEX payload is invalid")
        return raw

class ProxyIntentHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def before_hooked_method(self, param):
        intent = None
        for value in param.args or []:
            try:
                if str(value.getClass().getName()) == "android.content.Intent":
                    intent = value
                    break
            except Exception:
                continue
        if intent is None:
            return
        try:
            data = intent.getData()
            if data is None:
                return
            parsed = self.plugin.parse_link(str(data))
        except Exception:
            return
        if parsed is None:
            return
        server, secret, server_port = parsed
        server_full = server if server_port == 443 else "%s:%d" % (server, server_port)
        try:
            local = self.plugin.start_adapter(server_full, secret)
        except Exception as error:
            self.plugin.log("WEB proxy link failed: %s" % error)
            try:
                param.setResult(True)
            except Exception:
                pass
            return
        # Anything below must never propagate into AndroidUtilities.handleProxyIntent:
        # on failure the intent is left as it was and Telegram handles the link itself.
        try:
            port, local_secret = local
            Uri = jclass("android.net.Uri")
            intent.setData(Uri.parse(
                "tg://proxy?server=127.0.0.1&port=%d&secret=dd%s" % (port, local_secret)
            ))
            self.plugin.dex.invoke(
                "upsertEntry", ApplicationLoader.applicationContext, server_full, secret)
            self.plugin.pending_display = (server, port, local_secret, secret, server_port)
            self.plugin._pending_rows = 0
        except Exception as error:
            try:
                self.plugin.log("WEB proxy intent rewrite failed: %s" % error)
            except Exception:
                pass


class SettingsCreateViewHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def after_hooked_method(self, param):
        try:
            self.plugin.dex.invoke("injectThirdType", param.thisObject)
        except Exception as error:
            self.plugin.log("WEB radio inject failed: %s" % error)

        # Restore the WEB type/radio for a saved loopback entry INDEPENDENT of whether the
        # third radio cell was just injected: stock's createView always ends with
        # setProxyType(secret empty?0:1, false) which lands on MTProto for dd-secret entries.
        def try_restore():
            try:
                self.plugin.dex.invoke("restoreWebEditState", param.thisObject)
            except Exception as error:
                self.plugin.log("WEB edit restore failed: %s" % error)

        try_restore()
        from android_utils import run_on_ui_thread
        run_on_ui_thread(try_restore, 400)
        run_on_ui_thread(try_restore, 1200)


class ProxyTypeHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def after_hooked_method(self, param):
        try:
            requested = int(param.args[0])
        except Exception:
            return
        try:
            animated = bool(param.args[1]) if len(param.args) > 1 else True
        except Exception:
            animated = True
        if not animated:
            return
        try:
            self.plugin.dex.invoke("onProxyTypeSelected", param.thisObject, requested)
        except Exception as error:
            self.plugin.log("WEB type handling failed: %s" % error)


class SaveProxyHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def before_hooked_method(self, param):
        try:
            info = param.args[0]
            if info is None:
                return
            rewritten = bool(self.plugin.dex.invoke("rewriteForWeb", info))
            if rewritten:
                self.plugin.log("WEB Proxy: entry redirected to loopback adapter")
            else:
                addr = ''
                secret = ''
                try:
                    addr = str(info.getClass().getField('address').get(info))
                    secret = str(info.getClass().getField('secret').get(info))
                except Exception:
                    pass
                self.plugin.log("WEB rewrite skipped addr=%s secret=%s" % (addr, secret))
        except Exception as error:
            self.plugin.log("WEB rewrite failed: %s" % error)

    def after_hooked_method(self, param):
        try:
            named = bool(self.plugin.dex.invoke("applyWebNaming", param.getResult()))
            if named:
                self.plugin.log("WEB Proxy: entry titled with relay domain")
        except Exception as error:
            self.plugin.log("WEB naming failed: %s" % error)


class DisplayNameHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def after_hooked_method(self, param):
        try:
            result = param.getResult()
            replacement = self.plugin.dex.invoke(
                "displayNameHook", param.args[0], "" if result is None else str(result))
            if replacement:
                param.setResult(replacement)
        except Exception:
            pass


class TypeNameHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def after_hooked_method(self, param):
        try:
            result = param.getResult()
            replacement = self.plugin.dex.invoke(
                "typeNameHook", param.args[0], "" if result is None else str(result))
            if replacement:
                param.setResult(replacement)
        except Exception:
            pass


class CheckProxyHook(MethodHook):
    """WEB check runs as a real native MTProto connection through the loopback adapter.

    We intercept stock checkProxy only so that WEB rows resolve to a real end-to-end
    round-trip in the adapter instead of stocks' raw loopback counter-part. Stock
    native_checkProxy(127.0.0.1:port, dd-secret) performs the client side of the MTProxy
    obfuscated2 handshake; our adapter completes it (obfuscated2 + relay session + data
    echo), so the measured RTT is genuine and the shared relay session is warmed for an
    immediate first connection.
    """
    def __init__(self, plugin):
        self.plugin = plugin

    def before_hooked_method(self, param):
        # Nothing to redirect: WEB rows are loopback 127.0.0.1 + dd-secret, which routes
        # straight into our adapter. Let the native call run and report the real latency.
        pass



class DeleteProxyHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def before_hooked_method(self, param):
        try:
            info = param.args[0]
            if info is None:
                return
            self.plugin.dex.invoke("deleteWebEntry", info)
        except Exception as error:
            self.plugin.log("WEB entry cleanup failed: %s" % error)


class ShareLinkHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def after_hooked_method(self, param):
        try:
            result = param.getResult()
            if result is None:
                return
            replacement = self.plugin.dex.invoke(
                "shareLinkHook", param.args[0], str(result))
            if replacement and replacement != str(result):
                param.setResult(replacement)
        except Exception:
            pass



class SheetRowHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def before_hooked_method(self, param):
        pending = getattr(self.plugin, 'pending_display', None)
        if not pending or len(param.args) < 2:
            return
        try:
            server, port, local_secret, web_secret, server_port = pending
            label = '' if param.args[0] is None else str(param.args[0])
            value = param.args[1]
            if value is None:
                return
            text = str(value)
            labels = self.plugin.proxy_type_labels()
            row = self.plugin.pending_row_index()
            is_type_row = (row == 0) or (labels and label in labels)
            self.plugin.pending_row_advance()
            if is_type_row:
                param.args[1] = 'WEB'
            elif label and label == self.plugin.port_label():
                param.args[1] = str(server_port)
            elif text == '127.0.0.1':
                param.args[1] = server
            elif text == str(port):
                param.args[1] = str(server_port)
            elif local_secret and text in ('dd' + local_secret, local_secret):
                param.args[1] = web_secret or value
        except Exception:
            pass


class CountryHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin
        # Overlapping requestProxyCountry calls must not share one slot: a lost
        # stash would leave a persisted ProxyInfo.address as the relay domain.
        self._restores = {}
        self._restores_lock = threading.Lock()

    def before_hooked_method(self, param):
        try:
            info = param.args[0]
            if info is None:
                return
        except Exception:
            return
        try:
            server = self.plugin.dex.invoke("webServerFor", info)
            if not server:
                return
            # Temporarily resolve country against the REAL relay domain, not the loopback
            # address: stock's getProxyCountryKey(address) would reject 127.0.0.1 as local
            # and show Unknown. The key is extracted SYNCHRONOUSLY at the top of stock's
            # method (verified against the 12.9.0 decompile), so the mutation only needs to
            # span the call itself - after_hooked_method restores the original address.
            # Without the restore, a PERSISTED list record was left with address=domain and
            # any later saveProxyList wrote "domain:localPort" into it - tgnet then dialed
            # the relay domain on the local adapter port forever ("connected once, then
            # connects never again", invisible to restore/migrate which require 127.0.0.1).
            field = info.getClass().getField('address')
            stash = (info, field, str(field.get(info)))
            with self._restores_lock:
                self._restores[id(param)] = stash
            try:
                field.set(info, server)
            except Exception:
                with self._restores_lock:
                    self._restores.pop(id(param), None)
                try:
                    field.set(info, stash[2])
                except Exception:
                    pass
        except Exception:
            with self._restores_lock:
                self._restores.pop(id(param), None)

    def after_hooked_method(self, param):
        with self._restores_lock:
            stash = self._restores.pop(id(param), None)
        if not stash:
            return
        try:
            stash[1].set(stash[0], stash[2])
        except Exception:
            pass


class SheetCloseHook(MethodHook):
    def __init__(self, plugin):
        self.plugin = plugin

    def after_hooked_method(self, param):
        pending = getattr(self.plugin, 'pending_display', None)
        self.plugin.pending_display = None
        if not pending:
            return
        # B1: this fires when the sheet is shown, not dismissed - schedule a late
        # orphan sweep instead of tearing the preview down while it is on screen.
        # The DEX side keeps anything that got saved or connected in the meantime.
        try:
            server, port, local_secret = pending[0], pending[1], pending[2]
            self.plugin.dex.invoke("schedulePreviewDiscard", port, server, local_secret)
        except Exception:
            pass



class WebProxyNativePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.dex = Dex(ENTRY_CLASS)
        self.hooks = []
        self.pending_display = None
        self._type_labels = None
        self._country_label = None
        self._port_label = None
        self._pending_rows = 0

    def proxy_type_labels(self):
        if self._type_labels is None:
            self._type_labels = tuple(self.localized_field_labels(["ProxyType"]))
        return self._type_labels

    def country_label(self):
        if self._country_label is None:
            labels = self.localized_field_labels(["Country"])
            self._country_label = labels[0] if labels else ''
        return self._country_label

    def port_label(self):
        if self._port_label is None:
            labels = self.localized_field_labels(["UseProxyPort"])
            self._port_label = labels[0] if labels else ''
        return self._port_label

    def localized_field_labels(self, names):
        labels = []
        try:
            locale = raw_class("org.telegram.messenger.LocaleController")
            lazy_meta = None
            for m in locale.getDeclaredMethods():
                if str(m.getName()) != "getString" or len(m.getParameterTypes()) != 1:
                    continue
                if str(m.getParameterTypes()[0]) != "int":
                    continue
                m.setAccessible(True)
                lazy_meta = m
                break
            label = ''
            if lazy_meta is not None:
                for name in names:
                    try:
                        string_id = raw_class("org.telegram.R$string").getField(name).get(None)
                        label = str(lazy_meta.invoke(None, string_id))
                        if label:
                            labels.append(label)
                            break
                    except Exception:
                        continue
        except Exception:
            pass
        if not labels:
            try:
                resources = ApplicationLoader.applicationContext.getResources()
                for name in names:
                    try:
                        string_id = raw_class("org.telegram.R$string").getField(name).get(None)
                        label = str(resources.getString(string_id))
                        if label:
                            labels.append(label)
                            break
                    except Exception:
                        continue
            except Exception:
                pass
        return tuple(dict.fromkeys(labels))

    def pending_row_index(self):
        return self._pending_rows

    def pending_row_advance(self):
        self._pending_rows += 1

    def on_plugin_load(self):
        if not _client_supports_webproxy():
            self.log("WEB proxy needs client >= 12.9.0, skipped")
            return
        self.dex.load()
        try:
            self.install_hooks()
        except Exception:
            # Roll back a partial load (DEX loaded, some hooks installed) before failing.
            try:
                self.on_plugin_unload()
            except Exception:
                pass
            raise
        try:
            restored = int(self.dex.invoke(
                "restoreEntries", ApplicationLoader.applicationContext))
            if restored:
                self.log("WEB proxy: restored %d relay(s)" % restored)
        except Exception as error:
            self.log("WEB proxy restore failed: %s" % error)
        try:
            # Live 10s ping of the active WEB proxy (native-level status: Connected/Ping on
            # the list row + pill/drawer), like stock ProxyPingController.
            self.dex.invoke("startLivePing")
        except Exception as error:
            self.log("WEB proxy live ping start failed: %s" % error)

    def on_plugin_unload(self):
        for hook in self.hooks:
            try:
                self.unhook_method(hook)
            except Exception:
                pass
        self.hooks = []
        try:
            ours_active = bool(self.dex.invoke("isOurLoopbackActive"))
        except Exception:
            ours_active = False
        try:
            self.dex.invoke("stopAll")
        except Exception:
            pass
        if ours_active:
            # Prefs + native: Telegram persists the active proxy, so a native-only
            # disable would leave a dead loopback adapter selected for the next start.
            try:
                _set_tg_proxy_enabled(False)
            except Exception:
                self.apply_native(False, 0, "")
        try:
            self.dex.unload()
        except Exception:
            pass

    def install_hooks(self):
        # One getDeclaredMethods() pass per class: every getName() is a JNI
        # round trip and AndroidUtilities alone has well over a thousand methods.
        utils = _methods_by_name(raw_class("org.telegram.messenger.AndroidUtilities"),
                                 "handleProxyIntent", "showProxyAlert")
        if utils is None:
            raise RuntimeError("AndroidUtilities not found")
        installed = 0
        for method in utils["handleProxyIntent"]:
            if self._hook(method, ProxyIntentHook(self)):
                installed += 1
        if installed == 0:
            raise RuntimeError("handleProxyIntent hook not installed")

        settings = _methods_by_name(raw_class("org.telegram.ui.ProxySettingsActivity"),
                                    "createView", "setProxyType")
        if settings is not None:
            for method in settings["createView"]:
                if len(method.getParameterTypes()) == 1:
                    self._hook(method, SettingsCreateViewHook(self))
            for method in settings["setProxyType"]:
                self._hook(method, ProxyTypeHook(self))

        controller = _methods_by_name(
            raw_class("com.exteragram.messenger.proxy.ProxyController"),
            "saveProxy", "buildShareLink", "deleteProxy", "getDisplayName",
            "getProxyTypeName", "requestProxyCountry") or {}
        for method in controller.get("saveProxy", ()):
            types = method.getParameterTypes()
            if len(types) == 3 and str(types[0]).endswith("SharedConfig$ProxyInfo"):
                self._hook(method, SaveProxyHook(self))

        cm = _methods_by_name(raw_class("org.telegram.tgnet.ConnectionsManager"), "checkProxy")
        if cm is not None:
            string_cls = jclass("java.lang.String")
            for method in cm["checkProxy"]:
                types = method.getParameterTypes()
                if len(types) == 6 and types[0] == string_cls:
                    self._hook(method, CheckProxyHook(self))

        for method in controller.get("buildShareLink", ()):
            types = method.getParameterTypes()
            if len(types) >= 1 and str(types[0]).endswith("SharedConfig$ProxyInfo"):
                self._hook(method, ShareLinkHook(self))

        table_view = _methods_by_name(raw_class("org.telegram.ui.Components.TableView"), "addRow")
        if table_view is not None:
            for method in table_view["addRow"]:
                types = method.getParameterTypes()
                if len(types) >= 2 and types[0] == CharSequence and types[1] == CharSequence:
                    self._hook(method, SheetRowHook(self))

        for method in utils["showProxyAlert"][:1]:
            self._hook(method, SheetCloseHook(self))

        for method in controller.get("deleteProxy", ()):
            types = method.getParameterTypes()
            if len(types) == 1 and str(types[0]).endswith("SharedConfig$ProxyInfo"):
                self._hook(method, DeleteProxyHook(self))

        for method_name, hook_cls in (("getDisplayName", DisplayNameHook), ("getProxyTypeName", TypeNameHook)):
            for method in controller.get(method_name, ()):
                if len(method.getParameterTypes()) == 1:
                    self._hook(method, hook_cls(self))

        for method in controller.get("requestProxyCountry", ()):
            types = method.getParameterTypes()
            if len(types) == 2 and str(types[0]).endswith("SharedConfig$ProxyInfo"):
                self._hook(method, CountryHook(self))

    def _hook(self, method, hook):
        handle = self.hook_method(method, hook)
        if handle is not None:
            self.hooks.append(handle)
        return handle is not None

    def parse_link(self, value):
        match = LINK_PATTERN.match((value or "").strip())
        if not match:
            return None
        fields = {}
        for pair in match.group(1).split("&"):
            key, separator, data = pair.partition("=")
            if separator:
                fields[key.lower()] = data.strip()
        server = fields.get("server") or fields.get("host") or ""
        secret = (fields.get("secret") or "").lower()
        # B4: split an inline "host:port" tail BEFORE the hostname check. The regex below
        # has no ':' in its class, so the old post-regex fallback was dead code and any
        # share link carrying "server=host:port" was rejected outright.
        server_port = 443
        port_raw = fields.get("server_port")
        if port_raw:
            try:
                server_port = int(port_raw)
            except ValueError:
                pass
        if ':' in server:
            host_part, _, port_part = server.rpartition(':')
            try:
                maybe = int(port_part)
                if 1 <= maybe <= 65535:
                    server = host_part
                    if server_port == 443:
                        server_port = maybe
            except ValueError:
                pass
        if not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", server):
            return None
        if not re.match(r"^(?:dd)?[0-9a-f]{32}$", secret):
            return None
        return server, secret, server_port

    def start_adapter(self, server, secret):
        result = str(self.dex.invoke("prepare", server, secret))
        if result.startswith("error:"):
            raise RuntimeError(result[6:])
        port, _, local_secret = result.partition(":")
        return int(port), local_secret

    def apply_native(self, enabled, port, secret):
        try:
            _set_native_proxy_settings(
                bool(enabled),
                address="127.0.0.1",
                port=int(port or 0),
                secret=str(secret or ""),
                proxy_type="MTPROTO",
            )
        except Exception as error:
            self.notify("Could not apply proxy: %s" % error)
