"""Java method hooks GreenPass installs into Telegram.

Each hook only forwards to the plugin (`gp`); hooks are installed once per
plugin load and do nothing after unload (gp.active is False).
"""

import time

from base_plugin import MethodHook

from . import links

try:
    from hook_utils import find_class
except Exception:
    find_class = None

try:
    from org.telegram.messenger import MessagesController, NotificationCenter
    from org.telegram.tgnet import ConnectionsManager
except Exception:
    MessagesController = NotificationCenter = ConnectionsManager = None

AWG_FILE_PICKER_REQ = 13371
IMPORT_FILE_PICKER_REQ = 13372
_LINK_SCHEMES = tuple(links.SCHEMES) + ("wdtt", "qwdtt", "olcrtc")


def _cls(name):
    try:
        return find_class(name) if find_class is not None else None
    except Exception:
        return None


def _field(obj, name):
    field = obj.getClass().getDeclaredField(name)
    field.setAccessible(True)
    return field


def show_proxy_button(dialogs_activity):
    """Keep the shield in the chat list visible and in sync with the proxy state."""
    try:
        from android.view import View
        _field(dialogs_activity, "proxyItem").get(dialogs_activity).setVisibility(View.VISIBLE)
    except Exception:
        pass
    try:
        _field(dialogs_activity, "proxyItemVisible").setBoolean(dialogs_activity, True)
    except Exception:
        pass
    try:
        drawable = _field(dialogs_activity, "proxyDrawable").get(dialogs_activity)
        state = _field(dialogs_activity, "currentConnectionState").getInt(dialogs_activity)
        from .telegram import is_proxy_enabled
        connected = state in (ConnectionsManager.ConnectionStateConnected, ConnectionsManager.ConnectionStateUpdating)
        drawable.setConnected(is_proxy_enabled(), connected, False)
    except Exception:
        pass


def add_link_spans(spannable, text=None):
    """Make proxy links in a message clickable. Returns how many spans were added."""
    if spannable is None or not hasattr(spannable, "setSpan"):
        return 0
    text = str(text if text is not None else spannable)
    try:
        from android.text import Spanned
        from android.text.style import URLSpan
        flags = int(Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    except Exception:
        return 0
    added = 0
    for start, end, link in links.find_links(text):
        covered = False
        for span in list(spannable.getSpans(start, end, URLSpan) or []):
            url = str(span.getURL() or "").lower()
            if spannable.getSpanStart(span) <= start and spannable.getSpanEnd(span) >= end and \
                    url.startswith(_LINK_SCHEMES + ("tg://ws", "tg://relay", "https://hvpn", "https://hitray", "hitvpn")):
                covered = True
                break
        if not covered:
            try:
                spannable.setSpan(URLSpan(link), start, end, flags)
                added += 1
            except Exception:
                pass
    return added


class _Hook(MethodHook):
    def __init__(self, gp, before=None, after=None):
        self.gp, self._before, self._after = gp, before, after

    def before_hooked_method(self, param):
        if self._before is not None and self.gp.active:
            try:
                self._before(param)
            except Exception:
                pass

    def after_hooked_method(self, param):
        if self._after is not None and self.gp.active:
            try:
                self._after(param)
            except Exception:
                pass


class Hooks:
    def __init__(self, gp):
        self.gp = gp                       # the plugin: hook_all_methods, hook_method, handlers
        self._installed = set()
        self._pause_leases = {}

    def _hook_all(self, key, class_name, methods, hook):
        if key in self._installed:
            return
        cls = _cls(class_name)
        if cls is None:
            return
        for method in methods:
            try:
                self.gp.hook_all_methods(cls, method, hook)
                self._installed.add(key)
            except Exception:
                continue

    def install(self):
        gp = self.gp
        on_button = _Hook(gp, after=lambda p: gp.app.wants_running() and show_proxy_button(p.thisObject))
        self._hook_all("button", "org.telegram.ui.DialogsActivity", ("updateProxyButton", "showSearch", "showDoneItem"), on_button)
        self._hook_all("notify", "org.telegram.messenger.NotificationCenter", ("postNotificationName",),
                       _Hook(gp, after=self._on_notification))
        self._hook_all("killswitch", "org.telegram.tgnet.ConnectionsManager", ("setProxySettings",),
                       _Hook(gp, before=self._pause_network, after=self._resume_network))
        self._hook_all("ipv6", "org.telegram.tgnet.ConnectionsManager", ("checkConnection",),
                       _Hook(gp, after=lambda p: gp.ipv6_enabled() or gp.force_ipv4()))
        self._hook_all("browser", "org.telegram.messenger.browser.Browser", ("openUrl",), _Hook(gp, before=self._open_url))
        self._hook_all("relay-intent", "org.telegram.ui.LaunchActivity", ("handleIntent",), _Hook(gp, before=self._relay_intent))
        self._hook_all("text", "org.telegram.messenger.AndroidUtilities", ("addLinksSafe", "addLinks"),
                       _Hook(gp, after=lambda p: p.args and links.contains_link(str(p.args[0] or "")) and add_link_spans(p.args[0])))
        cell_hook = _Hook(gp, after=self._message_cell)
        self._hook_all("cell", "org.telegram.ui.Cells.ChatMessageCell", ("setMessageObject",), cell_hook)
        self._hook_all("action-cell", "org.telegram.ui.Cells.ChatActionCell", ("setMessageObject",), cell_hook)
        self._hook_all("file", "org.telegram.messenger.AndroidUtilities", ("openForView",), _Hook(gp, before=self._open_file))
        self._hook_all("webrtc", "org.telegram.messenger.voip.NativeInstance", ("setJoinResponsePayload",),
                       _Hook(gp, before=self._rewrite_join))
        endpoint_class = _cls("org.telegram.messenger.voip.Instance$Endpoint")
        if endpoint_class is not None:
            self._hook_all("voip", "org.telegram.messenger.voip.Instance", ("makeInstance",),
                           _Hook(gp, before=lambda p: len(p.args) >= 4 and gp.relay.rewrite_endpoints(p.args[3], endpoint_class)))
        self._install_activity_result()

    def _install_activity_result(self):
        if "activity" in self._installed:
            return
        try:
            from java.lang import Integer
            launch = _cls("org.telegram.ui.LaunchActivity")
            intent = _cls("android.content.Intent")
            method = launch.getClass().getDeclaredMethod("onActivityResult", Integer.TYPE, Integer.TYPE, intent)
            self.gp.hook_method(method, _Hook(self.gp, before=self._activity_result))
            self._installed.add("activity")
        except Exception:
            pass

    # --- handlers ---

    def _on_notification(self, param):
        event = int(param.args[0]) if param.args else -1
        if event == int(getattr(NotificationCenter, "didUpdateConnectionState", -2)):
            self.gp.app.apply_network_policy_async()
        elif event == int(NotificationCenter.proxySettingsChanged):
            self.gp.on_telegram_proxy_changed()

    def _pause_network(self, param):
        # Pause every connection while Telegram switches proxies, so nothing
        # leaks out directly between the old and the new setting.
        if param.args and len(param.args) >= 2:
            self._pause_leases[id(param)] = self.gp.app.network_pause.pause()

    def _resume_network(self, param):
        lease = self._pause_leases.pop(id(param), None)
        if lease is not None:
            self.gp.app.network_pause.release(lease, 0.12)

    def _open_url(self, param):
        for arg in list(param.args or []):
            url = links.first_import_link(arg) if isinstance(arg, str) else ""
            if not url and hasattr(arg, "getScheme"):
                text = str(arg.toString() or "")
                if str(arg.getScheme() or "").lower() in _LINK_SCHEMES or text.lower().startswith(("qwdtt:config?", "tg://ws", "tg://relay?")):
                    url = text
                else:
                    url = links.first_import_link(text)
            if url:
                from .android import on_ui
                on_ui(lambda: self.gp.handle_link(url, confirm=True))
                param.setResult(None)
                return

    def _relay_intent(self, param):
        intent = param.args[0] if param.args else None
        if intent is None or str(intent.getAction()) != "android.intent.action.VIEW":
            return
        uri = str(intent.getData() or "")
        if uri.lower().startswith("tg://relay?"):
            param.setResult(None)
            from .android import on_ui
            on_ui(lambda: self.gp.handle_link(uri))

    def _message_cell(self, param):
        message = param.args[0] if param.args else None
        if message is None:
            return
        added = 0
        for attr in ("messageText", "caption", "linkDescription"):
            value = getattr(message, attr, None)
            if value is not None:
                added += add_link_spans(value)
        if added:
            param.thisObject.invalidate()

    def _open_file(self, param):
        if param.args and self.gp.open_document(param.args[0]):
            param.setResult(False)

    def _rewrite_join(self, param):
        if param.args:
            param.args[0] = self.gp.relay.rewrite_group_call_join(param.args[0])

    def _activity_result(self, param):
        if len(param.args or []) < 3:
            return
        request, result, data = int(param.args[0]), int(param.args[1]), param.args[2]
        if result != -1 or data is None or data.getData() is None:
            return
        if request in (AWG_FILE_PICKER_REQ, IMPORT_FILE_PICKER_REQ):
            self.gp.on_file_picked(request, data.getData())


def hide_proxy_sponsor():
    """Hide the "proxy sponsor" chat Telegram pins when a proxy is used."""
    try:
        from org.telegram.messenger import UserConfig
        prefs = MessagesController.getGlobalMainSettings()
        if int(prefs.getLong("proxy_dialog", 0)) == 0 or \
                int(prefs.getInt("promo_dialog_type", -1)) != int(getattr(MessagesController, "PROMO_TYPE_PROXY", 0)):
            return
        for account in range(int(UserConfig.MAX_ACCOUNT_COUNT)):
            controller = MessagesController.getInstance(account)
            if controller is not None and hasattr(controller, "hidePromoDialog"):
                try:
                    controller.hidePromoDialog()
                except Exception:
                    pass
    except Exception:
        pass


_last_sponsor_hide = [0.0]


def hide_proxy_sponsor_throttled():
    if time.monotonic() - _last_sponsor_hide[0] >= 30:
        _last_sponsor_hide[0] = time.monotonic()
        from .android import on_ui
        on_ui(hide_proxy_sponsor)
