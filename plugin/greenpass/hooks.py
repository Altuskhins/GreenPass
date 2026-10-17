from .foundation import *
from .protocols import *
from .subscriptions import *

def _force_show_dialogs_proxy_button(da):
    try:
        if da is None:
            return

        cls = None
        try:
            cls = da.getClass()
        except:
            cls = None

        proxy_item = None
        if cls is not None:
            try:
                f = cls.getDeclaredField("proxyItem")
                f.setAccessible(True)
                proxy_item = f.get(da)
            except:
                proxy_item = None

        if proxy_item is not None:
            try:
                from android.view import View
                proxy_item.setVisibility(View.VISIBLE)
            except:
                pass

        if cls is not None:
            try:
                vf = cls.getDeclaredField("proxyItemVisible")
                vf.setAccessible(True)
                try:
                    vf.setBoolean(da, True)
                except:
                    vf.set(da, True)
            except:
                pass

        proxy_drawable = None
        if cls is not None:
            try:
                df = cls.getDeclaredField("proxyDrawable")
                df.setAccessible(True)
                proxy_drawable = df.get(da)
            except:
                proxy_drawable = None

        if proxy_drawable is not None:
            state = None
            try:
                sf = cls.getDeclaredField("currentConnectionState")
                sf.setAccessible(True)
                state = sf.getInt(da)
            except:
                state = None

            enabled = _is_tg_proxy_enabled()
            connected = False
            try:
                connected = (
                    state == ConnectionsManager.ConnectionStateConnected
                    or state == ConnectionsManager.ConnectionStateUpdating
                )
            except:
                connected = False

            try:
                proxy_drawable.setConnected(bool(enabled), bool(connected), False)
            except:
                pass
    except:
        pass

class HideProxySponsorDialogHook(MethodHook):
    _last_hide = {}

    def after_hooked_method(self, param):
        try:
            mc = param.thisObject
            if not mc:
                return

            proxy_type = 0
            try:
                proxy_type = int(getattr(MessagesController, "PROMO_TYPE_PROXY", 0))
            except:
                proxy_type = 0

            promo_type = None
            try:
                promo_type = int(mc.promoDialogType)
            except:
                promo_type = None

            promo_id = 0
            promo_type_pref = None
            try:
                prefs = MessagesController.getGlobalMainSettings()
                promo_id = int(prefs.getLong("proxy_dialog", 0))
                promo_type_pref = int(prefs.getInt("promo_dialog_type", -1))
            except:
                promo_id = 0
                promo_type_pref = None

            is_proxy_promo = False
            if promo_id != 0 and promo_type_pref is not None and promo_type_pref == proxy_type:
                is_proxy_promo = True
            elif promo_type is not None and promo_type == proxy_type:
                is_proxy_promo = True

            if not is_proxy_promo:
                return

            now = int(time.time())
            key = id(mc)
            last = int(HideProxySponsorDialogHook._last_hide.get(key, 0) or 0)
            if now - last < 30:
                return
            HideProxySponsorDialogHook._last_hide[key] = now

            def _hide():
                try:
                    from hook_utils import get_private_field, set_private_field

                    promo_dialog = None
                    try:
                        promo_dialog = get_private_field(mc, "promoDialog")
                    except:
                        promo_dialog = None

                    if promo_dialog is None and promo_id != 0:
                        try:
                            promo_dialog = mc.dialogs_dict.get(promo_id)
                        except:
                            promo_dialog = None
                        if promo_dialog is not None:
                            try:
                                set_private_field(mc, "promoDialog", promo_dialog)
                            except:
                                pass

                    if hasattr(mc, "hidePromoDialog"):
                        mc.hidePromoDialog()
                except:
                    pass

            run_on_ui_thread(_hide)
        except:
            pass


class _ForceDialogsProxyButtonHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if (not self._plugin._is_plugin_proxy_enabled()) or self._plugin._is_proxy_policy_suspended():
                return
            _force_show_dialogs_proxy_button(param.thisObject)
        except:
            pass


class _DialogsShowSearchForceProxyHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if (not self._plugin._is_plugin_proxy_enabled()) or self._plugin._is_proxy_policy_suspended():
                return
            _force_show_dialogs_proxy_button(param.thisObject)
        except:
            pass


class _DialogsShowDoneItemForceProxyHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if (not self._plugin._is_plugin_proxy_enabled()) or self._plugin._is_proxy_policy_suspended():
                return
            _force_show_dialogs_proxy_button(param.thisObject)
        except:
            pass


class _ProxySettingsChangedNotifyHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if not param.args or len(param.args) < 1:
                return

            try:
                event_id = int(param.args[0])
            except:
                return

            try:
                network_changed_id = int(getattr(NotificationCenter, "didUpdateConnectionState"))
            except:
                network_changed_id = -1
            if event_id == network_changed_id:
                threading.Thread(target=self._plugin._apply_vpn_policy, daemon=True).start()

            try:
                proxy_changed_id = int(NotificationCenter.proxySettingsChanged)
            except:
                return

            if event_id != proxy_changed_id:
                return

            if (
                self._plugin._is_vless_mode_selected()
                and self._plugin._is_plugin_proxy_enabled()
                and not self._plugin._is_proxy_policy_suspended()
                and not _is_tg_proxy_enabled()
            ):
                threading.Thread(target=self._plugin._restore_running_vless_proxy, daemon=True).start()
            else:
                self._plugin._refresh_settings_without_reopen()
            self._plugin._refresh_current_dialogs_proxy_button()
        except:
            pass


class _ProxyTransitionKillSwitchHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            lease = self._plugin._maybe_acquire_proxy_transition_killswitch_from_args(param.args)
            if lease is None:
                return
            self._plugin._remember_proxy_transition_param_lease(param, lease)
        except:
            pass

    def after_hooked_method(self, param):
        try:
            lease = self._plugin._pop_proxy_transition_param_lease(param)
            if lease is None:
                return
            self._plugin._release_proxy_transition_killswitch(
                lease,
                delay_sec=float(PROXY_TRANSITION_KILLSWITCH_RESUME_DELAY_SEC),
            )
        except:
            pass


class _AwgActivityResultHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if not param.args or len(param.args) < 3:
                return
            req_code = int(param.args[0])
            res_code = int(param.args[1])
            data = param.args[2]
            if res_code != -1 or data is None:
                return
            uri = data.getData()
            if uri is None:
                return
            if req_code == int(AWG_FILE_PICKER_REQ):
                self._plugin._process_awg_file_uri(uri)
            elif req_code == int(GREENPASS_IMPORT_FILE_PICKER_REQ):
                self._plugin._process_greenpass_import_file_uri(uri)
        except:
            pass


class _BrowserOpenUrlHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if not param.args:
                return

            raw_url = ""
            for arg in list(param.args or []):
                try:
                    candidate = _extract_import_uri(arg)
                    if candidate:
                        raw_url = candidate
                        break
                except:
                    pass
                try:
                    if hasattr(arg, "getScheme"):
                        scheme = str(arg.getScheme() or "").lower()
                        arg_text = str(arg.toString() or "")
                        if scheme in tuple(PROXY_URI_SCHEMES) + tuple(QWDTT_URI_SCHEMES) or scheme == "olcrtc" or arg_text.lower().startswith(("qwdtt:config?", "tg://ws", "tg://relay?")):
                            raw_url = arg_text
                            break
                except:
                    pass

            if not raw_url:
                return

            run_on_ui_thread(lambda: self._plugin._handle_import_uri(raw_url, confirm=True))
            try:
                param.setResult(None)
            except:
                try:
                    param.result = None
                except:
                    pass
        except:
            pass


class _VoipRelayLinkIntentHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active or not param.args:
                return
            intent = param.args[0]
            if intent is None or str(intent.getAction()) != "android.intent.action.VIEW":
                return
            uri = str(intent.getData() or "")
            if not uri.lower().startswith("tg://relay?"):
                return
            param.setResult(None)
            run_on_ui_thread(lambda: self._plugin._handle_import_uri(uri))
        except:
            pass


class _AddVlessTextLinksHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if not param.args:
                return
            target = param.args[0]
            if target is None:
                return
            try:
                raw = str(target or "")
            except:
                raw = ""
            if not _contains_import_uri_text(raw):
                return
            _ensure_vless_url_spans(target, raw_text=raw)
        except:
            pass


class _BindVlessTextLinksHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if not param.args:
                return
            message_object = param.args[0]
            if message_object is None:
                return

            applied = 0
            for attr_name in ("messageText", "caption", "linkDescription"):
                try:
                    value = getattr(message_object, attr_name, None)
                except:
                    value = None
                if value is None:
                    continue
                try:
                    applied += int(_ensure_vless_url_spans(value))
                except:
                    pass

            if applied > 0:
                try:
                    param.thisObject.invalidate()
                except:
                    pass
        except:
            pass


class _GreenPassOpenForViewHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active:
                return
            if not param.args:
                return
            message_object = param.args[0]
            if message_object is None:
                return
            if self._plugin._handle_greenpass_file_open(message_object):
                try:
                    param.setResult(False)
                except:
                    try:
                        param.result = False
                    except:
                        pass
        except:
            pass


class _VoipEndpointRewriteHook(MethodHook):
    def __init__(self, plugin, endpoint_cls):
        self._plugin = plugin
        self._endpoint_cls = endpoint_cls

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active or not param.args or len(param.args) < 4:
                return
            self._plugin._rewrite_voip_endpoints(param.args[3], self._endpoint_cls)
        except:
            pass


class _WebRtcJoinResponseRewriteHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def before_hooked_method(self, param):
        try:
            if not self._plugin._active or not param.args:
                return
            param.args[0] = self._plugin._rewrite_webrtc_join_response(param.args[0])
        except:
            pass

__all__ = [name for name in globals() if not name.startswith("__")]


class _Ipv6PolicyHook(MethodHook):
    def __init__(self, plugin):
        self._plugin = plugin

    def after_hooked_method(self, param):
        try:
            if self._plugin._active and not self._plugin._ipv6_enabled():
                self._plugin._force_ipv4_strategy()
        except:
            pass
