"""Small wrappers around the Android and exteraGram SDK APIs."""

import threading
import traceback

try:
    from android_utils import run_on_ui_thread as _run_on_ui_thread
except Exception:                      # outside the app (tests)
    _run_on_ui_thread = None

try:
    from ui.bulletin import BulletinHelper as _Bulletin
except Exception:
    _Bulletin = None

from .i18n import t


def app_context():
    try:
        from org.telegram.messenger import ApplicationLoader
        return ApplicationLoader.applicationContext
    except Exception:
        return None


def files_dir():
    try:
        return str(app_context().getFilesDir().getAbsolutePath())
    except Exception:
        return "."


def cache_dir():
    try:
        return str(app_context().getCacheDir().getAbsolutePath())
    except Exception:
        return "."


def on_ui(func, delay_ms=0):
    """Run func on the Android UI thread (directly when there is none, in tests)."""
    def guarded():
        try:
            func()
        except Exception:
            traceback.print_exc()
    if _run_on_ui_thread is None:
        guarded()
    elif delay_ms:
        _run_on_ui_thread(guarded, int(delay_ms))
    else:
        _run_on_ui_thread(guarded)


def in_background(func, *args, name="greenpass"):
    def guarded():
        try:
            func(*args)
        except Exception:
            traceback.print_exc()
    thread = threading.Thread(target=guarded, name=name, daemon=True)
    thread.start()
    return thread


def toast_info(text, *args):
    if _Bulletin is not None:
        on_ui(lambda: _Bulletin.show_info(t(text, *args)))


def toast_error(text, *args):
    if _Bulletin is not None:
        on_ui(lambda: _Bulletin.show_error(t(text, *args)))


def toast_success(text, *args):
    if _Bulletin is not None:
        on_ui(lambda: _Bulletin.show_success(t(text, *args)))


def prefs(name="greenpass_prefs"):
    try:
        return app_context().getSharedPreferences(name, 0)
    except Exception:
        return None


def clipboard_text(limit=65536):
    try:
        from android.content import Context
        manager = app_context().getSystemService(Context.CLIPBOARD_SERVICE)
        clip = manager.getPrimaryClip()
        if clip is None or clip.getItemCount() <= 0:
            return ""
        text = clip.getItemAt(0).coerceToText(app_context())
        return str(text or "")[:int(limit)]
    except Exception:
        return ""


def copy_text(text):
    try:
        from android.content import ClipData, Context
        manager = app_context().getSystemService(Context.CLIPBOARD_SERVICE)
        manager.setPrimaryClip(ClipData.newPlainText("GreenPass", str(text or "")))
        return True
    except Exception:
        return False


def is_app_paused():
    try:
        from org.telegram.messenger import ApplicationLoader
        return bool(ApplicationLoader.mainInterfacePaused)
    except Exception:
        return False


def is_system_vpn_active():
    """True when another VPN carries the default network."""
    try:
        from android.content import Context
        from android.net import NetworkCapabilities
        manager = app_context().getSystemService(Context.CONNECTIVITY_SERVICE)
        network = manager.getActiveNetwork()
        if network is None:
            return False
        caps = manager.getNetworkCapabilities(network)
        return bool(caps is not None and caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
    except Exception:
        return False


def wifi_state():
    """(on_wifi, ssid). Looks at every network, since a VPN can be the active one.

    ssid is "" when Android hides it (no location permission).
    """
    from .store import normalize_ssid
    try:
        from android.content import Context
        from android.net import NetworkCapabilities
        context = app_context()
        manager = context.getSystemService(Context.CONNECTIVITY_SERVICE)
        networks = []
        active = manager.getActiveNetwork()
        if active is not None:
            networks.append(active)
        try:
            networks.extend(n for n in list(manager.getAllNetworks() or []) if n not in networks)
        except Exception:
            pass
        infos = []
        for network in networks:
            try:
                caps = manager.getNetworkCapabilities(network)
                if caps is not None and caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI):
                    infos.append(caps.getTransportInfo())
            except Exception:
                continue
        if not infos:
            return False, ""
        try:
            infos.append(context.getApplicationContext().getSystemService(Context.WIFI_SERVICE).getConnectionInfo())
        except Exception:
            pass
        for info in infos:
            try:
                ssid = normalize_ssid(info.getSSID()) if info is not None else ""
            except Exception:
                ssid = ""
            if ssid:
                return True, ssid
        return True, ""
    except Exception:
        return False, ""
