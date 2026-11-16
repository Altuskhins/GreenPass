"""The controller: which mode should run, and one worker thread that makes it so.

Everything that starts or stops a proxy goes through the worker queue, so modes
never race each other. The UI only changes the wanted state and calls sync().
"""

import queue
import threading

from . import android, telegram
from .core import Core
from .modes.awg import AwgMode
from .modes.base import CONNECTED, OFF
from .modes.olcrtc import OlcRtcMode
from .modes.tgws import TgWsMode
from .modes.vless import VlessMode
from .nodes import Nodes
from .store import MODES, WIFI_RULE_OFF, Store, normalize_mode

WATCHDOG_SEC = 30.0
CORE_SWITCH_PAUSE_RELEASE_SEC = 0.12


class App:
    def __init__(self, plugin, package_dir, plugin_file):
        self.plugin = plugin
        self.store = Store(android.files_dir())
        self.core = Core(android.files_dir(), package_dir, plugin_file)
        self.local_proxy = telegram.LocalProxy(on_change=self._proxy_changed)
        self.network_pause = telegram.NetworkPause()
        self.nodes = Nodes(self.store, self.hidden_sources)
        self.modes = {m.kind: m for m in (VlessMode(self), TgWsMode(self), AwgMode(self), OlcRtcMode(self))}
        self.on_ui_refresh = None          # set by the plugin: rebuild the settings page
        self.on_proxy_changed = None       # set by the plugin: plugin-proxy bridge
        self.suspended_reason = ""         # "vpn" / "wifi" while a policy holds the proxy off
        self.backgrounded = False
        self.plugin_is_package = False     # .elyx build (a package dir) vs single .plugin file
        self._wifi_rule_ssid = ""
        self._queue = queue.Queue()
        self._generation = 0
        self._current = None               # the mode the worker last connected
        self._stop = threading.Event()
        self._worker = None
        self._watchdog = None
        self._timers = {}

    # --- lifecycle ---

    def load(self):
        changed = self.store.load()
        changed = self._ensure_socks_password() or changed
        if self.store.legacy_qwdtt:
            from . import qwdtt
            migrated = qwdtt.migrate_legacy(self.store.legacy_qwdtt)
            known = {n["uri"] for n in migrated}
            self.store.vless_manual = (migrated + [n for n in self.store.vless_manual if n.get("uri") not in known])[:64]
            if migrated and not self.store.vless_active_uri:
                self.store.vless_active_uri = migrated[0]["uri"]
            self.store.legacy_qwdtt = None
            changed = True
        from . import olcrtc_links
        clean = olcrtc_links.clean_profiles(self.store.olcrtc_profiles)
        if clean != self.store.olcrtc_profiles:
            self.store.olcrtc_profiles, changed = clean, True
        if self.store.core_restart_pid:
            self.core.restart_required = True
        if changed:
            self.store.save()

    def _ensure_socks_password(self):
        """The SOCKS password survives reinstalls in SharedPreferences."""
        prefs = android.prefs()
        saved = ""
        try:
            saved = str(prefs.getString("vless_socks_password", "") or "").strip().lower()
        except Exception:
            pass
        if len(saved) == 32 and all(c in "0123456789abcdef" for c in saved):
            if saved != self.store.socks_password:
                self.store.socks_password = saved
                return True
            return False
        changed = self.store.ensure_socks_password()
        try:
            prefs.edit().putString("vless_socks_password", self.store.socks_password).commit()
        except Exception:
            pass
        return changed

    def start(self):
        self._stop.clear()
        self._worker = threading.Thread(target=self._run_worker, name="greenpass-worker", daemon=True)
        self._worker.start()
        self._watchdog = threading.Thread(target=self._run_watchdog, name="greenpass-watchdog", daemon=True)
        self._watchdog.start()
        android.in_background(self._install_core)
        self.sync()

    def shutdown(self):
        """Plugin unload: stop the worker and every mode, clear the Telegram proxy."""
        self._stop.set()
        self._queue.put(("stop", None))
        for mode in self.modes.values():
            try:
                mode.disconnect()
            except Exception:
                pass
        self.network_pause.release_all()
        for timer in self._timers.values():
            timer.cancel()

    def _install_core(self):
        if self.core.status() != "current":
            android.toast_info("Распаковываю ядро GreenPass...")
            if self.core.install():
                if self.core.restart_required:
                    self._remember_core_restart()
                    android.toast_success("Ядро GreenPass обновлено. Перезапустите приложение")
                else:
                    android.toast_success("Ядро GreenPass установлено")
            else:
                android.toast_error("Не удалось установить ядро GreenPass")
        self.sync()

    def _remember_core_restart(self):
        import os
        store = self.store
        store.core_restart_pid = os.getpid()
        store.core_restart_reason = "library_update"
        store.core_restart_mode = store.mode
        store.core_restart_enabled = store.enabled
        store.save()

    # --- settings and helpers for modes ---

    def setting(self, key, default=None):
        try:
            value = self.plugin.get_setting(key, default)
        except Exception:
            return default
        return default if value is None else value

    def set_setting(self, key, value):
        try:
            self.plugin.set_setting(key, value, reload_settings=False)
        except TypeError:
            self.plugin.set_setting(key, value)

    def local_port(self, kind, default):
        """User's port for a mode (1024-65535), else the default."""
        try:
            port = int(str(self.setting("local_port_" + kind, "") or "").strip())
        except ValueError:
            return default
        return port if 1024 <= port <= 65535 else default

    def calls_via_proxy(self):
        return bool(self.setting("proxy_calls_via_proxy", False))

    def failover_enabled(self):
        return bool(self.setting("vless_failover_enabled", True))

    def hidden_sources(self):
        import json
        raw = self.setting("vless_browser_hidden_sources", "[]")
        try:
            values = raw if isinstance(raw, (list, tuple, set)) else json.loads(str(raw or "[]"))
        except ValueError:
            values = []
        return {str(v).strip() for v in values if str(v or "").strip()}

    def refresh_ui(self):
        if self.on_ui_refresh is not None:
            android.on_ui(self.on_ui_refresh)

    def _proxy_changed(self):
        if self.on_proxy_changed is not None:
            try:
                self.on_proxy_changed()
            except Exception:
                pass

    def start_core(self, config):
        """Start the shared core with a mode's config; pause Telegram's network meanwhile."""
        if self.core.restart_required:
            return "Ядро обновлено — перезапустите приложение"
        if self.core.status() != "current" and not self.core.install():
            return "Ядро GreenPass не установлено"
        lease = self.network_pause.pause()
        try:
            return self.core.start(config)
        finally:
            self.network_pause.release(lease, CORE_SWITCH_PAUSE_RELEASE_SEC)

    def stop_core(self):
        self.core.stop()

    def is_current(self, mode):
        """mode is still the one that should be connecting (the user did not switch away)."""
        return self._current is mode and self.wants_running() and self.store.mode == mode.kind

    # --- wanted state ---

    @property
    def mode(self):
        return self.modes[normalize_mode(self.store.mode)]

    def wants_running(self):
        return bool(self.store.enabled) and not self.suspended_reason

    def set_enabled(self, enabled):
        self.store.enabled = bool(enabled)
        self.store.save()
        self.sync()

    def set_mode(self, kind, by_wifi_rule=False):
        self.store.set_mode(kind, by_wifi_rule=by_wifi_rule)
        self.store.save()
        self.sync()

    def sync(self):
        """Ask the worker to bring the running mode in line with the wanted state."""
        self._generation += 1
        self._queue.put(("sync", self._generation))

    def reconnect(self):
        """Restart the current mode (from a health check or after a config change)."""
        self._generation += 1
        self._queue.put(("reconnect", self._generation))

    # --- worker ---

    def _run_worker(self):
        while not self._stop.is_set():
            command, generation = self._queue.get()
            if command == "stop":
                return
            if generation != self._generation:
                continue                        # a newer request supersedes this one
            try:
                self._apply(command == "reconnect")
            except Exception:
                import traceback
                traceback.print_exc()

    def _apply(self, restart):
        target = self.mode if self.wants_running() else None
        for mode in self.modes.values():
            if mode is not target and mode.state != OFF:
                mode.disconnect()
        if target is None:
            self._current = None
            if self.store.enabled is False or self.suspended_reason:
                if telegram.is_proxy_enabled() and self.local_proxy.owner:
                    self.local_proxy.clear()
            self.refresh_ui()
            return
        if self.core.restart_required and target.uses_core:
            target.set_state("failed", "Ядро обновлено — перезапустите приложение")
            return
        self._current = target
        if restart:
            target.disconnect()
        if target.state == CONNECTED and target.is_alive() and target.proxy_applied():
            return
        target.connect()

    # --- watchdog: policy, health checks, periodic jobs ---

    def _run_watchdog(self):
        self._stop.wait(2.0)
        while not self._stop.is_set():
            try:
                self.apply_network_policy()
                if self.wants_running() and not self.backgrounded and self._online():
                    mode = self._current
                    if mode is not None and mode.state == CONNECTED:
                        mode.health_check()
                    elif mode is None or mode.state != "connecting":
                        self.sync()
                self.plugin.periodic_jobs()
            except Exception:
                import traceback
                traceback.print_exc()
            self._stop.wait(WATCHDOG_SEC)

    def _online(self):
        try:
            from org.telegram.messenger import ApplicationLoader
            return bool(ApplicationLoader.isNetworkOnline())
        except Exception:
            return True

    def apply_network_policy_async(self):
        android.in_background(self.apply_network_policy)

    def apply_network_policy(self):
        """Hold the proxy off under another VPN or on an "off" Wi-Fi, and switch
        modes by Wi-Fi rules."""
        store = self.store
        on_wifi, ssid = android.wifi_state()
        rule = store.wifi_rules.get(ssid, "") if on_wifi and ssid else ""
        if rule and rule != WIFI_RULE_OFF and rule != store.mode:
            self._wifi_rule_ssid = ssid
            self.set_mode(rule, by_wifi_rule=True)
        elif not rule and self._wifi_rule_ssid:
            self._wifi_rule_ssid = ""
            if store.wifi_default_mode != store.mode:
                self.set_mode(store.wifi_default_mode, by_wifi_rule=True)

        reason = ""
        if store.enabled:
            if bool(self.setting("dont_use_with_vpn", True)) and android.is_system_vpn_active():
                reason = "vpn"
            elif rule == WIFI_RULE_OFF:
                reason = "wifi"
        if reason != self.suspended_reason:
            was = self.suspended_reason
            self.suspended_reason = reason
            if reason == "vpn":
                android.toast_info("VPN активен — прокси приостановлен")
            elif reason == "wifi":
                android.toast_info("Wi-Fi %s — прокси приостановлен", ssid)
            elif was and store.enabled:
                android.toast_info("Прокси восстановлен")
            self.sync()

    # --- app foreground / background ---

    def on_pause(self):
        self.backgrounded = True
        tgws = self.modes["tgws"]
        # TG WS's listener does not survive background: let Telegram reconnect directly
        # meanwhile; on resume the proxy is applied again.
        if self._current is tgws and tgws.port > 0:
            self.local_proxy.clear(owner="tgws", port=tgws.port)

    def on_resume(self):
        was = self.backgrounded
        self.backgrounded = False
        if not was:
            return

        def resume():
            self.apply_network_policy()
            mode = self._current
            if mode is not None and mode.state == CONNECTED:
                if mode.kind == "tgws":
                    mode.on_resume()
                if not mode.is_alive():
                    self.reconnect()
                    return
                if not mode.proxy_applied():
                    mode.apply_proxy(mode.port)
                return
            self.sync()

        android.in_background(resume)

    def status_mode(self):
        """(mode, state) shown on the main page."""
        mode = self.mode
        return mode, (mode.state if self.wants_running() else OFF)

    @staticmethod
    def mode_kinds():
        return MODES
