import os
import time

from base_plugin import AppEvent, BasePlugin

from .greenpass import android, links, meta, qwdtt, subscriptions, transfer, updater
from .greenpass.app import App
from .greenpass.calls import VoiceRelay, build_link as relay_link, parse_link as parse_relay_link, ping as relay_ping
from .greenpass.hooks import AWG_FILE_PICKER_REQ, IMPORT_FILE_PICKER_REQ, Hooks, hide_proxy_sponsor_throttled
from .greenpass.i18n import t
from .greenpass.plugin_proxy import PluginProxy
from .greenpass.singbox import file_node, mihomo_node
from .greenpass.ui import kit
from .greenpass.ui.pages import MODE_INFO, Pages
# Import the module, not the class: Elyx loads the first BasePlugin subclass it
# finds in main.py, and that must be GreenPassPlugin.
from .greenpass import webproxy as _webproxy

__id__ = meta.__id__
__description__ = meta.__description__
__author__ = meta.__author__
__version__ = meta.__version__
__icon__ = meta.__icon__
__app_version__ = meta.__app_version__
__sdk_version__ = meta.__sdk_version__

CLIPBOARD_LIMIT = 65536


class GreenPassPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.active = False
        package_dir = os.path.dirname(os.path.abspath(__file__))
        self.app = App(self, os.path.join(package_dir, "greenpass"), os.path.abspath(__file__))
        self.app.plugin_is_package = os.path.isdir(os.path.join(package_dir, "greenpass"))
        self.relay = VoiceRelay(self.app)
        self.plugin_proxy = PluginProxy(self.app, os.path.abspath(__file__))
        self.pages = Pages(self)
        self.hooks = Hooks(self)
        self.webproxy = _webproxy.WebProxyNativePlugin()
        self._last_auto_ping = 0.0
        self._last_olcrtc_refresh = time.time()

    # --- SDK entry points ---

    def create_settings(self):
        try:
            return self.pages.root()
        except Exception as exc:
            return [kit.Header("Ошибка"), kit.Text(str(exc), icon="msg_info")]

    def on_plugin_load(self):
        self.active = True
        self.app.load()
        self.app.on_ui_refresh = self.refresh
        self.app.on_proxy_changed = self.plugin_proxy.sync
        self.hooks.install()
        if not self.ipv6_enabled():
            self.force_ipv4()
        try:
            self.webproxy.on_plugin_load()
        except Exception:
            pass
        self.app.start()
        self.plugin_proxy.sync()

    def on_plugin_unload(self):
        self.active = False
        try:
            self.webproxy.on_plugin_unload()
        except Exception:
            pass
        self.plugin_proxy.remove()
        self.app.shutdown()

    def on_app_event(self, event):
        if event in (AppEvent.PAUSE, AppEvent.STOP):
            self.app.on_pause()
        elif event in (AppEvent.RESUME, AppEvent.START):
            self.hooks.install()
            self.app.on_resume()
            if self.app.wants_running():
                hide_proxy_sponsor_throttled()

    def periodic_jobs(self):
        """Every watchdog tick (30 s): auto ping, olcRTC subscriptions, update check."""
        minutes = int(self.app.setting("vless_auto_check_minutes", 0) or 0)
        if minutes > 0 and self.app.store.mode == "vless" and time.time() - self._last_auto_ping >= minutes * 60:
            self._last_auto_ping = time.time()
            self.app.nodes.refresh_pings()
            self.app.store.save()
            self.refresh()
        if time.time() - self._last_olcrtc_refresh >= 3600:
            self._last_olcrtc_refresh = time.time()
            self.refresh_olcrtc_subscriptions(silent=True)
        if time.time() - self.app.store.update_checked_at >= meta.UPDATE_CHECK_INTERVAL_SEC:
            self.check_updates(force=False)

    # --- shared helpers ---

    def refresh(self):
        kit.refresh_pages(self.id if getattr(self, "id", None) else meta.PLUGIN_ID)

    def copy(self, text):
        if android.copy_text(text):
            android.toast_success("Скопировано")

    def _work(self, func, *args):
        android.in_background(func, *args)

    # --- main switches ---

    def on_enabled_changed(self, enabled):
        self.app.set_enabled(enabled)
        if enabled and not self.app.mode.has_config() and self.app.store.mode == "awg":
            android.toast_info("Получаю WARP конфиг...")
        self.refresh()

    def select_mode(self, kind):
        self.app.set_mode(kind)
        if not self.app.store.enabled:
            self.app.set_enabled(True)
        self.refresh()

    def reconnect(self):
        if self.app.store.enabled:
            android.toast_info("Переподключаю...")
            self.app.reconnect()

    def on_setting_reconnect(self, key, value):
        self.app.set_setting(key, value)
        self.app.reconnect()

    def on_policy_setting(self, key, value):
        self.app.set_setting(key, value)
        self.app.apply_network_policy_async()

    def on_engine_changed(self, index):
        self.app.store.engine = "mihomo" if int(index) == 1 else "singbox"
        self.app.store.save()
        if self.app.store.mode == "vless":
            self.app.reconnect()

    def on_telegram_proxy_changed(self):
        """Something changed Telegram's proxy: if ours got switched off, put it back."""
        mode = self.app._current
        if mode is not None and mode.state == "connected" and self.app.wants_running() and not mode.proxy_applied():
            self._work(mode.apply_proxy, mode.port)
        self.refresh()

    # --- IPv6 ---

    def ipv6_enabled(self):
        return bool(self.app.setting("ipv6_enabled", True))

    def force_ipv4(self):
        try:
            from org.telegram.tgnet import ConnectionsManager
            from .greenpass.telegram import logged_in_accounts
            for account in logged_in_accounts():
                ConnectionsManager.native_setIpStrategy(account, 0)
        except Exception:
            pass

    def on_ipv6_changed(self, enabled):
        self.app.set_setting("ipv6_enabled", bool(enabled))

        def apply():
            from org.telegram.tgnet import ConnectionsManager
            from .greenpass.telegram import logged_in_accounts
            for account in logged_in_accounts():
                try:
                    ConnectionsManager.getInstance(account).checkConnection()
                except Exception:
                    pass
        android.on_ui(apply)
        android.toast_info("IPv6 включён" if enabled else "IPv6 выключен")

    def on_plugins_proxy_changed(self, enabled):
        self.app.set_setting("proxy_plugins_via_greenpass", bool(enabled))
        self.plugin_proxy.sync()

    # --- importing links ---

    def import_from_clipboard(self):
        text = android.clipboard_text(CLIPBOARD_LIMIT).strip()
        if not text:
            android.toast_error("Буфер обмена пуст")
            return
        link = links.first_import_link(text)
        if link:
            self.handle_link(link)
        elif subscriptions.normalize_url(text) and text.lower().startswith(("http://", "https://")):
            self.add_subscription(text, activate=True)
        else:
            android.toast_error("В буфере нет ссылки")

    def handle_link(self, url, confirm=False):
        """Open any importable link: proxy, qWDTT, olcRTC, tg://ws, tg://relay."""
        text = str(url or "").strip()
        low = text.lower()
        if qwdtt.is_qwdtt_link(text):
            profile = qwdtt.parse_link(text)
            if not profile:
                android.toast_error("Неверная qWDTT ссылка")
                return
            node = qwdtt.node_from_profile(profile)
            self._ask_or_do(confirm, "Добавить qWDTT?", profile["name"], lambda: self._use_node(node))
        elif low.startswith("olcrtc://"):
            self._import_olcrtc_text(text, confirm)
        elif low.startswith("tg://relay?"):
            self._import_relay(text)
        elif low.startswith("tg://ws"):
            self._ask_or_do(confirm, "Включить TG WS?", "Telegram через WebSocket", lambda: self.select_mode("tgws"))
        else:
            node = links.node_from_link(text)
            if node is None:
                scheme = text.split("://", 1)[0].lower() if "://" in text else ""
                android.toast_error("Протокол %s не поддерживается" % scheme if scheme and scheme not in links.SCHEMES
                                    else "Неверная ссылка")
                return
            self._preview_node(node)

    def _ask_or_do(self, confirm, title, message, action):
        if confirm:
            kit.confirm(title, message, "Подключить", action)
        else:
            action()

    def _preview_node(self, node):
        info = "%s • %s" % (links.label(node), links.address_name(node.get("server"), node.get("port")))

        def connect():
            self._use_node(node)

        kit.confirm(node.get("name") or "Узел", info + "\n" + t("Проверяю доступность..."), "Подключить", connect)

    def _use_node(self, node):
        self.app.nodes.add_manual(node, activate=True)
        self.app.store.save()
        self.select_mode("vless")
        android.toast_success("Узел добавлен")

    def ask_subscription(self):
        kit.ask_text("Добавить подписку", "https://...", lambda text: self.add_subscription(text, activate=True))

    def add_subscription(self, url, activate=False):
        target = subscriptions.normalize_url(url)
        if not target:
            android.toast_error("Нужна ссылка на подписку")
            return
        android.toast_info("Загружаю подписку...")
        self._work(self._load_subscription, target, activate)

    def _load_subscription(self, url, activate):
        from .greenpass import olcrtc_links
        text = subscriptions.fetch_text(url)
        found = subscriptions.nodes_from_text(text, url)
        if not found:
            parsed = qwdtt.parse_payload(text)
            found = [n for n in (qwdtt.node_from_profile(p) for p in parsed["profiles"]) if n]
            if found:
                self.app.nodes.put_subscription(url, found, parsed["name"])
        if not found:
            text = olcrtc_links.fetch_subscription(url) or text
            profiles = olcrtc_links.subscription_profiles(text, olcrtc_links.device_id())
            if profiles:
                self._save_olcrtc_profiles(profiles, url, activate)
                android.toast_success("olcRTC профилей: %d", len(profiles))
                return
            info = subscriptions.LAST_FETCH.get(url, {})
            android.toast_error("Нет узлов%s" % ((": " + info.get("errors")) if info.get("errors") else ""))
            return
        existed = self.app.nodes.put_subscription(url, found)
        if activate:
            self.app.nodes.set_active(found[0]["uri"])
        self.app.nodes.repair_active()
        self.app.store.save()
        android.toast_success("Импортировано узлов: %d", len(found))
        if activate:
            self.select_mode("vless")
        elif existed and self.app.store.mode == "vless":
            self.app.reconnect()
        self.refresh()

    def refresh_subscriptions(self):
        android.toast_info("Обновляю подписки...")

        def run():
            for sub in list(self.app.store.vless_subs):
                found = subscriptions.fetch_nodes(sub["url"])
                if found:
                    self.app.nodes.put_subscription(sub["url"], found)
            self.app.nodes.repair_active()
            self.app.store.save()
            android.toast_success("Подписки обновлены")
            if self.app.store.mode == "vless":
                self.app.reconnect()
            self.refresh()
        self._work(run)

    def subscription_menu(self, url):
        hidden = self.app.hidden_sources()
        hide_label = "Показать в автовыборе" if url in hidden else "Скрыть из автовыбора"

        def pick(index):
            if index == 0:
                self.add_subscription(url)
            elif index == 1:
                self.app.set_setting("vless_browser_hidden_sources", __import__("json").dumps(sorted(hidden ^ {url})))
                self.app.nodes.invalidate()
                self.refresh()
            elif index == 2:
                self.copy(url)
            else:
                kit.confirm("Удалить подписку?", url, "Удалить", lambda: self._remove_subscription(url), danger=True)
        kit.choose("Подписка", ["Обновить", hide_label, "Скопировать ссылку", "Удалить"], pick)

    def _remove_subscription(self, url):
        self.app.nodes.remove_subscription(url)
        self.app.store.save()
        self.app.reconnect()
        self.refresh()

    # --- nodes ---

    def activate_node(self, uri):
        self.app.nodes.set_active(uri)
        self.app.store.save()
        self.select_mode("vless")

    def node_menu(self, node):
        def pick(index):
            if index == 0:
                self.activate_node(node["uri"])
            elif index == 1:
                self.copy(node["uri"])
            else:
                kit.confirm("Удалить узел?", node.get("name") or "", "Удалить", lambda: self._remove_node(node["uri"]), danger=True)
        kit.choose(node.get("name") or "Узел", ["Подключить", "Скопировать ссылку", "Удалить"], pick)

    def _remove_node(self, uri):
        was_active = uri == self.app.store.vless_active_uri
        self.app.nodes.remove(uri)
        self.app.store.save()
        if was_active:
            self.app.reconnect()
        self.refresh()

    def confirm_clear_nodes(self):
        def clear():
            self.app.nodes.clear()
            self.app.store.save()
            self.app.reconnect()
            self.refresh()
        kit.confirm("Удалить все узлы?", "Свои узлы и подписки будут удалены", "Удалить", clear, danger=True)

    def ping_nodes(self):
        android.toast_info("Проверяю пинг...")

        def run():
            checked, alive = self.app.nodes.refresh_pings(force=True, on_progress=self.refresh)
            self.app.store.save()
            android.toast_success("Доступно %d из %d", alive, checked)
            self.refresh()
        self._work(run)

    def copy_core_logs(self):
        text = self.app.core.logs_json() or self.app.core.last_log() or self.app.core.last_error()
        if text:
            self.copy(text)
        else:
            android.toast_info("Логов нет")

    # --- AWG ---

    def new_warp(self):
        android.toast_info("Получаю WARP конфиг...")

        def run():
            if self.app.modes["awg"].generate_warp():
                android.toast_success("WARP конфиг получен")
                self.select_mode("awg")
                self.app.reconnect()
        self._work(run)

    def pick_awg_file(self):
        self._open_picker(AWG_FILE_PICKER_REQ)

    def pick_import_file(self):
        self._open_picker(IMPORT_FILE_PICKER_REQ)

    def _open_picker(self, request):
        def open_picker():
            from android.content import Intent
            intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.setType("*/*")
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            kit.activity().startActivityForResult(intent, int(request))
        android.on_ui(open_picker)

    def on_file_picked(self, request, uri):
        def run():
            try:
                raw = transfer.read_content_uri(kit.activity(), uri)
            except Exception as exc:
                android.toast_error("Не удалось прочитать файл: %s", exc)
                return
            if request == AWG_FILE_PICKER_REQ:
                self._import_awg_conf(raw.decode("utf-8", errors="ignore"), "config.conf")
            else:
                self._import_export_bytes(raw)
        self._work(run)

    def _import_awg_conf(self, text, name):
        from .greenpass.singbox import awg_config
        try:
            awg_config(text, 1)
        except Exception as exc:
            android.toast_error("Неверный конфиг AWG: %s", exc)
            return
        store = self.app.store
        store.awg_conf_name, store.awg_conf_content = name, text
        store.save()
        android.toast_success("Конфиг AWG загружен")
        self.select_mode("awg")
        self.app.reconnect()

    def confirm_clear_awg(self):
        def clear():
            self.app.store.awg_conf_name = self.app.store.awg_conf_content = ""
            self.app.store.save()
            self.app.reconnect()
            self.refresh()
        kit.confirm("Удалить конфиг AWG?", "", "Удалить", clear, danger=True)

    # --- olcRTC ---

    def import_olcrtc_from_clipboard(self):
        text = android.clipboard_text(CLIPBOARD_LIMIT).strip()
        if text.lower().startswith(("http://", "https://")) and not any(h in text for h in ("telemost", "stream.wb.ru", "meet.", "jitsi")):
            self.add_subscription(text, activate=not self.app.modes["olcrtc"].profiles())
        else:
            self._import_olcrtc_text(text, confirm=False)

    def _import_olcrtc_text(self, text, confirm):
        data, error = transfer.parse_olcrtc_text(text)
        if error or not data:
            android.toast_error(error or "Неверный olcRTC конфиг")
            return

        def save():
            if self._save_olcrtc_profiles([data], text if text.lower().startswith("olcrtc://") else "", True):
                android.toast_success("olcRTC: %s", data.get("room_id", "")[:32])
            else:
                android.toast_error("Неверный olcRTC конфиг")
        self._ask_or_do(confirm, "Подключить olcRTC?", data.get("room_id", ""), save)

    def _save_olcrtc_profiles(self, profiles, link, activate):
        mode = self.app.modes["olcrtc"]
        previous = self.app.store.olcrtc_active_id
        saved = [mode.upsert(p, link) for p in reversed(profiles)]
        saved = [p for p in saved if p]
        if not saved:
            return 0
        if activate:
            self.select_mode("olcrtc")
            self.app.reconnect()
        elif previous:
            mode.activate(previous)
        self.refresh()
        return len(saved)

    def refresh_olcrtc_subscriptions(self, silent=False):
        from .greenpass import olcrtc_links
        mode = self.app.modes["olcrtc"]
        urls = sorted({p["subscription_url"] for p in mode.profiles() if p.get("subscription_url")})
        if not urls:
            return

        def run():
            store = self.app.store
            changed = False
            for url in urls:
                fresh = olcrtc_links.subscription_profiles(olcrtc_links.fetch_subscription(url), olcrtc_links.device_id())
                if fresh:
                    kept = [p for p in store.olcrtc_profiles if p.get("subscription_url") != url]
                    added = [dict(p, subscription_url=url, subscription_updated_at=int(time.time())) for p in fresh]
                    store.olcrtc_profiles = olcrtc_links.clean_profiles(kept + added)
                    changed = True
            if changed:
                mode.active_profile()
                store.save()
                self.refresh()
            if not silent:
                (android.toast_success if changed else android.toast_error)(
                    "olcRTC подписки обновлены" if changed else "Не удалось обновить olcRTC подписки")
        self._work(run)

    def olcrtc_menu(self, profile):
        mode = self.app.modes["olcrtc"]

        def pick(index):
            if index == 0:
                mode.activate(profile["id"])
                self.select_mode("olcrtc")
                self.app.reconnect()
            elif index == 1:
                self.copy(profile.get("link", ""))
            else:
                kit.confirm("Удалить профиль?", profile["name"], "Удалить",
                            lambda: (mode.delete(profile["id"]), self.app.reconnect(), self.refresh()), danger=True)
        kit.choose(profile["name"], ["Подключить", "Скопировать ссылку", "Удалить"], pick)

    # --- Voice Relay ---

    def _import_relay(self, text):
        config, error = parse_relay_link(text)
        if config is None:
            android.toast_error(error)
            return
        android.toast_info("Проверяю Voice Relay...")

        def run():
            ping = relay_ping(config)
            message = "%s:%d\n%s" % (config[0], config[1], ("%d ms" % ping) if ping else t("нет ответа"))
            kit.confirm("Сменить Voice Relay?", message, "Сменить",
                        lambda: (self.relay.save(config), android.toast_success("Voice Relay переключён"), self.refresh()))
        self._work(run)

    def ping_relay(self):
        config, error = self.relay.config()
        if config is None:
            android.toast_error(error)
            return
        self._work(lambda: (lambda ping: android.toast_success("Relay: %d ms", ping) if ping
                            else android.toast_error("Relay не ответил"))(relay_ping(config)))

    def copy_relay_link(self):
        config, error = self.relay.config()
        if config is None:
            android.toast_error(error)
        else:
            self.copy(relay_link(config))

    # --- HWID ---

    def hwid_text(self):
        custom = subscriptions.custom_hwid()
        return subscriptions.hwid() + (" (" + t("свой") + ")" if custom else "")

    def ask_hwid(self):
        def done(text):
            if subscriptions.set_custom_hwid(text):
                self.app.set_setting("subscription_hwid_custom", text.strip().lower())
                android.toast_success("HWID сохранён")
                self.refresh()
            else:
                android.toast_error("HWID: 16 символов 0-9 a-f")
        kit.ask_text("HWID", "16 символов 0-9 a-f (пусто — случайный)", done, subscriptions.custom_hwid())

    # --- Wi-Fi rules ---

    def add_current_wifi(self):
        on_wifi, ssid = android.wifi_state()
        if not ssid:
            android.toast_error("Wi-Fi не найден (нужен доступ к местоположению)" if on_wifi else "Нет Wi-Fi")
            return
        self.wifi_rule_menu(ssid)

    def ask_wifi_name(self):
        kit.ask_text("Сеть Wi-Fi", "Имя сети (SSID)", lambda name: name and self.wifi_rule_menu(name))

    def wifi_rule_menu(self, ssid):
        from .greenpass.store import normalize_ssid
        ssid = normalize_ssid(ssid)
        kinds = list(self.app.mode_kinds())
        options = ["Прокси выключен"] + [MODE_INFO[k][0] for k in kinds]
        if ssid in self.app.store.wifi_rules:
            options.append("Удалить правило")

        def pick(index):
            rules = self.app.store.wifi_rules
            if index == 0:
                rules[ssid] = "off"
            elif index <= len(kinds):
                rules[ssid] = kinds[index - 1]
            else:
                rules.pop(ssid, None)
            self.app.store.save()
            self.app.apply_network_policy_async()
            self.refresh()
        kit.choose(ssid, options, pick)

    # --- export / import ---

    def export_settings(self):
        def run():
            settings = {}
            for key in transfer.SETTINGS_KEYS:
                value = self.app.setting(key, None)
                if value is not None:
                    settings[key] = transfer.clean_setting(key, value)
            settings["use_proxy"] = bool(self.app.store.enabled)
            path = os.path.join(android.files_dir(), transfer.EXPORT_FILE_NAME)
            with open(path, "wb") as handle:
                handle.write(transfer.export_bytes(self.app.store, settings))

            def send():
                from client_utils import send_document
                from org.telegram.messenger import UserConfig
                account = int(UserConfig.selectedAccount)
                peer = UserConfig.getInstance(account).getClientUserId()
                try:
                    send_document(peer, path, caption=transfer.EXPORT_FILE_NAME, account=account)
                except TypeError:
                    send_document(peer, path, caption=transfer.EXPORT_FILE_NAME)
                android.toast_success("Экспорт отправлен в Избранное")
            android.on_ui(send)
        self._work(run)

    def _import_export_bytes(self, raw):
        try:
            payload = transfer.decode_export(raw)
        except Exception as exc:
            android.toast_error("Ошибка импорта: %s", exc)
            return
        store = self.app.store
        store._apply(payload["config"])
        store.save()
        self.app.load()
        for key, value in (payload.get("settings") or {}).items():
            if key in transfer.SETTINGS_KEYS:
                self.app.set_setting(key, transfer.clean_setting(key, value))
        subscriptions.set_custom_hwid(self.app.setting("subscription_hwid_custom", ""))
        self.app.set_enabled(bool((payload.get("settings") or {}).get("use_proxy", store.enabled)))
        self.plugin_proxy.sync()
        android.toast_success("Импорт выполнен")
        self.refresh()

    def open_document(self, message):
        """A chat file was tapped: import GreenPass files. True when we handled it."""
        name = transfer.document_name(message)
        kind = transfer.file_kind(name)
        if not kind:
            return False
        path = transfer.document_path(message)
        if not path:
            android.toast_info("Сначала скачайте файл")
            return True
        titles = {"greenpass": "Импортировать настройки?", "singbox": "Импортировать sing-box конфиг?",
                  "mihomo": "Импортировать Mihomo конфиг?", "qwdtt": "Импортировать qWDTT?"}
        kit.confirm(titles[kind], name, "Импортировать", lambda: self._work(self._import_file, kind, path, name))
        return True

    def _import_file(self, kind, path, name):
        try:
            if kind == "greenpass":
                with open(path, "rb") as handle:
                    self._import_export_bytes(handle.read(transfer.MAX_IMPORT_BYTES))
                return
            text = transfer.read_text(path)
            if kind == "qwdtt":
                parsed = qwdtt.parse_payload(text)
                found = [n for n in (qwdtt.node_from_profile(p) for p in parsed["profiles"]) if n]
                if not found:
                    raise ValueError(t("неверный формат qWDTT"))
                for node in reversed(found):
                    self.app.nodes.add_manual(node, activate=False)
                self.app.nodes.set_active(found[0]["uri"])
            else:
                node = file_node(text, name) if kind == "singbox" else mihomo_node(text, name)
                self.app.store.engine = "singbox" if kind == "singbox" else "mihomo"
                self.app.nodes.add_manual(node, activate=True)
            self.app.store.save()
            android.toast_success("Конфиг импортирован")
            self.select_mode("vless")
            self.app.reconnect()
        except Exception as exc:
            android.toast_error("Ошибка импорта: %s", exc)

    # --- updates ---

    def check_updates_now(self):
        android.toast_info("Проверяю обновления...")
        self._work(self.check_updates, True)

    def check_updates(self, force=False):
        if not force and not bool(self.app.setting("plugin_autoupdate_enabled", True)):
            return
        store = self.app.store
        store.update_checked_at = int(time.time())
        store.save()
        self.app.modes["tgws"].refresh_domains()
        skip = "" if force else str(self.app.setting("plugin_autoupdate_prompted_version", "") or "")
        try:
            tag, path = updater.check(android.cache_dir(), elyx=self.app.plugin_is_package, skip_tag=skip)
        except Exception:
            if force:
                android.toast_error("Не удалось проверить обновления")
            return
        store.update_seen_tag = tag
        store.save()
        if not path:
            if force:
                android.toast_success("Установлена последняя версия")
            return
        self.app.set_setting("plugin_autoupdate_prompted_version", tag)

        def install():
            try:
                updater.open_installer(path)
            except Exception:
                android.toast_error("Не удалось открыть установщик обновления")
        kit.confirm("Обновление GreenPass", "Доступно обновление", "Установить", install)
