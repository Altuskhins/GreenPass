"""GreenPass settings pages. Pages only read state and call actions on the plugin (gp)."""

from .. import links, nodes as nodes_mod, olcrtc_links
from ..i18n import t
from ..meta import VERSION
from ..modes.base import CONNECTED, CONNECTING, FAILED
from .kit import Divider, EditText, Header, Selector, Switch, Text

MODE_INFO = {
    "vless": ("Прокси", "VLESS, VMess, Trojan, Hysteria2 и др.", "msg2_proxy_on"),
    "tgws": ("TG WS", "Telegram через WebSocket, без сервера", "msg_language"),
    "awg": ("AmneziaWG", "WireGuard / Cloudflare WARP", "msg_channel"),
    "olcrtc": ("olcRTC", "Туннель через видеозвонок", "msg_videocall"),
}
PAGE_SIZES = (10, 20, 50, 100)
AUTO_PING_MINUTES = (0, 5, 15, 30, 60)


def _state_line(gp):
    mode, state = gp.app.status_mode()
    title = MODE_INFO[mode.kind][0]
    if gp.app.suspended_reason == "vpn":
        return title, "Приостановлен: включён другой VPN", "msg2_proxy_off"
    if gp.app.suspended_reason == "wifi":
        return title, "Приостановлен правилом Wi-Fi", "msg2_proxy_off"
    if gp.app.core.restart_required and mode.uses_core:
        return title, "Ядро обновлено — перезапустите приложение", "msg_retry"
    if state == CONNECTED:
        return title, "Подключено", "msg2_proxy_on"
    if state == CONNECTING:
        return title, "Подключение...", "msg_retry"
    if state == FAILED:
        return title, mode.error or "Ошибка", "msg2_proxy_off"
    return title, "Выключено", "msg2_proxy_off"


class Pages:
    def __init__(self, gp):
        self.gp = gp
        self.page_index = 0

    # --- root ---

    def root(self):
        gp = self.gp
        title, status, icon = _state_line(gp)
        items = [
            Header("GreenPass %s" % VERSION),
            Switch("use_proxy", "Использовать прокси", gp.app.store.enabled, gp.on_enabled_changed,
                   subtext="Подключать Telegram через выбранный режим",
                   icon="msg2_proxy_on" if gp.app.store.enabled else "msg2_proxy_off"),
            Text(title, status, icon=icon, on_click=gp.reconnect if gp.app.store.enabled else None),
            Divider(),
            Header("Режим"),
        ]
        for kind in gp.app.mode_kinds():
            name, description, mode_icon = MODE_INFO[kind]
            selected = kind == gp.app.store.mode
            items.append(Text(("✓ " if selected else "") + t(name), description, icon=mode_icon,
                              on_click=lambda kind=kind: gp.select_mode(kind), accent=selected))
        items += [
            Text("Настройки режима", MODE_INFO[gp.app.store.mode][0], icon="msg_customize", page=self.mode_page),
            Divider(),
            Text("Дополнительно", "Сеть, звонки, обновления, перенос", icon="msg_settings", page=self.extra),
        ]
        return items

    def mode_page(self):
        return {"vless": self.vless, "tgws": self.tgws, "awg": self.awg, "olcrtc": self.olcrtc}[self.gp.app.store.mode]()

    # --- proxy links (vless) ---

    def vless(self):
        gp, app = self.gp, self.gp.app
        mode = app.modes["vless"]
        active = app.nodes.active()
        counts = app.nodes.counts()
        items = [Header("Сервер")]
        if active is not None:
            detail = "%s • %s" % (links.label(active), mode.title_detail or app.store.engine) if mode.state == CONNECTED else links.label(active)
            items.append(Text(active.get("name") or "Узел", detail, icon="msg2_proxy_on" if mode.state == CONNECTED else "msg_link"))
        else:
            items.append(Text("Нет выбранного узла", "Импортируйте ссылку или подписку", icon="msg_info"))
        items += [
            Text("Импорт из буфера", "Ссылка на сервер или подписку", icon="msg_download", accent=True,
                 on_click=gp.import_from_clipboard),
            Text("Добавить подписку", "Вставить ссылку вручную", icon="msg_add", on_click=gp.ask_subscription),
        ]
        if counts["subs"]:
            items.append(Text("Подписки", "%d шт." % counts["subs"], icon="msg_channel", page=self.subscriptions))
        auto = app.nodes.auto_node(app.failover_enabled())
        node_list = sorted(app.nodes.all(), key=nodes_mod.sort_key)
        visible = [n for n in node_list if app.nodes.visible(n)]
        if visible:
            items += [Divider(), Header("Узлы (%d)" % len(visible)),
                      Text("Проверить пинг", "Задержка до каждого сервера", icon="msg_speed", on_click=gp.ping_nodes)]
            if auto is not None:
                selected = app.store.vless_active_uri == nodes_mod.AUTO_URI
                items.append(Text(("✓ " if selected else "") + t("Автовыбор"),
                                  "Лучший из %d узлов подписок" % len(auto["balance_nodes"]),
                                  icon="msg_autodelete", accent=selected,
                                  on_click=lambda: gp.activate_node(nodes_mod.AUTO_URI)))
            size = self.page_size()
            pages = max(1, (len(visible) + size - 1) // size)
            self.page_index = min(self.page_index, pages - 1)
            for node in visible[self.page_index * size:(self.page_index + 1) * size]:
                selected = node.get("uri") == app.store.vless_active_uri
                badge = nodes_mod.ping_badge(node)
                sub = "%s • %s" % (links.label(node), links.address_name(node.get("server"), node.get("port")))
                items.append(Text(("✓ " if selected else "") + str(node.get("name") or "Узел"),
                                  sub + (" • " + t(badge) if badge else ""), accent=selected,
                                  on_click=lambda node=node: gp.node_menu(node)))
            if pages > 1:
                items.append(Text("Страница %d из %d" % (self.page_index + 1, pages), "Нажмите, чтобы листать",
                                  icon="msg_arrowright", on_click=lambda: self.turn_page(pages)))
            items.append(Text("Удалить все узлы", None, icon="msg_delete", on_click=gp.confirm_clear_nodes))
        items += [
            Divider(), Header("Настройки"),
            Selector("vless_engine", "Ядро", ("sing-box", "Mihomo"), 1 if app.store.engine == "mihomo" else 0,
                     gp.on_engine_changed, icon="msg_settings"),
            Switch("vless_failover_enabled", "Автовыбор по всем узлам", app.failover_enabled(),
                   lambda value: gp.on_setting_reconnect("vless_failover_enabled", value),
                   subtext="Выключено — только первый узел подписки"),
            Selector("vless_auto_check_minutes", "Автопроверка пинга",
                     ["Выкл"] + ["%d мин" % m for m in AUTO_PING_MINUTES[1:]],
                     self._index(AUTO_PING_MINUTES, gp.app.setting("vless_auto_check_minutes", 0)),
                     lambda i: gp.app.set_setting("vless_auto_check_minutes", AUTO_PING_MINUTES[i])),
            Selector("vless_browser_page_size", "Узлов на странице", [str(s) for s in PAGE_SIZES],
                     self._index(PAGE_SIZES, self.page_size()),
                     lambda i: (gp.app.set_setting("vless_browser_page_size", PAGE_SIZES[i]), gp.refresh())),
            Text("Скопировать логи ядра", None, icon="msg_copy", on_click=gp.copy_core_logs),
        ]
        return items

    def page_size(self):
        try:
            size = int(self.gp.app.setting("vless_browser_page_size", 20) or 20)
        except (TypeError, ValueError):
            size = 20
        return size if size in PAGE_SIZES else 20

    @staticmethod
    def _index(values, value):
        try:
            return list(values).index(int(value or 0))
        except (ValueError, TypeError):
            return 0

    def turn_page(self, pages):
        self.page_index = (self.page_index + 1) % pages
        self.gp.refresh()

    def subscriptions(self):
        gp, app = self.gp, self.gp.app
        hidden = app.hidden_sources()
        items = [Header("Подписки"),
                 Text("Обновить все", "Загрузить свежие списки узлов", icon="msg_retry", on_click=gp.refresh_subscriptions)]
        for sub in app.store.vless_subs:
            url = sub.get("url", "")
            off = url in hidden
            items.append(Text(str(sub.get("name") or url), "%d узлов%s" % (len(sub.get("nodes") or []),
                                                                            " • " + t("скрыта") if off else ""),
                              icon="msg_channel", on_click=lambda url=url: gp.subscription_menu(url)))
        return items

    # --- TG WS ---

    def tgws(self):
        gp = self.gp
        mode = gp.app.modes["tgws"]
        return [
            Header("TG WS"),
            Text("Как работает", "Telegram ходит через свои веб-адреса, сервер не нужен", icon="msg_info"),
            Switch("tgws_cfproxy_priority", "Сначала Cloudflare", mode.cf_priority(),
                   lambda value: gp.on_setting_reconnect("tgws_cfproxy_priority", value),
                   subtext="Помогает, если обычный путь заблокирован"),
            Text("Перезапустить", None, icon="msg_retry", on_click=gp.reconnect),
            Text("Ссылка tg://ws", "Включает TG WS у того, кто откроет", icon="msg_link",
                 on_click=lambda: gp.copy("tg://ws")),
        ]

    # --- AmneziaWG ---

    def awg(self):
        gp, store = self.gp, self.gp.app.store
        mode = gp.app.modes["awg"]
        items = [Header("AmneziaWG")]
        if store.awg_conf_content.strip():
            items.append(Text(store.awg_conf_name or "Конфиг", "WARP" if mode.is_warp() else "Свой конфиг", icon="msg_channel"))
        else:
            items.append(Text("Нет конфига", "Получите WARP или выберите .conf", icon="msg_info"))
        items += [
            Text("Получить WARP конфиг", "Бесплатный Cloudflare WARP, новый ключ", icon="msg_download",
                 accent=True, on_click=gp.new_warp),
            Text("Выбрать .conf файл", "Конфиг WireGuard или AmneziaWG", icon="msg_folder", on_click=gp.pick_awg_file),
            Text("Перезапустить", None, icon="msg_retry", on_click=gp.reconnect),
        ]
        if store.awg_conf_content.strip():
            items.append(Text("Удалить конфиг", None, icon="msg_delete", on_click=gp.confirm_clear_awg))
        items += [
            Divider(), Header("WARP"),
            EditText("awg_warp_port", "Порт WARP (пусто — случайный)", gp.app.setting("awg_warp_port", "")),
        ]
        return items

    # --- olcRTC ---

    def olcrtc(self):
        gp = self.gp
        mode = gp.app.modes["olcrtc"]
        active = mode.active_profile()
        items = [Header("olcRTC"),
                 Text("Импорт из буфера", "Ссылка olcrtc://, звонок или подписка", icon="msg_download", accent=True,
                      on_click=gp.import_olcrtc_from_clipboard)]
        if any(p.get("subscription_url") for p in mode.profiles()):
            items.append(Text("Обновить подписки", None, icon="msg_retry", on_click=gp.refresh_olcrtc_subscriptions))
        if mode.state == CONNECTED:
            status = mode.core_status()
            items.append(Text("Статус ядра", str(status.get("state", "")) + (" • " + str(status.get("message")) if status.get("message") else ""),
                              icon="msg_info"))
        if mode.profiles():
            items += [Divider(), Header("Профили")]
            for profile in mode.profiles():
                selected = active is not None and profile["id"] == active["id"]
                carrier = olcrtc_links.CARRIER_LABELS[olcrtc_links.CARRIERS.index(profile["carrier"])] \
                    if profile["carrier"] in olcrtc_links.CARRIERS else profile["carrier"]
                transport = olcrtc_links.TRANSPORT_LABELS[olcrtc_links.TRANSPORTS.index(profile["transport"])] \
                    if profile["transport"] in olcrtc_links.TRANSPORTS else profile["transport"]
                items.append(Text(("✓ " if selected else "") + profile["name"], "%s • %s" % (t(carrier), t(transport)),
                                  accent=selected, on_click=lambda p=profile: gp.olcrtc_menu(p)))
        return items

    # --- extra ---

    def extra(self):
        gp, app = self.gp, self.gp.app
        rules = len(app.store.wifi_rules)
        return [
            Header("Сеть"),
            Switch("dont_use_with_vpn", "Не использовать с VPN", app.setting("dont_use_with_vpn", True),
                   lambda value: gp.on_policy_setting("dont_use_with_vpn", value),
                   subtext="Выключать прокси, пока работает другой VPN"),
            Text("Правила Wi-Fi", "%d сетей" % rules if rules else "Режим или выключение для своих сетей",
                 icon="msg_language", page=self.wifi_rules),
            Switch("ipv6_enabled", "IPv6", gp.ipv6_enabled(), gp.on_ipv6_changed,
                   subtext="Выключено — Telegram работает только по IPv4"),
            Switch("proxy_plugins_via_greenpass", "Проксировать плагины", app.setting("proxy_plugins_via_greenpass", False),
                   gp.on_plugins_proxy_changed, subtext="Запросы других плагинов идут через GreenPass"),
            Divider(), Header("Звонки"),
            Switch("proxy_calls_via_proxy", "Звонки через прокси", app.calls_via_proxy(),
                   lambda value: gp.on_setting_reconnect("proxy_calls_via_proxy", value)),
            Switch("tgws_voip_relay_enabled", "Voice Relay", app.setting("tgws_voip_relay_enabled", True),
                   lambda value: app.set_setting("tgws_voip_relay_enabled", value),
                   subtext="Звонки через свой UDP-сервер"),
            Text("Настроить Voice Relay", "Сервер и ключ", icon="msg_calls", page=self.voice_relay),
            Divider(), Header("Подписки"),
            Text("HWID", gp.hwid_text(), icon="msg_devices", on_click=gp.ask_hwid),
            Divider(), Header("Локальные порты"),
            Text("Свои порты 127.0.0.1", "Пусто — по умолчанию", icon="msg_info"),
            EditText("local_port_vless", "Прокси (по умолчанию 10804)", app.setting("local_port_vless", "")),
            EditText("local_port_tgws", "TG WS (по умолчанию 10805)", app.setting("local_port_tgws", "")),
            EditText("local_port_awg", "AmneziaWG (по умолчанию 2337)", app.setting("local_port_awg", "")),
            EditText("local_port_olcrtc", "olcRTC (по умолчанию 11808)", app.setting("local_port_olcrtc", "")),
            Divider(), Header("Перенос"),
            Text("Экспорт настроек", "Файл в Избранное", icon="msg_share", on_click=gp.export_settings),
            Text("Импорт настроек", "Из файла .greenpass", icon="msg_download", on_click=gp.pick_import_file),
            Divider(), Header("Обновления"),
            Switch("plugin_autoupdate_enabled", "Автообновление", app.setting("plugin_autoupdate_enabled", True),
                   lambda value: app.set_setting("plugin_autoupdate_enabled", value),
                   subtext="Раз в сутки проверять GitHub"),
            Text("Проверить обновления", "Версия %s" % VERSION, icon="msg_retry",
                 on_click=gp.check_updates_now),
        ]

    def wifi_rules(self):
        gp, store = self.gp, self.gp.app.store
        items = [Header("Правила Wi-Fi"),
                 Text("Добавить текущую сеть", None, icon="msg_add", on_click=gp.add_current_wifi),
                 Text("Добавить по имени", None, icon="msg_edit", on_click=gp.ask_wifi_name)]
        for ssid, rule in sorted(store.wifi_rules.items()):
            label = "Прокси выключен" if rule == "off" else MODE_INFO[rule][0]
            items.append(Text(ssid, label, icon="msg_language", on_click=lambda ssid=ssid: gp.wifi_rule_menu(ssid)))
        return items

    def voice_relay(self):
        gp = self.gp
        return [
            Header("Voice Relay"),
            EditText("tgws_voip_relay_ip", "IPv4 сервера", gp.app.setting("tgws_voip_relay_ip", "")),
            EditText("tgws_voip_relay_port", "Порт (по умолчанию 8765)", gp.app.setting("tgws_voip_relay_port", "8765")),
            EditText("tgws_voip_relay_hmac", "HMAC-ключ (16-512 байт)", gp.app.setting("tgws_voip_relay_hmac", "")),
            Text("Проверить", "Пинг до сервера", icon="msg_speed", on_click=gp.ping_relay),
            Text("Скопировать tg://relay", None, icon="msg_copy", on_click=gp.copy_relay_link),
        ]
