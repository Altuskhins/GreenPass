from .foundation import *
from .protocols import *
from .tgws import *
from .native import *
from .subscriptions import *
from .hooks import *


class SettingsUiMixin:
    # Settings reloads look up the same PluginSettingsActivity members on every
    # toggle; Field/Method objects are reusable, so resolve each one only once.
    _settings_java_member_cache = {}

    def _settings_java_member(self, kind, cls, name, lookup):
        try:
            key = (kind, str(cls.getName()), str(name or ""))
        except:
            return lookup()
        cache = SettingsUiMixin._settings_java_member_cache
        if key not in cache:
            cache[key] = lookup()
        return cache[key]

    def _settings_java_field(self, cls, name):
        def _lookup():
            current = cls
            while current is not None:
                try:
                    field = current.getDeclaredField(name)
                    field.setAccessible(True)
                    return field
                except:
                    try:
                        current = current.getSuperclass()
                    except:
                        current = None
            return None
        return self._settings_java_member("field", cls, name, _lookup)

    def _settings_java_method(self, cls, name):
        def _lookup():
            current = cls
            while current is not None:
                try:
                    for method in list(current.getDeclaredMethods() or []):
                        if str(method.getName() or "") == str(name or ""):
                            method.setAccessible(True)
                            return method
                except:
                    pass
                try:
                    current = current.getSuperclass()
                except:
                    current = None
            return None
        return self._settings_java_member("method", cls, name, _lookup)

    def _bind_view_click(self, view, callback):
        if view is None or dynamic_proxy is None:
            return False
        try:
            class _Click(dynamic_proxy(View.OnClickListener)):
                def onClick(self, clicked_view):
                    try:
                        callback(clicked_view)
                    except Exception as exc:
                        try:
                            BulletinHelper.show_error("Ошибка интерфейса: %s" % str(exc))
                        except:
                            pass

            listener = _Click()
            view.setOnClickListener(listener)
            refs = list(getattr(self, "_settings_view_click_refs", []) or [])
            refs.append(listener)
            self._settings_view_click_refs = refs[-16:]
            return True
        except:
            return False

    def _build_settings_hero(self):
        try:
            fragment = get_last_fragment()
            context = fragment.getParentActivity() if fragment else None
            if context is None:
                return None

            dp = AndroidUtilities.dp
            outer = FrameLayout(context)
            # Keep the hero aligned with Telegram's standard settings cells.
            # A fixed inset also prevents the card from looking wider than the
            # rows below it on compact screens.
            outer.setPadding(dp(16), dp(8), dp(16), dp(8))

            card = LinearLayout(context)
            card.setOrientation(LinearLayout.VERTICAL)
            card.setPadding(dp(18), dp(18), dp(18), dp(18))

            background = GradientDrawable()
            background.setColor(Theme.getColor(Theme.key_windowBackgroundWhite))
            background.setCornerRadius(dp(20))
            background.setStroke(dp(1), Theme.getColor(Theme.key_divider))
            card.setBackground(background)
            card.setClickable(True)
            try:
                card.setForeground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_listSelector), 2))
            except:
                pass
            self._bind_view_click(card, lambda _view: self._open_plugin_update_menu())
            try:
                card.setElevation(float(dp(1)))
            except:
                pass

            top = LinearLayout(context)
            top.setOrientation(LinearLayout.HORIZONTAL)
            top.setGravity(Gravity.CENTER_VERTICAL)

            title = TextView(context)
            title.setText("GreenPass")
            title.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 23)
            title.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText))
            try:
                title.setTypeface(AndroidUtilities.getTypeface(AndroidUtilities.TYPEFACE_ROBOTO_MEDIUM))
            except:
                pass
            top.addView(title, LinearLayout.LayoutParams(0, -2, 1.0))

            version = str(getattr(self, "version", "") or "").strip()
            mode = self._settings_mode_title(self._get_connection_mode())
            mode_chip = TextView(context)
            mode_chip.setText(mode)
            mode_chip.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 12)
            mode_chip.setTextColor(Theme.getColor(Theme.key_featuredStickers_buttonText))
            mode_chip.setGravity(Gravity.CENTER)
            mode_chip.setPadding(dp(10), dp(4), dp(10), dp(4))
            try:
                mode_chip.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"))
                mode_chip.setLetterSpacing(0.04)
            except:
                pass
            chip_background = GradientDrawable()
            chip_background.setColor(Theme.getColor(Theme.key_featuredStickers_addButton))
            chip_background.setCornerRadius(dp(12))
            mode_chip.setBackground(chip_background)
            mode_chip.setClickable(True)
            self._bind_view_click(mode_chip, lambda _view: self._open_core_quick_menu())
            top.addView(mode_chip, LinearLayout.LayoutParams(-2, -2))
            card.addView(top, LinearLayout.LayoutParams(-1, -2))

            subtitle = TextView(context)
            subtitle.setText(Z("Универсальный прокси для Telegram") + ((" • " + version) if version else ""))
            subtitle.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 14)
            subtitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText))
            subtitle_params = LinearLayout.LayoutParams(-1, -2)
            subtitle_params.topMargin = dp(7)
            card.addView(subtitle, subtitle_params)

            status_text, status_color = self._settings_connection_badge()
            status = TextView(context)
            status.setText(Z(status_text))
            status.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 13)
            status.setTextColor(status_color)
            status.setPadding(dp(10), dp(6), dp(10), dp(6))
            try:
                status_background = GradientDrawable()
                status_background.setColor(Theme.getColor(Theme.key_dialogBackground))
                status_background.setCornerRadius(dp(12))
                status_background.setStroke(dp(1), status_color)
                status.setBackground(status_background)
            except:
                pass
            status_params = LinearLayout.LayoutParams(-1, -2)
            status_params.topMargin = dp(12)
            card.addView(status, status_params)

            outer.addView(card, FrameLayout.LayoutParams(-1, -2))
            return _Custom(view=outer)
        except:
            return None

    def _plugin_autoupdate_enabled(self):
        try:
            value = self.get_setting("plugin_autoupdate_enabled", True)
        except:
            return True
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() not in ("", "0", "false", "off", "no")

    def _set_plugin_autoupdate_enabled(self, enabled, notify=False):
        value = bool(enabled)
        self._set_setting_value("plugin_autoupdate_enabled", value, reload_settings=False)
        if value:
            self._autoupdate_last_check_ts = 0
            threading.Thread(target=lambda: self._run_autoupdate_check(force=False), daemon=True).start()
        if notify:
            BulletinHelper.show_success("Автообновление плагина включено" if value else "Автообновление плагина выключено")
        return True

    def _check_plugin_update_now(self):
        if self._autoupdate_in_progress:
            BulletinHelper.show_info("Обновления уже проверяются")
            return True
        BulletinHelper.show_info("Проверяю обновления GreenPass…")
        threading.Thread(target=lambda: self._run_autoupdate_check(force=True), daemon=True).start()
        return True

    def _open_plugin_update_menu(self):
        activity = self._current_activity()
        if activity is None:
            return False
        enabled = self._plugin_autoupdate_enabled()
        builder = AlertDialogBuilder(activity)
        builder.set_title("Обновления GreenPass")
        builder.set_message("Версия: %s\nАвтообновление: %s" % (
            str(getattr(self, "version", "") or ""),
            "включено" if enabled else "выключено",
        ))

        def _check(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._check_plugin_update_now()

        def _toggle(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._set_plugin_autoupdate_enabled(not enabled, notify=True)

        builder.set_items(["Проверить обновления"], _check)
        builder.set_positive_button("Выключить автообновление" if enabled else "Включить автообновление", _toggle)
        builder.set_negative_button("Закрыть", lambda dlg, which: dlg.dismiss())
        builder.show()
        return True

    def _show_plugin_update_available(self, version, archive_path):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_info("Доступно обновление GreenPass %s" % str(version))
            return False
        self._set_setting_value("plugin_autoupdate_prompted_version", str(version or ""), reload_settings=False)
        builder = AlertDialogBuilder(activity)
        builder.set_title("Доступно обновление")
        builder.set_message("GreenPass %s готов к установке." % str(version))

        def _install(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._open_elyx_update_archive(archive_path)

        builder.set_positive_button("Установить", _install)
        builder.set_negative_button("Позже", lambda dlg, which: dlg.dismiss())
        builder.show()
        return True

    def _core_autoupdate_enabled(self):
        try:
            value = self.get_setting("core_autoupdate_enabled", True)
        except:
            return True
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() not in ("", "0", "false", "off", "no")

    def _set_core_autoupdate_enabled(self, enabled, notify=False):
        value = bool(enabled)
        self._set_setting_value("core_autoupdate_enabled", value, reload_settings=False)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        if value and self._libsingbox_addon_status(quick=True) in ("missing", "outdated"):
            self._update_outdated_core_in_background()
        if notify:
            BulletinHelper.show_success("Автообновление ядра включено" if value else "Автообновление ядра выключено")
        return True

    def _check_core_update_now(self):
        if self._vless_prepare_in_progress:
            BulletinHelper.show_info("Ядро уже загружается")
            return True
        status = self._libsingbox_addon_status()
        if status == "current":
            BulletinHelper.show_success("Ядро уже актуально")
            return True
        if status == "missing":
            self._download_vless_addon()
            return True
        if self._update_outdated_core_in_background(force=True):
            BulletinHelper.show_info("Обновляю ядро в фоне…")
            return True
        BulletinHelper.show_error("Не удалось запустить обновление ядра")
        return False

    def _open_core_quick_menu(self):
        activity = self._current_activity()
        if activity is None:
            return False
        enabled = self._core_autoupdate_enabled()
        status = self._libsingbox_addon_status(quick=True)
        status_text = "загружается…" if self._vless_prepare_in_progress else {
            "current": "установлено и актуально",
            "outdated": "требуется обновление",
            "missing": "не установлено",
            "checking": "проверяется…",
        }.get(status, "состояние неизвестно")
        builder = AlertDialogBuilder(activity)
        builder.set_title("Режим и ядро")
        builder.set_message("Режим: %s\nЯдро GreenPass: %s\nАвтообновление: %s" % (
            self._settings_mode_title(self._get_connection_mode()),
            status_text,
            "включено" if enabled else "выключено",
        ))

        def _check_now(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._check_core_update_now()

        def _toggle(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._set_core_autoupdate_enabled(not enabled, notify=True)

        builder.set_items(["Проверить обновление ядра"], _check_now)
        builder.set_positive_button("Выключить автообновление" if enabled else "Включить автообновление", _toggle)
        builder.set_negative_button("Закрыть", lambda dlg, which: dlg.dismiss())
        builder.show()
        return True

    def _open_greenpass_import_file_picker(self):
        try:
            Intent = jclass("android.content.Intent") if jclass is not None else find_class("android.content.Intent")
            intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.setType("*/*")
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            activity = self._current_activity()
            if activity is not None:
                activity.startActivityForResult(intent, int(GREENPASS_IMPORT_FILE_PICKER_REQ))
            else:
                BulletinHelper.show_error("Не удалось открыть файл")
        except Exception as exc:
            BulletinHelper.show_error("Ошибка выбора: %s" % str(exc))

    def _confirm_greenpass_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт")
            return
        try:
            name = str(display_name or GREENPASS_EXPORT_FILE_NAME)
        except:
            name = GREENPASS_EXPORT_FILE_NAME
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Импорт GreenPass")
            builder.set_message("Импортировать настройки из %s?\nТекущие настройки будут заменены." % name)

            def _on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._process_greenpass_import_file_path(file_path)

            def _on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Импортировать", _on_yes)
            builder.set_negative_button("Отмена", _on_no)
            builder.show()
        except Exception as exc:
            BulletinHelper.show_error("Ошибка импорта: %s" % str(exc))

    def _confirm_singconf_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт")
            return
        try:
            name = str(display_name or os.path.basename(str(file_path)) or "config.singconf")
        except:
            name = "config.singconf"
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Импорт sing-box")
            builder.set_message("Импортировать sing-box конфиг из %s?" % name)

            def _on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._process_singconf_import_file_path(file_path, name)

            def _on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Импортировать", _on_yes)
            builder.set_negative_button("Отмена", _on_no)
            builder.show()
        except Exception as exc:
            BulletinHelper.show_error("Ошибка импорта: %s" % str(exc))

    def _confirm_qwdtt_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть qWDTT")
            return
        name = str(display_name or os.path.basename(str(file_path)) or "config.qwdtt")
        builder = AlertDialogBuilder(activity)
        builder.set_title("Импорт qWDTT")
        builder.set_message("Импортировать %s?" % name)

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._process_qwdtt_import_file_path(file_path)

        builder.set_positive_button("Импортировать", _on_yes)
        builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
        builder.set_cancelable(True)
        builder.show()

    def _confirm_mihomo_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт")
            return
        name = str(display_name or os.path.basename(str(file_path)) or "config.mihomo")
        builder = AlertDialogBuilder(activity)
        builder.set_title("Импорт Mihomo")
        builder.set_message("Импортировать Mihomo конфиг из %s?" % name)

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._process_mihomo_import_file_path(file_path, name)

        builder.set_positive_button("Импортировать", _on_yes)
        builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
        builder.set_cancelable(True)
        builder.show()

    def _excluded_wifi_menu_subtext(self):
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        _, current = self._active_wifi_state()
        if current and current in rules:
            return "%d сет. • %s" % (len(rules), self._wifi_rule_mode_title(rules[current]))
        return "%d сет." % len(rules) if rules else "Не настроено"

    def _create_themed_dialog_input(self, activity, hint=""):
        try:
            from org.telegram.ui.Components import EditTextBoldCursor
            field = EditTextBoldCursor(activity)
            field.setBackground(None)
        except:
            from android.widget import EditText as AndroidEditText
            field = AndroidEditText(activity)
        text_color = Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)
        hint_color = Theme.getColor(Theme.key_windowBackgroundWhiteHintText)
        accent_color = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)
        field.setTextColor(text_color)
        field.setHintTextColor(hint_color)
        field.setHint(str(hint or ""))
        field.setSingleLine(True)
        field.setPadding(
            0, AndroidUtilities.dp(8), 0, AndroidUtilities.dp(8),
        )
        try:
            field.setCursorColor(accent_color)
            field.setLineColors(
                Theme.getColor(Theme.key_dialogInputField),
                Theme.getColor(Theme.key_dialogInputFieldActivated),
                Theme.getColor(Theme.key_text_RedBold),
            )
        except:
            pass
        layout = LinearLayout(activity)
        layout.setOrientation(LinearLayout.VERTICAL)
        layout.setPadding(
            AndroidUtilities.dp(24), 0,
            AndroidUtilities.dp(24), AndroidUtilities.dp(8),
        )
        layout.addView(field, LinearLayout.LayoutParams(-1, -2))
        return field, layout

    def _prompt_add_excluded_wifi(self):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return False
        try:
            from android.text import InputFilter
            field, field_view = self._create_themed_dialog_input(activity, "SSID")
            field.setFilters([InputFilter.LengthFilter(64)])
            builder = AlertDialogBuilder(activity)
            builder.set_title("Добавить WIFI сеть")
            builder.set_view(field_view)

            def _save(dlg, which):
                ssid = self._normalize_wifi_ssid(field.getText())
                if not ssid:
                    BulletinHelper.show_error("Укажите SSID сети")
                    return
                try:
                    dlg.dismiss()
                except:
                    pass
                self._open_wifi_rule_picker(ssid)

            builder.set_positive_button("Добавить", _save)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.show()
            return True
        except:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return False

    def _open_wifi_rule_picker(self, value):
        ssid = self._normalize_wifi_ssid(value)
        if not ssid:
            return False
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            return False
        choices = [("off", "Без прокси")] + list(self._settings_mode_choices())
        if ssid in self._sanitize_wifi_mode_rules(self._wifi_mode_rules):
            choices.append(("delete", "Удалить правило"))
        modes = [mode for mode, label in choices]
        labels = [label for mode, label in choices]
        builder = AlertDialogBuilder(activity)
        builder.set_title(ssid)

        def _select(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            try:
                mode = modes[int(which)]
            except:
                return
            if mode == "delete":
                self._remove_excluded_wifi_ssid(ssid)
            else:
                self._set_wifi_rule(ssid, mode)

        builder.set_items(labels, _select)
        builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
        builder.show()
        return True

    def _create_excluded_wifi_subpage(self):
        wifi_active, current = self._active_wifi_state()
        current_text = current or ("SSID недоступен" if wifi_active else "WIFI не подключён")
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        items = [
            Header(text="Исключённые WIFI сети"),
            Text(
                text="Настроить текущую сеть",
                subtext=current_text,
                icon="msg_link",
                on_click=lambda *a: self._add_current_wifi_to_excluded(),
            ),
            Text(
                text="Добавить сеть",
                icon="msg_link",
                on_click=lambda *a: self._prompt_add_excluded_wifi(),
            ),
            Divider(),
            Header(text="Сети"),
        ]
        if not rules:
            items.append(Text(text="Список пуст", icon="msg_list"))
        else:
            for ssid, mode in rules.items():
                items.append(Text(
                    text=ssid,
                    subtext=self._wifi_rule_mode_title(mode),
                    icon="msg2_proxy_off" if mode == "off" else self._settings_mode_icon(mode),
                    on_click=lambda *a, ssid=ssid: self._open_wifi_rule_picker(ssid),
                ))
        return items

    def _regenerate_subscription_hwid(self):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return False
        try:
            from android.text import InputFilter
            from android.text.method import DigitsKeyListener
            field, field_view = self._create_themed_dialog_input(activity, "16 hex-символов")
            field.setText(_get_or_create_subscription_hwid())
            field.setSelection(field.length())
            field.setKeyListener(DigitsKeyListener.getInstance("0123456789abcdefABCDEF"))
            field.setFilters([InputFilter.LengthFilter(16)])
            builder = AlertDialogBuilder(activity)
            builder.set_title("Изменить HWID")
            builder.set_view(field_view)

            def _save(dlg, which):
                value = str(field.getText() or "").strip().lower()
                if not _set_subscription_hwid_custom(value):
                    BulletinHelper.show_error("HWID должен содержать ровно 16 hex-символов")
                    return
                self._set_setting_value("subscription_hwid_custom", value, reload_settings=False)
                try:
                    dlg.dismiss()
                except:
                    pass
                BulletinHelper.show_success("HWID подписок обновлён")
                self._refresh_settings_without_reopen(reload_stack=True)

            builder.set_positive_button("Сохранить", _save)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("Не удалось изменить HWID: " + str(exc))
            return False

    def _copy_tgws_voip_relay_link(self):
        link, error = self._tgws_voip_relay_link()
        if not link:
            BulletinHelper.show_error(error)
            return
        self._copy_link(link)

    def _reload_settings_ui(self, delay_ms=100):
        try:
            if bool(getattr(self, "_reload_ui_pending", False)):
                return
            self._reload_ui_pending = True
        except:
            pass

        def _run():
            try:
                self._reload_ui_pending = False
            except:
                pass
            try:
                frag = get_last_fragment()
            except:
                frag = None

            def _fallback_full_reload():
                try:
                    inst = self._plugins_controller_instance()
                    pid = self._plugin_settings_id()
                    if inst is not None and pid:
                        inst.loadPluginSettings(pid)
                        return
                except:
                    pass
                try:
                    self._set_setting_value("__reload__", time.time(), reload_settings=True)
                except:
                    pass

            if frag is None:
                return

            try:
                cls = frag.getClass()
                frag_name = str(cls.getName() or "")
            except:
                cls = None
                frag_name = ""
            if frag_name != "com.exteragram.messenger.plugins.ui.PluginSettingsActivity" or cls is None:
                return

            try:
                plugin_field = self._settings_java_field(cls, "plugin")
                plugin_obj = plugin_field.get(frag)
                frag_pid = str(plugin_obj.getId() or "") if plugin_obj is not None else ""
            except:
                frag_pid = ""
            if frag_pid != str(self._plugin_settings_id() or ""):
                return

            try:
                callback_field = self._settings_java_field(cls, "createSubFragmentCallback")
                callback_obj = callback_field.get(frag)
            except:
                callback_obj = None

            if callback_obj is not None:
                try:
                    method = self._settings_java_method(cls, "lambda$didReceivedNotification$1")
                    if method is not None:
                        method.invoke(frag)
                        return
                except:
                    pass

            try:
                list_field = self._settings_java_field(cls, "listView")
                list_view = list_field.get(frag)
            except:
                list_view = None
            if list_view is None:
                _fallback_full_reload()
                return

            try:
                adapter = getattr(list_view, "adapter", None)
            except:
                adapter = None
            if adapter is None:
                _fallback_full_reload()
                return

            try:
                adapter.update(True)
            except Exception as e:
                err = ""
                try:
                    err = str(e)
                except:
                    err = ""
                if "RecyclerView is computing a layout" in err:
                    try:
                        run_on_ui_thread(_run, 300)
                        return
                    except:
                        pass
                _fallback_full_reload()

        try:
            run_on_ui_thread(_run, int(delay_ms))
        except:
            try:
                self._reload_ui_pending = False
            except:
                pass
            _run()

    def _reload_settings_stack_ui(self, delay_ms=100):
        try:
            if bool(getattr(self, "_reload_stack_ui_pending", False)):
                return
            self._reload_stack_ui_pending = True
        except:
            pass

        def _run():
            try:
                self._reload_stack_ui_pending = False
            except:
                pass
            try:
                frag = get_last_fragment()
                stack = frag.getParentLayout().getFragmentStack()
            except:
                self._reload_settings_ui()
                return

            pid = str(self._plugin_settings_id() or "")
            try:
                NotificationCenter.getGlobalInstance().postNotificationName(
                    NotificationCenter.pluginSettingsRegistered,
                    pid,
                )
                return
            except:
                pass

            def _reload_fragment(parent):
                cls = None
                try:
                    cls = parent.getClass()
                    if str(cls.getName() or "") != "com.exteragram.messenger.plugins.ui.PluginSettingsActivity":
                        return False

                    plugin_field = self._settings_java_field(cls, "plugin")
                    plugin_obj = plugin_field.get(parent)
                    if str(plugin_obj.getId() or "") != pid:
                        return False

                    callback_field = self._settings_java_field(cls, "createSubFragmentCallback")
                    if callback_field.get(parent) is None:
                        return False
                except:
                    return False

                try:
                    method = self._settings_java_method(cls, "lambda$didReceivedNotification$1")
                    if method is not None:
                        method.invoke(parent)
                        return True
                except:
                    pass

                try:
                    list_field = self._settings_java_field(cls, "listView")
                    list_view = list_field.get(parent) if list_field is not None else None
                    adapter = getattr(list_view, "adapter", None) if list_view is not None else None
                    if adapter is None:
                        return False
                    adapter.update(True)
                    return True
                except Exception as e:
                    err = ""
                    try:
                        err = str(e)
                    except:
                        err = ""
                    if "RecyclerView is computing a layout" in err:
                        try:
                            run_on_ui_thread(_run, 300)
                            return True
                        except:
                            pass
                return False

            touched = False
            try:
                for index in range(int(stack.size()) - 1, -1, -1):
                    try:
                        if _reload_fragment(stack.get(index)):
                            touched = True
                    except:
                        continue
            except:
                pass

            if not touched:
                self._reload_settings_ui()

        try:
            run_on_ui_thread(_run, int(delay_ms))
        except:
            try:
                self._reload_stack_ui_pending = False
            except:
                pass
            _run()

    def _refresh_settings_without_reopen(self, reload_main=False, reload_stack=False):
        if reload_stack:
            self._reload_settings_stack_ui()
        else:
            self._reload_settings_ui()
        if reload_main:
            run_on_ui_thread(self._refresh_mode_summary)

    def _install_settings_theme_observer(self):
        if getattr(self, "_settings_theme_observer", None) is not None or dynamic_proxy is None:
            return
        try:
            delegate = find_class("org.telegram.messenger.NotificationCenter$NotificationCenterDelegate")
            plugin = self

            class _ThemeObserver(dynamic_proxy(delegate)):
                def didReceivedNotification(self, notification_id, account, *args):
                    try:
                        theme_event = getattr(NotificationCenter, "didSetNewTheme", None)
                        accent_event = getattr(NotificationCenter, "themeAccentColorChanged", None)
                        if ((theme_event is not None and int(notification_id) == int(theme_event)) or
                                (accent_event is not None and int(notification_id) == int(accent_event))):
                            run_on_ui_thread(
                                lambda: plugin._refresh_settings_without_reopen(reload_main=True, reload_stack=True),
                                120,
                            )
                    except:
                        pass

            observer = _ThemeObserver()
            events = []
            for event_name in ("didSetNewTheme", "themeAccentColorChanged"):
                try:
                    event = getattr(NotificationCenter, event_name, None)
                    if event is None:
                        continue
                    NotificationCenter.getGlobalInstance().addObserver(observer, event)
                    events.append(event)
                except:
                    continue
            self._settings_theme_observer_events = events
            self._settings_theme_observer = observer
        except:
            self._settings_theme_observer = None

    def _remove_settings_theme_observer(self):
        observer = getattr(self, "_settings_theme_observer", None)
        self._settings_theme_observer = None
        if observer is None:
            return
        events = list(getattr(self, "_settings_theme_observer_events", []) or [])
        self._settings_theme_observer_events = []
        if not events:
            try:
                events = [NotificationCenter.didSetNewTheme]
            except:
                events = []
        for event in events:
            try:
                NotificationCenter.getGlobalInstance().removeObserver(observer, event)
            except:
                pass

    def _copy_active_olcrtc_link(self):
        link = self._active_olcrtc_link()
        if not link:
            BulletinHelper.show_error("Нет olcRTC ссылки")
            return
        self._copy_link(link)

    def _confirm_remove_olcrtc_profile(self, profile_id):
        profile = self._find_olcrtc_profile(profile_id)
        if not profile:
            BulletinHelper.show_error("Профиль не найден")
            return
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if not activity:
            self._delete_olcrtc_profile(profile_id)
            return
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Удалить профиль?")
            builder.set_message(self._olcrtc_profile_name(profile))

            def on_yes(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass
                self._delete_olcrtc_profile(profile_id)

            def on_no(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass

            builder.set_positive_button("Удалить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            try:
                builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
            except:
                pass
            builder.show()
        except:
            self._delete_olcrtc_profile(profile_id)

    def _create_olcrtc_profiles_subpage(self):
        self._ensure_olcrtc_legacy_profile()
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        self._olcrtc_profiles = profiles
        active_id = str(self._olcrtc_active_profile_id or "")
        transport_choices = self._olcrtc_transport_choices()
        items = [
            Header(text="olcRTC профили"),
            Selector(
                key="olcrtc_carrier",
                text="Провайдер",
                default=self._olcrtc_carrier_index(),
                items=list(OLCRTC_CARRIER_LABELS),
                icon="msg_list",
                on_change=self._on_olcrtc_carrier_changed,
            ),
            Selector(
                key="olcrtc_transport",
                text="Транспорт",
                default=self._olcrtc_transport_choice_index(),
                items=[self._olcrtc_transport_label(value) for value in transport_choices],
                icon="msg_list",
                on_change=self._on_olcrtc_transport_changed,
            ),
            EditText(
                key="olcrtc_room_id",
                hint="room_id",
                default=self._get_olcrtc_room_id(),
                multiline=True,
                max_length=2000,
            ),
            EditText(
                key="olcrtc_key_hex",
                hint="key_hex",
                default=self._get_olcrtc_key_hex(),
                multiline=True,
                max_length=256,
            ),
            Text(text="Импорт из буфера", accent=True, icon="msg_link", on_click=lambda *a: self._import_olcrtc_from_clipboard()),
        ]
        if self._get_olcrtc_transport() == "vp8channel":
            fps, batch = self._get_olcrtc_vp8_options()
            items[4:4] = [
                EditText(key="olcrtc_vp8_fps", hint="VP8 FPS (1-120)", default=str(fps), multiline=False, max_length=3),
                EditText(key="olcrtc_vp8_batch_size", hint="VP8 batch (1-64)", default=str(batch), multiline=False, max_length=2),
            ]
        subscription_urls = self._olcrtc_subscription_urls()
        if subscription_urls:
            items.append(Text(text="Обновить подписки", icon="msg_retry", on_click=lambda *a: self._refresh_olcrtc_subscriptions(silent=False)))
            if self._olcrtc_subscriptions_stale():
                self._refresh_olcrtc_subscriptions(silent=True)
        active_link = self._active_olcrtc_link()
        if active_link:
            items.append(Text(text="Скопировать ссылку", icon="msg_link", on_click=lambda *a: self._copy_active_olcrtc_link()))
        if profiles:
            items.append(Divider())
            items.append(Header(text="Профили"))
        for profile in profiles:
            pid = str(profile.get("id", "") or "")
            label = self._olcrtc_profile_name(profile)
            subtext = "%s / %s" % (
                self._olcrtc_carrier_label(profile.get("carrier", "")),
                self._olcrtc_transport_label(profile.get("transport", "")),
            )
            items.append(Text(
                text=("🟢 " if pid == active_id else "") + label,
                subtext=subtext,
                icon="msg2_proxy_on" if pid == active_id else "msg2_proxy_off",
                accent=bool(pid == active_id),
                on_click=lambda *a, pid=pid: self._activate_olcrtc_profile(pid, connect=True),
                on_long_click=lambda view, pid=pid: self._confirm_remove_olcrtc_profile(pid),
            ))
        if not profiles:
            items.append(Divider())
            items.append(Text(text="Профилей нет", icon="msg_info"))
        return items

    def _open_awg_file_picker(self):
        try:
            Intent = jclass("android.content.Intent") if jclass is not None else find_class("android.content.Intent")
            intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.setType("*/*")
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            activity = None
            try:
                fragment = get_last_fragment()
                if fragment is not None:
                    activity = fragment.getParentActivity()
            except:
                activity = None
            if activity is None:
                try:
                    AU = find_class("org.telegram.messenger.AndroidUtilities")
                    activity = AU.getActivity()
                except:
                    activity = None
            if activity is not None:
                activity.startActivityForResult(intent, int(AWG_FILE_PICKER_REQ))
            else:
                BulletinHelper.show_error("Не удалось открыть выбор файла")
        except Exception as exc:
            BulletinHelper.show_error("Ошибка выбора файла: %s" % str(exc))

    def _confirm_clear_vless_nodes(self):
        counts = self._vless_counts()
        if int(counts.get("nodes", 0) or 0) <= 0:
            BulletinHelper.show_info("Нет узлов")
            return True
        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        builder = AlertDialogBuilder(activity)
        builder.set_title("Очистить узлы?")
        builder.set_message("Все узлы и подписки будут удалены. Действие необратимо.")

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._clear_vless_nodes()

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Очистить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _confirm_remove_vless_node(self, uri):
        target_uri = str(uri or "")
        if not target_uri:
            return True
        node = self._find_vless_node(target_uri)
        if node is None:
            return True

        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        builder = AlertDialogBuilder(activity)
        try:
            title = "Удалить %s?" % _proxy_protocol_label(node)
        except:
            title = "Удалить узел?"
        builder.set_title(title)
        builder.set_message(self._vless_node_label(node))

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._remove_vless_uri(target_uri)

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Удалить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _open_proxy_import_preview(self, activity, uri, details, initial_status, initial_kind="checking"):
        try:
            dp = AndroidUtilities.dp
            accent = Theme.getColor(Theme.key_featuredStickers_addButton)
            text_color = Theme.getColor(Theme.key_dialogTextBlack)
            muted_color = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText)
            green_color = Theme.getColor(Theme.key_windowBackgroundWhiteGreenText)
            red_color = Theme.getColor(Theme.key_text_RedBold)

            container = LinearLayout(activity)
            container.setOrientation(LinearLayout.VERTICAL)
            container.setPadding(dp(20), dp(4), dp(20), dp(10))

            protocol = _proxy_protocol_label(details)
            protocol_chip = TextView(activity)
            protocol_chip.setText(protocol)
            protocol_chip.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 12)
            protocol_chip.setTextColor(Theme.getColor(Theme.key_featuredStickers_buttonText))
            protocol_chip.setGravity(Gravity.CENTER)
            protocol_chip.setPadding(dp(10), dp(4), dp(10), dp(4))
            try:
                protocol_chip.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"))
                protocol_chip.setLetterSpacing(0.04)
            except:
                pass
            protocol_bg = GradientDrawable()
            protocol_bg.setColor(accent)
            protocol_bg.setCornerRadius(dp(12))
            protocol_chip.setBackground(protocol_bg)
            chip_lp = LinearLayout.LayoutParams(-2, -2)
            chip_lp.bottomMargin = dp(12)
            container.addView(protocol_chip, chip_lp)

            server = str(details.get("server", "") or "")[:120]
            port = str(details.get("port", "") or "")[:12]
            endpoint = TextView(activity)
            endpoint.setText((server + (":" + port if port else "")) or Z("Адрес не указан"))
            endpoint.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 18)
            endpoint.setTextColor(text_color)
            try:
                endpoint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"))
            except:
                pass
            endpoint.setSingleLine(True)
            container.addView(endpoint, LinearLayout.LayoutParams(-1, -2))

            network = str(details.get("network", "tcp") or "tcp")
            security = str(details.get("security", "none") or "none")
            meta = TextView(activity)
            meta.setText(Z("Транспорт") + ": " + network + "  •  " + Z("Безопасность") + ": " + security)
            meta.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 14)
            meta.setTextColor(muted_color)
            meta_lp = LinearLayout.LayoutParams(-1, -2)
            meta_lp.topMargin = dp(5)
            container.addView(meta, meta_lp)

            params = dict(details.get("params", {}) or {})
            route_parts = []
            for label, value in (
                ("SNI", params.get("sni", "")),
                ("Host", params.get("host", "")),
                ("Path", params.get("path", "")),
            ):
                value = str(value or "").strip()
                if value:
                    route_parts.append(label + ": " + value[:96])
            if route_parts:
                route = TextView(activity)
                route.setText("\n".join(route_parts))
                route.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 13)
                route.setTextColor(muted_color)
                route_lp = LinearLayout.LayoutParams(-1, -2)
                route_lp.topMargin = dp(10)
                container.addView(route, route_lp)

            status = TextView(activity)
            status.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 14)
            status.setPadding(dp(12), dp(9), dp(12), dp(9))
            try:
                status.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"))
            except:
                pass
            status_lp = LinearLayout.LayoutParams(-1, -2)
            status_lp.topMargin = dp(16)
            container.addView(status, status_lp)

            def _update_status(status_text, kind="checking"):
                color = green_color if kind == "ok" else red_color if kind == "error" else accent
                status.setText(Z(str(status_text or "")))
                status.setTextColor(color)
                status_bg = GradientDrawable()
                status_bg.setColor(Theme.getColor(Theme.key_dialogBackground))
                status_bg.setCornerRadius(dp(14))
                status_bg.setStroke(dp(1), color)
                status.setBackground(status_bg)

            _update_status(initial_status, initial_kind)

            dialog = AlertDialogBuilder(activity)
            dialog.set_title(str(details.get("name", protocol) or protocol)[:80])
            dialog.set_view(container)

            def _connect(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._activate_vless_uri(uri, enable_plugin=True)

            dialog.set_positive_button("Подключить", _connect)
            dialog.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            dialog.set_cancelable(True)
            dialog.show()
            return dialog, _update_status
        except Exception:
            return None, None

    def _open_core_download_progress(self):
        activity = self._current_activity()
        if activity is None:
            return None, lambda *_args: None
        try:
            container = LinearLayout(activity)
            container.setOrientation(LinearLayout.VERTICAL)
            padding = AndroidUtilities.dp(20)
            container.setPadding(padding, AndroidUtilities.dp(8), padding, AndroidUtilities.dp(12))

            label = TextView(activity)
            label.setText("%s • 0%%" % Z("Подготовка"))
            label.setTextSize(16)
            try:
                label.setTextColor(Theme.getColor(Theme.key_dialogTextBlack))
            except:
                pass

            progress = LineProgressView(activity)
            try:
                progress.setProgressColor(Theme.getColor(Theme.key_featuredStickers_addButton))
                progress.setBackColor(Theme.getColor(Theme.key_dialogLineProgressBackground))
            except:
                pass
            progress.setProgress(0.0, False)

            text_lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            bar_lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, AndroidUtilities.dp(6))
            bar_lp.setMargins(0, AndroidUtilities.dp(12), 0, AndroidUtilities.dp(8))
            container.addView(label, text_lp)
            container.addView(progress, bar_lp)

            dialog = AlertDialogBuilder(activity, _AlertDialogBuilder.ALERT_TYPE_MESSAGE)
            dialog.set_title("Ядро GreenPass")
            dialog.set_view(container)
            dialog.set_cancelable(False)
            dialog.show()

            def _update(value, stage="Скачивание"):
                value = max(0.0, min(1.0, float(value)))
                def _ui():
                    label.setText("%s • %d%%" % (Z(stage), int(value * 100)))
                    progress.setProgress(value, True)
                run_on_ui_thread(_ui)

            return dialog, _update
        except:
            return None, lambda *_args: None

    def _confirm_delete_vless_addon(self):
        if not self._has_libvless_addon():
            BulletinHelper.show_info("Ядро не установлено")
            return True
        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        builder = AlertDialogBuilder(activity)
        builder.set_title("Удалить ядро?")
        builder.set_message("Файл ядра прокси будет удалён. Его можно скачать снова.")

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._delete_vless_addon()

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Удалить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _open_plugin_settings(self, context):
        def _run():
            try:
                primary_id = str(self._plugin_settings_id() or "")
            except:
                primary_id = str(getattr(self, "id", "") or "")
            plugin_ids = []
            for candidate in (primary_id, str(getattr(self, "id", "") or ""), "GreenPass", "greenpass"):
                if candidate and candidate not in plugin_ids:
                    plugin_ids.append(candidate)
            try:
                PC = find_class("com.exteragram.messenger.plugins.PluginsController")
            except:
                PC = None
            try:
                PSA = find_class("com.exteragram.messenger.plugins.ui.PluginSettingsActivity")
            except:
                PSA = None

            try:
                if PC:
                    inst = None
                    try:
                        inst = PC.getInstance()
                    except:
                        inst = None
                    if inst is not None and hasattr(inst, "plugins") and PSA:
                        plugin_obj = None
                        for pid in plugin_ids:
                            try:
                                plugin_obj = inst.plugins.get(pid)
                            except:
                                plugin_obj = None
                            if plugin_obj is not None:
                                break
                        if plugin_obj is not None:
                            frag = get_last_fragment()
                            if frag is not None:
                                frag.presentFragment(PSA(plugin_obj))
                                return

                    for x in plugin_ids:
                        try:
                            r = PC.openPluginSettings(x)
                            if bool(r):
                                return
                        except:
                            pass
            except:
                pass

            try:
                frag = get_last_fragment()
                if frag and PC:
                    PC.getInstance().openPluginSettings(primary_id, frag)
                    return
            except:
                pass

        try:
            run_on_ui_thread(_run)
        except:
            _run()

    def _get_clipboard_text(self):
        try:
            from android.content import Context
            ctx = ApplicationLoader.applicationContext
            clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
            if clipboard is None:
                return ""
            clip = clipboard.getPrimaryClip()
            if clip is None or clip.getItemCount() <= 0:
                return ""
            return str(clip.getItemAt(0).coerceToText(ctx) or "")[:VLESS_IMPORT_CLIPBOARD_MAX]
        except:
            return ""

    def _confirm_olcrtc_link(self, data, uri):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть подтверждение")
            return False
        try:
            carrier = str(data.get("carrier", "") or "").strip().lower() or self._get_olcrtc_carrier()
            transport = str(data.get("transport", "") or "").strip().lower() or self._get_olcrtc_transport()
            room_id = str(data.get("room_id", "") or "").strip()
            client_id = str(data.get("client_id", "") or "").strip()
            key_hex = str(data.get("key_hex", "") or "").strip()
            key_mask = key_hex[:6] + "..." + key_hex[-6:] if len(key_hex) > 12 else "***"
            message = "\n".join([
                "Подключиться к olcRTC?",
                "",
                "Провайдер: %s" % self._olcrtc_carrier_label(carrier),
                "Транспорт: %s" % self._olcrtc_transport_label(transport),
                "Комната: %s" % (room_id[:120] if room_id else "—"),
                "Клиент: %s" % (client_id[:80] if client_id else "—"),
                "Ключ: %s" % key_mask,
            ])
            builder = AlertDialogBuilder(activity)
            builder.set_title("Подключение olcRTC")
            builder.set_message(message)

            def on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._apply_olcrtc_import_data(data, connect=True, imported_link=str(uri or ""))

            def on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Подключить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("olcRTC: %s" % str(exc))
            return False

    def _confirm_tgws_link(self, uri="tg://ws"):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть подтверждение")
            return False
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Подключение TG WS")
            builder.set_message("Включить режим TG WS и применить локальный прокси Telegram?")

            def on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._handle_tgws_link(uri, confirm=False)

            def on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Подключить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("TG WS: %s" % str(exc))
            return False

    def _confirm_qwdtt_link(self, profile, uri):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None or not isinstance(profile, dict):
            BulletinHelper.show_error("Не удалось открыть qWDTT")
            return False
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Подключение qWDTT")
            builder.set_message("\n".join([
                "Профиль: %s" % str(profile.get("name", "qWDTT") or "qWDTT")[:80],
                "Сервер: %s" % str(profile.get("peer", "") or "")[:120],
                "VK-хешей: %d" % len(list(profile.get("hashes", []) or [])),
            ]))

            def on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                saved = self._save_qwdtt_profile(profile, activate=True)
                if saved:
                    self._switch_to_vless_mode()

            builder.set_positive_button("Подключить", on_yes)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("qWDTT: %s" % str(exc))
            return False

    def _custom_proxy_label(self, node=None):
        target = node
        if target is None:
            try:
                target = self._current_vless_node()
            except:
                target = None
        try:
            kind = str((target or {}).get("kind", "") or "").strip().lower()
        except:
            kind = ""
        if not kind and target is not None:
            try:
                kind = _proxy_uri_scheme((target or {}).get("uri", ""))
            except:
                kind = ""
        return _proxy_protocol_label(kind)

    def _select_mode_from_settings(self, mode):
        target = str(mode or VLESS_KIND)
        if target not in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            target = VLESS_KIND
        if target == self._get_connection_mode():
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
            return True
        _switch = {
            VLESS_KIND: self._switch_to_vless_mode,
            TGWS_KIND: self._switch_to_tgws_mode,
            AWG_KIND: self._switch_to_awg_mode,
            OLCRTC_KIND: self._switch_to_olcrtc_mode,
        }[target]
        self._set_connection_mode(target)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        try:
            threading.Thread(target=lambda: _switch(False), daemon=True).start()
        except:
            _switch(False)
        return True

    def _confirm_remove_vless_subscription(self, url):
        target = str(url or "").strip()
        sub = self._find_vless_subscription(target)
        if sub is None:
            return True

        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None

        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        try:
            title = str(sub.get("name", "Подписка") or "Подписка")
        except:
            title = "Подписка"
        count = len(list(sub.get("nodes", []) or []))

        builder = AlertDialogBuilder(activity)
        builder.set_title("Удалить подписку?")
        builder.set_message(f"{title}\n{count} узл.")

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._delete_vless_subscription(target)

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Удалить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    # ExitFy keeps a large node list usable with search, protocol filters and
    # pagination.  Keep the same UX locally; the query is intentionally
    # transient so opening the page never mutates the user's proxy config.
    def _vless_browser_query_value(self):
        try:
            return str(getattr(self, "_vless_browser_query", "") or "").strip()[:80]
        except:
            return ""

    def _vless_browser_protocol_value(self):
        try:
            value = str(getattr(self, "_vless_browser_protocol", "") or "").strip().lower()
            return self._vless_browser_normalize_protocol(value)
        except:
            return ""

    def _ui_filter_vless_browser_nodes(self, nodes):
        query = self._vless_browser_query_value().lower()
        protocol = self._vless_browser_protocol_value()
        result = []
        for node in list(nodes or []):
            if not isinstance(node, dict):
                continue
            try:
                uri = str(node.get("uri", "") or "")
                kind = str(node.get("kind", "") or "").strip().lower() or _proxy_uri_scheme(uri)
                try:
                    kind = self._vless_browser_normalize_protocol(kind)
                except:
                    pass
                name = str(node.get("name", "") or "")
                server = str(node.get("server", "") or "")
                haystack = " ".join((name, server, kind, uri)).lower()
                if query and query not in haystack:
                    continue
                if protocol and kind != protocol:
                    continue
            except:
                continue
            result.append(node)
        return result

    def _vless_browser_protocol_choices(self, nodes):
        values = set()
        for node in list(nodes or []):
            try:
                uri = str(node.get("uri", "") or "")
                kind = str(node.get("kind", "") or "").strip().lower() or _proxy_uri_scheme(uri)
                try:
                    kind = self._vless_browser_normalize_protocol(kind)
                except:
                    pass
                if kind:
                    values.add(kind)
            except:
                continue
        choices = [("", "Все протоколы")]
        for value in sorted(values):
            choices.append((value, _proxy_protocol_label(value) or value.upper()))
        return choices

    def _vless_browser_protocol_label(self, nodes):
        selected = self._vless_browser_protocol_value()
        if not selected:
            return "Все протоколы"
        for value, label in self._vless_browser_protocol_choices(nodes):
            if value == selected:
                return label
        return "Все протоколы"

    def _open_vless_browser_search(self):
        activity = self._current_activity()
        if activity is None:
            return False
        try:
            field, field_view = self._create_themed_dialog_input(activity, "Имя, адрес или протокол")
            current = self._vless_browser_query_value()
            if current:
                field.setText(current)
                field.setSelection(field.length())
            builder = AlertDialogBuilder(activity)
            builder.set_title("Поиск серверов")
            builder.set_view(field_view)

            def _save(dlg, which):
                self._vless_browser_query = str(field.getText() or "").strip()[:80]
                self._vless_browser_page = 0
                try:
                    dlg.dismiss()
                except:
                    pass
                self._refresh_settings_without_reopen(reload_stack=True)

            def _clear(dlg, which):
                self._vless_browser_query = ""
                self._vless_browser_page = 0
                try:
                    dlg.dismiss()
                except:
                    pass
                self._refresh_settings_without_reopen(reload_stack=True)

            builder.set_positive_button("Применить", _save)
            builder.set_neutral_button("Очистить", _clear)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("Поиск: " + str(exc))
            return False

    def _open_vless_browser_filter(self, nodes):
        activity = self._current_activity()
        if activity is None:
            return False
        choices = self._vless_browser_protocol_choices(nodes)
        labels = []
        selected = self._vless_browser_protocol_value()
        for value, label in choices:
            labels.append(("✓ " if value == selected else "") + label)
        values = [value for value, _label in choices]
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Фильтр протокола")

            def _select(dlg, which):
                try:
                    self._vless_browser_protocol = values[int(which)]
                except:
                    return
                self._vless_browser_page = 0
                try:
                    dlg.dismiss()
                except:
                    pass
                self._refresh_settings_without_reopen(reload_stack=True)

            builder.set_items(labels, _select)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("Фильтр: " + str(exc))
            return False

    def _vless_browser_page_slice(self, nodes):
        nodes = list(nodes or [])
        # Keep the page size in one place so the selector and fallback agree.
        page_size = self._vless_browser_page_size_value()
        page_count = max(1, (len(nodes) + page_size - 1) // page_size)
        try:
            page = int(getattr(self, "_vless_browser_page", 0) or 0)
        except:
            page = 0
        page = max(0, min(page, page_count - 1))
        self._vless_browser_page = page
        start = page * page_size
        return nodes[start:start + page_size], page, page_count

    def _set_vless_browser_page(self, page):
        try:
            self._vless_browser_page = max(0, int(page))
        except:
            self._vless_browser_page = 0
        self._refresh_settings_without_reopen(reload_stack=True)

    def _vless_browser_page_size_value(self):
        try:
            return int(self._vless_browser_page_size())
        except:
            return 20

    def _vless_browser_page_size_index(self):
        values = (10, 20, 40, 60)
        value = self._vless_browser_page_size_value()
        try:
            return values.index(value)
        except:
            return min(range(len(values)), key=lambda index: abs(values[index] - value))

    def _on_vless_browser_page_size_changed(self, index):
        values = (10, 20, 40, 60)
        try:
            value = values[max(0, min(len(values) - 1, int(index)))]
        except:
            value = 20
        try:
            self._set_vless_browser_page_size(value)
        except:
            pass
        self._vless_browser_page = 0
        self._refresh_settings_without_reopen(reload_stack=True)
        return True

    def _on_vless_browser_auto_check_changed(self, index):
        values = (0, 5, 15, 30, 60)
        try:
            value = values[max(0, min(len(values) - 1, int(index)))]
        except:
            value = 0
        try:
            self._set_vless_browser_auto_check_minutes(value)
        except:
            pass
        self._refresh_settings_without_reopen(reload_stack=True)
        return True

    def _vless_browser_auto_check_index(self):
        values = (0, 5, 15, 30, 60)
        try:
            value = int(self._vless_browser_auto_check_minutes())
        except:
            value = 0
        try:
            return values.index(value)
        except:
            return 0

    def _on_vless_browser_failover_changed(self, enabled):
        try:
            self._set_vless_browser_failover_enabled(bool(enabled))
        except:
            pass
        self._refresh_settings_without_reopen(reload_stack=True)
        return True

    def _toggle_vless_browser_source(self, key, currently_hidden):
        try:
            self._vless_set_browser_source_visible(key, bool(currently_hidden))
        except:
            return False
        self._vless_browser_page = 0
        self._refresh_settings_without_reopen(reload_stack=True)
        return True

    def _create_vless_sources_subpage(self):
        try:
            sources = list(self._vless_browser_sources(include_hidden=True) or [])
        except:
            sources = []
        items = [
            Header(text="Источники узлов"),
            Text(
                text="Показывать узлы источника",
                subtext="Скрытые источники не участвуют в автовыборе",
                icon="msg_info",
            ),
        ]
        if not sources:
            items.append(Text(text="Источники не найдены", icon="msg_info"))
            return items
        items.append(Divider())
        for source in sources:
            key = str(source.get("key", "") or "")
            name = str(source.get("name", "") or key or "Источник")[:64]
            hidden = bool(source.get("hidden", False))
            count = int(source.get("count", 0) or 0)
            items.append(Text(
                text=name,
                subtext=("Скрыт" if hidden else "Виден") + " • %d узл." % count,
                icon="msg2_proxy_off" if hidden else "msg2_proxy_on",
                accent=not hidden,
                on_click=lambda *a, key=key, hidden=hidden: self._toggle_vless_browser_source(key, hidden),
            ))
        return items

    def _vless_node_source_label(self, node):
        target = str((node or {}).get("uri", "") or "")
        if not target:
            return "Свой узел"
        try:
            source = self._vless_browser_source_for_node(node)
            source_name = str((source or {}).get("name", "") or "").strip()
            if source_name and not bool((source or {}).get("manual", False)):
                return source_name[:48]
        except:
            pass
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for item in list(sub.get("nodes", []) or []):
                    if str((item or {}).get("uri", "") or "") == target:
                        return str(sub.get("name", "") or "Подписка").strip()[:48] or "Подписка"
        except:
            pass
        return "Свой узел"

    def _vless_browser_row_subtext(self, node):
        try:
            kind = str(node.get("kind", "") or "").strip().lower() or _proxy_uri_scheme(node.get("uri", ""))
            protocol = _proxy_protocol_label(kind) or kind.upper()
            source = self._vless_node_source_label(node)
            server = str(node.get("server", "") or "").strip()
            port = str(node.get("port", "") or "").strip()
            endpoint = server + ((":" + port) if server and port else "")
            parts = [protocol, source]
            if endpoint:
                parts.append(endpoint[:72])
            return " • ".join(part for part in parts if part)
        except:
            return ""

    def _create_vless_subscription_subpage(self, sub_url):
        sub = self._find_vless_subscription(sub_url)
        if sub is None:
            return [Header(text="Подписка"), Text(text="Подписка не найдена", icon="msg_info")]

        try:
            title = str(sub.get("name", "Подписка") or "Подписка").strip()
        except:
            title = "Подписка"
        title = title if title else "Подписка"
        nodes = self._sorted_vless_nodes(list(sub.get("nodes", []) or []))
        active = bool(self._vless_subscription_has_active(sub))

        items = [
            Header(text="Подписка"),
            Text(
                text=title,
                subtext=("Активная • " if active else "") + f"{len(nodes)} узл.",
                icon="msg_channel",
                accent=active,
            ),
            Divider(),
            Header(text="Действия"),
            Text(
                text="Обновить подписку",
                subtext="Загрузить свежий список узлов",
                icon="msg_retry",
                on_click=lambda *a, url=str(sub.get("url", "") or ""): self._update_vless_subscription(url),
            ),
        ]
        if nodes:
            items.append(Text(
                text="Тест пинга",
                subtext="Проверить узлы этой подписки",
                icon="msg_speed",
                on_click=lambda *a, nodes=nodes: self._run_vless_ping_test(nodes=nodes, refresh_each=True),
            ))

        active_uri = self._get_active_vless_uri()
        items.extend([Divider(), Header(text="Узлы")])
        for node in nodes:
            selected = str(node.get("uri", "") or "") == active_uri
            items.append(Text(
                text=self._vless_node_label(node),
                subtext=self._vless_browser_row_subtext(node),
                icon="msg2_proxy_on" if selected else "msg_link2",
                accent=selected,
                on_click=lambda *a, uri=str(node.get("uri", "") or ""): self._activate_vless_uri(uri, enable_plugin=True),
                on_long_click=lambda view, uri=str(node.get("uri", "") or ""): self._confirm_remove_vless_node(uri),
            ))

        if not nodes:
            items.append(Text(
                text="Подписка пуста",
                subtext="Обновите подписку или проверьте её адрес",
                icon="msg_info",
            ))
        items.extend([
            Divider(),
            Header(text="Управление"),
            Text(
                text="Удалить подписку",
                subtext="Узлы из неё также будут удалены",
                red=True,
                icon="msg_delete",
                on_click=lambda *a, url=str(sub.get("url", "") or ""): self._confirm_remove_vless_subscription(url),
            ),
        ])
        return items

    def _create_vless_nodes_subpage(self):
        current = self._current_vless_node()
        manual = list(self._vless_data.get("manual", []) or [])
        subs = list(self._vless_data.get("subs", []) or [])
        counts = self._vless_counts()
        nodes_count = int(counts.get("nodes", 0) or 0)
        subs_count = int(counts.get("subs", 0) or 0)
        active_uri = self._get_active_vless_uri()
        auto_node = self._find_vless_node(VLESS_AUTO_SUBSCRIPTIONS_URI)

        items = [
            Header(text="Обзор"),
            Text(
                text="Узлы и подписки",
                subtext=f"Узлов: {nodes_count} • подписок: {subs_count}",
                icon="msg_folders",
            ),
        ]

        if current:
            items.append(Text(
                text="Текущий узел",
                subtext=self._append_green_tail(self._vless_node_plain_label(current), self._vless_ping_badge(current)),
                icon="msg2_proxy_on",
                accent=True,
                on_click=(lambda *a, link=str(current.get("uri", "") or ""): self._copy_link(link)) if _is_proxy_uri(str(current.get("uri", "") or "")) else None,
            ))
        else:
            items.append(Text(
                text="Узел не выбран",
                subtext="Добавьте сервер или подписку",
                icon="msg2_proxy_off",
            ))

        items.extend([
            Divider(),
            Header(text="Добавить"),
            Text(
                text="Импорт из буфера",
                subtext="Сервер или ссылка на подписку",
                accent=True,
                icon="msg_download",
                on_click=lambda *a: self._import_vless_from_clipboard(),
            ),
            Text(
                text="Встроенные подписки",
                subtext="Готовые источники GreenPass",
                icon="msg_channel",
                create_sub_fragment=self._create_builtin_vless_subs_subpage,
            ),
        ])

        if auto_node:
            items.extend([Divider(), Header(text="Автоматизация")])
            items.append(Text(
                text="Автовыбор",
                subtext="Автоматически выбирать доступный узел",
                icon="media_flip",
                accent=active_uri == VLESS_AUTO_SUBSCRIPTIONS_URI,
                on_click=lambda *a: self._activate_vless_uri(VLESS_AUTO_SUBSCRIPTIONS_URI, enable_plugin=True),
            ))

        if subs:
            items.extend([Divider(), Header(text="Подписки")])
            for sub in subs:
                sub_nodes = list(sub.get("nodes", []) or [])
                active = bool(self._vless_subscription_has_active(sub))
                items.append(Text(
                    text=str(sub.get("name", "Подписка") or "Подписка"),
                    subtext=("Активная • " if active else "") + f"{len(sub_nodes)} узл.",
                    icon="msg_list",
                    accent=active,
                    create_sub_fragment=lambda sub_url=str(sub.get("url", "") or ""): self._create_vless_subscription_subpage(sub_url),
                    on_long_click=lambda view, url=str(sub.get("url", "") or ""): self._confirm_remove_vless_subscription(url),
                ))

        # Unified server browser (search/filter/pagination) keeps large
        # subscriptions usable while retaining the separate subscription rows
        # above for refresh/delete actions.
        all_nodes = []
        seen_uris = set()
        for source_nodes in [manual] + [list(sub.get("nodes", []) or []) for sub in subs if isinstance(sub, dict)]:
            for node in source_nodes:
                if not isinstance(node, dict):
                    continue
                uri = str(node.get("uri", "") or "").strip()
                if not uri or uri in seen_uris:
                    continue
                seen_uris.add(uri)
                all_nodes.append(node)
        if all_nodes:
            query = self._vless_browser_query_value()
            protocol = self._vless_browser_protocol_value()
            try:
                snapshot = self._vless_browser_snapshot(
                    query=query,
                    protocol=protocol,
                    page=int(getattr(self, "_vless_browser_page", 0) or 0),
                )
                browser_nodes = list(snapshot.get("nodes", []) or [])
                browser_total = int(snapshot.get("total", 0) or 0)
                page = int(snapshot.get("page", 0) or 0)
                page_size = int(snapshot.get("page_size", 20) or 20)
                page_count = int(snapshot.get("pages", 0) or 0)
                self._vless_browser_page = page
            except:
                filtered = self._sorted_vless_nodes(self._ui_filter_vless_browser_nodes(all_nodes))
                browser_nodes, page, page_count = self._vless_browser_page_slice(filtered)
                browser_total = len(filtered)
                page_size = self._vless_browser_page_size_value()
            filter_label = self._vless_browser_protocol_label(all_nodes)
            items.extend([Divider(), Header(text="Серверы")])
            items.append(Text(
                text="Поиск серверов" if not query else "Поиск: " + query,
                subtext="Имя, адрес или протокол" if not query else "%d совпадений" % browser_total,
                icon="msg_search",
                on_click=lambda *a: self._open_vless_browser_search(),
            ))
            items.append(Text(
                text="Фильтр протокола",
                subtext=filter_label,
                icon="msg_list",
                on_click=lambda *a, source=all_nodes: self._open_vless_browser_filter(source),
            ))
            try:
                source_count = len(list(self._vless_browser_sources(include_hidden=True) or []))
            except:
                source_count = 0
            if source_count:
                items.append(Text(
                    text="Источники",
                    subtext="%d источника" % source_count,
                    icon="msg_channel",
                    create_sub_fragment=self._create_vless_sources_subpage,
                ))
            items.append(Selector(
                key="vless_browser_page_size",
                text="Серверов на странице",
                default=self._vless_browser_page_size_index(),
                items=["10", "20", "40", "60"],
                icon="msg_list",
                on_change=self._on_vless_browser_page_size_changed,
            ))
            if not browser_nodes:
                items.append(Text(
                    text="Ничего не найдено",
                    subtext="Измените запрос или фильтр",
                    icon="msg_info",
                ))
            else:
                first = page * page_size + 1
                last = first + len(browser_nodes) - 1
                items.append(Text(
                    text="Серверы %d–%d из %d" % (first, last, browser_total),
                    subtext="Нажмите на сервер для подключения",
                    icon="msg_list",
                ))
                for node in browser_nodes:
                    selected = str(node.get("uri", "") or "") == active_uri
                    items.append(Text(
                        text=self._vless_node_label(node),
                        subtext=self._vless_browser_row_subtext(node),
                        icon="msg2_proxy_on" if selected else "msg_link2",
                        accent=selected,
                        on_click=lambda *a, uri=str(node.get("uri", "") or ""): self._activate_vless_uri(uri, enable_plugin=True),
                        on_long_click=lambda view, uri=str(node.get("uri", "") or ""): self._confirm_remove_vless_node(uri),
                    ))
                if page_count > 1:
                    if page > 0:
                        items.append(Text(
                            text="Предыдущая страница",
                            icon="msg_retry",
                            on_click=lambda *a, target=page - 1: self._set_vless_browser_page(target),
                        ))
                    if page + 1 < page_count:
                        items.append(Text(
                            text="Следующая страница",
                            icon="msg_forward",
                            on_click=lambda *a, target=page + 1: self._set_vless_browser_page(target),
                        ))

        if not manual and not subs:
            items.extend([
                Divider(),
                Text(
                    text="Пока нет узлов",
                    subtext="Добавьте сервер или подписку",
                    icon="msg_info",
                ),
            ])

        if nodes_count > 0 or subs_count > 0:
            items.extend([Divider(), Header(text="Обслуживание")])
        if nodes_count > 0:
            items.append(Text(
                text="Тест пинга",
                subtext="Проверить задержку всех узлов",
                icon="msg_speed",
                on_click=lambda *a: self._run_vless_ping_test(),
            ))
        if subs_count > 0:
            items.append(Text(
                text="Обновить подписки",
                subtext="Загрузить свежие списки узлов",
                icon="msg_retry",
                on_click=lambda *a: self._refresh_vless_subscriptions(),
            ))
        if nodes_count > 0 or subs_count > 0:
            items.append(Text(
                text="Очистить узлы",
                subtext="Удалить свои узлы и подписки",
                icon="msg_delete",
                red=True,
                on_click=lambda *a: self._confirm_clear_vless_nodes(),
            ))

        return items

    def _settings_mode_choices(self):
        return [
            (VLESS_KIND, self._settings_mode_title(VLESS_KIND)),
            (TGWS_KIND, "TG WS"),
            (AWG_KIND, "AmneziaWG"),
            (OLCRTC_KIND, "olcRTC"),
        ]

    def _settings_mode_title(self, mode):
        target = str(mode or VLESS_KIND)
        if target == VLESS_KIND:
            return "Mihomo" if self._effective_vless_engine() == VLESS_ENGINE_MIHOMO else "sing-box"
        if target == TGWS_KIND:
            return "TG WS"
        if target == AWG_KIND:
            return "AmneziaWG"
        if target == OLCRTC_KIND:
            return "olcRTC"
        return self._settings_mode_title(VLESS_KIND)

    def _settings_mode_description(self, mode):
        target = str(mode or VLESS_KIND)
        if target == VLESS_KIND:
            return "Узлы, подписки и автоматический выбор"
        if target == TGWS_KIND:
            return "WebSocket-прокси для Telegram"
        if target == AWG_KIND:
            return "Туннель AmneziaWG из .conf"
        if target == OLCRTC_KIND:
            return "TURN/WebRTC-профили и подписки"
        return self._settings_mode_description(VLESS_KIND)

    def _settings_mode_icon(self, mode):
        target = str(mode or VLESS_KIND)
        if target == VLESS_KIND:
            return "msg_folders"
        if target == TGWS_KIND:
            return "msg_link2"
        if target == AWG_KIND:
            return "msg_secret"
        if target == OLCRTC_KIND:
            return "msg_calls"
        return "msg_folders"

    def _settings_mode_runtime_state(self, mode=None):
        target = self._normalize_proxy_mode(mode or self._get_connection_mode())
        if target != self._get_connection_mode() or not bool(self._is_plugin_proxy_enabled()):
            return "off"
        if bool(getattr(self, "_proxy_suspended_by_wifi", False)) or bool(getattr(self, "_proxy_suspended_by_vpn", False)):
            return "paused"

        try:
            owner, owner_port = self._local_socks_owner_snapshot()
        except:
            owner, owner_port = "", 0

        ready = False
        busy = False
        if target == VLESS_KIND:
            try:
                port = int(self._vless_port or (owner_port if owner == VLESS_KIND else 0) or 0)
            except:
                port = 0
            try:
                ready = bool(port > 0 and self._is_local_vless_proxy_applied(port))
            except:
                ready = False
            busy = bool(getattr(self, "_vless_connecting", False)) or bool(getattr(self, "_vless_prepare_in_progress", False)) or (bool(getattr(self, "_vless_running", False)) and not ready)
        elif target == TGWS_KIND:
            try:
                port = int(self._tgws_port or (owner_port if owner == TGWS_KIND else 0) or 0)
            except:
                port = 0
            try:
                ready = bool(port > 0 and self._is_local_tgws_proxy_applied(port))
            except:
                ready = False
            busy = bool(getattr(self, "_tgws_connecting", False)) or (bool(getattr(self, "_tgws_running", False)) and not ready)
        elif target == AWG_KIND:
            ready = bool(self._is_awg_connection_ready())
            busy = (
                bool(getattr(self, "_awg_connecting", False))
                or bool(getattr(self, "_awg_prepare_in_progress", False))
                or bool(getattr(self, "_awg_config_downloading", False))
                or (bool(getattr(self, "_awg_running", False)) and not ready)
            )
        elif target == OLCRTC_KIND:
            try:
                port = int(self._olcrtc_port or (owner_port if owner == OLCRTC_KIND else 0) or OLCRTC_LOCAL_PORT)
            except:
                port = int(OLCRTC_LOCAL_PORT)
            try:
                ready = bool(port > 0 and self._is_local_olcrtc_proxy_applied(port))
            except:
                ready = False
            busy = (
                bool(getattr(self, "_olcrtc_connecting", False))
                or bool(getattr(self, "_olcrtc_prepare_in_progress", False))
                or bool(getattr(self, "_olcrtc_resume_checking", False))
                or bool(getattr(self, "_olcrtc_backgrounded", False))
                or (bool(getattr(self, "_olcrtc_running", False)) and not ready)
            )

        if ready:
            return "connected"
        if busy:
            return "connecting"
        return "disconnected"

    def _settings_connection_badge(self):
        gray = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText)
        accent = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)
        green = Theme.getColor(Theme.key_windowBackgroundWhiteGreenText)
        red = Theme.getColor(Theme.key_text_RedBold)
        if bool(getattr(self, "_proxy_suspended_by_wifi", False)):
            return "● Приостановлен в этой WIFI сети", accent
        if bool(getattr(self, "_proxy_suspended_by_vpn", False)):
            return "● Приостановлен из-за VPN", accent
        if not bool(self._is_plugin_proxy_enabled()):
            return "● Прокси выключен", gray

        mode = self._get_connection_mode()
        state = self._settings_mode_runtime_state(mode)
        if state == "connected":
            label = {
                VLESS_KIND: "Прокси",
                TGWS_KIND: "TG WS",
                AWG_KIND: "AmneziaWG",
                OLCRTC_KIND: "olcRTC",
            }.get(mode, "Прокси")
            return "● " + label + " подключён", green
        if state == "connecting":
            label = self._settings_mode_title(mode)
            return "● " + label + " подключается…", accent
        if state == "paused":
            return "● Прокси приостановлен", accent
        if state == "disconnected":
            return "● Прокси не подключён", red
        return "● Состояние неизвестно", gray

    def _refresh_mode_summary(self):
        try:
            controller = self._plugins_controller_instance()
            plugin_id = self._plugin_settings_id()
            if controller is not None and plugin_id:
                controller.loadPluginSettings(plugin_id)
        except:
            pass

    def _safe_settings_items(self, title, builder):
        try:
            return list(builder() or [])
        except:
            return [Text(text=f"{str(title or 'Раздел')[:18]}: ошибка", icon="msg_settings")]

    def _build_mode_picker_cards(self):
        try:
            activity = self._current_activity()
            if activity is None:
                return None

            dp = AndroidUtilities.dp
            accent = Theme.getColor(Theme.key_featuredStickers_addButton)
            title_color = Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)
            muted_color = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText)
            surface_color = Theme.getColor(Theme.key_windowBackgroundWhite)
            divider_color = Theme.getColor(Theme.key_divider)
            current = self._get_connection_mode()
            resource = find_class("org.telegram.messenger.R")

            root = LinearLayout(activity)
            root.setOrientation(LinearLayout.VERTICAL)
            root.setPadding(dp(16), dp(6), dp(16), dp(8))

            for index, (mode, title_text) in enumerate(self._settings_mode_choices()):
                selected = mode == current
                card = LinearLayout(activity)
                card.setOrientation(LinearLayout.HORIZONTAL)
                card.setGravity(Gravity.CENTER_VERTICAL)
                card.setPadding(dp(16), dp(14), dp(14), dp(14))
                card.setClickable(True)
                card.setFocusable(True)

                background = GradientDrawable()
                background.setColor(surface_color)
                background.setCornerRadius(dp(14))
                background.setStroke(dp(2) if selected else dp(1), accent if selected else divider_color)
                card.setBackground(background)
                try:
                    card.setElevation(float(dp(1)))
                except:
                    pass
                try:
                    card.setForeground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_listSelector), 2))
                except:
                    pass
                self._bind_view_click(card, lambda _view, target=mode: self._select_mode_from_settings(target))

                icon = ImageView(activity)
                try:
                    icon_id = int(getattr(resource.drawable, self._settings_mode_icon(mode), 0))
                    if icon_id:
                        icon.setImageResource(icon_id)
                except:
                    pass
                icon.setColorFilter(accent if selected else muted_color)
                icon_lp = LinearLayout.LayoutParams(dp(26), dp(26))
                icon_lp.rightMargin = dp(15)
                card.addView(icon, icon_lp)

                labels = LinearLayout(activity)
                labels.setOrientation(LinearLayout.VERTICAL)

                title = TextView(activity)
                title.setText(Z(title_text))
                title.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16)
                title.setTextColor(accent if selected else title_color)
                try:
                    title.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"))
                except:
                    pass
                labels.addView(title, LinearLayout.LayoutParams(-1, -2))

                description = TextView(activity)
                description.setText(Z(self._settings_mode_description(mode)))
                description.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 13)
                description.setTextColor(muted_color)
                description_lp = LinearLayout.LayoutParams(-1, -2)
                description_lp.topMargin = dp(2)
                labels.addView(description, description_lp)
                card.addView(labels, LinearLayout.LayoutParams(0, -2, 1.0))

                # A stable trailing affordance keeps every card's right edge
                # aligned, including unselected rows.
                affordance = TextView(activity)
                affordance.setText("✓" if selected else "›")
                affordance.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 21 if selected else 24)
                affordance.setTextColor(accent if selected else muted_color)
                affordance.setGravity(Gravity.CENTER)
                affordance_lp = LinearLayout.LayoutParams(dp(30), dp(30))
                affordance_lp.leftMargin = dp(8)
                card.addView(affordance, affordance_lp)

                card_lp = LinearLayout.LayoutParams(-1, -2)
                card_lp.topMargin = dp(8)
                root.addView(card, card_lp)

            return _Custom(view=root)
        except:
            return None

    def _create_mode_picker_subpage(self):
        current = self._get_connection_mode()
        items = [Header(text="Режим подключения")]
        cards = self._build_mode_picker_cards()
        if cards is not None:
            items.append(cards)
        else:
            for mode, title in self._settings_mode_choices():
                selected = mode == current
                items.append(Text(
                    text=("✓ " if selected else "") + title,
                    subtext=self._settings_mode_description(mode),
                    icon=self._settings_mode_icon(mode),
                    accent=selected,
                    on_click=lambda *a, target=mode: self._select_mode_from_settings(target),
                ))
        items.extend([
            Divider(),
            Text(
                text="Настройки сохраняются отдельно",
                subtext="При возврате к режиму его конфиг останется на месте",
                icon="msg_info",
            ),
        ])
        return items

    def _build_status_settings_items(self):
        items = []
        if bool(getattr(self, "_proxy_suspended_by_wifi", False)):
            ssid = str(getattr(self, "_current_wifi_ssid_cache", "") or "")
            items.append(Text(text="Приостановлено: WIFI " + (ssid or "сеть"), icon="msg_list"))
        elif bool(getattr(self, "_proxy_suspended_by_vpn", False)):
            items.append(Text(text="Приостановлено: активен VPN", icon="msg_secret"))
        mode = self._get_connection_mode()
        runtime_state = self._settings_mode_runtime_state(mode)
        current_vless = self._current_vless_node()

        if mode == VLESS_KIND:
            vless_applied = runtime_state == "connected"
            vless_connecting = runtime_state == "connecting"
            vless_error = str(getattr(self, "_vless_last_error", "") or "").strip()
            node_label = self._vless_node_plain_label(current_vless) if current_vless else "узел не выбран"
            if runtime_state == "off":
                status_text = "VLESS: выключен"
            elif runtime_state == "paused":
                status_text = "VLESS: приостановлен"
            elif vless_connecting:
                status_text = "🟠 Подключение: " + node_label
            elif vless_error and not vless_applied:
                status_text = "🔴 Не подключено: " + node_label
            elif not vless_applied:
                status_text = "🔴 Не подключено: " + node_label
            else:
                status_text = self._custom_proxy_label(current_vless) + ": " + node_label if current_vless else "VLESS: подключен"
            status_kwargs = {
                "text": self._append_green_tail(
                    status_text,
                    self._vless_ping_badge(current_vless) if current_vless else "",
                ),
                "icon": "msg_retry" if vless_connecting else "msg2_proxy_on" if vless_applied else "msg2_proxy_off",
            }
            if vless_error and runtime_state == "disconnected":
                status_kwargs["subtext"] = vless_error[:160]
                status_kwargs["red"] = True
            active_uri = str((current_vless or {}).get("uri", "") or "")
            if _is_proxy_uri(active_uri):
                status_kwargs["on_click"] = lambda *a, link=active_uri: self._copy_link(link)
            items.append(Text(**status_kwargs))
        elif mode == TGWS_KIND:
            tgws_ready = runtime_state == "connected"
            if tgws_ready:
                tgws_text = "TG WS: подключен"
            elif runtime_state == "connecting":
                tgws_text = "TG WS: соединяю"
            elif runtime_state == "paused":
                tgws_text = "TG WS: приостановлен"
            elif runtime_state == "disconnected":
                tgws_text = "● Прокси не подключён"
            else:
                tgws_text = "TG WS: выключен"
            items.append(Text(
                text=tgws_text,
                icon="msg2_proxy_on" if tgws_ready else "msg_retry" if runtime_state == "connecting" else "msg2_proxy_off",
            ))
        elif mode == AWG_KIND:
            name = str(self._awg_conf_name or "").strip() or "конфиг не выбран"
            items.append(Text(
                text="AWG: " + name,
                subtext={
                    "connected": "AmneziaWG подключён",
                    "connecting": "AmneziaWG подключается…",
                    "paused": "AmneziaWG приостановлен",
                    "disconnected": "Прокси не подключён",
                    "off": "AmneziaWG выключен",
                }.get(runtime_state, "Состояние неизвестно"),
                icon="msg2_proxy_on" if runtime_state == "connected" else "msg_retry" if runtime_state == "connecting" else "msg2_proxy_off",
            ))
        elif mode == OLCRTC_KIND:
            status_text, status_subtext, core_state = self._olcrtc_status_presentation()
            if runtime_state == "connected":
                status_text = "olcRTC: подключен"
            elif runtime_state == "off":
                status_text = "olcRTC: выключен"
            elif runtime_state == "paused":
                status_text = "olcRTC: приостановлен"
            elif runtime_state == "disconnected" and core_state in ("ready", "running"):
                status_text = "olcRTC: прокси не применён"
            items.append(Text(
                text=status_text,
                subtext=status_subtext,
                icon="msg2_proxy_on" if runtime_state == "connected" else "msg_retry" if runtime_state == "connecting" else "msg2_proxy_off",
            ))
        else:
            items.append(Text(text="Прокси не установлен", icon="msg2_proxy_off"))

        return items

    def _create_builtin_vless_subs_subpage(self):
        items = [Header(text="Встроенные подписки")]
        sources = self._builtin_vless_sub_sources()
        if not sources:
            items.append(Text(text="Подписок нет", icon="msg_info"))
            return items

        for source in sources:
            url = str(source.get("url", "") or "")
            imported = self._find_vless_subscription(url) is not None
            label = str(source.get("name", "Подписка") or "Подписка")
            if imported:
                label = "Импортировано: " + label
            items.append(Text(
                text=label,
                accent=bool(imported),
                icon="msg_link",
                on_click=lambda *a, url=url: self._add_vless_subscription(url, activate_first=(not self._get_active_vless_uri())),
            ))
        return items

    def _build_vless_mode_items(self):
        current_vless = self._current_vless_node()
        counts = self._vless_counts()
        nodes_count = int(counts.get("nodes", 0) or 0)
        subs_count = int(counts.get("subs", 0) or 0)
        auto_available = self._find_vless_node(VLESS_AUTO_SUBSCRIPTIONS_URI) is not None
        runtime_state = self._settings_mode_runtime_state(VLESS_KIND)
        vless_ready = runtime_state == "connected"
        vless_connecting = runtime_state == "connecting"
        vless_error = str(getattr(self, "_vless_last_error", "") or "").strip()

        if current_vless:
            if runtime_state == "off":
                status_text = "Выключен: " + self._vless_node_plain_label(current_vless)
            elif runtime_state == "paused":
                status_text = "Приостановлен: " + self._vless_node_plain_label(current_vless)
            elif vless_connecting:
                status_text = "🟠 Подключение: " + self._vless_node_plain_label(current_vless)
            elif vless_error and not vless_ready:
                status_text = "🔴 Не подключено: " + self._vless_node_plain_label(current_vless)
            elif not vless_ready:
                status_text = "🔴 Не подключено: " + self._vless_node_plain_label(current_vless)
            else:
                status_text = "Работает: " + self._vless_node_plain_label(current_vless)
            status_tail = self._vless_ping_badge(current_vless)
            active_link = str(current_vless.get("uri", "") or "")
        else:
            status_text = "Узел не выбран"
            status_tail = ""
            active_link = ""

        status_item_kwargs = {
            "text": self._append_green_tail(status_text, status_tail),
            "subtext": vless_error[:160] if current_vless and vless_error and runtime_state == "disconnected" else f"Узлов: {nodes_count} • подписок: {subs_count}",
            "icon": "msg_retry" if current_vless and vless_connecting else "msg2_proxy_on" if vless_ready else "msg2_proxy_off",
        }
        if current_vless and vless_error and runtime_state == "disconnected":
            status_item_kwargs["red"] = True
        if _is_proxy_uri(active_link):
            status_item_kwargs["on_click"] = lambda *a, link=active_link: self._copy_link(link)

        items = [
            Header(text="Состояние"),
            Text(**status_item_kwargs),
            Divider(),
            Header(text="Узлы и подписки"),
            Text(text="Импорт из буфера", accent=True, icon="msg_download", on_click=lambda *a: self._import_vless_from_clipboard()),
            Text(
                text="Управление узлами",
                subtext=f"Узлов: {nodes_count} • подписок: {subs_count}",
                icon="msg_folders",
                create_sub_fragment=self._create_vless_nodes_subpage,
            ),
        ]
        if nodes_count > 0 or subs_count > 0:
            items.extend([Divider(), Header(text="Автоматизация")])
        if auto_available:
            items.append(Text(
                text="Подключить лучший",
                subtext="Включить сервер «Автовыбор»",
                icon="msg_speed",
                on_click=lambda *a: self._connect_best_vless_node(),
            ))
        if nodes_count > 0:
            items.append(Switch(
                key="vless_failover_enabled",
                text="Переключать при сбое",
                default=bool(self._vless_browser_failover_enabled()),
                subtext="Переходить к следующему узлу",
                icon="msg_retry",
                on_change=self._on_vless_browser_failover_changed,
            ))
            items.append(Selector(
                key="vless_auto_check_minutes",
                text="Автопроверка пинга",
                default=self._vless_browser_auto_check_index(),
                items=["Выключена", "5 минут", "15 минут", "30 минут", "60 минут"],
                icon="msg_speed",
                on_change=self._on_vless_browser_auto_check_changed,
            ))
            items.append(Text(
                text="Проверить пинг",
                subtext="Обновить задержку всех узлов",
                icon="msg_speed",
                on_click=lambda *a: self._run_vless_ping_test(),
            ))
        if subs_count > 0:
            items.append(Text(
                text="Обновить подписки",
                subtext="Загрузить свежий список узлов",
                icon="msg_retry",
                on_click=lambda *a: self._refresh_vless_subscriptions(),
            ))
        else:
            items.append(Text(
                text="Встроенные подписки",
                subtext="Готовые источники GreenPass",
                icon="msg_channel",
                create_sub_fragment=self._create_builtin_vless_subs_subpage,
            ))

        items.extend([Divider(), Header(text="Ядро")])
        core_status = self._libsingbox_addon_status(quick=True)
        if self._vless_prepare_in_progress:
            items.append(Text(
                text="Ядро загружается…",
                subtext="Скачивание и проверка библиотеки",
                icon="msg_download_settings",
                accent=True,
            ))
        elif core_status == "checking":
            items.append(Text(
                text="Проверяю ядро…",
                subtext="Проверка библиотеки выполняется в фоне",
                icon="msg_retry",
                accent=True,
            ))
        elif core_status == "current":
            items.append(Text(
                text="Удалить ядро GreenPass",
                subtext="Текущая версия установлена",
                icon="msg_delete",
                red=True,
                on_click=lambda *a: self._confirm_delete_vless_addon(),
            ))
        else:
            core_action = "Обновить ядро" if core_status == "outdated" and SINGBOX_BUNDLE_URLS else "Скачать ядро прокси"
            items.append(Text(
                text=core_action,
                subtext="Нативная библиотека для этого устройства",
                icon="msg_download_settings",
                on_click=lambda *a: self._download_vless_addon(),
            ))
        return items

    def _build_tgws_mode_items(self):
        runtime_state = self._settings_mode_runtime_state(TGWS_KIND)
        running = runtime_state in ("connected", "connecting")
        ready = runtime_state == "connected"
        if ready:
            status_text = "TG WS работает"
        elif runtime_state == "connecting":
            status_text = "TG WS соединяется"
        elif runtime_state == "paused":
            status_text = "TG WS приостановлен"
        elif runtime_state == "disconnected":
            status_text = "● Прокси не подключён"
        else:
            status_text = "TG WS выключен"
        return [
            Header(text="Состояние"),
            Text(
                text=status_text,
                subtext="Локальный WebSocket-прокси Telegram",
                icon="msg2_proxy_on" if ready else "msg_retry" if runtime_state == "connecting" else "msg2_proxy_off",
            ),
            Divider(),
            Header(text="Подключение"),
            Text(
                text="Перезапустить TG WS" if running else "Запустить TG WS",
                subtext="Пересоздать локальное подключение" if running else "Запустить локальный прокси",
                icon="msg_retry" if running else "msg_start",
                on_click=lambda *a: self._restart_tgws_from_settings(),
            ),
            Text(
                text="Скопировать tg://proxy",
                subtext="Ссылка на текущий локальный прокси",
                icon="msg_copy_filled",
                on_click=lambda *a: self._copy_link("tg://ws"),
            ),
        ]

    def _build_awg_mode_items(self):
        runtime_state = self._settings_mode_runtime_state(AWG_KIND)
        running = runtime_state == "connected"
        conf_name = str(self._awg_conf_name or "").strip() or "Не выбран"
        if running:
            status_text = "AWG работает"
        elif runtime_state == "connecting":
            status_text = "● Подключение…"
        elif runtime_state == "paused":
            status_text = "AWG приостановлен"
        elif runtime_state == "disconnected":
            status_text = "● Прокси не подключён"
        else:
            status_text = "AWG выключен"
        items = [
            Header(text="Состояние"),
            Text(
                text=status_text,
                subtext="Конфиг: " + conf_name,
                icon="msg2_proxy_on" if running else "msg_retry" if runtime_state == "connecting" else "msg2_proxy_off",
            ),
            Divider(),
            Header(text="Конфигурация"),
            Text(
                text="Получить AWG конфиг",
                subtext="Сгенерировать бесплатный Cloudflare WARP",
                icon="msg_download",
                on_click=lambda *a: self._download_free_awg_config(),
            ),
            Text(
                text="Выбрать .conf",
                subtext=conf_name,
                icon="msg_folder",
                on_click=lambda *a: self._open_awg_file_picker(),
            ),
            Divider(),
            Header(text="Подключение"),
            Text(
                text="Перезапустить AWG" if running else "Запустить AWG",
                subtext="Пересоздать туннель" if running else "Запустить выбранный конфиг",
                icon="msg_retry" if running else "msg_start",
                on_click=lambda *a: self._restart_awg_from_settings(),
            ),
            Divider(),
            Header(text="Очистка"),
            Text(
                text="Очистить AWG",
                subtext="Удалить сохранённый конфиг",
                icon="msg_delete",
                red=True,
                on_click=lambda *a: self._confirm_clear_awg(),
            ),
        ]
        return items

    def _build_olcrtc_mode_items(self):
        runtime_state = self._settings_mode_runtime_state(OLCRTC_KIND)
        running = runtime_state == "connected"
        config_err = self._olcrtc_config_error()
        status_text, status_subtext, core_state = self._olcrtc_status_presentation()
        if runtime_state == "connected":
            status_text = "olcRTC: подключен"
        elif runtime_state == "off":
            status_text = "olcRTC: выключен"
        elif runtime_state == "paused":
            status_text = "olcRTC: приостановлен"
        elif runtime_state == "disconnected" and core_state in ("ready", "running"):
            status_text = "olcRTC: прокси не применён"
        profiles_count = len(self._sanitize_olcrtc_profiles(self._olcrtc_profiles))
        if config_err:
            status_subtext = config_err
        elif profiles_count > 0:
            status_subtext = "%s • профилей: %d" % (status_subtext, profiles_count)
        active_or_busy = runtime_state in ("connected", "connecting")
        items = [
            Header(text="Состояние"),
            Text(
                text=status_text,
                subtext=status_subtext,
                icon="msg2_proxy_on" if running else "msg_retry" if runtime_state == "connecting" else "msg2_proxy_off",
                on_click=lambda *a: self._on_olcrtc_status_tap(),
            ),
            Divider(),
            Header(text="Профили"),
            Text(
                text="Профили и настройки",
                subtext="Профилей: %d" % profiles_count,
                icon="msg_folders",
                create_sub_fragment=self._create_olcrtc_profiles_subpage,
            ),
            Divider(),
            Header(text="Подключение"),
            Text(
                text="Перезапустить olcRTC" if active_or_busy else "Запустить olcRTC",
                subtext="Повторить рукопожатие" if active_or_busy else "Запустить выбранный профиль",
                icon="msg_retry" if active_or_busy else "msg_start",
                on_click=lambda *a: self._restart_olcrtc_from_settings(),
            ),
        ]
        items.extend([Divider(), Header(text="Ядро")])
        core_status = self._libsingbox_addon_status(quick=True)
        if core_status == "checking":
            items.append(Text(text="Проверяю ядро…", subtext="Проверка библиотеки выполняется в фоне", icon="msg_retry", accent=True))
        elif core_status == "current":
            items.append(Text(text="Ядро установлено", subtext="Текущая версия GreenPass", icon="msg_check"))
        else:
            core_action = "Обновить ядро" if core_status == "outdated" and SINGBOX_BUNDLE_URLS else "Скачать ядро"
            items.append(Text(
                text=core_action,
                subtext="Нативная библиотека для этого устройства",
                icon="msg_download_settings",
                on_click=lambda *a: self._download_olcrtc_addon(),
            ))
        return items

    def _build_active_mode_items(self):
        mode = self._get_connection_mode()
        if mode == VLESS_KIND:
            return self._build_vless_mode_items()
        if mode == TGWS_KIND:
            return self._build_tgws_mode_items()
        if mode == AWG_KIND:
            return self._build_awg_mode_items()
        if mode == OLCRTC_KIND:
            return self._build_olcrtc_mode_items()
        return self._build_vless_mode_items()

    def _create_active_mode_subpage(self):
        mode = self._get_connection_mode()
        title = self._settings_mode_title(mode)
        items = [
            Header(text=title),
            Text(
                text="Сменить режим",
                subtext=self._settings_mode_description(mode),
                icon="media_flip",
                create_sub_fragment=self._create_mode_picker_subpage,
            ),
            Divider(),
        ]
        items.extend(self._safe_settings_items(title, self._build_active_mode_items))
        items.extend([
            Divider(),
            Header(text="Диагностика"),
            Text(
                text="Скопировать логи ядра",
                subtext="Состояние и последние сообщения",
                icon="msg_log",
                on_click=lambda *a: self._copy_active_core_logs(),
            ),
        ])
        return items

    def _create_greenpass_extra_subpage(self):
        items = [
            Header(text="Обновления GreenPass"),
            Switch(
                key="plugin_autoupdate_enabled",
                text="Автообновление GreenPass",
                default=self._plugin_autoupdate_enabled(),
                subtext="Проверять новые версии в GitHub Releases",
                icon="msg_retry",
                on_change=self._set_plugin_autoupdate_enabled,
            ),
            Text(
                text="Проверить обновления",
                subtext="Текущая версия: %s (сборка %d)" % (str(getattr(self, "version", "") or "?"), GREENPASS_BUILD),
                icon="msg_download_settings",
                on_click=lambda *a: self._check_plugin_update_now(),
            ),
            Divider(),
            Header(text="Ядро и устройство"),
            Selector(
                key="vless_engine",
                text="Ядро VLESS",
                default=self._vless_engine_index(),
                items=list(VLESS_ENGINE_ITEMS),
                icon="msg_settings",
                on_change=self._on_vless_engine_changed,
            ),
            Switch(
                key="core_autoupdate_enabled",
                text="Автообновление ядра",
                default=self._core_autoupdate_enabled(),
                subtext="Обновлять устаревшую библиотеку в фоне",
                icon="msg_retry",
                on_change=self._set_core_autoupdate_enabled,
            ),
            Text(
                text="Изменить HWID",
                subtext="Текущий: " + _get_or_create_subscription_hwid(),
                icon="msg_edit",
                on_click=lambda *a: self._regenerate_subscription_hwid(),
            ),
            Divider(),
            Header(text="Сеть"),
            Switch(
                key="proxy_plugins_via_greenpass",
                text="Проксировать плагины",
                default=bool(self._get_plugins_proxy_enabled()),
                subtext="Направляет запросы плагинов через GreenPass",
                icon="msg_link",
                on_change=self._on_plugins_proxy_changed,
            ),
            Switch(
                key="ipv6_enabled",
                text="IPv6",
                default=bool(self._ipv6_enabled()),
                subtext="Выключено — Telegram работает только по IPv4",
                icon="msg_language",
                on_change=self._on_ipv6_changed,
            ),
            Switch(
                key="dont_use_with_vpn",
                text="Не использовать с VPN",
                default=bool(self.get_setting("dont_use_with_vpn", True)),
                subtext="Отключать при VPN",
                icon="msg_secret",
                on_change=self._on_dont_use_with_vpn_changed,
            ),
            Text(
                text="Исключённые WIFI сети",
                subtext=self._excluded_wifi_menu_subtext(),
                icon="msg_list",
                create_sub_fragment=self._create_excluded_wifi_subpage,
            ),
            Divider(),
            Header(text="Звонки"),
            Switch(
                key="tgws_voip_relay_enabled",
                text="Звонки через Relay",
                default=bool(self._get_tgws_voip_relay_enabled()),
                icon="msg_calls",
                on_change=self._set_tgws_voip_relay_enabled,
            ),
            Text(
                text="Voice Relay",
                subtext="Сервер и ключ",
                icon="msg_settings",
                create_sub_fragment=self._create_voice_relay_subpage,
            ),
            Divider(),
            Header(text="Перенос настроек"),
            Text(
                text="Экспорт настроек",
                subtext="Сохранить конфиги и настройки",
                icon="msg_link",
                on_click=lambda *a: self._export_settings_to_favorites(),
            ),
            Text(
                text="Импорт настроек",
                subtext="Восстановить конфиги и настройки",
                icon="msg_download",
                on_click=lambda *a: self._open_greenpass_import_file_picker(),
            ),
        ]
        return items

    def _create_voice_relay_subpage(self):
        return [
            Header(text="Voice Relay"),
            EditText(
                key="tgws_voip_relay_ip",
                hint="IPv4 Relay",
                default=str(self.get_setting("tgws_voip_relay_ip", TGWS_VOIP_RELAY_HOST)),
                max_length=15,
            ),
            EditText(
                key="tgws_voip_relay_port",
                hint="UDP-порт Relay",
                default=str(self.get_setting("tgws_voip_relay_port", str(TGWS_VOIP_RELAY_CONTROL_PORT))),
                max_length=5,
            ),
            EditText(
                key="tgws_voip_relay_hmac",
                hint="HMAC-ключ Relay",
                default=str(self.get_setting("tgws_voip_relay_hmac", TGWS_VOIP_RELAY_SECRET.decode("utf-8"))),
                max_length=512,
            ),
            Text(
                text="Скопировать tg://relay",
                icon="msg_link",
                on_click=lambda *a: self._copy_tgws_voip_relay_link(),
            ),
        ]

    def create_settings(self):
        try:
            hero = self._build_settings_hero()
            settings = [hero] if hero is not None else [Header(text="GreenPass")]
            if self._vless_prepare_in_progress:
                settings.append(Text(
                    text="Ядро загружается…",
                    subtext="Скачивание и проверка библиотеки",
                    icon="msg_download_settings",
                    accent=True,
                ))
            settings.append(Header(text="Подключение"))
            tg_proxy_enabled = bool(self._is_plugin_proxy_enabled())
            settings.append(Switch(
                key="use_proxy",
                text="Использовать прокси",
                default=bool(tg_proxy_enabled),
                subtext="Подключать Telegram через выбранный режим",
                icon="msg2_proxy_on" if bool(tg_proxy_enabled) else "msg2_proxy_off",
                on_change=self._on_use_proxy_changed,
            ))

            settings.extend(self._safe_settings_items("Статус", self._build_status_settings_items))

            active_mode = self._get_connection_mode()
            settings.append(Divider())
            settings.append(Header(text="Режим"))
            settings.append(Text(
                text="Текущий режим",
                subtext=self._settings_mode_title(active_mode) + " • " + self._settings_mode_description(active_mode),
                icon=self._settings_mode_icon(active_mode),
                create_sub_fragment=self._create_mode_picker_subpage,
            ))
            settings.append(Text(
                text="Настройки режима",
                subtext="Серверы, подключения и диагностика",
                icon="msg_customize",
                create_sub_fragment=self._create_active_mode_subpage,
            ))

            settings.append(Divider())
            settings.append(Header(text="Прочее"))
            settings.append(Text(
                text="Дополнительно",
                subtext="Сети, ядро, Relay и перенос",
                icon="msg_settings_art",
                create_sub_fragment=self._create_greenpass_extra_subpage,
            ))

            return settings
        except Exception as e:
            return [Header(text="Ошибка"), Text(text=str(e), icon="msg_info")]

    def _confirm_clear_awg(self):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except Exception:
            activity = None
        if not activity:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Очистить AWG?")
            builder.set_message("Конфиг AWG будет удалён, туннель отключён. Действие необратимо.")

            def on_yes(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass
                self._clear_awg_config()

            def on_no(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass

            builder.set_positive_button("Очистить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            try:
                builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
            except:
                pass
            builder.show()
        except Exception:
            self._clear_awg_config()

    def _copy_text(self, label, text, success_text="Скопировано"):
        label_text = str(label or "Text")
        copy_text = str(text or "")
        if len(copy_text) > 240000:
            copy_text = copy_text[:240000] + "\n...truncated..."
        ok_text = str(success_text or "Скопировано")

        def _run():
            try:
                from android.content import ClipData, Context
                ctx = ApplicationLoader.applicationContext
                clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                clip = ClipData.newPlainText(label_text, copy_text)
                clipboard.setPrimaryClip(clip)
                BulletinHelper.show_success(ok_text)
            except:
                try:
                    BulletinHelper.show_error("Не удалось скопировать")
                except:
                    pass

        try:
            run_on_ui_thread(_run)
        except:
            _run()

    def _copy_active_core_logs(self):
        mode = self._get_connection_mode()
        if mode == TGWS_KIND:
            return self._copy_tgws_logs()
        if mode == AWG_KIND:
            core = getattr(getattr(self._awg_core, "_real", None), "_core", None)
        elif mode == OLCRTC_KIND:
            core = getattr(self._olcrtc_core, "_real", None)
        else:
            core = getattr(self._vless_core, "_real", None)
        self._copy_singbox_logs(core)

    def _copy_singbox_logs(self, core=None):
        parts = ["state:\nmode=%s\nvless_running=%s\nvless_port=%s\nconnect_worker=%s\nconnect_pending=%s" % (
            self._get_connection_mode(),
            bool(getattr(self, "_vless_running", False)),
            int(getattr(self, "_vless_port", 0) or 0),
            bool(getattr(self, "_vless_connect_worker_active", False)),
            bool(getattr(self, "_vless_connect_pending", False)),
        )]
        if core is not None:
            for name in ("logs_json", "last_error", "last_log"):
                try:
                    value = getattr(core, name)()
                except:
                    value = ""
                value = str(value or "").strip()
                if value:
                    parts.append("%s:\n%s" % (name, value))
        self._copy_text("GreenPass core logs", "\n\n".join(parts), "Логи скопированы")

    def _copy_tgws_logs(self):
        try:
            port = int(getattr(self, "_tgws_port", 0) or 0)
        except:
            port = 0

        def _safe_len(value):
            try:
                return len(value)
            except:
                return 0

        def _safe_bool(fn):
            try:
                return bool(fn())
            except:
                return False

        local_port_alive = _safe_bool(lambda: port > 0 and _check_vless_port(port))
        local_mtproto_ready = local_port_alive
        local_proxy_applied = _safe_bool(lambda: port > 0 and self._is_local_tgws_proxy_applied(port))

        rows = [
            ("mode", self._get_connection_mode()),
            ("running", bool(getattr(self, "_tgws_running", False))),
            ("ready", bool(getattr(self, "_tgws_ready", False))),
            ("connecting", bool(getattr(self, "_tgws_connecting", False))),
            ("backgrounded", bool(getattr(self, "_tgws_backgrounded", False))),
            ("generation", int(getattr(self, "_tgws_generation", 0) or 0)),
            ("port", port),
            ("local_port_alive", local_port_alive),
            ("local_mtproto_ready", local_mtproto_ready),
            ("local_proxy_applied", local_proxy_applied),
        ]

        try:
            last_heal = float(getattr(self, "_tgws_last_heal_ts", 0.0) or 0.0)
            rows.append(("last_heal_age_sec", int(time.time() - last_heal) if last_heal > 0 else 0))
        except:
            pass

        core = getattr(self, "_tgws_core", None)
        if core is not None:
            rows.append(("core_available", _safe_bool(lambda: core.is_available())))
            rows.append(("listener", getattr(core, "listener", None) is not None))
            try:
                thread = getattr(core, "listener_thread", None)
                rows.append(("listener_thread_alive", bool(thread is not None and thread.is_alive())))
            except:
                pass
            try:
                with core.lock:
                    rows.append(("tracked", _safe_len(getattr(core, "tracked", []))))
            except:
                rows.append(("tracked", _safe_len(getattr(core, "tracked", []))))
            rows.extend([
                ("core_port", int(getattr(core, "port", 0) or 0)),
                ("fail_until", _safe_len(getattr(core, "fail_until", {}))),
                ("fail_count", _safe_len(getattr(core, "fail_count", {}))),
                ("ip_fail_until", _safe_len(getattr(core, "ip_fail_until", {}))),
                ("ws_blacklist", _safe_len(getattr(core, "ws_blacklist", set()))),
                ("ws_domain_pref", _safe_len(getattr(core, "ws_domain_pref", {}))),
                ("cf_domain_pref", _safe_len(getattr(core, "cf_domain_pref", {}))),
                ("cf_429_until", _safe_len(getattr(core, "cf_429_until", {}))),
                ("cfproxy_enabled", bool(getattr(core, "cfproxy_enabled", False))),
                ("cfproxy_priority", bool(getattr(core, "cfproxy_priority", False))),
                ("cfproxy_domains", _safe_len(getattr(core, "cfproxy_domains", []))),
                ("cfproxy_worker", bool(str(getattr(core, "cfproxy_worker_domain", "") or "").strip())),
            ])
            try:
                pool = getattr(core, "ws_pool", None)
                idle_count = 0
                idle_keys = 0
                refilling = 0
                rotating = 0
                refill_backoff = 0
                if pool is not None:
                    with pool.lock:
                        idle = getattr(pool, "idle", {}) or {}
                        idle_keys = len(idle)
                        idle_count = sum(len(value) for value in idle.values())
                        refilling = _safe_len(getattr(pool, "refilling", set()))
                        rotating = _safe_len(getattr(pool, "rotating", set()))
                        refill_backoff = _safe_len(getattr(pool, "refill_after", {}))
                rows.extend([
                    ("ws_pool_size", int(getattr(pool, "size", 0) or 0) if pool is not None else 0),
                    ("ws_pool_idle_keys", idle_keys),
                    ("ws_pool_idle", idle_count),
                    ("ws_pool_refilling", refilling),
                    ("ws_pool_rotating", rotating),
                    ("ws_pool_refill_backoff", refill_backoff),
                ])
            except:
                pass

        text = "\n".join("%s: %s" % (key, value) for key, value in rows)
        self._copy_text("GreenPass TG WS logs", text, "Логи скопированы")

    def _copy_link(self, link):
        self._copy_text("Proxy Link", link, "Ссылка скопирована")
