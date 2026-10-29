from ..foundation import *
from ..protocols import *
from ..tgws import *
from ..native import *
from ..subscriptions import *
from ..hooks import *


class OlcRtcModeMixin:
    def _libzvonki_so_path(self):
        return self._libsingbox_so_path()

    def _has_libzvonki_addon(self):
        return self._has_libsingbox_addon()

    def _is_olcrtc_mode_selected(self):
        return self._get_connection_mode() == OLCRTC_KIND

    def _olcrtc_item_by_setting(self, key, items, default_index=0):
        try:
            idx = int(self.get_setting(key, int(default_index)))
        except:
            idx = int(default_index)
        try:
            if idx < 0 or idx >= len(items):
                idx = int(default_index)
        except:
            idx = int(default_index)
        try:
            return str(items[idx])
        except:
            return str(items[int(default_index)])

    def _olcrtc_carrier_index(self):
        try:
            idx = int(self.get_setting("olcrtc_carrier", 0))
            if 0 <= idx < len(OLCRTC_CARRIER_ITEMS):
                return idx
        except:
            pass
        return 0

    def _get_olcrtc_carrier(self):
        return self._olcrtc_item_by_setting("olcrtc_carrier", OLCRTC_CARRIER_ITEMS, 0)

    def _get_olcrtc_transport(self):
        transport = self._olcrtc_item_by_setting("olcrtc_transport", OLCRTC_TRANSPORT_ITEMS, 0)
        supported = _olcrtc_supported_transports(self._get_olcrtc_carrier())
        return transport if transport in supported else supported[0]

    def _olcrtc_transport_choices(self):
        return _olcrtc_supported_transports(self._get_olcrtc_carrier())

    def _olcrtc_transport_choice_index(self):
        choices = self._olcrtc_transport_choices()
        try:
            return choices.index(self._get_olcrtc_transport())
        except:
            return 0

    def _olcrtc_carrier_label(self, value):
        return self._olcrtc_label_for_item(value, OLCRTC_CARRIER_ITEMS, OLCRTC_CARRIER_LABELS, 0)

    def _olcrtc_transport_label(self, value):
        return self._olcrtc_label_for_item(value, OLCRTC_TRANSPORT_ITEMS, OLCRTC_TRANSPORT_LABELS, 0)

    def _olcrtc_label_for_item(self, value, items, labels, default_index=0):
        try:
            target = str(value or "").strip().lower()
            for idx, item in enumerate(items):
                if str(item or "").strip().lower() == target and idx < len(labels):
                    return str(labels[idx] or item)
        except:
            pass
        try:
            idx = int(default_index)
            if 0 <= idx < len(labels):
                return str(labels[idx] or items[idx])
        except:
            pass
        return str(value or "")

    def _olcrtc_current_labels(self):
        return self._olcrtc_carrier_label(self._get_olcrtc_carrier()), self._olcrtc_transport_label(self._get_olcrtc_transport())

    def _get_olcrtc_room_id(self):
        try:
            return str(self.get_setting("olcrtc_room_id", "") or "").strip()
        except:
            return ""

    def _get_olcrtc_client_id(self):
        return _get_or_create_olcrtc_device_id()

    def _get_olcrtc_vp8_options(self):
        try:
            fps = max(1, min(120, int(self.get_setting("olcrtc_vp8_fps", "60") or 60)))
        except:
            fps = 60
        try:
            batch = max(1, min(64, int(self.get_setting("olcrtc_vp8_batch_size", "64") or 64)))
        except:
            batch = 64
        return fps, batch

    def _get_olcrtc_key_hex(self):
        try:
            return str(self.get_setting("olcrtc_key_hex", "") or "").strip()
        except:
            return ""

    def _olcrtc_config_error(self):
        if not self._get_olcrtc_room_id():
            return "Укажите room_id"
        if not self._get_olcrtc_client_id():
            return "Укажите client_id"
        key_hex = self._get_olcrtc_key_hex()
        if not key_hex:
            return "Укажите key_hex"
        if len(key_hex) != 64 or re.search(r"[^0-9a-fA-F]", key_hex):
            return "key_hex должен быть 64 hex"
        return ""

    def _is_olcrtc_config_ready(self):
        return not bool(self._olcrtc_config_error())

    def _olcrtc_profile_id_for(self, carrier, transport, room_id, client_id, key_hex):
        try:
            raw = "|".join([
                str(carrier or "").strip().lower(),
                str(transport or "").strip().lower(),
                str(room_id or "").strip(),
                str(client_id or "").strip(),
                str(key_hex or "").strip().lower(),
            ])
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        except:
            return str(int(time.time() * 1000))

    def _olcrtc_profile_name(self, profile):
        try:
            name = str(profile.get("name", "") or "").strip()
            if name:
                return name[:48]
            room_id = str(profile.get("room_id", "") or "").strip()
            client_id = str(profile.get("client_id", "") or "").strip()
            tail = room_id.rstrip("/").split("/")[-1] if room_id else ""
            base = tail or room_id or client_id or "olcRTC"
            if client_id and client_id not in base:
                base = "%s • %s" % (base, client_id)
            return base[:48] if base else "olcRTC"
        except:
            return "olcRTC"

    def _ensure_olcrtc_legacy_profile(self):
        if self._olcrtc_profiles:
            return
        try:
            profile = self._normalize_olcrtc_profile({
                "carrier": self._get_olcrtc_carrier(),
                "transport": self._get_olcrtc_transport(),
                "room_id": self._get_olcrtc_room_id(),
                "client_id": self._get_olcrtc_client_id(),
                "key_hex": self._get_olcrtc_key_hex(),
            })
        except:
            profile = None
        if profile:
            self._olcrtc_profiles = [profile]
            self._olcrtc_active_profile_id = str(profile.get("id", "") or "")

    def _set_olcrtc_legacy_settings_from_profile(self, profile):
        if not isinstance(profile, dict):
            return
        self._set_setting_value("olcrtc_carrier", self._olcrtc_index_for_item(profile.get("carrier"), OLCRTC_CARRIER_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(profile.get("transport"), OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_room_id", str(profile.get("room_id", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_client_id", str(profile.get("client_id", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_key_hex", str(profile.get("key_hex", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_vp8_fps", str(profile.get("vp8_fps", 60) or 60), reload_settings=False)
        self._set_setting_value("olcrtc_vp8_batch_size", str(profile.get("vp8_batch_size", 64) or 64), reload_settings=False)

    def _olcrtc_core_query_allowed(self, allow_connecting=False):
        if bool(getattr(self, "_olcrtc_prepare_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_start_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_stop_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            return False
        if (not bool(allow_connecting)) and bool(getattr(self, "_olcrtc_connecting", False)):
            return False
        try:
            return bool(self._olcrtc_core.is_available())
        except:
            return False

    def _set_olcrtc_last_log(self, message, event="state", level="info", **fields):
        try:
            text = str(message or "").strip()
        except:
            text = ""
        self._olcrtc_last_log = text

    def _set_olcrtc_last_error(self, message, event="error", **fields):
        try:
            text = str(message or "").strip()
        except:
            text = ""
        self._olcrtc_last_error = text

    def _olcrtc_core_status_data(self):
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            fallback_state = "background"
        elif bool(getattr(self, "_olcrtc_resume_checking", False)) or bool(getattr(self, "_olcrtc_health_stale", False)):
            fallback_state = "checking"
        elif bool(self._olcrtc_running):
            fallback_state = "ready"
        elif bool(getattr(self, "_olcrtc_connecting", False)):
            fallback_state = "handshake"
        elif bool(getattr(self, "_olcrtc_prepare_in_progress", False)) or bool(getattr(self, "_vless_prepare_in_progress", False)):
            fallback_state = "starting"
        elif self._should_run_olcrtc() and str(getattr(self, "_olcrtc_last_error", "") or "").strip():
            fallback_state = "error"
        else:
            fallback_state = "stopped"
        fallback = {
            "state": fallback_state,
            "message": str(getattr(self, "_olcrtc_last_error", "") or getattr(self, "_olcrtc_last_log", "") or "").strip(),
            "running": fallback_state == "ready",
        }
        if fallback_state in ("background", "checking"):
            return fallback
        try:
            raw = self._safe_olcrtc_core_text("status_json", allow_connecting=False)
            if not raw:
                return fallback
            data = json.loads(raw)
            if not isinstance(data, dict):
                return fallback
            state = str(data.get("state", "") or "").strip().lower()
            if not state:
                return fallback
            data["state"] = state
            return data
        except:
            return fallback

    def _olcrtc_status_presentation(self):
        data = self._olcrtc_core_status_data()
        state = str(data.get("state", "") or "stopped").strip().lower()
        labels = {
            "starting": "olcRTC: запуск",
            "handshake": "olcRTC: handshake",
            "ready": "olcRTC: подключен",
            "running": "olcRTC: подключен",
            "background": "olcRTC: в фоне",
            "checking": "olcRTC: проверка",
            "stopping": "olcRTC: остановка",
            "stopped": "olcRTC: выключен",
            "error": "olcRTC: ошибка",
        }
        text = labels.get(state, "olcRTC: " + state[:24])
        message = str(data.get("message", "") or "").strip()
        carrier_label, transport_label = self._olcrtc_current_labels()
        subtext = message[:120] if message else "%s / %s" % (carrier_label, transport_label)
        return text, subtext, state

    def _olcrtc_local_ready(self, port, check_tunnel=False, reason="health"):
        try:
            target_port = int(port or 0)
        except:
            target_port = 0
        if target_port <= 0:
            return False
        if not _check_vless_port(target_port):
            return False
        if not _check_vless_socks_ready(target_port, timeout=0.5):
            return False
        if not bool(check_tunnel):
            return True
        ok = _check_olcrtc_tunnel_ready(target_port, timeout=float(OLCRTC_TUNNEL_CHECK_TIMEOUT_SEC))
        if not ok:
            pass
        return bool(ok)

    def _olcrtc_state_needs_restart(self, core_state):
        state = str(core_state or "").strip().lower()
        return state in ("error", "stopped") and (not bool(getattr(self, "_olcrtc_connecting", False)))

    def _olcrtc_try_next_profile(self, reason=""):
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        if len(profiles) < 2:
            return False
        active_id = str(self._olcrtc_active_profile_id or "")
        index = 0
        for idx, profile in enumerate(profiles):
            if str(profile.get("id", "") or "") == active_id:
                index = idx
                break
        next_profile = profiles[(index + 1) % len(profiles)]
        next_id = str(next_profile.get("id", "") or "")
        if not next_id or next_id == active_id:
            return False
        self._olcrtc_profiles = profiles
        self._olcrtc_active_profile_id = next_id
        self._set_olcrtc_legacy_settings_from_profile(next_profile)
        self._set_connection_mode(OLCRTC_KIND)
        self._save_config()
        self._set_olcrtc_last_log("next profile after " + str(reason or "failure"), event="profile_failover")
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        self._ensure_olcrtc_core_then(self._olcrtc_connect)
        return True

    def _ensure_olcrtc_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_olcrtc_mode = runner_name == "_olcrtc_connect"
        show_feedback = bool(getattr(self, "_olcrtc_feedback_requested", False))
        if require_olcrtc_mode and (not self._should_run_olcrtc()):
            if show_feedback and self._is_olcrtc_mode_selected():
                run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
            return
        if self._go_core_switch_blocked("olcrtc"):
            return
        self._olcrtc_core._ensure()
        if self._olcrtc_core.is_available():
            if require_olcrtc_mode and (not self._should_run_olcrtc()):
                if show_feedback and self._is_olcrtc_mode_selected():
                    run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._olcrtc_prepare_in_progress:
            if show_feedback:
                BulletinHelper.show_info("olcRTC уже готовится")
            return

        self._olcrtc_prepare_in_progress = True
        if show_feedback:
            BulletinHelper.show_info("Готовлю olcRTC...")

        def _worker():
            try:
                ok = self._install_libzvonki_bundle(allow_network=True)
                if ok and self._core_restart_required():
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    return
                self._reload_olcrtc_core()
                self._olcrtc_core._ensure()
                if ok and self._olcrtc_core.is_available():
                    if require_olcrtc_mode and (not self._should_run_olcrtc()):
                        return
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро olcRTC готово"))
                    try:
                        runner()
                    except Exception as exc:
                        err_text = str(exc)
                        self._set_olcrtc_last_error(err_text, event="ensure_runner_exception", runner=runner_name)
                        if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка olcRTC: %s" % err_text))
                else:
                    self._set_olcrtc_last_error("core prepare failed", event="ensure_prepare_failed", runner=runner_name, installed=ok)
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить olcRTC"))
            finally:
                self._olcrtc_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()

    def _olcrtc_connect(self):
        with self._olcrtc_connect_lock:
            if bool(getattr(self, "_olcrtc_connect_worker_active", False)):
                self._olcrtc_connect_pending = True
                should_queue = True
            else:
                self._olcrtc_connect_worker_active = True
                self._olcrtc_connect_pending = False
                should_queue = False
        if should_queue:
            self._set_olcrtc_last_log("restart queued", event="connect_queued")
            return True

        result = False
        try:
            while True:
                with self._olcrtc_connect_lock:
                    self._olcrtc_connect_pending = False
                result = self._olcrtc_connect_once()
                with self._olcrtc_connect_lock:
                    repeat = bool(self._olcrtc_connect_pending) and bool(self._should_run_olcrtc())
                    if not repeat:
                        self._olcrtc_connect_worker_active = False
                        return result
        finally:
            with self._olcrtc_connect_lock:
                self._olcrtc_connect_worker_active = False

    def _olcrtc_connect_once(self):
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            return False
        show_feedback = bool(getattr(self, "_olcrtc_feedback_requested", False))
        if not self._should_run_olcrtc():
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_feedback_requested = False
            if show_feedback and self._is_olcrtc_mode_selected():
                run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
            return False
        config_json, config_err = self._build_olcrtc_config_json()
        if config_err:
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._olcrtc_feedback_requested = False
            self._set_olcrtc_last_error(config_err, event="connect_config_error")
            if show_feedback:
                run_on_ui_thread(lambda config_err=config_err: BulletinHelper.show_error(config_err))
            return False
        if not self._olcrtc_core.is_available():
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
            return False

        self._olcrtc_feedback_requested = False
        generation = self._next_olcrtc_generation()
        old_port = int(self._olcrtc_port or 0)
        self._olcrtc_running = False
        self._olcrtc_connecting = True
        self._olcrtc_dead_checks = 0
        self._olcrtc_last_error = ""
        self._set_olcrtc_last_log(
            "starting %s %s" % (self._get_olcrtc_carrier(), self._get_olcrtc_transport()),
            event="connect_start",
            generation=generation,
            old_port=old_port,
            carrier=self._get_olcrtc_carrier(),
            transport=self._get_olcrtc_transport(),
            room_id=self._get_olcrtc_room_id(),
            client_id=self._get_olcrtc_client_id(),
            key_hex=self._mask_olcrtc_key(),
        )
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=OLCRTC_KIND)
        port = int(self._local_port(OLCRTC_KIND))

        self._olcrtc_port = port
        self._olcrtc_start_in_progress = True
        self._set_olcrtc_last_log("handshake started", event="native_start_enter", generation=generation, port=port)
        try:
            err = self._olcrtc_core.start(config_json)
        finally:
            self._olcrtc_start_in_progress = False
        if err:
            if not self._same_olcrtc_generation(generation) or not self._is_olcrtc_mode_selected():
                return False
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            detail = str(err or "")
            self._set_olcrtc_last_error(detail, event="native_start_failed", generation=generation, port=port)
            self._set_olcrtc_last_log("start failed", event="connect_failed", generation=generation, port=port)
            if self._olcrtc_try_next_profile("start failed"):
                return False
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
            if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                run_on_ui_thread(lambda detail=detail: BulletinHelper.show_error("Ошибка olcRTC: %s" % str(detail)))
            return False

        def _watchdog():
            deadline = time.time() + float(OLCRTC_LOCAL_READY_TIMEOUT_SEC)
            while time.time() < deadline:
                if not self._same_olcrtc_generation(generation) or not self._should_run_olcrtc() or int(self._olcrtc_port or 0) != int(port):
                    self._olcrtc_running = False
                    self._olcrtc_connecting = False
                    self._set_olcrtc_last_log("watchdog cancelled", event="watchdog_cancelled", generation=generation, port=port)
                    return
                if self._olcrtc_local_ready(port, check_tunnel=True, reason="watchdog_ready"):
                    if not self._same_olcrtc_generation(generation) or not self._should_run_olcrtc() or int(self._olcrtc_port or 0) != int(port):
                        self._clear_local_socks_proxy_if_port(port, owner=OLCRTC_KIND)
                        self._olcrtc_running = False
                        self._olcrtc_connecting = False
                        self._set_olcrtc_last_log("cancelled before ready", event="watchdog_cancelled_before_apply", generation=generation, port=port)
                        return
                    applied = self._apply_local_socks_proxy(port, True, owner=OLCRTC_KIND)
                    apply_deadline = time.time() + 1.5
                    while applied and time.time() < apply_deadline:
                        if self._is_local_olcrtc_proxy_applied(port):
                            break
                        time.sleep(0.1)
                    if not applied or (not self._is_local_olcrtc_proxy_applied(port)):
                        self._olcrtc_running = False
                        self._olcrtc_connecting = False
                        self._olcrtc_port = 0
                        self._set_olcrtc_last_error("telegram local proxy apply failed", event="telegram_proxy_apply_failed", generation=generation, port=port, applied=applied)
                        self._set_olcrtc_last_log("socks ready, telegram apply failed", event="connect_failed_after_socks_ready", generation=generation, port=port)
                        if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)) and self._same_olcrtc_generation(generation) and self._is_olcrtc_mode_selected():
                            run_on_ui_thread(lambda: BulletinHelper.show_error("Локальный прокси не применился"))
                        return
                    self._olcrtc_running = True
                    self._olcrtc_connecting = False
                    self._olcrtc_health_stale = False
                    self._olcrtc_resume_checking = False
                    self._olcrtc_dead_checks = 0
                    self._olcrtc_last_error = ""
                    self._set_olcrtc_last_log("connected on socks port %s" % int(port), event="connect_ready", generation=generation, port=port)
                    self._save_config()
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_success("olcRTC подключен"))
                    return
                time.sleep(0.3)
            if not self._same_olcrtc_generation(generation) or not self._is_olcrtc_mode_selected():
                return
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._set_olcrtc_last_error("WebRTC timeout", event="watchdog_timeout", generation=generation, port=port)
            self._set_olcrtc_last_log("ready watchdog timeout", event="connect_timeout", generation=generation, port=port)
            if self._olcrtc_try_next_profile("timeout"):
                return
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
            if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                run_on_ui_thread(lambda: BulletinHelper.show_error("olcRTC: WebRTC timeout"))

        threading.Thread(target=_watchdog, daemon=True).start()
        return True

    def _olcrtc_disconnect_with_reason(self, reason, silent=False):
        reason_text = str(reason or "")
        stop_core = reason_text in ("manual_stop", "start_failed", "ready_timeout", "apply_failed")
        self._olcrtc_disconnect(silent=bool(silent), stop_core=bool(stop_core))

    def _olcrtc_disconnect(self, silent=False, stop_core=False):
        self._next_olcrtc_generation()
        self._olcrtc_feedback_requested = False
        old_port = int(self._olcrtc_port or 0)
        with self._olcrtc_connect_lock:
            self._olcrtc_connect_pending = False
        if bool(stop_core):
            self._stop_olcrtc_core_async()
        self._olcrtc_running = False
        self._olcrtc_connecting = False
        self._olcrtc_dead_checks = 0
        self._olcrtc_port = 0
        self._set_olcrtc_last_log("stopped", event="disconnect_finish", old_port=old_port)
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=OLCRTC_KIND)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _olcrtc_index_for_item(self, value, items, default_index=0):
        try:
            target = str(value or "").strip().lower()
            for idx, item in enumerate(items):
                if str(item).lower() == target:
                    return int(idx)
        except:
            pass
        return int(default_index)

    def _olcrtc_subscription_urls(self):
        result = []
        for profile in self._sanitize_olcrtc_profiles(self._olcrtc_profiles):
            url = str(profile.get("subscription_url", "") or "").strip()
            if url.lower().startswith(("http://", "https://")) and url not in result:
                result.append(url)
        return result

    def _olcrtc_subscriptions_stale(self):
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        cutoff = int(time.time()) - 86400
        for url in self._olcrtc_subscription_urls():
            updated = max([
                int(profile.get("subscription_updated_at", 0) or 0)
                for profile in profiles
                if str(profile.get("subscription_url", "") or "") == url
            ] or [0])
            if updated < cutoff:
                return True
        return False

    def _switch_to_olcrtc_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("olcrtc"):
            return
        if persist_mode:
            self._set_connection_mode(OLCRTC_KIND)
        self._vless_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        if not self._is_olcrtc_config_ready():
            run_on_ui_thread(lambda: BulletinHelper.show_info("Заполните olcRTC"))
        else:
            self._enable_plugin_proxy_flag()
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
