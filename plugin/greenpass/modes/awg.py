from ..foundation import *
from ..protocols import *
from ..tgws import *
from ..native import *
from ..subscriptions import *
from ..hooks import *
from ..warp import WARP_CONF_NAME, generate_warp_conf


class AwgModeMixin:
    def _libawg_so_path(self):
        return self._libsingbox_so_path()

    def _has_libawg_addon(self):
        return self._has_libsingbox_addon()

    def _is_awg_mode_selected(self):
        return self._get_connection_mode() == AWG_KIND

    def _is_awg_connection_ready(self):
        if not self._should_run_awg():
            return False
        try:
            return bool(self._is_local_proxy_applied(int(self._awg_port or AWG_LOCAL_PORT), owner=AWG_KIND))
        except Exception:
            return False

    def _restore_running_awg_proxy(self, force_reapply=False):
        if not self._should_run_awg():
            return False
        started_conf = str(getattr(self, "_awg_started_conf", "") or "")
        if started_conf and started_conf != str(self._awg_conf_content or "").strip():
            return False
        port = int(self._awg_port or AWG_LOCAL_PORT)
        if not _check_vless_socks_ready(port, timeout=0.35):
            return False
        applied = self._is_local_proxy_applied(port, owner=AWG_KIND)
        changed = bool(force_reapply) or not bool(self._awg_running) or int(self._awg_port or 0) != port or not applied
        if (bool(force_reapply) or not applied) and not self._apply_local_socks_proxy(port, True, owner=AWG_KIND):
            return False
        self._awg_port = port
        self._awg_running = True
        if changed:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        return True

    def _ensure_awg_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_awg_mode = runner_name == "_awg_connect"
        if require_awg_mode and (not self._should_run_awg()):
            return
        if self._go_core_switch_blocked("awg"):
            return
        self._awg_core._ensure()
        if self._awg_core.is_available():
            if require_awg_mode and (not self._should_run_awg()):
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._awg_prepare_in_progress:
            return

        self._awg_prepare_in_progress = True
        BulletinHelper.show_info("Скачиваю ядро AWG...")

        def _worker():
            try:
                ok = self._has_libawg_addon()
                if ok:
                    self._reload_awg_core()
                    self._awg_core._ensure()
                    if not self._awg_core.is_available():
                        try:
                            os.remove(self._libawg_so_path())
                            self._libsingbox_validation_cache = None
                        except:
                            pass
                        ok = False
                if not ok:
                    ok = self._download_libawg_with_progress()
                    if ok and self._core_restart_required():
                        run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                        return
                    self._reload_awg_core()
                    self._awg_core._ensure()
                if not (ok and self._awg_core.is_available()):
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро AWG"))
                    return
                if require_awg_mode and (not self._should_run_awg()):
                    return
                try:
                    runner()
                except Exception as exc:
                    err_text = str(exc)
                    run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка AWG: %s" % err_text))
            finally:
                self._awg_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()

    def _awg_connect(self):
        if not self._should_run_awg():
            self._awg_connecting = False
            return False
        self._awg_connecting = True
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        try:
            conf_content = str(self._awg_conf_content or "").strip()
            if not conf_content:
                self._awg_running = False
                self._awg_port = 0
                self._download_free_awg_config()
                return False

            if self._restore_running_awg_proxy():
                return True

            if not self._awg_core.is_available():
                self._awg_running = False
                self._awg_port = 0
                self._ensure_awg_core_then(self._awg_connect)
                return False

            port = int(AWG_LOCAL_PORT)
            self._awg_port = port
            if not self._should_run_awg():
                self._awg_port = 0
                return False
            err = self._awg_core.start(conf_content)
            if err:
                self._awg_running = False
                self._awg_port = 0
                self._awg_started_conf = ""
                run_on_ui_thread(lambda: BulletinHelper.show_error("Ошибка AWG: %s" % str(err)))
                return False

            self._awg_started_conf = conf_content
            self._awg_running = True
            if not self._should_run_awg():
                self._awg_running = False
                self._awg_port = 0
                return False
            if not self._apply_local_socks_proxy(port, True, owner=AWG_KIND):
                self._awg_running = False
                return False
            if not self._should_run_awg() or int(self._awg_port or 0) != int(port):
                self._clear_local_socks_proxy_if_port(port, owner=AWG_KIND)
                self._awg_running = False
                return False
            self._save_config()
            run_on_ui_thread(lambda: BulletinHelper.show_success("AmneziaWG подключен"))
            return True
        finally:
            self._awg_connecting = False
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _awg_disconnect_with_reason(self, reason, silent=False):
        reason_text = str(reason or "unknown")
        stop_core = reason_text in ("manual_stop", "restart_awg", "clear_awg_config", "start_failed", "apply_failed")
        self._awg_disconnect(silent=bool(silent), reason=reason_text, stop_core=bool(stop_core))

    def _awg_disconnect(self, silent=False, reason="unknown", stop_core=False):
        old_port = int(self._awg_port or 0)
        if bool(stop_core) and bool(getattr(self._awg_core, "started", False)):
            try:
                self._awg_core.stop()
            except Exception:
                pass
            self._awg_started_conf = ""
        self._awg_running = False
        self._awg_connecting = False
        self._awg_port = 0
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=AWG_KIND)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _ensure_awg_config_then_connect(self):
        if str(self._awg_conf_content or "").strip():
            self._ensure_awg_core_then(self._awg_connect)
            return
        self._download_free_awg_config()

    def _switch_to_awg_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("awg"):
            return
        if persist_mode:
            self._set_connection_mode(AWG_KIND)
        self._vless_disconnect_with_reason("switch_to_awg_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_awg_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_awg_mode", silent=True)
        if not str(self._awg_conf_content or "").strip():
            self._enable_plugin_proxy_flag()
            self._ensure_awg_config_then_connect()
        else:
            self._enable_plugin_proxy_flag()
            self._ensure_awg_core_then(self._awg_connect)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    # ---- AWG health check -------------------------------------------------
    # A free config can die (server gone, key revoked) while the core keeps
    # running, so Telegram sits on "Соединение..." until a reinstall. Once a
    # minute, connect to a Telegram DC through the local AWG proxy; after 3
    # failures in a row, regenerate the WARP config (or restart a user config).
    _AWG_HEALTH_TARGETS = (("149.154.167.50", 443), ("149.154.175.50", 443))

    def _awg_probe_once(self):
        port = int(self._awg_port or AWG_LOCAL_PORT)
        for host, dport in self._AWG_HEALTH_TARGETS:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=10.0) as sock:
                    sock.settimeout(10.0)
                    sock.sendall(b"\x05\x01\x00")
                    if sock.recv(2) != b"\x05\x00":
                        continue
                    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + int(dport).to_bytes(2, "big"))
                    head = sock.recv(4)
                    if len(head) >= 2 and head[0] == 5 and head[1] == 0:
                        return True
            except Exception:
                pass
        return False

    def _awg_health_fix(self):
        if str(self._awg_conf_name or "") == WARP_CONF_NAME:
            try:
                text = generate_warp_conf()
                self._awg_conf_content = text
                self._save_config()
                run_on_ui_thread(lambda: BulletinHelper.show_info("AWG не отвечал — создан новый WARP конфиг"))
            except Exception as exc:
                err_text = str(exc)
                run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Не удалось обновить WARP: %s" % err_text))
        else:
            run_on_ui_thread(lambda: BulletinHelper.show_info("AWG не отвечал — переподключаю"))
        run_on_ui_thread(self._restart_awg_from_settings)

    def _start_awg_health_thread(self):
        if bool(getattr(self, "_awg_health_thread_started", False)):
            return
        self._awg_health_thread_started = True

        def _loop():
            fails = 0
            last_fix = 0.0
            while self._active:
                time.sleep(60)
                if not self._active:
                    break
                try:
                    if (not self._is_awg_connection_ready()) or bool(getattr(self, "_awg_connecting", False)):
                        fails = 0
                        continue
                    try:
                        if not bool(ApplicationLoader.isNetworkOnline()):
                            continue
                    except Exception:
                        pass
                    if self._awg_probe_once():
                        fails = 0
                        continue
                    fails += 1
                    if fails < 3 or time.time() - last_fix < 600:
                        continue
                    fails = 0
                    last_fix = time.time()
                    self._awg_health_fix()
                except Exception:
                    pass

        threading.Thread(target=_loop, daemon=True).start()
