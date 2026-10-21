from ..foundation import *
from ..protocols import *
from ..tgws import *
from ..native import *
from ..subscriptions import *
from ..hooks import *
import socket


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
        self._on_awg_connected()
        return True

    def _ensure_awg_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_awg_mode = runner_name == "_awg_connect"
        if require_awg_mode and (not self._should_run_awg()):
            return
        if self._go_core_switch_blocked("awg"):
            return

        def _prepare_and_run():
            # dlopen of the ~120 MB library, hashing and downloads run on this worker
            # thread, never on the caller's (possibly UI) thread.
            try:
                self._prepare_awg_core_and_run(runner, require_awg_mode)
            except Exception as exc:
                err_text = str(exc)
                BulletinHelper.show_error("Ошибка AWG: %s" % err_text)

        try:
            threading.Thread(target=_prepare_and_run, daemon=True).start()
        except Exception:
            pass

    def _prepare_awg_core_and_run(self, runner, require_awg_mode):
        if self._libsingbox_core_load_allowed():
            self._awg_core._ensure()
        if self._awg_core.is_available():
            if require_awg_mode and (not self._should_run_awg()):
                return
            runner()
            return
        if self._core_needs_restart_notice():
            BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
            return
        if self._awg_prepare_in_progress:
            return
        if time.monotonic() < float(getattr(self, "_awg_core_fail_until", 0.0) or 0.0):
            return

        self._awg_prepare_in_progress = True
        BulletinHelper.show_info("Скачиваю ядро AWG...")
        try:
            ok = self._has_libawg_addon()
            if ok:
                self._reload_awg_core()
                self._awg_core._ensure()
                if not self._awg_core.is_available():
                    if self._core_needs_restart_notice():
                        BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
                        return
                    # Delete and re-download only when the file fails its integrity check,
                    # at most once per 10 minutes. A valid file that will not dlopen is not
                    # corruption: report once and stop retrying for a while.
                    status = self._libsingbox_addon_status()
                    now_m = time.monotonic()
                    if status == "current" or now_m - float(getattr(self, "_awg_core_redownload_ts", 0.0) or 0.0) < 600.0:
                        self._awg_core_fail_until = now_m + 600.0
                        BulletinHelper.show_error("Не удалось загрузить ядро AWG")
                        return
                    self._awg_core_redownload_ts = now_m
                    try:
                        os.remove(self._libawg_so_path())
                        self._libsingbox_validation_cache = None
                    except:
                        pass
                    ok = False
            if not ok:
                ok = self._download_libawg_with_progress()
                if ok and self._core_restart_required():
                    BulletinHelper.show_success("Ядро установлено — перезапустите приложение")
                    return
                self._reload_awg_core()
                self._awg_core._ensure()
            if not (ok and self._awg_core.is_available()):
                BulletinHelper.show_error("Не удалось загрузить ядро AWG")
                return
            if require_awg_mode and (not self._should_run_awg()):
                return
            try:
                runner()
            except Exception as exc:
                err_text = str(exc)
                BulletinHelper.show_error("Ошибка AWG: %s" % err_text)
        finally:
            self._awg_prepare_in_progress = False

    def _awg_connect(self):
        if not self._should_run_awg():
            self._awg_connecting = False
            return False
        self._awg_connecting = True
        self._awg_health_hold_until = 0.0
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
            self._awg_epoch = int(getattr(self, "_awg_epoch", 0) or 0) + 1
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
            self._on_awg_connected()
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
        stop_epoch = None
        if bool(stop_core) and bool(getattr(self._awg_core, "started", False)):
            stop_epoch = int(getattr(self, "_awg_epoch", 0) or 0)
            self._awg_started_conf = ""
        self._awg_running = False
        self._awg_connecting = False
        self._awg_port = 0
        # Telegram's proxy first, then the core: Telegram never dials a dead port.
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=AWG_KIND)
        if stop_epoch is not None:
            self._stop_awg_core(stop_epoch)
        if not str(reason or "").startswith("health_"):
            self._stop_awg_health_loop()
        if str(reason or "") != "health_restart" and str(reason or "") != "health_refresh":
            self._update_awg_ipv4_state()
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _stop_awg_core(self, epoch):
        """StopCore for the AWG start identified by `epoch`; a newer start is left alone.
        On the UI thread it runs on a daemon thread (StopCore waits for any StartCore)."""
        def _stop():
            try:
                if int(getattr(self, "_awg_epoch", 0) or 0) != int(epoch):
                    return
                self._awg_core.stop()
            except Exception:
                pass

        if _gp_is_ui_thread():
            try:
                threading.Thread(target=_stop, daemon=True).start()
                return
            except Exception:
                pass
        _stop()

    def _ensure_awg_config_then_connect(self):
        if str(self._awg_conf_content or "").strip():
            self._ensure_awg_core_then(self._awg_connect)
            return
        self._download_free_awg_config()

    def _switch_to_awg_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("awg"):
            return
        self._native_start_guard_release()
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

    # ---- IPv4-only mode for configs without an IPv6 address ----

    @staticmethod
    def _awg_conf_has_ipv6(conf_text):
        section = ""
        for raw in str(conf_text or "").splitlines():
            line = str(raw or "").strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            if section != "interface" or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() == "address" and ":" in value:
                return True
        return False

    def _update_awg_ipv4_state(self):
        try:
            conf = str(getattr(self, "_awg_started_conf", "") or self._awg_conf_content or "")
            want = bool(
                self._awg_running
                and self._should_run_awg()
                and conf.strip()
                and not self._awg_conf_has_ipv6(conf)
            )
            old = bool(getattr(self, "_awg_ipv4_only", False))
            self._awg_ipv4_only = want
            if want:
                self._install_ipv6_hook()
                self._force_ipv4_strategy()
            if want != old:
                self._check_all_connections()
        except Exception:
            pass

    # ---- health check ----

    def _on_awg_connected(self):
        try:
            self._update_awg_ipv4_state()
        except Exception:
            pass
        try:
            self._start_awg_health_loop()
        except Exception:
            pass

    def _start_awg_health_loop(self):
        try:
            thread = self._awg_health_thread
            if thread is not None and thread.is_alive() and not self._awg_health_stop.is_set():
                return
            self._awg_health_gen = int(self._awg_health_gen or 0) + 1
            gen = int(self._awg_health_gen)
            stop = threading.Event()
            self._awg_health_stop = stop
            thread = threading.Thread(target=self._awg_health_loop, args=(gen, stop), daemon=True)
            self._awg_health_thread = thread
            thread.start()
        except Exception:
            pass

    def _stop_awg_health_loop(self):
        try:
            self._awg_health_gen = int(self._awg_health_gen or 0) + 1
            self._awg_health_stop.set()
            self._awg_health_thread = None
        except Exception:
            pass

    def _awg_network_online(self):
        try:
            return bool(ApplicationLoader.isNetworkOnline())
        except Exception:
            return True

    def _awg_probe_once(self):
        def _recv_exact(sock, count):
            data = b""
            while len(data) < count:
                chunk = sock.recv(count - len(data))
                if not chunk:
                    break
                data += chunk
            return data

        port = int(self._awg_port or AWG_LOCAL_PORT)
        for host, dport in (("149.154.167.50", 443), ("149.154.175.50", 443)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(10.0)
                    sock.connect((VLESS_LOCAL_HOST, port))
                    sock.sendall(b"\x05\x01\x00")
                    if _recv_exact(sock, 2) != b"\x05\x00":
                        continue
                    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + int(dport).to_bytes(2, "big"))
                    head = _recv_exact(sock, 4)
                    if len(head) == 4 and head[0] == 5 and head[1] == 0:
                        return True
            except Exception:
                pass
        return False

    def _awg_health_loop(self, gen, stop):
        fails = 0
        stop.wait(5)
        while (not stop.is_set()) and self._active and gen == int(self._awg_health_gen or 0):
            delay = 60.0
            try:
                if (
                    (not self._should_run_awg())
                    or bool(self._awg_connecting)
                    or (not self._awg_running)
                    or bool(self._awg_health_recovering)
                    or self._is_proxy_policy_suspended()
                    or (not self._awg_network_online())
                ):
                    fails = 0
                elif self._awg_probe_once():
                    fails = 0
                    self._awg_health_restarts = 0
                    self._awg_refresh_failures = 0
                elif not self._awg_network_online():
                    fails = 0
                else:
                    fails += 1
                    delay = 15.0
                    if fails >= 3:
                        fails = 0
                        if not stop.is_set() and gen == int(self._awg_health_gen or 0):
                            self._awg_health_recover()
                        delay = 20.0
            except Exception:
                pass
            stop.wait(delay)

    def _awg_reconnect_async(self):
        try:
            if self._should_run_awg():
                self._ensure_awg_core_then(self._awg_connect)
        except Exception:
            pass

    def _awg_free_source(self):
        try:
            value = str(self.get_setting("awg_free_source", "warp") or "warp").strip().lower()
        except Exception:
            value = "warp"
        return value if value in ("vpgram", "warp") else "warp"

    def _awg_free_source_index(self):
        return 0 if self._awg_free_source() == "warp" else 1

    def _on_awg_free_source_changed(self, index):
        try:
            source = "vpgram" if int(index) == 1 else "warp"
        except Exception:
            source = "warp"
        try:
            self._set_setting_value("awg_free_source", source, reload_settings=False)
        except Exception:
            try:
                self.set_setting("awg_free_source", source, reload_settings=False)
            except Exception:
                pass
        if bool(self._awg_conf_is_free):
            self._refresh_free_awg_config_from_settings(source=source)
        return True

    def _awg_download_and_wait(self, source=None):
        done = threading.Event()
        result = [False]

        def _cb(ok):
            result[0] = bool(ok)
            done.set()

        self._download_free_awg_config(refreshed=True, on_done=_cb, source=source)
        done.wait(30)
        return result[0]

    def _awg_health_recover(self):
        self._awg_health_recovering = True
        try:
            now = time.time()
            backoff = min(600.0 * (2 ** int(self._awg_refresh_failures or 0)), 3600.0)
            if bool(self._awg_conf_is_free) and now - float(self._awg_last_refresh_ts or 0.0) >= backoff:
                self._awg_last_refresh_ts = now
                self._awg_refresh_failures = int(self._awg_refresh_failures or 0) + 1
                self._awg_disconnect(silent=True, reason="health_refresh", stop_core=True)
                if not self._awg_download_and_wait():
                    self._awg_reconnect_async()
                return
            if int(self._awg_health_restarts or 0) < 1:
                self._awg_health_restarts = 1
                self._awg_disconnect(silent=True, reason="health_restart", stop_core=True)
                self._awg_reconnect_async()
                return
            self._awg_health_restarts = 0
            self._awg_health_hold_until = now + 600.0
            self._awg_disconnect(silent=True, reason="health_dead", stop_core=True)
            run_on_ui_thread(lambda: BulletinHelper.show_error("AWG сервер не отвечает"))
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        except Exception:
            pass
        finally:
            self._awg_health_recovering = False

    def _refresh_free_awg_config_from_settings(self, source=None):
        def _work():
            self._awg_health_recovering = True
            try:
                self._awg_last_refresh_ts = time.time()
                self._awg_health_hold_until = 0.0
                if self._awg_running or bool(getattr(self._awg_core, "started", False)):
                    self._awg_disconnect(silent=True, reason="health_refresh", stop_core=True)
                use_source = source if source is not None else self._awg_free_source()
                if use_source == "warp":
                    run_on_ui_thread(lambda: BulletinHelper.show_info("Регистрирую Cloudflare WARP..."))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_info("Скачиваю новый конфиг AWG..."))
                if not self._awg_download_and_wait(source=use_source):
                    self._awg_reconnect_async()
            except Exception:
                pass
            finally:
                self._awg_health_recovering = False

        threading.Thread(target=_work, daemon=True).start()
