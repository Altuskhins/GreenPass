from ..foundation import *
from ..protocols import *
from ..tgws import *
from ..native import *
from ..subscriptions import *
from ..hooks import *


class TgWsModeMixin:
    def _is_tgws_mode_selected(self):
        return self._get_connection_mode() == TGWS_KIND

    def _get_tgws_voip_relay_enabled(self):
        try:
            return bool(self.get_setting("tgws_voip_relay_enabled", True))
        except:
            return False

    def _set_tgws_voip_relay_enabled(self, enabled, reload_settings=True):
        self._set_setting_value("tgws_voip_relay_enabled", bool(enabled), reload_settings=bool(reload_settings))

    def _get_tgws_voip_relay_config(self):
        return _validate_tgws_voip_relay(
            self.get_setting("tgws_voip_relay_ip", TGWS_VOIP_RELAY_HOST),
            self.get_setting("tgws_voip_relay_port", str(TGWS_VOIP_RELAY_CONTROL_PORT)),
            self.get_setting("tgws_voip_relay_hmac", TGWS_VOIP_RELAY_SECRET.decode("utf-8")),
        )

    def _tgws_voip_relay_link(self):
        config, error = self._get_tgws_voip_relay_config()
        if config is None:
            return "", error
        relay_ip, relay_port, secret = config
        return "tg://relay?" + urllib.parse.urlencode({
            "ip": relay_ip,
            "port": relay_port,
            "h": secret,
        }), ""

    def _tgws_allocate_voip_relay(self, target_ip, target_port, timeout_sec=None):
        if not self._get_tgws_voip_relay_enabled() or not _is_telegram_reflector_ip(target_ip):
            return None
        try:
            config, _ = self._get_tgws_voip_relay_config()
            if config is None:
                return None
            relay_ip, relay_control_port, relay_secret = config
            relay_secret = relay_secret.encode("utf-8")
            target_port = int(target_port)
            if target_port <= 0 or target_port > 65535:
                return None
            nonce = os.urandom(16)

            def build_request(operation, request_nonce):
                body = bytearray((2, int(operation)))
                body.extend(struct.pack(">Q", int(time.time())))
                body.extend(request_nonce)
                body.extend(struct.pack(">IHH", _ipv4_to_int(target_ip), target_port, 0))
                body.extend(hmac.new(relay_secret, bytes(body), hashlib.sha256).digest())
                return bytes(body)

            def valid_response(data):
                return (
                    len(data) == 48
                    and data[0] == 2
                    and hmac.compare_digest(
                        data[16:],
                        hmac.new(relay_secret, data[:16], hashlib.sha256).digest(),
                    )
                )

            deadline = None if timeout_sec is None else time.monotonic() + max(0.05, float(timeout_sec))

            def receive_timeout():
                if deadline is None:
                    return float(TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC)
                return max(0.05, deadline - time.monotonic())

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((relay_ip, relay_control_port))
                sock.send(build_request(1, nonce))
                sock.settimeout(receive_timeout())
                challenge = sock.recv(128)
                if not valid_response(challenge) or challenge[1] != 9:
                    return None
                allocation_nonce = nonce[:8] + challenge[8:16]
                sock.send(build_request(2, allocation_nonce))
                sock.settimeout(receive_timeout())
                data = sock.recv(128)
            if not valid_response(data) or data[8:16] != nonce[:8]:
                return None
            relay_port = struct.unpack(">H", data[2:4])[0]
            if data[1] != 0 or relay_port <= 0:
                return None
            return relay_ip, relay_port
        except:
            return None

    def _tgws_allocate_voip_relays(self, targets, timeout_sec=TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC):
        targets = list(targets or [])
        if not targets:
            return []
        if time.monotonic() < float(getattr(self, "_tgws_voip_relay_retry_after", 0.0) or 0.0):
            return [None] * len(targets)
        deadline = time.monotonic() + max(0.05, float(timeout_sec))

        def allocate(target):
            return self._tgws_allocate_voip_relay(
                target[0], target[1], timeout_sec=max(0.05, deadline - time.monotonic())
            )

        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as executor:
            relays = list(executor.map(allocate, targets))
        self._tgws_voip_relay_retry_after = 0.0 if any(relays) else time.monotonic() + 20.0
        return relays

    def _is_tgws_connection_ready(self, port=None):
        try:
            expected_port = int(port or self._tgws_port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False
        return bool(
            self._is_local_tgws_proxy_applied(expected_port)
            and _check_vless_port(expected_port)
            and self._tgws_accept_thread_alive()
        )

    def _tgws_accept_thread_alive(self):
        try:
            return bool(self._tgws_core.is_healthy())
        except:
            return True

    def _tgws_heal_if_due(self):
        now = time.time()
        try:
            last = float(getattr(self, "_tgws_last_heal_ts", 0.0) or 0.0)
        except:
            last = 0.0
        if last and (now - last) < float(TGWS_HEAL_COOLDOWN_SEC):
            return False
        self._tgws_last_heal_ts = float(now)
        try:
            self._tgws_core.self_heal()
            return True
        except:
            return False

    def _tgws_local_alive(self):
        try:
            return bool(
                self._tgws_running and self._tgws_port and _check_vless_port(self._tgws_port)
                and self._tgws_accept_thread_alive()
            )
        except:
            return False

    def _tgws_unapply_local_proxy_for_background(self):
        self._tgws_ready = False
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0:
            try:
                owner, owner_port = self._local_socks_owner_snapshot()
                if owner == TGWS_KIND:
                    port = int(owner_port or 0)
            except:
                port = 0
        if port > 0:
            try:
                self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
            except:
                pass
        return True

    def _tgws_ensure_local_proxy(self):
        if not self._should_run_tgws():
            self._tgws_ready = False
            return False
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0 or not self._tgws_local_alive():
            self._tgws_ready = False
            if not bool(getattr(self, "_tgws_connecting", False)):
                self._tgws_connect()
            return False
        if not self._is_local_tgws_proxy_applied(port):
            if not self._apply_local_socks_proxy(port, True, owner=TGWS_KIND, secret=_tgws_proxy_secret_for_telegram()):
                self._tgws_ready = False
                if not bool(getattr(self, "_tgws_connecting", False)):
                    self._tgws_disconnect_with_reason("tgws_local_proxy_reapply_failed", silent=True)
                    self._tgws_connect()
                return False
        self._tgws_running = True
        self._tgws_ready = bool(self._is_tgws_connection_ready(port))
        return bool(self._tgws_ready)

    def _tgws_connect(self):
        if not self._should_run_tgws():
            self._tgws_ready = False
            return False
        if _gp_is_ui_thread():
            # Picking a port, starting the listener and the HTTP/2 runtime can take
            # seconds: never on the UI thread.
            try:
                threading.Thread(target=self._tgws_connect, daemon=True).start()
                return True
            except Exception:
                pass
        with self._tgws_connect_lock:
            if bool(getattr(self, "_tgws_connecting", False)):
                return False
            self._tgws_connecting = True
            try:
                self._tgws_generation = int(getattr(self, "_tgws_generation", 0) or 0) + 1
            except:
                self._tgws_generation = 1
            generation = int(self._tgws_generation or 0)
        handed_off = False
        try:
            try:
                self._vless_disconnect_with_reason("tgws_connect_preempt", silent=True)
            except:
                pass
            self._tgws_ready = False
            if not self._should_run_tgws():
                return False
            port = _pick_tgws_port(TGWS_LOCAL_PORT)
            if int(port or 0) <= 0:
                self._tgws_running = False
                self._tgws_ready = False
                self._tgws_port = 0
                return False
            self._tgws_port = port
            config_json = json.dumps({"port": int(port), "verbose": False, "dc_ip": dict(TGWS_DEFAULT_DC_IP)})
            err = self._tgws_core.start(config_json)
            if err:
                self._tgws_running = False
                self._tgws_ready = False
                self._tgws_port = 0
                return False

            def _watchdog():
                self._tgws_ready = False

                def _same_generation():
                    try:
                        return int(getattr(self, "_tgws_generation", 0) or 0) == int(generation)
                    except:
                        return False

                def _is_current():
                    try:
                        return bool(
                            _same_generation()
                            and self._should_run_tgws()
                            and int(self._tgws_port or 0) == int(port)
                        )
                    except:
                        return False

                deadline = time.time() + float(TGWS_LOCAL_READY_TIMEOUT_SEC)
                while time.time() < deadline:
                    if not _is_current():
                        if _same_generation():
                            self._tgws_running = False
                            self._tgws_ready = False
                            try:
                                self._tgws_core.stop()
                            except:
                                pass
                        return
                    if _check_vless_port(port):
                        if not _is_current():
                            if _same_generation():
                                self._tgws_ready = False
                            return
                        if self._is_local_tgws_proxy_applied(port):
                            applied = True
                        else:
                            applied = self._apply_local_socks_proxy(port, True, owner=TGWS_KIND, secret=_tgws_proxy_secret_for_telegram())
                        apply_deadline = time.time() + 1.5
                        while applied and time.time() < apply_deadline:
                            if not _is_current():
                                if _same_generation():
                                    self._tgws_ready = False
                                    self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
                                return
                            if self._is_local_tgws_proxy_applied(port):
                                break
                            time.sleep(0.1)
                        if not applied or (not self._is_local_tgws_proxy_applied(port)):
                            if _same_generation():
                                self._tgws_running = False
                                self._tgws_ready = False
                                self._tgws_port = 0
                                try:
                                    self._tgws_core.stop()
                                except:
                                    pass
                            return
                        if not _is_current():
                            if _same_generation():
                                self._tgws_ready = False
                                self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
                            return
                        self._tgws_running = True
                        self._tgws_ready = False
                        self._save_config()
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                        confirm_deadline = time.time() + float(TGWS_CONNECT_CONFIRM_TIMEOUT_SEC)
                        connected = False
                        while time.time() < confirm_deadline:
                            if not _is_current():
                                if _same_generation():
                                    self._tgws_ready = False
                                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                                return
                            if self._is_tgws_connection_ready(port):
                                connected = True
                                break
                            time.sleep(0.5)
                        if connected:
                            self._tgws_ready = True
                            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                            run_on_ui_thread(lambda: BulletinHelper.show_success("TG WS подключен"))
                        else:
                            self._tgws_ready = False
                            self._tgws_heal_if_due()
                            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                            run_on_ui_thread(lambda: BulletinHelper.show_info("TG WS: соединяю..."))
                        return
                    time.sleep(0.3)
                if _same_generation():
                    self._tgws_running = False
                    self._tgws_ready = False
                    self._tgws_port = 0
                    try:
                        self._tgws_core.stop()
                    except:
                        pass
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

            def _watchdog_wrapped():
                try:
                    _watchdog()
                finally:
                    changed = False
                    try:
                        if int(getattr(self, "_tgws_generation", 0) or 0) == int(generation):
                            changed = bool(getattr(self, "_tgws_connecting", False))
                            self._tgws_connecting = False
                    except:
                        changed = bool(getattr(self, "_tgws_connecting", False))
                        self._tgws_connecting = False
                    if changed:
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

            threading.Thread(target=_watchdog_wrapped, daemon=True).start()
            handed_off = True
            return True
        except Exception:
            self._tgws_running = False
            self._tgws_ready = False
            self._tgws_port = 0
            try:
                self._tgws_core.stop()
            except:
                pass
            return False
        finally:
            if not handed_off:
                self._tgws_connecting = False

    def _tgws_disconnect_with_reason(self, reason, silent=False):
        self._tgws_disconnect(silent=bool(silent))

    def _tgws_stop_core(self):
        """Stop the TG-WS server. On the UI thread only the non-blocking half runs there
        (listener and live bridges are closed); the joins and the HTTP/2 runtime teardown
        finish on a daemon thread, and are skipped if a newer start() superseded them."""
        core = self._tgws_core
        if _gp_is_ui_thread():
            try:
                token = core.request_stop()
                threading.Thread(target=lambda: core.finish_stop(token), daemon=True).start()
                return
            except Exception:
                pass
        try:
            core.stop()
        except:
            pass

    def _tgws_disconnect(self, silent=False):
        old_port = int(self._tgws_port or 0)
        try:
            self._tgws_generation = int(getattr(self, "_tgws_generation", 0) or 0) + 1
        except:
            self._tgws_generation = 1
        self._tgws_running = False
        self._tgws_ready = False
        self._tgws_port = 0
        self._tgws_connecting = False
        # Telegram's proxy first, then the server: Telegram never dials a dead port.
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=TGWS_KIND)
        self._tgws_stop_core()
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _switch_to_tgws_mode(self, persist_mode=True):
        if persist_mode:
            self._set_connection_mode(TGWS_KIND)
        self._vless_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        if self._is_plugin_proxy_enabled():
            self._tgws_connect()
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
