from ..foundation import *
from ..protocols import *
from ..tgws import *
from ..native import *
from ..subscriptions import *
from ..hooks import *


class SingBoxModeMixin:
    def _libvless_so_path(self):
        return self._libsingbox_so_path()

    def _libsingbox_so_path(self):
        try:
            return os.path.join(self._vless_dir, SINGBOX_SO_FILE)
        except:
            return SINGBOX_SO_FILE

    def _libsingbox_addon_status(self, quick=False):
        if not SINGBOX_BUNDLE_FILE:
            return "missing"
        try:
            path = self._libsingbox_so_path()
            if not path or not os.path.exists(path):
                return "missing"
            stat = os.stat(path)
            if int(stat.st_size) < 1024:
                return "missing"
            if int(stat.st_size) != int(SINGBOX_SO_SIZE):
                return "outdated"
            cache_key = (str(path), int(stat.st_size), int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000))))
            lock = getattr(self, "_libsingbox_validation_lock", None)
            if lock is None:
                lock = threading.Lock()
                self._libsingbox_validation_lock = lock
            with lock:
                cached = self._libsingbox_validation_cache
                if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
                    return "current" if cached[1] else "outdated"

            if quick:
                should_start = False
                try:
                    with lock:
                        if not bool(getattr(self, "_libsingbox_validation_in_progress", False)):
                            self._libsingbox_validation_in_progress = True
                            should_start = True
                except:
                    pass
                if should_start:
                    def _validate_in_background():
                        status = "missing"
                        try:
                            status = self._libsingbox_addon_status()
                        finally:
                            try:
                                with lock:
                                    self._libsingbox_validation_in_progress = False
                            except:
                                pass
                            try:
                                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                            except:
                                pass
                        if status in ("missing", "outdated") and self._core_autoupdate_enabled():
                            try:
                                self._update_outdated_core_in_background()
                            except:
                                pass
                    threading.Thread(target=_validate_in_background, daemon=True).start()
                return "checking"

            with lock:
                cached = self._libsingbox_validation_cache
                if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
                    return "current" if cached[1] else "outdated"
                digest, size = self._sha256_file(path, max_bytes=int(SINGBOX_SO_SIZE))
                valid = bool(size == int(SINGBOX_SO_SIZE) and digest == SINGBOX_SO_SHA256)
                self._libsingbox_validation_cache = (cache_key, valid)
                return "current" if valid else "outdated"
        except:
            return "missing"

    def _has_libsingbox_addon(self):
        return self._libsingbox_addon_status() != "missing"

    def _vless_disconnect_with_reason(self, reason, silent=False):
        self._vless_disconnect(silent=bool(silent))

    def _vless_engine_index(self):
        return 1 if self._effective_vless_engine() == VLESS_ENGINE_MIHOMO else 0

    def _vless_auto_subscription_nodes(self, uri=None):
        node = self._find_vless_node(uri if uri is not None else self._get_active_vless_uri())
        hidden = self._vless_browser_hidden_sources()
        nodes = [
            item for item in list((node or {}).get("balance_nodes", []) or [])
            if isinstance(item, dict) and self._vless_browser_source_key(item) not in hidden
        ]
        # ExitFy exposes failover as an explicit opt-in.  Keep the automatic
        # route deterministic when it is disabled instead of silently
        # rotating through every subscription node.
        if not self._vless_browser_failover_enabled() and nodes:
            return nodes[:1]
        return nodes

    def _vless_ping_value(self, node):
        try:
            return int(node.get("ping", -1) or 0)
        except:
            return -1

    def _vless_ping_checked_at(self, node):
        try:
            return float(node.get("ping_checked_at", 0.0) or 0.0)
        except:
            return 0.0

    def _vless_ping_badge(self, node):
        ping = self._vless_ping_value(node)
        checked_at = self._vless_ping_checked_at(node)
        if checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC):
            return ""
        if ping <= 0 or ping >= 9999:
            return "нет"
        return f"{int(ping)} ms"

    def _vless_sort_key(self, node):
        checked_at = self._vless_ping_checked_at(node)
        ping = self._vless_ping_value(node)
        stale = checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC)
        if stale or ping < 0:
            rank = 2
            score = 999999
        elif ping <= 0 or ping >= 9999:
            rank = 1
            score = 999998
        else:
            rank = 0
            score = int(ping)
        try:
            name = str(node.get("name", "") or "").strip().lower()
        except:
            name = ""
        return (rank, score, name)

    # ExitFy-style server browser primitives.  Keep the browser state in the
    # plugin settings instead of the node records so subscription refreshes do
    # not accidentally reset the user's filters/visibility choices.
    def _vless_browser_page_size(self):
        try:
            value = int(self.get_setting("vless_browser_page_size", 20) or 20)
        except:
            value = 20
        return max(5, min(100, value))

    def _set_vless_browser_page_size(self, value):
        try:
            value = int(value)
        except:
            value = 20
        value = max(5, min(100, value))
        try:
            self._set_setting_value("vless_browser_page_size", value, reload_settings=False)
        except:
            try:
                self.set_setting("vless_browser_page_size", value, reload_settings=False)
            except:
                return False
        return value

    def _vless_browser_auto_check_minutes(self):
        """Return periodic latency-check interval; zero means disabled."""
        try:
            value = int(self.get_setting("vless_auto_check_minutes", 0) or 0)
        except:
            value = 0
        return max(0, min(60, value))

    def _set_vless_browser_auto_check_minutes(self, value):
        try:
            value = int(value)
        except:
            value = 0
        value = max(0, min(60, value))
        try:
            self._set_setting_value("vless_auto_check_minutes", value, reload_settings=False)
        except:
            try:
                self.set_setting("vless_auto_check_minutes", value, reload_settings=False)
            except:
                return False
        return value

    def _vless_browser_failover_enabled(self):
        try:
            raw = self.get_setting("vless_failover_enabled", True)
            if isinstance(raw, str):
                return raw.strip().lower() not in ("", "0", "false", "off", "no")
            return bool(raw)
        except:
            return True

    def _set_vless_browser_failover_enabled(self, enabled):
        value = bool(enabled)
        try:
            self._set_setting_value("vless_failover_enabled", value, reload_settings=False)
        except:
            try:
                self.set_setting("vless_failover_enabled", value, reload_settings=False)
            except:
                return False
        return value

    def _vless_browser_hidden_sources(self):
        """Read hidden source keys as a tolerant set (old clients may return JSON)."""
        try:
            raw = self.get_setting("vless_browser_hidden_sources", "[]")
        except:
            raw = "[]"
        if isinstance(raw, (list, tuple, set)):
            values = raw
        else:
            try:
                values = json.loads(str(raw or "[]"))
            except:
                values = []
        return {str(item or "").strip() for item in list(values or []) if str(item or "").strip()}

    def _set_vless_browser_hidden_sources(self, sources):
        values = sorted({str(item or "").strip() for item in list(sources or []) if str(item or "").strip()})
        payload = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
        try:
            self._set_setting_value("vless_browser_hidden_sources", payload, reload_settings=False)
        except:
            try:
                self.set_setting("vless_browser_hidden_sources", payload, reload_settings=False)
            except:
                return False
        return values

    def _vless_browser_source_for_node(self, node):
        """Return stable source metadata for a node, including manual nodes."""
        node = node if isinstance(node, dict) else {}
        uri = str(node.get("uri", "") or "").strip()
        explicit_url = str(
            node.get("subscription_url", "")
            or node.get("source_url", "")
            or node.get("provider_url", "")
            or ""
        ).strip()
        if explicit_url:
            try:
                source = self._vless_browser_source_index().get("\x00" + explicit_url)
                if source:
                    return dict(source)
            except:
                pass
        # Subscription ownership is queried for every row while building the
        # settings page. Resolve it once per config snapshot; the old nested
        # scan made opening a large subscription quadratic and blocked the UI.
        if uri:
            try:
                source = self._vless_browser_source_index().get(uri)
                if source:
                    return dict(source)
            except:
                pass
        # Balancer wrappers often carry no source metadata themselves; inherit
        # the first concrete subscription source from their children.
        try:
            for child in list(node.get("balance_nodes", []) or []):
                if not isinstance(child, dict):
                    continue
                child_source = self._vless_browser_source_for_node(child)
                if not bool(child_source.get("manual", False)) and str(child_source.get("key", "") or ""):
                    return child_source
        except:
            pass
        source_name = str(node.get("source_name", "") or node.get("provider", "") or "").strip()
        source_url = explicit_url or str(node.get("source", "") or "").strip()
        if source_name or source_url:
            key = source_url or source_name
            return {"key": key, "name": source_name or source_url, "url": source_url, "manual": False}
        return {"key": "__manual__", "name": "Свои узлы", "url": "", "manual": True}

    def _vless_browser_source_index(self):
        """Map node URIs to their subscription without repeated nested scans."""
        data = getattr(self, "_vless_data", None)
        cached = getattr(self, "_vless_browser_source_index_cache", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is data:
            return cached[1]

        index = {}

        def _walk(node, source):
            if not isinstance(node, dict):
                return
            uri = str(node.get("uri", "") or "").strip()
            if uri and uri not in index:
                index[uri] = source
            for child in list(node.get("balance_nodes", []) or []):
                _walk(child, source)

        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                url = str(sub.get("url", "") or "").strip()
                if not url:
                    continue
                source = {
                    "key": url,
                    "name": str(sub.get("name", "") or "").strip() or url,
                    "url": url,
                    "manual": False,
                }
                index["\x00" + url] = source
                for node in list(sub.get("nodes", []) or []):
                    _walk(node, source)
        except:
            pass
        self._vless_browser_source_index_cache = (data, index)
        return index

    def _vless_browser_source_key(self, node):
        try:
            return str(self._vless_browser_source_for_node(node).get("key", "") or "")
        except:
            return "__manual__"

    def _vless_browser_leaf_nodes(self, node):
        """Yield endpoint leaves so balancer wrappers do not hide their count."""
        if not isinstance(node, dict):
            return
        children = [item for item in list(node.get("balance_nodes", []) or []) if isinstance(item, dict)]
        if not children:
            yield node
            return
        for child in children:
            yield from self._vless_browser_leaf_nodes(child)

    def _vless_browser_sources(self, include_hidden=True):
        """Return source rows suitable for a provider filter/visibility screen."""
        rows = {}
        for root in self._get_all_vless_nodes():
            for node in self._vless_browser_leaf_nodes(root):
                source = self._vless_browser_source_for_node(node)
                key = str(source.get("key", "") or "")
                if not key:
                    continue
                row = rows.get(key)
                if row is None:
                    row = dict(source)
                    row["count"] = 0
                    rows[key] = row
                row["count"] = int(row.get("count", 0) or 0) + 1
        hidden = self._vless_browser_hidden_sources()
        result = []
        for row in rows.values():
            row["hidden"] = str(row.get("key", "") or "") in hidden
            if include_hidden or not row["hidden"]:
                result.append(row)
        result.sort(key=lambda item: (str(item.get("name", "") or "").lower(), str(item.get("key", "") or "")))
        return result

    def _vless_set_browser_source_visible(self, source_key, visible):
        key = str(source_key or "").strip()
        if not key:
            return False
        hidden = self._vless_browser_hidden_sources()
        if bool(visible):
            hidden.discard(key)
        else:
            hidden.add(key)
        self._set_vless_browser_hidden_sources(hidden)
        return True

    def _vless_browser_protocol(self, node):
        node = node if isinstance(node, dict) else {}
        kind = str(node.get("kind", "") or "").strip().lower()
        if not kind:
            try:
                kind = str(_proxy_uri_scheme(node.get("uri", "")) or "").lower()
            except:
                kind = ""
        aliases = {
            "shadowsocks": "ss",
            "hysteria": "hysteria2",
            "singbox-config": "sing-box",
            "mihomo-config": "mihomo",
        }
        return aliases.get(kind, kind or "unknown")

    def _vless_browser_normalize_protocol(self, value):
        value = str(value or "").strip().lower().replace("_", "-")
        aliases = {
            "shadowsocks": "ss",
            "hysteria": "hysteria2",
            "hysteria-2": "hysteria2",
            "singbox": "sing-box",
            "sing-box-config": "sing-box",
            "mihomo-config": "mihomo",
        }
        return aliases.get(value, value)

    def _vless_browser_filter_nodes(self, query="", protocol="", source="", include_hidden=False):
        query = str(query or "").strip().lower()
        protocol = self._vless_browser_normalize_protocol(protocol)
        source = str(source or "").strip()
        hidden = self._vless_browser_hidden_sources()
        cache_key = (
            id(getattr(self, "_vless_data", None)),
            query,
            protocol,
            source,
            bool(include_hidden),
            tuple(sorted(hidden)),
        )
        cached = getattr(self, "_vless_browser_filter_cache", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
            return list(cached[1])
        result = []
        seen = set()
        for node in self._get_all_vless_nodes():
            if not isinstance(node, dict):
                continue
            uri = str(node.get("uri", "") or "").strip()
            dedup = _proxy_uri_dedup_key(uri) or uri
            if not dedup or dedup in seen:
                continue
            seen.add(dedup)
            source_row = self._vless_browser_source_for_node(node)
            source_key = str(source_row.get("key", "") or "")
            if source and source_key != source:
                continue
            if (not include_hidden) and source_key in hidden:
                continue
            node_protocol = self._vless_browser_protocol(node)
            if protocol and node_protocol != protocol:
                continue
            if query:
                haystack = " ".join(
                    str(node.get(name, "") or "")
                    for name in ("name", "server", "uri", "network", "security", "method")
                )
                haystack += " " + str(source_row.get("name", "") or "") + " " + node_protocol
                if query not in haystack.lower():
                    continue
            result.append(node)
        result = self._sorted_vless_nodes(result)
        self._vless_browser_filter_cache = (cache_key, list(result))
        return result

    def _vless_browser_snapshot(self, query="", protocol="", source="", page=0, page_size=None, include_hidden=False):
        """Return one deterministic page and metadata for the ExitFy-like browser."""
        nodes = self._vless_browser_filter_nodes(query, protocol, source, include_hidden=include_hidden)
        try:
            size = int(page_size or self._vless_browser_page_size())
        except:
            size = self._vless_browser_page_size()
        size = max(5, min(100, size))
        try:
            page = max(0, int(page or 0))
        except:
            page = 0
        total = len(nodes)
        pages = (total + size - 1) // size if total else 0
        if not pages:
            page = 0
        elif page >= pages:
            page = pages - 1
        start = page * size
        return {
            "nodes": nodes[start:start + size],
            "total": total,
            "page": page,
            "page_size": size,
            "pages": pages,
            "has_previous": bool(page > 0),
            "has_next": bool(start + size < total),
            "query": str(query or ""),
            "protocol": str(protocol or ""),
            "source": str(source or ""),
        }

    def _vless_browser_ping_interval_sec(self):
        minutes = self._vless_browser_auto_check_minutes()
        return float(minutes * 60) if minutes > 0 else 0.0

    def _maybe_run_vless_auto_ping(self, now=None):
        """Schedule one quiet periodic check; never block the worker loop."""
        interval = self._vless_browser_ping_interval_sec()
        if interval <= 0 or bool(getattr(self, "_vless_backgrounded", False)):
            return False
        try:
            if not self._is_vless_mode_selected() or not self._is_plugin_proxy_enabled():
                return False
        except:
            return False
        try:
            now = float(time.time() if now is None else now)
        except:
            now = time.time()
        lock = getattr(self, "_vless_transition_lock", None)
        try:
            if lock is None:
                return False
            with lock:
                last = float(getattr(self, "_vless_auto_ping_last_ts", 0.0) or 0.0)
                if bool(getattr(self, "_vless_auto_ping_in_progress", False)) or now - last < interval:
                    return False
                self._vless_auto_ping_last_ts = now
                self._vless_auto_ping_in_progress = True
        except:
            return False

        def _worker():
            try:
                self._refresh_vless_node_pings(force=True, save=True)
            except:
                pass
            finally:
                try:
                    with lock:
                        self._vless_auto_ping_in_progress = False
                except:
                    pass
                try:
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
                except:
                    pass

        try:
            threading.Thread(target=_worker, daemon=True).start()
            return True
        except:
            try:
                with lock:
                    self._vless_auto_ping_in_progress = False
            except:
                pass
            return False

    def _is_vless_mode_selected(self):
        return self._get_connection_mode() == VLESS_KIND and bool(self._get_active_vless_uri())

    def _vless_save_data(self):
        try:
            self._vless_data["active_uri"] = str(self._vless_data.get("active_uri", "") or "")
        except:
            self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._vless_browser_source_index_cache = None
        self._vless_browser_filter_cache = None
        self._save_config()

    def _vless_provider_name(self, idx):
        try:
            provider_idx = int(idx or 0)
        except:
            provider_idx = 0
        if provider_idx == 0:
            return "Текущий"
        if provider_idx < 0 or provider_idx >= len(VLESS_PROVIDER_ITEMS):
            provider_idx = 0
        try:
            return str(VLESS_PROVIDER_ITEMS[provider_idx] or "")
        except:
            return ""

    def _vless_apply_tg_proxy(self, port, enable, username="", password=""):
        result = self._apply_local_socks_proxy(
            port,
            enable,
            owner=str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND),
            username=username,
            password=password,
        )
        return result

    def _vless_runtime_config_key(self, uri=None, node=None, auto_nodes=None):
        engine_prefix = self._effective_vless_engine(node if isinstance(node, dict) else None) + ":"
        try:
            nodes = list(auto_nodes or [])
        except:
            nodes = []
        if len(nodes) > 1:
            values = []
            seen = set()
            for candidate in nodes:
                if not isinstance(candidate, dict):
                    continue
                try:
                    kind = str(candidate.get("kind", "") or "").strip().lower()
                    if kind == "singbox-config":
                        value = str(candidate.get("raw_config", "") or "")
                    else:
                        value = str(candidate.get("uri", "") or "")
                    key = _proxy_uri_dedup_key(value) or value
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    values.append(kind + ":" + value)
                except:
                    continue
            if len(values) > 1:
                try:
                    return engine_prefix + "auto:" + hashlib.sha256("\n".join(values).encode("utf-8", errors="ignore")).hexdigest()
                except:
                    return engine_prefix + "auto:" + "|".join(values)
        try:
            node = node if isinstance(node, dict) else None
            kind = str((node or {}).get("kind", "") or "").strip().lower()
            if kind == "singbox-config":
                raw = str((node or {}).get("raw_config", "") or "")
                if raw:
                    return "singbox-config:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
            if kind == "mihomo-config":
                raw = str((node or {}).get("raw_config", "") or "")
                if raw:
                    return "mihomo-config:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
        except:
            pass
        try:
            value = str(uri if uri is not None else self._get_active_vless_uri() or "")
        except:
            value = ""
        value = _proxy_uri_dedup_key(value) or value
        if not value:
            return ""
        try:
            return engine_prefix + "uri:" + hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
        except:
            return value

    def _is_vless_connection_ready(self, port=None, check_tunnel=False):
        try:
            expected_port = int(port or self._vless_port or 0)
        except:
            expected_port = 0
        if expected_port <= 0 or not bool(self._vless_running):
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(expected_port, timeout=0.5, username=username, password=password):
            return False
        if not self._is_local_vless_proxy_applied(expected_port):
            return False
        if bool(check_tunnel) and not _check_vless_tunnel_ready(expected_port, timeout=1.0, username=username, password=password):
            return False
        return True

    def _vless_balancer_nodes(self):
        groups = []
        hidden = self._vless_browser_hidden_sources()
        for sub in list(self._vless_data.get("subs", []) or []):
            sub_url = str((sub or {}).get("url", "") or "").strip()
            if sub_url and sub_url in hidden:
                continue
            group = []
            for node in list((sub or {}).get("nodes", []) or []):
                children = list((node or {}).get("balance_nodes", []) or [])
                for candidate in (children or [node]):
                    if self._vless_browser_source_key(candidate) not in hidden:
                        group.append(candidate)
            if self._vless_browser_failover_enabled():
                group = self._sorted_vless_nodes(group)
            if group:
                groups.append(group)

        selected = []
        seen = set()
        while groups and len(selected) < VLESS_BALANCER_MAX_NODES:
            remaining = []
            for group in groups:
                node = group.pop(0)
                if group:
                    remaining.append(group)
                uri = str((node or {}).get("uri", "") or "")
                key = _proxy_uri_dedup_key(uri) or uri
                if _proxy_uri_scheme(uri) not in PROXY_PROTOCOL_REGISTRY or not key or key in seen:
                    continue
                seen.add(key)
                selected.append(node)
                if len(selected) >= VLESS_BALANCER_MAX_NODES:
                    break
            groups = remaining
        return selected

    def _set_vless_connection_state(self, connecting=False, error=""):
        connecting = bool(connecting)
        error = str(error or "").strip()
        changed = connecting != bool(getattr(self, "_vless_connecting", False)) or error != str(getattr(self, "_vless_last_error", "") or "")
        self._vless_connecting = connecting
        self._vless_last_error = error
        if changed:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _ensure_vless_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_vless_mode = runner_name == "_vless_connect"
        if require_vless_mode and (not self._should_run_vless()):
            return
        if self._go_core_switch_blocked("vless"):
            if require_vless_mode:
                self._set_vless_connection_state(False, "Перезапустите приложение для смены ядра")
            return
        self._vless_core._ensure()
        if self._vless_core.is_available():
            if require_vless_mode and (not self._should_run_vless()):
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._vless_prepare_in_progress:
            return

        self._set_core_download_in_progress(True)
        BulletinHelper.show_info("Скачиваю ядро прокси...")

        def _worker():
            try:
                ok = self._download_libvless_with_progress()
                if ok and self._core_restart_required():
                    if require_vless_mode:
                        self._set_vless_connection_state(False, "Перезапустите приложение для нового ядра")
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    return
                self._reload_vless_core()
                self._vless_core._ensure()
                if ok and self._vless_core.is_available():
                    if require_vless_mode and (not self._should_run_vless()):
                        return
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро прокси готово"))
                    try:
                        runner()
                    except Exception as e:
                        error_text = f"Ошибка прокси: {e}"
                        if require_vless_mode:
                            self._set_vless_connection_state(False, error_text)
                        else:
                            run_on_ui_thread(lambda text=error_text: BulletinHelper.show_error(text))
                else:
                    if require_vless_mode:
                        self._set_vless_connection_state(False, "Не удалось загрузить ядро прокси")
                    else:
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро прокси"))
            finally:
                self._set_core_download_in_progress(False)

        threading.Thread(target=_worker, daemon=True).start()

    def _add_vless_manual_node(self, uri):
        node = _proxy_node_from_uri(uri)
        if not node:
            return None
        return self._save_vless_manual_node(node)

    def _vless_connect(self):
        with self._vless_connect_lock:
            if bool(self._vless_connect_worker_active):
                self._vless_connect_pending = True
                return True
            self._vless_connect_worker_active = True
            self._vless_connect_pending = False

        def _worker():
            try:
                while True:
                    with self._vless_connect_lock:
                        self._vless_connect_pending = False
                    self._vless_connect_once()
                    with self._vless_connect_lock:
                        if bool(self._vless_connect_pending) and self._should_run_vless():
                            continue
                        self._vless_connect_worker_active = False
                        return
            except Exception as exc:
                with self._vless_connect_lock:
                    self._vless_connect_worker_active = False
                self._set_vless_connection_state(False, f"Ошибка подключения: {exc}")

        try:
            threading.Thread(target=_worker, daemon=True).start()
            return True
        except:
            with self._vless_connect_lock:
                self._vless_connect_worker_active = False
            self._set_vless_connection_state(False, "Не удалось запустить подключение")
            return False

    def _vless_connect_once(self):
        if not self._should_run_vless():
            return False
        if self._repair_active_vless_subscription_uri():
            self._vless_save_data()
        uri = self._get_active_vless_uri()
        scheme = _proxy_uri_scheme(uri)
        current_node = self._current_vless_node()
        mode_title = _proxy_protocol_label(current_node or scheme)
        qwdtt_mode = str((current_node or {}).get("kind", "") or "").strip().lower() == QWDTT_KIND
        if qwdtt_mode:
            mode_title = "qWDTT"
        if not uri or not current_node:
            self._set_vless_connection_state(False, "Нет выбранного узла")
            return False
        try:
            if str((current_node or {}).get("kind", "") or "").strip().lower() == "singbox-config":
                mode_title = "sing-box config"
        except:
            pass
        try:
            is_file_config = str((current_node or {}).get("kind", "") or "").strip().lower() == "singbox-config"
        except:
            is_file_config = False
        try:
            is_mihomo_config = str((current_node or {}).get("kind", "") or "").strip().lower() == "mihomo-config"
        except:
            is_mihomo_config = False
        use_sb = _is_singbox_core(self._vless_core)
        active_engine = self._effective_vless_engine(current_node)
        mihomo_mode = active_engine == VLESS_ENGINE_MIHOMO
        if mihomo_mode:
            mode_title = "Mihomo"
        auto_nodes = self._vless_auto_subscription_nodes(uri) if use_sb and not is_file_config and not is_mihomo_config and not qwdtt_mode else []
        resume_reconnect = bool(getattr(self, "_vless_resume_reconnect", False))
        self._vless_resume_reconnect = False
        target_config_key = self._vless_runtime_config_key(uri, current_node, auto_nodes=auto_nodes)
        if self._reuse_running_vless_if_ready(target_config_key):
            self._set_vless_connection_state(False, "")
            return True

        self._vless_disconnect(silent=True, cancel_pending=False)
        self._set_vless_connection_state(True, "")
        try:
            self._vless_core.lib
        except Exception as _le:
            pass
        if not self._vless_core.is_available():
            self._vless_running = False
            self._vless_port = 0
            self._delay_vless_retry()
            self._set_vless_connection_state(False, "Ядро прокси не загружено")
            return False
        port = int(self._pick_vless_runtime_port() or 0)
        if port <= 0:
            self._vless_running = False
            self._vless_port = 0
            self._delay_vless_retry()
            self._set_vless_connection_state(False, "Нет свободного локального порта")
            return False
        username = "" if qwdtt_mode else "greenpass"
        password = "" if qwdtt_mode else str(self._vless_socks_password or "")
        with self._vless_transition_lock:
            if not self._should_run_vless():
                return False
            generation = self._next_vless_generation()
            self._vless_port = int(port)
            self._vless_socks_username = username
            if not qwdtt_mode:
                self._vless_socks_password = password
            self._vless_local_owner = VLESS_KIND
        if qwdtt_mode:
            single_config = _qwdtt_core_config((current_node or {}).get("qwdtt", {}), port)
        elif is_mihomo_config:
            try:
                single_config = _build_mihomo_core_config(
                    config_text=str((current_node or {}).get("raw_config", "") or ""),
                    local_port=port,
                    work_dir=os.path.join(self._vless_dir, "mihomo"),
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
        elif is_file_config:
            if not use_sb:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, "Нужно ядро прокси")
                return False
            try:
                single_config = _prepare_singbox_file_config(
                    str((current_node or {}).get("raw_config", "") or ""),
                    port,
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
        elif mihomo_mode:
            links = [
                str(node.get("uri", "") or "")
                for node in (auto_nodes or [current_node])
                if isinstance(node, dict) and _is_proxy_uri(node.get("uri", ""))
            ]
            try:
                single_config = _build_mihomo_core_config(
                    links=links,
                    local_port=port,
                    work_dir=os.path.join(self._vless_dir, "mihomo"),
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
            if len(links) > 1:
                mode_title = "Mihomo Auto"
        elif use_sb:
            single_config = None
            if auto_nodes:
                if len(auto_nodes) > 1:
                    single_config = _build_singbox_balanced_config(
                        auto_nodes,
                        port,
                        socks_username=username,
                        socks_password=password,
                    )
                else:
                    single_config, _ = _build_registered_proxy_config(
                        str(auto_nodes[0].get("uri", "") or ""),
                        port,
                        socks_username=username,
                        socks_password=password,
                    )
                if single_config:
                    mode_title = "VLESS Auto"
            if not single_config:
                single_config, _ = _build_registered_proxy_config(
                    uri,
                    port,
                    socks_username=username,
                    socks_password=password,
                )
        else:
            single_config, _ = _build_vless_config(
                uri,
                port,
                socks_username=username,
                socks_password=password,
            )
        if not single_config:
            self._abort_vless_generation(generation, port)
            self._set_vless_connection_state(False, "Не удалось разобрать ссылку")
            return False
        if use_sb and not qwdtt_mode and not mihomo_mode:
            try:
                runtime_config = json.loads(single_config)
                log_config = runtime_config.get("log")
                log_config = dict(log_config) if isinstance(log_config, dict) else {}
                log_config.update({"disabled": False, "level": "info"})
                runtime_config["log"] = log_config
                experimental = runtime_config.get("experimental")
                experimental = dict(experimental) if isinstance(experimental, dict) else {}
                cache_file = experimental.get("cache_file")
                cache_file = dict(cache_file) if isinstance(cache_file, dict) else {}
                cache_file["path"] = os.path.join(self._vless_dir, "singbox-cache.db")
                experimental["cache_file"] = cache_file
                runtime_config["experimental"] = experimental
                single_config = json.dumps(runtime_config)
            except Exception as exc:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, f"Ошибка конфига sing-box: {exc}")
                return False
        if use_sb and not qwdtt_mode:
            validation_error = self._validate_core_config_for_import(single_config, mode_title)
            if validation_error:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, validation_error)
                return False
        config_json = single_config

        if qwdtt_mode:
            with self._vless_transition_lock:
                if not self._same_vless_generation(generation) or not self._should_run_vless() or int(self._vless_port or 0) != int(port):
                    return False
            err = self._vless_core.start(config_json)
            with self._vless_transition_lock:
                still_current = bool(self._same_vless_generation(generation) and self._should_run_vless() and int(self._vless_port or 0) == int(port))
            if not still_current:
                try:
                    if self._vless_core.current_engine() == QWDTT_KIND:
                        self._vless_core.stop()
                except:
                    pass
                return False
        else:
            with self._vless_transition_lock:
                if not self._same_vless_generation(generation) or not self._should_run_vless() or int(self._vless_port or 0) != int(port):
                    return False
                err = self._vless_core.start(config_json)
        bind_error = str(err or "").lower()
        if err and ("address already in use" in bind_error or "eaddrinuse" in bind_error):
            if self._abort_vless_generation(generation, port):
                self._vless_avoid_preferred_port_once = True
                with self._vless_connect_lock:
                    self._vless_connect_pending = True
                self._set_vless_connection_state(True, "")
            return False
        if err:
            self._abort_vless_generation(generation, port)
            self._set_vless_connection_state(False, f"Ошибка ядра прокси: {err}")
            return False

        def _watchdog():
            ready_timeout = float(VLESS_LOCAL_READY_TIMEOUT_SEC)
            if resume_reconnect and uri == VLESS_AUTO_SUBSCRIPTIONS_URI:
                ready_timeout = max(ready_timeout, float(VLESS_RESUME_AUTO_READY_TIMEOUT_SEC))
            deadline = time.time() + ready_timeout
            local_ready = False
            while time.time() < deadline:
                if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port) or not self._should_run_vless():
                    return
                if _check_vless_port(port) and _check_vless_socks_ready(port, timeout=0.5, username=username, password=password):
                    local_ready = True
                    allow_waking_auto = resume_reconnect and uri == VLESS_AUTO_SUBSCRIPTIONS_URI
                    if (not qwdtt_mode) and (not allow_waking_auto) and not _check_vless_tunnel_ready(port, timeout=1.5, username=username, password=password):
                        time.sleep(0.3)
                        continue
                    with self._vless_transition_lock:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port) or not self._should_run_vless():
                            return
                        applied = self._vless_apply_tg_proxy(port, True, username=username, password=password)
                    apply_deadline = time.time() + 1.5
                    while applied and time.time() < apply_deadline:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port):
                            return
                        if self._is_local_vless_proxy_applied(port):
                            break
                        time.sleep(0.1)
                    if not applied or (not self._is_local_vless_proxy_applied(port)):
                        if not self._abort_vless_generation(generation, port):
                            return
                        self._set_vless_connection_state(False, "Локальный прокси не применился")
                        return
                    with self._vless_transition_lock:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port):
                            return
                        self._vless_running = True
                        self._vless_active_config_key = target_config_key
                        self._reset_vless_retry()
                        self._save_config()
                    self._set_vless_connection_state(False, "")
                    return
                time.sleep(0.3)
            if mihomo_mode and local_ready:
                self._vless_retry_after = float("inf")
                self._set_vless_connection_state(False, "Прокси не работает. Попробуйте переключиться на ядро sing-box")
                return
            if not self._abort_vless_generation(generation, port):
                return
            self._set_vless_connection_state(False, f"{mode_title} не запустился")

        threading.Thread(target=_watchdog, daemon=True).start()
        return True

    def _vless_disconnect(self, silent=False, cancel_pending=True):
        if cancel_pending:
            with self._vless_connect_lock:
                self._vless_connect_pending = False
        with self._vless_transition_lock:
            self._vless_generation = int(self._vless_generation or 0) + 1
            old_port = int(self._vless_port or 0)
            old_owner = str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND)
            self._vless_running = False
            self._vless_connecting = False
            if cancel_pending:
                self._vless_last_error = ""
            self._vless_port = 0
            self._vless_socks_username = ""
            self._vless_active_config_key = ""
            self._vless_local_owner = VLESS_KIND
            try:
                self._vless_core.stop()
            except:
                pass
            if old_port > 0:
                self._clear_local_socks_proxy_if_port(old_port, owner=old_owner)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _add_vless_subscription(self, url, activate_first=False):
        target = _normalize_subscription_url(url)
        if not target:
            BulletinHelper.show_error("Нужна ссылка на подписку")
            return

        BulletinHelper.show_info("Загружаю подписку...")

        def _worker():
            subscription_text = _fetch_text_url(target, timeout_sec=15.0)
            nodes = _fetch_vless_nodes(target, text=subscription_text)
            if not nodes:
                qwdtt_count = 0
                try:
                    qwdtt_count = self._import_qwdtt_payload(subscription_text, activate_first=bool(activate_first), subscription_url=target)
                except:
                    qwdtt_count = 0
                if qwdtt_count > 0:
                    run_on_ui_thread(lambda count=qwdtt_count: BulletinHelper.show_success(f"qWDTT профилей: {count}"))
                    return
                olcrtc_count = 0
                try:
                    olcrtc_count = self._try_import_olcrtc_subscription_text(target, subscription_text, activate_first=bool(activate_first))
                except:
                    olcrtc_count = 0
                if olcrtc_count <= 0:
                    try:
                        olcrtc_text = _fetch_olcrtc_subscription_text(target, timeout_sec=15.0)
                        olcrtc_count = self._try_import_olcrtc_subscription_text(target, olcrtc_text, activate_first=bool(activate_first)) if olcrtc_text else 0
                    except:
                        olcrtc_count = 0
                if olcrtc_count > 0:
                    run_on_ui_thread(lambda count=olcrtc_count: BulletinHelper.show_success(f"olcRTC профилей: {count}"))
                    return
                diag = _get_vless_fetch_diag(target)
                if diag:
                    text_len = int(diag.get("text_len", 0) or 0)
                    vless_count = int(diag.get("vless_count", 0) or 0)
                    ss_count = int(diag.get("ss_count", 0) or 0)
                    proxy_count = int(diag.get("proxy_count", 0) or 0)
                    link_count = int(diag.get("link_count", 0) or 0)
                    stage = str(diag.get("stage", "") or "")
                    tried = int(diag.get("tried", 0) or 0)
                    fetched_host = ""
                    try:
                        fetched_host = str(urllib.parse.urlparse(str(diag.get("fetched_url", "") or "")).netloc or "").strip()
                    except:
                        fetched_host = ""
                    errors = str(diag.get("errors", "") or "").strip()
                    msg = f"Нет узлов: text={text_len} proxy={proxy_count} sing-box={vless_count} ss={ss_count} links={link_count} tried={tried}"
                    if stage:
                        msg += f" stage={stage}"
                    if fetched_host:
                        msg += f" host={fetched_host}"
                    if errors:
                        msg += f" err={errors[:120]}"
                    run_on_ui_thread(lambda: BulletinHelper.show_error(msg))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Подписка не содержит узлов"))
                return

            try:
                subs = list(self._vless_data.get("subs", []) or [])
            except:
                subs = []

            updated = False
            for sub in subs:
                try:
                    if str(sub.get("url", "") or "") == target:
                        sub["nodes"] = nodes
                        updated = True
                except:
                    continue
            if not updated:
                subs.append({
                    "id": target,
                    "url": target,
                    "name": str(urllib.parse.urlparse(target).netloc or target),
                    "nodes": nodes,
                })
            self._vless_data["subs"] = subs
            if activate_first and nodes:
                try:
                    self._vless_data["active_uri"] = str(nodes[0].get("uri", "") or "")
                    self._set_connection_mode(VLESS_KIND)
                except:
                    pass
            self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
            run_on_ui_thread(lambda: BulletinHelper.show_success(f"Импортировано узлов: {len(nodes)}"))

            if activate_first and nodes:
                try:
                    self._enable_plugin_proxy_flag()
                except:
                    pass
                try:
                    self._tgws_disconnect_with_reason("activate_vless_subscription", silent=True)
                except:
                    pass
                try:
                    self._awg_disconnect_with_reason("activate_vless_subscription", silent=True)
                except:
                    pass
                self._ensure_vless_core_then(self._vless_connect)
            elif (updated or self._get_active_vless_uri() == VLESS_AUTO_SUBSCRIPTIONS_URI) and self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND:
                self._ensure_vless_core_then(self._vless_connect)

        threading.Thread(target=_worker, daemon=True).start()

    def _vless_counts(self):
        try:
            manual_count = len(list(self._vless_data.get("manual", []) or []))
        except:
            manual_count = 0
        try:
            subs = list(self._vless_data.get("subs", []) or [])
        except:
            subs = []
        sub_count = len(subs)
        node_count = int(manual_count)
        for sub in subs:
            try:
                node_count += len(list(sub.get("nodes", []) or []))
            except:
                pass
        return {"manual": int(manual_count), "subs": int(sub_count), "nodes": int(node_count)}

    def _download_vless_addon(self):
        if self._vless_prepare_in_progress:
            BulletinHelper.show_info("Ядро прокси уже скачивается")
            return

        self._set_core_download_in_progress(True)
        dialog, update_progress = self._open_core_download_progress()
        if dialog is None:
            BulletinHelper.show_info("Скачиваю ядро прокси...")

        def _worker():
            try:
                ok = self._install_singbox_as_vless_core(on_progress=update_progress)
                if ok:
                    message = "Ядро установлено — перезапустите приложение" if self._core_restart_required() else "Ядро прокси готово"
                    run_on_ui_thread(lambda: BulletinHelper.show_success(message))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро прокси"))
            finally:
                self._set_core_download_in_progress(False)
                if dialog is not None:
                    run_on_ui_thread(lambda: dialog.dismiss())

        threading.Thread(target=_worker, daemon=True).start()

    def _import_vless_from_clipboard(self):
        blob = self._get_clipboard_text()
        if not blob:
            BulletinHelper.show_error("Буфер обмена пуст")
            return

        uri = _extract_import_uri(blob)
        if uri:
            self._handle_import_uri(uri)
            return

        subscription_url = _normalize_subscription_url(blob)
        if subscription_url:
            self._add_vless_subscription(subscription_url, activate_first=(not self._get_active_vless_uri()))
            return

        BulletinHelper.show_error("В буфере нет ссылки на сервер")

    def _vless_node_label(self, node):
        base = self._vless_node_plain_label(node)
        ping = self._vless_ping_value(node)
        checked_at = self._vless_ping_checked_at(node)
        if checked_at > 0 and (time.time() - checked_at) <= float(VLESS_NODE_PING_STALE_SEC):
            if ping > 0 and ping < 9999:
                return f"🟢 {int(ping)} ms: {base}"
            return f"🔴 {base}"
        return base

    def _vless_node_plain_label(self, node):
        try:
            target_uri = str(node.get("uri", "") or "")
        except:
            target_uri = ""
        is_active = bool(
            target_uri
            and target_uri == self._get_active_vless_uri()
            and self._is_vless_mode_selected()
            and self._is_plugin_proxy_enabled()
        )
        if target_uri == VLESS_AUTO_SUBSCRIPTIONS_URI:
            return ("🟢 " if is_active else "") + Z("Автовыбор")
        try:
            raw_name = str(node.get("name", "") or "").strip()
            name = _clean_proxy_name(raw_name, "") if raw_name else ""
            name = re.sub(r"\s+proxy(?:[-_ ]*\d+)?$", "", name, flags=re.I).strip()
        except:
            name = ""
        try:
            kind = str(node.get("kind", "") or "").strip().lower()
        except:
            kind = ""
        if not kind:
            kind = _proxy_uri_scheme(target_uri)
        protocol_label = _proxy_protocol_label(kind)

        parts = []
        if name:
            parts.append(name)
        if protocol_label and protocol_label.lower() != name.lower():
            parts.append(protocol_label)
        prefix = "🟢 " if is_active else ""
        return prefix + (" • ".join(parts) if parts else "Узел")

    def _switch_to_vless_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("vless"):
            return
        if persist_mode:
            self._set_connection_mode(VLESS_KIND)
        try:
            self._tgws_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        try:
            self._awg_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        try:
            self._olcrtc_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        if self._get_active_vless_uri():
            self._enable_plugin_proxy_flag()
            self._reset_vless_retry()
            self._ensure_vless_core_then(self._vless_connect)
        else:
            run_on_ui_thread(lambda: BulletinHelper.show_info("Импортируйте сервер"))
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _vless_subscription_has_active(self, sub):
        active_uri = self._get_active_vless_uri()
        if not active_uri:
            return False
        for node in list(sub.get("nodes", []) or []):
            try:
                if str(node.get("uri", "") or "") == active_uri:
                    return True
            except:
                pass
        return False
