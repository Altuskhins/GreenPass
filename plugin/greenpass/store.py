"""Persistent plugin state in config.json.

The file name and keys match the old plugin, so users keep their nodes,
subscriptions and profiles when they update.
"""

import json
import os
import re
import threading
import time

from .meta import VERSION

CONFIG_FILE_NAME = "safebypass_v2_config.json"
CONFIG_SCHEMA = 3

MODE_VLESS = "vless"
MODE_TGWS = "tgws"
MODE_AWG = "awg"
MODE_OLCRTC = "olcrtc"
MODES = (MODE_VLESS, MODE_TGWS, MODE_AWG, MODE_OLCRTC)

ENGINE_SINGBOX = "singbox"
ENGINE_MIHOMO = "mihomo"

WIFI_RULE_OFF = "off"
MAX_ITEMS = 64


def normalize_mode(value, fallback=MODE_VLESS):
    mode = str(value or "")
    if mode in MODES:
        return mode
    return fallback if fallback in MODES else MODE_VLESS


def normalize_engine(value):
    return ENGINE_MIHOMO if str(value or "").strip().lower() == ENGINE_MIHOMO else ENGINE_SINGBOX


def normalize_ssid(value):
    ssid = str(value or "").strip()
    if len(ssid) >= 2 and ssid[0] == '"' and ssid[-1] == '"':
        ssid = ssid[1:-1].strip()
    if not ssid or ssid.lower() in ("<unknown ssid>", "unknown ssid", "0x"):
        return ""
    return ssid[:64]


def clean_wifi_rules(values):
    rules = {}
    if isinstance(values, dict):
        for raw_ssid, raw_mode in values.items():
            ssid = normalize_ssid(raw_ssid)
            mode = str(raw_mode or "")
            if ssid and (mode == WIFI_RULE_OFF or mode in MODES):
                rules[ssid] = mode
            if len(rules) >= MAX_ITEMS:
                break
    return rules


def _list(value):
    return list(value) if isinstance(value, list) else []


def _is_secret(value):
    return bool(re.fullmatch(r"[0-9a-f]{32}", str(value or "")))


class Store:
    """Plugin state. Mutate fields, then call save()."""

    def __init__(self, files_dir):
        self.path = os.path.join(str(files_dir or "."), CONFIG_FILE_NAME)
        self._lock = threading.RLock()
        self.reset()

    def reset(self):
        self.mode = MODE_AWG
        self.enabled = False                     # "desired_use_proxy": the user wants the proxy on
        self.engine = ENGINE_SINGBOX
        self.socks_password = ""
        self.wifi_rules = {}                     # ssid -> mode or "off"
        self.wifi_default_mode = MODE_AWG
        self.awg_conf_name = ""
        self.awg_conf_content = ""
        self.vless_manual = []                   # node dicts
        self.vless_subs = []                     # {"id", "url", "name", "nodes": [...]}
        self.vless_active_uri = ""
        self.olcrtc_profiles = []
        self.olcrtc_active_id = ""
        self.legacy_qwdtt = None                 # old qwdtt_data, migrated by the app
        self.update_checked_at = 0
        self.update_seen_tag = ""
        self.core_restart_pid = 0
        self.core_restart_reason = ""
        self.core_restart_mode = ""
        self.core_restart_enabled = False
        self.core_restart_resumed = False        # this process started after a core update
        self.server = ""
        self.port = 0

    # --- load / save ---

    def load(self):
        """Read config.json, falling back to the backup. Returns True when it changed on load."""
        with self._lock:
            for path in (self.path, self.path + ".bak"):
                data = self._read(path)
                if data is not None:
                    changed = self._apply(data) or path != self.path
                    self._write(self.path + ".bak", data)
                    return changed
            return False

    def _read(self, path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def _apply(self, data):
        self.reset()
        changed = int(data.get("config_schema", 0) or 0) < CONFIG_SCHEMA
        self.server = str(data.get("server", "") or "")
        try:
            self.port = int(data.get("port", 0) or 0)
        except (TypeError, ValueError):
            self.port = 0
        self.mode = normalize_mode(data.get("connection_mode"), MODE_AWG) if data.get("connection_mode") != "qwdtt" else MODE_VLESS
        self.enabled = bool(data.get("desired_use_proxy", data.get("use_proxy", False)))
        self.engine = normalize_engine(data.get("vless_engine"))
        password = str(data.get("vless_socks_password", "") or "").strip().lower()
        self.socks_password = password if _is_secret(password) else ""
        self.update_checked_at = int(data.get("autoupdate_last_check_ts", 0) or 0)
        self.update_seen_tag = str(data.get("autoupdate_last_seen_version", "") or "")

        self.wifi_rules = clean_wifi_rules(data.get("wifi_mode_rules"))
        for ssid in _list(data.get("excluded_wifi_ssids")):
            ssid = normalize_ssid(ssid)
            if ssid:
                self.wifi_rules.setdefault(ssid, WIFI_RULE_OFF)
        default_mode = data.get("wifi_default_mode", self.mode)
        self.wifi_default_mode = normalize_mode(MODE_VLESS if default_mode == "qwdtt" else default_mode, self.mode)
        self.mode = self.wifi_default_mode

        awg = data.get("awg_data")
        if isinstance(awg, dict):
            self.awg_conf_name = str(awg.get("conf_name", "") or "")
            self.awg_conf_content = str(awg.get("conf_content", "") or "")

        vless = data.get("vless_data")
        if isinstance(vless, dict):
            self.vless_manual = [n for n in _list(vless.get("manual")) if isinstance(n, dict)]
            self.vless_subs = [s for s in _list(vless.get("subs")) if isinstance(s, dict)]
            self.vless_active_uri = str(vless.get("active_uri", "") or "")

        olcrtc = data.get("olcrtc_data")
        if isinstance(olcrtc, dict):
            self.olcrtc_profiles = [p for p in _list(olcrtc.get("profiles")) if isinstance(p, dict)]
            self.olcrtc_active_id = str(olcrtc.get("active_profile_id", "") or "")

        qwdtt = data.get("qwdtt_data")
        if isinstance(qwdtt, dict) and (qwdtt.get("profiles") or qwdtt.get("subs")):
            self.legacy_qwdtt = qwdtt
            changed = True

        # A core update asks for an app restart; the next process resumes the mode.
        restart_pid = int(data.get("core_restart_required_pid", 0) or 0)
        restart_reason = str(data.get("core_restart_reason", "") or "")
        resume_mode = str(data.get("core_restart_resume_mode", "") or "")
        resume_enabled = bool(data.get("core_restart_resume_enabled", False))
        if restart_pid:
            if resume_mode:
                self.set_mode(resume_mode)
            if restart_pid == os.getpid() and restart_reason == "library_update":
                self.core_restart_pid = restart_pid
                self.core_restart_reason = restart_reason
                self.core_restart_mode = resume_mode
                self.core_restart_enabled = resume_enabled
            else:
                self.enabled = resume_enabled
                self.core_restart_resumed = restart_pid != os.getpid()
                changed = True
        return changed

    def to_dict(self):
        excluded = [ssid for ssid, mode in self.wifi_rules.items() if mode == WIFI_RULE_OFF]
        return {
            "server": self.server,
            "port": self.port,
            "connection_mode": self.mode,
            "desired_use_proxy": bool(self.enabled),
            "vless_engine": self.engine,
            "vless_socks_password": self.socks_password,
            "config_schema": CONFIG_SCHEMA,
            "last_loaded_version": VERSION,
            "core_restart_required_pid": int(self.core_restart_pid or 0),
            "core_restart_reason": self.core_restart_reason,
            "core_restart_resume_mode": self.core_restart_mode,
            "core_restart_resume_enabled": bool(self.core_restart_enabled),
            "autoupdate_last_check_ts": int(self.update_checked_at or 0),
            "autoupdate_last_seen_version": self.update_seen_tag,
            "proxy_suspended_by_vpn": False,
            "excluded_wifi_ssids": excluded,
            "wifi_mode_rules": dict(self.wifi_rules),
            "wifi_default_mode": self.wifi_default_mode,
            "awg_data": {"conf_name": self.awg_conf_name, "conf_content": self.awg_conf_content},
            "vless_data": {
                "manual": list(self.vless_manual),
                "subs": list(self.vless_subs),
                "active_uri": self.vless_active_uri,
            },
            "olcrtc_data": {
                "profiles": list(self.olcrtc_profiles),
                "active_profile_id": self.olcrtc_active_id,
            },
        }

    def save(self):
        with self._lock:
            data = self.to_dict()
            ok = self._write(self.path, data)
            self._write(self.path + ".bak", data)
            return ok

    def _write(self, path, data):
        tmp = "%s.%d.%d.tmp" % (path, threading.get_ident(), int(time.time() * 1000000))
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(data, ensure_ascii=False))
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            os.replace(tmp, path)
            return True
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False

    # --- helpers ---

    def ensure_socks_password(self):
        if not _is_secret(self.socks_password):
            self.socks_password = os.urandom(16).hex()
            return True
        return False

    def set_mode(self, mode, by_wifi_rule=False):
        self.mode = normalize_mode(mode, self.mode)
        if not by_wifi_rule:
            self.wifi_default_mode = self.mode
