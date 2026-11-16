"""olcRTC: tunnel over a video call (Telemost, Jitsi, WB Stream) run by the core."""

import json
import time

from .. import net, olcrtc_links
from ..android import toast_error, toast_success
from .base import CONNECTED, CONNECTING, FAILED, Mode

READY_TIMEOUT_SEC = 22.0
TELEGRAM_TARGETS = (("149.154.167.51", 443),)


class OlcRtcMode(Mode):
    kind = "olcrtc"
    title = "olcRTC"
    default_port = 11808

    # --- profiles ---

    def profiles(self):
        return self.app.store.olcrtc_profiles

    def active_profile(self):
        store = self.app.store
        profile = next((p for p in store.olcrtc_profiles if p.get("id") == store.olcrtc_active_id), None)
        if profile is None and store.olcrtc_profiles:
            profile = store.olcrtc_profiles[0]
            store.olcrtc_active_id = profile["id"]
        return profile

    def has_config(self):
        return self.active_profile() is not None

    def upsert(self, data, link=""):
        """Save a profile (newest first) and make it active. Returns it or None."""
        sub_url = str(data.get("subscription_url", "") or "").strip()
        if str(link or "").lower().startswith(("http://", "https://")):
            sub_url = link
        profile = olcrtc_links.normalize_profile(dict(data, subscription_url=sub_url,
                                                      subscription_updated_at=int(time.time())))
        if profile is None:
            return None
        store = self.app.store
        store.olcrtc_profiles = ([profile] + [p for p in store.olcrtc_profiles if p.get("id") != profile["id"]])[:olcrtc_links.MAX_PROFILES]
        store.olcrtc_active_id = profile["id"]
        store.save()
        return profile

    def activate(self, profile_id):
        store = self.app.store
        if not any(p.get("id") == profile_id for p in store.olcrtc_profiles):
            return False
        store.olcrtc_active_id = profile_id
        store.save()
        return True

    def delete(self, profile_id):
        store = self.app.store
        store.olcrtc_profiles = [p for p in store.olcrtc_profiles if p.get("id") != profile_id]
        if store.olcrtc_active_id == profile_id:
            store.olcrtc_active_id = store.olcrtc_profiles[0]["id"] if store.olcrtc_profiles else ""
        store.save()

    def _next_profile(self):
        """Move to the next profile after a failure. True when there is another one."""
        store = self.app.store
        profiles = store.olcrtc_profiles
        if len(profiles) < 2:
            return False
        index = next((i for i, p in enumerate(profiles) if p.get("id") == store.olcrtc_active_id), 0)
        store.olcrtc_active_id = profiles[(index + 1) % len(profiles)]["id"]
        store.save()
        return True

    # --- runtime ---

    def _config(self, profile, port):
        config = {
            "engine": "olcrtc", "carrier": profile["carrier"], "transport": profile["transport"],
            "room_id": profile["room_id"], "client_id": profile["client_id"], "key_hex": profile["key_hex"],
            "socks_listen_host": net.LOCAL_HOST, "socks_port": int(port), "socks_user": "", "socks_pass": "",
            "dns_server": "1.1.1.1:53", "wait_ready_timeout_millis": int(READY_TIMEOUT_SEC * 1000),
        }
        if profile["transport"] == "vp8channel":
            config["vp8_fps"] = int(profile.get("vp8_fps", 60) or 60)
            config["vp8_batch_size"] = int(profile.get("vp8_batch_size", 64) or 64)
        return config

    def is_alive(self):
        return self.port > 0 and net.socks_ready(self.port, 0.5)

    def _tunnel_ready(self, port):
        return net.socks_ready(port, 0.5) and any(
            net.socks_connect(port, host, target, timeout=1.2) for host, target in TELEGRAM_TARGETS)

    def core_status(self):
        """{"state", "message"} from the core, for the settings page."""
        if self.state != CONNECTED:
            return {"state": {CONNECTING: "handshake", FAILED: "error"}.get(self.state, "stopped"), "message": self.error}
        try:
            data = json.loads(self.app.core.status_json() or "{}")
            if isinstance(data, dict) and data.get("state"):
                return data
        except ValueError:
            pass
        return {"state": "ready", "message": ""}

    def connect(self, tried=0):
        profile = self.active_profile()
        if profile is None:
            self.set_state(FAILED, "Нет профиля olcRTC")
            return False
        self.set_state(CONNECTING)
        port = self.local_port()
        error = self.app.start_core(self._config(profile, port))
        if not error:
            self.port = port
            deadline = time.monotonic() + READY_TIMEOUT_SEC
            while time.monotonic() < deadline:
                if not self.app.is_current(self):
                    return False
                if self._tunnel_ready(port):
                    if not self.apply_proxy(port):
                        self.set_state(FAILED, "Локальный прокси не применился")
                        return False
                    self.set_state(CONNECTED)
                    toast_success("olcRTC подключен")
                    return True
                time.sleep(0.3)
            error = "WebRTC timeout"
        self.port = 0
        self.app.stop_core()
        # Try the other profiles once each before giving up.
        if tried + 1 < len(self.app.store.olcrtc_profiles) and self._next_profile():
            return self.connect(tried + 1)
        self.set_state(FAILED, "Ошибка olcRTC: %s" % error)
        toast_error("Ошибка olcRTC: %s", error)
        return False

    def stop_runtime(self):
        self.app.stop_core()

    def health_check(self):
        if self.state != CONNECTED:
            return
        state = str(self.core_status().get("state", "") or "").lower()
        if state in ("error", "stopped") or not self.is_alive():
            self.app.reconnect()
