"""
GreenPass mini-module: VirusKiller RAT Guard.

Local-only defensive module loaded by GreenPass from greenpass_modules/.
It never hooks compile() and never blocks the plugin installer. It scans .plugin/.py
files after they appear, tries to disable loaded malicious plugins, alerts the user,
and moves only high-confidence RAT/C2 samples into reversible quarantine.
"""

import ast
import builtins
import hashlib
import json
import os
import re
import shutil
import threading
import time

try:
    from android_utils import log, run_on_ui_thread
except Exception:
    def log(message):
        print(message)

    def run_on_ui_thread(func, *args, **kwargs):
        try:
            return func()
        except Exception:
            return None

try:
    from ui.bulletin import BulletinHelper
except Exception:
    class BulletinHelper:
        @staticmethod
        def show_info(message, *args, **kwargs):
            print(f"[INFO] {message}")

        @staticmethod
        def show_success(message, *args, **kwargs):
            print(f"[OK] {message}")

        @staticmethod
        def show_error(message, *args, **kwargs):
            print(f"[ERR] {message}")

try:
    from ui.alert import AlertDialogBuilder
except Exception:
    AlertDialogBuilder = None

try:
    from client_utils import get_last_fragment
except Exception:
    def get_last_fragment():
        return None

try:
    from hook_utils import find_class
except Exception:
    def find_class(name):
        return None

TAG = "[GP-RATGuard]"
MAX_SCAN_BYTES = 768 * 1024
FAST_SCAN_SECONDS = 90
FAST_SCAN_INTERVAL = 3.0
SLOW_SCAN_INTERVAL = 30.0
MAX_FILES_PER_PASS = 300
MAX_SEEN_STATE = 1200

MALICIOUS_IPS = {
    "45.13.237.28",
    "45.192.12.135",
    "82.38.213.49",
}
MALICIOUS_INT_IPS = {
    755887388: "45.13.237.28",
    767560839: "45.192.12.135",
    1378246897: "82.38.213.49",
}
C2_PORTS = {5050, 9998, 9999}
C2_MARKERS = (
    "REG:",
    "USER_TOKEN",
    "<END>",
    "RESPONSE:",
)
REPLUGIN_MARKERS = (
    "/replugin/code",
    "/replugin/log",
    "/replugin/op",
    "castle.telepanel.live",
    "castleteam.top",
)
SENSITIVE_MARKERS = (
    "tgnet.dat",
    "userconfig",
    "userconfing",
    "/shared_prefs/",
    "/data/data/com.exteragram.messenger/",
    "/data/data/com.radolyn.ayugram/",
)

_lock = threading.RLock()
_stop_event = threading.Event()
_worker = None
_started = False
_config = {}
_state = {
    "version": 1,
    "seen": {},
    "quarantine": [],
    "last_scan_ts": 0,
}
_alerted = set()


def _log(message):
    try:
        log(f"{TAG} {message}")
    except Exception:
        pass


def _basename(path):
    try:
        return os.path.basename(str(path or "")) or "plugin"
    except Exception:
        return "plugin"


def _modules_dir():
    value = str(_config.get("modules_dir") or "greenpass_modules")
    try:
        if not os.path.exists(value):
            os.makedirs(value)
    except Exception:
        pass
    return value


def _quarantine_dir():
    value = str(_config.get("quarantine_dir") or os.path.join(_modules_dir(), "rat_quarantine"))
    try:
        if not os.path.exists(value):
            os.makedirs(value)
    except Exception:
        pass
    return value


def _state_path():
    return os.path.join(_modules_dir(), "rat_guard_state.json")


def _atomic_write_json(path, data):
    tmp = f"{path}.{threading.get_ident()}.{int(time.time() * 1000000)}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        try:
            handle.flush()
            os.fsync(handle.fileno())
        except Exception:
            pass
    os.replace(tmp, path)


def _load_state():
    global _state
    try:
        path = _state_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                base = {"version": 1, "seen": {}, "quarantine": [], "last_scan_ts": 0}
                base.update(data)
                if not isinstance(base.get("seen"), dict):
                    base["seen"] = {}
                if not isinstance(base.get("quarantine"), list):
                    base["quarantine"] = []
                _state = base
    except Exception as exc:
        _log(f"state load skipped: {exc}")


def _save_state():
    try:
        _atomic_write_json(_state_path(), _state)
    except Exception as exc:
        _log(f"state save skipped: {exc}")


def _restore_stale_compile_hook():
    # Old VirusKiller builds patched builtins.compile globally and broke plugin install.
    # This module never patches compile(); it only unwraps that stale hook if present.
    try:
        current = builtins.compile
        if getattr(current, "__name__", "") != "_patched_compile":
            return False
        original = getattr(current, "__globals__", {}).get("_original_compile")
        if callable(original) and original is not current:
            builtins.compile = original
            _log("stale VirusKiller compile hook removed")
            _notify("Установка плагинов разблокирована", error=False)
            return True
    except Exception as exc:
        _log(f"compile restore skipped: {exc}")
    return False


def _notify(message, error=False):
    def show():
        try:
            if error:
                BulletinHelper.show_error(message)
            else:
                BulletinHelper.show_info(message)
        except Exception:
            pass
    try:
        run_on_ui_thread(show)
    except Exception:
        show()


def _show_detection_alert(result, quarantined):
    sha = str(result.get("sha256", ""))[:16]
    if sha and sha in _alerted:
        return
    if sha:
        _alerted.add(sha)
    title = "RAT найден"
    action = "карантин" if quarantined else "найден, карантин не выполнен"
    unload = "unload выполнен" if result.get("unloaded") else "unload не выполнен"
    message = f"{_basename(result.get('path'))}: {action}, {unload}.\n{result.get('summary', '')}"

    def show():
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment and hasattr(fragment, "getParentActivity") else None
            if AlertDialogBuilder is None or activity is None:
                BulletinHelper.show_error("RAT найден")
                return
            builder = AlertDialogBuilder(activity)
            builder.set_title(title)
            builder.set_message(message)
            builder.set_positive_button("Понятно", lambda dialog, which: dialog.dismiss() if dialog else None)
            builder.set_cancelable(True)
            try:
                builder.set_canceled_on_touch_outside(True)
            except Exception:
                pass
            builder.show()
        except Exception:
            try:
                BulletinHelper.show_error("RAT найден")
            except Exception:
                pass

    try:
        run_on_ui_thread(show)
    except Exception:
        show()


def _java_class(name):
    try:
        cls = find_class(name)
        if cls is not None:
            return cls
    except Exception:
        pass
    try:
        from java import jclass
        return jclass(name)
    except Exception:
        return None


def _detected_plugin_id(result):
    pid = str(result.get("plugin_id") or "").strip()
    if pid:
        return pid
    base = _basename(result.get("path"))
    if base.lower().endswith((".plugin", ".py")):
        base = os.path.splitext(base)[0]
    return str(base or "").strip()


def _unload_detected_plugin(result):
    pid = _detected_plugin_id(result)
    if not pid or pid == "GreenPass":
        return False
    state = {"ok": False}

    def do_unload():
        try:
            PC = _java_class("com.exteragram.messenger.plugins.PluginsController")
            controller = PC.getInstance() if PC is not None else None
            if controller is None:
                return
            try:
                controller.setPluginEnabled(pid, False, None)
                state["ok"] = True
            except Exception:
                try:
                    controller.setPluginEnabled(pid, False)
                    state["ok"] = True
                except Exception:
                    pass
            if not state["ok"]:
                try:
                    plugins = getattr(controller, "plugins", None)
                    plugin = plugins.get(pid) if plugins is not None else None
                    for name in ("unload", "unloadPlugin", "onPluginUnload", "on_plugin_unload", "stop"):
                        method = getattr(plugin, name, None) if plugin is not None else None
                        if callable(method):
                            method()
                            state["ok"] = True
                            break
                except Exception:
                    pass
            try:
                NC = _java_class("org.telegram.messenger.NotificationCenter")
                if NC is not None:
                    NC.getGlobalInstance().postNotificationName(NC.pluginsUpdated)
            except Exception:
                pass
        except Exception as exc:
            _log(f"unload failed for {pid}: {exc}")

    done = threading.Event()

    def wrapped_unload():
        try:
            do_unload()
        finally:
            done.set()

    try:
        run_on_ui_thread(wrapped_unload)
    except Exception:
        wrapped_unload()
    try:
        done.wait(1.0)
    except Exception:
        pass
    if state["ok"]:
        _log(f"plugin unloaded: {pid}")
    return bool(state["ok"])


def _int_to_ipv4(value):
    try:
        n = int(value)
    except Exception:
        return ""
    if n < 0 or n > 0xFFFFFFFF:
        return ""
    return ".".join(str((n >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _int_ip_candidates(value):
    out = set()
    ip = _int_to_ipv4(value)
    if ip:
        out.add(ip)
    try:
        n = int(value)
        little = ".".join(str((n >> shift) & 0xFF) for shift in (0, 8, 16, 24))
        if little:
            out.add(little)
    except Exception:
        pass
    return out


def _parse_ast(source, path):
    try:
        return compile(source, path or "<plugin>", "exec", ast.PyCF_ONLY_AST)
    except Exception:
        return None


def _parse_meta(source):
    meta = {"id": "", "name": "Unknown", "version": ""}
    tree = _parse_ast(source, "<meta>")
    if tree is not None:
        try:
            for node in getattr(tree, "body", []) or []:
                if not isinstance(node, ast.Assign):
                    continue
                for target in getattr(node, "targets", []) or []:
                    if not isinstance(target, ast.Name):
                        continue
                    if target.id not in ("__id__", "__name__", "__version__"):
                        continue
                    try:
                        value = ast.literal_eval(node.value)
                    except Exception:
                        continue
                    if target.id == "__id__":
                        meta["id"] = str(value)
                    elif target.id == "__name__":
                        meta["name"] = str(value)
                    elif target.id == "__version__":
                        meta["version"] = str(value)
        except Exception:
            pass
    for key, out_key in (("__id__", "id"), ("__name__", "name"), ("__version__", "version")):
        if meta.get(out_key) and meta.get(out_key) != "Unknown":
            continue
        try:
            match = re.search(rf"{re.escape(key)}\s*=\s*(['\"])(.*?)\1", source, re.DOTALL)
            if match:
                meta[out_key] = match.group(2)[:120]
        except Exception:
            pass
    return meta


def _collect_ints(tree):
    values = []
    if tree is None:
        return values
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
                values.append(int(node.value))
    except Exception:
        pass
    return values


def _line_evidence(lines, markers, limit=4):
    evidence = []
    seen = set()
    for i, line in enumerate(lines, start=1):
        low = str(line or "").lower()
        if not any(str(marker).lower() in low for marker in markers):
            continue
        text = str(line or "").strip()
        text = re.sub(r"\b[a-fA-F0-9]{32,}\b", "<hex>", text)
        text = re.sub(r"\b[A-Za-z0-9_/-]{48,}={0,2}\b", "<blob>", text)
        if len(text) > 130:
            text = text[:127] + "..."
        item = f"L{i}: {text}"
        if item in seen:
            continue
        seen.add(item)
        evidence.append(item)
        if len(evidence) >= limit:
            break
    return evidence


def _has_word_number(source, numbers):
    try:
        pattern = r"(?<!\d)(" + "|".join(re.escape(str(value)) for value in numbers) + r")(?!\d)"
        return bool(re.search(pattern, source))
    except Exception:
        return any(str(value) in source for value in numbers)


def _has_dynamic_exec_obfuscation(source):
    low = str(source or "").lower()
    if "__dict__" not in low and "getattr(" not in low:
        return False
    if "builtins" not in low and "sys.modules" not in low:
        return False
    if "exec" in low:
        return True
    try:
        return bool(re.search(r"['\"]e['\"]\s*\+\s*['\"]x['\"]\s*\+\s*['\"]e['\"]\s*\+\s*['\"]c['\"]", low))
    except Exception:
        return False


def _scan_source(source, path):
    source = str(source or "")
    low = source.lower()
    lines = source.splitlines()
    tree = _parse_ast(source, path)
    ints = _collect_ints(tree)
    int_ips = set()
    for value in ints:
        int_ips.update(_int_ip_candidates(value))
    known_ints = [value for value in ints if value in MALICIOUS_INT_IPS]
    known_ips = {ip for ip in MALICIOUS_IPS if ip in low or ip in int_ips}

    has_socket = "socket" in low or ".connect" in low or "sendall" in low
    has_sendall = "sendall" in low
    has_recv = "recv(" in low or ".recv" in low
    has_port = _has_word_number(low, C2_PORTS)
    has_sensitive = any(marker.lower() in low for marker in SENSITIVE_MARKERS)
    has_file_read = "open(" in low or ".read(" in low or "os.path.isfile" in low
    has_exec = "exec(" in low or "eval(" in low or "compile(" in low or _has_dynamic_exec_obfuscation(low)
    has_network = has_socket or "urlopen" in low or "requests." in low or "openconnection" in low
    has_protocol = any(marker.lower() in low for marker in C2_MARKERS)
    has_replugin = any(marker.lower() in low for marker in REPLUGIN_MARKERS)
    has_plain_http = "http://" in low
    has_persistent_thread = "threading.thread" in low and "while true" in low and has_network
    try:
        has_remote_exec_loader = bool(
            re.search(r"\bexec\s*\([^\n]{0,240}\burlopen\s*\([^\n]{0,240}\.read\s*\(", source, re.IGNORECASE)
            or re.search(r"\bexec\s*\([^\n]{0,240}\brequests\.get\s*\([^\n]{0,240}\.(?:text|content)\b", source, re.IGNORECASE)
        )
    except Exception:
        has_remote_exec_loader = False
    has_remote_json_code_exec = bool(
        (("urlopen(" in low or "openconnection(" in low or ".openconnection" in low)
         and ".get(\"code\"" in low
         and "checksum" in low
         and "exec(compile(" in low)
    )

    findings = []
    seen_rules = set()

    def add(rule_id, title, markers):
        if rule_id in seen_rules:
            return
        seen_rules.add(rule_id)
        findings.append({"id": rule_id, "title": title, "evidence": _line_evidence(lines, markers)})

    if ("45.192.12.135" in known_ips or 767560839 in known_ints) and has_socket and has_sendall and has_port and has_sensitive:
        add("c2_socket_exfil", "C2-эксфильтрация Telegram данных", ["45.192.12.135", "767560839", "sendall", "tgnet.dat", "userconfig", "9998"])

    if has_sensitive and has_file_read and (has_sendall or known_ips or known_ints):
        add("telegram_sensitive_file_read", "Чтение sensitive Telegram файлов", ["/data/data/", "shared_prefs", "tgnet.dat", "userconfig", "open("])

    if has_network and has_exec and (known_ips or known_ints or has_protocol or has_replugin):
        add("remote_exec_backdoor", "Удалённый exec/backdoor", ["exec", "eval", "compile", "builtins", "recv", "REG:", "<END>"])

    if has_remote_exec_loader:
        add("remote_exec_loader", "Прямой remote exec loader", ["exec", "urlopen", "requests.get", ".read()", ".text"])

    if has_remote_json_code_exec:
        add("remote_json_code_exec", "JSON code payload + exec", ["urlopen", "\"code\"", "checksum", "exec(compile"])

    if ("45.13.237.28" in known_ips or 755887388 in known_ints or has_replugin) and has_network:
        add("replugin_loader_c2", "RePlugin C2 loader", ["45.13.237.28", "755887388", "/replugin/code", "castle.telepanel.live"])

    if has_socket and has_recv and has_sendall and has_port and has_protocol:
        add("socket_c2_protocol", "TCP C2 protocol", ["REG:", "USER_TOKEN", "<END>", "recv", "sendall", "9999", "9998"])

    if known_ints and has_socket:
        add("int_ip_obfuscation", "Обфускация C2 IP через integer", [str(value) for value in known_ints] + [">>24", "&255"])

    if has_network and has_exec and "remote_exec_backdoor" not in seen_rules:
        add("network_dynamic_code", "Сеть + динамическое выполнение кода", ["socket", "urlopen", "requests.", "recv", "exec", "eval", "compile", "builtins"])

    if has_socket and has_sendall and has_port and "c2_socket_exfil" not in seen_rules and "socket_c2_protocol" not in seen_rules:
        add("suspicious_socket_sendall", "Подозрительный socket.sendall", ["socket", "connect", "sendall", "9998", "9999", "5050"])

    if has_persistent_thread:
        add("persistent_c2_thread", "Фоновый persistent network thread", ["threading.Thread", "daemon=True", "while True", "socket", "urlopen"])

    if has_plain_http and not known_ips and not known_ints and not has_replugin:
        add("plain_http", "Незащищённый HTTP", ["http://"])

    ids = {item["id"] for item in findings}
    danger = bool(
        "c2_socket_exfil" in ids
        or "remote_exec_loader" in ids
        or "remote_json_code_exec" in ids and ("replugin_loader_c2" in ids or known_ips or known_ints)
        or "replugin_loader_c2" in ids and "remote_exec_backdoor" in ids
        or "socket_c2_protocol" in ids and "remote_exec_backdoor" in ids
        or "telegram_sensitive_file_read" in ids and ("remote_exec_backdoor" in ids or "c2_socket_exfil" in ids)
    )
    watch = bool(findings)
    meta = _parse_meta(source)
    sha = hashlib.sha256(source.encode("utf-8", "ignore")).hexdigest()
    return {
        "path": path,
        "sha256": sha,
        "plugin_id": meta.get("id", ""),
        "plugin_name": meta.get("name", "Unknown"),
        "plugin_version": meta.get("version", ""),
        "verdict": "danger" if danger else ("watch" if watch else "safe"),
        "summary": "Найдены точные признаки RAT/C2, файл помещён в карантин." if danger else "Точных RAT/C2 признаков нет.",
        "findings": findings,
        "can_quarantine": danger,
        "can_auto_quarantine": danger,
    }


def _is_plugin_file(path):
    low = str(path or "").lower()
    return low.endswith(".plugin") or low.endswith(".py")


def _read_source(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_SCAN_BYTES + 1)
    if len(data) > MAX_SCAN_BYTES:
        raise ValueError("too_large")
    return data.decode("utf-8-sig", "ignore")


def _read_source_and_sha(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_SCAN_BYTES + 1)
    if len(data) > MAX_SCAN_BYTES:
        raise ValueError("too_large")
    return data.decode("utf-8-sig", "ignore"), hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _stat_key(path):
    try:
        stat = os.stat(path)
        mtime_ns = getattr(stat, "st_mtime_ns", None)
        if mtime_ns is None:
            mtime_ns = int(float(getattr(stat, "st_mtime", 0)) * 1000000000)
        return {"size": int(getattr(stat, "st_size", 0)), "mtime_ns": int(mtime_ns)}
    except Exception:
        return None


def _seen_is_current(seen, stat):
    if not isinstance(seen, dict) or not isinstance(stat, dict):
        return False
    verdict = seen.get("verdict")
    if verdict not in ("safe", "watch", "quarantined", "skip"):
        return False
    return seen.get("size") == stat.get("size") and seen.get("mtime_ns") == stat.get("mtime_ns")


def _remember_seen(path, sha, verdict, stat=None, error=None):
    item = {"sha256": sha, "verdict": verdict, "ts": int(time.time())}
    if isinstance(stat, dict):
        item.update(stat)
    if error:
        item["error"] = str(error)[:120]
    _state.setdefault("seen", {})[path] = item


def _prune_seen_state():
    try:
        seen = _state.setdefault("seen", {})
        if len(seen) <= MAX_SEEN_STATE:
            return
        items = sorted(seen.items(), key=lambda item: int((item[1] or {}).get("ts", 0) or 0), reverse=True)
        _state["seen"] = dict(items[:MAX_SEEN_STATE])
    except Exception:
        pass


def _iter_dir_entries(directory, limit):
    yielded = 0
    try:
        scanner = getattr(os, "scandir", None)
        if callable(scanner):
            with scanner(directory) as entries:
                for entry in entries:
                    if yielded >= limit:
                        return
                    try:
                        yield entry.name, entry.path, entry.is_dir()
                        yielded += 1
                    except Exception:
                        continue
            return
    except Exception:
        pass
    try:
        for name in os.listdir(directory):
            if yielded >= limit:
                return
            path = os.path.join(directory, name)
            yield name, path, os.path.isdir(path)
            yielded += 1
    except Exception:
        return


def _candidate_dirs():
    dirs = []

    def add(path):
        try:
            path = os.path.abspath(str(path or ""))
            if path and os.path.isdir(path) and path not in dirs:
                dirs.append(path)
        except Exception:
            pass

    module_dir = _modules_dir()
    add(module_dir)
    add(os.path.dirname(module_dir))
    plugin_path = str(_config.get("plugin_path") or "")
    add(os.path.dirname(plugin_path))
    parent = os.path.dirname(os.path.dirname(plugin_path)) if plugin_path else ""
    add(parent)
    for root in list(dirs):
        try:
            for name, full, is_dir in _iter_dir_entries(root, 80):
                low = name.lower()
                if low in ("__pycache__",) or low.startswith("."):
                    continue
                if is_dir and ("plugin" in low or low in ("nextgen", "viruskiller")):
                    add(full)
        except Exception:
            pass
    qdir = os.path.abspath(_quarantine_dir())
    return [d for d in dirs if not os.path.abspath(d).startswith(qdir)][:24]


def _iter_plugin_files():
    qdir = os.path.abspath(_quarantine_dir())
    own = os.path.abspath(__file__)
    gp = os.path.abspath(str(_config.get("plugin_path") or ""))
    seen = set()
    count = 0
    for directory in _candidate_dirs():
        for name, raw_path, is_dir in _iter_dir_entries(directory, MAX_FILES_PER_PASS):
            if is_dir:
                continue
            path = os.path.abspath(os.path.join(directory, name))
            try:
                path = os.path.abspath(raw_path)
            except Exception:
                pass
            if path in seen:
                continue
            seen.add(path)
            if path == own or path.startswith(qdir):
                continue
            if not _is_plugin_file(path):
                continue
            if path == gp:
                # GreenPass itself must never be quarantined by the helper module.
                continue
            try:
                if os.path.getsize(path) > MAX_SCAN_BYTES:
                    continue
            except Exception:
                continue
            count += 1
            yield path
            if count >= MAX_FILES_PER_PASS:
                return


def _quarantine(path, result):
    try:
        if not result.get("can_quarantine"):
            return False
        if not os.path.exists(path):
            return False
        sha = result.get("sha256") or _sha256_file(path)
        qdir = _quarantine_dir()
        base = re.sub(r"[^A-Za-z0-9А-Яа-я._()-]+", "_", _basename(path))[:90]
        target = os.path.join(qdir, f"{base}.{time.strftime('%Y%m%d-%H%M%S')}.{sha[:12]}.ratblocked")
        if os.path.exists(target):
            target += f".{int(time.time())}"
        shutil.move(path, target)
        entry = {
            "id": hashlib.sha1((path + target + sha).encode("utf-8", "ignore")).hexdigest()[:16],
            "ts": int(time.time()),
            "original_path": path,
            "quarantine_path": target,
            "sha256": sha,
            "plugin_id": result.get("plugin_id", ""),
            "plugin_name": result.get("plugin_name", "Unknown"),
            "verdict": result.get("verdict", ""),
            "unloaded": bool(result.get("unloaded")),
            "findings": result.get("findings", [])[:8],
        }
        _state.setdefault("quarantine", []).append(entry)
        _state.setdefault("seen", {})[path] = {"sha256": sha, "verdict": "quarantined", "ts": int(time.time())}
        _save_state()
        return True
    except Exception as exc:
        _log(f"quarantine failed for {path}: {exc}")
        return False


def scan_once():
    _restore_stale_compile_hook()
    findings = 0
    quarantined = 0
    scanned = 0
    for path in _iter_plugin_files():
        stat = _stat_key(path)
        seen = _state.setdefault("seen", {}).get(path)
        if _seen_is_current(seen, stat):
            continue
        try:
            source, sha = _read_source_and_sha(path)
            result = _scan_source(source, path)
            result["sha256"] = sha
        except Exception as exc:
            old_sha = seen.get("sha256") if isinstance(seen, dict) else ""
            _remember_seen(path, old_sha, "skip", stat=stat, error=exc)
            continue
        scanned += 1
        verdict = result.get("verdict", "safe")
        _remember_seen(path, sha, verdict, stat=stat)
        if verdict == "danger" and result.get("can_quarantine"):
            findings += 1
            result["unloaded"] = _unload_detected_plugin(result)
            ok = _quarantine(path, result)
            if ok:
                quarantined += 1
            _show_detection_alert(result, quarantined=ok)
        elif verdict == "watch":
            # Do not quarantine weak hits. Keep install/use flow untouched.
            pass
    _state["last_scan_ts"] = int(time.time())
    _prune_seen_state()
    _save_state()
    if scanned and not findings:
        _log(f"scan ok: scanned={scanned}, no exact RAT")
    if quarantined:
        _notify(f"RAT Guard: карантин {quarantined}", error=True)
    return {"scanned": scanned, "findings": findings, "quarantined": quarantined}


def _worker_loop():
    start_ts = time.time()
    while not _stop_event.is_set():
        try:
            scan_once()
        except Exception as exc:
            _log(f"scan loop error: {exc}")
        elapsed = time.time() - start_ts
        delay = FAST_SCAN_INTERVAL if elapsed < FAST_SCAN_SECONDS else SLOW_SCAN_INTERVAL
        _stop_event.wait(delay)


def start(config=None):
    global _started, _worker, _config
    with _lock:
        _config = dict(config or {})
        _restore_stale_compile_hook()
        _load_state()
        if _started and _worker and _worker.is_alive():
            return True
        _stop_event.clear()
        _worker = threading.Thread(target=_worker_loop, name="GreenPassRATGuard", daemon=True)
        _worker.start()
        _started = True
        _log("started; install flow is not hooked")
        return True


def stop():
    global _started
    with _lock:
        _stop_event.set()
        _started = False
    return True


if __name__ == "__main__":
    start({"modules_dir": os.path.dirname(os.path.abspath(__file__))})
    print(scan_once())
    stop()
