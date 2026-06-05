"""
GreenPass mini-module: VirusKiller RAT Guard.

Local-only defensive module loaded by GreenPass from greenpass_modules/.
It never hooks compile() and never blocks the plugin installer. It scans .plugin/.py
files after they appear, alerts the user, and moves only high-confidence RAT/C2
samples into reversible quarantine.
"""

import ast
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
    "/replugin/code",
    "/replugin/log",
    "/replugin/op",
    "castle.telepanel.live",
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
    message = f"{_basename(result.get('path'))}: {action}.\n{result.get('summary', '')}"

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
    has_port = any(str(port) in low for port in C2_PORTS)
    has_sensitive = any(marker.lower() in low for marker in SENSITIVE_MARKERS)
    has_file_read = "open(" in low or ".read(" in low or "os.path.isfile" in low
    has_exec = "exec(" in low or "eval(" in low or "compile(" in low or "__dict__" in low and "exec" in low
    has_network = has_socket or "urlopen" in low or "requests." in low or "openconnection" in low
    has_protocol = any(marker.lower() in low for marker in C2_MARKERS)
    has_replugin = "/replugin/code" in low or "/replugin/log" in low or "castle.telepanel.live" in low

    findings = []

    def add(rule_id, title, markers):
        findings.append({"id": rule_id, "title": title, "evidence": _line_evidence(lines, markers)})

    if ("45.192.12.135" in known_ips or 767560839 in known_ints) and has_socket and has_sendall and has_port and has_sensitive:
        add("c2_socket_exfil", "C2-эксфильтрация Telegram данных", ["45.192.12.135", "767560839", "sendall", "tgnet.dat", "userconfig", "9998"])

    if has_sensitive and has_file_read and (has_sendall or known_ips or known_ints):
        add("telegram_sensitive_file_read", "Чтение sensitive Telegram файлов", ["/data/data/", "shared_prefs", "tgnet.dat", "userconfig", "open("])

    if has_network and has_exec and (known_ips or known_ints or has_protocol):
        add("remote_exec_backdoor", "Удалённый exec/backdoor", ["exec", "eval", "compile", "builtins", "recv", "REG:", "<END>"])

    if ("45.13.237.28" in known_ips or 755887388 in known_ints or has_replugin) and has_network:
        add("replugin_loader_c2", "RePlugin C2 loader", ["45.13.237.28", "755887388", "/replugin/code", "castle.telepanel.live"])

    if has_socket and has_recv and has_sendall and has_port and has_protocol:
        add("socket_c2_protocol", "TCP C2 protocol", ["REG:", "USER_TOKEN", "<END>", "recv", "sendall", "9999", "9998"])

    if known_ints and has_socket:
        add("int_ip_obfuscation", "Обфускация C2 IP через integer", [str(value) for value in known_ints] + [">>24", "&255"])

    ids = {item["id"] for item in findings}
    danger = bool(
        "c2_socket_exfil" in ids
        or "replugin_loader_c2" in ids and "remote_exec_backdoor" in ids
        or "socket_c2_protocol" in ids and "remote_exec_backdoor" in ids
        or "telegram_sensitive_file_read" in ids and ("remote_exec_backdoor" in ids or "c2_socket_exfil" in ids)
    )
    meta = _parse_meta(source)
    sha = hashlib.sha256(source.encode("utf-8", "ignore")).hexdigest()
    return {
        "path": path,
        "sha256": sha,
        "plugin_id": meta.get("id", ""),
        "plugin_name": meta.get("name", "Unknown"),
        "plugin_version": meta.get("version", ""),
        "verdict": "danger" if danger else ("watch" if findings else "safe"),
        "summary": "Найдены точные признаки RAT/C2, файл помещён в карантин." if danger else "Точных RAT/C2 признаков нет.",
        "findings": findings,
        "can_quarantine": danger,
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


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


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
            for name in list(os.listdir(root))[:80]:
                low = name.lower()
                if low in ("__pycache__",) or low.startswith("."):
                    continue
                full = os.path.join(root, name)
                if os.path.isdir(full) and ("plugin" in low or low in ("nextgen", "viruskiller")):
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
        try:
            entries = list(os.listdir(directory))[:MAX_FILES_PER_PASS]
        except Exception:
            continue
        for name in entries:
            path = os.path.abspath(os.path.join(directory, name))
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
    findings = 0
    quarantined = 0
    scanned = 0
    for path in _iter_plugin_files():
        try:
            sha = _sha256_file(path)
        except Exception:
            continue
        seen = _state.setdefault("seen", {}).get(path)
        if isinstance(seen, dict) and seen.get("sha256") == sha and seen.get("verdict") in ("safe", "watch", "quarantined"):
            continue
        try:
            source = _read_source(path)
            result = _scan_source(source, path)
            result["sha256"] = sha
        except Exception as exc:
            _state.setdefault("seen", {})[path] = {"sha256": sha, "verdict": "skip", "ts": int(time.time()), "error": str(exc)[:120]}
            continue
        scanned += 1
        verdict = result.get("verdict", "safe")
        _state.setdefault("seen", {})[path] = {"sha256": sha, "verdict": verdict, "ts": int(time.time())}
        if verdict == "danger" and result.get("can_quarantine"):
            findings += 1
            ok = _quarantine(path, result)
            if ok:
                quarantined += 1
            _show_detection_alert(result, quarantined=ok)
        elif verdict == "watch":
            # Do not quarantine weak hits. Keep install/use flow untouched.
            pass
    _state["last_scan_ts"] = int(time.time())
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
