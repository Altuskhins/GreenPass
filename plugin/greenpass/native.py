from .foundation import *
from .protocols import _build_singbox_awg_config

class _NativeLinker:
    def __init__(self):
        self.libdl = None
        self.open_ext = None
        self.Info = None
        try:
            self.libdl = ctypes.CDLL("libdl.so")
            self.open_ext = self.libdl.android_dlopen_ext

            class Info(ctypes.Structure):
                _fields_ = [
                    ("flags", ctypes.c_uint64),
                    ("reserved_addr", ctypes.c_void_p),
                    ("reserved_size", ctypes.c_size_t),
                    ("relro_fd", ctypes.c_int),
                    ("library_fd", ctypes.c_int),
                    ("library_fd_offset", ctypes.c_uint64),
                    ("library_namespace", ctypes.c_void_p),
                ]

            self.Info = Info
            self.open_ext.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(self.Info)]
            self.open_ext.restype = ctypes.c_void_p
        except:
            self.open_ext = None

    def load(self, path):
        try:
            p = str(path or "")
        except:
            p = ""
        if not p or not os.path.exists(p):
            return None

        try:
            from android.os import Build
            if int(Build.VERSION.SDK_INT) >= 29 and self.open_ext and self.Info:
                fd = os.open(p, os.O_RDONLY)
                try:
                    info = self.Info(flags=0x10, library_fd=fd)
                    handle = self.open_ext(p.encode("utf-8"), 2 | 0x100, ctypes.byref(info))
                    if handle:
                        return ctypes.CDLL(p, handle=handle)
                finally:
                    try:
                        os.close(fd)
                    except:
                        pass
        except:
            pass

        try:
            return ctypes.CDLL(p, mode=2 | 0x100)
        except:
            return None


_GP_PROCESS_STATE_MODULE = "_greenpass_process_state"
_GP_PROCESS_STATE = sys.modules.get(_GP_PROCESS_STATE_MODULE)
if _GP_PROCESS_STATE is None:
    _GP_PROCESS_STATE = types.ModuleType(_GP_PROCESS_STATE_MODULE)
    sys.modules[_GP_PROCESS_STATE_MODULE] = _GP_PROCESS_STATE
# The state module outlives plugin reloads (it lives in sys.modules), so every
# field is added only when missing: an older module object may already exist.
for _gp_name, _gp_default in (
    ("go_core_blocked", False),
    # True once ANY plugin instance dlopen'd libgreenpass.so in this process.
    ("go_core_loaded", False),
    # (st_dev, st_ino) of the loaded library, and its path.
    ("go_core_id", None),
    ("go_core_path", ""),
    # Which mode ("vless" / "awg" / "olcrtc") last started the shared Go runtime.
    ("core_owner", ""),
    # StartCore calls currently in flight (crash-loop marker bookkeeping).
    ("start_inflight", 0),
):
    if not hasattr(_GP_PROCESS_STATE, _gp_name):
        setattr(_GP_PROCESS_STATE, _gp_name, _gp_default)
if not hasattr(_GP_PROCESS_STATE, "go_core_lock"):
    _GP_PROCESS_STATE.go_core_lock = threading.Lock()
# ONE lock for the one Go runtime. Lock order (outermost first):
#   _vless_transition_lock -> _GP_NATIVE_LOCK (this) -> _GP_GO_CORE_LOCK (bookkeeping only)
# Native calls made while holding this lock never call back into the plugin, so it is a
# leaf with respect to every plugin lock; never take a plugin lock while holding it.
if not hasattr(_GP_PROCESS_STATE, "native_lock"):
    _GP_PROCESS_STATE.native_lock = threading.RLock()
_GP_GO_CORE_LOCK = _GP_PROCESS_STATE.go_core_lock
_GP_NATIVE_LOCK = _GP_PROCESS_STATE.native_lock
GP_NATIVE_READ_LOCK_TIMEOUT_SEC = 3.0
GP_NATIVE_READ_LOCK_UI_TIMEOUT_SEC = 0.3


def _gp_native_read_timeout():
    # The UI thread must never sit behind a long StartCore for more than a blink.
    try:
        if _gp_is_ui_thread():
            return min(float(GP_NATIVE_READ_LOCK_UI_TIMEOUT_SEC), float(GP_NATIVE_READ_LOCK_TIMEOUT_SEC))
    except Exception:
        pass
    return float(GP_NATIVE_READ_LOCK_TIMEOUT_SEC)
GP_CORE_START_MARKER_FILE = "core_start.json"
GP_CORE_START_MARKER_MAX_AGE_SEC = 86400.0


def _gp_set_go_core_blocked(value=True):
    with _GP_GO_CORE_LOCK:
        _GP_PROCESS_STATE.go_core_blocked = bool(value)


def _gp_claim_go_core(kind):
    """All modes share libgreenpass.so and its single Go runtime."""
    with _GP_GO_CORE_LOCK:
        if bool(getattr(_GP_PROCESS_STATE, "go_core_blocked", False)):
            return False
        return True


def _gp_file_id(path):
    try:
        st = os.stat(str(path))
        return (int(st.st_dev), int(st.st_ino))
    except Exception:
        return None


def _gp_core_loaded_in_process():
    """True when some plugin instance already runs a Go runtime in this process."""
    return bool(getattr(_GP_PROCESS_STATE, "go_core_loaded", False))


def _gp_core_load_allowed(path):
    """A second Go runtime in one process crashes it. Once a library is loaded, only
    that very file (same device+inode) may be loaded again; anything else, such as
    an updated library that replaced the file, needs an app restart."""
    with _GP_GO_CORE_LOCK:
        if not bool(getattr(_GP_PROCESS_STATE, "go_core_loaded", False)):
            return True
        loaded_id = getattr(_GP_PROCESS_STATE, "go_core_id", None)
        current_id = _gp_file_id(path)
        return bool(loaded_id is not None and current_id is not None and tuple(loaded_id) == tuple(current_id))


def _gp_note_core_loaded(path):
    with _GP_GO_CORE_LOCK:
        if not bool(getattr(_GP_PROCESS_STATE, "go_core_loaded", False)):
            _GP_PROCESS_STATE.go_core_loaded = True
            _GP_PROCESS_STATE.go_core_id = _gp_file_id(path)
            _GP_PROCESS_STATE.go_core_path = str(path or "")


# ---- crash-loop guard: "a native StartCore is in progress" marker ----
# A Go panic inside StartCore kills the whole process, and the plugin would then
# auto-start the same node on the next launch. The marker is written (and fsync'd)
# before StartCore and removed when it returns; if it is still there at the next
# load, the previous process died inside StartCore.

def _gp_start_marker_path(so_path):
    try:
        return os.path.join(os.path.dirname(str(so_path or "")) or ".", GP_CORE_START_MARKER_FILE)
    except Exception:
        return GP_CORE_START_MARKER_FILE


def _gp_start_marker_begin(so_path, kind):
    try:
        with _GP_GO_CORE_LOCK:
            _GP_PROCESS_STATE.start_inflight = int(getattr(_GP_PROCESS_STATE, "start_inflight", 0) or 0) + 1
        path = _gp_start_marker_path(so_path)
        tmp = "%s.%d.tmp" % (path, threading.get_ident())
        with open(tmp, "w") as handle:
            json.dump({"kind": str(kind or ""), "pid": int(os.getpid()), "ts": float(time.time())}, handle)
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
    except Exception:
        pass


def _gp_start_marker_end(so_path):
    try:
        with _GP_GO_CORE_LOCK:
            left = max(0, int(getattr(_GP_PROCESS_STATE, "start_inflight", 0) or 0) - 1)
            _GP_PROCESS_STATE.start_inflight = left
        if left == 0:
            try:
                os.remove(_gp_start_marker_path(so_path))
            except OSError:
                pass
    except Exception:
        pass


def _gp_consume_crashed_start_marker(so_path, now=None, pid=None):
    """At plugin load: return the marker dict when a previous process died inside
    StartCore (and delete the file), else None. A marker written by this very
    process is a start still in flight (plugin reload), not a crash."""
    path = _gp_start_marker_path(so_path)
    try:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as handle:
                data = json.load(handle)
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        current_pid = int(os.getpid() if pid is None else pid)
        try:
            marker_pid = int(data.get("pid", 0) or 0)
        except Exception:
            marker_pid = 0
        if marker_pid and marker_pid == current_pid:
            return None
        try:
            os.remove(path)
        except OSError:
            pass
        try:
            ts = float(data.get("ts", 0) or 0)
            # No readable timestamp: treat it as recent rather than silently ignoring it.
            age = (float(time.time() if now is None else now) - ts) if ts > 0 else 0.0
        except Exception:
            age = 0.0
        if age > GP_CORE_START_MARKER_MAX_AGE_SEC:
            return None
        return {"kind": str(data.get("kind", "") or ""), "ts": float(data.get("ts", 0) or 0), "pid": marker_pid}
    except Exception:
        return None


class VlessCore:
    def __init__(self, so_path, kind=""):
        self.lib = None
        self.libc = None
        self.free_c_string = None
        self.mode = None
        self.load_error = ""
        # The Go runtime is one per process, so one lock covers all wrappers.
        self._native_lock = _GP_NATIVE_LOCK
        self._so_path = str(so_path or "")
        self._kind = str(kind or "")
        self._init_native()

    def _init_native(self):
        try:
            if not self._so_path or (not os.path.exists(self._so_path)) or os.path.getsize(self._so_path) < 1024:
                return
            if not _gp_core_load_allowed(self._so_path):
                # Another Go runtime already runs here and the file is not the one it
                # was loaded from: mapping this one would start a second runtime.
                self.load_error = "restart_required"
                _gp_set_go_core_blocked(True)
                return
            linker = _NativeLinker()
            lib = linker.load(self._so_path)
            if not lib:
                return
            _gp_note_core_loaded(self._so_path)
            lib.StartCore.argtypes = [ctypes.c_char_p]
            lib.StartCore.restype = ctypes.c_void_p
            lib.StopCore.argtypes = []
            lib.StopCore.restype = None
            try:
                lib.FreeCString.argtypes = [ctypes.c_void_p]
                lib.FreeCString.restype = None
                self.free_c_string = lib.FreeCString
            except:
                self.free_c_string = None
            try:
                lib.LastLog.argtypes = []
                lib.LastLog.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.LastError.argtypes = []
                lib.LastError.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.GetStatusJSON.argtypes = []
                lib.GetStatusJSON.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.GetLogsJSON.argtypes = []
                lib.GetLogsJSON.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.Version.argtypes = []
                lib.Version.restype = ctypes.c_void_p
                self.mode = "singbox"
            except Exception as _e:
                pass
            try:
                lib.IsRunning.argtypes = []
                lib.IsRunning.restype = ctypes.c_int
            except:
                pass
            try:
                lib.CurrentEngine.argtypes = []
                lib.CurrentEngine.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.ValidateConfig.argtypes = [ctypes.c_char_p]
                lib.ValidateConfig.restype = ctypes.c_void_p
            except:
                pass
            self.lib = lib
            if not self.mode:
                self.mode = "standalone"
            try:
                self.libc = ctypes.CDLL("libc.so")
                self.libc.free.argtypes = [ctypes.c_void_p]
                self.libc.free.restype = None
            except:
                self.libc = None
        except Exception as _e:
            self.lib = None

    def _free_result_ptr(self, result_ptr):
        if not result_ptr:
            return
        try:
            if self.free_c_string:
                self.free_c_string(result_ptr)
                return
        except:
            pass
        try:
            if self.libc:
                self.libc.free(result_ptr)
        except:
            pass

    def is_available(self):
        return self.lib is not None

    def start(self, config_json):
        if not self.is_available():
            return "Native library not loaded"
        try:
            config_text = str(config_json or "")
            is_qwdtt = False
            try:
                is_qwdtt = str(json.loads(config_text).get("engine", "") or "").strip().lower() == QWDTT_KIND
            except:
                is_qwdtt = False
            _gp_start_marker_begin(self._so_path, self._kind)
            try:
                if is_qwdtt:
                    result_ptr = self.lib.StartCore(config_text.encode("utf-8"))
                else:
                    with self._native_lock:
                        result_ptr = self.lib.StartCore(config_text.encode("utf-8"))
            finally:
                _gp_start_marker_end(self._so_path)
            if not result_ptr:
                self._note_started(True)
                return ""
            try:
                raw = ctypes.cast(result_ptr, ctypes.c_char_p).value
                out = raw.decode("utf-8", errors="ignore") if raw else ""
            except:
                out = ""
            self._free_result_ptr(result_ptr)
            self._note_started(not out)
            return out
        except Exception as e:
            return str(e)

    def _note_started(self, ok):
        # core_owner lets stop() skip a StopCore that would kill another mode's tunnel.
        try:
            with _GP_GO_CORE_LOCK:
                _GP_PROCESS_STATE.core_owner = self._kind if ok else ""
        except Exception:
            pass

    def _read_c_string_func(self, name):
        if not self.is_available():
            return ""
        try:
            fn = getattr(self.lib, str(name or ""))
        except:
            return ""
        # Bounded wait: a status poll must not hang behind a long StartCore.
        if not self._native_lock.acquire(timeout=_gp_native_read_timeout()):
            return ""
        try:
            result_ptr = fn()
            if not result_ptr:
                return ""
            try:
                raw = ctypes.cast(result_ptr, ctypes.c_char_p).value
                out = raw.decode("utf-8", errors="ignore") if raw else ""
            except:
                out = ""
            self._free_result_ptr(result_ptr)
            return out
        except:
            return ""
        finally:
            self._native_lock.release()

    def last_log(self):
        return self._read_c_string_func("LastLog")

    def last_error(self):
        return self._read_c_string_func("LastError")

    def status_json(self):
        return self._read_c_string_func("GetStatusJSON")

    def logs_json(self):
        return self._read_c_string_func("GetLogsJSON")

    def current_engine(self):
        return self._read_c_string_func("CurrentEngine").strip().lower()

    def validate(self, config_json):
        if not self.is_available():
            return None
        try:
            fn = self.lib.ValidateConfig
        except:
            return None
        if not self._native_lock.acquire(timeout=_gp_native_read_timeout()):
            return None
        try:
            result_ptr = fn(str(config_json or "").encode("utf-8"))
            if not result_ptr:
                return ""
            try:
                raw = ctypes.cast(result_ptr, ctypes.c_char_p).value
                out = raw.decode("utf-8", errors="ignore") if raw else ""
            except:
                out = ""
            self._free_result_ptr(result_ptr)
            return out
        except Exception as exc:
            return str(exc)
        finally:
            self._native_lock.release()

    def is_running(self):
        if not self.is_available():
            return False
        try:
            return bool(int(self.lib.IsRunning()))
        except:
            return False

    def stop(self):
        if not self.is_available():
            return
        try:
            with self._native_lock:
                owner = str(getattr(_GP_PROCESS_STATE, "core_owner", "") or "")
                if self._kind and owner and owner != self._kind:
                    # Another mode owns the running core: its tunnel is not ours to stop.
                    return
                self.lib.StopCore()
                with _GP_GO_CORE_LOCK:
                    _GP_PROCESS_STATE.core_owner = ""
        except Exception as _e:
            pass


class _LazySingboxCore:
    """Lazy view of the shared GreenPass core used by sing-box modes."""
    def __init__(self, so_path):
        self._so_path = str(so_path or "")
        self._real = None

    def _ensure(self):
        if self._real is None:
            if not _gp_claim_go_core("vless"):
                return None
            self._real = VlessCore(self._so_path, kind="vless")
            if not self._real.is_available():
                self._real = None
        return self._real

    def _peek(self):
        # Read-only queries never dlopen the 120 MB library on the UI thread.
        if self._real is not None:
            return self._real
        if _gp_is_ui_thread():
            return None
        return self._ensure()

    def is_available(self) -> bool:
        if self._real is not None:
            return self._real.is_available()
        return False

    def start(self, config_json):
        core = self._ensure()
        if core is None:
            return "Ядро GreenPass не загружено"
        return core.start(config_json)

    def stop(self):
        if self._real is not None:
            self._real.stop()

    def logs_json(self):
        core = self._peek()
        return core.logs_json() if core is not None else ""

    def last_log(self):
        core = self._peek()
        return core.last_log() if core is not None else ""

    def last_error(self):
        core = self._peek()
        return core.last_error() if core is not None else ""

    def status_json(self):
        core = self._peek()
        return core.status_json() if core is not None else ""

    def current_engine(self):
        core = self._peek()
        return core.current_engine() if core is not None else ""

    def validate(self, config_json):
        core = self._peek()
        return core.validate(config_json) if core is not None else None

    def is_running(self):
        core = self._peek()
        return core.is_running() if core is not None else False

    @property
    def lib(self):
        core = self._peek()
        return core.lib if core is not None else None

    @property
    def mode(self):
        if self._real is not None:
            return self._real.mode
        return None


class _LazyAWGCore:
    """Lazy AWG view of the shared GreenPass core."""
    def __init__(self, so_path):
        self._so_path = str(so_path or "")
        self._real = None
        self.is_downloading = False
        self.started = False

    def _ensure(self):
        if self._real is None:
            if not _gp_claim_go_core("awg"):
                return None
            self._real = AWGCore(self._so_path)
            if not self._real.is_available():
                self._real = None
        return self._real

    def init_native(self, on_success=None, on_error=None):
        core = self._ensure()
        if core is None:
            if on_error:
                on_error("Ядро GreenPass не загружено")
            return
        return core.init_native(on_success=on_success, on_error=on_error)

    def is_available(self) -> bool:
        if self._real is not None:
            return self._real.is_available()
        return False

    def start(self, conf_text: str) -> str:
        core = self._ensure()
        if core is None:
            self.started = False
            return "Ядро GreenPass не загружено"
        err = core.start(conf_text)
        self.started = bool(getattr(core, "started", False))
        return err

    def stop(self):
        if self._real is not None:
            self._real.stop()
            self.started = bool(getattr(self._real, "started", False))
        else:
            self.started = False


class _LazyVlessCore:
    """Lazy olcRTC view of the shared GreenPass core."""
    def __init__(self, so_path):
        self._so_path = str(so_path or "")
        self._real = None

    def _ensure(self):
        if self._real is None:
            if not _gp_claim_go_core("olcrtc"):
                return None
            self._real = VlessCore(self._so_path, kind="olcrtc")
            if not self._real.is_available():
                self._real = None
        return self._real
    def start(self, config_json):
        core = self._ensure()
        if core is None:
            return "Ядро GreenPass не загружено"
        return core.start(config_json)

    def _peek(self):
        # Read-only queries never dlopen the 120 MB library on the UI thread.
        if self._real is not None:
            return self._real
        if _gp_is_ui_thread():
            return None
        return self._ensure()

    def is_available(self) -> bool:
        return self._real is not None and self._real.is_available()
    def stop(self):
        if self._real is not None:
            self._real.stop()
    def status_json(self):
        core = self._peek()
        return core.status_json() if core is not None else ""

    @property
    def lib(self):
        core = self._peek()
        return core.lib if core is not None else None

    @property
    def mode(self):
        if self._real is not None:
            return self._real.mode
        return None

class AWGCore:
    def __init__(self, so_path):
        self.lib = None
        self.is_downloading = False
        self.started = False
        self._so_path = str(so_path or "")
        self._init_native()

    def _init_native(self):
        self._core = VlessCore(self._so_path, kind="awg")
        self.lib = self._core.lib

    def init_native(self, on_success=None, on_error=None):
        if self.is_available():
            if on_success: on_success()
            return
        if on_error:
            on_error("Ядро AWG не загружено")

    def is_available(self) -> bool:
        return self.lib is not None

    def start(self, conf_text: str) -> str:
        if not self.is_available(): return "Нативная библиотека еще не загружена"
        try:
            config = json.loads(_build_singbox_awg_config(conf_text, PROXY_PORT))
            experimental = config.get("experimental")
            experimental = dict(experimental) if isinstance(experimental, dict) else {}
            cache_file = experimental.get("cache_file")
            cache_file = dict(cache_file) if isinstance(cache_file, dict) else {}
            cache_file["path"] = os.path.join(os.path.dirname(self._so_path), "singbox-cache.db")
            experimental["cache_file"] = cache_file
            config["experimental"] = experimental
            config_json = json.dumps(config)
            err = self._core.start(config_json)
            if not err:
                self.started = True
            return err
        except Exception as e:
            return str(e)

    def stop(self):
        if self.is_available():
            if not bool(self.started):
                return
            try:
                self.started = False
                self._core.stop()
            except Exception:
                pass


def _check_vless_port(port, timeout=0.2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            return sock.connect_ex((VLESS_LOCAL_HOST, int(port))) == 0
    except:
        return False


def _wait_vless_port_closed(port, timeout_sec=1.5, poll_sec=0.1):
    try:
        target_port = int(port)
    except:
        return False

    deadline = time.time() + float(timeout_sec)
    while time.time() < deadline:
        if not _check_vless_port(target_port):
            return True
        time.sleep(float(poll_sec))
    return not _check_vless_port(target_port)


def _recv_socks_bytes(sock, size):
    data = b""
    while len(data) < int(size):
        chunk = sock.recv(int(size) - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def _check_vless_socks_auth(sock, username="", password=""):
    user = str(username or "")
    secret = str(password or "")
    method = b"\x02" if user and secret else b"\x00"
    sock.sendall(b"\x05\x01" + method)
    if _recv_socks_bytes(sock, 2) != b"\x05" + method:
        return False
    if method == b"\x02":
        user_bytes = user.encode("utf-8")[:255]
        pass_bytes = secret.encode("utf-8")[:255]
        sock.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
        auth = _recv_socks_bytes(sock, 2)
        if len(auth) != 2 or auth[1] != 0:
            return False
    return True


def _check_vless_socks_ready(port, timeout=0.5, username="", password=""):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            sock.connect((VLESS_LOCAL_HOST, int(port)))
            return _check_vless_socks_auth(sock, username, password)
    except:
        return False


def _check_vless_socks_connect(port, host, target_port, timeout=1.5, username="", password="", probe=b""):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            sock.connect((VLESS_LOCAL_HOST, int(port)))
            if not _check_vless_socks_auth(sock, username, password):
                return False

            try:
                host_bytes = socket.inet_aton(str(host or ""))
                req = b"\x05\x01\x00\x01" + host_bytes + int(target_port).to_bytes(2, "big")
            except:
                host_raw = str(host or "").encode("idna", errors="ignore")
                if not host_raw:
                    return False
                req = b"\x05\x01\x00\x03" + bytes([len(host_raw)]) + host_raw + int(target_port).to_bytes(2, "big")

            sock.sendall(req)
            head = _recv_socks_bytes(sock, 4)
            if len(head) < 4 or head[1] != 0x00:
                return False
            atyp = head[3]
            if atyp == 0x01:
                need = 4 + 2
            elif atyp == 0x03:
                size = _recv_socks_bytes(sock, 1)
                if len(size) != 1:
                    return False
                need = int(size[0]) + 2
            elif atyp == 0x04:
                need = 16 + 2
            else:
                return False
            remaining = b""
            while len(remaining) < need:
                chunk = _recv_socks_bytes(sock, need - len(remaining))
                if not chunk:
                    return False
                remaining += chunk
            if probe:
                sock.sendall(bytes(probe))
                return bool(sock.recv(1))
            return True
    except:
        return False


def _check_vless_tunnel_ready(port, timeout=1.5, username="", password=""):
    probe = b"HEAD /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"
    for host, target_port in list(VLESS_EGRESS_TEST_TARGETS or []):
        if _check_vless_socks_connect(port, host, target_port, timeout=timeout, username=username, password=password, probe=probe):
            return True
    return False


def _check_vless_telegram_route(port, timeout=1.5, username="", password=""):
    """Weaker check than _check_vless_tunnel_ready: SOCKS CONNECT to a Telegram DC only."""
    for host, target_port in list(VLESS_TELEGRAM_TEST_TARGETS or []):
        if _check_vless_socks_connect(port, host, target_port, timeout=timeout, username=username, password=password):
            return True
    return False


def _check_olcrtc_tunnel_ready(port, timeout=OLCRTC_TUNNEL_CHECK_TIMEOUT_SEC):
    for host, target_port in list(OLCRTC_TEST_TARGETS or []):
        if _check_vless_socks_connect(port, host, target_port, timeout=timeout):
            return True
    return False


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def _pick_tgws_port(preferred=None, excluded=None):
    used = set(int(x) for x in list(TGWS_RESERVED_PORTS or []))
    try:
        preferred_port = int(preferred or 0)
    except:
        preferred_port = 0
    if excluded:
        try:
            for value in excluded:
                try:
                    used.add(int(value))
                except:
                    pass
        except:
            pass
    if preferred_port > 0 and preferred_port not in used and _wait_vless_port_closed(preferred_port, timeout_sec=0.05, poll_sec=0.05):
        return preferred_port
    for _ in range(32):
        candidate = _get_free_port()
        if candidate in used:
            continue
        if _wait_vless_port_closed(candidate, timeout_sec=0.05, poll_sec=0.05):
            return int(candidate)
    return 0

__all__ = [name for name in globals() if not name.startswith("__")]
