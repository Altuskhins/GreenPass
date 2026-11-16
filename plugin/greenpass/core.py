"""The native GreenPass core (libgreenpass.so: sing-box-extended, mihomo, AWG, olcRTC).

The core ships inside the plugin as an .xz bundle: as a file next to this module
in the .elyx build, and as base64 comment lines in the single-file .plugin build.
On load it is unpacked once into the app's files dir and verified by hash.

All modes share one Go runtime: StartCore(json) starts whatever the JSON
describes and replaces the previous instance.
"""

import base64
import ctypes
import hashlib
import json
import lzma
import os
import struct
import sys
import threading
import types

BUNDLES = {
    "arm64-v8a": {
        "file": "libgreenpass.so.xz",
        "so_size": 126646176,
        "so_sha256": "da0db309d4d118d03b4797c8a097c8bdb7dbf3ce168d91f4a0af6248af7b389a",
        "bundle_size": 25513204,
        "bundle_sha256": "b43ef0257bf3a53fe984ceee284d2a1893d4a3bc2fd7876c6b39c90819db9ca4",
    },
    "armeabi-v7a": {
        "file": "libgreenpass-armeabi-v7a.so.xz",
        "so_size": 115947844,
        "so_sha256": "3cef15595ec068aad8b777c8cb8b01d3efbb1fff52b9168734209a574970c349",
        "bundle_size": 26078408,
        "bundle_sha256": "d58d9c8fe7834d9f780ee3cee9b47ca4c3503e6ccd525f8018726341bef9fe2b",
    },
}
SO_FILE = "libgreenpass.so"
MODULES_DIR = "greenpass_modules"
# The .plugin build appends the bundle as lines "#GPCORE:<abi>:<base64>".
EMBED_PREFIX = "#GPCORE:"
LEGACY_FILES = ("libvless.so", "libawg_proxy.so", "libzvonki.so")

STATUS_CURRENT = "current"
STATUS_MISSING = "missing"
STATUS_OUTDATED = "outdated"


def native_abi(machine=None, pointer_size=None):
    if machine is None:
        try:
            machine = os.uname().machine
        except Exception:
            machine = ""
    if pointer_size is None:
        pointer_size = struct.calcsize("P")
    machine = str(machine or "").lower()
    if "arm" not in machine and "aarch" not in machine:
        return ""
    return "arm64-v8a" if int(pointer_size) >= 8 else "armeabi-v7a"


# State that must survive plugin reloads inside one app process: the library can
# be loaded only once, so a core installed after that needs an app restart.
def _process_state():
    name = "_greenpass_process_state"
    state = sys.modules.get(name)
    if state is None:
        state = types.ModuleType(name)
        state.lib = None
        state.lib_lock = threading.RLock()
        state.blocked = False
        sys.modules[name] = state
    if not hasattr(state, "lib"):
        state.lib = None
        state.lib_lock = threading.RLock()
    return state


_STATE = _process_state()


def _sha256_file(path, limit):
    hasher = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return "", total
            hasher.update(chunk)
    return hasher.hexdigest(), total


class _EmbeddedBundle:
    """Reads the bundled .xz either from a file or from base64 lines in the plugin file."""

    def __init__(self, bundle, abi, package_dir, plugin_file):
        self.bundle = bundle
        self.abi = abi
        self.file_path = os.path.join(package_dir, "core", bundle["file"]) if bundle else ""
        self.plugin_file = plugin_file

    def available(self):
        if not self.bundle:
            return False
        if os.path.isfile(self.file_path):
            return True
        return self._has_lines()

    def _has_lines(self):
        prefix = EMBED_PREFIX + self.abi + ":"
        try:
            with open(self.plugin_file, "r", encoding="utf-8") as handle:
                return any(line.startswith(prefix) for line in handle)
        except Exception:
            return False

    def chunks(self):
        """Yields the compressed bytes."""
        if os.path.isfile(self.file_path):
            with open(self.file_path, "rb") as handle:
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        return
                    yield chunk
        prefix = EMBED_PREFIX + self.abi + ":"
        with open(self.plugin_file, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith(prefix):
                    yield base64.b64decode(line[len(prefix):].strip())


class Core:
    """Owns libgreenpass.so: install from the bundle, load, and call it."""

    def __init__(self, files_dir, package_dir, plugin_file):
        self.abi = native_abi()
        self.bundle = BUNDLES.get(self.abi, {})
        self.dir = os.path.join(str(files_dir), MODULES_DIR)
        self.so_path = os.path.join(self.dir, SO_FILE)
        self._stamp_path = self.so_path + ".stamp"
        self._embedded = _EmbeddedBundle(self.bundle, self.abi, package_dir, plugin_file)
        self._install_lock = threading.Lock()
        self._free = None
        self.restart_required = False

    # --- install ---

    def status(self):
        """current / outdated / missing, from the size and a stamp written at install."""
        if not self.bundle:
            return STATUS_MISSING
        try:
            stat = os.stat(self.so_path)
        except OSError:
            return STATUS_MISSING
        if stat.st_size < 1024:
            return STATUS_MISSING
        if stat.st_size != self.bundle["so_size"]:
            return STATUS_OUTDATED
        try:
            with open(self._stamp_path, "r", encoding="utf-8") as handle:
                stamp = json.load(handle)
            if (stamp.get("sha256") == self.bundle["so_sha256"]
                    and stamp.get("mtime_ns") == stat.st_mtime_ns
                    and stamp.get("size") == stat.st_size):
                return STATUS_CURRENT
        except Exception:
            pass
        # No stamp (installed by the old plugin): hash once and stamp it.
        digest, size = _sha256_file(self.so_path, self.bundle["so_size"])
        if size == self.bundle["so_size"] and digest == self.bundle["so_sha256"]:
            self._write_stamp()
            return STATUS_CURRENT
        return STATUS_OUTDATED

    def _write_stamp(self):
        try:
            stat = os.stat(self.so_path)
            with open(self._stamp_path, "w", encoding="utf-8") as handle:
                json.dump({"sha256": self.bundle["so_sha256"], "size": stat.st_size,
                           "mtime_ns": stat.st_mtime_ns}, handle)
        except Exception:
            pass

    def install(self, on_progress=None):
        """Unpack the embedded core if the installed one is missing or another build.

        Returns True when the right core is on disk. If an older core is already
        loaded in this process, the new one waits for an app restart.
        """
        with self._install_lock:
            if self.status() == STATUS_CURRENT:
                return True
            if not self._embedded.available():
                return False
            os.makedirs(self.dir, exist_ok=True)
            tmp = self.so_path + ".tmp"
            try:
                self._unpack(tmp, on_progress)
                os.replace(tmp, self.so_path)
            except Exception:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                return False
            self._write_stamp()
            if _STATE.lib is not None:
                self.restart_required = True
                _STATE.blocked = True
            for name in LEGACY_FILES:
                try:
                    os.remove(os.path.join(self.dir, name))
                except OSError:
                    pass
            return True

    def _unpack(self, target, on_progress):
        bundle = self.bundle
        bundle_hash = hashlib.sha256()
        so_hash = hashlib.sha256()
        packed = unpacked = 0
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        with open(target, "wb") as out:
            for chunk in self._embedded.chunks():
                packed += len(chunk)
                if packed > bundle["bundle_size"]:
                    raise ValueError("core bundle too large")
                bundle_hash.update(chunk)
                data = decompressor.decompress(chunk)
                unpacked += len(data)
                if unpacked > bundle["so_size"]:
                    raise ValueError("core library too large")
                so_hash.update(data)
                out.write(data)
                if on_progress is not None:
                    on_progress(min(1.0, unpacked / float(bundle["so_size"])))
            out.flush()
            os.fsync(out.fileno())
        if bundle_hash.hexdigest() != bundle["bundle_sha256"]:
            raise ValueError("core bundle checksum mismatch")
        if unpacked != bundle["so_size"] or so_hash.hexdigest() != bundle["so_sha256"]:
            raise ValueError("core library checksum mismatch")

    # --- native calls ---

    def available(self):
        return self._lib() is not None

    def _lib(self):
        with _STATE.lib_lock:
            if _STATE.lib is not None:
                return _STATE.lib
            if _STATE.blocked or self.status() != STATUS_CURRENT:
                return None
            lib = _dlopen(self.so_path)
            if lib is None:
                return None
            lib.StartCore.argtypes = [ctypes.c_char_p]
            lib.StartCore.restype = ctypes.c_void_p
            lib.StopCore.argtypes = []
            lib.StopCore.restype = None
            for name in ("LastLog", "LastError", "GetStatusJSON", "GetLogsJSON", "CurrentEngine", "Version"):
                try:
                    func = getattr(lib, name)
                    func.argtypes = []
                    func.restype = ctypes.c_void_p
                except AttributeError:
                    pass
            for name, argtypes, restype in (("IsRunning", [], ctypes.c_int),
                                            ("ValidateConfig", [ctypes.c_char_p], ctypes.c_void_p),
                                            ("FreeCString", [ctypes.c_void_p], None)):
                try:
                    func = getattr(lib, name)
                    func.argtypes = argtypes
                    func.restype = restype
                except AttributeError:
                    pass
            _STATE.lib = lib
            return lib

    def _take_string(self, lib, pointer):
        if not pointer:
            return ""
        try:
            raw = ctypes.cast(pointer, ctypes.c_char_p).value
            return raw.decode("utf-8", errors="ignore") if raw else ""
        finally:
            try:
                lib.FreeCString(pointer)
            except Exception:
                pass

    def start(self, config):
        """Start the core with a config dict or JSON text. Returns "" or an error."""
        lib = self._lib()
        if lib is None:
            return "Ядро GreenPass не загружено"
        text = config if isinstance(config, str) else json.dumps(config)
        try:
            with _STATE.lib_lock:
                return self._take_string(lib, lib.StartCore(text.encode("utf-8")))
        except Exception as exc:
            return str(exc)

    def stop(self):
        lib = _STATE.lib
        if lib is None:
            return
        try:
            with _STATE.lib_lock:
                lib.StopCore()
        except Exception:
            pass

    def is_running(self):
        lib = _STATE.lib
        try:
            return bool(lib is not None and int(lib.IsRunning()))
        except Exception:
            return False

    def validate(self, config):
        lib = self._lib()
        if lib is None or not hasattr(lib, "ValidateConfig"):
            return None
        text = config if isinstance(config, str) else json.dumps(config)
        try:
            with _STATE.lib_lock:
                return self._take_string(lib, lib.ValidateConfig(text.encode("utf-8")))
        except Exception as exc:
            return str(exc)

    def _text(self, name):
        lib = _STATE.lib
        if lib is None or not hasattr(lib, name):
            return ""
        try:
            with _STATE.lib_lock:
                return self._take_string(lib, getattr(lib, name)())
        except Exception:
            return ""

    def last_log(self):
        return self._text("LastLog")

    def last_error(self):
        return self._text("LastError")

    def status_json(self):
        return self._text("GetStatusJSON")

    def logs_json(self):
        return self._text("GetLogsJSON")

    def version(self):
        return self._text("Version")


def _dlopen(path):
    """Load with RTLD_NOW|RTLD_GLOBAL; on Android 10+ through android_dlopen_ext with
    a file descriptor, which works for libraries outside the app's lib dir."""
    flags = 2 | 0x100
    try:
        from android.os import Build
        if int(Build.VERSION.SDK_INT) >= 29:
            libdl = ctypes.CDLL("libdl.so")
            open_ext = libdl.android_dlopen_ext

            class ExtInfo(ctypes.Structure):
                _fields_ = [
                    ("flags", ctypes.c_uint64),
                    ("reserved_addr", ctypes.c_void_p),
                    ("reserved_size", ctypes.c_size_t),
                    ("relro_fd", ctypes.c_int),
                    ("library_fd", ctypes.c_int),
                    ("library_fd_offset", ctypes.c_uint64),
                    ("library_namespace", ctypes.c_void_p),
                ]

            open_ext.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ExtInfo)]
            open_ext.restype = ctypes.c_void_p
            fd = os.open(path, os.O_RDONLY)
            try:
                info = ExtInfo(flags=0x10, library_fd=fd)          # ANDROID_DLEXT_USE_LIBRARY_FD
                handle = open_ext(path.encode("utf-8"), flags, ctypes.byref(info))
                if handle:
                    return ctypes.CDLL(path, handle=handle)
            finally:
                os.close(fd)
    except Exception:
        pass
    try:
        return ctypes.CDLL(path, mode=flags)
    except Exception:
        return None
