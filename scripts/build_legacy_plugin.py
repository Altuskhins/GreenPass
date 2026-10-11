"""Flatten plugin/ (Elyx sources) into a single-file legacy GreenPass.plugin,
mirroring the layout of upstream Altuskhins/GreenPass GreenPass.plugin.

Usage: python scripts/build_legacy_plugin.py plugin builds/GreenPass.plugin
"""
import ast, re, sys, os

SRC = sys.argv[1]            # .../plugin
OUT = sys.argv[2]
DEFERRED = {"greenpass.webproxy", "greenpass.tgws_cf_h2"}   # appended after the plugin class (see below)

REL_IMPORT = re.compile(r"^from (\.+)([\w.]*) import (.+)$")
ELYX_IMPORT = "try:\n    from elyx import get_environment as _elyx_get_environment\nexcept:\n    _elyx_get_environment = None\n"
META_LINE = re.compile(r"^__(id|name|description|author|version|icon|app_version|sdk_version|min_version)__ = ")

emitted = set()
out = []


def mod_path(mod):
    return os.path.join(SRC, *mod.split(".")) + ".py"


def resolve(current, dots, name):
    pkg = current.split(".")[:-1]
    if len(dots) > 1:
        pkg = pkg[: len(pkg) - (len(dots) - 1)]
    return ".".join([p for p in pkg + ([name] if name else []) if p])


def emit_import(target, names):
    # "from .pkg import submodule as alias" -> inline the submodule
    if os.path.isdir(os.path.join(SRC, *target.split("."))):
        for name in names.split(","):
            emit_import(target + "." + name.split(" as ")[0].strip(), "*")
        return
    if target not in DEFERRED:
        emit_module(target)


def emit_module(mod, strip_meta=False):
    if mod in emitted:
        return
    emitted.add(mod)
    text = open(mod_path(mod), encoding="utf-8").read()
    text = text.replace(ELYX_IMPORT, "_elyx_get_environment = None\n")
    if mod == "greenpass.tgws_cf_h2":
        # HTTP/2 is optional in legacy installs where the app cannot install
        # Elyx requirements. Keep the plugin importable and let TG-WS fall back
        # to WebSocket if httpx/h2 are absent.
        out.append("# --- optional bundled from %s.py ---\ntry:\n" % mod)
        out.extend("    " + line if line.strip() else line
                   for line in text.splitlines(keepends=True))
        out.append("except ImportError:\n    pass\n\n")
        return
    out.append("# --- bundled from %s.py ---\n" % mod)
    for line in text.splitlines(keepends=True):
        m = REL_IMPORT.match(line.rstrip("\n"))
        if m:
            emit_import(resolve(mod, m.group(1), m.group(2)), m.group(3))
            continue
        if strip_meta and META_LINE.match(line):
            continue
        out.append(line)
    if not out[-1].endswith("\n"):
        out.append("\n")
    out.append("\n")


# main.py: inline its package imports, drop the _foundation re-exports.
main = open(os.path.join(SRC, "main.py"), encoding="utf-8").read()
out.append("# --- bundled from main.py ---\n")
body = []
for line in main.splitlines(keepends=True):
    s = line.rstrip("\n")
    m = REL_IMPORT.match(s)
    if m:
        emit_import(resolve("main", m.group(1), m.group(2)), m.group(3))
        continue
    if re.match(r"^__\w+__ = _foundation\.__\w+__$", s):
        continue
    body.append(line.replace("_foundation.__name__", "__name__"))
if "_foundation" in "".join(body):
    raise SystemExit("unhandled _foundation reference in main.py")
out.append("# --- main.py ---\n")
out.extend(body)
if not out[-1].endswith("\n"):
    out.append("\n")
out.append("\n")
# WebProxyNativePlugin is also a BasePlugin subclass: define it after
# SafeBypassPlugin so the loader picks GreenPass, and drop its own metadata so
# it cannot override GreenPass's __id__/__name__/__version__.
for mod in sorted(DEFERRED):
    emit_module(mod, strip_meta=True)

result = "".join(out).rstrip() + "\n"
ast.parse(result)
open(OUT, "w", encoding="utf-8", newline="\n").write(result)
print("wrote", OUT, len(result.encode("utf-8")), "bytes;", "modules:", len(emitted))
