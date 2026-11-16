"""Build the single-file GreenPass.plugin from plugin/.

The plugin's modules stay separate modules: their sources are embedded in a dict
and served by a small import hook under a package name unique to this build, so
a reloaded or updated plugin never picks up modules from the previous one.
The core bundles from plugin/greenpass/core/ are appended as "#GPCORE:<abi>:"
base64 comment lines, which core.py reads back from the plugin file.

    python scripts/build_plugin.py plugin GreenPass.plugin
"""

import ast
import base64
import os
import re
import sys

SRC, OUT = sys.argv[1], sys.argv[2]
PKG_DIR = os.path.join(SRC, "greenpass")
CORE_DIR = os.path.join(PKG_DIR, "core")
META_NAMES = ("__id__", "__name__", "__description__", "__author__", "__version__", "__icon__",
              "__app_version__", "__sdk_version__")
SKIP = {"__pycache__", "core"}


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


meta_src = read(os.path.join(PKG_DIR, "meta.py"))
build = int(re.search(r"(?m)^GREENPASS_BUILD\s*=\s*(\d+)\s*$", meta_src).group(1))
package = "_greenpass_b%d" % build

# Metadata first, as literal assignments the client can read without running code.
meta_values = {}
for node in ast.parse(meta_src).body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in META_NAMES:
        meta_values[node.targets[0].id] = ast.literal_eval(node.value)
missing = [n for n in META_NAMES if n not in meta_values]
if missing:
    raise SystemExit("meta.py lacks %s" % missing)

sources = {}
for root, dirs, files in os.walk(PKG_DIR):
    dirs[:] = sorted(d for d in dirs if d not in SKIP)
    for name in sorted(files):
        if not name.endswith(".py"):
            continue
        path = os.path.join(root, name)
        rel = os.path.relpath(path, SRC).replace(os.sep, "/")[:-3]
        module = rel.replace("/", ".")
        if module.endswith(".__init__"):
            module = module[:-len(".__init__")]
        text = read(path)
        compile(text, path, "exec")
        sources[module] = (text, name == "__init__.py")
for package_name in {m.rsplit(".", 1)[0] for m in sources if "." in m}:
    sources.setdefault(package_name, ("", True))

main = read(os.path.join(SRC, "main.py"))
main = re.sub(r"(?m)^(\s*)from \.greenpass\b", r"\1from %s.greenpass" % package, main)
main = main.replace("from .greenpass import", "from %s.greenpass import" % package)
if re.search(r"(?m)^\s*from \.", main):
    raise SystemExit("main.py has a relative import the builder does not handle")

out = []
for name in META_NAMES:
    out.append("%s = %r\n" % (name, meta_values[name]))
out.append("GREENPASS_BUILD = %d\n\n" % build)
out.append('''
import importlib.abc as _gp_abc
import importlib.util as _gp_util
import sys as _gp_sys

_GP_PACKAGE = %r
_GP_SOURCES = {
''' % package)
for module in sorted(sources):
    text, is_package = sources[module]
    out.append("    %r: (%r, %r),\n" % (package + "." + module, text, is_package))
out.append('''}
_GP_SOURCES[_GP_PACKAGE] = ("", True)


class _GreenPassImporter(_gp_abc.MetaPathFinder, _gp_abc.Loader):
    """Serves this build's modules from _GP_SOURCES."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in _GP_SOURCES:
            return None
        return _gp_util.spec_from_loader(fullname, self, is_package=_GP_SOURCES[fullname][1])

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        source, is_package = _GP_SOURCES[module.__name__]
        module.__file__ = __file__
        if is_package:
            module.__path__ = []
        exec(compile(source, __file__, "exec"), module.__dict__)


for _gp_name in [n for n in _gp_sys.modules if n == _GP_PACKAGE or n.startswith(_GP_PACKAGE + ".")]:
    del _gp_sys.modules[_gp_name]
_gp_sys.meta_path[:] = [f for f in _gp_sys.meta_path if type(f).__name__ != "_GreenPassImporter"]
_gp_sys.meta_path.insert(0, _GreenPassImporter())

# --- main.py ---
''')
out.append(main.rstrip() + "\n")

core_lines = 0
if os.path.isdir(CORE_DIR):
    out.append("\n# Embedded GreenPass core (read by greenpass/core.py from this file).\n")
    abi_by_file = {"libgreenpass.so.xz": "arm64-v8a", "libgreenpass-armeabi-v7a.so.xz": "armeabi-v7a"}
    for name, abi in sorted(abi_by_file.items()):
        path = os.path.join(CORE_DIR, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(57 * 1024)
                if not chunk:
                    break
                out.append("#GPCORE:%s:%s\n" % (abi, base64.b64encode(chunk).decode("ascii")))
                core_lines += 1

result = "".join(out)
ast.parse(result)
with open(OUT, "w", encoding="utf-8", newline="\n") as handle:
    handle.write(result)
print("wrote %s: %d bytes, %d modules, %d core lines, package %s"
      % (OUT, len(result.encode("utf-8")), len(sources), core_lines, package))
