"""Build GreenPass.elyx and GreenPass.plugin into builds/, optionally publish a release.

Usage (from anywhere):
    python scripts/build_release.py            # build only
    python scripts/build_release.py --release  # build and publish release v<version> via GitHub CLI (gh)
"""
import glob
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDS = os.path.join(ROOT, "builds")
ELYB = "import sys; from elyb.cli import main; sys.argv[0] = 'elyb'; sys.exit(main())"


def run(cmd):
    print("> " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def plugin_version():
    with open(os.path.join(ROOT, "plugin", "meta.yml"), encoding="utf-8") as f:
        match = re.search(r'^version:\s*["\']?([^"\'\s]+)', f.read(), re.M)
    if not match:
        raise SystemExit("version not found in plugin/meta.yml")
    return match.group(1)


def main():
    publish = "--release" in sys.argv[1:]
    version = plugin_version()
    tag = "v" + version
    os.makedirs(BUILDS, exist_ok=True)
    for old in glob.glob(os.path.join(BUILDS, "GreenPass*")):
        os.remove(old)

    run([sys.executable, "-c", ELYB, "build", "--ast", "-nf"])
    built = glob.glob(os.path.join(BUILDS, "GreenPass-%s*.eaf" % version))
    if len(built) != 1:
        raise SystemExit("expected one ElyxBuilder archive in builds/, got: %s" % built)
    elyx = os.path.join(BUILDS, "GreenPass.elyx")
    shutil.move(built[0], elyx)

    legacy = os.path.join(BUILDS, "GreenPass.plugin")
    run([sys.executable, os.path.join("scripts", "build_legacy_plugin.py"), "plugin", legacy])

    print("\nBuilt GreenPass %s:\n  %s\n  %s" % (version, elyx, legacy))

    if not publish:
        return
    if shutil.which("gh") is None:
        raise SystemExit("GitHub CLI (gh) not found: install it from https://cli.github.com and run 'gh auth login'")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                            capture_output=True, text=True).stdout.strip()
    notes = os.path.join("release-notes", tag + ".md")
    notes_args = ["--notes-file", notes] if os.path.isfile(os.path.join(ROOT, notes)) else ["--generate-notes"]
    run(["gh", "release", "create", tag, elyx, legacy, "--target", commit,
         "--title", "GreenPass " + version] + notes_args)


if __name__ == "__main__":
    main()
