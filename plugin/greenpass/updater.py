"""Plugin auto-update from GitHub releases.

Releases are ordered by build id (tag v<version>-b<build>). The new file is
downloaded to the cache dir, checked (plugin id, declared build equals the
tag's, GitHub's sha256 digest) and handed to exteraGram's own installer.
The builds carry the core, so downloads are streamed, not held in memory.
"""

import hashlib
import hmac
import json
import os
import re
import ssl
import urllib.request
import zipfile

from .meta import GREENPASS_BUILD, PLUGIN_ID, RELEASES_LATEST_URL, declared_build, release_build

ASSET_ELYX = "GreenPass.elyx"
ASSET_PLUGIN = "GreenPass.plugin"
MAX_ASSET_BYTES = 160 * 1024 * 1024
DOWNLOAD_PREFIX = "https://github.com/Altuskhins/GreenPass/releases/download/"
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "GreenPass-Updater",
           "X-GitHub-Api-Version": "2022-11-28"}


class UpdateError(Exception):
    pass


def latest_release():
    """(tag, assets) of the latest stable release."""
    request = urllib.request.Request(RELEASES_LATEST_URL, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
        raw = response.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise UpdateError("release info too large")
    release = json.loads(raw.decode("utf-8"))
    if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
        raise UpdateError("no stable release")
    tag = str(release.get("tag_name", "") or "").strip()
    if not tag or not isinstance(release.get("assets"), list):
        raise UpdateError("bad release info")
    return tag, release["assets"]


def _download(asset, path, on_progress=None):
    size = int(asset.get("size", 0) or 0)
    url = str(asset.get("browser_download_url", "") or "")
    if size < 1024 or size > MAX_ASSET_BYTES or not url.startswith(DOWNLOAD_PREFIX):
        raise UpdateError("unexpected asset")
    hasher = hashlib.sha256()
    total = 0
    tmp = path + ".tmp"
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "User-Agent": "GreenPass-Updater"})
    try:
        with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response, \
                open(tmp, "wb") as out:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise UpdateError("asset larger than announced")
                hasher.update(chunk)
                out.write(chunk)
                if on_progress is not None:
                    on_progress(total / float(size))
        if total != size:
            raise UpdateError("incomplete download")
        digest = str(asset.get("digest", "") or "").lower()
        if digest.startswith("sha256:") and not hmac.compare_digest(hasher.hexdigest(), digest[7:]):
            raise UpdateError("checksum mismatch")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _check_plugin_file(path, expected_build):
    """The single-file build declares its id and build near the top."""
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        head = handle.read(64 * 1024)
    plugin_id = re.search(r'(?m)^__id__\s*=\s*["\']([^"\']+)["\']', head)
    if not plugin_id or plugin_id.group(1) != PLUGIN_ID or declared_build(head) != expected_build:
        raise UpdateError("not a GreenPass build %d" % expected_build)


def _check_elyx_file(path, expected_build):
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if not {"refmap.yml", "plugin/main.py", "plugin/meta.yml", "plugin/greenpass/meta.py"} <= names:
            raise UpdateError("not a GreenPass archive")
        meta_yml = archive.read("plugin/meta.yml")[:64 * 1024].decode("utf-8", errors="ignore")
        meta_py = archive.read("plugin/greenpass/meta.py")[:64 * 1024].decode("utf-8", errors="ignore")
    plugin_id = re.search(r'(?mi)^id\s*:\s*["\']?([^"\'\s]+)', meta_yml)
    if not plugin_id or plugin_id.group(1) != PLUGIN_ID or declared_build(meta_py) != expected_build:
        raise UpdateError("not a GreenPass build %d" % expected_build)


def check(cache_dir, elyx, skip_tag="", on_progress=None):
    """Download a newer build if there is one.

    Returns (tag, path): path is "" when there is nothing new (or skip_tag is the
    latest). Raises UpdateError / OSError when the check fails.
    """
    tag, assets = latest_release()
    build = release_build(tag)
    if build <= GREENPASS_BUILD or (skip_tag and tag == skip_tag):
        return tag, ""
    name = ASSET_ELYX if elyx else ASSET_PLUGIN
    asset = next((a for a in assets if isinstance(a, dict) and a.get("name") == name), None)
    if asset is None:
        raise UpdateError("release has no %s" % name)
    path = os.path.join(cache_dir, "GreenPass-update" + (".elyx" if elyx else ".plugin"))
    _download(asset, path, on_progress)
    try:
        (_check_elyx_file if elyx else _check_plugin_file)(path, build)
    except (UpdateError, zipfile.BadZipFile):
        os.remove(path)
        raise
    return tag, path


def open_installer(path):
    """Hand the downloaded file to exteraGram's plugin install dialog."""
    from client_utils import get_last_fragment
    from hook_utils import find_class
    controller_class = find_class("com.exteragram.messenger.plugins.PluginsController")
    controller = controller_class.getInstance()
    fragment = get_last_fragment()
    if fragment is None or controller is None or not os.path.isfile(path):
        raise UpdateError("installer is unavailable")
    controller.showInstallDialog(fragment, path, True)
