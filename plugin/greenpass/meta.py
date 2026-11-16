__id__ = "GreenPass"
__name__ = "GreenPass"
__description__ = "Прокси для Telegram: vless/vmess/hysteria2 и др., встроенные TG WS, AmneziaWG и olcRTC, прокси для звонков"
__author__ = "@AltyPlugins | claude opus 5.5"
__version__ = "2.6.4"
__icon__ = "bratpass/0"
__app_version__ = ">=12.5.1"
__sdk_version__ = ">=1.4.5.3"

import re

PLUGIN_ID = __id__
VERSION = __version__

# Updates are ordered by this build id, not by the shown version: bump it by one
# for every release. Releases are tagged v<version>-b<build>.
GREENPASS_BUILD = 14

RELEASES_LATEST_URL = "https://api.github.com/repos/Altuskhins/GreenPass/releases/latest"
UPDATE_CHECK_INTERVAL_SEC = 24 * 60 * 60


def release_build(tag):
    """Build id from a release tag such as "v2.6.3-b8"; 0 when it has none."""
    match = re.search(r"-b(\d+)$", str(tag or "").strip())
    return int(match.group(1)) if match else 0


def declared_build(source):
    """GREENPASS_BUILD declared in a plugin source text; 0 when missing."""
    match = re.search(r"(?m)^GREENPASS_BUILD\s*=\s*(\d+)\s*$", str(source or ""))
    return int(match.group(1)) if match else 0
