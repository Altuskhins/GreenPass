# Bundled runtime wheels

These pure-Python wheels provide the optional HTTPX HTTP/2 transport used by TG-WS. Elyx extracts the wheels into GreenPass's private library directory, so installation does not need to resolve or download Python dependencies from PyPI.

The wheel files are pinned by filename and their SHA-256 digests are recorded in `SHA256SUMS.txt`. Each wheel includes its upstream license in `.dist-info/licenses`. Keep each wheel intact when updating this set.

| Package | Version | License |
| --- | --- | --- |
| anyio | 4.15.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| h11 | 0.16.0 | MIT |
| h2 | 4.4.1 | MIT |
| hpack | 4.2.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| hyperframe | 6.1.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| typing_extensions | 4.16.0 | PSF-2.0 |
