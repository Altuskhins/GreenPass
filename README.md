# GreenPass Elyx

Structured Elyx package for GreenPass. The sources under `plugin/` are the
primary codebase. The same sources can also be flattened into `GreenPass.plugin`
for exteraGram installations without Elyx support.

Targets the current [exteraGram plugin SDK](https://plugins.exteragram.app/docs):

| Build | App | SDK | Metadata |
| --- | --- | --- | --- |
| Elyx (`.eaf`) | `>=12.5.1` | `>=1.4.5.3` | `plugin/meta.yml` |
| Legacy (`.plugin`) | `>=12.5.1` | `>=1.4.5.3` | top of `plugin/greenpass/foundation.py` |

## Runtime dependencies

The Elyx archive bundles the pinned, pure-Python HTTPX and HTTP/2 wheels under
`plugin/wheels`. Elyx installs them in GreenPass's private library directory,
so users do not need to install packages from PyPI. The legacy single-file
plugin keeps HTTP/2 optional and falls back to WebSocket when those libraries
are unavailable.

## Build on Windows

Run `build.bat` (needs Python 3.10+, ideally 3.11). It installs ElyxBuilder and
writes `builds/GreenPass.elyx` and `builds/GreenPass.plugin`.

`build.bat release` also publishes them as GitHub release `v<version>` through
the [GitHub CLI](https://cli.github.com) (`gh auth login` first; the current
commit must be pushed). On other systems: `python scripts/build_release.py
[--release]`.

## Build with ElyxBuilder

Install [ElyxBuilder](https://plugins.exteragram.app/docs/elyx/elyxbuilder)
(Python 3.10+; compiled builds need Python 3.11):

```sh
python -m pip install --upgrade ElyxBuilder
```

From the repository root (the directory with `refmap.yml`):

```sh
# source build with syntax check
elyb build --ast -v -nf

# compiled build (.pyc, optimization level 2)
elyb build -c 2 -v -nf
```

Archives are written to `builds/`.

Build the legacy single-file plugin from the same sources:

```sh
python scripts/build_legacy_plugin.py plugin builds/GreenPass.plugin
```

## Releases

`build.bat release` (above) or `.github/workflows/release.yml` (on a `v*` tag
push or a manual run) builds both files and publishes release `v<version>`
(from `version` in `plugin/meta.yml`). Notes come from
`release-notes/v<version>.md` when that file exists.

## Build with the PowerShell scripts

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-greenpass-elyx.ps1
```

The output is `builds/GreenPass.elyx`.

Build the legacy single-file plugin:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-greenpass-legacy-plugin.ps1
```

The legacy builder also accepts a built `GreenPass.elyx` as `-SourcePath`.
