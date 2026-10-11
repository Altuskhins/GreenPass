@echo off
rem Build GreenPass.elyx and GreenPass.plugin into builds\
rem   build.bat           - build only
rem   build.bat release   - build and publish release v<version> (needs GitHub CLI: gh auth login)
setlocal
cd /d "%~dp0"

set "PY="
py -3.11 -c "" >nul 2>nul && set "PY=py -3.11"
if not defined PY (
    py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PY=py -3"
)
if not defined PY (
    python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo Python 3.10+ not found. Install Python 3.11 from https://www.python.org/downloads/ ^(check "Add python.exe to PATH"^).
    goto :fail
)
echo Using %PY%

%PY% -m pip install --disable-pip-version-check --quiet --upgrade "ElyxBuilder==0.6.3" || goto :fail

set "ARGS="
if /i "%~1"=="release" set "ARGS=--release"
%PY% scripts\build_release.py %ARGS% || goto :fail

echo.
echo Done.
if not defined NOPAUSE pause
exit /b 0

:fail
echo.
echo Build failed.
if not defined NOPAUSE pause
exit /b 1
