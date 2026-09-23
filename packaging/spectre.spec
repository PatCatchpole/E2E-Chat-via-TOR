# PyInstaller spec for the packaged Spectre build. Run via packaging/build.py,
# which fetches and verifies the tor binary into build/tor first.
#
# macOS and Windows get the desktop window (pywebview) as a windowed app:
# Spectre.app on macOS -- PyInstaller no longer recommends one-file windowed
# builds there -- and a one-file Spectre.exe on Windows. Linux keeps the
# terminal interface in a one-file console binary, because a webview there
# needs system GTK/WebKit libraries that do not bundle sensibly.
#
# The relay and backend are shipped as source files, not analysed as modules:
# the frozen launcher runs them with runpy when it re-executes itself with
# `--serve`. Their imports are invisible to PyInstaller's analysis for the same
# reason, so the packages they need are collected explicitly below --
# engineio in particular picks its async driver by name at runtime, and a
# build without `engineio.async_drivers.threading` fails only once hosting.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
TOR = ROOT / "build" / "tor"
WEB = ROOT / "client" / "desktop" / "web"

if not TOR.is_dir() or not any(TOR.iterdir()):
    raise SystemExit("build/tor is empty; run packaging/build.py, not pyinstaller directly")

try:
    import webview  # noqa: F401
    DESKTOP = sys.platform in ("darwin", "win32")
except ImportError:
    DESKTOP = False

# PyNaCl reaches libsodium through cffi, whose compiled backend is imported
# from C and so never shows up in the analysis.
hidden = ["_cffi_backend", "socks", "urllib3.contrib.socks"]
for package in ("flask", "flask_socketio", "socketio", "engineio",
                "simple_websocket", "werkzeug", "nacl"):
    hidden += collect_submodules(package)

datas = [
    (str(ROOT / "server" / "app.py"), "server"),
    (str(ROOT / "tools" / "dev_backend.py"), "tools"),
]
# Data, not binaries: PyInstaller would otherwise rewrite and re-sign the
# libraries, and tor finds them beside itself exactly as the bundle laid out.
datas += [(str(path), "tor") for path in TOR.iterdir()]

if DESKTOP:
    hidden += ["desktop", "desktop.app", "webview"]
    # The page is read from disk and inlined at start-up; see desktop/app.py.
    # Frozen, that module's __file__ sits at <bundle>/desktop/, so the page
    # goes to <bundle>/desktop/web/.
    for path in WEB.rglob("*"):
        if path.is_file():
            datas.append((str(path), str(path.parent.relative_to(ROOT / "client"))))

a = Analysis(
    [str(ROOT / "spectre.py")],
    pathex=[str(ROOT / "client")],
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

if DESKTOP and sys.platform == "darwin":
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Spectre",
              console=False, upx=False, strip=False, debug=False)
    coll = COLLECT(exe, a.binaries, a.datas, name="Spectre", upx=False, strip=False)
    app = BUNDLE(
        coll, name="Spectre.app", bundle_identifier="org.spectreprotocol.spectre",
        info_plist={
            "CFBundleDisplayName": "Spectre",
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable": True,
            "LSApplicationCategoryType": "public.app-category.social-networking",
        },
    )
else:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, name="Spectre",
              console=not DESKTOP,     # the desktop build draws its own window
              upx=False, strip=False, debug=False)
