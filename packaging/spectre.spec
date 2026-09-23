# PyInstaller spec for the one-file Spectre build. Run via packaging/build.py,
# which fetches and verifies the tor binary into build/tor first.
#
# The relay and backend are shipped as source files, not analysed as modules:
# the frozen launcher runs them with runpy when it re-executes itself with
# `--serve`. Their imports are invisible to PyInstaller's analysis for the same
# reason, so the packages they need are collected explicitly below --
# engineio in particular picks its async driver by name at runtime, and a
# build without `engineio.async_drivers.threading` fails only once hosting.

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
TOR = ROOT / "build" / "tor"

if not TOR.is_dir() or not any(TOR.iterdir()):
    raise SystemExit("build/tor is empty; run packaging/build.py, not pyinstaller directly")

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

a = Analysis(
    [str(ROOT / "spectre.py")],
    pathex=[str(ROOT / "client")],
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="Spectre",
    console=True,           # the chat is a terminal UI
    upx=False,
    strip=False,
    debug=False,
)
