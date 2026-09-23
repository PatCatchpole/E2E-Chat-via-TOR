#!/usr/bin/env python3
"""
Build the one-file Spectre executable for the platform this runs on.

    pip install -r requirements.txt pyinstaller
    python packaging/build.py

The result is `dist/Spectre` (`dist/Spectre.exe` on Windows): Python, every
dependency, the relay, the in-memory backend and a tor binary in one file, so
the person running it installs nothing. PyInstaller cannot cross-compile --
a Windows build has to be made on Windows -- which is what
`.github/workflows/build.yml` is for.

Tor comes from the Tor Project's expert bundle. The archive is checked against
a SHA-256 pinned below rather than against a checksum file fetched alongside
it: a checksum served by the same host as the file proves nothing if that host
is the thing being attacked. The pins were copied from the release's
`sha256sums-signed-build.txt`; to move to a newer tor, update TOR_VERSION and
all four pins from that file (and check its .asc signature when you do).
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CACHE = ROOT / "build" / "tor-cache"
TOR_DIR = ROOT / "build" / "tor"

TOR_VERSION = "15.0.23"          # Tor Browser release; ships tor 0.4.9.12
TOR_URL = "https://dist.torproject.org/torbrowser/{version}/{name}"
TOR_SHA256 = {
    "windows-x86_64": "231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e",
    "macos-aarch64":  "e8ea3f667c83309abad34280f0f9e1cfae52843da6b8db111ca15d6221051db5",
    "macos-x86_64":   "be1be1cb13cd093713f02a0beade0d2471b61119011bfeb0efc08353eadf2e4e",
    "linux-x86_64":   "08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985",
}


def target() -> str:
    machine = platform.machine().lower()
    arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
    if sys.platform == "win32":
        system = "windows"
    elif sys.platform == "darwin":
        system = "macos"
    else:
        system = "linux"
    key = f"{system}-{arch}"
    if key not in TOR_SHA256:
        sys.exit(f"No tor bundle is pinned for {key}.")
    return key


def fetch_tor(key: str) -> bytes:
    name = f"tor-expert-bundle-{key}-{TOR_VERSION}.tar.gz"
    cached = CACHE / name
    if cached.exists():
        data = cached.read_bytes()
    else:
        url = TOR_URL.format(version=TOR_VERSION, name=name)
        print(f"downloading {url}")
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()

    digest = hashlib.sha256(data).hexdigest()
    if digest != TOR_SHA256[key]:
        cached.unlink(missing_ok=True)
        sys.exit(f"{name}: SHA-256 {digest} does not match the pinned "
                 f"{TOR_SHA256[key]}. Refusing to bundle it.")

    CACHE.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(data)
    return data


def unpack_tor(data: bytes) -> None:
    """
    Keep only tor itself and the libraries beside it. The pluggable transports
    are not used -- nothing configures bridges -- and would only add size and
    more unsigned binaries for macOS to object to.
    """
    shutil.rmtree(TOR_DIR, ignore_errors=True)
    TOR_DIR.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if len(parts) != 2 or parts[0] != "tor" or not member.isfile():
                continue
            source = archive.extractfile(member)
            destination = TOR_DIR / parts[1]
            destination.write_bytes(source.read())
            destination.chmod(0o755)

    if sys.platform == "darwin":
        # The expert bundle's binaries are unsigned, and Apple Silicon kills an
        # unsigned binary on launch (exit 137, no message). An ad-hoc
        # signature is enough to run.
        for path in TOR_DIR.iterdir():
            subprocess.run(["codesign", "--force", "--sign", "-", str(path)], check=True)

    binary = TOR_DIR / ("tor.exe" if sys.platform == "win32" else "tor")
    if not binary.exists():
        sys.exit(f"the tor bundle did not contain {binary.name}")
    environment = dict(os.environ)
    if sys.platform.startswith("linux"):
        environment["LD_LIBRARY_PATH"] = str(TOR_DIR)
    version = subprocess.run([str(binary), "--version"], env=environment,
                             capture_output=True, text=True, check=True)
    print(version.stdout.splitlines()[0])


def build() -> None:
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build" / "pyinstaller"),
         str(HERE / "spectre.spec")],
        cwd=str(ROOT), check=True,
    )


def main() -> None:
    key = target()
    print(f"building Spectre for {key}")
    unpack_tor(fetch_tor(key))
    build()
    name = "Spectre.exe" if sys.platform == "win32" else "Spectre"
    print(f"\nbuilt {ROOT / 'dist' / name}")


if __name__ == "__main__":
    main()
