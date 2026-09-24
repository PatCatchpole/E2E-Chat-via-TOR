"""
The torrc and command line the launcher gives tor.

Tor on Windows reads both in the ANSI code page rather than UTF-8. The first
real Windows run (v1.0.2) was under an account name with accents in it: the
absolute DataDirectory in torrc arrived with those letters garbled, tor could
not create it, and
joining failed with an error about ports 9050/9150 instead. Nothing tor is
given may carry the home directory's name.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spectre  # noqa: E402


@pytest.mark.parametrize("publish_port", [None, 5999])
def test_tor_is_given_no_path_through_the_home_directory(tmp_path, monkeypatch, publish_port):
    home = tmp_path / "João Gonçalves"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(spectre.TorProcess, "binary", staticmethod(lambda: "tor"))
    monkeypatch.setattr(spectre.TorProcess, "_await_bootstrap", lambda self, cb=None: None)
    monkeypatch.setattr(spectre, "_stop_on_exit", lambda stop: None)
    started = {}

    class FakePopen:
        def __init__(self, args, cwd=None, **kwargs):
            started.update(args=args, cwd=cwd)

        def poll(self):
            return 0

    monkeypatch.setattr(spectre.subprocess, "Popen", FakePopen)
    tor = spectre.TorProcess(publish_port=publish_port)
    if publish_port:
        tor.service_dir.mkdir(parents=True)
        (tor.service_dir / "hostname").write_text("x.onion\n", encoding="utf-8")
    tor.start()
    tor.stop()

    torrc = (tor.root / "torrc").read_bytes()
    torrc.decode("ascii")                      # raises on any non-ASCII byte
    assert str(home).encode() not in torrc and b"/" not in torrc.split(b"\n", 1)[1]
    for argument in started["args"][1:]:
        assert argument.isascii() and not os.path.isabs(argument), argument
    # Relative paths are only correct because tor runs inside its own directory.
    assert Path(started["cwd"]) == tor.root
