"""
The desktop window's Python side.

The window itself needs a display, so these exercise what can go wrong without
one: the page must never be able to reach the network, the sign-in screen must
keep the launcher Tor-only, and nothing pushed into the page may be able to
break out of the call it is carried in.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re

import pytest

import storage
from desktop import app as desktop


def make_onion(key: bytes) -> str:
    """A v3 onion address for `key`, built the way tor builds one."""
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode().lower() + ".onion"


ONION = make_onion(os.urandom(32))
# One character changed: right length and alphabet, wrong checksum.
TYPO = ONION[:10] + ("a" if ONION[10] != "a" else "b") + ONION[11:]


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "SPECTRE_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(storage, "PEERS_DIR", tmp_path / "peers")
    storage.ensure_dirs()
    yield


class FakeWindow:
    def __init__(self):
        self.calls = []

    def run_js(self, script):
        self.calls.append(script)


def bridge(mode=None, prefs=None):
    b = desktop.Bridge(desktop.Launcher(host=None, client_tor=None, prefs=prefs or {}))
    b._mode = mode
    return b


# ---- the page --------------------------------------------------------------


def test_the_page_is_self_contained():
    page = desktop.build_page()
    assert "{{" not in page and "/*{{" not in page, "a placeholder was not filled"
    # Every font is inlined; nothing is left for the webview to fetch.
    assert 'url("fonts/' not in page
    assert page.count("data:font/woff2;base64,") == 4
    # No reference to any other host -- a font or script pulled from the
    # internet would leave the machine outside Tor.
    assert not re.search(r"https?://", page), "the page refers to a network address"


def test_the_page_forbids_network_access():
    page = desktop.build_page()
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert "default-src 'none'" in policy
    for directive in ("connect-src", "frame-src", "child-src"):
        assert directive not in policy, f"{directive} would override default-src 'none'"
    assert "data:" in policy and "http" not in policy


def test_the_script_never_parses_received_text_as_html():
    script = (desktop.WEB / "app.js").read_text(encoding="utf-8")
    code = "\n".join(line for line in script.splitlines() if not line.strip().startswith("//"))
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code, f"app.js uses {sink}"


# ---- pushing events into the page ------------------------------------------


def test_pushed_payloads_cannot_break_out_of_the_call():
    b = bridge()
    window = FakeWindow()
    b._attach(window)
    hostile = "</script>\"); alert(1); (\"  "
    b._push("message", {"user": hostile, "text": hostile})

    (call,) = window.calls
    assert call.startswith("window.spectre && spectre.receive(") and call.endswith(")")
    argument = call[len("window.spectre && spectre.receive("):-1]
    assert json.loads(argument) == ["message", {"user": hostile, "text": hostile}]
    assert " " not in call and " " not in call


# ---- sign in: Tor only ------------------------------------------------------


@pytest.mark.parametrize("address", [
    "", "127.0.0.1:5055", "localhost", "192.168.1.20:5055", "http://example.com",
    "abc.onion", TYPO, ONION[:-7] + ".onion",
])
def test_joining_refuses_anything_but_an_onion_address(address):
    result = bridge("join").sign_in(address, "alice", "pw")
    assert result["ok"] is False and result["field"] == "onion"


def test_a_typo_is_reported_as_a_typo():
    error = bridge("join").sign_in(TYPO, "alice", "pw")["error"]
    assert "character is probably wrong" in error


def test_a_real_address_from_tor_is_accepted():
    # Published by a tor during development; its checksum is tor's own.
    real = "vnhs4nq3i5iskiw7xkdwplysgqncjg42brzuf6bt5ht4zuhcz445yead.onion"
    assert bridge("join").sign_in(real, "alice", "pw")["ok"] is True


def test_joining_accepts_an_onion_address_in_any_case():
    b = bridge("join")
    result = b.sign_in(ONION.upper(), "alice", "pw")
    assert result["ok"] is True
    assert b._relay_url == f"http://{ONION}:80"
    assert storage.load_launcher_prefs()["relay"] == ONION


def test_hosting_signs_in_to_our_own_relay_only():
    b = bridge("host")
    assert b.sign_in(ONION, "alice", "pw")["ok"] is False, "signed in before the room was published"
    b._relay_url = "http://127.0.0.1:5055"
    assert b.sign_in("ignored", "alice", "pw")["ok"] is True
    assert b._relay_url == "http://127.0.0.1:5055"
    assert "relay" not in storage.load_launcher_prefs()


@pytest.mark.parametrize("user", ["", "has space", "slash/name", "x" * 101])
def test_usernames_the_backend_would_refuse_are_refused_here(user):
    result = bridge("join").sign_in(ONION, user, "pw")
    assert result["ok"] is False and result["field"] == "user"


def test_a_password_is_required():
    assert bridge("join").sign_in(ONION, "alice", "")["field"] == "pass"


def test_only_a_saved_onion_address_is_offered_again():
    assert bridge(prefs={"relay": "127.0.0.1:5055"}).boot()["onion"] == ""
    assert bridge(prefs={"relay": ONION}).boot()["onion"] == ONION


def test_a_room_cannot_be_opened_twice_at_once(monkeypatch):
    b = bridge("join")
    b._user = "alice"
    monkeypatch.setattr(b, "_background", lambda *args: None)   # never finishes opening
    assert b.enter("spectre")["ok"] is True
    assert b.enter("spectre")["ok"] is False, "a double-click opened a second session"


def test_room_names_must_be_one_short_line():
    b = bridge("join")
    b._user = "alice"
    assert b.enter("")["ok"] is False
    assert b.enter("a\nb")["ok"] is False
    assert b.enter("x" * (desktop.ROOM_MAX + 1))["ok"] is False


def test_a_failed_tor_is_reported_not_only_the_fallback(monkeypatch):
    # The first Windows run showed only "Tried 127.0.0.1:9050, 9150": the
    # fallback's error. Why Spectre's own tor did not start was thrown away.
    reason = "Could not start tor: tor exited.\n  Log: tor.log"
    b = desktop.Bridge(desktop.Launcher(host=None, client_tor=lambda: reason, prefs={}))
    b._mode, b._user, b._password, b._relay_url = "join", "alice", "pw", "http://" + ONION

    def unreachable(self):
        raise desktop.SessionError("could not reach the relay through Tor.")

    monkeypatch.setattr(desktop.SpectreSession, "connect", unreachable)
    pushed = []
    monkeypatch.setattr(b, "_push", lambda kind, payload: pushed.append((kind, payload)))
    b._enter("spectre")

    kind, payload = pushed[-1]
    assert kind == "enter_failed"
    assert payload["text"].startswith(reason)
    assert "could not reach the relay" in payload["text"]
