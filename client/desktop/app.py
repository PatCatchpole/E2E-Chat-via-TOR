"""
Desktop window.

The chat as a native window instead of a terminal: pywebview puts the page in
`web/` inside the platform's own webview (WebKit on macOS, Edge WebView2 on
Windows) and lets its script call the `Bridge` methods below. The page is a
view and nothing more. Keys, ratchets and plaintext live in Python, in the
same `SpectreSession` the terminal UI drives; the page is handed only what it
has to draw.

Three things about how the page is loaded are deliberate, and each closes a
hole a webview opens by default:

  * No network. The HTML, CSS, script and fonts are inlined into one document
    and a Content-Security-Policy forbids every fetch. A font pulled from
    Google on launch would leave the machine outside Tor and announce that
    Spectre had just been opened.
  * No server. The document is handed to the webview as a string, and the
    page reaches Python through pywebview's native bridge rather than HTTP,
    so there is no localhost port for another process -- or a web page in a
    browser -- to talk to.
  * No markup from the network. Usernames, room names and message text all
    come from other people, and this page can call into the session. The
    script only ever places them with `textContent`; nothing received is
    parsed as HTML.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

import storage
from client_cli import onion_url
from session import SessionError, SpectreSession

WEB = Path(__file__).resolve().parent / "web"

# Mirrors the backend's @Pattern, so a bad name is refused here rather than
# after a Tor round trip.
USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
# Looks like a v3 address, whether or not its checksum holds.
ONION_SHAPE = re.compile(r"\b[a-z2-7]{56}\.onion\b")
ROOM_MAX = 64
ROOM_CAPACITY = 8

# 'unsafe-eval' is pywebview's requirement, not ours: it builds the
# `pywebview.api.*` stubs with `new Function`, and without it the bridge never
# comes up. The page itself never evaluates a string. What the policy is for
# is `default-src 'none'`: no fetch, socket, image or font can leave the page.
CSP = ("default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; "
       "style-src 'unsafe-inline'; font-src data:; img-src data:; "
       "base-uri 'none'; form-action 'none'")


def build_page() -> str:
    """index.html with its stylesheet, script and fonts inlined."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    css = (WEB / "app.css").read_text(encoding="utf-8")
    js = (WEB / "app.js").read_text(encoding="utf-8")

    def font(match):
        data = (WEB / "fonts" / match.group(1)).read_bytes()
        return "url(data:font/woff2;base64," + base64.b64encode(data).decode() + ")"

    css = re.sub(r'url\("fonts/([\w.-]+\.woff2)"\)', font, css)
    return (html.replace("{{CSP}}", CSP)
                .replace("/*{{CSS}}*/", css)
                .replace("/*{{JS}}*/", js))


def copy_to_clipboard(text: str) -> bool:
    """The webview's own clipboard API is unreliable for a page with no origin."""
    if sys.platform == "darwin":
        command = ["pbcopy"]
    elif sys.platform == "win32":
        command = ["clip"]
    else:
        command = ["wl-copy"] if subprocess.run(
            ["which", "wl-copy"], capture_output=True).returncode == 0 else ["xclip", "-selection", "clipboard"]
    try:
        # clip.exe reads the console code page; UTF-16 is what it reliably takes.
        encoding = "utf-16" if sys.platform == "win32" else "utf-8"
        subprocess.run(command, input=text.encode(encoding), check=True, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


class Launcher:
    """
    What the window needs from spectre.py, which owns the child processes.

    `host(progress)` starts the relay and publishes it, calling
    `progress(step, **info)` as it goes, and returns our own relay URL.
    `client_tor()` starts a tor for joining and returns its SOCKS port, or None.
    """

    def __init__(self, host, client_tor, prefs):
        self.host = host
        self.client_tor = client_tor
        self.prefs = prefs


class Bridge:
    """
    The page's view of Python. Public methods are callable from the page as
    `pywebview.api.<name>`; everything else is underscored so pywebview does
    not expose it.
    """

    def __init__(self, launcher: Launcher):
        self._launcher = launcher
        self._window = None
        self._lock = threading.Lock()
        self._mode = None           # "host" or "join"
        self._relay_url = None      # our relay when hosting, the onion when joining
        self._user = None
        self._password = None
        self._session = None
        self._queued = []           # [(id, text)] waiting for a peer to be reachable
        self._next_id = 0

    # ---- plumbing ------------------------------------------------------

    def _attach(self, window) -> None:
        self._window = window

    def _push(self, kind: str, payload: dict = None) -> None:
        if self._window is None:
            return
        # ensure_ascii keeps U+2028 and friends out of the script source.
        call = "window.spectre && spectre.receive(%s)" % json.dumps(
            [kind, payload or {}], ensure_ascii=True)
        try:
            self._window.run_js(call)
        except Exception:
            pass                    # the window is closing

    def _background(self, target, *args) -> None:
        threading.Thread(target=target, args=args, daemon=True).start()

    # ---- start ---------------------------------------------------------

    def boot(self) -> dict:
        prefs = self._launcher.prefs
        saved = prefs.get("relay") or ""
        return {
            "user": prefs.get("user", ""),
            "onion": saved if onion_url(saved) else "",
            "mode": "host" if prefs.get("start") in ("host", "host-tor") or prefs.get("hosted") else "join",
        }

    def host(self) -> dict:
        with self._lock:
            if self._mode == "host" and self._relay_url:
                return {"ok": True, "already": True}
            self._mode = "host"
        self._background(self._host)
        return {"ok": True}

    def _host(self) -> None:
        def progress(step, **info):
            self._push("host", dict(step=step, **info))
        try:
            self._relay_url = self._launcher.host(progress)
        except Exception as e:           # RuntimeError from the launcher, or worse
            with self._lock:
                self._mode = None
            self._push("host_failed", {"text": str(e)})

    def join(self) -> dict:
        with self._lock:
            if self._mode == "host":
                return {"ok": False, "error": "This window is hosting a room. Close it to join another."}
            self._mode = "join"
        return {"ok": True}

    def copy(self, text: str) -> bool:
        return copy_to_clipboard(str(text))

    # ---- sign in -------------------------------------------------------

    def sign_in(self, onion: str, user: str, password: str) -> dict:
        user = (user or "").strip()
        if self._mode == "join":
            url = onion_url(onion)
            if not onion.strip():
                return {"ok": False, "field": "onion", "error": "Paste the .onion address your host sent you."}
            if url is None:
                shaped = ONION_SHAPE.search(onion.strip().lower())
                return {"ok": False, "field": "onion", "error": (
                    "That onion address doesn't check out, so a character is probably "
                    "wrong. Copy it again from your host." if shaped else
                    "That isn't an onion address. It should be 56 letters and digits "
                    "followed by .onion.")}
            self._relay_url = url
        elif self._mode == "host":
            if not self._relay_url:
                return {"ok": False, "error": "The room is still being published."}
        else:
            return {"ok": False, "error": "Choose whether to host or join first."}

        if not user:
            return {"ok": False, "field": "user", "error": "Choose a username."}
        if not USERNAME.match(user):
            return {"ok": False, "field": "user",
                    "error": "Usernames can use letters, digits, dot, underscore and hyphen."}
        if not password:
            return {"ok": False, "field": "pass", "error": "Enter a password."}

        self._user, self._password = user, password
        saved = {"user": user, "start": "host-tor" if self._mode == "host" else "join"}
        if self._mode == "join":
            saved["relay"] = onion.strip().lower()
        storage.save_launcher_prefs(saved)
        return {"ok": True, "rooms": self._rooms()}

    def _rooms(self) -> list:
        rooms = []
        for entry in storage.list_rooms(self._user):
            peers = sorted(entry.get("peers") or [])
            rooms.append({"room": entry["room"], "peers": peers,
                          "last_used": entry.get("last_used") or 0})
        return rooms

    # ---- room ----------------------------------------------------------

    def enter(self, room: str) -> dict:
        room = (room or "").strip().lstrip("#")
        if not room:
            return {"ok": False, "error": "Type a name for the room."}
        if len(room) > ROOM_MAX or any(ord(c) < 32 for c in room):
            return {"ok": False, "error": f"Room names are up to {ROOM_MAX} characters, on one line."}
        if self._user is None:
            return {"ok": False, "error": "Sign in first."}
        self._background(self._enter, room)
        return {"ok": True}

    def _enter(self, room: str) -> None:
        use_tor = self._mode == "join"
        try:
            if use_tor:
                self._push("status", {"text": "Connecting to the Tor network. The first time can take a minute."})
                self._launcher.client_tor()
            session = SpectreSession(
                url=self._relay_url, room=room, user=self._user,
                password=self._password, use_tor=use_tor, on_event=self._on_event,
            )
            self._push("status", {"text": "Reaching the room over Tor." if use_tor else "Opening the room."})
            session.connect()
            session.start()
            session.authenticate()
        except SessionError as e:
            self._push("enter_failed", {"text": str(e), "back": "signin"})
            return
        except Exception as e:
            self._push("enter_failed", {"text": f"Could not reach the room: {e}", "back": "signin"})
            return

        with self._lock:
            self._session = session
            self._queued = []
        session.join()
        self._push("entered", {"room": room, "user": self._user, "mode": self._mode})
        self._push_state()

    def leave(self) -> dict:
        with self._lock:
            session, self._session = self._session, None
            self._queued = []
        if session is not None:
            session.close()
        return {"ok": True, "rooms": self._rooms() if self._user else []}

    # ---- chat ----------------------------------------------------------

    def send(self, text: str) -> dict:
        text = (text or "").strip()
        session = self._session
        if not text or session is None:
            return {"ok": False}
        with self._lock:
            self._next_id += 1
            message_id = self._next_id
            # The session queues rather than sends when nobody can be reached
            # yet, and emits "sent" only when the queue drains. Recording the
            # text here lets that later event update this bubble instead of
            # drawing a second one.
            queued = not (session.joined and session.can_send)
            if queued:
                self._queued.append((message_id, text))
        session.send_message(text)
        return {"ok": True, "id": message_id, "queued": queued}

    def peer(self, name: str) -> dict:
        session = self._session
        if session is None:
            return {}
        changed = name in session.pending_identity_changes
        peer = session.peers.get(name)
        number = session.safety_number_for(name)
        return {
            "name": name,
            "digits": number.split() if number else [],
            "verified": bool(peer and peer.verified),
            "changed": changed,
        }

    def verify(self, name: str) -> bool:
        session = self._session
        ok = bool(session and session.mark_verified(name))
        if ok:
            self._push_state()
        return ok

    def trust(self, name: str) -> bool:
        session = self._session
        ok = bool(session and session.trust_new_identity(name))
        if ok:
            self._push_state()
        return ok

    # ---- session events ------------------------------------------------

    def _on_event(self, kind: str, payload: dict) -> None:
        payload = dict(payload)
        if kind == "sent":
            with self._lock:
                for index, (message_id, text) in enumerate(self._queued):
                    if text == payload.get("text"):
                        payload["id"] = message_id
                        del self._queued[index]
                        break
                else:
                    payload["id"] = self._next_id
            session = self._session
            payload["copies"] = sum(1 for p in session.peers.values() if p.can_send) if session else 0
        if kind == "status" and str(payload.get("text", "")).startswith("Queued"):
            return                  # the bubble already says so
        self._push(kind, payload)
        if kind in ("state", "peer", "ready", "warning", "message", "sent"):
            self._push_state()

    def _push_state(self) -> None:
        session = self._session
        if session is None:
            return
        changed = set(session.pending_identity_changes)
        members = []
        for name in sorted(set(session.peers) | changed):
            peer = session.peers.get(name)
            members.append({
                "name": name,
                "online": bool(peer and peer.online),
                "verified": bool(peer and peer.verified),
                "ready": bool(peer and peer.can_send),
                "changed": name in changed,
            })
        self._push("snapshot", {
            "members": members,
            "sessions": sum(1 for p in session.peers.values() if p.ratchet is not None),
            "connected": session.connected,
            "capacity": ROOM_CAPACITY,
        })

    def _close(self) -> None:
        self.leave()


def run(launcher: Launcher) -> None:
    """Open the window and block until it is closed."""
    import webview

    bridge = Bridge(launcher)
    window = webview.create_window(
        "Spectre", html=build_page(), js_api=bridge,
        width=1120, height=760, min_size=(760, 560),
        background_color="#FFF7E8", text_select=True,
    )
    bridge._attach(window)
    try:
        # private_mode: no cookies, cache or local storage written to disk.
        webview.start(private_mode=True)
    finally:
        bridge._close()
