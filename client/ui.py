"""
Terminal chat screen.

A full-screen layout with a fixed header, a scrolling transcript, a status bar
carrying the security state, and an input line pinned to the bottom. The old
CLI interleaved `print()` calls with `input()`, so an inbound message would
land in the middle of whatever was being typed.

The session runs on a background thread and calls `handle_event` from there;
`Application.invalidate()` is safe across threads, so rendering stays on the UI
thread and no locking is needed beyond appending to the transcript list.
"""

from __future__ import annotations

import time

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import TextArea

STYLE = Style.from_dict({
    "header": "bg:#1c2833 #7fd1e0 bold",
    "header.room": "bg:#1c2833 #ffffff bold",
    "header.dim": "bg:#1c2833 #6b7b8c",
    "header.ok": "bg:#1c2833 #5fd75f bold",
    "header.bad": "bg:#1c2833 #ff6b6b bold",
    "header.tor": "bg:#1c2833 #c792ea bold",

    "status": "bg:#1c2833 #9aa5b1",
    "status.verified": "bg:#1c2833 #5fd75f bold",
    "status.unverified": "bg:#1c2833 #ffb454 bold",
    "status.number": "bg:#1c2833 #7fd1e0",

    "time": "#5c6773",
    "self": "#5fd75f bold",
    "peer": "#7fd1e0 bold",
    "text": "",
    "system": "#6b7b8c italic",
    "error": "#ff6b6b",
    "warning": "#ffb454 bold",
    "prompt": "#5fd75f bold",
})

HELP_LINES = [
    "/verify   show the full safety number and mark this peer verified",
    "/trust    accept a changed peer identity key (only after re-verifying)",
    "/clear    clear the transcript",
    "/help     this list",
    "/quit     leave the room and exit",
]


class ChatUI:
    def __init__(self, session, room, user, use_tor):
        self.session = session
        self.room = room
        self.user = user
        self.use_tor = use_tor

        self.entries = []      # (style, prefix, text, ts)
        self._scroll_back = 0
        self._line_count = 0

        self.input = TextArea(
            height=1,
            prompt=[("class:prompt", "> ")],
            multiline=False,
            wrap_lines=False,
            accept_handler=self._on_submit,
        )

        self.transcript = Window(
            content=FormattedTextControl(
                text=self._render_transcript,
                focusable=False,
                get_cursor_position=self._cursor_position,
            ),
            wrap_lines=True,
        )

        self.app = Application(
            layout=Layout(
                HSplit([
                    Window(FormattedTextControl(self._render_header), height=1),
                    self.transcript,
                    Window(FormattedTextControl(self._render_status), height=1),
                    self.input,
                ]),
                focused_element=self.input,
            ),
            key_bindings=self._key_bindings(),
            style=STYLE,
            full_screen=True,
            mouse_support=False,
        )

        self.system("Type /help for commands.")

    # ---- rendering ----------------------------------------------------

    def _render_header(self):
        if self.session.connected:
            state = ("class:header.ok", " online ")
        else:
            state = ("class:header.bad", " offline ")

        peer = self.session.peer_user or "waiting for peer"
        fragments = [
            ("class:header", " SPECTRE "),
            ("class:header.room", f"#{self.room} "),
            ("class:header.dim", " "),
            ("class:header.room", self.user),
            ("class:header.dim", " <-> "),
            ("class:header.room", peer),
            ("class:header.dim", "  "),
            state,
        ]
        if self.use_tor:
            fragments.append(("class:header.tor", " tor "))
        fragments.append(("class:header", " " * 200))
        return fragments

    def _render_status(self):
        if not self.session.ready:
            return [("class:status", " handshake pending"),
                    ("class:status", " " * 200)]

        if self.session.peer_verified:
            mark = ("class:status.verified", " verified ")
        else:
            mark = ("class:status.unverified", " unverified ")

        number = self.session.safety_number or ""
        short = " ".join(number.split()[:4]) + (" ..." if number else "")

        fragments = [
            mark,
            ("class:status", " safety "),
            ("class:status.number", short),
            ("class:status", f"   sent {self.session.sent_count}"),
            ("class:status", f"  recv {self.session.recv_count}"),
        ]
        if not self.session.can_send:
            fragments.append(("class:status.unverified", "   waiting for first message"))
        fragments.append(("class:status", " " * 200))
        return fragments

    def _render_transcript(self):
        fragments = []
        lines = 0

        # Anchor the transcript to the bottom of its pane, the way a chat log
        # reads, instead of letting a short conversation sit at the top with a
        # gap above the status bar. The pane height is only known after a
        # render, so this settles on the first frame.
        info = self.transcript.render_info
        if info is not None:
            padding = info.window_height - len(self.entries)
            if padding > 0:
                fragments.append(("", "\n" * padding))
                lines += padding

        for style, prefix, text, ts in self.entries:
            stamp = time.strftime("%H:%M", time.localtime(ts))
            fragments.append(("class:time", f"{stamp} "))
            if prefix:
                fragments.append((f"class:{style}", f"{prefix} "))
                fragments.append(("class:text", text))
            else:
                fragments.append((f"class:{style}", text))
            fragments.append(("", "\n"))
            lines += 1
        self._line_count = lines
        return fragments

    def _cursor_position(self):
        # Placing a virtual cursor on the last line makes the window scroll to
        # follow new output; _scroll_back lifts it for manual scrollback.
        target = max(0, self._line_count - 1 - self._scroll_back)
        return Point(x=0, y=target)

    def refresh(self):
        self.app.invalidate()

    # ---- transcript entries -------------------------------------------

    def _add(self, style, prefix, text, ts=None):
        self.entries.append((style, prefix, text, ts or time.time()))
        if len(self.entries) > 2000:
            del self.entries[:500]
        self._scroll_back = 0
        self.refresh()

    def system(self, text):
        self._add("system", "", text)

    def error(self, text):
        self._add("error", "", f"! {text}")

    def warning(self, text):
        self._add("warning", "", f"! {text}")

    def message(self, user, text, ts=None, own=False):
        self._add("self" if own else "peer", f"{user}:", text, ts)

    # ---- events from the session --------------------------------------

    def handle_event(self, kind, payload):
        if kind == "message":
            self.message(payload["user"], payload["text"], payload.get("ts"))
        elif kind == "sent":
            self.message(payload["user"], payload["text"], payload.get("ts"), own=True)
        elif kind == "status":
            self.system(payload["text"])
        elif kind == "error":
            self.error(payload["text"])
        elif kind == "warning":
            self.warning(payload["text"])
        elif kind == "peer":
            verb = "joined" if payload.get("joined") else "left"
            self.system(f"{payload.get('user')} {verb} the room")
        elif kind == "ready":
            self.system(f"Secure session established with {payload.get('peer')}.")
            self.system("Run /verify and compare the safety number out of band.")
        elif kind == "state":
            self.refresh()
        else:
            self.refresh()

    # ---- input --------------------------------------------------------

    def _on_submit(self, buffer):
        text = buffer.text.strip()
        buffer.text = ""
        if not text:
            return
        if text.startswith("/"):
            self._command(text)
        else:
            self.session.send_message(text)

    def _command(self, raw):
        command = raw.split()[0].lower()

        if command == "/quit":
            self.app.exit()

        elif command == "/help":
            for line in HELP_LINES:
                self.system(line)

        elif command == "/clear":
            self.entries.clear()
            self.refresh()

        elif command == "/verify":
            if not self.session.safety_number:
                self.error("No session yet -- nothing to verify.")
                return
            self.system("Safety number -- both of you must read the same digits:")
            digits = self.session.safety_number.split()
            for row in range(0, len(digits), 6):
                self.system("    " + " ".join(digits[row:row + 6]))
            self.system("Compare over a channel the relay does not control "
                        "(in person, a phone call you both recognise).")
            self.session.mark_verified()

        elif command == "/trust":
            if self.session.trust_new_identity():
                self.system("Peer identity updated.")
            else:
                self.error("No pending identity change to accept.")

        else:
            self.error(f"Unknown command {command}. Try /help.")

    def _key_bindings(self):
        kb = KeyBindings()

        @kb.add("c-c")
        @kb.add("c-d")
        def _(event):
            event.app.exit()

        @kb.add("pageup")
        def _(event):
            self._scroll_back = min(self._scroll_back + 10,
                                    max(0, self._line_count - 1))
            self.refresh()

        @kb.add("pagedown")
        def _(event):
            self._scroll_back = max(0, self._scroll_back - 10)
            self.refresh()

        return kb

    def run(self):
        self.app.run()
