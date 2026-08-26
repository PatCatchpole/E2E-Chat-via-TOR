"""
Pre-chat screens: sign in, then pick a room.

Each screen is its own full-screen Application that exits with the value it
collected, or None if the user backed out. Keeping them separate from the chat
UI means neither has to know about the other's state.

Navigation is uniform: Tab and Shift-Tab move between fields, Enter submits
from anywhere except a button (which runs its own action), Esc or Ctrl-C backs
out.
"""

from __future__ import annotations

import time

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Box, Button, Frame, Label, RadioList, TextArea

STYLE = Style.from_dict({
    "banner": "#7fd1e0 bold",
    "tagline": "#6b7b8c italic",
    "frame.border": "#3c5a6b",
    "frame.label": "#7fd1e0 bold",
    "field.label": "#9aa5b1",
    "text-area": "bg:#12181d #d8dee4",
    "text-area.focused": "bg:#1c2833 #ffffff",
    "button": "#9aa5b1",
    "button.focused": "bg:#7fd1e0 #10161b bold",
    "hint": "#5c6773",
    "error": "#ff6b6b bold",
    "radio": "#d8dee4",
    "radio-selected": "#7fd1e0 bold",
    "radio-checked": "#5fd75f bold",
    "peer": "#5fd75f",
    "dim": "#5c6773",
})

BANNER = [
    r" ___ ___ ___ ___ _____ ___ ___ ",
    r"/ __| _ \ __/ __|_   _| _ \ __|",
    r"\__ \  _/ _| (__  | | |   / _| ",
    r"|___/_| |___\___| |_| |_|_\___|",
]


def _banner_block():
    fragments = []
    for line in BANNER:
        fragments.append(("class:banner", line + "\n"))
    fragments.append(("class:tagline", "     end-to-end encrypted chat\n"))
    return fragments


class SubmitOnEnterList(RadioList):
    """
    A RadioList whose Enter both selects and submits.

    RadioList's arrow keys move a cursor without changing `current_value`;
    only Enter or Space commits it. Its own Enter binding lives on the widget
    and so takes precedence over an application-level one, which meant a plain
    "Enter submits" binding never fired. Overriding the handler keeps the stock
    selection behaviour (via super()) and then submits, so `current_value` is
    always the item the user is looking at.
    """

    def __init__(self, values, on_submit, default=None):
        super().__init__(values=values, default=default)
        self._on_submit = on_submit

    def _handle_enter(self) -> None:
        super()._handle_enter()
        self._on_submit()


def _labelled(label: str, widget, label_width: int = 11):
    return VSplit([
        Window(FormattedTextControl([("class:field.label", label)]),
               width=label_width, dont_extend_width=True),
        widget,
    ])


def _run(container, key_bindings, focus_target):
    app = Application(
        layout=Layout(container, focused_element=focus_target),
        key_bindings=key_bindings,
        style=STYLE,
        full_screen=True,
        mouse_support=False,
    )
    return app.run()


def _base_bindings(on_cancel):
    kb = KeyBindings()
    kb.add("tab")(focus_next)
    kb.add("s-tab")(focus_previous)

    # Arrow keys are deliberately left alone. They belong to whichever widget
    # has focus (the radio lists use them), and binding Escape eagerly here
    # would be worse still: arrow keys arrive as escape sequences, so an eager
    # Escape binding fires on the "\x1b" prefix and every arrow press quits
    # the screen. A non-eager binding lets the longer sequence match first.
    @kb.add("c-c")
    @kb.add("escape")
    def _(event):
        on_cancel(event)

    return kb


# ---------------------------------------------------------------- sign in


def login_screen(relay: str = "127.0.0.1:5055", username: str = "",
                 role: str = "initiator", message: str = ""):
    """
    Collect connection details.

    Returns {"relay", "user", "password", "role"} or None if cancelled.
    Credentials are not checked here -- that happens when the session connects,
    so a failure comes back as `message` on the next pass.
    """
    error = {"text": message}

    relay_field = TextArea(text=relay, multiline=False, wrap_lines=False, height=1)
    user_field = TextArea(text=username, multiline=False, wrap_lines=False, height=1)
    pass_field = TextArea(password=True, multiline=False, wrap_lines=False, height=1)
    role_list = SubmitOnEnterList(
        values=[("initiator", "Initiator  - starts the conversation"),
                ("responder", "Responder  - replies to the initiator")],
        on_submit=lambda: submit(),
        default=role,
    )

    def submit():
        if not relay_field.text.strip():
            error["text"] = "A relay address is required."
        elif not user_field.text.strip():
            error["text"] = "A username is required."
        elif not pass_field.text:
            error["text"] = "A password is required."
        else:
            app.exit(result={
                "relay": relay_field.text.strip(),
                "user": user_field.text.strip(),
                "password": pass_field.text,
                "role": role_list.current_value,
            })
            return
        app.invalidate()

    for field in (relay_field, user_field, pass_field):
        field.accept_handler = lambda buf: (submit(), False)[1]

    kb = _base_bindings(lambda event: event.app.exit(result=None))

    @kb.add("enter")
    def _(event):
        submit()

    body = HSplit([
        Window(height=1),
        Window(FormattedTextControl(_banner_block), height=len(BANNER) + 1),
        Window(height=1),
        Frame(
            Box(HSplit([
                _labelled("Relay", relay_field),
                Window(height=1),
                _labelled("Username", user_field),
                Window(height=1),
                _labelled("Password", pass_field),
                Window(height=1),
                _labelled("Role", role_list),
            ]), padding_left=1, padding_right=1, padding_top=1, padding_bottom=1),
            title="Sign in",
        ),
        Window(FormattedTextControl(lambda: [("class:error", error["text"])]), height=1),
        VSplit([
            Window(),
            Button("Connect", handler=submit, width=13),
            Window(width=2),
            Button("Quit", handler=lambda: app.exit(result=None), width=10),
            Window(),
        ], height=1),
        Window(height=1),
        Window(FormattedTextControl([
            ("class:hint", "Tab / Shift-Tab move   Enter connects   Esc quits")
        ]), height=1),
    ])

    root = Box(body, padding_left=4, padding_right=4)
    app = Application(
        layout=Layout(root, focused_element=user_field if not username else pass_field),
        key_bindings=kb, style=STYLE, full_screen=True, mouse_support=False,
    )
    return app.run()


# ------------------------------------------------------------ room picker

NEW_ROOM = object()


def room_screen(user: str, rooms: list):
    """
    Pick a previously used room or name a new one.

    `rooms` is storage.list_rooms() output. Returns the room name, or None.
    """
    error = {"text": ""}
    new_field = TextArea(multiline=False, wrap_lines=False, height=1)

    # With no previous rooms there is no radio list to show or focus; the
    # screen collapses to just the "new room" field. Focusing a widget that is
    # not in the layout raises, which is exactly what a first-time user hit.
    values = []
    for entry in rooms:
        peer = entry.get("peer")
        when = entry.get("last_used") or 0
        stamp = time.strftime("%d %b %H:%M", time.localtime(when)) if when else ""
        label = [
            ("class:radio", f"{entry['room']:<18}"),
            ("class:peer", f"{('with ' + peer) if peer else 'no peer yet':<20}"),
            ("class:dim", stamp),
        ]
        values.append((entry["room"], label))
    values.append((NEW_ROOM, [("class:radio", "+ new room")]))

    room_list = (
        SubmitOnEnterList(values=values, on_submit=lambda: submit(),
                          default=values[0][0])
        if rooms else None
    )

    def submit():
        choice = room_list.current_value if room_list is not None else NEW_ROOM
        if choice is NEW_ROOM:
            name = new_field.text.strip()
            if not name:
                error["text"] = "Type a name for the new room below."
                app.invalidate()
                return
            app.exit(result=name)
        else:
            app.exit(result=choice)

    new_field.accept_handler = lambda buf: (submit(), False)[1]

    kb = _base_bindings(lambda event: event.app.exit(result=None))

    @kb.add("enter")
    def _(event):
        submit()

    if room_list is not None:
        known = HSplit([room_list])
    else:
        known = HSplit([
            Window(FormattedTextControl([
                ("class:dim", "No rooms on this machine yet. Name one below to start.")
            ]), height=1)
        ])

    body = HSplit([
        Window(height=1),
        Window(FormattedTextControl(
            lambda: [("class:banner", "  SPECTRE  "),
                     ("class:tagline", f"signed in as {user}")]), height=1),
        Window(height=1),
        Frame(
            Box(HSplit([
                known,
                Window(height=1),
                _labelled("New room", new_field, label_width=11),
            ]), padding_left=1, padding_right=1, padding_top=1, padding_bottom=1),
            title="Choose a room",
        ),
        Window(FormattedTextControl(lambda: [("class:error", error["text"])]), height=1),
        VSplit([
            Window(),
            Button("Enter room", handler=submit, width=15),
            Window(width=2),
            Button("Back", handler=lambda: app.exit(result=None), width=10),
            Window(),
        ], height=1),
        Window(height=1),
        Window(FormattedTextControl([
            ("class:hint", "Up / Down choose   Enter joins   Esc goes back")
        ]), height=1),
    ])

    root = Box(body, padding_left=4, padding_right=4)
    app = Application(
        layout=Layout(root, focused_element=room_list or new_field),
        key_bindings=kb, style=STYLE, full_screen=True, mouse_support=False,
    )
    return app.run()
