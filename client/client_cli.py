"""
Spectre client entry point.

By default this runs a sign-in screen and a room picker, then hands over to the
chat UI. `--classic` falls back to plain stdin prompts, which is what scripts
and pipes want.
"""

from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass

import storage
from session import SessionError, SpectreSession
from ui import ChatUI

# Overridable because the default port collides with AirPlay Receiver on macOS.
LOCAL_HOST = os.environ.get("SPECTRE_RELAY_HOST", "127.0.0.1")
LOCAL_PORT = os.environ.get("SPECTRE_RELAY_PORT", "5000")
LOCAL_URL = f"http://{LOCAL_HOST}:{LOCAL_PORT}"
DEFAULT_RELAY = f"{LOCAL_HOST}:{LOCAL_PORT}"


def parse_args():
    parser = argparse.ArgumentParser(
        prog="spectre",
        description="End-to-end encrypted chat over Tor.",
    )
    parser.add_argument("--room", help="room name (skips the room picker)")
    parser.add_argument("--user", help="your username")
    parser.add_argument("--onion", help="onion host of the relay (without http://)")
    parser.add_argument("--url", help=f"relay URL for local use (default {LOCAL_URL})")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="discard the saved session for this room and handshake again",
    )
    parser.add_argument(
        "--classic",
        action="store_true",
        help="use plain text prompts instead of the full-screen screens",
    )
    return parser.parse_args()


def prompt(label, default=None):
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default


def normalise_onion(host):
    """
    Accept 'abc', 'abc.onion', 'abc.onion:8080' or 'http://abc.onion/' and
    build a URL.

    The port has to be split off before the '.onion' suffix is stripped;
    otherwise 'abc.onion:80' keeps its suffix and gets a second one appended.
    """
    host = host.strip()
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.rstrip("/")

    port = "80"
    if ":" in host:
        host, _, given = host.rpartition(":")
        if given.isdigit():
            port = given
        else:                       # not a port after all; put it back
            host = f"{host}:{given}"

    if host.endswith(".onion"):
        host = host[: -len(".onion")]
    return f"http://{host}.onion:{port}"


def resolve_relay(text: str):
    """
    Turn whatever was typed into (url, use_tor).

    Accepts 'host:port', 'http://host:port' and '<hash>.onion'.
    """
    text = (text or "").strip()
    if not text:
        return LOCAL_URL, False
    if ".onion" in text:
        return normalise_onion(text), True
    if text.startswith("http://") or text.startswith("https://"):
        return text.rstrip("/"), False
    return f"http://{text}", False


def classic_details(args):
    """Plain prompts, for scripts and for when the full-screen UI is unwanted."""
    print("Spectre -- end-to-end encrypted chat\n")

    user = args.user or prompt("Username", "user")
    password = getpass(f"Password for {user}: ")
    if not password:
        sys.exit("A password is required.")

    if args.onion:
        url, use_tor = normalise_onion(args.onion), True
    elif args.url:
        url, use_tor = args.url, False
    else:
        onion = prompt("Onion host (blank for localhost)", "")
        url, use_tor = (normalise_onion(onion), True) if onion else (LOCAL_URL, False)

    room = args.room or prompt("Room", "spectre")
    return {"user": user, "password": password,
            "url": url, "use_tor": use_tor, "room": room}


def screen_details(args):
    """
    Sign-in screen, then the room picker.

    Same shape as `classic_details`, or None if the user backed out. Backing out
    of the room picker returns to sign in rather than quitting.
    """
    import screens

    if args.onion:
        relay_default = args.onion
    elif args.url:
        relay_default = args.url
    else:
        relay_default = DEFAULT_RELAY

    message = ""
    username = args.user or ""

    while True:
        credentials = screens.login_screen(
            relay=relay_default, username=username, message=message,
        )
        if credentials is None:
            return None

        username = credentials["user"]
        relay_default = credentials["relay"]
        url, use_tor = resolve_relay(credentials["relay"])

        if args.room:
            room = args.room
        else:
            room = screens.room_screen(username, storage.list_rooms(username))
            if room is None:
                message = ""
                continue        # back to sign in

        return {"user": username, "password": credentials["password"],
                "url": url, "use_tor": use_tor, "room": room}


def run_session(details, reset: bool = False):
    """
    Connect, sign in, join the room and hand over to the chat UI.

    `details` is what the sign-in screens produce: user, password, url,
    use_tor and room. Split out of `main` so `spectre.py` can drive exactly
    this path after starting a relay, rather than re-implementing it.
    """
    if reset:
        storage.clear_state(details["user"], details["room"])
        print(f"Saved session for '{details['room']}' discarded.")

    print(f"\nConnecting to {details['url']} ...")

    ui_holder = {}

    def on_event(kind, payload):
        ui = ui_holder.get("ui")
        if ui is not None:
            ui.handle_event(kind, payload)
        elif kind in ("status", "error", "warning"):
            print(f"  {payload.get('text', '')}")

    session = SpectreSession(
        url=details["url"], room=details["room"], user=details["user"],
        password=details["password"], use_tor=details["use_tor"],
        on_event=on_event,
    )

    try:
        session.connect()
    except Exception as e:
        hint = ("Is Tor running and listening on 127.0.0.1:9150?"
                if details["use_tor"] else "Is the relay running?")
        sys.exit(f"Could not reach the relay at {details['url']}: {e}\n{hint}")

    session.start()

    try:
        session.authenticate()
    except SessionError as e:
        session.close()
        sys.exit(f"Sign-in failed: {e}")

    session.join()

    ui = ChatUI(session, room=details["room"], user=details["user"],
                use_tor=details["use_tor"])
    ui_holder["ui"] = ui

    try:
        ui.run()
    finally:
        session.close()
        print("Disconnected.")


def main():
    args = parse_args()
    storage.ensure_dirs()

    # The full-screen screens need a real terminal; piped input falls back to
    # plain prompts so scripts keep working.
    use_screens = not args.classic and sys.stdin.isatty() and sys.stdout.isatty()
    details = screen_details(args) if use_screens else classic_details(args)
    if details is None:
        return
    run_session(details, reset=args.reset)


if __name__ == "__main__":
    main()
