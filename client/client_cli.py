"""
Spectre client entry point.

Collects connection details, brings up the session, then hands control to the
full-screen chat UI.
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


def parse_args():
    parser = argparse.ArgumentParser(
        prog="spectre",
        description="End-to-end encrypted chat over Tor.",
    )
    parser.add_argument("--room", help="room name")
    parser.add_argument("--user", help="your username")
    parser.add_argument("--onion", help="onion host of the relay (without http://)")
    parser.add_argument("--url", help=f"relay URL for local use (default {LOCAL_URL})")
    parser.add_argument(
        "--role",
        choices=["initiator", "responder"],
        help="initiator sends the first message; responder replies",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="discard the saved session for this room and handshake again",
    )
    return parser.parse_args()


def prompt(label, default=None):
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default


def normalise_onion(host):
    """Accept 'abc', 'abc.onion' or 'http://abc.onion' and build a URL."""
    host = host.strip()
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.rstrip("/")
    if host.endswith(".onion"):
        host = host[: -len(".onion")]
    return f"http://{host}.onion:80"


def main():
    args = parse_args()
    storage.ensure_dirs()

    print("Spectre -- end-to-end encrypted chat\n")

    room = args.room or prompt("Room", "spectre")
    user = args.user or prompt("Username", "user")

    password = getpass(f"Password for {user}: ")
    if not password:
        sys.exit("A password is required.")

    if args.role:
        is_initiator = args.role == "initiator"
    else:
        answer = prompt("Role - [i]nitiator sends first, [r]esponder replies", "i")
        is_initiator = not answer.lower().startswith("r")

    onion = args.onion if args.onion is not None else prompt(
        "Onion host (blank for localhost)", ""
    )
    if onion:
        url, use_tor = normalise_onion(onion), True
    else:
        url, use_tor = args.url or LOCAL_URL, False

    if args.reset:
        storage.clear_state(user, room)
        print("Saved session for this room discarded.")

    print(f"\nConnecting to {url} ...")

    ui_holder = {}

    def on_event(kind, payload):
        ui = ui_holder.get("ui")
        if ui is not None:
            ui.handle_event(kind, payload)
        elif kind in ("status", "error", "warning"):
            print(f"  {payload.get('text', '')}")

    session = SpectreSession(
        url=url, room=room, user=user, password=password,
        is_initiator=is_initiator, use_tor=use_tor, on_event=on_event,
    )

    try:
        session.connect()
    except Exception as e:
        sys.exit(
            f"Could not reach the relay at {url}: {e}\n"
            + ("Is Tor running and listening on 127.0.0.1:9150?"
               if use_tor else "Is the relay running?")
        )

    session.start()

    try:
        session.authenticate()
    except SessionError as e:
        session.close()
        sys.exit(f"Sign-in failed: {e}")

    session.join()

    ui = ChatUI(session, room=room, user=user, use_tor=use_tor)
    ui_holder["ui"] = ui

    try:
        ui.run()
    finally:
        session.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
