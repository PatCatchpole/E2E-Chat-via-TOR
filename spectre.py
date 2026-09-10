#!/usr/bin/env python3
"""
Spectre launcher -- the one file to run.

Everything the chat needs is started from here, so there is nothing to type and
no second terminal to keep open:

    python spectre.py

It asks whether to host a room or join one, starts the relay and its backend
when hosting, and then hands over to the sign-in screen and the chat UI.

`client_cli.py` is still the client, and is unchanged in what it does; this
only removes the setup around it. Anything this launcher does by hand can still
be done by hand -- see README §4.
"""

from __future__ import annotations

import atexit
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLIENT_DIR = ROOT / "client"

# The client imports its own modules flat (`storage`, `session`, `crypto.*`),
# which is why it has always had to be run from inside client/. Putting the
# directory on the path here is what removes that requirement.
sys.path.insert(0, str(CLIENT_DIR))

RELAY_SCRIPT = ROOT / "server" / "app.py"
BACKEND_SCRIPT = ROOT / "tools" / "dev_backend.py"

# 5000 is AirPlay Receiver on macOS, which answers 403 rather than refusing the
# connection -- an error that looks like a relay bug. Start above it.
PREFERRED_RELAY_PORT = 5055
PREFERRED_BACKEND_PORT = 8090

STARTUP_TIMEOUT = 20


# ---------------------------------------------------------------- guards


def _require(modules, purpose):
    """Fail with an instruction rather than a traceback from deep in an import."""
    missing = []
    for module, package in modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if not missing:
        return

    here = Path(sys.executable).resolve()
    venv_pip = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / "pip"
    pip = str(venv_pip) if venv_pip.exists() else f"{here} -m pip"
    sys.exit(
        f"Missing {purpose}: {', '.join(missing)}\n\n"
        f"Install them with:\n    {pip} install -r {ROOT / 'requirements.txt'}"
    )


CLIENT_DEPENDENCIES = [
    ("nacl", "PyNaCl"),
    ("prompt_toolkit", "prompt_toolkit"),
    ("socketio", "python-socketio"),
    ("requests", "requests"),
]

RELAY_DEPENDENCIES = [
    ("flask", "Flask"),
    ("flask_socketio", "Flask-SocketIO"),
    ("engineio", "python-engineio"),
]


# ------------------------------------------------------------ networking


def _listening(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(timeout)
        return probe.connect_ex((host, port)) == 0


def _free_port(preferred: int) -> int:
    """The preferred port if nothing holds it, otherwise the next one that is free."""
    for port in range(preferred, preferred + 20):
        if not _listening(port):
            return port
    with socket.socket() as sock:      # give up on being predictable
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_until_listening(port: int, process=None, timeout: float = STARTUP_TIMEOUT) -> bool:
    """
    Poll until the port answers, giving up early if the process has already died
    -- otherwise a backend that exits on a bad token costs a full timeout before
    saying so.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            return False
        if _listening(port):
            return True
        time.sleep(0.15)
    return False


def _lan_address():
    """
    This machine's address on the local network, or None.

    Opening a UDP socket towards a public address sends no packets; it just
    makes the kernel choose a route, which is the only reliable way to find
    which of several interfaces a peer would actually reach us on.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


# ------------------------------------------------------------ local relay


class LocalRelay:
    """
    A relay and its backend, running as child processes for as long as we do.

    Both write to log files rather than the terminal: the chat UI takes over
    the screen, and relay output scribbled across it would be unreadable. The
    logs are where to look when something fails to start.
    """

    def __init__(self, token: str):
        self.token = token
        self.relay_port = _free_port(PREFERRED_RELAY_PORT)
        self.backend_port = _free_port(PREFERRED_BACKEND_PORT)
        self.processes = []
        self.log_dir = Path.home() / ".spectre" / "logs"

    # -- lifecycle --

    def start(self) -> None:
        _require(RELAY_DEPENDENCIES, "relay dependencies")
        self.log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        environment = dict(os.environ)
        environment.update({
            "SPECTRE_INTERNAL_TOKEN": self.token,
            "SPECTRE_BACKEND_PORT": str(self.backend_port),
            "SPECTRE_BACKEND_URL": f"http://127.0.0.1:{self.backend_port}",
            # Bound to every interface so other machines can reach the room.
            # The client below still connects over loopback.
            "SPECTRE_RELAY_HOST": "0.0.0.0",
            "SPECTRE_RELAY_PORT": str(self.relay_port),
            "SPECTRE_ALLOW_DEV_SERVER": "1",
            "SPECTRE_LOG_LEVEL": "WARNING",
            "PYTHONUNBUFFERED": "1",
        })

        backend = self._spawn(BACKEND_SCRIPT, environment, "backend")
        if not _wait_until_listening(self.backend_port, backend):
            self.stop()
            raise RuntimeError(self._failure("backend", backend))

        relay = self._spawn(RELAY_SCRIPT, environment, "relay")
        if not _wait_until_listening(self.relay_port, relay):
            self.stop()
            raise RuntimeError(self._failure("relay", relay))

        atexit.register(self.stop)
        self._install_signal_handlers()

    def _install_signal_handlers(self) -> None:
        """
        Stop the children when we are killed, not just when we exit cleanly.

        `atexit` covers a normal return and Ctrl-C, but not SIGTERM or SIGHUP --
        and SIGHUP is what closing the Terminal window sends. Because the relay
        runs in its own process group it does not receive those signals itself,
        so without this it would be orphaned and go on listening on the network
        with nobody attached to it.
        """
        def handler(signum, _frame):
            self.stop()
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)      # exit as the signal intended

        for name in ("SIGTERM", "SIGHUP"):
            number = getattr(signal, name, None)
            if number is None:
                continue
            try:
                signal.signal(number, handler)
            except (OSError, ValueError):
                pass                          # not the main thread, or unsupported

    def _spawn(self, script: Path, environment: dict, name: str):
        # 0600 like everything else under ~/.spectre. The relay never logs
        # ciphertext or the token, but it does log who joined which room, and
        # that is exactly the metadata the rest of this directory protects.
        path = self.log_dir / f"{name}.log"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        handle = os.fdopen(descriptor, "w", encoding="utf-8")
        if os.name == "posix":
            # The mode above applies only when the file is created, so a log
            # left behind by an earlier version keeps its old permissions.
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        process = subprocess.Popen(
            [sys.executable, str(script)],
            cwd=str(ROOT),
            env=environment,
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            # Its own process group, so the Ctrl-C that stops the chat UI does
            # not also kill the relay before we have saved session state.
            start_new_session=(os.name != "nt"),
        )
        self.processes.append((name, process, handle))
        return process

    def _failure(self, name: str, process) -> str:
        log = self.log_dir / f"{name}.log"
        detail = ""
        try:
            tail = log.read_text(encoding="utf-8").strip().splitlines()[-6:]
            detail = "\n    ".join(tail)
        except OSError:
            pass
        exited = "" if process.poll() is None else f" (exited {process.returncode})"
        return (
            f"The {name} did not start{exited}.\n"
            f"  Log: {log}\n"
            + (f"    {detail}" if detail else "")
        )

    def stop(self) -> None:
        for _, process, handle in reversed(self.processes):
            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                except OSError:
                    pass
            try:
                handle.close()
            except OSError:
                pass
        self.processes = []

    # -- views --

    @property
    def local_url(self) -> str:
        return f"http://127.0.0.1:{self.relay_port}"

    def addresses(self) -> list:
        rows = [("On this Mac", f"127.0.0.1:{self.relay_port}")]
        lan = _lan_address()
        if lan:
            rows.append(("Share this", f"{lan}:{self.relay_port}"))
        return rows


def _relay_token() -> str:
    """Reuse the machine's token so a restart does not orphan stored accounts."""
    import storage

    token = storage.load_relay_token()
    if not token:
        token = secrets.token_urlsafe(32)
        storage.save_relay_token(token)
    return token


# ------------------------------------------------------------------ flow


def _sign_in(screens, storage, client_cli, relay_default: str, hosting: bool):
    """
    Sign in, then pick a room. Returns the details dict, or None to quit.

    When hosting, the relay field is prefilled with our own address but stays
    editable -- silently overriding what somebody typed would be worse than
    letting them point elsewhere on purpose.
    """
    prefs = storage.load_launcher_prefs()
    username = prefs.get("user", "")
    message = ""

    while True:
        credentials = screens.login_screen(
            relay=relay_default, username=username, message=message,
        )
        if credentials is None:
            return None

        username = credentials["user"]
        relay_default = credentials["relay"]
        url, use_tor = client_cli.resolve_relay(relay_default)

        room = screens.room_screen(username, storage.list_rooms(username))
        if room is None:
            message = ""
            continue                    # back to sign in

        storage.save_launcher_prefs({
            "user": username, "relay": relay_default, "hosted": hosting,
        })
        return {
            "user": username, "password": credentials["password"],
            "url": url, "use_tor": use_tor, "room": room,
        }


def main() -> None:
    _require(CLIENT_DEPENDENCIES, "client dependencies")

    import client_cli
    import screens
    import storage

    storage.ensure_dirs()

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.exit(
            "spectre.py needs a real terminal for its screens.\n"
            "For scripts and pipes, run: python client/client_cli.py --classic"
        )

    prefs = storage.load_launcher_prefs()
    choice = screens.start_screen(
        default=screens.HOST if prefs.get("hosted") else screens.JOIN
    )
    if choice is None:
        return

    relay = None
    try:
        if choice == screens.HOST:
            relay = LocalRelay(_relay_token())
            print("Starting the relay ...")
            try:
                relay.start()
            except RuntimeError as error:
                sys.exit(str(error))

            if screens.host_ready_screen(relay.addresses()) is None:
                return
            relay_default = f"127.0.0.1:{relay.relay_port}"
        else:
            relay_default = prefs.get("relay") or f"127.0.0.1:{PREFERRED_RELAY_PORT}"

        details = _sign_in(screens, storage, client_cli, relay_default,
                           hosting=choice == screens.HOST)
        if details is None:
            return

        client_cli.run_session(details)
    finally:
        if relay is not None:
            print("Stopping the relay ...")
            relay.stop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
