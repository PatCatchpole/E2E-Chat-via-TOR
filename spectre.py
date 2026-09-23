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

It is also the entry point of the packaged build (`packaging/`), where Python,
every dependency and a tor binary are frozen into one executable. That build
has no interpreter to hand a script to, so the relay and backend are started
by running this same executable again with `--serve`.
"""

from __future__ import annotations

import argparse
import atexit
import os
import runpy
import secrets
import signal
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

# In a PyInstaller build the sources are unpacked to a temporary directory
# named by `sys._MEIPASS`, and `sys.executable` is the bundle, not Python.
FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parent
CLIENT_DIR = ROOT / "client"

# The client imports its own modules flat (`storage`, `session`, `crypto.*`),
# which is why it has always had to be run from inside client/. Putting the
# directory on the path here is what removes that requirement.
sys.path.insert(0, str(CLIENT_DIR))

RELAY_SCRIPT = ROOT / "server" / "app.py"
BACKEND_SCRIPT = ROOT / "tools" / "dev_backend.py"
SERVICES = {"relay": RELAY_SCRIPT, "backend": BACKEND_SCRIPT}

# 5000 is AirPlay Receiver on macOS, which answers 403 rather than refusing the
# connection -- an error that looks like a relay bug. Start above it.
PREFERRED_RELAY_PORT = 5055
PREFERRED_BACKEND_PORT = 8090

STARTUP_TIMEOUT = 20

# The packaged build carries its own tor (the Tor Project's expert bundle) so
# that nobody has to install one; it is always preferred when present.
# Otherwise Homebrew does not put tor on a login shell's PATH for every setup,
# so the usual install locations are checked too rather than failing with
# "not found" on a machine that has it.
BUNDLED_TOR = ROOT / "tor" / ("tor.exe" if os.name == "nt" else "tor")
TOR_BINARIES = ("tor", "/opt/homebrew/bin/tor", "/usr/local/bin/tor", "/usr/bin/tor")
TOR_BOOTSTRAP_TIMEOUT = 120

# Children must not share our Ctrl-C. POSIX gets that from a new session;
# Windows delivers Ctrl-C to the whole console process group instead, so the
# child needs a group of its own. Closing the console window still ends every
# process attached to it, so nothing is left listening unattended.
if os.name == "nt":
    DETACHED = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
else:
    DETACHED = {"start_new_session": True}


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


# ------------------------------------------------------------ children


_STOPPERS = []


def _stop_on_exit(stop) -> None:
    """
    Run `stop` when we exit, however we exit.

    `atexit` covers a normal return and Ctrl-C, but not SIGTERM or SIGHUP --
    and SIGHUP is what closing the Terminal window sends. Every child runs in
    its own process group, so it does not receive those signals itself, and
    without this it would be orphaned and go on listening on the network with
    nobody attached to it.

    One shared list rather than a handler per child: the handler used to belong
    to the relay alone, so a closed window stopped the relay and left tor
    running -- still publishing the onion address, and in a packaged build
    still running out of a temporary directory that was never cleaned up.
    """
    if not _STOPPERS:
        atexit.register(_stop_all)
        _install_signal_handlers()
    _STOPPERS.append(stop)


def _stop_all() -> None:
    while _STOPPERS:
        try:
            _STOPPERS.pop()()
        except Exception:
            pass


def _install_signal_handlers() -> None:
    def handler(signum, _frame):
        _stop_all()
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

        backend = self._spawn(environment, "backend")
        if not _wait_until_listening(self.backend_port, backend):
            self.stop()
            raise RuntimeError(self._failure("backend", backend))

        relay = self._spawn(environment, "relay")
        if not _wait_until_listening(self.relay_port, relay):
            self.stop()
            raise RuntimeError(self._failure("relay", relay))

        _stop_on_exit(self.stop)

    def _spawn(self, environment: dict, name: str):
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
        # A frozen build has no interpreter to hand the script to, so it runs
        # itself again and `--serve` picks the service.
        if FROZEN:
            command = [sys.executable, "--serve", name]
        else:
            command = [sys.executable, str(SERVICES[name])]
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            env=environment,
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            # Its own process group, so the Ctrl-C that stops the chat UI does
            # not also kill the relay before we have saved session state.
            **DETACHED,
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


class TorProcess:
    """
    A private tor, run for as long as we do: a SOCKS proxy for reaching onion
    addresses, and optionally a v3 onion service publishing the relay.

    Self-contained under ~/.spectre: its own DataDirectory, its own torrc and
    its own SocksPort, so it neither needs root nor collides with a system
    `tor` daemon or an open Tor Browser. Nothing in /etc is touched.

    Hosting and joining use separate directories (`tor` and `tor-client`).
    Tor locks its DataDirectory, so sharing one would stop somebody from
    hosting a room in one window and joining another in the next.

    When publishing, the service key in `tor/spectre/` is what makes the
    address yours, and it is kept across runs so an address you have handed
    out keeps working. Tor refuses to start unless that directory is 0700,
    which is the same standard the rest of ~/.spectre is held to.
    """

    def __init__(self, publish_port: int = None):
        self.publish_port = publish_port
        self.root = Path.home() / ".spectre" / ("tor" if publish_port else "tor-client")
        self.service_dir = self.root / "spectre"
        # Our own SOCKS port: 9050 and 9150 may already be taken by a daemon
        # or by Tor Browser, and starting a second tor on a used port fails.
        self.socks_port = _free_port(9250)
        self.process = None
        self.handle = None
        self.hostname = None

    # -- lifecycle --

    @staticmethod
    def binary():
        if BUNDLED_TOR.exists():
            return str(BUNDLED_TOR)
        for candidate in TOR_BINARIES:
            path = shutil.which(candidate)
            if path:
                return path
        return None

    @staticmethod
    def _path(path: Path) -> str:
        # Quoted so a home directory with a space in it survives, and with
        # forward slashes because a quoted torrc value treats backslashes as
        # escapes -- which every Windows path is full of. Tor on Windows
        # accepts forward slashes.
        return '"' + path.as_posix() + '"'

    def start(self) -> None:
        binary = self.binary()
        if binary is None:
            raise RuntimeError(
                "tor is not installed.\n  Install it with:  brew install tor\n"
                "  or use a packaged build of Spectre, which carries its own."
            )

        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.root / "data").mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (self.root, self.root / "data"):
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass

        lines = [
            "# Written by spectre.py. Self-contained: no system tor config.",
            f"SocksPort {self.socks_port}",
            f"DataDirectory {self._path(self.root / 'data')}",
            # To stdout, which is redirected to tor.log below. A `Log ... file`
            # line cannot take a quoted path, so it would break on a space.
            "Log notice stdout",
        ]
        if self.publish_port:
            lines += [
                f"HiddenServiceDir {self._path(self.service_dir)}",
                f"HiddenServicePort 80 127.0.0.1:{self.publish_port}",
            ]
        torrc = self.root / "torrc"
        torrc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(torrc, 0o600)

        environment = dict(os.environ)
        if binary == str(BUNDLED_TOR) and sys.platform.startswith("linux"):
            # The expert bundle ships libevent and friends beside the binary;
            # macOS finds them through @executable_path, Linux needs telling.
            environment["LD_LIBRARY_PATH"] = str(BUNDLED_TOR.parent)

        descriptor = os.open(self.root / "tor.log",
                             os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.handle = os.fdopen(descriptor, "w", encoding="utf-8")
        self.process = subprocess.Popen(
            [binary, "-f", str(torrc)],
            cwd=str(self.root), env=environment,
            stdout=self.handle, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            # Same reasoning as the relay: its own process group so the Ctrl-C
            # that stops the chat does not kill it mid-publish.
            **DETACHED,
        )
        _stop_on_exit(self.stop)

        self._await_bootstrap()
        if self.publish_port:
            self.hostname = (self.service_dir / "hostname").read_text(encoding="utf-8").strip()

    def _await_bootstrap(self) -> None:
        """Wait for tor to bootstrap (and publish), or explain why it did not."""
        deadline = time.time() + TOR_BOOTSTRAP_TIMEOUT
        hostname_file = self.service_dir / "hostname"
        log_path = self.root / "tor.log"

        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self._failure("exited"))
            try:
                log = log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                log = ""
            published = hostname_file.exists() or not self.publish_port
            if published and "Bootstrapped 100%" in log:
                return
            time.sleep(1.0)

        self.stop()
        raise RuntimeError(self._failure("did not finish bootstrapping"))

    def _failure(self, what: str) -> str:
        log = self.root / "tor.log"
        detail = ""
        try:
            tail = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-6:]
            detail = "\n    ".join(tail)
        except OSError:
            pass
        return (
            f"tor {what}.\n"
            f"  Log: {log}\n"
            + (f"    {detail}" if detail else "")
        )

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except OSError:
                pass
        self.process = None
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None


def _relay_token() -> str:
    """Reuse the machine's token so a restart does not orphan stored accounts."""
    import storage

    token = storage.load_relay_token()
    if not token:
        token = secrets.token_urlsafe(32)
        storage.save_relay_token(token)
    return token


# ------------------------------------------------------------------ flow


def _sign_in(screens, storage, client_cli, relay_default: str, choice: str):
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
            "user": username, "relay": relay_default, "start": choice,
        })
        return {
            "user": username, "password": credentials["password"],
            "url": url, "use_tor": use_tor, "room": room,
        }


def _parse_args():
    parser = argparse.ArgumentParser(
        prog="spectre.py",
        description="Start Spectre: host a room or join one.",
    )
    parser.add_argument(
        "--tor", action="store_true",
        help="preselect hosting over Tor on the start screen. Joining over "
             "Tor needs no flag -- just paste the .onion address.",
    )
    # Internal: how a frozen build runs its own relay and backend.
    parser.add_argument("--serve", choices=sorted(SERVICES), help=argparse.SUPPRESS)
    return parser.parse_args()


def _serve(name: str) -> None:
    """Run the relay or backend in this process, as its own script would."""
    script = SERVICES[name]
    sys.path.insert(0, str(script.parent))
    sys.argv = [str(script)]
    runpy.run_path(str(script), run_name="__main__")


def _start_screen_default(screens, prefs: dict, args) -> str:
    if args.tor:
        return screens.HOST_TOR
    choice = prefs.get("start")
    if choice in (screens.HOST, screens.HOST_TOR, screens.JOIN):
        return choice
    # Preferences written before hosting over Tor was a menu choice.
    return screens.HOST if prefs.get("hosted") else screens.JOIN


def _tor_for_joining(session_module):
    """
    Start our own tor to reach an onion relay, or None to fall back.

    Without this, joining over Tor only worked for somebody already running a
    tor daemon or a connected Tor Browser -- one more thing to install and
    start before the chat would. An explicit SPECTRE_TOR_SOCKS_PORT still
    wins, and with no tor binary at all the old 9050/9150 search is kept.
    """
    if session_module.TOR_SOCKS_PORT or TorProcess.binary() is None:
        return None
    tor = TorProcess()
    print("Connecting to the Tor network (the first time can take a minute) ...")
    try:
        tor.start()
    except RuntimeError as error:
        print(f"\nCould not start tor: {error}\n"
              f"Trying a tor that is already running instead.\n")
        return None
    session_module.TOR_SOCKS_PORT = tor.socks_port
    return tor


def main() -> None:
    args = _parse_args()
    if args.serve:
        _serve(args.serve)
        return

    _require(CLIENT_DEPENDENCIES, "client dependencies")

    import client_cli
    import screens
    import session as session_module
    import storage

    storage.ensure_dirs()

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.exit(
            "spectre.py needs a real terminal for its screens.\n"
            "For scripts and pipes, run: python client/client_cli.py --classic"
        )

    prefs = storage.load_launcher_prefs()
    choice = screens.start_screen(default=_start_screen_default(screens, prefs, args))
    if choice is None:
        return

    relay = None
    tor = None
    try:
        if choice in (screens.HOST, screens.HOST_TOR):
            relay = LocalRelay(_relay_token())
            print("Starting the relay ...")
            try:
                relay.start()
            except RuntimeError as error:
                sys.exit(str(error))

            if choice == screens.HOST_TOR:
                # Publishing reaches the whole Tor network, so it is a
                # separate choice rather than something hosting does on your
                # behalf.
                print("Publishing the room on Tor (this takes a minute) ...")
                tor = TorProcess(publish_port=relay.relay_port)
                try:
                    tor.start()
                except RuntimeError as error:
                    tor = None
                    print(f"\nCould not publish over Tor: {error}\n"
                          f"Carrying on with the local room only.\n")

            if screens.host_ready_screen(
                    relay.addresses(),
                    onion=tor.hostname if tor else None) is None:
                return
            relay_default = f"127.0.0.1:{relay.relay_port}"
        else:
            relay_default = prefs.get("relay") or f"127.0.0.1:{PREFERRED_RELAY_PORT}"

        details = _sign_in(screens, storage, client_cli, relay_default, choice)
        if details is None:
            return

        if details["use_tor"] and tor is None:
            tor = _tor_for_joining(session_module)

        client_cli.run_session(details)
    finally:
        if tor is not None:
            print("Stopping tor ...")
            tor.stop()
        if relay is not None:
            print("Stopping the relay ...")
            relay.stop()


def _hold_window(message) -> None:
    """
    Keep an error on screen in a packaged build.

    Double-clicking opens a console that closes the moment we exit -- on
    Windows always, elsewhere depending on the terminal -- taking the reason
    with it. Spectre.command does the same for the script.
    """
    if message:
        print(message if isinstance(message, str) else f"Exited with status {message}.",
              file=sys.stderr)
    try:
        input("\nPress Enter to close this window.")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
    except SystemExit as exit_:
        if FROZEN and exit_.code not in (None, 0) and "--serve" not in sys.argv:
            _hold_window(exit_.code)
            sys.exit(1)
        raise
    except Exception:
        if not FROZEN or "--serve" in sys.argv:
            raise
        import traceback
        traceback.print_exc()
        _hold_window(None)
        sys.exit(1)
