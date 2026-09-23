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
import threading
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
# child needs a group of its own. CREATE_NO_WINDOW because the packaged app is
# a windowed program with no console: tor.exe is a console program, and without
# it every launch would flash up a black window of its own.
if os.name == "nt":
    DETACHED = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP
                                 | subprocess.CREATE_NO_WINDOW}
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
            # Loopback only. People reach the room through the onion service,
            # which tor forwards here; binding every interface as well would
            # put the relay's plain HTTP -- login verifiers included -- on the
            # local network for anyone on it to read.
            "SPECTRE_RELAY_HOST": "127.0.0.1",
            "SPECTRE_RELAY_PORT": str(self.relay_port),
            "SPECTRE_ALLOW_DEV_SERVER": "1",
            "SPECTRE_LOG_LEVEL": "WARNING",
            "PYTHONUNBUFFERED": "1",
            # Checked by _serve, so the relay and backend exit if we vanish.
            "SPECTRE_PARENT_PID": str(os.getpid()),
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
        # Always through `--serve`, which is what makes a child exit when we
        # die (see _watch_parent). A frozen build has no interpreter to hand
        # a script to anyway, so it runs itself again.
        if FROZEN:
            command = [sys.executable, "--serve", name]
        else:
            command = [sys.executable, str(Path(__file__).resolve()), "--serve", name]
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

    def start(self, on_bootstrapped=None) -> None:
        """
        Start tor and wait until it is usable. `on_bootstrapped`, if given, is
        called once tor has reached the network -- before the onion service
        is published, which can take as long again.
        """
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
            # Tor exits by itself once this process is gone. Our own cleanup
            # never runs when the app is ended abruptly -- and on macOS that
            # includes Cmd-Q, which terminates without returning to Python --
            # and a tor left behind keeps the onion service published and
            # holds the data directory, so the next launch cannot start one.
            f"__OwningControllerProcess {os.getpid()}",
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

        self._await_bootstrap(on_bootstrapped)
        if self.publish_port:
            self.hostname = (self.service_dir / "hostname").read_text(encoding="utf-8").strip()

    def _await_bootstrap(self, on_bootstrapped=None) -> None:
        """Wait for tor to bootstrap (and publish), or explain why it did not."""
        deadline = time.time() + TOR_BOOTSTRAP_TIMEOUT
        hostname_file = self.service_dir / "hostname"
        log_path = self.root / "tor.log"
        announced = False

        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self._failure("exited"))
            try:
                log = log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                log = ""
            bootstrapped = "Bootstrapped 100%" in log
            if bootstrapped and not announced and on_bootstrapped is not None:
                announced = True
                on_bootstrapped()
            published = hostname_file.exists() or not self.publish_port
            if published and bootstrapped:
                return
            time.sleep(1.0)

        self.stop()
        raise RuntimeError(self._failure("did not finish bootstrapping"))

    def _failure(self, what: str) -> str:
        log = self.root / "tor.log"
        detail = ""
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
            tail = text.strip().splitlines()[-6:]
            detail = "\n    ".join(tail)
        except OSError:
            text = ""
        if "another Tor process is running with the same data directory" in text:
            return (
                "Another copy of Spectre is still using Tor on this computer -- "
                "one that is open, or one that was closed and is still shutting "
                "down. Quit it, wait half a minute, and try again. If it keeps "
                "happening, restarting the computer clears it.\n"
                f"  Log: {log}"
            )
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


def _sign_in(screens, storage, client_cli, relay, choice: str):
    """
    Sign in, then pick a room. Returns the details dict, or None to quit.

    `relay` is our own relay's address when hosting, and the field is hidden.
    When joining it is whatever onion address was used last, or empty, and
    anything that is not an onion address is refused: this launcher only
    connects through Tor.
    """
    prefs = storage.load_launcher_prefs()
    username = prefs.get("user", "")
    hosting = choice == screens.HOST_TOR
    message = ""

    while True:
        credentials = screens.login_screen(
            relay=None if hosting else relay, username=username,
            message=message, relay_label="Onion address",
        )
        if credentials is None:
            return None

        username = credentials["user"]
        if hosting:
            url, use_tor = relay, False
        else:
            # Anything but an onion address is refused: this launcher only
            # connects through Tor.
            relay = credentials["relay"].strip().lower()
            url, use_tor = client_cli.onion_url(relay), True
            if url is None:
                message = ("That is not an onion address. Paste the 56-character "
                           ".onion address your host sent you.")
                continue

        room = screens.room_screen(username, storage.list_rooms(username))
        if room is None:
            message = ""
            continue                    # back to sign in

        saved = {"user": username, "start": choice}
        if not hosting:
            saved["relay"] = relay
        storage.save_launcher_prefs(saved)
        return {
            "user": username, "password": credentials["password"],
            "url": url, "use_tor": use_tor, "room": room,
        }


def _parse_args():
    parser = argparse.ArgumentParser(
        prog="spectre.py",
        description="Start Spectre: host a room or join one.",
    )
    # Everything goes through Tor now, so there is nothing left to switch on.
    # Accepted and ignored so existing shortcuts keep working.
    parser.add_argument("--tor", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--terminal", action="store_true",
        help="use the full-screen terminal interface instead of the desktop window",
    )
    # Internal: how a frozen build runs its own relay and backend.
    parser.add_argument("--serve", choices=sorted(SERVICES), help=argparse.SUPPRESS)
    return parser.parse_args()


def _watch_parent() -> None:
    """
    Exit when the launcher that started us is gone.

    Its cleanup stops us on a normal exit, but it never runs when the app is
    ended abruptly -- a crash, a force quit, or Cmd-Q on macOS, which
    terminates without returning to Python. A relay left behind goes on
    listening with nobody attached, and keeps its port.
    """
    parent = int(os.environ.get("SPECTRE_PARENT_PID", "0") or 0)
    if not parent:
        return

    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # A handle, not a pid: it keeps meaning *that* process even if the pid
        # is reused. os.kill(pid, 0) is no test on Windows -- it terminates.
        handle = kernel32.OpenProcess(0x00100000, False, parent)      # SYNCHRONIZE
        if not handle:
            os._exit(0)

        def alive():
            return kernel32.WaitForSingleObject(handle, 0) == 0x102   # WAIT_TIMEOUT
    else:
        # Once the parent dies we are re-parented, so the pid we were started
        # under stops being our parent -- immune to the pid being reused.
        def alive():
            return os.getppid() == parent

    def watch():
        while alive():
            time.sleep(2)
        os._exit(0)

    threading.Thread(target=watch, name="parent-watch", daemon=True).start()


def _serve(name: str) -> None:
    """Run the relay or backend in this process, as its own script would."""
    _watch_parent()
    # A windowed PyInstaller build starts with no sys.stdout or sys.stderr at
    # all, and Werkzeug and logging both write to them. The handles
    # LocalRelay passed in point at the log file, so reattach those.
    for stream, descriptor in (("stdout", 1), ("stderr", 2)):
        if getattr(sys, stream) is None:
            try:
                setattr(sys, stream, os.fdopen(descriptor, "w", buffering=1,
                                               encoding="utf-8", errors="replace"))
            except OSError:
                setattr(sys, stream, open(os.devnull, "w", encoding="utf-8"))
    script = SERVICES[name]
    sys.path.insert(0, str(script.parent))
    sys.argv = [str(script)]
    runpy.run_path(str(script), run_name="__main__")


def _start_screen_default(screens, prefs: dict) -> str:
    # "host" and "hosted" are from builds that could host on the local network.
    if prefs.get("start") in ("host", screens.HOST_TOR) or prefs.get("hosted"):
        return screens.HOST_TOR
    return screens.JOIN


def _tor_for_joining(session_module, say=print):
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
    say("Connecting to the Tor network (the first time can take a minute) ...")
    try:
        tor.start()
    except RuntimeError as error:
        say(f"\nCould not start tor: {error}\n"
            f"Trying a tor that is already running instead.\n")
        return None
    session_module.TOR_SOCKS_PORT = tor.socks_port
    return tor


def _desktop_available() -> bool:
    try:
        import webview  # noqa: F401
    except ImportError:
        return False
    return True


def _run_desktop(storage, session_module) -> None:
    """
    The desktop window. Same flow as the terminal screens below -- host or
    join, sign in, pick a room -- but driven by the page in client/desktop.
    This function owns the child processes; the window only asks for them.
    """
    from desktop import app as desktop

    children = {}

    def host(progress):
        relay = LocalRelay(_relay_token())
        relay.start()
        children["relay"] = relay
        progress("relay")

        # Publishing is the only way in: the relay listens on loopback.
        tor = TorProcess(publish_port=relay.relay_port)
        try:
            tor.start(on_bootstrapped=lambda: progress("tor"))
        except RuntimeError:
            children.pop("relay").stop()
            raise
        children["tor"] = tor
        progress("published", onion=tor.hostname)
        return relay.local_url

    def client_tor():
        tor = _tor_for_joining(session_module, say=lambda _text: None)
        if tor is not None:
            children["client_tor"] = tor

    try:
        desktop.run(desktop.Launcher(host, client_tor, storage.load_launcher_prefs()))
    finally:
        for name in ("client_tor", "tor", "relay"):
            child = children.pop(name, None)
            if child is not None:
                child.stop()


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

    if not args.terminal and _desktop_available():
        _run_desktop(storage, session_module)
        return

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.exit(
            "spectre.py needs a real terminal for its screens.\n"
            "For scripts and pipes, run: python client/client_cli.py --classic"
        )

    prefs = storage.load_launcher_prefs()
    choice = screens.start_screen(default=_start_screen_default(screens, prefs))
    if choice is None:
        return

    relay = None
    tor = None
    try:
        if choice == screens.HOST_TOR:
            relay = LocalRelay(_relay_token())
            print("Starting the relay ...")
            try:
                relay.start()
            except RuntimeError as error:
                sys.exit(str(error))

            # Publishing is the only way in: the relay listens on loopback, so
            # a room that is not on Tor is a room nobody else can reach.
            print("Publishing the room on Tor (this takes a minute) ...")
            tor = TorProcess(publish_port=relay.relay_port)
            try:
                tor.start()
            except RuntimeError as error:
                tor = None
                sys.exit(f"Could not publish the room on Tor: {error}")

            if screens.host_ready_screen(tor.hostname) is None:
                return
            relay_address = relay.local_url
        else:
            # Only a previously used onion address is offered again; anything
            # else a preferences file holds is from a build that allowed it.
            saved = prefs.get("relay") or ""
            relay_address = saved if client_cli.resolve_relay(saved)[1] else ""

        details = _sign_in(screens, storage, client_cli, relay_address, choice)
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
