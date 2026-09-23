# CLAUDE.md

SpectreProtocol — end-to-end encrypted group chat (X3DH + Double Ratchet) relayed
over Socket.IO, optionally behind a Tor hidden service.

`README.md` is the user-facing document and is accurate and detailed — read §1
(architecture), §7 (threat model) and §10 (status) before changing protocol code.
This file covers what the README does not: how to work in the repo.

## Commands

```bash
source .venv/bin/activate                  # Python 3.9 venv already present
python spectre.py                          # the launcher: desktop window, starts everything
python spectre.py --terminal               # same flow in the full-screen terminal UI
python -m pytest tests/ -q                 # 125 tests, ~3s, all passing
cd back-end/spectre-chat && mvn -B compile # Java 25 + Maven are installed and it builds
cd back-end/spectre-chat && mvn -B test -Dtest=MessageWireFormatTest   # pins the stored-message format
python packaging/build.py                  # one-file dist/Spectre with tor inside (pyinstaller is in the venv)
```

The manual path, for working on one piece at a time:

```bash
source dev.env                             # local token + port 5055 + dev server opt-in
python tools/dev_backend.py                # in-memory stand-in for the Java backend
python server/app.py                       # relay
cd client && python client_cli.py --room spectre --user alice
```

`tools/dev_backend.py` implements the same `/internal/**` contract as the Spring
Boot service, so the whole Python side runs without a JVM or Postgres. Use it for
anything that is not specifically about the Java code.

## Layout and conventions

- Three processes: `client/` (Python, holds all key material), `server/app.py`
  (Socket.IO relay, ciphertext only), `back-end/spectre-chat` (Spring Boot +
  Postgres, ciphertext only).
- A room is a **mesh of pairwise ratchets** — one `DoubleRatchet` per peer, each
  message encrypted once per recipient. Nothing in `crypto/` is group-aware; the
  fan-out lives in `SpectreSession`.
- The client imports its crypto package as `crypto.*`, not `client.crypto.*`.
  `tests/conftest.py` and `spectre.py` both put `client/` on `sys.path` so they
  exercise the same import graph the CLI does. Keep it that way.
- `spectre.py` is a launcher, not a second client: it picks host-or-join, starts
  `server/app.py` and `tools/dev_backend.py` as children when hosting, and then
  calls `client_cli.run_session(details)`. Chat behaviour belongs in the client,
  not here.
- `SpectreSession` has no UI code. Everything reaches the terminal through the
  `on_event(kind, payload)` callback, which is what lets tests drive it.
- Two front ends drive that one session: `ui.py` (terminal) and
  `client/desktop/` (pywebview window). The window's page is a view only: keys
  and plaintext stay in Python, and `desktop/app.py`'s `Bridge` is the entire
  surface the page can call. Its public methods are exposed to JavaScript by
  pywebview, so anything not meant for the page must be underscored.
- In the window's page, text from other people (names, rooms, messages) is
  placed with `textContent` only -- never `innerHTML`. The page can call the
  session, so markup from the network would be code from the network.
  `tests/test_desktop.py` fails on any HTML sink in `app.js`.
- The page is inlined into one document (fonts as data URIs) under a CSP with
  `default-src 'none'`: it must never fetch anything, since that would leave
  the machine outside Tor. `'unsafe-eval'` is there only because pywebview
  builds its API stubs with `new Function`. Push events with `run_js` (native,
  CSP-exempt); `evaluate_js` wraps the code in `eval` and is blocked.
- Module docstrings explain the defect the module replaces, not just what it
  does. That history is deliberate — this project is a rewrite of code with real
  vulnerabilities, and the docstrings are what stops them being reintroduced.
  Preserve them, and follow the pattern for new security-relevant code.
- Roles are never chosen by the user. `crypto/roles.py` derives them: the
  lexicographically smaller username initiates. `--role` and the `is_initiator`
  argument are accepted and ignored for compatibility.

## Invariants that must not regress

Each of these was a live vulnerability; each has a test that fails if it returns.

- The relay takes the sender from its own session (`session["user"]`), never from
  the client payload, and requires room membership on every `packet`.
- Ratchet headers are AEAD associated data (`_header_bytes`). Changing the header
  encoding is a wire break for both peers simultaneously.
- `DoubleRatchet.decrypt` is atomic: state is snapshotted and rolled back on any
  failure. Do not add mutation outside that try block.
- Bundles are verified (`Bundle.verify()`) before any key is touched, and peer
  identities are pinned on first use — a change raises `PeerIdentityChanged`.
- `MAX_SKIP` / `MAX_SKIPPED_KEYS` bound skipped-key derivation; without them a
  forged counter is a DoS.
- The relay and backend exit rather than default `SPECTRE_INTERNAL_TOKEN`; CORS is
  empty unless configured; ciphertext and the token are never logged.
- The backend carries `header` and `body` as opaque JSON. They were typed
  records whose field names did not match the wire, and Jackson dropped the
  ciphertext on the way into the database. Do not re-introduce a typed DTO —
  the header is AEAD associated data and must round-trip byte for byte.
- Storage filenames end in a `_key(...)` digest of the exact components.
  `_safe_name` is lossy and the parts are joined with `__`, so without it two
  different pairwise sessions can name one state file.
- Delivery is never gated on the backend's message id. Ids restart at 1
  whenever the in-memory backend does; the ratchet is the authority on replay.
- Sign-in and packets are rate limited per username and per socket, never per
  IP — behind a hidden service every client is `127.0.0.1`.
- Local files are 0600 via atomic writes in `storage.py` (POSIX only — Windows has
  no equivalent, and `storage.POSIX_PERMISSIONS` guards the assertions).

## Gotchas

- The launcher's child processes run in their own process group so Ctrl-C does
  not kill the relay before session state is saved. That makes `atexit`
  insufficient: `_stop_on_exit` registers every child (relay, backend, tor) with
  one SIGTERM/SIGHUP handler (SIGHUP is what closing the Terminal window sends)
  so a killed launcher cannot leave a relay or an onion service running
  unattended. It used to cover the relay only and orphaned tor. Verified by
  closing the pty; do not remove it.
- The packaged build (`packaging/`) is `spectre.py` frozen by PyInstaller. It
  re-executes itself with `--serve relay|backend`, and runs those scripts via
  runpy, so their imports are invisible to analysis — anything they need goes
  in `hiddenimports` in `spectre.spec`. Tor is the pinned expert bundle,
  ad-hoc signed on macOS (Apple Silicon SIGKILLs unsigned binaries, exit 137).
  Test a build end to end, not just `--serve`: the TUI renders by diff, so
  scraping a pty for a message is unreliable — check the saved ratchet state.
- Hosting from the launcher uses the **in-memory** backend, so accounts and
  history die with the window. The hosting screen says so — keep it saying so.

- Bump `crypto/state.STATE_VERSION` for any change to the serialised ratchet.
  Old state is discarded with a warning rather than misread.
- Flask-SocketIO must be ≥5.4 against Flask ≥3.1; pinned in `requirements.txt`.
- Port 5000 is AirPlay Receiver on macOS — `dev.env` uses 5055.
- The client tries SOCKS 9050 then 9150 by *connecting*, not by checking for a
  listener: Tor Browser holds 9150 open with `DisableNetwork 1` until you click
  Connect, so a probe cannot tell a working proxy from an idle one.
- The launcher is Tor-only by design: hosting always publishes an onion
  service with the relay bound to 127.0.0.1, and joining refuses anything but
  an onion address. Do not reintroduce a LAN host option -- the relay is plain
  HTTP and the login verifier crossed the network readable. `--tor` is a no-op
  kept for old shortcuts. The manual `client_cli.py` path still allows local
  addresses for development.
- `spectre.py` runs its own `tor` under `~/.spectre/tor` on its own
  SocksPort, so it never fights a system daemon or Tor Browser. The service key
  there is what keeps the `.onion` address stable — treat it as key material.
- `dev.env` is gitignored and holds a placeholder token; never commit a real one.
- Never add key material to the repo. The two private keys were stripped from
  all five branches with `git filter-repo` and force-pushed, so no commit
  contains them now. They remain fetchable by old SHA through GitHub's fork
  network (README §10.2) and are permanently burned — never reuse them.
- Work lives on `harden-protocol`; `main` is the old, vulnerable code.
- Plain `mvn test` fails on `SpectreChatApplicationTests.contextLoads`: it is a
  `@SpringBootTest` and needs `SPECTRE_DB_PASSWORD` and a live Postgres. That
  is pre-existing, not a regression — scope to `-Dtest=MessageWireFormatTest`
  unless a database is actually running.
