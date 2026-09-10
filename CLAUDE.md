# CLAUDE.md

SpectreProtocol — end-to-end encrypted group chat (X3DH + Double Ratchet) relayed
over Socket.IO, optionally behind a Tor hidden service.

`README.md` is the user-facing document and is accurate and detailed — read §1
(architecture), §7 (threat model) and §10 (status) before changing protocol code.
This file covers what the README does not: how to work in the repo.

## Commands

```bash
source .venv/bin/activate                  # Python 3.9 venv already present
python spectre.py                          # the launcher: starts everything, no setup
python -m pytest tests/ -q                 # 70 tests, ~1s, all passing
cd back-end/spectre-chat && mvn -B compile # Java 25 + Maven are installed and it builds
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
- Local files are 0600 via atomic writes in `storage.py` (POSIX only — Windows has
  no equivalent, and `storage.POSIX_PERMISSIONS` guards the assertions).

## Gotchas

- The launcher's child processes run in their own process group so Ctrl-C does
  not kill the relay before session state is saved. That makes `atexit`
  insufficient: `LocalRelay._install_signal_handlers` catches SIGTERM and SIGHUP
  (what closing the Terminal window sends) so a killed launcher cannot leave a
  relay listening on the network unattended. Verified; do not remove it.
- Hosting from the launcher uses the **in-memory** backend, so accounts and
  history die with the window. The hosting screen says so — keep it saying so.

- Bump `crypto/state.STATE_VERSION` for any change to the serialised ratchet.
  Old state is discarded with a warning rather than misread.
- Flask-SocketIO must be ≥5.4 against Flask ≥3.1; pinned in `requirements.txt`.
- Port 5000 is AirPlay Receiver on macOS — `dev.env` uses 5055.
- `dev.env` is gitignored and holds a placeholder token; never commit a real one.
- Never add key material to the repo. Two private keys are still reachable in git
  history at `5b3f23f` (README §10.2) — treat them as burned.
- Work lives on `harden-protocol`; `main` is the old, vulnerable code.
