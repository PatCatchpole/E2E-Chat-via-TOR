# SpectreProtocol — End-to-end encrypted chat over Tor

Group text chat using X3DH for key agreement and the Double Ratchet for forward
secrecy and post-compromise security, relayed over Socket.IO and optionally
exposed as a Tor hidden service.

A room is a **mesh of pairwise sessions**: every member holds a separate ratchet
with every other member, and each message is encrypted once per recipient. Every
member therefore keeps exactly the guarantees they would have one-to-one. The
cost is that traffic grows with the square of the room size, which is why
`SPECTRE_ROOM_CAPACITY` defaults to 8.

> **Status: a learning project, not a vetted messenger.** The cryptography is
> hand-rolled against the published specifications rather than delegated to a
> reviewed library. It has a test suite covering the protocol properties, but it
> has not been audited. Do not use it to protect anything that matters.

---

## 0. Quick start

**Easiest: the packaged app.** Download the file for your system from the
repository's GitHub Releases (or the latest `build` workflow run) and
double-click it. Python, every dependency and Tor are inside; there is nothing
to install.

| System  | File                         |
|---------|------------------------------|
| Windows | `Spectre-windows-x86_64.exe` |
| macOS   | `Spectre-macos-arm64`        |
| Linux   | `Spectre-linux-x86_64`       |

Choose **Host a room anyone can join over Tor**, send the `.onion` address it
shows to your friends, and sign in. They choose **Join**, paste the address
into the relay field, and sign in too. Joining starts the app's own Tor in the
background, so nobody needs Tor Browser open.

The builds are not signed with a paid developer certificate, so the first launch
needs one extra click:

- **macOS** — "cannot be opened because Apple cannot verify it": right-click the
  file, choose **Open**, then **Open** again (on macOS 15, allow it under
  System Settings → Privacy & Security → **Open Anyway**). A file downloaded by
  a browser may also need `chmod +x Spectre-macos-arm64` once.
- **Windows** — SmartScreen: **More info** → **Run anyway**.
- **Linux** — `chmod +x Spectre-linux-x86_64` and run it from a terminal;
  most file managers do not open a terminal for it.

To build it yourself, see §4.1.

**From source.** Nothing to configure, and no second terminal:

```bash
python spectre.py
```

On macOS you can also double-click **Spectre.command** in Finder.

To let people join from anywhere rather than just your network, choose
**Host a room anyone can join over Tor** (or pass `--tor` to preselect it).

It asks whether to host a room or join one. Hosting starts the relay and its
backend for you and shows the address to pass to whoever is joining; joining
just wants that address. Then it signs you in and drops you into the chat.

> Hosting this way uses the in-memory backend (`tools/dev_backend.py`), so
> **accounts and message history last only as long as the window stays open**.
> For anything that should survive a restart, run the Spring Boot backend and
> the relay yourself — see §4.

Everything below is the manual path, which is still there and still works.

---

## 1. Architecture

Three processes:

| Component | Language | Role |
|---|---|---|
| `client/` | Python | CLI. Holds all key material, runs X3DH and the Double Ratchet, encrypts and decrypts. |
| `server/` | Python | Socket.IO relay. Routes ciphertext, never holds a session key. |
| `back-end/` | Java / Spring Boot | Persists users, rooms, key bundles and ciphertext in Postgres. |

The relay and the backend see ciphertext and metadata only. Neither can read a
message, but both see who talks to whom and when — see [Threat model](#7-threat-model).

```
client  <--- Socket.IO (Tor) --->  relay  <--- HTTP (loopback) --->  backend  ---> Postgres
```

### Layout

```text
spectre.py            launcher: host or join, starts the relay, then signs in
Spectre.command       double-clickable wrapper for Finder
packaging/
  build.py            one-file executable: fetches + verifies tor, runs PyInstaller
  spectre.spec        PyInstaller spec
.github/workflows/    builds the executable for Windows, macOS and Linux
client/
  client_cli.py       client entry point, argument and prompt handling
  screens.py          start, sign-in and room-picker screens
  session.py          transport, handshake, message dispatch
  ui.py               full-screen terminal chat interface
  storage.py          0600 local persistence for keys and ratchet state
  crypto/
    kdf.py            HKDF-SHA256 (RFC 5869)
    keys.py           identities, signed prekey bundles, safety numbers
    x3dh.py           key agreement
    ratchet.py        Double Ratchet
    message.py        XChaCha20-Poly1305 AEAD
    state.py          ratchet serialisation
    password.py       PBKDF2 password verifier
server/app.py         Socket.IO relay
tests/                protocol test suite
back-end/spectre-chat Spring Boot service
```

---

## 2. Requirements

- Python 3.9+
- Java 21 and Maven (the backend targets Spring Boot 4)
- PostgreSQL
- Tor, for `.onion` operation — a `tor` daemon (`brew install tor`) or Tor
  Browser. `spectre.py --tor` needs the daemon on PATH; joining an existing
  `.onion` works with either.

---

## 3. Configuration

Nothing secret is committed. Both the relay and the backend read their
configuration from the environment and **refuse to start without it** rather
than falling back to a default.

Generate the shared token once:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

| Variable | Used by | Purpose |
|---|---|---|
| `SPECTRE_INTERNAL_TOKEN` | relay + backend | Shared secret for `/internal/**`. Must match on both. |
| `SPECTRE_DB_PASSWORD` | backend | Postgres password. |
| `SPECTRE_DB_URL`, `SPECTRE_DB_USER` | backend | Default to `localhost:5432/spectre_chat` and `spectre_user`. |
| `SPECTRE_BACKEND_URL` | relay | Defaults to `http://127.0.0.1:8090`. |
| `SPECTRE_RELAY_HOST`, `SPECTRE_RELAY_PORT` | relay | Default `127.0.0.1:5000`. |
| `SPECTRE_CORS_ORIGINS` | relay | Comma-separated browser origins. Empty by default; the CLI does not need it. |
| `SPECTRE_ROOM_CAPACITY` | relay | Maximum members per room. Defaults to 8. |
| `SPECTRE_ALLOW_DEV_SERVER` | relay | Set to `1` to run the Werkzeug dev server non-interactively (systemd, docker). |
| `SPECTRE_LOG_LEVEL` | relay | Defaults to `INFO`. |
| `SPECTRE_AUTH_RATE` | relay | Sign-in attempts per username per 5 minutes. Defaults to 10. |
| `SPECTRE_AUTH_RATE_SOCKET` | relay | Sign-in attempts per socket per 5 minutes. Defaults to 20. |
| `SPECTRE_PACKET_RATE` | relay | Packets per socket per 10 seconds. Defaults to 240. |
| `SPECTRE_TOR_SOCKS_PORT` | client | Pins the SOCKS port. Otherwise 9050 then 9150 are tried. |

---

## 4. Running locally

**Database**

```sql
CREATE DATABASE spectre_chat;
CREATE USER spectre_user WITH ENCRYPTED PASSWORD 'choose-a-strong-one';
GRANT ALL PRIVILEGES ON DATABASE spectre_chat TO spectre_user;
```

Flyway applies the schema on first start; `ddl-auto` is `validate`, so the
migrations in `src/main/resources/db/migration` are the single source of truth.

**Backend**

```bash
cd back-end/spectre-chat
export SPECTRE_INTERNAL_TOKEN='<token>'
export SPECTRE_DB_PASSWORD='choose-a-strong-one'
mvn spring-boot:run          # listens on 127.0.0.1:8090
```

**Relay**

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SPECTRE_INTERNAL_TOKEN='<token>'   # the same value
python server/app.py
```

**Clients** — two terminals:

```bash
cd client
python client_cli.py --room spectre --user alice --role initiator
python client_cli.py --room spectre --user bob   --role responder
```

There is no role to choose. Who initiates a given pairwise session is derived
from the two usernames (the lower one initiates), which is the only rule that
still works once a room holds more than two people. Run without flags to use the
sign-in screen and room picker.

### Windows

Only the client needs to run on Windows; the relay and backend can stay on
another machine. Paths and the interpreter differ from the examples above:

```cmd
git clone <repo> && cd E2E-Chat-via-TOR
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

cd client
..\.venv\Scripts\python client_cli.py --room spectre --user alice --url http://<relay-host>:5055
```

The interpreter lives in `.venv\Scripts\`, not `.venv/bin/`. Installing the
requirements globally instead of in a venv also works — then it is just
`python client_cli.py ...`.

Set variables with `set` rather than `export`:

```cmd
set SPECTRE_RELAY_PORT=5055
```

Use Windows Terminal or PowerShell if you can; the full-screen interface
renders poorly in legacy `cmd.exe`.

Key material goes to `%USERPROFILE%\.spectre\`. The 0600 permissions the
client applies on Unix have no equivalent there — Windows has no POSIX mode
bits — so those files are protected by the ACL on your user profile directory
and nothing more.

> **macOS:** AirPlay Receiver listens on port 5000 and will answer the relay's
> requests with `403`. Either turn it off in System Settings → General →
> AirDrop & Handoff, or set `SPECTRE_RELAY_PORT` to something else.

### 4.1 Building the packaged app

```bash
pip install -r requirements-build.txt
python packaging/build.py            # -> dist/Spectre, or dist\Spectre.exe
```

This builds for the system it runs on; PyInstaller cannot cross-compile. The
`build` GitHub Actions workflow runs it on Windows, macOS and Linux, smoke-tests
each result, and attaches all three to a release when a `v*` tag is pushed.

The Tor Project's *expert bundle* is downloaded and checked against a SHA-256
pinned in `packaging/build.py` — not against a checksum fetched from the same
server. To move to a newer tor, update `TOR_VERSION` and the four pins from
that release's `sha256sums-signed-build.txt`, after checking its `.asc`.

The executable is the launcher. When hosting it starts the relay and the backend
by running itself again with `--serve relay` / `--serve backend`, because a
frozen build has no Python interpreter to hand a script to.

---

## 5. Using the chat screen

```
 SPECTRE #spectre  alice <-> bob   online  tor
 09:11 bob: hey, did the handshake land?
 09:11 alice: yes - safety number matches what you read out
 verified  safety 04100 56204 84454 71388 ...   sent 7  recv 5
> _
```

| Command | Effect |
|---|---|
| `/who` | List everyone in the room, with verification and channel status. |
| `/verify [name]` | Print a peer's 60-digit safety number and mark them verified. |
| `/trust <name>` | Accept a changed identity key, after re-verifying out of band. |
| `/clear` | Clear the transcript. |
| `/help` | Command list. |
| `/quit` | Leave the room and exit. |

`PageUp` / `PageDown` scroll the transcript. `Ctrl-C` exits.

### Verifying a peer

Signature checks stop the relay forging a bundle, but they cannot tell you the
identity key you received is the one you expect. Run `/verify <name>` and compare
the digits over a channel the relay does not control. **There is one safety
number per pair**, so in a group of four each member has three to check. The
status bar shows how many are done.

With a single peer the name can be omitted: `/verify` on its own is unambiguous.

If a peer's identity key ever changes, the client refuses the new one and warns.
That is either a reinstall or an interception attempt; confirm which out of band
before running `/trust`.

---

## 6. Running via Tor

The launcher does the whole thing. Choose **Host a room anyone can join over
Tor** (`python spectre.py --tor` preselects it), and the room is published as a
v3 onion service whose address is shown next to the local one. Whoever is
joining pastes that address into the relay field — joining needs no flag and
no configuration: the launcher starts a client-only tor of its own under
`~/.spectre/tor-client` and routes through it. An explicit
`SPECTRE_TOR_SOCKS_PORT` still wins, and with no tor available at all the client
falls back to a running daemon on 9050 or Tor Browser on 9150.

The launcher uses the tor bundled into the packaged app, then one on `PATH`
or in the usual Homebrew locations.

Everything lives under `~/.spectre/tor`: its own `torrc`, its own
`DataDirectory` and its own `SocksPort`. Nothing in `/etc` is touched and no
root is needed, so it cannot collide with a system `tor` daemon or with Tor
Browser. The service key in `~/.spectre/tor/spectre/` is kept between runs, so
an address you have handed out keeps working — it is key material, and Tor
refuses to start unless that directory is `0700`.

Publishing is a separate choice because it makes the relay reachable from the
entire Tor network. **Host a room on this network only** stays on your own
network.

### By hand

If you would rather run the hidden service yourself, add to your `torrc`:

```
HiddenServiceDir /var/lib/tor/spectre/
HiddenServicePort 80 127.0.0.1:5055
```

Read the hostname from `/var/lib/tor/spectre/hostname`, then:

```bash
cd client
python client_cli.py --onion <host>.onion
```

The client finds the SOCKS proxy itself, trying `9050` (a `tor` daemon) and
then `9150` (Tor Browser). `SPECTRE_TOR_SOCKS_PORT` pins it if you need it to.
Hostname resolution goes through `socks5h`, so `.onion` lookups stay inside
Tor.

It tries each port by connecting through it rather than by checking that
something is listening, because those are not the same thing: Tor Browser
starts its `tor` with `DisableNetwork 1` and only lifts it when you click
Connect, so an open-but-unconnected Tor Browser holds 9150 while routing
nothing.

## 7. Threat model

**Protected against**

- A malicious relay or backend reading messages. They hold ciphertext only.
- A relay forging or altering a key bundle. Every published key is signed by its
  identity key, bound to the user and room.
- A relay tampering with message headers. The header is authenticated as AEAD
  associated data.
- Injection or impersonation by other clients. The relay takes the sender from
  its own session and requires room membership.
- Past messages after a key compromise, and future messages after the ratchet
  recovers, given continued two-way traffic.
- A forged or corrupted packet damaging a session. Decryption is atomic: a
  packet that fails to authenticate leaves the ratchet exactly as it was.

**Not protected against**

- **Metadata.** The relay and backend see who talks to whom, when, and how
  often. Message rows are never deleted. Tor hides network location, not this —
  behind a hidden service every client appears to the relay as `127.0.0.1`.
- **An unverified identity key.** Signatures prove a bundle is self-consistent,
  not that it belongs to your peer. Only `/verify` establishes that.
- **The transport, unless it is Tor.** The relay speaks plain HTTP. Message
  contents are safe either way — they are already end-to-end encrypted before
  they reach it — but the login verifier is not: it is the value the backend
  checks, so anyone who can watch the connection can capture it and sign in as
  you. Over Tor the circuit is encrypted and this does not arise. On a LAN or
  across the internet without Tor it does, including the address the launcher
  offers under "Share this". Host with `--tor`, or put TLS in front of the
  relay.

- **A compromised endpoint.** Ratchet state on disk is 0600 but not encrypted at
  rest; anyone who can read your files can read your session.
- **Traffic analysis.** No padding, no cover traffic; message sizes and timing
  are visible. In a group the relay also sees the fan-out pattern, so it learns
  the membership and how many copies each message produced.
- **A member who leaves.** Removing somebody from a room does not re-key the
  others; they keep whatever they already received. There is no group key to
  rotate, because there is no group key.

---

## 8. Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

102 tests. The suite covers the protocol properties directly: out-of-order and
dropped messages, both peers ratcheting simultaneously, save/restore across a
restart, replay and stale-chain rejection, forged header counters, tampered
headers and ciphertext, rollback after a failed authentication, bundle
signature forgery, per-peer identity changes, role derivation, payload framing,
and safety number stability.

It also covers the parts that are not cryptography but were the easiest place
for a defect to come back unnoticed: the relay taking the sender from its own
session, room membership on every packet, a departed client leaving the
broadcast room, rate limiting, `0600` on everything written to disk, storage
paths that cannot collide, and delivery of a message whose id sits below a
stale watermark.

The Java side has its own:

```bash
cd back-end/spectre-chat && mvn test -Dtest=MessageWireFormatTest
```

which pins the wire format of a stored message — see §10. It is scoped on
purpose: plain `mvn test` also runs `contextLoads`, which needs a live
Postgres and `SPECTRE_DB_PASSWORD`.

---

## 9. Troubleshooting

| Symptom | Cause |
|---|---|
| Relay exits with `SPECTRE_INTERNAL_TOKEN is not set` | Export it. There is deliberately no default. |
| `401` from the backend | The token differs between relay and backend. |
| Relay exits refusing to start non-interactively | Set `SPECTRE_ALLOW_DEV_SERVER=1`, or front it with a real WSGI server. |
| `403` connecting to the relay on macOS | AirPlay Receiver owns port 5000. See §4. |
| `AttributeError: can't set attribute` in the relay | Flask-SocketIO older than 5.4 against Flask ≥ 3.1. Reinstall from `requirements.txt`. |
| `Could not restore the saved session` | State file from an older format; it is discarded and a fresh handshake runs. |
| Peer identity change warning | Reinstall or interception. Verify out of band, then `/trust`. |
| A member cannot send yet | Their channel opens when the initiating side's priming message arrives; it is normally instant. |
| Room says it is full | `SPECTRE_ROOM_CAPACITY` reached, or a stale client still holds a slot. |

To start a room over, delete the saved state: `python client_cli.py --reset`.

---

## 10. Status

### What was rebuilt

The project began as a two-party chat whose cryptography and authentication had
a number of defects. Everything below was reviewed, rewritten where necessary,
and covered by tests that fail if the defect returns.

**Cryptography**

- X3DH now runs against a *signed* prekey, with separate initiator and responder
  functions. Previously nothing authenticated the key bundles, so the relay
  could substitute its own keys for both peers and read everything.
- Identities are Ed25519 keys signing every published key, bound to the user and
  room. Peer identities are pinned on first use, and a change is refused with a
  warning until `/trust` accepts it.
- The Double Ratchet follows the published algorithm: skipped-message keys,
  previous-chain length in the header, automatic DH rotation. The old manual
  `/rotate` is gone -- rotating twice without sending in between left the peer
  unable to reach the new root key.
- Message headers are authenticated as AEAD associated data. They were
  unauthenticated, and a forged counter drove an unbounded key-derivation loop.
- Key derivation uses real HKDF-SHA256 with domain separation.
- Restoring saved state no longer re-runs a DH ratchet step, which used to
  advance the root key past the peer's on every restart.
- Decryption is atomic: a packet that fails to authenticate leaves the ratchet
  exactly as it was. Without this one forged packet destroyed a session
  permanently, and the damage was persisted.

**Authentication**

- The client sent a locally-computed bcrypt hash which the backend compared with
  string equality, making the stored hash itself the credential. The client now
  derives a PBKDF2 verifier and the backend applies randomly-salted bcrypt. The
  deterministic client salt also makes signing in from a second machine
  possible, which it previously was not.

**Relay**

- `packet` had no authentication at all: no session check, no room membership
  check, and the sender was read from the client payload. Both are now enforced
  and the sender comes from the server-side session.
- CORS defaulted to `*`; it is now empty unless configured.
- `leave` never called `leave_room`, so departed clients kept receiving traffic.
- The internal token and full ciphertext were logged on every request.

**Backend**

- Token and database credentials come from the environment, and the service
  refuses to start without them rather than using a committed default.
- Typed exceptions replace bare 500s; requests are validated; writes are
  transactional; migrations add the missing constraints and indexes.

**Interface**

- A full-screen chat screen, a sign-in screen and a room picker, replacing
  interleaved `print()` and `input()` calls.

**Group chat** — rooms are a mesh of pairwise sessions; see §1.

**Tor** — `spectre.py --tor` publishes the room as a v3 onion service, managed
under `~/.spectre/tor` with no root and no system configuration; see §6.

**Later fixes** — a persisted delivery watermark silently discarded genuinely
new messages whenever the in-memory backend restarted its ids at 1; storage
filenames could collide between two different pairwise sessions, which would
have had two ratchets sharing one state file; `retired_dh` and the pending-
packet queue grew without bound; sign-in had no rate limiting at all.

### Outstanding

1. **The Java backend now compiles, and did not survive first contact.**
   It had never been built when it was written, and once it was, it turned out
   to be destroying every message it stored. `MessageHeaderDTO` declared
   `(dh_pub_b64, n)` and `MessageBodyDTO` declared `(nonce_b64, ct_b64)`, while
   the ratchet emits `(dh, pn, n)` and `(nonce, ct)`. Jackson dropped every
   field whose name did not match, so a stored message was
   `{"dh_pub_b64":null,"n":3}` and `{"nonce_b64":null,"ct_b64":null}` — the DH
   public key, the previous-chain length and the ciphertext itself, all gone on
   the way into the database. Offline delivery was therefore broken end to end,
   and nothing caught it because the Python side is exercised against
   `tools/dev_backend.py`, which stores the JSON verbatim.

   Both records are gone. The header and body are carried as opaque JSON, which
   is what the backend should have been doing anyway: it holds ciphertext it
   must not interpret, and the header is AEAD associated data that has to come
   back byte for byte or the tag will not verify. A typed record cannot promise
   that — it silently destroys anything it was not told about, which would make
   any future header field a wire break. `MessageWireFormatTest` pins it.

   The service still needs running against a real Postgres; it compiles and its
   unit tests pass, which is not the same thing.

2. **The two private keys are out of every branch, but not un-published.**
   History was rewritten with `git filter-repo` across all five branches and
   force-pushed. `client/crypto/identity_key` and `client/crypto/ephemeral_key`
   no longer exist in any commit, and a fresh clone carries nothing.

   The rewrite had to cover four paths, not two: the files were added at
   `crypto/` and moved to `client/crypto/` later, so the same blob sits at both
   (`identity_key` is `73f21406` at each) and stripping one leaves the other.
   `frontend` and `tor-test` also carried them, despite not descending from the
   commit the old note named — they were found by searching for the blob rather
   than by ancestry.

   ```bash
   git filter-repo --force --invert-paths \
       --path crypto/identity_key        --path crypto/ephemeral_key \
       --path client/crypto/identity_key --path client/crypto/ephemeral_key
   git remote add origin <url>      # filter-repo drops the remote deliberately
   git push --force --all origin
   ```

   **What that did not do.** The repository is public and has a fork
   (`kauan-novello/E2E-Chat-via-TOR`). A fork is a separate repository, and
   GitHub serves objects across a fork network, so the old commits are still
   fetchable by SHA from both URLs:

   ```
   raw.githubusercontent.com/PatCatchpole/E2E-Chat-via-TOR/d8b7f0a/crypto/identity_key        200
   raw.githubusercontent.com/PatCatchpole/E2E-Chat-via-TOR/5b3f23f/client/crypto/identity_key 200
   ```

   Removing that needs GitHub Support to purge the fork network's cached
   objects, and the fork itself deleted or rewritten by its owner. Until then
   the keys are retrievable by anyone who knows the SHA.

   None of which matters for safety, because the keys are burned and unused:
   identity seeds are generated per user into `~/.spectre` and nothing in the
   repository is loadable as a key. The rewrite's real value is that the next
   person to clone does not receive them.

   Every stored password hash predating the auth rewrite is also void; drop the
   users table and have people register again.

3. **This work lives on `harden-protocol`, not `main`.** A fresh clone gets the
   old, broken code. Merge it when you are satisfied with it.

### Possible next steps

- **Sender keys.** Each member distributes one symmetric chain key over the
  existing pairwise channels and then encrypts each message once, turning
  O(n^2) traffic into O(n). It costs some post-compromise security -- a leaked
  sender key stays useful until rotation -- and needs redistribution whenever
  membership changes. The pairwise mesh is the transport it would be built on,
  so it is an addition rather than a rewrite.
- **Message retention.** Rows are never deleted. A TTL or an explicit purge
  would limit what a seized database reveals, since the ciphertext is retained
  forever today.
- **Removing a member.** Nothing re-keys when somebody leaves. There is no group
  key to rotate, so this needs a policy decision before it needs code.
- **A vetted library.** If this ever needs to be trustworthy rather than
  instructive, the honest move is binding `crypto/` to a reviewed
  implementation. Hand-rolled primitives are the point of the project, not a
  path to production.

