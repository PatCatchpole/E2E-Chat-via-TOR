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

Nothing to configure, and no second terminal:

```bash
python spectre.py
```

On macOS you can also double-click **Spectre.command** in Finder.

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
- Tor, for `.onion` operation (Tor Browser, or a `tor` daemon)

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

Add to your `torrc`:

```
HiddenServiceDir /var/lib/tor/spectre/
HiddenServicePort 80 127.0.0.1:5000
```

Read the hostname from `/var/lib/tor/spectre/hostname`, then:

```bash
cd client
python client_cli.py --onion <host>.onion
```

The client proxies through SOCKS5 at `127.0.0.1:9150` (Tor Browser). For a
standalone `tor` daemon, change `TOR_SOCKS_PORT` in `client/session.py` to 9050.
Hostname resolution goes through `socks5h`, so `.onion` lookups stay inside Tor.

---

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
  often. Message rows are never deleted. Tor hides network location, not this.
- **An unverified identity key.** Signatures prove a bundle is self-consistent,
  not that it belongs to your peer. Only `/verify` establishes that.
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

The suite covers the protocol properties directly: out-of-order and dropped
messages, both peers ratcheting simultaneously, save/restore across a restart,
replay and stale-chain rejection, forged header counters, tampered headers and
ciphertext, rollback after a failed authentication, bundle signature forgery,
per-peer identity changes, role derivation, payload framing, and safety number
stability.

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

### Outstanding

1. **The Java backend has never been compiled.** No JDK 21 or Maven was
   available while it was written, so it was reviewed by inspection only. Run
   `mvn compile` in `back-end/spectre-chat` before trusting it. The Python side
   is verified end to end against `tools/dev_backend.py`, which implements the
   same HTTP contract, so the wire protocol is exercised even though the Java
   is not.

2. **Two private keys remain in git history** at commit `5b3f23f`
   (`client/crypto/identity_key`, `client/crypto/ephemeral_key`). They are no
   longer tracked, but untracking is not deletion -- they are still fetchable.
   Treat them as burned regardless, and to remove them:

   ```bash
   git filter-repo --path client/crypto/identity_key \
                   --path client/crypto/ephemeral_key --invert-paths
   git remote add origin <url>      # filter-repo drops the remote deliberately
   git push --force --all
   ```

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

