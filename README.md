# SpectreProtocol — End-to-end encrypted chat over Tor

Two-party text chat using X3DH for key agreement and the Double Ratchet for
forward secrecy and post-compromise security, relayed over Socket.IO and
optionally exposed as a Tor hidden service.

> **Status: a learning project, not a vetted messenger.** The cryptography is
> hand-rolled against the published specifications rather than delegated to a
> reviewed library. It has a test suite covering the protocol properties, but it
> has not been audited. Do not use it to protect anything that matters.

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
client/
  client_cli.py       entry point, argument and prompt handling
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

The initiator sends the first message; the responder cannot send until it has
received one, because its sending chain does not exist until then. Run without
flags to be prompted instead.

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
| `/verify` | Print the full 60-digit safety number and mark the peer verified. |
| `/trust` | Accept a changed peer identity key, after re-verifying out of band. |
| `/clear` | Clear the transcript. |
| `/help` | Command list. |
| `/quit` | Leave the room and exit. |

`PageUp` / `PageDown` scroll the transcript. `Ctrl-C` exits.

### Verifying a peer

Signature checks stop the relay forging a bundle, but they cannot tell you the
identity key you received is the one you expect. Run `/verify` on both sides and
compare the digits over a channel the relay does not control. Until you do, the
status bar reads `unverified`.

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

**Not protected against**

- **Metadata.** The relay and backend see who talks to whom, when, and how
  often. Message rows are never deleted. Tor hides network location, not this.
- **An unverified identity key.** Signatures prove a bundle is self-consistent,
  not that it belongs to your peer. Only `/verify` establishes that.
- **A compromised endpoint.** Ratchet state on disk is 0600 but not encrypted at
  rest; anyone who can read your files can read your session.
- **Traffic analysis.** No padding, no cover traffic; message sizes and timing
  are visible.

---

## 8. Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

The suite covers the protocol properties directly: out-of-order and dropped
messages, both peers ratcheting simultaneously, save/restore across a restart,
replay and stale-chain rejection, forged header counters, tampered headers and
ciphertext, bundle signature forgery, and safety number stability.

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
| Responder cannot send | Expected until it receives the first message. |

To start a room over, delete the saved state: `python client_cli.py --reset`.
