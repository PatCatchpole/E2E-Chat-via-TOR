import json
import sys
import threading
from typing import Optional
import os
import pathlib
from getpass import getpass

import bcrypt
import requests
import socketio
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder

from crypto.ratchet import RatchetState, ChainState
from crypto.message import encrypt_with_message_key, decrypt_with_message_key
from crypto.x3dh import derive_shared_secret, dh, kdf
from crypto.keys import export_public_key, import_public_key

# ============================================================
# Diretórios locais
# ============================================================

SPECTRE_DIR = os.path.join(pathlib.Path.home(), ".spectre")
STATE_DIR = os.path.join(SPECTRE_DIR, "state")

os.makedirs(SPECTRE_DIR, exist_ok=True)
os.makedirs(STATE_DIR, exist_ok=True)

# ============================================================
# Helpers
# ============================================================

def b64_pubkey(pk: PublicKey) -> str:
    return Base64Encoder.encode(pk.encode()).decode()

def decode_pubkey_b64(s: str) -> PublicKey:
    return PublicKey(Base64Encoder.decode(s))

def ensure_cred_dir():
    """Creates ~/.spectre/ if it doesn't exist"""
    path = os.path.expanduser("~/.spectre")
    if not os.path.exists(path):
        os.mkdir(path)
    return path

def cred_path(username: str):
    directory = ensure_cred_dir()
    return os.path.join(directory, f"{username}.cred")

def load_stored_hash(username: str) -> Optional[str]:
    fpath = cred_path(username)
    if os.path.exists(fpath):
        with open(fpath, "r") as f:
            stored = f.read().strip()
            if stored:
                return stored
    return None

def store_hash(username: str, pwd_hash: str):
    fpath = cred_path(username)
    with open(fpath, "w") as f:
        f.write(pwd_hash)

def print_hr():
    print("-" * 60)

# ---------------- Identity key persistente ----------------

def identity_key_path(username: str) -> str:
    safe_user = username.replace("/", "_")
    return os.path.join(SPECTRE_DIR, f"{safe_user}.id")

def load_or_create_identity(username: str) -> tuple[PrivateKey, PublicKey]:
    """
    Carrega ou gera a identity keypair do usuário.
    Essa chave é de longo prazo e fica só no client (~/.spectre/<user>.id).
    """
    path = identity_key_path(username)
    if os.path.exists(path):
        with open(path, "rb") as f:
            priv_bytes = f.read()
        priv = PrivateKey(priv_bytes)
        return priv, priv.public_key

    priv = PrivateKey.generate()
    with open(path, "wb") as f:
        f.write(priv.encode())
    return priv, priv.public_key

# ---------------- Ratchet state persistente ----------------

def ratchet_state_path(username: str, room: str) -> str:
    safe_user = username.replace("/", "_")
    safe_room = room.replace("/", "_")
    return os.path.join(STATE_DIR, f"{safe_user}__{safe_room}.state.json")

def serialize_ratchet_state(state: RatchetState, user: str, room: str) -> dict:
    """
    Transforma o RatchetState em um dict JSON-serializable.
    """
    def b64(b: bytes | None) -> str | None:
        if b is None:
            return None
        return Base64Encoder.encode(b).decode()

    their_pub_b64 = None
    if state.their_dh_pub is not None:
        their_pub_b64 = Base64Encoder.encode(state.their_dh_pub.encode()).decode()

    return {
        "version": 1,
        "user": user,
        "room": room,
        "is_initiator": state.is_initiator,
        "root_key_b64": b64(state.root_key),
        "dh_priv_b64": b64(state.dh_keypair.encode()),
        "their_dh_pub_b64": their_pub_b64,
        "sending": {
            "ck_b64": b64(state.sending_chain.chain_key),
            "index": state.sending_chain.index,
        },
        "receiving": {
            "ck_b64": b64(state.receiving_chain.chain_key),
            "index": state.receiving_chain.index,
        },
    }

def deserialize_ratchet_state(data: dict) -> RatchetState:
    """
    Reconstrói um RatchetState a partir do dict salvo.
    """
    def b64d(s: str | None) -> bytes | None:
        if s is None:
            return None
        return Base64Encoder.decode(s.encode())

    root_key = b64d(data["root_key_b64"])
    dh_priv_bytes = b64d(data["dh_priv_b64"])
    dh_priv = PrivateKey(dh_priv_bytes)

    their_pub_b64 = data.get("their_dh_pub_b64")
    their_pub = None
    if their_pub_b64:
        their_pub_bytes = Base64Encoder.decode(their_pub_b64.encode())
        their_pub = PublicKey(their_pub_bytes)

    send_ck = b64d(data["sending"]["ck_b64"])
    send_index = data["sending"]["index"]
    recv_ck = b64d(data["receiving"]["ck_b64"])
    recv_index = data["receiving"]["index"]

    # 🚨 ChainState só aceita chain_key no __init__
    sending_chain = ChainState(send_ck)
    sending_chain.index = send_index

    receiving_chain = ChainState(recv_ck)
    receiving_chain.index = recv_index

    state = RatchetState(
        root_key=root_key,
        dh_keypair=dh_priv,
        their_dh_pub=their_pub,
        is_initiator=data["is_initiator"],
    )
    state.sending_chain = sending_chain
    state.receiving_chain = receiving_chain
    return state

def save_ratchet_state_to_disk(state: RatchetState, user: str, room: str) -> None:
    path = ratchet_state_path(user, room)
    payload = serialize_ratchet_state(state, user, room)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, path)

def load_ratchet_state_from_disk(user: str, room: str) -> Optional[RatchetState]:
    path = ratchet_state_path(user, room)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != 1:
            return None
        return deserialize_ratchet_state(data)
    except Exception as e:
        print(f"[!] Failed to load ratchet state: {e}")
        return None

# ============================================================
# SpectreClient
# ============================================================

class SpectreClient:
    def __init__(self, url: str, room: str, user: str, is_initiator: bool, use_tor: bool):
        self.url = url
        self.room = room
        self.user = user
        self.is_initiator = is_initiator
        self.role_str = "initiator" if is_initiator else "responder"

        # Socket.IO
        self.sio = socketio.Client()
        self.state: Optional[RatchetState] = None
        
        self.pending_packets: list[dict] = []

        self.identity_priv, self.identity_pub = load_or_create_identity(self.user)

        self.eph_priv = PrivateKey.generate()
        self.eph_pub = self.eph_priv.public_key

        self.init_dh_priv = PrivateKey.generate()
        self.init_dh_pub = self.init_dh_priv.public_key

        self.peer_id_pub: Optional[PublicKey] = None
        self.peer_eph_pub: Optional[PublicKey] = None
        self.peer_init_dh_pub: Optional[PublicKey] = None

        existing_state = load_ratchet_state_from_disk(self.user, self.room)
        if existing_state is not None:
            self.state = existing_state
            print("[*] Loaded ratchet state from disk (resume session).")
        else:
            print("[*] No previous ratchet state. Will start a fresh X3DH+DR session.")

        # Events for register/login
        self._register_event = threading.Event()
        self._register_success = False
        self._register_message = ""

        self._login_event = threading.Event()
        self._login_success = False
        self._login_message = ""

        # SocketIO session com/sem Tor
        if use_tor:
            session = requests.Session()
            session.proxies = {
                "http": "socks5h://127.0.0.1:9150",   # ajuste pra 9050 se usar tor daemon
                "https": "socks5h://127.0.0.1:9150",
            }
            self.sio = socketio.Client(http_session=session)
        else:
            self.sio = socketio.Client()

        # ====================================================
        # Socket.IO event handlers
        # ====================================================

        @self.sio.event
        def connect():
            print("[*] Connected to server")

        @self.sio.event
        def disconnect():
            print("[*] Disconnected from server")

        @self.sio.on("register_result")
        def on_register_result(data):
            self._register_success = bool(data.get("success"))
            self._register_message = data.get("message", "")
            print(f"[register] {self._register_message}")
            self._register_event.set()

        @self.sio.on("login_result")
        def on_login_result(data):
            self._login_success = bool(data.get("success"))
            self._login_message = data.get("message", "")
            print(f"[login] {self._login_message}")
            self._login_event.set()

        @self.sio.on("sys")
        def sysmsg(data):
            print(f"[server] {data.get('msg', '')}")

        @self.sio.on("bundle")
        def on_bundle(data):
            """
            {
              "from": "Bob",
              "bundle": {
                  "user": "...",
                  "identity_pub_b64": "...",
                  "ephemeral_pub_b64": "...",
                  "init_dh_pub_b64": "...",
                  "role": "initiator"|"responder"
              }
            }
            """
            b = data["bundle"]
            self.peer_id_pub = import_public_key(b["identity_pub_b64"])
            self.peer_eph_pub = import_public_key(b["ephemeral_pub_b64"])
            self.peer_init_dh_pub = import_public_key(b["init_dh_pub_b64"])

            print(f"[!] Bundle received from {b.get('user', 'peer')}")
            self._maybe_init_ratchet()

        @self.sio.on("packet")
        def on_packet(data):
            try:
                if data.get("type") != "msg":
                    return

                if self.state is None:
                    # Ratchet ainda não pronto: enfileira
                    self.pending_packets.append(data)
                    return

                self._process_incoming_message_packet(data)

                # após receber mensagem, o ratchet avançou; salvar estado
                save_ratchet_state_to_disk(self.state, self.user, self.room)

            except Exception as e:
                print(f"\n[!] decrypt error: {e}")
                print("> ", end="", flush=True)

    # ============================================================
    # Processamento de mensagens recebidas
    # ============================================================

    def _process_incoming_message_packet(self, data: dict):
        hdr = data["hdr"]
        body = data["body"]

        peer_dh_pub = import_public_key(hdr["dh_pub_b64"])
        self.state.receive_header_and_ratchet_if_needed(peer_dh_pub)

        n = int(hdr["n"])
        while self.state.receiving_chain.index < n:
            _ = self.state.receiving_chain.next_message_key()

        mk = self.state.receiving_chain.next_message_key()
        pt = decrypt_with_message_key(mk, body["nonce_b64"], body["ct_b64"])

        sender = data.get("user", "peer")
        print(f"\n[{sender} -> {self.user}] {pt.decode(errors='replace')}")
        print("> ", end="", flush=True)

    # ============================================================
    # Bundle management
    # ============================================================

    def my_bundle(self):
        return {
            "user": self.user,
            "identity_pub_b64": export_public_key(self.identity_pub),
            "ephemeral_pub_b64": export_public_key(self.eph_pub),
            "init_dh_pub_b64": export_public_key(self.init_dh_pub),
            "role": self.role_str,
        }

    def _maybe_init_ratchet(self):
        """
        Inicializa o Double Ratchet via X3DH SE ainda não existir estado.
        Se já existe self.state (carregado do disco), só sincroniza e processa fila.
        """
        # Já tenho estado salvo: só reusa
        if self.state is not None:
            if self.peer_init_dh_pub is not None:
                self.state.their_dh_pub = self.peer_init_dh_pub
            print("[*] Ratchet already loaded from disk. Skipping X3DH.")
            if self.pending_packets:
                print(f"[*] Processing {len(self.pending_packets)} queued messages.")
                queued = list(self.pending_packets)
                self.pending_packets.clear()
                for pkt in queued:
                    try:
                        self._process_incoming_message_packet(pkt)
                    except Exception as e:
                        print(f"[!] Error processing queued msg: {e}")
            print("[*] Ratchet synchronized.")
            return

        # Ainda não temos o bundle completo do peer
        if not (self.peer_id_pub and self.peer_eph_pub and self.peer_init_dh_pub):
            return

        # ---------- X3DH CORRETO ----------
        if self.is_initiator:
            # Mesma fórmula do x3dh.py (já implementada)
            shared = derive_shared_secret(
                initiator_priv_id=self.identity_priv,
                initiator_priv_eph=self.eph_priv,
                responder_pub_id=self.peer_id_pub,
                responder_pub_eph=self.peer_eph_pub,
            )
        else:
            # Responder precisa reproduzir os MESMOS 3 DHs que o initiator combinou,
            # mas usando SUAS privadas e as públicas do initiator.

            # Queremos o mesmo vetor do initiator:
            #   [ DH(I_A, I_B), DH(E_A, I_B), DH(I_A, E_B) ]
            #
            # Usando simetria do X25519:
            #   DH(I_A, I_B) = DH(I_B, I_A)
            #   DH(E_A, I_B) = DH(I_B, E_A)
            #   DH(I_A, E_B) = DH(E_B, I_A)

            dh1 = dh(self.identity_priv, self.peer_id_pub)      # DH(I_B, I_A)
            dh2 = dh(self.identity_priv, self.peer_eph_pub)     # DH(I_B, E_A)
            dh3 = dh(self.eph_priv, self.peer_id_pub)           # DH(E_B, I_A)

            combined = dh1 + dh2 + dh3
            shared = kdf(combined)

        root_key = shared
        # ----------------------------------

        self.state = RatchetState(
            root_key=root_key,
            dh_keypair=self.init_dh_priv,
            their_dh_pub=self.peer_init_dh_pub,
            is_initiator=self.is_initiator,
        )
        print("[*] Ratchet initialized (fresh X3DH).")

        save_ratchet_state_to_disk(self.state, self.user, self.room)

        if self.pending_packets:
            print(f"[*] Processing {len(self.pending_packets)} queued messages.")
            queued = list(self.pending_packets)
            self.pending_packets.clear()
            for pkt in queued:
                try:
                    self._process_incoming_message_packet(pkt)
                except Exception as e:
                    print(f"[!] Error processing queued msg: {e}")

        print("[*] Ratchet synchronized.")

    # ============================================================
    # Socket connection
    # ============================================================

    def connect(self, url=None):
        if url is not None:
            self.url = url
        self.sio.connect(
            self.url,
            wait=True,
            wait_timeout=500,
            transports=["polling"],
        )

    def start_recv_loop(self):
        threading.Thread(target=self.sio.wait, daemon=True).start()

    # ============================================================
    # Auth: Register + Login
    # ============================================================

    def register(self, pwd_hash: str) -> bool:
        self._register_event.clear()
        self.sio.emit("register", {
            "user": self.user,
            "password_hash_bcrypt": pwd_hash,
            "role": self.role_str,
        })
        self._register_event.wait(timeout=500)
        return self._register_success

    def login(self, pwd_hash: str) -> bool:
        self._login_event.clear()
        self.sio.emit("login", {
            "user": self.user,
            "password_hash_bcrypt": pwd_hash,
            "role": self.role_str,
        })
        self._login_event.wait(timeout=500)
        return self._login_success

    # ============================================================
    # Room / Messaging
    # ============================================================

    def join_room(self):
        self.sio.emit("join", {
            "room": self.room,
            "user": self.user,
            "role": self.role_str,
            "bundle": self.my_bundle(),
        })

    def send_packet(self, pkt: dict):
        pkt["room"] = self.room
        self.sio.emit("packet", pkt)

    def send_message(self, text: str, rotate=False):
        if self.state is None:
            print("[!] Cannot send; ratchet uninitialized.")
            return

        if rotate:
            new_pub = self.state.initiate_sending_ratchet()
            dh_pub_b64 = b64_pubkey(new_pub)
        else:
            dh_pub_b64 = b64_pubkey(self.state.dh_keypair.public_key)

        n = self.state.sending_chain.index
        mk = self.state.sending_chain.next_message_key()

        body = encrypt_with_message_key(mk, text.encode())
        pkt = {
            "type": "msg",
            "hdr": {"dh_pub_b64": dh_pub_b64, "n": n},
            "body": body,
            "user": self.user,
        }
        self.send_packet(pkt)
        # após enviar, cadeias avançaram; salvar estado
        save_ratchet_state_to_disk(self.state, self.user, self.room)

# ============================================================
# MAIN
# ============================================================

def main():
    room = input("Room name: ").strip() or "spectre"
    user = input("Your name: ").strip() or "user"
    pwd = getpass(f"Senha de {user}: ")
    role = input("Role [i=initiator / r=responder]: ").strip().lower()
    is_initiator = (role != "r")

    stored = load_stored_hash(user)
    if stored:
        pwd_hash = stored
        print("[*] Using stored password hash.")
    else:
        pwd_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
        store_hash(user, pwd_hash)
        print("[*] New hash generated & stored locally.")

    # -- Tor / localhost selection --
    onion = input("Onion host (leave blank for localhost): ").strip()
    if onion:
        if onion.endswith(".onion"):
            onion = onion[:-6]
        url = f"http://{onion}.onion:80"
        use_tor = True
    else:
        url = "http://127.0.0.1:5000"
        use_tor = False

    cli = SpectreClient(
        url=url,
        room=room,
        user=user,
        is_initiator=is_initiator,
        use_tor=use_tor,
    )

    # Connect
    cli.connect(url)
    cli.start_recv_loop()

    # First try login
    if not cli.login(pwd_hash):
        if "não existe" in cli._login_message.lower() or "existe" in cli._login_message.lower():
            print("[*] User does not exist. Registering...")
            if not cli.register(pwd_hash):
                print("[!] Registration failed.")
                return
            print("[*] Registration OK. Trying login again...")
            if not cli.login(pwd_hash):
                print("[!] Login failed even after register.")
                return
        else:
            print("[!] Login failed.")
            return

    # Join room
    cli.join_room()

    print("\nCommands:")
    print("  /rotate")
    print("  /quit")
    print_hr()

    rotate_flag = False
    while True:
        msg = input("> ").rstrip("\n")
        if msg == "/quit":
            if cli.state is not None:
                save_ratchet_state_to_disk(cli.state, cli.user, cli.room)
            cli.sio.disconnect()
            break
        elif msg == "/rotate":
            rotate_flag = True
            print("[*] Will rotate DH before next message.")
            continue
        elif msg:
            cli.send_message(msg, rotate=rotate_flag)
            rotate_flag = False

if __name__ == "__main__":
    main()
