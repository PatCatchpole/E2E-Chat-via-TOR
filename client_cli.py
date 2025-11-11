import json
import sys
import threading
from typing import Optional

import socketio
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder

from crypto.keys import (
    generate_identity_keypair,
    generate_ephemeral_keypair,
    export_public_key,
    import_public_key,
)
from crypto.x3dh import derive_shared_secret
from crypto.ratchet import RatchetState
from crypto.message import encrypt_with_message_key, decrypt_with_message_key

# ---------- helpers ----------
def b64_pubkey(pk: PublicKey) -> str:
    return Base64Encoder.encode(pk.encode()).decode()

def decode_pubkey_b64(s: str) -> PublicKey:
    return PublicKey(Base64Encoder.decode(s))

def prompt(msg: str) -> str:
    return input(msg)

def print_hr():
    print("-" * 60)

# ---------- CLI client ----------
class SpectreClient:
    def __init__(self, url: str, room: str, user: str, is_initiator: bool):
        self.url = url
        self.room = room
        self.user = user
        self.is_initiator = is_initiator

        # Local identity + ephemeral (identity should persist; ephemeral per session)
        self.id_priv, self.id_pub = generate_identity_keypair()
        self.eph_priv, self.eph_pub = generate_ephemeral_keypair()

        # Initial per-session DH for the Double Ratchet
        self.dh_priv = PrivateKey.generate()

        # Peer bundle placeholders (normally provided via QR/manual)
        self.peer_id_pub: Optional[PublicKey] = None
        self.peer_eph_pub: Optional[PublicKey] = None
        self.peer_init_dh_pub: Optional[PublicKey] = None

        # Double Ratchet state (created after bundle exchange)
        self.state: Optional[RatchetState] = None

        # Socket.IO client
        self.sio = socketio.Client()

        @self.sio.event
        def connect():
            print("[*] Connected to relay")
            self.sio.emit("join", {"room": self.room, "user": self.user})

        @self.sio.event
        def disconnect():
            print("[*] Disconnected")

        @self.sio.on("sys")
        def sysmsg(data):
            print(f"[server] {data['msg']}")

        @self.sio.on("packet")
        def on_packet(data):
            # Relay sends us encrypted packets (or demo bundle packets)
            try:
                if data.get("type") == "bundle":
                    # You said: exchange identity via QR/offline.
                    # This is convenience for testing in one terminal pair.
                    print("\n[!] Received peer bundle over relay (use QR/manual in real use).")
                    self._load_peer_bundle(data["payload"])
                    self._maybe_init_ratchet()
                    print_hr()
                    print("> ", end="", flush=True)
                    return

                if data.get("type") != "msg":
                    return

                hdr = data["hdr"]
                body = data["body"]

                # 1) Receive-side ratchet if peer rotated DH
                peer_dh_pub = decode_pubkey_b64(hdr["dh_pub_b64"])
                self.state.receive_header_and_ratchet_if_needed(peer_dh_pub)

                # 2) Advance receiving chain up to n (MVP in-order)
                n = int(hdr["n"])

                # Skip messages if needed (out of order handling)
                while self.state.receiving_chain.index < n:
                    _ = self.state.receiving_chain.next_message_key()

                # Now decrypt the message at index n
                mk = self.state.receiving_chain.next_message_key()
                pt = decrypt_with_message_key(mk, body["nonce_b64"], body["ct_b64"])
                print(f"\n[{self.user} recv] {pt.decode()}")
                print("> ", end="", flush=True)
            except Exception as e:
                print(f"\n[!] decrypt error: {e}")
                print("> ", end="", flush=True)

    # ---------- bundle (QR/manual ideally) ----------
    def my_bundle(self) -> dict:
        return {
            "user": self.user,
            "identity_pub_b64": export_public_key(self.id_pub),
            "ephemeral_pub_b64": export_public_key(self.eph_pub),
            "init_dh_pub_b64": b64_pubkey(self.dh_priv.public_key),
            "role": "initiator" if self.is_initiator else "responder",
        }

    def _load_peer_bundle(self, bundle: dict):
        self.peer_id_pub = import_public_key(bundle["identity_pub_b64"])
        self.peer_eph_pub = import_public_key(bundle["ephemeral_pub_b64"])
        self.peer_init_dh_pub = decode_pubkey_b64(bundle["init_dh_pub_b64"])

    def paste_peer_bundle(self):
        print("\nPaste peer bundle JSON and press Enter (or leave blank to skip):")
        raw = sys.stdin.readline().strip()
        if raw:
            try:
                self._load_peer_bundle(json.loads(raw))
            except json.JSONDecodeError as e:
                print(f"[!] Invalid JSON: {e}")
            except Exception as e:
                print(f"[!] Error loading bundle: {e}")

    def print_my_bundle(self):
        print_hr()
        print("[*] Share this bundle out-of-band (QR/manual):")
        print(json.dumps(self.my_bundle(), indent=2))
        print_hr()

    def _maybe_init_ratchet(self):
        if not (self.peer_id_pub and self.peer_eph_pub and self.peer_init_dh_pub):
            return
        # X3DH → root key
        if self.is_initiator:
            root_key = derive_shared_secret(
                initiator_priv_id=self.id_priv,
                initiator_priv_eph=self.eph_priv,
                responder_pub_id=self.peer_id_pub,
                responder_pub_eph=self.peer_eph_pub,
            )
        else:
            from crypto.x3dh import dh, kdf
            dh1 = dh(self.id_priv, self.peer_id_pub)       # DH(responder_priv_id, initiator_pub_id)
            dh2 = dh(self.id_priv, self.peer_eph_pub)      # DH(responder_priv_id, initiator_pub_eph)
            dh3 = dh(self.eph_priv, self.peer_id_pub)      # DH(responder_priv_eph, initiator_pub_id)
            combined = dh1 + dh2 + dh3
            root_key = kdf(combined)
                    
        # Double Ratchet state
        self.state = RatchetState(
            root_key=root_key,
            dh_keypair=self.dh_priv,
            their_dh_pub=self.peer_init_dh_pub,
            is_initiator=self.is_initiator,
        )
        print("[*] Ratchet initialized.")

    # ---------- socket lifecycle ----------
    def connect(self):
        self.sio.connect(self.url, wait=True)

    def start_recv_loop(self):
        t = threading.Thread(target=self.sio.wait, daemon=True)
        t.start()

    def send_packet(self, pkt: dict):
        pkt["room"] = self.room
        self.sio.emit("packet", pkt)

    def send_message(self, text: str, rotate: bool = False):
        # Optional: rotate DH before sending (send-side ratchet)
        if rotate:
            new_pub = self.state.initiate_sending_ratchet()
            hdr_pub_b64 = b64_pubkey(new_pub)
        else:
            hdr_pub_b64 = b64_pubkey(self.state.dh_keypair.public_key)

        # Get the message key and the index BEFORE incrementing
        n = self.state.sending_chain.index
        mk = self.state.sending_chain.next_message_key()
        body = encrypt_with_message_key(mk, text.encode("utf-8"))
        pkt = {
            "type": "msg",
            "hdr": {"dh_pub_b64": hdr_pub_b64, "n": n},
            "body": body,
        }
        self.send_packet(pkt)

def main():
    url = "http://127.0.0.1:5000"
    room = prompt("Room name: ").strip() or "spectre"
    user = prompt("Your name: ").strip() or "user"
    role = prompt("Role [i=initiator / r=responder]: ").strip().lower()
    is_initiator = (role != "r")

    cli = SpectreClient(url, room, user, is_initiator=is_initiator)
    cli.connect()
    cli.start_recv_loop()

    # Out-of-band exchange (demo: copy/paste JSON).
    cli.print_my_bundle()
    print("-> On the other terminal, copy its bundle and paste below.")
    cli.paste_peer_bundle()
    if cli.peer_id_pub and cli.peer_eph_pub and cli.peer_init_dh_pub:
        cli._maybe_init_ratchet()
    else:
        print("[!] No peer bundle pasted yet. You can /sendbundle for convenience (demo).")

    print("\nCommands:")
    print("  /sendbundle   (broadcast your bundle via relay for convenience)")
    print("  /rotate       (rotate DH before next send)")
    print("  /quit")
    print_hr()

    rotate_flag = False
    while True:
        try:
            msg = input("> ").rstrip("\n")
        except (EOFError, KeyboardInterrupt):
            msg = "/quit"

        if msg == "/quit":
            break
        elif msg == "/sendbundle":
            cli.send_packet({"type": "bundle", "payload": cli.my_bundle()})
            continue
        elif msg == "/rotate":
            rotate_flag = True
            print("[*] Will rotate DH on next message.")
            continue
        elif not msg:
            continue

        if cli.state is None:
            print("[!] No ratchet yet. Paste peer bundle (or use /sendbundle and wait).")
            continue

        cli.send_message(msg, rotate=rotate_flag)
        rotate_flag = False

if __name__ == "__main__":
    main()
