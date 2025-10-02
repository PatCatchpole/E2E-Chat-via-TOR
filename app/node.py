import socket
import threading
import json
import os
from crypto import (
    generate_keypair, save_keypair, load_keypair,
    pk_to_b64, b64_to_pk, encrypt_with, decrypt_with, KEYFILE
)
import socks #why the fuck do I need this 

LOCAL_PORT = 9000
PEERS_FILE = "peers.json"  # this keeps list of {"id": "<b64pk>", "onion": "<addr.onion:port>"}

def ensure_keys():
    if not os.path.exists(KEYFILE):
        sk, pk = generate_keypair()
        save_keypair(sk, KEYFILE)
        print("Generated keypair and saved to", KEYFILE)
    sk, pk = load_keypair(KEYFILE)
    return sk, pk

def load_peers():
    if not os.path.exists(PEERS_FILE):
        return []
    with open(PEERS_FILE, "r") as f:
        return json.load(f)

def save_peers(peers):
    with open(PEERS_FILE, "w") as f:
        json.dump(peers, f, indent=2)

def start_server(sk, pk, local_port=LOCAL_PORT):
    def handle_conn(conn, addr):
        try:
            sender_b64 = conn.recv(88).decode().strip()
            if not sender_b64:
                conn.close(); return
            sender_pk = b64_to_pk(sender_b64)
            ciphertext = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                ciphertext += chunk
            msg = decrypt_with(sk, sender_pk, ciphertext)
            print(f"\n<<< MESSAGE from {sender_b64[:12]}...: {msg}\n> ", end="", flush=True)
        except Exception as e:
            print("Error handling conn:", e)
        finally:
            conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", local_port))
    s.listen(5)
    print(f"Local server listening on 127.0.0.1:{local_port} (Tor maps this to your .onion)")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()

def send_message(sk, pk, target_onion, target_pk_b64, message):
    hostport = target_onion.split(":")
    if len(hostport) != 2:
        raise ValueError("target_onion must be like addr.onion:port")
    target_host, target_port = hostport[0], int(hostport[1])
    target_pk = b64_to_pk(target_pk_b64)
    ciphertext = encrypt_with(target_pk, sk, message)
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True)
    sock.connect((target_host, target_port))
    my_pk_b64 = pk_to_b64(pk)
    sock.sendall(my_pk_b64.encode().ljust(88))
    sock.sendall(ciphertext)
    sock.close()
