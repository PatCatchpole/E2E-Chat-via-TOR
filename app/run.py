import threading
from node import ensure_keys, start_server, load_peers, save_peers, send_message
from crypto import pk_to_b64

def start_cli(sk, pk):
    peers = load_peers()
    print("Known peers (use 'peers add <onion:port> <pubkey_b64>' to add):")
    for i, p in enumerate(peers):
        print(i, p)
    print("\nCommands:")
    print("  peers list")
    print("  peers add <onion:port> <pubkey_b64>")
    print("  send <peer_index> <message>")
    print("  me  -> prints your public key\n")

    while True:
        try:
            cmd = input("> ").strip()
        except EOFError:
            break
        if not cmd:
            continue
        parts = cmd.split(" ", 2)
        if parts[0] == "peers":
            if len(parts) == 1 or parts[1] == "list":
                for i, p in enumerate(peers):
                    print(i, p)
            elif parts[1] == "add" and len(parts) == 3:
                rest = parts[2].split(" ", 1)
                if len(rest) != 2:
                    print("Usage: peers add <onion:port> <pubkey_b64>")
                    continue
                onion = rest[0].strip()
                pubkey = rest[1].strip()
                peers.append({"onion": onion, "id": pubkey})
                save_peers(peers)
                print("added")
            else:
                print("peers commands: list | add <onion:port> <pubkey_b64>")
        elif parts[0] == "send" and len(parts) == 3:
            idx = int(parts[1])
            if idx < 0 or idx >= len(peers):
                print("invalid index")
                continue
            peer = peers[idx]
            send_message(sk, pk, peer["onion"], peer["id"], parts[2])
            print("sent")
        elif parts[0] == "me":
            print("Your public key (base64):", pk_to_b64(pk))
        else:
            print("unknown command")

if __name__ == "__main__":
    sk, pk = ensure_keys()
    server_thread = threading.Thread(target=start_server, args=(sk, pk), daemon=True)
    server_thread.start()
    start_cli(sk, pk)
