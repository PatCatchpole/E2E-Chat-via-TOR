import json
import requests
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room

BACKEND_BASE_URL = "http://127.0.0.1:8090"
INTERNAL_TOKEN = "super-secreto-local"

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*')

# sid -> { "user": "...", "role": "...", "userId": ... }
sessions = {}

# room -> { "participants": { sid -> { "user": "...", "role": "...", "bundle": {...} } } }
rooms_state = {}


# =============== helpers ==================

def backend_post(path: str, json_body: dict):
    url = f"{BACKEND_BASE_URL}{path}"
    headers = {"X-Internal-Token": INTERNAL_TOKEN}
    print(f"[HTTP] POST {url} headers={headers} body={json_body}")
    resp = requests.post(url, json=json_body, headers=headers, timeout=5)

    print(f"[HTTP] RESP {resp.status_code} body={resp.text}")
    if resp.status_code == 401:
        raise requests.exceptions.HTTPError(
            f"401 Unauthorized from backend at {url}. "
            f"Verifique X-Internal-Token no server e no Spring."
        )
    resp.raise_for_status()

    if resp.content:
        return resp.json()
    return None


def backend_get(path: str, params: dict | None = None):
    url = f"{BACKEND_BASE_URL}{path}"
    headers = {"X-Internal-Token": INTERNAL_TOKEN}
    print(f"[HTTP] GET {url} headers={headers} params={params}")
    resp = requests.get(url, params=params, headers=headers, timeout=5)

    print(f"[HTTP] RESP {resp.status_code} body={resp.text}")
    if resp.status_code == 401:
        raise requests.exceptions.HTTPError(
            f"401 Unauthorized from backend at {url}. "
            f"Verifique X-Internal-Token no server e no Spring."
        )
    resp.raise_for_status()

    if resp.content:
        return resp.json()
    return None



# ======================= HTTP simples =======================

@app.route("/")
def index():
    return "Spectre E2E Chat Server is running"


# ======================= EVENTOS =======================

@socketio.on("connect")
def handle_connect():
    sid = request.sid
    print(f"[*] Client connected: {sid}")


@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    print(f"[*] Client disconnected: {sid}")

    user = None

    if sid in sessions:
        user = sessions[sid]["user"]
        del sessions[sid]
        print(f"[*] Session removed for {user}")

    # remove do rooms_state
    for room, state in list(rooms_state.items()):
        participants = state.get("participants", {})
        if sid in participants:
            if user is None:
                user = participants[sid]["user"]
            del participants[sid]
            print(f"[*] {user} removed from room {room}")

        if not participants:
            del rooms_state[room]
            print(f"[*] Room {room} now empty; removed from state.")



# ---------- REGISTER ----------

@socketio.on("register")
def handle_register(data):
    """
    Client -> server:
    {
      "user": "...",
      "password_hash_bcrypt": "...",
      "role": "initiator"|"responder"
    }
    """
    user = data.get("user")
    pwd_hash = data.get("password_hash_bcrypt")
    role = data.get("role")

    try:
        resp = backend_post("/internal/auth/register", {
            "username": user,
            "passwordHashBcrypt": pwd_hash,
            "role": role,
        }) or {}
    except Exception as e:
        emit("register_result", {
            "success": False,
            "message": f"Erro backend: {e}"
        })
        return

    success = bool(resp.get("valid"))
    msg = resp.get("message", "")
    emit("register_result", {"success": success, "message": msg})


# ---------- LOGIN ----------

@socketio.on("login")
def handle_login(data):
    """
    {
      "user": "...",
      "password_hash_bcrypt": "...",
      "role": "initiator"|"responder"
    }
    """
    user = data.get("user")
    pwd_hash = data.get("password_hash_bcrypt")
    role = data.get("role")

    try:
        resp = backend_post("/internal/auth/login", {
            "username": user,
            "passwordHashBcrypt": pwd_hash,
            "role": role,
        }) or {}
    except Exception as e:
        emit("login_result", {"success": False, "message": f"Erro backend: {e}"})
        return

    if not resp.get("valid"):
        emit("login_result", {
            "success": False,
            "message": resp.get("message", "Login inválido")
        })
        return

    sid = request.sid
    sessions[sid] = {
        "user": user,
        "role": resp.get("role"),
        "userId": resp.get("userId"),
    }

    print(f"[*] User logged in: {user} ({role}), sid={sid}")
    emit("login_result", {"success": True, "message": "OK"})


# ---------- JOIN ROOM  ----------

@socketio.on("join")
def handle_join(data):
    """
    Client -> server:
    {
      "room": "sala-secreta-xyz",
      "user": "alice",
      "role": "initiator",
      "bundle": { ...my_bundle()... }
    }
    """
    sid    = request.sid
    room   = data.get("room")
    user   = data.get("user")
    role   = data.get("role")
    bundle = data.get("bundle")

    if sid not in sessions or sessions[sid]["user"] != user:
        emit("sys", {"msg": "Precisa fazer login primeiro."})
        return

    join_room(room)
    print(f"[*] {user} joined room: {room}")
    emit("sys", {"msg": f"{user} joined the room"}, room=room)

    try:
        join_resp = backend_post("/internal/rooms/join", {
            "room": room,
            "user": user,
        }) or {}
    except Exception as e:
        print(f"[!] Erro /internal/rooms/join: {e}")
        join_resp = {}

    print(f"[JOIN] user={user} room={room} join_resp={join_resp}")

    last_seen = join_resp.get("lastSeenMessageId")
    print(f"[JOIN] user={user} room={room} last_seen(before fetch)={last_seen}")

    if room not in rooms_state:
        rooms_state[room] = {"participants": {}}

    rooms_state[room]["participants"][sid] = {
        "user": user,
        "role": role,
        "bundle": bundle
    }

    try:
        backend_post(f"/internal/rooms/{room}/bundles", {
            "user": user,
            "bundle": bundle,
        })
    except Exception as e:
        print(f"[!] Erro ao salvar bundle: {e}")

    participants = rooms_state[room]["participants"]
    others = [(other_sid, info) for other_sid, info in participants.items() if other_sid != sid]

    if others:
        other_sid, other_info = others[0]

        socketio.emit("bundle", {
            "from": user,
            "bundle": bundle,
        }, room=other_sid)

        socketio.emit("bundle", {
            "from": other_info["user"],
            "bundle": other_info["bundle"],
        }, room=sid)

        print(f"[*] Bundle exchange between {user} and {other_info['user']} in room {room}")

    try:
        params = {}
        if last_seen is not None:
            params["sinceId"] = last_seen

        print(f"[JOIN] user={user} room={room} fetching backlog with params={params}")

        msgs = backend_get(f"/internal/rooms/{room}/messages", params=params) or []

        print(f"[JOIN] user={user} room={room} msgs_ids={[m['id'] for m in msgs]}")
    except Exception as e:
        print(f"[!] Erro ao buscar mensagens pendentes: {e}")
        msgs = []
        params = {}

    max_id = last_seen or 0

    for m in msgs:
        mid        = m["id"]
        headerJson = m["headerJson"]
        bodyJson   = m["bodyJson"]
        sender     = m.get("sender")

        try:
            hdr  = json.loads(headerJson)
            body = json.loads(bodyJson)
        except Exception:
            print(f"[!] Erro parse JSON em message {mid}")
            continue
        
        if sender == user:
            continue

        socketio.emit("packet", {
            "type": "msg",
            "room": room,
            "user": sender,
            "hdr": hdr,
            "body": body,
            "id": mid,
        }, room=sid)


        if mid > max_id:
            max_id = mid
            
@socketio.on("leave")
def handle_leave(data):
    sid  = request.sid
    room = data.get("room")
    user = data.get("user")

    if room in rooms_state:
        participants = rooms_state[room].get("participants", {})
        if sid in participants:
            del participants[sid]
            print(f"[*] {user} left room {room} via /leave")
            emit("sys", {"msg": f"{user} exited the room"}, room=room)

        if not participants:
            del rooms_state[room]
            print(f"[*] Room {room} now empty; removed from state.")


# ---------- MENSAGENS ----------

@socketio.on("packet")
def handle_packet(data):
    """
    {
      "type": "msg",
      "room": "...",
      "user": "alice",
      "hdr": {...},
      "body": {...}
    }
    """
    room     = data.get("room")
    pkt_type = data.get("type")

    if pkt_type != "msg":
        print("[*] Ignorando packet type != 'msg'")
        return

    msg_id = None
    try:
        resp = backend_post(f"/internal/rooms/{room}/messages", {
            "user": data.get("user"),
            "header": data.get("hdr"),
            "body": data.get("body"),
        }) or {}
        msg_id = resp.get("id")
    except Exception as e:
        print(f"[!] Erro ao salvar mensagem no backend: {e}")

    out = dict(data)
    if msg_id is not None:
        out["id"] = msg_id

    emit("packet", out, room=room, include_self=False)
    
@socketio.on("seen")
def handle_seen(data):
    """
    Client -> server:
    {
      "room": "...",
      "lastSeenMessageId": 123
    }
    """
    sid = request.sid
    if sid not in sessions:
        print("[!] seen recebido de sid sem sessão")
        return

    user = sessions[sid]["user"]
    room = data.get("room")
    last_seen_id = data.get("lastSeenMessageId")

    if room is None or last_seen_id is None:
        print("[!] seen inválido (room ou lastSeenMessageId ausentes)")
        return

    try:
        backend_post(f"/internal/rooms/{room}/last-seen", {
            "user": user,
            "lastSeenMessageId": last_seen_id
        })
        print(f"[SEEN] user={user} room={room} lastSeen={last_seen_id}")
    except Exception as e:
        print(f"[!] Erro ao processar seen de {user} em {room}: {e}")


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
