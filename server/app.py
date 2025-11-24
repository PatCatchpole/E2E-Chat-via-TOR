import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask
from flask_socketio import SocketIO, emit, join_room
from crypto.e2e import encrypt_message, decrypt_message 


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*')

@app.route('/')
def index():
    return "Server is running"

@socketio.on('connect')
def handle_connect():
    print(f"[*] Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[*] Client disconnected")

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    user = data.get('user')
    join_room(room)
    print(f"[*] {user} joined room: {room}")
    emit('sys', {'msg': f'{user} joined the room'}, room=room)

@socketio.on('packet')
def handle_packet(data):
    room = data.get('room')
    print(f"[*] Relaying packet in room: {room}")
    # Broadcast the packet to everyone in the room except sender
    emit('packet', data, room=room, include_self=False)

@socketio.on('message')
def handle_message(data):
    room = data.get('room')
    print("Received (Encrypted):", data)
    emit('message', data, room=room)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

    