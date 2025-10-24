from flask import Flask
from flask_socketio import SocketIO, emit
from crypto.e2e import encrypt_message, decrypt_message 


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*')

@app.route('/')
def index():
    return "Server is running"

@socketio.on('message')
def handle_message(data):
    print("Received (Encrypted):", data)
    emit('message', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app,host='0.0.0.0', port = 5000)

    