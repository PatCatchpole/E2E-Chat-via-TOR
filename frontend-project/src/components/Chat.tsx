import React, { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import '../styles/main.css';

const SOCKET_URL = 'http://localhost:5000';

interface Message {
  user: string;
  text: string;
}

const Chat: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [user, setUser] = useState('');
  const [room, setRoom] = useState('');
  const [role, setRole] = useState<'initiator' | 'responder' | ''>('');
  const [joined, setJoined] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    if (joined && !socketRef.current) {
      const socket = io(SOCKET_URL);
      socketRef.current = socket;

      socket.on('connect', () => {
        socket.emit('join', { room, user });
      });

      socket.on('message', (data: any) => {
        // Só adiciona mensagem recebida se não for do próprio usuário
        if (data.user !== user || data.text !== input) {
          setMessages((msgs) => [...msgs, { user: data.user || 'anon', text: data.text || String(data) }]);
        }
      });

      return () => {
        socket.disconnect();
      };
    }
  }, [joined, room, user]);

  const handleSend = () => {
    if (input.trim() && socketRef.current) {
      socketRef.current.emit('message', { user, text: input, room });
      setInput('');
    }
  };

  if (!joined) {
    return (
      <div className="container" style={{ maxWidth: 400, margin: '2rem auto' }}>
        <div className="card">
          <h2 className="text-center" style={{ marginBottom: 16 }}>Entrar no Chat</h2>
          <input
            className="card"
            style={{ width: '90%', marginBottom: 8 }}
            placeholder="Seu nome"
            value={user}
            onChange={e => setUser(e.target.value)}
          />
          <input
            className="card"
            style={{ width: '90%', marginBottom: 8 }}
            placeholder="Sala"
            value={room}
            onChange={e => setRoom(e.target.value)}
          />
          <div style={{ margin: '8px 0', display: 'flex', justifyContent: 'center', gap: 16 }}>
            <label>
              <input
                type="radio"
                name="role"
                value="initiator"
                checked={role === 'initiator'}
                onChange={() => setRole('initiator')}
              /> Initiator
            </label>
            <label>
              <input
                type="radio"
                name="role"
                value="responder"
                checked={role === 'responder'}
                onChange={() => setRole('responder')}
              /> Responder
            </label>
          </div>
          <button className="button" style={{ width: '100%' }} onClick={() => user && room && role && setJoined(true)}>
            Entrar
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="container" style={{ maxWidth: 500, margin: '2rem auto' }}>
      <div className="card">
        <h2 className="text-center" style={{ marginBottom: 8 }}>Chat: {room}</h2>
        <div
          style={{
            border: '1px solid #ddd',
            borderRadius: 5,
            height: 300,
            overflowY: 'auto',
            padding: 8,
            marginBottom: 8,
            background: '#fafbfc',
          }}
        >
          {messages.map((msg, idx) => (
            <div
              key={idx}
              style={{
                margin: '4px 0',
                color: msg.user === user ? '#007bff' : '#222',
                textAlign: msg.user === user ? 'right' : 'left',
              }}
            >
              <span style={{ fontWeight: 600 }}>{msg.user}:</span> {msg.text}
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="card"
            style={{ flex: 1 }}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSend()}
            placeholder="Digite sua mensagem..."
          />
          <button className="button" onClick={handleSend}>Enviar</button>
        </div>
      </div>
    </div>
  );
};

export default Chat;
