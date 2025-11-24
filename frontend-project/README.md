
# Frontend do Chat E2E via Socket.IO

Este projeto é o frontend web para o sistema de chat seguro E2E-Chat-via-TOR.

## Funcionalidades
- Interface moderna para salas de chat
- Integração em tempo real com backend Python via Socket.IO
- Escolha de nome, sala e papel (initiator/responder)
- Mensagens entre usuários na mesma sala

## Como rodar

1. Instale as dependências:
   ```sh
   npm install
   ```
2. Inicie o frontend:
   ```sh
   npm start
   ```
3. Acesse [http://localhost:3000](http://localhost:3000) no navegador.

> Certifique-se de que o backend (servidor Python) está rodando em http://localhost:5000.

## Estrutura
- `src/components/Chat.tsx`: Componente principal do chat
- `src/components/App.tsx`: Estrutura da aplicação
- `src/styles/main.css`: Estilos globais