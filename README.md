# SpectreProtocol — Chat E2E via Tor (X3DH + Double Ratchet)

Mensageiro de texto com criptografia de ponta-a-ponta, usando:

- **X3DH simplificado** para acordo de chaves iniciais  
- **Double Ratchet** para sigilo futuro e pós-comprometimento (cada mensagem com uma chave distinta)  
- **Transporte em tempo real** via Socket.IO (Python)  
- **Persistência** em um back-end Spring Boot

Em produção, o tráfego pode ser exposto através de um **Hidden Service Tor (.onion)**.

---

## 1. Arquitetura

A aplicação é dividida em três partes:

- **Client (Python)**: CLI que o usuário executa, faz login/registro, realiza o X3DH, mantém o estado do Double Ratchet e cifra/decifra mensagens.  
- **Server (Python)**: servidor Socket.IO que recebe pacotes dos clientes, fala com o back-end e faz o roteamento das mensagens. Não descriptografa nada.  
- **Back-end (Java/Spring Boot)**: API interna que persiste usuários, salas, mensagens e bundles de chaves em um banco relacional.

### 1.1 Estrutura de pastas

```text
.
├─ Server/
│  └─ app.py
│
├─ Client/
│  ├─ client_cli.py          # CLI principal
│  └─ crypto/
│     ├─ e2e.py              # Orquestra X3DH + Double Ratchet
│     ├─ keys.py             # Geração/import/export de chaves
│     ├─ message.py          # Encrypt/Decrypt de mensagens
│     ├─ ratchet.py          # Double Ratchet
│     └─ x3dh.py             # X3DH simplificado
│
└─ Back-end/
   └─ spectre-chat/
      └─ src/main/java/br/com/spectre/spectrechat/
         ├─ controller/
         │  ├─ InternalAuthController.java
         │  ├─ InternalBundleController.java
         │  ├─ InternalMessageController.java
         │  └─ InternalRoomController.java
         ├─ domain/
         │  ├─ KeyBundle.java
         │  ├─ Message.java
         │  ├─ Room.java
         │  ├─ RoomParticipant.java
         │  └─ User.java
         ├─ repository/
         │  ├─ KeyBundleRepository.java
         │  ├─ MessageRepository.java
         │  ├─ RoomParticipantRepository.java
         │  ├─ RoomRepository.java
         │  └─ UserRepository.java
         ├─ dto/
         │  ├─ auth/
         │  ├─ bundle/
         │  ├─ message/
         │  └─ room/
         └─ config/
            ├─ InternalTokenFilter.java
            └─ SecurityConfig.java
```

---

## 2. Visão geral das funcionalidades

### 2.1 Client (CLI em Python)

Responsabilidades principais:

- Interface de linha de comando para o usuário final
- Registro e login:
  - Envia `username` + hash de senha para o Server
  - Server repassa para o back-end (`/internal/auth/register` e `/internal/auth/login`)
- Geração e armazenamento local de:
  - **Chave de identidade** de longo prazo (IK)
  - Estado do **Double Ratchet** por sala (root key, cadeias de envio/recebimento, contadores)
- Execução do **X3DH**:
  - Usa chaves de identidade + chaves efêmeras locais e do peer
  - Gera uma `root_key` inicial compartilhada
- Execução do **Double Ratchet**:
  - Rotação de DH periodicamente ou sob comando (`/rotate`)
  - Cadeias de envio/recebimento gerando `message_key` de uso único
- Criptografia de mensagens:
  - Usa `message_key` + nonce aleatório
  - Envia mensagem cifrada (header + body) ao Server
- Persistência de estado:
  - Arquivos em `~/.spectre/` (ou similar) guardando credenciais e estado do ratchet
- Comandos da CLI (exemplos):
  - Digitar texto → envia mensagem cifrada na sala
  - `/rotate` → força nova rotação de DH
  - `/quit` → sai da sala e encerra a sessão

### 2.2 Server (Python – Flask + Socket.IO)

Responsabilidades principais:

- Expor o endpoint HTTP básico (health-check)  
- Servir Socket.IO (`/socket.io`) para os clientes
- Gerenciar sessões em memória:
  - `sid` ↔ `user`, `userId`, `role`
- Gerenciar salas:
  - Cada sala mapeia `roomName -> participantes -> (sid, user, bundle)`
- Integração com o back-end:
  - Registro e login internos:
    - `POST /internal/auth/register`
    - `POST /internal/auth/login`
  - Informações de sala:
    - `POST /internal/rooms/join`
    - `POST /internal/rooms/{room}/last-seen`
  - Mensagens:
    - `GET  /internal/rooms/{room}/messages` (backlog)
    - `POST /internal/rooms/{room}/messages` (salvar nova mensagem)
  - Bundles:
    - `POST /internal/rooms/{room}/bundles` (armazenar bundle de chaves de um participante)
- Troca de bundles:
  - Primeiro cliente que entra na sala: bundle é armazenado
  - Segundo cliente: server troca os bundles entre eles (evento `bundle`)
- Encaminhamento de mensagens:
  - Recebe do client (`packet`)
  - Persiste no back-end (recebe `id` da mensagem)
  - Reenvia para os demais participantes da sala com o `id`
- Processamento de `seen`:
  - Atualiza o último `lastSeenMessageId` de cada usuário na sala

> O Server **nunca descriptografa** mensagens. Ele só repassa ciphertext e metadados.

### 2.3 Back-end (Java / Spring Boot)

Responsabilidades principais:

- **Autenticação interna**:
  - Controlada por `InternalAuthController` e DTOs de `auth/`
  - Registra usuários e realiza login para o Server (não exposto ao público)
- **Gestão de salas**:
  - `Room`, `RoomParticipant` e DTOs em `room/`
  - Controle de quem participa de qual sala
  - Controle de `lastSeenMessageId` por usuário/sala
- **Bundles de chaves**:
  - `KeyBundle` + `KeyBundleRepository`
  - `InternalBundleController` para salvar/consultar bundles de chaves por room/user
- **Mensagens**:
  - `Message` + `MessageRepository`
  - `InternalMessageController` recebe mensagens cifradas do Server e as persiste
  - Retorna backlog de mensagens para o Server quando um usuário entra em uma sala
- **Camada de segurança interna**:
  - `InternalTokenFilter`: valida um header como `X-Internal-Token`
  - `SecurityConfig`: registra o filtro e libera apenas os endpoints internos necessários

> O back-end não tem acesso às chaves de sessão do Double Ratchet, apenas guarda o que o Server manda: headers/bodies cifrados e bundles públicos.

---

## 3. Pré-requisitos

### 3.1 Ferramentas

- Python **3.11+**
- Java **17+**
- Maven ou Gradle (conforme o projeto do Spring Boot)
- PostgreSQL (ou outro banco configurado no back-end)
- Tor Browser (opcional, para uso via .onion)

### 3.2 Dependências Python (Client + Server)

No diretório raiz do projeto:

```bash
python -m venv .venv

# Windows PowerShell
. .\.venv\Scripts\Activate.ps1

# Linux/macOS
# source .venv/bin/activate

pip install --upgrade pip
pip install -r ./requirements.txt
```

---

## 4. Configuração do Back-end

### 4.1 Banco de dados (exemplo PostgreSQL)

```sql
CREATE DATABASE spectre;
CREATE USER spectre WITH ENCRYPTED PASSWORD 'SENHA_FORTE';
GRANT ALL PRIVILEGES ON DATABASE spectre TO spectre;
```

Em `application.properties` ou `application.yml`, configurar algo como:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/spectre
spring.datasource.username=spectre
spring.datasource.password=SENHA_FORTE

spring.jpa.hibernate.ddl-auto=update
# ou validate/none, dependendo de migrations
server.port=8090
```

### 4.2 Token interno

No back-end:

- Configure o token esperado pelo `InternalTokenFilter` (ex.: `super-secreto-local`).

No `Server/app.py`:

```python
BACKEND_BASE_URL = "http://127.0.0.1:8090"
INTERNAL_TOKEN = "super-secreto-local"
```

O filtro deve validar algo como:

- Header: `X-Internal-Token: super-secreto-local`

### 4.3 Rodar o back-end

Na pasta `Back-end/spectre-chat`:

```bash
mvn spring-boot:run
# ou rodar pela IDE
```

---

## 5. Configuração do Server (Python)
Para estar 100% funcional é necessário estar na rede Tor. (Conectado no Tor Browser ou semelhante)

Na pasta `Server/`:

1. Ajustar se necessário:

   ```python
   BACKEND_BASE_URL = "http://127.0.0.1:8090"
   INTERNAL_TOKEN = "super-secreto-local"
   ```

2. Rodar:

   ```bash
   cd Server
   python app.py
   ```

3. Verificar no navegador:

   - Acessar `http://127.0.0.1:5000/`  
   - Deve aparecer uma resposta simples de health-check.

---

## 6. Configuração do Client (Python)

Na pasta `Client/`:

```bash
cd Client
python client_cli.py
```

Entrada típica na CLI:

- `Room name:` nome da sala (ex.: `spectre`)
- `Your name:` nome de usuário (ex.: qualquer)
- `Senha de <user>:` senha local (usada para gerar/validar hash Bcrypt)
- `Role [i=initiator / r=responder]:` papel na sessão:
  - `i` inicia o X3DH
  - `r` responde
- `Onion host (leave blank for localhost):`
  - Deixe em branco para usar `http://127.0.0.1:5000`
  - Informe o host `.onion` para usar através da Tor (sem `http://`)

O client:

1. Gera (ou carrega) chaves de identidade e arquivos de estado.  
2. Tenta login no back-end via Server; se o usuário não existir, tenta registro e login.  
3. Efetua `join` na sala.  
4. Recebe/entrega bundles de chaves e inicializa X3DH + Double Ratchet.

---

## 7. Execução local (sem Tor)

Passo a passo:

1. **Subir o banco e o back-end**

   ```bash
   # PostgreSQL já em execução
   cd Back-end/spectre-chat
   mvn spring-boot:run
   # back-end em http://127.0.0.1:8090
   ```

2. **Subir o Server**

   ```bash
   cd Server
   python app.py
   # server em http://127.0.0.1:5000
   ```

3. **Abrir dois terminais para os Clients**

   Terminal 1:

   ```bash
   cd Client
   python client_cli.py

   Room name: spectre
   Your name: alice
   Senha de alice: ********
   Role [i=initiator / r=responder]: i
   Onion host (leave blank for localhost):
   ```

   Terminal 2:

   ```bash
   cd Client
   python client_cli.py

   Room name: spectre
   Your name: bob
   Senha de bob: ********
   Role [i=initiator / r/responder]: r
   Onion host (leave blank for localhost):
   ```

4. **Troca de mensagens**

   - Digite mensagens em cada terminal → aparecem descriptografadas no outro.  
   - Use `/rotate` para rotacionar a chave DH.  
   - Use `/quit` para sair.

---

## 8. Execução via Tor (.onion)

Pré-requisitos:

- Tor Browser ou serviço Tor em execução localmente (SOCKS5 em `127.0.0.1:9150`)  
- Hidden Service configurado apontando para `127.0.0.1:5000` (Server)

Passos:

1. Subir back-end e Server normalmente (localhost).  
2. Iniciar o Tor Browser.  
3. Rodar o Client:

   ```bash
   cd Client
   python client_cli.py

   Room name: spectre
   Your name: alice
   Senha de alice: ********
   Role [i=initiator / r/responder]: i
   Onion host (leave blank for localhost): <host_onion_sem_http>
   ```

O client monta algo como `http://<host>.onion:80` e usa `requests` com proxy SOCKS5 (`127.0.0.1:9150`).

---

## 9. Problemas comuns

- **401 Unauthorized do back-end**
  - Token interno do `Server` diferente do configurado no `InternalTokenFilter`
  - Header incorreto (`X-Internal-Token` com valor errado)

- **Cliente não consegue conectar ao Server**
  - Verificar se o Server está rodando na porta correta (`5000`)
  - Verificar se o host `.onion` está correto (via Tor)
  - Reiniciar o Tor Browser, o Server e o Back-end normalmente resolvem.

- **Erro ao descriptografar mensagens**
  - Ratchet desincronizado (por exemplo, arquivos de estado corrompidos)
  - Arquivo de estado antigo → possível solução: apagar o estado da sala e reiniciar sessão


---
