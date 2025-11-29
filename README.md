SpectreProtocol — Chat E2E via Tor (X3DH + Double Ratchet)

Mensageiro ponta-a-ponta com X3DH para bootstrap e Double Ratchet para sigilo futuro/pós-comprometimento.
Transporte em tempo real via Socket.IO e suporte a mensagens assíncronas (fila offline) via REST.
Servidor atua como roteador cego: nunca vê plaintext.

Hidden Service (.onion) já disponível:

jvwjozfkejvf6ypklaf6b5j6723vbr6xcewu5frpjt3izxeeixejanad.onion

Fora de banda (QR): troca chave pública de identidade (IK) + metadados → autenticidade.

Em banda: apenas prekeys (SPK/OTK) e pacotes cifrados.

Servidor: roteia tempo real, guarda ciphertext em fila e prekeys públicos.

Stack

Cliente: Python 3.11+, pynacl, python-socketio, requests[socks]

Cripto: X25519 (X3DH simplificado), Double Ratchet, XSalsa20-Poly1305 (NaCl SecretBox)

Servidor: Flask + Flask-SocketIO + REST

Banco: PostgreSQL (SQLAlchemy)

Tor: Hidden Service v3 (já publicado)

Estrutura do projeto
E2E-Chat-via-TOR/
├─ client_cli.py
├─ crypto/
│  ├─ __init__.py
│  ├─ keys.py
│  ├─ x3dh.py
│  ├─ ratchet.py
│  └─ message.py
└─ server/
   ├─ app.py        # REST + relay Socket.IO
   ├─ auth.py       # registro/login/token
   └─ db.py         # modelos SQLAlchemy (PostgreSQL)

Instalação

Crie venv e instale dependências:

python -m venv .venv
# Windows PowerShell
. .\.venv\Scripts\Activate.ps1
# Linux/macOS
# source .venv/bin/activate

pip install --upgrade pip
pip install flask flask-socketio python-socketio pynacl requests[socks] \
            sqlalchemy psycopg2-binary argon2-cffi itsdangerous


Crie um .env 

Configuração do PostgreSQL

Crie DB/usuário:

CREATE DATABASE spectre;
CREATE USER spectre WITH ENCRYPTED PASSWORD 'SENHA_FORTE';
GRANT ALL PRIVILEGES ON DATABASE spectre TO spectre;


Inicialize as tabelas:

python -c "from server.db import create_all; create_all(); print('DB pronto')"


O servidor lê DATABASE_URL. Ajuste conforme seu ambiente.

Execução
Servidor (uma máquina)

Suba o backend (bind local para uso com .onion):

python -m server.app
# Esperado: Running on http://127.0.0.1:5000


O Hidden Service Tor já está configurado e aponta para 127.0.0.1:5000.
Não é necessário alterar o torrc para usar o endereço abaixo.

Cliente (cada máquina que vai conversar)

Abra o Tor Browser (deixa SOCKS em 127.0.0.1:9150).

Rode o cliente:

python client_cli.py
# Room: qualquer (apenas rótulo de transporte)
# Your name: alice|bob
# Role [i/r]: i ou r
# Onion host: jvwjozfkejvf6ypklaf6b5j6723vbr6xcewu5frpjt3izxeeixejanad


Cole somente o host (sem http://, sem porta). O cliente monta http://<host>.onion e usa HTTP polling via SOCKS (estável no Tor).

Fluxo de uso

Troca automatica fora de banda a chave pública de identidade (IK) + metadados (bundle).

Compare o fingerprint da IK em ambos os lados (TOFU).

2) Sessão síncrona (ambos online)

X3DH → root_key.

Double Ratchet inicia; mensagens fluem via Socket.IO (por .onion).

3) Mensagens assíncronas (destinatário offline)

Destinatário: /login → /publish-prekeys (publica SPK + OTKs).

Remetente (destinatário offline): /start-async <peer>

GET /prekeys/<peer> → recebe SPK (+ 1 OTK).

Roda X3DH (usando IK do QR, não do servidor) → root_key.

Envia prekey message para /queue/<peer>.

Destinatário ao voltar: /login → /inbox → processa prekey message, reconstrói root_key, inicia o ratchet e lê mensagens.

Comandos no CLI:

/rotate
Rotates double rachet


/quit
quits chat

Endpoints REST
Método & Rota	Auth	Descrição
POST /register	—	Cria usuário (username, password, identity_fingerprint opcional).
POST /login	—	Retorna bearer token (token).
POST /prekeys	Bearer	Publica spk_pub_b64 e otk_pub_b64[] (opcional).
GET /prekeys/<id>	—	Retorna SPK e consome 1 OTK. Recomenda-se <id> = fingerprint da IK.
POST /queue/<id>	—	Enfileira pacote cifrado para <id>.
GET /queue	Bearer	Entrega e remove pacotes pendentes do usuário logado.

Melhor prática: vincule username → fingerprint no cadastro e use fingerprint como chave primária de roteamento (evita colisões).

Segurança (resumo)

E2E real: servidor não possui chaves de sessão e não vê plaintext.

X3DH: bootstrap com IK (via QR) + prekeys (SPK/OTK) em banda.

Double Ratchet: sigilo futuro e pós-comprometimento.

AEAD: XSalsa20-Poly1305; cabeçalho pode ser associado como AD (opcional no message.py).

Fila offline: armazena somente ciphertext, com TTL e limite de tamanho.

Login: senhas com Argon2id, token assinado.

Identidade fora do servidor: IK pública não é servida pelo backend; autenticidade vem do QR.

Trabalhos futuros sugeridos: assinatura do SPK verificada com IK do QR, buffer de mensagens fora de ordem, persistência cifrada do estado do ratchet, quotas/limites por conta/IP.

Problemas comuns

“Connection refused / 10061”

No cliente: mantenha o Tor Browser aberto (SOCKS 127.0.0.1:9150).

O servidor deve estar ouvindo 127.0.0.1:5000.

Use o host .onion sem http:// no prompt do cliente.

No module named crypto

Execute sempre da raiz do projeto; garanta crypto/__init__.py.

Falha ao descriptografar

Ratchet: avance a receiving chain até n; só faça DH-ratchet quando dh_pub mudar.

Se AD estiver habilitado, use o mesmo header no encrypt/decrypt.

Licença

Defina a licença (MIT/Apache-2.0/etc).

