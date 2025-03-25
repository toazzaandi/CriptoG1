# CriptoG1

## Projeto de Criptografia

Este projeto foi desenvolvido como parte do trabalho G1 na matéria de Criptografia e Segurança, tutelada pelo Prof. Rafael Basso Reis. O objetivo é implementar um sistema de comunicação segura utilizando criptografia simétrica e assimétrica.

### Descrição

O sistema permite que os usuários enviem mensagens de forma segura através de um servidor WebSocket. As mensagens são criptografadas usando AES, e a integridade e autenticidade são garantidas através de HMAC e assinaturas digitais com RSA.

### Funcionalidades

- Criptografia de mensagens usando AES (modo CBC).
- Geração e verificação de HMAC para garantir a integridade das mensagens.
- Assinatura e verificação de mensagens usando RSA.
- Comunicação em tempo real através de WebSockets.

### Tecnologias Utilizadas

- Python
- Bibliotecas: `asyncio`, `websockets`, `pycryptodome`

### Instalação

1. Clone o repositório:
   ```bash
   git clone <URL_DO_REPOSITORIO>
   cd CriptoG1
   ```

2. Instale as dependências:
   ```bash
   pip install websockets pycryptodome
   ```

### Uso

1. Inicie o servidor:
   ```bash
   python server.py
   ```

2. Em seguida, inicie o cliente:
   ```bash
   python client.py
   ```

3. Siga as instruções no terminal para enviar mensagens.

## Alunos

- Andriano Toazza