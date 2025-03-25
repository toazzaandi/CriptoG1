import asyncio
import websockets
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# Chave simétrica, HMAC e RSA (idealmente, devem ser trocadas de forma segura)
KEY = b"thisisaverysecretkey12345678"  # 32 bytes para AES-256
IV = b"thisisinitialvectr"
HMAC_KEY = b"supersecrethmackey"

# Geração de chaves RSA (em um cenário real, cada cliente teria suas próprias chaves)
private_key = RSA.generate(2048)
public_key = private_key.publickey()

def encrypt_message(message):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)
    return decrypted.decode()

def generate_hmac(message):
    return hmac.new(HMAC_KEY, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message, received_hmac):
    return hmac.compare_digest(generate_hmac(message), received_hmac)

def sign_message(message):
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return base64.b64encode(signature).decode()

def verify_signature(message, received_signature):
    message_hash = hashlib.sha256(message.encode()).digest()
    try:
        pkcs1_15.new(public_key).verify(message_hash, base64.b64decode(received_signature))
        return True
    except (ValueError, TypeError):
        return False

async def listen_server(websocket):
    async for received_data in websocket:
        encrypted_message, received_hmac, received_signature = received_data.split("||")
        decrypted_message = decrypt_message(encrypted_message)
        if verify_hmac(decrypted_message, received_hmac) and verify_signature(decrypted_message, received_signature):
            print(f"Mensagem recebida: {decrypted_message}")
        else:
            print("⚠️ Alerta: Mensagem corrompida, adulterada ou assinatura inválida!")

async def client():
    async with websockets.connect("ws://localhost:8766") as websocket:
        asyncio.create_task(listen_server(websocket))
        while True:
            message = input("Digite sua mensagem: ")
            if not message.strip():  # Verifica se a mensagem não está vazia
                print("⚠️ Mensagem não pode ser vazia!")
                continue
            encrypted_message = encrypt_message(message)
            message_hmac = generate_hmac(message)
            message_signature = sign_message(message)
            await websocket.send(f"{encrypted_message}||{message_hmac}||{message_signature}")

if __name__ == "__main__":
    asyncio.run(client())
