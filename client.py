import asyncio
import websockets
import security
from Crypto.PublicKey import RSA

KEY = b"thisisaverysecretkey1234"
IV = b"thisisinitvector"
HMAC_KEY = b"supersecrethmackey"

# Gera um par de chaves RSA para o cliente
private_key = RSA.generate(2048)
public_key = private_key.publickey().export_key().decode()  # Exporta a chave pública como string

async def client():
    async with websockets.connect("ws://localhost:8765") as websocket:
        while True:
            message = input("Digite sua mensagem: ").strip()
            if not message:
                print("⚠️ Mensagem não pode ser vazia!")
                continue

            encrypted_message = security.encrypt_message(message, KEY, IV)
            message_hmac = security.generate_hmac(message, HMAC_KEY)
            message_signature = security.sign_message(message, private_key)

            # Enviamos também a chave pública do cliente
            await websocket.send(f"{encrypted_message}||{message_hmac}||{message_signature}||{public_key}")

            response = await websocket.recv()
            print(response)

if __name__ == "__main__":
    asyncio.run(client())
