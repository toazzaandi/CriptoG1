import asyncio
import websockets
import security
from Crypto.PublicKey import RSA

KEY = b"thisisaverysecretkey1234"
IV = b"thisisinitvector"
HMAC_KEY = b"supersecrethmackey"

private_key = RSA.generate(2048)
public_key = private_key.publickey().export_key().decode()

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

            await websocket.send(f"{encrypted_message}||{message_hmac}||{message_signature}||{public_key}")

            response_data = await websocket.recv()
            response_parts = response_data.split("||")
            
            if len(response_parts) != 4:
                print("⚠️ Formato de resposta inválido!")
                continue

            encrypted_response, response_hmac, response_signature, server_public_key = response_parts
            
            try:
                server_public_key = RSA.import_key(server_public_key)
            except ValueError:
                print("⚠️ Erro: Chave pública do servidor inválida!")
                continue

            decrypted_response = security.decrypt_message(encrypted_response, KEY, IV)
            if not decrypted_response:
                print("⚠️ Erro: Resposta do servidor corrompida!")
                continue

            if not security.verify_hmac(decrypted_response, response_hmac, HMAC_KEY):
                print("⚠️ Erro: HMAC da resposta inválido!")
                continue

            if not security.verify_signature(decrypted_response, response_signature, server_public_key):
                print("⚠️ Erro: Assinatura digital do servidor inválida!")
                continue

            print(f"Resposta do servidor: {decrypted_response}")

if __name__ == "__main__":
    asyncio.run(client())