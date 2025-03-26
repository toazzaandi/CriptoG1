import asyncio
import websockets
import security
from Crypto.PublicKey import RSA

KEY = b"thisisaverysecretkey1234"
IV = b"thisisinitvector"
KEY_ERROR = b"thisisaverysecretkey4321"
HMAC_KEY = b"supersecrethmackey"
HMAC_KEY_ERROR = b"supersecrethmackei"

private_key = RSA.generate(2048)
public_key = private_key.publickey()

async def client():
    async with websockets.connect("ws://localhost:8765") as websocket:
        while True:
            message = input("Digite sua mensagem: ")
            if not message.strip():
                print("⚠️ Mensagem não pode ser vazia!")
                continue

            encrypted_message = security.encrypt_message(message, KEY, IV)
            message_hmac = security.generate_hmac(message, HMAC_KEY)
            message_signature = security.sign_message(message, private_key)

            await websocket.send(f"{encrypted_message}||{message_hmac}")
            #await websocket.send(f"{encrypted_message}||{message_hmac}||{message_signature}") ## TODO: Implements With message_signature
            response = await websocket.recv()
            print(response)

            fail_encrypted_message = security.encrypt_message(message, KEY_ERROR, IV)
            fail_message_hmac = security.generate_hmac(message, HMAC_KEY_ERROR)
            await websocket.send(f"{fail_encrypted_message}||{fail_message_hmac}")
            response_error = await websocket.recv()
            print(response_error)      


if __name__ == "__main__":
    asyncio.run(client())
