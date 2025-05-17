import asyncio
import websockets
import security
from Crypto.PublicKey import RSA

KEY = b"thisisaverysecretkey1234"
IV = b"thisisinitvector"
HMAC_KEY = b"supersecrethmackey"

connected_clients = set()

async def handler(websocket, path=None):
    connected_clients.add(websocket)
    try:
        async for received_data in websocket:
            parts = received_data.split("||")

            if len(parts) != 4:
                await websocket.send("⚠️ Formato inválido! Esperado: Encrypted||HMAC||Signature||PublicKey")
                continue

            encrypted_message, received_hmac, received_signature, client_public_key = parts

            try:
                client_public_key = RSA.import_key(client_public_key)
            except ValueError:
                await websocket.send("⚠️ Erro: Chave pública inválida!")
                continue

            decrypted_message = security.decrypt_message(encrypted_message, KEY, IV)
            if not decrypted_message:
                await websocket.send("⚠️ Erro: Mensagem corrompida!")
                continue

            if not security.verify_hmac(decrypted_message, received_hmac, HMAC_KEY):
                await websocket.send("⚠️ Erro: HMAC inválido! A mensagem pode ter sido adulterada.")
                continue

            if not security.verify_signature(decrypted_message, received_signature, client_public_key):
                await websocket.send("⚠️ Erro: Assinatura digital inválida! Origem não confiável.")
                continue

            print(f"\n✅ Mensagem recebida do cliente: {decrypted_message}")
            
            response_message = input("Digite a resposta para o cliente: ")
            
            encrypted_response = security.encrypt_message(response_message, KEY, IV)
            response_hmac = security.generate_hmac(response_message, HMAC_KEY)
            response_signature = security.sign_message(response_message, RSA.import_key(open('server_private.pem').read()))
            
            await websocket.send(
                f"{encrypted_response}||{response_hmac}||{response_signature}||{open('server_public.pem').read()}"
            )

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.remove(websocket)

async def main():
    try:
        with open('server_private.pem') as f:
            pass
    except FileNotFoundError:
        key = RSA.generate(2048)
        with open('server_private.pem', 'wb') as f:
            f.write(key.export_key())
        with open('server_public.pem', 'wb') as f:
            f.write(key.publickey().export_key())
    
    async with websockets.serve(handler, "localhost", 8765):
        print("🚀 Servidor iniciado na porta 8765")
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("🛑 Servidor encerrado pelo usuário.")