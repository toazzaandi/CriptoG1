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

            # Converte a chave pública do cliente recebida para um objeto RSA
            try:
                client_public_key = RSA.import_key(client_public_key)
            except ValueError:
                await websocket.send("⚠️ Erro: Chave pública inválida!")
                continue

            # Tenta descriptografar a mensagem com IV
            decrypted_message = security.decrypt_message(encrypted_message, KEY, IV)
            if not decrypted_message:
                await websocket.send("⚠️ Erro: Mensagem corrompida!")
                continue

            # Verifica a integridade com HMAC
            if not security.verify_hmac(decrypted_message, received_hmac, HMAC_KEY):
                await websocket.send("⚠️ Erro: HMAC inválido! A mensagem pode ter sido adulterada.")
                continue

            # Verifica a assinatura digital com a chave pública do cliente
            if not security.verify_signature(decrypted_message, received_signature, client_public_key):
                await websocket.send("⚠️ Erro: Assinatura digital inválida! Origem não confiável.")
                continue

            print(f"✅ Mensagem recebida: {decrypted_message}")
            await websocket.send("✅ Mensagem recebida com sucesso!")

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.remove(websocket)

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("🚀 Servidor iniciado na porta 8765")
        await asyncio.Future()  # Mantém o servidor rodando

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("🛑 Servidor encerrado pelo usuário.")
