import asyncio
import websockets
import security
from Crypto.PublicKey import RSA

KEY = b"thisisaverysecretkey1234"
IV = b"thisisinitvector"
HMAC_KEY = b"supersecrethmackey"

private_key = RSA.generate(2048)
public_key = private_key.publickey()

connected_clients = set()

async def handler(websocket, path=None):
    connected_clients.add(websocket)
    try:
        async for received_data in websocket:
            parts = received_data.split("||")

            if len(parts) == 2:
                encrypted_message, received_hmac = received_data.split("||")
                received_signature = None
            elif len(parts) == 3:
                encrypted_message, received_hmac, received_signature = received_data.split("||")
            else:
                raise Exception("Invalid arguments lenght")

            try:
                message = security.verify_and_get_message(encrypted_message, received_hmac, received_signature, KEY, IV, HMAC_KEY, None)
                print(f"Mensagem recebida: {message}")
                await websocket.send("OK!")
            except Exception as e:
                error_response = f"⚠️ Alerta: {e}";
                print(error_response)
                await websocket.send(error_response)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.remove(websocket)

async def main():
    async with websockets.serve(handler, "localhost", 8765) as server:
        try:
            port = server.sockets[0].getsockname()[1]
            print(f"Server is listening on port {port}")
            await asyncio.Future()
        except asyncio.CancelledError:
            print("Servidor encerrado.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Servidor interrompido pelo usuário.")
