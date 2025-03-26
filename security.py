import base64
import hmac
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15

## Encrypt AES-CBC (com IV)
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

## Decrypt AES-CBC (com IV)
def decrypt_message(encrypted_message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)
        return decrypted.decode()
    except ValueError:
        return None

## HMAC para verificação de integridade
def generate_hmac(message, hmac_key):
    return hmac.new(hmac_key, message.encode(), SHA256).hexdigest()

def verify_hmac(message, received_hmac, hmac_key):
    return hmac.compare_digest(generate_hmac(message, hmac_key), received_hmac)

## Assinatura Digital RSA
def sign_message(message, private_key):
    message_hash = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return base64.b64encode(signature).decode()

def verify_signature(message, received_signature, public_key):
    try:
        message_hash = SHA256.new(message.encode())
        pkcs1_15.new(public_key).verify(message_hash, base64.b64decode(received_signature))
        return True
    except (ValueError, TypeError):
        return False
