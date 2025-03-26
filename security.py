import base64
import hmac
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15


## Encryption
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def generate_hmac(message, hmac_key):
    if message:
        return hmac.new(hmac_key, message.encode(), SHA256).hexdigest()
    return ""

def sign_message(message, private_key):
    message_hash = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return base64.b64encode(signature).decode('utf-8')


## Decriptation
def decrypt_message(encrypted_message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)
        return decrypted.decode('utf-8')
    except ValueError as e:
        return None

def verify_hmac(message, received_hmac, hmac_key):
    return hmac.compare_digest(generate_hmac(message, hmac_key), received_hmac)

def verify_signature(message, received_signature, private_key):
    message_hash = SHA256.new(message.encode())
    try:
        pkcs1_15.new(private_key).verify(message_hash, base64.b64decode(received_signature))
        return True
    except (ValueError, TypeError):
        return False

def verify_and_get_message(encrypted_message, received_hmac, received_signature, key, iv, hmac_key, private_key=None):
    errors = []

    decrypted_message = decrypt_message(encrypted_message, key, iv)
    if not decrypted_message:
        errors.append("Mensagem corrompida!");
    

    if not verify_hmac(decrypted_message, received_hmac, hmac_key):
        errors.append("HMAC adulterado!")

    if private_key: 
        if not verify_signature(decrypted_message, received_signature, private_key): 
            errors.append("Assinatura inválida!")
        
    if len(errors) == 0:
        return decrypted_message
    else: 
        raise Exception('||'.join(errors))

    