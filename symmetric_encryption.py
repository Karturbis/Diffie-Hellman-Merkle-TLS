import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def int_to_fernet_key(key):
    key = str(key).encode()

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = b'',
        iterations = 320000
    )
    aes_key = base64.b64encode(kdf.derive(key))
    return Fernet(aes_key)

def encrypt(message, key):
    fernet_key = int_to_fernet_key(key)
    print(f"DEBUGING: ENcrypt fernet key = {fernet_key}")
    chiffre = fernet_key.encrypt(message.encode())
    return chiffre

def decrypt(chiffre, key):
    print(f"DEBUGING: symmetric_encryption.decrypt() chiffre = {chiffre}, key = {key}")
    fernet_key = int_to_fernet_key(key)
    message = fernet_key.decrypt(chiffre)
    return message.decode()

#print(decrypt(b'gAAAAABmI8az-IkZpmRY-_5tLZqI2pdCimmqiSS4b-CdRudy06c3cmEVJUIpp1Qf0oZbUvmWrQsdimdBMOToWa4fDTEopDtLFA==', 84027))
