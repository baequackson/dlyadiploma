from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os


def aes_generate_key():
    aes_key = os.urandom(32)  # 32 bytes key for AES-256
    return urlsafe_b64encode(aes_key).decode('utf-8')


def aes_generate_iv():
    iv = os.urandom(16)  # 16 bytes IV for AES
    return iv


def aes_encrypt(data, aes_key):
    aes_key_bytes = urlsafe_b64decode(aes_key)
    iv = aes_generate_iv()
    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(ciphertext, aes_key):
    aes_key_bytes = urlsafe_b64decode(aes_key)
    data = ciphertext
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext