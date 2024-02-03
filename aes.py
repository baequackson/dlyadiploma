# import secrets
#
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#
#
# def generate_aes_key():
#     key = secrets.token_bytes(32)  # 256-bit key
#     return key
#
#
# def encrypt_aes(plaintext, key):
#     iv = secrets.token_bytes(16)  # 128-bit IV
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(plaintext) + encryptor.finalize()
#     return iv + ciphertext
#
#
# def decrypt_aes(ciphertext, key):
#     iv = ciphertext[:16]
#     ciphertext = ciphertext[16:]
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     plaintext = decryptor.update(ciphertext) + decryptor.finalize()
#     return plaintext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def generate_key():
    key = urlsafe_b64encode(os.urandom(32))  # 32 bytes key for AES-256
    return key.decode('utf-8')

def generate_iv():
    iv = os.urandom(16)  # 16 bytes IV for AES
    return iv

def encrypt(text, key):
    key = urlsafe_b64decode(key)
    iv = generate_iv()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
    return urlsafe_b64encode(iv + ciphertext).decode('utf-8')

def decrypt(ciphertext, key):
    key = urlsafe_b64decode(key)
    data = urlsafe_b64decode(ciphertext)
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

# Пример использования:
key = generate_key()
text = "djbobo"

# Шифрование
encrypted_text = encrypt(text, key)
print(f"Зашифрованный текст: {encrypted_text}")

# Дешифрование
decrypted_text = decrypt(encrypted_text, key)
print(f"Расшифрованный текст: {decrypted_text}")

key2 = "7z1lJi0BtZKbpbT_kKkcpwCI_aVUUg=="
