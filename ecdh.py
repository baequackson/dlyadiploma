# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.asymmetric import padding
#
# # Выбор кривой
# curve = ec.SECP256K1()
#
# # Генерация ключей
# private_key = ec.generate_private_key(curve)
# public_key = private_key.public_key()
#
# # Сериализация ключей
# private_key_bytes = private_key.private_bytes(
#     encoding=ec.Encoding.PEM,
#     format=ec.PrivateFormat.PKCS8,
#     encryption_algorithm=ec.NoEncryption(),
# )
# public_key_bytes = public_key.public_bytes(
#     encoding=ec.Encoding.PEM,
#     format=ec.PublicFormat.SubjectPublicKeyInfo,
# )
#
# # Сохранение ключей
# with open("private_key.pem", "wb") as f:
#     f.write(private_key_bytes)
# with open("public_key.pem", "wb") as f:
#     f.write(public_key_bytes)
#
#
#
# # Загрузка ключей
# with open("private_key.pem", "rb") as f:
#     private_key_bytes = f.read()
# private_key = ec.load_private_key(
#     private_key_bytes,
#     encoding=ec.Encoding.PEM,
#     backend=default_backend(),
# )
# with open("public_key.pem", "rb") as f:
#     public_key_bytes = f.read()
# public_key = ec.load_public_key(
#     public_key_bytes,
#     encoding=ec.Encoding.PEM,
#     backend=default_backend(),
# )
#
# # Шифрование
# data = b"This is a secret message."
# ciphertext = public_key.encrypt(
#     data,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None,
#     ),
# )
#
# # Расшифрование
# plaintext = private_key.decrypt(
#     ciphertext,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None,
#     ),
# )
#
# print(plaintext)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from aes import key, key2


def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key


def encrypt(text, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def decrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()


# Пример использования
alice_private_key, alice_public_key = generate_key_pair()
bob_private_key, bob_public_key = generate_key_pair()

# Алиса и Боб обмениваются публичными ключами
alice_shared_key = derive_shared_key(alice_private_key, bob_public_key)
bob_shared_key = derive_shared_key(bob_private_key, alice_public_key)

# Шифрование текста с использованием общих ключей
text_to_encrypt = key2
alice_ciphertext = encrypt(text_to_encrypt, alice_shared_key)
bob_ciphertext = encrypt(text_to_encrypt, bob_shared_key)

# Дешифрование текста с использованием общих ключей
alice_decrypted_text = decrypt(bob_ciphertext, alice_shared_key)
bob_decrypted_text = decrypt(alice_ciphertext, bob_shared_key)

print(f"Alice decrypted text: {alice_decrypted_text}")
print(f"Bob decrypted text: {bob_decrypted_text}")
print(key2)

print(alice_private_key)










