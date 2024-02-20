from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


def rsa_generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_key_pem, public_key_pem


def rsa_encrypt_text(public_key_pem, plaintext):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()


def rsa_decrypt_text(private_key_pem, ciphertext):
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None,
                                                     backend=default_backend())
    decrypted_text = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode('utf-8')


# # Пример использования:
# private_key, public_key = generate_key_pair()
# print(private_key)
# print(public_key)
#
# plaintext = "Hello, RSA!"
#
# ciphertext = encrypt_text(public_key, plaintext)
# print(f"Ciphertext: {ciphertext}")
#
# decrypted_text = decrypt_text(private_key, ciphertext)
# print(f"Decrypted Text: {decrypted_text}")
