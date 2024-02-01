from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes


def encrypt_data(public_key, plaintext):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        ec.ECIES()
    )
    return ciphertext


def decrypt_data(private_key, ciphertext):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    plaintext = private_key.decrypt(
        ciphertext,
        ec.ECIES()
    )
    return plaintext.decode('utf-8')


# Пример использования
private_key, public_key = generate_ecc_key_pair()
plaintext_data = "Hello, ECC!"

# Шифрование
ciphertext = encrypt_data(public_key, plaintext_data)
print("Ciphertext:", ciphertext)

# Расшифрование
decrypted_text = decrypt_data(private_key, ciphertext)
print("Decrypted Text:", decrypted_text)
