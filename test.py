from ecdh import *

# Пример использования:

private_key, public_key = generate_ecc_key_pair()
serialized_public_key = serialize_public_key(public_key)
serialized_private_key = serialize_private_key(private_key)

plaintext = b'This is a secret message.'

ciphertext = encrypt_data(public_key, plaintext)
decrypted_text = decrypt_data(private_key, serialized_public_key, ciphertext)

print(f"Original: {plaintext}")
print(f"Decrypted: {decrypted_text}")