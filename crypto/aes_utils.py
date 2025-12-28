from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def encrypt_aes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext


def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()