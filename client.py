import socket
import os

from protocol import pack_message, unpack_message
from crypto.aes_utils import encrypt_aes, decrypt_aes

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = "127.0.0.1"
PORT = 9000

sock = socket.socket()
sock.connect((HOST, PORT))

_, session_id, _ = unpack_message(sock.recv(1024))
print("Session:", session_id)

sock.sendall(pack_message("MSG", session_id, b"HELLO"))

_, _, pubkey_bytes = unpack_message(sock.recv(4096))
public_key = serialization.load_pem_public_key(pubkey_bytes)

aes_key = os.urandom(32)

encrypted_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

sock.sendall(pack_message("KEY", session_id, encrypted_key))
print(unpack_message(sock.recv(1024))[2].decode())

# AUTH
print("=====LOGIN=====");
userName = input("Enter your user name: ")
password = input("Enter your password: ")
auth_msg = f"AUTH|{userName}|{password}".encode()
sock.sendall(pack_message("ENC", session_id, encrypt_aes(aes_key, auth_msg)))

_, _, resp = unpack_message(sock.recv(4096))
result = decrypt_aes(aes_key, resp).decode()
print("Auth result:", result)

if result != "OK":
    sock.close()
    exit()

# VPN DATA
sock.sendall(pack_message("ENC", session_id,
    encrypt_aes(aes_key, b"HELLO VPN AFTER AUTH")))

_, _, resp = unpack_message(sock.recv(4096))
print("Server:", decrypt_aes(aes_key, resp).decode())

sock.close()