import socket
import threading
import time

from protocol import pack_message, unpack_message
from crypto.aes_utils import encrypt_aes, decrypt_aes
from crypto.rsa_utils import load_private_key
from session_manager import SessionManager

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = "0.0.0.0"
PORT = 9000

private_key = load_private_key()
session_manager = SessionManager()


def handle_client(conn, addr):
    session = session_manager.create(addr, conn)
    sid = session.session_id

    print(f"Client {addr} | Session {sid}")

    # Gửi session ID cho client
    conn.sendall(pack_message("SID", sid, b""))

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            msg_type, session_id, payload = unpack_message(data)
            session.touch()

            if msg_type == "MSG" and payload == b"HELLO":
                with open("keys/server_public.pem", "rb") as f:
                    conn.sendall(pack_message("MSG", sid, f.read()))

            elif msg_type == "KEY":
                session.aes_key = private_key.decrypt(
                    payload,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"AES key set for {sid}")
                conn.sendall(pack_message("MSG", sid, b"OK"))

            elif msg_type == "ENC":
                plaintext = decrypt_aes(session.aes_key, payload)
                print(f"[{sid[:8]}] {plaintext.decode()}")

                response = encrypt_aes(session.aes_key, b"VPN OK")
                conn.sendall(pack_message("ENC", sid, response))

        except Exception as e:
            print("Error:", e)
            break

    conn.close()
    session_manager.remove(sid)
    print(f"Session closed: {sid}")


def cleanup_thread():
    while True:
        session_manager.cleanup()
        time.sleep(5)


threading.Thread(target=cleanup_thread, daemon=True).start()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(5)
print("VPN Server running (Session enabled)")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()