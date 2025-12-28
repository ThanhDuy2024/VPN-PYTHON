from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

KEY_DIR = "keys"


def generate_keys():
    if not os.path.exists(KEY_DIR):
        os.mkdir(KEY_DIR)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(f"{KEY_DIR}/server_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )

    with open(f"{KEY_DIR}/server_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key():
    with open(f"{KEY_DIR}/server_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)