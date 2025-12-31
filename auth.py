import hashlib

USERS = {
    "admin": hashlib.sha256(b"123456").hexdigest(),
    "user": hashlib.sha256(b"password").hexdigest(),
}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(username: str, password: str) -> bool:
    if username not in USERS:
        return False
    return USERS[username] == hash_password(password)