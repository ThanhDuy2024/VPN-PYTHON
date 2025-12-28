import time
import uuid

class Session:
    def __init__(self, addr, conn):
        self.session_id = str(uuid.uuid4())
        self.addr = addr
        self.conn = conn
        self.aes_key = None
        self.start_time = time.time()
        self.last_active = time.time()

    def touch(self):
        self.last_active = time.time()