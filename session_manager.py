import time
from session import Session

SESSION_TIMEOUT = 60


class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create(self, addr, conn):
        session = Session(addr, conn)
        self.sessions[session.session_id] = session
        return session

    def get(self, session_id):
        return self.sessions.get(session_id)

    def remove(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]

    def cleanup(self):
        now = time.time()
        for sid in list(self.sessions.keys()):
            session = self.sessions[sid]
            if now - session.last_active > SESSION_TIMEOUT:
                try:
                    session.conn.close()
                except:
                    pass
                del self.sessions[sid]