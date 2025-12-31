def pack_message(msg_type, session_id, payload):
    header = msg_type.encode().ljust(4, b' ')
    sid = session_id.encode().ljust(36, b' ')
    return header + sid + payload


def unpack_message(data):
    msg_type = data[:4].decode().strip()
    session_id = data[4:40].decode().strip()
    payload = data[40:]
    return msg_type, session_id, payload