# Custom UUIDs for the project (data plane service)
SERVICE_UUID = '12345678-1234-5678-1234-56789abcdef0'
CHAR_UUID = '12345678-1234-5678-1234-56789abcdef1'

# Frame types for multiplexing
FRAME_TYPE_HEARTBEAT = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_HANDSHAKE_CERT = 0x10
FRAME_TYPE_HANDSHAKE_DH = 0x11
FRAME_TYPE_HANDSHAKE_AUTH = 0x12

def create_frame(src, dest, ftype, payload):
    return src.encode() + dest.encode() + bytes([ftype]) + SEQ_START.to_bytes(4, 'big') + payload

def parse_frame(self, data):
    # Placeholder: src(8), dest(8), type(1), seq(4), payload
    return {'src': data[:8], 'dest': data[8:16], 'type': data[16], 'seq': data[17:21], 'payload': data[21:]}
