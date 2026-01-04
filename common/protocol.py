from __future__ import annotations
from dataclasses import dataclass
import struct
from typing import Union

SERVICE_UUID = '12345678-1234-5678-1234-56789abcdef0'
CHAR_UUID = '12345678-1234-5678-1234-56789abcdef1'

FRAME_TYPE_HEARTBEAT = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_HANDSHAKE_CERT = 0x10
FRAME_TYPE_HANDSHAKE_DH = 0x11
FRAME_TYPE_HANDSHAKE_AUTH = 0x12

VERSION = 1
NID_LEN = 16
MAX_PAYLOAD = 512


def nid_from_hex(hexstr: str) -> bytes:
    
    s = hexstr.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    raw = bytes.fromhex(s)
    if len(raw) != NID_LEN:
        raise ValueError(f"NID must be {NID_LEN} bytes (got {len(raw)})")    
    return raw

def ensure_nid(nid: Union[str, bytes]) -> bytes:
    if isinstance(nid, bytes):
        if len(nid) != NID_LEN:
            raise ValueError(f"NID must be {NID_LEN} bytes (got {len(nid)})")
        return nid
    if isinstance(nid, str):
        return nid_from_hex(nid)
    raise TypeError("NID must be 16 bytes or hex string")
    
    
@dataclass(frozen=True)
class Frame:
    version: int
    src: bytes
    dest: bytes
    ftype: int
    seq: int
    payload: bytes
    
    def pack(self) -> bytes:
        if not (0 <= self.version <= 255):
            raise ValueError("version out of range")
        if not (0 <= self.ftype <= 255):
            raise ValueError("ftype out of range")
        if not (0 <= self.seq <= 0xFFFFFFFF):
            raise ValueError("seq out of range")
        if len(self.src) != NID_LEN or len(self.dest) != NID_LEN:
            raise ValueError("src/dest NID must be 16 bytes")
        if len(self.payload) > MAX_PAYLOAD:
            raise ValueError(f"payload too large: {len(self.payload)} > {MAX_PAYLOAD}")

        header = struct.pack(
            HEADER_FMT,
            self.version,
            self.src,
            self.dest,
            self.ftype,
            self.seq,
            len(self.payload),
        )
        return header + self.payload

    @staticmethod
    def unpack(data: bytes) -> "Frame":
        if len(data) < HEADER_LEN:
            raise ValueError("frame too short for header")
        version, src, dest, ftype, seq, plen = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
        if version != VERSION:
            raise ValueError(f"unsupported version: {version}")
        if len(data) != HEADER_LEN + plen:
            raise ValueError(f"bad length: header says {plen}, got {len(data) - HEADER_LEN}")
        payload = data[HEADER_LEN:]
        return Frame(version, src, dest, ftype, seq, payload)


class SeqCounter:
    def __init__(self, start: int = 0):
        self._seq = start

    def next(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq


def pack_frame(src: Union[bytes, str], dest: Union[bytes, str], ftype: int, seq: int, payload: bytes) -> bytes:
    return Frame(VERSION, ensure_nid(src), ensure_nid(dest), ftype, seq, payload).pack()


def unpack_frame(data: bytes) -> Frame:
    return Frame.unpack(data)
        
def create_frame(src, dest, ftype, payload):
    return src.encode() + dest.encode() + bytes([ftype]) + SEQ_START.to_bytes(4, 'big') + payload

def parse_frame(self, data):
    # Placeholder: src(8), dest(8), type(1), seq(4), payload
    return {'src': data[:8], 'dest': data[8:16], 'type': data[16], 'seq': data[17:21], 'payload': data[21:]}
