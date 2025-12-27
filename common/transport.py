"""Transport wrappers for different link layers.

This module contains minimal stubs for two transport abstractions used by
the project: a SimpleBLE wrapper and an L2CAP socket wrapper. Implementations
are placeholders — replace with actual platform-specific code when available.

Citations: skeleton references for transport [cite: 137].
"""
import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)


class BaseTransport:
    """Minimal abstract transport contract.

    Methods:
        send(bytes) -> int: send bytes, return bytes sent.
        recv(n) -> bytes: receive up to n bytes.
    """

    def send(self, data: bytes) -> int:
        raise NotImplementedError()

    def recv(self, n: int = 4096) -> bytes:
        raise NotImplementedError()


class SimpleBLETransport(BaseTransport):
    """Stub for a BLE-based transport.

    Real implementations should use a BLE library (e.g., bleak) and handle
    connection, MTU, fragmentation, pairing, etc. This stub provides the
    API surface for tests and integration.
    """

    def __init__(self, device_addr: Optional[str] = None):
        self.device_addr = device_addr

    def send(self, data: bytes) -> int:
        logger.debug("SimpleBLETransport.send: %d bytes", len(data))
        # Placeholder: pretend all bytes were sent
        return len(data)

    def recv(self, n: int = 4096) -> bytes:
        logger.debug("SimpleBLETransport.recv: asked for %d bytes", n)
        return b""


class L2CAPSocketTransport(BaseTransport):
    """Simple L2CAP socket wrapper (POSIX)."""

    def __init__(self, host: str = "localhost", port: int = 12345):
        # This is a placeholder; real L2CAP sockets require bluetooth support.
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def send(self, data: bytes) -> int:
        if not self.sock:
            raise RuntimeError("socket not connected")
        return self.sock.send(data)

    def recv(self, n: int = 4096) -> bytes:
        if not self.sock:
            raise RuntimeError("socket not connected")
        return self.sock.recv(n)
