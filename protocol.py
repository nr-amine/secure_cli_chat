import struct
import json
import socket

def send_frame(sock: socket.socket, data: dict):
    """Encodes a Python dict as JSON and transmits it with a 4-byte big-endian length prefix."""
    payload = json.dumps(data).encode('utf-8')
    header = struct.pack('>I', len(payload))
    sock.sendall(header + payload)

def recv_frame(sock: socket.socket) -> dict | None:
    """Reads a 4-byte length-prefixed JSON frame from the socket. Returns None on disconnect."""
    raw_header = recv_all(sock, 4)
    if not raw_header:
        return None
    length = struct.unpack('>I', raw_header)[0]
    payload = recv_all(sock, length)
    if not payload:
        return None
    return json.loads(payload.decode('utf-8'))

def recv_all(sock: socket.socket, n: int) -> bytes | None:
    """Helper to ensure exactly n bytes are read from a stream socket."""
    data = bytearray()
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except (ConnectionResetError, BrokenPipeError):
            return None
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)
