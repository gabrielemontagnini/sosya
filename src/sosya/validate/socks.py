"""A minimal SOCKS5 client (RFC 1928, no authentication, CONNECT only), standard library only.

`sosya validate` uses it from the host to check that the proxy of `sosya up --proxy` reaches
the range's services, and that it gives no internet when the attacker box has none.
"""

import socket

TIMEOUT = 5.0


def _receive(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("the proxy closed the connection")
        data += chunk
    return data


def connect(proxy: tuple[str, int], host: str, port: int, timeout: float = TIMEOUT) -> bool:
    """True when the proxy opens a TCP connection to `host:port` (resolved by the proxy)."""
    try:
        with socket.create_connection(proxy, timeout=timeout) as sock:
            sock.sendall(b"\x05\x01\x00")  # version 5, one method: no authentication
            if _receive(sock, 2) != b"\x05\x00":
                return False
            name = host.encode("idna")
            request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big")
            sock.sendall(request)
            reply = _receive(sock, 4)
            return reply[0] == 5 and reply[1] == 0
    except (OSError, ConnectionError, UnicodeError):
        return False
