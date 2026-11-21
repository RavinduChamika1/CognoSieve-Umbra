"""TLS capability check for endpoints."""

import socket
import ssl
from typing import Optional


def check_tls_sync(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if endpoint negotiates TLS connection."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception:
        return False

