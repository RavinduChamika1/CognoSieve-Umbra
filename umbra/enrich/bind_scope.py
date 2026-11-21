"""Bind scope classification: loopback, lan, public, unknown."""

import ipaddress
from typing import Optional


def is_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip())
        return True
    except ValueError:
        return False


def classify_bind_scope(
    bind_addr: Optional[str] = None,
    target_host: Optional[str] = None,
    has_public_interface: bool = False
) -> str:
    """
    Classify listener or target scope into: loopback | lan | public | unknown
    Rules:
    - 127.0.0.1 or ::1 or localhost -> loopback
    - 0.0.0.0 or :: -> lan unless has_public_interface is True, then public
    - RFC1918 private IP / link-local / ULA -> lan
    - Public IP -> public
    """
    check_addr = (bind_addr or target_host or "").strip().lower()
    if not check_addr:
        return "unknown"

    # Handle loopback strings
    if check_addr in ("127.0.0.1", "::1", "localhost"):
        return "loopback"

    # Handle all-interfaces bind
    if check_addr in ("0.0.0.0", "::", "*"):
        return "public" if has_public_interface else "lan"

    try:
        ip = ipaddress.ip_address(check_addr)
        if ip.is_loopback:
            return "loopback"
        if ip.is_unspecified:
            return "public" if has_public_interface else "lan"
        if ip.is_private or ip.is_link_local:
            return "lan"
        return "public"
    except ValueError:
        # Hostname check
        if check_addr.endswith(".local") or check_addr.endswith(".internal"):
            return "lan"
        return "unknown"

