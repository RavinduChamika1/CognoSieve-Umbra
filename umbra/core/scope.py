"""Scope parsing, validation, CIDR expansion, and authorization enforcement."""

import ipaddress
import socket
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union
import yaml

from umbra.core.models import ScopeConfig


class ScopeRefusalError(Exception):
    """Raised when a target is outside authorized scope or authorization is missing."""
    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


def parse_scope_file(path: Union[str, Path]) -> ScopeConfig:
    """Load and validate a YAML scope configuration file."""
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Scope file not found: {path_obj}")

    with open(path_obj, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return ScopeConfig(
        label=data.get("label", path_obj.stem),
        authorized_by=data.get("authorized_by", "").strip(),
        targets=data.get("targets", []) or [],
        excluded=data.get("excluded", []) or [],
        notes=data.get("notes")
    )


def is_ip_address(host_or_ip: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host_or_ip)
        return True
    except ValueError:
        return False


def is_loopback(host: str) -> bool:
    """Check if host represents a loopback address."""
    clean = host.strip().lower()
    if clean in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_loopback
    except ValueError:
        return False


def is_private_or_link_local(ip_str: str) -> bool:
    """Check if an IP string is loopback, RFC1918 private, link-local, or ULA."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local)
    except ValueError:
        return False


def resolve_host_to_ips(host: str) -> List[str]:
    """Resolve a host name or return the IP itself."""
    clean = host.strip()
    if is_ip_address(clean):
        return [clean]
    if clean.lower() == "localhost":
        return ["127.0.0.1"]
    try:
        infos = socket.getaddrinfo(clean, None)
        ips = list(dict.fromkeys(info[4][0] for info in infos if info[4]))
        return ips if ips else [clean]
    except Exception:
        return [clean]


def parse_network_or_ip(entry: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address, str]:
    """Parse string as IP network, IP address, or raw string."""
    entry = entry.strip()
    try:
        if "/" in entry:
            return ipaddress.ip_network(entry, strict=False)
        return ipaddress.ip_address(entry)
    except ValueError:
        return entry


def is_ip_in_entry(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], entry: str) -> bool:
    """Check if an IP address matches an entry (IP or CIDR or hostname)."""
    parsed = parse_network_or_ip(entry)
    if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return ip_obj in parsed
    if isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_obj == parsed
    if isinstance(parsed, str):
        if parsed.lower() == "localhost" and ip_obj.is_loopback:
            return True
        for resolved in resolve_host_to_ips(parsed):
            try:
                if ipaddress.ip_address(resolved) == ip_obj:
                    return True
            except ValueError:
                pass
    return False


def is_public_target(target: str) -> bool:
    """Determine if a target (IP, CIDR, hostname) is a public address."""
    clean = target.strip()
    if "/" in clean:
        try:
            net = ipaddress.ip_network(clean, strict=False)
            return not (net.is_loopback or net.is_private or net.is_link_local)
        except ValueError:
            pass

    try:
        ip = ipaddress.ip_address(clean)
        return not (ip.is_loopback or ip.is_private or ip.is_link_local)
    except ValueError:
        # Hostname - check resolved IPs
        ips = resolve_host_to_ips(clean)
        for resolved in ips:
            try:
                ip = ipaddress.ip_address(resolved)
                if not (ip.is_loopback or ip.is_private or ip.is_link_local):
                    return True
            except ValueError:
                return True
        return False


def expand_cidr(cidr: str, max_hosts: int = 1024) -> List[str]:
    """Expand a CIDR network into a list of host IP strings."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if not hosts:
            hosts = [str(net.network_address)]
        if len(hosts) > max_hosts:
            raise ValueError(f"CIDR {cidr} contains {len(hosts)} hosts, exceeding maximum allowed {max_hosts}")
        return hosts
    except ValueError as e:
        if "exceeding maximum" in str(e):
            raise
        return [cidr]


def validate_and_expand_targets(
    target_entries: List[str],
    scope: Optional[ScopeConfig] = None,
    confirm_authorized: bool = False
) -> List[str]:
    """
    Validate target list against safety principles and expand CIDR ranges.
    Refuses public targets without authorized_by and confirm_authorized=True.
    Filters out excluded targets.
    """
    combined_targets: List[str] = list(target_entries)
    excluded_entries: List[str] = []

    if scope:
        if not combined_targets and scope.targets:
            combined_targets = list(scope.targets)
        if scope.excluded:
            excluded_entries.extend(scope.excluded)

    if not combined_targets:
        raise ScopeRefusalError("No targets specified to scan.", exit_code=2)

    has_auth_by = bool(scope and scope.authorized_by.strip())

    expanded_targets: List[str] = []
    for entry in combined_targets:
        clean = entry.strip()
        if not clean:
            continue

        # Check public status
        if is_public_target(clean):
            if not has_auth_by:
                raise ScopeRefusalError(
                    f"Refusal: Public target '{clean}' requires a scope file with an 'authorized_by' field.",
                    exit_code=2
                )
            if not confirm_authorized:
                raise ScopeRefusalError(
                    f"Refusal: Public target '{clean}' authorized by '{scope.authorized_by}' requires '--confirm-authorized' flag.",
                    exit_code=2
                )

        if "/" in clean:
            expanded = expand_cidr(clean)
            expanded_targets.extend(expanded)
        else:
            expanded_targets.append(clean)

    # Filter out excluded targets
    final_targets: List[str] = []
    for t in expanded_targets:
        is_excluded = False
        t_clean = t.strip()
        try:
            t_ip = ipaddress.ip_address(t_clean)
            for ex in excluded_entries:
                if is_ip_in_entry(t_ip, ex):
                    is_excluded = True
                    break
        except ValueError:
            # Match string directly
            for ex in excluded_entries:
                if t_clean.lower() == ex.strip().lower():
                    is_excluded = True
                    break
        if not is_excluded:
            final_targets.append(t)

    # Deduplicate while preserving order
    unique_targets = list(dict.fromkeys(final_targets))
    return unique_targets

