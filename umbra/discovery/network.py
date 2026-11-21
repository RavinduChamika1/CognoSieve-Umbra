"""Asynchronous TCP connect network discovery."""

import asyncio
from typing import List, Tuple


async def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open using async socket connection."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False


async def scan_host_port(
    semaphore: asyncio.Semaphore,
    host: str,
    port: int,
    timeout: float
) -> Tuple[str, int, bool]:
    """Scan a single host and port with concurrency control."""
    async with semaphore:
        is_open = await check_port_open(host, port, timeout=timeout)
        return host, port, is_open


async def scan_targets(
    targets: List[str],
    ports: List[int],
    concurrency: int = 50,
    timeout: float = 2.0
) -> List[Tuple[str, int]]:
    """
    Perform an asynchronous TCP connect scan across a list of target IPs and ports.
    Returns a list of (host, port) tuples that are open.
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []

    for host in targets:
        for port in ports:
            tasks.append(scan_host_port(semaphore, host, port, timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_endpoints: List[Tuple[str, int]] = []
    for res in results:
        if isinstance(res, tuple):
            h, p, is_open = res
            if is_open:
                open_endpoints.append((h, p))

    return open_endpoints

