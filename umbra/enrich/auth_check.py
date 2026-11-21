"""Authentication state evaluation: none, required, unknown."""

from typing import Optional
import httpx


async def check_auth_state(
    host: str,
    port: Optional[int],
    auth_check_path: Optional[str],
    tls: bool = False,
    timeout: float = 3.0,
    client: Optional[httpx.AsyncClient] = None
) -> str:
    """
    Perform read-only unauthenticated request to auth_check_path.
    200 -> 'none' (authentication is not enforced)
    401, 403 -> 'required' (authentication is enforced)
    Timeout or other error -> 'unknown'
    """
    if not auth_check_path:
        return "unknown"

    port_str = f":{port}" if port else ""
    scheme = "https" if tls else "http"
    target_url = f"{scheme}://{host}{port_str}{auth_check_path}"

    try:
        if client is not None:
            resp = await client.get(target_url)
            if resp.status_code == 200:
                return "none"
            elif resp.status_code in (401, 403):
                return "required"
            return "unknown"

        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as local_client:
            resp = await local_client.get(target_url)
            if resp.status_code == 200:
                return "none"
            elif resp.status_code in (401, 403):
                return "required"
            return "unknown"
    except Exception:
        return "unknown"

