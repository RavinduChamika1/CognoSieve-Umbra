"""Inventory matching logic: approved, unapproved, unknown."""

import ipaddress
from pathlib import Path
from typing import List, Optional, Tuple, Union
import yaml

from umbra.core.models import Finding, InventoryEntry
from umbra.core.scope import is_ip_in_entry


def load_inventory(path: Optional[Union[str, Path]] = None) -> List[InventoryEntry]:
    """Load inventory entries from approved.yaml."""
    if path is None:
        path = Path("approved.yaml")
        if not path.exists():
            path = Path(__file__).parent / "approved.yaml"

    p = Path(path)
    if not p.exists():
        return []

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return []

    entries: List[InventoryEntry] = []
    services_list = data.get("services", [])
    if isinstance(services_list, list):
        for item in services_list:
            if isinstance(item, dict) and "service" in item and "host_or_cidr" in item:
                entries.append(InventoryEntry(**item))

    return entries


def match_finding_to_inventory(
    finding: Finding,
    inventory: List[InventoryEntry]
) -> Tuple[str, Optional[str]]:
    """
    Match a finding against approved inventory.
    Returns (approval_status, owner).
    approval_status is 'approved', 'unapproved', or 'unknown'.
    """
    if not inventory:
        # Empty inventory means every discovered AI service is Shadow AI (unapproved)
        return "unapproved", None

    f_host = finding.host.strip()
    f_port = finding.port
    f_service = finding.service.strip().lower()

    try:
        f_ip = ipaddress.ip_address(f_host)
    except ValueError:
        f_ip = None

    for entry in inventory:
        e_service = entry.service.strip().lower()
        if e_service != "*" and e_service != f_service:
            continue

        # Check port
        if entry.port is not None and f_port is not None:
            if entry.port != f_port:
                continue

        # Check host or CIDR
        e_target = entry.host_or_cidr.strip()
        matched_host = False
        if e_target == "*":
            matched_host = True
        elif f_ip is not None:
            matched_host = is_ip_in_entry(f_ip, e_target)
        else:
            if f_host.lower() == e_target.lower():
                matched_host = True

        if matched_host:
            status = "approved" if entry.approved else "unapproved"
            return status, entry.owner

    # If inventory exists but this finding wasn't listed -> unapproved shadow AI
    return "unapproved", None


def init_approved_template(destination_path: Path) -> Path:
    """Create a new approved.yaml inventory template file."""
    dest = Path(destination_path)
    template_src = Path(__file__).parent / "approved.yaml"
    if template_src.exists():
        dest.write_text(template_src.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        dest.write_text(
            """# Approved AI Service Allowlist
services:
  - service: ollama
    host_or_cidr: 127.0.0.1
    port: 11434
    owner: "Engineering"
    approved: true
""",
            encoding="utf-8"
        )
    return dest


def add_inventory_entry(path: Union[str, Path], entry: InventoryEntry) -> Path:
    """Add or update an entry in the inventory file."""
    p = Path(path)
    if not p.exists():
        data = {"services": []}
    else:
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            data = {"services": []}
        if not isinstance(data, dict) or "services" not in data or not isinstance(data["services"], list):
            data = {"services": []}

    entry_clean = {
        "service": entry.service,
        "host_or_cidr": entry.host_or_cidr,
        "port": entry.port,
        "owner": entry.owner,
        "approved": entry.approved,
        "purpose": entry.purpose,
        "ticket_or_doc": entry.ticket_or_doc
    }
    entry_clean = {k: v for k, v in entry_clean.items() if v is not None}

    updated = False
    for i, existing in enumerate(data["services"]):
        if isinstance(existing, dict):
            if (existing.get("service", "").lower() == entry.service.lower() and
                str(existing.get("host_or_cidr", "")).lower() == str(entry.host_or_cidr).lower() and
                existing.get("port") == entry.port):
                data["services"][i] = entry_clean
                updated = True
                break

    if not updated:
        data["services"].append(entry_clean)

    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)

    return p


