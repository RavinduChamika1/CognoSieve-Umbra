"""Known vulnerability check against local database."""

from pathlib import Path
from typing import List, Optional
from packaging import version as pkg_version
import yaml


def load_known_issues(path: Optional[Path] = None) -> dict:
    if path is None:
        path = Path(__file__).parent / "known_issues.yaml"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def check_known_version_issues(
    service: str,
    version_str: Optional[str],
    known_issues: Optional[dict] = None
) -> List[str]:
    """
    Check if a service version is vulnerable to known critical issues.
    Returns list of issue descriptions. No network lookups.
    """
    if not version_str or not service:
        return []

    if known_issues is None:
        known_issues = load_known_issues()

    clean_service = service.strip().lower()
    if clean_service not in known_issues:
        return []

    # Clean version string (remove leading 'v' or 'b')
    clean_v = version_str.strip().lstrip("vV")
    try:
        parsed_v = pkg_version.parse(clean_v)
    except Exception:
        return []

    found_issues: List[str] = []
    for issue in known_issues[clean_service]:
        max_v_str = issue.get("max_version")
        if max_v_str:
            try:
                max_v = pkg_version.parse(max_v_str)
                if parsed_v < max_v:
                    cve = issue.get("cve", "VULN")
                    desc = issue.get("description", "Vulnerable version detected")
                    found_issues.append(f"{cve}: {desc}")
            except Exception:
                continue

    return found_issues

