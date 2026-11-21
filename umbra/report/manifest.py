"""SHA-256 integrity manifest creation and verification."""

import hashlib
from pathlib import Path
from typing import Dict, Tuple


def calculate_file_sha256(file_path: Path) -> str:
    """Calculate the hex SHA-256 digest of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def create_manifest(folder_path: Path) -> Path:
    """
    Calculate SHA-256 digest of every file in the folder (recursively)
    and write manifest.sha256 in standard format: '<hash>  <relative_path>'.
    """
    folder = Path(folder_path)
    manifest_file = folder / "manifest.sha256"

    lines = []
    for item in sorted(folder.rglob("*")):
        if item.is_file() and item.name != "manifest.sha256":
            rel_path = item.relative_to(folder).as_posix()
            digest = calculate_file_sha256(item)
            lines.append(f"{digest}  {rel_path}")

    with open(manifest_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

    return manifest_file


def verify_manifest(folder_path: Path) -> Tuple[bool, Dict[str, str]]:
    """
    Verify all files in manifest.sha256 match their digests.
    Returns (all_valid, failure_reasons).
    """
    folder = Path(folder_path)
    manifest_file = folder / "manifest.sha256"
    if not manifest_file.exists():
        return False, {"manifest": "manifest.sha256 missing"}

    failures: Dict[str, str] = {}
    with open(manifest_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            expected_hash, rel_path = parts[0].strip(), parts[1].strip()
            file_path = folder / rel_path
            if not file_path.exists():
                failures[rel_path] = "file missing"
                continue
            actual_hash = calculate_file_sha256(file_path)
            if actual_hash.lower() != expected_hash.lower():
                failures[rel_path] = f"digest mismatch (expected {expected_hash}, got {actual_hash})"

    return (len(failures) == 0), failures

