"""Credential detection and redaction utilities for data minimization."""

import re
from typing import Any, Union

PATTERNS = [
    # Authorization header tokens
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/=]{10,}", re.IGNORECASE), r"\1[REDACTED_BASIC_AUTH]"),
    # OpenAI & Anthropic keys
    (re.compile(r"sk-[a-zA-Z0-9_\-]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"sk-proj-[a-zA-Z0-9_\-]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"sk-ant-[a-zA-Z0-9_\-]{16,}"), "[REDACTED_API_KEY]"),
    # AWS Access Keys
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # Private Key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Generic key/secret assignments (json/yaml/env/cli)
    (
        re.compile(
            r"""(?i)\b(api[_-]?key|secret|token|password|passwd|auth[_-]?token|access[_-]?token|client[_-]?secret)\b(\s*[:=]\s*["']?)([^\s"',;&]{6,})(["']?)"""
        ),
        r"\1\2[REDACTED_CREDENTIAL]\4"
    ),
    # Common CLI flags with secrets e.g. --api-key <secret>
    (
        re.compile(
            r"""(?i)(--(?:api[-_]?key|secret|token|password|auth[-_]?token))\s+([^\s"';]+)"""
        ),
        r"\1 [REDACTED_CREDENTIAL]"
    ),
]

# Quick detector for credential-like presence
CREDENTIAL_INDICATOR_REGEXES = [
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9_\-]{16,}"),
    re.compile(r"sk-proj-[a-zA-Z0-9_\-]{16,}"),
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"""(?i)\b(api[_-]?key|secret|token|password|auth[_-]?token)\b\s*[:=]\s*["']?[A-Za-z0-9_\-\.]{6,}"""),
]


def detect_credentials(text: Union[str, bytes, None]) -> bool:
    """Return True if any credential-like pattern is detected in text."""
    if not text:
        return False
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    for pattern in CREDENTIAL_INDICATOR_REGEXES:
        if pattern.search(text):
            return True
    return False


def redact_text(text: Union[str, bytes, None]) -> str:
    """Redact sensitive credential tokens from string/bytes."""
    if text is None:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    redacted = text
    for pattern, replacement in PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_command_line(cmdline: Union[list[str], str, None]) -> Union[list[str], str]:
    """Redact secrets from a process command line."""
    if cmdline is None:
        return ""
    if isinstance(cmdline, list):
        joined = " ".join(cmdline)
        redacted = redact_text(joined)
        return redacted.split()
    return redact_text(str(cmdline))


def redact_structure(data: Any) -> Any:
    """Recursively redact strings in dicts, lists, and primitives."""
    if isinstance(data, str):
        return redact_text(data)
    elif isinstance(data, bytes):
        return redact_text(data)
    elif isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ["api_key", "secret", "password", "token", "auth"]):
                if isinstance(v, (str, bytes)):
                    new_dict[k] = "[REDACTED_CREDENTIAL]"
                    continue
            new_dict[k] = redact_structure(v)
        return new_dict
    elif isinstance(data, list):
        return [redact_structure(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(redact_structure(item) for item in data)
    return data
