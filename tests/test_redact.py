"""Tests for credential detection and redaction."""

from umbra.core.redact import (
    detect_credentials,
    redact_text,
    redact_command_line,
    redact_structure,
)


def test_detect_credentials():
    assert detect_credentials("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") is True
    assert detect_credentials("Authorization: Bearer sk-ant-api03-1234567890abcdef") is True
    assert detect_credentials("sk-proj-abcde1234567890xyz") is True
    assert detect_credentials("AKIAIOSFODNN7EXAMPLE") is True
    assert detect_credentials("api_key: secret_token_value_here") is True
    assert detect_credentials("Normal safe text with no tokens") is False
    assert detect_credentials("") is False
    assert detect_credentials(None) is False


def test_redact_text():
    raw = "Header Bearer supersecrettokenvalue123 and sk-proj-1234567890abcdef"
    redacted = redact_text(raw)
    assert "supersecrettokenvalue123" not in redacted
    assert "sk-proj-1234567890abcdef" not in redacted
    assert "[REDACTED_BEARER_TOKEN]" in redacted or "[REDACTED_API_KEY]" in redacted


def test_redact_command_line():
    cmd = ["ollama", "serve", "--api-key", "secret123456"]
    redacted_cmd = redact_command_line(cmd)
    redacted_str = " ".join(redacted_cmd)
    assert "secret123456" not in redacted_str
    assert "[REDACTED_CREDENTIAL]" in redacted_str


def test_redact_structure():
    data = {
        "service": "ollama",
        "env": {
            "OLLAMA_API_KEY": "sk-1234567890abcdef",
            "HOST": "127.0.0.1"
        },
        "tags": ["model1", "Bearer mysecrettoken123"]
    }
    redacted = redact_structure(data)
    assert "sk-1234567890abcdef" not in str(redacted)
    assert "mysecrettoken123" not in str(redacted)
    assert redacted["env"]["HOST"] == "127.0.0.1"

