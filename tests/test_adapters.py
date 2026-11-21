"""Tests for Julius and AIMap import adapters."""

from pathlib import Path
from umbra.fingerprint.adapters.julius import parse_julius_output
from umbra.fingerprint.adapters.aimap import parse_aimap_output


def test_julius_adapter_parsing():
    sample_julius = {
        "results": [
            {
                "host": "192.168.1.50",
                "port": 11434,
                "service": "ollama",
                "version": "0.1.30",
                "models": ["llama3:latest", "mistral:7b"]
            }
        ]
    }
    findings = parse_julius_output(sample_julius, run_id="julius_test")
    assert len(findings) == 1
    f = findings[0]
    assert f.service == "ollama"
    assert f.host == "192.168.1.50"
    assert f.port == 11434
    assert f.source == "import"
    assert "llama3:latest" in f.models_or_tools


def test_aimap_adapter_parsing():
    sample_aimap = {
        "services": [
            {
                "ip": "10.0.0.15",
                "port": 8000,
                "name": "vllm",
                "version": "0.4.1",
                "models": ["meta-llama-3"]
            }
        ]
    }
    findings = parse_aimap_output(sample_aimap, run_id="aimap_test")
    assert len(findings) == 1
    f = findings[0]
    assert f.service == "vllm"
    assert f.host == "10.0.0.15"
    assert f.port == 8000
    assert f.source == "import"
    assert "meta-llama-3" in f.models_or_tools

