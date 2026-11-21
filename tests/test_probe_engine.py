"""Tests for YAML probe engine, match rules, specificity, and fixtures."""

from pathlib import Path
import pytest
import httpx

from umbra.fingerprint.engine import (
    load_probe_pack,
    fingerprint_endpoint,
)


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "responses"


@pytest.mark.asyncio
async def test_ollama_probe_matching(fixtures_dir: Path):
    ollama_root = (fixtures_dir / "ollama_root.txt").read_bytes()
    ollama_tags = (fixtures_dir / "ollama_tags.json").read_bytes()
    ollama_version = (fixtures_dir / "ollama_version.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=ollama_root)
        elif path == "/api/tags":
            return httpx.Response(200, content=ollama_tags)
        elif path == "/api/version":
            return httpx.Response(200, content=ollama_version)
        return httpx.Response(404, text="Not found")

    probes = load_probe_pack()
    assert len(probes) >= 15

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fingerprint_endpoint("127.0.0.1", 11434, probes, client=client)
        assert result is not None
        assert result["service"] == "ollama"
        assert result["category"] == "inference"
        assert "llama3:latest" in result["models_or_tools"]
        assert result["version"] == "0.1.32"


@pytest.mark.asyncio
async def test_vllm_probe_matching(fixtures_dir: Path):
    vllm_version = (fixtures_dir / "vllm_version.json").read_bytes()
    vllm_models = (fixtures_dir / "vllm_models.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, content=vllm_version)
        elif path == "/v1/models":
            return httpx.Response(200, content=vllm_models)
        return httpx.Response(404, text="Not found")

    probes = load_probe_pack()
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fingerprint_endpoint("127.0.0.1", 8000, probes, client=client)
        assert result is not None
        assert result["service"] == "vllm"
        assert "meta-llama/Meta-Llama-3-8B-Instruct" in result["models_or_tools"]
        assert result["version"] == "0.4.2"


@pytest.mark.asyncio
async def test_generic_openai_never_overrides_specific(fixtures_dir: Path):
    vllm_version = (fixtures_dir / "vllm_version.json").read_bytes()
    vllm_models = (fixtures_dir / "vllm_models.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, content=vllm_version)
        elif path == "/v1/models":
            return httpx.Response(200, content=vllm_models)
        return httpx.Response(404, text="Not found")

    probes = load_probe_pack()
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fingerprint_endpoint("127.0.0.1", 8000, probes, client=client)
        assert result is not None
        # Must match vllm, NEVER generic-openai-compatible
        assert result["service"] == "vllm"


@pytest.mark.asyncio
async def test_generic_openai_matches_when_no_specific(fixtures_dir: Path):
    generic_models = (fixtures_dir / "generic_openai_models.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/models":
            return httpx.Response(200, content=generic_models)
        return httpx.Response(404, text="Not found")

    probes = load_probe_pack()
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fingerprint_endpoint("127.0.0.1", 9999, probes, client=client)
        assert result is not None
        assert result["service"] == "generic-openai-compatible"
        assert "gpt-4-custom" in result["models_or_tools"]


def test_all_probes_have_verify_notes():
    probes = load_probe_pack()
    for probe in probes:
        assert probe.verify_note != "", f"Probe {probe.name} is missing verify_note"
        assert probe.verify_note.startswith("http"), f"Probe {probe.name} verify_note should be a URL"
