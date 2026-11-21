"""Docker container discovery for AI workloads."""

import json
import shutil
import subprocess
from typing import Any, Dict, List

from umbra.core.models import Finding
from umbra.enrich.bind_scope import classify_bind_scope

KNOWN_CONTAINER_IMAGES = {
    "ollama/ollama": ("ollama", "inference", 11434),
    "vllm/vllm-openai": ("vllm", "inference", 8000),
    "ghcr.io/open-webui/open-webui": ("open-webui", "chat-ui", 8080),
    "mintplexlabs/anythingllm": ("anythingllm", "chat-ui", 3001),
    "chromadb/chroma": ("chromadb", "vector-db", 8000),
    "qdrant/qdrant": ("qdrant", "vector-db", 6333),
    "semitechnologies/weaviate": ("weaviate", "vector-db", 8080),
    "milvusdb/milvus": ("milvus", "vector-db", 19530),
    "zilliztech/attu": ("milvus-attu", "vector-db", 3000),
    "flowiseai/flowise": ("flowise", "agent-platform", 3000),
    "langflowai/langflow": ("langflow", "agent-platform", 7860),
    "n8nio/n8n": ("n8n", "agent-platform", 5678),
    "localai/localai": ("llama-cpp", "inference", 8080),
}


def discover_containers(run_id: str = "local") -> List[Finding]:
    """
    Run 'docker ps --format json' to detect running AI containers.
    Gracefully skips if Docker is absent or inactive.
    """
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return []

    try:
        proc = subprocess.run(
            [docker_bin, "ps", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if proc.returncode != 0:
            return []
    except Exception:
        return []

    findings: List[Finding] = []
    lines = proc.stdout.strip().splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            container_info = json.loads(line)
        except Exception:
            continue

        image_name = container_info.get("Image", "").lower()
        matched_service = None
        category = "inference"
        default_port = None

        for known_image, (s_name, cat, port) in KNOWN_CONTAINER_IMAGES.items():
            if known_image in image_name:
                matched_service = s_name
                category = cat
                default_port = port
                break

        if not matched_service:
            # Check container names
            c_names = container_info.get("Names", "").lower()
            for known_image, (s_name, cat, port) in KNOWN_CONTAINER_IMAGES.items():
                short_name = known_image.split("/")[-1]
                if short_name in c_names:
                    matched_service = s_name
                    category = cat
                    default_port = port
                    break

        if matched_service:
            ports_str = container_info.get("Ports", "")
            bind_scope = "loopback"
            if "0.0.0.0" in ports_str or ":::" in ports_str:
                bind_scope = "lan"

            finding = Finding.create(
                run_id=run_id,
                host="127.0.0.1",
                port=default_port,
                service=matched_service,
                category=category,
                source="container",
                bind_scope=bind_scope,
                auth_state="unknown",
                approval="unapproved",
                models_or_tools=[f"Container: {container_info.get('Names', 'unknown')} ({image_name})"],
                risk_factors=[f"Discovered active Docker container running {matched_service} ({image_name})"],
                remediation=[f"Inspect container configuration for {matched_service}. Restrict exposed ports to 127.0.0.1."]
            )
            findings.append(finding)

    return findings

