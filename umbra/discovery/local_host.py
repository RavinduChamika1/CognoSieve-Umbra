"""Host-local listener inspection, process matching, and local model store discovery."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import psutil

from umbra.core.models import Finding
from umbra.core.redact import redact_command_line
from umbra.enrich.bind_scope import classify_bind_scope

KNOWN_AI_PROCESS_NAMES = {
    "ollama": "ollama",
    "ollama_llama_server": "ollama",
    "llama-server": "llama-cpp",
    "vllm": "vllm",
    "weaviate": "weaviate",
    "qdrant": "qdrant",
    "milvus": "milvus",
    "attu": "milvus-attu",
    "lm-studio": "lm-studio",
    "anythingllm": "anythingllm",
}


def discover_listening_sockets() -> List[Dict[str, Any]]:
    """
    Inspect local listening inet sockets via psutil.
    Records address, port, pid, process name, and redacted command line.
    """
    listeners = []
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return listeners

    for conn in connections:
        if conn.status != "LISTEN":
            continue

        laddr = conn.laddr
        if not laddr:
            continue

        host = laddr.ip
        port = laddr.port
        pid = conn.pid
        proc_name = ""
        cmdline = []

        if pid:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                cmdline = proc.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        redacted_cmd = redact_command_line(cmdline)
        inferred_service = None
        for known_name, s_name in KNOWN_AI_PROCESS_NAMES.items():
            if known_name in proc_name.lower() or any(known_name in str(arg).lower() for arg in cmdline):
                inferred_service = s_name
                break

        listeners.append({
            "host": host,
            "port": port,
            "pid": pid,
            "process_name": proc_name,
            "command_line": redacted_cmd,
            "inferred_service": inferred_service,
            "bind_scope": classify_bind_scope(bind_addr=host)
        })

    return listeners


def get_dir_size_safe(path: Path) -> int:
    """Calculate directory size in bytes without failing on locked files."""
    total = 0
    try:
        for entry in os.scandir(path):
            try:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += get_dir_size_safe(Path(entry.path))
            except Exception:
                continue
    except Exception:
        pass
    return total


def discover_model_stores(run_id: str = "local") -> List[Finding]:
    """
    Detect local model storage directories (Ollama models, Hugging Face cache, LM Studio).
    Records directory path and size only; never reads weights or private contents.
    """
    findings = []
    home = Path.home()

    stores = [
        ("ollama-model-store", home / ".ollama" / "models", "local-model-store"),
        ("huggingface-cache", home / ".cache" / "huggingface" / "hub", "local-model-store"),
        ("lm-studio-models", home / ".cache" / "lm-studio" / "models", "local-model-store"),
    ]

    for service_name, store_path, category in stores:
        if store_path.exists() and store_path.is_dir():
            size_bytes = get_dir_size_safe(store_path)
            size_mb = round(size_bytes / (1024 * 1024), 2)
            f = Finding.create(
                run_id=run_id,
                host="127.0.0.1",
                port=None,
                service=service_name,
                category=category,
                source="local-process",
                bind_scope="loopback",
                auth_state="none",
                approval="unapproved",
                models_or_tools=[f"Directory: {store_path.as_posix()} ({size_mb} MB)"],
                risk_factors=[f"Local model store detected on disk: {size_mb} MB weights"],
                remediation=[f"Audit local AI model store at {store_path.as_posix()} for compliance with corporate data policy."]
            )
            findings.append(f)

    return findings

