"""Configuration defaults and loader for CognoSieve Umbra."""

from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import yaml

DEFAULT_AI_PORTS: Dict[int, str] = {
    11434: "Ollama",
    8000: "vLLM / ChromaDB",
    3000: "Open WebUI / Flowise",
    3001: "AnythingLLM",
    3080: "LibreChat",
    4000: "LiteLLM",
    1234: "LM Studio",
    8080: "llama.cpp / LocalAI / Weaviate",
    7860: "Langflow / Gradio",
    6333: "Qdrant",
    19530: "Milvus",
    5678: "n8n",
    8188: "ComfyUI"
}

WIDE_AI_PORTS: Dict[int, str] = {
    **DEFAULT_AI_PORTS,
    8001: "Triton Inference Server HTTP",
    8002: "Triton Inference Server Metrics",
    8501: "Streamlit",
    5000: "MLflow / Flask AI API",
    9000: "MinIO / S3 Store",
    8081: "LocalAI alt",
    8088: "Dify API",
    8090: "Dify Web",
    18080: "Xinference",
    2379: "etcd (Milvus dependency)",
    9090: "Prometheus AI metrics",
    1337: "Local API alt",
}


class UmbraConfig(BaseModel):
    """Runtime configuration for Umbra."""
    concurrency: int = 50
    timeout: float = 3.0
    ports: str = "default"  # 'default' or 'wide' or comma-separated
    reports_dir: str = "reports"
    formats: List[str] = Field(default_factory=lambda: ["md", "html", "json", "csv"])
    fail_on: Optional[str] = None  # low | medium | high | critical
    db_path: str = "umbra.db"
    include_experimental: bool = False
    ai_summary: bool = True
    gemini_api_key: Optional[str] = None
    max_response_bytes: int = 65536  # 64 KB hard cap


def load_config(path: Optional[Path] = None) -> UmbraConfig:
    """Load config from umbra.yaml or return defaults."""
    if path and path.exists():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return UmbraConfig(**data)

    default_file = Path("umbra.yaml")
    if default_file.exists():
        with open(default_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return UmbraConfig(**data)

    return UmbraConfig()


def get_api_key(name: str = "GEMINI_API_KEY") -> Optional[str]:
    """
    Centralized resolver for API keys across environment, .env file, and umbra.yaml.
    Resolves in priority order:
      1. os.environ[name]
      2. .env file in project root
      3. umbra.yaml config
    """
    import os
    val = os.environ.get(name)
    if val:
        return val.strip()

    if name == "GEMINI_API_KEY":
        alt = os.environ.get("GOOGLE_API_KEY")
        if alt:
            return alt.strip()

    env_file = Path(".env")
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k == name or (name == "GEMINI_API_KEY" and k == "GOOGLE_API_KEY"):
                    if v:
                        return v
        except Exception:
            pass

    cfg = load_config()
    if name == "GEMINI_API_KEY" and cfg.gemini_api_key:
        return cfg.gemini_api_key.strip()

    return None


def get_port_list(ports_spec: Optional[str]) -> List[int]:
    """Parse port specifier ('default', 'wide', or comma-separated list)."""
    if not ports_spec or ports_spec.strip().lower() == "default":
        return list(DEFAULT_AI_PORTS.keys())
    if ports_spec.strip().lower() == "wide":
        return list(WIDE_AI_PORTS.keys())

    ports: List[int] = []
    for part in ports_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            ports.extend(range(int(start_s), int(end_s) + 1))
        else:
            ports.append(int(part))
    return list(dict.fromkeys(ports))

