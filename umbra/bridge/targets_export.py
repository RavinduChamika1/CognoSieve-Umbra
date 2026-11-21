"""Convert approved and owned findings into target configurations for CognoSievePromptinj."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from umbra.core.models import Finding
from umbra.core.scope import is_loopback


def export_promptinj_targets(
    findings: List[Finding],
    output_file: Optional[Path] = None,
    default_owner: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
    """
    Export targets for CognoSievePromptinj.
    Enforces strict safety guard: ONLY findings with approval == 'approved'
    AND owner set (or default_owner from scope) are exported.
    Returns (exported_targets, skipped_reasons).
    """
    exported: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, str]] = []

    for f in findings:
        # Check approval
        if f.approval != "approved":
            skipped.append((f.id, f"Finding '{f.service}' at {f.host}:{f.port} is not approved (status: {f.approval})"))
            continue

        # Check ownership
        effective_owner = f.owner or default_owner
        if not effective_owner:
            skipped.append((f.id, f"Finding '{f.service}' at {f.host}:{f.port} has no designated owner"))
            continue

        # Map target type
        service_lower = f.service.lower()
        target_entry: Dict[str, Any] = {
            "name": f"{f.service}_{f.host}_{f.port or 'local'}",
            "asset_id": f.id,
            "service": f.service,
            "owner": effective_owner,
            "approval": f.approval,
            "host": f.host,
            "port": f.port,
            "models": f.models_or_tools,
        }

        if "ollama" in service_lower:
            if is_loopback(f.host):
                target_entry["target_type"] = "ollama_local"
                target_entry["endpoint"] = f"http://{f.host}:{f.port or 11434}"
            else:
                target_entry["target_type"] = "ollama_remote"
                target_entry["endpoint"] = f"http://{f.host}:{f.port or 11434}"
        elif any(s in service_lower for s in ["vllm", "openai", "lm-studio", "litellm", "llama-cpp"]):
            target_entry["target_type"] = "custom_http_endpoint"
            scheme = "https" if f.tls else "http"
            target_entry["endpoint"] = f"{scheme}://{f.host}:{f.port or 8000}/v1/chat/completions"
            target_entry["request_format"] = {
                "model": f.models_or_tools[0] if f.models_or_tools else "default",
                "messages": "[{\"role\": \"user\", \"content\": \"{{prompt}}\"}]"
            }
        else:
            target_entry["target_type"] = "custom_http_endpoint"
            scheme = "https" if f.tls else "http"
            target_entry["endpoint"] = f"{scheme}://{f.host}:{f.port or 80}"

        exported.append(target_entry)

    if output_file is not None:
        out_p = Path(output_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(exported, f, indent=2)

    return exported, skipped

