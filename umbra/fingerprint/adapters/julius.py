"""Adapter for ingesting Praetorian Julius probe JSON output."""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from umbra.core.models import Finding
from umbra.enrich.bind_scope import classify_bind_scope


def parse_julius_output(content: Union[str, Path, Dict[str, Any], List[Dict[str, Any]]], run_id: str = "import") -> List[Finding]:
    """Parse 'julius probe' JSON results into Umbra Findings."""
    if isinstance(content, (str, Path)):
        p = Path(content)
        if p.exists() and p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(str(content))
    else:
        data = content

    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("results") or data.get("findings") or data.get("targets") or [data]

    findings: List[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        host = item.get("host") or item.get("ip") or item.get("target") or "127.0.0.1"
        port_raw = item.get("port")
        port = int(port_raw) if port_raw is not None else None
        service = item.get("service") or item.get("name") or item.get("component") or "unknown-ai"
        version = item.get("version")
        models = item.get("models") or []
        if isinstance(models, str):
            models = [models]

        category = item.get("category", "inference")
        bind_scope = classify_bind_scope(target_host=host)

        finding = Finding.create(
            run_id=run_id,
            host=host,
            port=port,
            service=service,
            version=version,
            category=category,
            source="import",
            bind_scope=bind_scope,
            auth_state="unknown",
            approval="unknown",
            models_or_tools=[str(m) for m in models],
            risk_factors=[f"Imported from Julius probe: {service} at {host}:{port}"],
            remediation=[f"Verify Julius discovery for {service}. Inspect network exposure."]
        )
        findings.append(finding)

    return findings

