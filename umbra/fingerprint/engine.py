"""Fingerprint engine for declarative YAML probe packs."""

import re
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import httpx
from pydantic import BaseModel, Field
import yaml

from umbra.core.models import Finding
from umbra.core.redact import detect_credentials, redact_text


class RequestRule(BaseModel):
    """Rule defining a single HTTP probe request and its match conditions."""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Union[str, Dict[str, Any]]] = None
    match_all: List[Dict[str, Any]] = Field(default_factory=list)
    match_any: List[Dict[str, Any]] = Field(default_factory=list)
    extract: Dict[str, str] = Field(default_factory=dict)


class ProbeDefinition(BaseModel):
    """Complete service probe definition loaded from YAML."""
    name: str
    category: str = "inference"
    default_ports: List[int] = Field(default_factory=list)
    requests: List[RequestRule] = Field(default_factory=list)
    auth_check_path: Optional[str] = None
    capability_flags: List[str] = Field(default_factory=list)
    specificity: int = 50
    status: str = "active"  # "active" or "experimental"
    verify_note: str = ""


def get_json_path_value(data: Any, path: str) -> Tuple[bool, Any]:
    """
    Simple JSON path resolver supporting dot notation and list unrolling e.g.
    'version' -> data['version']
    'models[].name' -> [m['name'] for m in data['models']]
    'data[].id' -> [item['id'] for item in data['data']]
    """
    if not isinstance(data, (dict, list)):
        return False, None

    parts = path.split(".")
    current = data

    for i, part in enumerate(parts):
        if "[]" in part:
            key = part.replace("[]", "")
            if not isinstance(current, dict) or key not in current:
                return False, None
            items = current[key]
            if not isinstance(items, list):
                return False, None
            sub_path = ".".join(parts[i+1:])
            if not sub_path:
                return True, items
            results = []
            for item in items:
                ok, val = get_json_path_value(item, sub_path)
                if ok:
                    results.append(val)
            return True, results
        else:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return False, None

    return True, current


def evaluate_match_condition(condition: Dict[str, Any], response: httpx.Response, text_body: str) -> bool:
    """Evaluate a single match rule condition against an HTTP response."""
    # 1. status
    if "status" in condition:
        expected = condition["status"]
        if isinstance(expected, list):
            if response.status_code not in expected:
                return False
        elif response.status_code != expected:
            return False

    # 2. header_contains
    if "header_contains" in condition:
        for header_name, expected_val in condition["header_contains"].items():
            found_val = response.headers.get(header_name, "")
            if expected_val.lower() not in found_val.lower():
                return False

    # 3. body_contains
    if "body_contains" in condition:
        expected_text = condition["body_contains"]
        if expected_text.lower() not in text_body.lower():
            return False

    # 4. html_title_contains
    if "html_title_contains" in condition:
        expected_title = condition["html_title_contains"]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text_body, re.IGNORECASE | re.DOTALL)
        if not title_match or expected_title.lower() not in title_match.group(1).lower():
            return False

    # 5. json_path_exists
    if "json_path_exists" in condition:
        target_path = condition["json_path_exists"]
        try:
            data = response.json()
            exists, _ = get_json_path_value(data, target_path)
            if not exists:
                return False
        except Exception:
            return False

    # 6. json_path_equals
    if "json_path_equals" in condition:
        for target_path, expected_val in condition["json_path_equals"].items():
            try:
                data = response.json()
                exists, val = get_json_path_value(data, target_path)
                if not exists or val != expected_val:
                    return False
            except Exception:
                return False

    return True


def evaluate_request(
    rule: RequestRule,
    response: httpx.Response,
    max_response_bytes: int = 65536
) -> Tuple[bool, Dict[str, Any]]:
    """
    Evaluate if response matches the request rule.
    Returns (is_match, extracted_fields).
    """
    raw_content = response.content[:max_response_bytes]
    text_body = raw_content.decode("utf-8", errors="replace")

    # Evaluate match_all
    if rule.match_all:
        for cond in rule.match_all:
            if not evaluate_match_condition(cond, response, text_body):
                return False, {}

    # Evaluate match_any
    if rule.match_any:
        any_passed = False
        for cond in rule.match_any:
            if evaluate_match_condition(cond, response, text_body):
                any_passed = True
                break
        if not any_passed:
            return False, {}

    # If neither match_all nor match_any was defined, require status 200
    if not rule.match_all and not rule.match_any:
        if response.status_code != 200:
            return False, {}

    # Extract fields if matched
    extracted: Dict[str, Any] = {}
    if rule.extract:
        try:
            json_data = response.json()
        except Exception:
            json_data = None

        for field_name, json_path in rule.extract.items():
            if json_data is not None:
                exists, val = get_json_path_value(json_data, json_path)
                if exists:
                    extracted[field_name] = val
            elif field_name == "version":
                v_match = re.search(r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text_body)
                if v_match:
                    extracted["version"] = v_match.group(1)

    return True, extracted


def load_probe_pack(
    probes_dir: Optional[Path] = None,
    include_experimental: bool = False
) -> List[ProbeDefinition]:
    """Load all probe YAML files from directory and sort by specificity descending."""
    if probes_dir is None:
        probes_dir = Path(__file__).parent / "probes"

    probes: List[ProbeDefinition] = []
    if not probes_dir.exists():
        return probes

    for yaml_file in probes_dir.glob("*.yaml"):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if not data or not isinstance(data, dict):
                    continue
                probe = ProbeDefinition(**data)
                if probe.status == "experimental" and not include_experimental:
                    continue
                probes.append(probe)
        except Exception:
            continue

    probes.sort(key=lambda p: p.specificity, reverse=True)
    return probes


async def execute_probe(
    client: httpx.AsyncClient,
    base_url: str,
    probe: ProbeDefinition,
    max_response_bytes: int = 65536
) -> Optional[Dict[str, Any]]:
    """Execute requests declared in probe definition against base_url."""
    if not probe.requests:
        return None

    first_req = probe.requests[0]
    first_url = f"{base_url.rstrip('/')}{first_req.path}"

    try:
        resp = await client.request(
            first_req.method,
            first_url,
            headers=first_req.headers,
            json=first_req.body if isinstance(first_req.body, dict) else None,
            content=first_req.body if isinstance(first_req.body, str) else None,
        )
    except Exception:
        return None

    matched, extracted = evaluate_request(first_req, resp, max_response_bytes)
    if not matched:
        return None

    raw_snippet = resp.content[:1024].decode("utf-8", errors="replace")
    cred_seen = detect_credentials(resp.content[:max_response_bytes])
    clean_snippet = redact_text(raw_snippet)

    models_or_tools: List[str] = []
    version_found = extracted.get("version")
    if "models_or_tools" in extracted:
        val = extracted["models_or_tools"]
        if isinstance(val, list):
            models_or_tools.extend([str(item) for item in val if item])
        elif isinstance(val, str):
            models_or_tools.append(val)

    for secondary_req in probe.requests[1:]:
        sec_url = f"{base_url.rstrip('/')}{secondary_req.path}"
        try:
            sec_resp = await client.request(
                secondary_req.method,
                sec_url,
                headers=secondary_req.headers,
            )
            sec_matched, sec_extracted = evaluate_request(secondary_req, sec_resp, max_response_bytes)
            if sec_matched:
                if "version" in sec_extracted and not version_found:
                    version_found = sec_extracted["version"]
                if "models_or_tools" in sec_extracted:
                    m_val = sec_extracted["models_or_tools"]
                    if isinstance(m_val, list):
                        models_or_tools.extend([str(item) for item in m_val if item])
                    elif isinstance(m_val, str):
                        models_or_tools.append(m_val)
            if detect_credentials(sec_resp.content[:max_response_bytes]):
                cred_seen = True
        except Exception:
            pass

    return {
        "service": probe.name,
        "category": probe.category,
        "version": str(version_found) if version_found else None,
        "models_or_tools": list(dict.fromkeys(models_or_tools)),
        "capability_flags": probe.capability_flags,
        "auth_check_path": probe.auth_check_path,
        "credential_indicator": cred_seen,
        "raw_evidence": clean_snippet,
    }


async def fingerprint_endpoint(
    host: str,
    port: int,
    probes: List[ProbeDefinition],
    timeout: float = 3.0,
    tls: bool = False,
    max_response_bytes: int = 65536,
    client: Optional[httpx.AsyncClient] = None
) -> Optional[Dict[str, Any]]:
    """
    Run sorted probes against an endpoint (host, port).
    Returns the first (highest specificity) matched probe outcome.
    Generic probe will only match if no higher specificity probe matched.
    """
    scheme = "https" if tls else "http"
    base_url = f"{scheme}://{host}:{port}"

    prioritized_probes = sorted(
        probes,
        key=lambda p: (
            1 if (port in p.default_ports) else 0,
            p.specificity
        ),
        reverse=True
    )

    if client is not None:
        for probe in prioritized_probes:
            res = await execute_probe(client, base_url, probe, max_response_bytes=max_response_bytes)
            if res is not None:
                res["tls"] = tls
                return res
        return None

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as local_client:
        for probe in prioritized_probes:
            res = await execute_probe(local_client, base_url, probe, max_response_bytes=max_response_bytes)
            if res is not None:
                res["tls"] = tls
                return res

    return None
