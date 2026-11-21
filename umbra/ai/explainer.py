"""Defensive AI narrative summarizer using Gemini."""

import os
from typing import Any, Dict, List, Optional
from umbra.core.config import get_api_key
from umbra.core.models import Finding
from umbra.core.redact import redact_structure


def generate_ai_summary(
    findings: List[Finding],
    run_meta: Dict[str, Any],
    enabled: bool = True
) -> Optional[str]:
    """
    Generate an optional executive defensive security narrative using Gemini.
    Passes only minimized, redacted findings.
    If API key is missing or call fails, returns None without blocking.
    """
    if not enabled:
        return None

    # Never make external LLM calls during automated unit/integration tests
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return None

    api_key = get_api_key("GEMINI_API_KEY")
    if not api_key:
        return None

    # Minimize findings: service, severity, factors, remediation only
    minimized_findings = []
    for f in findings:
        minimized_findings.append({
            "service": f.service,
            "target": f"{f.host}:{f.port}" if f.port else f.host,
            "category": f.category,
            "approval": f.approval,
            "severity": f.severity,
            "score": f.risk_score,
            "risk_factors": f.risk_factors,
            "remediation": f.remediation[:2]
        })

    prompt_payload = {
        "context": "You are a defensive security reviewer summarizing an authorized shadow AI discovery scan of the operator's own environment.",
        "goal": "Provide a concise 1-2 paragraph executive narrative summarizing the shadow AI posture, the highest-risk exposure, and the most urgent fix.",
        "findings": redact_structure(minimized_findings)
    }

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        candidate_models = ["gemini-2.5-flash", "gemini-3.8-flash", "gemini-3.5-flash", "gemini-3.1-flash-lite"]
        for model_name in candidate_models:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=str(prompt_payload),
                )
                if response and response.text:
                    return response.text.strip()
            except Exception:
                continue
    except Exception:
        # Graceful fallback: return None without breaking report generation
        return None

    return None

