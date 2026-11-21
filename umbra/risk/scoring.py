"""Deterministic risk scoring, severity calculation, remediation, and framework mapping."""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import yaml

from umbra.core.models import Finding, RiskRubric


def load_rubric(path: Optional[Union[str, Path]] = None) -> RiskRubric:
    """Load scoring rubric from rubric.yaml."""
    if path is None:
        path = Path("rubric.yaml")
        if not path.exists():
            path = Path(__file__).parent / "rubric.yaml"

    p = Path(path)
    if not p.exists():
        return RiskRubric()

    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return RiskRubric(
        factors=data.get("factors", {}),
        cap=data.get("cap", 10.0),
        severity_bands=data.get("severity_bands", {})
    )


def load_remediation_guide(path: Optional[Union[str, Path]] = None) -> dict:
    """Load remediation guidance mappings."""
    if path is None:
        path = Path(__file__).parent / "remediation.yaml"
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_framework_mappings(path: Optional[Union[str, Path]] = None) -> dict:
    """Load OWASP and NIST framework mappings."""
    if path is None:
        path = Path(__file__).parent / "frameworks.yaml"
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def determine_severity(score: float, bands: Optional[dict] = None) -> str:
    """Classify numerical risk score into a severity level."""
    if score >= 8.0:
        return "critical"
    elif score >= 6.0:
        return "high"
    elif score >= 3.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "info"


def score_finding(
    finding: Finding,
    rubric: Optional[RiskRubric] = None,
    remediation_guide: Optional[dict] = None,
    framework_guide: Optional[dict] = None,
    has_known_issues: bool = False,
    has_agent_capability: bool = False
) -> Tuple[float, str, List[str], List[str], List[str]]:
    """
    Compute a deterministic risk score (0-10), severity, factors list,
    ordered remediation steps, and framework tags.
    """
    if rubric is None:
        rubric = load_rubric()
    if remediation_guide is None:
        remediation_guide = load_remediation_guide()
    if framework_guide is None:
        framework_guide = load_framework_mappings()

    weights = rubric.factors
    cap = rubric.cap

    score = 0.0
    applied_factor_keys: List[str] = []
    risk_factors: List[str] = []

    # 1. Authentication factor
    if finding.auth_state == "none":
        w = weights.get("auth_none", 3.0)
        score += w
        applied_factor_keys.append("auth_none")
        risk_factors.append(f"No authentication required (+{w:.1f})")

    # 2. Bind scope factors
    if finding.bind_scope == "public":
        w = weights.get("bind_public", 3.0)
        score += w
        applied_factor_keys.append("bind_public")
        risk_factors.append(f"Service bound to public internet interface (+{w:.1f})")
    elif finding.bind_scope == "lan":
        w = weights.get("bind_lan", 1.5)
        score += w
        applied_factor_keys.append("bind_lan")
        risk_factors.append(f"Service bound to local network subnet (+{w:.1f})")
    elif finding.bind_scope == "loopback":
        w = weights.get("bind_loopback", 0.0)
        score += w
        if w > 0:
            risk_factors.append(f"Bound to loopback (+{w:.1f})")

    # 3. TLS check on non-loopback
    if finding.tls is False and finding.bind_scope in ("lan", "public"):
        w = weights.get("no_tls_non_loopback", 0.5)
        score += w
        applied_factor_keys.append("no_tls_non_loopback")
        risk_factors.append(f"Unencrypted HTTP communication on shared network (+{w:.1f})")

    # 4. Model/data exposure
    if finding.models_or_tools:
        w = weights.get("exposes_models_or_data", 1.5)
        score += w
        applied_factor_keys.append("exposes_models_or_data")
        risk_factors.append(f"Exposes active models or tools: {len(finding.models_or_tools)} listed (+{w:.1f})")

    # 5. Agent or tool execution capability
    if has_agent_capability or finding.category in ("agent-platform", "mcp"):
        w = weights.get("agent_or_tool_execution_capability", 2.0)
        score += w
        applied_factor_keys.append("agent_or_tool_execution_capability")
        risk_factors.append(f"Autonomous agent or tool execution capability (+{w:.1f})")

    # 6. Unapproved by inventory
    if finding.approval == "unapproved":
        w = weights.get("unapproved_by_inventory", 1.0)
        score += w
        applied_factor_keys.append("unapproved_by_inventory")
        risk_factors.append(f"Unapproved shadow AI deployment (+{w:.1f})")

    # 7. Known issue / CVE version
    if has_known_issues:
        w = weights.get("known_issue_version", 2.0)
        score += w
        applied_factor_keys.append("known_issue_version")
        risk_factors.append(f"Known critical vulnerability or unpatched CVE (+{w:.1f})")

    # 8. Credential indicator seen
    if finding.credential_indicator:
        w = weights.get("credential_indicator_present", 1.5)
        score += w
        applied_factor_keys.append("credential_indicator_present")
        risk_factors.append(f"Detected secret or credential pattern in response or config (+{w:.1f})")

    # Enforce deterministic cap
    final_score = round(min(score, cap), 1)
    severity = determine_severity(final_score, rubric.severity_bands)

    # Compile remediation steps (service-specific first, then factor-specific)
    remediation_steps: List[str] = []
    service_remeds = remediation_guide.get("services", {}).get(finding.service.lower(), [])
    remediation_steps.extend(service_remeds)

    factor_remeds = remediation_guide.get("factors", {})
    for fk in applied_factor_keys:
        if fk in factor_remeds:
            for step in factor_remeds[fk]:
                if step not in remediation_steps:
                    remediation_steps.append(step)

    # Compile framework tags
    framework_tags: List[str] = []
    category_frameworks = framework_guide.get("categories", {}).get(finding.category, [])
    framework_tags.extend(category_frameworks)

    factor_frameworks = framework_guide.get("factors", {})
    for fk in applied_factor_keys:
        if fk in factor_frameworks:
            for tag in factor_frameworks[fk]:
                if tag not in framework_tags:
                    framework_tags.append(tag)

    return final_score, severity, risk_factors, remediation_steps, framework_tags

