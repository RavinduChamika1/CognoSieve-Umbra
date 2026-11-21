"""Pydantic data models for CognoSieve Umbra."""

from datetime import datetime, timezone
import hashlib
from typing import Any, List, Optional
from pydantic import BaseModel, Field


def generate_finding_id(host: str, port: Optional[int], service: str) -> str:
    """Generate a stable deterministic ID for a finding based on host, port, and service."""
    normalized_port = str(port) if port is not None else "none"
    normalized_key = f"{host.strip().lower()}:{normalized_port}:{service.strip().lower()}"
    return hashlib.sha256(normalized_key.encode("utf-8")).hexdigest()[:16]


class ScopeConfig(BaseModel):
    """Scope specification for authorized scans."""
    label: str = "default-scope"
    authorized_by: str = ""
    targets: List[str] = Field(default_factory=list)
    excluded: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


class InventoryEntry(BaseModel):
    """Entry in approved.yaml inventory."""
    service: str
    host_or_cidr: str
    port: Optional[int] = None
    owner: Optional[str] = None
    approved: bool = True
    purpose: Optional[str] = None
    ticket_or_doc: Optional[str] = None


class Finding(BaseModel):
    """Represents a discovered AI service, tool, or asset finding."""
    id: str
    run_id: str
    host: str
    port: Optional[int] = None
    service: str
    version: Optional[str] = None
    category: str = "inference"  # inference | chat-ui | gateway | vector-db | agent-platform | mcp | local-model-store
    source: str = "network"      # network | local-process | container | config-file | import
    bind_scope: str = "unknown"  # loopback | lan | public | unknown
    auth_state: str = "unknown"  # none | required | unknown
    tls: Optional[bool] = None
    approval: str = "unknown"    # approved | unapproved | unknown
    owner: Optional[str] = None
    models_or_tools: List[str] = Field(default_factory=list)
    credential_indicator: bool = False
    risk_score: float = 0.0
    severity: str = "info"       # critical | high | medium | low | info
    risk_factors: List[str] = Field(default_factory=list)
    remediation: List[str] = Field(default_factory=list)
    framework_tags: List[str] = Field(default_factory=list)
    status: str = "new"          # new | changed | unchanged | gone
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_file: Optional[str] = None

    @classmethod
    def create(
        cls,
        run_id: str,
        host: str,
        service: str,
        port: Optional[int] = None,
        **kwargs: Any
    ) -> "Finding":
        f_id = kwargs.pop("id", None) or generate_finding_id(host, port, service)
        return cls(id=f_id, run_id=run_id, host=host, port=port, service=service, **kwargs)


class Asset(BaseModel):
    """Normalized asset representation stored in SQLite."""
    id: str
    host: str
    port: Optional[int] = None
    service: str
    category: str
    bind_scope: str = "unknown"
    owner: Optional[str] = None
    approval: str = "unknown"
    first_seen: str
    last_seen: str


class Run(BaseModel):
    """Scan execution run metadata."""
    id: str
    command: str
    target_summary: str = ""
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    exit_code: int = 0
    scope_label: str = "default"
    findings_count: int = 0
    unapproved_count: int = 0
    stats: dict = Field(default_factory=dict)


class RunDiff(BaseModel):
    """Difference between two runs."""
    previous_run_id: Optional[str] = None
    current_run_id: str
    new: List[Finding] = Field(default_factory=list)
    changed: List[Finding] = Field(default_factory=list)
    unchanged: List[Finding] = Field(default_factory=list)
    gone: List[Finding] = Field(default_factory=list)


class RiskRubric(BaseModel):
    """Deterministic risk calculation weights."""
    factors: dict[str, float] = Field(default_factory=dict)
    cap: float = 10.0
    severity_bands: dict[str, str] = Field(default_factory=dict)

