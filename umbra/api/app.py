"""FastAPI endpoints exposing Umbra core discovery and assessment operations."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from umbra import __version__
from umbra.bridge.targets_export import export_promptinj_targets
from umbra.core.models import Asset, Finding, Run, RunDiff
from umbra.report.diff import compute_run_diff
from umbra.store.db import Database

app = FastAPI(
    title="CognoSieve Umbra API",
    version=__version__,
    description="Thin API layer over CognoSieve Umbra shadow AI discovery engine."
)

DEFAULT_DB_PATH = Path("umbra.db")


class ScanRequest(BaseModel):
    mode: str = "local"  # 'local' or 'scan'
    targets: Optional[List[str]] = Field(default_factory=list)
    ports: str = "default"
    scope_file: Optional[str] = None
    confirm_authorized: bool = False


class AssessRequest(BaseModel):
    run_id: str = "latest"
    only: str = "approved-owned"
    output_path: Optional[str] = "targets.json"


@app.get("/")
def root():
    return {
        "app": "CognoSieve Umbra",
        "version": __version__,
        "status": "online"
    }


@app.get("/assets", response_model=List[Asset])
def get_assets():
    """Retrieve all discovered assets stored in SQLite."""
    db = Database(DEFAULT_DB_PATH)
    return db.get_all_assets()


@app.get("/scans/{id}")
def get_scan(id: str):
    """Retrieve details, status, and findings of a specific scan run."""
    db = Database(DEFAULT_DB_PATH)
    run_obj = db.get_latest_run() if id == "latest" else db.get_run(id)
    if not run_obj:
        raise HTTPException(status_code=404, detail=f"Scan run '{id}' not found.")

    findings = db.get_findings_for_run(run_obj.id)
    return {
        "run": run_obj,
        "findings": findings
    }


@app.get("/runs/{id}/diff")
def get_run_diff(id: str):
    """Retrieve configuration and inventory drift for a specific run against its predecessor."""
    db = Database(DEFAULT_DB_PATH)
    run_obj = db.get_latest_run() if id == "latest" else db.get_run(id)
    if not run_obj:
        raise HTTPException(status_code=404, detail=f"Run '{id}' not found.")

    prev_run = db.get_previous_run(run_obj.id)
    if not prev_run:
        return {
            "current_run_id": run_obj.id,
            "previous_run_id": None,
            "message": "No baseline run exists to compute drift."
        }

    curr_findings = db.get_findings_for_run(run_obj.id)
    prev_findings = db.get_findings_for_run(prev_run.id)
    diff = compute_run_diff(curr_findings, prev_findings, current_run_id=run_obj.id, previous_run_id=prev_run.id)
    return diff


@app.post("/assess")
def trigger_assess(req: AssessRequest):
    """Bridge approved and owned findings into CognoSievePromptinj target configurations."""
    if req.only != "approved-owned":
        raise HTTPException(status_code=400, detail="Safety rule: Only 'approved-owned' targets may be exported.")

    db = Database(DEFAULT_DB_PATH)
    run_obj = db.get_latest_run() if req.run_id == "latest" else db.get_run(req.run_id)
    if not run_obj:
        raise HTTPException(status_code=404, detail=f"Run '{req.run_id}' not found.")

    findings = db.get_findings_for_run(run_obj.id)
    out_p = Path(req.output_path) if req.output_path else None
    exported, skipped = export_promptinj_targets(findings, output_file=out_p)

    return {
        "run_id": run_obj.id,
        "exported_count": len(exported),
        "exported_targets": exported,
        "skipped_count": len(skipped),
        "skipped_reasons": [{"asset_id": fid, "reason": r} for fid, r in skipped]
    }

