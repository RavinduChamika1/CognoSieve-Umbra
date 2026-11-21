"""Tests for FastAPI web endpoints."""

from pathlib import Path
from starlette.testclient import TestClient

from umbra.api.app import app
from umbra.core.models import Finding, Run
from umbra.store.db import Database

client = TestClient(app)


def test_api_root():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["app"] == "CognoSieve Umbra"


def test_api_get_assets_and_scans():
    db = Database(Path("umbra.db"))
    run_id = "run_api_test"
    db.save_run(Run(id=run_id, command="umbra local", started_at="2026-11-19T12:00:00Z"))

    f = Finding.create(
        run_id=run_id,
        host="127.0.0.1",
        port=11434,
        service="ollama",
        approval="approved",
        owner="DevOps"
    )
    db.save_findings([f])

    # Test /assets
    resp_assets = client.get("/assets")
    assert resp_assets.status_code == 200
    assets = resp_assets.json()
    assert any(a["service"] == "ollama" for a in assets)

    # Test /scans/{id}
    resp_scan = client.get(f"/scans/{run_id}")
    assert resp_scan.status_code == 200
    scan_data = resp_scan.json()
    assert scan_data["run"]["id"] == run_id
    assert len(scan_data["findings"]) >= 1


def test_api_assess_export(tmp_path: Path):
    target_out = tmp_path / "api_targets.json"
    payload = {
        "run_id": "latest",
        "only": "approved-owned",
        "output_path": str(target_out)
    }
    resp = client.post("/assess", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "exported_count" in data

