"""Acceptance criteria validation suite for CognoSieve Umbra."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from typer.testing import CliRunner

from umbra.cli import app
from umbra.core.models import Finding, Run
from umbra.store.db import Database
from umbra.report.manifest import verify_manifest

runner = CliRunner()


def test_acceptance_local_finds_loopback_ollama_and_marks_unapproved_when_empty_inventory(tmp_path: Path):
    """
    Acceptance Criteria 1:
    'umbra local' finds a mock loopback-bound Ollama that 'umbra scan' on the LAN range does not,
    and labels it unapproved when the inventory is empty.
    """
    mock_conn = MagicMock()
    mock_conn.status = "LISTEN"
    mock_conn.laddr = MagicMock(ip="127.0.0.1", port=11434)
    mock_conn.pid = 9999

    mock_proc = MagicMock()
    mock_proc.name.return_value = "ollama.exe"
    mock_proc.cmdline.return_value = ["ollama", "serve"]

    mock_fingerprint = {
        "service": "ollama",
        "category": "inference",
        "version": "0.1.34",
        "models_or_tools": ["llama3:latest"],
        "raw_evidence": "Ollama is running",
        "auth_check_path": "/api/tags"
    }

    # Empty inventory file
    empty_inv = tmp_path / "empty_approved.yaml"
    empty_inv.write_text("services: []\n", encoding="utf-8")

    reports_dir = tmp_path / "reports_local"

    with patch("psutil.net_connections", return_value=[mock_conn]):
        with patch("psutil.Process", return_value=mock_proc):
            with patch("umbra.cli.fingerprint_endpoint", return_value=mock_fingerprint):
                with patch("umbra.cli.check_auth_state", return_value="none"):
                    with patch("umbra.cli.discover_model_stores", return_value=[]):
                        with patch("umbra.cli.discover_containers", return_value=[]):
                            with patch("umbra.cli.discover_agent_configs", return_value=[]):
                                result = runner.invoke(app, [
                                    "local",
                                    "--inventory", str(empty_inv),
                                    "--out", str(reports_dir)
                                ])
                                assert result.exit_code == 0
                                assert "Unapproved (Shadow AI): 1" in result.output

    # Check database finding
    db = Database(Path("umbra.db"))
    latest_run = db.get_latest_run()
    assert latest_run is not None
    findings = db.get_findings_for_run(latest_run.id)
    assert len(findings) == 1
    assert findings[0].service == "ollama"
    assert findings[0].host == "127.0.0.1"
    assert findings[0].bind_scope == "loopback"
    assert findings[0].approval == "unapproved"

    # Now verify 'umbra scan' targeting LAN range 192.168.1.0/24 does not scan or report loopback 127.0.0.1
    with patch("umbra.cli.scan_targets", return_value=[]) as mock_scan:
        res_scan = runner.invoke(app, [
            "scan",
            "--target", "192.168.1.50",
            "--out", str(tmp_path / "reports_scan")
        ])
        assert res_scan.exit_code == 0
        # Assert scan_targets was called with 192.168.1.50, never 127.0.0.1
        called_targets = mock_scan.call_args[0][0]
        assert "127.0.0.1" not in called_targets
        assert "192.168.1.50" in called_targets


def test_acceptance_adding_entry_changes_finding_to_approved(tmp_path: Path):
    """
    Acceptance Criteria 2:
    Adding an entry to approved.yaml changes that finding to approved on the next run and the report headline updates.
    """
    inv_file = tmp_path / "approved.yaml"
    inv_file.write_text("services: []\n", encoding="utf-8")

    # Add entry for ollama on 127.0.0.1:11434
    res_add = runner.invoke(app, [
        "inventory", "add",
        "--service", "ollama",
        "--target", "127.0.0.1",
        "--port", "11434",
        "--owner", "CorePlatform",
        "--file", str(inv_file)
    ])
    assert res_add.exit_code == 0

    mock_conn = MagicMock()
    mock_conn.status = "LISTEN"
    mock_conn.laddr = MagicMock(ip="127.0.0.1", port=11434)
    mock_conn.pid = 9999
    mock_proc = MagicMock()
    mock_proc.name.return_value = "ollama"
    mock_proc.cmdline.return_value = ["ollama"]

    mock_fingerprint = {
        "service": "ollama",
        "category": "inference",
        "version": "0.1.34",
        "models_or_tools": ["llama3"],
        "raw_evidence": "Ollama is running"
    }

    reports_dir = tmp_path / "reports_approved"

    with patch("psutil.net_connections", return_value=[mock_conn]):
        with patch("psutil.Process", return_value=mock_proc):
            with patch("umbra.cli.fingerprint_endpoint", return_value=mock_fingerprint):
                with patch("umbra.cli.check_auth_state", return_value="none"):
                    with patch("umbra.cli.discover_model_stores", return_value=[]):
                        with patch("umbra.cli.discover_containers", return_value=[]):
                            with patch("umbra.cli.discover_agent_configs", return_value=[]):
                                result = runner.invoke(app, [
                                    "local",
                                    "--inventory", str(inv_file),
                                    "--out", str(reports_dir)
                                ])
                                assert result.exit_code == 0
                                # Unapproved count must be 0!
                                assert "Unapproved (Shadow AI): 0" in result.output

    db = Database(Path("umbra.db"))
    latest_run = db.get_latest_run()
    findings = db.get_findings_for_run(latest_run.id)
    assert len(findings) == 1
    assert findings[0].approval == "approved"
    assert findings[0].owner == "CorePlatform"


def test_acceptance_report_folder_contains_all_files_and_manifest_verifies(tmp_path: Path):
    """
    Acceptance Criteria 3:
    The report folder contains every file listed in report_output and manifest.sha256 verifies.
    """
    reports_root = tmp_path / "reports_full"

    mock_conn = MagicMock()
    mock_conn.status = "LISTEN"
    mock_conn.laddr = MagicMock(ip="127.0.0.1", port=11434)
    mock_conn.pid = 9999
    mock_proc = MagicMock()
    mock_proc.name.return_value = "ollama"
    mock_proc.cmdline.return_value = ["ollama"]

    mock_fingerprint = {
        "service": "ollama",
        "category": "inference",
        "version": "0.1.34",
        "models_or_tools": ["llama3"],
        "raw_evidence": "Ollama is running"
    }

    with patch("psutil.net_connections", return_value=[mock_conn]):
        with patch("psutil.Process", return_value=mock_proc):
            with patch("umbra.cli.fingerprint_endpoint", return_value=mock_fingerprint):
                with patch("umbra.cli.check_auth_state", return_value="none"):
                    with patch("umbra.cli.discover_model_stores", return_value=[]):
                        with patch("umbra.cli.discover_containers", return_value=[]):
                            with patch("umbra.cli.discover_agent_configs", return_value=[]):
                                res = runner.invoke(app, ["local", "--out", str(reports_root)])
                                assert res.exit_code == 0

    # Find the generated report folder
    subdirs = [d for d in reports_root.iterdir() if d.is_dir() and d.name != "raw"]
    assert len(subdirs) >= 1
    report_folder = subdirs[0]

    required_files = [
        "report.html",
        "report.md",
        "report.json",
        "findings.csv",
        "diff.md",
        "scope.yaml",
        "run-meta.json",
        "manifest.sha256"
    ]
    for rf in required_files:
        assert (report_folder / rf).exists(), f"Missing required file: {rf}"

    # Verify integrity manifest
    valid, failures = verify_manifest(report_folder)
    assert valid is True, f"Manifest verification failed: {failures}"



def test_acceptance_assess_exports_only_approved_and_owned(tmp_path: Path):
    """
    Acceptance Criteria 4:
    'umbra assess --from-run latest' exports only approved-and-owned targets.
    """
    db = Database(Path("umbra.db"))
    run_id = "run_assess_acceptance"
    db.save_run(Run(id=run_id, command="umbra local"))

    # Target 1: approved and owned -> EXPORTED
    f1 = Finding.create(
        run_id=run_id,
        host="127.0.0.1",
        port=11434,
        service="ollama",
        approval="approved",
        owner="DevSecOps"
    )
    # Target 2: unapproved -> SKIPPED
    f2 = Finding.create(
        run_id=run_id,
        host="10.0.0.5",
        port=8000,
        service="vllm",
        approval="unapproved",
        owner="R&D"
    )
    # Target 3: approved but no owner -> SKIPPED
    f3 = Finding.create(
        run_id=run_id,
        host="127.0.0.1",
        port=3000,
        service="open-webui",
        approval="approved",
        owner=None
    )

    db.save_findings([f1, f2, f3])

    out_file = tmp_path / "promptinj_targets.json"
    result = runner.invoke(app, [
        "assess",
        "--from-run", run_id,
        "--output", str(out_file)
    ])
    assert result.exit_code == 0
    assert "Exported 1 approved and owned target" in result.output
    assert "Skipped 2 target" in result.output
