"""Tests for Umbra CLI commands and exit codes (0, 1, 2, 3)."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from typer.testing import CliRunner

from umbra.cli import app
from umbra.core.models import Finding
from umbra.store.db import Database

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Find the AI nobody told you about" in result.output


def test_cli_scope_refusal_exit_code_2():
    # Public IP without scope / authorization must exit with code 2
    result = runner.invoke(app, ["scan", "--target", "8.8.8.8"])
    assert result.exit_code == 2
    assert "Refusal" in result.output or "requires a scope file" in result.output


def test_cli_scope_missing_confirm_authorized_exit_code_2(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        """
label: prod-scan
authorized_by: CISO
targets:
  - 8.8.8.8
""",
        encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", "--scope", str(scope_file)])
    assert result.exit_code == 2
    assert "--confirm-authorized" in result.output


def test_cli_fail_on_threshold_exit_code_1(tmp_path: Path):
    # Mock finding with public bind and no auth -> score 7.0+ (high/critical)
    mock_finding = Finding.create(
        run_id="temp",
        host="8.8.8.8",
        port=11434,
        service="ollama",
        category="inference",
        bind_scope="public",
        auth_state="none",
        approval="unapproved",
        risk_score=7.0,
        severity="high"
    )

    with patch("umbra.cli.discover_listening_sockets", return_value=[]):
        with patch("umbra.cli.discover_model_stores", return_value=[mock_finding]):
            with patch("umbra.cli.discover_containers", return_value=[]):
                with patch("umbra.cli.discover_agent_configs", return_value=[]):
                    result = runner.invoke(app, ["local", "--out", str(tmp_path), "--fail-on", "medium"])
                    assert result.exit_code == 1
                    assert "FAILURE" in result.output


def test_cli_fail_on_threshold_not_reached_exit_code_0(tmp_path: Path):
    # Finding is low severity, fail-on is critical -> exit code 0
    mock_finding = Finding.create(
        run_id="temp",
        host="127.0.0.1",
        port=11434,
        service="ollama",
        category="inference",
        bind_scope="loopback",
        auth_state="required",
        approval="approved",
        risk_score=0.0,
        severity="info"
    )

    with patch("umbra.cli.discover_listening_sockets", return_value=[]):
        with patch("umbra.cli.discover_model_stores", return_value=[mock_finding]):
            with patch("umbra.cli.discover_containers", return_value=[]):
                with patch("umbra.cli.discover_agent_configs", return_value=[]):
                    result = runner.invoke(app, ["local", "--out", str(tmp_path), "--fail-on", "critical"])
                    assert result.exit_code == 0


def test_cli_assess_approved_and_owned_export(tmp_path: Path):
    db_file = Path("umbra.db")
    db = Database(db_file)

    run_id = "run_assess_test"
    f_approved = Finding.create(
        run_id=run_id,
        host="127.0.0.1",
        port=11434,
        service="ollama",
        approval="approved",
        owner="Engineering"
    )
    f_shadow = Finding.create(
        run_id=run_id,
        host="127.0.0.1",
        port=8000,
        service="vllm",
        approval="unapproved",
        owner=None
    )

    from umbra.core.models import Run
    db.save_run(Run(id=run_id, command="umbra local"))
    db.save_findings([f_approved, f_shadow])

    out_targets = tmp_path / "targets.json"
    result = runner.invoke(app, ["assess", "--from-run", run_id, "--output", str(out_targets)])
    assert result.exit_code == 0
    assert "Exported 1 approved and owned target" in result.output
    assert "Skipped 1 target" in result.output


def test_cli_inventory_commands(tmp_path: Path):
    inv_file = tmp_path / "test_approved.yaml"

    # 1. init
    res_init = runner.invoke(app, ["inventory", "init", "--out", str(inv_file)])
    assert res_init.exit_code == 0
    assert inv_file.exists()

    # 2. add
    res_add = runner.invoke(app, [
        "inventory", "add",
        "--service", "chromadb",
        "--target", "127.0.0.1",
        "--port", "8000",
        "--owner", "DataScience",
        "--file", str(inv_file)
    ])
    assert res_add.exit_code == 0
    assert "Successfully added approved entry" in res_add.output

    # 3. list
    res_list = runner.invoke(app, ["inventory", "list", "--file", str(inv_file)])
    assert res_list.exit_code == 0
    assert "chromadb" in res_list.output
    assert "DataScience" in res_list.output


def test_cli_probes_commands():
    res_list = runner.invoke(app, ["probes", "list"])
    assert res_list.exit_code == 0
    assert "ollama" in res_list.output
    assert "vllm" in res_list.output

    res_val = runner.invoke(app, ["probes", "validate"])
    assert res_val.exit_code == 0
    assert "Successfully validated" in res_val.output


def test_cli_internal_error_exit_code_3():
    # Force an unexpected internal error during discovery
    with patch("umbra.cli.discover_listening_sockets", side_effect=RuntimeError("Unexpected OS crash")):
        result = runner.invoke(app, ["local"])
        assert result.exit_code == 3
        assert "Internal error" in result.output

