"""Tests for SQLite persistence, migrations, and credential hygiene."""

from pathlib import Path
from umbra.core.models import Finding, Run
from umbra.store.db import Database


def test_database_init_and_run_persistence(tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = Database(db_file)

    run = Run(
        id="run_12345",
        command="umbra scan --target 127.0.0.1",
        target_summary="127.0.0.1",
        started_at="2026-11-19T10:00:00Z",
        completed_at="2026-11-19T10:01:00Z",
        duration_seconds=60.0,
        exit_code=0,
        scope_label="local-test",
        findings_count=1,
        unapproved_count=1,
        stats={"fake_key": "Bearer supersecretvalue123"}
    )
    db.save_run(run)

    fetched = db.get_run("run_12345")
    assert fetched is not None
    assert fetched.command == "umbra scan --target 127.0.0.1"
    # Ensure stats were redacted
    assert "supersecretvalue123" not in str(fetched.stats)
    assert fetched.unapproved_count == 1


def test_findings_persistence_and_credential_sanitization(tmp_path: Path):
    db_file = tmp_path / "test.db"
    db = Database(db_file)

    run = Run(id="run_001", command="umbra local")
    db.save_run(run)

    finding = Finding.create(
        run_id="run_001",
        host="127.0.0.1",
        port=11434,
        service="ollama",
        category="inference",
        source="local-process",
        bind_scope="loopback",
        auth_state="none",
        approval="unapproved",
        models_or_tools=["llama3:latest", "sk-proj-supersecretkey123"],
        credential_indicator=True,
        risk_score=4.5,
        severity="medium",
        risk_factors=["Unauthenticated endpoint with key sk-proj-supersecretkey123"]
    )

    db.save_findings([finding])

    findings = db.get_findings_for_run("run_001")
    assert len(findings) == 1
    saved = findings[0]
    assert saved.service == "ollama"
    assert saved.credential_indicator is True

    # Check raw database text to ensure NO secret entered SQLite
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT models_or_tools_json, risk_factors_json FROM findings WHERE id = ?", (finding.id,))
        row = cursor.fetchone()
        assert "supersecretkey123" not in row[0]
        assert "supersecretkey123" not in row[1]

    # Check assets upsert
    assets = db.get_all_assets()
    assert len(assets) == 1
    assert assets[0].service == "ollama"

