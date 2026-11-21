"""Tests for multi-format report bundle generation and SHA-256 manifest integrity."""

from pathlib import Path
import json
import csv

from umbra.core.models import Finding, Run, ScopeConfig
from umbra.report.writers import write_report_bundle
from umbra.report.manifest import verify_manifest


def test_full_report_bundle_generation_and_integrity(tmp_path: Path):
    run = Run(
        id="run_test_bundle",
        command="umbra scan --target 127.0.0.1",
        target_summary="127.0.0.1",
        scope_label="local-test",
        findings_count=1,
        unapproved_count=1
    )

    finding = Finding.create(
        run_id="run_test_bundle",
        host="127.0.0.1",
        port=11434,
        service="ollama",
        category="inference",
        source="network",
        bind_scope="loopback",
        auth_state="none",
        approval="unapproved",
        risk_score=4.0,
        severity="medium",
        risk_factors=["Unauthenticated endpoint (+3.0)", "Unapproved shadow deployment (+1.0)"],
        remediation=["Set OLLAMA_HOST=127.0.0.1:11434", "Enable reverse proxy"],
        framework_tags=["OWASP LLM01:2025 Model Denial of Service", "NIST AI RMF MAP 1.1"]
    )

    scope_cfg = ScopeConfig(
        label="test-lab",
        authorized_by="Lead Auditor",
        targets=["127.0.0.1"]
    )

    raw_evidences = {finding.id: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOllama is running"}

    report_dir = write_report_bundle(
        run=run,
        findings=[finding],
        out_dir_root=tmp_path,
        scope_cfg=scope_cfg,
        raw_evidences=raw_evidences,
        formats=["md", "html", "json", "csv"]
    )

    # 1. Assert all expected files exist in report folder
    expected_files = [
        "report.html",
        "report.md",
        "report.json",
        "findings.csv",
        "diff.md",
        "scope.yaml",
        "run-meta.json",
        "manifest.sha256",
        f"raw/{finding.id}.txt"
    ]
    for ef in expected_files:
        p = report_dir / ef
        assert p.exists(), f"Expected report file missing: {ef}"

    # 2. Validate JSON schema
    with open(report_dir / "report.json", "r", encoding="utf-8") as f:
        json_data = json.load(f)
        assert json_data["run"]["id"] == "run_test_bundle"
        assert len(json_data["findings"]) == 1
        assert json_data["findings"][0]["service"] == "ollama"

    # 3. Validate HTML contains key sections
    html_text = (report_dir / "report.html").read_text(encoding="utf-8")
    assert "Executive Summary" in html_text
    assert "Top 5 Priority Actions" in html_text
    assert "Coverage and Limits" in html_text
    assert "ollama" in html_text

    # 4. Validate CSV
    with open(report_dir / "findings.csv", "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 1
        assert reader[0]["service"] == "ollama"

    # 5. Verify manifest hashes
    valid, failures = verify_manifest(report_dir)
    assert valid is True, f"Manifest verification failed: {failures}"

