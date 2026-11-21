"""Tests for bind scope, auth check, inventory matching, and deterministic risk scoring."""

import pytest
import httpx
from pathlib import Path

from umbra.enrich.bind_scope import classify_bind_scope
from umbra.enrich.auth_check import check_auth_state
from umbra.enrich.version_check import check_known_version_issues
from umbra.inventory.matcher import match_finding_to_inventory
from umbra.core.models import Finding, InventoryEntry
from umbra.risk.scoring import score_finding, load_rubric


def test_bind_scope_table_driven():
    # Table-driven tests as required
    cases = [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("localhost", "loopback"),
        ("0.0.0.0", "lan"),
        ("::", "lan"),
        ("10.0.1.5", "lan"),
        ("192.168.1.100", "lan"),
        ("172.16.5.20", "lan"),
        ("8.8.8.8", "public"),
        ("1.1.1.1", "public"),
        ("", "unknown"),
    ]
    for addr, expected in cases:
        actual = classify_bind_scope(bind_addr=addr)
        assert actual == expected, f"Failed for {addr}: got {actual}, expected {expected}"

    # All-interfaces with public interface present
    assert classify_bind_scope(bind_addr="0.0.0.0", has_public_interface=True) == "public"


@pytest.mark.asyncio
async def test_auth_check_outcomes():
    # 200 -> none
    h_200 = lambda req: httpx.Response(200, text="ok")
    c_200 = httpx.AsyncClient(transport=httpx.MockTransport(h_200))
    res_200 = await check_auth_state("127.0.0.1", 11434, "/api/tags", client=c_200)
    assert res_200 == "none"

    # 401 -> required
    h_401 = lambda req: httpx.Response(401, text="Unauthorized")
    c_401 = httpx.AsyncClient(transport=httpx.MockTransport(h_401))
    res_401 = await check_auth_state("127.0.0.1", 11434, "/api/tags", client=c_401)
    assert res_401 == "required"

    # 403 -> required
    h_403 = lambda req: httpx.Response(403, text="Forbidden")
    c_403 = httpx.AsyncClient(transport=httpx.MockTransport(h_403))
    res_403 = await check_auth_state("127.0.0.1", 11434, "/api/tags", client=c_403)
    assert res_403 == "required"

    # Timeout / connection error -> unknown
    def h_err(req):
        raise httpx.ConnectTimeout("timeout")
    c_err = httpx.AsyncClient(transport=httpx.MockTransport(h_err))
    res_err = await check_auth_state("127.0.0.1", 11434, "/api/tags", client=c_err)
    assert res_err == "unknown"


def test_known_version_issues():
    issues_vuln = check_known_version_issues("ollama", "0.1.32")
    assert len(issues_vuln) > 0
    assert "CVE-2024-37032" in issues_vuln[0]

    issues_patched = check_known_version_issues("ollama", "0.1.35")
    assert len(issues_patched) == 0


def test_inventory_matching():
    inv = [
        InventoryEntry(service="ollama", host_or_cidr="127.0.0.1", port=11434, approved=True, owner="Infra"),
        InventoryEntry(service="vllm", host_or_cidr="10.0.0.0/16", port=8000, approved=True, owner="AI Team"),
        InventoryEntry(service="flowise", host_or_cidr="*", port=3000, approved=False, owner="ShadowDept"),
    ]

    # Matching approved entry
    f1 = Finding.create(run_id="r1", host="127.0.0.1", port=11434, service="ollama")
    status, owner = match_finding_to_inventory(f1, inv)
    assert status == "approved"
    assert owner == "Infra"

    # Matching CIDR
    f2 = Finding.create(run_id="r1", host="10.0.5.12", port=8000, service="vllm")
    status, owner = match_finding_to_inventory(f2, inv)
    assert status == "approved"
    assert owner == "AI Team"

    # Matching explicitly unapproved entry
    f3 = Finding.create(run_id="r1", host="192.168.1.5", port=3000, service="flowise")
    status, owner = match_finding_to_inventory(f3, inv)
    assert status == "unapproved"
    assert owner == "ShadowDept"

    # Not in inventory -> unapproved
    f4 = Finding.create(run_id="r1", host="127.0.0.1", port=1234, service="lm-studio")
    status, owner = match_finding_to_inventory(f4, inv)
    assert status == "unapproved"

    # Empty inventory -> unapproved
    status_empty, _ = match_finding_to_inventory(f1, [])
    assert status_empty == "unapproved"


def test_deterministic_risk_scoring_and_cap():
    rubric = load_rubric()

    # Create high-risk finding
    finding = Finding.create(
        run_id="r1",
        host="8.8.8.8",
        port=8000,
        service="vllm",
        category="inference",
        bind_scope="public",
        auth_state="none",
        approval="unapproved",
        models_or_tools=["meta-llama-3"],
        credential_indicator=True,
        tls=False
    )

    score1, sev1, factors1, remeds1, frames1 = score_finding(
        finding, rubric=rubric, has_known_issues=True, has_agent_capability=True
    )
    score2, sev2, factors2, remeds2, frames2 = score_finding(
        finding, rubric=rubric, has_known_issues=True, has_agent_capability=True
    )

    # Determinism: identical inputs yield identical results
    assert score1 == score2
    assert sev1 == sev2
    assert factors1 == factors2

    # Verify score is capped at 10.0
    assert score1 <= 10.0
    assert sev1 == "critical"

    # Every applied factor appears in risk_factors in plain language
    assert any("No authentication" in f for f in factors1)
    assert any("public internet" in f for f in factors1)
    assert any("Unapproved" in f for f in factors1)
    assert any("vulnerability" in f for f in factors1)
    assert any("secret" in f or "credential" in f for f in factors1)

    # Remediation steps present
    assert len(remeds1) > 0
    assert any("reverse proxy" in r.lower() or "api key" in r.lower() for r in remeds1)

    # Framework tags present
    assert len(frames1) > 0
    assert any("OWASP" in ft for ft in frames1)
    assert any("NIST" in ft for ft in frames1)

