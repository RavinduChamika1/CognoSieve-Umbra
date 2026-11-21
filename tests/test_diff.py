"""Tests for run diffing and drift tracking."""

from umbra.core.models import Finding
from umbra.report.diff import compute_run_diff, render_diff_markdown


def test_diff_new_changed_unchanged_gone():
    f1 = Finding.create(run_id="r1", host="127.0.0.1", port=11434, service="ollama", auth_state="none", risk_score=4.0)
    f2 = Finding.create(run_id="r1", host="127.0.0.1", port=8000, service="vllm", auth_state="required", risk_score=3.0)
    f3 = Finding.create(run_id="r1", host="127.0.0.1", port=3000, service="open-webui", auth_state="none", risk_score=5.0)

    # In second run:
    # f1 is changed (auth state became required, score dropped to 1.0)
    f1_mod = f1.model_copy()
    f1_mod.auth_state = "required"
    f1_mod.risk_score = 1.0

    # f2 is unchanged
    f2_mod = f2.model_copy()

    # f3 is gone (decommissioned)
    # f4 is new (newly discovered)
    f4_new = Finding.create(run_id="r2", host="127.0.0.1", port=6333, service="qdrant", auth_state="none", risk_score=4.5)

    diff = compute_run_diff(
        current_findings=[f1_mod, f2_mod, f4_new],
        previous_findings=[f1, f2, f3],
        current_run_id="r2",
        previous_run_id="r1"
    )

    assert len(diff.new) == 1
    assert diff.new[0].service == "qdrant"
    assert diff.new[0].status == "new"

    assert len(diff.changed) == 1
    assert diff.changed[0].service == "ollama"
    assert diff.changed[0].status == "changed"

    assert len(diff.unchanged) == 1
    assert diff.unchanged[0].service == "vllm"
    assert diff.unchanged[0].status == "unchanged"

    assert len(diff.gone) == 1
    assert diff.gone[0].service == "open-webui"
    assert diff.gone[0].status == "gone"

    md = render_diff_markdown(diff, "r2", "r1")
    assert "New Findings" in md
    assert "Changed Findings" in md
    assert "Gone" in md
    assert "qdrant" in md

