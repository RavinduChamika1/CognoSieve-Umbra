"""Run-to-run drift analysis (new, changed, unchanged, gone)."""

from typing import List, Optional
from umbra.core.models import Finding, RunDiff


def are_findings_equal(a: Finding, b: Finding) -> bool:
    """Compare key operational attributes to detect meaningful configuration drift."""
    return (
        a.auth_state == b.auth_state
        and a.bind_scope == b.bind_scope
        and a.approval == b.approval
        and a.risk_score == b.risk_score
        and a.version == b.version
        and set(a.models_or_tools) == set(b.models_or_tools)
        and a.tls == b.tls
    )


def compute_run_diff(
    current_findings: List[Finding],
    previous_findings: List[Finding],
    current_run_id: str = "current",
    previous_run_id: Optional[str] = None
) -> RunDiff:
    """Classify findings across runs as new, changed, unchanged, or gone."""
    prev_map = {f.id: f for f in previous_findings}
    curr_map = {f.id: f for f in current_findings}

    new_list: List[Finding] = []
    changed_list: List[Finding] = []
    unchanged_list: List[Finding] = []
    gone_list: List[Finding] = []

    for fid, cur_f in curr_map.items():
        if fid not in prev_map:
            cur_f.status = "new"
            new_list.append(cur_f)
        else:
            prev_f = prev_map[fid]
            if are_findings_equal(cur_f, prev_f):
                cur_f.status = "unchanged"
                unchanged_list.append(cur_f)
            else:
                cur_f.status = "changed"
                changed_list.append(cur_f)

    for fid, prev_f in prev_map.items():
        if fid not in curr_map:
            # Gone in current run
            gone_f = prev_f.model_copy()
            gone_f.status = "gone"
            gone_list.append(gone_f)

    return RunDiff(
        previous_run_id=previous_run_id,
        current_run_id=current_run_id,
        new=new_list,
        changed=changed_list,
        unchanged=unchanged_list,
        gone=gone_list
    )


def render_diff_markdown(
    diff: Optional[RunDiff],
    current_run_id: str,
    previous_run_id: Optional[str] = None
) -> str:
    """Format drift findings into a clean Markdown document."""
    if not diff:
        return f"# Scan Diff: {current_run_id}\n\nNo baseline or previous run available for comparison.\n"

    prev_id = diff.previous_run_id or previous_run_id or "initial"
    md = [
        f"# Run-to-Run Diff: `{current_run_id}` vs `{prev_id}`\n",
        f"- **New Findings**: {len(diff.new)}",
        f"- **Changed Findings**: {len(diff.changed)}",
        f"- **Unchanged Findings**: {len(diff.unchanged)}",
        f"- **Gone (Resolved)**: {len(diff.gone)}\n"
    ]

    if diff.new:
        md.append("## 🟢 New Findings")
        for f in diff.new:
            target = f"{f.host}:{f.port}" if f.port else f.host
            md.append(f"- **{f.service}** (`{target}`): Category `{f.category}`, Severity `{f.severity.upper()}`, Approval `{f.approval}`")
        md.append("")

    if diff.changed:
        md.append("## 🟡 Changed Findings")
        for f in diff.changed:
            target = f"{f.host}:{f.port}" if f.port else f.host
            md.append(f"- **{f.service}** (`{target}`): Status `{f.status}`, Auth `{f.auth_state}`, Score `{f.risk_score:.1f}`")
        md.append("")

    if diff.gone:
        md.append("## ⚪ Gone (Decommissioned / Inaccessible)")
        for f in diff.gone:
            target = f"{f.host}:{f.port}" if f.port else f.host
            md.append(f"- **{f.service}** (`{target}`): Previously `{f.severity.upper()}`")
        md.append("")

    if not diff.new and not diff.changed and not diff.gone:
        md.append("No configuration or inventory drift detected between runs.\n")

    return "\n".join(md)

