"""Report generation module for JSON, Markdown, HTML, CSV, run-meta, and evidence files."""

import csv
import json
import os
import platform
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import jinja2
import yaml

from umbra import __version__
from umbra.core.models import Finding, Run, RunDiff, ScopeConfig
from umbra.core.redact import redact_structure, redact_text
from umbra.report.manifest import create_manifest


def get_executive_summary(findings: List[Finding]) -> str:
    """
    Lead with the number of unapproved AI services, then the highest-severity finding,
    then the single most valuable fix. Keep under 150 words.
    """
    unapproved = [f for f in findings if f.approval == "unapproved"]
    highest_severity = "none"
    severities = ["critical", "high", "medium", "low", "info"]
    top_finding: Optional[Finding] = None

    for sev in severities:
        matching = [f for f in findings if f.severity == sev]
        if matching:
            highest_severity = sev
            top_finding = matching[0]
            break

    if not findings:
        return "No AI services or local models were detected in the designated scope. All systems appear within expected baseline parameters."

    summary = (
        f"Discovery identified {len(findings)} total AI service endpoint(s), including {len(unapproved)} "
        f"unapproved shadow AI deployment(s). "
    )

    if top_finding:
        summary += (
            f"The highest-severity risk identified is a {highest_severity.upper()} exposure on "
            f"{top_finding.service} ({top_finding.host}:{top_finding.port or 'local'}), "
            f"driven by: {', '.join(top_finding.risk_factors[:2]) or 'unauthenticated or exposed network binding'}. "
        )

    if top_finding and top_finding.remediation:
        summary += f"Priority action: {top_finding.remediation[0]}."
    else:
        summary += "Priority action: Restrict unapproved services to local loopback and require token authentication."

    return summary


def get_top_fix_list(findings: List[Finding], limit: int = 5) -> List[Dict[str, Any]]:
    """Return top findings prioritized by risk score."""
    sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
    top = []
    for f in sorted_findings[:limit]:
        top.append({
            "service": f.service,
            "host": f.host,
            "port": f.port,
            "score": f.risk_score,
            "severity": f.severity,
            "approval": f.approval,
            "primary_fix": f.remediation[0] if f.remediation else "Restrict listener to loopback or bind authentication",
            "factors": f.risk_factors
        })
    return top


def render_markdown_report(
    run: Run,
    findings: List[Finding],
    diff: Optional[RunDiff] = None,
    scope_cfg: Optional[ScopeConfig] = None,
    ai_summary: Optional[str] = None
) -> str:
    """Generate Markdown report according to G6 specifications."""
    exec_summary = get_executive_summary(findings)
    top_fixes = get_top_fix_list(findings, limit=5)

    md = []
    md.append(f"# CognoSieve Umbra Discovery Report: {run.scope_label}\n")
    md.append(f"**Run ID**: `{run.id}`  ")
    md.append(f"**Started At**: `{run.started_at}`  ")
    md.append(f"**Command**: `{run.command}`  ")
    md.append(f"**Target Summary**: `{run.target_summary}`  ")
    md.append(f"**Exit Code**: `{run.exit_code}`\n")

    # Executive Summary
    md.append("## Executive Summary\n")
    md.append(f"> {exec_summary}\n")

    if ai_summary:
        md.append("### AI Security Reviewer Narrative\n")
        md.append(f"{ai_summary}\n")

    # Metrics Summary
    unapproved_count = len([f for f in findings if f.approval == "unapproved"])
    approved_count = len([f for f in findings if f.approval == "approved"])
    unknown_count = len([f for f in findings if f.approval == "unknown"])

    md.append("## Discovery Overview\n")
    md.append(f"- **Total Discovered**: {len(findings)}")
    md.append(f"- **Unapproved (Shadow AI)**: {unapproved_count}")
    md.append(f"- **Approved**: {approved_count}")
    md.append(f"- **Unknown / Unclassified**: {unknown_count}\n")

    # Top 5 Fix First List
    md.append("## Top Fix-First Actions\n")
    if top_fixes:
        md.append("| # | Service | Target | Severity | Score | Priority Remediation |")
        md.append("|---|---------|--------|----------|-------|----------------------|")
        for i, tf in enumerate(top_fixes, start=1):
            target_str = f"{tf['host']}:{tf['port']}" if tf['port'] else tf['host']
            md.append(f"| {i} | **{tf['service']}** | `{target_str}` | {tf['severity'].upper()} | {tf['score']:.1f} | {tf['primary_fix']} |")
        md.append("")
    else:
        md.append("No active remediations required.\n")

    # Full Findings Table
    md.append("## Detailed Inventory & Findings\n")
    if findings:
        md.append("| Service | Host:Port | Category | Source | Scope | Auth | TLS | Approval | Score | Severity |")
        md.append("|---------|-----------|----------|--------|-------|------|-----|----------|-------|----------|")
        for f in findings:
            target_str = f"{f.host}:{f.port}" if f.port else f.host
            tls_str = "Yes" if f.tls is True else ("No" if f.tls is False else "-")
            md.append(
                f"| {f.service} | `{target_str}` | {f.category} | {f.source} | {f.bind_scope} | "
                f"{f.auth_state} | {tls_str} | **{f.approval}** | {f.risk_score:.1f} | {f.severity.upper()} |"
            )
        md.append("")
    else:
        md.append("No findings discovered.\n")

    # Per-finding details
    md.append("## Remediation Guidance & Evidence\n")
    for f in findings:
        target_str = f"{f.host}:{f.port}" if f.port else f.host
        md.append(f"### {f.service} ({target_str})\n")
        md.append(f"- **Asset ID**: `{f.id}`")
        md.append(f"- **Category**: {f.category} | **Approval**: {f.approval} | **Owner**: {f.owner or 'Unassigned'}")
        md.append(f"- **Bind Scope**: {f.bind_scope} | **Auth State**: {f.auth_state}")
        if f.models_or_tools:
            md.append(f"- **Models / Tools Exposed**: `{', '.join(f.models_or_tools)}`")
        if f.risk_factors:
            md.append(f"- **Risk Factors**: {'; '.join(f.risk_factors)}")
        if f.framework_tags:
            md.append(f"- **Frameworks**: {', '.join(f.framework_tags)}")
        if f.remediation:
            md.append("- **Remediation Steps**:")
            for step in f.remediation:
                md.append(f"  1. {step}")
        if f.evidence_file:
            md.append(f"- **Raw Evidence File**: `{f.evidence_file}`")
        md.append("")

    # What Changed / Drift
    if diff:
        md.append("## What Changed (Drift Analysis)\n")
        md.append(f"- **New Findings**: {len(diff.new)}")
        md.append(f"- **Changed Findings**: {len(diff.changed)}")
        md.append(f"- **Unchanged**: {len(diff.unchanged)}")
        md.append(f"- **Gone (Resolved)**: {len(diff.gone)}\n")

    # Coverage and Limits Section
    md.append("## Coverage and Limits\n")
    md.append(
        "This scan operates under explicit defensive safety bounds. What this run could not see:\n"
        "- Ports outside the requested scan range were not probed.\n"
        "- Services without signatures in the current YAML probe pack are not fingerprinted.\n"
        "- Excluded hosts and networks were strictly avoided.\n"
        "- If Docker is absent or inaccessible, container inspection was gracefully skipped.\n"
        "- Non-HTTP proprietary protocols (e.g., custom binary RPCs) are not covered by HTTP probes.\n"
        "- A clean report does not guarantee the complete absence of shadow AI.\n"
    )

    return "\n".join(md)


def write_csv_findings(findings: List[Finding], file_path: Path) -> None:
    """Write findings to CSV for spreadsheet triage."""
    fieldnames = [
        "id", "service", "host", "port", "category", "source", "bind_scope",
        "auth_state", "tls", "approval", "owner", "models_or_tools",
        "credential_indicator", "risk_score", "severity", "risk_factors",
        "remediation", "framework_tags", "status", "first_seen", "last_seen"
    ]
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow({
                "id": finding.id,
                "service": finding.service,
                "host": finding.host,
                "port": finding.port or "",
                "category": finding.category,
                "source": finding.source,
                "bind_scope": finding.bind_scope,
                "auth_state": finding.auth_state,
                "tls": finding.tls if finding.tls is not None else "",
                "approval": finding.approval,
                "owner": finding.owner or "",
                "models_or_tools": "; ".join(finding.models_or_tools),
                "credential_indicator": finding.credential_indicator,
                "risk_score": finding.risk_score,
                "severity": finding.severity,
                "risk_factors": "; ".join(finding.risk_factors),
                "remediation": "; ".join(finding.remediation),
                "framework_tags": "; ".join(finding.framework_tags),
                "status": finding.status,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen
            })


def write_report_bundle(
    run: Run,
    findings: List[Finding],
    out_dir_root: Path,
    scope_cfg: Optional[ScopeConfig] = None,
    diff: Optional[RunDiff] = None,
    formats: Optional[List[str]] = None,
    raw_evidences: Optional[Dict[str, str]] = None,
    ai_summary: Optional[str] = None
) -> Path:
    """
    Generate the complete timestamped report folder structure:
    reports/YYYY-MM-DD_HHMMSS_<scope-label>/
    Outputs: report.html, report.md, report.json, findings.csv, diff.md,
             scope.yaml, run-meta.json, raw/, manifest.sha256, latest link.
    """
    if formats is None:
        formats = ["md", "html", "json", "csv"]

    # Safe folder name format
    time_str = run.started_at.replace(":", "").replace("-", "").replace(".", "")[:15]
    scope_label_clean = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in run.scope_label)
    folder_name = f"{time_str}_{scope_label_clean}"

    report_dir = out_dir_root / folder_name
    report_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = report_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write raw evidence files
    if raw_evidences:
        for finding in findings:
            if finding.id in raw_evidences:
                evidence_filename = f"{finding.id}.txt"
                evidence_path = raw_dir / evidence_filename
                cleaned_evidence = redact_text(raw_evidences[finding.id])
                with open(evidence_path, "w", encoding="utf-8") as f:
                    f.write(cleaned_evidence)
                finding.evidence_file = f"raw/{evidence_filename}"

    # 2. Scope copy
    scope_copy_path = report_dir / "scope.yaml"
    effective_scope = scope_cfg.model_dump() if scope_cfg else {
        "label": run.scope_label,
        "authorized_by": "",
        "targets": [run.target_summary],
        "excluded": []
    }
    with open(scope_copy_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(effective_scope, f, sort_keys=False)

    # 3. run-meta.json
    run_meta = {
        "tool": "cognosieve-umbra",
        "version": __version__,
        "command": run.command,
        "run_id": run.id,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "duration_seconds": run.duration_seconds,
        "exit_code": run.exit_code,
        "host_os": platform.platform(),
        "python_version": sys.version,
        "scope_label": run.scope_label,
        "findings_count": len(findings),
        "unapproved_count": len([f for f in findings if f.approval == "unapproved"]),
    }
    with open(report_dir / "run-meta.json", "w", encoding="utf-8") as f:
        json.dump(redact_structure(run_meta), f, indent=2)

    # 4. report.json
    if "json" in formats:
        full_json = {
            "run": run.model_dump(),
            "scope": effective_scope,
            "executive_summary": get_executive_summary(findings),
            "findings": [f.model_dump() for f in findings],
            "diff": diff.model_dump() if diff else None,
            "ai_summary": ai_summary
        }
        with open(report_dir / "report.json", "w", encoding="utf-8") as f:
            json.dump(redact_structure(full_json), f, indent=2)

    # 5. report.md
    if "md" in formats:
        md_content = render_markdown_report(run, findings, diff, scope_cfg, ai_summary)
        with open(report_dir / "report.md", "w", encoding="utf-8") as f:
            f.write(md_content)

    # 6. findings.csv
    if "csv" in formats:
        write_csv_findings(findings, report_dir / "findings.csv")

    # 7. diff.md
    diff_md_path = report_dir / "diff.md"
    from umbra.report.diff import render_diff_markdown
    diff_content = render_diff_markdown(diff, run.id)
    with open(diff_md_path, "w", encoding="utf-8") as f:
        f.write(diff_content)

    # 8. report.html (single self-contained file, light/dark aware)
    if "html" in formats:
        from umbra.report.html_writer import render_html_report
        html_content = render_html_report(run, findings, diff, scope_cfg, ai_summary)
        with open(report_dir / "report.html", "w", encoding="utf-8") as f:
            f.write(html_content)

    # 9. manifest.sha256
    create_manifest(report_dir)

    # 10. latest symlink / latest.txt
    latest_pointer = out_dir_root / "latest"
    latest_txt = out_dir_root / "latest.txt"

    # Always write latest.txt for reliable cross-platform reading
    with open(latest_txt, "w", encoding="utf-8") as f:
        f.write(report_dir.name)

    # Try symlink if possible
    try:
        if latest_pointer.is_symlink() or latest_pointer.exists():
            if latest_pointer.is_dir() and not latest_pointer.is_symlink():
                pass
            else:
                latest_pointer.unlink()
        os.symlink(report_dir.name, latest_pointer)
    except Exception:
        pass

    return report_dir

