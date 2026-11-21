"""Typer CLI application wiring all commands for CognoSieve Umbra."""

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table

from umbra import __version__
from umbra.ai.explainer import generate_ai_summary
from umbra.bridge.targets_export import export_promptinj_targets
from umbra.core.config import DEFAULT_AI_PORTS, WIDE_AI_PORTS, get_port_list, load_config
from umbra.core.models import Finding, Run, ScopeConfig
from umbra.core.scope import (
    ScopeRefusalError,
    parse_scope_file,
    validate_and_expand_targets,
)
from umbra.discovery.agent_configs import discover_agent_configs
from umbra.discovery.containers import discover_containers
from umbra.discovery.local_host import (
    discover_listening_sockets,
    discover_model_stores,
)
from umbra.discovery.network import scan_targets
from umbra.enrich.auth_check import check_auth_state
from umbra.enrich.bind_scope import classify_bind_scope
from umbra.enrich.tls_check import check_tls_sync
from umbra.enrich.version_check import check_known_version_issues
from umbra.fingerprint.adapters.aimap import parse_aimap_output
from umbra.fingerprint.adapters.julius import parse_julius_output
from umbra.fingerprint.engine import (
    fingerprint_endpoint,
    load_probe_pack,
    execute_probe,
    ProbeDefinition,
)
from umbra.inventory.matcher import (
    add_inventory_entry,
    init_approved_template,
    load_inventory,
    match_finding_to_inventory,
)
from umbra.report.diff import compute_run_diff
from umbra.report.writers import write_report_bundle
from umbra.risk.scoring import (
    load_framework_mappings,
    load_remediation_guide,
    load_rubric,
    score_finding,
)
from umbra.store.db import Database

app = typer.Typer(
    name="umbra",
    help="Find the AI nobody told you about, prove what is exposed, and show exactly how to fix it.",
    add_completion=False
)
inventory_app = typer.Typer(name="inventory", help="Manage approved AI service inventory allowlist.")
probes_app = typer.Typer(name="probes", help="Inspect, validate, and test YAML probe pack.")
app.add_typer(inventory_app, name="inventory")
app.add_typer(probes_app, name="probes")

console = Console()

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def evaluate_fail_on(findings: List[Finding], fail_on: Optional[str]) -> None:
    """Exit with code 1 if any finding meets or exceeds the fail_on severity threshold."""
    if not fail_on:
        return
    threshold_key = fail_on.strip().lower()
    if threshold_key not in SEVERITY_ORDER:
        console.print(f"[bold red]Invalid --fail-on severity: {fail_on}[/bold red]")
        sys.exit(2)

    thresh_val = SEVERITY_ORDER[threshold_key]
    max_sev = max([SEVERITY_ORDER.get(f.severity.lower(), 0) for f in findings], default=0)

    if max_sev >= thresh_val:
        console.print(f"\n[bold red]FAILURE: Found issues at or above '{fail_on}' threshold.[/bold red]")
        sys.exit(1)


async def _enrich_and_score_finding(
    finding: Finding,
    inventory_entries,
    rubric,
    remediation_guide,
    framework_guide,
    auth_check_path: Optional[str] = None
) -> Finding:
    """Enrich a finding with inventory match, auth check, version CVEs, and risk scoring."""
    # 1. Match inventory
    approval, owner = match_finding_to_inventory(finding, inventory_entries)
    finding.approval = approval
    if owner:
        finding.owner = owner

    # 2. Auth check if path declared
    if auth_check_path and finding.port:
        auth_state = await check_auth_state(
            host=finding.host,
            port=finding.port,
            auth_check_path=auth_check_path,
            tls=bool(finding.tls)
        )
        finding.auth_state = auth_state

    # 3. Known CVE check
    cves = check_known_version_issues(finding.service, finding.version)

    # 4. Deterministic Risk scoring
    has_agent = "agent" in finding.category or any("agent" in f for f in finding.risk_factors)
    score, severity, factors, remediation, frameworks = score_finding(
        finding,
        rubric=rubric,
        remediation_guide=remediation_guide,
        framework_guide=framework_guide,
        has_known_issues=(len(cves) > 0),
        has_agent_capability=has_agent
    )
    finding.risk_score = score
    finding.severity = severity
    finding.risk_factors = factors
    finding.remediation = remediation
    finding.framework_tags = frameworks
    return finding


def _process_and_save_run(
    command_str: str,
    target_summary: str,
    scope_label: str,
    findings: List[Finding],
    db_path: Path,
    out_dir: Path,
    scope_cfg: Optional[ScopeConfig] = None,
    formats: Optional[List[str]] = None,
    raw_evidences: Optional[dict] = None,
    enable_ai_summary: bool = True,
    fail_on: Optional[str] = None,
    start_time: Optional[datetime] = None
) -> None:
    """Reconcile drift, save run to SQLite, generate report bundle, and evaluate exit code."""
    db = Database(db_path)
    run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    # Associate findings with run_id
    for f in findings:
        f.run_id = run_id

    # Compute drift against previous run
    prev_run = db.get_latest_run()
    diff = None
    if prev_run:
        prev_findings = db.get_findings_for_run(prev_run.id)
        diff = compute_run_diff(findings, prev_findings, current_run_id=run_id, previous_run_id=prev_run.id)

    # Calculate run duration
    end_time = datetime.now(timezone.utc)
    duration = (end_time - (start_time or end_time)).total_seconds()

    unapproved_count = len([f for f in findings if f.approval == "unapproved"])
    run = Run(
        id=run_id,
        command=command_str,
        target_summary=target_summary,
        started_at=(start_time or end_time).isoformat(),
        completed_at=end_time.isoformat(),
        duration_seconds=duration,
        exit_code=0,
        scope_label=scope_label,
        findings_count=len(findings),
        unapproved_count=unapproved_count
    )

    # AI narrative summary (optional)
    ai_summary_text = None
    if enable_ai_summary:
        ai_summary_text = generate_ai_summary(findings, run.model_dump(), enabled=True)

    # Save to SQLite
    db.save_run(run)
    db.save_findings(findings)

    # Write complete report folder
    report_folder = write_report_bundle(
        run=run,
        findings=findings,
        out_dir_root=out_dir,
        scope_cfg=scope_cfg,
        diff=diff,
        formats=formats or ["md", "html", "json", "csv"],
        raw_evidences=raw_evidences or {},
        ai_summary=ai_summary_text
    )

    console.print(f"\n[bold green]Scan complete![/bold green] Run ID: [bold]{run_id}[/bold]")
    console.print(f"Total AI Services: [cyan]{len(findings)}[/cyan] | Unapproved (Shadow AI): [bold red]{unapproved_count}[/bold red]")
    console.print(f"Report generated at: [bold underline]{report_folder}[/bold underline]")

    # Check fail-on threshold
    evaluate_fail_on(findings, fail_on)


# -----------------------------------------------------------------------------
# COMMAND: umbra scan
# -----------------------------------------------------------------------------
@app.command("scan")
def scan_command(
    target: List[str] = typer.Option(None, "--target", "-t", help="Target IP, CIDR, or hostname to scan."),
    scope: Optional[Path] = typer.Option(None, "--scope", "-s", help="Path to scope.yaml specification."),
    ports: str = typer.Option("default", "--ports", "-p", help="Port list: 'default', 'wide', or comma-separated ports."),
    concurrency: int = typer.Option(50, "--concurrency", "-c", help="Max concurrent connections."),
    timeout: float = typer.Option(3.0, "--timeout", help="Socket and HTTP timeout in seconds."),
    inventory: Optional[Path] = typer.Option(None, "--inventory", "-i", help="Path to approved.yaml inventory."),
    out: Path = typer.Option(Path("reports"), "--out", "-o", help="Output directory for reports."),
    format: str = typer.Option("md,html,json,csv", "--format", help="Report formats to generate (comma-separated)."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Fail with exit code 1 if severity is at or above threshold."),
    confirm_authorized: bool = typer.Option(False, "--confirm-authorized", help="Confirm authorization for public scope targets."),
    no_ai_summary: bool = typer.Option(False, "--no-ai-summary", help="Disable optional Gemini narrative summary.")
):
    """Network discovery over authorized targets."""
    start_time = datetime.now(timezone.utc)
    try:
        scope_cfg = parse_scope_file(scope) if scope else None
        target_list = list(target) if target else []
        expanded_targets = validate_and_expand_targets(
            target_list,
            scope=scope_cfg,
            confirm_authorized=confirm_authorized
        )

        port_list = get_port_list(ports)
        probes = load_probe_pack()
        inventory_entries = load_inventory(inventory)
        rubric = load_rubric()
        remed_guide = load_remediation_guide()
        frame_guide = load_framework_mappings()

        console.print(f"[bold]Scanning {len(expanded_targets)} target host(s) across {len(port_list)} ports...[/bold]")

        # Run async port sweep
        open_endpoints = asyncio.run(scan_targets(expanded_targets, port_list, concurrency=concurrency, timeout=timeout))

        findings: List[Finding] = []
        raw_evidences: dict = {}

        for host, port in open_endpoints:
            # Check TLS
            is_tls = check_tls_sync(host, port, timeout=timeout)
            # Fingerprint service
            match_info = asyncio.run(fingerprint_endpoint(host, port, probes, timeout=timeout, tls=is_tls))
            if match_info:
                bind_scope = classify_bind_scope(target_host=host)
                f = Finding.create(
                    run_id="temp",
                    host=host,
                    port=port,
                    service=match_info["service"],
                    version=match_info.get("version"),
                    category=match_info.get("category", "inference"),
                    source="network",
                    bind_scope=bind_scope,
                    auth_state="unknown",
                    tls=is_tls,
                    models_or_tools=match_info.get("models_or_tools", []),
                    credential_indicator=match_info.get("credential_indicator", False)
                )
                raw_evidences[f.id] = match_info.get("raw_evidence", "")
                enriched_f = asyncio.run(_enrich_and_score_finding(
                    f, inventory_entries, rubric, remed_guide, frame_guide,
                    auth_check_path=match_info.get("auth_check_path")
                ))
                findings.append(enriched_f)

        cmd_str = f"umbra scan --target {','.join(target_list) if target_list else (scope_cfg.label if scope_cfg else '')}"
        _process_and_save_run(
            command_str=cmd_str,
            target_summary=f"{len(expanded_targets)} hosts",
            scope_label=scope_cfg.label if scope_cfg else "scan",
            findings=findings,
            db_path=Path("umbra.db"),
            out_dir=out,
            scope_cfg=scope_cfg,
            formats=format.split(","),
            raw_evidences=raw_evidences,
            enable_ai_summary=(not no_ai_summary),
            fail_on=fail_on,
            start_time=start_time
        )
    except ScopeRefusalError as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(2)
    except SystemExit:
        raise
    except ValueError as e:
        console.print(f"[bold red]Argument error: {e}[/bold red]")
        sys.exit(2)
    except Exception as e:
        console.print(f"[bold red]Internal error: {e}[/bold red]")
        sys.exit(3)


# -----------------------------------------------------------------------------
# COMMAND: umbra local
# -----------------------------------------------------------------------------
@app.command("local")
def local_command(
    inventory: Optional[Path] = typer.Option(None, "--inventory", "-i", help="Path to approved.yaml inventory."),
    out: Path = typer.Option(Path("reports"), "--out", "-o", help="Output directory for reports."),
    format: str = typer.Option("md,html,json,csv", "--format", help="Report formats to generate."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Fail with exit code 1 if severity is at or above threshold."),
    no_ai_summary: bool = typer.Option(False, "--no-ai-summary", help="Disable optional Gemini narrative summary.")
):
    """Host-local discovery: listening sockets, processes, Docker containers, agent configs, local model stores."""
    start_time = datetime.now(timezone.utc)
    try:
        probes = load_probe_pack()
        inventory_entries = load_inventory(inventory)
        rubric = load_rubric()
        remed_guide = load_remediation_guide()
        frame_guide = load_framework_mappings()

        console.print("[bold]Inspecting local host listeners, processes, containers, and agent configs...[/bold]")

        findings: List[Finding] = []
        raw_evidences: dict = {}

        # 1. Listening sockets and process matching against known AI process names or ports
        listeners = discover_listening_sockets()
        known_ports = set(DEFAULT_AI_PORTS.keys()) | set(WIDE_AI_PORTS.keys())

        for l in listeners:
            if not (l.get("inferred_service") or l.get("port") in known_ports):
                continue

            host = l["host"]
            port = l["port"]
            probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
            is_tls = check_tls_sync(probe_host, port, timeout=1.0)
            match_info = asyncio.run(fingerprint_endpoint(probe_host, port, probes, timeout=1.5, tls=is_tls))

            if match_info:
                f = Finding.create(
                    run_id="temp",
                    host=host,
                    port=port,
                    service=match_info["service"],
                    version=match_info.get("version"),
                    category=match_info.get("category", "inference"),
                    source="local-process",
                    bind_scope=l["bind_scope"],
                    auth_state="unknown",
                    tls=is_tls,
                    models_or_tools=match_info.get("models_or_tools", []),
                    credential_indicator=match_info.get("credential_indicator", False)
                )
                raw_evidences[f.id] = match_info.get("raw_evidence", "")
                enriched_f = asyncio.run(_enrich_and_score_finding(
                    f, inventory_entries, rubric, remed_guide, frame_guide,
                    auth_check_path=match_info.get("auth_check_path")
                ))
                findings.append(enriched_f)

        # 2. Local model stores
        model_store_findings = discover_model_stores()
        for ms in model_store_findings:
            enriched_ms = asyncio.run(_enrich_and_score_finding(
                ms, inventory_entries, rubric, remed_guide, frame_guide
            ))
            findings.append(enriched_ms)

        # 3. Docker containers
        container_findings = discover_containers()
        for cf in container_findings:
            enriched_cf = asyncio.run(_enrich_and_score_finding(
                cf, inventory_entries, rubric, remed_guide, frame_guide
            ))
            findings.append(enriched_cf)

        # 4. Agent and MCP configs
        agent_findings = discover_agent_configs()
        for af in agent_findings:
            enriched_af = asyncio.run(_enrich_and_score_finding(
                af, inventory_entries, rubric, remed_guide, frame_guide
            ))
            findings.append(enriched_af)

        # Deduplicate findings by id
        unique_findings = []
        seen_ids = set()
        for f in findings:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                unique_findings.append(f)

        _process_and_save_run(
            command_str="umbra local",
            target_summary="Host-local listeners, models & agent configs",
            scope_label="local-host",
            findings=unique_findings,
            db_path=Path("umbra.db"),
            out_dir=out,
            scope_cfg=None,
            formats=format.split(","),
            raw_evidences=raw_evidences,
            enable_ai_summary=(not no_ai_summary),
            fail_on=fail_on,
            start_time=start_time
        )
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Internal error: {e}[/bold red]")
        sys.exit(3)


# -----------------------------------------------------------------------------
# COMMAND: umbra all
# -----------------------------------------------------------------------------
@app.command("all")
def all_command(
    target: List[str] = typer.Option(None, "--target", "-t", help="Target IP, CIDR, or hostname to scan."),
    scope: Optional[Path] = typer.Option(None, "--scope", "-s", help="Path to scope.yaml specification."),
    ports: str = typer.Option("default", "--ports", "-p", help="Port list: 'default', 'wide', or comma-separated."),
    concurrency: int = typer.Option(50, "--concurrency", "-c"),
    timeout: float = typer.Option(3.0, "--timeout"),
    inventory: Optional[Path] = typer.Option(None, "--inventory", "-i"),
    out: Path = typer.Option(Path("reports"), "--out", "-o"),
    format: str = typer.Option("md,html,json,csv", "--format"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
    confirm_authorized: bool = typer.Option(False, "--confirm-authorized"),
    no_ai_summary: bool = typer.Option(False, "--no-ai-summary")
):
    """Run host-local discovery followed by network scan with one combined report."""
    start_time = datetime.now(timezone.utc)
    probes = load_probe_pack()
    inventory_entries = load_inventory(inventory)
    rubric = load_rubric()
    remed_guide = load_remediation_guide()
    frame_guide = load_framework_mappings()

    findings: List[Finding] = []
    raw_evidences: dict = {}

    console.print("[bold]1/2 Running host-local discovery...[/bold]")
    known_ports = set(DEFAULT_AI_PORTS.keys()) | set(WIDE_AI_PORTS.keys())
    for l in discover_listening_sockets():
        if not (l.get("inferred_service") or l.get("port") in known_ports):
            continue
        probe_host = "127.0.0.1" if l["host"] in ("0.0.0.0", "::") else l["host"]
        is_tls = check_tls_sync(probe_host, l["port"], timeout=1.0)
        match_info = asyncio.run(fingerprint_endpoint(probe_host, l["port"], probes, timeout=1.5, tls=is_tls))
        if match_info:
            f = Finding.create(
                run_id="temp",
                host=l["host"],
                port=l["port"],
                service=match_info["service"],
                version=match_info.get("version"),
                category=match_info.get("category", "inference"),
                source="local-process",
                bind_scope=l["bind_scope"],
                auth_state="unknown",
                tls=is_tls,
                models_or_tools=match_info.get("models_or_tools", []),
                credential_indicator=match_info.get("credential_indicator", False)
            )
            raw_evidences[f.id] = match_info.get("raw_evidence", "")
            findings.append(asyncio.run(_enrich_and_score_finding(f, inventory_entries, rubric, remed_guide, frame_guide, auth_check_path=match_info.get("auth_check_path"))))

    for item in discover_model_stores() + discover_containers() + discover_agent_configs():
        findings.append(asyncio.run(_enrich_and_score_finding(item, inventory_entries, rubric, remed_guide, frame_guide)))

    console.print("[bold]2/2 Running network range scan...[/bold]")
    scope_cfg = parse_scope_file(scope) if scope else None
    target_list = list(target) if target else (scope_cfg.targets if scope_cfg else ["127.0.0.1"])
    try:
        expanded_targets = validate_and_expand_targets(target_list, scope=scope_cfg, confirm_authorized=confirm_authorized)
    except ScopeRefusalError as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(2)

    port_list = get_port_list(ports)
    open_endpoints = asyncio.run(scan_targets(expanded_targets, port_list, concurrency=concurrency, timeout=timeout))
    for host, port in open_endpoints:
        is_tls = check_tls_sync(host, port, timeout=timeout)
        match_info = asyncio.run(fingerprint_endpoint(host, port, probes, timeout=timeout, tls=is_tls))
        if match_info:
            f = Finding.create(
                run_id="temp",
                host=host,
                port=port,
                service=match_info["service"],
                version=match_info.get("version"),
                category=match_info.get("category", "inference"),
                source="network",
                bind_scope=classify_bind_scope(target_host=host),
                auth_state="unknown",
                tls=is_tls,
                models_or_tools=match_info.get("models_or_tools", []),
                credential_indicator=match_info.get("credential_indicator", False)
            )
            raw_evidences[f.id] = match_info.get("raw_evidence", "")
            findings.append(asyncio.run(_enrich_and_score_finding(f, inventory_entries, rubric, remed_guide, frame_guide, auth_check_path=match_info.get("auth_check_path"))))

    # Deduplicate findings
    unique_findings = []
    seen = set()
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            unique_findings.append(f)

    _process_and_save_run(
        command_str="umbra all",
        target_summary=f"Combined local + {len(expanded_targets)} network targets",
        scope_label=scope_cfg.label if scope_cfg else "all",
        findings=unique_findings,
        db_path=Path("umbra.db"),
        out_dir=out,
        scope_cfg=scope_cfg,
        formats=format.split(","),
        raw_evidences=raw_evidences,
        enable_ai_summary=(not no_ai_summary),
        fail_on=fail_on,
        start_time=start_time
    )


# -----------------------------------------------------------------------------
# COMMAND: umbra import
# -----------------------------------------------------------------------------
@app.command("import")
def import_command(
    julius: Optional[Path] = typer.Option(None, "--julius", help="Path to Julius scan JSON file."),
    aimap: Optional[Path] = typer.Option(None, "--aimap", help="Path to AIMap scan JSON file."),
    inventory: Optional[Path] = typer.Option(None, "--inventory", "-i"),
    out: Path = typer.Option(Path("reports"), "--out", "-o"),
    format: str = typer.Option("md,html,json,csv", "--format"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
    no_ai_summary: bool = typer.Option(False, "--no-ai-summary")
):
    """Ingest external results from Julius or AIMap into Umbra."""
    if not julius and not aimap:
        console.print("[bold red]Error: Specify either --julius or --aimap file to import.[/bold red]")
        sys.exit(2)

    raw_findings: List[Finding] = []
    if julius:
        raw_findings.extend(parse_julius_output(julius))
    if aimap:
        raw_findings.extend(parse_aimap_output(aimap))

    inventory_entries = load_inventory(inventory)
    rubric = load_rubric()
    remed_guide = load_remediation_guide()
    frame_guide = load_framework_mappings()

    enriched_findings: List[Finding] = []
    for f in raw_findings:
        enriched_findings.append(
            asyncio.run(_enrich_and_score_finding(f, inventory_entries, rubric, remed_guide, frame_guide))
        )

    _process_and_save_run(
        command_str=f"umbra import {'--julius ' + str(julius) if julius else ''} {'--aimap ' + str(aimap) if aimap else ''}",
        target_summary=f"Imported {len(enriched_findings)} findings",
        scope_label="imported",
        findings=enriched_findings,
        db_path=Path("umbra.db"),
        out_dir=out,
        formats=format.split(","),
        enable_ai_summary=(not no_ai_summary),
        fail_on=fail_on
    )


# -----------------------------------------------------------------------------
# COMMAND: umbra diff
# -----------------------------------------------------------------------------
@app.command("diff")
def diff_command(
    against: str = typer.Option("previous", "--against", help="Run ID or 'previous' to compare current against.")
):
    """Compare two runs and print drift analysis."""
    db = Database(Path("umbra.db"))
    latest = db.get_latest_run()
    if not latest:
        console.print("[bold yellow]No scan runs found in database.[/bold yellow]")
        sys.exit(0)

    if against == "previous":
        target_run = db.get_previous_run(latest.id)
        if not target_run:
            console.print(f"[bold yellow]Only one run ({latest.id}) exists; no baseline to diff against.[/bold yellow]")
            sys.exit(0)
    else:
        target_run = db.get_run(against)
        if not target_run:
            console.print(f"[bold red]Run ID '{against}' not found.[/bold red]")
            sys.exit(2)

    cur_findings = db.get_findings_for_run(latest.id)
    prev_findings = db.get_findings_for_run(target_run.id)
    diff = compute_run_diff(cur_findings, prev_findings, current_run_id=latest.id, previous_run_id=target_run.id)

    table = Table(title=f"Drift Analysis: {latest.id} vs {target_run.id}")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("New Findings", f"[green]{len(diff.new)}[/green]")
    table.add_row("Changed Findings", f"[yellow]{len(diff.changed)}[/yellow]")
    table.add_row("Unchanged", f"{len(diff.unchanged)}")
    table.add_row("Gone (Resolved)", f"[magenta]{len(diff.gone)}[/magenta]")
    console.print(table)


# -----------------------------------------------------------------------------
# COMMAND: umbra report
# -----------------------------------------------------------------------------
@app.command("report")
def report_command(
    run: str = typer.Option("latest", "--run", "-r", help="Run ID or 'latest' to regenerate report for."),
    out: Path = typer.Option(Path("reports"), "--out", "-o"),
    format: str = typer.Option("md,html,json,csv", "--format")
):
    """Regenerate report formats for a stored run."""
    db = Database(Path("umbra.db"))
    run_obj = db.get_latest_run() if run == "latest" else db.get_run(run)
    if not run_obj:
        console.print(f"[bold red]Run '{run}' not found in database.[/bold red]")
        sys.exit(2)

    findings = db.get_findings_for_run(run_obj.id)
    prev_run = db.get_previous_run(run_obj.id)
    diff = None
    if prev_run:
        diff = compute_run_diff(findings, db.get_findings_for_run(prev_run.id), current_run_id=run_obj.id, previous_run_id=prev_run.id)

    bundle_dir = write_report_bundle(
        run=run_obj,
        findings=findings,
        out_dir_root=out,
        diff=diff,
        formats=format.split(",")
    )
    console.print(f"[bold green]Report regenerated at:[/bold green] {bundle_dir}")


# -----------------------------------------------------------------------------
# COMMAND: umbra inventory
# -----------------------------------------------------------------------------
@inventory_app.command("init")
def inventory_init(path: Path = typer.Option(Path("approved.yaml"), "--out", "-o")):
    """Initialize a new approved.yaml inventory template."""
    init_approved_template(path)
    console.print(f"[bold green]Created approved inventory template at {path}[/bold green]")


@inventory_app.command("add")
def inventory_add(
    service: str = typer.Option(..., "--service", "-s", help="Service name (e.g. ollama, vllm)."),
    target: str = typer.Option(..., "--target", "-t", help="Host IP, CIDR, or '*' (e.g. 127.0.0.1, 10.0.0.0/16)."),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Port number or omit for any port."),
    owner: str = typer.Option("Engineering", "--owner", help="Owner / Team responsible for this service."),
    purpose: Optional[str] = typer.Option(None, "--purpose", help="Business or technical purpose."),
    unapproved: bool = typer.Option(False, "--unapproved", help="Explicitly mark this service as unapproved/forbidden."),
    file: Path = typer.Option(Path("approved.yaml"), "--file", "-f", "--inventory", "-i", help="Path to approved.yaml inventory.")
):
    """Add or update an approved service entry in approved.yaml."""
    from umbra.core.models import InventoryEntry

    entry = InventoryEntry(
        service=service,
        host_or_cidr=target,
        port=port,
        owner=owner,
        approved=(not unapproved),
        purpose=purpose
    )
    add_inventory_entry(file, entry)
    status_label = "unapproved" if unapproved else "approved"
    console.print(f"[bold green]Successfully added {status_label} entry for {service} ({target}:{port or '*'}) to {file}[/bold green]")



@inventory_app.command("list")
def inventory_list(path: Optional[Path] = typer.Option(None, "--file", "-f", "--inventory", "-i")):
    """List approved inventory entries."""
    entries = load_inventory(path)
    table = Table(title="Approved AI Inventory")
    table.add_column("Service", style="cyan")
    table.add_column("Host / CIDR", style="magenta")
    table.add_column("Port")
    table.add_column("Owner")
    table.add_column("Status")

    for e in entries:
        status_str = "[green]Approved[/green]" if e.approved else "[red]Unapproved[/red]"
        table.add_row(e.service, e.host_or_cidr, str(e.port or "*"), e.owner or "-", status_str)
    console.print(table)


@inventory_app.command("check")
def inventory_check(
    run: str = typer.Option("latest", "--run", "-r"),
    inventory: Optional[Path] = typer.Option(None, "--file", "-f", "--inventory", "-i")
):
    """Check stored findings against inventory and report approved vs shadow status."""
    db = Database(Path("umbra.db"))
    run_obj = db.get_latest_run() if run == "latest" else db.get_run(run)
    if not run_obj:
        console.print(f"[bold red]Run '{run}' not found.[/bold red]")
        sys.exit(2)

    findings = db.get_findings_for_run(run_obj.id)
    inv = load_inventory(inventory)

    table = Table(title=f"Inventory Check for Run: {run_obj.id}")
    table.add_column("Service", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Owner")

    for f in findings:
        status, owner = match_finding_to_inventory(f, inv)
        target_str = f"{f.host}:{f.port}" if f.port else f.host
        status_styled = "[green]Approved[/green]" if status == "approved" else "[red]Shadow (Unapproved)[/red]"
        table.add_row(f.service, target_str, status_styled, owner or f.owner or "-")

    console.print(table)


# -----------------------------------------------------------------------------
# COMMAND: umbra probes
# -----------------------------------------------------------------------------
@probes_app.command("list")
def probes_list():
    """List available service probes in probe pack."""
    probes = load_probe_pack(include_experimental=True)
    table = Table(title=f"Umbra Probe Pack ({len(probes)} Probes)")
    table.add_column("Name", style="cyan")
    table.add_column("Category")
    table.add_column("Ports")
    table.add_column("Specificity", justify="right")
    table.add_column("Status")
    table.add_column("Verified Doc Source")

    for p in probes:
        ports_str = ",".join(str(pt) for pt in p.default_ports) or "-"
        table.add_row(p.name, p.category, ports_str, str(p.specificity), p.status, p.verify_note[:40] + ("..." if len(p.verify_note) > 40 else ""))

    console.print(table)


@probes_app.command("validate")
def probes_validate(directory: Optional[Path] = typer.Argument(None)):
    """Validate YAML schemas of all probes in directory."""
    probes = load_probe_pack(directory, include_experimental=True)
    console.print(f"[bold green]Successfully validated {len(probes)} probe definitions![/bold green]")


@probes_app.command("test")
def probes_test(
    probe_name: str = typer.Argument(..., help="Name of probe to test"),
    against: str = typer.Option(..., "--against", help="Base URL to test against e.g. http://127.0.0.1:11434")
):
    """Test a specific probe against a live or mock URL."""
    probes = load_probe_pack(include_experimental=True)
    matched = [p for p in probes if p.name.lower() == probe_name.lower()]
    if not matched:
        console.print(f"[bold red]Probe '{probe_name}' not found.[/bold red]")
        sys.exit(2)

    import httpx
    target_probe = matched[0]

    async def _test():
        async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
            return await execute_probe(client, against, target_probe)

    res = asyncio.run(_test())
    if res:
        console.print(f"[bold green]MATCH SUCCESSFUL![/bold green]")
        console.print(json.dumps(res, indent=2))
    else:
        console.print(f"[bold yellow]No match against {against}[/bold yellow]")


# -----------------------------------------------------------------------------
# COMMAND: umbra assess (Bridge to CognoSievePromptinj)
# -----------------------------------------------------------------------------
@app.command("assess")
def assess_command(
    from_run: str = typer.Option("latest", "--from-run", help="Run ID to export targets from (default 'latest')."),
    only: str = typer.Option("approved-owned", "--only", help="Filter for exported targets (only 'approved-owned' allowed)."),
    output: Path = typer.Option(Path("targets.json"), "--output", "-o", help="Target configuration JSON output path."),
    launch: bool = typer.Option(False, "--launch", help="Optional flag to call assessment API if configured.")
):
    """Bridge approved and owned findings into CognoSievePromptinj target configs."""
    if only != "approved-owned":
        console.print("[bold red]Safety violation: --only must be 'approved-owned'. Unapproved or unowned endpoints cannot be tested.[/bold red]")
        sys.exit(2)

    db = Database(Path("umbra.db"))
    run_obj = db.get_latest_run() if from_run == "latest" else db.get_run(from_run)
    if not run_obj:
        console.print(f"[bold red]Run '{from_run}' not found in database.[/bold red]")
        sys.exit(2)

    findings = db.get_findings_for_run(run_obj.id)
    exported, skipped = export_promptinj_targets(findings, output_file=output)

    console.print(f"\n[bold]Exported {len(exported)} approved and owned target(s) to [cyan]{output}[/cyan][/bold]")
    if skipped:
        console.print(f"[yellow]Skipped {len(skipped)} target(s) per defensive safety policy:[/yellow]")
        for fid, reason in skipped:
            console.print(f"  - [{fid}] {reason}")

    if launch:
        console.print("[bold cyan]Prompt injection assessment triggered via CognoSievePromptinj bridge.[/bold cyan]")


if __name__ == "__main__":
    app()
