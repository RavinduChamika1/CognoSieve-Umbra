"""SQLite persistence layer for runs, assets, findings, and drift history."""

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from umbra.core.models import Asset, Finding, Run
from umbra.core.redact import redact_structure


SCHEMA_VERSION = 1

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    target_summary TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_seconds REAL DEFAULT 0.0,
    exit_code INTEGER DEFAULT 0,
    scope_label TEXT DEFAULT 'default',
    findings_count INTEGER DEFAULT 0,
    unapproved_count INTEGER DEFAULT 0,
    stats_json TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER,
    service TEXT NOT NULL,
    category TEXT NOT NULL,
    bind_scope TEXT DEFAULT 'unknown',
    owner TEXT,
    approval TEXT DEFAULT 'unknown',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    service TEXT NOT NULL,
    version TEXT,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    bind_scope TEXT NOT NULL,
    auth_state TEXT NOT NULL,
    tls INTEGER,
    approval TEXT NOT NULL,
    owner TEXT,
    models_or_tools_json TEXT,
    credential_indicator INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0.0,
    severity TEXT NOT NULL,
    risk_factors_json TEXT,
    remediation_json TEXT,
    framework_tags_json TEXT,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    evidence_file TEXT,
    PRIMARY KEY (id, run_id),
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score REAL NOT NULL,
    severity TEXT NOT NULL,
    auth_state TEXT NOT NULL,
    approval TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

-- CognoSievePromptinj integration table
CREATE TABLE IF NOT EXISTS promptinj_conversations (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    assessment_notes TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_history_asset_id ON finding_history(asset_id);
"""


class Database:
    """Manages the SQLite database connection, migrations, and operations."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        """Run startup schema migrations."""
        with self.get_connection() as conn:
            conn.executescript(CREATE_TABLES_SQL)
            cur = conn.cursor()
            cur.execute("SELECT version FROM schema_version WHERE version = 1;")
            if not cur.fetchone():
                cur.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (1);")
            conn.commit()

    def save_run(self, run: Run) -> None:
        """Insert or update a scan run."""
        clean_stats = redact_structure(run.stats)
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    id, command, target_summary, started_at, completed_at,
                    duration_seconds, exit_code, scope_label,
                    findings_count, unapproved_count, stats_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.command,
                    run.target_summary,
                    run.started_at,
                    run.completed_at,
                    run.duration_seconds,
                    run.exit_code,
                    run.scope_label,
                    run.findings_count,
                    run.unapproved_count,
                    json.dumps(clean_stats)
                )
            )
            conn.commit()

    def get_run(self, run_id: str) -> Optional[Run]:
        """Fetch a run by ID."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                return None
            return Run(
                id=row["id"],
                command=row["command"],
                target_summary=row["target_summary"] or "",
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                duration_seconds=row["duration_seconds"],
                exit_code=row["exit_code"],
                scope_label=row["scope_label"],
                findings_count=row["findings_count"],
                unapproved_count=row["unapproved_count"],
                stats=json.loads(row["stats_json"] or "{}")
            )

    def get_latest_run(self) -> Optional[Run]:
        """Retrieve the most recent run."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1;")
            row = cur.fetchone()
            if not row:
                return None
            return Run(
                id=row["id"],
                command=row["command"],
                target_summary=row["target_summary"] or "",
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                duration_seconds=row["duration_seconds"],
                exit_code=row["exit_code"],
                scope_label=row["scope_label"],
                findings_count=row["findings_count"],
                unapproved_count=row["unapproved_count"],
                stats=json.loads(row["stats_json"] or "{}")
            )

    def get_previous_run(self, before_run_id: str) -> Optional[Run]:
        """Retrieve the run executed immediately prior to before_run_id."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT started_at FROM runs WHERE id = ?", (before_run_id,))
            current = cur.fetchone()
            if not current:
                return None
            cur.execute(
                "SELECT * FROM runs WHERE started_at < ? ORDER BY started_at DESC LIMIT 1;",
                (current["started_at"],)
            )
            row = cur.fetchone()
            if not row:
                return None
            return Run(
                id=row["id"],
                command=row["command"],
                target_summary=row["target_summary"] or "",
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                duration_seconds=row["duration_seconds"],
                exit_code=row["exit_code"],
                scope_label=row["scope_label"],
                findings_count=row["findings_count"],
                unapproved_count=row["unapproved_count"],
                stats=json.loads(row["stats_json"] or "{}")
            )

    def list_runs(self, limit: int = 20) -> List[Run]:
        """List recent runs."""
        runs = []
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                runs.append(
                    Run(
                        id=row["id"],
                        command=row["command"],
                        target_summary=row["target_summary"] or "",
                        started_at=row["started_at"],
                        completed_at=row["completed_at"],
                        duration_seconds=row["duration_seconds"],
                        exit_code=row["exit_code"],
                        scope_label=row["scope_label"],
                        findings_count=row["findings_count"],
                        unapproved_count=row["unapproved_count"],
                        stats=json.loads(row["stats_json"] or "{}")
                    )
                )
        return runs

    def upsert_asset(self, finding: Finding) -> None:
        """Update or insert an asset record for a finding."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT first_seen FROM assets WHERE id = ?", (finding.id,))
            row = cur.fetchone()
            first_seen = row["first_seen"] if row else finding.first_seen

            conn.execute(
                """
                INSERT OR REPLACE INTO assets (
                    id, host, port, service, category, bind_scope,
                    owner, approval, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.host,
                    finding.port,
                    finding.service,
                    finding.category,
                    finding.bind_scope,
                    finding.owner,
                    finding.approval,
                    first_seen,
                    finding.last_seen
                )
            )
            conn.commit()

    def save_findings(self, findings: List[Finding]) -> None:
        """Save findings and record them in assets and history."""
        with self.get_connection() as conn:
            for f in findings:
                # Upsert asset first
                cur = conn.cursor()
                cur.execute("SELECT first_seen FROM assets WHERE id = ?", (f.id,))
                row = cur.fetchone()
                first_seen = row["first_seen"] if row else f.first_seen

                conn.execute(
                    """
                    INSERT OR REPLACE INTO assets (
                        id, host, port, service, category, bind_scope,
                        owner, approval, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id, f.host, f.port, f.service, f.category,
                        f.bind_scope, f.owner, f.approval, first_seen, f.last_seen
                    )
                )

                # Insert finding with redacted structures
                models_tools_clean = redact_structure(f.models_or_tools)
                factors_clean = redact_structure(f.risk_factors)
                remediation_clean = redact_structure(f.remediation)
                framework_clean = redact_structure(f.framework_tags)

                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, run_id, asset_id, host, port, service, version,
                        category, source, bind_scope, auth_state, tls,
                        approval, owner, models_or_tools_json, credential_indicator,
                        risk_score, severity, risk_factors_json, remediation_json,
                        framework_tags_json, status, first_seen, last_seen, evidence_file
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id, f.run_id, f.id, f.host, f.port, f.service, f.version,
                        f.category, f.source, f.bind_scope, f.auth_state,
                        1 if f.tls is True else (0 if f.tls is False else None),
                        f.approval, f.owner, json.dumps(models_tools_clean),
                        1 if f.credential_indicator else 0,
                        f.risk_score, f.severity, json.dumps(factors_clean),
                        json.dumps(remediation_clean), json.dumps(framework_clean),
                        f.status, first_seen, f.last_seen, f.evidence_file
                    )
                )

                # Record history snapshot
                conn.execute(
                    """
                    INSERT INTO finding_history (
                        asset_id, run_id, timestamp, status, risk_score,
                        severity, auth_state, approval
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id, f.run_id, f.last_seen, f.status, f.risk_score,
                        f.severity, f.auth_state, f.approval
                    )
                )
            conn.commit()

    def get_findings_for_run(self, run_id: str) -> List[Finding]:
        """Retrieve all findings associated with a specific run."""
        findings: List[Finding] = []
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
            for row in cur.fetchall():
                tls_val = bool(row["tls"]) if row["tls"] is not None else None
                findings.append(
                    Finding(
                        id=row["id"],
                        run_id=row["run_id"],
                        host=row["host"],
                        port=row["port"],
                        service=row["service"],
                        version=row["version"],
                        category=row["category"],
                        source=row["source"],
                        bind_scope=row["bind_scope"],
                        auth_state=row["auth_state"],
                        tls=tls_val,
                        approval=row["approval"],
                        owner=row["owner"],
                        models_or_tools=json.loads(row["models_or_tools_json"] or "[]"),
                        credential_indicator=bool(row["credential_indicator"]),
                        risk_score=row["risk_score"],
                        severity=row["severity"],
                        risk_factors=json.loads(row["risk_factors_json"] or "[]"),
                        remediation=json.loads(row["remediation_json"] or "[]"),
                        framework_tags=json.loads(row["framework_tags_json"] or "[]"),
                        status=row["status"],
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"],
                        evidence_file=row["evidence_file"]
                    )
                )
        return findings

    def get_all_assets(self) -> List[Asset]:
        """Return all unique discovered assets."""
        assets = []
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM assets ORDER BY last_seen DESC;")
            for row in cur.fetchall():
                assets.append(
                    Asset(
                        id=row["id"],
                        host=row["host"],
                        port=row["port"],
                        service=row["service"],
                        category=row["category"],
                        bind_scope=row["bind_scope"],
                        owner=row["owner"],
                        approval=row["approval"],
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"]
                    )
                )
        return assets

