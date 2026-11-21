"""Self-contained HTML report renderer (light/dark theme aware)."""

from typing import List, Optional
import jinja2

from umbra import __version__
from umbra.core.models import Finding, Run, RunDiff, ScopeConfig
from umbra.report.writers import get_executive_summary, get_top_fix_list

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CognoSieve Umbra Report - {{ run.scope_label }}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #10b981;
      --info: #64748b;
      --approved: #10b981;
      --unapproved: #ef4444;
      --table-stripe: rgba(255, 255, 255, 0.02);
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f8fafc;
        --card-bg: #ffffff;
        --card-border: #e2e8f0;
        --text: #0f172a;
        --text-muted: #64748b;
        --accent: #0284c7;
        --table-stripe: rgba(0, 0, 0, 0.02);
      }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 2rem;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    header {
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1, h2, h3 {
      font-weight: 700;
      line-height: 1.2;
    }
    h1 { font-size: 2rem; color: var(--accent); margin-bottom: 0.5rem; }
    h2 { font-size: 1.4rem; margin-top: 2rem; border-bottom: 1px solid var(--card-border); padding-bottom: 0.5rem; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-critical { background-color: var(--critical); color: #fff; }
    .badge-high { background-color: var(--high); color: #fff; }
    .badge-medium { background-color: var(--medium); color: #000; }
    .badge-low { background-color: var(--low); color: #fff; }
    .badge-info { background-color: var(--info); color: #fff; }
    .badge-approved { background-color: var(--approved); color: #fff; }
    .badge-unapproved { background-color: var(--unapproved); color: #fff; }
    .badge-unknown { background-color: var(--info); color: #fff; }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin: 1.5rem 0;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 0.5rem;
      padding: 1.25rem;
    }
    .stat-val {
      font-size: 2.2rem;
      font-weight: 800;
      color: var(--accent);
    }
    .stat-val.unapproved { color: var(--unapproved); }
    .stat-label {
      font-size: 0.85rem;
      color: var(--text-muted);
      text-transform: uppercase;
    }

    .exec-summary {
      background: var(--card-bg);
      border-left: 4px solid var(--accent);
      padding: 1.25rem;
      border-radius: 0 0.5rem 0.5rem 0;
      margin: 1.5rem 0;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1.5rem 0;
      background: var(--card-bg);
      border-radius: 0.5rem;
      overflow: hidden;
      border: 1px solid var(--card-border);
    }
    th, td {
      padding: 0.85rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--card-border);
    }
    th {
      background: rgba(0, 0, 0, 0.2);
      font-size: 0.85rem;
      text-transform: uppercase;
      color: var(--text-muted);
    }
    tr:nth-child(even) { background-color: var(--table-stripe); }
    
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 0.5rem;
      padding: 1.25rem;
      margin-bottom: 1.25rem;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .finding-title {
      font-size: 1.15rem;
      font-weight: 700;
    }
    .remediation-box {
      background: rgba(0,0,0,0.15);
      border-radius: 0.35rem;
      padding: 0.75rem 1rem;
      margin-top: 0.75rem;
    }
    .remediation-box ol { margin: 0; padding-left: 1.2rem; }
    footer {
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--card-border);
      font-size: 0.85rem;
      color: var(--text-muted);
      text-align: center;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85em;
      background: rgba(125, 125, 125, 0.15);
      padding: 0.15em 0.35em;
      border-radius: 0.25rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>CognoSieve Umbra Discovery Report</h1>
      <p style="color: var(--text-muted); margin: 0;">
        Scope: <strong>{{ run.scope_label }}</strong> | Run ID: <code>{{ run.id }}</code> |
        Generated: {{ run.started_at }} | Version: v{{ version }}
      </p>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val unapproved">{{ unapproved_count }}</div>
        <div class="stat-label">Unapproved Shadow AI</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{{ findings|length }}</div>
        <div class="stat-label">Total Endpoints Found</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: var(--approved)">{{ approved_count }}</div>
        <div class="stat-label">Approved Inventory</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: var(--critical)">{{ critical_count }}</div>
        <div class="stat-label">Critical Exposures</div>
      </div>
    </div>

    <h2>Executive Summary</h2>
    <div class="exec-summary">
      <p style="margin: 0; font-size: 1.05rem;">{{ exec_summary }}</p>
    </div>

    {% if ai_summary %}
    <h2>AI Security Reviewer Narrative</h2>
    <div class="exec-summary" style="border-left-color: #a855f7;">
      <p style="margin: 0;">{{ ai_summary }}</p>
    </div>
    {% endif %}

    <h2>Top 5 Priority Actions (Fix First)</h2>
    {% if top_fixes %}
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Service</th>
          <th>Target</th>
          <th>Severity</th>
          <th>Score</th>
          <th>Priority Remediation</th>
        </tr>
      </thead>
      <tbody>
        {% for tf in top_fixes %}
        <tr>
          <td>{{ loop.index }}</td>
          <td><strong>{{ tf.service }}</strong></td>
          <td><code>{{ tf.host }}:{{ tf.port or 'local' }}</code></td>
          <td><span class="badge badge-{{ tf.severity }}">{{ tf.severity }}</span></td>
          <td><strong>{{ "%.1f"|format(tf.score) }}</strong></td>
          <td>{{ tf.primary_fix }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p>No active remediation actions required.</p>
    {% endif %}

    <h2>Discovered AI Inventory</h2>
    {% if findings %}
    <table>
      <thead>
        <tr>
          <th>Service</th>
          <th>Target</th>
          <th>Category</th>
          <th>Bind Scope</th>
          <th>Auth</th>
          <th>TLS</th>
          <th>Status</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody>
        {% for f in findings %}
        <tr>
          <td><strong>{{ f.service }}</strong></td>
          <td><code>{{ f.host }}:{{ f.port or 'local' }}</code></td>
          <td>{{ f.category }}</td>
          <td>{{ f.bind_scope }}</td>
          <td>{{ f.auth_state }}</td>
          <td>{% if f.tls %}TLS{% else %}Plain{% endif %}</td>
          <td><span class="badge badge-{{ f.approval }}">{{ f.approval }}</span></td>
          <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p>No services detected in this scan.</p>
    {% endif %}

    <h2>Finding Cards & Remediation Guidance</h2>
    {% for f in findings %}
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">
          {{ f.service }} &mdash; <code>{{ f.host }}:{{ f.port or 'local' }}</code>
        </div>
        <div>
          <span class="badge badge-{{ f.approval }}">{{ f.approval }}</span>
          <span class="badge badge-{{ f.severity }}">{{ f.severity }} ({{ "%.1f"|format(f.risk_score) }})</span>
        </div>
      </div>
      <p style="color: var(--text-muted); font-size: 0.9rem; margin: 0.25rem 0;">
        Category: <strong>{{ f.category }}</strong> | Source: <strong>{{ f.source }}</strong> |
        Scope: <strong>{{ f.bind_scope }}</strong> | Auth: <strong>{{ f.auth_state }}</strong> |
        Owner: <strong>{{ f.owner or 'Unassigned' }}</strong>
      </p>

      {% if f.models_or_tools %}
      <p style="margin: 0.5rem 0; font-size: 0.9rem;">
        <strong>Discovered Models / Tools:</strong>
        {% for m in f.models_or_tools %}
        <code>{{ m }}</code>{% if not loop.last %}, {% endif %}
        {% endfor %}
      </p>
      {% endif %}

      {% if f.risk_factors %}
      <p style="margin: 0.5rem 0; font-size: 0.9rem;">
        <strong>Risk Factors:</strong> {{ f.risk_factors|join('; ') }}
      </p>
      {% endif %}

      {% if f.framework_tags %}
      <p style="margin: 0.5rem 0; font-size: 0.85rem; color: var(--text-muted);">
        <strong>Framework Tags:</strong> {{ f.framework_tags|join(', ') }}
      </p>
      {% endif %}

      {% if f.remediation %}
      <div class="remediation-box">
        <strong>Remediation Steps:</strong>
        <ol>
          {% for step in f.remediation %}
          <li>{{ step }}</li>
          {% endfor %}
        </ol>
      </div>
      {% endif %}
    </div>
    {% endfor %}

    {% if diff %}
    <h2>What Changed (Drift Analysis)</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-val" style="color: var(--low)">{{ diff.new|length }}</div><div class="stat-label">New Findings</div></div>
      <div class="stat-card"><div class="stat-val" style="color: var(--medium)">{{ diff.changed|length }}</div><div class="stat-label">Changed Findings</div></div>
      <div class="stat-card"><div class="stat-val">{{ diff.unchanged|length }}</div><div class="stat-label">Unchanged</div></div>
      <div class="stat-card"><div class="stat-val" style="color: var(--text-muted)">{{ diff.gone|length }}</div><div class="stat-label">Gone</div></div>
    </div>
    {% endif %}

    <h2>Coverage and Limits</h2>
    <div class="exec-summary" style="border-left-color: var(--text-muted);">
      <p style="margin: 0 0 0.5rem 0; font-weight: 600;">Defensive Scan Limitations:</p>
      <ul style="margin: 0; padding-left: 1.2rem; font-size: 0.9rem; color: var(--text-muted);">
        <li>Ports outside the configured scan range were not probed.</li>
        <li>Services without signatures in the YAML probe pack cannot be fingerprinted.</li>
        <li>Excluded hosts and networks were strictly avoided according to safety policy.</li>
        <li>If Docker is not running or not installed, container discovery was skipped gracefully.</li>
        <li>Non-HTTP proprietary protocols are not detected.</li>
        <li>A clean report confirms absence of matching signatures, not the absolute absence of shadow AI.</li>
      </ul>
    </div>

    <footer>
      CognoSieve Umbra v{{ version }} &bull; Defensive Shadow AI Discovery
    </footer>
  </div>
</body>
</html>
"""


def render_html_report(
    run: Run,
    findings: List[Finding],
    diff: Optional[RunDiff] = None,
    scope_cfg: Optional[ScopeConfig] = None,
    ai_summary: Optional[str] = None
) -> str:
    """Render the single self-contained light/dark aware HTML report."""
    template = jinja2.Template(HTML_TEMPLATE)
    exec_summary = get_executive_summary(findings)
    top_fixes = get_top_fix_list(findings, limit=5)

    unapproved_count = len([f for f in findings if f.approval == "unapproved"])
    approved_count = len([f for f in findings if f.approval == "approved"])
    critical_count = len([f for f in findings if f.severity in ("critical", "high")])

    return template.render(
        run=run,
        findings=findings,
        diff=diff,
        scope_cfg=scope_cfg,
        version=__version__,
        exec_summary=exec_summary,
        top_fixes=top_fixes,
        unapproved_count=unapproved_count,
        approved_count=approved_count,
        critical_count=critical_count,
        ai_summary=ai_summary
    )

