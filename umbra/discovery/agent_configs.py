"""Agent and MCP configuration file inventory."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import platform

from umbra.core.models import Finding
from umbra.core.redact import redact_command_line


def infer_capability_category(server_name: str, command: str, args: List[str]) -> str:
    """Infer MCP capability category: filesystem, shell, browser, database, cloud, other."""
    blob = f"{server_name} {command} {' '.join(args)}".lower()

    if any(k in blob for k in ["filesystem", "fs", "file", "drive"]):
        return "filesystem"
    elif any(k in blob for k in ["shell", "bash", "terminal", "exec", "sh", "cmd"]):
        return "shell"
    elif any(k in blob for k in ["browser", "puppeteer", "playwright", "chrome", "selenium"]):
        return "browser"
    elif any(k in blob for k in ["postgres", "mysql", "sqlite", "sql", "mongo", "database", "db"]):
        return "database"
    elif any(k in blob for k in ["aws", "gcp", "azure", "github", "gitlab", "cloudflare", "cloud", "s3"]):
        return "cloud"
    return "other"


def get_candidate_config_paths() -> List[Path]:
    """Return platform-specific candidate paths for MCP and agent config files."""
    home = Path.home()
    system = platform.system()
    candidates = []

    # Cross-platform common paths
    candidates.append(home / ".cursor" / "mcp.json")
    candidates.append(home / "mcp.json")
    candidates.append(home / ".config" / "mcp.json")

    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            appdata_p = Path(appdata)
            candidates.append(appdata_p / "Claude" / "claude_desktop_config.json")
            candidates.append(appdata_p / "Cursor" / "User" / "globalStorage" / "mcp.json")
            candidates.append(appdata_p / "Code" / "User" / "globalStorage" / "mcp.json")
    elif system == "Darwin":
        candidates.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
        candidates.append(home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "mcp.json")
    else:
        # Linux
        candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")
        candidates.append(home / ".config" / "Code" / "User" / "globalStorage" / "mcp.json")

    return candidates


def parse_mcp_config_file(file_path: Path, run_id: str = "local") -> List[Finding]:
    """Parse a single MCP configuration file and extract server definitions."""
    if not file_path.exists():
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    servers_dict = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers_dict, dict):
        return []

    findings: List[Finding] = []
    for s_name, s_cfg in servers_dict.items():
        if not isinstance(s_cfg, dict):
            continue

        raw_cmd = s_cfg.get("command", "")
        raw_args = [str(a) for a in s_cfg.get("args", [])]
        # Redact secrets from command and args
        clean_cmdline = redact_command_line([raw_cmd] + raw_args)
        cap = infer_capability_category(s_name, raw_cmd, raw_args)

        # Record ONLY environment variable names, NEVER values
        raw_env = s_cfg.get("env", {})
        env_var_names = list(raw_env.keys()) if isinstance(raw_env, dict) else []

        models_tools_desc = [
            f"MCP Server: {s_name}",
            f"Capability: {cap}",
            f"Launch: {' '.join(clean_cmdline) if isinstance(clean_cmdline, list) else clean_cmdline}",
            f"Env Keys Declared: {', '.join(env_var_names) if env_var_names else 'None'}"
        ]

        f = Finding.create(
            run_id=run_id,
            host="127.0.0.1",
            port=None,
            service=f"mcp-{s_name}",
            category="mcp",
            source="config-file",
            bind_scope="loopback",
            auth_state="none",
            approval="unapproved",
            models_or_tools=models_tools_desc,
            risk_factors=[
                f"Agent tool / MCP server configured in {file_path.name}: {s_name} (Category: {cap})",
                "Tool execution capability enabled via local agent host"
            ],
            remediation=[
                f"Review configured MCP server '{s_name}' permissions in {file_path.as_posix()}.",
                "Ensure command paths and arguments do not expose shell execution or sensitive file directories."
            ]
        )
        findings.append(f)

    return findings


def discover_agent_configs(run_id: str = "local") -> List[Finding]:
    """Discover all MCP server configurations across known host paths."""
    all_findings: List[Finding] = []
    candidate_paths = get_candidate_config_paths()

    for p in candidate_paths:
        if p.exists() and p.is_file():
            findings = parse_mcp_config_file(p, run_id=run_id)
            all_findings.extend(findings)

    return all_findings

