"""Tests for local host listeners, containers, and agent/MCP configs."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from umbra.discovery.agent_configs import (
    infer_capability_category,
    parse_mcp_config_file,
)
from umbra.discovery.containers import discover_containers
from umbra.discovery.local_host import (
    discover_listening_sockets,
    discover_model_stores,
)


def test_infer_mcp_capability():
    assert infer_capability_category("fetch", "npx", ["-y", "@modelcontextprotocol/server-filesystem"]) == "filesystem"
    assert infer_capability_category("terminal", "bash", []) == "shell"
    assert infer_capability_category("chrome-dev", "node", ["puppeteer-server.js"]) == "browser"
    assert infer_capability_category("db-query", "python", ["sqlite_server.py"]) == "database"
    assert infer_capability_category("aws-tools", "npx", ["aws-mcp"]) == "cloud"
    assert infer_capability_category("misc", "echo", ["hi"]) == "other"


def test_parse_mcp_config_file(tmp_path: Path):
    cfg_file = tmp_path / "claude_desktop_config.json"
    cfg_file.write_text(
        json.dumps({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\safe_dir"],
                    "env": {
                        "API_SECRET": "secret_token_12345",
                        "ALLOWED_DIR": "C:\\safe_dir"
                    }
                }
            }
        }),
        encoding="utf-8"
    )

    findings = parse_mcp_config_file(cfg_file, run_id="local_test")
    assert len(findings) == 1
    f = findings[0]
    assert f.service == "mcp-filesystem"
    assert f.category == "mcp"
    assert f.source == "config-file"

    # Verify secret value is NOT present, but key name IS
    desc = " ".join(f.models_or_tools)
    assert "secret_token_12345" not in desc
    assert "API_SECRET" in desc


def test_discover_containers_with_mocked_docker():
    mock_output = json.dumps({
        "Image": "ollama/ollama:latest",
        "Names": "ollama-service",
        "Ports": "0.0.0.0:11434->11434/tcp"
    }) + "\n"

    with patch("shutil.which", return_value="docker"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_output)
            findings = discover_containers(run_id="c_test")
            assert len(findings) == 1
            f = findings[0]
            assert f.service == "ollama"
            assert f.category == "inference"
            assert f.bind_scope == "lan"


def test_discover_containers_skipped_when_docker_missing():
    with patch("shutil.which", return_value=None):
        findings = discover_containers()
        assert findings == []


def test_discover_listening_sockets_with_mock():
    mock_conn = MagicMock()
    mock_conn.status = "LISTEN"
    mock_conn.laddr = MagicMock(ip="127.0.0.1", port=11434)
    mock_conn.pid = 1234

    mock_proc = MagicMock()
    mock_proc.name.return_value = "ollama.exe"
    mock_proc.cmdline.return_value = ["ollama", "serve"]

    with patch("psutil.net_connections", return_value=[mock_conn]):
        with patch("psutil.Process", return_value=mock_proc):
            listeners = discover_listening_sockets()
            assert len(listeners) == 1
            l = listeners[0]
            assert l["host"] == "127.0.0.1"
            assert l["port"] == 11434
            assert l["inferred_service"] == "ollama"
            assert l["bind_scope"] == "loopback"

