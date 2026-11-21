"""End-to-end test against a real local mock AI HTTP server."""

import http.server
import json
from pathlib import Path
import threading
import time
from unittest.mock import MagicMock, patch
import pytest
from typer.testing import CliRunner

from umbra.cli import app
from umbra.report.manifest import verify_manifest

runner = CliRunner()


class MockOllamaHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Ollama is running\n")
        elif self.path == "/api/tags":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "models": [{"name": "llama3:latest", "model": "llama3:latest", "size": 4661224676}]
            }).encode("utf-8"))
        elif self.path == "/api/version":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"version": "0.1.34"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress console logging


class MockOpenWebUIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": True,
                "name": "Open WebUI",
                "version": "0.3.10"
            }).encode("utf-8"))
        elif self.path == "/api/v1/auths":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"detail":"Unauthorized"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def mock_servers():
    """Start local mock Ollama and Open WebUI HTTP servers."""
    ollama_server = http.server.ThreadingHTTPServer(("127.0.0.1", 11435), MockOllamaHandler)
    webui_server = http.server.ThreadingHTTPServer(("127.0.0.1", 3000), MockOpenWebUIHandler)

    t1 = threading.Thread(target=ollama_server.serve_forever, daemon=True)
    t2 = threading.Thread(target=webui_server.serve_forever, daemon=True)
    t1.start()
    t2.start()
    time.sleep(0.3)

    yield {"ollama_port": 11435, "webui_port": 3000}

    ollama_server.shutdown()
    webui_server.shutdown()
    ollama_server.server_close()
    webui_server.server_close()


def test_e2e_scan_against_mock_ai_server(mock_servers, tmp_path: Path):
    """End-to-end network discovery against live local mock server."""
    out_dir = tmp_path / "reports"
    result = runner.invoke(app, [
        "scan",
        "--target", "127.0.0.1",
        "--ports", "11435,3000",
        "--out", str(out_dir),
        "--no-ai-summary"
    ])
    assert result.exit_code == 0
    assert "Scan complete!" in result.output

    # Verify report directory
    subdirs = [d for d in out_dir.iterdir() if d.is_dir() and d.name != "raw"]
    assert len(subdirs) >= 1
    report_folder = subdirs[0]

    # Check that report.json contains both discovered services
    with open(report_folder / "report.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        findings = data.get("findings", [])
        services = {f["service"] for f in findings}
        assert "ollama" in services
        assert "open-webui" in services

    # Verify sha256 manifest
    valid, failures = verify_manifest(report_folder)
    assert valid is True, f"Manifest verification failed: {failures}"


def test_e2e_local_against_mock_ai_server(mock_servers, tmp_path: Path):
    """End-to-end local discovery against listening mock sockets."""
    mock_conn1 = MagicMock(status="LISTEN", laddr=MagicMock(ip="127.0.0.1", port=11435), pid=101)
    mock_conn2 = MagicMock(status="LISTEN", laddr=MagicMock(ip="127.0.0.1", port=3000), pid=102)

    mock_proc1 = MagicMock()
    mock_proc1.name.return_value = "ollama"
    mock_proc1.cmdline.return_value = ["ollama", "serve"]

    mock_proc2 = MagicMock()
    mock_proc2.name.return_value = "node"
    mock_proc2.cmdline.return_value = ["node", "open-webui.js"]

    def proc_side_effect(pid):
        return mock_proc1 if pid == 101 else mock_proc2

    out_dir = tmp_path / "reports_local"
    with patch("psutil.net_connections", return_value=[mock_conn1, mock_conn2]):
        with patch("psutil.Process", side_effect=proc_side_effect):
            with patch("umbra.cli.discover_model_stores", return_value=[]):
                with patch("umbra.cli.discover_containers", return_value=[]):
                    with patch("umbra.cli.discover_agent_configs", return_value=[]):
                        result = runner.invoke(app, [
                            "local",
                            "--out", str(out_dir),
                            "--no-ai-summary"
                        ])
                        assert result.exit_code == 0
                        assert "Scan complete!" in result.output

    subdirs = [d for d in out_dir.iterdir() if d.is_dir() and d.name != "raw"]
    assert len(subdirs) >= 1
    report_folder = subdirs[0]

    with open(report_folder / "report.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        findings = data.get("findings", [])
        services = {f["service"] for f in findings}
        assert "ollama" in services
        assert "open-webui" in services

    valid, failures = verify_manifest(report_folder)
    assert valid is True
