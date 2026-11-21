"""Runner script to execute CognoSieve Umbra CLI end-to-end and populate sample_report."""

import http.server
import json
import os
from pathlib import Path
import shutil
import threading
import time
from typer.testing import CliRunner

from umbra.cli import app
from umbra.report.manifest import verify_manifest


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
                "models": [
                    {"name": "llama3:latest", "model": "llama3:latest", "size": 4661224676},
                    {"name": "mistral:7b", "model": "mistral:7b", "size": 4109865159}
                ]
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
        pass


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


def run_e2e():
    print("Starting mock servers...")
    ollama_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 11435), MockOllamaHandler)
    webui_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 3000), MockOpenWebUIHandler)

    t1 = threading.Thread(target=ollama_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=webui_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    time.sleep(0.5)

    runner = CliRunner()
    sample_reports_dir = Path("examples/sample_report")
    sample_reports_dir.mkdir(parents=True, exist_ok=True)

    print("Running CLI: umbra scan --target 127.0.0.1 --ports 11435,3000...")
    res = runner.invoke(app, [
        "scan",
        "--target", "127.0.0.1",
        "--ports", "11435,3000",
        "--scope", "examples/scope.yaml",
        "--inventory", "examples/approved.yaml",
        "--out", str(sample_reports_dir),
        "--no-ai-summary"
    ])
    print(res.output)

    # Find generated report directory
    subdirs = [d for d in sample_reports_dir.iterdir() if d.is_dir() and d.name != "raw"]
    if not subdirs:
        raise RuntimeError("No report directory generated!")
    report_folder = subdirs[-1]
    print(f"Generated report at: {report_folder}")

    # Verify manifest
    valid, failures = verify_manifest(report_folder)
    print(f"Manifest verification: {valid} (failures: {failures})")

    # Copy files to artifact dir
    artifact_dir = Path("C:/Users/Chamika/.gemini/antigravity/brain/c7ee0b23-6309-4a84-abca-909cc9912dda/verification_report")
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    shutil.copytree(report_folder, artifact_dir)
    print(f"Copied report to artifact directory: {artifact_dir}")

    ollama_srv.shutdown()
    webui_srv.shutdown()
    ollama_srv.server_close()
    webui_srv.server_close()
    print("E2E Run completed successfully!")


if __name__ == "__main__":
    run_e2e()
