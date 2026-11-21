<p align="center">
  <img src="assets/logo.png" alt="CognoSieve Umbra Banner" width="800">
</p>

<p align="center">
  <strong>Find the AI nobody told you about, prove what is exposed, and show exactly how to fix it.</strong>
</p>

<p align="center">
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-why-this-tool-exists">Why this exists</a> ·
  <a href="#-why-it-is-safer-than-generic-scanners">Why it is safer</a> ·
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-usage">Usage</a> ·
  <a href="#-learn-from-this-project">Learn</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Series-52%20Weeks%20of%20Security-orange.svg" alt="52 Weeks of Security">
  <img src="https://img.shields.io/badge/Week-08-purple.svg" alt="Week 08">
  <img src="https://img.shields.io/badge/Tests-53%20Passing-brightgreen.svg" alt="Tests 53 Passing">
  <img src="https://img.shields.io/badge/Security-Defensive%20Only-red.svg" alt="Defensive Only">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
</p>

---

## 📌 Table of contents
- [Why this tool exists](#-why-this-tool-exists)
- [Why it is safer than generic scanners](#-why-it-is-safer-than-generic-scanners)
- [Features](#-features)
- [How it works](#-how-it-works)
- [Quick start](#-quick-start)
- [Usage](#-usage)
- [Example output](#-example-output)
- [Project structure](#-project-structure)
- [Testing](#-testing)
- [Security notes and limitations](#-security-notes-and-limitations)
- [Learn from this project](#-learn-from-this-project)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Why this tool exists

Developers and engineering teams are rapidly spinning up local inference servers (Ollama, LM Studio, vLLM), vector databases (ChromaDB, Qdrant, Weaviate), and autonomous agent frameworks (Flowise, Langflow, n8n). Often, this happens without the knowledge or approval of the security team—creating **Shadow AI**.

These unmanaged services introduce severe risks:
- Unauthenticated REST endpoints exposing private company data or API keys.
- Services listening on `0.0.0.0` or open LAN addresses, exposing internal LLMs to the local subnet.
- Agent and MCP configurations with excessive capabilities (e.g. arbitrary shell execution or unrestricted filesystem access).
- Rogue models that have never been tested for prompt injection or jailbreak vulnerabilities.

Most security teams cannot answer three fundamental questions:
1. **What AI services are running across our machines and subnets that nobody told us about?**
2. **Which endpoints are unauthenticated, exposed to LAN/WAN, or misconfigured?**
3. **Which verified assets can safely undergo prompt injection assessment without breaking production?**

**CognoSieve Umbra** answers all three in seconds, on your own infrastructure, producing deterministic risk scores mapped to **OWASP Top 10 for LLMs** and **NIST AI RMF**, and bridging safely into automated prompt security evaluation.

---

## 🛡️ Why it is safer than generic scanners

Running aggressive network scanners (like raw Nmap sweeps or active exploit tools) against delicate AI services can exhaust GPU memory, corrupt model caches, or trigger unauthorized mutations.

| Risk with Generic Scanners | What Can Go Wrong | CognoSieve Umbra (This Tool) |
|---|---|---|
| **Network-only blindspot** | Remotely misses services bound strictly to loopback (`127.0.0.1:11434`). | **Host-local discovery** inspects listening sockets (`psutil`) and process tables to find local Ollama and LM Studio instances. |
| **Intrusive mutations** | Blind fuzzing can trigger stateful mutations, send malicious prompts, or download gigabytes of model weights. | **Strict read-only GET probes**; non-mutating YAML probe pack; never downloads weights, never sends user prompts. |
| **No "Shadow" concept** | Dumps raw IPs without knowing what has been officially authorized by the business. | **Inventory allowlist (`approved.yaml`)** automatically labels findings as *Approved* or *Shadow (Unapproved)*. |
| **Credential leakage** | Scanners often print and store exposed API keys and bearer tokens in plaintext logs. | **Automated Redaction Engine** sanitizes OpenAI, Anthropic, Hugging Face, AWS, and Bearer tokens before writing to disk or SQLite. |
| **Accidental public scanning** | Scanning third-party or cloud IPs without written authorization creates legal liability. | **Strict Scope Refusal**: Refuses public targets with exit code `2` unless explicitly declared in `scope.yaml` and verified with `--confirm-authorized`. |
| **Disconnected testing** | Discovery findings sit in unused JSON files, disconnected from security testing. | **Controlled Handoff**: Safely exports *only* approved and owned assets into `CognoSievePromptinj` for prompt safety testing. |

---

## ✨ Features

- ✅ **Host-Local & Network Discovery**: Detects loopback listeners (`127.0.0.1`), LAN services, offline model caches (`~/.ollama`, Hugging Face, LM Studio), Docker containers, and MCP configs (Claude Desktop, Cursor, VS Code).
- 🔍 **Declarative YAML Probe Pack**: 15 verified service fingerprints (Ollama, vLLM, Open WebUI, AnythingLLM, LiteLLM, LM Studio, llama.cpp, ChromaDB, Qdrant, Weaviate, Milvus Attu, Flowise, Langflow, n8n, Generic OpenAI).
- ⚖️ **Approved vs. Shadow Inventory**: Automatically cross-references findings against `approved.yaml` with team ownership and ticket tracking.
- 📊 **Deterministic Risk Rubric**: Scores exposure from 0.0 to 10.0 based on bind scope, authentication absence, TLS status, and known vulnerabilities, tagged with **OWASP LLM Top 10 (2025)** and **NIST AI RMF** codes.
- 📈 **Scan-to-Scan Drift Analysis**: SQLite persistence tracks state changes (`new`, `changed`, `unchanged`, `gone`), surfacing configuration regressions in `diff.md`.
- 📁 **Multi-Format Report Bundle**: Generates self-contained HTML (with light/dark theme toggle), Markdown, JSON, CSV, raw evidence, and a cryptographic `manifest.sha256`.
- 🤖 **Optional Gemini AI Executive Summary**: Synthesizes minimized findings into a concise 1–2 paragraph executive brief with graceful offline fallback.
- 🌉 **CognoSievePromptinj Bridge**: Securely exports verified, approved-and-owned targets into `targets.json` for prompt injection testing.
- 🔌 **Thin REST API**: FastAPI backend with full OpenAPI / Swagger UI at `http://127.0.0.1:8000/docs`.
- 🧪 **100% Offline Testing**: 53 automated unit and integration tests with fully mocked network and subprocess calls.

---

## 🔬 How it works

```
   [ Local Machine / Authorized Subnet ]
                    │
                    ▼
   [1] Multi-Vector Discovery ───────────► Sockets (127.0.0.1), Processes, Docker, MCP configs, TCP Scan
                    │
                    ▼
   [2] Non-Mutating HTTP Fingerprint ────► 15+ YAML Probes (Status, Headers, Body, JSON path)
                    │
                    ▼
   [3] Enrichment & Risk Scoring ────────► Bind Scope (Loopback / LAN / Public)
                    │                      Auth State (None / Required / Unknown)
                    │                      Deterministic Rubric (0.0 - 10.0 Cap)
                    │                      OWASP LLM Top 10 + NIST AI RMF Tagging
                    │
                    ▼
   [4] Inventory Allowlist Matching ─────► Cross-reference approved.yaml
                    │                      Status: "Approved" vs "Shadow (Unapproved)"
                    │
                    ▼
   [5] Persistence & Drift ──────────────► SQLite Store (runs, assets, findings, history)
                    │                      Computes run diff: new, changed, unchanged, gone
                    │
                    ▼
   [6] Integrity Report Bundle ──────────► report.html (Dark/Light), report.md, report.json,
                                           findings.csv, diff.md, raw/, manifest.sha256
```

---

## 🚀 Quick start

You need **Python 3.11** or newer. Check with `python --version`.

### 1. Clone the repository
```bash
git clone https://github.com/RavinduChamika1/CognoSieve-Umbra.git
cd CognoSieve-Umbra
```

### 2. Create and activate a virtual environment
```powershell
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Linux / macOS
source .venv/bin/activate
```

### 3. Install in editable mode
```powershell
python -m pip install -e .
```

### 4. (Optional) Configure Windows PATH automatically
```powershell
python scripts/set_path.py
```

### 5. Verify CLI installation
```powershell
umbra --help
```

---

## 💻 Usage

```powershell
# 1. Host-local discovery (Ollama on 127.0.0.1, MCP configs, Docker, local models)
umbra local --out reports/

# 2. Network range discovery over authorized subnet
umbra scan --target 192.168.1.0/24 --ports default

# 3. Combined local and network discovery with unified reporting
umbra all --target 127.0.0.1 --out reports/

# 4. Initialize approved inventory template
umbra inventory init --out approved.yaml

# 5. Add an approved service entry
umbra inventory add --service ollama --target 127.0.0.1 --port 11434 --owner DevOps

# 6. Reconcile scan findings against inventory
umbra inventory check --run latest

# 7. Compare scan drift against baseline run
umbra diff --against previous

# 8. List and validate YAML probe definitions
umbra probes list
umbra probes validate

# 9. Export approved targets for prompt injection evaluation
umbra assess --from-run latest --only approved-owned --output targets.json

# 10. Start the REST API server
uvicorn umbra.api.app:app --host 127.0.0.1 --port 8000
```

### What happens when you run it
1. **Target Validation**: Validates IP ranges and ensures public targets are explicitly authorized.
2. **Discovery & Probing**: Identifies listening ports and runs specificity-ranked HTTP fingerprints.
3. **Risk Analysis**: Evaluates bind scope, checks authentication endpoints, and calculates deterministic scores.
4. **Inventory Match**: Labels each finding as *Approved* or *Shadow*.
5. **Report Bundle**: Emits a timestamped report folder with a cryptographic `manifest.sha256`.

---

## 📺 Example output

```text
Inspecting local host listeners, processes, containers, and agent configs...

Scan complete! Run ID: run_20261121_145616
Total AI Services: 2 | Unapproved (Shadow AI): 1
Report generated at: reports\20261121T145615_local-host

             Inventory Check for Run: run_20261121_145616              
┌────────────────────┬─────────────────┬─────────────────────┬────────┐
│ Service            │ Target          │ Status              │ Owner  │
├────────────────────┼─────────────────┼─────────────────────┼────────┤
│ ollama             │ 127.0.0.1:11434 │ Approved            │ DevOps │
│ ollama-model-store │ 127.0.0.1       │ Shadow (Unapproved) │ -      │
└────────────────────┴─────────────────┴─────────────────────┴────────┘

      Drift Analysis: run_20261121_145616 vs run_20261121_133557      
┌──────────────────┬───────┐
│ Category         │ Count │
├──────────────────┼───────┤
│ New Findings     │     0 │
│ Changed Findings │     0 │
│ Unchanged        │     2 │
│ Gone (Resolved)  │     0 │
└──────────────────┴───────┘
```

---

## 🗂️ Project structure

```text
CognoSieve-Umbra/
├── assets/
│   └── logo.png                  # Project banner logo
├── examples/
│   ├── approved.yaml             # Example inventory allowlist
│   ├── scope.yaml                # Example authorized scope definition
│   └── sample_report/            # Sample multi-format report bundle
├── scripts/
│   ├── run_e2e_verification.py   # Mock AI server end-to-end integration test
│   └── set_path.py               # Automated Windows PATH configuration script
├── tests/
│   ├── test_acceptance.py        # Acceptance tests for core discovery & safety
│   ├── test_adapters.py          # Julius & AIMap external ingestion tests
│   ├── test_api.py               # FastAPI endpoint tests
│   ├── test_cli.py               # Typer CLI invocation and exit code tests
│   ├── test_db.py                # SQLite persistence and migration tests
│   ├── test_diff.py              # Drift computation tests
│   ├── test_e2e_mock_server.py   # Mock Ollama & vLLM server tests
│   ├── test_enrich_and_risk.py   # Bind scope & deterministic risk scoring tests
│   ├── test_local_discovery.py   # Sockets, Docker & MCP config parsing tests
│   ├── test_network.py           # Async TCP connect scan tests
│   ├── test_probe_engine.py      # Declarative YAML probe execution tests
│   ├── test_redact.py            # Regex credential sanitization tests
│   ├── test_reports.py           # HTML, MD, JSON, CSV & manifest integrity tests
│   └── test_scope.py             # Public target refusal & CIDR expansion tests
├── umbra/
│   ├── ai/
│   │   └── explainer.py          # Defensive Gemini AI narrative summarizer
│   ├── api/
│   │   └── app.py                # FastAPI REST endpoints
│   ├── bridge/
│   │   └── targets_export.py     # Safe export gate for CognoSievePromptinj
│   ├── core/
│   │   ├── config.py             # Centralized config & API key resolver
│   │   ├── models.py             # Pydantic v2 data models
│   │   ├── redact.py             # Regex credential detection & redaction
│   │   └── scope.py              # Scope parser & public target refusal
│   ├── discovery/
│   │   ├── agent_configs.py      # MCP & AI agent configuration parser
│   │   ├── containers.py         # Docker AI container discovery
│   │   ├── local_host.py         # psutil socket & model store discovery
│   │   └── network.py            # Async TCP connect scanner
│   ├── enrich/
│   │   ├── auth_check.py         # Unauthenticated HTTP access checker
│   │   ├── bind_scope.py         # Loopback / LAN / Public classifier
│   │   ├── tls_check.py          # TLS handshake inspector
│   │   └── version_check.py      # Offline known vulnerabilities matcher
│   ├── fingerprint/
│   │   ├── adapters/             # Ingestion for Julius and AIMap JSON
│   │   ├── engine.py             # HTTPX YAML probe engine
│   │   └── probes/               # 15 declarative service probe definitions
│   ├── inventory/
│   │   ├── approved.yaml         # Default inventory template
│   │   └── matcher.py            # Allowlist matcher & manager
│   ├── report/
│   │   ├── diff.py               # Drift calculator (new/changed/unchanged/gone)
│   │   ├── html_writer.py        # Self-contained theme-aware HTML generator
│   │   ├── manifest.py           # SHA-256 integrity calculator & validator
│   │   └── writers.py            # Multi-format report bundle coordinator
│   ├── risk/
│   │   ├── frameworks.yaml       # OWASP LLM Top 10 & NIST AI RMF mappings
│   │   ├── remediation.yaml      # Fix guidance per service & factor
│   │   ├── rubric.yaml           # Deterministic scoring weights
│   │   └── scoring.py            # Score calculator (capped at 10.0)
│   ├── store/
│   │   └── db.py                 # SQLite database schema, migrations & CRUD
│   └── cli.py                    # Main Typer CLI entrypoint
├── .env.example                  # Environment configuration template
├── pyproject.toml                # Packaging metadata & dependencies
├── pytest.ini                   # Pytest configuration
├── LICENSE                       # MIT License
└── README.md                     # Documentation
```

---

## 🧪 Testing

Execute the automated test suite with `pytest`:

```powershell
python -m pytest -v
```

All **53 tests** run completely offline with mocked networks and verify:
- Sockets and process table matching without touching live processes.
- Declarative YAML probe matching, fallback logic, and specificity sorting.
- Scope refusal logic: public IPs exit with code `2` unless properly authorized.
- Regex credential scrubbing before any write to disk or database.
- Report bundle integrity and cryptographic `manifest.sha256` verification.
- Assess bridge export guard restricting export to approved-and-owned targets.

---

## 🔒 Security notes and limitations

- **Defensive By Design**: Probes are strictly read-only GET requests (POST is permitted only for non-mutating query endpoints declared in probe YAML). The tool never injects prompts, never downloads model weights, and never attempts brute-force authentication.
- **Zero Credential Exposure**: API keys and tokens found in responses or MCP config files are scrubbed using regular expressions before writing to disk or SQLite.
- **Scope Refusal**: Public targets are strictly rejected (exit code `2`) unless documented in `scope.yaml` under `authorized_by` and confirmed with `--confirm-authorized`.
- **Authorized Testing Only**: Only scan and probe infrastructure that you own or have explicit written permission to assess.
- **Disclaimer**: This tool is developed for educational, compliance, and internal security defense purposes.

---

## 📚 Learn from this project

This project teaches key concepts in modern AI security and defensive engineering:
- **Shadow AI Discovery**: Detecting developer-hosted inference endpoints that bypass corporate proxies.
- **Bind Scope Risks**: Why services listening on `0.0.0.0` or LAN interfaces present critical risk compared to `127.0.0.1`.
- **Model Context Protocol (MCP) Security**: How client agent configurations grant excessive tool capabilities (shell, filesystem) to LLMs.
- **OWASP Top 10 for LLMs (2025)**: Mapping shadow endpoints to real-world threats like *LLM01: Prompt Injection*, *LLM02: Sensitive Information Disclosure*, and *LLM06: Excessive Agency*.
- **NIST AI Risk Management Framework (AI RMF 1.0)**: Operationalizing the *GOVERN*, *MAP*, *MEASURE*, and *MANAGE* functions for local AI deployments.

---

## 🗺️ Roadmap

Part of **52 Weeks of Security**: one new cybersecurity project every week.

- [x] **Week 1**: Password strength and breach checker ([PassVigil](https://github.com/RavinduChamika1/passvigil))
- [x] **Week 2**: Hashing and password storage lab
- [x] **Week 3**: Phishing URL analyzer
- [x] **Week 4**: Port scanner & service banner grabber
- [x] **Week 5**: HTTP security header auditor
- [x] **Week 6**: Subdomain takeover checker
- [x] **Week 7**: JWT security analyzer
- [x] **Week 8**: **CognoSieve Umbra** - Defensive Shadow AI discovery, fingerprinting, and risk-scoring tool
- [ ] *More coming every week!*

---

## 🤝 Contributing

Contributions are welcome!
1. Fork the repository: `https://github.com/RavinduChamika1/CognoSieve-Umbra`
2. Create a feature branch: `git checkout -b feature/new-service-probe`
3. Add a new declarative probe in `umbra/fingerprint/probes/<service>.yaml`
4. Run the test suite: `python -m pytest -v`
5. Commit and push: `git push origin feature/new-service-probe`
6. Open a Pull Request.

---

## 👤 Author

**Ravindu Chamika**  
*52 Weeks of Security Series*

If this tool helped you discover unmanaged AI workloads or secure your environment, please ⭐ the repository!

---

## 📄 License

Copyright © 2026 Ravindu Chamika. Released under the [MIT License](LICENSE).
Built for cybersecurity students and practitioners · **52 Weeks of Security** · **Week 8**
