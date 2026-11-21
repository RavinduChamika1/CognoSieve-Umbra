# CognoSieve Umbra Discovery Report: enterprise-security-audit

**Run ID**: `run_20261121_075136`  
**Started At**: `2026-11-21T07:51:36.544502+00:00`  
**Command**: `umbra scan --target 127.0.0.1`  
**Target Summary**: `1 hosts`  
**Exit Code**: `0`

## Executive Summary

> Discovery identified 2 total AI service endpoint(s), including 2 unapproved shadow AI deployment(s). The highest-severity risk identified is a MEDIUM exposure on ollama (127.0.0.1:11435), driven by: No authentication required (+3.0), Exposes active models or tools: 2 listed (+1.5). Priority action: Set OLLAMA_HOST=127.0.0.1:11434 in environment or service configuration..

## Discovery Overview

- **Total Discovered**: 2
- **Unapproved (Shadow AI)**: 2
- **Approved**: 0
- **Unknown / Unclassified**: 0

## Top Fix-First Actions

| # | Service | Target | Severity | Score | Priority Remediation |
|---|---------|--------|----------|-------|----------------------|
| 1 | **ollama** | `127.0.0.1:11435` | MEDIUM | 5.5 | Set OLLAMA_HOST=127.0.0.1:11434 in environment or service configuration. |
| 2 | **open-webui** | `127.0.0.1:3000` | LOW | 1.0 | Enable WEBUI_AUTH=True in Open WebUI environment variables. |

## Detailed Inventory & Findings

| Service | Host:Port | Category | Source | Scope | Auth | TLS | Approval | Score | Severity |
|---------|-----------|----------|--------|-------|------|-----|----------|-------|----------|
| ollama | `127.0.0.1:11435` | inference | network | loopback | none | No | **unapproved** | 5.5 | MEDIUM |
| open-webui | `127.0.0.1:3000` | chat-ui | network | loopback | required | No | **unapproved** | 1.0 | LOW |

## Remediation Guidance & Evidence

### ollama (127.0.0.1:11435)

- **Asset ID**: `56638b72daa08eec`
- **Category**: inference | **Approval**: unapproved | **Owner**: Unassigned
- **Bind Scope**: loopback | **Auth State**: none
- **Models / Tools Exposed**: `llama3:latest, mistral:7b`
- **Risk Factors**: No authentication required (+3.0); Exposes active models or tools: 2 listed (+1.5); Unapproved shadow AI deployment (+1.0)
- **Frameworks**: OWASP LLM01:2025 Model Denial of Service, OWASP LLM02:2025 Sensitive Information Disclosure, NIST AI RMF MAP 1.1 (AI System Context & Asset Inventory), NIST AI RMF MEASURE 2.6 (Security & Resiliency), NIST AI RMF MEASURE 2.6
- **Remediation Steps**:
  1. Set OLLAMA_HOST=127.0.0.1:11434 in environment or service configuration.
  1. Upgrade to Ollama >= 0.1.34 to patch CVE-2024-37032.
  1. Do not expose Ollama port 11434 to untrusted networks without an authenticating reverse proxy.
  1. Enable API key or bearer token authentication in the service configuration.
  1. Place an authenticating reverse proxy (e.g., Caddy, Envoy, LiteLLM with master key) in front of the listener.
  1. Audit and restrict model listing endpoints (/v1/models, /api/tags) to authenticated callers.
  1. Remove unapproved or proprietary fine-tuned model weights from public storage directories.
  1. Review this discovery with the security/compliance team. Add to approved.yaml if legitimate, or decommission.
- **Raw Evidence File**: `raw/56638b72daa08eec.txt`

### open-webui (127.0.0.1:3000)

- **Asset ID**: `735e9e8047194d79`
- **Category**: chat-ui | **Approval**: unapproved | **Owner**: Unassigned
- **Bind Scope**: loopback | **Auth State**: required
- **Risk Factors**: Unapproved shadow AI deployment (+1.0)
- **Frameworks**: OWASP LLM02:2025 Sensitive Information Disclosure, OWASP LLM07:2025 System Prompt Leakage, NIST AI RMF GOVERN 1.2 (Accountability & Policy)
- **Remediation Steps**:
  1. Enable WEBUI_AUTH=True in Open WebUI environment variables.
  1. Disable untrusted custom tools and restrict admin account creation.
  1. Upgrade Open WebUI to >= 0.3.10.
  1. Review this discovery with the security/compliance team. Add to approved.yaml if legitimate, or decommission.
- **Raw Evidence File**: `raw/735e9e8047194d79.txt`

## What Changed (Drift Analysis)

- **New Findings**: 0
- **Changed Findings**: 1
- **Unchanged**: 1
- **Gone (Resolved)**: 0

## Coverage and Limits

This scan operates under explicit defensive safety bounds. What this run could not see:
- Ports outside the requested scan range were not probed.
- Services without signatures in the current YAML probe pack are not fingerprinted.
- Excluded hosts and networks were strictly avoided.
- If Docker is absent or inaccessible, container inspection was gracefully skipped.
- Non-HTTP proprietary protocols (e.g., custom binary RPCs) are not covered by HTTP probes.
- A clean report does not guarantee the complete absence of shadow AI.
