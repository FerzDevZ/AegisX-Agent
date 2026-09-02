<p align="center">
  <img src="https://img.shields.io/badge/🛡️-Aegisx--Agent-v0.1.0-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-red" alt="OWASP">
  <img src="https://img.shields.io/badge/CVSS-v3.1-orange" alt="CVSS">
  <img src="https://img.shields.io/badge/Status-Alpha-purple" alt="Status">
</p>

<h1 align="center">🛡️ Aegisx-Agent</h1>

<h3 align="center">Autonomous AI-Powered Cybersecurity Penetration Testing Agent</h3>

<p align="center">
  An intelligent security scanner that autonomously discovers vulnerabilities,<br>
  verifies exploits, and generates severity-ranked reports — all in one pipeline.
</p>

---

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 🔍 **OWASP Top 10 Scanning** | SQL Injection, XSS, CSRF, IDOR, SSRF, and more |
| 🔐 **Secret Detection** | Hardcoded credentials, API keys, JWT tokens, private keys |
| ⚙️ **Configuration Audit** | Missing security headers, CORS misconfig, debug mode leaks |
| 📦 **Dependency Scanning** | CVE detection in third-party JS libraries |
| 🔓 **Exploit Verification** | Confirm findings are actually exploitable (reduces false positives) |
| 📊 **Multi-format Reports** | Markdown, JSON, SARIF (GitHub Code Scanning integration) |
| 🎯 **CVSS v3.1 Scoring** | Industry-standard severity assessment with vector strings |
| 🔌 **Plugin Architecture** | Extend with custom scanners via pluggy |
| 🐳 **Docker Support** | Sandboxed exploit execution in isolated containers |
| 🧠 **Knowledge Base** | OWASP, CWE, MITRE ATT&CK mappings built-in |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/FerzDevZ/AegisX-Agent.git
cd AegisX-Agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

### First Scan

```bash
# Quick scan
aegisx scan https://example.com

# Full scan with all scanners
aegisx scan https://example.com --mode full --report all

# Scan with authentication
aegisx scan https://example.com --auth "your-jwt-token"

# Verbose output with JSON report
aegisx scan https://example.com -v --report json -o ./reports/
```

### Full Pentest (with exploit verification)

```bash
aegisx pentest https://example.com
```

### Recon Only

```bash
aegisx recon https://example.com
```

---

## 📖 CLI Reference

```
🛡️ Aegisx-Agent — Autonomous Security Scanner

Commands:
  scan       Scan a target for vulnerabilities
  pentest    Full penetration test with exploit verification
  recon      Passive reconnaissance — gather target info
  plugins    List all available scanner/exploit/reporter plugins
  info       Show version and system information
```

### Scan Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--mode` | `-m` | Scan mode: `passive`, `quick`, `full`, `stealth` | `quick` |
| `--report` | `-r` | Report format: `markdown`, `json`, `sarif`, `html`, `all` | `markdown` |
| `--output` | `-o` | Report output directory | `reports/` |
| `--scope` | `-s` | Comma-separated domain whitelist | target domain |
| `--depth` | `-d` | Max crawl depth (1-10) | `3` |
| `--rps` | | Max requests per second | `10.0` |
| `--exploit` | `-e` | Enable exploit verification | `false` |
| `--verbose` | `-v` | Verbose output | `false` |
| `--auth` | | Auth token for target | — |
| `--user-agent` | `-ua` | Custom User-Agent string | `AegisxAgent/0.1.0` |

### Scan Modes

| Mode | Description | Speed | Use Case |
|------|-------------|-------|----------|
| `passive` | Recon + fingerprinting only | ⚡⚡⚡ | Initial assessment |
| `quick` | Common vulnerability checks | ⚡⚡ | Regular scans |
| `full` | Comprehensive + exploit verification | ⚡ | Pre-production audit |
| `stealth` | Low-profile to avoid detection | ⚡ | Authorized pentests |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete — no critical/high findings |
| `1` | Scan complete — high findings detected |
| `2` | Scan complete — critical findings detected |

---

## 🏗️ Architecture

```
aegisx-agent/
├── src/aegisx/
│   ├── core/                    # 🧠 Core engine
│   │   ├── orchestrator.py      #    3-phase pipeline coordinator
│   │   ├── config.py            #    Pydantic settings management
│   │   ├── context.py           #    Scan state & findings tracker
│   │   └── exceptions.py        #    Exception hierarchy
│   │
│   ├── scanners/                # 🔍 Vulnerability scanners
│   │   ├── base_scanner.py      #    Abstract scanner interface
│   │   ├── web_scanner.py       #    OWASP Top 10 (SQLi, XSS, CORS, headers)
│   │   ├── secret_scanner.py    #    API keys, tokens, passwords
│   │   ├── config_scanner.py    #    Debug mode, default pages, HTTP methods
│   │   └── dependency_scanner.py#    JS library CVE detection
│   │
│   ├── exploits/                # 💥 Exploit verification
│   │   └── base_exploit.py      #    Abstract exploit interface
│   │
│   ├── reporters/               # 📊 Report generation
│   │   ├── base_reporter.py     #    Abstract reporter interface
│   │   ├── markdown_reporter.py #    Human-readable Markdown report
│   │   ├── json_reporter.py     #    Machine-readable JSON output
│   │   ├── sarif_reporter.py    #    SARIF v2.1.0 (GitHub integration)
│   │   └── cvss.py              #    CVSS v3.1 scoring engine
│   │
│   ├── knowledge/               # 🧠 Security knowledge base
│   │   └── owasp_top10.py       #    OWASP Top 10 2021 + CWE mappings
│   │
│   ├── plugins/                 # 🔌 Plugin management
│   │   └── __init__.py          #    pluggy-based plugin system
│   │
│   ├── utils/                   # 🛠️ Shared utilities
│   │   └── logger.py            #    Structured logging (Rich)
│   │
│   └── cli.py                   # 🖥️ CLI entry point (Typer)
│
├── tests/                       # 🧪 Test suite
│   ├── conftest.py              #    Shared fixtures
│   ├── test_config.py           #    Config tests
│   ├── test_context.py          #    Context & finding tests
│   ├── test_exceptions.py       #    Exception hierarchy tests
│   ├── test_cvss.py             #    CVSS scoring tests
│   ├── test_owasp.py            #    OWASP knowledge base tests
│   └── test_plugins.py          #    Plugin manager tests
│
├── pyproject.toml               # 📦 Project configuration
├── Dockerfile                   # 🐳 Docker build
├── .env.example                 # 🔑 Environment variable template
└── README.md                    # 📖 This file
```

### Three-Phase Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGISX-AGENT PIPELINE                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PHASE 1: RECONNAISSANCE                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Target Reach │→ │ Tech Stack   │→ │ Security     │     │
│  │ Validation   │  │ Detection    │  │ Header Check │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  PHASE 2: SCANNING & EXPLOITATION                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Web Scanner  │→ │ Secret Scan  │→ │ Config Audit │     │
│  │ (OWASP Top10)│  │ (API Keys)   │  │ (Headers)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  PHASE 3: REPORTING & REMEDIATION                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ CVSS Scoring │→ │ Report Gen   │→ │ Remediation  │     │
│  │ & Triage     │  │ MD/JSON/SARIF│  │ Guidance     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔌 Plugin System

Aegisx-Agent uses a pluggy-based architecture. Community developers can write custom scanners without modifying core code.

### Custom Scanner Example

```python
# plugins/my_scanner.py
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.core.context import Finding, ScanContext, Severity

class MyCustomScanner(BaseScanner):
    name = "my_scanner"
    description = "My custom vulnerability scanner"

    async def validate_target(self) -> bool:
        return bool(self.config.target_url)

    async def scan(self) -> list[Finding]:
        findings = []
        # Your scanning logic here
        findings.append(Finding(
            title="Custom Finding",
            description="Found something interesting",
            severity=Severity.MEDIUM,
            cwe_id="CWE-000",
        ))
        return findings

# Register the plugin
def register(manager):
    manager.register_scanner("my_scanner", MyCustomScanner)
```

### Entry Point Registration

Third-party packages can register via `pyproject.toml`:

```toml
[project.entry-points."aegisx.scanners"]
my_scanner = "my_package.scanner:MyScanner"
```

---

## 🐳 Docker

```bash
# Build the image
docker build -t aegisx-agent .

# Run a scan
docker run --rm aegisx-agent scan https://example.com

# Run with report output
docker run --rm -v $(pwd)/reports:/app/reports aegisx-agent scan https://example.com --report all
```

---

## ⚙️ Configuration

### Environment Variables

All settings use the `AEGISX_` prefix:

```bash
# Scan Settings
AEGISX_SCAN_MODE=full
AEGISX_MAX_DEPTH=5
AEGISX_TIMEOUT_SECONDS=60
AEGISX_USER_AGENT=MyCustomAgent/1.0

# Exploit Settings
AEGISX_EXPLOIT_VERIFICATION=true
AEGISX_SANDBOX_ENABLED=true

# Reporting
AEGISX_REPORT_FORMAT=sarif
AEGISX_REPORT_OUTPUT=./reports/

# Logging
AEGISX_LOG_LEVEL=DEBUG
AEGISX_VERBOSE=true
```

See `.env.example` for the complete list.

### Configuration via Code

```python
from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.core.orchestrator import AegisxOrchestrator

config = AegisxConfig(
    target_url="https://example.com",
    scan_mode=ScanMode.FULL,
    exploit_verification=True,
    scope=["example.com", "api.example.com"],
)

orchestrator = AegisxOrchestrator(config)
stats = await orchestrator.run()
```

---

## 📊 Report Examples

### Markdown Report

```markdown
# 🛡️ Aegisx-Agent Security Assessment Report

## Executive Summary
⚠️ **Risk Level: HIGH**

A total of **6** security issue(s) were identified.

## 🟠 HIGH Findings (1)

### VF-96FDD70C: CORS Origin Reflection

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 7.4 |
| **CWE** | CWE-942 |
| **OWASP** | A05:2021 |

**Description:** The server reflects the attacker-controlled Origin header.
**Remediation:** Validate Origin against a whitelist before reflecting it.
```

### JSON Output (for CI/CD)

```json
{
  "scan_id": "a1b2c3d4e5f6",
  "target_url": "https://example.com",
  "stats": {
    "total_findings": 6,
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 2
  },
  "findings": [...]
}
```

### SARIF (GitHub Code Scanning)

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "Aegisx-Agent" } },
    "results": [...]
  }]
}
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=aegisx --cov-report=html

# Run specific test file
pytest tests/test_cvss.py -v

# Run tests matching a pattern
pytest -k "severity" -v
```

---

## 🛡️ Security Checks

| Check | CWE | OWASP | Severity |
|-------|-----|-------|----------|
| SQL Injection | CWE-89 | A03:2021 | Critical |
| Cross-Site Scripting (XSS) | CWE-79 | A03:2021 | High |
| CORS Misconfiguration | CWE-942 | A05:2021 | High |
| Missing Security Headers | CWE-319 | A05:2021 | Medium |
| Server Version Disclosure | CWE-200 | A05:2021 | Low |
| Exposed API Keys | CWE-798 | A07:2021 | Critical |
| Path Traversal | CWE-22 | A01:2021 | High |
| Debug Mode Enabled | CWE-215 | A05:2021 | Medium |
| Directory Listing | CWE-548 | A01:2021 | Medium |
| Vulnerable Libraries | CWE-1104 | A06:2021 | Varies |

---

## ⚠️ Legal Notice

**Only scan targets you have explicit authorization to test.**

Unauthorized scanning, penetration testing, or security assessment of systems you do not own or have written permission to test is **illegal** in most jurisdictions.

Aegisx-Agent includes:
- Authorization confirmation before full pentest mode
- Scope whitelist enforcement
- Rate limiting to prevent DoS
- Detailed audit logging

---

## 🗺️ Roadmap

- [x] Core engine with 3-phase pipeline
- [x] OWASP Top 10 web scanner
- [x] Secret detection scanner
- [x] Configuration audit scanner
- [x] Dependency scanner
- [x] CVSS v3.1 scoring engine
- [x] Markdown/JSON/SARIF reporters
- [x] Plugin architecture
- [x] CLI with Typer + Rich
- [x] Docker support
- [ ] **Exploit verification modules** (SQLi, XSS payload testing)
- [ ] **Network scanner** (port scanning, service enumeration)
- [ ] **HTML reporter** (interactive dashboard)
- [ ] **SSRF scanner** (server-side request forgery)
- [ ] **Auth scanner** (JWT, session, OAuth testing)
- [ ] **API scanner** (IDOR, mass assignment, rate limiting)
- [ ] **Continuous monitoring mode** (scheduled scans)
- [ ] **Slack/Discord notifications** (alert on findings)
- [ ] **GitHub Actions integration** (CI/CD security gates)
- [ ] **Web dashboard** (scan history, trend analysis)

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-scanner`)
3. **Commit** your changes (`git commit -m 'Add amazing scanner'`)
4. **Push** to the branch (`git push origin feature/amazing-scanner`)
5. **Open** a Pull Request

### Development Setup

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/

# Run tests
pytest -v
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [OWASP Top 10](https://owasp.org/Top10/) — Vulnerability taxonomy
- [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) — Severity scoring
- [CWE](https://cwe.mitre.org/) — Weakness enumeration
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversary tactics
- [Typer](https://typer.tiangolo.com/) — CLI framework
- [Rich](https://rich.readthedocs.io/) — Terminal formatting
- [Pydantic](https://docs.pydantic.dev/) — Settings management
- [pluggy](https://pluggy.readthedocs.io/) — Plugin system

---

<p align="center">
  <b>🛡️ Aegisx-Agent — Because security should be autonomous.</b>
</p>

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/FerzDevZ">FerzDevZ</a></sub>
</p>
