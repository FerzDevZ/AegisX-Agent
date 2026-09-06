<p align="center">
  <img src="https://img.shields.io/badge/🛡️-Aegisx--Agent-v0.1.2-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-red" alt="OWASP">
  <img src="https://img.shields.io/badge/CVSS-v3.1-orange" alt="CVSS">
  <img src="https://img.shields.io/badge/tests-234%20passing-brightgreen?logo=pytest&logoColor=white" alt="Tests">
  <img src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?logo=githubactions&logoColor=white" alt="CI">
  <img src="https://img.shields.io/badge/Status-Alpha-purple" alt="Status">
</p>

<h1 align="center">🛡️ Aegisx-Agent</h1>

<h3 align="center">Autonomous AI-Powered Security Scanner</h3>

<p align="center">
  Bring your own LLM — Aegisx plans, scans, verifies, and reports.<br>
  A complete penetration-testing pipeline: 5 scanners, 4 exploit verifiers,<br>
  4 report formats, SQLite scan history, and SIEM-ready export.
</p>

---

## Why Aegisx-Agent

Most scanners stop at detection. Aegisx runs the full assessment loop:

1. **Reconnaissance** — fingerprint the stack before touching it.
2. **Scanning** — 5 specialized modules probe for 60+ weakness patterns.
3. **Verification** — exploit modules confirm findings are real, not false positives.
4. **Reporting** — Markdown, JSON, SARIF, and interactive HTML with CVSS v3.1 scoring.
5. **AI operation (optional)** — plug in any OpenAI-compatible LLM and the agent runs the assessment autonomously.

Everything runs locally. Every request is rate-limited and scope-checked. Scan history is persisted to SQLite so you can diff scans and verify fixes.

---

## ⚡ Features

| Capability | Details |
|---------|-------------|
| 🔍 **Web Scanner** | SQLi, XSS, path traversal injection; security headers; CORS; cookie flags; auth bypass; API endpoint discovery |
| 🔐 **Secret Scanner** | 19 patterns: AWS keys, GitHub tokens, OpenAI keys, Stripe live keys, private keys, DB connection strings, and more |
| ⚙️ **Config Scanner** | Debug mode leaks, default pages, directory listing, dangerous HTTP methods, server info disclosure, CORS misconfig |
| 📦 **Dependency Scanner** | Known-vulnerable JS library detection (jQuery, AngularJS, Bootstrap, Lodash) |
| 🌐 **Network Scanner** | TCP port scan (28 common ports), service fingerprinting, 18 dangerous-service checks, SSL certificate expiry |
| 💥 **Exploit Verification** | SQLi, XSS, CSRF, SSRF — verify findings are actually exploitable before you trust them |
| 📊 **Report Formats** | Markdown, JSON, SARIF v2.1.0 (GitHub Code Scanning), interactive HTML dashboard |
| 🎯 **CVSS v3.1** | Vector strings, base scores, severity buckets |
| 🧠 **Knowledge Base** | OWASP Top 10 2021 + CWE mappings + remediation guidance |
| 🤖 **AI Agent Mode** | Any OpenAI-compatible endpoint (custom base URL + key + model); the LLM plans and executes via tool calling |
| 📜 **Scan History** | SQLite persistence, target filtering, scan-to-scan diffing |
| 🏢 **SIEM Export** | One event per finding, JSON-lines for Splunk HEC / Elastic / Sentinel |
| 🔌 **Plugin System** | pluggy-based; add scanners, exploits, and reporters without touching core |
| 🛡️ **Safe by Default** | Scope whitelist, token-bucket rate limiting, response size caps, phase timeouts |

---

## 🚀 Quick Start

### One-Line Install

```bash
curl -sL https://raw.githubusercontent.com/FerzDevZ/AegisX-Agent/main/install.sh | bash
```

The installer:
- Verifies Python 3.12+, pip, git
- Clones the repo to `~/.aegisx`
- Creates an isolated virtualenv
- Installs the `aegisx` command
- Uninstalls cleanly with `install.sh --uninstall`

### Manual Installation

```bash
git clone https://github.com/FerzDevZ/AegisX-Agent.git
cd AegisX-Agent
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t aegisx-agent .
docker run --rm aegisx-agent scan https://example.com --report all
docker run --rm -v "$(pwd)/reports:/app/reports" aegisx-agent scan https://example.com --report all
```

### First Scan

```bash
aegisx scan https://example.com
```

Exit code reflects the worst finding: `0` clean, `1` high, `2` critical — wire it straight into CI.

---

## 📖 CLI Reference

```
aegisx scan        Scan a target for vulnerabilities
aegisx pentest     Full pentest with exploit verification (consent-gated)
aegisx agent       Autonomous AI-driven pentest (AegisX Brain)
aegisx ask         Ask the AI about the most recent scan
aegisx ai-config   Test AI endpoint connectivity and show resolved config
aegisx recon       Passive reconnaissance only
aegisx history     Show / export scan history
aegisx plugins     List registered scanners, exploits, reporters
aegisx info        Version and component info
```

### `aegisx scan` Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--mode` | `-m` | `passive` \| `quick` \| `full` \| `stealth` | `quick` |
| `--report` | `-r` | `markdown` \| `json` \| `sarif` \| `html` \| `all` | `markdown` |
| `--output` | `-o` | Report output directory | `reports/` |
| `--scope` | `-s` | Comma-separated domain whitelist | target domain only |
| `--depth` | `-d` | Max crawl depth (1–10) | `3` |
| `--rps` | | Max requests per second | `10.0` |
| `--exploit` | `-e` | Enable exploit verification | off |
| `--proxy` | `-p` | Route through Burp/ZAP (e.g. `http://127.0.0.1:8080`) | none |
| `--auth` | | Auth token for the target | none |
| `--user-agent` | `-ua` | Custom User-Agent | `AegisxAgent/x.y` |
| `--siem` | | Export SIEM JSON-lines events to a file | none |
| `--verbose` | `-v` | Verbose logging | off |

### Scan Modes

| Mode | Behavior | Speed |
|------|-------------|-------|
| `passive` | Recon + fingerprinting, no active probing | ⚡⚡⚡ |
| `quick` | Common vulnerability checks | ⚡⚡ |
| `full` | All scanners + exploit verification | ⚡ |
| `stealth` | Slow, low-profile probing | ⚡ |

---

## 🧠 AI Agent Mode (AegisX Brain)

Aegisx Brain is an agent loop in the DeepSeek-harness style: the LLM
decides *what to do next*, the harness decides *what is allowed*. The
model plans the assessment and calls tools; the harness enforces scope,
consent, and budget on every call.

```
┌──────────────────────────────────────────────────────────┐
│  YOUR LLM (custom base_url + api_key + model)            │
│  OpenAI · DeepSeek · Groq · OpenRouter · Ollama · ...    │
│                       ⇅ OpenAI-compatible tool calling   │
├──────────────────────────────────────────────────────────┤
│  AGENT LOOP (budget-capped, duplicate-damped)            │
│  pentest methodology prompt → tool calls → results → ... │
├──────────────────────────────────────────────────────────┤
│  TOOL REGISTRY (scope-enforced, consent-gated)           │
│  run_recon · run_scanner · verify_exploit                │
│  get_findings · http_request · generate_report           │
├──────────────────────────────────────────────────────────┤
│  SCAN ENGINE: 5 scanners · 4 exploits · 4 reporters      │
└──────────────────────────────────────────────────────────┘
```

### Setup (once)

Configure via environment (works from any directory):

```bash
# Global config lives at ~/.aegisx/.env — a .env in your project overrides it
export AEGISX_AI_BASE_URL="https://api.deepseek.com/v1"
export AEGISX_AI_API_KEY="sk-..."
export AEGISX_AI_MODEL="deepseek-chat"
```

Or per-run with flags:

```bash
aegisx agent https://example.com \
  --ai-base-url "https://api.deepseek.com/v1" \
  --ai-api-key "sk-..." \
  --ai-model "deepseek-chat"
```

Built-in presets — `custom` (default), `deepseek`, `openai`, `groq`, `openrouter`, `ollama` (local, free, no key):

```bash
aegisx agent https://example.com --ai-provider ollama
```

### Usage

```bash
# Verify connectivity and show the resolved config
aegisx ai-config

# Autonomous assessment: the AI reconnoiters, scans, interprets, reports
aegisx agent https://example.com

# Larger budget, exploit tools authorized
aegisx agent https://example.com --max-iterations 40 --exploit

# Q&A over the most recent scan (reads ~/.aegisx/history.db)
aegisx ask "which finding is the most urgent and how do I fix it?"
```

### Safety Rails

The harness — not the LLM — enforces these, and they are unit-tested:

| Guardrail | Behavior |
|-----------|----------|
| Scope enforcement | `http_request` and exploit tools reject URLs outside the whitelist |
| Metadata blocking | `169.254.169.254` and friends are always refused (SSRF self-targeting) |
| Consent gate | `verify_exploit` requires the `--exploit` flag |
| Iteration budget | `--max-iterations` (default 25) caps the loop |
| Duplicate damping | Repeated identical tool calls are cached, annotated, then blocked |
| Key hygiene | API keys are never logged in full |

---

## 🏗️ Architecture

```
src/aegisx/
├── core/                     # Engine
│   ├── orchestrator.py       #   3-phase pipeline: recon → scan → report
│   ├── config.py             #   Layered settings (env > .env > ~/.aegisx/.env)
│   ├── context.py            #   ScanContext, Finding, ScanStats
│   └── exceptions.py         #   Exception hierarchy
│
├── scanners/                 # Detection modules (BaseScanner)
│   ├── web_scanner.py        #   OWASP Top 10 orchestrator
│   ├── web/                  #   crawler · header · cookie · auth
│   │                         #   · api · param (SQLi/XSS/traversal)
│   ├── secret_scanner.py     #   19 credential patterns
│   ├── config_scanner.py     #   Misconfiguration checks
│   ├── dependency_scanner.py #   Vulnerable JS libraries
│   └── network_scanner.py    #   Ports, services, SSL/TLS
│
├── exploits/                 # Verification modules (BaseExploit)
│   ├── sqli_exploit.py       #   Error-based + boolean-based SQLi
│   ├── xss_exploit.py        #   Reflected XSS probing
│   ├── csrf_exploit.py       #   Missing-token CSRF checks
│   └── ssrf_exploit.py       #   Blind SSRF probes
│
├── reporters/                # Output modules (BaseReporter)
│   ├── markdown_reporter.py  #   Human-readable assessment
│   ├── json_reporter.py      #   Machine-readable
│   ├── sarif_reporter.py     #   SARIF v2.1.0 for GitHub
│   ├── html_reporter.py      #   Self-contained interactive dashboard
│   └── cvss.py               #   CVSS v3.1 scoring engine
│
├── ai/                       # AegisX Brain
│   ├── provider.py           #   OpenAI-compatible client (httpx, no SDK)
│   ├── tools.py              #   Tool schemas + scope-enforced dispatcher
│   ├── agent.py              #   Budget-capped tool-calling loop
│   └── prompts.py            #   Pentest methodology system prompt
│
├── knowledge/                # OWASP Top 10 + CWE mapping
├── plugins/                  # pluggy registry + entry-point loader
└── utils/                    # http_client (factory) · ratelimit
                              # history (SQLite) · siem_export · logger
```

### Three-Phase Pipeline

```
PHASE 1  RECON              → reachability, tech stack, headers
PHASE 2  SCAN (+ EXPLOIT)   → scanners in parallel → optional verification
PHASE 3  REPORT             → CVSS scoring → MD/JSON/SARIF/HTML → audit log
```

Each phase has a timeout; a hung scanner cannot hang the scan. Every
completed scan is appended to `~/.aegisx/history.db` and audited under
`reports/.audit/`.

---

## 📜 Scan History

Every scan lands in SQLite. Track trends and verify fixes across runs:

```bash
aegisx history                          # recent scans
aegisx history --target https://a.com   # filter by target
aegisx history --export history.json    # export everything
```

Programmatic diffing (what got fixed, what regressed):

```python
from aegisx.utils.history import ScanHistory

db = ScanHistory()
diff = db.compare_scans(old_scan_id, new_scan_id)

print(diff["new_findings"])      # regressions
print(diff["resolved_findings"]) # fixed since last scan
print(diff["severity_delta"])    # per-severity count changes
```

---

## 🏢 SIEM Integration

Export findings as flat, event-per-finding JSON-lines with ECS-style
fields (`event.*`, `vulnerability.*`, `url.*`):

```bash
aegisx scan https://example.com --siem events.jsonl
```

```json
{"event": {"kind": "alert", "severity": "critical", "dataset": "aegisx.findings"},
 "vulnerability": {"id": "VF-3F9A2C11", "title": "SQL Injection", "cwe": "CWE-89", "score": 9.8},
 "url": {"full": "https://example.com/search"}, "@timestamp": "2026-09-06T09:21:06+00:00"}
```

Ingest with Splunk HEC, Filebeat, or Azure Sentinel — one line, one event.

---

## 🔌 Plugin System

Community plugins register through entry points — no core changes:

```toml
# your package's pyproject.toml
[project.entry-points."aegisx.scanners"]
my_scanner = "my_package.scanner:MyScanner"
```

Minimal scanner:

```python
from aegisx.core.config import Severity
from aegisx.core.context import Finding
from aegisx.scanners.base_scanner import BaseScanner

class MyScanner(BaseScanner):
    name = "my_scanner"
    description = "Detects exposed debug endpoints"

    async def validate_target(self) -> bool:
        return True

    async def scan(self) -> list[Finding]:
        # create_client() gives you proxy, rate limiting, and timeouts for free
        from aegisx.utils.http_client import create_client

        findings: list[Finding] = []
        async with create_client(self.config) as client:
            for path in ("/debug", "/_debug/vars"):
                resp = await client.get(f"{self.config.target_url}{path}")
                if resp.status_code == 200:
                    findings.append(Finding(
                        title="Debug Endpoint Exposed",
                        description=f"{path} is publicly reachable.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-489",
                        url=f"{self.config.target_url}{path}",
                    ))
        return findings
```

Full walkthrough — including exploits and reporters — in
[docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md).

---

## ⚙️ Configuration

All settings use the `AEGISX_` prefix. Resolution order (highest wins):
CLI flags → environment variables → `./.env` → `~/.aegisx/.env`.

```bash
# Scan
AEGISX_SCAN_MODE=full
AEGISX_MAX_DEPTH=5
AEGISX_MAX_REQUESTS_PER_SECOND=10
AEGISX_TIMEOUT_SECONDS=30

# Auth & proxy
AEGISX_AUTH_TOKEN=your-token
AEGISX_PROXY=http://127.0.0.1:8080

# Reporting
AEGISX_REPORT_FORMAT=all
AEGISX_REPORT_OUTPUT=./reports/

# AI agent
AEGISX_AI_BASE_URL=https://api.deepseek.com/v1
AEGISX_AI_API_KEY=sk-...
AEGISX_AI_MODEL=deepseek-chat
AEGISX_AI_MAX_ITERATIONS=25
```

Python API:

```python
import asyncio
from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.core.orchestrator import AegisxOrchestrator

config = AegisxConfig(
    target_url="https://example.com",
    scan_mode=ScanMode.QUICK,
    scope=["example.com"],
)

stats = asyncio.run(AegisxOrchestrator(config).run())
print(stats.total_findings, stats.critical_count)
```

---

## 🧪 Testing

```bash
pytest -v                                  # 234 tests
pytest --cov=aegisx --cov-report=term      # with coverage
ruff check src tests                       # lint
mypy src/aegisx                            # types
```

All LLM and HTTP traffic is mocked (`respx`) — the suite never touches
the network. CI runs lint + typecheck + tests on Python 3.11/3.12 for
every push and PR.

---

## ⚠️ Legal Notice

**Only scan targets you have explicit authorization to test.**
Unauthorized scanning is illegal in most jurisdictions.

Aegisx-Agent is built to keep authorized work safe:

- Scope whitelist enforced on every request and tool call
- Cloud metadata endpoints always blocked (anti-SSRF self-targeting)
- Token-bucket rate limiting to avoid degrading the target
- Consent prompts before exploit verification
- JSON audit logs of every scan

---

## 🗺️ Roadmap

- [x] Core engine, 5 scanners, 4 exploit verifiers, 4 report formats
- [x] AI agent mode with bring-your-own LLM
- [x] Scan history + SIEM export + proxy support
- [x] GitHub Actions CI
- [ ] SSRF *detection* scanner (the exploit verifier already exists)
- [ ] Auth scanner (JWT, session, OAuth testing)
- [ ] Continuous monitoring (scheduled scans + diff alerts)
- [ ] Slack/Discord notifications
- [ ] Web dashboard

---

## 🤝 Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow. Short version:

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format src tests
pytest -v
```

Every feature needs at least one happy-path test and two edge-case
tests. Conventional Commits with emoji prefixes. Update
`CHANGELOG.md` under **Unreleased**.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 🙏 Acknowledgments

- [OWASP Top 10](https://owasp.org/Top10/) — vulnerability taxonomy
- [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) — severity scoring
- [CWE](https://cwe.mitre.org/) — weakness enumeration
- [Typer](https://typer.tiangolo.com/) · [Rich](https://rich.readthedocs.io/) · [Pydantic](https://docs.pydantic.dev/) · [pluggy](https://pluggy.readthedocs.io/) — foundations

---

<p align="center">
  <b>🛡️ Aegisx-Agent — Because security should be autonomous.</b>
</p>

<p align="center">
  <sub>Built by <a href="https://github.com/FerzDevZ">FerzDevZ</a></sub>
</p>
