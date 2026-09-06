# Aegisx-Agent

[![CI](https://github.com/FerzDevZ/AegisX-Agent/actions/workflows/ci.yml/badge.svg)](https://github.com/FerzDevZ/AegisX-Agent/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-green)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-332%20passing-brightgreen)](#testing)

An autonomous security scanner for web applications, written in async Python.
It maps a target, probes it with seven scanner modules, verifies findings with
exploit modules, and writes scored reports — optionally driven end-to-end by
any OpenAI-compatible LLM you supply.

Everything runs on your machine. Every request passes a scope whitelist and a
token-bucket rate limiter before it leaves. No telemetry, no cloud component.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [How a scan works](#how-a-scan-works)
- [Scanners and exploits](#scanners-and-exploits)
- [AI agent mode](#ai-agent-mode)
- [Continuous monitoring](#continuous-monitoring)
- [Scan history and diffing](#scan-history-and-diffing)
- [SIEM export](#siem-export)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Python API](#python-api)
- [Architecture](#architecture)
- [Extending with plugins](#extending-with-plugins)
- [Testing](#testing)
- [Legal notice](#legal-notice)
- [Roadmap](#roadmap)

## Install

One line (installs to `~/.aegisx`, exposes the `aegisx` command):

```bash
curl -sL https://raw.githubusercontent.com/FerzDevZ/AegisX-Agent/main/install.sh | bash
```

Or manually:

```bash
git clone https://github.com/FerzDevZ/AegisX-Agent.git
cd AegisX-Agent
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Docker:

```bash
docker build -t aegisx-agent .
docker run --rm -v "$(pwd)/reports:/app/reports" aegisx-agent scan https://example.com --report all
```

## Quick start

```bash
# Fast scan of one target
aegisx scan https://example.com

# Everything: recon, all scanners, exploit verification, all report formats
aegisx pentest https://example.com

# Autonomous AI assessment (needs an LLM endpoint, see below)
aegisx agent https://example.com

# Re-scan every hour and ping Slack/Discord on new findings
aegisx monitor https://example.com --every 3600 --notify <webhook-url>
```

The `scan` exit code reflects the worst finding: `0` clean, `1` at least one
high, `2` at least one critical. A CI job that scans your staging site fails
when something serious ships.

## How a scan works

Four phases, each with its own timeout so a hung check cannot hang the run:

```
Phase 1  Recon       reachability, server fingerprint, response headers
Phase 2  Scan        all enabled scanners run concurrently
Phase 3  Exploit     (optional, consent-gated) verify findings are exploitable
Phase 4  Report      CVSS v3.1 scoring → Markdown / JSON / SARIF / HTML
```

Every completed scan is appended to `~/.aegisx/history.db` and audited under
`reports/.audit/`. The HTML report is a single self-contained file — open it
anywhere, no server needed.

## Scanners and exploits

Seven scanners are enabled by default (`aegisx plugins` lists them all):

| Scanner | What it checks |
|---|---|
| `web_scanner` | SQLi, XSS, and path-traversal injection (8 SQLi + 6 XSS payloads); security headers; CORS; cookie flags; auth bypass; API endpoint discovery |
| `secret_scanner` | 19 credential patterns: AWS keys, GitHub tokens, OpenAI keys, Stripe live keys, private keys, database connection strings |
| `config_scanner` | Debug mode leaks, default pages, directory listing, dangerous HTTP methods, server disclosure |
| `dependency_scanner` | Known-vulnerable JavaScript libraries (jQuery, AngularJS, Bootstrap, Lodash) |
| `network_scanner` | TCP scan of 28 common ports, service fingerprinting, dangerous-service checks, SSL certificate expiry |
| `ssrf_scanner` | URL-parameter discovery (40+ canonical names), open redirects (CWE-601), blind-SSRF reflections (CWE-918) |
| `auth_scanner` | JWT `alg=none` (CWE-347), missing/overlong expiry (CWE-613), sensitive claims (CWE-312), session IDs in URLs (CWE-598), OAuth missing `state` (CWE-352) and loose `redirect_uri` (CWE-601) |

Findings can be verified by four exploit modules — `sqli_exploit`,
`xss_exploit`, `csrf_exploit`, `ssrf_exploit` — so the report distinguishes
*confirmed* from *suspected*. Verification is gated behind an explicit
authorization prompt (`aegisx pentest`) or the `--exploit` flag.

Each finding carries a CVSS v3.1 vector and base score, a CWE identifier, an
OWASP Top 10 2021 category, evidence, and remediation guidance.

## AI agent mode

AegisX Brain is a tool-calling agent loop. The LLM decides what to do next;
the harness decides what is allowed. Scope, consent, budget, and redaction
are enforced in the harness — not promised in the prompt.

The agent ships with nine tools and an eight-step methodology
(recon → map → deep scan → SSRF probe → auth probe → review → verify →
report):

| Tool | Purpose |
|---|---|
| `run_recon` | Fingerprint the target |
| `run_scanner` | Run any subset of the seven scanners |
| `probe_ssrf` | Discover URL parameters and probe for redirects/SSRF |
| `probe_auth` | Mine JWTs/OAuth links and return decoded facts to reason about |
| `verify_exploit` | Confirm a finding is exploitable (consent-gated) |
| `http_request` | Send a scoped raw request for manual analysis |
| `get_findings` | Read the current finding set |
| `compare_history` | Diff two previous scans (new/resolved findings) |
| `generate_report` | Write the final report in any supported format |

### Setup

Any OpenAI-compatible endpoint works — DeepSeek, OpenAI, Groq, OpenRouter,
or a local Ollama. Configure once in `~/.aegisx/.env`:

```bash
export AEGISX_AI_BASE_URL="https://api.deepseek.com/v1"
export AEGISX_AI_API_KEY="sk-..."
export AEGISX_AI_MODEL="deepseek-chat"
```

Or per run:

```bash
aegisx agent https://example.com \
  --ai-base-url "https://api.deepseek.com/v1" \
  --ai-api-key "sk-..." \
  --ai-model "deepseek-chat"

# Local model, no key:
aegisx agent https://example.com --ai-provider ollama
```

### Usage

```bash
aegisx ai-config                       # verify connectivity, show resolved config
aegisx agent https://example.com       # autonomous assessment
aegisx agent ... --max-iterations 40 --exploit   # bigger budget + exploit tools
aegisx agent --continue list           # list checkpointed runs
aegisx agent --continue <scan-id>      # resume an interrupted run
aegisx agent ... --stream              # print model output as it generates
aegisx ask "which finding is most urgent?"       # Q&A over the last scan
```

### Enforced guardrails

| Guardrail | Behavior |
|---|---|
| Scope enforcement | Every tool call and probe request is checked against the whitelist; out-of-scope calls return `blocked: true` to the model |
| Metadata blocking | `169.254.169.254` and similar are always refused |
| Secret redaction | Tool output is scanned before it reaches the LLM: AWS keys, GitHub tokens, JWTs, private keys, DB strings, and generic `key=value` secrets are masked as `[REDACTED:<label>]` |
| Consent gate | `verify_exploit` refuses unless the run started with `--exploit` |
| Iteration budget | `--max-iterations` (default 25) caps the loop |
| Duplicate damping | Repeated identical tool calls are annotated and then blocked |
| Retry policy | Network errors, 429, and 5xx retry with backoff; 4xx fails fast |
| Key hygiene | API keys are never logged in full |

### Reliability and audit

- Interrupted runs checkpoint after every iteration (atomic writes) and resume
  without re-executing tools.
- `--stream` renders model output live; endpoints without SSE fall back
  automatically to plain requests.
- Multiple tool calls in one turn run concurrently (capped at 4), results
  paired in protocol order.
- Trimmed history is condensed into a `[CONTEXT DIGEST]` block instead of
  dropped, so the model keeps what it learned.
- Token usage (prompt/completion/total) is metered and logged per run.
- Full transcripts land in `reports/.audit/agent-transcript-*.json`.

### Evals

Eight scripted scenarios run through the real agent loop (real dispatcher,
real scope checks, mock provider) and are scored automatically:

```bash
python -m aegisx.ai.evals
```

```
✅ full_pipeline                 ✅ truncation_nudge_recovery
✅ scope_violation_blocked       ✅ ssrf_probing_flow
✅ parallel_tool_execution       ✅ auth_probing_flow
✅ exploit_requires_consent      ✅ ssrf_probe_scope_blocked
Score: 100% (8/8)
```

Any regression in the harness — including a leaked scope check — turns an
eval red.

## Continuous monitoring

`aegisx monitor` re-scans a target on an interval and alerts only on findings
that are new relative to the previous cycle, diffed through the history
database. The first cycle establishes a silent baseline, so you are never
spammed with the existing backlog. A failed cycle is logged and skipped; the
monitor keeps running.

```bash
# Hourly patrol with Slack/Discord alerts
aegisx monitor https://example.com --every 3600 \
  --notify https://hooks.slack.com/services/T000/B000/XXX

# Nightly full-mode patrol, capped at 30 cycles
aegisx monitor https://example.com --every 86400 --mode full --cycles 30

# Webhook from the environment
export AEGISX_NOTIFY_WEBHOOK=https://discord.com/api/webhooks/...
aegisx monitor https://example.com
```

One-shot scans can notify too:

```bash
aegisx scan https://example.com --notify <webhook-url>
```

Notification delivery is best-effort: a webhook failure is logged and never
fails the scan.

## Scan history and diffing

Every scan is persisted to SQLite. Compare two runs to see what changed:

```bash
aegisx history                          # recent scans
aegisx history --target https://a.com   # filter by target
aegisx history --export history.json    # export everything
```

```python
from aegisx.utils.history import ScanHistory

diff = ScanHistory().compare_scans(old_scan_id, new_scan_id)
print(diff["new_findings"])       # regressions
print(diff["resolved_findings"])  # fixed since last scan
print(diff["severity_delta"])     # per-severity count changes
```

The default database location can be moved with `AEGISX_HISTORY_DB`, the
session store with `AEGISX_SESSIONS_DIR`.

## SIEM export

Export one event per finding as JSON-lines with ECS-style fields:

```bash
aegisx scan https://example.com --siem events.jsonl
```

```json
{"event": {"kind": "alert", "severity": "critical", "dataset": "aegisx.findings"},
 "vulnerability": {"id": "VF-3F9A2C11", "title": "SQL Injection", "cwe": "CWE-89", "score": 9.8},
 "url": {"full": "https://example.com/search"},
 "@timestamp": "2026-09-06T09:21:06+00:00"}
```

Ingest with Splunk HEC, Filebeat, or Azure Sentinel.

## CLI reference

| Command | Purpose |
|---|---|
| `aegisx scan` | Scan a target |
| `aegisx pentest` | Full pipeline with exploit verification (consent prompt) |
| `aegisx agent` | Autonomous AI-driven assessment |
| `aegisx monitor` | Scheduled re-scans with new-finding alerts |
| `aegisx recon` | Passive reconnaissance only |
| `aegisx ask` | Ask the AI about the most recent scan |
| `aegisx ai-config` | Test the AI endpoint, show resolved config |
| `aegisx history` | Show, filter, or export scan history |
| `aegisx plugins` | List registered scanners, exploits, reporters |
| `aegisx info` | Version and component info |

### `aegisx scan` options

| Option | Short | Description | Default |
|---|---|---|---|
| `--mode` | `-m` | `passive` \| `quick` \| `full` \| `stealth` | `quick` |
| `--report` | `-r` | `markdown` \| `json` \| `sarif` \| `html` \| `all` | `markdown` |
| `--output` | `-o` | Report output directory | `reports/` |
| `--scope` | `-s` | Comma-separated domain whitelist | target domain only |
| `--depth` | `-d` | Max crawl depth (1–10) | `3` |
| `--rps` | | Max requests per second | `10.0` |
| `--exploit` | `-e` | Enable exploit verification | off |
| `--proxy` | `-p` | Route through Burp/ZAP | none |
| `--auth` | | Auth token for the target | none |
| `--user-agent` | `-ua` | Custom User-Agent | `AegisxAgent/x.y` |
| `--siem` | | Export SIEM JSON-lines to a file | none |
| `--notify` | | Webhook URL for the findings summary | `AEGISX_NOTIFY_WEBHOOK` |
| `--verbose` | `-v` | Verbose logging | off |

Scan modes: `passive` (recon only), `quick` (common checks), `full` (all
scanners + verification), `stealth` (slow, low-profile probing).

## Configuration

All settings use the `AEGISX_` prefix. Resolution order, highest wins:
CLI flags → environment variables → `./.env` → `~/.aegisx/.env`.

```bash
AEGISX_SCAN_MODE=full
AEGISX_MAX_DEPTH=5
AEGISX_MAX_REQUESTS_PER_SECOND=10
AEGISX_TIMEOUT_SECONDS=30
AEGISX_AUTH_TOKEN=your-token
AEGISX_PROXY=http://127.0.0.1:8080
AEGISX_REPORT_FORMAT=all
AEGISX_NOTIFY_WEBHOOK=https://hooks.slack.com/services/...

# AI agent
AEGISX_AI_BASE_URL=https://api.deepseek.com/v1
AEGISX_AI_API_KEY=sk-...
AEGISX_AI_MODEL=deepseek-chat
AEGISX_AI_MAX_ITERATIONS=25

# Relocation hooks (also keep the test suite hermetic)
AEGISX_HISTORY_DB=~/.aegisx/history.db
AEGISX_SESSIONS_DIR=~/.aegisx/sessions
```

## Python API

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

## Architecture

```
src/aegisx/
├── core/                     Engine
│   ├── orchestrator.py         phase pipeline: recon → scan → exploit → report
│   ├── config.py               layered settings (env > .env > ~/.aegisx/.env)
│   ├── context.py              ScanContext, Finding, ScanStats
│   └── exceptions.py           exception hierarchy
├── scanners/                 Detection (BaseScanner)
│   ├── web_scanner.py          OWASP Top 10 orchestrator
│   ├── web/                    crawler, header, cookie, auth, api, param modules
│   ├── secret_scanner.py       19 credential patterns
│   ├── config_scanner.py       misconfiguration checks
│   ├── dependency_scanner.py   vulnerable JS libraries
│   ├── ssrf_scanner.py         open redirect + blind SSRF
│   ├── auth_scanner.py         JWT, session, OAuth checks
│   └── network_scanner.py      ports, services, SSL/TLS
├── exploits/                 Verification (BaseExploit)
│   ├── sqli_exploit.py         error-based + boolean-based SQLi
│   ├── xss_exploit.py          reflected XSS
│   ├── csrf_exploit.py         missing-token CSRF
│   └── ssrf_exploit.py         blind SSRF
├── reporters/                Output (BaseReporter)
│   ├── markdown_reporter.py    human-readable assessment
│   ├── json_reporter.py        machine-readable
│   ├── sarif_reporter.py       SARIF 2.1.0 for GitHub Code Scanning
│   ├── html_reporter.py        self-contained interactive dashboard
│   └── cvss.py                 CVSS v3.1 scoring engine
├── ai/                       AegisX Brain
│   ├── provider.py             OpenAI-compatible client (httpx, no SDK)
│   ├── tools.py                tool schemas + scope-enforced dispatcher
│   ├── agent.py                budget-capped tool-calling loop
│   ├── prompts.py              pentest methodology system prompt
│   ├── sessions.py             checkpoint/resume store
│   ├── redaction.py            secret masking before LLM egress
│   └── evals.py                scripted agent scenarios
├── monitoring.py             interval re-scan + diff alerts
├── knowledge/                OWASP Top 10 + CWE mappings
├── plugins/                  pluggy registry + entry-point loader
└── utils/                    http_client, ratelimit, history,
                              siem_export, notify, logger
```

## Extending with plugins

Plugins register through entry points, no core changes needed:

```toml
[project.entry-points."aegisx.scanners"]
my_scanner = "my_package.scanner:MyScanner"
```

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

`create_client` inherits the proxy, rate limiter, and timeouts from the scan
config. Full walkthrough — exploits and reporters included — in
[docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md).

## Testing

```bash
pytest -v                                  # 332 tests
pytest --cov=aegisx --cov-report=term      # with coverage
ruff check src tests                       # lint
ruff format --check src tests              # format gate (same as CI)
mypy src/aegisx                            # types
python -m aegisx.ai.evals                  # agent scenarios, 8/8
```

All HTTP and LLM traffic is mocked with `respx` — the suite never touches the
network. CI runs lint, format check, type check, and the full suite on Python
3.11/3.12 for every push and pull request.

## Legal notice

Only scan targets you have explicit authorization to test. Unauthorized
scanning is illegal in most jurisdictions.

The tool keeps authorized work safe by default: scope whitelist enforced on
every request and tool call, cloud metadata endpoints always blocked,
token-bucket rate limiting, consent prompts before exploit verification, and
JSON audit logs of every run.

## Roadmap

- [x] Core engine, seven scanners, four exploit verifiers, four report formats
- [x] AI agent mode with bring-your-own LLM, nine tools, enforced guardrails
- [x] Agent session resume and streaming output
- [x] Agent eval harness (8 scenarios through the real loop)
- [x] SSRF and auth scanners (detection + probing + exploit verification)
- [x] Continuous monitoring with webhook notifications
- [x] SIEM export and scan-history diffing
- [ ] Web dashboard for history and trends
- [ ] Multi-model voting to reduce false negatives

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Short version:

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format src tests
pytest -v
```

Every feature ships with at least one happy-path test and two edge-case
tests. Conventional Commits with emoji prefixes. Update `CHANGELOG.md` under
**Unreleased**.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [OWASP Top 10](https://owasp.org/Top10/) — vulnerability taxonomy
- [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) — severity scoring
- [CWE](https://cwe.mitre.org/) — weakness enumeration
- [Typer](https://typer.tiangolo.com/), [Rich](https://rich.readthedocs.io/), [Pydantic](https://docs.pydantic.dev/), [pluggy](https://pluggy.readthedocs.io/) — foundations

Built by [FerzDevZ](https://github.com/FerzDevZ).
