# Changelog

All notable changes to Aegisx-Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Agent session resume**: every agent iteration is atomically checkpointed to `~/.aegisx/sessions/<scan-id>.json`; interrupted runs (Ctrl-C, network loss) resume with `aegisx agent --continue <scan-id>` — message history, counters, and token usage are restored and no tool is re-executed. List saved sessions with `aegisx agent --continue list`
- **Streaming output**: `aegisx agent --stream` forwards content deltas to the terminal as the model generates them (`stream: true` SSE); the provider accumulates streamed tool-call fragments into complete calls and silently falls back to a plain request when the endpoint does not support SSE
- **Nudge eval scenario**: `truncation_nudge_recovery` added to the eval harness (now 5 scenarios) so the stub-answer nudge stays regression-tested
- `AEGISX_SESSIONS_DIR` env var to relocate the session store (tests are fully hermetic now)

- **AegisX Brain hardening batch (agent upgrades #1–#8)**:
  - **Secret redaction** (`ai/redaction.py`): AWS keys, OpenAI/Anthropic-style keys, GitHub tokens, JWTs, private key blocks (including truncated ones), DB connection strings, and generic key=value secrets are masked as `[REDACTED:<label>]` before any tool output reaches the LLM provider
  - **Retry with exponential backoff** in the provider: network errors, HTTP 429, and 5xx are retried (3 attempts, 1s→2s→4s); client errors (4xx) fail fast
  - **Transcript auto-save**: every agent run writes its full message transcript plus token/iteration stats to `reports/.audit/agent-transcript-*.json` for auditability
  - **Parallel tool execution**: multiple tool calls in one assistant turn run concurrently (`asyncio.gather`, capped at 4) with results paired back in protocol order
  - **Context digest on trim**: when the message history is trimmed, older tool results are folded into a `[CONTEXT DIGEST]` block instead of being dropped — the model retains what it learned
  - **Token meter**: prompt/completion/total token usage aggregated across the run and logged at the end
  - **New tool `compare_history`**: the agent can diff two previous scans (new/resolved findings + severity delta) without arguments, defaulting to the two most recent scans
  - **Agent eval harness** (`ai/evals.py`, `python -m aegisx.ai.evals`): 4 builtin scripted scenarios (full pipeline, scope-violation blocking, parallel tools, exploit consent gate) run through the real agent loop with a mock provider and are scored automatically — regression harness for prompts and models
  - `AEGISX_HISTORY_DB` env var to relocate the history database (also used to keep tests hermetic)
  - 21 new tests (total 255) + eval harness scenarios

- **AegisX Brain — AI agent layer** (`aegisx.ai` package):
  - `aegisx agent <url>` — autonomous AI pentest: the LLM plans recon, runs scanners, interprets findings, and writes the report via OpenAI-compatible tool calling
  - `aegisx ask "..."` — Q&A about the most recent scan history entry
  - `aegisx ai-config` — test AI endpoint connectivity and display resolved config
  - **Custom provider support**: any OpenAI-compatible base URL + API key + model (`AEGISX_AI_BASE_URL`, `AEGISX_AI_API_KEY`, `AEGISX_AI_MODEL`, or `--ai-base-url/--ai-api-key/--ai-model`)
  - Built-in presets: deepseek, openai, groq, openrouter, ollama (local)
  - 6 agent tools wrapping the scan engine: `run_recon`, `run_scanner`, `verify_exploit`, `get_findings`, `http_request`, `generate_report`
  - Robust response parser tolerating SSE framing, `data: [DONE]` sentinels, and concatenated JSON objects (non-standard gateways)
  - Safety rails enforced by the harness: scope enforcement, cloud-metadata blocking, exploit consent gate, iteration budget, redacted key logging
  - 22 new tests with fully mocked LLM traffic (no real AI endpoint in tests)
- **SQLite scan history**: Every scan recorded automatically; `aegisx history` CLI command with `--target`, `--limit`, `--export` options; scan-to-scan diffing via `compare_scans()`
- **SIEM export**: `--siem events.jsonl` flag on `scan` — flat event-per-finding JSON-lines for Splunk HEC / Elastic / Sentinel ingestion
- **Plugin development guide**: `docs/PLUGIN_DEVELOPMENT.md` with full scanner/exploit/reporter authoring walkthrough
- **CONTRIBUTING.md**: Development setup, dual-gate quality standards, commit conventions, PR process
- **Reporter tests**: 16 unit tests covering Markdown, JSON, SARIF, and HTML reporters
- **Pentest flow integration tests**: End-to-end pipeline tests (recon → scan → exploit → report) with mocked target
- **Scan history tests**: 12 tests for SQLite storage, filtering, diffing, and export
- **SIEM export tests**: 8 tests for event shape, severity normalization, and output formats
- **Docstrings**: Filled missing docstrings in secret scanner inner functions and all reporter `generate()` methods
- **`py.typed` marker**: Package now advertises inline type hints
- **`__all__` exports** in `scanners/__init__.py`

### Fixed
- **XSS in HTML report** (CVE-worthy): Finding data was embedded unescaped inside `<script>` JSON blocks — a malicious finding title like `<script>alert(1)</script>` could execute in the report viewer. Now escaped via `\u003c`/`\u003e`/`\u0026` JSON unicode escapes
- **SSL certificate date parsing**: `strptime` produced naive datetime causing `TypeError` when compared to aware `datetime.now(timezone.utc)` — certificate expiry checks now attach UTC tzinfo
- **Deprecated `datetime.utcnow()`** removed
- **Invalid ruff rule selector `SEC`** in pyproject.toml (renamed to `S` — flake8-bandit)
- **11 F821 undefined-name errors** (missing TYPE_CHECKING imports for `httpx`, `ScanStats`, `Finding`)
- **24 unused imports** removed (F401)
- **Duplicate exception handler** in DNS check (B025)

### Changed
- Test suite grew from 170 to **212 tests** (+42), all passing
- Lint clean: 0 errors on F/E/I/B025 rule families

## [0.1.2] - 2026-09-05

### Added
- **Shared HTTP client factory** (`utils/http_client.py`): eliminates 20+ duplicated `httpx.AsyncClient` setups across scanners/exploits; central proxy, rate-limit, timeout, and response-size configuration
- **Parallel secret scanning**: path checks use `asyncio.Semaphore(10)`, JS file scans `Semaphore(5)` — ~5x faster
- **Audit log**: Every scan writes a JSON audit entry under `reports/.audit/`
- **SSRF payload warning**: Explicit user consent warning when SSRF exploit targets cloud metadata endpoints
- **Progress bar**: Rich-based phase progress in the CLI
- **`--siem` groundwork**, `ScanHistory` planning

### Fixed
- Pre-existing test failures in `test_context.py` (finding ID length, set ordering)

## [0.1.1] - 2026-09-03

### Added
- **Proxy support**: Route all requests through Burp/ZAP with `--proxy` flag
- **Rate limiting**: Token bucket rate limiter prevents DoS on targets
- **Request size limit**: Max 5MB response by default (configurable)
- **Scan timeout per phase**: Phase 2 (scanning) times out after 300s
- **Scope enforcement**: Exploit modules now check `is_in_scope()` before testing
- **`__all__` exports**: Clean public API for `scanners/web/` package
- **CHANGELOG.md**: Track changes properly
- **GitHub Actions CI/CD**: Automated testing on push/PR

### Changed
- Fixed 29 bare `except Exception` handlers — now use specific exceptions
- Improved error logging across all scanners and exploits
- Updated banner with ASCII art "AEGISX" logo
- Bumped version to 0.1.1

### Fixed
- `install.sh`: Clean ALL old alias entries from `.bashrc` (was only removing marked entries)
- `install.sh`: Fix `cd` issue when installing from within AegisX-Agent directory
- `install.sh`: Fix `ModuleNotFoundError` by ensuring `pip install -e .` runs in correct directory

## [0.1.0] - 2026-09-02

### Added
- **Scanners**: web, secret, config, dependency, network (5 total)
- **Exploits**: SQLi, XSS, CSRF, SSRF (4 total)
- **Reporters**: Markdown, JSON, SARIF, HTML (4 total)
- **CLI**: `aegisx scan`, `aegisx pentest`, `aegisx plugins`, `aegisx info`
- **Plugin system**: pluggy-based architecture for community plugins
- **Async parallel crawling**: 10 concurrent pages, 5 concurrent injections
- **Rate limiter**: Token bucket for outgoing requests
- **WAF detection**: Detects challenge pages (Cloudflare, Vercel)
- **Scope enforcement**: Configurable domain whitelist
- **install.sh**: One-command installer with dependency checking

### Security
- All HTTP clients use `verify=False` by default (necessary for scanning)
- SSRF payloads tested with scope enforcement
- Target URL validation prevents `file://` and `javascript:` schemes
