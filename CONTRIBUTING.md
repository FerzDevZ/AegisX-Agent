# Contributing to Aegisx-Agent

Thanks for your interest in contributing! This document covers the
development workflow, code standards, and PR process.

## 🛠️ Development Setup

```bash
# Clone your fork
git clone https://github.com/<your-username>/AegisX-Agent.git
cd AegisX-Agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## ✅ Code Standards

All contributions must pass the **Dual-Gate** quality checks:

### Gate 1 — Static Analysis

```bash
# Lint (ruff)
ruff check src tests

# Format check
ruff format --check src tests

# Type check (mypy)
mypy src/aegisx
```

Rules:

- **No `any` types** — every public function is fully typed.
- **No bare `except:`** — catch specific exceptions and log them.
- **No `# TODO` placeholders** — unfinished code should not be merged.
- Line length ≤ 100 characters.

### Gate 2 — Behavioral Tests

```bash
# Run the full test suite
pytest -v

# With coverage
pytest --cov=aegisx --cov-report=term-missing
```

Requirements for new code:

- **Minimum 1 happy-path test** per feature.
- **Minimum 2 negative/edge-case tests** per feature.
- New scanners need unit tests using `respx` to mock HTTP traffic.
- Do **not** hit real external hosts in tests.

## 🔌 Writing a New Scanner

See [docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) for the full
guide. Quick checklist:

1. Create `src/aegisx/scanners/my_scanner.py` subclassing `BaseScanner`.
2. Set `name`, `description` class attributes.
3. Implement `validate_target()` and `scan()`.
4. Register the class in `src/aegisx/core/orchestrator.py`.
5. Add tests and update `README.md` + `CHANGELOG.md`.

## 📝 Commit Messages

Follow Conventional Commits with an emoji prefix:

```
✨ feat: add subdomain enumeration scanner
🐛 fix: prevent false positive on empty cookie headers
🧪 test: add integration tests for pentest flow
📝 docs: update CLI reference for --siem flag
♻️ refactor: extract shared HTTP client factory
```

## 🔄 Pull Request Process

1. Rebase onto `main` — keep history linear.
2. Ensure CI passes (lint, typecheck, tests run automatically).
3. Update `CHANGELOG.md` under the **Unreleased** section.
4. Update `README.md` if you added user-facing features.
5. One feature per PR — small, reviewable diffs merge faster.

## 🧭 Project Layout

```
src/aegisx/
├── cli.py              # Typer CLI commands
├── core/               # Config, context, orchestrator
├── scanners/           # Scanner plugins (web, secret, config, ...)
│   └── web/            # Web scanner sub-modules
├── exploits/           # Exploit verification modules
├── reporters/          # Markdown/JSON/SARIF/HTML report generators
├── plugins/            # pluggy plugin manager
└── utils/              # HTTP client, rate limiter, history, SIEM export
tests/                  # pytest suite (unit + integration)
```

## ⚖️ Legal

By contributing, you agree that your code may be used for authorized
security testing only. Never include live credentials, real API keys, or
personally identifiable scan data in commits.

## 🙋 Questions?

Open a [GitHub Issue](https://github.com/FerzDevZ/AegisX-Agent/issues)
with the `question` label.
