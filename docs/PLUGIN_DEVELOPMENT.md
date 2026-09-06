# Plugin Development Guide

Aegisx-Agent uses [pluggy](https://pluggy.readthedocs.io/) for its plugin
system. There are three plugin types you can write:

| Type | Purpose | Base class |
|------|---------|-----------|
| **Scanner** | Discover vulnerabilities | `aegisx.scanners.base_scanner.BaseScanner` |
| **Exploit** | Verify a finding is exploitable | `aegisx.exploits.base_exploit.BaseExploit` |
| **Reporter** | Render findings in a new format | `aegisx.reporters.base_reporter.BaseReporter` |

---

## 1. Writing a Scanner

A scanner inspects a target and produces `Finding` objects.

```python
"""My custom security scanner."""
from __future__ import annotations

from aegisx.core.config import Severity
from aegisx.core.context import Finding
from aegisx.scanners.base_scanner import BaseScanner


class MyScanner(BaseScanner):
    """Detects example.com debug endpoints."""

    name = "my_scanner"                      # Unique plugin ID
    description = "Checks for debug endpoints"
    enabled_by_default = True                # Or opt-in via --scanners

    async def validate_target(self) -> bool:
        """Return False to skip this scanner for the current target."""
        return True

    async def scan(self) -> list[Finding]:
        """Do the actual scanning work and return findings."""
        findings: list[Finding] = []

        # Use the shared HTTP client — respects proxy, rate limit, timeouts
        from aegisx.utils.http_client import create_client

        async with create_client(self.config) as client:
            for path in ("/debug", "/_debug/vars"):
                url = f"{self.config.target_url}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and "debug" in resp.text.lower():
                        findings.append(Finding(
                            id="VF-MYDEBUG01",
                            title="Debug Endpoint Exposed",
                            description=f"Debug endpoint {path} is publicly accessible.",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cwe_id="CWE-489",
                            owasp_category="A05:2021",
                            url=url,
                            endpoint=path,
                            method="GET",
                            evidence=resp.text[:200],
                            remediation="Disable debug endpoints in production.",
                            references=["https://cwe.mitre.org/data/definitions/489.html"],
                        ))
                except Exception:
                    # Network errors must not crash the scan
                    continue

        return findings
```

### Key rules

- **Return findings, don't call the console** — the orchestrator handles
  logging via `self.context`.
- **Use `create_client(self.config)`** — you inherit proxy support, rate
  limiting, timeouts, and response-size limits for free.
- **Never raise** from `scan()` — catch `httpx.HTTPError` around each
  request. One bad request shouldn't kill the scan.
- **Respect `self.config.max_requests_per_second`** — the shared client
  does this automatically.

---

## 2. Writing an Exploit (Verification Module)

Exploits *verify* an existing finding — they confirm it's actually
exploitable, reducing false positives. They receive one `Finding` and
return an `ExploitResult`.

```python
from __future__ import annotations

from aegisx.core.context import ExploitResult, Finding
from aegisx.exploits.base_exploit import BaseExploit


class MyExploit(BaseExploit):
    name = "my_exploit"
    description = "Verifies debug endpoint exposure"

    async def verify(self, finding: Finding) -> ExploitResult:
        """Attempt safe verification. NEVER destructive."""
        from aegisx.utils.http_client import create_client

        async with create_client(self.config) as client:
            resp = await client.get(finding.url)
            success = resp.status_code == 200 and "debug" in resp.text.lower()

        return ExploitResult(
            finding_id=finding.id,
            exploit_name=self.name,
            success=success,
            payload=None,                     # Request body if applicable
            evidence=resp.text[:500] if success else None,
            notes="Read-only verification",
        )
```

### Safety requirements

- Exploits run **only** with `--exploit` / full pentest mode, after an
  authorization prompt.
- Requests are **scope-enforced** — URLs outside the target/scope are
  rejected automatically by `BaseExploit.run()`.
- Keep verification **read-only** where possible: no data destruction,
  no DoS, no persistence.

---

## 3. Writing a Reporter

Reporters turn a completed `ScanContext` into an output string.

```python
from aegisx.reporters.base_reporter import BaseReporter


class CSVReporter(BaseReporter):
    format_name = "csv"          # Referenced by --report csv
    file_extension = ".csv"

    def generate(self) -> str:
        lines = ["id,severity,title,url"]
        for f in self.context.findings:
            lines.append(f"{f.id},{f.severity.value},{f.title!r},{f.url}")
        return "\n".join(lines)
```

---

## 4. Registering Your Plugin

### Built-in (in this repository)

Register the class in `src/aegisx/core/orchestrator.py`:

```python
# Register scanners
from aegisx.scanners.my_scanner import MyScanner
self.plugin_manager.register_scanner(MyScanner.name, MyScanner)
```

### External (separate package)

Expose your plugin class via the `aegisx` entry-point group in your
package's `pyproject.toml`:

```toml
[project.entry-points.aegisx]
my_scanner = "my_package.scanner:MyScanner"
```

Aegisx-Agent loads entry-point plugins automatically at startup.

---

## 5. Testing Your Plugin

```python
import httpx
import pytest
import respx

from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.scanners.my_scanner import MyScanner


@pytest.fixture
def config():
    return AegisxConfig(
        target_url="https://test.example.com",
        scan_mode=ScanMode.QUICK,
        enabled_scanners=["my_scanner"],
    )


@respx.mock
@pytest.mark.asyncio
async def test_detects_debug_endpoint(config):
    respx.get("https://test.example.com/debug").mock(
        return_value=httpx.Response(200, text="debug mode active")
    )
    scanner = MyScanner(config)
    findings = await scanner.scan()
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


@respx.mock
@pytest.mark.asyncio
async def test_clean_target_no_findings(config):
    respx.get(url__regex=r"https://test\.example\.com/.*").mock(
        return_value=httpx.Response(404)
    )
    scanner = MyScanner(config)
    assert await scanner.scan() == []
```

Run your tests:

```bash
pytest tests/test_my_scanner.py -v
```

---

## Finding Data Model Cheat Sheet

| Field | Type | Notes |
|-------|------|-------|
| `id` | `str` | `VF-` + 8 hex chars, unique per finding |
| `severity` | `Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `cvss_score` | `float` | 0.0–10.0 (auto-computable via CVSS engine) |
| `cwe_id` | `str` | e.g. `"CWE-89"` |
| `owasp_category` | `str` | e.g. `"A03:2021"` |
| `url` / `endpoint` | `str` | Where the finding lives |
| `evidence` | `str` | Raw proof from the response |
| `payload` | `str` | Input that triggered it |
| `remediation` | `str` | How to fix it |
| `references` | `list[str]` | Links to advisories/CWE |

Questions? Open a GitHub issue with the `plugin` label.
