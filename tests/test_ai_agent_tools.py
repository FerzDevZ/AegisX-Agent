"""Tests for Batch 1 tools and spawn_agent orchestration.

Covers:
- store_note  — persistent scratchpad across context trims
- fuzz_param  — payload set + response diffing (observations only)
- diff_responses — blind-injection confirmation primitive
- enum_paths  — content discovery with concurrency cap
- lookup_cwe  — OWASP knowledge-base grounding
- spawn_agent — specialist sub-agent loops: toolset restriction, consent
  gate for the exploit specialty, recursion block, usage drain
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from aegisx.ai.agent import AegisxAgent
from aegisx.ai.evals import MockProvider, ScriptedStep
from aegisx.ai.tools import SPECIALTY_TOOLS, TOOL_SCHEMAS, ToolDispatcher
from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext

BASE = "https://test.example.com"


def _config(**overrides: Any) -> AegisxConfig:
    defaults = dict(
        target_url=BASE,
        enabled_scanners=["secret_scanner"],
        exploit_verification=False,
        timeout_seconds=5,
    )
    defaults.update(overrides)
    return AegisxConfig(**defaults)


def _dispatcher(config: AegisxConfig | None = None) -> ToolDispatcher:
    cfg = config or _config()
    ctx = ScanContext(config=cfg, target_url=cfg.target_url)
    return ToolDispatcher(cfg, ctx)


def _spawn_script(sub_tool: str, sub_args: dict[str, Any]) -> list[ScriptedStep]:
    """Script for one spawn_agent round trip through a shared provider.

    Turn 1: orchestrator spawns a specialist.
    Turn 2: sub-agent does its one tool call.
    Turn 3: sub-agent summarizes (its run ends).
    Turn 4: orchestrator summarizes (its run ends).
    """
    return [
        ScriptedStep(tool_calls=[("spawn_agent", {"specialty": "recon"})]),
        ScriptedStep(tool_calls=[(sub_tool, sub_args)]),
        ScriptedStep(content="Sub-agent done: attack surface mapped."),
        ScriptedStep(content="Orchestrator received the delegation result."),
    ]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TestToolSchemas:
    def test_batch1_tools_registered(self):
        names = [t["function"]["name"] for t in TOOL_SCHEMAS]
        for tool in ("store_note", "fuzz_param", "diff_responses", "enum_paths", "lookup_cwe"):
            assert tool in names

    def test_spawn_agent_schema_enum(self):
        schema = next(t for t in TOOL_SCHEMAS if t["function"]["name"] == "spawn_agent")
        enum = schema["function"]["parameters"]["properties"]["specialty"]["enum"]
        assert enum == ["recon", "vuln", "exploit"]

    def test_specialty_toolsets_shape(self):
        assert set(SPECIALTY_TOOLS) == {"recon", "vuln", "exploit"}
        for specialty, tools in SPECIALTY_TOOLS.items():
            assert "spawn_agent" not in tools, f"{specialty} must not spawn recursively"
        assert "verify_exploit" in SPECIALTY_TOOLS["exploit"]
        assert "verify_exploit" not in SPECIALTY_TOOLS["recon"]


# ---------------------------------------------------------------------------
# store_note
# ---------------------------------------------------------------------------


class TestStoreNote:
    @pytest.mark.asyncio
    async def test_note_saved_and_listed(self):
        d = _dispatcher()
        out = json.loads(await d.execute("store_note", {"note": "login page uses GET"}))
        assert out["saved"] is True
        assert out["total_notes"] == 1
        assert "login page uses GET" in out["notes"]

    @pytest.mark.asyncio
    async def test_notes_accumulate(self):
        d = _dispatcher()
        await d.execute("store_note", {"note": "one"})
        out = json.loads(await d.execute("store_note", {"note": "two"}))
        assert out["total_notes"] == 2
        assert out["notes"] == ["one", "two"]

    @pytest.mark.asyncio
    async def test_empty_note_rejected(self):
        d = _dispatcher()
        out = json.loads(await d.execute("store_note", {"note": "   "}))
        assert "error" in out

    @pytest.mark.asyncio
    async def test_note_truncated_at_500_chars(self):
        d = _dispatcher()
        await d.execute("store_note", {"note": "x" * 900})
        assert len(d.context.agent_notes[0]) == 500


# ---------------------------------------------------------------------------
# fuzz_param
# ---------------------------------------------------------------------------


class TestFuzzParam:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fuzz_reports_signals(self):
        # specific routes first — respx matches in registration order
        respx.get(
            path="/search",
            params__contains={"q": "' OR '1'='1"},
        ).mock(return_value=httpx.Response(500, text="Warning: mysql error near"))
        respx.get(f"{BASE}/search").mock(return_value=httpx.Response(200, text="ok"))
        d = _dispatcher()
        out = json.loads(await d.execute("fuzz_param", {"url": f"{BASE}/search?q=x", "param": "q"}))
        assert out["baseline"]["status"] == 200
        sqli = next(o for o in out["observations"] if o["payload_label"] == "sqli_or")
        assert "sql_error_string" in sqli["signals"]
        assert "status 200->500" in sqli["signals"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_fuzz_ssti_evaluated(self):
        respx.get(
            path="/page",
            params__contains={"tpl": "{{7*7}}"},
        ).mock(return_value=httpx.Response(200, text="result 49"))
        respx.get(f"{BASE}/page").mock(return_value=httpx.Response(200, text="plain"))
        d = _dispatcher()
        out = json.loads(
            await d.execute("fuzz_param", {"url": f"{BASE}/page?tpl=x", "param": "tpl"})
        )
        ssti = next(o for o in out["observations"] if o["payload_label"] == "ssti_jinja")
        assert "template_expression_evaluated" in ssti["signals"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_fuzz_traversal_signature(self):
        respx.get(
            path="/download",
            params__contains={"file": "../../../../etc/passwd"},
        ).mock(return_value=httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash"))
        respx.get(f"{BASE}/download").mock(return_value=httpx.Response(200, text="binary"))
        d = _dispatcher()
        out = json.loads(
            await d.execute("fuzz_param", {"url": f"{BASE}/download?file=a", "param": "file"})
        )
        trav = next(o for o in out["observations"] if o["payload_label"] == "traversal")
        assert "passwd_file_contents" in trav["signals"]

    @pytest.mark.asyncio
    async def test_fuzz_out_of_scope_blocked(self):
        d = _dispatcher()
        out = json.loads(
            await d.execute("fuzz_param", {"url": "https://evil.test/x", "param": "q"})
        )
        assert "Blocked" in out["error"]

    @pytest.mark.asyncio
    async def test_fuzz_missing_args(self):
        d = _dispatcher()
        out = json.loads(await d.execute("fuzz_param", {"url": f"{BASE}/x"}))
        assert "error" in out

    @pytest.mark.asyncio
    async def test_fuzz_does_not_register_findings(self):
        respx.mock()
        respx.get(host="test.example.com", path="/x").mock(
            return_value=httpx.Response(200, text="ok")
        )
        d = _dispatcher()
        await d.execute("fuzz_param", {"url": f"{BASE}/x?q=1", "param": "q"})
        assert d.context.findings == []


# ---------------------------------------------------------------------------
# diff_responses
# ---------------------------------------------------------------------------


class TestDiffResponses:
    @pytest.mark.asyncio
    @respx.mock
    async def test_identical_bodies_flagged(self):
        respx.get(f"{BASE}/a").mock(return_value=httpx.Response(200, text="same"))
        respx.get(f"{BASE}/b").mock(return_value=httpx.Response(200, text="same"))
        d = _dispatcher()
        out = json.loads(
            await d.execute("diff_responses", {"url_a": f"{BASE}/a", "url_b": f"{BASE}/b"})
        )
        assert out["same_body"] is True and out["same_status"] is True
        assert out["a"]["sha256"] == out["b"]["sha256"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_different_status_detected(self):
        respx.get(f"{BASE}/a").mock(return_value=httpx.Response(200, text="ok"))
        respx.get(f"{BASE}/b").mock(return_value=httpx.Response(500, text="boom"))
        d = _dispatcher()
        out = json.loads(
            await d.execute("diff_responses", {"url_a": f"{BASE}/a", "url_b": f"{BASE}/b"})
        )
        assert out["same_status"] is False
        assert out["b"]["status"] == 500

    @pytest.mark.asyncio
    async def test_out_of_scope_blocked(self):
        d = _dispatcher()
        out = json.loads(
            await d.execute("diff_responses", {"url_a": f"{BASE}/a", "url_b": "https://evil.test/"})
        )
        assert "Blocked" in out["error"]


# ---------------------------------------------------------------------------
# enum_paths
# ---------------------------------------------------------------------------


class TestEnumPaths:
    @pytest.mark.asyncio
    @respx.mock
    async def test_custom_paths_hits_and_misses(self):
        respx.head(f"{BASE}/admin").mock(return_value=httpx.Response(200))
        respx.head(f"{BASE}/missing").mock(return_value=httpx.Response(404))
        respx.head(f"{BASE}/blocked").mock(return_value=httpx.Response(403))
        d = _dispatcher()
        out = json.loads(
            await d.execute("enum_paths", {"paths": ["/admin", "/missing", "/blocked"]})
        )
        assert out["probed"] == 3
        paths = {h["path"] for h in out["hits"]}
        assert paths == {"/admin", "/blocked"}  # 404 filtered, 403 kept

    @pytest.mark.asyncio
    @respx.mock
    async def test_dead_paths_are_misses_not_errors(self):
        respx.head(f"{BASE}/dead").mock(side_effect=httpx.ConnectError("down"))
        d = _dispatcher()
        out = json.loads(await d.execute("enum_paths", {"paths": ["/dead"]}))
        assert out["hits"] == [] and out["probed"] == 1

    @pytest.mark.asyncio
    async def test_invalid_paths_filtered(self):
        d = _dispatcher()
        out = json.loads(await d.execute("enum_paths", {"paths": ["no-slash", "/ok", "", "/x"]}))
        assert out["probed"] == 2

    @pytest.mark.asyncio
    async def test_out_of_scope_path_blocked(self):
        d = _dispatcher()
        out = json.loads(await d.execute("enum_paths", {"paths": ["/ok"]}))
        # default origin comes from config.target_url (test.example.com) — fine;
        # a path can't leave scope, so this must succeed
        assert "probed" in out


# ---------------------------------------------------------------------------
# lookup_cwe
# ---------------------------------------------------------------------------


class TestLookupCwe:
    @pytest.mark.asyncio
    async def test_lookup_by_cwe(self):
        d = _dispatcher()
        out = json.loads(await d.execute("lookup_cwe", {"query": "CWE-89"}))
        assert out["query"] == "CWE-89"
        assert "owasp" in out and "remediation" in out

    @pytest.mark.asyncio
    async def test_lookup_by_owasp_code(self):
        d = _dispatcher()
        out = json.loads(await d.execute("lookup_cwe", {"query": "a03"}))
        assert out["query"] == "A03"

    @pytest.mark.asyncio
    async def test_unknown_query_returns_error(self):
        d = _dispatcher()
        out = json.loads(await d.execute("lookup_cwe", {"query": "CWE-99999999"}))
        assert "error" in out


# ---------------------------------------------------------------------------
# spawn_agent
# ---------------------------------------------------------------------------


class TestSpawnAgentGuards:
    @pytest.mark.asyncio
    async def test_unknown_specialty(self):
        d = _dispatcher()
        out = json.loads(await d.execute("spawn_agent", {"specialty": "crypto"}))
        assert "error" in out and "Valid" in out["error"]

    @pytest.mark.asyncio
    async def test_exploit_specialty_requires_consent(self):
        d = _dispatcher(_config(exploit_verification=False))
        out = json.loads(await d.execute("spawn_agent", {"specialty": "exploit"}))
        assert "requires --exploit" in out["error"]

    @pytest.mark.asyncio
    async def test_exploit_specialty_allowed_with_consent(self):
        d = _dispatcher(_config(exploit_verification=True))
        # No orchestrator attached in this bare test — recursion/owner guard fires first.
        out = json.loads(await d.execute("spawn_agent", {"specialty": "exploit"}))
        assert "no orchestrator" in out["error"]

    @pytest.mark.asyncio
    async def test_no_orchestrator_attached(self):
        d = _dispatcher()
        out = json.loads(await d.execute("spawn_agent", {"specialty": "recon"}))
        assert "no orchestrator" in out["error"]

    @pytest.mark.asyncio
    async def test_budget_clamped(self):
        cfg = _config()
        ctx = ScanContext(config=cfg, target_url=cfg.target_url)
        d = ToolDispatcher(cfg, ctx)

        seen_budgets: list[int] = []

        class FakeAgent:
            def __init__(self, _cfg, **kwargs: Any) -> None:
                seen_budgets.append(kwargs["max_iterations"])
                self.messages = [{"role": "user", "content": "x"}]
                self.session_store = None

            async def run(self):  # minimal duck-typed AgentResult
                from aegisx.ai.agent import AgentResult

                return AgentResult(
                    final_message="done",
                    iterations_used=1,
                    tool_calls_made=0,
                    prompt_tokens=10,
                    completion_tokens=5,
                    stopped_reason="done",
                )

        from types import SimpleNamespace

        import aegisx.ai.agent as agent_mod

        original = agent_mod.AegisxAgent
        agent_mod.AegisxAgent = FakeAgent  # type: ignore[misc]
        d.owner = SimpleNamespace(provider=object())  # provider without .primary
        try:
            await d.execute("spawn_agent", {"specialty": "recon", "max_iterations": 999})
        finally:
            agent_mod.AegisxAgent = original
        assert seen_budgets == [12]  # clamped to the cap


class TestSpawnAgentEndToEnd:
    @pytest.mark.asyncio
    async def test_recon_delegation_shares_context_and_drains_usage(self):
        cfg = _config()
        ctx = ScanContext(config=cfg, target_url=cfg.target_url)
        provider = MockProvider(_spawn_script("run_recon", {}))
        agent = AegisxAgent(cfg, context=ctx, provider=provider)
        result = await agent.run()

        assert result.stopped_reason == "done"
        # Sub-agent summary came back through the tool result
        assert any("Sub-agent done" in str(m.get("content", "")) for m in agent.messages)
        # Sub-agent tokens drained into the parent's totals (4 scripted turns)
        assert result.prompt_tokens == 4 * 100

    @pytest.mark.asyncio
    async def test_allowed_tools_restriction_enforced(self):
        """The restriction mechanism itself: a recon toolset must not reach
        exploit tools. (End-to-end sub-agent message flow is covered by the
        eval scenarios — tool results live in the sub-agent's own history.)"""
        d = _dispatcher(_config(exploit_verification=True))
        out = json.loads(
            await d.execute(
                "verify_exploit",
                {"finding_id": "VF-00000001"},
                allowed_tools=SPECIALTY_TOOLS["recon"],
            )
        )
        assert out["blocked"] is True
        assert "not available" in out["error"]

    @pytest.mark.asyncio
    async def test_orchestrator_unrestricted(self):
        """allowed_tools=None (orchestrator) reaches every tool."""
        d = _dispatcher()
        out = json.loads(await d.execute("verify_exploit", {"finding_id": "VF-1"}))
        assert "blocked" not in out  # got past the restriction check

    @pytest.mark.asyncio
    async def test_exploit_specialty_with_consent_runs(self):
        cfg = _config(exploit_verification=True)
        ctx = ScanContext(config=cfg, target_url=cfg.target_url)
        provider = MockProvider(
            [
                ScriptedStep(tool_calls=[("spawn_agent", {"specialty": "exploit"})]),
                ScriptedStep(content="Nothing to verify yet."),
                ScriptedStep(content="Orchestrator done."),
            ]
        )
        agent = AegisxAgent(cfg, context=ctx, provider=provider)
        result = await agent.run()
        assert result.stopped_reason == "done"

    @pytest.mark.asyncio
    async def test_recursion_blocked_at_depth_one(self):
        """spawn_depth >= 1 (inside a sub-agent) must refuse further spawns."""
        d = _dispatcher()
        d.owner = object()
        d.spawn_depth = 1
        out = json.loads(await d.execute("spawn_agent", {"specialty": "recon"}))
        assert "cannot spawn further agents" in out["error"]
