"""Tests for AI agent upgrades (#1–#8):

- #1 secret redaction
- #2 provider retry/backoff
- #3 transcript persistence
- #4 parallel tool execution
- #5 context digest on trim
- #6 token metering
- #7 compare_history tool
- #8 eval harness
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from aegisx.ai.agent import AegisxAgent
from aegisx.ai.evals import EvalRunner, MockProvider, ScriptedStep
from aegisx.ai.provider import AIProvider
from aegisx.ai.redaction import redact
from aegisx.ai.tools import TOOL_SCHEMAS, ToolDispatcher
from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext
from aegisx.utils.history import ScanHistory


def _config(**overrides) -> AegisxConfig:
    """Config pointing at a fake endpoint (mocked in tests)."""
    defaults = dict(
        target_url="https://test.example.com",
        enabled_scanners=["secret_scanner"],
        exploit_verification=False,
        ai_base_url="http://ai.test/v1",
        ai_api_key="sk-test-key-123",
        ai_model="test-model",
        timeout_seconds=5,
    )
    defaults.update(overrides)
    return AegisxConfig(**defaults)


def _completion(
    content: str | None = None,
    tool_calls: list[dict] | None = None,
    finish: str = "stop",
    usage: dict | None = None,
) -> dict:
    """Build an OpenAI-compatible completion body."""
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"index": 0, "finish_reason": finish, "message": message}],
        "usage": usage or {},
    }


def _tc(call_id: str, name: str, args: dict) -> dict:
    """One OpenAI tool_call entry."""
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


# ---------------------------------------------------------------------------
# #1 Redaction
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_aws_key_redacted(self):
        out = redact('evidence: AKIAIOSFODNN7EXAMPLE found')
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "REDACTED" in out

    def test_openai_key_redacted(self):
        out = redact("sk-proj-abcdefghij0123456789")
        assert "sk-proj-abcdefghij" not in out

    def test_github_token_redacted(self):
        out = redact("token ghp_AbCdEf123456789012345678901234567890")
        assert "ghp_AbCdEf" not in out

    def test_jwt_redacted(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        out = redact(f"Bearer {jwt}")
        assert "dozjgNryP4J3" not in out

    def test_private_key_block_redacted(self):
        out = redact("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...")
        assert "MIIEow" not in out

    def test_normal_content_untouched(self):
        text = '{"status": 200, "server": "nginx", "findings": []}'
        assert redact(text) == text

    def test_dispatcher_redacts_tool_output(self):
        """Tool output containing a secret is masked before reaching the LLM."""

        async def main():
            config = _config()
            context = ScanContext(config=config, target_url=config.target_url)
            dispatcher = ToolDispatcher(config, context)
            # Simulate a handler that leaks a secret
            dispatcher._tool_get_findings = lambda args: json.dumps(
                {"note": "leak AKIAIOSFODNN7EXAMPLE"}
            )
            return await dispatcher.execute("get_findings", {})

        import asyncio

        out = asyncio.run(main())
        assert "AKIAIOSFODNN7EXAMPLE" not in out


# ---------------------------------------------------------------------------
# #2 Retry / backoff
# ---------------------------------------------------------------------------


class TestProviderRetry:
    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_429_then_succeeds(self):
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            httpx.Response(429, json={"error": "rate limited"}),
            httpx.Response(200, json=_completion(content="recovered")),
        ]
        provider = AIProvider(_config())
        chat = await provider.chat([{"role": "user", "content": "hi"}], tools=None)
        assert chat.content == "recovered"
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_500_then_succeeds(self):
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            httpx.Response(500, text="boom"),
            httpx.Response(200, json=_completion(content="ok")),
        ]
        provider = AIProvider(_config())
        chat = await provider.chat([{"role": "user", "content": "hi"}], tools=None)
        assert chat.content == "ok"

    @respx.mock
    @pytest.mark.asyncio
    async def test_persistent_429_raises_provider_error(self):
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(429, json={"error": "still limited"})
        )
        from aegisx.ai.provider import AIProviderError

        provider = AIProvider(_config())
        with pytest.raises(AIProviderError):
            await provider.chat([{"role": "user", "content": "hi"}], tools=None)

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_retry_on_400(self):
        """Client errors (4xx other than 429) are not retried."""
        route = respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(400, json={"error": "bad request"})
        )
        from aegisx.ai.provider import AIProviderError

        provider = AIProvider(_config())
        with pytest.raises(AIProviderError):
            await provider.chat([{"role": "user", "content": "hi"}], tools=None)
        assert route.call_count == 1


# ---------------------------------------------------------------------------
# #3 Transcript, #5 digest, #6 token meter
# ---------------------------------------------------------------------------


class TestAgentPersistenceAndMetering:
    @respx.mock
    @pytest.mark.asyncio
    async def test_transcript_saved_to_audit_dir(self, tmp_path: Path):
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(200, json=_completion(content="done"))
        )
        config = _config(report_output=tmp_path)
        agent = AegisxAgent(config)
        result = await agent.run()
        assert result.transcript_path, "transcript path must be set"
        saved = Path(result.transcript_path)
        assert saved.exists()
        data = json.loads(saved.read_text())
        assert data["target"] == config.target_url
        assert data["model"] == "test-model"
        assert isinstance(data["messages"], list) and data["messages"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_stub_answer_gets_one_nudge(self):
        """A short no-tool answer triggers exactly one nudge, then the loop continues."""
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            # 1st call: model answers with a truncated stub, no tools
            httpx.Response(200, json=_completion(content="The user wants me to begin")),
            # 2nd call (after nudge): model starts working
            httpx.Response(
                200,
                json=_completion(
                    tool_calls=[_tc("c1", "run_recon", {})],
                    finish="tool_calls",
                ),
            ),
            # 3rd call: proper final summary (long enough)
            httpx.Response(
                200,
                json=_completion(
                    content="Assessment complete. " * 20,  # > 200 chars
                ),
            ),
        ]
        agent = AegisxAgent(_config())
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert result.tool_calls_made == 1
        assert route.call_count == 3
        # The nudge message must be present in the transcript
        assert any(
            "cut off" in str(m.get("content", ""))
            for m in result.transcript
            if m.get("role") == "user"
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_short_summary_after_work_is_accepted(self):
        """A short final answer AFTER doing work is a valid summary — no nudge."""
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            httpx.Response(
                200,
                json=_completion(
                    tool_calls=[_tc("c1", "get_findings", {})],
                    finish="tool_calls",
                ),
            ),
            httpx.Response(200, json=_completion(content="No findings.")),
        ]
        agent = AegisxAgent(_config())
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert result.final_message == "No findings."
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_token_meter_accumulates(self):
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            httpx.Response(
                200,
                json=_completion(
                    tool_calls=[_tc("c1", "get_findings", {})],
                    finish="tool_calls",
                    usage={"prompt_tokens": 100, "completion_tokens": 20},
                ),
            ),
            httpx.Response(
                200,
                json=_completion(
                    content="done",
                    usage={"prompt_tokens": 50, "completion_tokens": 10},
                ),
            ),
        ]
        agent = AegisxAgent(_config())
        result = await agent.run()
        assert result.prompt_tokens == 150
        assert result.completion_tokens == 30
        assert result.total_tokens == 180

    def test_trim_creates_digest(self):
        """Long histories fold old tool results into a digest, not drop them."""
        config = _config()
        agent = AegisxAgent(config)
        # Pad history beyond the keep-recent threshold
        agent.messages.append({"role": "user", "content": "Target: https://x.example.com"})
        for i in range(20):
            agent.messages.append(
                {
                    "role": "tool",
                    "tool_call_id": f"id-{i}",
                    "content": json.dumps({"iteration": i, "data": "x" * 50}),
                }
            )
        agent._trim_history()
        joined = json.dumps(agent.messages, ensure_ascii=False)
        assert "[CONTEXT DIGEST" in joined
        # Oldest facts must survive in digest form
        assert "iteration" in joined


# ---------------------------------------------------------------------------
# #4 Parallel tool execution
# ---------------------------------------------------------------------------


class TestParallelTools:
    @respx.mock
    @pytest.mark.asyncio
    async def test_parallel_calls_execute_and_pair(self):
        """Two tool calls in one turn both execute and pair with their ids."""
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            httpx.Response(
                200,
                json=_completion(
                    tool_calls=[
                        _tc("c1", "get_findings", {}),
                        _tc("c2", "compare_history", {}),
                    ],
                    finish="tool_calls",
                ),
            ),
            httpx.Response(200, json=_completion(content="both done")),
        ]
        agent = AegisxAgent(_config())
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert result.tool_calls_made == 2
        tool_msgs = [m for m in result.transcript if m.get("role") == "tool"]
        ids = {m["tool_call_id"] for m in tool_msgs}
        assert ids == {"c1", "c2"}


# ---------------------------------------------------------------------------
# #7 compare_history tool
# ---------------------------------------------------------------------------


class TestCompareHistoryTool:
    def test_schema_registered(self):
        names = [t["function"]["name"] for t in TOOL_SCHEMAS]
        assert "compare_history" in names

    @pytest.mark.asyncio
    async def test_compare_two_scans(self, tmp_path: Path, monkeypatch):
        db = tmp_path / "history.db"
        monkeypatch.setenv("AEGISX_HISTORY_DB", str(db))
        history = ScanHistory(db_path=db)
        from aegisx.core.context import ScanStats

        stats1 = ScanStats(
            total_findings=1,
            critical_count=0,
            high_count=1,
            medium_count=0,
            low_count=0,
            info_count=0,
            scan_duration_seconds=1.0,
            scanners_used=["web_scanner"],
        )
        stats2 = ScanStats(
            total_findings=2,
            critical_count=0,
            high_count=2,
            medium_count=0,
            low_count=0,
            info_count=0,
            scan_duration_seconds=2.0,
            scanners_used=["web_scanner"],
        )
        f = {
            "id": "VF-00000001",
            "title": "XSS",
            "severity": "high",
            "url": "https://test.example.com/",
            "endpoint": "/",
            "param": "q",
        }
        history.record_scan("oldscan0001", "https://test.example.com", "quick", stats1, [f])
        history.record_scan(
            "newscan0002",
            "https://test.example.com",
            "quick",
            stats2,
            [f, {**f, "id": "VF-00000002", "title": "SQLi"}],
        )

        config = _config()
        context = ScanContext(config=config, target_url=config.target_url)
        dispatcher = ToolDispatcher(config, context)
        out = await dispatcher.execute(
            "compare_history",
            {"old_scan_id": "oldscan0001", "new_scan_id": "newscan0002"},
        )
        data = json.loads(out)
        assert data["new_scan"] == "newscan0002"
        assert len(data["new_findings"]) == 1
        assert data["new_findings"][0]["title"] == "SQLi"

    @pytest.mark.asyncio
    async def test_compare_with_insufficient_history(self, tmp_path: Path, monkeypatch):
        """No history → graceful JSON error, never a crash."""
        # Point ScanHistory at an empty temp DB
        monkeypatch.setenv("HOME", str(tmp_path))
        config = _config()
        context = ScanContext(config=config, target_url=config.target_url)
        dispatcher = ToolDispatcher(config, context)
        out = await dispatcher.execute("compare_history", {})
        data = json.loads(out)
        assert "error" in data or "old_scan" in data  # either is acceptable
        assert not data.get("blocked")


# ---------------------------------------------------------------------------
# #8 Eval harness
# ---------------------------------------------------------------------------


class TestEvalHarness:
    @pytest.mark.asyncio
    async def test_all_builtin_scenarios_pass(self):
        report = await EvalRunner().run_all()
        assert report.passed, report.summary()
        assert report.score == 1.0
        assert len(report.results) >= 4

    @pytest.mark.asyncio
    async def test_mock_provider_script_exhaustion_ends_run(self):
        provider = MockProvider([ScriptedStep(tool_calls=[("get_findings", {})])])
        chat = await provider.chat([], tools=None)
        assert chat.has_tool_calls
        chat2 = await provider.chat([], tools=None)
        assert not chat2.has_tool_calls
        assert chat2.content

    @pytest.mark.asyncio
    async def test_scenario_scores_detect_missing_tool(self):
        """A scenario whose script never calls an expected tool must fail."""
        from aegisx.ai.evals import EvalScenario

        scenario = EvalScenario(
            name="never_calls_report",
            description="Script omits generate_report — must fail scoring",
            target_url="https://eval-miss.example.com",
            expect_tools_called=["generate_report"],
            script=[ScriptedStep(content="skipped everything")],
        )
        result = await EvalRunner().run_scenario(scenario)
        assert not result.passed
        assert not result.checks.get("called:generate_report", False)
