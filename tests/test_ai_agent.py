"""Tests for the AI agent layer (provider, tools, agent loop).

All LLM traffic is mocked via respx — no real AI endpoint is contacted.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from aegisx.ai.agent import AegisxAgent
from aegisx.ai.provider import AIProvider, AIProviderError
from aegisx.ai.tools import TOOL_SCHEMAS, ToolDispatcher
from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.core.context import ScanContext


def _config(**overrides) -> AegisxConfig:
    """Config pointing at a fake endpoint (mocked in tests)."""
    defaults = dict(
        target_url="https://test.example.com",
        scan_mode=ScanMode.QUICK,
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
) -> dict:
    """Build an OpenAI-compatible completion body."""
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"choices": [{"index": 0, "finish_reason": finish, "message": message}], "usage": {}}


def _mock_chat(body: dict, url: str = "http://ai.test/v1/chat/completions"):
    return respx.post(url).mock(return_value=httpx.Response(200, json=body))


class TestConfigResolution:
    def test_explicit_overrides_preset(self):
        c = _config(ai_provider="deepseek")
        base, key, model = c.resolve_ai_endpoint()
        assert base == "http://ai.test/v1"  # explicit wins over preset
        assert model == "test-model"

    def test_preset_used_when_no_override(self):
        c = AegisxConfig(target_url="https://x.com", ai_provider="groq", ai_api_key="k")
        base, _key, model = c.resolve_ai_endpoint()
        assert base == "https://api.groq.com/openai/v1"
        assert model == "llama-3.3-70b-versatile"

    def test_missing_base_url_raises(self):
        c = AegisxConfig(target_url="https://x.com", ai_provider="custom")
        with pytest.raises(ValueError, match="base URL"):
            c.resolve_ai_endpoint()

    def test_unknown_preset_raises(self):
        c = _config(ai_provider="not-a-thing")
        with pytest.raises(ValueError, match="Unknown AI provider"):
            c.resolve_ai_endpoint()

    def test_missing_model_raises(self):
        c = AegisxConfig(target_url="https://x.com", ai_base_url="http://x/v1", ai_model="")
        with pytest.raises(ValueError, match="model"):
            c.resolve_ai_endpoint()


class TestProviderParsing:
    """The endpoint parser must tolerate gateway quirks."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_plain_json(self):
        _mock_chat(_completion(content="hello"))
        p = AIProvider(_config())
        result = await p.chat([{"role": "user", "content": "hi"}])
        assert result.content == "hello"

    @respx.mock
    @pytest.mark.asyncio
    async def test_trailing_data_done_sentinel(self):
        # Some gateways append the SSE [DONE] sentinel to the JSON body
        body = json.dumps(_completion(content="ok")) + "data: [DONE]\n\n"
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(
                200, text=body, headers={"content-type": "text/event-stream"}
            )
        )
        p = AIProvider(_config())
        result = await p.chat([{"role": "user", "content": "hi"}])
        assert result.content == "ok"

    @respx.mock
    @pytest.mark.asyncio
    async def test_concatenated_json_objects(self):
        first = json.dumps(_completion(content="ok"))
        usage = json.dumps({"usage": {"total_tokens": 10}})
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(200, text=first + usage)
        )
        p = AIProvider(_config())
        result = await p.chat([{"role": "user", "content": "hi"}])
        assert result.content == "ok"

    @respx.mock
    @pytest.mark.asyncio
    async def test_tool_calls_parsed(self):
        body = _completion(
            tool_calls=[
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "run_recon", "arguments": "{}"},
                }
            ],
            finish="tool_calls",
        )
        _mock_chat(body)
        p = AIProvider(_config())
        result = await p.chat([{"role": "user", "content": "hi"}], tools=TOOL_SCHEMAS)
        assert result.has_tool_calls
        assert result.tool_calls[0].name == "run_recon"
        assert result.tool_calls[0].arguments == {}

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_401_raises(self):
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(401, json={"error": "bad key"})
        )
        p = AIProvider(_config())
        with pytest.raises(AIProviderError, match="401"):
            await p.chat([{"role": "user", "content": "hi"}])

    @respx.mock
    @pytest.mark.asyncio
    async def test_unreachable_raises(self):
        respx.post("http://ai.test/v1/chat/completions").mock(
            side_effect=httpx.ConnectError("no route")
        )
        p = AIProvider(_config())
        with pytest.raises(AIProviderError, match="Cannot reach"):
            await p.chat([{"role": "user", "content": "hi"}])

    def test_api_key_not_in_error(self):
        """Redaction helper must mask keys."""
        from aegisx.ai.provider import _redact

        assert "sk-test-key-123" not in _redact("sk-test-key-123")


class TestToolSchemas:
    def test_all_tools_have_names(self):
        for t in TOOL_SCHEMAS:
            assert t["type"] == "function"
            assert t["function"]["name"], "tool schema missing name"

    def test_expected_tool_set(self):
        names = {t["function"]["name"] for t in TOOL_SCHEMAS}
        assert names == {
            "run_recon",
            "run_scanner",
            "verify_exploit",
            "get_findings",
            "http_request",
            "generate_report",
        }


class TestScopeEnforcement:
    """The harness, not the LLM, decides what is reachable."""

    @pytest.mark.asyncio
    async def test_out_of_scope_blocked(self):
        config = _config()
        ctx = ScanContext(config=config, target_url=config.target_url)
        d = ToolDispatcher(config, ctx)
        output = await d.execute(
            "http_request", {"url": "https://evil.example.com/"}
        )
        data = json.loads(output)
        assert data.get("blocked") is True
        assert "scope" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_metadata_ip_blocked(self):
        config = _config()
        ctx = ScanContext(config=config, target_url=config.target_url)
        d = ToolDispatcher(config, ctx)
        output = await d.execute(
            "http_request", {"url": "http://169.254.169.254/latest/meta-data/"}
        )
        data = json.loads(output)
        assert data.get("blocked") is True

    @pytest.mark.asyncio
    async def test_unknown_tool_rejected(self):
        config = _config()
        ctx = ScanContext(config=config, target_url=config.target_url)
        d = ToolDispatcher(config, ctx)
        output = await d.execute("rm_rf_slash", {})
        assert "Unknown tool" in output

    @pytest.mark.asyncio
    async def test_exploit_requires_consent(self):
        config = _config(exploit_verification=False)
        ctx = ScanContext(config=config, target_url=config.target_url)
        ctx.add_finding = ctx.add_finding  # noqa: PLW0127
        from aegisx.core.context import Finding
        from aegisx.core.config import Severity

        f = Finding(
            id="VF-TEST0001",
            title="SQLi",
            description="x",
            severity=Severity.CRITICAL,
            cwe_id="CWE-89",
        )
        ctx.add_finding(f)
        d = ToolDispatcher(config, ctx)
        output = await d.execute("verify_exploit", {"finding_id": "VF-TEST0001"})
        assert "not authorized" in output


class TestAgentLoop:
    def _agent(self, config) -> AegisxAgent:
        return AegisxAgent(config)

    @respx.mock
    @pytest.mark.asyncio
    async def test_immediate_final_answer(self):
        _mock_chat(_completion(content="Nothing to do — target looks clean."))
        agent = self._agent(_config())
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert "clean" in result.final_message
        assert result.tool_calls_made == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_tool_then_finish(self):
        """Model calls one tool, gets a result, then produces the summary."""
        route = respx.post("http://ai.test/v1/chat/completions")
        route.side_effect = [
            httpx.Response(
                200,
                json=_completion(
                    tool_calls=[
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": "get_findings", "arguments": "{}"},
                        }
                    ],
                    finish="tool_calls",
                ),
            ),
            httpx.Response(200, json=_completion(content="No findings at all.")),
        ]
        agent = self._agent(_config())
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert result.tool_calls_made == 1
        assert "No findings" in result.final_message

    @respx.mock
    @pytest.mark.asyncio
    async def test_budget_exhaustion_stops(self):
        """Model insists on calling tools forever — loop must stop at budget."""
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json=_completion(
                    tool_calls=[
                        {
                            "id": "c",
                            "type": "function",
                            "function": {"name": "get_findings", "arguments": "{}"},
                        }
                    ],
                    finish="tool_calls",
                ),
            )
        )
        agent = self._agent(_config(ai_max_iterations=3))
        result = await agent.run()
        assert result.stopped_reason == "budget"
        assert result.iterations_used == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_provider_error_surfaces(self):
        respx.post("http://ai.test/v1/chat/completions").mock(
            side_effect=httpx.ConnectError("down")
        )
        agent = self._agent(_config())
        result = await agent.run()
        assert result.stopped_reason == "error"
        assert "Cannot reach" in result.error
