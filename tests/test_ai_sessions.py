"""Tests for agent sessions (checkpoint/resume), streaming output, and the
truncation-nudge eval scenario."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from aegisx.ai.agent import AegisxAgent
from aegisx.ai.evals import BUILTIN_SCENARIOS, MockProvider, ScriptedStep
from aegisx.ai.provider import ChatResult, ToolCall
from aegisx.ai.sessions import AgentSessionState, SessionStore
from aegisx.core.config import AegisxConfig


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
) -> dict:
    """Build an OpenAI-compatible completion body."""
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"index": 0, "finish_reason": finish, "message": message}],
        "usage": {},
    }


# ---------------------------------------------------------------------------
# Session store basics
# ---------------------------------------------------------------------------


class TestSessionStore:
    def test_save_load_roundtrip(self, tmp_path):
        store = SessionStore(base_dir=tmp_path / "sessions")
        state = AgentSessionState(
            scan_id="abcd1234ffff",
            target_url="https://x.example.com",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
        )
        store.save(state)
        loaded = store.load("abcd1234ffff")
        assert loaded is not None
        assert loaded.target_url == "https://x.example.com"
        assert loaded.messages[0]["content"] == "hi"

    def test_load_missing_returns_none(self, tmp_path):
        store = SessionStore(base_dir=tmp_path / "sessions")
        assert store.load("nonexistent1") is None

    def test_load_corrupt_returns_none(self, tmp_path):
        store = SessionStore(base_dir=tmp_path / "sessions")
        (tmp_path / "sessions" / "corruptcafe.json").write_text("{not json")
        assert store.load("corruptcafe") is None

    def test_list_and_latest_and_delete(self, tmp_path):
        store = SessionStore(base_dir=tmp_path / "sessions")
        for i, sid in enumerate(["aaaa0001", "bbbb0002"]):
            store.save(
                AgentSessionState(
                    scan_id=sid,
                    target_url=f"https://{sid}.example.com",
                    status="done" if i else "running",
                )
            )
        rows = store.list_sessions()
        assert len(rows) == 2
        assert {r["scan_id"] for r in rows} == {"aaaa0001", "bbbb0002"}
        assert store.latest() is not None
        assert store.delete("aaaa0001") is True
        assert store.load("aaaa0001") is None
        assert store.delete("aaaa0001") is False


# ---------------------------------------------------------------------------
# Agent checkpointing + resume
# ---------------------------------------------------------------------------


class TestAgentCheckpoints:
    @respx.mock
    @pytest.mark.asyncio
    async def test_run_leaves_done_session(self, tmp_path):
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(200, json=_completion(content="x" * 250))
        )
        store = SessionStore(base_dir=tmp_path / "sessions")
        agent = AegisxAgent(_config())
        agent.session_store = store
        result = await agent.run()
        state = store.load(agent.context.scan_id)
        assert state is not None
        assert state.status == "done"
        assert state.iterations_used == result.iterations_used
        assert state.prompt_tokens == result.prompt_tokens

    @pytest.mark.asyncio
    async def test_resume_completes_interrupted_run(self, tmp_path):
        """A checkpointed mid-run session resumes without re-running tools."""
        store = SessionStore(base_dir=tmp_path / "sessions")

        # Craft an interrupted session: one tool call already executed
        marker = "SEED-TOOL-RESULT-7f3a"
        state = AgentSessionState(
            scan_id="resume0001",
            target_url="https://test.example.com",
            model="test-model",
            endpoint="http://ai.test/v1",
            iterations_used=1,
            tool_calls_made=1,
            prompt_tokens=500,
            completion_tokens=40,
            status="running",
            messages=[
                {"role": "system", "content": "system"},
                {"role": "user", "content": "Target: https://test.example.com"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": "get_findings", "arguments": "{}"},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "c1", "content": marker},
            ],
        )
        store.save(state)

        config = _config(ai_max_iterations=5)
        agent = AegisxAgent(config)
        agent.session_store = store
        # Mock provider: after resume, model produces the final summary
        agent.provider = MockProvider(
            [ScriptedStep(content="Resumed and finished: all clear." * 12)]
        )
        result = await agent.resume("resume0001")

        assert result.stopped_reason == "done"
        assert result.iterations_used == 2  # continued from 1
        assert result.tool_calls_made == 1  # NOT re-executed
        assert result.prompt_tokens == 600  # restored 500 + 100 from new turn
        # Pre-interrupt tool result still in context
        assert any(
            marker in str(m.get("content", ""))
            for m in result.transcript
            if m.get("role") == "tool"
        )
        # Session now terminal
        assert store.load("resume0001").status == "done"

    @pytest.mark.asyncio
    async def test_resume_unknown_session_raises(self, tmp_path):
        agent = AegisxAgent(_config())
        agent.session_store = SessionStore(base_dir=tmp_path / "sessions")
        with pytest.raises(ValueError, match="No such agent session"):
            await agent.resume("missing0000")

    @pytest.mark.asyncio
    async def test_resume_finished_session_raises(self, tmp_path):
        store = SessionStore(base_dir=tmp_path / "sessions")
        store.save(
            AgentSessionState(
                scan_id="finished01",
                target_url="https://test.example.com",
                status="done",
            )
        )
        agent = AegisxAgent(_config())
        agent.session_store = store
        with pytest.raises(ValueError, match="already finished"):
            await agent.resume("finished01")


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def _sse_body() -> str:
    """Build an SSE stream: content deltas, split tool call, usage, [DONE]."""
    chunks = [
        {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}, "finish_reason": None}]},
        {"choices": [{"index": 0, "delta": {"content": "lo world"}, "finish_reason": None}]},
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "get_fin", "arguments": ""},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ]
        },
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {"name": "dings", "arguments": '{"min_'},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ]
        },
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "function": {"arguments": 'severity": "high"}'}}
                        ]
                    },
                    "finish_reason": None,
                }
            ]
        },
        {
            "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
        },
        None,  # [DONE]
    ]
    lines = []
    for chunk in chunks:
        if chunk is None:
            lines.append("data: [DONE]\n\n")
        else:
            lines.append(f"data: {json.dumps(chunk)}\n\n")
    return "".join(lines)


class TestStreaming:
    @respx.mock
    @pytest.mark.asyncio
    async def test_chat_stream_parses_deltas_and_tool_fragments(self):
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(200, text=_sse_body())
        )
        provider = AIProviderForStream(_config())
        received: list[str] = []
        chat = await provider.chat_stream(
            [{"role": "user", "content": "hi"}],
            tools=None,
            on_delta=received.append,
        )
        assert chat is not None
        assert chat.content == "Hello world"
        assert "".join(received) == "Hello world"
        assert len(chat.tool_calls) == 1
        tc = chat.tool_calls[0]
        assert tc.name == "get_findings"  # fragments merged
        assert tc.arguments == {"min_severity": "high"}
        assert chat.usage["prompt_tokens"] == 11
        assert chat.finish_reason == "tool_calls"

    @respx.mock
    @pytest.mark.asyncio
    async def test_chat_stream_returns_none_on_http_error(self):
        respx.post("http://ai.test/v1/chat/completions").mock(
            return_value=httpx.Response(500, text="boom")
        )
        provider = AIProviderForStream(_config())
        chat = await provider.chat_stream([{"role": "user", "content": "hi"}])
        assert chat is None  # caller must fall back

    @pytest.mark.asyncio
    async def test_agent_streaming_receives_deltas_and_completes(self):
        """Agent with on_delta uses chat_stream; deltas arrive; run completes."""
        deltas: list[str] = []

        class StreamProvider:
            """Fake provider exposing both chat and chat_stream."""

            def __init__(self) -> None:
                self.model = "stream-model"
                self.base_url = "mock://stream"
                self._turn = 0

            async def chat(self, messages, tools=None):
                return ChatResult(
                    content="Final assessment complete." * 12,
                    usage={"prompt_tokens": 10, "completion_tokens": 5},
                )

            async def chat_stream(self, messages, tools=None, on_delta=None):
                piece = "Working on it... "
                if on_delta:
                    on_delta(piece)
                self._turn += 1
                if self._turn == 1:
                    return ChatResult(
                        tool_calls=[
                            ToolCall(id="c1", name="get_findings", arguments={})
                        ],
                        finish_reason="tool_calls",
                        usage={},
                    )
                return ChatResult(
                    content="Final assessment complete." * 12,
                    finish_reason="stop",
                    usage={"prompt_tokens": 10, "completion_tokens": 5},
                )

        agent = AegisxAgent(_config())
        agent.session_store = None
        agent.provider = StreamProvider()
        agent.on_delta = deltas.append
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert "Working on it" in "".join(deltas)

    @pytest.mark.asyncio
    async def test_agent_falls_back_when_stream_unsupported(self):
        """chat_stream returning None triggers exactly one plain retry."""

        class NoStreamProvider:
            def __init__(self) -> None:
                self.model = "m"
                self.base_url = "mock://x"
                self.stream_attempts = 0
                self.plain_calls = 0

            async def chat(self, messages, tools=None):
                self.plain_calls += 1
                return ChatResult(
                    content="Done: clean target summary." * 20,
                    usage={},
                )

            async def chat_stream(self, messages, tools=None, on_delta=None):
                self.stream_attempts += 1
                return None  # endpoint does not support streaming

        provider = NoStreamProvider()
        agent = AegisxAgent(_config())
        agent.session_store = None
        agent.provider = provider
        agent.on_delta = lambda piece: None
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert provider.stream_attempts == 1
        assert provider.plain_calls == 1
        assert agent.on_delta is None  # disabled after fallback


class AIProviderForStream:
    """Thin wrapper exposing the real AIProvider.chat_stream.

    Instantiating the real AIProvider resolves endpoint config; this test
    helper just forwards calls so the test reads cleanly.
    """

    def __init__(self, config: AegisxConfig) -> None:
        from aegisx.ai.provider import AIProvider

        self._impl = AIProvider(config)

    @property
    def model(self):
        return self._impl.model

    async def chat_stream(self, messages, tools=None, on_delta=None):
        return await self._impl.chat_stream(messages, tools=tools, on_delta=on_delta)


# ---------------------------------------------------------------------------
# Eval harness: nudge scenario registered
# ---------------------------------------------------------------------------


class TestNudgeEvalScenario:
    def test_nudge_scenario_registered(self):
        names = {s.name for s in BUILTIN_SCENARIOS}
        assert "truncation_nudge_recovery" in names

    @pytest.mark.asyncio
    async def test_nudge_scenario_passes(self):
        from aegisx.ai.evals import EvalRunner

        scenario = next(
            s for s in BUILTIN_SCENARIOS if s.name == "truncation_nudge_recovery"
        )
        result = await EvalRunner().run_scenario(scenario)
        assert result.passed, result.checks
