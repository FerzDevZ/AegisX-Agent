"""Tests for multi-model voting (VotingProvider + agent integration).

All LLM traffic is mocked via respx — no real AI endpoint is contacted.
The primary and peers share one endpoint URL, so routes are
distinguished by the ``model`` field in the request body.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from aegisx.ai.agent import AegisxAgent
from aegisx.ai.provider import AIProvider
from aegisx.ai.voting import VotingProvider, _extract_misssed_items
from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, ScanContext

URL = "http://ai.test/v1/chat/completions"


def _config(**overrides) -> AegisxConfig:
    defaults = dict(
        target_url="https://test.example.com",
        scope=["test.example.com"],
        ai_base_url="http://ai.test/v1",
        ai_api_key="key-123",
        ai_model="primary",
        timeout_seconds=5,
    )
    defaults.update(overrides)
    return AegisxConfig(**defaults)


def _completion(content: str | None = None, tool_calls: list[dict] | None = None) -> dict:
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _mock_by_model(
    responses: dict[str, dict | Exception],
    url: str = URL,
):
    """Route by request body ``model`` field (primary + peers share a URL)."""

    def _responder(request: httpx.Request) -> httpx.Response:
        model = json.loads(request.content.decode()).get("model", "")
        body = responses.get(model)
        if body is None:
            return httpx.Response(500, text=f"unexpected model {model}")
        if isinstance(body, Exception):
            raise body
        return httpx.Response(200, json=body)

    return respx.post(url).mock(side_effect=_responder)


def _context(config: AegisxConfig) -> ScanContext:
    ctx = ScanContext(config=config, target_url=config.target_url)
    ctx.findings.append(
        Finding(
            title="Missing security header",
            severity=__import__("aegisx.core.config", fromlist=["Severity"]).Severity.MEDIUM,
            url="https://test.example.com/",
            evidence="no CSP header",
        )
    )
    return ctx


class TestExtraction:
    def test_single_missed_line(self):
        assert _extract_misssed_items("MISSED: SQLi in /login — payload reflected") == [
            "SQLi in /login — payload reflected"
        ]

    def test_none_means_agreement(self):
        assert _extract_misssed_items("NONE") == []

    def test_multiple_lines(self):
        text = "MISSED: a\nsome noise\nMISSED: b\nMISSED:"  # bare 'MISSED:' dropped
        assert _extract_misssed_items(text) == ["a", "b"]

    def test_lowercase_prefix_accepted(self):
        assert _extract_misssed_items("missed: x") == ["x"]

    def test_preamble_and_trailer_ignored(self):
        text = "Sure, here are the gaps:\nMISSED: real finding\nHope this helps!"
        assert _extract_misssed_items(text) == ["real finding"]


class TestVotingProviderValidation:
    def test_empty_peer_list_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            VotingProvider(_config(), [])

    def test_primary_model_as_peer_rejected(self):
        with pytest.raises(ValueError, match="equals the primary"):
            VotingProvider(_config(), ["primary"])

    def test_duplicates_deduplicated(self):
        vp = VotingProvider(_config(), ["peer-a", "peer-a", "peer-b"])
        assert [p.model for p in vp.peers] == ["peer-a", "peer-b"]

    def test_duck_typed_surface(self):
        vp = VotingProvider(_config(), ["peer-a"])
        assert vp.model == "primary"
        assert vp.base_url == "http://ai.test/v1"


class TestReviewRound:
    @respx.mock
    @pytest.mark.asyncio
    async def test_all_agree(self):
        _mock_by_model(
            {
                "primary": _completion(content="unused"),
                "peer-1": _completion(content="NONE"),
                "peer-2": _completion(content="NONE"),
            }
        )
        config = _config()
        vp = VotingProvider(config, ["peer-1", "peer-2"])
        result = await vp.review_final_assessment(_context(config), "Clean report.")
        assert result.dissenting == []
        assert result.missed_items == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_dissent_extracted_and_tokenized(self):
        _mock_by_model(
            {
                "primary": _completion(content="unused"),
                "peer-1": _completion(
                    content="MISSED: Reflected XSS in /search?q\nMISSED: SSRF via fetch param"
                ),
                "peer-2": _completion(content="NONE"),
            }
        )
        config = _config()
        vp = VotingProvider(config, ["peer-1", "peer-2"])
        result = await vp.review_final_assessment(_context(config), "Clean report.")
        assert len(result.dissenting) == 1
        assert result.dissenting[0].model == "peer-1"
        assert len(result.missed_items) == 2
        # Token usage from peers is tracked for honest metering
        assert result.prompt_tokens > 0
        assert result.completion_tokens > 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_peer_failure_never_fails_review(self):
        _mock_by_model(
            {
                "primary": _completion(content="unused"),
                "peer-1": httpx.ConnectError("boom"),  # network error path
                "peer-2": _completion(content="NONE"),
            }
        )
        config = _config()
        vp = VotingProvider(config, ["peer-1", "peer-2"])
        result = await vp.review_final_assessment(_context(config), "Clean report.")
        assert result.dissenting == []
        assert "peer-1" in [v.model for v in result.verdicts]
        failed = [v for v in result.verdicts if v.error]
        assert len(failed) == 1 and failed[0].model == "peer-1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_checklist_noise_dropped(self):
        # > 5 items = generic checklist, not a concrete dissent
        spam = "\n".join(f"MISSED: generic item {i}" for i in range(8))
        _mock_by_model(
            {
                "primary": _completion(content="unused"),
                "peer-1": _completion(content=spam),
            }
        )
        config = _config()
        vp = VotingProvider(config, ["peer-1"])
        result = await vp.review_final_assessment(_context(config), "Clean report.")
        assert result.dissenting == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_evidence_sent_to_peer_is_redacted(self):
        captured: dict = {}

        def _peer_responder(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return httpx.Response(200, json=_completion(content="NONE"))

        respx.post(URL).mock(side_effect=_peer_responder)
        config = _config()
        ctx = _context(config)
        ctx.findings[0].evidence = "password=super-secret-value AKIAIOSFODNN7EXAMPLE"
        vp = VotingProvider(config, ["peer-1"])
        await vp.review_final_assessment(ctx, "report")
        body = captured["body"]
        assert "super-secret-value" not in body
        assert "AKIAIOSFODNN7EXAMPLE" not in body

    @respx.mock
    @pytest.mark.asyncio
    async def test_peers_never_see_primary_reasoning(self):
        captured: dict = {}

        def _peer_responder(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return httpx.Response(200, json=_completion(content="NONE"))

        respx.post(URL).mock(side_effect=_peer_responder)
        config = _config()
        vp = VotingProvider(config, ["peer-1"])
        await vp.review_final_assessment(_context(config), "report")
        body = captured["body"]
        assert '"tools"' not in body  # no tool-calling surface for peers
        assert "EVIDENCE" in body

    def test_health_check_lists_peers(self):
        # Health check requires a reachable endpoint; just verify wiring
        vp = VotingProvider(_config(), ["peer-1"])
        assert callable(vp.health_check)
        assert callable(vp.chat)


class TestAgentIntegration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_dissent_appended_to_final_message(self):
        _mock_by_model(
            {
                "primary": _completion(
                    content=(
                        "Assessment complete. One medium finding recorded. "
                        "No critical issues found on the target. "
                        "All checks concluded successfully."
                    )
                ),
                "peer-1": _completion(content="MISSED: SQL injection in /login"),
            }
        )
        config = _config(ai_vote_models=["peer-1"])
        agent = AegisxAgent(config, _context(config))
        assert isinstance(agent.provider, VotingProvider)
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert "Peer-Review Dissent" in result.final_message
        assert "SQL injection in /login" in result.final_message
        assert result.voting_result is not None
        assert len(result.voting_result.dissenting) == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_consensus_leaves_report_untouched(self):
        _mock_by_model(
            {
                "primary": _completion(
                    content=(
                        "Assessment complete. One medium finding recorded. "
                        "No critical issues found on the target. "
                        "All checks concluded successfully."
                    )
                ),
                "peer-1": _completion(content="NONE"),
            }
        )
        config = _config(ai_vote_models=["peer-1"])
        agent = AegisxAgent(config, _context(config))
        result = await agent.run()
        assert "Dissent" not in result.final_message
        assert result.voting_result is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_vote_models_uses_plain_provider(self):
        _mock_by_model(
            {
                "primary": _completion(
                    content=(
                        "Assessment complete. One medium finding recorded. "
                        "No critical issues found on the target. "
                        "All checks concluded successfully."
                    )
                ),
            }
        )
        config = _config()
        agent = AegisxAgent(config, _context(config))
        assert isinstance(agent.provider, AIProvider)
        result = await agent.run()
        assert result.stopped_reason == "done"
        assert result.voting_result is None
