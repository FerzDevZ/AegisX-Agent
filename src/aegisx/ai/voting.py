"""Multi-model voting — peer review of the agent's final assessment.

False negatives are the quiet failure mode of single-model pentesting:
one model misses one finding and the report reads clean. Voting attacks
that by giving the primary model's final assessment to N peer models
and asking a single question: *what did it miss?*

Design (kept deliberately small):

- The primary model drives the whole tool-calling loop exactly as
  before — voting adds no cost to iteration, only to the end.
- When the primary finishes, each peer receives an independent,
  evidence-only review request (never the primary's reasoning) and
  returns candidate missed findings.
- A peer reply counts as dissent only when it names concrete
  vulnerability classes or endpoints that the primary's report does
  not already cover. Vague "maybe check X" replies are dropped.
- Peer failures (network, quota, malformed output) degrade to
  silence: a dead peer must never fail the run.

All peer-bound content passes through :mod:`aegisx.ai.redaction` —
the same guarantee as the main loop: no live credential ever leaves
the machine because of a review request.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from aegisx.ai.provider import AIProvider, AIProviderError, ChatResult
from aegisx.ai.redaction import redact
from aegisx.core.config import AegisxConfig
from aegisx.utils.logger import get_logger

logger = get_logger("ai.voting")

# A dissent mentioning more than this many distinct items is treated as
# noise (models that dump generic checklists) and dropped entirely.
_MAX_DISSENT_ITEMS = 5

_REVIEW_SYSTEM_PROMPT = (
    "You are an independent security reviewer cross-checking another "
    "AI pentester's final report. You receive the evidence gathered "
    "during the assessment (recon data, findings, pages discovered) "
    "and the final report. Your ONLY job: identify concrete findings "
    "the report MISSED. Rules:\n"
    "- Only report issues supported by the evidence shown, or probing "
    "steps the evidence clearly begs for and the report ignores.\n"
    "- Name the vulnerability class and the endpoint/parameter.\n"
    "- One item per line, prefixed 'MISSED:'. No preamble, no praise, "
    "no restating the report.\n"
    "- If nothing concrete is missing, reply exactly: NONE"
)


@dataclass
class PeerVerdict:
    """One peer model's review outcome."""

    model: str
    endpoint: str
    dissent: bool = False
    missed: list[str] = field(default_factory=list)
    error: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class VotingResult:
    """Aggregate outcome of the peer-review round."""

    verdicts: list[PeerVerdict] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def dissenting(self) -> list[PeerVerdict]:
        return [v for v in self.verdicts if v.dissent]

    @property
    def missed_items(self) -> list[str]:
        """Deduplicated missed items across dissenting peers."""
        seen: set[str] = set()
        items: list[str] = []
        for v in self.dissenting:
            for item in v.missed:
                key = item.strip().lower()
                if key and key not in seen:
                    seen.add(key)
                    items.append(item.strip())
        return items


def _extract_misssed_items(text: str) -> list[str]:
    """Pull 'MISSED:' lines out of a peer reply; None means agreement."""
    items: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("MISSED:") and len(stripped) > 8:
            item = stripped[7:].strip()
            if item:
                items.append(item)
    return items


class VotingProvider:
    """Wraps a primary provider with N peer reviewers.

    Duck-types the surface the agent loop needs (``chat``,
    ``chat_stream``, ``model``, ``base_url``, ``health_check``) so it
    slots in wherever :class:`AIProvider` is used. The loop itself is
    untouched; :meth:`review_final_assessment` is called by the agent
    once, when the primary model produces its final answer.
    """

    def __init__(self, config: AegisxConfig, peer_models: list[str]) -> None:
        """Build the primary provider plus one provider per peer model.

        Peers share the primary's endpoint and API key — the common
        setup is one gateway serving several models (OpenRouter,
        self-hosted vLLM, Ollama with multiple pulls).

        Raises:
            ValueError: If ``peer_models`` is empty or equals the
                primary model (voting against itself is meaningless).
        """
        unique = [m for m in dict.fromkeys(peer_models) if m and m.strip()]
        primary_model = config.resolve_ai_endpoint()[2]
        if not unique:
            raise ValueError("Vote models list is empty — nothing to vote with.")
        if primary_model in unique:
            raise ValueError(
                f"Vote model {primary_model!r} equals the primary model — "
                "peers must differ from the primary."
            )
        self.config = config
        self.primary = AIProvider(config)
        self.peers = [AIProvider(config.model_copy(update={"ai_model": m})) for m in unique]
        self.peer_models = unique

    # --- agent-loop surface (delegates to primary) -------------------------

    @property
    def model(self) -> str:
        return self.primary.model

    @property
    def base_url(self) -> str:
        return self.primary.base_url

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        return await self.primary.chat(messages, tools=tools)

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        on_delta: Any = None,
    ) -> ChatResult | None:
        return await self.primary.chat_stream(messages, tools=tools, on_delta=on_delta)

    async def health_check(self) -> tuple[bool, str]:
        ok, detail = await self.primary.health_check()
        if not ok:
            return ok, detail
        peer_states = []
        for peer in self.peers:
            peer_ok, peer_detail = await peer.health_check()
            peer_states.append(f"{peer.model}: {'ok' if peer_ok else peer_detail}")
        return ok, f"{detail}; peers: " + "; ".join(peer_states)

    # --- the actual voting --------------------------------------------------

    def build_evidence_digest(self, context: Any) -> str:
        """Summarize the scan context as redacted evidence for peers.

        Evidence-only by design: peers never see the primary's
        reasoning, tool calls, or transcript — independence is the
        whole point of voting.
        """
        findings = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "cwe": f.cwe_id,
                "url": f.url,
                "parameter": f.parameter,
                "evidence": f.evidence[:300],
            }
            for f in context.findings
        ]
        digest = {
            "target": context.target_url,
            "recon": {
                k: v
                for k, v in (context.target_info or {}).items()
                if isinstance(v, (str, int, float, bool, list))
            },
            "pages_discovered": list(context.crawl_urls)[:50],
            "findings": findings,
            "exploit_results": [
                {
                    "exploit": e.exploit_name,
                    "success": e.success,
                    "finding_id": e.finding_id,
                }
                for e in context.exploit_results
            ],
        }
        return redact(json.dumps(digest, ensure_ascii=False, default=str))

    async def _review_with_peer(
        self,
        peer: AIProvider,
        evidence: str,
        final_assessment: str,
    ) -> PeerVerdict:
        """Ask one peer what the assessment missed. Never raises."""
        verdict = PeerVerdict(model=peer.model, endpoint=peer.base_url)
        user_prompt = (
            f"EVIDENCE (redacted JSON):\n{evidence}\n\n"
            f"FINAL REPORT UNDER REVIEW:\n{redact(final_assessment)}\n\n"
            "List concrete missed findings, one 'MISSED:' line each, "
            "or reply NONE."
        )
        try:
            chat = await peer.chat(
                [
                    {"role": "system", "content": _REVIEW_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                tools=None,
            )
            verdict.prompt_tokens = int(chat.usage.get("prompt_tokens", 0) or 0)
            verdict.completion_tokens = int(chat.usage.get("completion_tokens", 0) or 0)
            text = (chat.content or "").strip()
            items = _extract_misssed_items(text)
            if not items:
                return verdict  # explicit NONE or chatty non-list reply = agreement
            if len(items) > _MAX_DISSENT_ITEMS:
                logger.info(
                    "PEER %s listed %d items — treated as generic checklist noise",
                    peer.model,
                    len(items),
                )
                return verdict
            verdict.dissent = True
            verdict.missed = items
        except AIProviderError as exc:
            verdict.error = str(exc)
            logger.warning("PEER %s review failed: %s", peer.model, exc)
        except Exception as exc:  # noqa: BLE001 — a bad peer must not fail the run
            verdict.error = f"{type(exc).__name__}: {exc}"
            logger.warning("PEER %s review crashed: %s", peer.model, verdict.error)
        return verdict

    async def review_final_assessment(
        self,
        context: Any,
        final_assessment: str,
    ) -> VotingResult:
        """Run all peer reviews concurrently and aggregate the verdicts."""
        evidence = self.build_evidence_digest(context)
        results = await asyncio.gather(
            *(self._review_with_peer(p, evidence, final_assessment) for p in self.peers)
        )
        voting = VotingResult(verdicts=list(results))
        for v in results:
            voting.prompt_tokens += v.prompt_tokens
            voting.completion_tokens += v.completion_tokens
        if voting.dissenting:
            logger.info(
                "VOTE %d/%d peers dissent: %s",
                len(voting.dissenting),
                len(self.peers),
                "; ".join(voting.missed_items[:3]),
            )
        else:
            logger.info(
                "VOTE %d/%d peers agree with the assessment",
                len(self.peers),
                len(self.peers),
            )
        return voting
