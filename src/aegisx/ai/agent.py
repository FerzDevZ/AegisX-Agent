"""AegisX Brain — the autonomous AI agent loop.

Implements the DeepSeek-harness style loop::

    system prompt → LLM → tool calls → harness executes → results → LLM → …

until the model stops calling tools, the iteration budget is spent, or a
fatal provider error occurs. The LLM decides *what* to do; the harness
decides *what is allowed* (scope, consent, budget).

Loop upgrades:
- Parallel tool execution when the model requests independent calls
- Summarizing history trim (old tool results folded into a digest, not dropped)
- Token usage accounting surfaced in the result
- Transcript auto-saved to ``reports/.audit/`` for every run
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisx.ai.prompts import BUDGET_WARNING, SYSTEM_PROMPT
from aegisx.ai.provider import AIProvider, AIProviderError
from aegisx.ai.tools import TOOL_SCHEMAS, ToolDispatcher
from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext
from aegisx.utils.logger import get_logger

logger = get_logger("ai.agent")

_MAX_TOOL_RESULT_CHARS = 4_000
_KEEP_RECENT_MESSAGES = 12
_MAX_PARALLEL_TOOLS = 4


@dataclass
class AgentResult:
    """Outcome of one autonomous agent run."""

    final_message: str = ""
    iterations_used: int = 0
    tool_calls_made: int = 0
    http_requests_made: int = 0
    stopped_reason: str = ""  # "done" | "budget" | "error"
    error: str = ""
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    transcript: list[dict[str, Any]] = field(default_factory=list)
    transcript_path: str = ""


class AegisxAgent:
    """Orchestrates the LLM tool-calling loop against the scan engine."""

    def __init__(self, config: AegisxConfig, context: ScanContext | None = None) -> None:
        """Create an agent for the configured target.

        Args:
            config: Scan + AI configuration.
            context: Reuse an existing scan context, or create a fresh one.
        """
        self.config = config
        self.context = context or ScanContext(config=config, target_url=config.target_url)
        self.provider = AIProvider(config)
        self.dispatcher = ToolDispatcher(config, self.context)
        self.messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Target: {config.target_url}\n"
                    f"Scope: {config.scope or 'target domain only'}\n"
                    f"Exploit verification authorized: {config.exploit_verification}\n"
                    "Begin your assessment."
                ),
            },
        ]
        self._dup_warned = False
        self._context_digest: str = ""

    async def run(self) -> AgentResult:
        """Execute the autonomous loop until done, budget-exhausted, or error."""
        result = AgentResult()
        max_iters = self.config.ai_max_iterations

        try:
            for iteration in range(1, max_iters + 1):
                result.iterations_used = iteration
                self._trim_history()

                # Warn the model as it approaches the budget
                if iteration == max_iters - 2:
                    self.messages.append({"role": "user", "content": BUDGET_WARNING})

                chat = await self.provider.chat(self.messages, tools=TOOL_SCHEMAS)
                result.tool_calls_made += len(chat.tool_calls)
                self._accumulate_usage(result, chat.usage)

                # No tool calls → the model is done; capture final answer
                if not chat.has_tool_calls:
                    result.final_message = chat.content or ""
                    result.stopped_reason = "done"
                    self._finalize(result)
                    return result

                # Assistant turn referencing every requested call (protocol order)
                self.messages.append(
                    {
                        "role": "assistant",
                        "content": chat.content or "",
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                                },
                            }
                            for tc in chat.tool_calls
                        ],
                    }
                )

                # Execute tool calls — in parallel when independent
                await self._execute_tool_calls(chat.tool_calls, result)

                # Track progress: repeated calls get an explicit nudge
                if self.dispatcher.last_call_was_duplicate and not self._dup_warned:
                    self._dup_warned = True
                    self.messages.append(
                        {
                            "role": "user",
                            "content": (
                                "You are repeating tool calls you already made. "
                                "All data is already in your context. Call a NEW "
                                "tool or produce your final summary now."
                            ),
                        }
                    )

            result.stopped_reason = "budget"
            result.final_message = await self._force_summary()
            self._finalize(result)
            return result

        except AIProviderError as exc:
            result.stopped_reason = "error"
            result.error = str(exc)
            logger.error("[bold red]AI ERROR[/] %s", exc)
            self._finalize(result)
            return result

    # --- tool execution ----------------------------------------------------

    async def _execute_tool_calls(self, tool_calls: list, result: AgentResult) -> None:
        """Run requested tools, in parallel when there are several.

        Results are appended in the SAME order as the tool_calls list —
        the OpenAI protocol pairs each tool message with its call id.
        """
        if len(tool_calls) == 1:
            outputs = [await self.dispatcher.execute(tool_calls[0].name, tool_calls[0].arguments)]
        else:
            batch = tool_calls[:_MAX_PARALLEL_TOOLS]
            logger.info("[bold blue]AGENT[/] running %d tools in parallel", len(batch))
            outputs = list(
                await asyncio.gather(
                    *(self.dispatcher.execute(tc.name, tc.arguments) for tc in batch)
                )
            )
            # Overflow beyond the parallel cap runs sequentially
            for tc in tool_calls[_MAX_PARALLEL_TOOLS:]:
                outputs.append(await self.dispatcher.execute(tc.name, tc.arguments))

        for tc, output in zip(tool_calls, outputs, strict=True):
            self.messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": output[:_MAX_TOOL_RESULT_CHARS],
                }
            )

    # --- context management ------------------------------------------------

    def _trim_history(self) -> None:
        """Bound the context window without losing key facts.

        Keeps system + initial user + most recent messages. Older tool
        outputs are folded into a one-line digest entry so the model
        retains a trace of what it already learned.
        """
        if len(self.messages) <= _KEEP_RECENT_MESSAGES + 2:
            return

        head = self.messages[:2]  # system + initial user
        overflow = self.messages[2:-_KEEP_RECENT_MESSAGES]
        tail = self.messages[-_KEEP_RECENT_MESSAGES:]

        # Extract one-line facts from overflowed tool/assistant messages
        facts: list[str] = []
        for msg in overflow:
            if msg.get("role") == "tool" and isinstance(msg.get("content"), str):
                content = msg["content"][:160].replace("\n", " ")
                facts.append(f"tool: {content}")
            elif msg.get("role") == "assistant" and msg.get("content"):
                facts.append(f"assistant: {str(msg['content'])[:120]}")

        if facts:
            self._context_digest = (
                (self._context_digest + "\n" if self._context_digest else "")
                + "\n".join(f"- {f}" for f in facts[-20:])
            )
            # Refresh (not append) the digest message right after the head
            digest_msg = {
                "role": "user",
                "content": (
                    "[CONTEXT DIGEST — earlier tool results, condensed]\n"
                    f"{self._context_digest}"
                ),
            }
            self.messages = head + [digest_msg] + tail
        else:
            self.messages = head + tail

        logger.debug("History trimmed; digest holds %d facts", len(facts))

    # --- accounting --------------------------------------------------------

    @staticmethod
    def _accumulate_usage(result: AgentResult, usage: dict[str, int]) -> None:
        """Sum per-call token usage into the run result."""
        result.prompt_tokens += int(usage.get("prompt_tokens", 0) or 0)
        result.completion_tokens += int(usage.get("completion_tokens", 0) or 0)
        result.total_tokens = result.prompt_tokens + result.completion_tokens

    def _finalize(self, result: AgentResult) -> None:
        """Attach transcript, persist it to the audit dir, log the meter."""
        result.transcript = list(self.messages)
        result.transcript_path = self._save_transcript(result)
        logger.info(
            "[bold blue]AGENT[/] tokens: %d prompt + %d completion = %d total",
            result.prompt_tokens,
            result.completion_tokens,
            result.total_tokens,
        )

    def _save_transcript(self, result: AgentResult) -> str:
        """Write the full message transcript to reports/.audit/ (best-effort)."""
        try:
            audit_dir = Path(self.config.report_output) / ".audit"
            audit_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            path = audit_dir / f"agent-transcript-{ts}-{self.context.scan_id[:8]}.json"
            path.write_text(
                json.dumps(
                    {
                        "scan_id": self.context.scan_id,
                        "target": self.config.target_url,
                        "model": self.provider.model,
                        "endpoint": self.provider.base_url,
                        "iterations": result.iterations_used,
                        "tool_calls": result.tool_calls_made,
                        "tokens": {
                            "prompt": result.prompt_tokens,
                            "completion": result.completion_tokens,
                            "total": result.total_tokens,
                        },
                        "stopped_reason": result.stopped_reason,
                        "messages": result.transcript,
                    },
                    ensure_ascii=False,
                    default=str,
                    indent=2,
                ),
                encoding="utf-8",
            )
            logger.debug("Agent transcript saved to %s", path)
            return str(path)
        except Exception as exc:  # noqa: BLE001 — audit writing is best-effort
            logger.debug("Transcript not saved: %s", exc)
            return ""

    async def _force_summary(self) -> str:
        """Ask the model for a wrap-up when the budget runs out mid-flow."""
        self.messages.append(
            {
                "role": "user",
                "content": "Iteration limit reached. Produce your final summary now.",
            }
        )
        try:
            chat = await self.provider.chat(self.messages, tools=None)
            return chat.content or "(no summary produced)"
        except AIProviderError:
            return "(summary failed — see logs)"
