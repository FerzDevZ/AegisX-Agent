"""AegisX Brain — the autonomous AI agent loop.

Implements the DeepSeek-harness style loop::

    system prompt → LLM → tool calls → harness executes → results → LLM → …

until the model stops calling tools, the iteration budget is spent, or a
fatal provider error occurs. The LLM decides *what* to do; the harness
decides *what is allowed* (scope, consent, budget).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aegisx.ai.prompts import BUDGET_WARNING, SYSTEM_PROMPT
from aegisx.ai.provider import AIProvider, AIProviderError
from aegisx.ai.tools import TOOL_SCHEMAS, ToolDispatcher
from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext
from aegisx.utils.logger import get_logger

logger = get_logger("ai.agent")

# Tools whose results are summarized aggressively when trimming history
_MAX_TOOL_RESULT_CHARS = 4_000


@dataclass
class AgentResult:
    """Outcome of one autonomous agent run."""

    final_message: str = ""
    iterations_used: int = 0
    tool_calls_made: int = 0
    http_requests_made: int = 0
    stopped_reason: str = ""  # "done" | "budget" | "error"
    error: str = ""
    transcript: list[dict[str, Any]] = field(default_factory=list)


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

                # No tool calls → the model is done; capture final answer
                if not chat.has_tool_calls:
                    result.final_message = chat.content or ""
                    result.stopped_reason = "done"
                    return result

                # Assistant turn + one tool message per call (protocol order)
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
                for tc in chat.tool_calls:
                    logger.info("[bold blue]AGENT[/] tool=%s args=%s", tc.name, tc.arguments)
                    tool_output = await self.dispatcher.execute(tc.name, tc.arguments)
                    self.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": tool_output[:_MAX_TOOL_RESULT_CHARS],
                        }
                    )

                # Track progress: any fresh (non-duplicate) call = progress
                if self.dispatcher.last_call_was_duplicate and not getattr(
                    self, "_dup_warned", False
                ):
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
            return result

        except AIProviderError as exc:
            result.stopped_reason = "error"
            result.error = str(exc)
            logger.error("[bold red]AI ERROR[/] %s", exc)
            return result

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

    def _trim_history(self) -> None:
        """Keep the context window bounded: preserve system/first-user and
        the most recent 12 messages; summarize-drop older tool outputs."""
        keep_recent = 12
        if len(self.messages) <= keep_recent + 2:
            return
        head = self.messages[:2]  # system + initial user
        tail = self.messages[-keep_recent:]
        dropped = len(self.messages) - len(head) - len(tail)
        if dropped > 0:
            logger.debug("Trimmed %d old messages from agent history", dropped)
            self.messages = head + tail

    def _record_transcript(self, result: AgentResult) -> None:
        """Persist the message transcript onto the result (debug aid)."""
        result.transcript = list(self.messages)
