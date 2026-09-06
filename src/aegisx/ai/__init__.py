"""AI agent layer for Aegisx-Agent (AegisX Brain).

Provider-agnostic LLM integration: bring your own OpenAI-compatible
endpoint (base URL + API key + model) and the agent drives the existing
scan engine autonomously.
"""

from aegisx.ai.agent import AegisxAgent, AgentResult
from aegisx.ai.provider import AIProvider, AIProviderError, ChatResult, ToolCall
from aegisx.ai.tools import TOOL_SCHEMAS, ToolDispatcher

__all__ = [
    "AegisxAgent",
    "AgentResult",
    "AIProvider",
    "AIProviderError",
    "ChatResult",
    "ToolCall",
    "ToolDispatcher",
    "TOOL_SCHEMAS",
]
