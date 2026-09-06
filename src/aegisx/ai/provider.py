"""AI provider layer — OpenAI-compatible chat completions client.

Talks to ANY OpenAI-compatible endpoint (DeepSeek, OpenAI, Groq,
OpenRouter, Ollama, or a self-hosted gateway) using plain ``httpx`` —
no vendor SDK required. Base URL, API key, and model all come from
``AegisxConfig`` (env vars or CLI flags), so switching providers is a
config change, not a code change.

Wire format (POST ``{base_url}/chat/completions``)::

    {
      "model": "<model>",
      "messages": [{"role": "system"|"user"|"assistant"|"tool", ...}],
      "tools": [{"type": "function", "function": {...JSON Schema...}}],
      "temperature": 0.2,
      "max_tokens": 4000
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aegisx.core.config import AegisxConfig
from aegisx.utils.logger import get_logger

logger = get_logger("ai.provider")


class AIProviderError(Exception):
    """Raised when the AI endpoint is unreachable or returns an error."""


@dataclass
class ToolCall:
    """One function call requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResult:
    """Normalized assistant turn."""

    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


def _redact(value: str) -> str:
    """Mask a secret for safe logging: keep first 4 chars only."""
    if not value:
        return "(empty)"
    return value[:4] + "…" if len(value) > 8 else "…"


class AIProvider:
    """Minimal async client for OpenAI-compatible chat completions APIs."""

    def __init__(self, config: AegisxConfig) -> None:
        """Resolve endpoint settings from config and validate them."""
        self.config = config
        self.base_url, self.api_key, self.model = config.resolve_ai_endpoint()
        logger.debug(
            "AI provider ready: base_url=%s model=%s key=%s",
            self.base_url,
            self.model,
            _redact(self.api_key),
        )

    def _headers(self) -> dict[str, str]:
        """Build auth headers; Authorization omitted when key is empty."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        """Send a chat completion request and normalize the response.

        Args:
            messages: OpenAI-format message list.
            tools: Optional tool schemas (``{"type": "function", ...}``).

        Returns:
            ChatResult with content and/or tool calls.

        Raises:
            AIProviderError: On network failure, HTTP error, or malformed JSON.
        """
        import httpx

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.config.ai_temperature,
            "max_tokens": self.config.ai_max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"
        try:
            # verify=False is intentional: some self-hosted gateways use
            # self-signed certs. Traffic carries no secrets beyond the key itself.
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds, verify=False
            ) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
        except httpx.RequestError as exc:
            raise AIProviderError(
                f"Cannot reach AI endpoint {self.base_url}: {type(exc).__name__}"
            ) from exc

        if resp.status_code == 401:
            raise AIProviderError("AI endpoint rejected the API key (HTTP 401)")
        if resp.status_code == 429:
            raise AIProviderError("AI endpoint rate limited us (HTTP 429) — retry later")
        if resp.status_code >= 400:
            raise AIProviderError(
                f"AI endpoint error HTTP {resp.status_code}: {resp.text[:200]}"
            )

        try:
            data = self._parse_response_body(resp.text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AIProviderError(
                f"AI endpoint returned non-JSON response: {resp.text[:200]}"
            ) from exc

        try:
            choice = data["choices"][0]
        except (KeyError, IndexError) as exc:
            raise AIProviderError(f"Malformed AI response (no choices): {data!r:.200}") from exc

        message = choice.get("message", {})
        tool_calls = [
            ToolCall(
                id=tc.get("id", f"call_{i}"),
                name=tc.get("function", {}).get("name", ""),
                arguments=self._parse_arguments(tc.get("function", {}).get("arguments", "{}")),
            )
            for i, tc in enumerate(message.get("tool_calls") or [])
        ]

        return ChatResult(
            content=message.get("content"),
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason", ""),
            usage=data.get("usage", {}) or {},
        )

    @staticmethod
    def _parse_response_body(raw: str) -> dict[str, Any]:
        """Parse the completion body tolerating non-standard gateways.

        Some OpenAI-compatible gateways (e.g. SSE-proxied endpoints)
        return JSON with artifacts:

        - trailing ``data: [DONE]`` sentinel lines,
        - ``data: {json}`` SSE event framing,
        - multiple concatenated JSON objects (chunk + usage chunk).

        Strategy: try strict SSE parsing first (data: lines), then fall
        back to concatenated-JSON scanning; return the first object that
        looks like a chat.completion.
        """
        raw = raw.strip()
        if not raw:
            raise ValueError("empty response body")

        def _is_completion(obj: Any) -> bool:
            return isinstance(obj, dict) and "choices" in obj

        # 1) SSE framing: one JSON object per "data: " line
        sse_objects: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if _is_completion(obj):
                sse_objects.append(obj)
        if sse_objects:
            return sse_objects[0]

        # 2) Concatenated JSON scan (tolerates junk between objects)
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(raw):
            while idx < len(raw) and raw[idx] not in "{[":
                idx += 1
            if idx >= len(raw):
                break
            try:
                obj, end = decoder.raw_decode(raw, idx)
            except json.JSONDecodeError:
                idx += 1
                continue
            if _is_completion(obj):
                return obj
            idx = end

        raise ValueError("no chat.completion object found in response")

    @staticmethod
    def _parse_arguments(raw: str) -> dict[str, Any]:
        """Parse tool-call arguments JSON, tolerating empty/invalid input."""
        if not raw or not raw.strip():
            return {}
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_raw": parsed}
        except json.JSONDecodeError:
            logger.warning("Tool call arguments are not valid JSON: %.120s", raw)
            return {"_raw": raw}

    async def health_check(self) -> tuple[bool, str]:
        """Ping the endpoint with a tiny completion.

        Returns:
            ``(ok, detail)`` — detail is human-readable for CLI output.
        """
        try:
            result = await self.chat(
                [{"role": "user", "content": "Reply with exactly: ok"}],
                tools=None,
            )
            ok = bool(result.content or result.has_tool_calls)
            return ok, f"model={self.model} replied" if ok else "empty response"
        except AIProviderError as exc:
            return False, str(exc)
