"""Thin Gemini wrapper. The rest of the project never touches SDK types.

The agent loop keeps a provider-neutral message list:
    {"role": "user",      "content": str}
    {"role": "assistant", "content": str, "tool_calls": [...], "raw": <opaque>}
    {"role": "tool",      "name": str, "tool_call_id": str, "content": str}
This module converts that list to Gemini `Content` objects on every call. Assistant turns are
sent back exactly as the model produced them (`raw`), which preserves thought signatures that
newer Gemini models require when continuing a function-calling conversation.
"""
from __future__ import annotations

import itertools
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import config
from errors import LLMError
from redact import redact


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    raw: Any = None

    def to_message(self) -> dict:
        return {
            "role": "assistant",
            "content": self.text,
            "tool_calls": [{"id": c.id, "name": c.name, "args": c.args} for c in self.tool_calls],
            "raw": self.raw,
        }


_RETRYABLE_CODES = {408, 429, 500, 502, 503, 504}
_RETRYABLE_NAMES = {
    "ReadTimeout", "ConnectTimeout", "TimeoutException", "ConnectError", "ReadError",
    "RemoteProtocolError", "PoolTimeout", "WriteTimeout",
}


def _is_retryable(exc: BaseException) -> bool:
    if getattr(exc, "code", None) in _RETRYABLE_CODES:
        return True
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    return any(cls.__name__ in _RETRYABLE_NAMES for cls in type(exc).__mro__)


def _plain(obj: Any) -> Any:
    try:
        return json.loads(json.dumps(obj, default=str))
    except (TypeError, ValueError):
        return {}


class LLMClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        timeout: float = config.LLM_TIMEOUT,
        retries: int = config.LLM_RETRIES,
        client: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.api_key = api_key
        self.model = model
        self.retries = max(1, retries)
        self._api_calls = 0
        self._sleep = sleep
        self._ids = itertools.count(1)
        from google.genai import types  # imported lazily so tests of other modules need no SDK

        self._types = types
        if client is None:
            from google import genai

            client = genai.Client(
                api_key=api_key, http_options=types.HttpOptions(timeout=int(timeout * 1000))
            )
        self._client = client

    # ---------------------------------------------------------------- public API
    def chat(self, messages: list[dict], system: str, tools: list[dict]) -> LLMResponse:
        cfg = self._config(system, tools)
        response = self._generate(self._to_contents(messages), cfg)
        return self._parse(response)

    # ------------------------------------------------------------------ building
    def _config(self, system: str, tools: list[dict]):
        t = self._types
        decls = [
            t.FunctionDeclaration(
                name=d["name"], description=d["description"], parameters=d["parameters"]
            )
            for d in tools
        ]
        # Leave temperature at the provider default (recommended for Gemini 3 models).
        return t.GenerateContentConfig(
            system_instruction=system,
            tools=[t.Tool(function_declarations=decls)],
            automatic_function_calling=t.AutomaticFunctionCallingConfig(disable=True),
        )

    def _to_contents(self, messages: list[dict]) -> list:
        t = self._types
        contents: list = []
        pending: list = []  # consecutive user/tool messages merge into ONE user Content

        def flush():
            if pending:
                contents.append(t.Content(role="user", parts=list(pending)))
                pending.clear()

        for m in messages:
            role = m["role"]
            if role == "user":
                pending.append(t.Part(text=m["content"]))
            elif role == "tool":
                pending.append(
                    t.Part(
                        function_response=t.FunctionResponse(
                            id=m.get("tool_call_id"),
                            name=m["name"],
                            response={"result": m["content"]},
                        )
                    )
                )
            elif role == "assistant":
                flush()
                if m.get("raw") is not None:
                    contents.append(m["raw"])
                    continue
                parts = []
                if m.get("content"):
                    parts.append(t.Part(text=m["content"]))
                for c in m.get("tool_calls") or []:
                    parts.append(
                        t.Part(
                            function_call=t.FunctionCall(
                                id=c.get("id"), name=c["name"], args=c.get("args") or {}
                            )
                        )
                    )
                if not parts:
                    parts.append(t.Part(text="(no output)"))
                contents.append(t.Content(role="model", parts=parts))
        flush()
        return contents

    # --------------------------------------------------------------- API call
    def _generate(self, contents: list, cfg):
        if self._api_calls >= config.MAX_LLM_API_CALLS:
            raise LLMError(
                f"Gemini API call limit reached ({config.MAX_LLM_API_CALLS} requests per audit)"
            )
        for attempt in range(1, self.retries + 1):
            if self._api_calls >= config.MAX_LLM_API_CALLS:
                raise LLMError(
                    f"Gemini API call limit reached ({config.MAX_LLM_API_CALLS} requests per audit)"
                )
            self._api_calls += 1
            try:
                return self._client.models.generate_content(
                    model=self.model, contents=contents, config=cfg
                )
            except Exception as exc:  # noqa: BLE001 - classified below
                if (
                    not _is_retryable(exc)
                    or attempt == self.retries
                    or self._api_calls >= config.MAX_LLM_API_CALLS
                ):
                    hint = ""
                    if getattr(exc, "code", None) == 404:
                        hint = f" (is LLM_MODEL={self.model!r} still available?)"
                    raise LLMError(f"Gemini API error: {self._scrub(exc)}{hint}") from None
                delay = min(30.0, 2.0 * 2 ** (attempt - 1)) + random.random()
                self._sleep(delay)
        raise LLMError("Gemini API error: retries exhausted")  # pragma: no cover

    def _scrub(self, exc: BaseException) -> str:
        msg = f"{type(exc).__name__}: {exc}"
        if self.api_key:
            msg = msg.replace(self.api_key, "***")
        return redact(msg)[:500]

    # ----------------------------------------------------------------- parsing
    def _parse(self, response) -> LLMResponse:
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            block = getattr(getattr(response, "prompt_feedback", None), "block_reason", None)
            return LLMResponse(text=f"(empty response from model{f': {block}' if block else ''})")
        cand = candidates[0]
        content = getattr(cand, "content", None)
        parts = (getattr(content, "parts", None) or []) if content else []
        texts, calls = [], []
        for p in parts:
            fc = getattr(p, "function_call", None)
            if fc is not None and getattr(fc, "name", None):
                args = _plain(dict(fc.args)) if fc.args else {}
                calls.append(
                    ToolCall(id=getattr(fc, "id", None) or f"call_{next(self._ids)}", name=fc.name, args=args)
                )
            elif getattr(p, "text", None) and not getattr(p, "thought", False):
                texts.append(p.text)
        if not parts:
            reason = getattr(cand, "finish_reason", None)
            return LLMResponse(text=f"(model returned no usable output; finish_reason={reason})")
        return LLMResponse(text="\n".join(texts).strip(), tool_calls=calls, raw=content)
