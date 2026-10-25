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
import re
import sys
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
    model: Optional[str] = None

    def to_message(self) -> dict:
        message = {
            "role": "assistant",
            "content": self.text,
            "tool_calls": [{"id": c.id, "name": c.name, "args": c.args} for c in self.tool_calls],
            "raw": self.raw,
        }
        if self.model is not None:
            message["model"] = self.model
        return message


_RETRYABLE_CODES = {408, 429, 500, 502, 503, 504}
_RETRYABLE_NAMES = {
    "ReadTimeout", "ConnectTimeout", "TimeoutException", "ConnectError", "ReadError",
    "RemoteProtocolError", "PoolTimeout", "WriteTimeout",
}


def _fallback_model_key(name: str) -> tuple:
    version = re.search(r"gemini-(\d+)\.(\d+)", name.lower())
    major, minor = (map(int, version.groups()) if version else (0, 0))
    return (-major, -minor, "flash" not in name.lower(), "preview" in name.lower(), name.lower())


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
        self._preferred_model = model
        self.retries = max(1, retries)
        self._api_calls = 0
        self._fallback_models: Optional[list[str]] = None
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
        response, model = self._generate(messages, cfg)
        return self._parse(response, model)

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

    def _to_contents(self, messages: list[dict], model: Optional[str] = None) -> list:
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
                message_model = m.get("model", self._preferred_model)
                if m.get("raw") is not None and (model is None or message_model == model):
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
    def _discover_fallback_models(self) -> list[str]:
        if self._fallback_models is not None:
            return self._fallback_models
        if self._api_calls >= config.MAX_LLM_API_CALLS - 1:
            self._fallback_models = []
            return self._fallback_models

        list_models = getattr(self._client.models, "list", None)
        if list_models is None:
            self._fallback_models = []
            return self._fallback_models

        self._api_calls += 1
        try:
            models = list_models(config={"page_size": 100})
            candidates = []
            for model in itertools.islice(models, 100):
                name = getattr(model, "name", None)
                actions = getattr(model, "supported_actions", None) or []
                if isinstance(actions, str):
                    actions = [actions]
                if not isinstance(name, str) or not any(
                    isinstance(action, str) and action.lower() == "generatecontent"
                    for action in actions
                ):
                    continue
                name = name.removeprefix("models/")
                if (
                    name
                    and name != self._preferred_model
                    and "image" not in name.lower()
                ):
                    candidates.append(name)
        except Exception as exc:  # noqa: BLE001 - model discovery is an API operation
            raise LLMError(
                f"Gemini API error while discovering fallback models: {self._scrub(exc)}"
            ) from None

        self._fallback_models = sorted(set(candidates), key=_fallback_model_key)
        return self._fallback_models

    def _request_error(self, exc: BaseException, model: str) -> LLMError:
        hint = ""
        if getattr(exc, "code", None) == 404:
            hint = f" (is LLM_MODEL={model!r} still available?)"
        return LLMError(f"Gemini API error: {self._scrub(exc)}{hint}")

    def _generate(self, messages: list[dict], cfg):
        if self._api_calls >= config.MAX_LLM_API_CALLS:
            raise LLMError(
                f"Gemini API call limit reached ({config.MAX_LLM_API_CALLS} requests per audit)"
            )

        current_model = self.model
        attempted_models = {current_model}
        current_attempts = 0
        last_error = None
        fallback_ready = False
        primary_attempt_limit = self.retries

        while self._api_calls < config.MAX_LLM_API_CALLS:
            current_attempts += 1
            self._api_calls += 1
            try:
                response = self._client.models.generate_content(
                    model=current_model,
                    contents=self._to_contents(messages, model=current_model),
                    config=cfg,
                )
                self.model = current_model
                return response, current_model
            except Exception as exc:  # noqa: BLE001 - classified below
                last_error = exc
                unavailable = _is_retryable(exc) or getattr(exc, "code", None) == 404
                if not unavailable:
                    raise self._request_error(exc, current_model) from None

                if not fallback_ready:
                    try:
                        self._discover_fallback_models()
                    except LLMError as discovery_error:
                        raise LLMError(
                            f"{self._request_error(exc, current_model)}; "
                            f"{discovery_error}"
                        ) from None
                    fallback_ready = True

                    available_fallbacks = [
                        name for name in self._fallback_models or []
                        if name not in attempted_models
                    ]
                    if available_fallbacks and current_model == self.model:
                        primary_attempt_limit = min(self.retries, 2)

                available_fallbacks = [
                    name for name in self._fallback_models or []
                    if name not in attempted_models
                ]
                may_retry_current = (
                    _is_retryable(exc)
                    and current_attempts < primary_attempt_limit
                    and self._api_calls < config.MAX_LLM_API_CALLS
                    and (
                        not available_fallbacks
                        or self._api_calls < config.MAX_LLM_API_CALLS - min(len(available_fallbacks), 1)
                    )
                )
                if may_retry_current:
                    delay = min(30.0, 2.0 * 2 ** (current_attempts - 1)) + random.random()
                    self._sleep(delay)
                    continue

                if available_fallbacks and self._api_calls < config.MAX_LLM_API_CALLS:
                    unavailable_model = current_model
                    current_model = available_fallbacks[0]
                    attempted_models.add(current_model)
                    current_attempts = 0
                    primary_attempt_limit = 1
                    print(
                        f"warning: Gemini model {unavailable_model!r} is unavailable; "
                        f"trying fallback {current_model!r}",
                        file=sys.stderr,
                    )
                    continue

                raise self._request_error(exc, current_model) from None

        if last_error is not None:
            raise self._request_error(last_error, current_model) from None
        raise LLMError("Gemini API error: request budget exhausted")

    def _scrub(self, exc: BaseException) -> str:
        msg = f"{type(exc).__name__}: {exc}"
        if self.api_key:
            msg = msg.replace(self.api_key, "***")
        return redact(msg)[:500]

    # ----------------------------------------------------------------- parsing
    def _parse(self, response, model: Optional[str] = None) -> LLMResponse:
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            block = getattr(getattr(response, "prompt_feedback", None), "block_reason", None)
            return LLMResponse(
                text=f"(empty response from model{f': {block}' if block else ''})",
                model=model,
            )
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
            return LLMResponse(
                text=f"(model returned no usable output; finish_reason={reason})",
                model=model,
            )
        return LLMResponse(
            text="\n".join(texts).strip(), tool_calls=calls, raw=content, model=model
        )
