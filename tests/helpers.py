"""Test doubles shared by the agent-loop and CLI tests."""
from llm import LLMResponse, ToolCall

_counter = iter(range(1, 10_000))


def call(name, **args):
    return ToolCall(id=f"c{next(_counter)}", name=name, args=args)


def resp(*calls, text=""):
    return LLMResponse(text=text, tool_calls=list(calls))


class FakeLLM:
    """Returns a scripted sequence of responses and records what it was shown."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def chat(self, messages, system, tools):
        self.calls.append({"messages": list(messages), "tools": [t["name"] for t in tools]})
        if not self.script:
            raise AssertionError("FakeLLM script exhausted")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class SpyTools:
    """Wraps real tools and records dispatches."""

    def __init__(self, inner):
        self.inner = inner
        self.dispatched = []

    def dispatch(self, name, args):
        self.dispatched.append((name, dict(args)))
        return self.inner.dispatch(name, args)

    def list_paths(self):
        return self.inner.list_paths()
