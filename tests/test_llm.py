import pytest

pytest.importorskip("google.genai")

import config
from types import SimpleNamespace

from google.genai import types

import tool_schemas
from errors import LLMError
from llm import LLMClient, LLMResponse, ToolCall


class APIErr(Exception):
    def __init__(self, code, msg="boom"):
        super().__init__(msg)
        self.code = code


class FakeModels:
    def __init__(self, outcomes, available_models=None):
        self.outcomes = list(outcomes)
        self.available_models = list(available_models or [])
        self.calls = 0
        self.called_models = []
        self.list_calls = 0

    def generate_content(self, model, contents, config):
        self.calls += 1
        self.called_models.append(model)
        out = self.outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out

    def list(self, config=None):
        self.list_calls += 1
        assert config == {"page_size": 100}
        return iter(self.available_models)


def client(outcomes, api_key="KEY123", retries=3, available_models=None):
    fake = SimpleNamespace(models=FakeModels(outcomes, available_models))
    sleeps = []
    c = LLMClient(api_key, "m", retries=retries, client=fake, sleep=sleeps.append)
    return c, fake, sleeps


def model_response(*parts):
    return SimpleNamespace(
        candidates=[SimpleNamespace(content=types.Content(role="model", parts=list(parts)), finish_reason="STOP")]
    )


def test_tool_declarations_are_accepted_by_sdk():
    c, _, _ = client([])
    cfg = c._config("sys", tool_schemas.TOOL_DECLARATIONS)
    names = [d.name for d in cfg.tools[0].function_declarations]
    assert names == ["list_files", "read_file", "search_code", "git_log", "submit_report"]
    submit = cfg.tools[0].function_declarations[-1]
    item = submit.parameters.properties["violations"].items
    assert item.properties["file"].nullable is True and len(item.required) == 8


def test_parse_text_and_function_calls():
    c, _, _ = client([])
    r = c._parse(model_response(
        types.Part(text="thinking"),
        types.Part(function_call=types.FunctionCall(name="read_file", args={"path": "a.py", "reason": "x"})),
        types.Part(function_call=types.FunctionCall(name="git_log", args={})),
    ))
    assert r.text == "thinking"
    assert [(t.name, t.args) for t in r.tool_calls] == [
        ("read_file", {"path": "a.py", "reason": "x"}), ("git_log", {})]
    assert len({t.id for t in r.tool_calls}) == 2
    assert isinstance(r.raw, types.Content)


def test_parse_empty_responses():
    c, _, _ = client([])
    assert c._parse(SimpleNamespace(candidates=[])).text.startswith("(empty response")
    r = c._parse(SimpleNamespace(candidates=[SimpleNamespace(content=None, finish_reason="MALFORMED_FUNCTION_CALL")]))
    assert "MALFORMED_FUNCTION_CALL" in r.text and r.tool_calls == [] and r.raw is None


def test_to_contents_groups_tool_results_and_reuses_raw():
    c, _, _ = client([])
    raw = types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name="a", args={}))])
    msgs = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [], "raw": raw},
        {"role": "tool", "name": "a", "tool_call_id": "1", "content": "res1"},
        {"role": "tool", "name": "b", "tool_call_id": "2", "content": "res2"},
        {"role": "user", "content": "now submit"},
        {"role": "assistant", "content": "plain", "tool_calls": [], "raw": None},
        {"role": "user", "content": "nudge"},
    ]
    contents = c._to_contents(msgs)
    assert [x.role for x in contents] == ["user", "model", "user", "model", "user"]
    assert contents[1] is raw
    assert len(contents[2].parts) == 3
    assert contents[2].parts[0].function_response.name == "a"
    assert contents[2].parts[0].function_response.response == {"result": "res1"}
    assert contents[2].parts[2].text == "now submit"


def test_to_contents_rebuilds_assistant_without_raw():
    c, _, _ = client([])
    out = c._to_contents([
        {"role": "assistant", "content": "", "tool_calls": [{"id": "1", "name": "git_log", "args": {"n": 3}}], "raw": None},
        {"role": "assistant", "content": "", "tool_calls": [], "raw": None},
    ])
    assert out[0].parts[0].function_call.name == "git_log"
    assert out[1].parts[0].text == "(no output)"


def test_retries_then_succeeds():
    ok = model_response(types.Part(text="hi"))
    c, fake, sleeps = client([APIErr(503), APIErr(429), ok])
    r = c.chat([{"role": "user", "content": "x"}], "sys", tool_schemas.TOOL_DECLARATIONS)
    assert r.text == "hi" and fake.models.calls == 3 and len(sleeps) == 2 and sleeps[1] > sleeps[0] - 1


def test_unavailable_model_falls_back_to_available_flash(monkeypatch, capsys):
    ok = model_response(types.Part(text="fallback response"))
    available = [
        SimpleNamespace(name="models/gemini-2.5-flash", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-pro", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-3.8-flash", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-2.5-flash-image", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-image", supported_actions=["predict"]),
    ]
    c, fake, _ = client(
        [APIErr(503), APIErr(503), ok],
        available_models=available,
    )

    response = c.chat([{"role": "user", "content": "x"}], "sys", tool_schemas.TOOL_DECLARATIONS)

    assert response.text == "fallback response"
    assert response.model == "gemini-3.8-flash"
    assert fake.models.called_models == [
        "m", "m", "gemini-3.8-flash",
    ]
    assert fake.models.list_calls == 1
    assert c._api_calls == 4
    assert "trying fallback 'gemini-3.8-flash'" in capsys.readouterr().err


def test_fallback_tries_each_listed_model_until_one_succeeds(monkeypatch):
    ok = model_response(types.Part(text="success"))
    available = [
        SimpleNamespace(name="models/gemini-3.8-flash-preview", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-3.1-flash", supported_actions=["generateContent"]),
    ]
    c, fake, _ = client(
        [APIErr(404), APIErr(503), ok],
        available_models=available,
    )

    response = c.chat([{"role": "user", "content": "x"}], "sys", tool_schemas.TOOL_DECLARATIONS)

    assert response.text == "success"
    assert response.model == "gemini-3.1-flash"
    assert fake.models.called_models == ["m", "gemini-3.8-flash-preview", "gemini-3.1-flash"]
    assert fake.models.list_calls == 1


def test_fallback_skips_retired_model_and_tries_next(monkeypatch):
    ok = model_response(types.Part(text="success"))
    available = [
        SimpleNamespace(name="models/gemini-3.8-flash", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-3.1-flash", supported_actions=["generateContent"]),
        SimpleNamespace(name="models/gemini-2.5-flash", supported_actions=["generateContent"]),
    ]
    c, fake, _ = client(
        [APIErr(503), APIErr(503), APIErr(404), ok],
        available_models=available,
    )

    response = c.chat([{"role": "user", "content": "x"}], "sys", tool_schemas.TOOL_DECLARATIONS)

    assert response.text == "success"
    assert response.model == "gemini-3.1-flash"
    assert fake.models.called_models == ["m", "m", "gemini-3.8-flash", "gemini-3.1-flash"]


def test_model_fallback_rebuilds_other_models_assistant_turns():
    c, _, _ = client([])
    raw = types.Content(
        role="model",
        parts=[types.Part(function_call=types.FunctionCall(name="git_log", args={"reason": "inspect"}))],
    )
    contents = c._to_contents(
        [{
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "1", "name": "git_log", "args": {"reason": "inspect"}}],
            "raw": raw,
            "model": "m",
        }],
        model="fallback",
    )
    assert contents[0] is not raw
    assert contents[0].parts[0].function_call.name == "git_log"


def test_retries_exhausted_raises_llm_error():
    c, fake, _ = client([APIErr(503)] * 3)
    with pytest.raises(LLMError):
        c.chat([{"role": "user", "content": "x"}], "s", tool_schemas.TOOL_DECLARATIONS)
    assert fake.models.calls == 3


def test_chat_calls_can_exceed_five_requests():
    ok = model_response(types.Part(text="ok"))
    c, fake, _ = client([ok] * 6)

    for _ in range(6):
        response = c.chat([{"role": "user", "content": "x"}], "s", tool_schemas.TOOL_DECLARATIONS)
        assert response.text == "ok"

    assert fake.models.calls == 6
    assert c._api_calls == 6


def test_default_model_is_gemini_flash_lite(monkeypatch):
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert config.get_model() == "gemini-3.1-flash-lite"


def test_non_retryable_fails_fast_and_scrubs_key():
    c, fake, _ = client([APIErr(400, "bad request for key KEY123")])
    with pytest.raises(LLMError) as e:
        c.chat([{"role": "user", "content": "x"}], "s", tool_schemas.TOOL_DECLARATIONS)
    assert fake.models.calls == 1 and "KEY123" not in str(e.value) and "***" in str(e.value)


def test_404_hints_at_model_name():
    c, _, _ = client([APIErr(404, "model not found")])
    with pytest.raises(LLMError, match="LLM_MODEL"):
        c.chat([{"role": "user", "content": "x"}], "s", tool_schemas.TOOL_DECLARATIONS)


def test_timeouts_are_retryable():
    ok = model_response(types.Part(text="hi"))
    c, fake, _ = client([TimeoutError("slow"), ok])
    assert c.chat([{"role": "user", "content": "x"}], "s", tool_schemas.TOOL_DECLARATIONS).text == "hi"


def test_response_to_message_roundtrip():
    r = LLMResponse(text="t", tool_calls=[ToolCall("1", "git_log", {"n": 1})], raw="RAW")
    assert r.to_message() == {
        "role": "assistant", "content": "t",
        "tool_calls": [{"id": "1", "name": "git_log", "args": {"n": 1}}], "raw": "RAW"}
